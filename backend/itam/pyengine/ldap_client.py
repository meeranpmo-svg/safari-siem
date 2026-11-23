# Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
"""Minimal LDAPv3 client over TLS - the same protocol bytes and rules as engine/discovery/ldap-client.js (migration step
5b, docs/PYTHON-MIGRATION.md).

  Transport  ldaps://host:636 (TLS from the first byte) or ldap://host:389 + StartTLS - there is NO cleartext mode.
             Certificate verification is always on: the CA is a PEM file (the AD CS root) and the certificate must name
             the server's DNS name, even when an `ip` is dialled. TLS 1.2 or newer.
  Operations simple Bind (an empty DN / password is refused here and never sent: RFC 4513 unauthenticated bind),
             paged subtree Search (1.2.840.113556.1.4.319, page size capped at 1000), Unbind.
  Failover   run(fn): servers in order; a transport failure (connect, TLS, timeout, lost connection) moves on to the next
             server, an LDAP result error (e.g. 49) does not.
Standard library only (Python 3.8+). Passwords are never logged or put in an error.
"""
import ipaddress
import re
import socket
import ssl

PAGED, STARTTLS = '1.2.840.113556.1.4.319', '1.3.6.1.4.1.1466.20037'
RESULT = {0: 'success', 1: 'operationsError', 2: 'protocolError', 3: 'timeLimitExceeded', 4: 'sizeLimitExceeded', 7: 'authMethodNotSupported',
          8: 'strongerAuthRequired', 10: 'referral', 11: 'adminLimitExceeded', 12: 'unavailableCriticalExtension', 13: 'confidentialityRequired',
          32: 'noSuchObject', 34: 'invalidDNSyntax', 48: 'inappropriateAuthentication', 49: 'invalidCredentials', 50: 'insufficientAccessRights',
          51: 'busy', 52: 'unavailable', 53: 'unwillingToPerform', 80: 'other'}
MAX_PAGE = 1000
SCOPE = {'base': 0, 'one': 1, 'onelevel': 1, 'sub': 2, 'subtree': 2}


class LdapError(Exception):
    def __init__(self, message, code=None, transport=False):
        super().__init__(message)
        self.code, self.transport = code, transport


# ---- BER ------------------------------------------------------------------------------------------------------------
def len_bytes(n):
    if n < 0x80:
        return bytes([n])
    b = []
    while n > 0:
        b.insert(0, n & 0xff)
        n //= 256
    return bytes([0x80 | len(b)] + b)


def tlv(tag, content):
    c = content if isinstance(content, (bytes, bytearray)) else b''.join(content)
    return bytes([tag]) + len_bytes(len(c)) + bytes(c)


def int_bytes(n):
    n = int(n or 0)
    out = []
    while True:
        byte = n & 0xff
        out.insert(0, byte)
        n >>= 8
        if (n == 0 and not byte & 0x80) or (n == -1 and byte & 0x80):
            break
    return bytes(out)


def ber_int(n, tag=0x02):
    return tlv(tag, int_bytes(n))


def ber_enum(n):
    return tlv(0x0a, int_bytes(n))


def ber_bool(b, tag=0x01):
    return tlv(tag, bytes([0xff if b else 0x00]))


def ber_str(s, tag=0x04):
    return tlv(tag, s if isinstance(s, (bytes, bytearray)) else ('' if s is None else str(s)).encode('utf-8'))


def read_tlv(buf, off, limit=None):
    end0 = len(buf) if limit is None else limit
    if off + 2 > end0:
        return None
    tag, ln, p = buf[off], buf[off + 1], off + 2
    if ln & 0x80:
        nb = ln & 0x7f
        if nb == 0 or nb > 4:
            raise LdapError('BER: unsupported length encoding', transport=True)
        if p + nb > end0:
            return None
        ln = 0
        for i in range(nb):
            ln = ln * 256 + buf[p + i]
        p += nb
    if p + ln > end0:
        return None
    return (tag, p, p + ln)


def must_tlv(buf, off, limit=None):
    t = read_tlv(buf, off, limit)
    if t is None:
        raise LdapError('BER: truncated element', transport=True)
    return t


def children(buf, t):
    out, p = [], t[1]
    while p < t[2]:
        c = must_tlv(buf, p, t[2])
        out.append(c)
        p = c[2]
    return out


def read_int(buf, t):
    if t[2] - t[1] > 6:
        raise LdapError('BER: integer too large', transport=True)
    n = 0
    for i in range(t[1], t[2]):
        n = n * 256 + buf[i]
    if t[2] > t[1] and buf[t[1]] & 0x80:
        n -= 256 ** (t[2] - t[1])
    return n


def read_str(buf, t):
    return bytes(buf[t[1]:t[2]]).decode('utf-8', 'replace')


def read_buf(buf, t):
    return bytes(buf[t[1]:t[2]])


# ---- filters (RFC 4515) ---------------------------------------------------------------------------------------------
ATTR_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9;.-]*$')
OID_RE = re.compile(r'^([0-9]+(\.[0-9]+)+|[A-Za-z][A-Za-z0-9-]*)$')


def unescape_value(s):
    out, i = bytearray(), 0
    while i < len(s):
        ch = s[i]
        if ch == '\\':
            hx = s[i + 1:i + 3]
            if not re.match(r'^[0-9a-fA-F]{2}$', hx):
                raise LdapError('invalid filter: bad escape near "%s"' % s[i:i + 3])
            out.append(int(hx, 16))
            i += 3
            continue
        if ch in '()*\0':
            raise LdapError('invalid filter: unescaped "%s" in a value' % ch)
        out += ch.encode('utf-8')
        i += 1
    return bytes(out)


def parse_item(body):
    eq = body.find('=')
    if eq < 1:
        raise LdapError('invalid filter item: "%s"' % body)
    before, value = body[eq - 1], body[eq + 1:]
    if before == ':':
        left = body[:eq - 1].split(':')
        attr = left.pop(0)
        dn_attrs, rule = False, ''
        for p in left:
            if p.lower() == 'dn':
                dn_attrs = True
            elif p:
                rule = p
            else:
                raise LdapError('invalid extensible filter')
        if attr and not ATTR_RE.match(attr):
            raise LdapError('invalid attribute "%s"' % attr)
        if rule and not OID_RE.match(rule):
            raise LdapError('invalid matching rule "%s"' % rule)
        if not attr and not rule:
            raise LdapError('invalid extensible filter: attribute or rule required')
        return {'type': 'ext', 'attr': attr, 'rule': rule, 'dnAttributes': dn_attrs, 'value': unescape_value(value)}
    typ, attr = 'eq', body[:eq]
    if before in '><~':
        typ = {'>': 'ge', '<': 'le', '~': 'approx'}[before]
        attr = body[:eq - 1]
    if not ATTR_RE.match(attr):
        raise LdapError('invalid attribute "%s"' % attr)
    if typ == 'eq' and value == '*':
        return {'type': 'present', 'attr': attr}
    if typ == 'eq' and '*' in value:
        parts = value.split('*')
        return {'type': 'substr', 'attr': attr, 'initial': unescape_value(parts[0]) if parts[0] else None,
                'any': [unescape_value(x) for x in parts[1:-1] if x], 'final': unescape_value(parts[-1]) if parts[-1] else None}
    return {'type': typ, 'attr': attr, 'value': unescape_value(value)}


def parse_filter(text):
    s0 = (text or '').strip()
    if not s0:
        raise LdapError('empty filter')
    s = s0 if s0[0] == '(' else '(' + s0 + ')'
    pos = [0]

    def at(i):
        return s[i] if i < len(s) else ''

    def one():
        if at(pos[0]) != '(':
            raise LdapError('invalid filter: expected "(" at %d' % pos[0])
        pos[0] += 1
        op = at(pos[0])
        if op in ('&', '|'):
            pos[0] += 1
            lst = []
            while at(pos[0]) == '(':
                lst.append(one())
            node = {'type': 'and' if op == '&' else 'or', 'filters': lst}
        elif op == '!':
            pos[0] += 1
            node = {'type': 'not', 'filter': one()}
        else:
            close = s.find(')', pos[0])
            if close < 0:
                raise LdapError('invalid filter: missing ")"')
            node = parse_item(s[pos[0]:close])
            pos[0] = close
        if at(pos[0]) != ')':
            raise LdapError('invalid filter: expected ")" at %d' % pos[0])
        pos[0] += 1
        return node
    node = one()
    if pos[0] != len(s):
        raise LdapError('invalid filter: trailing characters at %d' % pos[0])
    return node


def encode_filter(f):
    if isinstance(f, str):
        f = parse_filter(f)
    t = f['type']
    if t == 'and':
        return tlv(0xa0, [encode_filter(x) for x in f['filters']])
    if t == 'or':
        return tlv(0xa1, [encode_filter(x) for x in f['filters']])
    if t == 'not':
        return tlv(0xa2, encode_filter(f['filter']))
    if t in ('eq', 'ge', 'le', 'approx'):
        return tlv({'eq': 0xa3, 'ge': 0xa5, 'le': 0xa6, 'approx': 0xa8}[t], [ber_str(f['attr']), ber_str(f['value'])])
    if t == 'present':
        return ber_str(f['attr'], 0x87)
    if t == 'substr':
        subs = []
        if f['initial']:
            subs.append(ber_str(f['initial'], 0x80))
        subs.extend(ber_str(a, 0x81) for a in f['any'] or [])
        if f['final']:
            subs.append(ber_str(f['final'], 0x82))
        return tlv(0xa4, [ber_str(f['attr']), tlv(0x30, subs)])
    if t == 'ext':
        parts = []
        if f['rule']:
            parts.append(ber_str(f['rule'], 0x81))
        if f['attr']:
            parts.append(ber_str(f['attr'], 0x82))
        parts.append(ber_str(f['value'], 0x83))
        if f['dnAttributes']:
            parts.append(ber_bool(True, 0x84))
        return tlv(0xa9, parts)
    raise LdapError('unknown filter type %s' % t)


# ---- messages -------------------------------------------------------------------------------------------------------
def message(mid, op, controls=None):
    parts = [ber_int(mid), op]
    if controls:
        parts.append(tlv(0xa0, controls))
    return tlv(0x30, parts)


def control(oid, critical, value):
    parts = [ber_str(oid)]
    if critical:
        parts.append(ber_bool(True))
    if value:
        parts.append(ber_str(value))
    return tlv(0x30, parts)


def paged_control(size, cookie):
    return control(PAGED, False, tlv(0x30, [ber_int(size), ber_str(cookie or b'')]))


def bind_request(dn, password):
    return tlv(0x60, [ber_int(3), ber_str(dn), ber_str(password, 0x80)])


def search_request(base, o):
    return tlv(0x63, [ber_str(base), ber_enum(o['scope']), ber_enum(o.get('deref') or 0), ber_int(o.get('sizeLimit') or 0), ber_int(o.get('timeLimit') or 0),
                      ber_bool(False), encode_filter(o['filter']), tlv(0x30, [ber_str(a) for a in o.get('attributes') or []])])


def extended_request(oid, value=None):
    p = [ber_str(oid, 0x80)]
    if value:
        p.append(ber_str(value, 0x81))
    return tlv(0x77, p)


UNBIND = bytes([0x42, 0x00])


def parse_result(buf, op):
    k = children(buf, op)
    return {'code': read_int(buf, k[0]), 'matchedDN': read_str(buf, k[1]), 'diagnostic': read_str(buf, k[2])}


def parse_entry(buf, op):
    k = children(buf, op)
    e = {'dn': read_str(buf, k[0]), 'attrs': {}, 'raw': {}}
    if len(k) > 1:
        for pa in children(buf, k[1]):
            pk = children(buf, pa)
            name = read_str(buf, pk[0]).lower()
            m = re.match(r'^([^;]+);range=', name)
            if m:
                name, e['ranged'] = m.group(1), True
            vals = [read_buf(buf, t) for t in children(buf, pk[1])] if len(pk) > 1 else []
            e['raw'][name] = e['raw'].get(name, []) + vals
            e['attrs'][name] = e['attrs'].get(name, []) + [v.decode('utf-8', 'replace') for v in vals]
    return e


def parse_message(buf):
    top = must_tlv(buf, 0)
    k = children(buf, top)
    if len(k) < 2 or k[0][0] != 0x02:
        raise LdapError('malformed LDAP message', transport=True)
    m = {'id': read_int(buf, k[0]), 'tag': k[1][0], 'op': k[1], 'buf': buf, 'controls': []}
    if len(k) > 2 and k[2][0] == 0xa0:
        for c in children(buf, k[2]):
            ck = children(buf, c)
            out = {'oid': read_str(buf, ck[0]), 'critical': False, 'value': None}
            for x in ck[1:]:
                if x[0] == 0x01:
                    out['critical'] = buf[x[1]] != 0
                if x[0] == 0x04:
                    out['value'] = read_buf(buf, x)
            m['controls'].append(out)
    return m


def result_error(op, r):
    name = RESULT.get(r['code'], 'resultCode %s' % r['code'])
    d = r.get('diagnostic') or ''
    return LdapError('%s failed: %s (%s)%s' % (op, name, r['code'], (' \u2014 ' + d[:200]) if d else ''), code=r['code'])


# ---- one connection (synchronous: a request, then its answers) ------------------------------------------------------
class Conn:
    def __init__(self, sock, server, opts, first_id=1):
        self.sock, self.server, self.opts = sock, server, opts
        self.next_id, self.buf, self.closed = first_id, b'', False

    def _fail(self, e):
        self.closed = True
        try:
            self.sock.close()
        except OSError:
            pass
        if isinstance(e, LdapError):
            e.transport = True
            raise e
        raise LdapError(str(e), transport=True)

    def _read_message(self):
        while True:
            t = read_tlv(self.buf, 0)
            if t is not None:
                msg, self.buf = self.buf[:t[2]], self.buf[t[2]:]
                return parse_message(msg)
            if len(self.buf) > (self.opts.get('maxMessageBytes') or 32 * 1048576):
                raise LdapError('LDAP message too large', transport=True)
            try:
                chunk = self.sock.recv(65536)
            except socket.timeout:
                raise LdapError('LDAP operation timed out after %s ms on %s' % (self.opts['timeoutMs'], self.server['url']), code='TIMEOUT', transport=True)
            except (OSError, ssl.SSLError) as e:
                raise LdapError(str(e), transport=True)
            if not chunk:
                raise LdapError('connection closed by %s' % self.server['url'], code='CLOSED', transport=True)
            self.buf += chunk

    def request(self, op, controls=None, max_entries=None):
        if self.closed:
            raise LdapError('connection is closed', code='CLOSED', transport=True)
        mid = self.next_id
        self.next_id += 1
        if self.next_id > 0x7fffffff:
            self.next_id = 1
        mx = max_entries or 500000
        entries, refs = [], []
        try:
            self.sock.settimeout(self.opts['timeoutMs'] / 1000.0)
            self.sock.sendall(message(mid, op, controls))
            while True:
                m = self._read_message()
                if m['id'] == 0:
                    raise LdapError('server sent a notice of disconnection', code='DISCONNECT', transport=True)
                if m['id'] != mid:
                    continue
                if m['tag'] == 0x64:
                    entries.append(parse_entry(m['buf'], m['op']))
                    if len(entries) > mx:
                        raise LdapError('search returned more than %d entries' % mx, code=4)   # a result error: the connection stays usable
                    continue
                if m['tag'] == 0x73:
                    refs.extend(read_str(m['buf'], t) for t in children(m['buf'], m['op']))
                    continue
                if m['tag'] in (0x61, 0x65, 0x78):
                    r = parse_result(m['buf'], m['op'])
                    r.update(controls=m['controls'], entries=entries, references=refs)
                    return r
                raise LdapError('unexpected LDAP response tag 0x%x' % m['tag'], transport=True)
        except LdapError as e:
            if e.transport:
                self._fail(e)
            raise
        except (OSError, ssl.SSLError) as e:
            self._fail(e)

    def extended(self, oid, value=None):
        return self.request(extended_request(oid, value))

    def bind(self, dn, password):
        if not isinstance(dn, str) or not dn.strip():
            raise LdapError('bind refused: empty DN', code='EMPTY_DN')
        if not isinstance(password, str) or len(password) == 0:
            raise LdapError('bind refused: empty password (unauthenticated bind)', code='EMPTY_PASSWORD')
        if re.match(r'^\s+$', password):
            raise LdapError('bind refused: blank password', code='EMPTY_PASSWORD')
        r = self.request(bind_request(dn, password))
        if r['code'] != 0:
            raise result_error('bind', r)
        return {'ok': True}

    def search(self, base, o):
        scope = o.get('scope') if isinstance(o.get('scope'), int) else SCOPE.get(str(o.get('scope') or 'sub').lower())
        if scope is None:
            raise LdapError('invalid scope %s' % o.get('scope'))
        flt = o['filter'] if isinstance(o.get('filter'), dict) else parse_filter(o.get('filter') or '(objectClass=*)')
        req = {'scope': scope, 'deref': o.get('deref') or 0, 'sizeLimit': o.get('sizeLimit') or 0, 'timeLimit': o.get('timeLimit') or 0,
               'filter': flt, 'attributes': o.get('attributes') or []}
        size = min(MAX_PAGE, max(1, int(o['pageSize']))) if o.get('pageSize') else 0
        mx = o.get('maxEntries') or 500000
        out = {'entries': [], 'references': [], 'pages': 0}
        cookie = b''
        while True:
            r = self.request(search_request(base, req), [paged_control(size, cookie)] if size else None, mx - len(out['entries']))
            out['pages'] += 1
            out['entries'] += r['entries']
            out['references'] += r['references']
            if r['code'] != 0:
                raise result_error('search', r)
            if not size:
                return out
            pc = next((c for c in r['controls'] if c['oid'] == PAGED), None)
            if not pc or not pc['value']:
                return out
            v = must_tlv(pc['value'], 0)
            k = children(pc['value'], v)
            nxt = read_buf(pc['value'], k[1]) if len(k) > 1 else b''
            if not nxt:
                return out
            cookie = nxt

    def close(self):
        if self.closed:
            return
        self.closed = True
        try:
            self.sock.sendall(message(self.next_id, UNBIND))
            self.next_id += 1
        except (OSError, ssl.SSLError):
            pass
        try:
            self.sock.close()
        except OSError:
            pass


# ---- client: server list, TLS, failover -----------------------------------------------------------------------------
_SERVER_RE = re.compile(r'^(ldaps?)://(\[[0-9a-fA-F:.]+\]|[A-Za-z0-9._-]+)(?::(\d{1,5}))?/?$')


def _is_ip(s):
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def parse_server(s):
    o = {'url': s} if isinstance(s, str) else dict(s or {})
    m = _SERVER_RE.match(str(o.get('url') or '').strip())
    if not m:
        raise LdapError('invalid LDAP server URL "%s" (use ldaps://dc.example.com:636 or ldap://dc.example.com:389 for StartTLS)' % o.get('url'))
    scheme, host = m.group(1).lower(), re.sub(r'^\[|\]$', '', m.group(2))
    if o.get('ip') and not _is_ip(str(o['ip'])):
        raise LdapError('invalid ip "%s" for %s' % (o['ip'], o.get('url')))
    port = int(m.group(3) or (636 if scheme == 'ldaps' else 389))
    return {'url': '%s://%s:%s' % (scheme, m.group(2), m.group(3) or (636 if scheme == 'ldaps' else 389)), 'scheme': scheme, 'host': host, 'port': port,
            'ip': str(o['ip']) if o.get('ip') else '', 'servername': str(o['servername']) if o.get('servername') else host}


class Client:
    def __init__(self, o):
        self.servers = [parse_server(s) for s in (o.get('servers') or [])]
        if not self.servers:
            raise LdapError('no LDAP servers configured')
        ca = o.get('ca')
        if not ca and o.get('caFile'):
            try:
                with open(o['caFile'], 'r', encoding='utf-8', errors='replace') as f:
                    ca = f.read()
            except OSError as e:
                raise LdapError('cannot read caFile %s: %s' % (o['caFile'], {2: 'ENOENT', 13: 'EACCES', 21: 'EISDIR'}.get(e.errno, e.errno)), code='CA_FILE')
        if not ca or '-----BEGIN CERTIFICATE-----' not in str(ca):
            raise LdapError('caFile must be a PEM (Base-64) certificate of the AD CS root CA', code='CA_FILE')
        self.ca = ca
        self.opts = {'timeoutMs': max(500, int(o.get('timeoutMs') or 10000)), 'maxMessageBytes': o.get('maxMessageBytes')}

    def _ctx(self):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.check_hostname, ctx.verify_mode = True, ssl.CERT_REQUIRED
        try:
            ctx.load_verify_locations(cadata=self.ca)
        except ssl.SSLError as e:
            raise LdapError('caFile must be a PEM (Base-64) certificate of the AD CS root CA (%s)' % e.reason, code='CA_FILE')
        return ctx

    def connect_to(self, s):
        timeout = self.opts['timeoutMs'] / 1000.0
        ctx = self._ctx()
        dial = s['ip'] or s['host']
        try:
            raw = socket.create_connection((dial, s['port']), timeout=timeout)
        except socket.timeout:
            raise LdapError('connect timeout after %d ms' % self.opts['timeoutMs'], code='TIMEOUT', transport=True)
        except OSError as e:
            raise LdapError('connect %s %s:%s' % (e.strerror or e, dial, s['port']), transport=True)
        first = 1
        try:
            if s['scheme'] == 'ldap':   # StartTLS, never cleartext
                plain = Conn(raw, s, self.opts, 1)
                r = plain.extended(STARTTLS)
                if r['code'] != 0:
                    raise result_error('StartTLS', r)
                first = plain.next_id
            ts = ctx.wrap_socket(raw, server_hostname=s['servername'])
        except ssl.SSLCertVerificationError as e:
            raw.close()
            raise LdapError('TLS certificate not trusted: %s' % (e.verify_message or e.reason), code=str(e.verify_code), transport=True)
        except ssl.SSLError as e:
            raw.close()
            raise LdapError('TLS failed: %s' % (e.reason or e), transport=True)
        except socket.timeout:
            raw.close()
            raise LdapError('connect timeout after %d ms' % self.opts['timeoutMs'], code='TIMEOUT', transport=True)
        except LdapError as e:
            raw.close()
            e.transport = True
            raise
        except OSError as e:
            raw.close()
            raise LdapError(str(e), transport=True)
        return Conn(ts, s, self.opts, first)

    def run(self, fn):
        errors = []
        for s in self.servers:
            try:
                conn = self.connect_to(s)
            except LdapError as e:
                errors.append('%s: %s' % (s['url'], e))
                continue
            try:
                return fn(conn)
            except LdapError as e:
                if not e.transport:
                    raise
                errors.append('%s: %s' % (s['url'], e))
            finally:
                conn.close()
        raise LdapError('no directory server reachable \u2014 ' + '; '.join(errors), code='UNAVAILABLE', transport=True)


# ---- Active Directory helpers ---------------------------------------------------------------------------------------
UAC_ACCOUNTDISABLE = 0x2
FILETIME_EPOCH_MS = 11644473600000


def file_time_to_ms(v):
    s = ('' if v is None else str(v)).strip()
    if not re.match(r'^\d+$', s) or s == '0' or s == '9223372036854775807':
        return 0
    ms = float(s) / 1e4 - FILETIME_EPOCH_MS   # Number(s) / 1e4: a double, as in Node.js
    return int(ms + 0.5) // 1 if ms > 0 else 0


def first_rdn_value(dn):
    m = re.match(r'^[^=]+=((?:\\.|[^,\\])*)', dn or '', re.S)
    if not m:
        return ''
    return re.sub(r'\\([0-9a-fA-F]{2}|.)', lambda x: chr(int(x.group(1), 16)) if len(x.group(1)) == 2 else x.group(1), m.group(1), flags=re.S)


def first(entry, name):
    v = (entry or {}).get('attrs', {}).get(str(name).lower())
    return v[0] if v else ''
