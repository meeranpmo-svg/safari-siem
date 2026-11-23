# Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
"""Read-only SNMP client (v1 / v2c / v3 USM) - the same protocol rules as engine/discovery/snmp-client.js (migration step
5c, docs/PYTHON-MIGRATION.md).

  BER codec, USM (RFC 3414 A.2 key derivation, SHA-1 / SHA-256 per RFC 7860, HMAC-SHA-96 / HMAC-SHA-256-192), AES-128-CFB
  privacy (RFC 3826: IV = engineBoots | engineTime | salt), engine discovery, notInTimeWindows / unknownEngineIDs retry.
  Session(host, port, version '1'|'2c'|'3', community, user, auth_protocol, auth_password, priv_protocol, priv_password,
          timeout_ms, retries, max_repetitions) -> get(oids), get_next(oids), get_bulk(oids, nr, mr), walk(root), table(entry)

SAFETY: only GetRequest, GetNextRequest and GetBulkRequest can be produced - there is NO SetRequest; encode_pdu() refuses
every PDU type outside ALLOWED_PDU and the message encoders re-check the PDU tag of the bytes they wrap.
Standard library, plus the `cryptography` package ONLY for SNMPv3 privacy (AES). Without it an authPriv session raises
NeedsCrypto and the Node.js reader answers instead; v1 / v2c / authNoPriv need nothing.
"""
import hashlib
import hmac
import os
import re
import socket
import time

TAG = {'INTEGER': 0x02, 'OCTET_STRING': 0x04, 'NULL': 0x05, 'OID': 0x06, 'SEQUENCE': 0x30, 'IP_ADDRESS': 0x40, 'COUNTER32': 0x41,
       'GAUGE32': 0x42, 'TIMETICKS': 0x43, 'OPAQUE': 0x44, 'COUNTER64': 0x46, 'NO_SUCH_OBJECT': 0x80, 'NO_SUCH_INSTANCE': 0x81, 'END_OF_MIB_VIEW': 0x82}
PDU = {'GET': 0xa0, 'GETNEXT': 0xa1, 'RESPONSE': 0xa2, 'GETBULK': 0xa5, 'REPORT': 0xa8}
ALLOWED_PDU = {0xa0, 0xa1, 0xa2, 0xa5, 0xa8}
ERROR_STATUS = ['noError', 'tooBig', 'noSuchName', 'badValue', 'readOnly', 'genErr', 'noAccess', 'wrongType', 'wrongLength', 'wrongEncoding',
                'wrongValue', 'noCreation', 'inconsistentValue', 'resourceUnavailable', 'commitFailed', 'undoFailed', 'authorizationError',
                'notWritable', 'inconsistentName']
USM_REPORTS = {'1.3.6.1.6.3.15.1.1.1.0': 'unsupportedSecLevels', '1.3.6.1.6.3.15.1.1.2.0': 'notInTimeWindows', '1.3.6.1.6.3.15.1.1.3.0': 'unknownUserNames',
               '1.3.6.1.6.3.15.1.1.4.0': 'unknownEngineIDs', '1.3.6.1.6.3.15.1.1.5.0': 'wrongDigests', '1.3.6.1.6.3.15.1.1.6.0': 'decryptionErrors'}
MAX_SAFE = 9007199254740991
EXCEPTIONS = ('NoSuchObject', 'NoSuchInstance', 'EndOfMibView')


class SnmpError(Exception):
    def __init__(self, code, message=None):
        super().__init__(message or code)
        self.code = code


class NeedsCrypto(Exception):
    pass


# ---- TLV ------------------------------------------------------------------------------------------------------------
def enc_len(n):
    if n < 0x80:
        return bytes([n])
    b = []
    while n > 0:
        b.insert(0, n & 0xff)
        n //= 256
    return bytes([0x80 | len(b)] + b)


def tlv(tag, value):
    return bytes([tag]) + enc_len(len(value)) + bytes(value)


def read_tlv(buf, pos):
    if pos + 2 > len(buf):
        raise SnmpError('ber', 'truncated TLV header')
    tag = buf[pos]
    if tag & 0x1f == 0x1f:
        raise SnmpError('ber', 'high-tag-number form not supported')
    ln, p = buf[pos + 1], pos + 2
    if ln & 0x80:
        n = ln & 0x7f
        if n == 0:
            raise SnmpError('ber', 'indefinite length not allowed')
        if n > 4:
            raise SnmpError('ber', 'length too large')
        if p + n > len(buf):
            raise SnmpError('ber', 'truncated length')
        ln = 0
        for i in range(n):
            ln = ln * 256 + buf[p + i]
        p += n
    if p + ln > len(buf):
        raise SnmpError('ber', 'truncated value')
    return {'tag': tag, 'hdr': pos, 'start': p, 'len': ln, 'end': p + ln}


def children(buf, t):
    out, p = [], t['start']
    while p < t['end']:
        c = read_tlv(buf, p)
        out.append(c)
        p = c['end']
    if p != t['end']:
        raise SnmpError('ber', 'constructed value overruns')
    return out


def body(buf, t):
    return bytes(buf[t['start']:t['end']])


def enc_int_body(v):
    n = int(v)
    out = []
    while True:
        b = n & 0xff
        out.insert(0, b)
        rest = n >> 8
        if (rest == 0 and not b & 0x80) or (rest == -1 and b & 0x80):
            break
        n = rest
    return bytes(out)


def dec_int(b):
    if not b:
        raise SnmpError('ber', 'empty INTEGER')
    n = int.from_bytes(b, 'big')
    if b[0] & 0x80:
        n -= 1 << (len(b) * 8)
    return n


def enc_int(v):
    return tlv(TAG['INTEGER'], enc_int_body(v))


def dec_unsigned(b, bits):
    n = dec_int(b)
    if n < 0:
        n += 1 << bits
    return n & ((1 << bits) - 1)


# ---- OIDs -----------------------------------------------------------------------------------------------------------
def parse_oid(oid):
    if isinstance(oid, list):
        arcs = list(oid)
    else:
        parts = re.sub(r'^\.', '', str(oid)).split('.')
        arcs = []
        for s in parts:
            try:
                arcs.append(int(s) if re.match(r'^\d+$', s) else None)
            except ValueError:
                arcs.append(None)
    if len(arcs) < 2 or any(a is None or a < 0 or a > 4294967295 for a in arcs) or arcs[0] > 2 or (arcs[0] < 2 and arcs[1] > 39):
        raise SnmpError('oid', 'invalid OID "%s"' % oid)
    return arcs


def _push_arc(out, v):
    tmp = [v % 128]
    v //= 128
    while v > 0:
        tmp.insert(0, (v % 128) | 0x80)
        v //= 128
    out.extend(tmp)


def enc_oid_body(oid):
    arcs = parse_oid(oid)
    out = []
    _push_arc(out, arcs[0] * 40 + arcs[1])
    for a in arcs[2:]:
        _push_arc(out, a)
    return bytes(out)


def dec_oid_body(b):
    if not b:
        raise SnmpError('ber', 'empty OID')
    arcs, v, in_arc = [], 0, False
    for x in b:
        v = v * 128 + (x & 0x7f)
        in_arc = bool(x & 0x80)
        if not in_arc:
            arcs.append(v)
            v = 0
        if v > 0xffffffff * 128:
            raise SnmpError('ber', 'OID arc too large')
    if in_arc:
        raise SnmpError('ber', 'truncated OID')
    first = arcs.pop(0)
    head = [0, first] if first < 40 else [1, first - 40] if first < 80 else [2, first - 80]
    return '.'.join(str(a) for a in head + arcs)


def oid_compare(a, b):
    x, y = parse_oid(a), parse_oid(b)
    for i in range(min(len(x), len(y))):
        if x[i] != y[i]:
            return -1 if x[i] < y[i] else 1
    return 0 if len(x) == len(y) else -1 if len(x) < len(y) else 1


def oid_starts_with(oid, root):
    return re.sub(r'^\.', '', str(oid)).startswith(re.sub(r'^\.', '', str(root)) + '.')


# ---- values ---------------------------------------------------------------------------------------------------------
def encode_value(val):
    typ = (val or {}).get('type') or 'Null'
    if typ == 'Null':
        return bytes([TAG['NULL'], 0])
    raise SnmpError('type', 'a read-only request only carries Null values')   # requests never carry data


def decode_value(tag, b):
    if tag == TAG['INTEGER']:
        return {'type': 'Integer', 'value': dec_int(b), 'big': not (-MAX_SAFE <= dec_int(b) <= MAX_SAFE)}
    if tag == TAG['OCTET_STRING']:
        return {'type': 'OctetString', 'value': bytes(b)}
    if tag == TAG['NULL']:
        return {'type': 'Null', 'value': None}
    if tag == TAG['OID']:
        return {'type': 'OID', 'value': dec_oid_body(b)}
    if tag == TAG['IP_ADDRESS']:
        if len(b) != 4:
            raise SnmpError('ber', 'bad IpAddress')
        return {'type': 'IpAddress', 'value': '.'.join(str(x) for x in b)}
    if tag in (TAG['COUNTER32'], TAG['GAUGE32'], TAG['TIMETICKS']):
        return {'type': {0x41: 'Counter32', 0x42: 'Gauge32', 0x43: 'TimeTicks'}[tag], 'value': dec_unsigned(b, 32)}
    if tag == TAG['COUNTER64']:
        return {'type': 'Counter64', 'value': dec_unsigned(b, 64), 'big': True}
    if tag == TAG['OPAQUE']:
        return {'type': 'Opaque', 'value': bytes(b)}
    if tag in (0x80, 0x81, 0x82):
        return {'type': {0x80: 'NoSuchObject', 0x81: 'NoSuchInstance', 0x82: 'EndOfMibView'}[tag], 'value': None}
    return {'type': 'Unknown', 'value': bytes(b), 'tag': tag}


def assert_allowed(t):
    if t not in ALLOWED_PDU:
        raise SnmpError('forbidden', 'PDU type 0x%x is not allowed: this SNMP code is read-only' % t)


def encode_pdu(pdu_type, request_id, error_status=0, error_index=0, oids=()):
    assert_allowed(pdu_type)
    vbs = b''.join(tlv(TAG['SEQUENCE'], tlv(TAG['OID'], enc_oid_body(o)) + encode_value(None)) for o in oids)
    return tlv(pdu_type, enc_int(request_id) + enc_int(error_status) + enc_int(error_index) + tlv(TAG['SEQUENCE'], vbs))


def decode_pdu(buf, t=None):
    t = t or read_tlv(buf, 0)
    k = children(buf, t)
    if len(k) < 4 or k[0]['tag'] != 2 or k[1]['tag'] != 2 or k[2]['tag'] != 2 or k[3]['tag'] != 0x30:
        raise SnmpError('ber', 'malformed PDU')
    vbs = []
    for vt in children(buf, k[3]):
        c = children(buf, vt)
        if len(c) < 2 or c[0]['tag'] != TAG['OID']:
            raise SnmpError('ber', 'malformed varbind')
        v = decode_value(c[1]['tag'], body(buf, c[1]))
        v['oid'] = dec_oid_body(body(buf, c[0]))
        vbs.append(v)
    return {'type': t['tag'], 'requestId': dec_int(body(buf, k[0])), 'errorStatus': dec_int(body(buf, k[1])), 'errorIndex': dec_int(body(buf, k[2])), 'varbinds': vbs}


def encode_community_message(version, community, pdu):
    if version not in (0, 1):
        raise SnmpError('version', 'community messages are v1 (0) or v2c (1)')
    assert_allowed(pdu[0])
    return tlv(TAG['SEQUENCE'], enc_int(version) + tlv(TAG['OCTET_STRING'], str(community).encode('utf-8')) + pdu)


# ---- USM ------------------------------------------------------------------------------------------------------------
AUTH = {'sha': {'name': 'sha', 'hash': 'sha1', 'macLen': 12}, 'sha256': {'name': 'sha256', 'hash': 'sha256', 'macLen': 24}}


def auth_proto(name):
    if not name:
        return None
    n = re.sub(r'[^a-z0-9]', '', str(name).lower())
    if n in ('sha', 'sha1', 'hmacsha96'):
        return AUTH['sha']
    if n in ('sha256', 'hmac192sha256', 'hmacsha256'):
        return AUTH['sha256']
    raise SnmpError('config', 'unsupported auth protocol "%s" (sha or sha256)' % name)


def priv_proto(name):
    if not name:
        return None
    n = re.sub(r'[^a-z0-9]', '', str(name).lower())
    if n in ('aes', 'aes128', 'aescfb128'):
        return 'aes128'
    raise SnmpError('config', 'unsupported privacy protocol "%s" (aes)' % name)


def password_to_key(password, hash_name):
    pw = str(password).encode('utf-8')
    if len(pw) < 8:
        raise SnmpError('config', 'SNMPv3 passphrases must be at least 8 characters')
    stream = (pw * (1048576 // len(pw) + 1))[:1048576]   # pw[i % len] for i in 0 … 1 MiB, as RFC 3414 A.2 hashes it
    return hashlib.new(hash_name, stream).digest()


def localize_key(ku, engine_id, hash_name):
    return hashlib.new(hash_name, ku + engine_id + ku).digest()


def _aes(key, boots, t, salt, data, decrypt):
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    except ImportError:
        raise NeedsCrypto('SNMPv3 privacy (AES) needs the Python "cryptography" package')
    iv = (boots & 0xffffffff).to_bytes(4, 'big') + (t & 0xffffffff).to_bytes(4, 'big') + salt[:8]
    c = Cipher(algorithms.AES(key[:16]), modes.CFB(iv))
    x = c.decryptor() if decrypt else c.encryptor()
    return x.update(data) + x.finalize()


def aes_encrypt(key, boots, t, salt, plain):
    return _aes(key, boots, t, salt, plain, False)


def aes_decrypt(key, boots, t, salt, data):
    if not salt or len(salt) != 8:
        raise SnmpError('decryptionError', 'privacy parameters must be 8 bytes')
    return _aes(key, boots, t, salt, data, True)


def encode_scoped_pdu(context_engine_id, context_name, pdu):
    assert_allowed(pdu[0])
    return tlv(TAG['SEQUENCE'], tlv(TAG['OCTET_STRING'], context_engine_id or b'') + tlv(TAG['OCTET_STRING'], (context_name or '').encode('utf-8')) + pdu)


def decode_scoped_pdu(buf):
    t = read_tlv(buf, 0)
    if t['tag'] != TAG['SEQUENCE']:
        raise SnmpError('decryptionError', 'scoped PDU is not a SEQUENCE (wrong privacy key?)')
    k = children(buf, t)
    if len(k) < 3 or k[0]['tag'] != 4 or k[1]['tag'] != 4:
        raise SnmpError('ber', 'malformed scoped PDU')
    return {'contextEngineId': body(buf, k[0]), 'pdu': decode_pdu(buf, k[2])}


def encode_v3_message(m):
    if m.get('scopedPdu'):
        sp = m['scopedPdu']
        inner = children(sp, read_tlv(sp, 0))
        assert_allowed(sp[inner[2]['hdr']])
    glob = tlv(TAG['SEQUENCE'], enc_int(m['msgId']) + enc_int(m.get('maxSize') or 65507) + tlv(TAG['OCTET_STRING'], bytes([m['flags'] & 0xff])) + enc_int(3))
    usm = tlv(TAG['SEQUENCE'], tlv(4, m.get('engineId') or b'') + enc_int(m.get('boots') or 0) + enc_int(m.get('time') or 0) + tlv(4, (m.get('user') or '').encode('utf-8'))
              + tlv(4, m.get('authParams') or b'') + tlv(4, m.get('privParams') or b''))
    data = tlv(4, m['encryptedPdu']) if m.get('encryptedPdu') else m.get('scopedPdu')
    if not data:
        raise SnmpError('ber', 'v3 message needs scopedPdu or encryptedPdu')
    return tlv(TAG['SEQUENCE'], enc_int(3) + glob + tlv(4, usm) + data)


def locate_auth_params(buf):
    parts = children(buf, read_tlv(buf, 0))
    f = children(buf, read_tlv(buf, parts[2]['start']))
    return f[4]


def hmac_of(proto, key, buf):
    return hmac.new(key, buf, proto['hash']).digest()[:proto['macLen']]


def sign_v3(buf, proto, key):
    loc = locate_auth_params(buf)
    if loc['len'] != proto['macLen']:
        raise SnmpError('ber', 'auth placeholder has the wrong length')
    out = bytearray(buf)
    out[loc['start']:loc['end']] = bytes(loc['len'])
    out[loc['start']:loc['end']] = hmac_of(proto, key, bytes(out))
    return bytes(out)


def verify_v3(buf, proto, key):
    loc = locate_auth_params(buf)
    if loc['len'] != proto['macLen']:
        return False
    got = bytes(buf[loc['start']:loc['end']])
    copy = bytearray(buf)
    copy[loc['start']:loc['end']] = bytes(loc['len'])
    return hmac.compare_digest(got, hmac_of(proto, key, bytes(copy)))


def decode_message(buf):
    outer = read_tlv(buf, 0)
    if outer['tag'] != TAG['SEQUENCE'] or outer['end'] != len(buf):
        raise SnmpError('ber', 'message is not a single SEQUENCE')
    parts = children(buf, outer)
    if not parts or parts[0]['tag'] != 2:
        raise SnmpError('ber', 'missing version')
    version = dec_int(body(buf, parts[0]))
    if version in (0, 1):
        if len(parts) < 3 or parts[1]['tag'] != 4:
            raise SnmpError('ber', 'malformed community message')
        return {'version': version, 'community': body(buf, parts[1]).decode('utf-8', 'replace'), 'pdu': decode_pdu(buf, parts[2])}
    if version != 3:
        raise SnmpError('version', 'unsupported SNMP version %s' % version)
    if len(parts) < 4 or parts[1]['tag'] != 0x30 or parts[2]['tag'] != 4:
        raise SnmpError('ber', 'malformed v3 message')
    g, s, d = parts[1], parts[2], parts[3]
    gf = children(buf, g)
    u = children(buf, read_tlv(buf, s['start']))
    if len(u) != 6:
        raise SnmpError('ber', 'malformed USM parameters')
    usm = {'engineId': body(buf, u[0]), 'boots': dec_int(body(buf, u[1])), 'time': dec_int(body(buf, u[2])), 'user': body(buf, u[3]).decode('utf-8', 'replace'),
           'authParams': body(buf, u[4]), 'privParams': body(buf, u[5])}
    fb = body(buf, gf[2])
    msg = {'version': 3, 'msgId': dec_int(body(buf, gf[0])), 'maxSize': dec_int(body(buf, gf[1])), 'flags': fb[0] if fb else 0, 'secModel': dec_int(body(buf, gf[3])), 'usm': usm}
    if d['tag'] == 4:
        msg['encryptedPdu'] = body(buf, d)
    else:
        msg['scopedPdu'] = bytes(buf[d['hdr']:d['end']])
    return msg


# ---- value helpers --------------------------------------------------------------------------------------------------
def is_exception(vb):
    return not vb or vb.get('type') in EXCEPTIONS


def vb_string(vb):
    if is_exception(vb) or vb.get('value') is None:
        return None
    v = vb['value']
    if isinstance(v, bytes):
        s = re.sub('\u0000+$', '', v.decode('utf-8', 'replace'))
        return re.sub('[\u0000-\u0008\u000b\u000c\u000e-\u001f]', ' ', s).strip()
    return str(v)


def vb_number(vb):
    if is_exception(vb):
        return None
    v = vb.get('value')
    if isinstance(v, bool) or not isinstance(v, int):
        return None
    if vb.get('big'):   # a BigInt in Node.js: a number only up to 2^53 - 1
        return v if v <= MAX_SAFE else None
    return v


# ---- session --------------------------------------------------------------------------------------------------------
class Session:
    def __init__(self, host, port=161, version='2c', community=None, user=None, auth_protocol=None, auth_password=None, priv_protocol=None,
                 priv_password=None, context='', timeout_ms=2000, retries=1, max_repetitions=20):
        self.host, self.port, self.version = host, int(port or 161), str(version or '2c')
        if self.version not in ('1', '2c', '3'):
            raise SnmpError('config', 'unsupported SNMP version %s' % self.version)
        self.timeout = (timeout_ms or 2000) / 1000.0
        self.retries = 1 if retries is None else int(retries)
        self.max_rep = max_repetitions or 20
        self.community = 'public' if community is None else str(community)
        self.v3 = None
        if self.version == '3':
            self.v3 = {'user': str(user or ''), 'auth': auth_proto(auth_protocol), 'priv': priv_proto(priv_protocol), 'authPassword': auth_password,
                       'privPassword': priv_password, 'context': context or ''}
            v = self.v3
            if not v['user']:
                raise SnmpError('config', 'SNMPv3 needs a user name')
            if v['priv'] and not v['auth']:
                raise SnmpError('config', 'SNMPv3 privacy requires authentication')
            if v['auth'] and not v['authPassword']:
                raise SnmpError('config', 'SNMPv3 auth passphrase missing')
            if v['priv'] and not v['privPassword']:
                raise SnmpError('config', 'SNMPv3 privacy passphrase missing')
        self.sock = None
        self.engine = None
        self.keys = None
        self.salt = int.from_bytes(os.urandom(8), 'big')
        self._id = int.from_bytes(os.urandom(4), 'big') & 0x3fffffff
        self.closed = False
        self._mk = {}

    def _next_id(self):
        self._id = (self._id + 1) & 0x7fffffff
        if self._id == 0:
            self._id = 1
        return self._id

    def _socket(self):
        if self.sock is None:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        return self.sock

    def _exchange(self, buf, key):
        if self.closed:
            raise SnmpError('closed', 'session closed')
        s = self._socket()
        for _ in range(self.retries + 1):
            try:
                s.sendto(buf, (self.host, self.port))
            except OSError as e:
                raise SnmpError('send', str(e))
            deadline = time.monotonic() + self.timeout
            while True:
                left = deadline - time.monotonic()
                if left <= 0:
                    break
                s.settimeout(left)
                try:
                    raw, addr = s.recvfrom(65535)
                except socket.timeout:
                    break
                except OSError:
                    continue   # e.g. ICMP port unreachable: the request times out, as in Node.js
                if addr[1] != self.port or (addr[0] != self.host and self.host != 'localhost'):
                    continue
                try:
                    m = decode_message(raw)
                except SnmpError:
                    continue   # a malformed datagram is ignored
                k = ('m%d' % m['msgId']) if m['version'] == 3 else ('r%d' % m['pdu']['requestId'])
                if k == key:
                    return raw, m
        raise SnmpError('timeout', 'no response from %s:%s' % (self.host, self.port))

    @staticmethod
    def _check(pdu, req_id):
        if pdu['requestId'] != req_id:
            raise SnmpError('mismatch', 'response request-id mismatch')
        if pdu['errorStatus']:
            es = pdu['errorStatus']
            name = ERROR_STATUS[es] if 0 <= es < len(ERROR_STATUS) else 'error%d' % es
            raise SnmpError(name, 'SNMP error %s (index %s)' % (ERROR_STATUS[es] if 0 <= es < len(ERROR_STATUS) else es, pdu['errorIndex']))
        return pdu['varbinds']

    def _req_community(self, typ, oids, a=0, b=0):
        rid = self._next_id()
        buf = encode_community_message(0 if self.version == '1' else 1, self.community, encode_pdu(typ, rid, a, b, oids))
        _, msg = self._exchange(buf, 'r%d' % rid)
        if msg['pdu']['type'] != PDU['RESPONSE']:
            raise SnmpError('unexpected', 'unexpected PDU type in response')
        return self._check(msg['pdu'], rid)

    def _master(self, password, h):
        k = (h, password)
        if k not in self._mk:
            self._mk[k] = password_to_key(password, h)
        return self._mk[k]

    def _engine_time(self):
        return self.engine['time'] + int((time.time() * 1000 - self.engine['at']) // 1000)

    def _set_engine(self, usm):
        self.engine = {'id': usm['engineId'], 'boots': usm['boots'], 'time': usm['time'], 'at': time.time() * 1000}
        hx = self.engine['id'].hex()
        if not self.keys or self.keys['engineHex'] != hx:
            self.keys = {'engineHex': hx, 'auth': None, 'priv': None}
            a = self.v3['auth']
            if a:
                self.keys['auth'] = localize_key(self._master(self.v3['authPassword'], a['hash']), self.engine['id'], a['hash'])
                if self.v3['priv']:
                    self.keys['priv'] = localize_key(self._master(self.v3['privPassword'], a['hash']), self.engine['id'], a['hash'])

    def discover_engine(self):
        if self.engine:
            return
        mid = self._next_id()
        pdu = encode_pdu(PDU['GET'], self._next_id(), 0, 0, [])
        buf = encode_v3_message({'msgId': mid, 'flags': 0x04, 'engineId': b'', 'boots': 0, 'time': 0, 'user': '', 'scopedPdu': encode_scoped_pdu(b'', '', pdu)})
        _, msg = self._exchange(buf, 'm%d' % mid)
        if msg['version'] != 3 or not msg['usm']['engineId']:
            raise SnmpError('discovery', 'engine discovery failed')
        self._set_engine(msg['usm'])

    def _open_v3(self, raw, msg):
        v = self.v3
        if msg['flags'] & 0x01:
            if not v['auth']:
                raise SnmpError('authenticationFailure', 'unexpected authenticated response')
            if msg['usm']['engineId'].hex() != self.keys['engineHex']:
                raise SnmpError('authenticationFailure', 'response from a different engine')
            if not verify_v3(raw, v['auth'], self.keys['auth']):
                raise SnmpError('authenticationFailure', 'response failed HMAC verification')
        scoped = msg.get('scopedPdu')
        if msg['flags'] & 0x02:
            if not v['priv'] or not msg.get('encryptedPdu'):
                raise SnmpError('decryptionError', 'unexpected encrypted response')
            scoped = aes_decrypt(self.keys['priv'], msg['usm']['boots'], msg['usm']['time'], msg['usm']['privParams'], msg['encryptedPdu'])
        if not scoped:
            raise SnmpError('ber', 'response without scoped PDU')
        return decode_scoped_pdu(scoped)['pdu']

    def _req_v3(self, typ, oids, a=0, b=0):
        self.discover_engine()
        v = self.v3
        for attempt in range(2):
            rid, mid = self._next_id(), self._next_id()
            scoped = encode_scoped_pdu(self.engine['id'], v['context'], encode_pdu(typ, rid, a, b, oids))
            boots, t = self.engine['boots'], self._engine_time()
            flags, priv_params, enc = 0x04, b'', None
            if v['auth']:
                flags |= 0x01
            if v['priv']:
                flags |= 0x02
                self.salt = (self.salt + 1) & 0xffffffffffffffff
                priv_params = self.salt.to_bytes(8, 'big')
                enc = aes_encrypt(self.keys['priv'], boots, t, priv_params, scoped)
            buf = encode_v3_message({'msgId': mid, 'flags': flags, 'engineId': self.engine['id'], 'boots': boots, 'time': t, 'user': v['user'],
                                     'authParams': bytes(v['auth']['macLen']) if v['auth'] else b'', 'privParams': priv_params,
                                     'scopedPdu': None if enc else scoped, 'encryptedPdu': enc})
            if v['auth']:
                buf = sign_v3(buf, v['auth'], self.keys['auth'])
            raw, msg = self._exchange(buf, 'm%d' % mid)
            rpdu = self._open_v3(raw, msg)
            if msg['flags'] & 0x01 and msg['usm']['boots'] >= self.engine['boots']:
                self.engine.update(boots=msg['usm']['boots'], time=msg['usm']['time'], at=time.time() * 1000)
            if rpdu['type'] == PDU['REPORT']:
                oid = rpdu['varbinds'][0]['oid'] if rpdu['varbinds'] else None
                what = USM_REPORTS.get(oid, 'report')
                if what == 'notInTimeWindows' and attempt == 0:
                    self.engine.update(boots=msg['usm']['boots'], time=msg['usm']['time'], at=time.time() * 1000)
                    continue
                if what == 'unknownEngineIDs' and attempt == 0:
                    self.engine = None
                    self.discover_engine()
                    continue
                raise SnmpError(what, 'SNMPv3 report: %s' % what)
            if rpdu['type'] != PDU['RESPONSE']:
                raise SnmpError('unexpected', 'unexpected PDU type in response')
            return self._check(rpdu, rid)
        raise SnmpError('notInTimeWindows', 'SNMPv3 time synchronisation failed')

    def request(self, typ, oids, a=0, b=0):
        oids = [re.sub(r'^\.', '', str(o)) for o in (oids if isinstance(oids, list) else [oids])]
        return self._req_v3(typ, oids, a, b) if self.version == '3' else self._req_community(typ, oids, a, b)

    def get(self, oids):
        return self.request(PDU['GET'], oids)

    def _walk_step(self, cur):
        try:
            return self.request(PDU['GETNEXT'], [cur])
        except SnmpError as e:
            if self.version == '1' and e.code == 'noSuchName':
                return [{'oid': cur, 'type': 'EndOfMibView', 'value': None}]
            raise

    def walk(self, root, max_rows=10000):
        base = re.sub(r'^\.', '', str(root))
        out, cur = [], base
        while True:
            vbs = self._walk_step(cur) if self.version == '1' else self.request(PDU['GETBULK'], [cur], 0, self.max_rep)
            if not vbs:
                break
            done = False
            for vb in vbs:
                if vb['type'] == 'EndOfMibView' or not oid_starts_with(vb['oid'], base):
                    done = True
                    break
                if oid_compare(vb['oid'], cur) <= 0:
                    raise SnmpError('loop', 'agent returned a non-increasing OID after %s' % cur)
                out.append(vb)
                cur = vb['oid']
                if len(out) >= max_rows:
                    done = True
                    break
            if done:
                break
        return out

    def table(self, entry, max_rows=10000):
        base = re.sub(r'^\.', '', str(entry))
        rows = {}
        for vb in self.walk(base, max_rows):
            rest = vb['oid'][len(base) + 1:].split('.')
            col = rest.pop(0)
            idx = '.'.join(rest)
            rows.setdefault(idx, {'index': idx, 'cols': {}})['cols'][int(col) if col.isdigit() else col] = vb
        return list(rows.values())

    def close(self):
        self.closed = True
        if self.sock:
            try:
                self.sock.close()
            except OSError:
                pass
            self.sock = None
