# Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
"""Read-only clients for storage arrays - the Python version of engine/storage-sources.js (same results, field for field).

collect(kind, cred, opts) -> {ok, platform, system: {name, model, version, serial, health},
   controllers: [{name, state, health, model, serial}], pools: [{name, owner, health, size_bytes, used_bytes, free_bytes}],
   volumes: [{name, container, state, size_bytes, used_bytes}], disks: {total, failed: [...], spares},
   events: [{at, severity, message}], ms}  |  {ok: False, error_class, error, presented?}
Only GET requests (the MSA session sign-in / sign-out are GETs too); guard() refuses anything else before a connection
is opened. Nothing on an array can be created, changed or deleted from here.
  NetApp ONTAP 9.6+ REST: GET /api/cluster, /cluster/nodes, /storage/aggregates, /storage/volumes, /storage/disks,
    /support/ems/events (optional), HTTP Basic with a read-only account (role "readonly", application http).
  HPE MSA 2060 / 2062 / 1060 / 2050 / 2052 / 2040 / 1040 / P2000 G3 (REST "api" interface): GET /api/login with HTTP Basic (newer firmware) or
    /api/login/<sha256("user_password")> (older), header "datatype: json", the session key in "sessionKey";
    GET /api/show/system, controllers, pools, disk-groups, disks, volumes, events/last/50; GET /api/exit at the end.
A value the array does not report stays None - never guessed. The JavaScript rounding and empty-value rules are kept on
purpose so both versions answer identically (tests/storage-python.test.js compares them).
"""
import base64
import hashlib
import math
import re
import time
import urllib.parse
from datetime import datetime, timezone

import httpc

CLASSES = ('auth', 'authz', 'timeout', 'unreachable', 'tls', 'config', 'protocol')
_MISSING = object()


class StorageError(Exception):
    def __init__(self, code, message, presented=None, http=None):
        super().__init__(message)
        self.code = code
        self.presented = presented
        self.http = http


def _cls(e):
    c = getattr(e, 'code', None)
    return c if c in CLASSES else 'protocol'


def _round(x):  # JavaScript Math.round: halves go up
    return math.floor(x + 0.5)


def _num(v=_MISSING):  # JavaScript Number(v) when finite, else None
    if v is _MISSING:
        return None
    if v is None:
        return 0
    if isinstance(v, bool):
        return 1 if v else 0
    if isinstance(v, (int, float)):
        return v if math.isfinite(v) else None
    s = str(v).strip()
    if s == '':
        return 0
    try:
        n = float(s)
    except ValueError:
        return None
    if not math.isfinite(n):
        return None
    return int(n) if n.is_integer() and 'e' not in s.lower() and '.' not in s else n


def _get(o, path):
    x = o
    for p in path.split('.'):
        if x is None:
            return None
        if isinstance(x, list):
            try:
                x = x[int(p)]
            except (ValueError, IndexError):
                return None
        elif isinstance(x, dict):
            x = x.get(p)
        else:
            return None
    return x


def _first(o, *keys):
    for k in keys:
        v = _get(o, k)
        if v is not None and v != '':
            return v
    return None


def _iso(v):
    if v is None or v == '':
        return None
    try:
        if isinstance(v, (int, float)) and not isinstance(v, bool):
            t = datetime.fromtimestamp(v / 1000.0, tz=timezone.utc)
        else:
            s = str(v).replace(' ', 'T', 1)
            if s.endswith('Z'):
                s = s[:-1] + '+00:00'
            d = datetime.fromisoformat(s)
            t = d.astimezone(timezone.utc) if d.tzinfo else d.astimezone().astimezone(timezone.utc)  # no zone = local time, like Date.parse
        if t.timestamp() <= 0:
            return None
        return t.strftime('%Y-%m-%dT%H:%M:%S.') + '%03dZ' % (t.microsecond // 1000)
    except (ValueError, OverflowError, OSError):
        return None


def _pct(u, s):
    if not s:
        return None
    return _round((u or 0) / s * 1000) / 10


# what to check on the array when it answers 401 (same text as engine/storage-sources.js)
AUTH_HINT = {
    'ontap': ' - on the cluster run "security login show -user-or-group-name <user>": it needs application http, authentication method password, role readonly, on the cluster (admin) SVM, not locked; reset with "security login password -username <user>" and enter the same password here',
    'msa': ' - the user needs the monitor role with the WBI/API interface enabled',
}
ALLOW = {
    'ontap': lambda m, p: m == 'GET' and re.match(r'^/api/(cluster|cluster/nodes|storage/aggregates|storage/volumes|storage/disks|support/ems/events)(\?|$)', p) is not None,
    'msa': lambda m, p: m == 'GET' and re.match(r'^/api/(login(/(?:[0-9a-f]{32}|[0-9a-f]{64}))?|exit|show/(system|controllers|pools|disk-groups|disks|volumes|events/last/\d{1,3}))$', p) is not None,
}


def guard(kind, method, path):
    if kind in ALLOW and ALLOW[kind](method, path):
        return
    raise StorageError('config', '%s storage reading is read-only; refusing %s %s' % (kind, method, path))


def base_of(url):
    b = re.sub(r'/+$', '', str(url or '').strip())
    # https; plain http only for a loopback test array (the HTTP client refuses anything else anyway)
    if not (re.match(r'^https://[A-Za-z0-9.-]+(:\d{1,5})?(/.*)?$', b) or re.match(r'^http://(127\.0\.0\.1|localhost)(:\d{1,5})?(/.*)?$', b)):
        raise StorageError('config', 'the address must be https://<host or IP>[:port]')
    u = urllib.parse.urlsplit(b)
    default = 443 if u.scheme == 'https' else 80
    return '%s://%s%s' % (u.scheme, u.hostname, ':%d' % u.port if u.port and u.port != default else '')


class _Client:
    def __init__(self, kind, cred, opts):
        t = cred.get('target') or {}
        self.kind, self.base, self.t, self.o = kind, base_of(t.get('base_url')), t, opts

    def call(self, path, headers=None):
        guard(self.kind, 'GET', path)
        h = {'Accept': 'application/json'}
        h.update(headers or {})
        short = path.split('?')[0]
        try:
            r = httpc.request(self.base + path, 'GET', h, ca_file=self.t.get('ca_file') or None, pin=self.t.get('tls_fingerprint') or None,
                              capture_untrusted=bool(self.o.get('captureUntrusted')), timeout_ms=self.o.get('timeoutMs') or 60000)
        except httpc.HttpcError as e:
            raise StorageError(e.code, str(e), presented=e.presented)
        if r['status'] == 401:
            raise StorageError('auth', '%s: the credentials were rejected (HTTP 401)%s' % (self.kind, AUTH_HINT.get(self.kind, '')))
        if r['status'] == 403:
            raise StorageError('authz', '%s: the account may not read %s (HTTP 403) - use a read-only / monitor account with API access' % (self.kind, short))
        if r['status'] < 200 or r['status'] >= 300:
            raise StorageError('protocol', '%s: GET %s answered HTTP %d' % (self.kind, short, r['status']), http=r['status'])
        if r['json'] is None:
            raise StorageError('protocol', '%s: %s did not answer JSON' % (self.kind, short))
        return r['json']


def _basic(u, p):
    return 'Basic ' + base64.b64encode(('%s:%s' % (u, p)).encode('utf-8')).decode('ascii')


def _fail(e, t0):
    return {'ok': False, 'error_class': _cls(e), 'error': str(e), 'presented': getattr(e, 'presented', None) or None, 'ms': int((time.time() - t0) * 1000)}


# ---------------------------------------------------------------- NetApp ONTAP --------------------------------------
def ontap(cred, opts=None):
    opts = opts or {}
    t0 = time.time()
    try:
        s = cred.get('secret') or {}
        if not s.get('username') or not s.get('password'):
            raise StorageError('config', 'ONTAP needs a user name and password (read-only role)')
        c = _Client('ontap', cred, opts)
        H = {'Authorization': _basic(s['username'], s['password'])}

        def recs(j):
            return j.get('records') if isinstance(j, dict) and isinstance(j.get('records'), list) else []
        cl = c.call('/api/cluster?fields=name,version,uuid', H)
        nodes = recs(c.call('/api/cluster/nodes?fields=name,model,serial_number,state,ha,uptime&max_records=100', H))
        aggr = recs(c.call('/api/storage/aggregates?fields=name,state,node.name,space.block_storage.size,space.block_storage.used,space.block_storage.available&max_records=1000', H))
        vols = recs(c.call('/api/storage/volumes?fields=name,svm.name,state,type,space.size,space.used,space.available,aggregates.name&max_records=10000', H))
        disks = []
        try:
            disks = recs(c.call('/api/storage/disks?fields=name,state,container_type,model,serial_number,node.name,bay,shelf.uid&max_records=10000', H))
        except StorageError as e:
            if e.code != 'authz' and e.http != 404:
                raise
        events = []
        try:
            events = recs(c.call('/api/support/ems/events?message.severity=emergency|alert|error&max_records=50&order_by=time%20desc&fields=time,log_message,message.severity,node.name', H))
        except StorageError as e:
            if e.code not in ('authz', 'protocol'):
                raise
        failed_states = re.compile(r'broken|failed|offline|unknown|removed', re.I)

        def pool(a):
            sz, us, av = _num(_first(a, 'space.block_storage.size')), _num(_first(a, 'space.block_storage.used')), _num(_first(a, 'space.block_storage.available'))
            st = a.get('state')
            return {'name': a.get('name'), 'owner': _first(a, 'node.name'), 'health': 'ok' if st == 'online' else ('degraded' if st else None), 'state': st or None,
                    'size_bytes': sz, 'used_bytes': us, 'free_bytes': av, 'used_pct': _pct(us, sz)}

        def vol(v):
            sz, us = _num(_first(v, 'space.size')), _num(_first(v, 'space.used'))
            return {'name': v.get('name'), 'container': _first(v, 'svm.name'), 'pool': _first(v, 'aggregates.0.name'), 'state': v.get('state') or None,
                    'type': v.get('type') or None, 'size_bytes': sz, 'used_bytes': us, 'used_pct': _pct(us, sz)}

        def failed(d):
            loc = [x for x in (_first(d, 'node.name'), ('bay %s' % d['bay']) if d.get('bay') is not None else '') if x]
            return {'name': d.get('name'), 'state': d.get('state') or d.get('container_type'), 'model': d.get('model') or None,
                    'serial': d.get('serial_number') or None, 'location': ' '.join(str(x) for x in loc)}
        n0 = nodes[0] if nodes else {}
        return {
            'ok': True, 'platform': 'ontap', 'ms': int((time.time() - t0) * 1000),
            'system': {'name': cl.get('name') or None, 'model': n0.get('model') or None, 'version': _first(cl, 'version.full', 'version.generation') or None,
                       'serial': n0.get('serial_number') or None, 'health': 'degraded' if any(n.get('state') and n.get('state') != 'up' for n in nodes) else 'ok'},
            'controllers': [{'name': n.get('name'), 'state': n.get('state') or None, 'health': None if not n.get('state') else ('ok' if n.get('state') == 'up' else 'degraded'),
                             'model': n.get('model') or None, 'serial': n.get('serial_number') or None, 'ha_partner': _first(n, 'ha.partners.0.name')} for n in nodes],
            'pools': [pool(a) for a in aggr],
            'volumes': [vol(v) for v in vols],
            'disks': {'total': len(disks), 'reported': len(disks) > 0, 'spares': len([d for d in disks if d.get('container_type') == 'spare']),
                      'failed': [failed(d) for d in disks if failed_states.search(d.get('state') or '') or d.get('container_type') == 'broken']},
            'events': [{'at': _iso(e.get('time')), 'severity': str(_first(e, 'message.severity') or '').lower(), 'message': str(e.get('log_message') or '')[:300],
                        'node': _first(e, 'node.name')} for e in events],
        }
    except Exception as e:  # every failure is a classified answer, never a crash
        return _fail(e, t0)


# ---------------------------------------------------------------- HPE MSA ------------------------------------------
BLOCK = 512


def _msa_health(v):
    s = ('' if v is None else str(v)).lower()
    if not s:
        return None
    if re.search(r'^(ok|0)$', s):
        return 'ok'
    if re.search(r'degrad|^1$', s):
        return 'degraded'
    if re.search(r'fault|^2$', s):
        return 'fault'
    return 'unknown'


def _msa_bytes(o, num_key, txt_key):
    n = _num(o[num_key]) if num_key in o else None
    if n is not None:
        return n * BLOCK
    m = re.match(r'^([\d.]+)\s*([KMGTP]?B)$', str(o.get(txt_key) or '').strip(), re.I)
    if not m:
        return None
    mult = {'B': 1, 'KB': 1e3, 'MB': 1e6, 'GB': 1e9, 'TB': 1e12, 'PB': 1e15}[m.group(2).upper()]
    return _round(float(m.group(1)) * mult)


def _list(j, *keys):
    for k in keys:
        if isinstance(j, dict) and isinstance(j.get(k), list):
            return j[k]
    return []


def _or(*vals):  # JavaScript a || b || c
    for v in vals:
        if v:
            return v
    return vals[-1] if vals else None


def msa(cred, opts=None):
    opts = opts or {}
    t0 = time.time()
    c, key = None, None
    try:
        s = cred.get('secret') or {}
        if not s.get('username') or not s.get('password'):
            raise StorageError('config', 'MSA needs a user name and password (monitor role)')
        c = _Client('msa', cred, opts)
        D = {'datatype': 'json'}

        def ok(j):
            st = (_list(j, 'status') or [{}])[0] or {}
            return st.get('response') if _num(st.get('return-code', _MISSING) if 'return-code' in st else _MISSING) == 1 else None
        try:
            key = ok(c.call('/api/login', dict({'Authorization': _basic(s['username'], s['password'])}, **D)))
        except StorageError as e:
            if e.code in ('tls', 'config'):
                raise
        # older firmware: SHA-256 of "user_password" (MSA 2050 / 2052), then MD5 (MSA 2040 / 1040 / P2000 G3)
        for alg in (hashlib.sha256, hashlib.md5):
            if key:
                break
            try:
                key = ok(c.call('/api/login/' + alg(('%s_%s' % (s['username'], s['password'])).encode('utf-8')).hexdigest(), D))
            except StorageError as e:
                if e.code not in ('auth', 'protocol'):
                    raise
        if not key:
            raise StorageError('auth', 'MSA: sign-in refused (wrong user / password, or the user has no API access)')
        H = dict({'sessionKey': key}, **D)
        sys_ = (_list(c.call('/api/show/system', H), 'system') or [{}])[0] or {}
        ctl = _list(c.call('/api/show/controllers', H), 'controllers')
        pools = _list(c.call('/api/show/pools', H), 'pools')
        if not pools:  # linear storage
            pools = _list(c.call('/api/show/disk-groups', H), 'disk-groups')
        drv = _list(c.call('/api/show/disks', H), 'drives', 'disks')
        vols = _list(c.call('/api/show/volumes', H), 'volumes')
        ev = []
        try:
            ev = _list(c.call('/api/show/events/last/50', H), 'events')
        except StorageError as e:
            if e.code != 'protocol':
                raise

        def pool(p):
            sz = _msa_bytes(p, 'total-size-numeric', 'total-size') or _msa_bytes(p, 'size-numeric', 'size')
            fr = _msa_bytes(p, 'total-avail-numeric', 'total-avail') or _msa_bytes(p, 'freespace-numeric', 'freespace')
            us = sz - fr if sz is not None and fr is not None else None
            return {'name': p.get('name') or None, 'owner': _or(p.get('owner'), p.get('preferred-owner'), None), 'health': _msa_health(_or(p.get('health'), p.get('health-numeric'))),
                    'state': p.get('status') or None, 'size_bytes': sz, 'used_bytes': us, 'free_bytes': fr, 'used_pct': _pct(us, sz)}

        def vol(v):
            sz, us = _msa_bytes(v, 'size-numeric', 'size'), _msa_bytes(v, 'allocated-size-numeric', 'allocated-size')
            return {'name': _or(v.get('volume-name'), v.get('name'), None), 'container': _or(v.get('storage-pool-name'), v.get('virtual-disk-name'), None),
                    'pool': v.get('storage-pool-name') or None, 'state': 'online' if _msa_health(_or(v.get('health'), v.get('health-numeric'))) == 'ok' else (v.get('health') or None),
                    'type': v.get('volume-type') or None, 'size_bytes': sz, 'used_bytes': us, 'used_pct': _pct(us, sz)}
        c0 = ctl[0] if ctl else {}
        return {
            'ok': True, 'platform': 'msa', 'ms': int((time.time() - t0) * 1000),
            'system': {'name': sys_.get('system-name') or None, 'model': _or(sys_.get('product-id'), sys_.get('product-brand'), None),
                       'version': _or(c0.get('sc-fw'), c0.get('bundle-version'), None) if ctl else None,
                       'serial': sys_.get('midplane-serial-number') or None, 'health': _msa_health(_or(sys_.get('health'), sys_.get('health-numeric')))},
            'controllers': [{'name': ('Controller ' + x['controller-id']) if x.get('controller-id') else (x.get('durable-id') or None), 'state': x.get('status') or None,
                             'health': _msa_health(_or(x.get('health'), x.get('health-numeric'))), 'model': x.get('model') or None, 'serial': x.get('serial-number') or None} for x in ctl],
            'pools': [pool(p) for p in pools],
            'volumes': [vol(v) for v in vols],
            'disks': {'total': len(drv), 'reported': len(drv) > 0, 'spares': len([d for d in drv if re.search('spare', d.get('usage') or '', re.I)]),
                      'failed': [{'name': _or(d.get('location'), d.get('durable-id'), None), 'state': _or(d.get('usage'), d.get('health'), None), 'model': d.get('model') or None,
                                  'serial': d.get('serial-number') or None, 'location': d.get('location') or None}
                                 for d in drv if re.search(r'fault|degrad', str(d.get('health') or ''), re.I) or re.search(r'fail|leftover', str(d.get('usage') or ''), re.I)]},
            'events': [{'at': _iso(e.get('time-stamp')), 'severity': str(e.get('severity') or '').lower(), 'message': str(e.get('message') or '')[:300], 'node': e.get('controller') or None}
                       for e in ev if re.search(r'error|critical|warning', e.get('severity') or '', re.I)],
        }
    except Exception as e:
        return _fail(e, t0)
    finally:
        if c is not None and key:
            try:
                c.call('/api/exit', {'sessionKey': key, 'datatype': 'json'})
            except Exception:
                pass


def test(kind, cred, opts=None):
    fn = {'ontap': ontap, 'msa': msa}.get(kind)
    if not fn:
        return {'ok': False, 'error_class': 'config', 'error': 'unknown storage platform'}
    r = fn(cred, dict(opts or {}, captureUntrusted=True))
    if not r.get('ok'):
        return r
    y = r['system']
    return {'ok': True, 'message': 'Connected: %s - %d pool(s), %d volume(s), %d disk(s).' % (y.get('name') or y.get('model') or 'array', len(r['pools']), len(r['volumes']), r['disks']['total'])}
