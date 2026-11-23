# Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
"""Assets - the human WRITES, migration step 9d (docs/PYTHON-MIGRATION.md): add (manual / barcode), edit, the lifecycle
transitions (retire, dispose, repair, restock, activate, lost, found), move and assign, decided here exactly like
engine/assets.js with the normalisation of engine/model/asset.js. The store keeps ONE writer, so nothing is written here:
each operation reads the asset (store.reader) and answers the record to write ({puts}), the audit entry and the route's
answer - or a refusal ({refuse: {status, error}}) worded as Node.js words it - plus based_on, the SHA-256 of the record
it decided on, so Node.js commits only a decision made on the record it holds now. Node.js supplies the new id and the
time. A value whose JavaScript reading is not reproduced exactly here (a date that is not plain ISO, which Date.parse
reads by rules of its own; a record missing a field Node.js would carry as undefined) answers {node: true}: Node.js
decides that one itself. Source upserts (discovery / agent merge) stay in Node.js for now.
Standard library only (Python 3.8+).
"""
import calendar
import copy
import re
from datetime import datetime, timedelta, timezone

from jscompat import MISSING, truthy
from roles_write import JS_WS, _utf16
from store import _js_number, reader as store_reader, sha256, stringify

TYPES = ['server', 'vm', 'workstation', 'laptop', 'network', 'printer', 'phone', 'storage', 'ups', 'mobile', 'peripheral', 'software', 'licence', 'other']
STATUSES = ['in_use', 'in_stock', 'in_repair', 'retired', 'lost', 'disposed']
SOURCES = ['sensor', 'agent', 'vcenter', 'manual', 'import', 'discovery']
TYPE_ALIASES = {
    'pc': 'workstation', 'desktop': 'workstation', 'notebook': 'laptop', 'macbook': 'laptop',
    'switch': 'network', 'router': 'network', 'ap': 'network', 'access point': 'network', 'firewall': 'network', 'gateway': 'network',
    'ip phone': 'phone', 'voip': 'phone', 'nas': 'storage', 'san': 'storage', 'virtual machine': 'vm',
    'smartphone': 'mobile', 'tablet': 'mobile', 'mfp': 'printer', 'scanner': 'peripheral', 'monitor': 'peripheral',
}
MERGE_FIELDS = ['asset_tag', 'name', 'type', 'site', 'location', 'owner', 'custodian', 'department',
                'vendor', 'model', 'serial', 'mgmt_ip', 'mac', 'os', 'cpu', 'mem_gb', 'disk_gb', 'warranty', 'support', 'purchase', 'eol', 'notes', 'classification', 'cia']
LIFECYCLE_ACTIONS = {'retire': 'retired', 'dispose': 'disposed', 'repair': 'in_repair', 'restock': 'in_stock', 'activate': 'in_use', 'lost': 'lost', 'found': 'in_use'}


class NodeDecides(Exception):
    pass


class Refuse(Exception):
    def __init__(self, status, error):
        super().__init__(error)
        self.status, self.error = status, error


# ---- JavaScript conversions -----------------------------------------------------------------------------------------
def _to_str(v):
    """String(v) for JSON values (Array.prototype.toString included)"""
    if v is None:
        return 'null'
    if isinstance(v, bool):
        return 'true' if v else 'false'
    if isinstance(v, (int, float)):
        return _js_number(v)
    if isinstance(v, list):
        return ','.join('' if x is None else _to_str(x) for x in v)
    if isinstance(v, dict):
        return '[object Object]'
    return v


def _trim(t):
    return t.strip(JS_WS)


def is_obj(v):
    return isinstance(v, dict)


def s(v, mx=2000):
    """s() of model/asset.js: strings, numbers and booleans only, trimmed, at most mx UTF-16 units"""
    if v is None or v is MISSING:
        return ''
    t = v if isinstance(v, str) else _to_str(v) if isinstance(v, (bool, int, float)) else ''
    return _utf16(_trim(t), mx)


_DEC = re.compile(r'^[+-]?(?:[0-9]+\.?[0-9]*|\.[0-9]+)(?:[eE][+-]?[0-9]+)?$')
_RADIX = re.compile(r'^0(?:([xX])([0-9a-fA-F]+)|([oO])([0-7]+)|([bB])([01]+))$')


def _str_to_num(t):
    t = _trim(t)
    if t == '':
        return 0
    m = _RADIX.match(t)
    if m:
        digits, base = (m.group(2), 16) if m.group(1) else (m.group(4), 8) if m.group(3) else (m.group(6), 2)
        return float(int(digits, base))
    if _DEC.match(t):
        return float(t)
    return None   # NaN, and +-Infinity (not finite either way)


def num(v):
    """num() of model/asset.js: Number(v) when finite, else null (Number(undefined) is NaN: a missing field is null, not 0)"""
    if v is MISSING:
        return None
    if v is None:
        return 0
    if isinstance(v, bool):
        return 1 if v else 0
    if isinstance(v, int):
        return v
    if isinstance(v, float):
        return v if v == v and v not in (float('inf'), float('-inf')) else None
    if isinstance(v, str):
        n = _str_to_num(v)
    elif isinstance(v, list):
        n = _str_to_num(_to_str(v))
    else:
        return None
    if n is None or n in (float('inf'), float('-inf')):
        return None
    return n


def _lower(t):
    return t.lower()


def enum_of(v, allowed, aliases=None):
    k = _lower(s(v))
    if k in ('constructor', '__proto__'):
        raise NodeDecides()   # aliases[k] is Object.prototype's own property in JavaScript
    if aliases and k in aliases:
        return aliases[k]
    return k if k in allowed else None


_ISO_DAY = re.compile(r'^[0-9]{4}-[0-9]{2}-[0-9]{2}')
_ISO_FULL = re.compile(r'^([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2})(?::([0-9]{2})(?:\.([0-9]{1,3}))?)?(Z|[+-][0-9]{2}:[0-9]{2})$')


def _iso(y, mo, d, h=0, mi=0, sec=0, ms=0, off=0):
    """new Date(Date.parse(...)).toISOString() for a VALID calendar date; anything V8 reads by its own rules -> Node.js"""
    if not (1 <= y <= 9999 and 1 <= mo <= 12 and 1 <= d <= calendar.monthrange(y, mo)[1] and h <= 23 and mi <= 59 and sec <= 59):
        raise NodeDecides()
    t = datetime(y, mo, d, h, mi, sec, ms * 1000, tzinfo=timezone.utc) - timedelta(minutes=off)
    if not 1 <= t.year <= 9999:
        raise NodeDecides()
    return t.strftime('%Y-%m-%dT%H:%M:%S.') + '%03dZ' % (t.microsecond // 1000)


def date_iso(v):
    t = s(v, 40)
    if not t:
        return None
    if not _ISO_DAY.match(t):
        raise NodeDecides()   # Date.parse's own (implementation-defined) formats
    if len(t) <= 10:
        return _iso(int(t[0:4]), int(t[5:7]), int(t[8:10]))
    m = _ISO_FULL.match(t)
    if not m:
        raise NodeDecides()   # no zone = local time, odd separators, more decimals ... Node.js reads those
    off = 0
    if m.group(8) != 'Z':
        oh, om = int(m.group(8)[1:3]), int(m.group(8)[4:6])
        if oh > 23 or om > 59:
            raise NodeDecides()
        off = (oh * 60 + om) * (1 if m.group(8)[0] == '+' else -1)
    frac = m.group(7) or ''
    ms = int((frac + '00')[:3]) if frac else 0
    return _iso(int(m.group(1)), int(m.group(2)), int(m.group(3)), int(m.group(4)), int(m.group(5)), int(m.group(6) or 0), ms, off)


_NOT_HEX = re.compile(r'[^0-9a-f]')
_IPV4 = re.compile(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$')


def norm_mac(v):
    t = _NOT_HEX.sub('', _lower(s(v, 40)))
    if len(t) != 12:
        return _lower(s(v, 40)) if s(v, 40) else None
    return ':'.join(t[i:i + 2] for i in range(0, 12, 2))


def norm_ip(v):
    t = s(v, 60)
    return t or None   # a valid dotted quad and anything else are both kept as given (model/asset.js)


def tag_list(v):
    a = v if isinstance(v, list) else [] if (v is None or v is MISSING or v == '') else [v]
    out = []
    for t in a:
        x = s(t, 60)
        if x and x not in out:
            out.append(x)
        if len(out) >= 50:
            break
    return out


def norm_warranty(w):
    if not is_obj(w):
        return None
    start, end, provider = date_iso(w.get('start')), date_iso(w.get('end')), s(w.get('provider'), 200)
    if not start and not end and not provider:
        return None
    return {'start': start, 'end': end, 'provider': provider or None}


def norm_support(v):
    if not is_obj(v):
        return None
    provider, contract, level = s(v.get('provider'), 200), s(v.get('contract'), 120), s(v.get('level'), 120)
    end, start = date_iso(v.get('end')), date_iso(v.get('start'))
    if not provider and not contract and not level and not end:
        return None
    return {'provider': provider or None, 'contract': contract or None, 'level': level or None, 'start': start, 'end': end, 'verified': v.get('verified') is True}


def norm_purchase(p):
    if not is_obj(p):
        return None
    date, cost, po, supplier = date_iso(p.get('date')), num(p.get('cost', MISSING)), s(p.get('po'), 100), s(p.get('supplier'), 200)
    if not date and cost is None and not po and not supplier:
        return None
    return {'date': date, 'cost': cost, 'po': po or None, 'supplier': supplier or None}


def normalise_fields(raw):
    o = raw if is_obj(raw) else {}
    W, f = [], {}
    if 'asset_tag' in o:
        f['asset_tag'] = s(o['asset_tag'], 120) or None
    if 'name' in o:
        f['name'] = s(o['name'], 300) or None
    if 'type' in o:
        t = enum_of(o['type'], TYPES, TYPE_ALIASES)
        if t:
            f['type'] = t
        elif s(o['type']):
            f['type'] = 'other'
            W.append('type "%s" not recognised — set to other' % s(o['type'], 40))
    if 'status' in o:
        st = enum_of(o['status'], STATUSES)
        if st:
            f['status'] = st
        elif s(o['status']):
            W.append('status "%s" invalid — ignored' % s(o['status'], 40))
    if 'site' in o:
        f['site'] = s(o['site'], 200) or None
    if 'location' in o and is_obj(o['location']):
        L = o['location']
        f['location'] = {'building': s(L.get('building'), 200) or None, 'room': s(L.get('room'), 120) or None, 'rack': s(L.get('rack'), 120) or None}
    for k in ['owner', 'custodian', 'department', 'vendor', 'model', 'serial', 'os', 'cpu', 'notes']:
        if k in o:
            f[k] = s(o[k], 8000 if k == 'notes' else 300) or None
    if 'mem_gb' in o:
        f['mem_gb'] = num(o['mem_gb'])
    if 'disk_gb' in o:
        f['disk_gb'] = num(o['disk_gb'])
    if 'mgmt_ip' in o:
        f['mgmt_ip'] = norm_ip(o['mgmt_ip'])
    if 'mac' in o:
        f['mac'] = norm_mac(o['mac'])
    if 'warranty' in o:
        f['warranty'] = norm_warranty(o['warranty'])
    if 'purchase' in o:
        f['purchase'] = norm_purchase(o['purchase'])
    if 'support' in o:
        f['support'] = norm_support(o['support'])
    if 'eol' in o:
        f['eol'] = date_iso(o['eol'])
    if 'networked' in o:
        f['networked'] = truthy(o['networked'])
    if 'no_network_source' in o:
        f['no_network_source'] = truthy(o['no_network_source'])
    if 'tags' in o:
        f['tags'] = tag_list(o['tags'])
    if 'classification' in o:
        c = norm_classification(o['classification'])
        if c is not MISSING:
            f['classification'] = c
        else:
            W.append('classification "%s" invalid — use top_secret, secret, restricted or public' % s(o['classification'], 40))
    if 'cia' in o:
        f['cia'] = norm_cia(o['cia'])
    return f, W


CLASSIFICATIONS = ['top_secret', 'secret', 'restricted', 'public']
CIA_LEVELS = ['high', 'medium', 'low']


def norm_classification(v):
    if v is None or v == '':
        return None
    t = re.sub(r'[\s-]+', '_', _to_str(v).strip().lower())
    return t if t in CLASSIFICATIONS else MISSING


def norm_cia(v):
    if not is_obj(v):
        return None

    def one(x):
        t = ('' if x is None else _to_str(x)).strip().lower()
        return t if t in CIA_LEVELS else None
    o = {'c': one(v.get('c')), 'i': one(v.get('i')), 'a': one(v.get('a'))}
    return o if (o['c'] or o['i'] or o['a']) else None


def _lc(v):
    return _lower(_trim('' if v is None else _to_str(v)))


def identity_keys(f):
    out = []

    def add(k, w):
        if k and not any(x['k'] == k for x in out):
            out.append({'k': k, 'w': w})
    if truthy(f.get('uuid')):
        add('uuid:' + _lc(f['uuid']), 95)
    if truthy(f.get('serial')) and len(_lc(f['serial'])) >= 3:
        add('serial:' + _lc(f['serial']), 100)
    if truthy(f.get('asset_tag')):
        add('tag:' + _lc(f['asset_tag']), 90)
    if truthy(f.get('mac')) and len(_NOT_HEX.sub('', _lc(f['mac']))) == 12:
        add('mac:' + _NOT_HEX.sub('', _lc(f['mac'])), 70)
    if truthy(f.get('mgmt_ip')) and truthy(f.get('name')):
        add('ipn:%s|%s' % (_lc(f['mgmt_ip']), _lc(f['name'])), 60)
    if truthy(f.get('name')):
        add('name:' + _lc(f['name']), 30)
    return out


def norm_software(raw):
    o = raw if is_obj(raw) else {'name': raw}
    name = s(o.get('name'), 300)
    if not name:
        return None
    return {'name': name, 'publisher': s(o.get('publisher'), 200) or None, 'version': s(o.get('version'), 80) or None,
            'install_date': date_iso(o.get('install_date')), 'licence_id': s(o.get('licence_id'), 80) or None}


def blank_asset():
    return {
        'id': None, 'asset_tag': None, 'type': 'other', 'name': None, 'status': 'in_use', 'source': 'manual', 'sources': [],
        'site': None, 'location': None, 'owner': None, 'custodian': None, 'department': None,
        'vendor': None, 'model': None, 'serial': None, 'mgmt_ip': None, 'mac': None, 'os': None, 'cpu': None, 'mem_gb': None, 'disk_gb': None,
        'warranty': None, 'support': None, 'purchase': None, 'eol': None, 'classification': None, 'cia': None,
        'first_seen': None, 'last_seen': None, 'networked': False, 'no_network_source': False,
        'tags': [], 'software': [], 'lifecycle': [], 'notes': None, 'created_at': None, 'updated_at': None,
    }


def public(a):
    return {k: v for k, v in a.items() if k not in ('prov', 'locked')}


# ---- the decisions --------------------------------------------------------------------------------------------------
def _who(r):
    w = r.get('who')
    if not isinstance(w, dict) or 'user' not in w or 'role' not in w:
        raise NodeDecides()   # an audit entry with by / role undefined: Node.js writes that one
    return w


def _audit(who, action, target, detail, by_default=None):
    """the entry engine/assets.js hands to audit()"""
    by = who['user']
    if by_default is not None and not truthy(by):
        by = by_default
    return {'by': by, 'role': who['role'], 'action': action, 'target': target, 'detail': detail}


def _event(a, ev, who, at, detail):
    lc = a.get('lifecycle')
    lc = lc if isinstance(lc, list) else []
    by = who.get('user')
    lc.append({'event': ev, 'at': at, 'by': by if truthy(by) else 'system', 'detail': detail})
    a['lifecycle'] = lc[-1000:] if len(lc) > 1000 else lc


def _networked(a):
    if truthy(a.get('mgmt_ip')) or truthy(a.get('mac')):
        return True
    if 'networked' not in a:
        raise NodeDecides()   # Node.js would hold networked: undefined
    return a['networked']


def _ensure(a, k):
    if not truthy(a.get(k)):
        a[k] = {}
    return a[k]


def _load(r, needs=()):
    """the asset as the store holds it now, and the hash of exactly that JSON (based_on)"""
    a = store_reader(r['dir']).collection('assets').get(str(r.get('id')))
    r['_based'] = sha256(stringify(a))
    if a is None:
        raise Refuse(404, 'asset not found')
    for k in needs:
        if k not in a:
            raise NodeDecides()   # Node.js would carry undefined into the record / audit
    return copy.deepcopy(a)   # the resident service's cache holds this record: never change it in place


def create(r):
    body = r.get('body')
    if not is_obj(body):
        raise NodeDecides()
    who, at = _who(r), r.get('at')
    source = r.get('source') if r.get('source') in SOURCES else 'manual'
    fields, warnings = normalise_fields(body)
    a = blank_asset()
    a['id'] = r.get('new_id')
    a['source'] = source
    a['created_at'] = at
    a['updated_at'] = at
    a['prov'] = {}
    a['locked'] = {}
    a.update(fields)
    if not truthy(a.get('type')):
        a['type'] = 'other'
    if not truthy(a.get('status')):
        a['status'] = 'in_use'
    if source == 'manual' and not truthy(a.get('mgmt_ip')) and not truthy(a.get('mac')) and body.get('no_network_source', MISSING) is not False:
        a['no_network_source'] = True
    a['networked'] = True if (truthy(a.get('mgmt_ip')) or truthy(a.get('mac'))) else a['networked']
    keys = [x['k'] for x in identity_keys(fields)]
    a['sources'] = [{'source': source, 'source_id': s(body.get('source_id'), 120) or None, 'first_seen': at, 'last_seen': at, 'keys': keys, 'detail': None}]
    a['first_seen'] = at
    a['last_seen'] = at
    for k in MERGE_FIELDS:
        if k in fields and fields[k] is not None:
            a['prov'][k] = source
            if source == 'manual':
                a['locked'][k] = True
    if isinstance(body.get('software'), list):
        a['software'] = [x for x in (norm_software(e) for e in body['software']) if x is not None][:5000]
    _event(a, 'created', who, at, {'source': source})
    audit = _audit(who, 'asset.create', a['id'], {'source': source, 'asset_tag': a['asset_tag'], 'type': a['type'], 'name': a['name'], 'warnings': warnings}, by_default='system')
    return {'puts': [{'c': 'assets', 'o': a}], 'audit': audit, 'result': {'asset': public(a), 'warnings': warnings}}


def edit(r):
    a = _load(r)
    who, at = _who(r), r.get('at')
    fields, warnings = normalise_fields(r.get('body'))
    _ensure(a, 'prov')
    _ensure(a, 'locked')
    changed = []
    for k in MERGE_FIELDS:
        if k not in fields:
            continue
        if k not in a or stringify(a[k]) != stringify(fields[k]):
            a[k] = fields[k]
            changed.append(k)
        a['prov'][k] = 'manual'
        a['locked'][k] = True
    if 'tags' in fields:
        if 'tags' not in a or stringify(a['tags']) != stringify(fields['tags']):
            changed.append('tags')
        a['tags'] = fields['tags']
    a['networked'] = _networked(a)
    a['updated_at'] = at
    _event(a, 'edited', who, at, {'fields': changed})
    return {'puts': [{'c': 'assets', 'o': a}], 'audit': _audit(who, 'asset.edit', a['id'], {'changed': changed}),
            'result': {'asset': public(a), 'warnings': warnings, 'changed': changed}}


def transition(r):
    a = _load(r, ('status',))
    action = r.get('action')
    if not isinstance(action, str) or action not in LIFECYCLE_ACTIONS:
        raise Refuse(400, 'unknown lifecycle action %s' % _to_str(action if action is not None else 'undefined'))
    who, at = _who(r), r.get('at')
    to, frm = LIFECYCLE_ACTIONS[action], a['status']
    reason = s(r.get('reason'), 2000) or None
    a['status'] = to
    a['updated_at'] = at
    _event(a, action, who, at, {'from': frm, 'to': to, 'reason': reason})
    return {'puts': [{'c': 'assets', 'o': a}], 'audit': _audit(who, 'asset.' + action, r.get('id'), {'from': frm, 'to': to, 'reason': reason}),
            'result': {'asset': public(a)}}


def move(r):
    a = _load(r, ('site', 'location'))
    body = r.get('body')
    if not is_obj(body):
        raise NodeDecides()
    who, at = _who(r), r.get('at')
    L = body.get('location')
    loc = {'building': s(L.get('building'), 200) or None, 'room': s(L.get('room'), 120) or None, 'rack': s(L.get('rack'), 120) or None} if is_obj(L) else None
    site = s(body.get('site'), 200)
    frm = {'site': a['site'], 'location': a['location']}
    if site:
        a['site'] = site
        _ensure(a, 'locked')['site'] = True
    if loc:
        a['location'] = loc
        _ensure(a, 'locked')['location'] = True
    a['updated_at'] = at
    to = {'site': a['site'], 'location': a['location']}
    _event(a, 'moved', who, at, {'from': frm, 'to': to})
    return {'puts': [{'c': 'assets', 'o': a}], 'audit': _audit(who, 'asset.move', r.get('id'), {'from': frm, 'to': to}), 'result': {'asset': public(a)}}


def assign(r):
    a = _load(r, ('owner', 'custodian', 'department'))
    body = r.get('body')
    if not is_obj(body):
        raise NodeDecides()
    who, at = _who(r), r.get('at')
    frm = {'owner': a['owner'], 'custodian': a['custodian'], 'department': a['department']}
    _ensure(a, 'locked')
    for k in ['owner', 'custodian', 'department']:
        if k in body:
            a[k] = s(body[k], 300) or None
            a['locked'][k] = True
    a['updated_at'] = at
    to = {'owner': a['owner'], 'custodian': a['custodian'], 'department': a['department']}
    _event(a, 'assigned', who, at, {'from': frm, 'to': to})
    return {'puts': [{'c': 'assets', 'o': a}], 'audit': _audit(who, 'asset.assign', r.get('id'), {'to': to}), 'result': {'asset': public(a)}}


def _guard(fn, reads=True):
    def run(r):
        r = dict(r)
        try:
            out = fn(r)
        except Refuse as e:
            out = {'refuse': {'status': e.status, 'error': e.error}}
        except NodeDecides:
            return {'node': True}
        if reads:   # the record decided on, hashed as read - before the decision changed it
            out['based_on'] = r.get('_based')
        return out
    return run


OPS = {'assets.create': _guard(create, reads=False), 'assets.edit': _guard(edit), 'assets.transition': _guard(transition),
       'assets.move': _guard(move), 'assets.assign': _guard(assign)}
