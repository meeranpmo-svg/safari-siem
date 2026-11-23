# Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
"""Support Contracts - the WRITES, migration step 9g (docs/PYTHON-MIGRATION.md): save (new / edit / renewal), verified with
the vendor, retire, CSV import and the expiring window, decided here exactly like engine/support-contracts.js. Nothing is
written here; the engine (engine/py-writer.js) commits the answer only if every record decided on is what it holds now.
Two JavaScript readings are reproduced only where they are certain, and anything else answers {node: true}:
  - the portal address (WHATWG URL): plain https://host[:port]/path?query#fragment in ASCII is normalised here (lower-case
    host, default port dropped, '/' for an empty path); a login, an IP address, an IDN, dot segments, backslashes or any
    character the URL parser would encode or strip are left to Node.js;
  - an object-literal lookup (FAMILIES[x]) with a prototype name (constructor, toString ...).
The CSV import makes its own contract ids (sc_ + 10 hex), one per created row, as Node.js does.
Standard library only (Python 3.8+).
"""
import os
import re

from assets_write import NodeDecides, Refuse, _to_str, _trim, _utf16, num
from core_write import _Ctx
from jscompat import MISSING, truthy
from roles_write import JS_WS

PROTO = {'constructor', '__proto__', 'hasOwnProperty', 'isPrototypeOf', 'propertyIsEnumerable', 'toLocaleString', 'toString', 'valueOf',
         '__defineGetter__', '__defineSetter__', '__lookupGetter__', '__lookupSetter__'}
FAMILIES = {
    'windows_server': ('Windows Server', 'Microsoft', ['servers', 'cores']),
    'exchange': ('Exchange Server', 'Microsoft', ['servers']),
    'sql_server': ('SQL Server', 'Microsoft', ['servers', 'cores']),
    'vmware': ('VMware vSphere / VCF', 'VMware by Broadcom', ['hosts', 'cores']),
    'nutanix': ('Nutanix (AOS / AHV, nodes)', 'Nutanix', ['nodes']),
    'oracle_db': ('Oracle Database', 'Oracle', ['servers', 'processors']),
    'rhel': ('Red Hat Enterprise Linux', 'Red Hat', ['servers']),
    'cisco': ('Cisco hardware (Smart Net)', 'Cisco', ['devices']),
    'fortinet': ('Fortinet (FortiCare, FortiGuard)', 'Fortinet', ['devices']),
    'paloalto': ('Palo Alto Networks (support, subscriptions)', 'Palo Alto Networks', ['devices']),
    'hardware': ('Hardware support (by vendor)', '', ['devices']),
    'other': ('Other (listed assets only)', '', ['devices', 'users', 'subscription']),
}
UNITS = ['devices', 'servers', 'hosts', 'nodes', 'cores', 'processors', 'users', 'subscription']
KINDS = ['support', 'subscription', 'hardware', 'software-assurance']
CLOSED = ('retired', 'disposed')
_CTRL = re.compile('[\u0000-\u001f\u007f]')


def U(v):
    return v is MISSING


def _string(v):
    return '' if v is None or v is MISSING else _to_str(v)


def s(v, mx=200):
    """s() of support-contracts.js: controls to spaces, trimmed, at most mx UTF-16 units"""
    return _utf16(_trim(_CTRL.sub(' ', _string(v))), mx or 200)


def _or(*vals):
    """a || b || c (the value itself)"""
    for v in vals[:-1]:
        if not U(v) and truthy(v):
            return v
    return vals[-1]


def low(v):
    return _string(_or(v, '')).lower()


def norm_serial(v):
    return re.sub('[^A-Z0-9]', '', _string(_or(v, '')).upper())[:40]


_ISO = re.compile(r'^([0-9]{4})-([0-9]{2})-([0-9]{2})$')


def iso_date(v):
    t = s(v, 30)
    if not t:
        return None
    if not _ISO.match(t):
        raise Refuse(400, 'dates must be YYYY-MM-DD: ' + t)
    return t


# WHATWG URL, for the plain https addresses only
_SCHEME = re.compile(r'^([A-Za-z][A-Za-z0-9+.\-]*):')
_LABEL = re.compile(r'^[A-Za-z0-9\-]+$')
_PATH = re.compile(r"^[A-Za-z0-9\-._~!$&()*+,;=:@/%']*$")
_QUERY = re.compile(r'^[A-Za-z0-9\-._~!$&()*+,;=:@/?%]*$')
_FRAG = re.compile(r"^[A-Za-z0-9\-._~!$&()*+,;=:@/?%']*$")
_DOTSEG = re.compile(r'^(\.|\.\.|%2e|\.%2e|%2e\.|%2e%2e)$', re.I)


def https_url(v):
    if U(v) or not truthy(v):
        return ''
    t = _to_str(v)
    if any(ord(ch) <= 0x20 or ord(ch) > 0x7e for ch in t) or '\\' in t:
        raise NodeDecides()   # stripped / removed / encoded by the URL parser
    m = _SCHEME.match(t)
    if not m:
        raise Refuse(400, 'portal must be an https:// address')   # relative: new URL() throws
    if m.group(1).lower() != 'https' or not t[m.end():].startswith('//'):
        raise NodeDecides()
    rest = t[m.end() + 2:]
    cut = min([i for i in (rest.find('/'), rest.find('?'), rest.find('#')) if i >= 0] or [len(rest)])
    auth, rest = rest[:cut], rest[cut:]
    if '@' in auth or '[' in auth:
        raise NodeDecides()   # a login (refused by Node.js) or an IPv6 address
    host, _, port = auth.partition(':')
    labels = host[:-1].split('.') if host.endswith('.') else host.split('.')
    if not host or not all(l and _LABEL.match(l) for l in labels) or re.match(r'^([0-9]+|0[xX][0-9a-fA-F]*)$', labels[-1]) or any(l.lower().startswith('xn--') for l in labels):
        raise NodeDecides()   # empty, IPv4 rules, IDNA
    if port and not port.isdigit():
        raise NodeDecides()
    p = int(port) if port else None
    if p is not None and p > 65535:
        raise NodeDecides()
    path, query, frag = rest, '', ''
    if '#' in path:
        path, frag = path.split('#', 1)
        frag = '#' + frag
    if '?' in path:
        path, query = path.split('?', 1)
        query = '?' + query
    if not _PATH.match(path) or not _QUERY.match(query[1:]) or not _FRAG.match(frag[1:]) or '#' in frag[1:]:
        raise NodeDecides()
    if any(_DOTSEG.match(seg) for seg in path.split('/')):
        raise NodeDecides()
    return 'https://' + host.lower() + (':%d' % p if p is not None and p != 443 else '') + (path or '/') + query + frag


def _who(r):
    w = r.get('who')
    if not isinstance(w, dict) or not all(k in w for k in ('user', 'role', 'ip')):
        raise NodeDecides()
    return w


def _audit(who, action, target, detail):
    return {'by': who['user'], 'role': who['role'], 'ip': who['ip'], 'action': action, 'target': target, 'detail': detail}


def _fam(name):
    if name in PROTO:
        raise NodeDecides()
    return FAMILIES.get(name)


def _finite(v):
    """Number.isFinite(v): a number (not a numeric string, not undefined), and finite"""
    return isinstance(v, (int, float)) and not isinstance(v, bool) and v == v and v not in (float('inf'), float('-inf'))


def _number(v):
    """Number(v) when finite, else None (Number(null) = 0 is excluded by the callers, as in Node.js)"""
    return num(v)


def _put(b, who, at, new_id, c, puts, audits):
    """put() of support-contracts.js for one body b (dict, a missing key = undefined)"""
    g = lambda k: b.get(k, MISSING)   # noqa: E731
    prev = None
    if truthy(g('id')) and not U(g('id')):
        prev = c.get('support_contracts', s(g('id'), 40))
        if prev is None:
            raise Refuse(404, 'contract not found')
    P = lambda k: (prev.get(k, MISSING) if prev is not None else None)   # noqa: E731  prev && prev.k
    family = s(_or(g('family'), P('family')), 30)
    F = _fam(family)
    if F is None:
        raise Refuse(400, 'family must be one of ' + ', '.join(FAMILIES))
    vendor = s(_or(g('vendor'), P('vendor'), F[1]), 80)
    if not vendor:
        raise Refuse(400, 'vendor required')
    end = iso_date(P('end') if U(g('end')) else g('end'))
    if not end:
        raise Refuse(400, 'end date required (YYYY-MM-DD)')
    unit = s(_or(g('unit'), P('unit'), F[2][0]), 20)
    if unit not in UNITS:
        raise Refuse(400, 'unit must be one of ' + ', '.join(UNITS))
    q = g('quantity')
    if U(q) or q == '' or q is None:
        qty = prev.get('quantity', MISSING) if prev is not None else None
    else:
        qty = _number(q)
        qty = MISSING if qty is None else qty
    if qty is not None and (not _finite(qty) or qty < 0 or qty > 1e7):
        raise Refuse(400, 'quantity must be a number')
    if isinstance(g('asset_ids'), list):
        ids = list(dict.fromkeys(x for x in (s(v, 60) for v in g('asset_ids')) if x))[:5000]
    else:
        ids = P('asset_ids') if prev is not None else []
        if not isinstance(ids, list):
            raise NodeDecides()
    for id_ in ids:
        if c.get('assets', id_) is None:
            raise Refuse(400, 'asset not found: ' + _to_str(id_))
    if isinstance(g('serials'), list):
        serials = list(dict.fromkeys(x for x in (norm_serial(v) for v in g('serials')) if x))[:5000]
    else:
        serials = P('serials') if prev is not None else []
        if not isinstance(serials, list):
            raise NodeDecides()
    cv = g('cost')
    if U(cv):
        cost = prev.get('cost', MISSING) if prev is not None else None
    elif cv == '' or cv is None:
        cost = None
    else:
        cost = _number(cv)
        cost = MISSING if cost is None else cost
    if cost is not None and (not _finite(cost) or cost < 0):
        raise Refuse(400, 'cost must be a number')
    kind = s(_or(g('kind'), P('kind'), 'support'), 30)
    if kind not in KINDS:
        raise Refuse(400, 'kind must be one of ' + ', '.join(KINDS))
    pick = lambda k: P(k) if U(g(k)) else g(k)   # noqa: E731  b.k !== undefined ? b.k : prev && prev.k
    product = s(pick('product'), 160) or F[0]
    contract_number = s(pick('contract_number'), 80)
    level = s(pick('level'), 120)
    start = iso_date(pick('start'))
    owner = s(pick('owner'), 120)
    currency = s(_or(g('currency'), P('currency'), 'SAR'), 3).upper()
    portal = https_url(pick('portal'))
    notes = s(pick('notes'), 1000)
    rec = {'id': new_id, 'status': 'active', 'created_by': who['user'], 'created_at': at, 'history': []}
    rec.update(prev or {})
    rec.update({'vendor': vendor, 'family': family, 'product': product, 'contract_number': contract_number, 'level': level, 'kind': kind, 'start': start,
                'end': end, 'quantity': qty, 'unit': unit, 'asset_ids': ids, 'serials': serials, 'owner': owner, 'cost': cost, 'currency': currency,
                'portal': portal, 'notes': notes, 'updated_by': who['user'], 'updated_at': at})
    hist = rec.get('history')
    if prev is not None and prev.get('end', MISSING) != rec['end']:
        if hist is not None and not isinstance(hist, list) and truthy(hist):
            raise NodeDecides()
        rec['verified'] = None
        pe = prev.get('end', MISSING)
        hist = (hist if isinstance(hist, list) else []) + [{'at': at, 'by': who['user'], 'what': 'end date %s → %s' % ('undefined' if U(pe) else _to_str(pe), rec['end'])}]
    if hist is not None and not isinstance(hist, list) and truthy(hist):
        raise NodeDecides()
    rec['history'] = ((hist if isinstance(hist, list) else []) + [{'at': at, 'by': who['user'], 'what': 'updated' if prev is not None else 'created'}])[-100:]
    puts.append({'c': 'support_contracts', 'o': rec})
    audits.append(_audit(who, 'support.update' if prev is not None else 'support.create', rec['id'],
                         {'vendor': vendor, 'family': family, 'contract': rec['contract_number'], 'end': end, 'assets': len(ids), 'serials': len(serials)}))
    return rec


def contract_put(r, c):
    who = _who(r)
    puts, audits = [], []
    rec = _put(r.get('body') or {}, who, r.get('at'), r.get('new_id'), c, puts, audits)
    return {'puts': puts, 'audits': audits, 'result': rec}


def _contract(r, c):
    cur = c.get('support_contracts', s(r.get('id'), 40))
    if cur is None:
        raise Refuse(404, 'contract not found')
    h = cur.get('history', MISSING)
    if not U(h) and h is not None and not isinstance(h, list) and truthy(h):
        raise NodeDecides()
    return cur, (h if isinstance(h, list) else [])


def contract_verify(r, c):
    who, at = _who(r), r.get('at')
    cur, h = _contract(r, c)
    ref = s((r.get('body') or {}).get('reference', MISSING), 300)
    if not ref:
        raise Refuse(400, 'a reference is required (what you checked: portal page, partner e-mail, case number)')
    if 'end' not in cur:
        raise NodeDecides()
    cur['verified'] = {'at': at, 'by': who['user'], 'reference': ref, 'end_seen': cur['end']}
    cur['history'] = (h + [{'at': at, 'by': who['user'], 'what': 'verified with the vendor: ' + ref}])[-100:]
    return {'puts': [{'c': 'support_contracts', 'o': cur}], 'result': cur, 'audit': _audit(who, 'support.verify', cur['id'], {'reference': ref})}


def contract_retire(r, c):
    who, at = _who(r), r.get('at')
    cur, h = _contract(r, c)
    reason = s((r.get('body') or {}).get('reason', MISSING), 300)
    if not reason:
        raise Refuse(400, 'a reason is required')
    cur['status'] = 'retired'
    cur['retired'] = {'at': at, 'by': who['user'], 'reason': reason}
    cur['history'] = h + [{'at': at, 'by': who['user'], 'what': 'retired: ' + reason}]
    return {'puts': [{'c': 'support_contracts', 'o': cur}], 'result': {'ok': True}, 'audit': _audit(who, 'support.retire', cur['id'], {'reason': reason})}


def settings_put(r, c):
    who = _who(r)
    v = num((r.get('body') or {}).get('expiring_days', MISSING))
    if v is None or v != int(v) or v < 7 or v > 365:
        raise Refuse(400, 'expiring window must be 7-365 days')
    v = int(v)
    c.get('support_contracts_cfg', 'settings')
    return {'puts': [{'c': 'support_contracts_cfg', 'o': {'id': 'settings', 's': {'expiring_days': v}}}], 'result': {'expiring_days': v},
            'audit': _audit(who, 'support.settings', 'support-contracts', {'expiring_days': v})}


# ---- CSV import -----------------------------------------------------------------------------------------------------
def parse_csv(text):
    """parseCsv of engine/import.js"""
    t = text[1:] if text.startswith('﻿') else text
    rows, row, field, inq, i, n = [], [], [], False, 0, len(t)
    while i < n:
        ch = t[i]
        if inq:
            if ch == '"':
                if i + 1 < n and t[i + 1] == '"':
                    field.append('"')
                    i += 1
                else:
                    inq = False
            else:
                field.append(ch)
        elif ch == '"':
            inq = True
        elif ch == ',':
            row.append(''.join(field))
            field = []
        elif ch == '\r':
            pass
        elif ch == '\n':
            row.append(''.join(field))
            rows.append(row)
            row, field = [], []
        else:
            field.append(ch)
        i += 1
    if field or row:
        row.append(''.join(field))
        rows.append(row)
    rows = [x for x in rows if any(_trim(f) != '' for f in x)]
    if not rows:
        return [], []
    headers = [_trim(h) for h in rows[0]]
    if any(h in ('__proto__', 'null') for h in headers):
        raise NodeDecides()   # o.__proto__ = '...' is ignored; r[null] reads a column called "null"
    out = []
    for x in rows[1:]:
        o = {}
        for idx, h in enumerate(headers):
            o[h] = x[idx] if idx < len(x) else ''
        out.append(o)
    return headers, out


def contracts_import(r, c):
    who, at = _who(r), r.get('at')
    body = r.get('body') or {}
    headers, rows = parse_csv(_string(_or(body.get('text', MISSING), '')))
    if not rows:
        raise Refuse(400, 'no rows (expected a header line: vendor, family, product, contract, end …)')
    H = {re.sub('[' + re.escape(JS_WS) + '_]+', ' ', low(h)): h for h in headers}

    def col_(*names):
        for nm in names:
            if truthy(H.get(nm)):
                return H[nm]
        return None
    C = {'vendor': col_('vendor'), 'family': col_('family', 'type'), 'product': col_('product'), 'contract': col_('contract', 'contract number', 'csi', 'agreement'),
         'level': col_('level', 'service level'), 'start': col_('start', 'start date'), 'end': col_('end', 'end date', 'expiry', 'expiry date'), 'quantity': col_('quantity', 'qty'),
         'unit': col_('unit'), 'serials': col_('serials', 'serial numbers'), 'assets': col_('assets', 'asset names', 'servers'), 'owner': col_('owner'), 'cost': col_('cost'),
         'currency': col_('currency'), 'notes': col_('notes')}
    if not C['end'] or not C['family']:
        raise Refuse(400, 'the CSV needs at least "family" and "end" columns')
    by_name = {}
    for a in c.all('assets'):
        st = a.get('status', MISSING)
        if isinstance(st, (list, dict)) or st in PROTO:
            raise NodeDecides()
        if not (isinstance(st, str) and st in CLOSED):
            by_name[low(a.get('name', MISSING))] = a['id']
    puts, audits, created, errors = [], [], 0, []

    def R(row, k):
        return row.get(C[k], MISSING) if C[k] is not None else MISSING
    for i, row in enumerate(rows):
        try:
            names = [x for x in (_trim(p) for p in re.split('[;|]', _string(_or(R(row, 'assets'), '')))) if x] if C['assets'] else []
            missing = [nm for nm in names if low(nm) not in by_name]
            if missing:
                raise Refuse(400, 'assets not in the inventory: ' + ', '.join(missing[:5]))
            b = {'vendor': R(row, 'vendor'), 'family': re.sub('[' + re.escape(JS_WS) + ']+', '_', low(R(row, 'family'))), 'product': R(row, 'product'),
                 'contract_number': R(row, 'contract'), 'level': R(row, 'level'), 'start': _or(R(row, 'start'), None), 'end': R(row, 'end'),
                 'quantity': R(row, 'quantity') if C['quantity'] else None,
                 'unit': (low(R(row, 'unit')) or MISSING) if C['unit'] else MISSING,
                 'serials': re.split('[;|' + re.escape(JS_WS) + ']', _string(_or(R(row, 'serials'), ''))) if C['serials'] else [],
                 'asset_ids': [by_name[low(nm)] for nm in names], 'owner': R(row, 'owner') if C['owner'] else '',
                 'cost': R(row, 'cost') if C['cost'] else None, 'currency': R(row, 'currency') if C['currency'] else MISSING, 'notes': R(row, 'notes') if C['notes'] else ''}
            b = {k: v for k, v in b.items() if not U(v)}
            _put(b, who, at, 'sc_' + os.urandom(5).hex(), c, puts, audits)
            created += 1
        except Refuse as e:
            errors.append({'line': i + 2, 'error': e.error})
    audits.append(_audit(who, 'support.import', 'support contracts', {'created': created, 'errors': len(errors)}))
    return {'puts': puts, 'audits': audits, 'result': {'created': created, 'errors': errors[:200], 'errors_total': len(errors)}}


def _guard(fn):
    def run(r):
        try:
            c = _Ctx(r)
        except Exception:
            return {'ok': False, 'error_class': 'protocol', 'error': 'store not readable'}
        try:
            out = fn(r, c)
        except Refuse as e:
            out = {'refuse': {'status': e.status, 'error': e.error}}
        except NodeDecides:
            return {'node': True}
        out['based_on'] = c.based
        return out
    return run


OPS = {'support.put': _guard(contract_put), 'support.verify': _guard(contract_verify), 'support.retire': _guard(contract_retire),
       'support.settings': _guard(settings_put), 'support.import': _guard(contracts_import)}
