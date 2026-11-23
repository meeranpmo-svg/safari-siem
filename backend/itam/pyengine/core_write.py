# Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
"""The other human writes of the core engine - migration step 9e (docs/PYTHON-MIGRATION.md), decided here exactly like
engine/licences.js (save, retire), engine/stocktake.js (open, scan, close), engine/findings.js (accept / dismiss) and
engine/assets.js addRelationship (a CMDB link a person adds). Same pattern as 9b-9d: nothing is written here. Each
operation answers the records to write ({puts}), the audit entry and the route's answer, or a refusal worded as Node.js
words it, plus based_on - "collection/id" -> SHA-256 of the JSON of each record it decided on (null when absent) - so the
engine (engine/py-writer.js) commits only a decision made on the records it holds now. Node.js supplies new ids and the
time. What Python does not read exactly like JavaScript answers {node: true} and Node.js decides it.
Not here on purpose: settings, credentials and agent tokens (they carry secrets) and the automatic writers (licence sync,
discovery merges, AI results).
Standard library only (Python 3.8+).
"""
import copy
import math

from assets_write import NodeDecides, Refuse, _to_str, _trim, _utf16, date_iso, is_obj, num, public, s
from jscompat import MISSING, truthy
from store import reader as store_reader, sha256, stringify


def _who(r):
    w = r.get('who')
    if not isinstance(w, dict) or 'user' not in w or 'role' not in w:
        raise NodeDecides()   # an audit entry with by / role undefined: Node.js writes that one
    return w


def _audit(who, action, target, detail):
    return {'by': who['user'], 'role': who['role'], 'action': action, 'target': target, 'detail': detail}


class _Ctx:
    """the store as read for one decision, remembering every record looked at (based_on)"""

    def __init__(self, r):
        self.st = store_reader(r['dir'])
        self.based = {}

    def get(self, col, id_):
        o = self.st.collection(col).get(id_)
        self.based['%s/%s' % (col, id_)] = sha256(stringify(o))
        return None if o is None else _copy(o)

    def all(self, col):
        return self.st.collection(col).all()

    def seen(self, col, o):
        """a record found by searching (not by id) that the decision is based on"""
        self.based['%s/%s' % (col, o.get('id'))] = sha256(stringify(o))
        return _copy(o)


def _copy(o):
    return copy.deepcopy(o)   # the resident service's cache holds these records: never change them in place


def js_round(x):
    """Math.round, exactly (floor(x + 0.5) is off for 0.49999999999999994)"""
    f = math.floor(x)
    return f + 1 if x - f >= 0.5 else f


def _js_or(*vals):
    """a || b || c in JavaScript (the value itself, not a boolean)"""
    for v in vals[:-1]:
        if v is not MISSING and truthy(v):
            return v
    v = vals[-1]
    return v


def _string(v):
    """String(v)"""
    return 'undefined' if v is MISSING else _to_str(v)


# ---- licences -------------------------------------------------------------------------------------------------------
def _norm_licence(o):
    lid, product = s(o.get('id'), 80), s(o.get('product'), 300)
    if not lid or not product:
        return None
    seats = num(o.get('seats', MISSING))
    return {'id': lid, 'product': product, 'type': s(o.get('type'), 80) or 'subscription',
            'seats': None if seats is None else max(0, js_round(seats)),
            'expiry': date_iso(o.get('expiry')), 'cost': num(o.get('cost', MISSING)),
            'publisher': s(o.get('publisher'), 200) or None, 'notes': s(o.get('notes'), 2000) or None,
            'product_key_match': s(o.get('product_key_match'), 300) or None}


def licence_save(r, c):
    who, at = _who(r), r.get('at')
    inc = dict(r.get('body') or {})
    if not truthy(inc.get('id')):
        inc['id'] = r.get('new_id')
    lic = _norm_licence(inc)
    if lic is None:
        raise Refuse(400, 'licence needs id and product')
    prev = c.get('licences', lic['id'])
    rec = {'status': 'active', 'created_at': at}
    rec.update(prev or {})
    rec.update(lic)
    rec['updated_at'] = at
    return {'puts': [{'c': 'licences', 'o': rec}], 'result': {'licence': rec},
            'audit': _audit(who, 'licence.update' if prev else 'licence.create', rec['id'], {'product': rec['product'], 'seats': rec['seats']})}


def licence_retire(r, c):
    who, at = _who(r), r.get('at')
    lid = str(r.get('id'))
    l = c.get('licences', lid)
    if l is None:
        raise Refuse(404, 'licence not found')
    reason = r.get('reason', MISSING)
    reason = reason if reason is not MISSING and truthy(reason) else None
    l.update({'status': 'inactive', 'retired_at': at, 'reason': reason})
    return {'puts': [{'c': 'licences', 'o': l}], 'result': {'ok': True}, 'audit': _audit(who, 'licence.retire', lid, {'reason': reason})}


# ---- stocktake ------------------------------------------------------------------------------------------------------
def _view(rec):
    scanned = set(x.get('asset_id') for x in rec['scanned'])
    missing = (rec.get('missing') or []) if rec['status'] == 'closed' else [a for a in rec['expected'] if a not in scanned]
    out = {'id': rec['id'], 'name': rec['name'], 'site': rec['site'], 'status': rec['status'], 'opened_by': rec.get('opened_by', MISSING),
           'opened_at': rec['opened_at'], 'closed_at': rec['closed_at'], 'expected': len(rec['expected']), 'found': len(rec['scanned']),
           'missing': len(missing), 'unexpected': len(rec['unexpected']), 'scanned': rec['scanned'], 'unexpected_scans': rec['unexpected'], 'missing_ids': missing}
    return out


def _stk(c, r, need_shape=True):
    rec = c.get('stocktakes', str(r.get('id')))
    if rec is None:
        raise Refuse(404, 'stocktake not found')
    for k in ('id', 'name', 'site', 'status', 'opened_at', 'closed_at', 'expected', 'scanned', 'unexpected'):
        if k not in rec:
            raise NodeDecides()   # a record of another shape: Node.js reads it as it always did
    if not all(isinstance(rec[k], list) for k in ('expected', 'scanned', 'unexpected')):
        raise NodeDecides()
    return rec


def stocktake_open(r, c):
    who, at = _who(r), r.get('at')
    body = r.get('body') or {}
    site = _trim(_string(_js_or(body.get('site', MISSING), ''))) or None
    expected = [a['id'] for a in c.all('assets') if a.get('status') not in ('disposed', 'retired') and (not site or a.get('site', MISSING) == site)]
    name = _utf16(_string(_js_or(body.get('name', MISSING), 'Stocktake ' + at[:10])), 200)
    rec = {'id': r.get('new_id'), 'name': name, 'site': site, 'status': 'open', 'opened_by': who['user'], 'opened_at': at,
           'expected': expected, 'scanned': [], 'unexpected': [], 'closed_at': None}
    return {'puts': [{'c': 'stocktakes', 'o': rec}], 'result': _view(rec),
            'audit': _audit(who, 'stocktake.open', rec['id'], {'site': site, 'expected': len(expected)})}


def _by_tag(assets, code):
    t = _trim(code).lower()
    out = []
    for a in assets:
        hit = False
        for k in ('asset_tag', 'serial'):
            v = a.get(k)
            if truthy(v) and v is not MISSING:
                if not isinstance(v, str):
                    raise NodeDecides()   # .toLowerCase() of a non-string throws in Node.js
                if v.lower() == t:
                    hit = True
                    break
        if hit:
            out.append(a)
    return out


def stocktake_scan(r, c):
    who, at = _who(r), r.get('at')
    rec = _stk(c, r)
    if rec['status'] != 'open':
        raise Refuse(400, 'stocktake is closed')
    body = r.get('body') or {}
    code = _trim(_string(_js_or(_js_or(body.get('code', MISSING), body.get('tag', MISSING), body.get('serial', MISSING)), '')))
    if not code:
        raise Refuse(400, 'scan needs a code (asset tag or serial)')
    matches = _by_tag(c.all('assets'), code)
    if not matches:
        if not any(isinstance(u, dict) and u.get('code') == code for u in rec['unexpected']):
            rec['unexpected'].append({'code': code, 'at': at, 'by': who['user']})
        return {'puts': [{'c': 'stocktakes', 'o': rec}], 'result': {'result': 'unexpected', 'code': code, 'asset': None, 'stocktake': _view(rec)}}
    a = public(matches[0])
    if not any(isinstance(x, dict) and x.get('asset_id') == a.get('id') for x in rec['scanned']):
        rec['scanned'].append({'asset_id': a.get('id'), 'code': code, 'at': at, 'by': who['user']})
    return {'puts': [{'c': 'stocktakes', 'o': rec}],
            'result': {'result': 'found' if a.get('id') in rec['expected'] else 'found_out_of_scope', 'code': code, 'asset': a, 'stocktake': _view(rec)}}


def stocktake_close(r, c):
    who, at = _who(r), r.get('at')
    rec = _stk(c, r)
    if rec['status'] == 'closed':
        return {'puts': [], 'result': _view(rec)}
    scanned = set(x.get('asset_id') for x in rec['scanned'])
    rec['missing'] = [a for a in rec['expected'] if a not in scanned]
    rec['status'] = 'closed'
    rec['closed_at'] = at
    rec['closed_by'] = who['user']
    return {'puts': [{'c': 'stocktakes', 'o': rec}], 'result': _view(rec),
            'audit': _audit(who, 'stocktake.close', rec['id'], {'expected': len(rec['expected']), 'found': len(rec['scanned']), 'missing': len(rec['missing']), 'unexpected': len(rec['unexpected'])})}


# ---- AI findings: accept / dismiss ----------------------------------------------------------------------------------
def finding_status(r, c):
    st = r.get('status')
    if st not in ('open', 'accepted', 'dismissed'):
        raise Refuse(400, 'status must be accepted or dismissed')
    who, at = _who(r), r.get('at')
    f = c.get('findings', str(r.get('id')))
    if f is None:
        raise Refuse(404, 'finding not found')
    reason = r.get('reason', MISSING)
    nxt = dict(f)
    nxt.update({'status': st, st + '_at': at, st + '_by': who['user'], 'reason': _js_or(reason, f.get('reason', MISSING), None)})
    detail = {'kind': f.get('kind', MISSING), 'asset_id': f.get('asset_id', MISSING), 'licence_id': f.get('licence_id', MISSING),
              'reason': reason if reason is not MISSING and truthy(reason) else None}
    return {'puts': [{'c': 'findings', 'o': nxt}], 'result': {'finding': nxt}, 'audit': _audit(who, 'ai.findings.' + st, str(r.get('id')), detail)}


# ---- CMDB: a relationship a person adds -----------------------------------------------------------------------------
REL_TYPES = ['runs_on', 'connected_to', 'depends_on', 'member_of', 'installed_on']
REL_STATUS = ['proposed', 'confirmed']
REL_SOURCE = ['sensor', 'vcenter', 'agent', 'manual', 'ai', 'import']


def _u16(t):
    return t.encode('utf-16-be', 'surrogatepass')   # JavaScript's default sort compares UTF-16 code units


def _rel_key(frm, to, typ):
    if typ == 'connected_to':
        a, b = sorted([frm, to], key=_u16)
        return '%s|%s|%s' % (typ, a, b)
    return '%s|%s|%s' % (typ, frm, to)


def _norm_rel(o):
    frm, to = s(o.get('from'), 80), s(o.get('to'), 80)
    typ = s(o.get('type')).lower()
    typ = typ if typ in REL_TYPES else None
    if not frm or not to or not typ or frm == to:
        return None
    st, src = s(o.get('status')).lower(), s(o.get('source')).lower()
    conf = num(o.get('confidence', MISSING))
    if conf is not None:
        conf = max(0, min(1, conf))
    return {'id': s(o.get('id'), 80) or None, 'from': frm, 'to': to, 'type': typ, 'status': st if st in REL_STATUS else 'proposed',
            'source': src if src in REL_SOURCE else 'manual', 'confidence': conf, 'rationale': s(o.get('rationale'), 2000) or None,
            'by': s(o.get('by'), 200) or None, 'at': s(o.get('at'), 40) or None, 'key': _rel_key(frm, to, typ)}


def cmdb_add(r, c):
    who, at = _who(r), r.get('at')
    body = r.get('body') or {}
    o = {'source': 'manual'}
    o.update(body)
    rel = _norm_rel(o)
    if rel is None:
        raise Refuse(400, 'invalid relationship (need from, to, type)')
    a, b = c.get('assets', rel['from']), c.get('assets', rel['to'])
    if a is None or b is None:
        raise Refuse(404, 'relationship endpoints must be existing assets')
    existing = next((x for x in c.all('relationships') if x.get('key') == rel['key']), None)
    if existing is not None:
        existing = c.seen('relationships', existing)
    confirm = body.get('confirm', MISSING) is not False
    rec = dict(existing or {})
    rec.update(rel)
    eid = existing.get('id') if existing else None
    rec.update({'id': eid if truthy(eid) else r.get('new_id'),
                'status': 'confirmed' if confirm else ('confirmed' if existing and existing.get('status') == 'confirmed' else rel['status']),
                'by': who['user'], 'at': at})
    pub = {k: v for k, v in rec.items() if k != 'key'}
    return {'puts': [{'c': 'relationships', 'o': rec}], 'result': {'relationship': pub},
            'audit': _audit(who, 'cmdb.update' if existing else 'cmdb.add', rec['id'], {'from': rec['from'], 'to': rec['to'], 'type': rec['type'], 'status': rec['status'], 'source': 'manual'})}   # the route's source option, not the body's


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


OPS = {'licences.save': _guard(licence_save), 'licences.retire': _guard(licence_retire),
       'stocktake.open': _guard(stocktake_open), 'stocktake.scan': _guard(stocktake_scan), 'stocktake.close': _guard(stocktake_close),
       'findings.status': _guard(finding_status), 'cmdb.add': _guard(cmdb_add)}
