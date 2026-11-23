# Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
"""Add-on module WRITES - migration step 9f (docs/PYTHON-MIGRATION.md): Locations (engine/locations.js: create, edit with
the rename on every inventory asset, delete) and Asset Ownership (engine/ownership.js: assign, service owners, CSV import),
decided here exactly like the Node.js functions. Nothing is written here: the answer is the records to write ({puts,
removes}), the audit entries and the result, or a refusal - which, like Node.js, may still write what was written before
it refused (an inventory site saved first, then a name refused). based_on lists every record decided on; the engine
(engine/py-writer.js) commits only if each is what it holds now. The Locations answers are a read of the list after the
write: Node.js builds them (its sort is ICU's localeCompare). What is not read exactly like JavaScript answers {node: true}.
Standard library only (Python 3.8+).
"""
import re

from assets_write import NodeDecides, Refuse, _to_str, _trim, _utf16
from core_write import _Ctx
from jscompat import MISSING, truthy
from roles_write import JS_WS

# JavaScript's \\s (= String.prototype.trim's set)
_WS = re.compile('[' + re.escape(JS_WS) + ']+')
_CTRL_DEL = re.compile('[\u0000-\u001f\u007f]')
_CTRL = re.compile('[\u0000-\u001f]')
_PROTO = ('constructor', '__proto__')   # keys an object literal answers from Object.prototype


class RefuseWith(Refuse):
    def __init__(self, status, error, puts):
        super().__init__(status, error)
        self.puts = puts


def _string(v):
    """String(v == null ? '' : v)"""
    return '' if v is None or v is MISSING else _to_str(v)


def _who(r):
    w = r.get('who')
    if not isinstance(w, dict) or not all(k in w for k in ('user', 'role', 'ip')):
        raise NodeDecides()
    return w


# ---- Locations ------------------------------------------------------------------------------------------------------
KINDS = ['main', 'dr', 'branch', 'cloud', 'other']


def ls(v, mx=120):
    """s() of locations.js: controls to spaces, whitespace runs to one space, trimmed, at most mx UTF-16 units"""
    return _utf16(_trim(_WS.sub(' ', _CTRL_DEL.sub(' ', _string(v)))), mx or 120)


def lkey(n):
    return ls(n).lower()


def _fields(b, cur):
    o = dict(cur or {})
    if not cur or 'name' in b:
        o['name'] = ls(b.get('name', MISSING))
        if not o['name']:
            raise Refuse(400, 'a location name is required')
    if 'city' in b:
        o['city'] = ls(b['city'], 80)
    if 'kind' in b:
        k = ls(b['kind'], 20).lower()
        if k and k not in KINDS:
            raise Refuse(400, 'kind must be one of ' + ', '.join(KINDS))
        o['kind'] = k
    if 'address' in b:
        o['address'] = ls(b['address'], 300)
    if 'notes' in b:
        o['notes'] = ls(b['notes'], 500)
    return o


def _clash(c, name, id_=MISSING):
    k = lkey(name)
    for l in c.all('locations'):
        if lkey(l.get('name', MISSING)) == k and l.get('id', MISSING) != id_:
            return c.seen('locations', l)
    return None


def _laudit(who, action, target, detail):
    return {'by': who['user'], 'role': who['role'], 'ip': who['ip'], 'action': action, 'target': target, 'detail': detail}


def location_create(r, c):
    who = _who(r)
    o = _fields(r.get('body') or {}, None)
    if _clash(c, o['name']):
        raise Refuse(409, 'location "%s" already exists' % o['name'])
    o['id'] = r.get('new_id')
    o['created_by'] = who['user']
    o['created_at'] = r.get('at')
    return {'puts': [{'c': 'locations', 'o': o}], 'result': {'location': o},
            'audit': _laudit(who, 'location.create', o['id'], {'name': o['name'], 'city': o.get('city', MISSING), 'kind': o.get('kind', MISSING)})}


def location_edit(r, c):
    who, at = _who(r), r.get('at')
    b = r.get('body') or {}
    lid = _string(r.get('id') or '')
    cur = c.get('locations', lid)
    puts = []
    if cur is None and lid.startswith('site:'):
        cur = {'id': r.get('new_id'), 'name': ls(lid[5:]), 'created_by': who['user'], 'created_at': at}
        puts.append({'c': 'locations', 'o': dict(cur)})
    if cur is None:
        raise Refuse(404, 'location not found')
    try:
        o = _fields(b, cur)
        frm = cur.get('name', MISSING)
        if lkey(o['name']) != lkey(frm) and _clash(c, o['name'], cur.get('id', MISSING)):
            raise Refuse(409, 'location "%s" already exists' % o['name'])
    except Refuse as e:
        raise RefuseWith(e.status, e.error, puts)
    o['updated_by'] = who['user']
    o['updated_at'] = at
    puts = [x for x in puts if x['o']['id'] != o['id']] + [{'c': 'locations', 'o': o}]
    renamed = 0
    if o['name'] != frm:
        for a in c.all('assets'):
            if lkey(a.get('site', MISSING)) == lkey(frm):
                x = c.seen('assets', a)
                x['site'] = o['name']
                x['updated_at'] = o['updated_at']
                puts.append({'c': 'assets', 'o': x})
                renamed += 1
    return {'puts': puts, 'result': {'location': o, 'renamed': renamed},
            'audit': _laudit(who, 'location.edit', o['id'], {'from': frm, 'to': o['name'], 'city': o.get('city', MISSING), 'kind': o.get('kind', MISSING), 'assets_renamed': renamed})}


def location_delete(r, c):
    who = _who(r)
    cur = c.get('locations', _string(r.get('id') or ''))
    if cur is None:
        raise Refuse(404, 'location not found')
    name = cur.get('name', MISSING)
    n = sum(1 for a in c.all('assets') if lkey(a.get('site', MISSING)) == lkey(name))
    if n:
        raise Refuse(409, '%d inventory assets are at "%s" - move them first' % (n, 'undefined' if name is MISSING else _to_str(name)))
    return {'puts': [], 'removes': [{'c': 'locations', 'id': cur['id']}], 'result': {},
            'audit': _laudit(who, 'location.delete', cur['id'], {'name': name})}


# ---- Asset ownership ------------------------------------------------------------------------------------------------
CLOSED = ('retired', 'disposed', 'lost')


def os_(v, n=200):
    """s() of ownership.js: controls to spaces, trimmed, then at most n UTF-16 units"""
    t = _trim(_CTRL.sub(' ', _string(v)))
    return _utf16(t, n or 200) if t else ''


def key_of(svc):
    return os_(svc, 120).lower()


def _oaudit(who, action, target, detail):
    def f(k):
        v = who.get(k)
        return v if truthy(v) else ''
    return {'by': f('user'), 'role': f('role'), 'ip': f('ip'), 'action': action, 'target': target, 'detail': detail}


def _active(c):
    out = []
    for a in c.all('assets'):
        st = a.get('status', MISSING)
        if isinstance(st, (list, dict)) or st in _PROTO:
            raise NodeDecides()   # CLOSED[status] of an object literal: String(array) / its prototype
        if not (isinstance(st, str) and st in CLOSED):
            out.append(a)
    return out


class _Own:
    """asset_ownership as Node.js sees it while it writes: each put is visible to the next record of the same call"""

    def __init__(self, c):
        self.c, self.cur = c, {}

    def get(self, id_):
        if id_ in self.cur:
            return self.cur[id_]
        return self.c.get('asset_ownership', id_)

    def put(self, o):
        self.cur[o['id']] = dict(o)


def _assign(r, c, body, who, own, puts, audits):
    raw = body.get('ids', MISSING)
    lst = raw if isinstance(raw, list) else ([raw] if raw is not MISSING and truthy(raw) else [])
    ids = [x for x in (_to_str(v) if v is not None else 'null' for v in lst) if x]
    if not ids:
        raise Refuse(400, 'choose at least one asset')
    if len(ids) > 2000:
        raise Refuse(400, 'at most 2000 assets at once')
    fields = [k for k in ('it_owner', 'business_owner', 'business_service') if k in body]
    if not fields:
        raise Refuse(400, 'set an IT owner, a business owner or a business service')
    reason = os_(body.get('reason', MISSING), 500)
    done, missing = [], []
    for id_ in ids:
        if c.get('assets', id_) is None:
            missing.append(id_)
            continue
        o = {'id': id_}
        o.update(own.get(id_) or {})
        g = lambda k: o[k] if truthy(o.get(k)) else ''   # noqa: E731
        before = {'it_owner': g('it_owner'), 'business_owner': g('business_owner'), 'business_service': g('business_service')}
        for k in fields:
            o[k] = os_(body[k], 120 if k == 'business_service' else 200)
        o['by'] = who['user'] if truthy(who.get('user')) else ''
        o['at'] = r.get('now')
        o['source'] = 'import' if body.get('source') == 'import' else 'manual'
        own.put(o)
        puts.append({'c': 'asset_ownership', 'o': dict(o)})
        done.append(id_)
        audits.append(_oaudit(who, 'asset.ownership', id_, {'before': before, 'after': {'it_owner': g('it_owner'), 'business_owner': g('business_owner'), 'business_service': g('business_service')}, 'reason': reason}))
    return {'updated': len(done), 'not_found': missing}


def _collapse(puts):
    """several puts of one record in one call: the store keeps the last"""
    last = {}
    for x in puts:
        last[(x['c'], x['o']['id'])] = x
    return list(last.values())


def ownership_assign(r, c):
    who = _who(r)
    puts, audits = [], []
    res = _assign(r, c, r.get('body') or {}, who, _Own(c), puts, audits)
    return {'puts': _collapse(puts), 'audits': audits, 'result': res}


def ownership_service(r, c):
    who = _who(r)
    body = r.get('body') or {}
    name = os_(body.get('service', MISSING), 120)
    if not name:
        raise Refuse(400, 'a business service name is required')
    id_ = key_of(name)
    cur = c.get('ownership_services', id_) or {'id': id_, 'service': name}
    g = lambda o, k: o[k] if truthy(o.get(k)) else ''   # noqa: E731
    before = {'business_owner': g(cur, 'business_owner'), 'it_owner': g(cur, 'it_owner')}
    rec = dict(cur)
    rec.update({'service': name, 'by': who['user'] if truthy(who.get('user')) else '', 'at': r.get('now')})
    for k in ('business_owner', 'it_owner'):
        if k in body:
            rec[k] = os_(body[k], 200)
    return {'puts': [{'c': 'ownership_services', 'o': rec}], 'result': rec,
            'audit': _oaudit(who, 'ownership.service', id_, {'service': name, 'before': before, 'after': {'business_owner': g(rec, 'business_owner'), 'it_owner': g(rec, 'it_owner')}})}


def ownership_import(r, c):
    who = _who(r)
    body = r.get('body') or {}
    raw = body.get('rows', MISSING)
    rows = raw if isinstance(raw, list) else ([raw] if raw is not MISSING and truthy(raw) else [])
    if not rows:
        raise Refuse(400, 'no rows')
    if len(rows) > 5000:
        raise Refuse(400, 'at most 5000 rows at once')
    if not all(isinstance(x, dict) for x in rows):
        raise NodeDecides()   # null.asset throws in Node.js; a string row reads as empty there - left to Node.js
    idx = {}

    def add(k, a):
        if k is MISSING or not truthy(k):
            return
        kk = _trim(_to_str(k)).lower()
        if not kk:
            return
        if kk in _PROTO:
            raise NodeDecides()
        idx.setdefault(kk, []).append(a)
    for a in _active(c):
        for f in ('asset_tag', 'serial', 'name', 'mgmt_ip'):
            add(a.get(f, MISSING), a)
    own, puts, audits = _Own(c), [], []
    updated, unmatched, ambiguous = 0, [], []
    for row in rows:
        ref_v = MISSING
        for f in ('asset', 'asset_tag', 'serial', 'name', 'ip'):
            v = row.get(f, MISSING)
            ref_v = v
            if v is not MISSING and truthy(v):
                break
        ref = os_(ref_v, 200)
        if ref.lower() in _PROTO:
            raise NodeDecides()
        hits = idx.get(ref.lower()) or []
        uniq = list(dict.fromkeys(a.get('id') for a in hits))
        if not uniq:
            unmatched.append(ref)
            continue
        if len(uniq) > 1:
            ambiguous.append(ref)
            continue
        b = {'ids': uniq, 'reason': os_(body.get('reason', MISSING), 400) or 'CSV import', 'source': 'import'}
        for k in ('it_owner', 'business_owner', 'business_service'):
            v = row.get(k, MISSING)
            if v is not MISSING and v is not None and _trim(_to_str(v)) != '':
                b[k] = v
        if len(b) <= 3:
            continue
        _assign(r, c, b, who, own, puts, audits)
        updated += 1
    return {'puts': _collapse(puts), 'audits': audits, 'result': {'rows': len(rows), 'updated': updated, 'unmatched': unmatched, 'ambiguous': ambiguous}}


def _guard(fn):
    def run(r):
        try:
            c = _Ctx(r)
        except Exception:
            return {'ok': False, 'error_class': 'protocol', 'error': 'store not readable'}
        try:
            out = fn(r, c)
        except RefuseWith as e:
            out = {'refuse': {'status': e.status, 'error': e.error}, 'puts': e.puts}
        except Refuse as e:
            out = {'refuse': {'status': e.status, 'error': e.error}}
        except NodeDecides:
            return {'node': True}
        out['based_on'] = c.based
        return out
    return run


OPS = {'locations.create': _guard(location_create), 'locations.edit': _guard(location_edit), 'locations.delete': _guard(location_delete),
       'ownership.assign': _guard(ownership_assign), 'ownership.service': _guard(ownership_service), 'ownership.import': _guard(ownership_import)}
