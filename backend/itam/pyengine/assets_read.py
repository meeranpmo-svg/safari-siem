# Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
"""The asset read routes - migration step 8c (docs/PYTHON-MIGRATION.md), answered from the store files themselves
(store.py, read-only), exactly like engine/routes.js over engine/assets.js and engine/licences.js:
  GET /assets          list(r)       filters type / status / site / owner / source / networked / text, limit
  GET /assets/:id      detail(r)     the asset, its relationships, software, lifecycle, seen by
  GET /lookup          lookup(r)     by asset tag or serial (everyone)
  GET /software        software(r)   the software roll-up of every asset not disposed
  GET /licences        licences(r)   each active licence with its usage (+ Microsoft 365 assigned seats when the licence
                                     sync add-on is installed: r.m365)
  GET /cmdb            cmdb(r)       one asset's graph, or every relationship
Creating, editing, moving, assigning and the lifecycle actions stay in Node.js, the only writer of the store until step 9.
Standard library only (Python 3.8+).
"""
from asset_rules import MISSING, S, T, g, licence_compliance, orv, rollup
from jscompat import num
from store import reader as store_reader

INTERNAL = ('prov', 'locked')   # provenance / lock: internal bookkeeping, never on the API


def _store(r):
    return store_reader(r['dir'])


def public(a):
    return {k: v for k, v in a.items() if k not in INTERNAL} if isinstance(a, dict) else None


def _limit(v, dflt, mx):
    """limitOf(): Number(v), a positive integer → min(n, max), else the default"""
    n = num(MISSING if v is None else v)
    if n is None or isinstance(n, bool) or not float(n).is_integer() or n <= 0:
        return dflt
    return min(int(n), mx)


def _q(r):
    q = r.get('query')
    return q if isinstance(q, dict) else {}


def list_(r):
    q = _q(r)
    text = S(orv(q.get('q', MISSING), '')).lower()

    def keep(a):
        for k in ('type', 'status', 'site', 'owner'):
            if T(q.get(k, MISSING)) and a.get(k, MISSING) != q[k]:
                return False
        if T(q.get('source', MISSING)) and not any(isinstance(s, dict) and s.get('source') == q['source'] for s in (a.get('sources') if isinstance(a.get('sources'), list) else [])):
            return False
        if q.get('networked') == '1' and not T(a.get('networked', MISSING)):
            return False
        if q.get('networked') == '0' and T(a.get('networked', MISSING)):
            return False
        if text:
            hay = ' '.join(S(orv(a.get(k, MISSING), '')) for k in ('name', 'asset_tag', 'serial', 'model', 'vendor')).lower()
            if text not in hay:
                return False
        return True
    rows = [public(a) for a in _store(r).collection('assets').all() if keep(a)]
    return {'total': len(rows), 'assets': rows[:_limit(q.get('limit'), 500, 5000)]}


def detail(r):
    s = _store(r)
    i = r.get('id')
    a = s.collection('assets').get(i)
    if a is None:
        return {'found': False}
    rels = [{k: v for k, v in x.items() if k != 'key'} for x in s.collection('relationships').all() if x.get('from') == i or x.get('to') == i]
    seen = []
    for sg in (a.get('sources') if T(a.get('sources', MISSING)) and isinstance(a.get('sources'), list) else []):
        sg = sg if isinstance(sg, dict) else {}
        seen.append({k: sg[k] for k in ('source', 'source_id', 'first_seen', 'last_seen') if k in sg})
    return {'found': True, 'detail': {'asset': public(a), 'relationships': rels, 'software': orv(a.get('software', MISSING), []), 'lifecycle': orv(a.get('lifecycle', MISSING), []), 'seen_by': seen}}


def lookup(r):
    t = S(orv(r.get('tag', MISSING), '')).strip().lower()
    hits = []
    if t:
        for a in _store(r).collection('assets').all():
            if (T(a.get('asset_tag', MISSING)) and S(a['asset_tag']).lower() == t) or (T(a.get('serial', MISSING)) and S(a['serial']).lower() == t):
                hits.append({k: a[k] for k in ('id', 'asset_tag', 'name', 'type', 'status', 'owner', 'custodian', 'department', 'site', 'location') if k in a})
    return {'tag': r.get('tag', MISSING), 'found': len(hits), 'assets': hits}


def software(r):
    return {'software': rollup([a for a in _store(r).collection('assets').all() if a.get('status') != 'disposed'])}


def licences(r):
    s = _store(r)
    rolled = rollup([a for a in s.collection('assets').all() if a.get('status') not in ('disposed', 'retired')])
    lic = s.collection('licences')
    out = []
    for l0 in lic.all():
        if l0.get('status') == 'inactive':
            continue
        c = licence_compliance(l0, rolled)
        l = dict(l0, used=c['used'], compliance=c['compliance'], delta=c['delta'], products=c['products'])
        rec = lic.get(l.get('id'))
        m = rec.get('m365') if r.get('m365') and isinstance(rec, dict) and rec.get('source') == 'm365' else None
        if T(m if m is not None else MISSING):
            used = num(m.get('consumed', MISSING)) if isinstance(m, dict) else None
            used = used or 0
            seats = l.get('seats', MISSING)
            none = seats is None or seats is MISSING
            l.update(used=used, delta=None if none else used - seats, compliance='unknown' if none else 'over' if used > seats else 'under' if used < seats else 'ok',
                     products=['assigned in Microsoft 365'], m365=m)
        out.append(l)
    return {'licences': out}


def cmdb(r):
    q = _q(r)
    rels = _store(r).collection('relationships').all()
    if T(q.get('asset', MISSING)):
        aid, conf = q['asset'], q.get('confirmed') == '1'
        nodes, edges = [aid], []
        for x in rels:
            if conf and x.get('status') != 'confirmed':
                continue
            if x.get('from') == aid or x.get('to') == aid:
                for n in (x.get('from'), x.get('to')):
                    if n not in nodes:
                        nodes.append(n)
                edges.append(x)
        return {'graph': {'center': aid, 'nodes': nodes, 'edges': edges}}
    return {'relationships': [{k: v for k, v in x.items() if k != 'key'} for x in rels]}
