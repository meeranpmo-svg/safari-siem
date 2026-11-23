# Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
"""GRC read routes - migration step 8d (docs/PYTHON-MIGRATION.md), answered from the store files themselves (store.py,
read-only), exactly like engine/grc.js:
  GET /grc/drafts, /grc/drafts/:id                 drafts(r), draft(r)       policy drafts (document bytes never sent)
  GET /grc/drills, /grc/drills/:id                 drills(r), drill(r)       DR drills with RTO / RPO met
  GET /grc/drills/systems, /grc/drills/summary     systems(r), summary(r)    per-system coverage and the summary
Drill dates are typed by people. Node.js reads them with Date.parse, which also accepts forms Python cannot reproduce
exactly ("10/01/2026", "Oct 1 2026"), so a drill date that is not ISO (YYYY-MM-DD[THH:MM[:SS]][Z|±hh:mm]) makes these
operations answer {"node": true} and Node.js answers instead - never a different order or a different "overdue".
Writing (plan, result, sign-off, upload, delete) stays in Node.js, the only writer of the store until step 9.
Standard library only (Python 3.8+).
"""
import calendar
import re

from asset_rules import MISSING, S, T, orv
from jscompat import iso, js_round, num
from store import reader as store_reader

DR_TYPES = ['failover', 'restore', 'backup-restore', 'tabletop', 'full-dr', 'component']
SAMA_DR_REFS = [
    {'ref': 'SAMA CSF 3.3.15', 'area': 'Business Continuity Management'},
    {'ref': 'SAMA CSF 3.3.16', 'area': 'Disaster Recovery'},
    {'ref': 'SAMA CSF 3.3.17', 'area': 'Backup & Restoration'},
    {'ref': 'SAMA BCM Framework', 'area': 'Business Continuity Programme'},
]
SAMA_NOTE = 'SAMA CSF requires business-continuity and recoverability to be tested periodically; a system with no completed drill, or one past its cadence, is flagged overdue.'
MONTH_MS = 2629800000
_ISO = re.compile(r'^\d{4}-\d{2}-\d{2}([T ]\d{2}:\d{2}(:\d{2}(\.\d+)?)?(Z|[+-]\d{2}:?\d{2})?)?$', re.I)


class NotIso(Exception):
    pass


def _col(r, name):
    return store_reader(r['dir']).collection(name)


def d_parse(s):
    """dParse(): Date.parse(String(s || '')) - ISO forms only; anything else hands the answer to Node.js"""
    t = S(orv(s, '')) if s is not MISSING else ''
    if t == '':
        return None
    if not _ISO.match(t.strip()):
        raise NotIso(t)
    v = iso(t.strip())
    if v is None:
        return None
    return calendar.timegm((int(v[0:4]), int(v[5:7]), int(v[8:10]), int(v[11:13]), int(v[14:16]), int(v[17:19]), 0, 0, 0)) * 1000 + int(v[20:23])


def guarded(fn):
    def run(r):
        try:
            return fn(r)
        except NotIso:
            return {'node': True}
    return run


# ---- drafts ---------------------------------------------------------------------------------------------------------
def _strip_doc(d, key):
    if not isinstance(d, dict):
        return d
    c = dict(d)
    if T(c.get(key, MISSING)) and isinstance(c[key], dict):
        c[key] = {k: v for k, v in c[key].items() if k != 'content_b64'}
    return c


def drafts(r):
    items = _col(r, 'grc_drafts').all()
    f = r.get('query') or {}
    if T(f.get('status', MISSING)):
        items = [d for d in items if d.get('status') == f['status']]
    items = sorted(items, key=lambda d: -(num(d.get('updated')) or 0) if T(d.get('updated', MISSING)) else 0)
    return {'items': [_strip_doc(d, 'document') for d in items]}


def draft(r):
    d = _col(r, 'grc_drafts').get(r.get('id'))
    return {'found': d is not None, 'draft': _strip_doc(d, 'document') if d is not None else None}


# ---- drills ---------------------------------------------------------------------------------------------------------
def _n(v):
    x = num(MISSING if v is None else v)
    return x if x is not None else float('nan')


def met(d):
    rto = (_n(d['rto_actual_min']) <= _n(d['rto_target_min'])) if d.get('rto_target_min') is not None and d.get('rto_actual_min') is not None else None
    rpo = (_n(d['rpo_actual_min']) <= _n(d['rpo_target_min'])) if d.get('rpo_target_min') is not None and d.get('rpo_actual_min') is not None else None
    return {'rto': rto, 'rpo': rpo}


def enrich(d):
    out = _strip_doc(d, 'evidence')
    ev = d.get('evidence')
    out.update(met=met(d), has_evidence=bool(T(ev if ev is not None else MISSING) and isinstance(ev, dict) and T(ev.get('filename', MISSING))))
    return out


def _orv(*v):
    for x in v[:-1]:
        if x:
            return x
    return v[-1]


def _when(d):
    return _orv(d_parse(d.get('executed', MISSING)), d_parse(d.get('scheduled', MISSING)), num(d['updated']) if T(d.get('updated', MISSING)) else 0, 0)


def drills(r):
    f = r.get('query') or {}
    items = _col(r, 'grc_drills').all()
    for k in ('status', 'result', 'type'):
        if T(f.get(k, MISSING)):
            items = [d for d in items if d.get(k) == f[k]]
    if T(f.get('system', MISSING)):
        items = [d for d in items if S(orv(d.get('system', MISSING), '')).lower() == S(f['system']).lower()]
    keys = {id(d): _when(d) for d in items}
    items = sorted(items, key=lambda d: -keys[id(d)])
    return {'items': [enrich(d) for d in items], 'types': DR_TYPES, 'sama_refs': SAMA_DR_REFS}


def drill(r):
    d = _col(r, 'grc_drills').get(r.get('id'))
    return {'found': d is not None, 'drill': enrich(d) if d is not None else None}


def _systems(all_, now):
    by = {}
    for d in all_:
        by.setdefault(S(orv(d.get('system', MISSING), '—')), []).append(d)
    out = []
    for sys_ in sorted(by, key=lambda s: s.encode('utf-16-be', 'surrogatepass')):
        lst = by[sys_]
        done = [d for d in lst if d.get('status') == 'completed']
        ex = {id(d): (d_parse(d.get('executed', MISSING)) or 0) for d in done}
        done.sort(key=lambda d: -ex[id(d)])
        last = done[0] if done else None
        freq = _orv(last.get('frequency_months'), 12) if last else _orv(lst[0].get('frequency_months'), 12)
        last_ms = d_parse(last.get('executed', MISSING)) if last else None
        due = last_ms + freq * MONTH_MS if last_ms and freq else None
        m = met(last) if last else {'rto': None, 'rpo': None}
        so = last.get('signoff') if last else None
        out.append({'system': sys_, 'drills': len(lst), 'completed': len(done),
                    'last': {k: last.get(k, MISSING) for k in ('id', 'executed', 'result', 'type')} if last else None,
                    'last_result': last.get('result', MISSING) if last else None, 'frequency_months': freq, 'next_due_ms': due,
                    'overdue': (now > due) if due is not None else True, 'tested': bool(last), 'rto_met': m['rto'], 'rpo_met': m['rpo'],
                    'signed_off': bool(isinstance(so, dict) and T(so.get('by', MISSING))) if last else False})
    return out


def systems(r):
    return {'systems': _systems(_col(r, 'grc_drills').all(), r.get('now'))}


def summary(r):
    all_ = _col(r, 'grc_drills').all()
    now = r.get('now')
    by_status = {'planned': 0, 'in-progress': 0, 'completed': 0, 'cancelled': 0}
    by_result = {'pass': 0, 'partial': 0, 'fail': 0}
    rto_met = rto_meas = rpo_met = rpo_meas = signed = awaiting = 0
    for d in all_:
        st = S(d.get('status', MISSING))
        by_status[st] = by_status.get(st, 0) + 1
        if d.get('status') == 'completed' and T(d.get('result', MISSING)):
            rs = S(d['result'])
            by_result[rs] = by_result.get(rs, 0) + 1
        m = met(d)
        if m['rto'] is not None:
            rto_meas += 1
            rto_met += 1 if m['rto'] else 0
        if m['rpo'] is not None:
            rpo_meas += 1
            rpo_met += 1 if m['rpo'] else 0
        if d.get('status') == 'completed':
            so = d.get('signoff')
            if isinstance(so, dict) and T(so.get('by', MISSING)):
                signed += 1
            else:
                awaiting += 1
    sy = _systems(all_, now)
    up = [d for d in all_ if d.get('status') == 'planned' and d_parse(d.get('scheduled', MISSING)) and d_parse(d.get('scheduled', MISSING)) >= now]
    up.sort(key=lambda d: d_parse(d.get('scheduled', MISSING)))
    upcoming = [{k: d.get(k, MISSING) for k in ('id', 'title', 'system', 'type', 'scheduled')} for d in up[:5]]
    return {'total': len(all_), 'by_status': by_status, 'by_result': by_result,
            'rto': {'measured': rto_meas, 'met': rto_met, 'pct': js_round(rto_met / rto_meas * 100) if rto_meas else None},
            'rpo': {'measured': rpo_meas, 'met': rpo_met, 'pct': js_round(rpo_met / rpo_meas * 100) if rpo_meas else None},
            'signed_off': signed, 'awaiting_signoff': awaiting,
            'systems': {'total': len(sy), 'tested': len([s for s in sy if s['tested']]), 'overdue': len([s for s in sy if s['overdue']])},
            'upcoming': upcoming, 'sama_note': SAMA_NOTE, 'generated': now}


OPS = {'grc.drafts': drafts, 'grc.draft': draft, 'grc.drills': guarded(drills), 'grc.drill': drill, 'grc.drill_systems': guarded(systems), 'grc.drill_summary': guarded(summary)}
