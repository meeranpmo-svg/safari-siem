# Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
"""RoPA workflow automation (engine/pdpl-ropa-flow.js): the machine learning that moves a RoPA campaign along without guessing.

op ropa.flow  {campaign: {id, name, due, created_at, departments: {name: {steward, status, submitted_at, ...}}},
               drafts: [{id, department, name, purpose, legal_basis, data_categories[], subjects, systems[], retention_months,
                         recipients[], flags..., updated_at, status}],
               events: [{department, at, kind}],   # every save / submit / return / approve, from the audit of the campaign
               records: [{id, owner, name, systems[], data_categories[], retention_months}],   # the approved register
               catalog: [{system, department, categories[]}],   # Data Catalog systems with personal data
               templates: {dept_key: [{key, name, data_categories[], systems_hint[]}]}, dept_keys: {name: key}, now}
  forecast   per department: progress now, progress per day over its own saves (needs 2 days of activity), the day it reaches
             100% at that pace and whether that is after the due date -> on track / at risk / late / not started
  risk       per draft: a 0-100 score from the data and the processing (sensitive / credit categories, transfer outside the Kingdom,
             reinsurance outside, automated decisions, profiling, large-scale monitoring, telematics, no retention), the reasons, and
             whether a DPIA is required (Implementing Regulation Art. 25 triggers)
  duplicates pairs of drafts / register records in different departments that describe the same processing (Jaccard over systems,
             categories and purpose words >= 0.6) - a question for the DPO, never merged automatically
  retention  drafts whose retention is far above what the register keeps for the same data categories (> 2x the median, needs 3)
  autodraft  per department: systems the Data Catalog found holding personal data that no draft or record covers, each matched to
             the closest template activity of the department (shared categories, name words) - a PROPOSED draft a steward accepts
"""

import math
import re
import statistics

DAY = 86400000
SENSITIVE = {'health', 'biometric', 'genetic', 'criminal', 'religious', 'beliefs', 'ethnic', 'parentage'}
STOP = {'the', 'and', 'of', 'for', 'to', 'a', 'an', 'in', 'on', 'with', 'by', 'data', 'customer', 'customers', 'process', 'processing', 'management'}


def _n(s):
    return re.sub(r'[^a-z0-9]+', ' ', str(s or '').lower()).strip()


def _words(s):
    return {w for w in _n(s).split() if len(w) > 2 and w not in STOP}


def _ms(v):
    if isinstance(v, (int, float)):
        return float(v)
    try:
        import datetime
        s = str(v or '')
        if len(s) == 10:
            s += 'T00:00:00+00:00'
        return datetime.datetime.fromisoformat(s.replace('Z', '+00:00')).timestamp() * 1000.0
    except Exception:  # noqa: BLE001 - an unreadable date is "not known"
        return None


def _jac(a, b):
    a, b = set(a), set(b)
    return len(a & b) / float(len(a | b)) if a | b else 0.0


def risk(d):
    cats = set(d.get('data_categories') or [])
    pts, why = 0, []
    sens = cats & SENSITIVE
    if sens:
        pts += 30
        why.append('sensitive data (%s)' % ', '.join(sorted(sens)))
    if 'credit' in cats:
        pts += 15
        why.append('credit data')
    for f, p, t in (('transfer_outside', 20, 'transferred outside the Kingdom'), ('reinsurance_outside', 15, 'shared with reinsurers outside the Kingdom'),
                    ('automated_decision', 15, 'solely automated decisions'), ('automated_underwriting', 10, 'automated underwriting'),
                    ('profiling', 10, 'profiling'), ('fraud_scoring', 10, 'fraud scoring'), ('large_scale_monitoring', 15, 'large-scale monitoring'), ('telematics', 10, 'telematics / location')):
        if d.get(f):
            pts += p
            why.append(t)
    if not d.get('retention_months'):
        pts += 5
        why.append('no retention period')
    score = min(100, pts)
    dpia = bool(sens) or bool(d.get('automated_decision')) or bool(d.get('large_scale_monitoring')) or (len(d.get('systems') or []) >= 2 and bool(sens or 'credit' in cats)) or bool(d.get('profiling'))
    return {'score': score, 'level': 'high' if score >= 50 else 'medium' if score >= 25 else 'low', 'why': why, 'dpia_required': dpia}


def op_flow(req):
    c = req.get('campaign') or {}
    now = float(req.get('now') or 0)
    due = _ms(c.get('due'))
    drafts = [d for d in (req.get('drafts') or []) if d.get('status') != 'removed']
    events = req.get('events') or []
    records = req.get('records') or []
    out = {'ok': True}

    # ---- forecast per department
    fc = {}
    for name, st in (c.get('departments') or {}).items():
        mine = [d for d in drafts if d.get('department') == name]
        prog = round(sum(d.get('complete') or 0 for d in mine) / len(mine)) if mine else 0
        status = st.get('status') or ('in_progress' if mine else 'not_started')
        ev = sorted([e['at'] for e in events if e.get('department') == name and e.get('at')])
        r = {'department': name, 'progress': prog, 'status': status, 'activity_days': 0}
        if status == 'approved':
            r.update(verdict='done', text='approved')
        elif status == 'submitted':
            r.update(verdict='waiting for review', text='submitted - the DPO reviews')
        elif not ev:
            late = bool(due and now > due)
            r.update(verdict='late' if late else 'not started', text='no activity yet' + (' and the due date has passed' if late else ''))
        else:
            first, span = ev[0], max((ev[-1] - ev[0]) / DAY, 0.0)
            days = len({int(x // DAY) for x in ev})
            r['activity_days'] = days
            if days >= 2 and span > 0 and prog > 0:
                pace = prog / max((now - first) / DAY, 1.0)
                left = (100 - prog) / pace if pace > 0 else None
                eta = now + left * DAY if left is not None else None
                r.update(pace_per_day=round(pace, 1), eta=eta)
                if due and now > due:
                    r.update(verdict='late', text='past the due date at %d%%' % prog)
                elif due and eta and eta > due:
                    r.update(verdict='at risk', text='at %.1f%% a day it finishes %d day(s) after the due date' % (pace, math.ceil((eta - due) / DAY)))
                else:
                    r.update(verdict='on track', text='at %.1f%% a day it finishes in time' % pace)
            else:
                r.update(verdict='late' if due and now > due else 'early days', text='needs activity on 2 days to forecast (%d so far)' % days)
        fc[name] = r
    out['forecast'] = fc

    # ---- risk per draft
    out['risk'] = {d['id']: risk(d) for d in drafts}

    # ---- duplicates across departments
    items = [('draft', d['id'], d.get('department'), d.get('name'), d) for d in drafts] + [('record', r['id'], r.get('owner'), r.get('name'), r) for r in records]
    dup = []
    for i in range(len(items)):
        for j in range(i + 1, len(items)):
            a, b = items[i], items[j]
            if _n(a[2]) == _n(b[2]) or (a[0] == 'record' and b[0] == 'record'):
                continue
            da, db = a[4], b[4]
            sa, sb = {_n(x) for x in da.get('systems') or []}, {_n(x) for x in db.get('systems') or []}
            if not (sa & sb):
                continue
            score = 0.5 * _jac(sa, sb) + 0.3 * _jac(da.get('data_categories') or [], db.get('data_categories') or []) + 0.2 * _jac(_words(da.get('purpose') or da.get('name')), _words(db.get('purpose') or db.get('name')))
            if score >= 0.6:
                dup.append({'a': {'kind': a[0], 'id': a[1], 'department': a[2], 'name': a[3]}, 'b': {'kind': b[0], 'id': b[1], 'department': b[2], 'name': b[3]}, 'score': round(score, 2),
                            'text': 'the same systems and data in two departments - one activity with a shared owner, or two different purposes?'})
    dup.sort(key=lambda x: -x['score'])
    out['duplicates'] = dup[:30]

    # ---- retention outliers against the register
    ret = []
    for d in drafts:
        m = d.get('retention_months')
        if not m:
            continue
        cats = set(d.get('data_categories') or [])
        peers = [r.get('retention_months') for r in records if r.get('retention_months') and cats & set(r.get('data_categories') or [])]
        if len(peers) >= 3:
            med = statistics.median(peers)
            if m > 2 * med:
                ret.append({'id': d['id'], 'department': d.get('department'), 'name': d.get('name'), 'months': m, 'usual': med,
                            'text': '%d months against a usual %g for the same data - keep only as long as the purpose needs (PDPL Art. 18)' % (m, med)})
    out['retention'] = ret

    # ---- autodraft: uncovered catalog systems matched to a template
    tpls = req.get('templates') or {}
    keys = req.get('dept_keys') or {}
    covered = {}
    for d in drafts:
        for s in d.get('systems') or []:
            covered.setdefault(_n(d.get('department')), set()).add(_n(s))
    for r in records:
        for s in r.get('systems') or []:
            covered.setdefault(_n(r.get('owner')), set()).add(_n(s))
    ad = {}
    for x in req.get('catalog') or []:
        dep = x.get('department')
        name = next((n for n in (c.get('departments') or {}) if _n(n) == _n(dep)), None)
        if not name or _n(x.get('system')) in covered.get(_n(name), set()):
            continue
        best, bs = None, 0.0
        for t in tpls.get(keys.get(name) or '', []):
            s = 0.7 * _jac(x.get('categories') or [], t.get('data_categories') or []) + 0.3 * _jac(_words(x.get('system')), _words(t.get('name')) | set(_n(' '.join(t.get('systems_hint') or [])).split()))
            if s > bs:
                best, bs = t, s
        ad.setdefault(name, []).append({'system': x.get('system'), 'categories': x.get('categories') or [], 'template': best.get('key') if best and bs >= 0.2 else None,
                                        'template_name': best.get('name') if best and bs >= 0.2 else None, 'confidence': round(bs, 2),
                                        'text': ('closest template: %s (%.0f%%)' % (best.get('name'), bs * 100)) if best and bs >= 0.2 else 'no close template - start from the system'})
    out['autodraft'] = ad
    out['totals'] = {'at_risk': sum(1 for v in fc.values() if v.get('verdict') in ('at risk', 'late')), 'dpia_required': sum(1 for v in out['risk'].values() if v['dpia_required']),
                     'duplicates': len(out['duplicates']), 'retention': len(ret), 'proposed_drafts': sum(len(v) for v in ad.values())}
    return out


OPS = {'ropa.flow': op_flow}
