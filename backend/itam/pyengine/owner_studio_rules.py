# Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
"""Accountability Studio rules (engine/owner-studio.js): who owns each asset, and where the register disagrees with its sources -
with machine learning that SUGGESTS and explains; a person applies every owner and decides every difference.

op owner.studio  {rows, assets, relationships, issues, decisions, freshness, blocked}
  suggestions  a missing IT owner / business owner / business service learned from evidence, strongest first:
                 dependency  the CIs it depends on / is installed on / is a member of (CMDB) share one value
                 peers       3+ assets with the same name prefix in the same subnet share one value (80 %+)
                 department  3+ assets of the same department share one business owner (80 %+)
               confidence = Laplace (agree + 1) / (n + 2); nothing below 0.7 is offered. The evidence is the counts.
  owners       how many assets each IT owner carries, and the share of the largest (concentration)
  reconcile    every open difference with a priority (severity, the asset's dependents) and a recommendation - fix or accept -
               learned from how people decided this kind of difference before (3+ decisions), else the stated default;
               clusters (the same kind from the same source, 5+) that point to one cause at the source; stale sources.
"""
import re

FIELDS = ('it_owner', 'business_owner', 'business_service')
LABEL = {'it_owner': 'IT owner', 'business_owner': 'business owner', 'business_service': 'business service'}
SEV = {'bad': 30, 'warn': 15, 'info': 5}


def prefix(name):
    m = re.match(r'^([A-Za-z]{2,})[-_ .]?', str(name or ''))
    return m.group(1).upper() if m else None


def net24(ip):
    p = str(ip or '').split('.')
    return '.'.join(p[:3]) if len(p) == 4 and all(x.isdigit() for x in p) else None


def op_studio(req):
    rows = [r for r in (req.get('rows') or []) if r.get('id')]
    by = {r['id']: r for r in rows}
    blocked = set(req.get('blocked') or [])
    sugg = []

    def offer(r, field, value, conf, kind, why):
        key = '%s|%s|%s' % (field, r['id'], value)
        if key in blocked or conf < 0.7:
            return
        sugg.append({'key': key, 'id': r['id'], 'name': r.get('name'), 'field': field, 'label': LABEL[field], 'value': value,
                     'confidence': round(conf, 2), 'kind': kind, 'why': why})

    # dependency evidence (CMDB): what the asset depends on / is installed on / is a member of
    deps = {}
    for x in req.get('relationships') or []:
        if x.get('type') in ('depends_on', 'installed_on', 'member_of') and x.get('status') == 'confirmed':
            deps.setdefault(x.get('from'), []).append(x.get('to'))
            deps.setdefault(x.get('to'), []).append(x.get('from'))
    # peer groups and departments
    peers, dept = {}, {}
    for r in rows:
        p, n = prefix(r.get('name')), net24(r.get('mgmt_ip'))
        if p and n:
            peers.setdefault((p, n), []).append(r)
        if r.get('department'):
            dept.setdefault(r['department'], []).append(r)

    def vote(group, field, me):
        d = {}
        for g in group:
            if g['id'] != me and g.get(field):
                d[g[field]] = d.get(g[field], 0) + 1
        if not d:
            return None
        n = sum(d.values())
        v, c = max(d.items(), key=lambda kv: kv[1])
        return v, c, n

    for r in rows:
        done = set()
        for field in FIELDS:
            if r.get(field):
                continue
            nb = [by[i] for i in deps.get(r['id'], []) if i in by]
            v = vote(nb, field, r['id'])
            if v and v[1] / float(v[2]) >= 0.8:
                offer(r, field, v[0], (v[1] + 1.0) / (v[2] + 2.0) + 0.1, 'dependency', '%d of %d confirmed CMDB neighbour(s) (%s) have %s "%s"'
                      % (v[1], v[2], ', '.join(sorted(set(str(x.get('name')) for x in nb))[:3]), LABEL[field], v[0]))
                done.add(field)
                continue
            p, n = prefix(r.get('name')), net24(r.get('mgmt_ip'))
            grp = peers.get((p, n)) if p and n else None
            v = vote(grp or [], field, r['id'])
            if v and v[2] >= 3 and v[1] / float(v[2]) >= 0.8:
                offer(r, field, v[0], (v[1] + 1.0) / (v[2] + 2.0), 'peers', '%d of %d assets named %s-* in %s.0/24 have %s "%s"' % (v[1], v[2], p, n, LABEL[field], v[0]))
                done.add(field)
                continue
            if field == 'business_owner' and r.get('department'):
                v = vote(dept.get(r['department'], []), field, r['id'])
                if v and v[2] >= 3 and v[1] / float(v[2]) >= 0.8:
                    offer(r, field, v[0], (v[1] + 1.0) / (v[2] + 2.0), 'department', '%d of %d %s assets have business owner "%s"' % (v[1], v[2], r['department'], v[0]))
    for p in req.get('ai') or []:
        if p.get('key') not in blocked:
            sugg.append(p)
    sugg.sort(key=lambda x: -(x.get('confidence') or 0))

    # owner load
    load = {}
    for r in rows:
        if r.get('it_owner'):
            load[r['it_owner']] = load.get(r['it_owner'], 0) + 1
    owned = sum(load.values())
    owners = sorted([{'owner': o, 'assets': c, 'share': round(100.0 * c / owned, 1) if owned else 0} for o, c in load.items()], key=lambda x: -x['assets'])[:30]

    # reconciliation: learn per kind how people decided
    hist = {}
    for d in req.get('decisions') or []:
        h = hist.setdefault(d.get('kind') or '?', {'fix': 0, 'accept': 0})
        if d.get('decision') in h:
            h[d['decision']] += 1
    dependents = {}
    for x in req.get('relationships') or []:
        if x.get('type') in ('runs_on', 'depends_on', 'installed_on'):
            dependents[x.get('to')] = dependents.get(x.get('to'), 0) + 1
    out_issues = []
    for i in req.get('issues') or []:
        if i.get('accepted'):
            continue
        h = hist.get(i.get('kind'), {'fix': 0, 'accept': 0})
        n = h['fix'] + h['accept']
        if n >= 3:
            rec = 'fix' if h['fix'] >= h['accept'] else 'accept'
            conf = round((max(h['fix'], h['accept']) + 1.0) / (n + 2.0), 2)
            basis = 'learned: people %s %d of %d "%s" differences' % ('fixed' if rec == 'fix' else 'accepted', max(h['fix'], h['accept']), n, i.get('kind'))
        else:
            rec = 'fix' if i.get('fix') else 'review'
            conf = None
            basis = ('default: an automatic fix exists' if i.get('fix') else 'no automatic fix - correct it at the source or accept it') + ' (fewer than 3 past decisions of this kind)'
        dep = dependents.get(i.get('asset_id'), 0)
        prio = SEV.get(i.get('sev') or 'warn', 15) + min(30, 6 * dep) + (10 if i.get('kind') in ('retired-seen', 'duplicate-ip', 'not-in-inventory') else 0)
        out_issues.append(dict(i, recommend=rec, recommend_confidence=conf, recommend_basis=basis, priority=min(100, prio), dependents=dep))
    out_issues.sort(key=lambda x: -x['priority'])
    cl = {}
    for i in out_issues:
        k = (i.get('source') or '?', i.get('kind') or '?')
        cl[k] = cl.get(k, 0) + 1
    clusters = [{'source': k[0], 'kind': k[1], 'count': c, 'hint': '%d "%s" differences all reported by %s - one setting at the source (naming, DNS suffix, OS string) may explain them; fix it there once instead of %d times' % (c, k[1], k[0], c)}
                for k, c in cl.items() if c >= 5]
    stale = [f for f in (req.get('freshness') or []) if (f.get('age_h') or 0) > 48 or f.get('error')]

    n = len(rows)
    cnt = lambda f: len([r for r in rows if r.get(f)])
    return {'ok': True,
            'summary': {'assets': n, 'it_pct': round(100.0 * cnt('it_owner') / n, 1) if n else None, 'business_pct': round(100.0 * cnt('business_owner') / n, 1) if n else None,
                        'service_pct': round(100.0 * cnt('business_service') / n, 1) if n else None,
                        'both_pct': round(100.0 * len([r for r in rows if r.get('it_owner') and r.get('business_owner')]) / n, 1) if n else None,
                        'suggestions': len(sugg), 'issues': len(out_issues), 'clusters': len(clusters), 'stale_sources': len(stale),
                        'top_owner_share': owners[0]['share'] if owners else None},
            'suggestions': sugg[:500], 'owners': owners, 'issues': out_issues[:500], 'clusters': sorted(clusters, key=lambda c: -c['count']),
            'stale': stale, 'learned': {'kinds': {k: v for k, v in hist.items()}, 'note': 'Recommendations learned from %d past reconciliation decision(s); owner suggestions from the CMDB, name / subnet peers and departments - a person applies each one.' % sum(v['fix'] + v['accept'] for v in hist.values())}}


OPS = {'owner.studio': op_studio}
