# Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
"""Discovery Studio rules (engine/discovery-studio.js): what Asset Discovery found, what to do with it, how the runs and the
credentials behave - from the platform's own records only (discovered devices, past decisions, runs, credential metadata; never a
secret).

op discovery.studio  {devices, decided, runs, scopes, credentials, now}
  recommend   per NEW device, with its reasons and a confidence:
                merge    a strong duplicate in IT Asset Management (MAC / serial) - merge, do not create a second asset
                review   a weak duplicate, or seen once with no identity (no host name, MAC, serial or vendor)
                approve  an identity and either seen more than once or classified with confidence >= 0.7
                ignore   only when past decisions say so: naive Bayes over the devices people already approved or ignored
                         (type, vendor, site, methods - Laplace smoothing); needs 10+ past decisions and P(ignore) >= 0.8.
              The learnt part also lifts or lowers "approve" and is shown with how many decisions it rests on.
  groups      the new devices grouped by (recommendation, type, vendor) - one bulk action per group, largest first.
  runs        per scope: devices seen per run against the median of the previous runs - a drop of 40 % or more (with 3+ runs) is
              flagged (a credential, route or firewall changed), a jump of 50 % too; failure rate and error classes per method.
  credentials health 0-100 per credential, every point named: last test failed 30, never tested 15, not used by any scope 10,
              older than 365 days 20 (180 days 10), its method failed in the last runs of the scopes that use it 25.
  coverage    hosts that expose SSH / a database listener / storage but whose scope has no credential for it - which scope needs one.
"""

import math
import datetime as dt

DAY = 86400.0


def _ts(v):
    try:
        return (dt.datetime.strptime(str(v)[:19], '%Y-%m-%dT%H:%M:%S') - dt.datetime(1970, 1, 1)).total_seconds()
    except (ValueError, TypeError):
        return None


def _feat(d):
    f = ['type=' + str(d.get('type') or 'unknown').lower(), 'vendor=' + str(d.get('vendor') or 'none').lower()[:40], 'site=' + str(d.get('site') or 'none').lower()]
    for m in sorted(d.get('methods_seen') or []):
        f.append('m=' + m)
    return f


def _nb(decided):
    """naive Bayes counts over past decisions: approved / ignored"""
    cls = {'approved': {}, 'ignored': {}}
    tot = {'approved': 0, 'ignored': 0}
    for d in decided:
        c = 'ignored' if d.get('status') == 'ignored' else 'approved'
        tot[c] += 1
        for f in _feat(d):
            cls[c][f] = cls[c].get(f, 0) + 1
    vocab = set(cls['approved']) | set(cls['ignored'])
    def p_ignore(d):
        n = tot['approved'] + tot['ignored']
        if n < 10 or not tot['ignored'] or not tot['approved']:
            return None
        lp = {}
        for c in ('approved', 'ignored'):
            lp[c] = math.log(tot[c] / float(n))
            for f in _feat(d):
                lp[c] += math.log((cls[c].get(f, 0) + 1.0) / (tot[c] + len(vocab) + 1.0))
        m = max(lp.values())
        e = {c: math.exp(v - m) for c, v in lp.items()}
        return e['ignored'] / (e['approved'] + e['ignored'])
    return p_ignore, tot


def op_studio(req):
    now = (req.get('now') or 0) / 1000.0
    devs = req.get('devices') or []
    decided = req.get('decided') or []
    p_ignore, tot = _nb(decided)
    nd = tot['approved'] + tot['ignored']
    out = []
    for d in devs:
        if d.get('status') != 'new':
            continue
        why, rec, conf = [], 'review', 0.5
        dups = d.get('duplicates') or []
        strong = [x for x in dups if x.get('strength') == 'strong']
        ident = [k for k in ('hostname', 'mac', 'serial', 'vendor') if d.get(k)]
        seen = int(d.get('seen_count') or 1)
        c = d.get('confidence')
        try:
            c = float(c) if c is not None else None
        except (TypeError, ValueError):
            c = None
        if c is not None and c <= 0:
            c = None   # 0 = the classifier did not decide: "not classified", never a confidence of zero
        pi = p_ignore(d) if p_ignore else None
        if strong:
            rec, conf = 'merge', 0.95
            why.append('the same %s as %s already in IT Asset Management' % ('/'.join(strong[0].get('by') or ['identity']), strong[0].get('name') or strong[0].get('asset_id')))
        elif dups:
            rec, conf = 'review', 0.6
            why.append('looks like %s (weak match on %s) - check before adding' % (dups[0].get('name') or dups[0].get('asset_id'), '/'.join(dups[0].get('by') or ['name'])))
        elif pi is not None and pi >= 0.8:
            rec, conf = 'ignore', round(pi, 2)
            why.append('people ignored devices like this before (%d%% of %d past decisions point that way)' % (round(pi * 100), nd))
        elif not ident and seen <= 1:
            rec, conf = 'review', 0.4
            why.append('seen once and no host name, MAC, serial or vendor - possibly a transient address')
        elif ident and (seen >= 2 or (c is not None and c >= 0.7)):
            rec = 'approve'
            conf = 0.7 + (0.1 if seen >= 3 else 0) + (0.1 if c is not None and c >= 0.85 else 0)
            why.append('identified by %s%s' % (', '.join(ident), ', seen %d times' % seen if seen >= 2 else ', classified with confidence %.2f' % c))
            if pi is not None:
                if pi <= 0.2:
                    conf = min(0.99, conf + 0.05)
                    why.append('similar devices were approved before (%d past decisions)' % nd)
                elif pi >= 0.5:
                    conf -= 0.15
                    why.append('but %d%% of similar past decisions were to ignore' % round(pi * 100))
        else:
            rec, conf = 'review', 0.5
            why.append('identity: %s; seen %d time(s)%s' % (', '.join(ident) or 'none', seen, '' if c is None else ', classification confidence %.2f' % c))
        if d.get('rogue'):
            why.append('flagged ROGUE: unknown on a managed network - investigate before approving')
            if rec == 'approve':
                rec, conf = 'review', 0.5
        out.append({'id': d.get('id'), 'ip': d.get('ip'), 'hostname': d.get('hostname'), 'mac': d.get('mac'), 'vendor': d.get('vendor'), 'type': d.get('type') or 'unknown', 'os': d.get('os'),
                    'site': d.get('site'), 'scope_id': d.get('scope_id'), 'seen_count': seen, 'first_seen': d.get('first_seen'), 'last_seen': d.get('last_seen'), 'methods': d.get('methods_seen') or [],
                    'confidence': c, 'rogue': bool(d.get('rogue')), 'recommend': rec, 'rec_confidence': round(max(0.05, min(0.99, conf)), 2), 'why': why, 'p_ignore': None if pi is None else round(pi, 2),
                    'merge_into': (strong[0].get('asset_id') if strong else None), 'duplicates': dups[:3]})
    groups = {}
    for r in out:
        k = (r['recommend'], r['type'], str(r['vendor'] or 'unknown vendor'))
        g = groups.setdefault(k, {'recommend': r['recommend'], 'type': r['type'], 'vendor': k[2], 'ids': [], 'avg_conf': 0.0})
        g['ids'].append(r['id'])
        g['avg_conf'] += r['rec_confidence']
    gl = []
    for g in groups.values():
        g['count'] = len(g['ids'])
        g['avg_conf'] = round(g['avg_conf'] / g['count'], 2)
        gl.append(g)
    order = {'merge': 0, 'approve': 1, 'ignore': 2, 'review': 3}
    gl.sort(key=lambda g: (order[g['recommend']], -g['count']))

    # ---- runs: per scope trend + anomaly, per method failures
    scopes = {s.get('id'): s for s in (req.get('scopes') or [])}
    runs = sorted(req.get('runs') or [], key=lambda r: str(r.get('started_at') or ''))
    by_scope, meth = {}, {}
    for r in runs:
        by_scope.setdefault(r.get('scope_id'), []).append(r)
        for m, st in (r.get('stats') or {}).items():
            x = meth.setdefault(m, {'method': m, 'runs': 0, 'failed': 0, 'errors': {}})
            x['runs'] += 1
            if st and st.get('ok') is False:
                x['failed'] += 1
                ec = st.get('error_class') or 'error'
                x['errors'][ec] = x['errors'].get(ec, 0) + 1
    trends = []
    for sid, L in by_scope.items():
        L = [r for r in L if r.get('status') in ('done', 'completed', 'finished', 'partial', 'ok') or r.get('devices_seen') is not None]
        if not L:
            continue
        seen = [int(r.get('devices_seen') or 0) for r in L]
        last = seen[-1]
        prev = sorted(seen[:-1][-10:])
        med = prev[len(prev) // 2] if prev else None
        flag = None
        if med and len(prev) >= 2:
            if last <= med * 0.6:
                flag = 'devices seen fell from about %d to %d - a credential, a route or a firewall rule may have changed' % (med, last)
            elif last >= med * 1.5 and last - med >= 5:
                flag = 'devices seen jumped from about %d to %d - new subnet, new devices, or a scope widened' % (med, last)
        fails = [m for m, st in (L[-1].get('stats') or {}).items() if st and st.get('ok') is False]
        trends.append({'scope_id': sid, 'scope': (scopes.get(sid) or {}).get('name') or sid, 'runs': len(L), 'last_seen': last, 'median': med, 'series': seen[-20:],
                       'last_at': L[-1].get('started_at'), 'last_status': L[-1].get('status'), 'flag': flag, 'failed_methods': fails, 'new_last': int(L[-1].get('devices_new') or 0)})
    trends.sort(key=lambda t: (0 if t['flag'] or t['failed_methods'] else 1, str(t['scope'])))

    # ---- credentials
    use = {}
    for s in req.get('scopes') or []:
        for m, cfg in (s.get('methods') or {}).items():
            if not isinstance(cfg, dict):
                continue
            ids = list(cfg.get('credential_ids') or []) + ([cfg.get('credential_id')] if cfg.get('credential_id') else [])
            for cid in ids:
                use.setdefault(cid, []).append({'scope_id': s.get('id'), 'scope': s.get('name'), 'method': m})
    last_by_scope = {sid: L[-1] for sid, L in by_scope.items() if L}
    creds = []
    for c in req.get('credentials') or []:
        why = []
        lt = c.get('last_tested') or None
        if lt and lt.get('ok') is False:
            why.append({'points': 30, 'text': 'the last test failed (%s)' % (lt.get('error_class') or 'error')})
        elif not lt and not c.get('future'):
            why.append({'points': 15, 'text': 'never tested'})
        u = use.get(c.get('id'), [])
        if not u:
            why.append({'points': 10, 'text': 'not used by any scope'})
        t = _ts(c.get('updated_at') or c.get('created_at'))
        age = (now - t) / DAY if t else None
        if age is not None and age > 365:
            why.append({'points': 20, 'text': 'not changed for %d days - rotate it' % age})
        elif age is not None and age > 180:
            why.append({'points': 10, 'text': 'not changed for %d days' % age})
        failing = []
        for x in u:
            st = ((last_by_scope.get(x['scope_id']) or {}).get('stats') or {}).get(x['method'])
            if st and st.get('ok') is False:
                failing.append('%s in %s (%s)' % (x['method'], x['scope'], st.get('error_class') or 'error'))
        if failing:
            why.append({'points': 25, 'text': 'its method failed in the last run: ' + '; '.join(failing[:3])})
        creds.append({'id': c.get('id'), 'kind': c.get('kind'), 'label': c.get('label'), 'used_by': u, 'last_tested': lt, 'age_days': None if age is None else int(age),
                      'score': max(0, 100 - sum(w['points'] for w in why)), 'why': why})
    creds.sort(key=lambda c: c['score'])

    # ---- coverage: a host with SSH / DB / storage whose scope has no credential for that method
    need = {}
    for d in devs:
        ex = d.get('extra') or {}
        sc = scopes.get(d.get('scope_id')) or {}
        ms = sc.get('methods') or {}
        def has(m):
            cfg = ms.get(m) or {}
            return bool(cfg.get('credential_id') or cfg.get('credential_ids'))
        for m, present in (('unix', bool(ex.get('unix')) or 'unix' in (d.get('methods_seen') or [])), ('db', bool(ex.get('db'))), ('storage', bool(ex.get('storage')))):
            if present and sc and not has(m):
                k = (d.get('scope_id'), m)
                need.setdefault(k, {'scope_id': d.get('scope_id'), 'scope': sc.get('name'), 'method': m, 'hosts': 0})
                need[k]['hosts'] += 1
    coverage = sorted(need.values(), key=lambda x: -x['hosts'])

    mlist = sorted(meth.values(), key=lambda x: -x['failed'])
    for x in mlist:
        x['fail_pct'] = round(100.0 * x['failed'] / x['runs']) if x['runs'] else 0
    counts = {}
    for r in out:
        counts[r['recommend']] = counts.get(r['recommend'], 0) + 1
    by_type = {}
    for d in devs:
        by_type[d.get('type') or 'unknown'] = by_type.get(d.get('type') or 'unknown', 0) + 1
    return {'ok': True, 'recommendations': out, 'groups': gl[:40], 'trends': trends, 'methods': mlist, 'credentials': creds, 'coverage': coverage,
            'summary': {'devices': len(devs), 'new': len(out), 'by_recommend': counts, 'by_type': by_type, 'rogue': len([r for r in out if r['rogue']]),
                        'learnt_from': nd, 'scopes': len(scopes), 'runs': len(runs), 'flagged_scopes': len([t for t in trends if t['flag'] or t['failed_methods']]),
                        'weak_credentials': len([c for c in creds if c['score'] < 70]), 'coverage_gaps': len(coverage)},
            'learnt': {'decisions': nd, 'approved': tot['approved'], 'ignored': tot['ignored'],
                       'note': 'ignore suggestions need 10+ past decisions with both outcomes' if nd < 10 or not tot['ignored'] or not tot['approved'] else 'learning from %d past decisions' % nd}}


OPS = {'discovery.studio': op_studio}
