# Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
"""Notification & Escalation learning (engine/notify-center.js). Everything is learnt from the platform's own incident history
(nc_incidents: when each incident opened, who was notified, when and by whom it was acknowledged, how it was closed). Nothing is
assumed: a team with fewer than 5 acknowledged incidents has no learnt acknowledge time, and every result says what it rests on.

op notify.learn  {incidents: [{id, team, policy, source, severity, title, first, acked_at, resolved_at, resolution, status,
                                notified: [{at, to: [names], after_hours}], group}], open: [ids], now, step_min: {policy: minutes}}
  teams        per team: acknowledged incidents, median / p90 minutes to acknowledge, share acknowledged within the first step
  predict      per open incident: chance it escalates past its first step = share of this team's past incidents (same hour band:
               working hours / after hours) not acknowledged within that step's minutes; null below 5 comparable incidents
  noise        per policy: notifications, share closed as false positive / benign or auto-resolved within 10 minutes; "noisy" when
               20+ incidents and 60%+ of them are noise -> a proposal to raise its threshold (never applied by this rule)
  fatigue      per person: notifications in 7 days, after-hours share; "high" from 25 notifications or 10 after hours a week
  storm        incidents opened in the last 60 minutes against the same hour's median over the last 14 days (needs 7 days)
  groups       titles with digits / addresses masked: incidents that are the same condition, for one page instead of many
"""

import re
import statistics

HOUR = 3600000
DAY = 86400000
RIYADH = 3 * HOUR


def _stem(t):
    t = str(t or '').lower()
    t = re.sub(r'\b\d{1,3}(\.\d{1,3}){3}\b', '<ip>', t)
    t = re.sub(r'[0-9a-f]{8,}', '<id>', t)
    t = re.sub(r'\d+', '#', t)
    return re.sub(r'\s+', ' ', t).strip()[:120]


def _after_hours(ms):
    t = ms + RIYADH
    wd = int((t // DAY + 4) % 7)  # 1970-01-01 was a Thursday -> 0 = Sunday
    h = int((t % DAY) // HOUR)
    return wd in (5, 6) or h < 7 or h >= 18  # Riyadh: Sun-Thu 07:00-18:00


def _pct(xs, p):
    xs = sorted(xs)
    if not xs:
        return None
    k = (len(xs) - 1) * p
    f = int(k)
    c = min(f + 1, len(xs) - 1)
    return xs[f] + (xs[c] - xs[f]) * (k - f)


def op_learn(req):
    inc = [i for i in (req.get('incidents') or []) if isinstance(i, dict) and i.get('first')]
    now = float(req.get('now') or 0)
    step_min = req.get('step_min') or {}
    out = {'ok': True, 'incidents': len(inc)}

    # ---- teams: time to acknowledge
    by_team = {}
    for i in inc:
        by_team.setdefault(i.get('team') or '(unrouted)', []).append(i)
    teams = {}
    for t, L in by_team.items():
        mins = [(i['acked_at'] - i['first']) / 60000.0 for i in L if i.get('acked_at') and i['acked_at'] >= i['first']]
        r = {'incidents': len(L), 'acked': len(mins)}
        if len(mins) >= 5:
            r.update(median_min=round(statistics.median(mins), 1), p90_min=round(_pct(mins, 0.9), 1))
        else:
            r['note'] = 'needs 5 acknowledged incidents (%d so far)' % len(mins)
        teams[t] = r
    out['teams'] = teams

    # ---- predict escalation for open incidents
    byid = {i['id']: i for i in inc}
    pred = {}
    for oid in req.get('open') or []:
        i = byid.get(oid)
        if not i:
            continue
        step = float(step_min.get(i.get('policy') or '', 15) or 15)
        ah = _after_hours(i['first'])
        past = [x for x in by_team.get(i.get('team') or '(unrouted)', []) if x['id'] != oid and x.get('status') != 'open' and _after_hours(x['first']) == ah]
        if len(past) < 5:
            pred[oid] = {'p': None, 'n': len(past), 'text': 'not enough history (%d comparable incidents)' % len(past)}
            continue
        late = [x for x in past if not x.get('acked_at') or (x['acked_at'] - x['first']) / 60000.0 > step]
        p = round(len(late) / float(len(past)), 2)
        pred[oid] = {'p': p, 'n': len(past), 'text': '%d%% of %d similar incidents (%s) were not acknowledged within %g min' % (round(p * 100), len(past), 'after hours' if ah else 'working hours', step)}
    out['predict'] = pred

    # ---- noise per policy
    noise = []
    by_pol = {}
    for i in inc:
        if i.get('policy'):
            by_pol.setdefault(i['policy'], []).append(i)
    for pid, L in by_pol.items():
        closed = [i for i in L if i.get('status') == 'resolved']
        noisy = [i for i in closed if i.get('resolution') in ('false-positive', 'benign') or (i.get('resolved_at') and i['resolved_at'] - i['first'] <= 10 * 60000 and i.get('resolution') == 'auto')]
        share = round(len(noisy) / float(len(L)), 2) if L else 0
        r = {'policy': pid, 'incidents': len(L), 'noise': len(noisy), 'share': share, 'noisy': len(L) >= 20 and share >= 0.6}
        if r['noisy']:
            r['proposal'] = 'raise the minimum severity of this policy by one, or narrow its match: %d of %d incidents were noise' % (len(noisy), len(L))
        noise.append(r)
    noise.sort(key=lambda r: -r['share'])
    out['noise'] = noise

    # ---- fatigue per person (last 7 days)
    fat = {}
    for i in inc:
        for n in i.get('notified') or []:
            if not n.get('at') or now - n['at'] > 7 * DAY:
                continue
            for who in n.get('to') or []:
                f = fat.setdefault(who, {'person': who, 'week': 0, 'after_hours': 0})
                f['week'] += 1
                if n.get('after_hours'):
                    f['after_hours'] += 1
    for f in fat.values():
        f['high'] = f['week'] >= 25 or f['after_hours'] >= 10
    out['fatigue'] = sorted(fat.values(), key=lambda f: -f['week'])

    # ---- storm: last hour vs the same hour over 14 days
    last = [i for i in inc if now - i['first'] <= HOUR]
    days = (now - min([i['first'] for i in inc])) / DAY if inc else 0
    if days >= 7:
        hist = []
        for d in range(1, 15):
            a, b = now - d * DAY - HOUR, now - d * DAY
            hist.append(len([i for i in inc if a < i['first'] <= b]))
        med = statistics.median(hist)
        storm = len(last) >= max(5, 3 * (med or 1))
        out['storm'] = {'last_hour': len(last), 'usual': med, 'storm': storm, 'text': ('%d incidents in the last hour against a usual %g - a storm' if storm else '%d incidents in the last hour, usual %g') % (len(last), med)}
    else:
        out['storm'] = {'last_hour': len(last), 'usual': None, 'storm': False, 'text': 'needs 7 days of incidents to know what is usual (%.0f so far)' % days}

    # ---- groups: the same condition
    g = {}
    for i in inc:
        if i.get('status') == 'open':
            g.setdefault((i.get('source'), _stem(i.get('title'))), []).append(i['id'])
    out['groups'] = [{'source': k[0], 'stem': k[1], 'ids': v, 'count': len(v)} for k, v in g.items() if len(v) >= 2]
    return out


def op_stem(req):
    return {'ok': True, 'stem': _stem(req.get('title'))}


OPS = {'notify.learn': op_learn, 'notify.stem': op_stem}
