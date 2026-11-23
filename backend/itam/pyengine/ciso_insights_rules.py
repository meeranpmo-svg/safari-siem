# Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
"""CISO insights (engine/ciso.js GET /ciso/insights): the trends behind the CISO dashboard, from the platform's own records only -
the daily posture history the AI CISO keeps (ciso_history) and the SOC's alerts per day (SIEM /metrics). Nothing is projected from
less history than stated: every result says how many days it rests on.

op ciso.insights  {history: [{day, overall, domains{}}], domains: [{id, name, score}], alerts_by_day: [{day, total, by_severity?}],
                   open_by_severity, now}
  forecast      least squares over the last 30 daily posture scores (7+ days): slope per day and the score in 30 days; "falling"
                when the slope is below -0.2 points a day.
  movers        each measured domain now against 7 days ago (or the oldest day held): the biggest falls and rises.
  alerts        today's alerts against the previous 14 days (7+ needed): z-score, unusual when z >= 2.5 and above the mean by 5+;
                the next 7 days expected from the last 14 (mean + trend), never below zero.
  focus         the weakest measured domain and the one falling fastest - where a CISO's next hour goes.
"""

import math


def _lsq(ys):
    n = len(ys)
    xs = list(range(n))
    mx, my = sum(xs) / float(n), sum(ys) / float(n)
    sxx = sum((x - mx) ** 2 for x in xs)
    if not sxx:
        return 0.0, my
    b = sum((x - mx) * (y - my) for x, y in zip(xs, ys)) / sxx
    return b, my - b * mx


def _num(v):
    try:
        x = float(v)
        return x if math.isfinite(x) else None
    except (TypeError, ValueError):
        return None


def op_insights(req):
    hist = [h for h in (req.get('history') or []) if isinstance(h, dict)]
    hist.sort(key=lambda h: str(h.get('day') or ''))
    pts = [(h.get('day'), _num(h.get('overall'))) for h in hist]
    pts = [p for p in pts if p[1] is not None][-30:]
    if len(pts) >= 7:
        b, a = _lsq([p[1] for p in pts])
        cur = pts[-1][1]
        proj = max(0.0, min(100.0, cur + b * 30))
        proj = round(proj)
        forecast = {'days': len(pts), 'slope_day': round(b, 2), 'in_30_days': proj, 'now': round(cur), 'falling': b < -0.2,
                    'text': ('falling %.1f points a day - about %d in 30 days' % (-b, proj)) if b < -0.2 else ('rising %.1f points a day - about %d in 30 days' % (b, proj)) if b > 0.2 else 'steady (about %d in 30 days)' % proj}
    else:
        forecast = {'days': len(pts), 'text': 'needs 7 days of posture history (%d so far)' % len(pts), 'falling': False}

    names = {d.get('id'): d.get('name') for d in (req.get('domains') or [])}
    movers = []
    if len(hist) >= 2:
        last = hist[-1]
        ref = hist[-8] if len(hist) >= 8 else hist[0]
        for k, v in (last.get('domains') or {}).items():
            nv, ov = _num(v), _num((ref.get('domains') or {}).get(k))
            if nv is None or ov is None:
                continue
            movers.append({'id': k, 'name': names.get(k) or k, 'now': round(nv), 'before': round(ov), 'delta': round(nv - ov), 'since': ref.get('day')})
        movers.sort(key=lambda m: m['delta'])

    days = [d for d in (req.get('alerts_by_day') or []) if isinstance(d, dict)]
    days.sort(key=lambda d: str(d.get('day') or ''))
    counts = [int(_num(d.get('total') if d.get('total') is not None else d.get('count')) or 0) for d in days]
    alerts = {'days': len(counts), 'series': [{'day': d.get('day'), 'total': c} for d, c in zip(days, counts)][-30:]}
    if len(counts) >= 8:
        today, prev = counts[-1], counts[-15:-1]
        m = sum(prev) / float(len(prev))
        sd = (sum((x - m) ** 2 for x in prev) / float(len(prev))) ** 0.5
        z = (today - m) / sd if sd > 0 else (0.0 if today <= m else 9.9)
        last14 = counts[-14:]
        b, a = _lsq(last14)
        nxt = [max(0, int(round(a + b * (len(last14) + i)))) for i in range(7)]
        alerts.update({'today': today, 'baseline': round(m, 1), 'z': round(z, 1), 'unusual': z >= 2.5 and today - m >= 5, 'next_7_days': sum(nxt), 'next_days': nxt,
                       'text': ('%d alerts today against a usual %.0f - unusual (z %.1f)' % (today, m, z)) if z >= 2.5 and today - m >= 5 else '%d alerts today, usual %.0f' % (today, m)})
    else:
        alerts['text'] = 'needs 8 days of alerts (%d so far)' % len(counts)

    measured = [d for d in (req.get('domains') or []) if _num(d.get('score')) is not None]
    focus = []
    if measured:
        w = min(measured, key=lambda d: _num(d.get('score')))
        focus.append({'kind': 'weakest', 'id': w.get('id'), 'name': w.get('name'), 'text': '%s is the weakest domain at %d' % (w.get('name'), round(_num(w.get('score'))))})
    if movers and movers[0]['delta'] <= -5:
        f = movers[0]
        focus.append({'kind': 'falling', 'id': f['id'], 'name': f['name'], 'text': '%s fell %d points since %s' % (f['name'], -f['delta'], f['since'])})
    if alerts.get('unusual'):
        focus.append({'kind': 'alerts', 'text': alerts['text']})
    obs = req.get('open_by_severity') or {}
    crit = int(_num(obs.get('critical') if 'critical' in obs else obs.get('4')) or 0)
    if crit:
        focus.append({'kind': 'critical', 'text': '%d critical alert(s) open now' % crit})
    return {'ok': True, 'forecast': forecast, 'movers': movers, 'alerts': alerts, 'focus': focus}


OPS = {'ciso.insights': op_insights}
