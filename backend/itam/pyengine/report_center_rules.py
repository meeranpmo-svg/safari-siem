# Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
"""Reporting Center insights (engine/report-center.js): what moved in the platform's own numbers, from the daily KPI history the
Reporting Center keeps (rc_kpis, one row per day). Nothing is projected from less history than stated; every result says how many
days it rests on, and a KPI that was not measured on a day is a gap, never a zero.

op reportcenter.insights  {kpis: [{key, label, report, good: 'up'|'down'|'none', unit}], history: [{day, values: {key: number}}], now}
  per KPI
    trend      least squares over the last 30 measured days (needs 5): slope per day, the value in 30 days (clamped to 0..100 for %)
    unusual    today's value against the previous 14 measured days (needs 8): z-score; unusual when |z| >= 2.5 and the move is
               at least 5% of the mean (or 2 for small counts)
    change     against 7 days ago (or the oldest day held): delta and whether that is better or worse for this KPI
    verdict    improving / worsening / steady / not enough history
  notable      the KPIs a reader should look at first: unusual ones, then the biggest moves the wrong way, ranked by size
  health       share of measured KPIs that are steady or improving (a single number for the cover page, with its count)
"""

import math


def _num(v):
    try:
        x = float(v)
        return x if math.isfinite(x) else None
    except (TypeError, ValueError):
        return None


def _lsq(ys):
    n = len(ys)
    if n < 2:
        return 0.0, (ys[0] if ys else 0.0)
    mx, my = (n - 1) / 2.0, sum(ys) / float(n)
    sxx = sum((x - mx) ** 2 for x in range(n))
    b = sum((x - mx) * (y - my) for x, y in zip(range(n), ys)) / sxx if sxx else 0.0
    return b, my - b * mx


def _series(history, key):
    out = []
    for h in history:
        v = _num((h.get('values') or {}).get(key))
        if v is not None:
            out.append((str(h.get('day')), v))
    return out


def _better(delta, good):
    if good == 'up':
        return delta > 0
    if good == 'down':
        return delta < 0
    return None


def one(k, history):
    key, good, unit = k.get('key'), k.get('good') or 'none', k.get('unit') or ''
    s = _series(history, key)
    r = {'key': key, 'label': k.get('label') or key, 'report': k.get('report'), 'good': good, 'unit': unit, 'days': len(s),
         'now': s[-1][1] if s else None, 'series': [{'day': d, 'v': v} for d, v in s[-30:]]}
    if not s:
        r.update(verdict='not measured', text='not measured yet')
        return r
    # change against 7 days ago (or the oldest day held)
    if len(s) >= 2:
        ref = s[-8] if len(s) >= 8 else s[0]
        d = s[-1][1] - ref[1]
        b = _better(d, good)
        r['change'] = {'since': ref[0], 'before': ref[1], 'delta': round(d, 2), 'better': b}
    # trend + forecast
    pts = [v for _, v in s[-30:]]
    if len(pts) >= 5:
        slope, a = _lsq(pts)
        f = a + slope * (len(pts) - 1 + 30)
        if unit == '%':
            f = max(0.0, min(100.0, f))
        elif min(pts) >= 0:
            f = max(0.0, f)
        scale = max(1.0, abs(sum(pts) / len(pts)))
        moving = abs(slope) * 30 >= max(0.05 * scale, 1.0)
        r['trend'] = {'days': len(pts), 'slope_day': round(slope, 3), 'in_30_days': round(f, 1), 'moving': moving}
    # unusual today against the previous 14
    if len(s) >= 8:
        prev = [v for _, v in s[-15:-1]]
        m = sum(prev) / len(prev)
        sd = (sum((x - m) ** 2 for x in prev) / len(prev)) ** 0.5
        today = s[-1][1]
        z = (today - m) / sd if sd > 0 else (0.0 if today == m else 9.9 * (1 if today > m else -1))
        big = abs(today - m) >= max(0.05 * abs(m), 2.0)
        r['unusual'] = {'z': round(z, 1), 'mean': round(m, 2), 'flag': abs(z) >= 2.5 and big, 'better': _better(today - m, good)}
    # verdict in words
    t = r.get('trend')
    if t and t['moving'] and good != 'none':
        up = t['slope_day'] > 0
        r['verdict'] = 'improving' if (up and good == 'up') or (not up and good == 'down') else 'worsening'
    elif t:
        r['verdict'] = 'steady'
    else:
        r['verdict'] = 'not enough history'
    parts = []
    if r.get('change'):
        c = r['change']
        parts.append('%+g since %s' % (c['delta'], c['since']))
    if t:
        parts.append('about %g in 30 days' % t['in_30_days'])
    if r.get('unusual') and r['unusual']['flag']:
        parts.append('unusual today (z %.1f)' % r['unusual']['z'])
    if not t:
        parts.append('trend needs 5 days (%d so far)' % len(s))
    r['text'] = '; '.join(parts)
    return r


def op_insights(req):
    hist = sorted([h for h in (req.get('history') or []) if isinstance(h, dict)], key=lambda h: str(h.get('day') or ''))
    items = [one(k, hist) for k in (req.get('kpis') or []) if isinstance(k, dict) and k.get('key')]
    notable = []
    for it in items:
        u = it.get('unusual') or {}
        if u.get('flag'):
            notable.append((3 + abs(u['z']), it, 'unusual today' + (' - the wrong way' if u.get('better') is False else '')))
        elif it.get('verdict') == 'worsening':
            notable.append((1 + abs((it.get('trend') or {}).get('slope_day') or 0), it, 'getting worse'))
        elif it.get('change') and it['change'].get('better') is False and abs(it['change']['delta']) > 0:
            notable.append((0.5, it, 'worse than %s' % it['change']['since']))
    notable.sort(key=lambda x: -x[0])
    measured = [i for i in items if i.get('verdict') in ('improving', 'worsening', 'steady')]
    ok = [i for i in measured if i['verdict'] in ('improving', 'steady')]
    health = {'measured': len(measured), 'ok': len(ok), 'pct': round(100.0 * len(ok) / len(measured)) if measured else None}
    return {'ok': True, 'kpis': items, 'health': health, 'days': len(hist),
            'notable': [{'key': it['key'], 'label': it['label'], 'report': it.get('report'), 'why': why, 'text': it.get('text')} for _, it, why in notable[:12]]}


OPS = {'reportcenter.insights': op_insights}
