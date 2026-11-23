# Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
"""DR Studio rules (engine/dr-studio.js): Main site <-> DR site replication health from the streams the platform reads
(Nutanix protection domains, Oracle Data Guard standbys) and this server's own 15-minute samples of them. Nothing invented:
a stream nobody reports is not listed, a missing sample is a gap, never a value.

op dr.studio  {streams, history, tests, now}
  ratio       lag / RPO for each sample (1.0 = at the RPO).
  forecast    least squares over the last 6 h of ratios (6+ samples): slope per hour; if rising, the hours until the ratio
              reaches 1.0 - "breach in about N h". Fewer samples: "not enough history" - never a forecast from one point.
  anomaly     the current ratio against the stream's own 7-day samples (12+): z >= 3 is unusual for THIS stream.
  flapping    status changes in the last 24 h (3+ = flapping).
  compliance  share of the last 7 days' samples within the RPO.
  readiness   0-100 per stream, every point named: 100 minus lag (up to 50: ratio x 50), rising trend (10), unusual (10),
              flapping (10), stale data (15), DR test (never 15, older than 180 days 10, last failed 15).
  overall     AT RISK (a stream past its RPO or a cross-site conflict), DEGRADED (a stream late, forecast to breach, or not
              protected), PROTECTED (every stream within its RPO), NOT MEASURED (no stream reported).
"""

DAY = 86400.0


def lsq(xs, ys):
    n = len(xs)
    mx, my = sum(xs) / n, sum(ys) / n
    sxx = sum((x - mx) ** 2 for x in xs)
    if not sxx:
        return 0.0, my
    b = sum((x - mx) * (y - my) for x, y in zip(xs, ys)) / sxx
    return b, my - b * mx


def op_studio(req):
    now = float(req.get('now') or 0) / 1000.0
    hist = {}
    for h in req.get('history') or []:
        hist.setdefault(h.get('key'), []).append(h)
    for k in hist:
        hist[k].sort(key=lambda x: x.get('t') or 0)
    tests = {}
    for t in req.get('tests') or []:
        k = t.get('key')
        if k not in tests or str(t.get('date') or '') > str(tests[k].get('date') or ''):
            tests[k] = t
    rows = []
    for s in req.get('streams') or []:
        k = s.get('key')
        rpo, lag = s.get('rpo_s'), s.get('lag_s')
        ratio = (float(lag) / rpo) if (rpo and lag is not None) else (0.0 if rpo == 0 and lag == 0 else None)
        H = [x for x in hist.get(k, []) if x.get('ratio') is not None]
        recent = [x for x in H if (now - x['t'] / 1000.0) <= 6 * 3600]
        why, score = [], 100

        def take(p, txt):
            why.append({'points': -p, 'text': txt})
            return p
        forecast = {'text': 'not enough history (%d sample(s) in 6 h, 6 needed)' % len(recent), 'slope_h': None, 'breach_h': None}
        if len(recent) >= 6:
            xs = [x['t'] / 3600000.0 for x in recent]
            ys = [x['ratio'] for x in recent]
            b, a = lsq(xs, ys)
            cur = ratio if ratio is not None else ys[-1]
            forecast = {'slope_h': round(b, 4), 'breach_h': None, 'text': 'steady (%+.0f %% of the RPO per hour)' % (100 * b)}
            if b > 0.01 and cur < 1:
                hrs = (1 - cur) / b
                forecast = {'slope_h': round(b, 4), 'breach_h': round(hrs, 1), 'text': 'rising %+.0f %% of the RPO per hour - at this rate it passes the RPO in about %.1f h' % (100 * b, hrs)}
        week = [x for x in H if (now - x['t'] / 1000.0) <= 7 * DAY]
        anomaly = None
        if len(week) >= 12 and ratio is not None:
            vals = [x['ratio'] for x in week]
            m = sum(vals) / len(vals)
            sd = (sum((v - m) ** 2 for v in vals) / len(vals)) ** 0.5
            if sd > 0 and (ratio - m) / sd >= 3:
                anomaly = {'z': round((ratio - m) / sd, 1), 'text': 'lag is unusual for this stream: %.0f %% of the RPO, usually %.0f %%' % (100 * ratio, 100 * m)}
        day = [x for x in H if (now - x['t'] / 1000.0) <= DAY]
        flaps = sum(1 for i in range(1, len(day)) if day[i].get('status') != day[i - 1].get('status'))
        comp = round(100.0 * len([x for x in week if x['ratio'] <= 1]) / len(week), 1) if week else None

        if ratio is not None:
            p = min(50, int(round(min(ratio, 1.0) * 50)))
            if p:
                score -= take(p, 'lag is %.0f %% of the RPO' % (100 * ratio))
        if forecast.get('breach_h') is not None:
            score -= take(10, forecast['text'])
        if anomaly:
            score -= take(10, anomaly['text'])
        if flaps >= 3:
            score -= take(10, 'status changed %d times in 24 h (flapping)' % flaps)
        if s.get('stale'):
            score -= take(15, 'the source has not reported recently - the lag may be out of date')
        t = tests.get(k)
        if not t:
            score -= take(15, 'never DR-tested (no test recorded)')
        else:
            age = (now - _ts(t.get('date'))) / DAY if _ts(t.get('date')) else None
            if t.get('result') == 'fail':
                score -= take(15, 'the last DR test failed (%s)' % t.get('date'))
            elif age is not None and age > 180:
                score -= take(10, 'last DR test %d days ago (%s)' % (age, t.get('date')))
        if s.get('status') in ('no-remote', 'no-schedule'):
            score -= take(30, s.get('why') or 'not protected')
        rows.append(dict(s, ratio=None if ratio is None else round(ratio, 3), forecast=forecast, anomaly=anomaly, flaps=flaps, compliance=comp,
                         readiness=max(0, score), why_score=why, last_test=t, spark=[{'t': x['t'], 'r': x['ratio']} for x in week][-96:]))
    rows.sort(key=lambda r: (r['readiness'], -(r['ratio'] or 0)))

    bad = [r for r in rows if r.get('status') in ('critical', 'breached') or (r['ratio'] is not None and r['ratio'] > 1 and r.get('status') != 'standby')]
    warn = [r for r in rows if r not in bad and (r.get('status') in ('late', 'no-remote', 'no-schedule', 'unknown') or (r['forecast'].get('breach_h') is not None))]
    conflicts = req.get('conflicts') or []
    if not rows:
        overall = {'state': 'NOT MEASURED', 'text': 'No replication stream reports yet - connect Nutanix (Virtualization) or the Oracle collector with Data Guard.'}
    elif bad or conflicts:
        overall = {'state': 'AT RISK', 'text': '%d stream(s) past the RPO%s - a failover now would lose more data than agreed.' % (len(bad), (' and %d cross-site conflict(s)' % len(conflicts)) if conflicts else '')}
    elif warn:
        overall = {'state': 'DEGRADED', 'text': 'Every stream is recoverable, but %d is late, not protected or forecast to pass its RPO.' % len(warn)}
    else:
        overall = {'state': 'PROTECTED', 'text': 'Every reported stream is inside its RPO.'}
    # 24 h heat map: per stream, per hour, the worst ratio sampled (None = no sample)
    heat = []
    for r in rows[:40]:
        cells = []
        for hb in range(24, 0, -1):
            lo, hi = now - hb * 3600, now - (hb - 1) * 3600
            v = [x['ratio'] for x in hist.get(r['key'], []) if x.get('ratio') is not None and lo <= x['t'] / 1000.0 < hi]
            cells.append(round(max(v), 2) if v else None)
        heat.append({'key': r['key'], 'name': r['system'], 'cells': cells})
    week_all = [x for k in hist for x in hist[k] if x.get('ratio') is not None and (now - x['t'] / 1000.0) <= 7 * DAY]
    return {'ok': True, 'overall': overall, 'streams': rows, 'heat': heat, 'conflicts': conflicts,
            'summary': {'streams': len(rows), 'past_rpo': len(bad), 'at_risk': len(warn), 'never_tested': len([r for r in rows if not r['last_test']]),
                        'forecast_breaches': len([r for r in rows if r['forecast'].get('breach_h') is not None]),
                        'compliance_7d': round(100.0 * len([x for x in week_all if x['ratio'] <= 1]) / len(week_all), 1) if week_all else None,
                        'readiness': int(round(sum(r['readiness'] for r in rows) / float(len(rows)))) if rows else None, 'samples_7d': len(week_all)},
            'learned': {'note': 'Forecast, anomaly and compliance from %d sample(s) this server took in the last 7 days (every 15 min).' % len(week_all)}}


def _ts(v):
    import datetime as dt
    try:
        return (dt.datetime.strptime(str(v)[:10], '%Y-%m-%d') - dt.datetime(1970, 1, 1)).total_seconds()
    except (ValueError, TypeError):
        return None


OPS = {'dr.studio': op_studio}
