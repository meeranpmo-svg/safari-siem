# Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
"""Sensitive-access log rules (engine/pdpl-access.js commits what these decide).

Claims, medical-review and fraud systems send who opened which record and why. These rules decide which events are
EXCEPTIONS (sensitive data opened with no purpose, "other" with no reason, a fraud investigation with no case reference,
an export or print of sensitive data, a deletion) and which user-days are INDICATORS (volume far above the person's own
recent pattern, or many sensitive exports). Both are leads for a reviewer - behavioural indicators, not proof of
wrongdoing (PDPL Art. 19 and Implementing Regulation Art. 26: tiered access to health data, every stage documented).

  pdpl.access_classify {events}                         -> per event: the exception types it raises ([] = none)
  pdpl.access_view     {days, exceptions, reviews, keys, settings, now} -> indicators, summaries, findings
"""
from datetime import datetime, timezone

DAY = 86400000
EXC_LABEL = {'no_purpose': 'sensitive record opened with no purpose', 'other_no_reason': 'purpose "other" with no reason', 'investigation_no_case': 'fraud investigation with no case reference',
             'sensitive_export': 'sensitive record exported or printed', 'delete': 'record deleted'}


def classify_one(e):
    t = []
    sens = bool(e.get('sensitive'))
    if sens and not e.get('purpose'):
        t.append('no_purpose')
    if e.get('purpose') == 'other' and not str(e.get('reason') or '').strip():
        t.append('other_no_reason')
    if e.get('purpose') == 'fraud_investigation' and not str(e.get('case_ref') or '').strip():
        t.append('investigation_no_case')
    if sens and e.get('action') in ('export', 'print'):
        t.append('sensitive_export')
    if e.get('action') == 'delete':
        t.append('delete')
    return t


def classify(req):
    return {'types': [classify_one(e) for e in req.get('events') or []]}


def _day_ms(d):
    return int(datetime.strptime(d, '%Y-%m-%d').replace(tzinfo=timezone.utc).timestamp() * 1000)


def _median(xs):
    s = sorted(xs)
    n = len(s)
    return 0 if not n else (s[n // 2] if n % 2 else (s[n // 2 - 1] + s[n // 2]) / 2.0)


def indicators(days, settings, now):
    """volume: n > max(min_volume, multiplier x the user's median over the 30 days before) with >= 7 days of history;
    without that history only n > 2 x min_volume counts. exports: sensitive exports in a day > export_limit."""
    mv, mult, el = int(settings.get('min_volume') or 50), float(settings.get('multiplier') or 3), int(settings.get('export_limit') or 20)
    by_user = {}
    for d in days:
        by_user.setdefault(str(d.get('user')).lower(), []).append(d)
    out, since = [], now - 30 * DAY
    for u, rows in by_user.items():
        for d in rows:
            t = _day_ms(d['day'])
            if t < since:
                continue
            hist = [x['n'] for x in rows if t - 30 * DAY <= _day_ms(x['day']) < t]
            n = int(d.get('n') or 0)
            if len(hist) >= 7:
                med = _median(hist)
                if n > max(mv, mult * med):
                    out.append({'id': d['day'] + '|' + u + '|volume', 'day': d['day'], 'user': d.get('user'), 'type': 'volume', 'n': n,
                                'why': '%d records opened; usual day %s (median of %d days); threshold %s' % (n, round(med, 1), len(hist), round(max(mv, mult * med), 1))})
            elif n > 2 * mv:
                out.append({'id': d['day'] + '|' + u + '|volume', 'day': d['day'], 'user': d.get('user'), 'type': 'volume', 'n': n,
                            'why': '%d records opened with under 7 days of history to compare; threshold %d (twice the minimum)' % (n, 2 * mv)})
            if int(d.get('exports') or 0) > el:
                out.append({'id': d['day'] + '|' + u + '|exports', 'day': d['day'], 'user': d.get('user'), 'type': 'exports', 'n': int(d.get('exports')),
                            'why': '%d sensitive records exported or printed; limit %d a day' % (int(d.get('exports')), el)})
    out.sort(key=lambda x: x['day'], reverse=True)
    return out


def view(req):
    days, exc, rev, keys, now = req.get('days') or [], req.get('exceptions') or [], req.get('reviews') or {}, req.get('keys') or [], req.get('now') or 0
    settings = req.get('settings') or {}
    ind = indicators(days, settings, now)
    for i in ind:
        r = rev.get(i['id'])
        i['status'] = r.get('decision') if r else 'open'
        i['review'] = r
    since = datetime.fromtimestamp((now - 30 * DAY) / 1000, tz=timezone.utc).strftime('%Y-%m-%d')
    recent = [d for d in days if d.get('day', '') >= since]
    users, systems = {}, {}
    for d in recent:
        u = users.setdefault(d.get('user'), {'user': d.get('user'), 'n': 0, 'sensitive': 0, 'exports': 0, 'days': 0})
        u['n'] += int(d.get('n') or 0); u['sensitive'] += int(d.get('sensitive') or 0); u['exports'] += int(d.get('exports') or 0); u['days'] += 1
        for s, c in (d.get('systems') or {}).items():
            systems[s] = systems.get(s, 0) + c
    F = []
    old = [x for x in exc if x.get('status') == 'open' and now - int(x.get('recorded') or now) > 7 * DAY]
    by_type = {}
    for x in old:
        for t in x.get('types') or []:
            by_type[t] = by_type.get(t, 0) + 1
    for t, c in sorted(by_type.items()):
        F.append({'key': 'access:exc:' + t, 'severity': 'high' if t in ('no_purpose', 'investigation_no_case', 'delete') else 'medium',
                  'title': '%d access exception(s) not reviewed for over 7 days: %s' % (c, EXC_LABEL.get(t, t)), 'evidence': [], 'requirement': 'P-14',
                  'recommendation': 'Review each one on the Sensitive Access Log page: justified (with the reason) or escalated. A reviewer never reviews their own access.'})
    open_ind = {}
    for i in ind:
        if i['status'] == 'open':
            open_ind.setdefault(i['user'], []).append(i)
    for u, xs in sorted(open_ind.items(), key=lambda kv: str(kv[0])):
        F.append({'key': 'access:ind:' + str(u).lower(), 'severity': 'medium', 'title': 'Access pattern to review for %s (%d indicator(s))' % (u, len(xs)), 'evidence': [x['why'] for x in xs[:3]], 'requirement': 'P-14',
                  'recommendation': 'Review the indicator: behavioural indicators, not proof. Record justified with the business reason, or escalated under the access policy.'})
    for k in keys:
        if k.get('revoked_at'):
            continue
        lu = k.get('last_used')
        t = int(datetime.fromisoformat(lu.replace('Z', '+00:00')).timestamp() * 1000) if lu else None
        if (t is None and k.get('created_ms') and now - k['created_ms'] > 7 * DAY) or (t is not None and now - t > 7 * DAY):
            F.append({'key': 'access:silent:' + k['id'], 'severity': 'medium', 'title': 'System "%s" has sent no access events for over 7 days' % k.get('name'), 'evidence': ['last event: ' + (lu or 'never')], 'requirement': 'P-14',
                      'recommendation': 'Check the system still sends its access log (key, network, job) - silence is not the same as no access.'})
    return {'indicators': ind, 'users': sorted(users.values(), key=lambda x: -x['sensitive'])[:50], 'systems': [{'name': k, 'n': v} for k, v in sorted(systems.items(), key=lambda kv: -kv[1])],
            'totals': {'events': sum(u['n'] for u in users.values()), 'sensitive': sum(u['sensitive'] for u in users.values()), 'users': len(users),
                       'exceptions_open': sum(1 for x in exc if x.get('status') == 'open'), 'indicators_open': sum(1 for i in ind if i['status'] == 'open')},
            'findings': F, 'labels': EXC_LABEL, 'settings': {'min_volume': int(settings.get('min_volume') or 50), 'multiplier': float(settings.get('multiplier') or 3), 'export_limit': int(settings.get('export_limit') or 20)},
            'note': 'Behavioural indicators, not proof of wrongdoing. An exception or an indicator is a lead for a reviewer, who records whether the access was justified or escalates it under the access policy. '
                    'The log shows only what the connected systems send.'}


OPS = {'pdpl.access_classify': classify, 'pdpl.access_view': view}
