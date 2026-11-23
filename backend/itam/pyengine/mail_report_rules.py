# Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
"""Regulator report on an e-mail service incident (outage and / or attack), for the CISO to send to SAMA or the Insurance
Authority. engine/mail-reputation.js passes what the platform recorded (availability probes, outages, the route checks,
Spamhaus results) and the SIEM counts the page read for the window; this module writes the report. Standard library only.

  mailreport.build {regulator, kind, from, to, outages, availability, route, reputation, siem, notes, prepared_by, now}

The report states only what the platform recorded. What it cannot know - business and customer impact, the actions people
took, the root cause once investigated - comes from the notes or is listed under "to be completed by the CISO". It is a
draft until the CISO approves it, and it is submitted through the regulator's own channel, never from the platform.
"""
from datetime import datetime, timezone
from org_brand import fill as _org_fill

REG = {'sama': ('Saudi Central Bank (SAMA)', 'Cyber security incident report - SAMA Cyber Security Framework (incident management, 3.3.15)'),
       'ia': ('Insurance Authority (IA)', 'Cyber security incident report - Insurance Authority (SAMA CSF baseline)')}
KIND = {'downtime': 'E-mail service outage', 'attack': 'E-mail borne attack', 'both': 'E-mail service outage and attack'}


def _t(ms):
    return datetime.fromtimestamp(ms / 1000, tz=timezone.utc).strftime('%Y-%m-%d %H:%M UTC') if ms else '-'


def _riyadh(ms):
    return datetime.fromtimestamp(ms / 1000 + 3 * 3600, tz=timezone.utc).strftime('%Y-%m-%d %H:%M') + ' Riyadh' if ms else '-'


def _n(x):
    try:
        return int(x or 0)
    except (TypeError, ValueError):
        return 0


def build(req):
    reg, kind = req.get('regulator'), req.get('kind')
    if reg not in REG or kind not in KIND:
        return {'refuse': {'status': 400, 'error': 'regulator must be sama or ia and kind downtime, attack or both'}}
    f, t, now = _n(req.get('from')), _n(req.get('to')), _n(req.get('now'))
    if not f or not t or t <= f:
        return {'refuse': {'status': 400, 'error': 'the report window needs a start before its end'}}
    notes = req.get('notes') or {}
    outs = [o for o in (req.get('outages') or []) if _n(o.get('end') or now) >= f and _n(o.get('start')) <= t]
    down = sum(_n(o.get('minutes')) for o in outs)
    av, target = req.get('availability') or {}, float(req.get('target') or 99.99)
    route, rep, siem = req.get('route') or {}, req.get('reputation') or [], req.get('siem') or {}
    th = siem.get('threats') or {}
    th_total, th_deliv = sum(_n(v) for v in th.values()), _n(th.get('delivered'))
    gw = siem.get('gateway') or {}
    missing, sections = [], []
    want_down, want_att = kind in ('downtime', 'both'), kind in ('attack', 'both')
    # summary
    parts = []
    if want_down:
        parts.append(('Between %s and %s the inbound e-mail service was unavailable for %d minute%s in %d outage%s (no MX host answered SMTP), as measured by the platform\'s minute-by-minute probe.'
                      % (_riyadh(f), _riyadh(t), down, '' if down == 1 else 's', len(outs), '' if len(outs) == 1 else 's')) if outs else
                     'No outage of the inbound e-mail service was recorded by the platform between %s and %s.' % (_riyadh(f), _riyadh(t)))
    if want_att:
        parts.append(('In the same period the e-mail gateway recorded %d phishing / malware message%s; %d %s delivered to mailboxes.' % (th_total, '' if th_total == 1 else 's', th_deliv, 'was' if th_deliv == 1 else 'were'))
                     if th else 'No phishing / malware counts were available from the SIEM for the period - the gateway logs must be checked before submitting.')
        if not th:
            missing.append('Attack figures: the SIEM did not return gateway threat counts for the window')
    sections.append({'heading': '1. Summary', 'paragraphs': parts + ([notes['summary']] if notes.get('summary') else [])})
    # details
    rows = [['Organisation', _org_fill('{{org.name}}')], ['Regulator', REG[reg][0]], ['Report type', KIND[kind]],
            ['Incident window', _riyadh(f) + ' to ' + _riyadh(t)], ['Detected', _riyadh(_n(outs[-1]['start'])) + ' (platform availability probe)' if outs and want_down else (notes.get('detected') or 'to be completed')],
            ['Prepared by', str(req.get('prepared_by') or '-')], ['Prepared at', _riyadh(now)], ['Classification', 'Confidential - regulator submission']]
    if not outs and not notes.get('detected'):
        missing.append('Detection time and how the incident was detected')
    sections.append({'heading': '2. Incident details', 'rows': rows})
    # timeline
    tl = []
    for o in sorted(outs, key=lambda o: _n(o.get('start'))):
        tl.append([_riyadh(_n(o.get('start'))), 'Inbound e-mail unavailable - no MX host answering (%s)' % '; '.join(o.get('hosts') or [])[:300]])
        tl.append([_riyadh(_n(o.get('end'))) if o.get('end') else 'ongoing', 'Service restored after %d minute%s' % (_n(o.get('minutes')), '' if _n(o.get('minutes')) == 1 else 's') if o.get('end') else 'Not yet restored at the time of the report'])
    for x in notes.get('timeline') or []:
        tl.append([str(x.get('at') or ''), str(x.get('event') or '')])
    if tl:
        sections.append({'heading': '3. Timeline', 'table': {'columns': ['Time', 'Event'], 'rows': tl}})
    # impact
    imp = []
    if want_down:
        imp += [['Service affected', 'Inbound e-mail (receiving from the Internet)'], ['Total downtime in the window', '%d minutes' % down],
                ['Availability target', '%g%% (%.1f minutes of downtime allowed a month)' % (target, 30 * 1440 * (100 - target) / 100.0)]]
        w = (av.get('windows') or [{}])[0]
        if w.get('availability') is not None:
            imp.append(['Availability, last 30 days', '%.3f%% - %s' % (w['availability'], {'met': 'within target', 'at_risk': 'within target, over 75%% of the budget used', 'breached': 'target missed'}.get(w.get('state'), w.get('state')))])
    if gw:
        imp.append(['Mail through the gateway in the window', ', '.join('%s %d' % (k, _n(v)) for k, v in gw.items())])
    imp.append(['Business and customer impact', notes.get('impact') or 'to be completed by the CISO'])
    imp.append(['Personal data affected', notes.get('personal_data') or 'to be completed (if yes, assess PDPL breach notification to SDAIA within 72 hours)'])
    if not notes.get('impact'):
        missing.append('Business and customer impact')
    if not notes.get('personal_data'):
        missing.append('Whether personal data was affected (PDPL)')
    sections.append({'heading': '4. Impact', 'rows': imp})
    # attack details
    if want_att and th:
        ar = [['Phishing / malware messages', str(th_total)], ['Delivered to mailboxes', str(th_deliv)], ['Stopped (blocked / rejected / quarantined)', str(th_total - th_deliv)]]
        if siem.get('top_threats'):
            ar.append(['Threats named by the gateway', ', '.join('%s (%d)' % (x.get('v'), _n(x.get('n'))) for x in siem['top_threats'][:8])])
        if siem.get('countries'):
            ar.append(['Main source countries (SMTP sessions)', ', '.join('%s (%d)' % (x.get('name'), _n(x.get('allow')) + _n(x.get('deny'))) for x in siem['countries'][:8])])
        ar.append(['ATT&CK technique', 'T1566 Phishing'])
        sections.append({'heading': '5. Attack details', 'rows': ar})
    # cause
    found = [i for i in (route.get('issues') or []) if i.get('severity') in ('critical', 'high')]
    listed = [r for r in rep if r.get('state') == 'listed']
    cause = [i['title'] for i in found[:10]] + ['%s listed on Spamhaus %s' % (r.get('target'), ', '.join(l.get('list') for l in r.get('lists') or [])) for r in listed]
    sections.append({'heading': '6. Cause and contributing factors', 'paragraphs': ([notes['cause']] if notes.get('cause') else ['Root cause: to be completed by the CISO after investigation.']) ,
                     'list_title': 'Platform findings at the time of the report' if cause else None, 'list': cause})
    if not notes.get('cause'):
        missing.append('Root cause after investigation')
    # actions
    sections.append({'heading': '7. Containment and recovery actions', 'paragraphs': [notes['actions']] if notes.get('actions') else ['To be completed by the CISO: what was done, by whom and when.']})
    if not notes.get('actions'):
        missing.append('Containment and recovery actions taken')
    prev = []
    for i in found[:6]:
        prev += (i.get('fix') or [])[:1]
    for g in (av.get('gaps') or []):
        if g.get('severity') in ('high', 'medium'):
            prev += (g.get('fix') or [])[:1]
    if notes.get('preventive'):
        prev = [notes['preventive']] + prev
    sections.append({'heading': '8. Preventive actions', 'list': list(dict.fromkeys(prev))[:10] or ['To be completed by the CISO']})
    cur = av.get('current') or {}
    sections.append({'heading': '9. Current status', 'paragraphs': ['E-mail service %s at %s.' % ('DOWN - no MX host answering since ' + _riyadh(_n(cur.get('down_since'))) if cur.get('up') is False else 'up' if cur.get('up') else 'not measured', _riyadh(now))]})
    return {'title': REG[reg][1], 'regulator': REG[reg][0], 'kind': KIND[kind], 'window': {'from': f, 'to': t}, 'sections': sections, 'missing': missing,
            'statement': _org_fill('Prepared from the records of the {{org.short}} platform (availability probes, mail route checks, Spamhaus results and SIEM counts). A draft until approved by the CISO; submitted by the CISO through %s\'s official incident reporting channel within the timeline it requires - it is not sent from the platform.') % REG[reg][0]}


OPS = {'mailreport.build': build}
