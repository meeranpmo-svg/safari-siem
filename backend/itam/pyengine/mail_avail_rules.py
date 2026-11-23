# Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
"""E-mail availability against its target (default 99.99%): engine/mail-reputation.js probes the MX hosts every minute
(read-only: TCP 25, banner, EHLO, QUIT) and keeps one bucket per day; this module decides. Standard library only.

  mailavail.assess {days, target, now, facts}  -> availability over 30 / 90 / 365 days, downtime budget used and left,
                                                  outages, and what in the design stands between the service and its target

Mail is UP in a minute when at least one MX host answered with 220 (senders retry the next MX). A minute with no probe
(platform down) is not counted either way. If no MX host has ever answered from the platform, outbound TCP 25 is most
likely blocked: availability is "not measurable here", never 0%.
"""
import ipaddress
from datetime import datetime, timezone

DAY = 86400000
WINDOWS = [(30, 'Last 30 days'), (90, 'Last 90 days'), (365, 'Last 365 days')]


def _ip24(ip):
    try:
        return str(ipaddress.ip_network(ip + '/24', strict=False))
    except ValueError:
        return None


def assess(req):
    days = sorted(req.get('days') or [], key=lambda d: d.get('id') or '')
    target = float(req.get('target') or 99.99)
    now = req.get('now') or 0
    today = datetime.fromtimestamp(now / 1000, tz=timezone.utc).date() if now else None
    ever_up = any((d.get('up') or 0) > 0 for d in days)
    windows = []
    for n, label in WINDOWS:
        sel = [d for d in days if today and (today - datetime.strptime(d['id'], '%Y-%m-%d').date()).days < n]
        measured = sum(d.get('measured') or 0 for d in sel)
        down = sum(d.get('down') or 0 for d in sel)
        allowed = n * 1440 * (100 - target) / 100.0      # minutes allowed in the whole window
        pct = round((measured - down) * 100.0 / measured, 4) if measured and ever_up else None
        coverage = round(measured * 100.0 / (n * 1440), 1)
        windows.append({'days': n, 'label': label, 'availability': pct, 'down_minutes': down if ever_up else None, 'measured_minutes': measured,
                        'coverage_pct': coverage, 'allowed_minutes': round(allowed, 1), 'budget_left_minutes': round(allowed - down, 1) if ever_up else None,
                        'budget_used_pct': round(down * 100.0 / allowed, 1) if ever_up and allowed else None,
                        'partial': coverage < 90,
                        # judged on the downtime budget of the window: a short measured history must not read as a breach
                        'state': 'not_measurable' if not ever_up else 'no_data' if not measured else 'breached' if down > allowed else 'at_risk' if allowed and down * 100.0 / allowed >= 75 else 'met'})
    outages = []
    for d in days:
        for o in d.get('outages') or []:
            outages.append(dict(o, day=d['id']))
    outages.sort(key=lambda o: o.get('start') or 0, reverse=True)
    # what stands between the design and the target
    gaps = []
    facts = req.get('facts') or {}
    for dom in facts.get('domains') or []:
        mx = dom.get('mx') or []
        ips = sorted({ip for m in mx for ip in (m.get('ips') or [])})
        nets = {_ip24(ip) for ip in ips if _ip24(ip)}
        provider = any('protection.outlook.com' in str(m.get('host')) or 'mimecast' in str(m.get('host')) or 'pphosted' in str(m.get('host')) for m in mx)
        if not mx:
            continue
        if len(mx) < 2 and not provider:
            gaps.append({'severity': 'high', 'title': '%s has one MX host - any outage of it stops inbound mail' % dom.get('name'),
                         'fix': ['Add a second gateway node as a second MX (different server, ideally a different site / ISP)', 'Or front the gateway with a cloud filtering service that queues mail while you are down']})
        elif len(ips) < 2 and not provider:
            gaps.append({'severity': 'high', 'title': '%s: all MX names resolve to one IP address' % dom.get('name'), 'fix': ['Give the MX hosts separate IPs on separate servers - two names on one IP are one point of failure']})
        elif len(nets) < 2 and not provider:
            gaps.append({'severity': 'medium', 'title': '%s: all MX addresses are in one /24 (one ISP link / one site)' % dom.get('name'), 'fix': ['Place a secondary MX behind a second ISP or in the DR site so one circuit failure does not stop mail']})
        prio = {m.get('priority') for m in mx}
        if len(mx) >= 2 and len(prio) == len(mx) and not provider:
            gaps.append({'severity': 'info', 'title': '%s: MX hosts have different priorities (active / standby)' % dom.get('name'), 'fix': ['Fine for failover; equal priorities spread load and keep both nodes warm - make sure the standby is tested regularly']})
    if not facts.get('domains'):
        gaps.append({'severity': 'medium', 'title': 'No mail domain in Domains & Hosting - nothing to measure', 'fix': ['Add the mail domains in Domains & Hosting, then run Check now on the reputation card']})
    gaps.append({'severity': 'info', 'title': 'Probed from the platform server, inside the network', 'fix': ['This measures whether the MX answers from here; add an external monitor (a probe from outside the Kingdom network) to see what senders on the Internet see']})
    if target >= 99.99:
        gaps.append({'severity': 'info', 'title': '%s%% allows %.1f minutes of downtime a month' % (('%g' % target), 30 * 1440 * (100 - target) / 100.0),
                     'fix': ['Patch and reboot gateway / Exchange nodes one at a time (DAG, load-balanced transport) so maintenance does not count as downtime',
                             'Keep a tested failover runbook; an outage longer than a few minutes breaks the month']})
    return {'target': target, 'windows': windows, 'outages': outages[:50], 'gaps': gaps, 'ever_up': ever_up,
            'note': 'Mail counts as up in a minute when at least one MX host answers SMTP (banner 220). Minutes the platform did not measure are not counted. Availability %s%% means about %.0f minutes of downtime a year.' % (('%g' % target), 365 * 1440 * (100 - target) / 100.0)}


OPS = {'mailavail.assess': assess}
