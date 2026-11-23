# Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
"""VAPT Center (engine/vapt-center.js): one analysis over every finding the platform holds - Greenbone internal scans, FireCompass,
Tenable and the penetration testing engineer. Nothing is guessed; every score lists its points.

op vapt.center  {findings: [{src, id, host, asset, title, severity, cvss, cves[], status, first_seen, last_seen, fixed_at, owner,
                             exposure, criticality, department}], snapshots: [{day, open: [key]}], sla: {critical, high, medium, low},
                 critical_assets: [{name, ip}], now}
  merged      one row per vulnerability on a host: the same CVE (or the same title) on the same host from several sources is ONE
              row listing its sources - it is counted once
  priority    0-100: severity / CVSS, known-exploited / RCE named, internet exposure, business-critical asset, age past its SLA,
              confirmed by more than one source; every point named
  sla         days allowed per severity (default 15 / 30 / 90 / 180): breached, due in 14 days, the breaches forecast for the next
              14 days at the current fix rate
  paths       an internet-facing host with a high / critical open finding in the same /24 as a business-critical asset: a likely
              lateral-movement path to check (a lead, not proof - the platform has no firewall rule model between them)
  delta       against the previous daily snapshot: new, fixed, and REOPENED (fixed before, open again = a regression)
  mttr        days from first seen to fixed, per severity and per owner (needs 3 fixed findings)
  rollups     per asset, per owner, per department, per source
"""

import ipaddress
import re
import statistics

DAY = 86400000
ORDER = ['info', 'low', 'medium', 'high', 'critical']
BASE = {'critical': 60, 'high': 45, 'medium': 25, 'low': 10, 'info': 0}
EXPL = re.compile(r'\b(exploit(ed|able)?|kev|known exploited|ransomware|rce|remote code execution|actively exploited|wormable)\b', re.I)


def _day(v):
    if v in (None, ''):
        return None
    if isinstance(v, (int, float)):
        return float(v)
    import datetime
    s = str(v)
    try:
        if len(s) == 10:
            s += 'T00:00:00+00:00'
        return datetime.datetime.fromisoformat(s.replace('Z', '+00:00')).timestamp() * 1000.0
    except ValueError:
        return None


def _key(f):
    cves = sorted(set(f.get('cves') or []))
    ident = cves[0] if cves else re.sub(r'[^a-z0-9]+', ' ', str(f.get('title') or '').lower()).strip()[:80]
    return (str(f.get('host') or f.get('asset') or '').lower()) + '|' + ident


def _net24(h):
    try:
        ip = ipaddress.ip_address(str(h))
        return str(ipaddress.ip_network(str(ip) + '/24', strict=False)) if ip.version == 4 else None
    except ValueError:
        return None


def op_center(req):
    now = float(req.get('now') or 0)
    sla = {'critical': 15, 'high': 30, 'medium': 90, 'low': 180}
    sla.update({k: int(v) for k, v in (req.get('sla') or {}).items() if k in sla and isinstance(v, (int, float)) and v > 0})
    rows = {}
    for f in req.get('findings') or []:
        if not isinstance(f, dict):
            continue
        k = _key(f)
        r = rows.get(k)
        if not r:
            r = rows[k] = dict(f, key=k, sources=[], ids=[])
        r['sources'] = sorted(set(r['sources'] + [f.get('src')]))
        r['ids'].append(f.get('src') + ':' + str(f.get('id')))
        if ORDER.index(f.get('severity') if f.get('severity') in ORDER else 'info') > ORDER.index(r.get('severity') if r.get('severity') in ORDER else 'info'):
            r['severity'] = f.get('severity')
        if f.get('cvss') is not None and (r.get('cvss') is None or f['cvss'] > r['cvss']):
            r['cvss'] = f['cvss']
        st = [x for x in (r.get('status'), f.get('status'))]
        r['status'] = 'open' if 'open' in st else ('accepted' if 'accepted' in st else 'fixed')
        fs = [_day(x) for x in (r.get('first_seen'), f.get('first_seen')) if _day(x)]
        if fs:
            r['first_seen_ms'] = min(fs)
        for k2 in ('owner', 'department', 'criticality', 'exposure'):
            if not r.get(k2) and f.get(k2):
                r[k2] = f[k2]
        if f.get('fixed_at'):
            r['fixed_at'] = f['fixed_at']
    out_rows = []
    for r in rows.values():
        if not r.get('exposure'):
            try:
                ip = ipaddress.ip_address(str(r.get('host')))
                inside = any(ip in ipaddress.ip_network(n) for n in ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '127.0.0.0/8', '169.254.0.0/16', '100.64.0.0/10')) if ip.version == 4 else ip.is_private
                r['exposure'] = 'internal' if inside else 'external'
            except ValueError:
                r['exposure'] = 'unknown'
        why = []
        b = BASE.get(r.get('severity'), 0)
        if r.get('cvss') is not None:
            b = max(b, int(round(float(r['cvss']) * 6)))
        why.append({'points': b, 'text': '%s severity%s' % (r.get('severity'), ' (CVSS %.1f)' % float(r['cvss']) if r.get('cvss') is not None else '')})
        if EXPL.search(str(r.get('title') or '') + ' ' + str(r.get('description') or '')):
            why.append({'points': 10, 'text': 'known-exploited / remote code execution named in the finding'})
        if r.get('exposure') == 'external':
            why.append({'points': 15, 'text': 'internet-facing'})
        if r.get('criticality') == 'critical':
            why.append({'points': 10, 'text': 'business-critical asset'})
        if len(r['sources']) > 1:
            why.append({'points': 5, 'text': 'confirmed by %d sources (%s)' % (len(r['sources']), ', '.join(r['sources']))})
        age = (now - r['first_seen_ms']) / DAY if r.get('first_seen_ms') else None
        allowed = sla.get(r.get('severity'))
        r['age_days'] = round(age) if age is not None else None
        r['sla_days'] = allowed
        if r['status'] == 'open' and allowed and age is not None:
            left = allowed - age
            r['sla_left'] = round(left)
            r['sla_state'] = 'breached' if left < 0 else 'due' if left <= 14 else 'ok'
            if left < 0:
                why.append({'points': 10, 'text': 'past its %d-day SLA by %d days' % (allowed, -left)})
        else:
            r['sla_state'] = None if r['status'] == 'open' else 'closed'
        r['priority'] = min(100, sum(w['points'] for w in why))
        r['why'] = why
        out_rows.append(r)
    out_rows.sort(key=lambda r: (r['status'] != 'open', -r['priority']))
    openr = [r for r in out_rows if r['status'] == 'open']

    # ---- SLA forecast: at the fix rate of the last 30 days, how many due in 14 days will breach
    fixed30 = [r for r in out_rows if r['status'] == 'fixed' and _day(r.get('fixed_at')) and now - _day(r['fixed_at']) <= 30 * DAY]
    rate = len(fixed30) / 30.0
    due14 = [r for r in openr if r.get('sla_state') == 'due']
    fixable = int(rate * 14)
    sla_out = {'days': sla, 'breached': sum(1 for r in openr if r.get('sla_state') == 'breached'), 'due_14d': len(due14),
               'fix_rate_per_day': round(rate, 2), 'forecast_breaches_14d': max(0, len(due14) - fixable),
               'text': 'at %.1f fixes a day, about %d of the %d findings due in 14 days will breach their SLA' % (rate, max(0, len(due14) - fixable), len(due14))}

    # ---- paths: internet-facing vulnerable host near a critical asset
    crit = [c for c in (req.get('critical_assets') or []) if c.get('ip')]
    paths = []
    for r in openr:
        if r.get('exposure') != 'external' or r.get('severity') not in ('high', 'critical'):
            continue
        n = _net24(r.get('host'))
        for c in crit:
            if n and _net24(c['ip']) == n and str(c['ip']) != str(r.get('host')):
                paths.append({'from': r.get('host'), 'finding': r.get('title'), 'severity': r.get('severity'), 'to': c.get('name') or c['ip'], 'to_ip': c['ip'], 'via': n,
                              'text': 'internet-facing %s (%s) shares %s with business-critical %s - check the firewall rules between them' % (r.get('host'), r.get('severity'), n, c.get('name') or c['ip'])})
    seen, P = set(), []
    for p in paths:
        k = (p['from'], p['to'])
        if k not in seen:
            seen.add(k)
            P.append(p)

    # ---- delta against the previous snapshot
    snaps = sorted([x for x in (req.get('snapshots') or []) if isinstance(x, dict) and x.get('day')], key=lambda x: x['day'])
    now_open = {r['key'] for r in openr}
    delta = {'since': None, 'new': [], 'fixed': [], 'reopened': []}
    if snaps:
        prev = set(snaps[-1].get('open') or [])
        ever = set()
        for x in snaps[:-1]:
            ever |= set(x.get('open') or [])
        delta['since'] = snaps[-1]['day']
        delta['new'] = sorted(now_open - prev)
        delta['fixed'] = sorted(prev - now_open)
        delta['reopened'] = sorted(k for k in (now_open - prev) if k in ever)

    # ---- MTTR
    def mttr(group):
        out = {}
        for k, L in group.items():
            ds = [(_day(r['fixed_at']) - r['first_seen_ms']) / DAY for r in L if r.get('first_seen_ms') and _day(r.get('fixed_at')) and _day(r['fixed_at']) >= r['first_seen_ms']]
            out[k] = {'fixed': len(ds), 'median_days': round(statistics.median(ds), 1) if len(ds) >= 3 else None}
        return out
    fixed = [r for r in out_rows if r['status'] == 'fixed']
    by_sev, by_owner = {}, {}
    for r in fixed:
        by_sev.setdefault(r.get('severity') or 'info', []).append(r)
        by_owner.setdefault(r.get('owner') or '(no owner)', []).append(r)

    # ---- rollups
    def roll(key):
        m = {}
        for r in openr:
            k = r.get(key) or '(not set)'
            x = m.setdefault(k, {key: k, 'open': 0, 'critical': 0, 'high': 0, 'breached': 0, 'max_priority': 0})
            x['open'] += 1
            if r.get('severity') in ('critical', 'high'):
                x[r['severity']] += 1
            if r.get('sla_state') == 'breached':
                x['breached'] += 1
            x['max_priority'] = max(x['max_priority'], r['priority'])
        return sorted(m.values(), key=lambda x: (-x['max_priority'], -x['open']))
    by_src = {}
    for r in openr:
        for s in r['sources']:
            by_src[s] = by_src.get(s, 0) + 1
    counts = {s: sum(1 for r in openr if r.get('severity') == s) for s in ORDER}
    return {'ok': True, 'findings': out_rows, 'counts': counts, 'open': len(openr), 'sla': sla_out, 'paths': P[:30], 'delta': delta,
            'mttr': {'severity': mttr(by_sev), 'owner': mttr(by_owner)},
            'rollups': {'asset': roll('host'), 'owner': roll('owner'), 'department': roll('department'), 'source': by_src},
            'duplicates_merged': sum(len(r['ids']) - 1 for r in out_rows)}


OPS = {'vapt.center': op_center}
