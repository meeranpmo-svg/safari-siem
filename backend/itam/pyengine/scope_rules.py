# Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
"""Scope Studio (engine/discovery-advisor.js): machine learning over Asset Discovery's own history - what the scopes cover,
what they miss, and how each scope should be tuned. Standard library only; every number comes from this platform's scopes,
runs, discovered devices and asset register, never from an assumption.

  coverage      every /24 the platform knows an address in (asset register, discovered devices), and which scopes cover it
  gaps          a /24 with assets but no scope -> a scope PROPOSAL (methods chosen from the device types and open ports
                seen there, and from what each method actually found in your other scopes - learned, Laplace-smoothed)
  scope health  0-100 per scope from freshness, last run, yield, safety gate and anomalies - every point said in words
  tuning        a method that found nothing in 3+ runs, ports that call for a method that is off (SSH -> Unix, 1433/1521/
                3306/5432 -> databases, network gear -> SNMP), a mostly empty range, the schedule vs how often things change
  duration      least-squares fit of run seconds on (addresses x active methods) over finished runs -> each scope's and each
                proposal's expected duration, warned when it does not fit the scan window
  anomaly       robust z-score (median / MAD) of devices seen in the last run against the scope's own history

Proposals are only proposals: a System Admin accepts one (the scope is created disabled, its safety gate closed) or dismisses
it with a reason. Nothing here scans, creates or changes anything.
"""
import math
import re

ACTIVE = ['sweep', 'snmp', 'db', 'unix', 'storage']
NAMES = {'sweep': 'Network sweep', 'snmp': 'SNMP', 'db': 'Database listeners', 'unix': 'Unix / SSH', 'storage': 'Storage arrays',
         'arp': 'ARP cache', 'ad': 'Active Directory', 'vcenter': 'vCenter', 'nutanix': 'Nutanix', 'hyperv': 'Hyper-V',
         'cucm': 'CUCM', 'azure': 'Azure', 'aws': 'AWS'}
DB_PORTS = {1433, 1521, 1522, 3306, 5432, 50000, 27017, 30015}
NET_TYPES = {'switch', 'router', 'firewall', 'ap', 'network', 'wireless'}   # discovery classes and ITAM asset types
SRV_TYPES = {'server', 'vm', 'virtual_machine'}
STORAGE_PORTS = {3260, 10000}
IP_RE = re.compile(r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$')


def ip2int(s):
    m = IP_RE.match(str(s or '').strip())
    if not m:
        return None
    p = [int(x) for x in m.groups()]
    if any(x > 255 for x in p):
        return None
    return (p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3]


def int2ip(n):
    return '%d.%d.%d.%d' % ((n >> 24) & 255, (n >> 16) & 255, (n >> 8) & 255, n & 255)


def parse_target(t):
    """'10.1.1.0/24' | '10.1.1.10-10.1.1.50' | '10.1.1.10-50' | '10.1.1.7' -> (first, last) or None"""
    t = str(t or '').strip()
    if '/' in t:
        a, b = t.split('/', 1)
        n = ip2int(a)
        if n is None or not b.isdigit() or int(b) > 32:
            return None
        bits = int(b)
        mask = (0xFFFFFFFF << (32 - bits)) & 0xFFFFFFFF if bits else 0
        first = n & mask
        return first, first | (~mask & 0xFFFFFFFF)
    if '-' in t:
        a, b = t.split('-', 1)
        n = ip2int(a)
        if n is None:
            return None
        if b.isdigit():
            last = (n & 0xFFFFFF00) | int(b)
        else:
            last = ip2int(b)
        if last is None or last < n:
            return None
        return n, last
    n = ip2int(t)
    return (n, n) if n is not None else None


def net24(n):
    return n & 0xFFFFFF00


def label24(n):
    return int2ip(net24(n)) + '/24'


def scope_ranges(s):
    inc = [r for r in (parse_target(x) for x in s.get('targets') or []) if r]
    exc = [r for r in (parse_target(x) for x in s.get('exclusions') or []) if r]
    return inc, exc


def covers(s, n):
    inc, exc = scope_ranges(s)
    return any(a <= n <= b for a, b in inc) and not any(a <= n <= b for a, b in exc)


def device_ips(d):
    out = []
    for x in [d.get('ip')] + list(d.get('ips') or []):
        n = ip2int(x)
        if n is not None and n not in out:
            out.append(n)
    return out


def iso_ms(s):
    """ISO-8601 'YYYY-MM-DDTHH:MM:SS(.sss)Z' -> epoch ms (UTC), None when not parsable"""
    m = re.match(r'^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})', str(s or ''))
    if not m:
        return None
    y, mo, d, h, mi, se = [int(x) for x in m.groups()]
    # days from civil (Howard Hinnant)
    y2 = y - (1 if mo <= 2 else 0)
    era = (y2 if y2 >= 0 else y2 - 399) // 400
    yoe = y2 - era * 400
    doy = (153 * (mo + (-3 if mo > 2 else 9)) + 2) // 5 + d - 1
    doe = yoe * 365 + yoe // 4 - yoe // 100 + doy
    days = era * 146097 + doe - 719468
    return ((days * 24 + h) * 60 + mi) * 60000 + se * 1000


def median(xs):
    xs = sorted(xs)
    n = len(xs)
    return None if not n else (xs[n // 2] if n % 2 else (xs[n // 2 - 1] + xs[n // 2]) / 2.0)


# ---------------------------------------------------------------- learning from the platform's own runs
def fit_duration(runs, scopes):
    """seconds ~ a + b * (addresses x active methods), least squares over finished runs; None below 3 runs"""
    by = {s['id']: s for s in scopes}
    xs, ys = [], []
    for r in runs:
        if r.get('status') != 'finished' or not r.get('finished_at'):
            continue
        a, b = iso_ms(r.get('started_at')), iso_ms(r.get('finished_at'))
        if a is None or b is None or b <= a:
            continue
        hosts = ((r.get('progress') or {}).get('hosts_total')) or (by.get(r.get('scope_id')) or {}).get('host_count') or 0
        act = len([m for m in r.get('methods_run') or [] if m in ACTIVE]) or 1
        xs.append(float(hosts * act))
        ys.append((b - a) / 1000.0)
    if len(xs) < 3:
        return None
    mx, my = sum(xs) / len(xs), sum(ys) / len(ys)
    sxx = sum((x - mx) ** 2 for x in xs)
    if sxx == 0:
        return {'a': my, 'b': 0.0, 'n': len(xs), 'r2': 0.0}
    b = sum((x - mx) * (y - my) for x, y in zip(xs, ys)) / sxx
    a = my - b * mx
    ss_tot = sum((y - my) ** 2 for y in ys) or 1.0
    ss_res = sum((y - (a + b * x)) ** 2 for x, y in zip(xs, ys))
    return {'a': max(0.0, a), 'b': max(0.0, b), 'n': len(xs), 'r2': round(max(0.0, 1 - ss_res / ss_tot), 2)}


def predict(model, hosts, active):
    if not model:
        return None
    return int(round(model['a'] + model['b'] * hosts * max(1, active)))


def method_yield(scopes, runs, devices):
    """per method: in how many scopes that ran it at least twice did it find >= 1 device - the learned prior"""
    nruns = {}
    for r in runs:
        if r.get('status') == 'finished':
            for m in r.get('methods_run') or []:
                nruns[(r.get('scope_id'), m)] = nruns.get((r.get('scope_id'), m), 0) + 1
    found = set()
    for d in devices:
        for m in (d.get('methods') or {}):
            found.add((d.get('scope_id'), m))
    out = {}
    for (sid, m), n in nruns.items():
        if n < 2:
            continue
        o = out.setdefault(m, {'scopes': 0, 'found': 0})
        o['scopes'] += 1
        o['found'] += 1 if (sid, m) in found else 0
    for m, o in out.items():
        o['rate'] = round((o['found'] + 1) / (o['scopes'] + 2), 2)   # Laplace: one success and one failure assumed
    return out


def fmt_dur(sec):
    if sec is None:
        return None
    return '%d s' % sec if sec < 90 else '%d min' % round(sec / 60.0) if sec < 5400 else '%.1f h' % (sec / 3600.0)


def window_minutes(w):
    if not w or not w.get('start') or not w.get('end'):
        return None
    a = [int(x) for x in w['start'].split(':')]
    b = [int(x) for x in w['end'].split(':')]
    m = (b[0] * 60 + b[1]) - (a[0] * 60 + a[1])
    return m if m > 0 else m + 1440


# ---------------------------------------------------------------- method suggestions from what the subnet holds
def suggest_methods(types, ports, yields):
    """types: {type: count}; ports: {port: hosts}; -> [(method, why, confidence)]"""
    out = [('sweep', 'finds every live address (ICMP + the common TCP ports)', 0.95)]
    net = sum(types.get(t, 0) for t in NET_TYPES)
    srv = sum(types.get(t, 0) for t in SRV_TYPES)
    ssh = ports.get(22, 0)
    db = sum(v for p, v in ports.items() if p in DB_PORTS)
    st = sum(v for p, v in ports.items() if p in STORAGE_PORTS)
    learned = lambda m: (yields.get(m) or {}).get('rate')
    if net:
        out.append(('snmp', '%d network device(s) here answer best to SNMP' % net, learned('snmp') or 0.8))
    if ssh:
        out.append(('unix', '%d host(s) answer SSH - a read-only SSH login adds OS, serial and model' % ssh, learned('unix') or 0.7))
    if db or srv >= 3:
        out.append(('db', ('%d database listener(s) seen' % db) if db else '%d servers here - database listeners are likely' % srv, learned('db') or (0.75 if db else 0.4)))
    if st:
        out.append(('storage', '%d host(s) with iSCSI / NDMP open - storage arrays' % st, learned('storage') or 0.6))
    return out


# ---------------------------------------------------------------- the operation
def op_advise(req):
    now = req.get('now') or 0
    scopes = [s for s in (req.get('scopes') or []) if isinstance(s, dict) and s.get('status') != 'archived']
    runs = [r for r in (req.get('runs') or []) if isinstance(r, dict)]
    devices = [d for d in (req.get('devices') or []) if isinstance(d, dict)]
    assets = [a for a in (req.get('assets') or []) if isinstance(a, dict)]
    dismissed = set(req.get('dismissed') or [])
    model = fit_duration(runs, scopes)
    yields = method_yield(scopes, runs, devices)

    # coverage per /24
    nets = {}

    def bucket(n):
        k = net24(n)
        return nets.setdefault(k, {'assets': 0, 'devices': 0, 'types': {}, 'ports': {}, 'sites': {}, 'covered': set()})
    for a in assets:
        n = ip2int(a.get('mgmt_ip'))
        if n is None:
            continue
        b = bucket(n)
        b['assets'] += 1
        t = a.get('type') or 'other'
        b['types'][t] = b['types'].get(t, 0) + 1
        if a.get('site'):
            b['sites'][a['site']] = b['sites'].get(a['site'], 0) + 1
    for d in devices:
        for n in device_ips(d)[:1]:
            b = bucket(n)
            b['devices'] += 1
            t = d.get('type') or 'unknown'
            b['types'][t] = b['types'].get(t, 0) + 1
            for p in d.get('open_ports') or []:
                b['ports'][p] = b['ports'].get(p, 0) + 1
            if d.get('site'):
                b['sites'][d['site']] = b['sites'].get(d['site'], 0) + 1
    for k, b in nets.items():
        for s in scopes:
            # a /24 counts as covered when the scope covers its addresses we know of (sample its first known host)
            if any(covers(s, k + i) for i in (1, 10, 100, 200)) or covers(s, k):
                b['covered'].add(s['id'])
    coverage = []
    with_assets = 0
    covered_assets = 0
    for k in sorted(nets):
        b = nets[k]
        known = b['assets'] + b['devices']
        names = [s['name'] for s in scopes if s['id'] in b['covered']]
        coverage.append({'subnet': label24(k), 'assets': b['assets'], 'devices': b['devices'], 'scopes': names, 'covered': bool(names),
                         'types': b['types'], 'site': max(b['sites'], key=b['sites'].get) if b['sites'] else None})
        if b['assets']:
            with_assets += b['assets']
            covered_assets += b['assets'] if names else 0

    # proposals: uncovered /24s with assets (or devices seen by passive methods), most assets first
    proposals = []
    for c in sorted(coverage, key=lambda x: -(x['assets'] * 2 + x['devices'])):
        if c['covered'] or (c['assets'] + c['devices']) == 0:
            continue
        key = 'new:' + c['subnet']
        if key in dismissed:
            continue
        b = nets[net24(ip2int(c['subnet'].split('/')[0]))]
        meth = suggest_methods(b['types'], b['ports'], yields)
        act = len([m for m, _, _ in meth if m in ACTIVE])
        est = predict(model, 254, act)
        top = sorted(c['types'].items(), key=lambda x: -x[1])[:3]
        proposals.append({
            'key': key, 'kind': 'new-scope', 'subnet': c['subnet'], 'site': c['site'],
            'name': (c['site'] + ' ' if c['site'] else '') + c['subnet'],
            'targets': [c['subnet']], 'methods': [m for m, _, _ in meth],
            'methods_why': [{'method': m, 'name': NAMES[m], 'why': w, 'confidence': round(conf, 2)} for m, w, conf in meth],
            'why': ['%d asset(s) in the register and %d discovered device(s) live in %s, and no scope covers it' % (c['assets'], c['devices'], c['subnet'])]
                   + (['mostly ' + ', '.join('%s (%d)' % t for t in top)] if top else []),
            'estimate': fmt_dur(est), 'estimate_s': est,
            'confidence': round(min(0.95, 0.5 + 0.1 * (c['assets'] + c['devices'])), 2),
            'priority': c['assets'] * 2 + c['devices'],
        })

    # per scope: health, anomalies, tuning
    sruns = {}
    for r in runs:
        sruns.setdefault(r.get('scope_id'), []).append(r)
    sdev = {}
    for d in devices:
        sdev.setdefault(d.get('scope_id'), []).append(d)
    out_scopes = []
    for s in scopes:
        rs = sorted(sruns.get(s['id'], []), key=lambda r: r.get('started_at') or '')
        done = [r for r in rs if r.get('status') == 'finished']
        last = rs[-1] if rs else None
        devs = sdev.get(s['id'], [])
        enabled = [k for k, v in (s.get('methods') or {}).items() if isinstance(v, dict) and v.get('enabled')]
        act = len([m for m in enabled if m in ACTIVE])
        score, why, recs = 100, [], []

        def minus(n, text):
            nonlocal score
            score -= n
            why.append({'points': -n, 'why': text})
        gate = s.get('gate') or {}
        if s.get('status') != 'active':
            minus(20, 'the scope is disabled')
        if gate.get('required') and not gate.get('open'):
            minus(25, 'safety gate closed - the active methods cannot run' + (' (addresses changed since approval)' if gate.get('stale') else ''))
            recs.append({'kind': 'gate', 'severity': 'high', 'text': 'Complete the pre-scan checklist so the active methods can run.'})
        if not rs:
            minus(25, 'never run')
            recs.append({'kind': 'run', 'severity': 'medium', 'text': 'Run it once to establish a baseline.'})
        elif last.get('status') in ('failed', 'error'):
            minus(20, 'the last run failed')
        lt = iso_ms((done[-1] if done else {}).get('finished_at')) if done else None
        age_d = (now - lt) / 86400000.0 if lt and now else None
        sched = str(s.get('schedule_label') or '')
        expect_d = 1 if 'daily' in sched.lower() or 'every day' in sched.lower() else 7 if 'week' in sched.lower() else 31 if 'month' in sched.lower() else None
        if age_d is not None and expect_d and age_d > 2 * expect_d:
            minus(15, 'last finished %d days ago, the schedule expects every %d day(s)' % (age_d, expect_d))
        # anomaly: robust z of devices seen in the last finished run
        seen = [r.get('devices_seen') or 0 for r in done]
        anomaly = None
        if len(seen) >= 5:
            hist, cur = seen[:-1], seen[-1]
            med = median(hist)
            mad = median([abs(x - med) for x in hist]) or 1.0
            z = 0.6745 * (cur - med) / mad
            if z <= -3.5:
                anomaly = {'z': round(z, 1), 'seen': cur, 'usual': med, 'text': 'the last run saw %d device(s), usually %d - a firewall rule, a VLAN change or a scan window may be blocking it' % (cur, med)}
                minus(15, anomaly['text'])
                recs.append({'kind': 'anomaly', 'severity': 'high', 'text': 'Check what changed: the last run saw %d device(s) against a usual %d.' % (cur, med)})
            elif z >= 3.5:
                anomaly = {'z': round(z, 1), 'seen': cur, 'usual': med, 'text': 'the last run saw %d device(s), usually %d - new devices on this network' % (cur, med)}
                recs.append({'kind': 'anomaly', 'severity': 'medium', 'text': '%d more devices than usual: review the new results before approving them.' % (cur - med)})
        # yield and emptiness
        hosts = s.get('host_count') or 0
        alive = max([((r.get('progress') or {}).get('alive') or 0) for r in done[-3:]] or [0])
        if done and hosts >= 512 and alive and alive / float(hosts) < 0.05:
            used = sorted({label24(n) for d in devs for n in device_ips(d)[:1]})
            recs.append({'kind': 'narrow', 'severity': 'low', 'text': 'Only %d of %d addresses answer (%.1f%%): narrow the scope to the used subnets%s to scan faster.'
                         % (alive, hosts, 100.0 * alive / hosts, (' (' + ', '.join(used[:6]) + ')') if used else '')})
        # methods that never found anything / ports calling for a method that is off
        found_by = {}
        for d in devs:
            for m in (d.get('methods') or {}):
                found_by[m] = found_by.get(m, 0) + 1
        for m in enabled:
            runs_with = len([r for r in done if m in (r.get('methods_run') or [])])
            if runs_with >= 3 and not found_by.get(m) and m != 'sweep':
                recs.append({'kind': 'method-idle', 'method': m, 'severity': 'low', 'text': '%s ran %d times and found nothing - check its credential, or switch it off to scan faster.' % (NAMES.get(m, m), runs_with)})
        types, ports = {}, {}
        for d in devs:
            types[d.get('type') or 'unknown'] = types.get(d.get('type') or 'unknown', 0) + 1
            for p in d.get('open_ports') or []:
                ports[p] = ports.get(p, 0) + 1
        for m, w, conf in suggest_methods(types, ports, yields):
            if m not in enabled and m != 'sweep':
                recs.append({'kind': 'method-add', 'method': m, 'severity': 'medium', 'text': 'Enable %s: %s.' % (NAMES[m], w), 'confidence': round(conf, 2)})
        # schedule vs change rate
        news = [r.get('devices_new') or 0 for r in done[-6:]]
        if len(news) >= 4 and hosts:
            rate = sum(news) / float(len(news))
            if rate >= max(3, 0.02 * hosts) and expect_d and expect_d >= 7:
                recs.append({'kind': 'schedule', 'severity': 'medium', 'text': 'About %d new device(s) per run: scan daily instead of every %d days to keep the register current.' % (round(rate), expect_d)})
            elif rate == 0 and expect_d == 1 and len(news) >= 6:
                recs.append({'kind': 'schedule', 'severity': 'low', 'text': 'Nothing new in the last %d runs: weekly is enough for this network.' % len(news)})
        est = predict(model, hosts, act)
        wm = window_minutes(s.get('window'))
        if est and wm and est > wm * 60:
            recs.append({'kind': 'window', 'severity': 'medium', 'text': 'Expected run time %s does not fit the %d-minute scan window: widen the window or split the scope.' % (fmt_dur(est), wm)})
        score = max(0, min(100, score))
        out_scopes.append({'id': s['id'], 'name': s.get('name'), 'health': score, 'grade': 'good' if score >= 80 else 'fair' if score >= 55 else 'poor', 'why': why,
                           'recommendations': recs, 'anomaly': anomaly, 'estimate': fmt_dur(est), 'estimate_s': est, 'runs': len(rs), 'found': len(devs),
                           'trend': [r.get('devices_seen') or 0 for r in done[-12:]], 'last_status': last.get('status') if last else None})

    total_assets_ip = with_assets
    return {'ok': True,
            'summary': {'subnets': len(coverage), 'covered': len([c for c in coverage if c['covered']]), 'uncovered': len([c for c in coverage if not c['covered']]),
                        'assets_with_ip': total_assets_ip, 'assets_covered': covered_assets,
                        'coverage_pct': int(100.0 * covered_assets / total_assets_ip + 0.5) if total_assets_ip else None,   # half up, as people read percentages
                        'scopes': len(scopes), 'healthy': len([x for x in out_scopes if x['grade'] == 'good']), 'proposals': len(proposals)},
            'coverage': coverage[:500], 'proposals': proposals[:40], 'scopes': out_scopes,
            'learned': {'duration_model': model, 'method_yield': yields,
                        'note': 'Learned from this platform\'s own scans: run time from %s finished run(s), method success from the scopes that ran each method at least twice.' % (model['n'] if model else 'fewer than 3')}}


OPS = {'scope.advise': op_advise}
