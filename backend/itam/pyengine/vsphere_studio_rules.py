# Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
"""vSphere Studio rules (engine/vsphere-studio.js): VMware vCenter / ESXi health from what the capacity collection read
(engine/virt-capacity.js, read-only SOAP) and this server's own hourly VM samples. Nothing is invented: a value vCenter did not
report stays None and costs nothing - the page says "not reported".

op vsphere.studio  {clusters, hosts, datastores, vms, rightsize, findings, settings, policy, now}
  host health     100 minus named points: disconnected / not responding 50, health red 30 / yellow 10, CPU over the limit 15,
                  memory over the limit 15, vCPU per core above the ratio 10, ESXi version differs from the cluster's 5.
  cluster health  100 minus: HA off 20, cannot survive one host failure (no room after N+1) 20, health red 25 / yellow 10,
                  hosts out of balance with DRS off 10, ESXi version drift 5, every open finding on it (high 5, critical 10).
  imbalance       spread (max - min) and standard deviation of host CPU and memory in use across the connected hosts; a spread
                  of 25 points or more with DRS off is a finding, with the busiest and the emptiest host named.
  workload        k-means (k up to 4, deterministic seeds) over the VMs' own 95th-percentile CPU and memory (hourly samples, the
  profiles        same basis as right-sizing); each group is named from its centre: idle, steady, memory-heavy, CPU-heavy, hot.
                  VMs with too little history are left out and counted - never guessed.
  unusual CPU     a running VM whose CPU now is above both 1.5x its own p95 and its p95 + 25 points (and above 40 %).
  VM health       100 minus: snapshots older than the policy (warn 10 / high 25), more than 3 snapshots 10, disks need
                  consolidation 15, VMware Tools not running 10, CPU or memory short (p95 >= 90 %) 15, unusual CPU 10.
  overall         the mean of the cluster scores weighted by VMs, and the ten things to look at first.
"""

import math


def _f(v):
    try:
        x = float(v)
        return x if math.isfinite(x) else None
    except (TypeError, ValueError):
        return None


def _score(items):
    return max(0, 100 - sum(i['points'] for i in items))


def _take(items, p, text):
    items.append({'points': p, 'text': text})


def _kmeans(pts, k, iters=30):
    """pts: list of (x, y) in 0..100. Deterministic seeds: spread along x+y. Returns (centres, labels)."""
    if not pts:
        return [], []
    k = max(1, min(k, len(pts)))
    order = sorted(range(len(pts)), key=lambda i: pts[i][0] + pts[i][1])
    cen = [pts[order[int(round(j * (len(pts) - 1) / max(1, k - 1)))]] for j in range(k)]
    lab = [0] * len(pts)
    for _ in range(iters):
        changed = False
        for i, (x, y) in enumerate(pts):
            j = min(range(len(cen)), key=lambda c: (x - cen[c][0]) ** 2 + (y - cen[c][1]) ** 2)
            if j != lab[i]:
                lab[i], changed = j, True
        for c in range(len(cen)):
            mem = [pts[i] for i in range(len(pts)) if lab[i] == c]
            if mem:
                cen[c] = (sum(p[0] for p in mem) / len(mem), sum(p[1] for p in mem) / len(mem))
        if not changed:
            break
    return cen, lab


def _profile_name(cx, cy):
    if cx >= 70 and cy >= 70:
        return 'hot', 'busy on both CPU and memory - watch, it may be short'
    if cx >= 50:
        return 'CPU-heavy', 'uses most of its vCPUs at peak'
    if cy >= 60:
        return 'memory-heavy', 'uses most of its memory, little CPU'
    if cx < 10 and cy < 30:
        return 'idle', 'little CPU or memory even at peak - right-size or retire'
    return 'steady', 'moderate, even load'


def op_studio(req):
    st = req.get('settings') or {}
    pol = req.get('policy') or {}
    cpu_max, mem_max, ratio_max = _f(st.get('cpu_max_pct')) or 80, _f(st.get('mem_max_pct')) or 90, _f(st.get('vcpu_ratio')) or 4
    warn_d, high_d = _f(pol.get('snapshot_warn_days')) or 3, _f(pol.get('snapshot_high_days')) or 7
    now = (_f(req.get('now')) or 0) / 1000.0
    clusters, hosts, dss, vms = req.get('clusters') or [], req.get('hosts') or [], req.get('datastores') or [], req.get('vms') or []
    rs = {(r.get('pid'), r.get('id')): r for r in (req.get('rightsize') or {}).get('rows', [])}
    findings = req.get('findings') or []
    ckey = lambda platform, name: '%s|%s' % (platform, name)

    # ---- hosts
    by_cluster = {}
    for h in hosts:
        by_cluster.setdefault(ckey(h.get('platform'), h.get('cluster') or 'Standalone hosts'), []).append(h)
    ver_major = {}
    for k, hs in by_cluster.items():
        cnt = {}
        for h in hs:
            v = h.get('version')
            if v:
                cnt[v] = cnt.get(v, 0) + 1
        ver_major[k] = max(cnt, key=cnt.get) if cnt else None
    out_hosts = []
    for h in hosts:
        k = ckey(h.get('platform'), h.get('cluster') or 'Standalone hosts')
        why = []
        state = h.get('state')
        if not h.get('maintenance') and state and state != 'connected':
            _take(why, 50, 'host is %s in vCenter' % ('not responding' if state == 'notResponding' else state))
        if h.get('status') == 'red':
            _take(why, 30, 'vCenter health is red')
        elif h.get('status') == 'yellow':
            _take(why, 10, 'vCenter health is yellow')
        cpu, mem, ratio = _f(h.get('cpu_used_pct')), _f(h.get('mem_used_pct')), _f(h.get('vcpu_ratio'))
        if cpu is not None and cpu > cpu_max:
            _take(why, 15, 'CPU %.0f %% (limit %.0f %%)' % (cpu, cpu_max))
        if mem is not None and mem > mem_max:
            _take(why, 15, 'memory %.0f %% (limit %.0f %%)' % (mem, mem_max))
        if ratio is not None and ratio > ratio_max:
            _take(why, 10, '%.2f vCPU per core (limit %.0f)' % (ratio, ratio_max))
        if ver_major.get(k) and h.get('version') and h.get('version') != ver_major[k]:
            _take(why, 5, 'runs %s; most hosts in the cluster run %s' % (h.get('version'), ver_major[k]))
        out_hosts.append(dict(h, score=_score(why), why_score=why))

    # ---- clusters
    open_by = {}
    for f in findings:
        tg = f.get('target') or {}
        name = tg.get('cluster') or (tg.get('name') if tg.get('type') == 'cluster' else None)
        if name:
            open_by.setdefault(ckey(tg.get('platform'), name), []).append(f)
    out_cl = []
    for c in clusters:
        k = ckey(c.get('platform'), c.get('name'))
        hs = [h for h in out_hosts if ckey(h.get('platform'), h.get('cluster') or 'Standalone hosts') == k]
        up = [h for h in hs if h.get('state') == 'connected' and not h.get('maintenance')]
        why = []
        if c.get('ha') is False:
            _take(why, 20, 'vSphere HA is off - a host failure leaves its VMs down')
        room = c.get('room') or {}
        if c.get('n_plus_1') and room and min(room.get('cpu') or 0, room.get('mem') or 0) == 0 and (c.get('vms_on') or 0) > 0:
            _take(why, 20, 'no room for one more average VM after one host fails (N+1, limit %s)' % (room.get('limit') or 'memory'))
        if c.get('status') == 'red':
            _take(why, 25, 'vCenter health is red')
        elif c.get('status') == 'yellow':
            _take(why, 10, 'vCenter health is yellow')
        bal = None
        for metric in ('cpu_used_pct', 'mem_used_pct'):
            vals = [_f(h.get(metric)) for h in up if _f(h.get(metric)) is not None]
            if len(vals) >= 2:
                m = sum(vals) / len(vals)
                sd = (sum((v - m) ** 2 for v in vals) / len(vals)) ** 0.5
                hi = max(up, key=lambda h: _f(h.get(metric)) if _f(h.get(metric)) is not None else -1)
                lo = min(up, key=lambda h: _f(h.get(metric)) if _f(h.get(metric)) is not None else 999)
                spread = max(vals) - min(vals)
                b = {'metric': 'CPU' if metric == 'cpu_used_pct' else 'memory', 'spread': int(round(spread)), 'sd': round(sd, 1), 'busiest': hi.get('name'), 'emptiest': lo.get('name')}
                if not bal or b['spread'] > bal['spread']:
                    bal = b
        if bal and bal['spread'] >= 25 and c.get('drs') is not True:
            _take(why, 10, 'hosts out of balance: %s %s points apart (%s busiest, %s emptiest) and DRS is %s' % (bal['metric'], bal['spread'], bal['busiest'], bal['emptiest'], 'off' if c.get('drs') is False else 'not reported'))
        vers = sorted(set(h.get('version') for h in hs if h.get('version')))
        if len(vers) > 1:
            _take(why, 5, 'ESXi version drift: %s' % ', '.join(vers))
        fs = open_by.get(k, [])
        crit = len([f for f in fs if f.get('severity') == 'critical'])
        high = len([f for f in fs if f.get('severity') == 'high'])
        if crit or high:
            _take(why, min(30, crit * 10 + high * 5), '%d critical and %d high open finding(s) from the AI Virtualization Administrator' % (crit, high))
        out_cl.append(dict(c, score=_score(why), why_score=why, balance=bal, versions=vers, open_findings=len(fs)))

    # ---- VMs: workload profiles, unusual CPU, health
    pts, idx, short = [], [], 0
    for i, v in enumerate(vms):
        if v.get('power') != 'on':
            continue
        r = rs.get((v.get('pid'), v.get('id')))
        if not r or r.get('cpu_p95') is None or r.get('mem_p95') is None:
            short += 1
            continue
        pts.append((min(100.0, _f(r['cpu_p95']) or 0), min(100.0, _f(r['mem_p95']) or 0)))
        idx.append(i)
    k = 4 if len(pts) >= 12 else (2 if len(pts) >= 4 else 1 if pts else 0)
    cen, lab = _kmeans(pts, k) if k else ([], [])
    # centres that land in the same named band are one profile (weighted centre); an empty centre is dropped
    byname = {}
    for c, (cx, cy) in enumerate(cen):
        n_ = lab.count(c)
        if not n_:
            continue
        name, desc = _profile_name(cx, cy)
        g = byname.setdefault(name, {'name': name, 'what': desc, 'sx': 0.0, 'sy': 0.0, 'vms': 0, 'ids': []})
        g['sx'] += cx * n_; g['sy'] += cy * n_; g['vms'] += n_; g['ids'].append(c)
    groups = [{'name': g['name'], 'what': g['what'], 'cpu_p95': round(g['sx'] / g['vms'], 1), 'mem_p95': round(g['sy'] / g['vms'], 1), 'vms': g['vms']} for g in sorted(byname.values(), key=lambda x: -x['vms'])]
    cname = {c: g['name'] for g in byname.values() for c in g['ids']}
    prof = {idx[j]: cname.get(lab[j]) for j in range(len(idx))}
    out_vms = []
    for i, v in enumerate(vms):
        r = rs.get((v.get('pid'), v.get('id'))) or {}
        why, flags = [], []
        sn = v.get('snapshots') or None
        if sn and sn.get('count'):
            age = None
            try:
                import datetime as dt
                age = (now - (dt.datetime.strptime(str(sn.get('oldest'))[:19], '%Y-%m-%dT%H:%M:%S') - dt.datetime(1970, 1, 1)).total_seconds()) / 86400.0
            except (ValueError, TypeError):
                age = None
            if age is not None and age >= high_d:
                _take(why, 25, '%d snapshot(s), oldest %d days (policy %d)' % (sn['count'], age, high_d))
            elif age is not None and age >= warn_d:
                _take(why, 10, '%d snapshot(s), oldest %d days (policy %d)' % (sn['count'], age, warn_d))
            if sn['count'] > 3:
                _take(why, 10, '%d snapshots in the chain' % sn['count'])
        if v.get('consolidate') is True:
            _take(why, 15, 'virtual disks need consolidation')
        if v.get('power') == 'on' and v.get('tools') == 'not-running':
            _take(why, 10, 'VMware Tools not running')
        if r.get('cpu_short') or r.get('mem_short'):
            _take(why, 15, 'short of %s at peak (p95 %s %%)' % ('CPU' if r.get('cpu_short') else 'memory', r.get('cpu_p95') if r.get('cpu_short') else r.get('mem_p95')))
        unusual = None
        cur, p95 = _f(v.get('cpu_pct')), _f(r.get('cpu_p95'))
        if v.get('power') == 'on' and cur is not None and p95 is not None and cur > 40 and cur > p95 * 1.5 and cur > p95 + 25:
            unusual = 'CPU %.0f %% now, usually at most %.0f %% (its own p95)' % (cur, p95)
            _take(why, 10, unusual)
        rec = None
        if r.get('vcpus_to') or r.get('mem_to'):
            rec = {'vcpus_to': r.get('vcpus_to'), 'mem_to': r.get('mem_to'), 'save_vcpu': r.get('save_vcpu'), 'save_mem_gb': r.get('save_mem_gb')}
        out_vms.append(dict(v, score=_score(why), why_score=why, profile=prof.get(i), unusual=unusual, rightsize=rec,
                            cpu_p95=r.get('cpu_p95'), mem_p95=r.get('mem_p95'), samples=r.get('samples')))

    # ---- datastores
    out_ds = []
    st_max = _f(st.get('storage_max_pct')) or 80
    for d in dss:
        used, prov = _f(d.get('used_pct')), _f(d.get('provisioned_pct'))
        risk = 'down' if d.get('accessible') is False else 'full' if used is not None and used >= 95 else 'high' if used is not None and used > st_max else 'overcommitted' if prov is not None and prov > 150 else 'ok' if used is not None else 'unknown'
        out_ds.append(dict(d, risk=risk))

    # ---- overall + look-at-first
    tot_vms = sum(max(1, c.get('vms') or 0) for c in out_cl)
    overall = int(round(sum(c['score'] * max(1, c.get('vms') or 0) for c in out_cl) / float(tot_vms))) if out_cl else None
    first = []
    for c in out_cl:
        for w in c['why_score']:
            first.append({'kind': 'cluster', 'name': c.get('name'), 'platform': c.get('platform'), 'points': w['points'], 'text': w['text']})
    for h in out_hosts:
        for w in h['why_score']:
            first.append({'kind': 'host', 'name': h.get('name'), 'platform': h.get('platform'), 'points': w['points'], 'text': w['text']})
    for v in out_vms:
        for w in v['why_score']:
            first.append({'kind': 'vm', 'name': v.get('name'), 'platform': v.get('platform'), 'id': v.get('id'), 'pid': v.get('pid'), 'points': w['points'], 'text': w['text']})
    for d in out_ds:
        if d['risk'] in ('down', 'full', 'high'):
            first.append({'kind': 'datastore', 'name': d.get('name'), 'platform': d.get('platform'), 'points': {'down': 50, 'full': 40, 'high': 15}[d['risk']],
                          'text': 'not accessible' if d['risk'] == 'down' else '%s %% used' % d.get('used_pct')})
    first.sort(key=lambda x: -x['points'])
    on = [v for v in vms if v.get('power') == 'on']
    return {'ok': True, 'overall': {'score': overall, 'state': 'NOT CONNECTED' if not clusters and not hosts else 'CRITICAL' if overall is not None and overall < 50 else 'ATTENTION' if overall is not None and overall < 80 else 'HEALTHY'},
            'clusters': out_cl, 'hosts': out_hosts, 'datastores': out_ds, 'vms': out_vms, 'profiles': groups, 'look_first': first[:10],
            'summary': {'clusters': len(out_cl), 'hosts': len(out_hosts), 'hosts_down': len([h for h in out_hosts if h.get('state') not in (None, 'connected') and not h.get('maintenance')]),
                        'maintenance': len([h for h in out_hosts if h.get('maintenance')]), 'vms': len(vms), 'vms_on': len(on),
                        'snapshots_old': len([v for v in out_vms if any('snapshot' in w['text'] and 'days' in w['text'] for w in v['why_score'])]),
                        'unusual': len([v for v in out_vms if v['unusual']]), 'rightsize': len([v for v in out_vms if v['rightsize']]),
                        'tools_off': len([v for v in out_vms if v.get('power') == 'on' and v.get('tools') == 'not-running']),
                        'ds_risk': len([d for d in out_ds if d['risk'] in ('down', 'full', 'high', 'overcommitted')]),
                        'profiled': len(pts), 'short_history': short, 'findings': len(findings)}}


OPS = {'vsphere.studio': op_studio}
