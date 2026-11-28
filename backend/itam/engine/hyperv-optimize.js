// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Hyper-V OPTIMIZATION ({P} = /api/itam): what can be given back, moved or planned across the Hyper-V hosts, from what the hosts
 * already report (hyperv-manager.js: the latest report, one snapshot a day for 120 days, one reading per report for 48 h). Read-only -
 * every recommendation is a change a person makes (VM settings in Hyper-V Manager, or the four-eyes VM actions on Hyper-V Servers).
 * The analysis, each number shown with how it was reached:
 *   rightsizing  memory: the 95th percentile of the VM's own daily demand (5+ days, else "learning") with 25 % headroom, rounded up to
 *                512 MB, against what it is assigned - under 60 % used = give back, over 90 % = add; vCPUs: the 95th percentile of its
 *                daily CPU - under 15 % with 4+ vCPUs = halve them (at least 2), over 80 % = add
 *   idle         VMs off for 30+ days (their disks to reclaim), checkpoints older than 7 days (they grow the disk and slow the VM)
 *   storage      per volume: used %, the days to 95 % along the daily trend (least squares, 5+ days), thin provisioning - the VHDs'
 *                maximum sizes on that volume against its size (over 150 % = overcommitted), VHDs over 90 % of their maximum
 *   balance      per host: memory used % and CPU p95 of the last 48 h; with 2+ hosts OF ONE GROUP (named alike - one site) more than 25 points apart, the VM that best evens
 *                them is named with the result on both hosts (it must fit under 85 % on the host it moves to)
 *   network      per physical NIC the peak of receive + transmit against its link speed over 48 h; the busiest VMs now
 *   anomalies    each host's latest reading against its own last 48 h (robust z on median / MAD, 3.5+) for CPU, memory, disk latency
 *   score        100 less points for what is open (named), so the page says what holds it down
 *   GET /hyperv/optimize   viewer
 */
const DAY = 86400000;
const r1 = (x) => (x == null || !Number.isFinite(x) ? null : Math.round(x * 10) / 10);
const med = (a) => { if (!a.length) return null; const s = a.slice().sort((x, y) => x - y), m = s.length >> 1; return s.length % 2 ? s[m] : (s[m - 1] + s[m]) / 2; };
const p95 = (a) => { const x = a.filter((v) => v != null && Number.isFinite(v)).sort((p, q) => p - q); return x.length ? x[Math.min(x.length - 1, Math.floor(0.95 * (x.length - 1)))] : null; };
const up512 = (mb) => Math.max(512, Math.ceil(mb / 512) * 512);
function lsq(pts) { const k = pts.length; if (k < 5) return null; let sx = 0, sy = 0, sxy = 0, sxx = 0; for (const [x, y] of pts) { sx += x; sy += y; sxy += x * y; sxx += x * x; } const d = k * sxx - sx * sx; if (!d) return null; const b = (k * sxy - sx * sy) / d; return { b, a: (sy - b * sx) / k }; }
const zOf = (vals, v) => { if (vals.length < 12 || v == null) return null; const m = med(vals), mad = med(vals.map((x) => Math.abs(x - m))) || Math.max(1, m * 0.05); return Math.round(10 * (v - m) / (1.4826 * mad)) / 10; };

function analyse({ latest = [], daily = [], samples = [], now = Date.now() } = {}) {
  const R = [], add = (priority, kind, target, host, title, why, gain, detail) => R.push({ priority, kind, target, host, title, why, gain: gain || {}, detail: Object.assign({ host }, detail || {}) });
  const hosts = [], vmsAll = [], volumes = [], nics = [], anomalies = [];
  let memBack = 0, memNeed = 0, vcpuBack = 0, diskBack = 0;
  for (const rep of latest) {
    const H = rep.host || {}, key = String(H.name || '').toLowerCase(), D = daily.filter((d) => String(d.id).split('|')[0] === key).sort((a, b) => String(a.id).localeCompare(String(b.id))).slice(-30);
    const S = samples.filter((x) => x.host === key && now - x.t <= 2 * DAY).sort((a, b) => a.t - b.t);
    const memPct = H.mem_total_mb && H.mem_free_mb != null ? 100 * (H.mem_total_mb - H.mem_free_mb) / H.mem_total_mb : null;
    const cpu95 = p95(S.map((x) => x.cpu)), vcpuRun = (rep.vms || []).filter((v) => v.state === 'running').reduce((t, v) => t + (v.vcpus || 0), 0);
    hosts.push({ name: H.name, cores: H.cores, mem_total_gb: H.mem_total_mb ? r1(H.mem_total_mb / 1024) : null, mem_pct: r1(memPct), cpu_now: H.cpu_pct, cpu_p95: r1(cpu95), vcpu_ratio: H.cores ? r1(vcpuRun / H.cores) : null,
      vms: (rep.vms || []).length, running: (rep.vms || []).filter((v) => v.state === 'running').length, disk_ms: H.disk ? H.disk.latency_ms : null,
      trend: S.map((x) => ({ t: new Date(x.t).toISOString(), cpu: x.cpu, mem: x.mem_pct, disk_ms: x.disk_ms, net_bps: (x.rx_bps || 0) + (x.tx_bps || 0) })) });
    // anomalies against the host's own last 48 h
    const last = S[S.length - 1], prev = S.slice(0, -1);
    if (last) for (const [k, label] of [['cpu', 'CPU %'], ['mem_pct', 'memory %'], ['disk_ms', 'disk latency (ms)']]) {
      const z = zOf(prev.map((x) => x[k]).filter((v) => v != null), last[k]);
      if (z != null && z >= 3.5) anomalies.push({ host: H.name, metric: label, value: last[k], usual: r1(med(prev.map((x) => x[k]).filter((v) => v != null))), z, at: new Date(last.t).toISOString() });
    }
    // VMs
    for (const v of rep.vms || []) {
      const hist = D.map((d) => (d.vms || {})[v.name]).filter(Boolean), memP = p95(hist.map((h) => h.mem_demand_mb)), cpuP = p95(hist.map((h) => h.cpu_pct));
      const vm = { host: H.name, name: v.name, state: v.state, os: v.os || null, vcpus: v.vcpus, mem_assigned_mb: v.mem_assigned_mb, mem_p95_mb: memP, cpu_p95: r1(cpuP), days: hist.length, dynamic: !!v.dynamic,
        disk_gb: r1((v.vhds || []).reduce((t, d) => t + (d.size_gb || 0), 0)), net_bps: (v.net_rx_bps || 0) + (v.net_tx_bps || 0), advice: null };
      vmsAll.push(vm);
      if (v.state === 'running' && hist.length >= 5) {
        if (v.mem_assigned_mb && memP != null && memP < 0.6 * v.mem_assigned_mb && v.mem_assigned_mb - up512(memP * 1.25) >= 1024) {
          const to = up512(memP * 1.25), back = v.mem_assigned_mb - to; memBack += back; vm.advice = 'memory ' + v.mem_assigned_mb + ' → ' + to + ' MB';
          add(back >= 8192 ? 'high' : 'medium', 'memory-down', v.name, H.name, v.name + ': give back ' + r1(back / 1024) + ' GB of memory (' + r1(v.mem_assigned_mb / 1024) + ' → ' + r1(to / 1024) + ' GB)', 'its memory demand never went above ' + r1(memP / 1024) + ' GB on 95 % of ' + hist.length + ' days; 25 % headroom kept' + (v.dynamic ? ' (dynamic memory: lower its maximum)' : ''), { mem_gb: r1(back / 1024) }, { vm: v.name, to_mb: to });
        } else if (v.mem_assigned_mb && memP != null && memP > 0.9 * v.mem_assigned_mb) {
          const to = up512(memP * 1.25), need = to - v.mem_assigned_mb; memNeed += need; vm.advice = 'memory ' + v.mem_assigned_mb + ' → ' + to + ' MB';
          add('high', 'memory-up', v.name, H.name, v.name + ': short of memory - give it ' + r1(need / 1024) + ' GB more', 'its demand reached ' + Math.round(100 * memP / v.mem_assigned_mb) + '% of what it has on 95 % of ' + hist.length + ' days - it pages to disk and slows down', { mem_gb: -r1(need / 1024) }, { vm: v.name, to_mb: to });
        }
        if (v.vcpus >= 4 && cpuP != null && cpuP < 15) { const to = Math.max(2, Math.floor(v.vcpus / 2)); vcpuBack += v.vcpus - to; vm.advice = (vm.advice ? vm.advice + ' · ' : '') + 'vCPU ' + v.vcpus + ' → ' + to;
          add('medium', 'vcpu-down', v.name, H.name, v.name + ': ' + v.vcpus + ' → ' + to + ' vCPUs', 'its CPU stayed under ' + Math.ceil(cpuP) + '% on 95 % of ' + hist.length + ' days - idle vCPUs still wait for a free core on a busy host', { vcpu: v.vcpus - to }, { vm: v.name, to }); }
        else if (cpuP != null && cpuP > 80) add('high', 'vcpu-up', v.name, H.name, v.name + ': CPU-bound - add vCPUs', 'its CPU was above ' + Math.floor(cpuP) + '% on 95 % of ' + hist.length + ' days', {}, { vm: v.name, to: v.vcpus + 2 });
      }
      if (v.state === 'off' && v.off_since && now - Date.parse(v.off_since) >= 30 * DAY) { diskBack += vm.disk_gb || 0;
        add('medium', 'idle', v.name, H.name, v.name + ': off for ' + Math.floor((now - Date.parse(v.off_since)) / DAY) + ' days - archive or delete it', (vm.disk_gb ? vm.disk_gb + ' GB of virtual disks' : 'its virtual disks') + ' to reclaim; confirm with the owner first', { disk_gb: vm.disk_gb || 0 }, { vm: v.name }); }
      const old = (v.checkpoints || []).filter((c) => now - Date.parse(c.created) > 7 * DAY);
      if (old.length) add('low', 'checkpoint', v.name, H.name, v.name + ': ' + old.length + ' checkpoint(s) older than 7 days', 'the oldest from ' + old.map((c) => c.created).sort()[0].slice(0, 10) + ' - delete them (Hyper-V merges the changes back) to free disk and speed the VM', {}, { vm: v.name });
      for (const d of v.vhds || []) if (d.max_gb && d.size_gb && d.size_gb / d.max_gb > 0.9) add('medium', 'vhd-full', v.name, H.name, v.name + ': virtual disk ' + d.path.split('\\').pop() + ' is ' + Math.round(100 * d.size_gb / d.max_gb) + '% of its maximum', 'extend it, or clean the guest\'s disk, before the guest runs out of space', {}, { vm: v.name, path: d.path, size_gb: d.size_gb, max_gb: d.max_gb });
    }
    // storage
    for (const vol of H.volumes || []) {
      const used = vol.size_gb - (vol.free_gb || 0), pct = vol.size_gb ? 100 * used / vol.size_gb : null;
      const pts = D.map((d, i) => [i, (d.volumes || {})[vol.name]]).filter((p) => p[1] != null), f = lsq(pts);
      const days = f && f.b > 0 ? Math.max(0, Math.round((vol.size_gb * 0.95 - (f.a + f.b * (pts.length - 1))) / f.b)) : null;
      const root = String(vol.name).toLowerCase(), prov = (rep.vms || []).reduce((t, v) => t + (v.vhds || []).filter((d) => String(d.path).toLowerCase().startsWith(root)).reduce((u, d) => u + (d.max_gb || 0), 0), 0);
      const over = vol.size_gb && prov ? prov / vol.size_gb : null;
      volumes.push({ host: H.name, name: vol.name, size_gb: vol.size_gb, used_gb: r1(used), used_pct: r1(pct), days_to_95: days, provisioned_gb: r1(prov) || null, overcommit: r1(over), csv: !!vol.csv, history: pts.map((p) => r1(p[1])) });
      if (pct != null && pct >= 90) add('high', 'volume-full', vol.name, H.name, H.name + ' ' + vol.name + ' is ' + Math.round(pct) + '% full', vol.free_gb + ' GB free of ' + vol.size_gb + ' GB', {}, { volume: vol.name, csv: !!vol.csv, free_gb: vol.free_gb, size_gb: vol.size_gb });
      else if (days != null && days <= 60) add(days <= 14 ? 'high' : 'medium', 'volume-trend', vol.name, H.name, H.name + ' ' + vol.name + ' reaches 95% in about ' + days + ' days', 'it grows ' + r1(f.b) + ' GB a day over the last ' + pts.length + ' days', {}, { volume: vol.name, csv: !!vol.csv, days });
      if (over != null && over > 1.5) add('medium', 'overcommit', vol.name, H.name, H.name + ' ' + vol.name + ': VHDs can grow to ' + Math.round(100 * over) + '% of the volume', 'dynamic disks maximum ' + r1(prov) + ' GB on ' + vol.size_gb + ' GB - if they all grow the volume fills and every VM on it stops', {}, { volume: vol.name });
    }
    // network: peak of each physical NIC against its link over 48 h
    for (const nic of H.nics || []) {
      const peak = Math.max(0, ...S.map((x) => { const q = (x.nics || {})[nic.name]; return q ? (q.rx_bps || 0) + (q.tx_bps || 0) : 0; }), (nic.rx_bps || 0) + (nic.tx_bps || 0));
      const pct = nic.link_mbps ? 100 * peak / (nic.link_mbps * 1e6 * 2) : null;
      nics.push({ host: H.name, name: nic.name, link_mbps: nic.link_mbps, peak_bps: peak, peak_pct: r1(pct) });
      if (pct != null && pct >= 70) add(pct >= 90 ? 'high' : 'medium', 'nic-busy', nic.name, H.name, H.name + ' ' + nic.name + ' peaked at ' + Math.round(pct) + '% of its link', 'add a team member or move the busiest VMs to another uplink / host', {}, { nic: nic.name });
    }
  }
  // balance: the VM that best evens two hosts apart by 25+ points of memory
  // only between hosts of the same group (named alike, e.g. HQPSUPERM01-04): a VM is live-migrated within a site, not across sites
  const { groupOf } = require('./hyperv-netmap'), groups = {};
  for (const h of hosts.filter((x) => x.mem_pct != null && x.mem_total_gb)) (groups[groupOf(h.name)] = groups[groupOf(h.name)] || []).push(h);
  const G = Object.values(groups).filter((L) => L.length >= 2).sort((a, b) => (Math.max(...b.map((h) => h.mem_pct)) - Math.min(...b.map((h) => h.mem_pct))) - (Math.max(...a.map((h) => h.mem_pct)) - Math.min(...a.map((h) => h.mem_pct))));
  const withMem = G[0] || [];
  let move = null;
  if (withMem.length >= 2) {
    const hi = withMem.slice().sort((a, b) => b.mem_pct - a.mem_pct)[0], lo = withMem.slice().sort((a, b) => a.mem_pct - b.mem_pct)[0];
    if (hi !== lo && hi.mem_pct - lo.mem_pct >= 25) {
      const gap = (hi.mem_pct - lo.mem_pct) / 2, cand = vmsAll.filter((v) => v.host === hi.name && v.state === 'running' && v.mem_assigned_mb).map((v) => {
        const gb = v.mem_assigned_mb / 1024, hiAfter = hi.mem_pct - 100 * gb / hi.mem_total_gb, loAfter = lo.mem_pct + 100 * gb / lo.mem_total_gb; return { v, gb, hiAfter, loAfter, miss: Math.abs(100 * gb / hi.mem_total_gb - gap) }; })
        .filter((c) => c.loAfter <= 85).sort((a, b) => a.miss - b.miss);
      if (cand.length) { const c = cand[0]; move = { vm: c.v.name, from: hi.name, to: lo.name, gb: r1(c.gb), from_after: r1(c.hiAfter), to_after: r1(c.loAfter) };
        add('medium', 'balance', c.v.name, hi.name, 'Move ' + c.v.name + ' (' + r1(c.gb) + ' GB) from ' + hi.name + ' to ' + lo.name, hi.name + ' memory ' + Math.round(hi.mem_pct) + '% → ' + Math.round(c.hiAfter) + '%, ' + lo.name + ' ' + Math.round(lo.mem_pct) + '% → ' + Math.round(c.loAfter) + '% (live migration; same virtual switch names on both hosts - see the Virtual Network Map)', {}, { vm: c.v.name, from: hi.name, to: lo.name }); }
    }
  }
  const PR = { high: 3, medium: 2, low: 1 }; R.sort((a, b) => PR[b.priority] - PR[a.priority]);
  // each recommendation carries how to fix it: checks, the change, how to confirm (engine/hyperv-fix.js) - a person runs it
  const { fixOf } = require('./hyperv-fix'); for (const x of R) x.fix = fixOf(x);
  const pts = R.reduce((t, x) => t + (x.priority === 'high' ? 6 : x.priority === 'medium' ? 3 : 1), 0), score = hosts.length ? Math.max(0, 100 - Math.min(100, pts)) : null;
  const ins = [];
  if (memBack) ins.push(r1(memBack / 1024) + ' GB of memory can be given back from VMs that never use it - more than buying it.');
  if (memNeed) ins.push(r1(memNeed / 1024) + ' GB of memory is needed by VMs running short - take it from the ones above first.');
  if (vcpuBack) ins.push(vcpuBack + ' idle vCPUs to remove - fewer vCPUs often makes a VM faster on a busy host (less waiting for cores).');
  if (diskBack) ins.push(r1(diskBack) + ' GB of disk held by VMs off for 30+ days.');
  if (move) ins.push('Hosts are uneven: moving ' + move.vm + ' from ' + move.from + ' to ' + move.to + ' brings them to ' + Math.round(move.from_after) + '% and ' + Math.round(move.to_after) + '% memory.');
  const fill = volumes.filter((v) => v.days_to_95 != null && v.days_to_95 <= 60).sort((a, b) => a.days_to_95 - b.days_to_95)[0]; if (fill) ins.push(fill.host + ' ' + fill.name + ' fills in about ' + fill.days_to_95 + ' days at the current growth.');
  if (anomalies.length) ins.push(anomalies.length + ' reading(s) far from the host\'s own last 48 h - the strongest: ' + anomalies.sort((a, b) => b.z - a.z)[0].host + ' ' + anomalies[0].metric + ' ' + anomalies[0].value + ' (usually ' + anomalies[0].usual + ').');
  if (!hosts.length) ins.push('No Hyper-V host reports yet - add the hosts on Hyper-V Servers.');
  else if (!R.length) ins.push('Nothing to optimize: every VM is sized to its use, storage and network have room, the hosts are even.');
  return { at: new Date(now).toISOString(), score, kpis: { hosts: hosts.length, vms: vmsAll.length, running: vmsAll.filter((v) => v.state === 'running').length, recommendations: R.length, high: R.filter((x) => x.priority === 'high').length,
      mem_back_gb: r1(memBack / 1024), mem_need_gb: r1(memNeed / 1024), vcpu_back: vcpuBack, disk_back_gb: r1(diskBack), learning: vmsAll.filter((v) => v.state === 'running' && v.days < 5).length },
    hosts, vms: vmsAll.slice(0, 2000), volumes, nics, anomalies, move, recommendations: R.slice(0, 300), insights: ins,
    note: 'From the Hyper-V hosts\' own reports (every 15 minutes; one snapshot a day). Sizing needs 5 days of a VM\'s history. Nothing is changed from here - each recommendation is a change a person makes.' };
}

function createHypervOptimize(app, opts = {}) {
  const now = opts.now || Date.now, C = (x) => app.store.collection(x);
  return { view: () => analyse({ latest: C('hv_latest').all(), daily: C('hv_daily').all(), samples: C('hv_samples').all(), now: now() }) };
}
function registerHypervOptimize(srv, app, X) { srv.route('GET', '/hyperv/optimize', (ctx) => { ctx.need('viewer'); return X.view(); }); }

module.exports = { createHypervOptimize, registerHypervOptimize, analyse };
