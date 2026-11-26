// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const { body, param } = require('./check');
const { isHuman } = require('./approve-scopes');
/*
 * Hyper-V servers - monitor, plan and manage ({P} = /api/itam). The Hyper-V hosts REPORT (install/hyperv-report.ps1, read-only
 * PowerShell, run by the Windows agent or a scheduled task; POST /agent/hyperv with the agent key) - the platform never connects
 * into a host. Besides the inventory Asset Discovery keeps, the report carries the metrics read here:
 *   host    logical processors, CPU %, memory total / free, volumes (size / free, Cluster Shared Volumes included)
 *   VM      state, uptime, vCPUs, CPU %, memory assigned / demand / dynamic, heartbeat, VHDs (size / max), checkpoints (name,
 *           created), replication (state, health)
 * LEARN (explainable; each finding says why):
 *   capacity     per host and volume, the daily memory use / free space trend (least squares over 5+ daily snapshots) → days
 *                until full; under 30 days is said
 *   rightsizing  a VM whose memory demand (p95 of its last 14 daily snapshots) is under 50 % of what it is assigned, or above
 *                90 %; a VM at 90 %+ CPU in its snapshots
 *   health       heartbeat lost on a running VM, replication not healthy, checkpoints older than 7 days (they grow the disk and
 *                slow the VM), a VM off for 30+ days (a zombie - reclaim it), a VHD over 90 % of its maximum, vCPU:core over 4:1
 * ACT (four-eyes): start, shut down (guest), turn off, restart, checkpoint - proposed by an operator, approved by a different
 * administrator, then FETCHED by the host's own report script (GET /agent/hyperv/actions) which runs only these verbs on that VM
 * and reports the result (POST /agent/hyperv/actions/:id/result). Nothing runs without the approval; a host never receives
 * another host's actions.
 *   GET  /hyperv                       viewer    hosts, VMs, findings, capacity
 *   POST /hyperv/actions               operator  {host, vm, action, reason}
 *   POST /hyperv/actions/:id/decide    admin     {decision, comment}   never the proposer
 *   GET  /agent/hyperv/actions?host=   agent key approved actions for that host (marked taken)
 *   POST /agent/hyperv/actions/:id/result  agent key  {ok, message}
 */
const DAY = 86400000;
const ACTIONS = { start: 'Start', shutdown: 'Shut down (guest)', 'turn-off': 'Turn off', restart: 'Restart (reset)', checkpoint: 'Take a checkpoint' };
const httpErr = (status, msg) => Object.assign(new Error(msg), { status });
const n = (v, max = 1e9) => { const x = Number(v); return Number.isFinite(x) && x >= 0 && x <= max ? x : null; };
const s = (v, m = 200) => String(v == null ? '' : v).replace(/[\u0000-\u001f]/g, ' ').trim().slice(0, m);
const iso = (v) => { const t = Date.parse(v); return Number.isFinite(t) ? new Date(t).toISOString() : null; };
const fmtMbps = (m) => (m >= 1000 ? (Math.round(m / 100) / 10) + ' Gbps' : Math.round(m) + ' Mbps');
const p95 = (a) => { const x = a.filter((v) => v != null).sort((p, q) => p - q); return x.length ? x[Math.min(x.length - 1, Math.floor(0.95 * (x.length - 1)))] : null; };
function lsq(pts) { const k = pts.length; if (k < 5) return null; let sx = 0, sy = 0, sxy = 0, sxx = 0; for (const [x, y] of pts) { sx += x; sy += y; sxy += x * y; sxx += x * x; } const d = k * sxx - sx * sx; if (!d) return null; const b = (k * sxy - sx * sy) / d; return { slope: b, icept: (sy - b * sx) / k }; }

// the metrics part of a report (tolerant: missing fields stay null - never a 0 that reads as a measurement)
function normMetrics(raw) {
  const b = raw && typeof raw === 'object' ? raw : {}, h = b.host && typeof b.host === 'object' ? b.host : {};
  const name = s(h.name || h.computer_name, 120); if (!name) throw httpErr(400, 'host.name is required');
  const host = { name, cores: n(h.logical_processors), cpu_pct: n(h.cpu_pct, 100), mem_total_mb: n(h.mem_total_mb), mem_free_mb: n(h.mem_free_mb),
    volumes: (Array.isArray(h.volumes) ? h.volumes : []).slice(0, 64).map((v) => ({ name: s(v.name, 120), size_gb: n(v.size_gb), free_gb: n(v.free_gb), csv: !!v.csv })).filter((v) => v.name && v.size_gb),
    // network speed: each physical NIC's link speed and its receive / send rate at the time of the report (bits per second)
    nics: (Array.isArray(h.nics) ? h.nics : []).slice(0, 32).map((x) => ({ name: s(x.name, 120), link_mbps: n(x.link_mbps, 1e6), rx_bps: n(x.rx_bps, 1e12), tx_bps: n(x.tx_bps, 1e12) })).filter((x) => x.name),
    // disk: average latency per transfer (ms) and throughput (bytes per second) over all physical disks
    disk: h.disk && typeof h.disk === 'object' ? { latency_ms: n(h.disk.latency_ms, 1e5), read_bps: n(h.disk.read_bps, 1e12), write_bps: n(h.disk.write_bps, 1e12) } : null };
  const vms = (Array.isArray(b.vms) ? b.vms : []).slice(0, 2000).map((v) => ({ id: s(v.vm_id || v.id, 64), name: s(v.name, 200), state: s(v.state, 20).toLowerCase(), uptime_s: n(v.uptime_s),
    vcpus: n(v.vcpus, 1024), cpu_pct: n(v.cpu_pct, 100), mem_assigned_mb: n(v.mem_assigned_mb), mem_demand_mb: n(v.mem_demand_mb), dynamic: !!v.dynamic_memory, heartbeat: s(v.heartbeat, 40),
    vhds: (Array.isArray(v.vhds) ? v.vhds : []).slice(0, 32).map((d) => ({ path: s(d.path, 260), size_gb: n(d.size_gb), max_gb: n(d.max_gb) })),
    checkpoints: (Array.isArray(v.checkpoints) ? v.checkpoints : []).slice(0, 64).map((c) => ({ name: s(c.name, 120), created: iso(c.created) })).filter((c) => c.created),
    replication: { state: s(v.replication_state, 40), health: s(v.replication_health, 40) }, off_since: iso(v.off_since),
    net_rx_bps: n(v.net_rx_bps, 1e12), net_tx_bps: n(v.net_tx_bps, 1e12) })).filter((v) => v.name);
  return { host, vms, at: iso(b.collected_at) || new Date().toISOString() };
}

function assess(rep, days, now, samples) {
  const F = [], add = (sev, code, target, title, fix) => F.push({ severity: sev, code, host: rep.host.name, target, title, fix });
  const H = rep.host;
  // capacity: memory and each volume, trend over the daily snapshots
  const pts = (f) => days.map((d) => [Date.parse(d.id.split('|')[1]) / DAY, f(d)]).filter((x) => x[1] != null);
  const fc = (series, cap) => { const L = lsq(series); if (!L || L.slope <= 0 || cap == null) return null; const t = (cap - L.icept) / L.slope - now / DAY; return t > 0 ? Math.round(t) : 0; };
  const cap = { memory: null, volumes: [] };
  if (H.mem_total_mb) { const d = fc(pts((x) => x.mem_used_mb), H.mem_total_mb * 0.95); cap.memory = d; if (d != null && d < 30) add(d < 7 ? 'high' : 'medium', 'capacity-memory', H.name, `Memory reaches 95 % in about ${d} day(s) at the current growth`, 'Move or right-size VMs, or add memory to the host'); }
  for (const v of H.volumes) {
    const d = fc(pts((x) => (x.volumes || {})[v.name]), v.size_gb * 0.95); cap.volumes.push({ name: v.name, days: d, free_pct: v.size_gb ? Math.round(100 * v.free_gb / v.size_gb) : null });
    if (v.free_gb != null && v.size_gb && v.free_gb / v.size_gb < 0.1) add('high', 'volume-full', v.name, `${v.name}: ${Math.round(100 * v.free_gb / v.size_gb)} % free`, 'Merge old checkpoints, move VHDs, or extend the volume');
    else if (d != null && d < 30) add('medium', 'capacity-volume', v.name, `${v.name} fills (95 %) in about ${d} day(s)`, 'Plan storage before it fills');
  }
  let vcpu = 0;
  for (const m of rep.vms) {
    if (m.state === 'running') vcpu += m.vcpus || 0;
    const hist = days.map((d) => (d.vms || {})[m.name]).filter(Boolean);
    const dem = p95(hist.map((x) => x.mem_demand_mb)), asg = m.mem_assigned_mb;
    if (m.state === 'running' && hist.length >= 7 && dem != null && asg) {
      if (dem < 0.5 * asg && asg >= 2048) add('low', 'oversized', m.name, `${m.name}: memory demand ${Math.round(dem)} MB (p95, ${hist.length} days) of ${Math.round(asg)} MB assigned`, 'Right-size it, or switch on dynamic memory - the host gets the memory back');
      if (dem > 0.9 * asg) add('medium', 'undersized', m.name, `${m.name}: memory demand ${Math.round(dem)} MB is over 90 % of the ${Math.round(asg)} MB assigned`, 'Give it more memory before it pages');
    }
    const cpu95 = p95(hist.map((x) => x.cpu_pct)); if (m.state === 'running' && hist.length >= 7 && cpu95 != null && cpu95 >= 90) add('medium', 'cpu', m.name, `${m.name}: CPU at ${Math.round(cpu95)} % (p95)`, 'Add vCPUs or move load');
    if (m.state === 'running' && /lost|nocontact|error/i.test(m.heartbeat)) add('high', 'heartbeat', m.name, `${m.name}: heartbeat ${m.heartbeat}`, 'The guest has stopped answering - check it from the console');
    if (m.replication.health && !/^(normal|notapplicable|)$/i.test(m.replication.health.replace(/\s+/g, ''))) add('high', 'replication', m.name, `${m.name}: replication ${m.replication.health}${m.replication.state ? ' (' + m.replication.state + ')' : ''}`, 'Resume or resynchronise replication; check the replica server');
    for (const c of m.checkpoints) { const age = Math.floor((now - Date.parse(c.created)) / DAY); if (age > 7) { add('medium', 'checkpoint', m.name, `${m.name}: checkpoint "${c.name}" is ${age} days old`, 'Delete or merge it - checkpoints grow the disk and slow the VM'); break; } }
    if (m.state === 'off' && m.off_since && now - Date.parse(m.off_since) > 30 * DAY) add('low', 'zombie', m.name, `${m.name}: off for ${Math.floor((now - Date.parse(m.off_since)) / DAY)} days`, 'Reclaim it (remove, keep a backup) - it still holds storage and licences');
    for (const d of m.vhds) if (d.max_gb && d.size_gb != null && d.size_gb / d.max_gb > 0.9) { add('medium', 'vhd-full', m.name, `${m.name}: ${d.path.split(/[\\/]/).pop()} at ${Math.round(100 * d.size_gb / d.max_gb)} % of its ${d.max_gb} GB`, 'Extend the virtual disk and the guest partition'); break; }
  }
  // network speed: a NIC over 90 % of its link now, or over 80 % at p95 of the last 24 h of samples, is a bottleneck
  const recent = (samples || []).filter((x) => now - x.t <= DAY);
  for (const nic of H.nics || []) {
    if (!nic.link_mbps) continue;
    const pct = (x) => (x.rx_bps == null && x.tx_bps == null ? null : 100 * Math.max(x.rx_bps || 0, x.tx_bps || 0) / (nic.link_mbps * 1e6));
    const nowPct = pct(nic), p = p95(recent.map((x) => { const y = (x.nics || {})[nic.name]; return y ? pct(y) : null; }));
    if (nowPct != null && nowPct >= 90) add('high', 'nic-saturated', nic.name, `${nic.name}: ${Math.round(nowPct)} % of its ${fmtMbps(nic.link_mbps)} link in use now`, 'Find the VM sending or receiving it (VM network below); add a NIC to the team or move the VM');
    else if (p != null && recent.length >= 12 && p >= 80) add('medium', 'nic-busy', nic.name, `${nic.name}: ${Math.round(p)} % of its ${fmtMbps(nic.link_mbps)} link at p95 over 24 h (${recent.length} readings)`, 'Plan more bandwidth: team another NIC or a faster link');
    if (nic.link_mbps < 1000) add('low', 'nic-slow', nic.name, `${nic.name}: link negotiated at ${fmtMbps(nic.link_mbps)}`, 'A Hyper-V host NIC below 1 Gbps is usually a cable, port or speed setting');
  }
  const lat = p95(recent.map((x) => x.disk_ms));
  if (H.disk && H.disk.latency_ms != null && H.disk.latency_ms >= 50) add('high', 'disk-latency', H.name, `Disk latency ${Math.round(H.disk.latency_ms)} ms per transfer now`, 'Storage is slowing every VM - check the array / CSV and the busiest VMs');
  else if (lat != null && recent.length >= 12 && lat >= 20) add('medium', 'disk-latency', H.name, `Disk latency ${Math.round(lat)} ms at p95 over 24 h`, 'Above 20 ms VMs feel slow - spread the busy VMs or add faster storage');
  if (H.cores && vcpu / H.cores > 4) add('medium', 'overcommit', H.name, `${vcpu} vCPUs running on ${H.cores} logical processors (${Math.round(10 * vcpu / H.cores) / 10}:1)`, 'Above 4:1 VMs wait for CPU - move VMs or add a host');
  const SEV = { high: 3, medium: 2, low: 1 }; F.sort((a, b) => SEV[b.severity] - SEV[a.severity]);
  return { findings: F, capacity: cap, vcpu_ratio: H.cores ? Math.round(10 * vcpu / H.cores) / 10 : null };
}

function createHypervManager(app, opts = {}) {
  const now = opts.now || Date.now, C = (x) => app.store.collection(x), isoNow = () => new Date(now()).toISOString();
  const latest = () => C('hv_latest'), daily = () => C('hv_daily'), acts = () => C('hv_actions'), samples = () => C('hv_samples');
  const sum = (a) => { const x = a.filter((v) => v != null); return x.length ? x.reduce((p, q) => p + q, 0) : null; };
  const audit = (who, action, target, detail) => { if (app.audit) app.audit({ by: who.user, role: who.role || '', ip: who.ip || '', action: 'hyperv.' + action, target, detail }); };
  function onReport(raw) {
    const r = normMetrics(raw), k = r.host.name.toLowerCase(), day = r.at.slice(0, 10);
    // since when a VM is off, when the host does not say: the first report that saw it off
    const prev = latest().get(k), was = new Map(((prev && prev.vms) || []).map((v) => [v.name, v.off_since]));
    for (const v of r.vms) v.off_since = v.state === 'off' ? (v.off_since || was.get(v.name) || r.at) : null;
    latest().put(Object.assign({ id: k }, r));
    const used = r.host.mem_total_mb != null && r.host.mem_free_mb != null ? r.host.mem_total_mb - r.host.mem_free_mb : null;
    daily().put({ id: k + '|' + day, mem_used_mb: used, volumes: Object.fromEntries(r.host.volumes.map((v) => [v.name, v.size_gb - (v.free_gb || 0)])),
      vms: Object.fromEntries(r.vms.map((v) => [v.name, { mem_demand_mb: v.mem_demand_mb, cpu_pct: v.cpu_pct }])) });
    for (const o of daily().all((x) => now() - Date.parse(x.id.split('|')[1]) > 120 * DAY)) daily().remove(o.id);
    // the last 48 h, one reading per report (every 15 min from the scheduled task): the trend charts and the p95 checks
    const t = Date.parse(r.at) || now();
    samples().put({ id: k + '|' + t, host: k, t, cpu: r.host.cpu_pct, mem_pct: used != null && r.host.mem_total_mb ? Math.round(1000 * used / r.host.mem_total_mb) / 10 : null,
      rx_bps: sum(r.host.nics.map((x) => x.rx_bps)), tx_bps: sum(r.host.nics.map((x) => x.tx_bps)), disk_ms: r.host.disk ? r.host.disk.latency_ms : null,
      nics: Object.fromEntries(r.host.nics.map((x) => [x.name, { rx_bps: x.rx_bps, tx_bps: x.tx_bps }])) });
    for (const o of samples().all((x) => x.host === k && now() - x.t > 2 * DAY)) samples().remove(o.id);
    return { metrics: true, vms: r.vms.length };
  }
  function view() {
    const t = now(), hosts = latest().all().sort((a, b) => a.host.name.localeCompare(b.host.name)).map((r) => {
      const days = daily().all((x) => x.id.startsWith(r.id + '|')).sort((a, b) => a.id.localeCompare(b.id)).slice(-60), sm = samples().all((x) => x.host === r.id && t - x.t <= DAY).sort((a, b) => a.t - b.t), a = assess(r, days, t, sm);
      return { name: r.host.name, at: r.at, stale: t - Date.parse(r.at) > 2 * 3600000, cores: r.host.cores, cpu_pct: r.host.cpu_pct, mem_total_mb: r.host.mem_total_mb, mem_free_mb: r.host.mem_free_mb, volumes: r.host.volumes, nics: r.host.nics || [], disk: r.host.disk || null,
        trend: sm.map((x) => ({ t: new Date(x.t).toISOString(), cpu: x.cpu, mem_pct: x.mem_pct, rx_bps: x.rx_bps, tx_bps: x.tx_bps, disk_ms: x.disk_ms })),
        vms: r.vms.map((v) => ({ name: v.name, state: v.state, vcpus: v.vcpus, cpu_pct: v.cpu_pct, mem_assigned_mb: v.mem_assigned_mb, mem_demand_mb: v.mem_demand_mb, heartbeat: v.heartbeat, checkpoints: v.checkpoints.length, replication: v.replication, uptime_s: v.uptime_s, net_rx_bps: v.net_rx_bps == null ? null : v.net_rx_bps, net_tx_bps: v.net_tx_bps == null ? null : v.net_tx_bps })),
        findings: a.findings, capacity: a.capacity, vcpu_ratio: a.vcpu_ratio, snapshots: days.length };
    });
    const all = hosts.flatMap((h) => h.findings);
    return { hosts, kpis: { hosts: hosts.length, vms: hosts.reduce((x, h) => x + h.vms.length, 0), running: hosts.reduce((x, h) => x + h.vms.filter((v) => v.state === 'running').length, 0),
      high: all.filter((f) => f.severity === 'high').length, stale_hosts: hosts.filter((h) => h.stale).length }, findings: all.slice(0, 300), actions: acts().all().sort((a, b) => String(b.id).localeCompare(String(a.id))).slice(0, 100), verbs: ACTIONS,
      note: hosts.length ? '' : 'No Hyper-V host has reported metrics yet: run install/hyperv-report.ps1 on each host (read-only; the Windows agent or a scheduled task).' };
  }
  function nextId() { let m = 0; for (const x of acts().all()) { const k = Number(String(x.id).slice(5)); if (k > m) m = k; } return 'HVAC-' + String(m + 1).padStart(5, '0'); }
  function propose(b0, who) {
    if (!isHuman(who.user)) throw httpErr(403, 'a person proposes an action');
    const b = body(b0).str('host', { required: true, max: 120 }).str('vm', { required: true, max: 200 }).oneOf('action', Object.keys(ACTIONS), { required: true }).str('reason', { required: true, min: 10, max: 400 }).done();
    const r = latest().get(b.host.toLowerCase()); if (!r) throw httpErr(404, 'host: ' + b.host + ' has not reported');
    if (!r.vms.some((v) => v.name === b.vm)) throw httpErr(400, 'vm: ' + b.vm + ' is not on ' + r.host.name + ' in its last report');
    if (acts().all((a) => a.host === r.host.name && a.vm === b.vm && ['proposed', 'approved', 'taken'].includes(a.status)).length) throw httpErr(409, 'an action for ' + b.vm + ' is already waiting');
    const a = acts().put({ id: nextId(), host: r.host.name, vm: b.vm, action: b.action, reason: b.reason, status: 'proposed', proposed_by: who.user, proposed_at: isoNow() });
    audit(who, 'action.propose', a.id, { host: a.host, vm: a.vm, action: a.action }); return a;
  }
  function decide(id, b0, who) {
    if (!isHuman(who.user)) throw httpErr(403, 'only a person approves'); if (who.role !== 'admin') throw httpErr(403, 'an administrator approves Hyper-V actions');
    param(id); const a = acts().get(id); if (!a) throw httpErr(404, 'action not found'); if (a.status !== 'proposed') throw httpErr(409, 'only a proposed action is decided');
    if (String(a.proposed_by).toLowerCase() === String(who.user).toLowerCase()) throw httpErr(403, 'four-eyes: the person who proposed it does not approve it');
    const b = body(b0).oneOf('decision', ['approved', 'rejected'], { required: true }).str('comment', { max: 400 }).done();
    if (b.decision === 'rejected' && !(b.comment && b.comment.length >= 5)) throw httpErr(400, 'comment: say why it is rejected');
    const x = acts().patch(id, (o) => { o.status = b.decision; o.decided_by = who.user; o.decided_at = isoNow(); o.comment = b.comment || ''; return o; });
    audit(who, 'action.' + (b.decision === 'approved' ? 'approve' : 'reject'), id, { host: a.host, vm: a.vm, proposed_by: a.proposed_by }); return x;
  }
  // the host's script: approved actions for THAT host only, each handed out once
  function pending(host, agent) {
    const h = s(host, 120).toLowerCase(); if (!h) throw httpErr(400, 'host is required');
    const out = acts().all((a) => a.status === 'approved' && a.host.toLowerCase() === h).map((a) => acts().patch(a.id, (o) => { o.status = 'taken'; o.taken_at = isoNow(); o.taken_by = agent; return o; }));
    return { actions: out.map((a) => ({ id: a.id, vm: a.vm, action: a.action })) };
  }
  function result(id, b0, agent) {
    param(id); const a = acts().get(id); if (!a) throw httpErr(404, 'action not found'); if (a.status !== 'taken') throw httpErr(409, 'this action was not handed out');
    const b = body(b0).bool('ok', { required: true }).str('message', { max: 400 }).done();
    const x = acts().patch(id, (o) => { o.status = b.ok ? 'done' : 'failed'; o.result = b.message || ''; o.done_at = isoNow(); return o; });
    if (app.audit) app.audit({ by: agent, role: 'agent', ip: '', action: 'hyperv.action.result', target: id, detail: { ok: b.ok, vm: a.vm, action: a.action } });
    return { id, status: x.status };
  }
  // ---- adding hosts the easy way: an administrator names the hosts, each gets its own one-time enrolment token (agentgw, 24 h)
  // and ONE PowerShell command that downloads this report script from the portal, checks its SHA-256, enrols and creates the
  // 15-minute scheduled task. The script itself carries no secret; the token is shown once and never stored here.
  const HOSTNAME = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$/;
  const scriptFile = opts.scriptFile || require('path').join(__dirname, '..', 'install', 'hyperv-report.ps1');
  function script() {
    let txt; try { txt = require('fs').readFileSync(scriptFile, 'utf8'); } catch (e) { throw httpErr(503, 'the Hyper-V report script is not installed on the server - run the platform update'); }
    if (txt.charCodeAt(0) === 0xfeff) txt = txt.slice(1);
    return { name: 'hyperv-report.ps1', sha256: require('crypto').createHash('sha256').update(txt, 'utf8').digest('hex'), script: txt };
  }
  const reported = () => new Set(latest().all().map((r) => String(r.host.name).toLowerCase()));
  function onboardView() {
    const sc = script(), seen = reported(), toks = app.agentgw ? app.agentgw.listTokens().filter((t) => /^Hyper-V: /.test(t.note || '') && !t.revoked) : [];
    const names = new Map(app.agentgw && app.agentgw.listAgents ? app.agentgw.listAgents().map((a) => [a.id, String(a.name || '')]) : []);
    return { script: { name: sc.name, sha256: sc.sha256, bytes: Buffer.byteLength(sc.script) },
      invited: toks.sort((a, b) => String(b.created_at).localeCompare(String(a.created_at))).slice(0, 100).map((t) => { const h = String(t.note).slice(9);
        // the host reports under its Windows computer name, which is what it enrolled with - so a host added by its IP address
        // (or a short / different name) is matched through the agent that used its key
        const as = t.used_by_agent && names.get(t.used_by_agent), on = seen.has(h.toLowerCase()) || (as && seen.has(as.toLowerCase()));
        return { id: t.token_prefix, host: h, reports_as: as && as.toLowerCase() !== h.toLowerCase() ? as : null, created_at: t.created_at, created_by: t.created_by, expires_at: t.expires_at, state: on ? 'reporting' : t.used_at ? 'enrolled - waiting for its first report' : t.revoked ? 'revoked' : Date.parse(t.expires_at) < now() ? 'expired' : 'waiting for the host' }; }) };
  }
  function onboard(b0, who) {
    if (!isHuman(who.user)) throw httpErr(403, 'a person adds Hyper-V hosts');
    if (!app.agentgw) throw httpErr(503, 'the agent gateway is not running');
    const b = body(b0).list('hosts', { required: true, max: 50, item: 'str', itemMax: 253, unique: true }).done();
    const hosts = b.hosts.map((h) => h.trim()).filter(Boolean);
    hosts.forEach((h, i) => { if (!HOSTNAME.test(h)) throw httpErr(400, 'hosts[' + i + ']: "' + s(h, 60) + '" is not a host name'); });
    if (!hosts.length) throw httpErr(400, 'hosts needs at least one host name');
    const sc = script();
    const out = hosts.map((h) => { const t = app.agentgw.issueToken({ note: 'Hyper-V: ' + h }, who); return { host: h, token: t.token, expires_at: t.expires_at }; });
    audit(who, 'onboard', 'hyperv', { hosts, script_sha256: sc.sha256 });
    return { script_sha256: sc.sha256, hosts: out };
  }
  // ---- the "Hosts added" list: correct a host's name, or remove it (administrators, a person, audited)
  function invite(id) {
    param(id); if (!app.agentgw) throw httpErr(503, 'the agent gateway is not running');
    if (!/^[0-9a-f]{8}$/i.test(String(id))) throw httpErr(400, 'id: the 8-character key reference from the list');
    const t = app.agentgw.listTokens().find((x) => x.token_prefix === id && /^Hyper-V: /.test(x.note || '') && !x.revoked);
    if (!t) throw httpErr(404, 'that host is not in the list'); return t;
  }
  function renameHost(id, b0, who) {
    if (!isHuman(who.user)) throw httpErr(403, 'a person edits Hyper-V hosts');
    const t = invite(id), b = body(b0).str('host', { required: true, max: 253 }).done(), h = b.host.trim();
    if (!HOSTNAME.test(h)) throw httpErr(400, 'host: "' + s(h, 60) + '" is not a host name');
    const from = String(t.note).slice(9);
    app.agentgw.setTokenNote(id, 'Hyper-V: ' + h, who);
    audit(who, 'onboard.rename', 'hyperv', { from, to: h });
    return onboardView();
  }
  // removing stops the host: its one-time key is cancelled; if it already enrolled, its agent key is revoked (its next report is
  // refused) and it leaves the Hyper-V dashboard. The 60-day capacity history stays for the record. The scheduled task on the
  // host is removed there (schtasks /Delete /TN "Sentra Hyper-V report" /F).
  function removeHost(id, who) {
    if (!isHuman(who.user)) throw httpErr(403, 'a person removes Hyper-V hosts');
    const t = invite(id), h = String(t.note).slice(9);
    app.agentgw.revokeToken(id, who);
    let as = null;
    if (t.used_by_agent) {
      const a = (app.agentgw.listAgents ? app.agentgw.listAgents() : []).find((x) => x.id === t.used_by_agent);
      if (a && a.status !== 'revoked') app.agentgw.revokeAgent(a.id, who);
      as = a ? String(a.name || '') : null;
    }
    for (const k of [h, as].filter(Boolean).map((x) => x.toLowerCase())) { latest().remove(k); for (const o of samples().all((x) => x.host === k)) samples().remove(o.id); }
    audit(who, 'onboard.remove', 'hyperv', { host: h, reported_as: as, agent_revoked: !!t.used_by_agent });
    return onboardView();
  }
  return { onReport, view, propose, decide, pending, result, onboardView, onboard, renameHost, removeHost, script, ACTIONS };
}

function registerHypervManager(srv, app, X) {
  srv.route('GET', '/hyperv', (ctx) => { ctx.need('viewer'); return X.view(); });
  srv.route('POST', '/hyperv/actions', (ctx) => { ctx.need('operator'); return X.propose(ctx.body, ctx.who); }, { maxBody: 4096 });
  srv.route('GET', '/hyperv/onboard', (ctx) => { ctx.need('admin'); return X.onboardView(); });
  srv.route('POST', '/hyperv/onboard', (ctx) => { ctx.need('admin'); return X.onboard(ctx.body, ctx.who); }, { maxBody: 16384 });
  // the report script for a host to download (agent side, no key needed: it carries no secret; the command checks its SHA-256)
  srv.route('PUT', '/hyperv/onboard/:id', (ctx) => { ctx.need('admin'); return X.renameHost(ctx.params.id, ctx.body, ctx.who); }, { maxBody: 2048 });
  srv.route('POST', '/hyperv/onboard/:id/remove', (ctx) => { ctx.need('admin'); return X.removeHost(ctx.params.id, ctx.who); }, { maxBody: 1024 });
  srv.route('GET', '/hyperv/script', () => X.script(), { agent: true });
  srv.route('POST', '/hyperv/actions/:id/decide', (ctx) => { ctx.need('admin'); return X.decide(ctx.params.id, ctx.body, ctx.who); }, { maxBody: 2048 });
  const agentOf = (ctx) => { const a = app.agentgw && app.agentgw.authenticate(ctx.bearer()); if (!a) throw httpErr(401, 'invalid or revoked agent key'); return 'agent:' + a.id; };
  srv.route('GET', '/hyperv/actions', (ctx) => X.pending((ctx.query || {}).host, agentOf(ctx)), { agent: true });
  srv.route('POST', '/hyperv/actions/:id/result', (ctx) => X.result(ctx.params.id, ctx.body, agentOf(ctx)), { agent: true, maxBody: 2048 });
}

module.exports = { createHypervManager, registerHypervManager, normMetrics, assess, ACTIONS };
