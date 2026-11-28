// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const { guard: guardJob } = require('../util/errors');
/*
 * Background health checks: every interval (default 15 min) the baseline checks (checks.json "baseline") run on each
 * server that has a login; organisation-wide Exchange checks run once, on the first Exchange server that answers.
 * Results are kept per server (state collection "sysadmin_health", so they survive a restart) and turned into findings
 * with plain thresholds - no AI needed:
 *   disk free < 10 % (high) / < 5 % (critical) · automatic services stopped · critical / error events · no update for
 *   45 days · reboot pending for > 7 days · memory free < 10 % · certificate expiring (< 30 d) or expired · Exchange:
 *   required services down, queues > 100 or in retry, database dismounted, no full backup for 7 days, copy not healthy,
 *   copy / replay queue high, content index not healthy, Exchange certificate expiring, health sets unhealthy.
 *   A server that cannot be checked is a finding too (with the reason) - never shown as healthy.
 *   Every IPv4 address the server itself reports (network check, part of the baseline) is kept, so a page can show a second NIC /
 *   DAG replication / NAT address instead of only the one address the server was added with.
 *   createHealth({ targets, runner, state, config, log })  .start() .stop() .pollServer(id) .pollAll() .snapshot(id) .findings({role})
 *     .addresses(id) → {at, items:[{ip, interface, prefix}]} | null   .refreshAddresses(by) → runs only the network check on every server with a login
 */
const CHECKS = require('./checks.json').checks;
const SEVR = { low: 1, medium: 2, high: 3, critical: 4 };
// what a server is: an administrator's setting first, then what the server itself reports (installed roles, the AD / Hyper-V
// tools answering), then the name (DC01, ADC2, ASDC1 - the platform's naming rule for domain controllers)
const DC_RE = /(^|[^a-z])(a|as|ad)?dc\d*([^a-z]|$)|domain controller/i;
function kindsOf(t, snap) {
  const R = (snap && snap.results) || {}, k = new Set(Array.isArray(t.kinds) ? t.kinds : []), data = (id) => (R[id] && !R[id].error ? R[id].data : undefined);
  const roles = [].concat(data('roles') || []).map((r) => String((r && r.name) || ''));
  if (roles.includes('AD-Domain-Services') || (data('dc_dcdiag') || {}).available === true || DC_RE.test(String(t.name || '')) || DC_RE.test(String(t.id || ''))) k.add('dc');
  if (roles.includes('Hyper-V') || (data('hv_host') || {}).available === true || Array.isArray(data('hv_vms'))) k.add('hyperv');
  return [...k];
}

function evaluate(t, snap, now = Date.now()) {
  const out = [], R = (snap && snap.results) || {};
  const add = (severity, kind, title, evidence, rec, scope) => out.push({ server: t.id, server_name: t.name, site: t.site, scope: scope || 'windows', severity, kind, title, evidence: [].concat(evidence || []).slice(0, 8), recommendation: rec });
  const arr = (x) => (Array.isArray(x) ? x : x == null ? [] : [x]);
  for (const [id, r] of Object.entries(R)) {
    if (r && r.error) add(r.kind === 'denied' ? 'low' : 'medium', 'cannot-check', `${t.name}: check "${id}" could not run`, [r.error], r.kind === 'auth' ? 'Check the login profile (user, password) and that the account is in Remote Management Users on the server.' : r.kind === 'denied' ? 'The account lacks a permission this check needs; grant it or ignore this check.' : 'Check WinRM on the server (Enable-PSRemoting, firewall 5985/5986) and the network path from the SIEM.', (CHECKS.find((c) => c.id === id) || {}).scope);
  }
  const d = (id) => (R[id] && !R[id].error ? R[id].data : undefined);
  for (const v of arr(d('disks'))) if (v && v.free_pct != null) {
    if (v.free_pct < 5) add('critical', 'disk', `${t.name} ${v.drive} almost full: ${v.free_pct} % free`, [`${v.free_gb} GB free of ${v.size_gb} GB`], 'Free space now (logs, temp, old updates: DISM /Online /Cleanup-Image /StartComponentCleanup) or extend the volume.');
    else if (v.free_pct < 10) add('high', 'disk', `${t.name} ${v.drive} low on space: ${v.free_pct} % free`, [`${v.free_gb} GB free of ${v.size_gb} GB`], 'Plan a cleanup or extend the volume before it fills.');
  }
  const svc = arr(d('stopped_auto_services'));
  if (svc.length) add('medium', 'service', `${t.name}: ${svc.length} automatic service(s) not running`, svc.slice(0, 8).map((s) => `${s.display || s.name} (${s.name}) ${s.state}${s.exit_code ? ', exit ' + s.exit_code : ''}`), 'Check why each stopped (System log, service account password) and start it, or set it to Manual if it is not needed.');
  const ev = arr(d('events')), crit = ev.filter((e) => /critical/i.test(e.level || ''));
  if (crit.length) add('high', 'events', `${t.name}: critical events in the System log`, crit.slice(0, 5).map((e) => `${e.source} ${e.id} ×${e.count}: ${e.message}`), 'Open the events (Ask the AI, or run the events check) and fix the cause.');
  else if (ev.length >= 5) add('low', 'events', `${t.name}: ${ev.reduce((s, e) => s + (e.count || 0), 0)} error events in the System log (24 h)`, ev.slice(0, 5).map((e) => `${e.source} ${e.id} ×${e.count}: ${e.message}`), 'Review the most frequent sources.');
  const up = d('updates');
  if (up && up.days_since_last_update != null && up.days_since_last_update > 45) add('medium', 'patch', `${t.name}: no update installed for ${up.days_since_last_update} days`, [`last: ${String(up.last_installed || '').slice(0, 10)}`], 'Patch the server in the next maintenance window (monthly cumulative update).');
  const si = d('system_info');
  if (up && up.pending_reboot && si && si.uptime_days > 7) add('low', 'reboot', `${t.name}: restart pending for updates (up ${si.uptime_days} days)`, (up.pending_reasons || []).map((x) => 'pending: ' + x), 'Restart in the next maintenance window so the installed updates take effect.');
  if (si && si.memory_free_pct != null && si.memory_free_pct < 10) add('medium', 'memory', `${t.name}: only ${si.memory_free_pct} % memory free`, [`${si.memory_gb} GB installed`], 'Find the process using it (top_processes) or add memory.');
  for (const c of arr(d('certificates'))) if (c && c.has_private_key && c.days_left != null && c.days_left < 30) add(c.days_left < 0 ? 'critical' : c.days_left < 7 ? 'high' : 'medium', 'certificate', `${t.name}: certificate ${c.days_left < 0 ? 'EXPIRED' : 'expires in ' + c.days_left + ' days'} - ${String(c.subject || '').slice(0, 80)}`, [`thumbprint ${c.thumbprint}`, `not after ${String(c.not_after).slice(0, 10)}`], 'Renew it and bind the new certificate where the old one is used (IIS, RDP, LDAPS, WinRM).');
  // Exchange
  // domain controllers: dcdiag, AD replication, SYSVOL, the time source
  const dg = d('dc_dcdiag'); if (dg && dg.available && dg.failed) add('high', 'dc-health', `${t.name}: dcdiag - ${dg.failed} test(s) failed`, arr(dg.tests).filter((x) => x && x.result === 'failed').map((x) => `${x.test} (${x.target})`), 'Run dcdiag /test:<name> /v on the DC for the detail; replication and SYSVOL failures first - ask the AI to explain the output.');
  const rs = d('dc_replication'); if (rs && rs.summary) { const fails = [...String(rs.summary).matchAll(/^\s*(\S+)\s+.+?\s+(\d+)\s*\/\s*(\d+)\s+\d+/gm)].filter((m) => +m[2] > 0); if (fails.length) add('high', 'dc-replication', `${t.name}: Active Directory replication failing`, fails.slice(0, 6).map((m) => `${m[1]}: ${m[2]} of ${m[3]} failed`), 'repadmin /showrepl on this DC names the partner and the error; check DNS and the network to that partner.'); }
  for (const f of arr((d('dc_sysvol') || {}).folders)) if (f && f.state != null && f.state !== 4) add(f.state === 5 ? 'critical' : 'high', 'dc-sysvol', `${t.name}: SYSVOL replicated folder ${f.folder || ''} is not in normal state`, [`DFSR state ${f.state} (${['uninitialised', 'initialised', 'initial sync', 'auto recovery', 'normal', 'in error'][f.state] || 'unknown'})`], 'Group Policy and logon scripts differ between DCs until it recovers; look at the DFS Replication event log on this DC.');
  const tm = d('dc_time'); if (tm) {
    if (/VM IC Time/i.test(tm.source || '')) add('medium', 'dc-time', `${t.name}: the domain controller takes its time from the Hyper-V host`, [`source: ${tm.source}`], 'Turn off Time synchronization in the VM\'s Integration Services and let the PDC emulator sync from an external NTP source; the other DCs follow the domain hierarchy.');
    else if (tm.local_clock) add('medium', 'dc-time', `${t.name}: the time source is the local clock`, [`source: ${tm.source}`], 'The PDC emulator should sync from a reliable NTP source (w32tm /config /manualpeerlist:... /syncfromflags:manual /reliable:yes); other DCs from the domain hierarchy.');
    if (tm.offset_s != null && Math.abs(tm.offset_s) >= 5) add(Math.abs(tm.offset_s) >= 60 ? 'high' : 'medium', 'dc-time', `${t.name}: clock ${tm.offset_s > 0 ? 'ahead of' : 'behind'} its source by ${Math.abs(tm.offset_s)} s`, [`source: ${tm.source}`], 'Kerberos refuses tickets beyond 5 minutes of skew; resync (w32tm /resync) after fixing the source.');
  }
  // Hyper-V hosts: VM replication, VMs not running cleanly, old checkpoints, integration services
  for (const r of arr(d('hv_replication'))) if (r && /critical|warning/i.test(r.health || '')) add(/critical/i.test(r.health) ? 'high' : 'medium', 'hv-replication', `${t.name}: Hyper-V Replica of ${r.vm} is ${r.health}`, [`state ${r.state}, last replication ${r.last || 'never'}`, `${r.primary || ''} -> ${r.replica || ''}`], 'Measure-VMReplication -VMName <vm> shows the reason; check the network and space on the replica server, then Resume-VMReplication (a person runs it).');
  for (const v of arr(d('hv_vms'))) {
    if (!v) continue;
    if (/^(Saved|Paused|Critical|.*Critical)$/i.test(v.state || '')) add(/Critical/i.test(v.state) ? 'high' : 'medium', 'hv-vm-state', `${t.name}: VM ${v.name} is ${v.state}`, [v.status || ''], 'A paused or critical VM usually means its storage is full or unreachable - free space on the volume, then resume it.');
    if (v.oldest_checkpoint_days != null && v.oldest_checkpoint_days > 7) add('low', 'hv-checkpoint', `${t.name}: VM ${v.name} has a checkpoint ${v.oldest_checkpoint_days} days old`, [`${v.checkpoints} checkpoint(s)`], 'Old checkpoints slow the VM and fill the volume; delete the ones nobody needs (Hyper-V merges them back).');
    if (/UpdateRequired|update required/i.test(v.integration || '') && v.state === 'Running') add('low', 'hv-integration', `${t.name}: VM ${v.name} - integration services need an update`, [v.integration], 'Update them through Windows Update in the guest (Windows Server 2016 and later) at the next maintenance window.');
  }
  for (const s of arr(d('ex_service_health'))) if (s && s.all_running === false) add('high', 'ex-service', `${t.name}: Exchange ${s.role} services not running`, arr(s.not_running), 'Start the listed services (Start-Service) and check the Application log for why they stopped.', 'exchange');
  for (const c of arr(d('ex_certificates'))) if (c && c.days_left != null && c.days_left < 30 && /IIS|SMTP|IMAP|POP/i.test(c.services || '')) add(c.days_left < 0 ? 'critical' : 'high', 'ex-certificate', `${t.name}: Exchange certificate for ${c.services} ${c.days_left < 0 ? 'EXPIRED' : 'expires in ' + c.days_left + ' days'}`, [String(c.subject || '').slice(0, 100), `thumbprint ${c.thumbprint}`], 'Renew it, Import-ExchangeCertificate on every server, Enable-ExchangeCertificate -Services IIS,SMTP; update the hybrid / connector TLS settings that name it.', 'exchange');
  for (const q of arr(d('ex_queues'))) if (q && (q.messages > 100 || /retry|suspended/i.test(q.status || ''))) add(q.messages > 1000 ? 'critical' : 'high', 'ex-queue', `Mail queue ${q.queue}: ${q.messages} messages, ${q.status}`, [q.next_hop ? 'next hop ' + q.next_hop : '', q.last_error ? 'last error: ' + q.last_error : ''].filter(Boolean), 'Check the next hop (DNS, smart host, firewall to port 25, certificate on the far side) and the last error; Retry-Queue after fixing.', 'exchange');
  for (const b of arr(d('ex_databases'))) if (b) {
    if (b.mounted === false) add('critical', 'ex-database', `Mailbox database ${b.name} is NOT mounted`, [`server ${b.server}`], 'Check the Application log (ESE events), free disk space on the database and log volumes, then Mount-Database.', 'exchange');
    const last = b.last_full_backup ? Date.parse(b.last_full_backup) : 0;
    if (!b.circular_logging && (!last || now - last > 7 * 86400000)) add('medium', 'ex-backup', `Mailbox database ${b.name}: ${last ? 'no full backup for ' + Math.floor((now - last) / 86400000) + ' days' : 'never backed up'}`, [`size ${b.size || '?'}`], 'Check the backup job (NetBackup / Veeam application-aware Exchange backup); without it transaction logs are never truncated and the log volume fills.', 'exchange');
  }
  for (const c of arr(d('ex_db_copies'))) if (c) {
    if (!/^(Healthy|Mounted)$/i.test(c.status || '')) add('high', 'ex-copy', `Database copy ${c.copy}: ${c.status}`, [`copy queue ${c.copy_queue}, replay queue ${c.replay_queue}`], 'Check the DAG network and the copy server; Resume-MailboxDatabaseCopy, or Update-MailboxDatabaseCopy if it stays failed.', 'exchange');
    else if ((c.copy_queue || 0) > 10 || (c.replay_queue || 0) > 100) add('medium', 'ex-copy-queue', `Database copy ${c.copy}: queues building up`, [`copy queue ${c.copy_queue}, replay queue ${c.replay_queue}`], 'Check DAG replication network bandwidth and the copy server disk.', 'exchange');
    if (c.content_index && !/Healthy|NotApplicable/i.test(c.content_index)) add('low', 'ex-index', `Database copy ${c.copy}: content index ${c.content_index}`, [], 'Search in Outlook / OWA may miss items; re-seed the index (Update-MailboxDatabaseCopy -CatalogOnly) if it does not recover.', 'exchange');
  }
  const hs = arr(d('ex_server_health'));
  if (hs.length) add('medium', 'ex-health', `${hs.length} Exchange health monitor(s) not healthy`, hs.slice(0, 8).map((h) => `${h.server} ${h.health_set}/${h.monitor}: ${h.state}`), 'Look at the health set (Get-ServerHealth / Get-HealthReport) - managed availability may already be recovering it.', 'exchange');
  return out;
}

function createHealth({ targets, runner, state, config, log } = {}) {
  const L = log || { info() {}, warn() {} }, store = state.collection('sysadmin_health');
  const cfg = () => (config && config.sysadmin) || {};
  let timer = null, running = null, lastRun = 0;
  const baseline = (role) => CHECKS.filter((c) => c.baseline && c.scope === role && !c.when);
  const roleChecks = (kinds) => CHECKS.filter((c) => c.baseline && c.when && kinds.includes(c.when));

  async function pollServer(id, opts = {}) {
    const t = targets.get(id); if (!t) throw Object.assign(new Error('server not found'), { code: 404 });
    const snap = store.get(t.id) || { id: t.id, results: {} };
    snap.results = Object.assign({}, snap.results);
    for (const role of t.roles || []) {
      if (!targets.login(t, role)) continue;
      for (const c of baseline(role)) {
        if (c.org && !opts.org) continue;
        try { const r = await runner.run(t.id, c.id, {}, { by: opts.by || 'health-check', via: 'health' }); snap.results[c.id] = { at: Date.now(), data: r.data }; }
        catch (e) { snap.results[c.id] = { at: Date.now(), error: String(e.message).slice(0, 300), kind: e.kind || '' }; if (/auth|missing|certificate|no-login/.test(e.kind) || e.code === 503) break; }
      }
      // what the server is (read once a day), then the checks of that role: domain controller, Hyper-V host
      if (role !== 'windows') continue;
      const stop = Object.values(snap.results).some((r) => r && r.error && /auth|missing|certificate|no-login/.test(r.kind || ''));
      if (stop) continue;
      if (!snap.results.roles || Date.now() - (snap.results.roles.at || 0) > 864e5) {
        try { const r = await runner.run(t.id, 'roles', {}, { by: opts.by || 'health-check', via: 'health' }); snap.results.roles = { at: Date.now(), data: r.data }; }
        catch (e) { snap.results.roles = { at: Date.now(), error: String(e.message).slice(0, 300), kind: e.kind || '' }; }
      }
      for (const c of roleChecks(kindsOf(t, snap))) {
        try { const r = await runner.run(t.id, c.id, {}, { by: opts.by || 'health-check', via: 'health' }); snap.results[c.id] = { at: Date.now(), data: r.data }; }
        catch (e) { snap.results[c.id] = { at: Date.now(), error: String(e.message).slice(0, 300), kind: e.kind || '' }; }
      }
    }
    snap.kinds = kindsOf(t, snap);
    snap.at = Date.now(); store.put(snap); return snap;
  }
  async function pollAll() {
    if (running) return running;
    running = (async () => {
      const st = await runner.status(); if (!st.available) return { skipped: st.reason };
      const list = targets.list().filter((t) => t.poll !== false && (t.roles || []).some((r) => targets.login(t, r)));
      let orgDone = false;
      for (const t of list) {
        const isEx = (t.roles || []).includes('exchange') && targets.login(t, 'exchange');
        try { const s = await pollServer(t.id, { org: isEx && !orgDone }); if (isEx && !orgDone && s.results.ex_databases && !s.results.ex_databases.error) orgDone = true; }
        catch (e) { L.warn('sysadmin health poll failed', { server: t.id, err: e.message }); }
      }
      lastRun = Date.now(); return { servers: list.length };
    })().finally(() => { running = null; });
    return running;
  }
  function snapshot(id) { return store.get(id) || null; }
  // the server's own view of its addresses: a host with two NICs shows both (never inferred, only what Get-NetIPAddress said)
  function addresses(id) {
    const s = store.get(id), r = s && s.results && s.results.network;
    if (!r) return null;
    if (r.error) return { at: r.at, error: r.error, items: [] };
    const a = (r.data && r.data.addresses) || [], list = Array.isArray(a) ? a : [a];
    const ok = (ip) => /^\d{1,3}(\.\d{1,3}){3}$/.test(String(ip || '')) && !/^(127\.|169\.254\.)/.test(ip);
    const seen = new Set(), items = [];
    for (const x of list) if (x && ok(x.ip) && !seen.has(x.ip)) { seen.add(x.ip); items.push({ ip: x.ip, interface: String(x.interface || '').slice(0, 80), prefix: x.prefix == null ? null : Number(x.prefix) }); }
    return { at: r.at, items };
  }
  // operator asks for the addresses now: only the read-only network check, on every server that has a login
  async function refreshAddresses(by) {
    const st = await runner.status(); if (!st.available) throw Object.assign(new Error('the PowerShell helper is not available: ' + (st.reason || 'not installed')), { code: 503 });
    const out = [];
    for (const t of targets.list()) {
      const role = (t.roles || []).find((r) => targets.login(t, r));
      if (!role) { out.push({ id: t.id, name: t.name, status: 'no-login' }); continue; }
      const snap = store.get(t.id) || { id: t.id, results: {} }; snap.results = Object.assign({}, snap.results);
      try { const r = await runner.run(t.id, 'network', {}, { by: by || 'addresses', via: 'addresses' }); snap.results.network = { at: Date.now(), data: r.data }; }
      catch (e) { snap.results.network = { at: Date.now(), error: String(e.message).slice(0, 300), kind: e.kind || '' }; L.warn('sysadmin address refresh failed', { server: t.id, err: e.message }); }
      store.put(snap);
      const a = addresses(t.id); out.push({ id: t.id, name: t.name, status: a.error ? 'failed' : 'ok', error: a.error || null, addresses: a.items.map((x) => x.ip) });
    }
    return out;
  }
  function findings({ role } = {}) {
    const out = [];
    for (const t of targets.list(role)) {
      const s = store.get(t.id);
      if (!s) continue;
      for (const f of evaluate(t, s)) if (!role || f.scope === role || role === 'exchange' && f.scope === 'windows') out.push(f);
    }
    return out.sort((a, b) => SEVR[b.severity] - SEVR[a.severity]);
  }
  return {
    start() { if (timer) return; const iv = Math.max(5, cfg().interval_min || 15) * 60000; const t1 = setTimeout(guardJob('sysadmin.health.pollAll', () => pollAll()), 90000); timer = setInterval(guardJob('sysadmin.health.pollAll', () => pollAll()), iv); if (t1.unref) t1.unref(); if (timer.unref) timer.unref(); },
    stop() { if (timer) clearInterval(timer); timer = null; },
    pollServer, pollAll, snapshot, findings, addresses, refreshAddresses, stats: () => ({ interval_min: Math.max(5, cfg().interval_min || 15), last_run: lastRun || null, running: !!running }),
  };
}

module.exports = { createHealth, evaluate, kindsOf, DC_RE };
