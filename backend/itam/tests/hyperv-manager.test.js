// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Hyper-V manager (engine/hyperv-manager.js) with SYNTHETIC host reports through the real report routes (admin import and the
// agent route with an enrolled key): metrics kept per host and day; capacity forecast from the daily trend; right-sizing from the
// VM's own 14 days; heartbeat lost, replication not healthy, an old checkpoint, a zombie VM, a full VHD, vCPU overcommit; VM
// actions four-eyes (operator proposes, a different administrator approves, never an AI identity), fetched once by THAT host's
// script with the agent key and reported back; roles, audit.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');
const { assess, normMetrics } = require('../engine/hyperv-manager');

const DAY = 86400000, VIEW = { user: 'vera.syn', role: 'viewer' }, OP = { user: 'nora.syn', role: 'operator' }, ADM = { user: 'admin.syn', role: 'admin' }, ADM2 = { user: 'sec.syn', role: 'admin' }, BOT = { user: 'ai:virt', role: 'admin' };
function report(day, o = {}) {
  const at = new Date(Date.parse('2026-11-01T06:00:00Z') + day * DAY).toISOString();
  return { collected_at: at, host: { name: 'HV-SYN-01', ip: '10.20.8.10', os: 'Windows Server 2022 Datacenter', logical_processors: 8, cpu_pct: 35, mem_total_mb: 262144, mem_free_mb: Math.max(1000, 120000 - day * 4000),
    volumes: [{ name: 'C:\\ClusterStorage\\Volume1', size_gb: 2000, free_gb: 900 - day * 5, csv: true }] },
    vms: [
      { name: 'APP-SYN-01', vm_id: 'a-1', state: 'Running', vcpus: 16, cpu_pct: 20, mem_assigned_mb: 32768, mem_demand_mb: 6000, heartbeat: 'OkApplicationsHealthy', ips: ['10.20.8.21'], macs: ['00155D010203'],
        vhds: [{ path: 'C:\\ClusterStorage\\Volume1\\APP-SYN-01\\disk0.vhdx', size_gb: 190, max_gb: 200 }], checkpoints: [{ name: 'before patch', created: '2026-11-01T00:00:00Z' }], replication_state: 'Replicating', replication_health: o.repl || 'Normal' },
      { name: 'DB-SYN-01', vm_id: 'a-2', state: 'Running', vcpus: 24, cpu_pct: 40, mem_assigned_mb: 16384, mem_demand_mb: 15800, heartbeat: o.hb || 'OkApplicationsHealthy' },
      { name: 'OLD-SYN-01', vm_id: 'a-3', state: 'Off', vcpus: 2, mem_assigned_mb: 0, off_since: '2026-09-01T00:00:00Z' }] };
}

test('the model on its own: tolerant parsing, nothing measured is never a number', () => {
  const r = normMetrics({ host: { name: 'H' }, vms: [{ name: 'V', state: 'Running' }] });
  assert.equal(r.host.mem_total_mb, null); assert.equal(r.vms[0].cpu_pct, null);
  assert.throws(() => normMetrics({ host: {} }), /host.name/);
  assert.equal(assess(r, [], Date.now()).findings.length, 0);
});

test('reports, learned findings, capacity, four-eyes actions run by the host script, roles, audit', async (t) => {
  let clock = Date.parse('2026-11-01T07:00:00Z');
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true, now: () => clock, python: process.env.PYTHON || 'python3' });
  const call = (m, p, b, who) => e.req(m, p, Object.assign(b !== undefined ? { body: b } : {}, who));
  const audit = (a) => e.app.store.auditTail(1000).filter((x) => x.action === a);
  const sr = await call('POST', '/discovery/scopes', { name: 'HQ Hyper-V', site: 'Riyadh HQ', targets: ['10.20.8.0/24'], methods: { hyperv: { enabled: true } } }, ADM); assert.equal(sr.status, 200, sr.text); const scope = sr.json.scope;
  let v = (await call('GET', '/hyperv', undefined, VIEW)).json; assert.equal(v.kpis.hosts, 0); assert.match(v.note, /hyperv-report\.ps1/);
  // 14 daily reports (admin import), the last with trouble
  for (let d = 0; d < 14; d++) {
    clock = Date.parse('2026-11-01T07:00:00Z') + d * DAY;
    const r = await call('POST', '/discovery/hyperv/import', { scope_id: scope.id, report: report(d, d === 13 ? { hb: 'LostCommunication', repl: 'Critical' } : {}) }, ADM);
    assert.equal(r.status, 200, r.text); assert.equal(r.json.manager.metrics, true);
  }
  v = (await call('GET', '/hyperv', undefined, VIEW)).json;
  assert.equal(v.kpis.hosts, 1); assert.equal(v.kpis.vms, 3); assert.equal(v.kpis.running, 2);
  const codes = v.findings.map((f) => f.code);
  for (const c of ['heartbeat', 'replication', 'checkpoint', 'zombie', 'vhd-full', 'oversized', 'undersized', 'overcommit', 'capacity-memory']) assert.ok(codes.includes(c), c + ' in ' + codes.join(','));
  const h = v.hosts[0]; assert.ok(h.capacity.memory != null && h.capacity.memory < 30, 'memory runs out within a month at this growth: ' + h.capacity.memory);
  assert.match(v.findings.find((f) => f.code === 'oversized').title, /APP-SYN-01: memory demand 6000 MB \(p95, 14 days\) of 32768 MB/);
  // actions: four-eyes, only known VMs, one waiting at a time
  assert.equal((await call('POST', '/hyperv/actions', { host: 'HV-SYN-01', vm: 'DB-SYN-01', action: 'restart', reason: 'guest stopped answering (synthetic)' }, VIEW)).status, 403);
  let r = await call('POST', '/hyperv/actions', { host: 'HV-SYN-01', vm: 'NOPE', action: 'restart', reason: 'synthetic reason' }, OP); assert.equal(r.status, 400);
  r = await call('POST', '/hyperv/actions', { host: 'HV-SYN-01', vm: 'DB-SYN-01', action: 'format-disk', reason: 'synthetic reason' }, OP); assert.equal(r.status, 400);
  r = await call('POST', '/hyperv/actions', { host: 'HV-SYN-01', vm: 'DB-SYN-01', action: 'restart', reason: 'guest stopped answering (synthetic)' }, ADM); assert.equal(r.status, 200, r.text); const id = r.json.id;
  assert.equal((await call('POST', '/hyperv/actions', { host: 'HV-SYN-01', vm: 'DB-SYN-01', action: 'start', reason: 'synthetic reason two' }, OP)).status, 409);
  assert.equal((await call('POST', `/hyperv/actions/${id}/decide`, { decision: 'approved' }, ADM)).status, 403, 'proposer');
  assert.equal((await call('POST', `/hyperv/actions/${id}/decide`, { decision: 'approved' }, OP)).status, 403, 'operator');
  assert.equal((await call('POST', `/hyperv/actions/${id}/decide`, { decision: 'approved' }, BOT)).status, 403, 'AI identity');
  // the host's script: agent key; nothing before approval; only its own host; each action once
  const tok = (await call('POST', '/settings/agent-tokens', {}, ADM)).json.token;
  const enr = (await e.req('POST', '/agent/enrol', { user: '', role: '', body: { token: tok, hostname: 'HV-SYN-01', platform: 'windows' } })).json;
  const ag = (m, p, b) => e.req(m, p, { user: '', role: '', bearer: enr.agent_key, body: b });
  assert.equal((await e.req('GET', '/agent/hyperv/actions?host=HV-SYN-01', { user: '', role: '', bearer: 'bogus' })).status, 401);
  assert.deepEqual((await ag('GET', '/agent/hyperv/actions?host=HV-SYN-01')).json.actions, [], 'nothing before approval');
  assert.equal((await call('POST', `/hyperv/actions/${id}/decide`, { decision: 'approved' }, ADM2)).status, 200);
  assert.deepEqual((await ag('GET', '/agent/hyperv/actions?host=HV-OTHER')).json.actions, [], 'another host never gets it');
  assert.deepEqual((await ag('GET', '/agent/hyperv/actions?host=HV-SYN-01')).json.actions, [{ id, vm: 'DB-SYN-01', action: 'restart' }]);
  assert.deepEqual((await ag('GET', '/agent/hyperv/actions?host=HV-SYN-01')).json.actions, [], 'handed out once');
  assert.equal((await ag('POST', `/agent/hyperv/actions/${id}/result`, { ok: true, message: 'Restart-VM completed' })).status, 200);
  assert.equal((await call('GET', '/hyperv', undefined, VIEW)).json.actions.find((a) => a.id === id).status, 'done');
  // the agent report route carries the metrics too
  assert.equal((await ag('POST', '/agent/hyperv', report(14))).json.manager.metrics, true);
  for (const a of ['hyperv.action.propose', 'hyperv.action.approve', 'hyperv.action.result']) assert.ok(audit(a).length && audit(a).every((x) => x.by && x.role), 'audited: ' + a);
});

test('the host script: read-only report, only the approved verbs the manager knows, this host only', () => {
  const fs = require('node:fs'), path = require('node:path'), { ACTIONS } = require('../engine/hyperv-manager');
  const ps = fs.readFileSync(path.join(__dirname, '..', 'install', 'hyperv-report.ps1'), 'utf8');
  const [report, actions] = ps.split('# ---- 2 approved actions');
  assert.ok(actions, 'two parts');
  const verbs = [...actions.matchAll(/^\s*'([a-z-]+)'\s*\{/gm)].map((m) => m[1]).sort();
  assert.deepEqual(verbs, Object.keys(ACTIONS).sort(), 'the script runs exactly the manager\'s verbs');
  assert.match(actions, /default\s*\{\s*throw "not an allowed action/, 'anything else is refused');
  assert.match(actions, /\/hyperv\/actions\?host=" \+ \[uri\]::EscapeDataString\(\$env:COMPUTERNAME\)/, 'asks for its own host only');
  const cmdlets = [...report.split('# ---- 1 the report (read-only)')[1].matchAll(/\b([A-Z][a-z]+-[A-Z][A-Za-z]+)\b/g)].map((m) => m[1]);
  const bad = cmdlets.filter((c) => !/^(Get|Measure|Where|ForEach|Select|Invoke|ConvertTo|Out)-/.test(c) && c !== 'Write-Warning');
  assert.deepEqual([...new Set(bad)], [], 'the report part only reads');
  assert.match(ps, /\$Server\/hyperv"/); assert.match(ps, /ValidatePattern\('\^https:/, 'https only');
});

// adding hosts: an administrator names them, each gets its own one-time key and the script's fingerprint; the script is served on the
// agent side without a key (it carries no secret) and matches the fingerprint; operators / viewers / an AI identity are refused; bad
// host names are a 400 naming the field; the list says which hosts enrolled and which report; audit without the keys
test('add Hyper-V hosts: one key per host, the script and its fingerprint, roles, validation, audit', async (t) => {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true, python: process.env.PYTHON || 'python3' });
  const call = (m, p, b, who) => e.req(m, p, Object.assign(b !== undefined ? { body: b } : {}, who));
  const sc = (await e.req('GET', '/agent/hyperv/script', { user: '', role: '' })).json;
  const sha = require('crypto').createHash('sha256').update(sc.script, 'utf8').digest('hex');
  assert.equal(sc.sha256, sha, 'the fingerprint is of the served text'); assert.match(sc.script, /hyperv-report\.ps1/); assert.ok(!/EnrolToken\s*=\s*'[0-9a-f]{8}/.test(sc.script), 'no key in the script');
  for (const who of [VIEW, OP]) assert.equal((await call('POST', '/hyperv/onboard', { hosts: ['HV-SYN-01'] }, who)).status, 403, who.role + ' refused');
  assert.equal((await call('GET', '/hyperv/onboard', undefined, OP)).status, 403);
  assert.equal((await call('POST', '/hyperv/onboard', { hosts: ['HV-SYN-01'] }, BOT)).status, 403, 'not an AI identity');
  let r = await call('POST', '/hyperv/onboard', { hosts: ['HV SYN;rm'] }, ADM); assert.equal(r.status, 400); assert.match(r.json.error, /hosts\[0\]/);
  r = await call('POST', '/hyperv/onboard', { hosts: 'HV-SYN-01' }, ADM); assert.equal(r.status, 400); assert.match(r.json.error, /hosts/);
  r = await call('POST', '/hyperv/onboard', { hosts: Array.from({ length: 51 }, (_, i) => 'HV-' + i) }, ADM); assert.equal(r.status, 400);
  r = await call('POST', '/hyperv/onboard', { hosts: ['HV-SYN-01', 'hv-syn-02.safari.local', 'HV-SYN-01'], extra: 'dropped' }, ADM);
  assert.equal(r.status, 200, r.text); assert.equal(r.json.hosts.length, 2, 'one per distinct host'); assert.equal(r.json.script_sha256, sha);
  assert.notEqual(r.json.hosts[0].token, r.json.hosts[1].token, 'each host its own key');
  // the key enrols that host once; the list shows enrolled / waiting
  const enr = await e.req('POST', '/agent/enrol', { user: '', role: '', body: { token: r.json.hosts[0].token, hostname: 'HV-SYN-01', platform: 'windows' } });
  assert.equal(enr.status, 200); assert.ok(enr.json.agent_key);
  assert.equal((await e.req('POST', '/agent/enrol', { user: '', role: '', body: { token: r.json.hosts[0].token, hostname: 'HV-SYN-01', platform: 'windows' } })).status, 401, 'a key works once');
  const ov = (await call('GET', '/hyperv/onboard', undefined, ADM)).json;
  assert.equal(ov.script.sha256, sha);
  const st = Object.fromEntries(ov.invited.map((x) => [x.host, x.state]));
  assert.match(st['HV-SYN-01'], /enrolled/); assert.equal(st['hv-syn-02.safari.local'], 'waiting for the host');
  const a = e.app.store.auditTail(200).filter((x) => x.action === 'hyperv.onboard');
  assert.equal(a.length, 1); assert.equal(a[0].by, 'admin.syn'); assert.deepEqual(a[0].detail.hosts, ['HV-SYN-01', 'hv-syn-02.safari.local']);
  assert.ok(!JSON.stringify(e.app.store.auditTail(200)).includes(r.json.hosts[0].token), 'no key in the audit');
});

// network speed and resource monitoring: NIC link and rate, disk latency, VM network kept per report (48 h of readings); a NIC over
// 90 % of its link now is high, over 80 % at p95 for 24 h is medium, a link below 1 Gbps is low; disk latency the same way; the trend
// is the host's own readings; a host that sends no counters shows nothing (no invented 0)
test('network speed and disk: per-NIC utilisation against the link, p95 over 24 h, disk latency, trend, no invented figures', async (t) => {
  let clock = Date.parse('2026-11-20T00:00:00Z');
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true, now: () => clock, python: process.env.PYTHON || 'python3' });
  const call = (m, p, b, who) => e.req(m, p, Object.assign(b !== undefined ? { body: b } : {}, who));
  const sc = (await call('POST', '/discovery/scopes', { name: 'HV', site: 'Riyadh HQ', targets: ['10.20.8.0/24'], methods: { hyperv: { enabled: true } } }, ADM)).json.scope;
  const rep = (at, gbps, ms, o = {}) => ({ collected_at: new Date(at).toISOString(), host: { name: 'HV-SYN-01', logical_processors: 8, cpu_pct: 30, mem_total_mb: 65536, mem_free_mb: 30000, volumes: [],
    nics: [{ name: 'Team-10G', link_mbps: 10000, rx_bps: gbps * 1e9, tx_bps: 1e8 }, { name: 'Mgmt', link_mbps: o.slow ? 100 : 1000, rx_bps: 1e6, tx_bps: 1e6 }], disk: { latency_ms: ms, read_bps: 5e7, write_bps: 2e7 } },
    vms: [{ name: 'FILE-SYN-01', state: 'Running', vcpus: 4, net_rx_bps: gbps * 0.9e9, net_tx_bps: 5e7 }] });
  // 24 h of readings every 30 min at 8.5 Gbps on a 10 Gbps link (85 %) and 25 ms disk latency
  for (let i = 47; i >= 1; i--) { clock = Date.parse('2026-11-20T12:00:00Z') - i * 1800000; assert.equal((await call('POST', '/discovery/hyperv/import', { scope_id: sc.id, report: rep(clock, 8.5, 25) }, ADM)).status, 200); }
  clock = Date.parse('2026-11-20T12:00:00Z');
  await call('POST', '/discovery/hyperv/import', { scope_id: sc.id, report: rep(clock, 8.5, 25, { slow: true }) }, ADM);
  let v = (await call('GET', '/hyperv', undefined, VIEW)).json, h = v.hosts[0], codes = (x) => v.findings.filter((f) => f.target === x).map((f) => f.code);
  assert.equal(h.nics.length, 2); assert.equal(h.nics[0].link_mbps, 10000); assert.equal(h.disk.latency_ms, 25);
  assert.ok(h.trend.length >= 40 && h.trend.every((x) => x.rx_bps > 8e9), 'the trend is the host\'s own readings: ' + h.trend.length);
  assert.deepEqual(codes('Team-10G'), ['nic-busy'], 'over 80 % at p95: busy, not yet saturated');
  assert.match(v.findings.find((f) => f.code === 'nic-busy').title, /85 % of its 10 Gbps link at p95 over 24 h/);
  assert.deepEqual(codes('Mgmt'), ['nic-slow'], 'a link at 100 Mbps');
  assert.ok(v.findings.some((f) => f.code === 'disk-latency' && f.severity === 'medium' && /25 ms at p95/.test(f.title)));
  assert.equal(h.vms[0].net_rx_bps, 8.5 * 0.9e9, 'VM network rate kept');
  // now saturated, disk at 60 ms: high
  clock += 900000; await call('POST', '/discovery/hyperv/import', { scope_id: sc.id, report: rep(clock, 9.6, 60) }, ADM);
  v = (await call('GET', '/hyperv', undefined, VIEW)).json;
  assert.ok(v.findings.some((f) => f.code === 'nic-saturated' && f.severity === 'high' && /96 % of its 10 Gbps link in use now/.test(f.title)));
  assert.ok(v.findings.some((f) => f.code === 'disk-latency' && f.severity === 'high'));
  // a host without counters: no NICs, no disk, no network figures - nothing invented
  await call('POST', '/discovery/hyperv/import', { scope_id: sc.id, report: { collected_at: new Date(clock).toISOString(), host: { name: 'HV-SYN-02', volumes: [] }, vms: [{ name: 'X', state: 'Running' }] } }, ADM);
  v = (await call('GET', '/hyperv', undefined, VIEW)).json; h = v.hosts.find((x) => x.name === 'HV-SYN-02');
  assert.deepEqual(h.nics, []); assert.equal(h.disk, null); assert.equal(h.vms[0].net_rx_bps, null); assert.equal(h.trend[0].rx_bps, null);
  assert.ok(!v.findings.some((f) => f.host === 'HV-SYN-02' && /nic|disk/.test(f.code)));
});
