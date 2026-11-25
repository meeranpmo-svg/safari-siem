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
  const bad = cmdlets.filter((c) => !/^(Get|Measure|Where|ForEach|Select|Invoke|ConvertTo|Out)-/.test(c));
  assert.deepEqual([...new Set(bad)], [], 'the report part only reads');
  assert.match(ps, /\$Server\/hyperv"/); assert.match(ps, /ValidatePattern\('\^https:/, 'https only');
});
