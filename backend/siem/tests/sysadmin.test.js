// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// AI Windows Server + Exchange Server Administrators (engine/sysadmin): server list, write-only logins, the read-only
// check catalogue (helper refuses anything else, parameters validated), certificate trust, health findings, routes and
// roles, change plans with re-check, and the AI tool loop (fake SDK).
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { createState } = require('../engine/soc/state');
const routes = require('../engine/sysadmin/routes');
const { evaluate } = require('../engine/sysadmin/health');
const { CHECKS } = require('../engine/sysadmin/runner');

const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'sentra-sysadm-'));
const DATA = {
  system_info: { computer: 'FS01', uptime_days: 30, memory_gb: 32, memory_free_pct: 6 },
  disks: [{ drive: 'C:', size_gb: 100, free_gb: 3, free_pct: 3 }, { drive: 'D:', size_gb: 500, free_gb: 200, free_pct: 40 }],
  stopped_auto_services: [{ name: 'W32Time', display: 'Windows Time', state: 'Stopped', exit_code: 1067 }],
  events: [{ source: 'Microsoft-Windows-Kernel-Power', id: 41, level: 'Critical', count: 2, message: 'The system has rebooted without cleanly shutting down first.' }],
  updates: { days_since_last_update: 70, last_installed: '2026-08-04T00:00:00Z', pending_reboot: true, pending_reasons: ['windows update'] },
  certificates: [{ subject: 'CN=fs01.corp.local', thumbprint: 'AB', not_after: '2026-10-20T00:00:00Z', days_left: 6, has_private_key: true }],
  ex_servers: [{ name: 'EXCH01', roles: 'Mailbox', version: 'Version 15.2 (Build 1544.4)' }],
  ex_service_health: [{ role: 'Mailbox Server Role', all_running: false, not_running: ['MSExchangeTransport'] }],
  ex_queues: [{ queue: 'EXCH01\\3', status: 'Retry', messages: 250, next_hop: 'gmail.com', last_error: '451 4.4.0 DNS query failed' }],
  ex_databases: [{ name: 'DB01', server: 'EXCH01', mounted: false, last_full_backup: null, circular_logging: false }],
  ex_db_copies: [{ copy: 'DB01\\EXCH02', status: 'FailedAndSuspended', copy_queue: 500, replay_queue: 0, content_index: 'Failed' }],
  ex_certificates: [{ thumbprint: 'CC', subject: 'CN=mail.corp.sa', services: 'IMAP, POP, IIS, SMTP', days_left: 12 }],
  ex_server_health: [],
  network: { addresses: [{ interface: 'MAPI', ip: '30.30.30.20', prefix: 24, origin: 'Manual' }, { interface: 'Replication', ip: '10.99.0.20', prefix: 24, origin: 'Manual' }, { interface: 'Loopback', ip: '127.0.0.1', prefix: 8 }, { interface: 'Unused', ip: '169.254.3.4', prefix: 16 }, { interface: 'MAPI', ip: '30.30.30.20', prefix: 24 }], dns: [], gateway: ['30.30.30.1'], listening: [25, 443] },
};
function fakeExec(o = {}) {
  const calls = [];
  const fn = async (req) => {
    calls.push(JSON.parse(JSON.stringify(req)));
    if (req.op === 'version') return { ok: true, pypsrp: '0.9', python: '3.11' };
    if (req.op === 'certificate') return { ok: true, fingerprint: o.fp || 'AA:BB' };
    if (req.op === 'run') { if (o.fail) return o.fail; return { ok: true, data: DATA[req.check] !== undefined ? DATA[req.check] : [], errors: [] }; }
    return { ok: false, kind: 'input', error: 'bad op' };
  };
  fn.calls = calls; return fn;
}
async function setup(exec, sdk) {
  const dir = tmp(), secrets = path.join(dir, 'secrets.json'); fs.writeFileSync(secrets, JSON.stringify({ netops: { anthropic_api_key: 'sk-test' } }), { mode: 0o600 });
  const state = await createState({ dir: path.join(dir, 'state') });
  const config = {};   // deps.sysadmin is passed, so register() does not start the health timer
  Object.defineProperty(config, 'secrets', { value: { netops: { anthropic_api_key: 'sk-test' } }, enumerable: false, writable: true });
  Object.defineProperty(config, '_paths', { value: { secrets }, enumerable: false });
  const S = routes.createSysadmin({ state, config, log: { info() {}, warn() {}, error() {} }, sysadminExec: exec, anthropicSdk: sdk });
  const R = {}; routes.register({ route: (m, p, h) => { R[m + ' ' + p] = h; } }, { state, config, log: { error() {}, info() {} }, sysadmin: S });
  const RANK = { viewer: 0, analyst: 1, operator: 2, admin: 3 }, audits = [];
  async function call(m, p, { role = 'viewer', user = 'u1', body, params = {}, query = {} } = {}) {
    const out = {}; const ctx = { role, user, body, params, query, path: p, need(r) { if (RANK[role] < RANK[r]) { out.status = 403; return false; } return true; }, audit: (a, t, d) => audits.push([a, t, d]), ok(b) { out.status = 200; out.body = b; }, fail(c, msg) { out.status = c; out.error = msg; } };
    const rv = await R[m + ' /api/soc/sysadmin' + p](ctx); if (rv !== undefined && !out.status) { out.status = 200; out.body = rv; } return out;
  }
  return { S, call, audits, secrets, state };
}

test('helper: every check renders, unknown checks and bad parameters are refused, values are quoted', () => {
  const py = (req) => JSON.parse(spawnSync('python3', [path.join(__dirname, '../engine/sysadmin/ps-helper.py')], { input: JSON.stringify(req), encoding: 'utf8' }).stdout);
  for (const c of CHECKS) {
    const params = c.id === 'service' ? { name: 'W32Time' } : (c.params && c.params.address) ? { address: 'a.b@corp.sa' } : {};
    const r = py({ op: 'render', check: c.id, params }); assert.equal(r.ok, true, c.id + ': ' + r.error);
    assert.match(r.script, /ConvertTo-Json|^\s*'\[\]'/m, c.id + ' returns JSON');
    if (c.scope === 'exchange') assert.match(r.script, /Add-PSSnapin Microsoft\.Exchange/);
  }
  assert.equal(py({ op: 'render', check: 'Remove-Item', params: {} }).ok, false);
  assert.match(py({ op: 'render', check: 'service', params: { name: "x'; Restart-Computer" } }).error, /invalid value/);
  assert.match(py({ op: 'render', check: 'events', params: { hours: 999 } }).error, /1-168/);
  assert.match(py({ op: 'render', check: 'events', params: { log: 'Security' } }).error, /one of/);
  assert.match(py({ op: 'render', check: 'disks', params: { x: 1 } }).error, /not allowed/);
  const q = py({ op: 'render', check: 'ex_mailbox', params: { address: "o'brien@corp.sa" } });
  assert.ok(q.script.includes("'o''brien@corp.sa'"), 'single quote doubled inside a PowerShell literal');
  for (const c of CHECKS) assert.ok(!/\b(Set|New|Remove|Restart|Stop|Start|Enable|Disable|Move|Mount|Dismount|Suspend|Resume|Update|Clear|Invoke)-[A-Z]/.test(c.script.replace(/Invoke-Command/g, '')), c.id + ' must be read-only');
});

test('server list: Exchange implies Windows, logins write-only, check scope, no login → refused, ITAM source', async () => {
  const exec = fakeExec(); const { call, secrets, audits } = await setup(exec);
  assert.equal((await call('POST', '/targets', { role: 'operator', body: { id: 'fs01', ip: '10.0.1.10' } })).status, 403);
  const ex = await call('POST', '/targets', { role: 'admin', body: { id: 'exch01', name: 'EXCH01', ip: '10.0.1.20', roles: ['exchange'], source: 'itam', asset_id: 'AST-1', detected_by: 'software: Microsoft Exchange Server 2019' } });
  assert.deepEqual(ex.body.roles, ['windows', 'exchange']); assert.equal(ex.body.source, 'itam');
  await call('POST', '/targets', { role: 'admin', body: { id: 'fs01', name: 'FS01', ip: '10.0.1.10' } });
  assert.equal((await call('POST', '/targets', { role: 'admin', body: { id: 'dup', ip: '10.0.1.10' } })).status, 409);
  assert.deepEqual((await call('GET', '/targets', { query: { role: 'exchange' } })).body.items.map((t) => t.id), ['exch01']);
  assert.equal((await call('GET', '/targets', { query: { role: 'windows' } })).body.items.length, 2);
  let r = await call('POST', '/targets/:id/check', { role: 'operator', params: { id: 'fs01' }, body: { check: 'disks' } });
  assert.equal(r.status, 409); assert.match(r.error, /no windows login/);
  assert.ok(!exec.calls.some((c) => c.op === 'run'), 'nothing sent without a login');
  assert.equal((await call('PUT', '/profiles/:id', { role: 'operator', params: { id: 'windows' }, body: { username: 'CORP\\svc-mon', password: 'Pw-123456' } })).status, 403);
  const p = await call('PUT', '/profiles/:id', { role: 'admin', params: { id: 'windows' }, body: { username: 'CORP\\svc-mon', password: 'Pw-123456' } });
  assert.deepEqual(p.body.set, { user: 'CORP\\svc-mon', auth: 'negotiate' });
  assert.equal(JSON.parse(fs.readFileSync(secrets, 'utf8')).sysadmin.profiles.windows.password, 'Pw-123456');
  assert.equal(JSON.parse(fs.readFileSync(secrets, 'utf8')).netops.anthropic_api_key, 'sk-test', 'other secrets kept');
  for (const x of [await call('GET', '/targets'), await call('GET', '/profiles', { role: 'admin' }), await call('GET', '/targets/:id', { params: { id: 'fs01' } })]) assert.ok(!JSON.stringify(x.body).includes('Pw-123456'));
  r = await call('POST', '/targets/:id/check', { role: 'operator', params: { id: 'fs01' }, body: { check: 'ex_queues' } });
  assert.equal(r.status, 400); assert.match(r.error, /not an Exchange server/);
  r = await call('POST', '/targets/:id/check', { role: 'operator', params: { id: 'fs01' }, body: { check: 'disks' } });
  assert.equal(r.status, 200); assert.equal(r.body.data[0].drive, 'C:');
  const run = exec.calls.find((c) => c.op === 'run'); assert.equal(run.check, 'disks'); assert.equal(run.username, 'CORP\\svc-mon'); assert.equal(run.port, 5985); assert.equal(run.ssl, false); assert.equal(run.script, undefined, 'a check name is sent, never a script');
  assert.equal((await call('POST', '/targets/:id/check', { role: 'analyst', params: { id: 'fs01' }, body: { check: 'disks' } })).status, 403);
  assert.equal((await call('GET', '/runs', { role: 'operator' })).body.items[0].check, 'disks');
  assert.ok(audits.some(([a]) => a === 'sysadmin.check') && audits.some(([a]) => a === 'sysadmin.profile.set'));
});

test('WinRM HTTPS: certificate must be read and trusted before any login; a changed one is reported', async () => {
  const exec = fakeExec({ fp: '11:22:33' }); const { call } = await setup(exec);
  await call('POST', '/targets', { role: 'admin', body: { id: 'dc01', ip: '10.0.0.5', winrm: { ssl: true } } });
  await call('PUT', '/profiles/:id', { role: 'admin', params: { id: 'windows' }, body: { username: 'svc@corp.local', password: 'Pw-123456' } });
  let r = await call('POST', '/targets/:id/check', { role: 'operator', params: { id: 'dc01' }, body: { check: 'system_info' } });
  assert.equal(r.status, 409); assert.match(r.error, /certificate .* not trusted/);
  assert.equal((await call('POST', '/targets/:id/certificate/trust', { role: 'admin', params: { id: 'dc01' }, body: { fingerprint: '11:22:33' } })).status, 409, 'read first');
  const c = await call('POST', '/targets/:id/certificate', { role: 'admin', params: { id: 'dc01' } });
  assert.equal(c.body.fingerprint, '11:22:33'); assert.equal(exec.calls.find((x) => x.op === 'certificate').password, undefined);
  assert.equal((await call('POST', '/targets/:id/certificate/trust', { role: 'admin', params: { id: 'dc01' }, body: { fingerprint: 'XX' } })).status, 409);
  assert.equal((await call('POST', '/targets/:id/certificate/trust', { role: 'admin', params: { id: 'dc01' }, body: { fingerprint: '11:22:33' } })).status, 200);
  r = await call('POST', '/targets/:id/check', { role: 'operator', params: { id: 'dc01' }, body: { check: 'system_info' } });
  assert.equal(r.status, 200); const run = exec.calls.filter((x) => x.op === 'run').pop(); assert.equal(run.port, 5986); assert.equal(run.pin, '11:22:33');
  const bad = await setup(fakeExec({ fail: { ok: false, kind: 'certificate', error: 'the server presented a DIFFERENT certificate' } }));
  await bad.call('POST', '/targets', { role: 'admin', body: { id: 'xx', ip: '10.0.0.9' } }); await bad.call('PUT', '/profiles/:id', { role: 'admin', params: { id: 'windows' }, body: { username: 'u@c.local', password: 'p-123456' } });
  r = await bad.call('POST', '/targets/:id/check', { role: 'operator', params: { id: 'xx' }, body: { check: 'disks' } }); assert.equal(r.status, 409); assert.match(r.error, /DIFFERENT/);
});

test('health findings: Windows and Exchange thresholds, unreachable servers are findings, org checks once', async () => {
  const t = { id: 'exch01', name: 'EXCH01', site: 'HQ', roles: ['windows', 'exchange'] };
  const results = Object.fromEntries(Object.entries(DATA).map(([k, v]) => [k, { at: Date.now(), data: v }]));
  const F = evaluate(t, { results });
  const kinds = F.map((f) => f.kind + ':' + f.severity);
  for (const k of ['disk:critical', 'service:medium', 'events:high', 'patch:medium', 'reboot:low', 'memory:medium', 'certificate:high', 'ex-service:high', 'ex-certificate:high', 'ex-queue:high', 'ex-database:critical', 'ex-backup:medium', 'ex-copy:high', 'ex-index:low']) assert.ok(kinds.includes(k), 'missing ' + k + ' in ' + kinds.join(','));
  assert.ok(!kinds.some((k) => k.startsWith('disk') && F.find((f) => f.kind === 'disk' && /D:/.test(f.title))), 'healthy D: is not a finding');
  const un = evaluate(t, { results: { disks: { at: Date.now(), error: 'login refused', kind: 'auth' } } });
  assert.equal(un[0].kind, 'cannot-check'); assert.match(un[0].recommendation, /Remote Management Users/);
  // poll: org-wide Exchange checks run on one Exchange server only
  const exec = fakeExec(); const { S, call } = await setup(exec);
  for (const [id, ip] of [['exch01', '10.0.1.20'], ['exch02', '10.0.1.21']]) await call('POST', '/targets', { role: 'admin', body: { id, ip, roles: ['exchange'] } });
  await call('PUT', '/profiles/:id', { role: 'admin', params: { id: 'windows' }, body: { username: 'svc@c.local', password: 'Pw-123456' } });
  await call('PUT', '/profiles/:id', { role: 'admin', params: { id: 'exchange' }, body: { username: 'exmon@c.local', password: 'Pw-123456' } });
  await S.health.pollAll();
  const runs = exec.calls.filter((c) => c.op === 'run');
  assert.equal(runs.filter((c) => c.check === 'ex_databases').length, 1, 'org check once');
  assert.equal(runs.filter((c) => c.check === 'ex_service_health').length, 2, 'per-server check on each');
  assert.equal(runs.find((c) => c.check === 'ex_queues').username, 'exmon@c.local', 'Exchange checks use the exchange login');
  assert.equal(runs.find((c) => c.check === 'disks').username, 'svc@c.local');
  const ov = await call('GET', '/overview', { query: { role: 'exchange' } });
  assert.equal(ov.body.servers, 2); assert.ok(ov.body.by_severity.critical >= 1); assert.ok(ov.body.findings.some((f) => f.kind === 'ex-database'));
});

test('change plans: AI / user propose, author cannot approve, applied re-checks the server', async () => {
  const exec = fakeExec(); const { call } = await setup(exec);
  await call('POST', '/targets', { role: 'admin', body: { id: 'fs01', ip: '10.0.1.10' } });
  await call('PUT', '/profiles/:id', { role: 'admin', params: { id: 'windows' }, body: { username: 'svc@c.local', password: 'Pw-123456' } });
  const p = await call('POST', '/changes', { role: 'operator', user: 'eng1', body: { server: 'FS01', title: 'Clean C:', reason: 'C: 3 % free', commands: ['Dism /Online /Cleanup-Image /StartComponentCleanup'], rollback: ['none'] } });
  assert.match(p.body.id, /^SCHG-0+1$/); assert.equal(p.body.execution, 'manual — the SIEM never changes servers');
  assert.equal((await call('POST', '/changes/:id/decide', { role: 'admin', user: 'eng1', params: { id: p.body.id }, body: { decision: 'approved' } })).status, 403);
  await call('POST', '/changes/:id/decide', { role: 'admin', user: 'boss', params: { id: p.body.id }, body: { decision: 'approved' } });
  const ap = await call('POST', '/changes/:id/applied', { role: 'operator', params: { id: p.body.id }, body: { note: 'done' } });
  assert.equal(ap.body.status, 'failed-validation', 'C: is still at 3 % in the fake data'); assert.match(ap.body.validation.summary, /still open/);
});

test('AI: persona tools, read-only checks, personal checks need operator, change proposal, per-role conversations', async () => {
  let script = []; const calls = [];
  class FakeAnthropic { constructor() { this.beta = { messages: { create: async (p) => { calls.push(JSON.parse(JSON.stringify(p))); return script.shift(); } } }; this.messages = this.beta.messages; } }
  const exec = fakeExec(); const { S, call } = await setup(exec, FakeAnthropic);
  await call('POST', '/targets', { role: 'admin', body: { id: 'exch01', name: 'EXCH01', ip: '10.0.1.20', roles: ['exchange'] } });
  await call('PUT', '/profiles/:id', { role: 'admin', params: { id: 'exchange' }, body: { username: 'exmon@c.local', password: 'Pw-123456' } });
  script = [
    { stop_reason: 'tool_use', model: 'm', usage: {}, content: [{ type: 'tool_use', id: 't1', name: 'run_check', input: { server: 'EXCH01', check: 'ex_queues' } }, { type: 'tool_use', id: 't2', name: 'run_check', input: { server: 'EXCH01', check: 'ex_message_trace', params: { address: 'ceo@corp.sa' } } }, { type: 'tool_use', id: 't3', name: 'run_check', input: { server: 'EXCH01', check: 'Restart-Service' } }] },
    { stop_reason: 'tool_use', model: 'm', usage: {}, content: [{ type: 'tool_use', id: 't4', name: 'propose_change', input: { server: 'exch01', title: 'Fix DNS for outbound', reason: 'queue to gmail.com in retry: DNS query failed', commands: ['Set-TransportService EXCH01 -ExternalDNSServers 10.0.0.5'], rollback: ['Set-TransportService EXCH01 -ExternalDNSServers $null'] } }] },
    { stop_reason: 'end_turn', model: 'm', usage: {}, content: [{ type: 'text', text: 'Outbound DNS is failing on EXCH01.' }] },
  ];
  const r = await call('POST', '/ask', { role: 'analyst', user: 'alice', body: { role: 'exchange', question: 'Why is mail to Gmail stuck?' } });
  assert.equal(r.status, 200, r.error); assert.equal(r.body.answer, 'Outbound DNS is failing on EXCH01.');
  assert.match(calls[0].system, /AI Exchange Server Administrator/);
  const rc = calls[0].tools.find((t) => t.name === 'run_check'); assert.ok(rc.input_schema.properties.check.enum.includes('disks') && rc.input_schema.properties.check.enum.includes('ex_queues'));
  // an analyst's AI may read the last health results, but running a check (a WinRM session with the service login) needs an
  // operator - same rule as POST /targets/:id/check
  assert.deepEqual(r.body.steps.map((s) => [s.tool, s.ok]), [['run_check', false], ['run_check', false], ['run_check', false], ['propose_change', false]]);
  assert.match(r.body.steps[1].error, /operator role/); assert.match(r.body.steps[2].error, /must be one of/);
  assert.match(r.body.steps[3].error || '', /operator role/, 'an analyst cannot have the AI record a change plan (same rule as POST /changes)');
  assert.equal((await call('GET', '/changes', { query: { role: 'exchange' } })).body.items.length, 0);
  script = [{ stop_reason: 'tool_use', model: 'm', usage: {}, content: [{ type: 'tool_use', id: 't9', name: 'propose_change', input: { server: 'exch01', title: 'Fix DNS for outbound', reason: 'DNS query failed', commands: ['Set-TransportService EXCH01 -ExternalDNSServers 10.0.0.5'], rollback: ['Set-TransportService EXCH01 -ExternalDNSServers $null'] } }] },
    { stop_reason: 'end_turn', model: 'm', usage: {}, content: [{ type: 'text', text: 'Recorded.' }] }];
  const ro = await call('POST', '/ask', { role: 'operator', user: 'bob', body: { role: 'exchange', question: 'Fix it' } });
  assert.deepEqual(ro.body.steps.map((s) => [s.tool, s.ok]), [['propose_change', true]]);
  const ch = (await call('GET', '/changes', { query: { role: 'exchange' } })).body.items; assert.equal(ch[0].source, 'ai'); assert.match(ch[0].proposed_by, /ai-exchange-admin \(asked by bob\)/);
  assert.equal(exec.calls.filter((c) => c.op === 'run' && c.check === 'ex_message_trace').length, 0, 'personal check not run for an analyst');
  script = [{ stop_reason: 'end_turn', model: 'm', usage: {}, content: [{ type: 'text', text: 'w' }] }];
  await call('POST', '/ask', { role: 'analyst', user: 'alice', body: { role: 'windows', question: 'disk?' } });
  assert.match(calls[calls.length - 1].system, /AI Windows Server Administrator/);
  assert.ok(!calls[calls.length - 1].tools.find((t) => t.name === 'run_check').input_schema.properties.check.enum.includes('ex_queues'), 'Windows persona has no Exchange checks');
  assert.equal((await call('GET', '/conversations', { role: 'analyst', user: 'alice', query: { role: 'exchange' } })).body.items.length, 1);
  assert.equal((await call('POST', '/ask', { role: 'viewer', body: { role: 'windows', question: 'x' } })).status, 403);
  assert.equal(S.ai.status().enabled, true);
});

test('addresses: every IPv4 address a server reports is shown (second NIC), refresh is operator-only, audited, no login is said', async () => {
  const exec = fakeExec(); const { call, audits } = await setup(exec);
  await call('POST', '/targets', { role: 'admin', body: { id: 'hqmail02', ip: '30.30.30.20', roles: ['exchange'] } });
  let r = await call('GET', '/targets'); assert.equal(r.body.items[0].addresses, null, 'nothing fetched yet - never guessed');
  assert.equal((await call('POST', '/addresses/refresh', { role: 'viewer' })).status, 403);
  r = await call('POST', '/addresses/refresh', { role: 'operator' }); assert.equal(r.body.items[0].status, 'no-login');
  assert.ok(!exec.calls.some((c) => c.op === 'run'), 'nothing sent without a login');
  await call('PUT', '/profiles/:id', { role: 'admin', params: { id: 'windows' }, body: { username: 'CORP\\svc-mon', password: 'Pw-123456' } });
  r = await call('POST', '/addresses/refresh', { role: 'operator', user: 'nora.syn' });
  assert.equal(r.status, 200); assert.deepEqual(r.body.items[0].addresses, ['30.30.30.20', '10.99.0.20'], 'both NICs, no loopback / APIPA / duplicate');
  assert.deepEqual(exec.calls.filter((c) => c.op === 'run').map((c) => c.check), ['network'], 'only the read-only network check');
  const a = audits.filter((x) => x[0] === 'sysadmin.addresses.refresh'); assert.equal(a.length, 2); assert.equal(a[1][2].ok, 1); assert.equal(a[0][2].no_login, 1);
  r = await call('GET', '/targets'); assert.deepEqual(r.body.items[0].addresses.items.map((x) => x.interface), ['MAPI', 'Replication']);
  assert.ok(CHECKS.find((c) => c.id === 'network').baseline, 'the 15-minute health round reads the addresses too');
});

test('domain controllers and Hyper-V hosts: what a server is, the role checks the health poll runs, and their findings', async () => {
  const { kindsOf, createHealth } = require('../engine/sysadmin/health');
  const { createState } = require('../engine/soc/state');
  // what a server is: an administrator's setting, its installed roles, the AD / Hyper-V tools answering, then the name
  assert.deepEqual(kindsOf({ id: 'adc1', name: 'ADC1' }, {}), ['dc']);
  assert.deepEqual(kindsOf({ id: 'app1', name: 'APP-SYN-01' }, { results: { roles: { data: [{ name: 'Hyper-V' }] } } }), ['hyperv']);
  assert.deepEqual(kindsOf({ id: 'x', name: 'X', kinds: ['dc'] }, { results: { roles: { data: [{ name: 'Hyper-V' }] } } }).sort(), ['dc', 'hyperv']);
  assert.deepEqual(kindsOf({ id: 'file1', name: 'FILE-SYN' }, { results: { roles: { data: [{ name: 'File-Services' }] } } }), []);
  // the poll: baseline, the roles once, then that role's checks - and nothing of the other role
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sysadm-kinds-')); const state = await createState({ dir, log: { info() {}, warn() {}, error() {} } });
  const ran = [], T = { id: 'hv01', name: 'HV-SYN-01', roles: ['windows'] };
  const DATA = { roles: [{ name: 'Hyper-V' }], hv_vms: [{ name: 'DB-SYN', state: 'Running', oldest_checkpoint_days: 40, checkpoints: 2, integration: 'UpdateRequired' }, { name: 'APP-SYN', state: 'Paused-Critical', status: 'disk full' }],
    hv_replication: [{ vm: 'DB-SYN', state: 'Replicating', health: 'Critical', last: null, primary: 'hv-syn-01', replica: 'hv-syn-dr' }] };
  const H = createHealth({ targets: { get: () => T, list: () => [T], login: () => true }, runner: { run: async (id, check) => { ran.push(check); return { data: DATA[check] || {} }; }, status: async () => ({ available: true }) }, state, config: {}, log: { info() {}, warn() {} } });
  const snap = await H.pollServer('hv01');
  assert.deepEqual(snap.kinds, ['hyperv']); assert.ok(ran.includes('roles') && ran.includes('hv_vms') && ran.includes('hv_replication'), ran.join(','));
  assert.ok(!ran.some((c) => /^dc_/.test(c)), 'no domain-controller check on a Hyper-V host');
  const F = evaluate(T, snap), kinds = F.map((f) => f.kind);
  for (const k of ['hv-replication', 'hv-vm-state', 'hv-checkpoint', 'hv-integration']) assert.ok(kinds.includes(k), k + ' in ' + kinds.join(','));
  assert.equal(F.find((f) => f.kind === 'hv-replication').severity, 'high');
  // a domain controller: dcdiag failures, replication failing, SYSVOL in error, time from the Hyper-V host and skewed
  const D = { id: 'dc01', name: 'DC01', site: 'HQ' };
  const DF = evaluate(D, { results: {
    dc_dcdiag: { data: { available: true, failed: 1, tests: [{ target: 'DC01', result: 'failed', test: 'SysVolCheck' }, { target: 'DC01', result: 'passed', test: 'Advertising' }] } },
    dc_replication: { data: { summary: 'Source DSA          largest delta    fails/total %%   error\n DC01                  05m:12s    0 /   5    0\n DC02                  >60 days    3 /   5   60  (1722) The RPC server is unavailable.' } },
    dc_sysvol: { data: { available: true, folders: [{ folder: 'SYSVOL Share', group: 'Domain System Volume', state: 5 }] } },
    dc_time: { data: { source: 'VM IC Time Synchronization Provider', local_clock: false, offset_s: 75.2 } } } });
  const dk = DF.map((f) => f.kind + ':' + f.severity);
  for (const k of ['dc-health:high', 'dc-replication:high', 'dc-sysvol:critical', 'dc-time:medium', 'dc-time:high']) assert.ok(dk.includes(k), k + ' in ' + dk.join(','));
  assert.match(DF.find((f) => f.kind === 'dc-replication').evidence.join(' '), /DC02: 3 of 5 failed/);
  assert.ok(!dk.some((k) => k.startsWith('dc-replication') && /DC01/.test(DF.find((f) => f.kind === 'dc-replication').evidence.join(' ').replace('DC02', ''))), 'DC01 (0 failures) is not listed');
  fs.rmSync(dir, { recursive: true, force: true });
});

test('the new domain-controller and Hyper-V checks are read-only scripts: no command that changes anything', () => {
  const C = require('../engine/sysadmin/checks.json').checks.filter((c) => c.when);
  assert.ok(C.length >= 10);
  const WRITE = /\b(Set|New|Remove|Start|Stop|Restart|Move|Resize|Enable|Disable|Add|Invoke|Clear|Reset|Rename|Suspend|Resume|Install|Uninstall|Update|Export|Repair|Sync)-[A-Za-z]+|\b(repadmin \/(sync|syncall|kcc)|dcdiag \/fix|w32tm \/(resync|config)|dfsrmig \/setglobalstate|net (stop|start))\b/i;
  for (const c of C) assert.ok(!WRITE.test(c.script), c.id + ' must only read: ' + (c.script.match(WRITE) || [])[0]);
});

test('AI: the agent snapshot gives the domain posture as counts - the privileged account names never reach the model; DCs and Hyper-V are in its brief', async () => {
  let script = []; const calls = [];
  class FakeAnthropic { constructor() { this.beta = { messages: { create: async (p) => { calls.push(JSON.parse(JSON.stringify(p))); return script.shift(); } } }; this.messages = this.beta.messages; } }
  const dir = tmp(), state = await createState({ dir: path.join(dir, 'state') }), config = {};
  Object.defineProperty(config, 'secrets', { value: { netops: { anthropic_api_key: 'sk-test' } }, enumerable: false, writable: true });
  const hardening = { list: () => [{ host: 'dc-syn-01', at: '2026-11-28T06:00:00Z', agent_version: '1.4.0', settings: { os: { caption: 'Windows Server 2022', domain_role: 5 },
    ad: { domain: 'corp.syn.test', domain_mode: 'Windows2016Domain', krbtgt_age_days: 1500, recycle_bin: false, pwd: { min_length: 8, lockout_threshold: 0 },
      groups: { domain_admins: { count: 9, names: ['adm.secret.syn', 'adm.other.syn'] } }, accounts: { pwd_never_expires: { count: 37, names: ['svc.backup.syn'] } } } } }] };
  const S = routes.createSysadmin({ state, config, log: { info() {}, warn() {}, error() {} }, sysadminExec: fakeExec(), anthropicSdk: FakeAnthropic, hardening });
  script = [{ stop_reason: 'tool_use', model: 'm', usage: {}, content: [{ type: 'tool_use', id: 'a1', name: 'agent_snapshot', input: { host: 'DC-SYN-01' } }] },
    { stop_reason: 'end_turn', model: 'm', usage: {}, content: [{ type: 'text', text: 'krbtgt is 1500 days old; 9 domain admins.' }] }];
  const r = await S.ai.ask({ role: 'windows', question: 'How healthy is our domain?', user: 'alice', userRole: 'analyst' });
  assert.match(JSON.stringify(r), /krbtgt is 1500 days old/);
  assert.ok(calls[0].tools.some((t) => t.name === 'agent_snapshot'), 'the tool is offered to the Windows administrator');
  assert.match(calls[0].system, /DOMAIN CONTROLLERS/); assert.match(calls[0].system, /HYPER-V HOSTS/);
  const sent = JSON.stringify(calls[1].messages);
  assert.match(sent, /krbtgt_age_days/); assert.match(sent, /domain_admins[^0-9]+9/);
  assert.ok(!/adm\.secret\.syn|adm\.other\.syn|svc\.backup\.syn/.test(sent), 'no account name is sent to the model');
  fs.rmSync(dir, { recursive: true, force: true });
});
