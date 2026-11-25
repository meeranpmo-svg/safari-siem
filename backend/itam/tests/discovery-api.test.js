// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const ZYB_ORG = require('../engine/brand');
// Asset Discovery end to end through the HTTP API (proxy secret + identity headers, like nginx): role matrix, write-only
// vault that never reaches logs/audit/API, the SAFETY GATE, a full sweep with fake ping/TCP/ARP + an in-process SNMP
// agent, review (approve / ignore / merge with de-dup), SIEM connect against a fake onboarding API, silent-source
// findings, rogue alerts + bridge, cancel, scheduler, hash-chained audit with user names. Loopback only.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const snmpClient = require('../engine/discovery/snmp-client');
const { startApp } = require('./helpers');
const { startFakeSnmpAgent, deviceMib, startHttpFake, fakeExec, fakeConnect } = require('./helpers/discovery-fakes');

const ADM = { user: 'adm.sara', role: 'admin' };
const OPR = { user: 'op.one', role: 'operator' };
const VIEW = { user: 'view.only', role: 'viewer' };
const COMMUNITY = 'S3cret-Community-XYZ-77';
const SIEM_SECRET = 'synthetic-siem-proxy-secret-0123456789';
const ARP = [
  'IP address       HW type     Flags       HW address            Mask     Device',
  '10.20.0.1        0x1         0x2         00:09:0f:aa:bb:01     *        ens160',
  '10.20.0.2        0x1         0x2         f8:b1:56:aa:00:02     *        ens160',
  '10.20.0.5        0x1         0x2         02:11:22:33:44:55     *        ens160',
  '10.99.0.1        0x1         0x2         02:99:99:99:99:99     *        ens192',
].join('\n');
const FW_MIB = () => deviceMib({
  descr: 'SYNTHETIC FortiGate-100F v7.2.8,build1234', objectId: '1.3.6.1.4.1.12356.101.1.1004', name: 'test-fw-01', location: 'Riyadh HQ DC',
  macs: ['00:09:0f:aa:bb:01'], entity: [{ cls: 3, serial: 'FGTEST0001', model: 'FortiGate-100F' }],
  lldp: [{ localPort: 1, localPortName: 'port1', chassisMac: '00:00:0c:11:22:33', portDesc: 'Gi1/0/48', sysName: 'test-sw-01' }],
  arp: [{ ifIndex: 4, ip: '10.30.5.20', mac: '3c:52:82:aa:bb:cc' }, { ifIndex: 4, ip: '10.30.5.99', mac: '3c:52:82:00:00:99' }, { ifIndex: 1, ip: '10.20.0.2', mac: 'f8:b1:56:aa:00:02' }],
});

function timeoutSession() {
  const no = () => Promise.reject(Object.assign(new Error('no response'), { code: 'timeout' }));
  return { get: no, walk: no, table: no, getNext: no, close() {} };
}

async function setup(o = {}) {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'sentra-itam-disc-'));
  const agent = await startFakeSnmpAgent({ rows: FW_MIB(), communities: [COMMUNITY] });
  const siem = { sources: new Map(), ingest: [], rows: {} };
  const siemFake = await startHttpFake((r) => {
    if (r.url === '/ingest/itam-bridge') { if (r.headers['x-sentra-token'] !== 'synthetic-bridge-token') return { status: 401, body: {} }; siem.ingest.push(...r.body.trim().split('\n').map((l) => JSON.parse(l))); return { body: { ok: true } }; }
    if (r.headers['x-sentra-proxy-secret'] !== SIEM_SECRET) return { status: 401, body: { error: 'missing or invalid proxy credentials' } };
    if (r.method === 'POST' && r.url === '/api/soc/onboard/sources') {
      if (r.headers['x-auth-role'] !== 'admin') return { status: 403, body: { error: 'admin' } };
      const b = JSON.parse(r.body);
      if (siem.sources.has(b.id)) return { status: 409, body: { error: 'duplicate' } };
      siem.sources.set(b.id, Object.assign({ by: r.headers['x-auth-user'] }, b));
      return { body: { source: { id: b.id, kind: b.kind, site: b.site, match: { ip: b.match_ip } }, token: b.kind === 'windows' ? 'tok-once-123' : null, instructions: [{ title: 'SYNTHETIC step', lang: 'text', body: `send syslog to ${ZYB_ORG.platform_addr}:5514 from ${b.match_ip}` }], steps: ['SYNTHETIC: enable syslog'], network: { port: 5514 } } };
    }
    if (r.method === 'GET' && r.url === '/api/soc/onboard/sources') return { body: { sources: [...siem.sources.values()].map((s) => Object.assign({ state: 'waiting', last_seen: null }, s, siem.rows[s.id] || {})) } };
    return null;
  });
  fs.writeFileSync(path.join(tmp, 'siem-proxy-secret'), JSON.stringify({ proxy_secret: SIEM_SECRET }));
  fs.writeFileSync(path.join(tmp, 'bridge-token'), 'synthetic-bridge-token\n');
  const exec = fakeExec({ alive: ['10.20.0.1', '10.20.0.2'] });
  const connect = fakeConnect({ open: { '10.20.0.1': [443], '10.20.0.2': [135, 445, 3389] } });
  const sessions = [];
  const deps = Object.assign({
    exec, connect, readFile: () => ARP,
    createSession: (opts) => { sessions.push({ host: opts.host, version: opts.version }); if (o.sessionHook) o.sessionHook(opts); return opts.host === '10.20.0.1' ? snmpClient.createSession(Object.assign({}, opts, { host: '127.0.0.1', port: agent.port, timeout: 800 })) : timeoutSession(); },
  }, o.deps || {});
  const h = await startApp({ noAi: true, discoveryDeps: deps, config: { discovery: { siem: { base_url: siemFake.url, secret_file: path.join(tmp, 'siem-proxy-secret'), bridge: { enabled: !!o.bridge, url: `${siemFake.url}/ingest/itam-bridge`, token_file: path.join(tmp, 'bridge-token') } } } } });
  const as = (who) => (method, p, body) => h.req(method, p, Object.assign({}, who, body === undefined ? {} : { body }));
  const env = { h, agent, siem, siemFake, exec, connect, sessions, adm: as(ADM), op: as(OPR), view: as(VIEW) };
  env.close = async () => { await h.close(); await agent.close(); await siemFake.close(); };
  env.waitRun = async (id) => h.app.discovery.wait(id);
  env.makeCred = async () => (await env.adm('POST', '/discovery/credentials', { kind: 'snmp_v2c', label: 'HQ read-only community', secret: { community: COMMUNITY } })).json.credential;
  env.makeScope = async (credId, extra) => (await env.adm('POST', '/discovery/scopes', Object.assign({ name: 'HQ server VLAN', site: 'Riyadh HQ', vlan: 120, targets: ['10.20.0.0/29'], exclusions: ['10.20.0.6'], rate: { max_hosts_per_sec: 200, concurrency: 8 }, methods: { sweep: { enabled: true }, snmp: { enabled: true, credential_ids: [credId] }, arp: { enabled: true } } }, extra || {}))).json.scope;
  env.checklist = (id) => env.adm('POST', `/discovery/scopes/${id}/checklist`, { firewall: { snmp_161: true, ssh_22: true, winrm_5985_5986: true, icmp: true }, soc_notified_name: 'SOC duty lead (test)', soc_notified_date: '2026-10-06', approved_by: 'IT Infrastructure Manager (test)' });
  env.run = async (scopeId) => { const r = await env.adm('POST', `/discovery/scopes/${scopeId}/run`, {}); assert.equal(r.status, 200, r.text); return env.waitRun(r.json.run.id); };
  return env;
}

test('role matrix: every discovery write and credential metadata is admin-only; results readable by all', async (t) => {
  const e = await setup();
  t.after(() => e.close());
  const writes = [
    ['POST', '/discovery/methods', { rogue_min_sightings: 2 }], ['POST', '/discovery/scopes', {}], ['POST', '/discovery/scopes/sc_x', {}],
    ['POST', '/discovery/scopes/sc_x/disable', {}], ['POST', '/discovery/scopes/sc_x/archive', {}], ['POST', '/discovery/scopes/sc_x/checklist', {}],
    ['POST', '/discovery/scopes/sc_x/checklist/revoke', {}], ['POST', '/discovery/scopes/sc_x/run', {}], ['POST', '/discovery/runs/dr_x/cancel', {}],
    ['POST', '/discovery/credentials', {}], ['POST', '/discovery/credentials/cr_x', {}], ['POST', '/discovery/credentials/cr_x/delete', {}],
    ['POST', '/discovery/credentials/cr_x/test', {}], ['POST', '/discovery/results/dd_x/approve', {}], ['POST', '/discovery/results/dd_x/ignore', {}],
    ['POST', '/discovery/results/dd_x/restore', {}], ['POST', '/discovery/results/dd_x/merge', {}], ['POST', '/discovery/hyperv/import', {}],
    ['POST', '/discovery/connect', {}], ['POST', '/discovery/connect/health', {}],
    ['GET', '/discovery/credentials'], ['GET', '/discovery/credentials/cr_x'], ['GET', '/discovery/audit'],
  ];
  for (const [m, p, b] of writes) {
    for (const who of [e.op, e.view]) { const r = await who(m, p, b); assert.equal(r.status, 403, `${m} ${p} → ${r.status}`); }
    const r = await e.adm(m, p, b);
    assert.notEqual(r.status, 403, `admin ${m} ${p}`);
  }
  for (const p of ['/discovery/dashboard', '/discovery/methods', '/discovery/scopes', '/discovery/runs', '/discovery/results', '/discovery/connect']) {
    assert.equal((await e.view('GET', p)).status, 200, p);
    assert.equal((await e.op('GET', p)).status, 200, p);
  }
  assert.equal((await e.h.req('GET', '/discovery/dashboard', { user: '', role: '' })).status, 401);
  assert.equal((await e.h.req('GET', '/discovery/dashboard', { secret: 'wrong-secret-xxxxxxxxxxxx' })).status, 401);
});

test('vault: write-only (set / fingerprint / last-tested only), ciphertext at rest, never in logs, audit or API', async (t) => {
  const e = await setup({ sessionHook: (opts) => { /* a careless library logging its options must still be scrubbed */ if (opts.community) e2.h.app.log.error(`snmp session to ${opts.host} with community ${opts.community}`, { community: opts.community, note: `c=${opts.community}` }); } });
  const e2 = e;
  t.after(() => e.close());
  const created = await e.adm('POST', '/discovery/credentials', { kind: 'snmp_v2c', label: 'HQ read-only community', secret: { community: COMMUNITY } });
  assert.equal(created.status, 200, created.text);
  const c = created.json.credential;
  assert.deepEqual(Object.keys(c).sort(), ['created_at', 'created_by', 'fingerprint', 'future', 'id', 'kind', 'label', 'last_tested', 'set', 'target', 'updated_at', 'updated_by', 'version']);
  assert.equal(c.set, true); assert.match(c.fingerprint, /^[0-9a-f]{16}$/);
  // same secret → same fingerprint; new secret → new fingerprint and last_tested cleared
  const same = (await e.adm('POST', `/discovery/credentials/${c.id}`, { label: 'HQ RO', secret: { community: COMMUNITY } })).json.credential;
  assert.equal(same.fingerprint, c.fingerprint); assert.equal(same.version, 2);
  const v3 = await e.adm('POST', '/discovery/credentials', { kind: 'snmp_v3', label: 'v3 user', target: { auth_protocol: 'sha256', priv_protocol: 'aes' }, secret: { user: 'itam-disc', auth_password: 'Synthetic-Auth-9999', priv_password: 'Synthetic-Priv-9999' } });
  assert.equal(v3.status, 200, v3.text);
  assert.equal((await e.adm('POST', '/discovery/credentials', { kind: 'snmp_v3', label: 'short', secret: { user: 'u', auth_password: 'short' } })).status, 400);
  assert.equal((await e.adm('POST', '/discovery/credentials', { kind: 'telnet', label: 'x', secret: {} })).status, 400);
  const ssh = (await e.adm('POST', '/discovery/credentials', { kind: 'winrm', label: 'future winrm', secret: { username: 'svc', password: 'Synthetic-Ssh-1' } })).json.credential;
  assert.equal(ssh.future, true);
  // an SSH login is now used by the scan (read-only commands); testing it needs a host inside a gate-open scope
  const sshc = (await e.adm('POST', '/discovery/credentials', { kind: 'ssh', label: 'unix ro', secret: { username: 'svc', password: 'Synthetic-Ssh-1' } })).json.credential;
  assert.equal(sshc.future, false);
  assert.equal((await e.adm('POST', `/discovery/credentials/${sshc.id}/test`, {})).status, 400, 'host required');
  assert.equal((await e.adm('POST', '/discovery/credentials', { kind: 'db_login', label: 'x', secret: { username: 'u', password: 'p' } })).status, 400, 'engine required');
  assert.equal((await e.adm('POST', '/discovery/credentials', { kind: 'db_login', label: 'ora', target: { engine: 'oracle', service: 'PROD; drop' }, secret: { username: 'u', password: 'p' } })).status, 400, 'service name validated');
  const nsup = (await e.adm('POST', `/discovery/credentials/${ssh.id}/test`, {})).json.result;
  assert.equal(nsup.ok, false); assert.equal(nsup.latency_ms, null); assert.equal(nsup.error_class, 'not_supported'); assert.equal(nsup.stage, 'none');
  // SNMP test must respect the safety gate
  const scope = await e.makeScope(c.id);
  assert.equal((await e.adm('POST', `/discovery/credentials/${c.id}/test`, { host: '10.20.0.1' })).status, 409);
  await e.checklist(scope.id);
  const tst = (await e.adm('POST', `/discovery/credentials/${c.id}/test`, { host: '10.20.0.1' })).json.result;
  assert.equal(tst.ok, true); assert.equal(typeof tst.latency_ms, 'number');
  assert.deepEqual(Object.keys(tst).sort(), ['discovered', 'error_class', 'hint', 'http', 'latency_ms', 'message', 'ok', 'stage', 'tls']);
  assert.equal(tst.stage, 'read'); assert.equal(tst.tls.trusted, true); assert.equal(tst.error_class, null);
  assert.equal((await e.adm('GET', `/discovery/credentials/${c.id}`)).json.credential.last_tested.ok, true);
  // a scan that opens the credential (the session hook logs the community — it must come out scrubbed)
  await e.run(scope.id);
  // deletion refused while a scope uses it
  assert.equal((await e.adm('POST', `/discovery/credentials/${c.id}/delete`, {})).status, 409);
  // everything the platform exposes or stores in clear
  const surfaces = [
    JSON.stringify(e.h.logs),
    (await e.adm('GET', '/discovery/credentials')).text, (await e.adm('GET', '/discovery/scopes')).text, (await e.adm('GET', '/discovery/runs')).text,
    (await e.adm('GET', '/discovery/results')).text, (await e.adm('GET', '/discovery/dashboard')).text,
    (await e.adm('GET', '/audit?limit=2000')).text, (await e.adm('GET', '/discovery/audit?limit=2000')).text,
  ];
  for (const s of surfaces) for (const secret of [COMMUNITY, 'Synthetic-Auth-9999', 'Synthetic-Priv-9999', 'Synthetic-Ssh-1']) assert.ok(!s.includes(secret), `secret leaked: ${s.slice(0, 200)}`);
  assert.ok(JSON.stringify(e.h.logs).includes('[redacted]'), 'the careless log line was redacted, not dropped');
  // at rest: the state journals hold only ciphertext; the key file is separate
  const stateDir = path.join(e.h.dir, 'state');
  for (const f of fs.readdirSync(stateDir)) { const txt = fs.readFileSync(path.join(stateDir, f), 'utf8'); assert.ok(!txt.includes(COMMUNITY) && !txt.includes('Synthetic-Auth-9999'), `plaintext in ${f}`); }
  assert.match(fs.readFileSync(path.join(e.h.dir, 'discovery-vault.key'), 'utf8').trim(), /^[0-9a-f]{64}$/);
  // delete after detaching from the scope
  await e.adm('POST', `/discovery/scopes/${scope.id}`, { methods: { snmp: { enabled: false, credential_ids: [] } } });
  assert.equal((await e.adm('POST', `/discovery/credentials/${c.id}/delete`, {})).status, 200);
  const acts = (await e.adm('GET', '/discovery/audit?limit=500')).json.audit.map((a) => `${a.action}:${a.by}`);
  for (const a of ['discovery.credential.create', 'discovery.credential.update', 'discovery.credential.test', 'discovery.credential.delete']) assert.ok(acts.includes(`${a}:adm.sara`), a);
});

test('BULK review: approve N new results in one call (deduped), one audit summary, idempotent skip, filter + role gate', async (t) => {
  const e = await setup();
  t.after(() => e.close());
  const D = e.h.app.discovery;
  // an existing asset the discovered device must merge into (MAC de-dup), not duplicate
  await e.adm('POST', '/assets', { name: 'TEST-SRV-EXIST', type: 'server', mac: '02:aa:00:00:00:09' });
  const assetsBefore = e.h.app.assets.all().filter((a) => a.status !== 'disposed').length;
  for (let i = 0; i < 5; i++) D.devices.observe({ method: 'arp', ip: `10.20.0.${20 + i}`, mac: `02:aa:00:00:00:0${i}`, hostname: `TEST-BULK-${i}`, type: 'server' }, { scope_id: 'sc_bulk', site: 'Riyadh HQ' });
  D.devices.observe({ method: 'arp', ip: '10.20.0.40', mac: '02:aa:00:00:00:09', hostname: 'TEST-BULK-DUP' }, { scope_id: 'sc_bulk', site: 'Riyadh HQ' });
  // all 6 are "new"
  const newIds = D.devices.list((d) => d.status === 'new').map((d) => d.id);
  assert.ok(newIds.length >= 6);
  // non-admin is refused
  assert.equal((await e.view('POST', '/discovery/results/bulk', { action: 'approve', filter: { status: 'new' } })).status, 403);
  assert.equal((await e.op('POST', '/discovery/results/bulk', { action: 'approve', filter: { status: 'new' } })).status, 403);
  // bulk approve by filter (site)
  const r = (await e.adm('POST', '/discovery/results/bulk', { action: 'approve', filter: { status: 'new', site: 'Riyadh HQ' } })).json;
  assert.equal(r.action, 'approve');
  assert.equal(r.approved, newIds.length); assert.equal(r.ignored, 0); assert.equal(r.skipped, 0); assert.deepEqual(r.errors, []);
  // every matching device is now approved
  assert.equal(D.devices.list((d) => d.status === 'new').length, 0);
  // the MAC duplicate merged into the existing asset — only the 5 distinct ones created new assets
  const assetsAfter = e.h.app.assets.all().filter((a) => a.status !== 'disposed').length;
  assert.equal(assetsAfter - assetsBefore, 5, 'MAC-matched device merged, not duplicated');
  // exactly ONE bulk summary audit line, with the count
  const audit = (await e.adm('GET', '/discovery/audit?limit=500')).json.audit;
  const summaries = audit.filter((a) => a.action === 'discovery.bulk.approve');
  assert.equal(summaries.length, 1);
  assert.equal(summaries[0].detail.approved, newIds.length); assert.equal(summaries[0].by, 'adm.sara');
  // per-item approve audit lines were written too
  assert.ok(audit.filter((a) => a.action === 'discovery.approve').length >= newIds.length);
  // idempotent: re-approving already-decided ids skips them, approves only the still-new one
  D.devices.observe({ method: 'arp', ip: '10.20.0.50', mac: '02:bb:00:00:00:01', hostname: 'TEST-BULK-LATE', type: 'server' }, { scope_id: 'sc_bulk', site: 'Riyadh HQ' });
  const lateId = D.devices.list((d) => d.status === 'new')[0].id;
  const mixed = (await e.adm('POST', '/discovery/results/bulk', { action: 'approve', ids: [newIds[0], newIds[1], lateId] })).json;
  assert.equal(mixed.approved, 1); assert.equal(mixed.skipped, 2);
  // bulk ignore needs a reason; then it ignores the remaining new ones
  assert.equal((await e.adm('POST', '/discovery/results/bulk', { action: 'ignore', filter: { status: 'new' }, reason: 'xy' })).status, 400);
  // (nothing new left to ignore after approvals, so a reasoned call just reports zero)
  const ig = (await e.adm('POST', '/discovery/results/bulk', { action: 'ignore', filter: { status: 'new' }, reason: 'synthetic bulk ignore reason' })).json;
  assert.equal(ig.ignored, 0); assert.equal(ig.action, 'ignore');
  // bad action rejected
  assert.equal((await e.adm('POST', '/discovery/results/bulk', { action: 'delete' })).status, 400);
});

test('SIEM log-coverage: assets matched by ip/host/mac → covered/silent/absent; gap finding; SIEM down → unknown', async (t) => {
  const e = await setup();
  t.after(() => e.close());
  const now = Date.now();
  // four assets: ip-match (receiving), host-match (silent/stale), mac-match (receiving), and a server with NO source
  const byIp = (await e.adm('POST', '/assets', { name: 'TEST-COV-IP', type: 'server', mgmt_ip: '10.70.0.10' })).json.asset;
  const byHost = (await e.adm('POST', '/assets', { name: 'TEST-COV-HOST', type: 'workstation' })).json.asset;
  const byMac = (await e.adm('POST', '/assets', { name: 'TEST-COV-MAC', type: 'server', mac: '02:cc:00:00:00:10' })).json.asset;
  const gap = (await e.adm('POST', '/assets', { name: 'TEST-COV-GAP', type: 'server', mgmt_ip: '10.70.0.99' })).json.asset;
  // synthetic SIEM sources carrying match fields (the fake now surfaces them)
  e.siem.sources.set('itam-ip', { id: 'itam-ip', kind: 'linux', match_ip: '10.70.0.10' });
  e.siem.sources.set('itam-host', { id: 'itam-host', kind: 'windows', host: 'test-cov-host' });
  e.siem.sources.set('itam-mac', { id: 'itam-mac', kind: 'linux', mac: '02:cc:00:00:00:10' });
  e.siem.rows['itam-ip'] = { state: 'receiving', last_seen: now };
  e.siem.rows['itam-host'] = { state: 'silent', last_seen: now - 6 * 3600 * 1000 }; // hours old → silent
  e.siem.rows['itam-mac'] = { state: 'receiving', last_seen: now };

  const cov = (await e.adm('GET', '/discovery/log-coverage')).json;
  assert.equal(cov.siem_reachable, true);
  const by = {}; cov.assets.forEach((p) => { by[p.asset_id] = p; });
  assert.equal(by[byIp.id].status, 'covered'); assert.equal(by[byIp.id].matched_by, 'ip');
  assert.equal(by[byHost.id].status, 'silent'); assert.equal(by[byHost.id].matched_by, 'hostname');
  assert.equal(by[byMac.id].status, 'covered'); assert.equal(by[byMac.id].matched_by, 'mac');
  assert.equal(by[gap.id].status, 'absent');
  assert.equal(cov.summary.total, cov.assets.length);
  assert.ok(cov.summary.covered >= 2 && cov.summary.silent >= 1 && cov.summary.absent >= 1);
  // a discovered SERVER with no logs is surfaced as a finding (after the cache is warm)
  const finds = e.h.app.findings ? e.h.app.findings.list().filter((f) => f.kind === 'log_coverage_gap') : [];
  assert.ok(finds.some((f) => f.asset_id === gap.id), 'absent server raised a log_coverage_gap finding');
  // viewer may read coverage (same as the results page)
  assert.equal((await e.view('GET', '/discovery/log-coverage')).status, 200);
  // SIEM unreachable → everything 'unknown', no crash
  await e.siemFake.close();
  const down = (await e.adm('GET', '/discovery/log-coverage')).json;
  assert.equal(down.siem_reachable, false);
  assert.ok(down.assets.every((p) => p.status === 'unknown'));
});

test('SAFETY GATE + sweep + SNMP + review + SIEM connect + health + rogue + bridge', async (t) => {
  const e = await setup({ bridge: true });
  t.after(() => e.close());
  const cred = await e.makeCred();
  assert.equal((await e.adm('POST', '/discovery/methods', { rogue_min_sightings: 2 })).json.settings.rogue_min_sightings, 2);
  const scope = await e.makeScope(cred.id);
  assert.equal(scope.gate.open, false); assert.equal(scope.gate.required, true);
  assert.deepEqual(scope.blocked_methods.map((b) => b.method).sort(), ['snmp', 'sweep']);
  assert.equal((await e.view('GET', '/discovery/dashboard')).json.scopes.gate_pending.length, 1);

  // run 1: gate closed → passive ARP only; no ping process, no TCP connect, no SNMP packet
  const r1 = await e.run(scope.id);
  assert.equal(r1.status, 'finished');
  assert.deepEqual(r1.methods_run, ['arp']);
  assert.deepEqual(r1.methods_blocked.map((b) => b.method).sort(), ['snmp', 'sweep']);
  assert.equal(e.exec.calls.length, 0); assert.equal(e.connect.calls.length, 0); assert.equal(e.sessions.length, 0);
  assert.equal(r1.devices_seen, 3, 'ARP rows inside the scope only (10.99.0.1 is outside)');

  // checklist completed (audited with the admin's name) → gate open
  const cl = await e.checklist(scope.id);
  assert.equal(cl.status, 200, cl.text);
  assert.equal(cl.json.scope.gate.open, true);
  assert.equal(cl.json.scope.checklist.completed_by, 'adm.sara');

  // run 2: active methods run under the scope limits; exclusions honoured
  const r2 = await e.run(scope.id);
  assert.equal(r2.status, 'finished', JSON.stringify(r2));
  assert.deepEqual(r2.methods_run.sort(), ['arp', 'snmp', 'sweep']);
  const pinged = e.exec.calls.flatMap((c) => c.args.filter((a) => /^10\./.test(a)));
  assert.deepEqual(pinged, ['10.20.0.1', '10.20.0.2', '10.20.0.3', '10.20.0.4', '10.20.0.5'], 'network/broadcast and the excluded .6 never probed');
  assert.ok(!e.connect.calls.some(([ip]) => ip === '10.20.0.6'));
  assert.ok(e.agent.seen.length > 0 && e.agent.seen.every((tag) => [0xa0, 0xa1, 0xa5].includes(tag)), 'SNMP read-only');
  const res = (await e.view('GET', '/discovery/results')).json;
  assert.equal(res.total, 3);
  const by = Object.fromEntries(res.devices.map((d) => [d.ip, d]));
  assert.deepEqual([by['10.20.0.1'].type, by['10.20.0.1'].vendor, by['10.20.0.1'].hostname, by['10.20.0.1'].serial, by['10.20.0.1'].location], ['firewall', 'Fortinet', 'test-fw-01', 'FGTEST0001', 'Riyadh HQ DC']);
  assert.deepEqual(by['10.20.0.1'].methods_seen.sort(), ['arp', 'snmp', 'sweep']);
  assert.equal(by['10.20.0.1'].neighbours[0].remote_name, 'test-sw-01');
  assert.equal(by['10.20.0.2'].type, 'workstation'); assert.deepEqual(by['10.20.0.2'].open_ports, [135, 445, 3389]); assert.equal(by['10.20.0.2'].vendor, 'Dell');
  assert.deepEqual([by['10.20.0.5'].type, by['10.20.0.5'].methods_seen], ['unknown', ['arp']]);
  assert.ok(res.devices.every((d) => d.site === 'Riyadh HQ' && d.vlan === 120 && d.seen_count === 2));
  // all three are unknown to the CMDB and seen twice → rogue alerts, findings, one bridge event each
  let dash = (await e.view('GET', '/discovery/dashboard')).json;
  assert.equal(dash.rogue.count, 3); assert.equal(dash.new_since_last_scan, 0); assert.equal(dash.devices.total, 3);
  assert.equal((await e.view('GET', '/ai/findings?kind=rogue_device')).json.findings.length, 3);
  assert.equal(e.siem.ingest.length, 3);
  assert.deepEqual(Object.keys(e.siem.ingest[0]).slice(0, 3), ['source', 'kind', 'at']);
  assert.deepEqual([e.siem.ingest[0].source, e.siem.ingest[0].kind], ['itam', 'rogue-device']);

  // approve the firewall → ITAM asset (network) with discovery stamp
  const ap = await e.adm('POST', `/discovery/results/${by['10.20.0.1'].id}/approve`, {});
  assert.equal(ap.status, 200, ap.text);
  assert.equal(ap.json.merged_into_existing, false);
  const fwAsset = (await e.view('GET', `/assets/${ap.json.asset_id}`)).json.asset;
  assert.deepEqual([fwAsset.type, fwAsset.vendor, fwAsset.serial, fwAsset.mgmt_ip, fwAsset.site], ['network', 'Fortinet', 'FGTEST0001', '10.20.0.1', 'Riyadh HQ']);
  assert.ok(fwAsset.tags.includes('disc:firewall'));
  assert.deepEqual(fwAsset.discovery.class, 'firewall');
  assert.equal((await e.adm('POST', `/discovery/results/${by['10.20.0.1'].id}/approve`, {})).status, 409, 'no double approval');

  // merge: an operator-entered asset with the same MAC is a strong duplicate → admin merges (no new asset)
  const pc = (await e.op('POST', '/assets', { name: 'TEST-PC-02', type: 'workstation', mac: 'F8-B1-56-AA-00-02', owner: 'Finance' })).json.asset;
  const det = (await e.view('GET', `/discovery/results/${by['10.20.0.2'].id}`)).json.device;
  assert.deepEqual(det.duplicates.map((d) => [d.asset_id, d.by, d.strength]), [[pc.id, ['mac'], 'strong']]);
  assert.equal(det.in_cmdb, true);
  const before = (await e.view('GET', '/assets')).json.total;
  const mg = await e.adm('POST', `/discovery/results/${by['10.20.0.2'].id}/merge`, { asset_id: pc.id });
  assert.equal(mg.status, 200, mg.text);
  assert.equal((await e.view('GET', '/assets')).json.total, before);
  const pcAfter = (await e.view('GET', `/assets/${pc.id}`)).json;
  assert.equal(pcAfter.asset.owner, 'Finance', 'human business data kept'); assert.equal(pcAfter.asset.mgmt_ip, '10.20.0.2');
  assert.ok(pcAfter.seen_by.some((s) => s.source === 'discovery'));

  // ignore needs a reason; remembered across re-discovery
  assert.equal((await e.adm('POST', `/discovery/results/${by['10.20.0.5'].id}/ignore`, { reason: '' })).status, 400);
  assert.equal((await e.adm('POST', `/discovery/results/${by['10.20.0.5'].id}/ignore`, { reason: 'SYNTHETIC lab analyser, not an IT asset' })).status, 200);
  dash = (await e.view('GET', '/discovery/dashboard')).json;
  assert.equal(dash.rogue.count, 0);
  assert.equal((await e.view('GET', '/ai/findings?kind=rogue_device')).json.findings.length, 0, 'rogue findings resolved by the decisions');
  const r3 = await e.run(scope.id);
  assert.equal(r3.status, 'finished');
  const ig = (await e.view('GET', `/discovery/results/${by['10.20.0.5'].id}`)).json.device;
  assert.deepEqual([ig.status, ig.ignore_reason, ig.seen_count], ['ignored', 'SYNTHETIC lab analyser, not an IT asset', 3]);
  assert.equal(e.siem.ingest.length, 3, 'no duplicate bridge events');

  // approving a device whose serial already exists in the CMDB de-duplicates instead of creating a second asset
  const ups = (await e.op('POST', '/assets', { name: 'TEST-UPS-01', type: 'ups', serial: 'TESTSERIAL-77', asset_tag: 'ZS-UPS-77' })).json.asset;
  e.h.app.discovery.devices.observe({ method: 'snmp', ip: '10.20.0.4', mac: '02:44:44:44:44:44', serial: 'testserial-77' }, { scope_id: scope.id, site: 'Riyadh HQ' });
  const dupe = (await e.view('GET', '/discovery/results?q=10.20.0.4')).json.devices[0];
  assert.deepEqual((await e.view('GET', `/discovery/results/${dupe.id}`)).json.device.duplicates.map((d) => [d.asset_id, d.by]), [[ups.id, ['serial']]]);
  const before2 = (await e.view('GET', '/assets')).json.total;
  const ap2 = (await e.adm('POST', `/discovery/results/${dupe.id}/approve`, {})).json;
  assert.equal(ap2.asset_id, ups.id); assert.equal(ap2.merged_into_existing, true);
  assert.equal((await e.view('GET', '/assets')).json.total, before2);
  assert.equal((await e.view('GET', `/assets/${ups.id}`)).json.asset.type, 'ups', 'the human-entered type is kept');

  // connect the firewall to the SIEM: kind from the mapping table, site mapped, token shown once, never stored
  const cands = (await e.view('GET', '/discovery/connect')).json.candidates;
  assert.deepEqual(cands.find((c) => c.asset_id === fwAsset.id).suggested_kind, 'fortigate');
  const cn = await e.adm('POST', '/discovery/connect', { asset_id: fwAsset.id });
  assert.equal(cn.status, 200, cn.text);
  assert.deepEqual([cn.json.kind, cn.json.site, cn.json.source_id], ['fortigate', 'riyadh-hq', 'itam-test-fw-01']);
  assert.deepEqual(e.siem.sources.get('itam-test-fw-01'), { by: 'adm.sara', id: 'itam-test-fw-01', kind: 'fortigate', site: 'riyadh-hq', match_ip: '10.20.0.1', label: 'test-fw-01' });
  assert.match(cn.json.instructions[0].body, /10\.20\.0\.1/);
  assert.equal((await e.adm('POST', '/discovery/connect', { asset_id: fwAsset.id })).status, 409, 'already connected');
  // a Windows workstation gets a one-time token
  const win = await e.adm('POST', '/discovery/connect', { asset_id: pc.id, kind: 'windows' });
  assert.equal(win.json.token, 'tok-once-123'); assert.equal(win.json.token_shown_once, true);
  assert.equal((await e.adm('POST', '/discovery/connect', { asset_id: ups.id, kind: 'telnet' })).status, 400);
  for (const s of [(await e.adm('GET', `/assets/${pc.id}`)).text, (await e.adm('GET', '/audit?limit=2000')).text, JSON.stringify(e.h.logs), (await e.view('GET', '/discovery/connect')).text]) assert.ok(!s.includes('tok-once-123'), 'token never stored/logged');

  // health: silent for > 60 min → ITAM finding; receiving again → resolved
  e.siem.rows['itam-test-fw-01'] = { state: 'silent', last_seen: Date.now() - 3 * 3600 * 1000 };
  e.siem.rows['itam-test-pc-02'] = { state: 'receiving', last_seen: Date.now() - 60000 };
  const hl = (await e.adm('POST', '/discovery/connect/health', {})).json.health;
  assert.deepEqual([hl.ok, hl.checked, hl.silent], [true, 2, 1]);
  const conns = (await e.view('GET', '/discovery/connect')).json.connections;
  assert.deepEqual(conns.map((c) => [c.source_id, c.state, c.alert]).sort(), [['itam-test-fw-01', 'silent', true], ['itam-test-pc-02', 'receiving', false]]);
  let silent = (await e.view('GET', '/ai/findings?kind=siem_silent')).json.findings;
  assert.equal(silent.length, 1); assert.equal(silent[0].asset_id, fwAsset.id); assert.equal(silent[0].ai_label, 'Discovery');
  e.siem.rows['itam-test-fw-01'] = { state: 'receiving', last_seen: Date.now() };
  await e.adm('POST', '/discovery/connect/health', {});
  silent = (await e.view('GET', '/ai/findings?kind=siem_silent')).json.findings;
  assert.equal(silent.length, 0);
  dash = (await e.view('GET', '/discovery/dashboard')).json;
  assert.deepEqual([dash.assets.connected, dash.assets.silent], [2, 0]);

  // scope change re-closes the gate (audited)
  const up = (await e.adm('POST', `/discovery/scopes/${scope.id}`, { targets: ['10.20.0.0/28'] })).json.scope;
  assert.deepEqual([up.gate.open, up.gate.stale], [false, true]);

  // audit: hash chain intact, every action carries the user's name
  const audit = (await e.adm('GET', '/audit?limit=2000')).json;
  assert.equal(audit.verify.ok, true);
  const acts = audit.audit.map((a) => `${a.action}:${a.by}`);
  for (const a of ['discovery.scope.create', 'discovery.scope.checklist', 'discovery.scan.start', 'discovery.scan.finish', 'discovery.approve', 'discovery.merge', 'discovery.ignore', 'discovery.connect', 'discovery.methods.update', 'discovery.scope.update']) assert.ok(acts.includes(`${a}:adm.sara`), a);
  const upd = audit.audit.find((a) => a.action === 'discovery.scope.update');
  assert.equal(upd.detail.checklist_invalidated, true);
});

test('cancel a run; scheduler starts due scopes; window blocks active methods; Hyper-V report via agent + admin', async (t) => {
  const slow = fakeConnect({});
  const e = await setup({ deps: { connect: async (ip, port) => { await new Promise((r) => setTimeout(r, 30)); return slow(ip, port); } } });
  t.after(() => e.close());
  const cred = await e.makeCred();
  const scope = await e.makeScope(cred.id, { targets: ['10.20.0.0/27'], exclusions: [], rate: { max_hosts_per_sec: 2, concurrency: 1 } });
  await e.checklist(scope.id);
  const st = (await e.adm('POST', `/discovery/scopes/${scope.id}/run`, {})).json.run;
  assert.equal((await e.adm('POST', `/discovery/scopes/${scope.id}/run`, {})).status, 409, 'one run per scope');
  const c = await e.adm('POST', `/discovery/runs/${st.id}/cancel`, {});
  assert.equal(c.status, 200);
  const done = await e.waitRun(st.id);
  assert.equal(done.status, 'cancelled'); assert.equal(done.cancelled_by, 'adm.sara');
  assert.ok(done.progress.hosts_done < done.progress.hosts_total);
  assert.equal((await e.adm('POST', `/discovery/runs/${st.id}/cancel`, {})).status, 409);

  // scheduler: a due daily scope is started by tick() (trigger "schedule"); next_run moves forward
  const sc2 = (await e.adm('POST', '/discovery/scopes', { name: 'Jeddah DR passive', site: 'Jeddah DR', targets: ['10.30.0.0/28'], schedule: { type: 'daily', time: '02:00' }, methods: { arp: { enabled: true } } })).json.scope;
  assert.ok(sc2.next_run > Date.now());
  e.h.app.store.collection('disc_scopes').patch(sc2.id, (s) => { s.next_run = Date.now() - 1000; });
  const started = e.h.app.discovery.tick();
  assert.equal(started.length, 1);
  const sr = await e.waitRun(started[0]);
  assert.deepEqual([sr.trigger, sr.status, sr.methods_run], ['schedule', 'finished', ['arp']]);
  assert.ok(e.h.app.store.collection('disc_scopes').get(sc2.id).next_run > Date.now());
  assert.deepEqual(e.h.app.discovery.tick(), [], 'not due again');

  // a scan window that is closed now blocks active methods even for a manual run
  const r = new Date(Date.now() + 3 * 3600000); const hh = (n) => String((r.getUTCHours() + n) % 24).padStart(2, '0');
  const sc3 = (await e.adm('POST', '/discovery/scopes', { name: 'Olaya night window', site: 'Riyadh Olaya', targets: ['10.40.0.0/29'], window: { start: `${hh(2)}:00`, end: `${hh(3)}:00` }, methods: { sweep: { enabled: true }, arp: { enabled: true } } })).json.scope;
  await e.checklist(sc3.id);
  const wr = await e.run(sc3.id);
  assert.deepEqual(wr.methods_run, ['arp']);
  assert.match(wr.methods_blocked[0].reason, /outside the scan window/);

  // Hyper-V: admin import into a scope with Hyper-V enabled, and the agent route with an enrolled agent key
  const hvScope = (await e.adm('POST', '/discovery/scopes', { name: 'HQ Hyper-V', site: 'Riyadh HQ', targets: ['10.20.8.0/24'], methods: { hyperv: { enabled: true } } })).json.scope;
  const report = { host: { name: 'TEST-HV01', ip: '10.20.8.10', os: 'Windows Server 2022 Datacenter' }, vms: [{ name: 'TEST-HV-VM1', vm_id: 'aaaa-1', state: 'Running', ips: ['10.20.8.21'], macs: ['00155D010203'] }] };
  const imp = await e.adm('POST', '/discovery/hyperv/import', { scope_id: hvScope.id, report });
  assert.deepEqual([imp.status, imp.json.vms], [200, 1]);
  const tok = (await e.adm('POST', '/settings/agent-tokens', {})).json.token;
  const enr = (await e.h.req('POST', '/agent/enrol', { user: '', role: '', body: { token: tok, hostname: 'TEST-HV01', platform: 'windows' } })).json;
  const ag = await e.h.req('POST', '/agent/hyperv', { user: '', role: '', bearer: enr.agent_key, body: report });
  assert.equal(ag.status, 200, ag.text); assert.equal(ag.json.scope_id, hvScope.id);
  assert.equal((await e.h.req('POST', '/agent/hyperv', { user: '', role: '', bearer: 'bogus', body: report })).status, 401);
  const vm = (await e.view('GET', '/discovery/results?q=10.20.8.21')).json.devices[0];
  assert.deepEqual([vm.type, vm.vendor, vm.methods_seen], ['vm', 'Microsoft (Hyper-V)', ['hyperv']]);
  assert.equal(vm.seen_count, 2);
  assert.equal((await e.adm('POST', '/discovery/hyperv/import', { report: Object.assign({}, report, { host: { name: 'X', ip: '10.250.0.1' } }) })).status, 409, 'no scope covers that host');
  // the hosts that reported (Integration Hub): every role reads; the last report wins; only an admin forgets a host, audited
  const hv = await e.view('GET', '/discovery/hyperv/hosts');
  assert.equal(hv.status, 200); assert.deepEqual(hv.json.hosts.map((h) => [h.host, h.vms, h.via, h.scope_id]), [['TEST-HV01', 1, 'agent', hvScope.id]]);
  assert.ok(hv.json.scopes.some((s) => s.id === hvScope.id), 'the scopes that accept Hyper-V reports are listed');
  assert.ok(!JSON.stringify(hv.json).includes(enr.agent_key), 'no agent key in the list');
  for (const who of [e.op, e.view]) assert.equal((await who('POST', '/discovery/hyperv/hosts/test-hv01/forget', {})).status, 403);
  assert.equal((await e.adm('POST', '/discovery/hyperv/hosts/no-such-host/forget', {})).status, 404);
  assert.equal((await e.adm('POST', '/discovery/hyperv/hosts/' + encodeURIComponent('bad host!') + '/forget', {})).status, 400);
  assert.equal((await e.adm('POST', '/discovery/hyperv/hosts/test-hv01/forget', {})).status, 200);
  assert.deepEqual((await e.view('GET', '/discovery/hyperv/hosts')).json.hosts, []);
  const fa = (await e.adm('GET', '/discovery/audit')).json.audit.find((a) => a.action === 'discovery.hyperv.forget');
  assert.ok(fa && fa.target === 'TEST-HV01' && fa.by, 'forgetting a host is audited with who');
});

test('passive AD + global method toggle + public-range flag through the API', async (t) => {
  const { makeCA, makeServerCert } = require('./helpers/x509');
  const { startFakeLdap, makeDirectory } = require('./helpers/fake-ldap');
  const ca = makeCA('Synthetic AD CA 2');
  const leaf = makeServerCert(ca, { cn: ('dc-hqa.' + 'corp-hq.com'), dns: [('dc-hqa.' + 'corp-hq.com')], ip: ['127.0.0.1'] });
  const dir = makeDirectory();
  const BASE = 'DC=corp-hq,DC=com'; const SVC = `CN=svc-itam-test,OU=Service Accounts,${BASE}`;
  dir.add(BASE, { objectClass: ['domain'] }); dir.add(SVC, { objectClass: ['user'], cn: 'svc-itam-test' });
  dir.add(`CN=TEST-SRV-07,OU=Servers,${BASE}`, { objectClass: ['computer'], cn: 'TEST-SRV-07', dNSHostName: ('test-srv-07.' + 'corp-hq.com'), operatingSystem: 'Windows Server 2019 Standard', userAccountControl: '4096' });
  const ldap = await startFakeLdap({ key: leaf.key, cert: leaf.cert, dir, passwords: { [SVC]: 'Synthetic-Ldap-Pass-5' } });
  const e = await setup({ deps: { ldapCa: ca.cert, resolve: async (h) => (h === ('test-srv-07.' + 'corp-hq.com') ? '10.20.0.2' : null) } });
  t.after(async () => { await e.close(); await ldap.close(); });
  const lc = (await e.adm('POST', '/discovery/credentials', { kind: 'ldap', label: 'AD read-only bind', target: { servers: [`ldaps://dc-hqa.corp-hq.com:${ldap.port}`], ip: '127.0.0.1', base_dn: BASE }, secret: { bind_dn: SVC, password: 'Synthetic-Ldap-Pass-5' } })).json.credential;
  assert.deepEqual((await e.adm('POST', `/discovery/credentials/${lc.id}/test`, {})).json.result.ok, true);
  const scope = (await e.adm('POST', '/discovery/scopes', { name: 'HQ AD', site: 'Riyadh HQ', targets: ['10.20.0.0/29'], methods: { ad: { enabled: true, credential_id: lc.id }, arp: { enabled: true } } })).json.scope;
  assert.equal(scope.gate.required, false, 'passive-only scope needs no checklist');
  const r = await e.run(scope.id);
  assert.equal(r.stats.ad.ok, true); assert.equal(r.stats.ad.seen, 1);
  const d = (await e.view('GET', '/discovery/results?q=test-srv-07')).json.devices[0];
  assert.deepEqual([d.type, d.ip, d.mac], ['server', '10.20.0.2', 'f8:b1:56:aa:00:02'], 'AD computer joined with the ARP entry through DNS inside the scope');
  assert.equal(d.extra.ad.ou, 'Servers');
  assert.equal((await e.view('GET', '/discovery/dashboard')).json.rogue.count, 0, 'AD-known device is never rogue; ARP-only ones need 3 sightings (default) first');
  // global toggle off → blocked for every scope
  await e.adm('POST', '/discovery/methods', { methods: { ad: false } });
  const r2 = await e.run(scope.id);
  assert.deepEqual(r2.methods_blocked, [{ method: 'ad', reason: 'disabled globally' }]);
  // public range only with the explicit flag
  assert.equal((await e.adm('POST', '/discovery/scopes', { name: 'DMZ', site: 'Riyadh HQ', targets: ['203.0.113.0/29'] })).status, 400);
  assert.equal((await e.adm('POST', '/discovery/scopes', { name: 'DMZ', site: 'Riyadh HQ', targets: ['203.0.113.0/29'], allow_public: true })).status, 200);
});

test('user PCs / servers outside the scanned range: AD name → IP kept (marked), MAC from the firewall ARP table over SNMP', async (t) => {
  const { makeCA, makeServerCert } = require('./helpers/x509');
  const { startFakeLdap, makeDirectory } = require('./helpers/fake-ldap');
  const ca = makeCA('Synthetic AD CA 3');
  const leaf = makeServerCert(ca, { cn: ('dc-hqa.' + 'corp-hq.com'), dns: [('dc-hqa.' + 'corp-hq.com')], ip: ['127.0.0.1'] });
  const dir = makeDirectory();
  const BASE = 'DC=corp-hq,DC=com'; const SVC = `CN=svc-itam-test,OU=Service Accounts,${BASE}`;
  dir.add(BASE, { objectClass: ['domain'] }); dir.add(SVC, { objectClass: ['user'], cn: 'svc-itam-test' });
  dir.add(`CN=TEST-PC-21,OU=Workstations,${BASE}`, { objectClass: ['computer'], cn: 'TEST-PC-21', dNSHostName: ('test-pc-21.' + 'corp-hq.com'), operatingSystem: 'Windows 11 Enterprise', userAccountControl: '4096' });
  const ldap = await startFakeLdap({ key: leaf.key, cert: leaf.cert, dir, passwords: { [SVC]: 'Synthetic-Ldap-Pass-6' } });
  const e = await setup({ deps: { ldapCa: ca.cert, resolve: async (h) => (h === ('test-pc-21.' + 'corp-hq.com') ? '10.30.5.20' : null) } });
  t.after(async () => { await e.close(); await ldap.close(); });
  const lc = (await e.adm('POST', '/discovery/credentials', { kind: 'ldap', label: 'AD', target: { servers: [`ldaps://dc-hqa.corp-hq.com:${ldap.port}`], ip: '127.0.0.1', base_dn: BASE }, secret: { bind_dn: SVC, password: 'Synthetic-Ldap-Pass-6' } })).json.credential;
  const cred = await e.makeCred();
  const scope = await e.makeScope(cred.id, { methods: { sweep: { enabled: true }, snmp: { enabled: true, credential_ids: [cred.id] }, ad: { enabled: true, credential_id: lc.id } } });
  assert.equal((await e.checklist(scope.id)).status, 200);
  const r = await e.run(scope.id);
  assert.equal(r.stats.ad.ok, true); assert.equal(r.stats.ad.resolved, 1);
  assert.equal(r.stats.arp_snmp.entries, 3); assert.equal(r.stats.arp_snmp.matched, 2, 'the AD PC (known) and 10.20.0.2 (in scope); 10.30.5.99 is neither');
  const pc = (await e.view('GET', '/discovery/results?q=test-pc-21')).json.devices[0];
  assert.deepEqual([pc.type, pc.ip, pc.mac], ['workstation', '10.30.5.20', '3c:52:82:aa:bb:cc']);
  assert.equal(pc.extra.ad.ip_outside_scope, true);
  assert.equal((await e.view('GET', '/discovery/results?q=10.30.5.99')).json.devices.length, 0, 'unknown out-of-range ARP entries are not added');
});

test('ZS-11 rogue suppression ignores agent-reported MACs and agent-key Hyper-V reports (not a system of record)', async (t) => {
  const e = await setup();
  t.after(() => e.close());
  await e.adm('POST', '/discovery/methods', { rogue_min_sightings: 1 });
  const D = e.h.app.discovery;
  // an unknown device seen by ARP
  const dev = D.devices.observe({ method: 'arp', ip: '10.20.0.5', mac: '02:11:22:33:44:55' }, {});
  assert.ok(D.rogueDevices().some((r) => r.id === dev.id), 'unknown ARP device is rogue');
  // an enrolled agent claims that MAC for its own (new) asset
  const tok = (await e.adm('POST', '/settings/agent-tokens', {})).json.token;
  const enr = (await e.h.req('POST', '/agent/enrol', { user: '', role: '', body: { token: tok, hostname: 'liar', platform: 'linux' } })).json;
  const rep = await e.h.req('POST', '/agent/report', { user: '', role: '', bearer: enr.agent_key, body: { seq: 1, ts: new Date().toISOString(), nonce: 'n1', host: { hostname: 'liar', serial: 'LIARSN1', mac: '02:11:22:33:44:55', macs: ['02:11:22:33:44:55'] }, software: [] } });
  assert.ok(rep.json.asset_id);
  assert.ok(D.rogueDevices().some((r) => r.id === dev.id), 'agent MAC claim does not suppress the rogue alert');
  // Hyper-V report pushed with an agent key is self-asserted → still rogue; the same report imported by an admin is trusted
  const hvScope = (await e.adm('POST', '/discovery/scopes', { name: 'HQ Hyper-V', site: 'Riyadh HQ', targets: ['10.20.8.0/24'], methods: { hyperv: { enabled: true } } })).json.scope;
  const report = { host: { name: 'ROGUE-HV', ip: '10.20.8.10' }, vms: [{ name: 'ROGUE-VM', vm_id: 'bbbb-1', ips: ['10.20.8.66'], macs: ['02:66:66:66:66:66'] }] };
  assert.equal((await e.h.req('POST', '/agent/hyperv', { user: '', role: '', bearer: enr.agent_key, body: report })).status, 200);
  const vm = () => D.devices.list((d) => (d.macs || []).includes('02:66:66:66:66:66'))[0];
  assert.ok(vm().methods.hyperv.untrusted);
  assert.ok(D.rogueDevices().some((r) => r.id === vm().id), 'agent-key Hyper-V sighting is not a system-of-record match');
  assert.equal((await e.adm('POST', '/discovery/hyperv/import', { scope_id: hvScope.id, report })).status, 200);
  assert.ok(!vm().methods.hyperv.untrusted, 'admin import marks it trusted');
  assert.ok(!D.rogueDevices().some((r) => r.id === vm().id), 'admin Hyper-V import suppresses');
});

test('ZS-12 vault: changing a credential target requires re-entering the secret; before/after target audited, never the secret', async (t) => {
  const e = await setup();
  t.after(() => e.close());
  const PW = 'Synthetic-VC-Passw0rd-AS12';
  const c = (await e.adm('POST', '/discovery/credentials', { kind: 'vcenter', label: 'VC', target: { base_url: 'https://vc.lab.example' }, secret: { username: 'ro@vsphere.local', password: PW } })).json.credential;
  // redirect without the secret → refused, stored target unchanged
  for (const target of [{ base_url: 'https://attacker.example' }, { ca_file: '/tmp/evil-ca.pem' }, { tls_fingerprint: 'ab'.repeat(32) }]) {
    const r = await e.adm('POST', `/discovery/credentials/${c.id}`, { target });
    assert.equal(r.status, 400, JSON.stringify(target));
    assert.match(r.json.error, /requires re-entering the secret/);
  }
  const partial = await e.adm('POST', `/discovery/credentials/${c.id}`, { target: { base_url: 'https://attacker.example' }, secret: { username: 'ro@vsphere.local' } });
  assert.equal(partial.status, 400, 'username alone is not enough');
  assert.equal((await e.adm('GET', `/discovery/credentials/${c.id}`)).json.credential.target.base_url, 'https://vc.lab.example');
  // label-only edit still keeps the stored secret
  assert.equal((await e.adm('POST', `/discovery/credentials/${c.id}`, { label: 'VC renamed' })).status, 200);
  // with the secret re-entered it is accepted and the audit shows before/after
  const ok = await e.adm('POST', `/discovery/credentials/${c.id}`, { target: { base_url: 'https://vc2.lab.example' }, secret: { username: 'ro@vsphere.local', password: 'New-Synthetic-Pw-2' } });
  assert.equal(ok.status, 200, ok.text);
  const audit = (await e.adm('GET', '/discovery/audit?limit=50')).json.audit;
  const line = audit.find((x) => x.action === 'discovery.credential.update' && x.detail.target_changed.length);
  assert.equal(line.detail.target_before.base_url, 'https://vc.lab.example');
  assert.equal(line.detail.target_after.base_url, 'https://vc2.lab.example');
  assert.deepEqual(line.detail.target_changed, ['base_url']);
  assert.ok(!JSON.stringify(audit).includes(PW) && !JSON.stringify(audit).includes('New-Synthetic-Pw-2'), 'secret never audited');
});

test('Nutanix Prism: vault kind, scope method, passive run → hosts as servers and VMs as vms, never rogue', async (t) => {
  const PW = 'Synthetic-Prism-Pw-77';
  const seen = [];
  const request = async (url, o) => {
    seen.push([o.method, url]);
    const m = /\/api\/nutanix\/v3\/(\w+)\/list$/.exec(url);
    const D = {
      hosts: { entities: [{ metadata: { uuid: 'h-1' }, status: { name: 'NTNX-RUH-A', cluster_reference: { name: 'RUH-CL1' }, resources: { num_cpu_sockets: 2, num_cpu_cores: 32, serial_number: 'NXSN01', block: { block_model: 'NX-3170-G8' }, hypervisor: { ip: '10.20.0.3', hypervisor_full_name: 'AHV 20230302' } } } }] },
      vms: { entities: [{ metadata: { uuid: 'v-1' }, status: { name: 'ERP-DB01', resources: { power_state: 'ON', host_reference: { uuid: 'h-1', name: 'NTNX-RUH-A' }, nic_list: [{ mac_address: '50:6b:8d:11:22:33', ip_endpoint_list: [{ ip: '10.20.0.4' }] }] } } }] },
      clusters: { entities: [{ metadata: { uuid: 'c1' }, status: { name: 'RUH-CL1' } }] },
    };
    return m ? { status: 200, json: D[m[1]] } : { status: 404, json: {} };
  };
  const e = await setup({ deps: { request } });
  t.after(() => e.close());
  const methods = (await e.adm('GET', '/discovery/methods')).json;
  assert.ok(methods.passive.includes('nutanix')); assert.ok(methods.credential_kinds.some((k) => k.kind === 'nutanix'));
  const c = (await e.adm('POST', '/discovery/credentials', { kind: 'nutanix', label: 'Prism Central', target: { base_url: 'https://prism.lab.example' }, secret: { username: 'svc-ro', password: PW } })).json.credential;
  assert.equal(c.kind, 'nutanix');
  const tr = (await e.adm('POST', `/discovery/credentials/${c.id}/test`, {})).json;
  assert.equal(tr.result ? tr.result.ok : tr.ok, true, JSON.stringify(tr));
  const sc = (await e.adm('POST', '/discovery/scopes', { name: 'HQ Nutanix', site: 'Riyadh HQ', targets: ['10.20.0.0/29'], methods: { nutanix: { enabled: true, credential_id: c.id } } })).json.scope;
  assert.equal(sc.gate.required, false, 'Nutanix is passive: no pre-scan checklist');
  const run = await e.run(sc.id);
  assert.equal(run.stats.nutanix.ok, true, JSON.stringify(run.stats)); assert.deepEqual([run.stats.nutanix.hosts, run.stats.nutanix.vms], [1, 1]);
  const devs = (await e.adm('GET', '/discovery/results?limit=50')).json.devices;
  const host = devs.find((d) => d.hostname === 'ntnx-ruh-a'), vm = devs.find((d) => d.hostname === 'erp-db01');
  assert.deepEqual([host.type, host.vendor, host.serial, host.extra.nutanix.cluster], ['server', 'Nutanix', 'NXSN01', 'RUH-CL1']);
  assert.deepEqual([vm.type, vm.ip, vm.extra.nutanix.host], ['vm', '10.20.0.4', 'NTNX-RUH-A']);
  assert.ok(!e.h.app.discovery.rogueDevices().some((r) => r.id === host.id || r.id === vm.id), 'Prism is a system of record');
  assert.ok(seen.every(([m, u]) => m === 'POST' && u.startsWith('https://prism.lab.example:9440/api/nutanix/v3/')));
  assert.ok(!JSON.stringify((await e.adm('GET', '/discovery/audit?limit=200')).json).includes(PW));
});

test('database listeners + Solaris / Unix probes: active methods behind the gate, engines, banners, classification', async (t) => {
  const greet = Buffer.concat([Buffer.from([0x30, 0, 0, 0, 0x0a]), Buffer.from('8.0.36\0junk', 'latin1')]);
  const banners = { '10.20.0.3:22': 'SSH-2.0-Sun_SSH_1.1.4\r\n', '10.20.0.4:3306': greet, '10.20.0.5:22': 'SSH-2.0-OpenSSH_8.4\r\n' };
  const banner = async (ip, port) => { const b = banners[`${ip}:${port}`]; return b ? { state: 'open', data: Buffer.isBuffer(b) ? b : Buffer.from(b, 'latin1') } : { state: 'timeout', data: Buffer.alloc(0) }; };
  const e = await setup({ deps: { banner, connect: fakeConnect({ open: { '10.20.0.3': [111, 6789], '10.20.0.4': [1521, 1433], '10.20.0.5': [111] } }) } });
  t.after(() => e.close());
  const m = (await e.adm('GET', '/discovery/methods')).json;
  assert.ok(m.active.includes('db') && m.active.includes('unix'));
  assert.equal((await e.adm('POST', '/discovery/scopes', { name: 'x', site: 'Riyadh HQ', targets: ['10.20.0.0/29'], methods: { db: { enabled: true, engines: ['sqlite'] } } })).status, 400);
  const sc = (await e.adm('POST', '/discovery/scopes', { name: 'DB + Solaris VLAN', site: 'Riyadh HQ', targets: ['10.20.0.0/29'], methods: { db: { enabled: true }, unix: { enabled: true } } })).json.scope;
  assert.equal(sc.gate.required, true, 'active methods need the pre-scan checklist');
  let run = await e.run(sc.id);
  assert.ok(run.methods_blocked.some((b) => b.method === 'db') && run.methods_blocked.some((b) => b.method === 'unix'));
  assert.equal((await e.checklist(sc.id)).status, 200);
  run = await e.run(sc.id);
  assert.equal(run.stats.db.ok, true, JSON.stringify(run.stats)); assert.equal(run.stats.db.seen, 1); assert.equal(run.stats.db.listeners, 3);
  assert.equal(run.stats.unix.seen, 1);
  const devs = (await e.adm('GET', '/discovery/results?limit=50')).json.devices;
  const dbh = devs.find((d) => d.ip === '10.20.0.4'), sol = devs.find((d) => d.ip === '10.20.0.3'), lin = devs.find((d) => d.ip === '10.20.0.5');
  assert.deepEqual(dbh.extra.db.map((x) => [x.engine, x.port, x.version || '']), [['oracle', 1521, ''], ['mssql', 1433, ''], ['mysql', 3306, 'MySQL 8.0.36']]);
  assert.equal(dbh.type, 'server');
  assert.deepEqual([sol.type, sol.vendor, sol.os], ['server', 'Oracle', 'Oracle Solaris 11.3 or older (Sun_SSH_1.1.4)']);
  assert.equal(sol.extra.unix.ssh_banner, 'SSH-2.0-Sun_SSH_1.1.4');
  assert.equal(lin.extra.unix.os, null, 'an OpenSSH banner alone does not claim an OS');
  const L = require('../engine/lifecycle');
  assert.equal(L.evaluate(sol.os, L.compile([]), Date.parse('2026-10-12')).status, 'eol');
});

test('scope logins: DB / SSH / storage credentials log in read-only, only to trusted keys and certificates', async (t) => {
  const FP = { '10.20.0.3': 'a'.repeat(64) }, CERT = 'c'.repeat(64);
  const banners = { '10.20.0.3:22': 'SSH-2.0-Sun_SSH_1.1.4\r\n' };
  const banner = async (ip, port) => { const b = banners[`${ip}:${port}`]; return b ? { state: 'open', data: Buffer.from(b, 'latin1') } : { state: 'timeout', data: Buffer.alloc(0) }; };
  const calls = [];
  const invRun = async (r) => {
    calls.push(Object.assign({}, r, r.password ? { password: '[set]' } : {}));
    if (r.op === 'hostkey') return { ok: true, type: 'ssh-ed25519', fp: FP[r.host] };
    if (r.op === 'ssh_facts') {
      if (r.fp !== FP[r.host]) return { ok: false, error_class: 'hostkey_changed', fp: FP[r.host], type: 'ssh-ed25519' };
      return { ok: true, facts: { uname: 'SunOS sol01 5.11 11.4.62.151.3 sun4v sparc sun4v', hostname: 'sol01', release: '                     Oracle Solaris 11.4 SPARC', platform: 'sun4v', sockets: '2', cpus: '128', memory: 'Memory size: 261632 Megabytes', smbios: '  Manufacturer: Oracle Corporation\n  Product: SPARC T8-1\n  Serial Number: AK00TEST01' } };
    }
    if (r.op === 'db') return r.engine === 'oracle' && r.password !== '[set]' ? { ok: true, engine: 'oracle', version: 'Oracle Database 19c Enterprise Edition Release 19.0.0.0.0 - Production', instance: 'PRODDB|oradb01|19.0.0.0.0', databases: ['PROD'] } : { ok: false, error_class: 'auth', error: 'ORA-01017' };
    return { ok: false, error_class: 'config' };
  };
  const ontap = { '/api/cluster': { name: 'ntap-hq', version: { full: 'NetApp Release 9.14.1' } }, '/api/cluster/nodes': { records: [{ name: 'ntap-hq-01', model: 'AFF-A400', serial_number: '7210000TEST', state: 'up' }] } };
  const request = async (url, o) => {
    if (!o.pin) { const e = new Error('self-signed certificate'); e.code = 'tls'; e.presented = { fingerprint256: CERT, subject: 'CN=ntap-hq', issuer: 'CN=ntap-hq', valid_to: '2030-01-01' }; throw e; }
    if (o.pin !== CERT) throw Object.assign(new Error('pin mismatch'), { code: 'tls' });
    const p = new URL(url).pathname;
    return { status: 200, json: ontap[p] || { records: [] } };
  };
  const e = await setup({ deps: { banner, invRun, request, connect: fakeConnect({ open: { '10.20.0.3': [111, 6789], '10.20.0.4': [1521, 1433], '10.20.0.2': [3260, 10000] } }) } });
  t.after(() => e.close());
  const mk = async (b) => { const r = await e.adm('POST', '/discovery/credentials', b); assert.equal(r.status, 200, r.text); return r.json.credential; };
  const ora = await mk({ kind: 'db_login', label: 'Oracle RO', target: { engine: 'oracle', service: 'PRODDB' }, secret: { username: 'itam_ro', password: 'Synthetic-Ora-1' } });
  const pg = await mk({ kind: 'db_login', label: 'PG RO', target: { engine: 'postgres' }, secret: { username: 'ro', password: 'Synthetic-Pg-1' } });
  const ssh = await mk({ kind: 'ssh', label: 'Solaris RO', secret: { username: 'itamro', password: 'Synthetic-Ssh-2' } });
  const st = await mk({ kind: 'storage_api', label: 'NetApp RO', target: { platform: 'ontap' }, secret: { username: 'monitor', password: 'Synthetic-St-1' } });
  // credentials are optional for these methods, and of the right kind when given
  assert.equal((await e.adm('POST', '/discovery/scopes', { name: 'x', site: 'Riyadh HQ', targets: ['10.20.0.0/29'], methods: { unix: { enabled: true, credential_id: ora.id } } })).status, 400);
  const sc = (await e.adm('POST', '/discovery/scopes', { name: 'Servers with logins', site: 'Riyadh HQ', targets: ['10.20.0.0/29'], methods: { db: { enabled: true, credential_ids: [ora.id, pg.id] }, unix: { enabled: true, credential_id: ssh.id }, storage: { enabled: true, credential_id: st.id } } })).json.scope;
  assert.deepEqual(sc.methods.db.credential_ids, [ora.id, pg.id]);
  await e.checklist(sc.id);
  let run = await e.run(sc.id);
  // first scan: database login works (no host key involved); SSH key and storage certificate are only RECORDED
  assert.deepEqual([run.stats.db_login.tried, run.stats.db_login.ok], [1, 1], JSON.stringify(run.stats.db_login));
  assert.equal(calls.filter((c) => c.op === 'db').length, 1, 'only the engine whose listener answered (oracle), not postgres');
  assert.equal(calls.find((c) => c.op === 'db').service, 'PRODDB');
  assert.equal(run.stats.unix_login.pending_trust, 1); assert.equal(run.stats.unix_login.tried, 0);
  assert.ok(!calls.some((c) => c.op === 'ssh_facts'), 'no SSH password sent to an untrusted key');
  assert.equal(run.stats.storage_login.pending_trust, 1); assert.equal(run.stats.storage_login.ok, 0);
  let dev = (ip) => e.h.app.discovery.devices.list((d) => d.ip === ip)[0];
  const dbx = dev('10.20.0.4').extra.db_login.oracle;
  assert.deepEqual([dbx.edition, dbx.instance, dbx.host_name, dbx.databases.join(), dbx.credential], ['Enterprise Edition', 'PRODDB', 'oradb01', 'PROD', 'Oracle RO']);
  // trust list: admin only; trust the waiting key and certificate
  assert.equal((await e.op('GET', '/discovery/trust')).status, 403);
  const tl = (await e.adm('GET', '/discovery/trust')).json.items;
  assert.deepEqual(tl.map((x) => [x.kind, x.ip, x.state]).sort(), [['ssh', '10.20.0.3', 'pending'], ['tls', '10.20.0.2', 'pending']]);
  assert.equal((await e.op('POST', '/discovery/trust', { ids: tl.map((x) => x.id), action: 'trust' })).status, 403);
  assert.equal((await e.adm('POST', '/discovery/trust', { ids: tl.map((x) => x.id), action: 'trust' })).json.done, 2);
  run = await e.run(sc.id);
  assert.equal(run.stats.unix_login.ok, 1, JSON.stringify(run.stats.unix_login)); assert.equal(run.stats.storage_login.ok, 1, JSON.stringify(run.stats.storage_login));
  const sol = dev('10.20.0.3');
  assert.deepEqual([sol.os, sol.serial, sol.model, sol.hostname, sol.vendor, sol.type], ['Oracle Solaris 11.4 SPARC', 'AK00TEST01', 'SPARC T8-1', 'sol01', 'Oracle Corporation', 'server']);
  assert.deepEqual([sol.extra.unix_login.sockets, sol.extra.unix_login.cpus, sol.extra.unix_login.mem_gb], [2, 128, 256]);
  const arr = dev('10.20.0.2');
  assert.deepEqual([arr.type, arr.serial, arr.model, arr.vendor, arr.hostname], ['storage', '7210000TEST', 'AFF-A400', 'NetApp', 'ntap-hq']);
  // the SSH key changes (server rebuilt or someone in the middle): no login, flagged, waits for the admin
  FP['10.20.0.3'] = 'b'.repeat(64);
  const before = calls.filter((c) => c.op === 'ssh_facts').length;
  run = await e.run(sc.id);
  assert.equal(run.stats.unix_login.key_changed, 1);
  assert.equal(calls.filter((c) => c.op === 'ssh_facts').length, before, 'no login to a changed key');
  assert.equal((await e.adm('GET', '/discovery/trust?state=changed')).json.items[0].new_fp, 'b'.repeat(64));
  // secrets never reach the audit trail, the run record or the API
  const blob = JSON.stringify([(await e.adm('GET', '/discovery/audit?limit=500')).json, run, (await e.adm('GET', '/discovery/credentials')).json]);
  for (const pw of ['Synthetic-Ora-1', 'Synthetic-Ssh-2', 'Synthetic-St-1']) assert.ok(!blob.includes(pw), pw);
});

test('non-standard database ports: a login\'s own port is probed, the scope can add ports per engine, bad ports refused', async (t) => {
  const calls = [];
  const invRun = async (r) => { calls.push(r); return r.op === 'db' && r.engine === 'oracle' ? { ok: true, engine: 'oracle', version: 'Oracle Database 19c Enterprise Edition Release 19.0.0.0.0', instance: 'PROD|oradb01|19.0.0.0.0', databases: ['PROD'] } : { ok: false, error_class: 'config' }; };
  // Oracle listens on 1600 and SQL Server on 51433 only - none of the well-known ports are open
  const e = await setup({ deps: { invRun, connect: fakeConnect({ open: { '10.20.0.4': [1600, 51433] } }) } });
  t.after(() => e.close());
  const ora = (await e.adm('POST', '/discovery/credentials', { kind: 'db_login', label: 'Oracle RO 1600', target: { engine: 'oracle', port: 1600, service: 'PRODPDB1' }, secret: { username: 'sentra_mon', password: 'Synthetic-Ora-9' } })).json.credential;
  const base = { name: 'DB on odd ports', site: 'Riyadh HQ', targets: ['10.20.0.4'] };
  for (const bad of [{ oracle: [70000] }, { nosuch: [1] }, [1600], { mssql: Array.from({ length: 17 }, (_, i) => 50000 + i) }]) {
    assert.equal((await e.adm('POST', '/discovery/scopes', Object.assign({}, base, { methods: { db: { enabled: true, ports: bad } } }))).status, 400, JSON.stringify(bad));
  }
  const sc = (await e.adm('POST', '/discovery/scopes', Object.assign({}, base, { methods: { db: { enabled: true, credential_ids: [ora.id], ports: { mssql: [51433, '51433'] } } } }))).json.scope;
  assert.deepEqual(sc.methods.db.ports, { mssql: [51433] });
  await e.checklist(sc.id);
  const run = await e.run(sc.id);
  const dev = e.h.app.discovery.devices.list((d) => d.ip === '10.20.0.4')[0];
  assert.deepEqual(dev.extra.db.map((x) => [x.engine, x.port]).sort(), [['mssql', 51433], ['oracle', 1600]], 'both listeners found on their own ports');
  const login = calls.find((c) => c.op === 'db');
  assert.deepEqual([login.engine, login.port, login.service], ['oracle', 1600, 'PRODPDB1'], 'login on the listener\'s port');
  assert.equal(dev.extra.db_login.oracle.edition, 'Enterprise Edition');
  assert.equal(run.stats.db_login.ok, 1);
});

test('credential Test: refused / timeout name the address and port tried, and point at Port on the credential', async (t) => {
  let answer = { ok: false, error_class: 'refused', error: '[Errno 111] Connection refused' };
  const invRun = async () => answer;
  const e = await setup({ deps: { invRun } });
  t.after(() => e.close());
  const sc = (await e.adm('POST', '/discovery/scopes', { name: 'db host', site: 'Riyadh HQ', targets: ['10.20.0.4'], methods: { sweep: { enabled: true } } })).json.scope;
  await e.checklist(sc.id);
  const mk = async (b) => (await e.adm('POST', '/discovery/credentials', b)).json.credential;
  const test1 = async (id) => (await e.adm('POST', `/discovery/credentials/${id}/test`, { host: '10.20.0.4' })).json.result;
  const def = await mk({ kind: 'db_login', label: 'Oracle default port', target: { engine: 'oracle', service: 'PROD' }, secret: { username: 'sentra_mon', password: 'Synthetic-1' } });
  let r = await test1(def.id);
  assert.equal(r.ok, false);
  assert.match(r.message, /Connection refused at 10\.20\.0\.4:1521/); assert.match(r.message, /default database listener port.*set Port on this credential/);
  const own = await mk({ kind: 'db_login', label: 'Oracle 1600', target: { engine: 'oracle', port: 1600, service: 'PROD' }, secret: { username: 'sentra_mon', password: 'Synthetic-1' } });
  r = await test1(own.id);
  assert.match(r.message, /10\.20\.0\.4:1600 - nothing listens there\. Check that the database listener runs on port 1600/);
  answer = { ok: false, error_class: 'timeout', error: 'timed out' };
  const ssh = await mk({ kind: 'ssh', label: 'ssh', secret: { username: 'ro', password: 'Synthetic-2' } });
  r = await test1(ssh.id);
  assert.match(r.message, /No answer from 10\.20\.0\.4:22 - a firewall .* \(or the SSH uses another port: set Port on this credential\)/);
});
