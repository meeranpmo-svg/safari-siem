// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// AI Oracle DBA + AI Application Manager (engine/duty/app-adapters.js) on the real duty cycle: Oracle collector issues
// become work items with the DBA's next step and clear when the collector stops reporting them; a stale instance is never
// "fixed"; per-service availability (down / no redundancy / SPOF / DR) and resource pressure on production servers become
// application items, business-critical services rank higher; nothing reported = not connected.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { createState } = require('../engine/soc/state');
const { createDuty } = require('../engine/duty/duty-core');
const { dbaAdapter, appAdapter } = require('../engine/duty/app-adapters');

const store = async () => createState({ dir: path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'sentra-dutyapps-')), 'state') });

function fakeOracle() {
  const O = { instances: [] };
  O.summary = async () => ({ instances: O.instances });
  O.instance = async (k) => O.instances.find((i) => i.key === k) || null;
  return O;
}
const inst = (over) => Object.assign({ key: 'dbhost1|CORE', host: 'dbhost1', instance: 'CORE', db_name: 'CORE', version: '19.21', status: 'OPEN', up: true, open_mode: 'READ WRITE', role: 'PRIMARY',
  stale: false, last_seen: Date.UTC(2026, 9, 16, 8), tablespaces: [{ name: 'USERS', used_pct: 96 }], sessions: { total: 120, active: 9, blocked: 2, max_sessions: 600 }, blocked_sessions: [],
  backup: { status: 'FAILED', input_type: 'DB INCR', age_h: 30, severity: 3 }, issues: [] }, over);

test('AI Oracle DBA: collector issues → work items with the next step; cleared when no longer reported; stale is not "fixed"', async () => {
  let t = Date.UTC(2026, 9, 16, 8); const O = fakeOracle(), st = await store();
  const D = createDuty({ store: st, engineers: dbaAdapter(O), now: () => t });
  let r = await D.patrol('dba'); assert.equal(r.not_connected, true, 'no database reports: not connected, never healthy');
  O.instances = [inst({ issues: [{ severity: 4, text: 'tablespace USERS 96% used', action: 'tablespace-usage' }, { severity: 3, text: 'last RMAN backup FAILED (30 h ago)', action: 'backup-status' }] })];
  r = await D.patrol('dba');
  assert.equal(r.opened, 2);
  const items = D.list({ engineer: 'dba' }).items;
  const tbs = items.find((x) => x.kind === 'tablespace-usage'), bk = items.find((x) => x.kind === 'backup-status');
  assert.equal(tbs.severity, 'critical'); assert.equal(bk.severity, 'high');
  assert.match(tbs.title, /CORE on dbhost1: tablespace USERS 96% used/);
  assert.match(tbs.recommendation, /datafile/); assert.match(bk.recommendation, /RMAN/);
  assert.ok(D.get(bk.id).investigation.checks.some((c) => c.name === 'Last RMAN backup' && c.status === 'fail'), 'investigation reads the instance');
  // 97% next sample: same item (digits masked), not a new one
  O.instances[0].issues[0].text = 'tablespace USERS 97% used'; t += 600000; r = await D.patrol('dba');
  assert.equal(r.opened, 0);
  // backup fixed: cleared
  O.instances[0].issues = O.instances[0].issues.filter((x) => x.action !== 'backup-status'); t += 600000; r = await D.patrol('dba');
  assert.equal(D.get(bk.id).status, 'resolved'); assert.equal(D.get(bk.id).resolution, 'cleared');
  // stale instance: verify answers "not yet known"
  O.instances[0].stale = true;
  const v = await dbaAdapter(O)[0].verify(D.get(tbs.id));
  assert.equal(v.present, null);
  // instance down without an explicit issue still opens a critical item
  O.instances = [inst({ key: 'dbhost2|ERP', host: 'dbhost2', instance: 'ERP', db_name: 'ERP', up: false, status: 'MOUNTED', issues: [] })]; t += 600000; r = await D.patrol('dba');
  assert.ok(D.list({ engineer: 'dba', status: 'open' }).items.some((x) => x.kind === 'instance-down' && x.severity === 'critical'));
});

function fakeAvail() {
  const A = { items: [], groups: [] };
  A.view = async () => ({ items: A.items, groups: A.groups });
  return A;
}

test('AI Application Manager: service down / no redundancy / SPOF / DR + resource pressure on production servers', async () => {
  let t = Date.UTC(2026, 9, 16, 8); const A = fakeAvail(), st = await store();
  const D = createDuty({ store: st, engineers: appAdapter(A), now: () => t });
  assert.equal((await D.patrol('apps')).not_connected, true);
  A.items = [
    { id: 'h1', name: 'claims-app-1', status: 'online', site: 'HQ', flags: ['disk-full'], resources: { cpu_pct: 20, mem_pct: 40, disk_max_pct: 95 } },
    { id: 'h2', name: 'claims-app-2', status: 'offline', site: 'HQ', flags: ['offline'] },
    { id: 'h3', name: 'uat-web', status: 'online', flags: ['cpu-high'], resources: { cpu_pct: 97, mem_pct: 10, disk_max_pct: 10 } },
    { id: 'h4', name: 'portal-1', status: 'offline', flags: ['offline'] },
  ];
  A.groups = [
    { key: 'svc:claims', name: 'Claims', required: true, critical: true, inferred: false, members: ['h1', 'h2'], production: 2, production_online: 1, issues: ['no-redundancy-now', 'no-dr'] },
    { key: 'auto:uat-web', name: 'uat-web', required: false, critical: false, inferred: true, members: ['h3'], production: 1, production_online: 1, issues: [] },
    { key: 'svc:portal', name: 'Customer portal', required: true, critical: false, inferred: false, members: ['h4'], production: 1, production_online: 0, issues: ['single-server', 'service-down', 'no-dr'] },
  ];
  const r = await D.patrol('apps');
  const items = D.list({ engineer: 'apps' }).items, by = (k) => items.filter((x) => x.kind === k);
  assert.equal(by('service-down')[0].severity, 'critical');
  assert.equal(by('no-redundancy-now')[0].severity, 'critical', 'business-critical service raises high to critical');
  assert.equal(by('no-dr').find((x) => /Claims/.test(x.title)).severity, 'high');
  assert.equal(by('disk-full').length, 1, 'resource finding on a production service server');
  assert.equal(by('cpu-high').length, 0, 'non-production server: not an application item');
  assert.equal(items.find((x) => x.kind === 'service-down').site, '');
  assert.equal(by('disk-full')[0].site, 'HQ');
  assert.ok(r.opened >= 6);
  assert.ok(D.get(by('service-down')[0].id).investigation.checks.some((c) => c.name === 'portal-1' && c.status === 'fail'));
  // portal back up: service-down clears
  A.items[3].status = 'online'; A.groups[2].issues = ['single-server', 'no-dr']; A.groups[2].production_online = 1; t += 600000; await D.patrol('apps');
  assert.equal(D.get(by('service-down')[0].id).resolution, 'cleared');
});

test('readiness: blocked / partial / ready per SIEM engineer, with the fix', async () => {
  const { readiness } = require('../engine/duty/readiness');
  const st = await store();
  const devs = [{ id: 'd1', vendor: 'aruba', role: 'switch' }, { id: 'f1', vendor: 'fortigate' }];
  const N = { inventory: { list: () => devs, credentialSummary: (id) => (id === 'd1' ? { snmp: 'v3 authPriv' } : {}) }, poller: { snapshot: (id) => (id === 'd1' ? { ok: true } : null) },
    ai: { status: () => ({ enabled: false, reason: 'no Anthropic API key' }) }, availability: { view: async () => ({ items: [{ id: 'h1' }], groups: [{ key: 'svc:x', inferred: false }] }) } };
  const S = { targets: { list: () => [], loginSummary: () => ({}) }, health: { snapshot: () => null }, runner: { status: async () => ({ available: false, reason: 'pypsrp not installed' }) }, ai: { status: () => ({ enabled: false, reason: 'no key' }) } };
  const O = { summary: async () => ({ totals: { instances: 0, stale: 0 } }) };
  const D = { policy: () => ({ enabled: true, patrol_min: 10 }), engineers: () => ['network', 'security', 'windows', 'exchange', 'dba', 'apps'].map((id) => ({ id, on_duty: true, last_patrol: Date.UTC(2026, 9, 17) })) };
  assert.ok(st);
  const r = await readiness({ netopsInstance: N, sysadminInstance: S, oracle: O }, D);
  const by = (id) => r.engineers.find((x) => x.id === id);
  assert.equal(by('network').status, 'partial', 'device onboarded and polling, but no AI key');
  assert.ok(by('network').to_fix.some((f) => /--set-key/.test(f.fix)));
  assert.equal(by('security').status, 'partial'); assert.ok(by('security').to_fix.some((f) => /credentials/.test(f.fix)), 'firewall without credentials named');
  assert.equal(by('windows').status, 'blocked'); assert.match(by('windows').to_fix[0].fix, /AI Server Administrators/);
  assert.equal(by('dba').status, 'blocked'); assert.ok(by('dba').to_fix.some((f) => /agents\/oracle/.test(f.fix)));
  assert.equal(by('apps').status, 'ready', 'servers monitored, services named, on duty');
  // Zscaler + Kaspersky KSC: their modules are not wired in this test, so they read blocked (module not installed)
  assert.equal(by('zscaler').status, 'blocked'); assert.equal(by('ksc').status, 'blocked');
  assert.equal(r.of, 12, 'eight engineers plus the four of the organisation\'s estate (FortiGate, NAC, NDR, Mimecast)');
});

// ---- performance: a database added in Connections & Setup (IT Asset Management's read-only connection, collector
// "sentra-oracle-itam") reaches the Database Performance view and the AI Oracle DBA exactly like the collector agent
test('AI Oracle DBA + performance: platform-collected records → perf view → CPU-bound / host CPU / wait work items; cleared when it calms', async () => {
  const health = require('../engine/db-audit/oracle-health');
  const { createOraclePerf } = require('../engine/db-audit/perf-api');
  let t = Date.now();
  const P = createOraclePerf({ ch: null, now: () => t });
  const common = { collector: 'sentra-oracle-itam', host: 'findb01', instance: 'FINPRD', db_name: 'FINPRD' };
  // the records inv-helper.py oracle_perf_records() sends (same names as agents/oracle/collect-perf.sql)
  const sample = (at, aas, hostCpu, uio) => [
    { kind: 'load_profile', scope: 'instance', aas, db_cpu_s: 3.8, executions_s: 1200, host_cpu_pct: hostCpu, cpu_count: 4, interval_s: 60 },
    { kind: 'efficiency', buffer_cache_hit_pct: 98.7 },
    { kind: 'wait_classes', class: 'User I/O', time_s: 0.05, waits_s: 25, avg_ms: 2, dbtime_pct: uio },
    { kind: 'active_sessions', captures: 1, active_total: 6, aas: 6, aas_cpu: 3, aas_user_i_o: 3, top_event: 'ON CPU', cpu_count: 4 },
  ].map((r) => Object.assign({}, r, common, { t: new Date(at).toISOString() }));
  const feed = (aas, hostCpu, uio) => { for (let k = 5; k >= 0; k--) for (const o of sample(t - k * 240000, aas, hostCpu, uio)) {
    assert.ok(health.sniff('', { obj: o }), 'the SIEM accepts the platform collector\'s records'); const ev = health.parse('', { obj: o }); ev.src_type = 'oracle-health'; P.stage(ev); } };
  feed(9.5, 93, 62);
  const v = await P.perf({ instance: 'findb01|FINPRD' });
  assert.ok(v.summary && v.summary.points >= 3, 'the Database Performance view has a series'); assert.equal(v.summary.cpu_count, 4);
  assert.ok(v.aas_by_class.classes.length >= 1, 'top activity by wait class');

  const O = fakeOracle(); O.instances = [inst({ key: 'findb01|FINPRD', host: 'findb01', instance: 'FINPRD', db_name: 'FINPRD', backup: null, tablespaces: [], sessions: null })];
  const st = await store(), D = createDuty({ store: st, engineers: dbaAdapter(O, P), now: () => t });
  await D.patrol('dba');
  const open = () => D.list({ status: 'open' }).items.filter((x) => x.engineer === 'dba');
  const kinds = () => open().map((x) => x.kind).sort();
  assert.deepEqual(kinds(), ['cpu-bound', 'host-cpu', 'wait-dominated']);
  const cpuItem = open().find((x) => x.kind === 'cpu-bound');
  assert.equal(cpuItem.severity, 'high', '9.5 active sessions on 4 CPUs is more than 2 per CPU'); assert.match(cpuItem.recommendation, /top SQL/);
  const inv = await dbaAdapter(O, P)[0].investigate(cpuItem);
  assert.ok(inv.checks.some((c) => c.name === 'Load (last hour)' && /for 4 CPUs/.test(c.detail)), 'the investigation shows the load');
  // the next patrol with the same averages keeps ONE item per problem (the numbers moving do not open new ones)
  feed(9.8, 94, 63); await D.patrol('dba'); assert.equal(open().length, 3);
  // load drops: the averages fall below the thresholds and the items verify as gone
  t += 2 * 3600000; feed(1.2, 40, 10); await D.patrol('dba');
  assert.deepEqual(kinds(), [], 'cleared once the last hour is calm');
  // a stale instance: its old averages raise nothing new
  O.instances[0].stale = true; t += 2 * 3600000; feed(9.5, 93, 62); await D.patrol('dba');
  assert.ok(!open().some((x) => x.kind === 'cpu-bound'));
});

test('AI Oracle DBA: no performance feed / too few samples → health items only, never a guessed performance problem', async () => {
  const O = fakeOracle(); O.instances = [inst({ issues: [] , backup: null, tablespaces: [], sessions: null })];
  const thin = { perf: async () => ({ summary: { points: 1, cpu_count: 4, aas_avg: 20, host_cpu_pct_avg: 99 }, wait_classes: [{ class: 'User I/O', dbtime_pct: 90 }] }) };
  for (const P of [undefined, thin, { perf: async () => { throw new Error('oracle instance not found'); } }]) {
    const f = await dbaAdapter(O, P)[0].findings();
    assert.ok(!f.some((x) => ['cpu-bound', 'host-cpu', 'wait-dominated'].includes(x.kind)));
  }
});
