// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// SQL Server / PostgreSQL / MySQL inventory (engine/db-inventory.js, inv-helper.py op db_details) through the real routes on
// SYNTHETIC servers: the servers come from the asset register + Asset Discovery's proven logins, the details are shaped per
// engine, backup and capacity notes come from the facts only, a server where a database runs without a proven login is
// listed with the read-only login to create, a failed read keeps the last good details, a missing privilege is named, the
// password is only ever sent to the helper (never stored or logged), roles (viewer refused, operator reads and runs, admin
// settings), validation errors and the audit record. inv-helper's queries are checked to be SELECT-only.
const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { execFileSync } = require('node:child_process');
const { startApp } = require('./helpers');
const { registerDbInventory, createDbInventory } = require('../engine/db-inventory');

const VIEW = { user: 'vera.syn', role: 'viewer' }, OP = { user: 'nora.syn', role: 'operator' }, ADM = { user: 'syed', role: 'admin' };
const NOW = Date.parse('2026-10-30T09:00:00Z'), PW = 'Synthetic-Pass-77';

async function setup(t, o = {}) {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  const mk = (x) => e.app.assets.create(Object.assign({ status: 'in_use', type: 'server' }, x), ADM).asset;
  const ids = { sql: mk({ name: 'SQL-SYN-01', os: 'Windows Server 2019', mgmt_ip: '10.9.0.11' }).id, pg: mk({ name: 'PG-SYN-01', os: 'Ubuntu 22.04', mgmt_ip: '10.9.0.12' }).id,
    my: mk({ name: 'MY-SYN-01', os: 'Rocky Linux 9', mgmt_ip: '10.9.0.13' }).id, my2: mk({ name: 'MY-SYN-02', os: 'Rocky Linux 9', mgmt_ip: '10.9.0.14' }).id };
  const D = e.app.store.collection('disc_devices');
  D.put({ id: 'd1', ip: '10.9.0.11', asset_id: ids.sql, status: 'matched', extra: { db_login: { mssql: { credential: 'sql-ro', instance: 'MSSQLSERVER' } } } });
  D.put({ id: 'd2', ip: '10.9.0.12', asset_id: ids.pg, status: 'matched', extra: { db_login: { postgres: { credential: 'pg-ro' } } } });
  D.put({ id: 'd3', ip: '10.9.0.13', asset_id: ids.my, status: 'matched', extra: { db_login: { mysql: { credential: 'my-ro' } } } });
  const creds = [{ id: 'c1', kind: 'db_login', label: 'sql-ro', target: { engine: 'mssql' } }, { id: 'c2', kind: 'db_login', label: 'pg-ro', target: { engine: 'postgres' } },
    { id: 'c3', kind: 'db_login', label: 'my-ro', target: { engine: 'mysql', port: 3307 } }];
  e.app.discovery = Object.assign({}, e.app.discovery, { vault: { list: () => creds, open: (id) => ({ target: creds.find((c) => c.id === id).target, secret: { username: 'zyb_inventory', password: PW }, release() {} }) } });
  // the Business Services map: MySQL also runs on MY-SYN-02 with no proven login
  e.app.addons = e.app.addons || {};
  e.app.addons.serviceMap = { view: () => ({ servers: [{ ip: '10.9.0.14', host: 'my-syn-02', asset: { id: ids.my2, name: 'MY-SYN-02' }, services: [{ id: 'mysql', confidence: 'confirmed', evidence: [{ detail: 'process mysqld' }] }] },
    { ip: '10.9.0.12', host: 'pg-syn-01', asset: { id: ids.pg, name: 'PG-SYN-01' }, services: [{ id: 'postgres', confidence: 'confirmed', evidence: [] }] }] }) };
  const calls = [];
  const invRun = async (r) => {
    calls.push(r);
    if (r.engine === 'mssql') {
      if (o.sqlFails) return { ok: false, error: 'Login failed for user zyb_inventory', error_class: 'auth' };
      return { ok: true, engine: 'mssql', system: ['master', 'model', 'msdb', 'tempdb'], errors: { replication: 'VIEW SERVER STATE' },
        server: [['SQL-SYN-01', 'MSSQLSERVER', '15.0.4345.5', 'RTM', 'Standard Edition (64-bit)', 0, 0, 'Arabic_CI_AS']], started: [['2026-10-01T02:00:00', 8, 32768]], sessions: [[42]],
        databases: [['master', 'ONLINE', 'SIMPLE', 150, 6, '2026-10-29T22:00:00', null, 0, 'MULTI_USER'], ['ClaimsSyn', 'ONLINE', 'FULL', 150, 51200, '2026-10-29T22:00:00', null, 0, 'MULTI_USER'],
          ['PolicySyn', 'ONLINE', 'SIMPLE', 150, 2048, '2026-10-10T22:00:00', null, 0, 'MULTI_USER'], ['ArchiveSyn', 'OFFLINE', 'SIMPLE', 140, 900, null, null, 1, 'MULTI_USER']], replication: null };
    }
    if (r.engine === 'postgres') return { ok: true, engine: 'postgres', system: ['postgres'], errors: {}, server: [['PostgreSQL 15.4 on x86_64', '15.4', 5432, 100, false, '/var/lib/pgsql']], started: [['2026-10-20T03:00:00']], sessions: [[95]],
      databases: [['postgres', 'ONLINE', 'UTF8', 8, 1, 0, 100], ['portal_syn', 'ONLINE', 'UTF8', 1200, 60, 3, 900000]], replication: [['standby1', 'streaming', 'async', 2]] };
    return { ok: true, engine: 'mysql', system: ['mysql', 'information_schema', 'performance_schema', 'sys'], errors: {}, server: [['8.0.36', 'MySQL Community Server - GPL', 'my-syn-01', 3307, 151, 0, '8.0.36']], started: [[86400]], sessions: [[12]],
      databases: [['mysql', 'ONLINE', 'utf8mb4', 3, 38], ['crm_syn', 'ONLINE', 'utf8mb4', 640, 120]], replication: [] };
  };
  const I = registerDbInventory(e.app.srv, e.app, createDbInventory(e.app, { now: () => NOW, invRun, noTimer: true }));
  const audits = () => e.app.store.auditTail(200).filter((x) => /^db_inventory\./.test(x.action));
  return { e, I, calls, audits, ids, call: (m, p, b, who) => e.req(m, p, Object.assign(b !== undefined ? { body: b } : {}, who)) };
}

test('read every server with a proven login; details shaped per engine; notes from the facts; found without a login', async (t) => {
  const { e, call, calls, audits, ids } = await setup(t);
  let r = await call('POST', '/db-inventory/run', {}, OP);
  assert.equal(r.status, 200, r.raw);
  assert.deepEqual(r.json.run, Object.assign({ at: r.json.run.at }, { targets: 3, read: 3, failed: 0 }));
  assert.deepEqual(calls.map((c) => [c.op, c.engine, c.host, c.port]), [['db_details', 'mssql', '10.9.0.11', 1433], ['db_details', 'postgres', '10.9.0.12', 5432], ['db_details', 'mysql', '10.9.0.13', 3307]]);
  const v = r.json, by = (eng) => v.servers.find((x) => x.engine === eng);
  const sql = by('mssql');
  assert.equal(sql.asset_id, ids.sql); assert.equal(sql.asset_name, 'SQL-SYN-01');
  assert.equal(sql.server.edition, 'Standard Edition (64-bit)'); assert.equal(sql.server.version, '15.0.4345.5'); assert.equal(sql.server.sessions, 42);
  assert.equal(sql.totals.databases, 3, 'system databases are not counted'); assert.equal(sql.totals.size_mb, 51200 + 2048 + 900);
  assert.ok(sql.databases.find((d) => d.name === 'master').system);
  const notes = sql.notes.map((n) => n.text).join(' | ');
  assert.match(notes, /ArchiveSyn is OFFLINE/); assert.match(notes, /PolicySyn: last full backup 2026-10-10/); assert.match(notes, /ClaimsSyn: FULL recovery but no log backup/);
  assert.deepEqual(sql.missing, [{ query: 'replication', reason: 'VIEW SERVER STATE' }], 'a query the login may not run is named');
  const pg = by('postgres');
  assert.equal(pg.server.version, '15.4'); assert.equal(pg.totals.databases, 1); assert.equal(pg.replication[0].name, 'standby1');
  assert.ok(pg.notes.some((n) => /sessions at 95% of max_connections/.test(n.text)) && pg.notes.some((n) => /portal_syn: 3 deadlock/.test(n.text)));
  const my = by('mysql');
  assert.equal(my.server.edition, 'MySQL Community Server - GPL'); assert.equal(my.server.started, '2026-10-29T09:00:00Z'); assert.equal(my.totals.size_mb, 640);
  assert.deepEqual(v.engines.map((x) => [x.engine, x.read, x.found]), [['oracle', 0, 0], ['mssql', 1, 0], ['postgres', 1, 0], ['mysql', 1, 1]]);
  assert.equal(v.found.length, 1, 'PostgreSQL on PG-SYN-01 is read, so only MY-SYN-02 is "found"');
  assert.equal(v.found[0].ip, '10.9.0.14'); assert.equal(v.found[0].asset_name, 'MY-SYN-02'); assert.match(v.found[0].next, /Asset Discovery/);
  assert.ok(v.grants.mysql.some((g) => /GRANT PROCESS, SHOW DATABASES/.test(g)) && v.grants.postgres.some((g) => /pg_monitor/.test(g)));
  const blob = JSON.stringify(e.app.store.collection('db_inventory').all(() => true)) + JSON.stringify(audits()) + JSON.stringify(v);
  assert.ok(!blob.includes(PW), 'the password never reaches the store, the audit or an answer');
  assert.equal(calls[0].password, PW, 'only the helper receives it');
  const a = audits().filter((x) => x.action === 'db_inventory.run');
  assert.equal(a.length, 1); assert.equal(a[0].by, 'nora.syn'); assert.equal(a[0].detail.read, 3);
});

test('a failed read keeps the last good details and says why; roles and validation', async (t) => {
  const ctx = await setup(t);
  await ctx.call('POST', '/db-inventory/run', {}, OP);
  const t2 = await setup(t, { sqlFails: true });
  // the second app has no previous read: the failure is recorded with its class
  let r = await t2.call('POST', '/db-inventory/run', {}, OP);
  const sql = r.json.servers.find((x) => x.engine === 'mssql');
  assert.equal(sql.error_class, 'auth'); assert.match(sql.error, /Login failed/); assert.equal(r.json.run.failed, 1);
  // a failure after a good read keeps the details
  const I = createDbInventory(ctx.e.app, { now: () => NOW + 3600000, invRun: async () => ({ ok: false, error: 'timed out', error_class: 'timeout' }), noTimer: true });
  await I.pass(null);
  const kept = I.view().servers.find((x) => x.engine === 'mssql');
  assert.equal(kept.error_class, 'timeout'); assert.equal(kept.server.edition, 'Standard Edition (64-bit)', 'the last good details stay');
  // roles
  r = await ctx.call('GET', '/db-inventory', undefined, VIEW); assert.equal(r.status, 403, 'database names are not for viewers');
  r = await ctx.call('POST', '/db-inventory/run', {}, VIEW); assert.equal(r.status, 403);
  r = await ctx.call('POST', '/db-inventory/settings', { interval_h: 12 }, OP); assert.equal(r.status, 403, 'operators cannot change the schedule');
  r = await ctx.call('POST', '/db-inventory/settings', {}, ADM); assert.equal(r.status, 400); assert.match(r.json.error, /interval_h is required/);
  r = await ctx.call('POST', '/db-inventory/settings', { interval_h: 0 }, ADM); assert.equal(r.status, 400); assert.match(r.json.error, /interval_h must be at least 1/);
  r = await ctx.call('POST', '/db-inventory/settings', { interval_h: 12, extra: 'dropped' }, ADM); assert.equal(r.status, 200); assert.equal(r.json.settings.interval_h, 12);
  assert.ok(!('extra' in ctx.e.app.store.collection('db_inventory_cfg').get('cfg')), 'undeclared fields are dropped');
  const a = ctx.audits().find((x) => x.action === 'db_inventory.settings');
  assert.deepEqual(a.detail.interval_h, [6, 12]); assert.equal(a.by, 'syed');
});

test('Oracle: proven login and registered database read the same way; PDBs, RMAN, Data Guard; an unsafe or refused login is held, not retried', async (t) => {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  const a = e.app.assets.create({ status: 'in_use', type: 'server', name: 'ORA-SYN-01', mgmt_ip: '10.9.1.21' }, ADM).asset;
  e.app.store.collection('disc_devices').put({ id: 'o1', ip: '10.9.1.21', asset_id: a.id, status: 'matched', extra: { db_login: { oracle: { credential: 'ora-ro' } } } });
  e.app.store.collection('db_health_targets').put({ id: 'odb_1', label: 'ERP-SYN', host: '10.9.1.30', port: 1521, service: 'ERPPDB', cred_id: 'c9' });
  const creds = [{ id: 'c8', kind: 'db_login', label: 'ora-ro', target: { engine: 'oracle', service: 'ORCLSYN' } }, { id: 'c9', kind: 'db_login', label: 'oracle-ERP-SYN', target: { engine: 'oracle', service: 'ERPPDB' } }];
  e.app.discovery = Object.assign({}, e.app.discovery, { vault: { list: () => creds, open: (id) => ({ target: creds.find((c) => c.id === id).target, secret: { username: 'ZYB_MONITOR', password: PW }, release() {} }) } });
  let erp = 'unsafe'; const calls = [];
  const invRun = async (r) => {
    calls.push([r.host, r.service]);
    if (r.host === '10.9.1.30') return erp === 'ok' ? { ok: true, engine: 'oracle', system: ['PDB$SEED'], errors: {}, server: [['ERP1', 'erp-syn', '19.0.0.0.0', 'Oracle Database 19c Standard Edition 2 Release 19.0.0.0.0 - Production', 'OPEN', 'PRIMARY', 'READ WRITE', 'NOARCHIVELOG', 'ERP', 'ERP']],
      started: [['2026-10-01T01:00:00', 4, 8192]], sessions: [[20, 300]], databases: [], database_noncdb: [['ERP', 'READ WRITE', 40960, 'NO']], backup: [[null, null]], replication: [] }
      : { ok: false, error: erp === 'unsafe' ? 'account holds more than read-only monitoring rights (DBA) - not used' : 'ORA-01017: invalid username/password', error_class: erp === 'unsafe' ? 'unsafe' : 'auth' };
    return { ok: true, engine: 'oracle', system: ['PDB$SEED'], errors: { replication: 'ORA-00942' },
      server: [['ORCL1', 'ora-syn-01', '19.0.0.0.0', 'Oracle Database 19c Enterprise Edition Release 19.0.0.0.0 - Production', 'OPEN', 'PRIMARY', 'READ WRITE', 'ARCHIVELOG', 'ORCL', 'ORCL_DC']],
      started: [['2026-10-15T01:00:00', 16, 24576]], sessions: [[180, 200]], databases: [['PDB$SEED', 'READ ONLY', 900, 'NO'], ['CLAIMSPDB', 'READ WRITE', 204800, 'NO'], ['HRPDB', 'MOUNTED', 10240, 'NO']],
      backup: [['2026-10-29T23:00:00', null]], replication: null };
  };
  const I = registerDbInventory(e.app.srv, e.app, createDbInventory(e.app, { now: () => NOW, invRun, noTimer: true }));
  const call = (m, p, b, who) => e.req(m, p, Object.assign(b !== undefined ? { body: b } : {}, who));
  let r = await call('POST', '/db-inventory/run', {}, OP);
  assert.equal(r.status, 200, r.raw);
  assert.deepEqual(calls, [['10.9.1.21', 'ORCLSYN'], ['10.9.1.30', 'ERPPDB']], 'the proven login and the registered database, each with its service');
  const ora = r.json.servers.find((x) => x.ip === '10.9.1.21');
  assert.equal(ora.label, 'Oracle'); assert.equal(ora.server.edition, 'Enterprise Edition Release 19.0.0.0.0 - Production'); assert.equal(ora.server.multitenant, true);
  assert.equal(ora.server.max_connections, 200); assert.equal(ora.totals.databases, 2, 'PDB$SEED is a system container'); assert.equal(ora.totals.size_mb, 204800 + 10240);
  const notes = ora.notes.map((n) => n.text).join(' | ');
  assert.match(notes, /HRPDB is MOUNTED/); assert.match(notes, /ARCHIVELOG but no archive-log backup/); assert.match(notes, /sessions at 90% of max_connections/);
  assert.deepEqual(ora.missing, [{ query: 'replication', reason: 'ORA-00942' }]);
  let erpRec = r.json.servers.find((x) => x.ip === '10.9.1.30');
  assert.equal(erpRec.error_class, 'unsafe');
  // the timer does not retry a refused / unsafe login (no lockout); a person does, after fixing it
  calls.length = 0; erp = 'auth';
  const run = await I.pass(null);
  assert.deepEqual(calls, [['10.9.1.21', 'ORCLSYN']], 'the held database is not touched by the timer'); assert.equal(run.held, 1);
  erp = 'ok'; r = await call('POST', '/db-inventory/run', {}, OP);
  erpRec = r.json.servers.find((x) => x.ip === '10.9.1.30');
  assert.equal(erpRec.error, null); assert.equal(erpRec.server.multitenant, false); assert.equal(erpRec.databases[0].name, 'ERP');
  assert.match(erpRec.notes.map((n) => n.text).join(' | '), /no completed RMAN full/); assert.match(erpRec.notes.map((n) => n.text).join(' | '), /NOARCHIVELOG/);
  assert.equal(r.json.engines.find((x) => x.engine === 'oracle').read, 2);
  assert.ok(!JSON.stringify(e.app.store.collection('db_inventory').all(() => true)).includes(PW));
});

test('inv-helper db_details: fixed SELECT-only queries for every engine, and an unknown engine is refused', () => {
  const py = process.env.PYTHON || 'python3', helper = path.join(__dirname, '..', 'engine', 'discovery', 'inv-helper.py');
  const outp = execFileSync(py, ['-I', '-c', `
import importlib.util, json, re
sp = importlib.util.spec_from_file_location('h', ${JSON.stringify(helper)}); h = importlib.util.module_from_spec(sp); sp.loader.exec_module(h)
bad = [e + ':' + n for e, qs in h.DB_DETAILS.items() for n, q in qs if not re.match(r'^\\s*select\\b', q, re.I) or re.search(r'\\b(insert|update|delete|drop|alter|create|grant|exec|execute|truncate|into|shutdown|kill)\\b', q, re.I)]
print(json.dumps({'engines': sorted(h.DB_DETAILS), 'bad': bad, 'oracle': h.op_db_details({'engine': 'db2'})}))`]).toString();
  const o = JSON.parse(outp);
  assert.deepEqual(o.engines, ['mssql', 'mysql', 'oracle', 'postgres']);
  assert.deepEqual(o.bad, [], 'every query is a SELECT and changes nothing');
  assert.equal(o.oracle.ok, false, 'an engine without an inventory read is refused');
});
