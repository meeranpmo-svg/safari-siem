// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// AI Database Administrator for SQL Server / PostgreSQL / MySQL (engine/sqldba.js over engine/db-inventory.js) through the real
// duty desk and routes on SYNTHETIC servers: the patrol opens one work item per problem the read found (and one for a server
// it cannot read), investigate gives read-only checks and the DBA's exact statement for that engine, a fix is verified by a
// fresh read of that one server and the item clears, Oracle stays with the AI Oracle DBA, no proven login = not connected,
// readiness lists the engineer, roles (viewer refused, operator reads, AI ask validated and audited).
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');
const { playbook } = require('../engine/sqldba');

const VIEW = { user: 'vera.syn', role: 'viewer' }, OP = { user: 'nora.syn', role: 'operator' }, ADM = { user: 'syed', role: 'admin' };
const NOW = Date.parse('2026-10-30T09:00:00Z');

async function setup(t, o = {}) {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  const mk = (x) => e.app.assets.create(Object.assign({ status: 'in_use', type: 'server' }, x), ADM).asset;
  const D = e.app.store.collection('disc_devices'), creds = [];
  if (!o.empty) {
    const sql = mk({ name: 'SQL-SYN-01', mgmt_ip: '10.9.0.11' }), pg = mk({ name: 'PG-SYN-01', mgmt_ip: '10.9.0.12' }), ora = mk({ name: 'ORA-SYN-01', mgmt_ip: '10.9.0.21' });
    D.put({ id: 'd1', ip: '10.9.0.11', asset_id: sql.id, status: 'matched', extra: { db_login: { mssql: { credential: 'sql-ro' } } } });
    D.put({ id: 'd2', ip: '10.9.0.12', asset_id: pg.id, status: 'matched', extra: { db_login: { postgres: { credential: 'pg-ro' } } } });
    D.put({ id: 'd3', ip: '10.9.0.21', asset_id: ora.id, status: 'matched', extra: { db_login: { oracle: { credential: 'ora-ro' } } } });
    creds.push({ id: 'c1', kind: 'db_login', label: 'sql-ro', target: { engine: 'mssql' } }, { id: 'c2', kind: 'db_login', label: 'pg-ro', target: { engine: 'postgres' } }, { id: 'c3', kind: 'db_login', label: 'ora-ro', target: { engine: 'oracle', service: 'ORCLSYN' } });
  }
  e.app.discovery = Object.assign({}, e.app.discovery, { vault: { list: () => creds, open: (id) => ({ target: creds.find((c) => c.id === id).target, secret: { username: 'zyb_monitor', password: 'Synthetic-9' }, release() {} }) } });
  const state = { claimsBackup: null, pgFails: false };
  const invRun = async (r) => {
    if (r.engine === 'oracle') return { ok: true, engine: 'oracle', system: ['PDB$SEED'], errors: {}, server: [['ORCL1', 'ora', '19.0', 'Oracle Database 19c Enterprise Edition', 'OPEN', 'PRIMARY', 'READ WRITE', 'NOARCHIVELOG', 'ORCL', 'ORCL']], started: [[null, 4, 1024]], sessions: [[5, 300]], databases: [], database_noncdb: [['ORCL', 'READ WRITE', 100, 'NO']], backup: [[null, null]], replication: [] };
    if (r.engine === 'postgres') return state.pgFails ? { ok: false, error: 'password authentication failed for user "zyb_monitor"', error_class: 'auth' }
      : { ok: true, engine: 'postgres', system: ['postgres'], errors: {}, server: [['PostgreSQL 15', '15.4', 5432, 100, false, '']], started: [['2026-10-20T03:00:00']], sessions: [[20]], databases: [['portal_syn', 'ONLINE', 'UTF8', 1200, 6, 0, 9]], replication: [] };
    return { ok: true, engine: 'mssql', system: ['master', 'model', 'msdb', 'tempdb'], errors: {}, server: [['SQL-SYN-01', 'MSSQLSERVER', '15.0.4345.5', 'RTM', 'Standard Edition', 0, 0, 'x']], started: [['2026-10-01T02:00:00', 8, 32768]], sessions: [[10]],
      databases: [['ClaimsSyn', 'ONLINE', 'SIMPLE', 150, 51200, state.claimsBackup, null, 0, 'MULTI_USER'], ['ArchiveSyn', state.archiveOnline ? 'ONLINE' : 'OFFLINE', 'SIMPLE', 140, 900, '2026-10-29T22:00:00', null, 0, 'MULTI_USER']], replication: [] };
  };
  registerDuty(e.app.srv, e.app, { noTimer: true, now: () => NOW, python: process.env.PYTHON || 'python3', invRun });
  const call = (m, p, b, who) => e.req(m, p, Object.assign(b !== undefined ? { body: b } : {}, who));
  return { e, state, call, D: e.app.duty, I: e.app.addons.dbInventory, Q: e.app.addons.sqldba };
}
const open = (D) => D.list({ engineer: 'sqldba', status: 'open' }).items.concat(D.list({ engineer: 'sqldba', status: 'diagnosed' }).items);

test('the patrol opens one work item per problem; investigate gives the DBA statement; a fix is verified by a fresh read', async (t) => {
  const { D, I, state, call } = await setup(t);
  await I.pass(null);
  const r = await D.patrol('sqldba');
  assert.equal(r.opened, 2, JSON.stringify(r));
  const all = D.list({ engineer: 'sqldba' }).items;
  const titles = all.map((x) => x.title).join(' | ');
  assert.match(titles, /SQL-SYN-01 \(SQL Server\): ClaimsSyn: no full backup recorded in msdb/);
  assert.match(titles, /SQL-SYN-01 \(SQL Server\): ArchiveSyn is OFFLINE/);
  assert.ok(!/ORA-SYN-01|NOARCHIVELOG/.test(titles), 'Oracle stays with the AI Oracle DBA');
  assert.ok(all.every((x) => x.severity === 'high'), 'offline and no backup are high');
  const bk = all.find((x) => /no full backup/.test(x.title));
  assert.match(bk.recommendation, /BACKUP DATABASE \[ClaimsSyn\] TO DISK/);
  const inv = await D.investigate(bk.id, OP);
  const x = inv.investigation || inv;
  assert.ok(JSON.stringify(x).includes('Database ClaimsSyn') && /no full backup/.test(JSON.stringify(x)), 'the read-only checks name the database');
  // the DBA adds the backup: a fresh read of that one server shows it, the next patrol clears it
  state.claimsBackup = '2026-10-30T02:00:00';
  const v = await I.readOne('mssql|10.9.0.11|1433');
  assert.equal(v.databases.find((d) => d.name === 'ClaimsSyn').last_full, '2026-10-30T02:00:00Z');
  const p2 = await D.patrol('sqldba');
  assert.equal(p2.cleared, 1, JSON.stringify(p2));
  assert.equal(D.list({ engineer: 'sqldba' }).items.find((y) => y.id === bk.id).status, 'resolved');
  // a server the platform cannot read becomes a work item, never a silent pass
  state.pgFails = true; await I.pass({ user: 'nora.syn', role: 'operator' });
  const p3 = await D.patrol('sqldba');
  assert.equal(p3.opened, 1);
  assert.ok(D.list({ engineer: 'sqldba' }).items.some((y) => /PG-SYN-01: PostgreSQL cannot be read - login refused/.test(y.title)));
  // routes and roles
  let rr = await call('GET', '/sqldba', undefined, VIEW); assert.equal(rr.status, 403);
  rr = await call('GET', '/sqldba', undefined, OP); assert.equal(rr.status, 200);
  assert.equal(rr.json.connected, true); assert.ok(rr.json.findings.length >= 2); assert.equal(rr.json.servers.length, 2);
  assert.match(rr.json.note, /Recommends only/);
  rr = await call('GET', '/sqldba/ai/status', undefined, OP); assert.equal(rr.json.enabled, false); assert.match(rr.json.reason, /external AI is not allowed/);
  rr = await call('POST', '/sqldba/ai/ask', {}, OP); assert.equal(rr.status, 400); assert.match(rr.json.error, /question is required/);
  rr = await call('POST', '/sqldba/ai/ask', { question: 'why is ArchiveSyn offline?' }, OP); assert.equal(rr.status, 503, 'AI not allowed yet: a clear 503 with the reason');
  rr = await call('POST', '/sqldba/ai/ask', { question: 'why?' }, VIEW); assert.equal(rr.status, 403);
});

test('no proven login anywhere = not connected: nothing is opened or closed; readiness lists the engineer', async (t) => {
  const { D, call } = await setup(t, { empty: true });
  const r = await D.patrol('sqldba');
  assert.equal(r.opened, 0);
  const eng = (await D.engineersAuto()).find((x) => x.id === 'sqldba');
  assert.ok(eng, 'on the team'); assert.equal(eng.not_connected, true);
  const rd = await call('GET', '/duty/readiness', undefined, ADM);
  const me = rd.json.engineers.find((x) => x.id === 'sqldba');
  assert.ok(me && me.checks.some((c) => /no SQL Server \/ PostgreSQL \/ MySQL login proven yet/.test(c.detail)), 'readiness says what to connect');
});

test('playbook: an engine-specific statement for every kind, identifiers quoted', () => {
  assert.match(playbook('no-log-backup', 'mssql', 'A]B').fix, /BACKUP LOG \[A\]\]B\]/);
  assert.match(playbook('sessions', 'postgres').fix, /pg_stat_activity/);
  assert.match(playbook('sessions', 'mysql').fix, /SHOW PROCESSLIST/);
  for (const k of ['db-state', 'no-backup', 'old-backup', 'no-log-backup', 'sessions', 'deadlocks', 'repl-lag', 'login', 'stale']) assert.ok(playbook(k, 'mssql', 'x').fix.length > 20, k);
});
