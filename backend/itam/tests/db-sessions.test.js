// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Long-Running Queries (engine/db-sessions.js): live read with the read-only login, impact in plain words (blockers first),
// the session-control login tested before it is kept (more than CREATE SESSION = refused), a request needs a reason and a
// session from a fresh read, four-eyes (never the requester, never a service identity, a DBA approver or admin), cancel /
// kill sent with the approved user and SQL_ID through the control login only, the database's answer recorded, expiry.
// The Oracle helper is a fake; data is SYNTHETIC.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { createDbSessions, REQ_TTL_MS } = require('../engine/db-sessions');

const SESS = [
  { inst_id: 1, sid: 101, serial: 5001, username: 'APP_ERP', status: 'ACTIVE', elapsed_s: 5400, state: 'WAITING', event: 'db file scattered read', sql_id: 'abcd1234efgh5', sql_text: 'select * from gl_lines where amount > :n', blocks: 0, temp_mb: 3072, machine: 'erp-app1' },
  { inst_id: 1, sid: 202, serial: 7002, username: 'HR_BATCH', status: 'INACTIVE', elapsed_s: 900, state: 'WAITING', event: 'SQL*Net message from client', sql_id: '', blocks: 4, machine: 'hr-job' },
  { inst_id: 2, sid: 303, serial: 9003, username: 'REPORTS', status: 'ACTIVE', elapsed_s: 120, state: 'ON CPU', sql_id: 'zzzz1234yyyy9', blocks: 0, blocked_by: 202, blocked_by_inst: 1 }];

function setup(e) {
  const calls = [], opened = [];
  let ctlAnswer = { ok: true, result: 'DONE: statement cancelled' }, ctlTest = { ok: true };
  const creds = new Map([['c1', { id: 'c1', kind: 'db_login', label: 'ORA-RO', target: { engine: 'oracle', port: 1521, service: 'PROD', tls: 'require' }, secret: { username: 'zyb_monitor', password: 'Mon-1' } }]]);
  const vault = {
    list: () => [...creds.values()], get: (id) => creds.get(id),
    open: (id) => { opened.push(id); const c = creds.get(id); return { secret: c.secret, target: c.target, release() {} }; },
    create: (b) => { const id = 'c' + (creds.size + 1); creds.set(id, Object.assign({ id }, b)); return { id, label: b.label }; },
    remove: (id) => { creds.delete(id); return { removed: id }; },
  };
  const H = { targets: () => ({ list: [{ key: 'reg:odb1', reg_id: 'odb1', ip: '10.0.0.5', host: 'ESS-PROD', cred_id: 'c1', port: 1521, service: 'PROD' }] }) };
  let clock = Date.parse('2026-10-21T08:00:00Z');
  const S = createDbSessions(e.app, { dbHealth: H, discovery: { vault }, now: () => clock,
    invRun: async (r) => { calls.push(r); if (r.op === 'oracle_long') return { ok: true, min_s: r.min_s, sessions: JSON.parse(JSON.stringify(SESS)) }; if (r.op === 'oracle_ctl_test') return ctlTest; if (r.op === 'oracle_ctl') return ctlAnswer; return { ok: false, error: 'op?' }; } });
  return { S, calls, opened, creds, tick: (ms) => { clock += ms; }, setCtl: (a) => { ctlAnswer = a; }, setTest: (a) => { ctlTest = a; } };
}
const ALI = { user: 'ali', role: 'operator', ip: '10.1.1.2' }, AHMED = { user: 'ahmed', role: 'operator', ip: '10.1.1.3' }, ADMIN = { user: 'syed', role: 'admin', ip: '10.1.1.1' };

test('long queries: read, impact, control login, four-eyes cancel / kill', async (t) => {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  const { S, calls, opened, creds, tick, setCtl, setTest } = setup(e);
  // a DBA approver role for ahmed (Roles & Functions)
  if (e.app.roles && e.app.roles.save) { /* real roles engine may not expose save; fall back below */ }
  const r = await S.readLong({ db: 'reg:odb1', min_s: 60 }, ALI);
  assert.equal(calls[0].op, 'oracle_long'); assert.equal(calls[0].username, 'zyb_monitor', 'read with the monitoring login'); assert.equal(calls[0].tls, 'require');
  assert.deepEqual(r.sessions.map((x) => x.sid), [202, 101, 303], 'the blocker first');
  assert.match(r.sessions[0].why.join('; '), /blocks 4 other sessions; idle but holding locks/);
  assert.match(r.sessions[1].why.join('; '), /running for 1\.5 h; 3 GB of TEMP; waiting on db file scattered read/);
  assert.match(r.sessions[2].why.join('; '), /itself blocked by SID 202 @1/);
  assert.deepEqual(r.totals, { sessions: 3, blockers: 1, blocked: 4, over_1h: 1 });

  // control login: tested first; more than CREATE SESSION is refused
  setTest({ ok: false, error_class: 'unsafe', error: 'holds more than CREATE SESSION (DBA)' });
  await assert.rejects(S.setControl({ db: 'reg:odb1', username: 'system', password: 'x' }, ADMIN), /not saved: holds more than CREATE SESSION/);
  setTest({ ok: true });
  await assert.rejects(S.setControl({ db: 'reg:odb1', username: 'zyb_control', password: 'Ctl-1' }, { user: 'system:x', role: 'admin' }), /only a person/);
  const L = await S.setControl({ db: 'reg:odb1', username: 'zyb_control', password: 'Ctl-1' }, ADMIN);
  assert.equal(L.databases[0].control.ok, true); assert.ok([...creds.values()].some((c) => c.secret && c.secret.username === 'zyb_control' && c.target.tls === 'require'), 'sealed in the vault, same TLS as the monitoring login');

  // requests
  assert.throws(() => S.request({ db: 'reg:odb1', inst_id: 1, sid: 101, serial: 5001, mode: 'cancel' }, ALI), /say why/);
  assert.throws(() => S.request({ db: 'reg:odb1', inst_id: 1, sid: 999, serial: 1, mode: 'kill', reason: 'x' }, ALI), /not in the last read/);
  assert.throws(() => S.request({ db: 'reg:odb1', inst_id: 1, sid: 202, serial: 7002, mode: 'cancel', reason: 'x' }, ALI), /not running a statement/);
  const q1 = S.request({ db: 'reg:odb1', inst_id: 1, sid: 101, serial: 5001, mode: 'cancel', reason: 'full scan of GL for 90 min, users waiting' }, ALI);
  assert.deepEqual([q1.status, q1.session.username, q1.session.sql_id], ['pending', 'APP_ERP', 'abcd1234efgh5']);
  assert.throws(() => S.request({ db: 'reg:odb1', inst_id: 1, sid: 101, serial: 5001, mode: 'kill', reason: 'again' }, ALI), /already waiting/);

  const before = calls.length;
  await assert.rejects(S.decide(q1.id, { decision: 'approve' }, Object.assign({}, ALI, { role: 'admin' })), /does not approve their own/);
  await assert.rejects(S.decide(q1.id, { decision: 'approve' }, { user: 'ai:dba', role: 'admin' }), /never a service or AI identity/);
  await assert.rejects(S.decide(q1.id, { decision: 'approve' }, { user: 'viewer1', role: 'viewer' }), /DBA approver/);
  assert.equal(calls.length, before, 'nothing reached the database before approval');
  const d1 = await S.decide(q1.id, { decision: 'approve', comment: 'ok' }, ADMIN);
  const c = calls[calls.length - 1];
  assert.deepEqual([c.op, c.mode, c.sid, c.serial, c.inst_id, c.target_user, c.sql_id, c.username, c.ref], ['oracle_ctl', 'cancel', 101, 5001, 1, 'APP_ERP', 'abcd1234efgh5', 'zyb_control', q1.id], 'sent through the control login with the approved user and SQL_ID');
  assert.deepEqual([d1.status, d1.decided_by, d1.result], ['done', 'syed', 'DONE: statement cancelled']);

  // kill of the idle blocker: no SQL_ID check (it runs nothing); the database says the session changed hands
  await S.readLong({ db: 'reg:odb1' }, ALI);
  const q2 = S.request({ db: 'reg:odb1', inst_id: 1, sid: 202, serial: 7002, mode: 'kill', reason: 'idle with locks, 4 sessions stuck' }, ALI);
  setCtl({ ok: true, result: 'REFUSED: the session now belongs to SCOTT, not HR_BATCH' });
  const d2 = await S.decide(q2.id, { decision: 'approve' }, ADMIN);
  assert.equal(calls[calls.length - 1].sql_id, ''); assert.equal(d2.status, 'refused');
  // reject needs a reason; expiry
  await S.readLong({ db: 'reg:odb1' }, ALI);
  const q3 = S.request({ db: 'reg:odb1', inst_id: 2, sid: 303, serial: 9003, mode: 'cancel', reason: 'report' }, ALI);
  await assert.rejects(S.decide(q3.id, { decision: 'reject' }, ADMIN), /say why/);
  tick(REQ_TTL_MS + 1000);
  assert.equal(S.requests().items.find((x) => x.id === q3.id).status, 'expired');
  await assert.rejects(S.decide(q3.id, { decision: 'approve' }, ADMIN), /already expired/);
  assert.throws(() => S.request({ db: 'reg:odb1', inst_id: 1, sid: 101, serial: 5001, mode: 'cancel', reason: 'x' }, ALI), /read the database again/);
  assert.ok(opened.filter((x) => x === 'c1').length >= 3 && opened.some((x) => x !== 'c1'), 'monitoring login for reads, the control login only to act');
  const acts = [];
  // removing session control: nothing can be done afterwards
  S.removeControl({ db: 'reg:odb1' }, ADMIN);
  await S.readLong({ db: 'reg:odb1' }, ALI);
  const q4 = S.request({ db: 'reg:odb1', inst_id: 1, sid: 101, serial: 5001, mode: 'kill', reason: 'x' }, ALI);
  await assert.rejects(S.decide(q4.id, { decision: 'approve' }, ADMIN), /session control is not set up/);
  assert.equal(acts.length, 0);
});

test('long queries: a database / helper / login failure is explained (4xx with the reason), never a bare "internal error"', async (t) => {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  const vault = { open: () => { throw Object.assign(new Error('credential c9 not found'), { status: 404 }); } };
  const mk = (targets, invRun, v) => createDbSessions(e.app, { dbHealth: { targets: () => ({ list: targets }) }, discovery: { vault: v || { open: () => ({ secret: { username: 'u', password: 'p' }, release() {} }) } }, invRun });
  const T = { key: 'reg:x', ip: '10.0.0.9', host: 'ESS', port: 1521, service: 'P', cred_id: 'c1' };
  const st = async (p) => { try { await p; return null; } catch (err) { return err; } };
  let err = await st(mk([T], async () => { throw new Error('spawn python3 ENOENT'); }).readLong({ db: 'reg:x' }, ALI));
  assert.equal(err.status, 424); assert.match(err.message, /helper did not run \(spawn python3 ENOENT\)/);
  err = await st(mk([T], async () => ({ ok: false, error: 'ORA-12541: TNS:no listener' })).readLong({ db: 'reg:x' }, ALI));
  assert.equal(err.status, 424); assert.match(err.message, /did not answer the session read: ORA-12541/);
  err = await st(mk([Object.assign({}, T, { cred_id: '' })], async () => ({ ok: true, sessions: [] })).readLong({ db: 'reg:x' }, ALI));
  assert.equal(err.status, 424); assert.match(err.message, /no saved monitoring login/);
  err = await st(mk([T], async () => ({ ok: true, sessions: [] }), vault).readLong({ db: 'reg:x' }, ALI));
  assert.equal(err.status, 424); assert.match(err.message, /removed - save it again/);
  const noH = createDbSessions(e.app, { discovery: { vault }, invRun: async () => ({}) });
  assert.throws(() => noH.list(), (x) => x.status === 424 && /Database Health is not installed/.test(x.message));
});
