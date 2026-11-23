// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Our own engines (engine/db-replicate.js): Data Verify end to end through the REAL helper and db_repl.py against a real
// PostgreSQL (when the binaries are there), repair proposals and replication approvals with four eyes (never the requester,
// never a service / AI identity, an administrator or a named eng:dba approver), Change Stream cycles (metadata to the SIEM,
// a log gap stops the job), Replication cycles (conflict stops it, resuming needs a note), setup scripts, audit.
const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { startApp } = require('./helpers');
const { startPg } = require('./_pg');
const { createReplicate } = require('../engine/db-replicate');

function vaultStub() {
  const creds = [];
  return { creds, list: () => creds, get: (id) => creds.find((c) => c.id === id), create: (b) => { const c = Object.assign({ id: 'cr' + (creds.length + 1) }, b, { _s: b.secret }); delete c.secret; creds.push(c); return c; },
    open: (id) => { const c = creds.find((x) => x.id === id); return { target: c.target, secret: Object.assign({}, c._s), release() {} }; } };
}
const ADM = { user: 'syed', role: 'admin' }, ADM2 = { user: 'rasheed', role: 'admin' }, OP = { user: 'siva', role: 'operator' };

test('Data Verify end to end on a real PostgreSQL, through the real helper', async (tt) => {
  const { spawnSync } = require('node:child_process');
  if (spawnSync('python3', ['-c', 'import pg8000']).status !== 0) { tt.skip('pg8000 not installed'); return; }
  const pg = startPg(); if (pg.skip) { tt.skip(pg.skip); return; }
  tt.after(() => pg.stop());
  const sql = (q) => { const r = spawnSync('psql', ['-h', '127.0.0.1', '-p', String(pg.port), '-U', 'zybsu', '-d', 'postgres', '-v', 'ON_ERROR_STOP=1', '-q', '-c', q], { encoding: 'utf8' }); if (r.status !== 0) throw new Error(r.stderr); };
  for (const q of ['create schema a', 'create schema b', 'create table a.cust (id int primary key, name text, bal numeric(12,2))', 'create table b.cust (id int primary key, name text, bal numeric)',
    "insert into a.cust select g, 'n'||g, g*1.5 from generate_series(1,2500) g", 'insert into b.cust select * from a.cust', "update b.cust set name = 'x' where id = 1234", 'delete from b.cust where id = 99',
    "create role zyb_verify login password 'Verify-Pw-1'", 'grant usage on schema a, b to zyb_verify', 'grant select on a.cust, b.cust to zyb_verify']) sql(q);
  const e = await startApp({ noAi: true }); tt.after(() => e.close());
  const V = vaultStub(), pushed = [];
  const R = createReplicate(e.app, { discovery: { vault: V }, dbHealth: { push: async (r) => { pushed.push(...r); return r.length; } }, invRun: require('../engine/discovery/methods/login').realRunner('python3', 120000), later: (fn) => setImmediate(fn) });
  const side = (schema) => ({ engine: 'postgres', host: '127.0.0.1', port: pg.port, database: 'postgres', username: 'zyb_verify', password: 'Verify-Pw-1', label: schema });
  const j = R.create({ type: 'verify', name: 'cust copy', src: side('a'), tgt: side('b'), tables: [{ owner: 'a', table: 'cust', tgt_owner: 'b', tgt_table: 'cust' }], chunk: 1000, recheck_s: 10 }, ADM);
  assert.equal(V.creds.length, 2, 'the two logins are sealed in the vault'); assert.ok(!JSON.stringify(e.app.store.collection('repl_jobs').get(j.id)).includes('Verify-Pw-1'), 'no password in the job');
  const run = await R.runVerify(j.id, ADM);
  for (let i = 0; i < 200 && e.app.store.collection('repl_runs').get(run.id).state !== 'done'; i++) await new Promise((r) => setTimeout(r, 100));
  const done = e.app.store.collection('repl_runs').get(run.id);
  assert.equal(done.state, 'done', done.error); const t = done.tables[0];
  assert.equal(t.rows, 2500); assert.equal(t.missing_n, 1); assert.equal(t.different_n, 1); assert.equal(t.extra_n, 0); assert.equal(done.in_sync, false);
  assert.deepEqual(t.missing, [[99]]); assert.deepEqual(t.different, [[1234]]);
  assert.ok(pushed.some((x) => x.kind === 'verify_result' && x.in_sync === false && x.missing === 1 && x.different === 1));
  // repair: four eyes
  const p = R.proposeRepair({ run: run.id, table: 'a.cust' }, OP);
  assert.match(p.fix_sql, /id=99/); assert.match(p.fix_sql, /id=1234/);
  const allow = () => true, deny = () => { throw Object.assign(new Error('approving needs an administrator or a named approver'), { status: 403 }); };
  assert.throws(() => R.decideRepair(p.id, { decision: 'approve' }, OP, allow), /four eyes/);
  assert.throws(() => R.decideRepair(p.id, { decision: 'approve' }, { user: 'ai:dba', role: 'admin' }, allow), /service \/ AI identity/);
  assert.throws(() => R.decideRepair(p.id, { decision: 'approve' }, { user: 'kumar', role: 'operator' }, deny), /named approver/);
  assert.throws(() => R.decideRepair(p.id, { decision: 'reject' }, ADM, allow), /needs a reason/);
  assert.equal(R.decideRepair(p.id, { decision: 'approve' }, ADM, allow).status, 'approved');
  assert.throws(() => R.decideRepair(p.id, { decision: 'done' }, OP, allow), /what was run/);
  assert.equal(R.decideRepair(p.id, { decision: 'done', note: 'copied row 99, fixed 1234; re-compared in sync' }, OP, allow).status, 'done');
  assert.ok(e.app.store.auditTail(50, (x) => /^db\.repl\./.test(x.action)).length >= 4);
});

test('Change Stream and Replication: cycles, approvals, stops and resumes, SIEM records, setup scripts', async (tt) => {
  const e = await startApp({ noAi: true }); tt.after(() => e.close());
  const V = vaultStub(), pushed = [], calls = [];
  let mode = 'ok';
  const helper = async (r) => {
    calls.push(r);
    if (r.op === 'logminer_read') {
      if (!r.cursor) return { ok: true, txns: [], cursor: { commit_scn: 1000, restart_scn: 1000 }, info: { started: true } };
      if (mode === 'gap') return { ok: true, txns: [], cursor: r.cursor, info: { gap: 'the logs needed from SCN 1000 are no longer on disk' } };
      return { ok: true, cursor: { commit_scn: 2000, restart_scn: 1900 }, info: { lag_s: 12, files: 2, open_transactions: 1 },
        txns: [{ xid: 'X1', commit_scn: 1500, commit_ts: '2026-10-20T21:30:00', user: 'SCOTT', os_user: 'scott', machine: 'pc-17', program: 'sqlplus@pc-17', rows: 25000, tables: { 'APP.ORDERS': { INSERT: 0, UPDATE: 0, DELETE: 25000 } }, ddl: [] },
          { xid: 'X2', commit_scn: 1600, commit_ts: '2026-10-20T21:31:00', user: 'APP', os_user: 'app', machine: 'erp1', program: 'JDBC', rows: 0, tables: {}, ddl: [{ table: 'APP.ORDERS', sql: 'truncate table "APP"."ORDERS"' }] }] };
    }
    if (r.op === 'repl_status') return { ok: true, source: { current_scn: 5000, supplemental_min: 'YES', tables: [{ table: 'APP.ORDERS', pk_logging: true, pk: ['ORDER_ID'] }] }, checkpoint: { commit_scn: 4000, restart_scn: 4000 } };
    if (r.op === 'repl_cycle') return mode === 'conflict' ? { ok: true, stats: { txns: 3, rows: 10, conflicts: [] }, stopped: { reason: 'conflict', table: 'APP.ORDERS', op: 'UPDATE', detail: 'row not found on the target', key: { ORDER_ID: '77' } }, info: { lag_s: 40 } }
      : { ok: true, stats: { txns: 12, rows: 80, conflicts: [], last_commit_ts: '2026-10-20T21:59:00' }, stopped: null, info: { lag_s: 8 }, cursor: { commit_scn: 4500, restart_scn: 4500 } };
    return { ok: false, error_class: 'error', error: 'unexpected op ' + r.op };
  };
  const R = createReplicate(e.app, { discovery: { vault: V }, dbHealth: { push: async (r) => { pushed.push(...r); return r.length; } }, invRun: helper, later: (fn) => setImmediate(fn) });
  const ora = (u) => ({ engine: 'oracle', host: '192.168.9.30', port: 1521, service: 'ESS', username: u, password: 'Pw-' + u, label: 'ESS' });

  // Change Stream
  const cs = R.create({ type: 'stream', name: 'ESS audit', src: ora('zyb_miner'), owners: 'app, hr', mass_rows: 1000 }, ADM);
  assert.deepEqual(cs.owners, ['APP', 'HR']); assert.equal(cs.state, 'stopped');
  await R.start(cs.id, {}, ADM); await new Promise((r) => setImmediate(r));
  assert.deepEqual(R.get(cs.id).cursor, { commit_scn: 1000, restart_scn: 1000 }, 'first cycle: starts at the current SCN, no backlog');
  await R.streamCycle(R.get(cs.id));
  const j2 = R.get(cs.id); assert.deepEqual(j2.cursor, { commit_scn: 2000, restart_scn: 1900 }); assert.equal(j2.last_cycle.txns, 2);
  const txn = pushed.filter((x) => x.kind === 'change_txn');
  assert.equal(txn.length, 2); assert.equal(txn[0].deletes, 25000); assert.equal(txn[0].mass, true); assert.equal(txn[0].instance, 'ESS'); assert.match(txn[1].ddl, /truncate/);
  assert.equal(R.changes(cs.id).items.length, 2);
  mode = 'gap'; await R.streamCycle(R.get(cs.id));
  assert.equal(R.get(cs.id).state, 'stopped'); assert.equal(R.get(cs.id).stopped.reason, 'gap'); R.stopTimer(cs.id);
  assert.ok(pushed.some((x) => x.kind === 'change_stream' && x.reason === 'gap'));

  // Replication
  assert.throws(() => R.create({ type: 'replicate', name: 'x', src: ora('m'), tgt: ora('w'), tables: [{ owner: 'APP', table: 'ORDERS' }] }, ADM), /target is the source table itself/);
  mode = 'ok';
  const rp = R.create({ type: 'replicate', name: 'ESS to reporting', src: ora('zyb_miner'), tgt: { engine: 'postgres', host: '10.5.5.5', port: 5432, database: 'rep', username: 'zyb_writer', password: 'W-pw', label: 'REP' }, tables: [{ owner: 'APP', table: 'ORDERS' }] }, ADM);
  assert.equal(rp.state, 'draft'); assert.deepEqual(rp.checkpoint, ['app', 'zyb_repl_checkpoint']); assert.equal(rp.tables[0].tgt_table, 'orders');
  await assert.rejects(() => R.start(rp.id, {}, ADM), /only after another person approved/);
  assert.throws(() => R.approve(rp.id, {}, ADM2, () => true), /primary key/);
  const st = await R.status(rp.id); assert.equal(st.source.current_scn, 5000); assert.deepEqual(R.get(rp.id).tables[0].pk, ['ORDER_ID'], 'draft takes the primary key the dictionary reports');
  assert.throws(() => R.approve(rp.id, {}, ADM, () => true), /four eyes: you created/);
  assert.throws(() => R.approve(rp.id, {}, { user: 'svc:sync', role: 'admin' }, () => true), /service \/ AI identity/);
  assert.equal(R.approve(rp.id, { note: 'CHG-2231' }, ADM2, () => true).state, 'approved');
  await R.start(rp.id, {}, ADM); await new Promise((r) => setImmediate(r));
  assert.equal(R.get(rp.id).state, 'running'); assert.equal(R.get(rp.id).totals.rows, 80);
  mode = 'conflict'; await R.replCycle(R.get(rp.id));
  const sj = R.get(rp.id); assert.equal(sj.state, 'stopped'); assert.equal(sj.stopped.reason, 'conflict'); assert.deepEqual(sj.stopped.key, { ORDER_ID: '77' }); R.stopTimer(rp.id);
  assert.ok(pushed.some((x) => x.kind === 'repl_status' && x.state === 'stopped' && x.reason === 'conflict'));
  await assert.rejects(() => R.start(rp.id, {}, ADM), /say what was done/);
  mode = 'ok'; await R.start(rp.id, { note: 'row 77 copied from the source (REPAIR-0001), resuming' }, ADM); R.stopTimer(rp.id);
  assert.equal(R.get(rp.id).state, 'running'); assert.match(R.get(rp.id).resumed.note, /row 77/);
  assert.equal(R.stop(rp.id, {}, ADM).state, 'paused');
  // setup scripts: object grants only, supplemental logging per table, checkpoint + instantiation
  const s = R.setup(rp.id);
  assert.match(s.source, /ADD SUPPLEMENTAL LOG DATA \(PRIMARY KEY\) COLUMNS/); assert.match(s.source, /GRANT CREATE SESSION, LOGMINING TO zyb_miner/);
  assert.match(s.target, /CREATE TABLE app\.zyb_repl_checkpoint/); assert.match(s.target, /GRANT SELECT, INSERT, UPDATE, DELETE ON app\.orders TO zyb_writer/);
  assert.match(s.instantiate, new RegExp(`VALUES \\('${rp.id}', <SCN>, <SCN>\\)`));
  assert.ok(!/GRANT DBA|ANY TABLE/.test(s.source + s.target), 'no broad grants');
  assert.ok(e.app.store.auditTail(80, (x) => x.action === 'db.repl.approved').length === 1);
});
