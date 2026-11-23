// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Oracle tuning readings through the platform connection (engine/db-health.js + discovery/inv-helper.py + oracle-tuning.sql):
// Top SQL as per-interval deltas between two V$SQLSTATS snapshots (never the cumulative totals), the licence switch
// (Diagnostics Pack only with a recorded reason, sent to the helper as pack=true), the execution-plan route (sql_id
// validated, audited), records kept on one instance key when the instance reading is missing, SQL literals masked, and
// the kit queries identical to the SIEM collector kit's.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { startApp } = require('./helpers');
const { createDbHealth, SRC_ID } = require('../engine/db-health');
const { createSealer } = require('../engine/discovery/vault');

const HELPER = path.join(__dirname, '../engine/discovery/inv-helper.py');
const SQLF = path.join(__dirname, '../engine/discovery/oracle-tuning.sql');

function setup(e, helper) {
  const creds = [{ id: 'cr1', kind: 'db_login', label: 'oracle-ESS', target: { engine: 'oracle', port: 1521, service: 'ESS', tls: 'require' }, _s: { username: 'zyb_monitor', password: 'Synthetic-1' } }];
  const vault = { available: () => true, list: () => creds, get: (id) => creds.find((c) => c.id === id), create: () => { throw new Error('no'); }, open: (id) => { const c = creds.find((x) => x.id === id); return { target: c.target, secret: Object.assign({}, c._s), release() {} }; } };
  e.app.store.collection('db_health_targets').put({ id: 'odb_1', label: 'Eskauat', host: '192.168.9.30', port: 1521, service: 'ESS', cred_id: 'cr1', cred_label: 'oracle-ESS' });
  const sent = [];
  let t = Date.UTC(2026, 9, 20, 10, 0);
  const H = createDbHealth(e.app, { discovery: { vault, siem: { call: async () => ({ status: 200, json: { source: { id: SRC_ID }, token: 't1' } }) } },
    sealer: createSealer({ keyFile: e.app.config.discovery.vault_key_file, createKey: true, purpose: 'sentra-itam-db-health' }),
    invRun: helper, request: async (url, o) => { sent.push(...o.body.trim().split('\n').map((l) => JSON.parse(l))); return { status: 200 }; }, now: () => t });
  return { H, sent, tick: (ms) => { t += ms; } };
}

test('Top SQL deltas, licence switch, plan route, instance fallback', async (tt) => {
  const e = await startApp({ noAi: true }); tt.after(() => e.close());
  const calls = [];
  let snap = [{ sql_id: 'a1b2c3d4e5f6g', plan_hash: 111, executions: 100, elapsed_us: 5e6, cpu_us: 2e6, buffer_gets: 1000, disk_reads: 10, rows_processed: 100, sql_text: 'select * from t where id = :n', module: 'ERP', user: 'APP' }];
  const helper = async (r) => {
    calls.push(r);
    if (r.op === 'oracle_plan') return { ok: true, found: true, lines: ['SQL_ID a1b2c3d4e5f6g', 'Plan hash value: 111', '|  0 | SELECT STATEMENT |'] };
    return { ok: true, records: [{ kind: 'tablespace', name: 'USERS', used_pct: 40 }], errors: [{ query: 'instance', error: 'denied' }], sqlstats: snap, tuning: true, version: null };
  };
  const { H, sent, tick } = setup(e, helper);
  await H.pass();
  assert.ok(!sent.some((x) => x.kind === 'sql_delta'), 'first snapshot: nothing to compare yet - no invented numbers');
  assert.ok(sent.every((x) => x.instance === 'ESS'), 'no instance reading: every record on the service name, not an empty key');
  snap = [Object.assign({}, snap[0], { executions: 160, elapsed_us: 8e6, cpu_us: 3e6, buffer_gets: 1600, disk_reads: 16, rows_processed: 160 })];
  tick(240000); sent.length = 0;
  await H.pass();
  const d = sent.find((x) => x.kind === 'sql_delta');
  assert.ok(d, 'second pass: a delta');
  assert.equal(d.executions, 60); assert.equal(d.elapsed_s, 3); assert.equal(d.ela_ms_exec, 50); assert.equal(d.period_s, 240); assert.equal(d.rank, 1);
  assert.equal(calls.filter((c) => c.op === 'oracle_health').every((c) => c.pack === false && c.tuning === true), true, 'Diagnostics Pack off by default');

  // licence switch: reason required, then sent as pack=true
  assert.throws(() => H.setSettings({ diagnostics_pack: true }, { user: 'syed', role: 'admin' }), /who confirmed/);
  H.setSettings({ diagnostics_pack: true, note: 'Oracle CSI 1234567, Diagnostics Pack confirmed by procurement' }, { user: 'syed', role: 'admin' });
  tick(240000); await H.pass();
  assert.equal(calls.filter((c) => c.op === 'oracle_health').pop().pack, true);
  assert.ok(e.app.store.auditTail(50, (x) => x.action === 'db.health.settings').length >= 1);

  // plan route
  await assert.rejects(() => H.plan({ sql_id: 'drop table x' }, { user: 'siva' }), /13-character/);
  const p = await H.plan({ sql_id: 'a1b2c3d4e5f6g', host: '192.168.9.30' }, { user: 'siva', role: 'operator' });
  assert.equal(p.found, true); assert.match(p.lines[1], /Plan hash/);
  assert.equal(calls.find((c) => c.op === 'oracle_plan').tls, 'require', 'over the login\'s TLS');
  // routes: admin-only switch, a service identity refused
  const R = (m, pth, body, user, role) => e.req(m, pth, { body, user, role });
  require('../engine/db-health').registerDbHealth(e.app.srv, e.app, { invRun: helper });
  assert.equal((await R('POST', '/db-health/settings', { tuning: true }, 'siva', 'operator')).status, 403);
  assert.equal((await R('POST', '/db-health/settings', { tuning: true }, 'duty:dba', 'admin')).status, 403);
});

test('oracle-tuning.sql: kit blocks identical to the SIEM collector kit; literals masked by the helper', { skip: !fs.existsSync(path.resolve(__dirname, '../../siem/agents/oracle/collect-perf.sql')) && !process.env.SENTRA_SIEM_DIR && 'SIEM checkout not next to shield' }, () => {
  const kitDir = process.env.SENTRA_SIEM_DIR ? path.join(process.env.SENTRA_SIEM_DIR, 'agents/oracle') : path.resolve(__dirname, '../../siem/agents/oracle');
  const kit = fs.readFileSync(path.join(kitDir, 'collect-perf.sql'), 'utf8') + fs.readFileSync(path.join(kitDir, 'collect-pack.sql'), 'utf8');
  const src = fs.readFileSync(SQLF, 'utf8');
  const blocks = src.split(/\n(?=-- @(?:kit|pack|own|fallback) )/).filter((b) => /^-- @(kit|pack) /.test(b));
  assert.ok(blocks.length >= 11);
  for (const b of blocks) { const stmt = b.split('\n').filter((l) => !l.trim().startsWith('--')).join('\n').trim(); assert.ok(kit.includes(stmt), 'not identical to the kit: ' + b.split('\n')[0]); }
});

test('inv-helper: masking and the tuning file loader', { skip: spawnSync('python3', ['-c', '1']).status !== 0 && 'python3 missing' }, () => {
  const r = spawnSync('python3', ['-c', `
import importlib.util,json
s=importlib.util.spec_from_file_location('h', ${JSON.stringify(HELPER)}); h=importlib.util.module_from_spec(s); s.loader.exec_module(h)
q=h.load_tuning(${JSON.stringify(SQLF)})
print(json.dumps({"names":[x["name"]+":"+x["mode"] for x in q],"mask":h.mask_sql("update emp set sal = 5000 where name = 'Ahmed' and id = :b1")}))`]);
  const o = JSON.parse(r.stdout.toString());
  assert.ok(o.names.includes('sqlstats:own') && o.names.includes('pack_ash:pack') && o.names.includes('gg_apply:fallback'));
  assert.equal(o.mask, "update emp set sal = :n where name = ':s' and id = :b1");
});

test('inv-helper tuning_records against a fake cursor: pack skipped unless licensed, fallback on a failed reading, sqlstats apart', { skip: spawnSync('python3', ['-c', '1']).status !== 0 && 'python3 missing' }, () => {
  const r = spawnSync('python3', ['-c', `
import importlib.util,json
s=importlib.util.spec_from_file_location('h', ${JSON.stringify(HELPER)}); h=importlib.util.module_from_spec(s); s.loader.exec_module(h)
class Cur:
    def __init__(self): self.ran=[]; self.rows=[]
    def execute(self, sql, *a):
        k = sql.split("'kind' value '")[1].split("'")[0]
        self.ran.append(k)
        if k == 'gg_apply' and 'v$gg_apply_coordinator' in sql: raise Exception('ORA-00942: table or view does not exist')
        self.rows = {'sqlstats': [(json.dumps({"kind":"sqlstats","sql_id":"x","sql_text":"select 1 from t where n = 'Sara'"}),)],
                     'long_query': [(json.dumps({"kind":"long_query","sid":1,"sql_text":"select * from emp where id = 42"}),)],
                     'gg_apply': [(json.dumps({"kind":"gg_apply","name":"R1","status":"ENABLED"}),)]}.get(k, [])
    def fetchall(self): return self.rows
out = {}
for pack in (False, True):
    c=Cur(); errs=[]; recs, snap = h.tuning_records(c, heavy=False, pack=pack, errors=errs)
    out[str(pack)] = {"ran": c.ran, "kinds": [x["kind"] for x in recs], "snap": len(snap), "errs": errs, "texts": [x.get("sql_text") for x in recs+snap if x.get("sql_text")]}
print(json.dumps(out))`]);
  assert.equal(r.status, 0, r.stderr.toString());
  const o = JSON.parse(r.stdout.toString());
  assert.ok(!o.False.ran.includes('pack_ash') && o.True.ran.includes('pack_ash'), 'ASH only when the licence is confirmed');
  assert.ok(!o.False.ran.includes('stats_stale'), 'heavy scan not on a light pass');
  assert.deepEqual(o.False.kinds.filter((k) => k === 'gg_apply'), ['gg_apply'], 'the fallback produced the reading');
  assert.deepEqual(o.False.errs, [], 'a reading saved by its fallback is not reported missing');
  assert.equal(o.False.snap, 1);
  assert.ok(o.False.texts.every((t) => !/Sara|42/.test(t)), 'literals masked: ' + o.False.texts.join(' | '));
});

// Bulk deletes (DBA alerts): rows each DELETE statement removed since the previous pass, from V$SQL command type 7. A cursor not
// seen before counts in full (new or reloaded); the first pass is a baseline; SQL statistics are not mixed with delete counters.
test('bulk deletes: per-pass rows deleted per DELETE statement, new cursor counted in full, table named, baseline first', async (tt) => {
  const e = await startApp({ noAi: true }); tt.after(() => e.close());
  const top = { kind: 'sqlstats', sql_id: 'a1b2c3d4e5f6g', plan_hash: 1, executions: 10, elapsed_us: 1e6, cpu_us: 1e6, buffer_gets: 10, disk_reads: 1, rows_processed: 10, sql_text: 'select 1 from dual' };
  let snap = [top, { kind: 'delstats', sql_id: 'd1d1d1d1d1d1d', plan_hash: 5, rows_processed: 500, executions: 2, user: 'APP', module: 'purge', sql_text: 'delete from app.claims_hist where created < :1' }];
  const helper = async (r) => (r.op === 'oracle_plan' ? { ok: true } : { ok: true, records: [{ kind: 'instance', instance: 'ESS', role: 'PRIMARY' }], errors: [], sqlstats: snap, tuning: true });
  const { H, sent, tick } = setup(e, helper);
  await H.pass();
  assert.ok(!sent.some((x) => x.kind === 'bulk_delete'), 'first pass: baseline only');
  snap = [Object.assign({}, top, { executions: 20 }),
    { kind: 'delstats', sql_id: 'd1d1d1d1d1d1d', plan_hash: 5, rows_processed: 20500, executions: 3, user: 'APP', module: 'purge', sql_text: 'delete from app.claims_hist where created < :1' },
    { kind: 'delstats', sql_id: 'n2n2n2n2n2n2n', plan_hash: 9, rows_processed: 3000, executions: 1, user: 'BATCH', sql_text: 'DELETE /*+ parallel */ "APP"."ORDERS" where status = :1' }];
  tick(300000); sent.length = 0;
  await H.pass();
  const del = sent.filter((x) => x.kind === 'bulk_delete');
  const a = del.find((x) => x.sql_id === 'd1d1d1d1d1d1d'), b = del.find((x) => x.sql_id === 'n2n2n2n2n2n2n');
  assert.equal(a.rows_deleted, 20000); assert.equal(a.executions, 1); assert.equal(a.table, 'APP.CLAIMS_HIST'); assert.equal(a.period_s, 300); assert.equal(a.new_cursor, false);
  assert.equal(b.rows_deleted, 3000); assert.equal(b.new_cursor, true, 'a new cursor counts in full'); assert.equal(b.table, 'APP.ORDERS');
  assert.ok(del[0].rows_deleted >= del[1].rows_deleted, 'largest first');
  assert.ok(sent.some((x) => x.kind === 'sql_delta' && x.sql_id === 'a1b2c3d4e5f6g') && !sent.some((x) => x.kind === 'sql_delta' && x.sql_id === 'd1d1d1d1d1d1d'), 'delete counters do not leak into Top SQL');
  // nothing more deleted: no record (no invented zeros)
  tick(300000); sent.length = 0; await H.pass();
  assert.ok(!sent.some((x) => x.kind === 'bulk_delete'));
});

test('oracle-tuning.sql: the DBA alert readings exist, read-only, Oracle\'s own schemas left out', () => {
  const src = fs.readFileSync(SQLF, 'utf8');
  for (const k of ['sched_jobs', 'delstats', 'code_change', 'code_change_by', 'rac_nodes', 'app_sessions', 'lsnr_conns', 'db_links', 'user_write']) assert.match(src, new RegExp('-- @own ' + k + '\\n'), k);
  const own = src.split(/\n(?=-- @)/).filter((b) => /^-- @own (sched_jobs|delstats|code_change|code_change_by|app_sessions|lsnr_conns|db_links|user_write)\n/.test(b));
  for (const b of own) {
    assert.doesNotMatch(b.replace(/^--.*$/gm, ''), /\b(insert|update|delete\s+from|merge|alter|drop|create|grant|truncate|execute)\b(?![^']*')/i, 'select only: ' + b.slice(0, 40));
  }
  assert.match(src, /oracle_maintained = 'Y'/); assert.match(src, /command_type = 7/);
});
