// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Oracle Tuning (engine/db-audit/tuning.js): findings from the collected readings (GoldenGate down / lagging, a plan
// change 2x slower -> SQL plan baseline with its rollback, stale statistics -> gather / restore, ORA-01555 -> undo
// retention with the previous value as rollback), the AI proposal in its fixed shape from a fake model that sees only the
// readings, a proposal with data-changing SQL refused, and the approval trail: a person, an admin or a named eng:dba
// approver, never the requester, a rejection with a reason, done / failed with what was run.
const test = require('node:test');
const assert = require('node:assert/strict');
const { createTuning, findingsFrom } = require('../engine/db-audit/tuning');

const NOW = Date.UTC(2026, 9, 20, 12, 0);
function fakeState() {
  const cols = {};
  return { collection: (n) => { const m = cols[n] || (cols[n] = new Map()); return { get: (id) => m.get(id) || null, put: (r) => m.set(r.id, JSON.parse(JSON.stringify(r))), all: (f) => [...m.values()].filter((x) => !f || f(x)) }; } };
}
const ev = (action, f) => ({ src_type: 'oracle-health', action, ts: NOW - 60000, host: 'eskauat', fields: Object.assign({ instance: 'ESS' }, f) });

test('findings, scripts, refusal, approval trail, AI proposal', async () => {
  const state = fakeState(), seen = [];
  const sdk = function () { return { messages: { create: async (p) => { seen.push(p); return { model: 'claude-opus-5-5', content: [{ type: 'text', text: JSON.stringify({ title: 'Index the join column', problem: 'Full scan of ORDERS', evidence: ['TABLE ACCESS FULL ORDERS'], recommendation: 'Review an index on ORDERS(CUSTOMER_ID)', fix_sql: 'CREATE INDEX app.orders_cust_ix ON app.orders(customer_id) ONLINE;', rollback_sql: 'DROP INDEX app.orders_cust_ix;', verify_sql: 'SELECT index_name FROM dba_indexes WHERE index_name = \'ORDERS_CUST_IX\';', risk: 'medium', needs_change_window: false, expected_benefit: 'fewer reads', confidence: 'medium' }) }] }; } } }; };
  const T = createTuning({ state, config: { secrets: { netops: { anthropic_api_key: 'sk-ant-synthetic' } } }, now: () => NOW, sdk });
  T.stage(ev('gg-apply', { key: 'RPROD', status: 'ABORTED', error: 'ORA-01403' }));
  T.stage(ev('gg-capture', { key: 'EPROD', status: 'ENABLED', lag_s: '2400' }));
  T.stage(ev('plan-change', { key: 'a1b2c3d4e5f6g', sql_id: 'a1b2c3d4e5f6g', old_plan: '1111', new_plan: '2222', old_ms_exec: '4', new_ms_exec: '40', ratio: '10' }));
  T.stage(ev('stale-statistics', { key: 'APP.ORDERS', owner: 'APP', table_name: 'ORDERS', num_rows: '5000000' }));
  T.stage(ev('stale-statistics', { key: 'APP.TINY', owner: 'APP', table_name: 'TINY', num_rows: '50' }));
  T.stage(ev('temp-undo', { ora1555_1h: '3', maxquerylen_s: '4000', undo_retention_s: '900' }));
  T.stage(ev('wait-event', { key: 'log file sync', avg_ms: '25', waits_s: '400' }));
  const v = await T.view({ instance: 'ESS' });
  const keys = v.findings.map((f) => f.key);
  assert.equal(v.findings[0].severity, 'critical'); assert.match(v.findings[0].title, /Replicat RPROD is ABORTED/);
  assert.ok(keys.includes('gg-capture:EPROD:lag') && keys.includes('plan:a1b2c3d4e5f6g') && keys.includes('stats:APP.ORDERS') && keys.includes('undo') && keys.includes('wait:lfs'));
  assert.ok(!keys.includes('stats:APP.TINY'), 'a tiny table is not worth a finding');
  const plan = v.findings.find((f) => f.key === 'plan:a1b2c3d4e5f6g');
  assert.match(plan.fix.sql, /LOAD_PLANS_FROM_CURSOR_CACHE\(sql_id => 'a1b2c3d4e5f6g', plan_hash_value => 1111/); assert.match(plan.fix.rollback, /DROP_SQL_PLAN_BASELINE/);
  const undo = v.findings.find((f) => f.key === 'undo');
  assert.match(undo.fix.sql, /undo_retention = 4800/); assert.match(undo.fix.rollback, /undo_retention = 900/);
  assert.equal(v.goldengate.length, 2); assert.equal(v.stale_statistics[0].table, 'ORDERS');

  // a rule finding becomes a proposal; approval rules
  const p = await T.proposeFromFinding({ instance: 'ESS', finding_key: 'stats:APP.ORDERS' }, { user: 'siva', role: 'operator' });
  assert.equal(p.status, 'proposed'); assert.match(p.fix_sql, /GATHER_TABLE_STATS/); assert.match(p.rollback_sql, /RESTORE_TABLE_STATS/);
  assert.throws(() => T.decide(p.id, { decision: 'approve' }, { user: 'duty:dba', role: 'admin' }), /service \/ AI identity/);
  assert.throws(() => T.decide(p.id, { decision: 'approve' }, { user: 'rasheed', role: 'operator' }, { state }), /named approver/);
  assert.throws(() => T.decide(p.id, { decision: 'approve' }, { user: 'siva', role: 'admin' }), /four eyes/);
  assert.throws(() => T.decide(p.id, { decision: 'done', note: 'x' }, { user: 'syed', role: 'admin' }), /proposed, not approved/);
  state.collection('approvers').put({ id: 'map', scopes: { 'eng:dba': ['rasheed'] } });
  const ap = T.decide(p.id, { decision: 'approve' }, { user: 'rasheed', role: 'operator' }, { state });
  assert.equal(ap.status, 'approved'); assert.equal(ap.approve_by, 'rasheed');
  assert.throws(() => T.decide(p.id, { decision: 'done' }, { user: 'rasheed', role: 'operator' }), /what was run/);
  const dn = T.decide(p.id, { decision: 'done', note: 'gathered 21:00, plan back to 1111, 4 ms/exec' }, { user: 'rasheed', role: 'operator' });
  assert.equal(dn.status, 'done'); assert.deepEqual(dn.history.map((h) => h.what.split(':')[0]), ['proposed', 'approve', 'done']);

  // AI: context = readings only (masked text), fixed JSON shape -> proposal
  const ai = await T.advise({ instance: 'ESS', sql_id: 'a1b2c3d4e5f6g', plan: ['| 1 | TABLE ACCESS FULL | ORDERS |', 'filter("CUSTOMER_ID"=:n)'], user: 'siva', role: 'operator' });
  assert.equal(ai.source, 'ai'); assert.equal(ai.status, 'proposed', 'an index with DROP INDEX as rollback is a reversible tuning change');
  assert.equal(ai.requested_by, 'siva'); assert.match(ai.fix_sql, /CREATE INDEX/); assert.equal(ai.sql_id, 'a1b2c3d4e5f6g');
  const msg = seen[0].messages[0].content;
  assert.ok(msg.includes('TABLE ACCESS FULL') && msg.includes('"diagnostics_pack":false'));
  assert.match(seen[0].system, /never run anything/); assert.match(seen[0].system, /Tuning Advisor/);
});

test('a proposal that would change data or end sessions is refused, not stored as proposed', () => {
  const T = createTuning({ state: fakeState(), now: () => NOW });
  const bad = T.propose({ instance: 'ESS', title: 'x', fix_sql: 'DELETE FROM app.audit_log WHERE ts < SYSDATE - 90;', rollback_sql: '' }, { user: 'siva' });
  assert.equal(bad.status, 'refused');
  const kill = T.propose({ instance: 'ESS', title: 'x', fix_sql: "ALTER SYSTEM KILL SESSION '12,345' IMMEDIATE;", rollback_sql: '' }, { user: 'siva' });
  assert.equal(kill.status, 'refused');
  const ok = T.propose({ instance: 'ESS', title: 'index', fix_sql: 'CREATE INDEX app.ix ON app.t(c) ONLINE;', rollback_sql: 'DROP INDEX app.ix;' }, { user: 'siva' });
  assert.equal(ok.status, 'proposed', 'creating / dropping an index is a reversible tuning change');
  assert.deepEqual(findingsFrom([]), []);
});

// Data Guard: records as the platform connection sends them -> oracle-health parse -> findings and the Data Guard view.
// A resolved gap / restarted apply must not linger (current readings only), a missing reading is never "stopped", and a
// standby keyed by its DB_UNIQUE_NAME stays apart from its primary.
test('Data Guard: transport, gap, apply stopped, lag, force logging; current readings only; no row is not "stopped"', async () => {
  const H = require('../engine/db-audit/oracle-health');
  const T = createTuning({ state: fakeState(), now: () => NOW });
  const send = (o, at) => { const e = H.parse(JSON.stringify(Object.assign({ collector: 'sentra-oracle-itam', host: 'eskaprd', instance: 'ESS', t: new Date(at || NOW - 60000).toISOString() }, o))); e.src_type = 'oracle-health'; T.stage(e); return e; };
  const cfg = send({ kind: 'dg_config', role: 'PRIMARY', protection_mode: 'MAXIMUM AVAILABILITY', protection_level: 'RESYNCHRONIZATION', force_logging: 'NO', flashback: 'NO', broker: 'DISABLED', db_unique_name: 'ESS_PRD', standbys: 1, switchover_status: 'TO STANDBY' });
  assert.equal(cfg.action, 'dg-config'); assert.equal(cfg.severity, 3);
  const d = send({ kind: 'dg_dest', dest_id: 2, db_unique_name: 'ess_dr', status: 'VALID', gap_status: 'NO GAP', recovery_mode: 'IDLE', archived_seq: 900, applied_seq: 880, transmit_mode: 'SYNCHRONOUS' });
  assert.equal(d.action, 'dg-transport'); assert.equal(d.fields.key, 'ESS_DR'); assert.equal(d.severity, 3);
  send({ kind: 'dg_applied', dest_id: 2, thread: 1, last_seq: 900, applied_seq: 880, unapplied: 20, unapplied_since_s: 2400 });
  send({ kind: 'dg_srl', srl_groups: 2, online_groups: 3, threads: 1 });
  send({ kind: 'dg_nologging', files: 2, last: '2026-10-19T22:00:00' });
  // a gap reported two hours ago and gone since: history, not a finding
  send({ kind: 'dg_gap', thread: 1, low_seq: 10, high_seq: 12 }, NOW - 2 * 3600000);
  let v = await T.view({ instance: 'ESS' }); const k = v.findings.map((f) => f.key);
  assert.ok(k.includes('dg:idle:ESS_DR') && k.includes('dg:force-logging') && k.includes('dg:protection') && k.includes('dg:flashback') && k.includes('dg:srl') && k.includes('dg:nologging') && k.includes('dg:lag:2:1'), k.join(' '));
  assert.ok(!k.includes('dg:sbgap:1'), 'an old gap reading is not a current gap');
  const fl = v.findings.find((f) => f.key === 'dg:force-logging');
  assert.equal(fl.fix.sql, 'ALTER DATABASE FORCE LOGGING;'); assert.equal(fl.fix.rollback, 'ALTER DATABASE NO FORCE LOGGING;');
  assert.match(v.findings.find((f) => f.key === 'dg:idle:ESS_DR').fix.sql, /RECOVER MANAGED STANDBY DATABASE DISCONNECT/);
  assert.equal(v.dataguard.role, 'PRIMARY'); assert.equal(v.dataguard.standbys[0].name, 'ESS_DR'); assert.equal(v.dataguard.standbys[0].unapplied_since_s, 2400);
  assert.equal(v.dataguard.standby_logs.srl_groups, 2);

  // the standby (keyed ESS_DR): MRP0 counted 0 -> apply not running, with the broker command because the broker is on
  const sb = (o) => send(Object.assign({ instance: 'ESS_DR', host: 'eskadr' }, o));
  sb({ kind: 'dg_config', role: 'PHYSICAL STANDBY', db_unique_name: 'ESS_DR', broker: 'ENABLED', open_mode: 'READ ONLY WITH APPLY' });
  const p = sb({ kind: 'dg_process', role: 'PHYSICAL STANDBY', mrp: 0, rfs: 2 }); assert.equal(p.severity, 4);
  const lag = sb({ kind: 'dg_stats', name: 'apply lag', value: '+00 00:40:00', unit: 'day(2) to second(0) interval' }); assert.equal(lag.fields.value_s, '2400'); assert.equal(lag.severity, 3);
  v = await T.view({ instance: 'ESS_DR' });
  const mrp = v.findings.find((f) => f.key === 'dg:mrp');
  assert.ok(mrp && mrp.severity === 'critical'); assert.match(mrp.fix.sql, /DGMGRL> EDIT DATABASE 'ESS_DR' SET STATE = 'APPLY-ON'/);
  assert.equal(v.dataguard.standby_side.mrp, 0); assert.equal(v.dataguard.standby_side.apply_lag.seconds, 2400);

  // no dg_process row at all (grant missing): no "apply not running" claim
  const T2 = createTuning({ state: fakeState(), now: () => NOW }); const e2 = H.parse(JSON.stringify({ collector: 'sentra-oracle-itam', host: 'x', instance: 'DR2', t: new Date(NOW - 60000).toISOString(), kind: 'dg_config', role: 'PHYSICAL STANDBY', db_unique_name: 'DR2' })); e2.src_type = 'oracle-health'; T2.stage(e2);
  const v2 = await T2.view({ instance: 'DR2' });
  assert.ok(!v2.findings.some((f) => f.key === 'dg:mrp'), 'a reading that did not run is not "stopped"');
  assert.equal(v2.dataguard.standby_side.mrp, null);
});

// Production / DR pairs (Database Dashboard): the DR open state comes from the primary (DATABASE_MODE), a mounted standby
// needs no reading of its own, an Active Data Guard standby that also reports is joined by DB_UNIQUE_NAME, verdicts
test('DR pairs: primary with standbys, open state from the primary, own readings joined, verdicts, orphan standby, route', async () => {
  const H = require('../engine/db-audit/oracle-health');
  const T = createTuning({ state: fakeState(), now: () => NOW });
  const send = (o) => { const e = H.parse(JSON.stringify(Object.assign({ collector: 'sentra-oracle-itam', host: 'prdhost', instance: 'CORE', t: new Date(NOW - 60000).toISOString() }, o))); e.src_type = 'oracle-health'; T.stage(e); return e; };
  send({ kind: 'dg_config', role: 'PRIMARY', db_unique_name: 'CORE_PRD', open_mode: 'READ WRITE', protection_mode: 'MAXIMUM PERFORMANCE', standbys: 2, force_logging: 'YES', broker: 'ENABLED' });
  const d1 = send({ kind: 'dg_dest', dest_id: 2, db_unique_name: 'core_dr', status: 'VALID', gap_status: 'NO GAP', recovery_mode: 'MANAGED REAL TIME APPLY', database_mode: 'MOUNTED-STANDBY', archived_seq: 500, applied_seq: 500 });
  assert.match(d1.message, /standby MOUNTED-STANDBY/);
  send({ kind: 'dg_dest', dest_id: 3, db_unique_name: 'core_rpt', status: 'VALID', gap_status: 'NO GAP', recovery_mode: 'MANAGED REAL TIME APPLY', database_mode: 'OPEN_READ-ONLY', archived_seq: 500, applied_seq: 499 });
  // the reporting standby is also registered in Databases (Active Data Guard) and reports a 40-minute apply lag of its own
  const sb = (o) => send(Object.assign({ instance: 'CORE_RPT', host: 'rpthost' }, o));
  sb({ kind: 'dg_config', role: 'PHYSICAL STANDBY', db_unique_name: 'CORE_RPT', open_mode: 'READ ONLY WITH APPLY' });
  sb({ kind: 'dg_process', role: 'PHYSICAL STANDBY', mrp: 1, rfs: 2 });
  sb({ kind: 'dg_stats', name: 'apply lag', value: '+00 00:40:00', unit: 'day(2) to second(0) interval' });
  // a standby whose primary is not monitored
  send({ instance: 'HR_DR', host: 'hrdr', kind: 'dg_config', role: 'PHYSICAL STANDBY', db_unique_name: 'HR_DR', open_mode: 'MOUNTED' });
  const r = await T.drPairs([]);
  assert.equal(r.pairs.length, 1); const P = r.pairs[0];
  assert.equal(P.primary.instance, 'CORE'); assert.equal(P.primary.db_unique_name, 'CORE_PRD'); assert.equal(P.primary.open_mode, 'READ WRITE');
  const dr = P.standbys.find((s) => s.name === 'CORE_DR'), rpt = P.standbys.find((s) => s.name === 'CORE_RPT');
  assert.equal(dr.open_mode, 'MOUNTED-STANDBY'); assert.equal(dr.open_mode_label, 'Mounted (physical standby)'); assert.equal(dr.open_mode_from, 'primary'); assert.equal(dr.own, null);
  assert.equal(dr.verdict.level, 'ok');
  assert.equal(rpt.open_mode_label, 'Open read-only with apply (Active Data Guard)'); assert.equal(rpt.own.instance, 'CORE_RPT'); assert.equal(rpt.own.apply_lag_s, 2400);
  assert.equal(rpt.verdict.level, 'bad'); assert.ok(rpt.verdict.why.some((w) => /apply lag 40 min/.test(w)), 'own apply lag counts');
  assert.equal(P.level, 'bad');
  assert.equal(r.orphans.length, 1); assert.equal(r.orphans[0].instance, 'HR_DR');
  assert.ok(!r.orphans.some((o) => o.instance === 'CORE_RPT'), 'a standby joined to its primary is not an orphan');
  // RAC: the second primary instance (same DB_UNIQUE_NAME) is the same database - one pair, its readings merged
  send({ instance: 'CORE2', host: 'prdhost2', kind: 'dg_config', role: 'PRIMARY', db_unique_name: 'CORE_PRD', open_mode: 'READ WRITE', standbys: 2 });
  send({ instance: 'CORE2', host: 'prdhost2', kind: 'dg_dest', dest_id: 2, db_unique_name: 'core_dr', status: 'ERROR', error: 'ORA-12541: TNS:no listener', gap_status: 'NO GAP', recovery_mode: 'MANAGED REAL TIME APPLY', database_mode: 'MOUNTED-STANDBY' });
  const rr = await T.drPairs([]);
  assert.equal(rr.pairs.length, 1, 'one pair per database, not per RAC instance');
  assert.equal(rr.pairs[0].primary.rac, true); assert.deepEqual(rr.pairs[0].primary.instances.map((x) => x.instance), ['CORE', 'CORE2']);
  const drR = rr.pairs[0].standbys.find((s) => s.name === 'CORE_DR');
  assert.equal(drR.verdict.level, 'bad'); assert.ok(drR.verdict.why.some((w) => /ORA-12541/.test(w)), 'an error on any RAC instance counts');
  assert.equal(rr.pairs[0].standbys.length, 2);
  // RAC node status: thread 2 configured but its instance is not running (no GV$INSTANCE row) -> NOT RUNNING, the pair is red
  const n1 = send({ kind: 'rac_node', thread: 1, thread_status: 'OPEN', enabled: 'PUBLIC', instance_name: 'CORE1', host_name: 'prdnode1', status: 'OPEN', database_status: 'ACTIVE', db_unique_name: 'CORE_PRD' });
  const n2 = send({ kind: 'rac_node', thread: 2, thread_status: 'CLOSED', enabled: 'PUBLIC', instance_name: 'CORE2', status: 'NOT RUNNING', db_unique_name: 'CORE_PRD' });
  assert.equal(n1.action, 'rac-node'); assert.equal(n1.severity, 0); assert.equal(n2.severity, 4); assert.match(n2.message, /RAC CORE_PRD node CORE2: NOT RUNNING/);
  // a RAC database with no Data Guard at all still shows its nodes
  send({ instance: 'HRMS1', host: 'hr1', kind: 'rac_node', thread: 1, instance_name: 'HRMS1', host_name: 'hr1', status: 'OPEN', db_unique_name: 'HRMS' });
  send({ instance: 'HRMS1', host: 'hr1', kind: 'rac_node', thread: 2, instance_name: 'HRMS2', host_name: 'hr2', status: 'OPEN', db_unique_name: 'HRMS' });
  const rc = await T.drPairs([]);
  const cl = rc.pairs[0].primary.cluster;
  assert.equal(cl.total, 2); assert.equal(cl.up, 1); assert.equal(cl.level, 'bad'); assert.match(cl.why[0], /node CORE2 is NOT RUNNING/);
  const hr = rc.rac_only.find((x) => x.db_unique_name === 'HRMS'); assert.ok(hr && hr.up === 2 && hr.level === 'ok', 'RAC without Data Guard listed');
  // apply stopped and a snapshot standby
  send({ kind: 'dg_dest', dest_id: 2, db_unique_name: 'core_dr', status: 'VALID', gap_status: 'RESOLVABLE GAP', recovery_mode: 'IDLE', database_mode: 'MOUNTED-STANDBY' });
  send({ kind: 'dg_dest', dest_id: 3, db_unique_name: 'core_rpt', status: 'VALID', gap_status: 'NO GAP', recovery_mode: 'IDLE', database_mode: 'OPEN' });
  const r2 = await T.drPairs([]);
  const dr2 = r2.pairs[0].standbys.find((s) => s.name === 'CORE_DR'), rpt2 = r2.pairs[0].standbys.find((s) => s.name === 'CORE_RPT');
  assert.equal(dr2.verdict.level, 'bad'); assert.ok(dr2.verdict.why.includes('redo apply is stopped (MRP not running)') && dr2.verdict.why.some((w) => /archive gap/.test(w)));
  assert.equal(rpt2.open_mode_label, 'Open read-write'); assert.ok(rpt2.verdict.why.some((w) => /snapshot standby/.test(w)));
  // the route: any signed-in role reads it
  const routes = {};
  require('../engine/db-audit/routes').register({ route: (m, p, fn) => { routes[m + ' ' + p] = fn; } }, { config: {}, state: fakeState(), oracle_tuning: T, log: { info() {}, warn() {}, error() {}, child() { return this; } } });
  let out = null; await routes['GET /api/soc/db/oracle/dr']({ role: 'viewer', user: 'v.syn', query: {}, ok: (b) => { out = b; return b; }, fail: (s, m) => { out = { s, m }; } });
  assert.equal(out.pairs.length, 1);
});

test('archive destination: DEFERRED / DISABLED with a stale error text is not a failure; ERROR is', () => {
  const H = require('../engine/db-audit/oracle-health');
  const ev = (o) => H.parse(JSON.stringify(Object.assign({ collector: 'sentra-oracle-itam', host: 'esx-agg', instance: 'ESX', t: new Date(NOW - 60000).toISOString(), kind: 'archive_dest' }, o)));
  const d = ev({ dest_id: 3, dest_name: 'LOG_ARCHIVE_DEST_3', status: 'DEFERRED', destination: '/backup/arch_test/arch_dest3', dest_error: 'ORA-19504: failed to create file' });
  assert.notEqual(d.outcome, 'failure'); assert.notEqual(d.severity, 3);
  const e = ev({ dest_id: 2, dest_name: 'LOG_ARCHIVE_DEST_2', status: 'ERROR', destination: 'ESX_DR', dest_error: 'ORA-12541: TNS:no listener' });
  assert.equal(e.outcome, 'failure'); assert.equal(e.severity, 3);
});
