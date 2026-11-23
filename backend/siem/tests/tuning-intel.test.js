// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Oracle Tuning intelligence (engine/db-audit/tuning-intel.js) over SYNTHETIC proposals, findings and Top SQL timings: a done fix
// verified as improved (with the DB time it saves), one made worse (rollback named), one with too few samples not measurable, one
// without a SQL_ID; success learned per kind (smoothed); findings ranked by the DB time their SQL costs and that confidence;
// unstable plans and literal SQL found; the Pareto line; the route: analyst reads, a viewer is refused, validation.
const test = require('node:test');
const assert = require('node:assert/strict');
const TI = require('../engine/db-audit/tuning-intel');
const { fakeApi } = require('./soc-fakes');

const H = 3600000, DAY = 86400000, NOW = Date.parse('2026-11-19T09:00:00Z'), DONE = NOW - 3 * DAY;
const pts = (msBefore, msAfter, n) => { const o = []; for (let t = DONE - 6 * DAY; t < NOW; t += 6 * H) o.push({ ts: t, executions: n, ela_ms_exec: t < DONE ? msBefore : msAfter }); return o; };
const detail = (b, a, n = 50) => ({ plans: [{ plan_hash: 1, points: pts(b, a, n) }] });
function data() {
  const proposals = [
    { id: 'TUN-0001', status: 'done', sql_id: 'good1', finding_key: 'plan:good1', title: 'Pin plan for good1', done_at: new Date(DONE).toISOString(), done_by: 'ahmed', rollback_sql: 'DROP BASELINE' },
    { id: 'TUN-0002', status: 'done', sql_id: 'bad1', finding_key: 'stats:APP.T', title: 'Gather stats on APP.T', done_at: new Date(DONE).toISOString(), rollback_sql: 'RESTORE STATS' },
    { id: 'TUN-0003', status: 'done', sql_id: 'thin', finding_key: 'plan:thin', title: 'thin', done_at: new Date(NOW - 2 * H).toISOString() },
    { id: 'TUN-0004', status: 'done', finding_key: 'dg:mrp', title: 'Restart apply', done_at: new Date(DONE).toISOString() },
    { id: 'TUN-0005', status: 'proposed', sql_id: 'x', title: 'not done' }];
  const findings = [{ key: 'plan:hot', severity: 'medium', area: 'SQL', sql_id: 'hot', title: 'SQL hot is 3x slower after a plan change' }, { key: 'stats:APP.U', severity: 'low', area: 'Statistics', title: 'Stale stats APP.U' }, { key: 'dg:lag', severity: 'high', area: 'Data Guard', title: 'Standby behind' }];
  const sql = [{ sql_id: 'hot', elapsed_s: 70000, executions: 1000 }, { sql_id: 'good1', elapsed_s: 100, executions: 10 },
    { sql_id: 'uns', elapsed_s: 7000, plans: [{ plan_hash: 11, ela_ms_exec: 20 }, { plan_hash: 22, ela_ms_exec: 90 }] },
    { sql_id: 'l1', elapsed_s: 10, executions: 5, sql_text: "select * from orders where id = 101 and st = 'A'" }, { sql_id: 'l2', elapsed_s: 20, executions: 5, sql_text: "select * from orders where id = 202 and st = 'B'" }, { sql_id: 'l3', elapsed_s: 30, executions: 5, sql_text: "SELECT * FROM orders WHERE id = 303 AND st = 'C'" }];
  return { view: { proposals, findings }, sql7d: { period_s: 7 * DAY / 1000, sql, sql_text_visible: true }, details: { good1: detail(400, 100), bad1: detail(50, 200), thin: detail(10, 10) }, now: NOW };
}

test('verified outcomes, learned success, ranking and candidates', () => {
  const v = TI.analyse(data()), by = Object.fromEntries(v.verified.map((x) => [x.id, x]));
  assert.equal(v.verified.length, 4, 'only done recommendations');
  assert.equal(by['TUN-0001'].verdict, 'improved'); assert.equal(by['TUN-0001'].ratio, 4); assert.match(by['TUN-0001'].why, /4x faster per execution \(400 -> 100 ms\), about \d+(\.\d)? s of DB time saved a day/);
  assert.ok(by['TUN-0001'].saves_s_day > 0); assert.equal(v.saved_s_day, by['TUN-0001'].saves_s_day);
  assert.equal(by['TUN-0002'].verdict, 'worse'); assert.match(by['TUN-0002'].why, /4x SLOWER.*rollback SQL/);
  assert.equal(by['TUN-0003'].verdict, 'not-measurable'); assert.match(by['TUN-0003'].why, /needs 3\+ samples/);
  assert.equal(by['TUN-0004'].verdict, 'not-measurable'); assert.match(by['TUN-0004'].why, /not tied to one SQL_ID/);
  assert.deepEqual(v.counts, { improved: 1, worse: 1, no_effect: 0, not_measurable: 2 });
  const plan = v.learned.find((k) => k.kind === 'plan'); assert.equal(plan.success_pct, 67, '1 of 1 smoothed to 2/3'); assert.equal(v.learned.find((k) => k.kind === 'stats').success_pct, 33);
  assert.equal(v.next[0].key, 'plan:hot', 'the costly SQL with a kind that worked comes first'); assert.equal(v.next[0].cost_s_day, 10000); assert.equal(v.next[0].confidence_pct, 67); assert.match(v.next[0].why, /costs 10000 s of DB time a day/);
  assert.ok(v.next.find((n) => n.key === 'dg:lag').why.includes('50 % prior'));
  assert.equal(v.candidates.unstable[0].sql_id, 'uns'); assert.equal(v.candidates.unstable[0].best_plan, 11); assert.equal(v.candidates.unstable[0].ratio, 4.5);
  assert.equal(v.candidates.literals.length, 1); assert.deepEqual(v.candidates.literals[0].sql_ids.sort(), ['l1', 'l2', 'l3']);
  assert.ok(v.candidates.pareto.top5_pct >= 99 && v.candidates.pareto.top[0].sql_id === 'hot');
  assert.equal(TI.norm("x = 'a''b' and y=12.5 and z=:b1"), 'x = ? and y=? and z=?');
});

test('route: analyst reads, a viewer is refused, validation', async () => {
  const api = fakeApi({ realRanks: true }), d = data(), asked = [];
  const deps = { now: () => NOW, oracle_perf: { topsql: async (q) => { asked.push(q); return q.sql_id ? { detail: d.details[q.sql_id] || null } : d.sql7d; } } };
  TI.register(api, deps, '/api/soc', (ctx) => Object.assign({}, ctx.query || {}), { view: async () => d.view });
  let r = await api.call('GET', '/api/soc/db/oracle/tuning/intel?instance=db1|PRD', { role: 'analyst' }); assert.equal(r.status, 200, JSON.stringify(r.body));
  assert.equal(r.body.counts.improved, 1); assert.ok(asked.some((q) => q.sql_id === 'good1' && q.period === '7d'));
  r = await api.call('GET', '/api/soc/db/oracle/tuning/intel', { role: 'viewer' }); assert.equal(r.status, 403);
  r = await api.call('GET', '/api/soc/db/oracle/tuning/intel?instance=' + 'x'.repeat(300), { role: 'analyst' }); assert.equal(r.status, 400); assert.match(r.body.error, /instance/);
});
