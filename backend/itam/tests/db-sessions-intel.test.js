// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Long-Running Queries - use cases and learning (engine/db-sessions-intel.js): matching (wildcards, SQL_ID, SQL text, database, the
// most specific case wins), time windows in Riyadh (crossing midnight); verdicts - expected, over its expected time, outside its
// window, watch, problem, and without a case usual / unusual / new from what was learned; a blocker always flagged; suggestions for a
// recurring query with no case; every live read recorded and annotated through db-sessions.js; routes: only a DBA approver or admin
// (a person) writes, validation names the field, version conflict 409, delete needs a reason, audit; the advisor refuses a viewer and a
// service identity. SYNTHETIC data.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const I = require('../engine/db-sessions-intel');
const { createDbSessions } = require('../engine/db-sessions');

const H = 3600000, DAY = 86400000;
const T = Date.parse('2026-11-18T23:30:00Z');   // Thursday 02:30 Riyadh (window Wed 23:00 - 04:00 crosses midnight)
const s = (o) => Object.assign({ status: 'ACTIVE', inst_id: 1, sid: 1, serial: 1, elapsed_s: 600, blocks: 0 }, o);

test('matching, windows and verdicts', () => {
  const C = [
    { id: 'a', name: 'GL nightly close', verdict: 'expected', expected_max_min: 120, match_module: 'GL_CLOSE*', days: [3], from: '23:00', to: '04:00' },
    { id: 'b', name: 'Bad report', verdict: 'problem', match_sql_id: 'bad123', note: 'cancel and tell the report owner' },
    { id: 'c', name: 'HR any', verdict: 'watch', match_username: 'HR_*' },
    { id: 'd', name: 'HR on PRD only', verdict: 'expected', expected_max_min: 30, db: 'reg:prd', match_username: 'HR_BATCH' },
  ];
  const L = new Map([['sql:usual1', { days: 6, p90_s: 900, hours: [10] }], ['sql:slow1', { days: 6, p90_s: 600, hours: [10] }], ['sql:young', { days: 2, p90_s: 100, hours: [] }]]);
  const v = (x, db) => I.verdictOf(s(x), { db: db || 'reg:prd', cases: C, learned: L, now: T });
  assert.equal(v({ module: 'GL_CLOSE_DAILY', elapsed_s: 3600 }).verdict, 'expected', 'Wed-night window covers Thu 02:30');
  let r = v({ module: 'GL_CLOSE_DAILY', elapsed_s: 9000 }); assert.equal(r.verdict, 'over-expected'); assert.match(r.why, /within 120 min - running 150 min \(30 min over\)/); assert.equal(r.severity, 'high');
  r = I.verdictOf(s({ module: 'GL_CLOSE_DAILY' }), { db: 'reg:prd', cases: C, learned: L, now: T + 10 * H }); assert.equal(r.verdict, 'outside-window'); assert.match(r.why, /Wed 23:00-04:00 only/);
  r = v({ sql_id: 'bad123' }); assert.equal(r.verdict, 'problem'); assert.match(r.why, /cancel and tell the report owner/);
  assert.equal(v({ username: 'HR_BATCH' }).case.id, 'd', 'the most specific case wins'); assert.equal(v({ username: 'HR_BATCH' }, 'reg:uat').case.id, 'c', 'a database-bound case does not apply elsewhere');
  assert.equal(v({ sql_id: 'usual1', elapsed_s: 1200 }).verdict, 'usual');
  r = v({ sql_id: 'slow1', elapsed_s: 1800 }); assert.equal(r.verdict, 'unusual'); assert.match(r.why, /usually 10 min \(6 days\)/);
  assert.equal(v({ sql_id: 'young' }).verdict, 'new'); assert.equal(v({ sql_id: 'never' }).verdict, 'new');
  r = v({ sql_id: 'usual1', blocks: 4 }); assert.equal(r.blocking, true); assert.match(r.why, /blocking 4 session/); assert.equal(r.severity, 'high');
  assert.equal(I.matches({ match_sql_text: 'FROM gl_lines' }, 'x', { sql_text: 'select * from GL_LINES where 1' }), true);
});

function world(e, clockRef) {
  const SESS = [s({ sid: 11, username: 'APP_ERP', module: 'NIGHTLY_SYNC', program: 'sync.exe', sql_id: 'nsync01', elapsed_s: 1200, sql_text: 'merge into stock' }), s({ sid: 12, username: 'REP', sql_id: 'r1', elapsed_s: 200 })];
  const creds = new Map([['c1', { id: 'c1', kind: 'db_login', target: { engine: 'oracle' }, secret: { username: 'mon', password: 'x' } }]]);
  const vault = { list: () => [...creds.values()], get: (id) => creds.get(id), open: (id) => ({ secret: creds.get(id).secret, target: creds.get(id).target, release() {} }) };
  const H2 = { targets: () => ({ list: [{ key: 'reg:prd', ip: '10.0.0.5', host: 'PRD', cred_id: 'c1', port: 1521, service: 'PRD' }] }) };
  return createDbSessions(e.app, { dbHealth: H2, discovery: { vault }, now: () => clockRef.t, invRun: async (r) => (r.op === 'oracle_long' ? { ok: true, sessions: JSON.parse(JSON.stringify(SESS)) } : { ok: true }) });
}

test('reads are learned and annotated; suggestions; routes, roles, validation and audit', async (t) => {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  const clock = { t: Date.parse('2026-11-12T07:00:00Z') };
  const X = I.registerDbSessionsIntel(e.app.srv, e.app, { now: () => clock.t });
  const S = world(e, clock), OP = { user: 'ali', role: 'operator' }, ADM = { user: 'syed', role: 'admin' };
  for (let d = 0; d < 6; d++) { await S.readLong({ db: 'reg:prd', min_s: 60 }, OP); clock.t += DAY; }
  const r = await S.readLong({ db: 'reg:prd', min_s: 60 }, OP);
  assert.equal(r.sessions.find((x) => x.sid === 11).intel.verdict, 'usual'); assert.ok(r.intel.learned_fingerprints >= 2); assert.equal(r.intel.verdicts.usual, 2);
  let q = await e.req('GET', '/db-sessions/cases?db=reg%3Aprd', OP); assert.equal(q.status, 200);
  const sg = q.json.suggestions.find((x) => x.match_sql_id === 'nsync01'); assert.ok(sg, JSON.stringify(q.json.suggestions)); assert.equal(sg.expected_max_min, 25); assert.equal(sg.days_seen, 7); assert.equal(q.json.can_edit, false);
  const body = { name: 'Nightly stock sync', db: 'reg:prd', match_sql_id: 'nsync01', verdict: 'expected', expected_max_min: 15, reason: 'agreed with the ERP team' };
  q = await e.req('POST', '/db-sessions/cases', Object.assign({ body }, OP)); assert.equal(q.status, 403, 'a plain operator does not write use cases');
  q = await e.req('POST', '/db-sessions/cases', Object.assign({ body: Object.assign({}, body, { expected_max_min: undefined }) }, ADM)); assert.equal(q.status, 400); assert.match(q.json.error, /expected_max_min/);
  q = await e.req('POST', '/db-sessions/cases', Object.assign({ body: Object.assign({}, body, { match_sql_id: '' }) }, ADM)); assert.equal(q.status, 400); assert.match(q.json.error, /at least one thing to match/);
  q = await e.req('POST', '/db-sessions/cases', Object.assign({ body: Object.assign({}, body, { from: '25:00', to: '02:00' }) }, ADM)); assert.equal(q.status, 400); assert.match(q.json.error, /HH:MM/);
  await assert.rejects(Promise.resolve().then(() => X.save(body, { user: 'svc:bot', role: 'admin' })), /a person/);
  q = await e.req('POST', '/db-sessions/cases', Object.assign({ body: Object.assign({}, body, { extra: 'dropped' }) }, ADM)); assert.equal(q.status, 200, q.text); const id = q.json.id; assert.equal(q.json.extra, undefined);
  const r2 = await S.readLong({ db: 'reg:prd', min_s: 60 }, OP);
  const v = r2.sessions.find((x) => x.sid === 11).intel; assert.equal(v.verdict, 'over-expected'); assert.equal(v.case.name, 'Nightly stock sync');
  q = await e.req('GET', '/db-sessions/cases?db=reg%3Aprd', OP); assert.ok(!q.json.suggestions.some((x) => x.match_sql_id === 'nsync01'), 'a covered query is no longer suggested');
  q = await e.req('POST', '/db-sessions/cases', Object.assign({ body: Object.assign({}, body, { id, base_version: 7, expected_max_min: 40 }) }, ADM)); assert.equal(q.status, 409);
  q = await e.req('POST', '/db-sessions/cases', Object.assign({ body: Object.assign({}, body, { id, base_version: 1, expected_max_min: 40, reason: 'month-end runs longer' }) }, ADM)); assert.equal(q.status, 200); assert.equal(q.json.version, 2);
  q = await e.req('POST', '/db-sessions/cases/' + id + '/delete', Object.assign({ body: {} }, ADM)); assert.equal(q.status, 400); assert.match(q.json.error, /reason/);
  q = await e.req('POST', '/db-sessions/cases/' + id + '/delete', Object.assign({ body: { reason: 'job retired' } }, ADM)); assert.equal(q.status, 200);
  const au = e.app.store.auditTail(100); assert.ok(['db.sessions.case.create', 'db.sessions.case.change', 'db.sessions.case.delete'].every((a) => au.some((x) => x.action === a && x.by === 'syed')));
  q = await e.req('GET', '/db-sessions/insights?db=reg%3Aprd', OP); assert.equal(q.status, 200); assert.ok(q.json.fingerprints.some((f) => f.sql_id === 'nsync01' && f.days === 7)); assert.equal(q.json.by_hour.length, 24);
  q = await e.req('GET', '/db-sessions/insights', OP); assert.equal(q.status, 400);
  q = await e.req('GET', '/db-sessions/cases', { user: 'vera.syn', role: 'viewer' }); assert.equal(q.status, 403);
  q = await e.req('POST', '/db-sessions/ask', { user: 'vera.syn', role: 'viewer', body: { question: 'what is unusual tonight?' } }); assert.equal(q.status, 403);
  await assert.rejects(X.ask({ question: 'what is unusual tonight?' }, { user: 'ai:dba', role: 'operator' }), /service or AI identity/);
});
