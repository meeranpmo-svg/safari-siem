// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// NCA ECC Compliance Studio (engine/nca-ecc-intel.js) over the REAL NCA ECC register with SYNTHETIC facts: priorities ranked by value with
// the kind of work (fix / connect / confirm), leverage groups of not-measured controls, quick wins; one snapshot a day; a REGRESSION when
// a control met in an earlier snapshot is not met now; the forecast needs 3 snapshots and is judged against the target date; settings
// admin-only with a version; roles, validation naming the field, the audit record, the AI officer off until allowed.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');
const { reasonKey } = require('../engine/nca-ecc-intel');

const PY = process.env.PYTHON || 'python3', DAY = 86400000;
const VIEW = { user: 'vera.syn', role: 'viewer' }, OP = { user: 'nora.syn', role: 'operator' }, ADM = { user: 'syed', role: 'admin' };
let F;
const FACTS = () => ({ grc: { available: true, total: 20, reviews_overdue: F.overdue, attested: 18, policies: [{ title: 'Information Security Policy (synthetic)', status: 'Approved', next_review: '2027-06-01' }], control_status: {} },
  risk: { available: true, total: 8, review_overdue: 0, actions_open: 3, actions_overdue: 0 }, ownership: { available: true, assets: 40, missing_it: 0, missing_business: 0 }, training_12m: 2 });
async function setup(t) {
  F = { overdue: 0 }; let clock = Date.parse('2026-11-02T08:00:00Z');
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true, now: () => clock, python: PY, eccFacts: async () => FACTS() });
  const call = (m, p, b, who) => e.req(m, p, Object.assign(b !== undefined ? { body: b } : {}, who));
  return { e, tick: (ms) => { clock += ms; }, post: (p, b, who = ADM) => call('POST', p, b, who), get: (p, who = OP) => call('GET', p, undefined, who), audit: (a) => e.app.store.auditTail(500).filter((x) => x.action === a) };
}

test('priorities with the kind of work, leverage, quick wins', async (t) => {
  const s = await setup(t);
  const r = await s.get('/nca-ecc-intel', VIEW); assert.equal(r.status, 200, r.raw); const v = r.json;
  assert.equal(v.installed, true); assert.ok(v.priorities.length > 10);
  const kinds = new Set(v.priorities.map((p) => p.kind)); for (const k of ['fix', 'connect', 'confirm']) assert.ok(kinds.has(k), 'kind ' + k);
  for (let i = 1; i < v.priorities.length; i++) assert.ok(v.priorities[i - 1].value >= v.priorities[i].value, 'ranked by value');
  assert.ok(v.priorities.every((p) => p.gain_pct > 0 && p.work));
  assert.equal(v.quick_wins, v.priorities.filter((p) => p.kind === 'confirm').length);
  assert.ok(v.leverage.length && v.leverage[0].count >= v.leverage[v.leverage.length - 1].count && v.leverage.every((l) => l.reason && l.controls.length === l.count));
  assert.equal(reasonKey('not measured: 3 hosts'), reasonKey('not measured: 12 hosts'), 'numbers do not split a reason');
  assert.match(v.note, /NCA's own assessment decides/);
});

test('history: one snapshot a day, a regression when a met control is not met any more, forecast against the target', async (t) => {
  const s = await setup(t);
  const X = s.e.app.addons.ncaEccIntel;
  let v = (await s.get('/nca-ecc-intel')).json; assert.match(v.learning.forecast.why, /needs 3 daily snapshots/); assert.equal(v.regressions.length, 0);
  const met = (await s.get('/nca-ecc', OP)).json.controls.filter((c) => c.result === 'verified').map((c) => c.id);
  for (let d = 0; d < 3; d++) { assert.ok(await X.snapshot()); assert.equal(await X.snapshot(), null, 'one a day'); s.tick(DAY); }
  F.overdue = 9;   // policy reviews now overdue: a verified control fails
  v = (await s.get('/nca-ecc-intel')).json;
  const now = (await s.get('/nca-ecc', OP)).json.controls;
  const lost = now.filter((c) => met.includes(c.id) && c.result !== 'verified').map((c) => c.id);
  assert.ok(lost.length, 'the synthetic change made a verified control fail');
  assert.deepEqual(v.regressions.map((x) => x.id).sort(), lost.sort()); assert.equal(v.regressions[0].last_met, '2026-11-04');
  assert.ok(v.learning.forecast.why.length); assert.equal(v.learning.snapshots, 3);
  let r = await s.post('/nca-ecc-intel/settings', { target_pct: 80, target_date: '2027-06-30', version: 0 }, OP); assert.equal(r.status, 403);
  r = await s.post('/nca-ecc-intel/settings', { target_pct: 5, version: 0 }); assert.equal(r.status, 400); assert.match(r.json.error, /target_pct/);
  r = await s.post('/nca-ecc-intel/settings', { target_pct: 80, target_date: '2027-06-30', version: 0 }); assert.equal(r.status, 200); assert.equal(r.json.version, 1);
  assert.equal((await s.post('/nca-ecc-intel/settings', { target_pct: 90, version: 0 })).status, 409);
  v = (await s.get('/nca-ecc-intel')).json; assert.ok(['on_track', 'at_risk'].includes(v.learning.forecast.target.status));
  assert.equal(s.audit('nca-ecc-intel.settings').length, 1);
  assert.equal((await s.post('/nca-ecc-intel/ask', { question: 'what first?' }, VIEW)).status, 403);
  r = await s.post('/nca-ecc-intel/ask', { question: 'x' }, OP); assert.equal(r.status, 400); assert.match(r.json.error, /question/);
  assert.equal((await s.post('/nca-ecc-intel/ask', { question: 'what should we fix first?' }, OP)).status, 424);
});
