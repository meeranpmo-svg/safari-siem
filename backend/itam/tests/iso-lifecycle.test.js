// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// ISO 27001 full lifecycle (engine/iso-lifecycle.js) over the REAL ISO 27001 register with SYNTHETIC facts: nine phases judged from the
// register (each criterion names its clause and why), the current phase, profile entries moving a phase forward; the certification cycle
// (Stage 1 first, Stage 2 issues the certificate, surveillance 12 months later, recertification before expiry, overdue said; a
// recommendation with majors refused); the plan (ISMS manager / admin, versioned); the forecast needs 3 snapshots then projects to 90 %
// against the planned Stage 2; one snapshot a day; roles, validation naming the field, audit records, the coach off until allowed.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');
const { addMonths } = require('../engine/iso-lifecycle');

const PY = process.env.PYTHON || 'python3', DAY = 86400000;
const VIEW = { user: 'vera.syn', role: 'viewer' }, OP = { user: 'nora.syn', role: 'operator' }, ADM = { user: 'syed', role: 'admin' }, MGR = { user: 'mona.syn', role: 'operator' }, BOT = { user: 'ai:grc', role: 'operator' };
const FACTS = () => ({
  grc: { available: true, total: 20, reviews_overdue: 0, attested: 18, policies: [{ title: 'Information Security Policy (synthetic)', status: 'Approved', next_review: '2027-06-01' }], control_status: {} },
  risk: { available: true, total: 8, review_overdue: 0, actions_open: 3, actions_overdue: 0 },
  ownership: { available: true, assets: 40, missing_it: 0, missing_business: 0 }, training_12m: 2,
});
async function setup(t) {
  let clock = Date.parse('2026-11-02T08:00:00Z');
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true, now: () => clock, python: PY, eccFacts: async () => FACTS() });
  const call = (m, p, b, who) => e.req(m, p, Object.assign(b !== undefined ? { body: b } : {}, who));
  return { e, tick: (ms) => { clock += ms; }, post: (p, b, who = ADM) => call('POST', p, b, who), get: (p, who = OP) => call('GET', p, undefined, who), audit: (a) => e.app.store.auditTail(500).filter((x) => x.action === a) };
}

test('phases from the register: criteria name their clause, the profile moves the first phases', async (t) => {
  const s = await setup(t);
  let v = (await s.get('/iso-lifecycle', VIEW)).json;
  assert.equal(v.installed, true); assert.equal(v.phases.length, 9); assert.equal(v.current.id, 'initiate');
  assert.ok(v.current.missing.some((c) => /ISMS manager named/.test(c.what) && /name the ISMS manager/.test(c.why)));
  assert.ok(v.phases.find((p) => p.id === 'context').criteria.every((c) => /^clause 4\./.test(c.source)));
  assert.ok(v.phases.find((p) => p.id === 'implement').criteria.some((c) => /Annex A/.test(c.source)));
  assert.equal((await s.post('/iso27001/profile', { isms_manager: MGR.user, top_management: 'CEO (synthetic)', scope: 'All IT services (synthetic)', scope_approved: '2026-09-01', context_reviewed: '2026-09-01', parties_reviewed: '2026-09-01' })).status, 200);
  v = (await s.get('/iso-lifecycle', VIEW)).json;
  assert.equal(v.phases[0].done, true, 'initiate done once the ISMS manager and sponsor are named'); assert.notEqual(v.current.id, 'initiate');
  assert.ok(v.progress > 0 && v.progress < 100); assert.match(v.note, /certification body decides/);
});

test('certification cycle: Stage 1 first, Stage 2 issues the certificate, surveillance due, overdue said', async (t) => {
  const s = await setup(t);
  await s.post('/iso27001/profile', { isms_manager: MGR.user });
  assert.equal(addMonths('2026-01-31', 12), '2027-01-31');
  let r = await s.post('/iso-lifecycle/cert', { event: 'stage1', date: '2026-10-01', body: 'Synthetic CB', result: 'minor', minor: 2 }, OP); assert.equal(r.status, 403, 'only the ISMS manager or an admin records');
  r = await s.post('/iso-lifecycle/cert', { event: 'stage1', date: '2026-10-01', body: 'Synthetic CB', result: 'minor', minor: 2 }, BOT); assert.equal(r.status, 403);
  r = await s.post('/iso-lifecycle/cert', { event: 'stage2', date: '2026-10-01', body: 'Synthetic CB', result: 'recommended' }, MGR); assert.equal(r.status, 409); assert.match(r.json.error, /Stage 1 first/);
  r = await s.post('/iso-lifecycle/cert', { event: 'stage1', date: '2099-10-01', body: 'Synthetic CB', result: 'minor' }, MGR); assert.equal(r.status, 400); assert.match(r.json.error, /date/);
  r = await s.post('/iso-lifecycle/cert', { event: 'stage1', date: '2026-08-01', body: 'Synthetic CB', result: 'minor', minor: 2, report_ref: 'S1-REP-001' }, MGR); assert.equal(r.status, 200, r.raw);
  let v = (await s.get('/iso-lifecycle')).json; assert.equal(v.cycle.next.event, 'stage2'); assert.equal(v.cycle.certified, false);
  r = await s.post('/iso-lifecycle/cert', { event: 'stage2', date: '2026-09-01', body: 'Synthetic CB', result: 'recommended', major: 1 }, MGR); assert.equal(r.status, 400); assert.match(r.json.error, /result/);
  r = await s.post('/iso-lifecycle/cert', { event: 'surveillance1', date: '2026-09-01', body: 'Synthetic CB', result: 'recommended' }, MGR); assert.equal(r.status, 409); assert.match(r.json.error, /no certificate yet/);
  r = await s.post('/iso-lifecycle/cert', { event: 'stage2', date: '2025-09-01', body: 'Synthetic CB', result: 'minor', minor: 1 }, MGR); assert.equal(r.status, 200);
  v = (await s.get('/iso-lifecycle')).json;
  assert.equal(v.cycle.certificate.issued, '2025-09-01'); assert.equal(v.cycle.certificate.expires, '2028-09-01'); assert.equal(v.cycle.certified, true);
  assert.equal(v.cycle.next.event, 'surveillance1'); assert.equal(v.cycle.next.due, '2026-09-01'); assert.equal(v.cycle.next.overdue, true, 'surveillance 1 is overdue on 2026-11-02');
  assert.equal(s.audit('iso-lifecycle.cert').length, 2);
});

test('plan, forecast and one snapshot a day; roles and the coach', async (t) => {
  const s = await setup(t);
  await s.post('/iso27001/profile', { isms_manager: MGR.user, top_management: 'CEO (synthetic)' });
  let r = await s.post('/iso-lifecycle/plan', { target_stage1: '2027-02-01', target_stage2: '2027-01-01', version: 0 }, MGR); assert.equal(r.status, 400); assert.match(r.json.error, /target_stage2/);
  r = await s.post('/iso-lifecycle/plan', { target_stage1: '2027-02-01', target_stage2: '2027-04-01', version: 0 }, OP); assert.equal(r.status, 403);
  r = await s.post('/iso-lifecycle/plan', { target_stage1: '2027-02-01', target_stage2: '2027-04-01', version: 0 }, MGR); assert.equal(r.status, 200); assert.equal(r.json.version, 1);
  assert.equal((await s.post('/iso-lifecycle/plan', { target_stage1: '2027-02-01', version: 0 }, MGR)).status, 409, 'stale version');
  let v = (await s.get('/iso-lifecycle')).json;
  assert.ok(v.learning.forecast.why.length && v.learning.forecast.target && ['on_track', 'at_risk'].includes(v.learning.forecast.target.status));
  const L = s.e.app.addons.isoLifecycle; assert.ok(await L.snapshot()); assert.equal(await L.snapshot(), null, 'one snapshot a day');
  v = (await s.get('/iso-lifecycle')).json; assert.equal(v.learning.snapshots, 1); const dI = v.learning.durations.find((d) => d.id === 'initiate'); assert.equal(dI.first_done, '2026-11-02', 'initiate first done on the snapshot day'); assert.equal(dI.days, 0);
  assert.equal(v.can_manage, false); assert.equal((await s.get('/iso-lifecycle', MGR)).json.can_manage, true);
  assert.equal((await s.post('/iso-lifecycle/ask', { question: 'what next?' }, VIEW)).status, 403);
  r = await s.post('/iso-lifecycle/ask', { question: 'x' }, OP); assert.equal(r.status, 400); assert.match(r.json.error, /question/);
  assert.equal((await s.post('/iso-lifecycle/ask', { question: 'what should we do next?' }, OP)).status, 424, 'off until external AI is allowed');
  assert.ok(s.audit('iso-lifecycle.plan').length === 1);
});
