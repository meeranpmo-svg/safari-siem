// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Remediation Roadmap (engine/roadmap.js) over the REAL framework crosswalk (NCA ECC register with SYNTHETIC facts) and GRC actions with
// SYNTHETIC history: a GRC action whose reference is a gap's control is that gap's tracking action (shown once); lanes by quarter; velocity
// over 12 weeks, burn-down, slip risk from the owner's own on-time history (Beta(1,1)) with the team's as fallback; a capacity-aware
// proposal for the unscheduled; accepting sets the date where the item lives (crosswalk plan / GRC action) and is audited; roles, a
// service identity refused, validation naming the field, the planner off until external AI is allowed.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');
const { quarterOf, quarterEnd, nextQuarter } = require('../engine/roadmap');

const PY = process.env.PYTHON || 'python3', DAY = 86400000;
const VIEW = { user: 'vera.syn', role: 'viewer' }, OP = { user: 'nora.syn', role: 'operator' }, ADM = { user: 'syed', role: 'admin' }, BOT = { user: 'ai:grc', role: 'operator' };
const FACTS = () => ({ grc: { available: true, total: 20, reviews_overdue: 3, attested: 18, policies: [{ title: 'Information Security Policy (synthetic)', status: 'Approved', next_review: '2027-06-01' }], control_status: {} },
  risk: { available: true, total: 8, review_overdue: 0, actions_open: 3, actions_overdue: 0 }, ownership: { available: true, assets: 40, missing_it: 0, missing_business: 0 }, training_12m: 2 });
const T0 = Date.parse('2026-11-02T08:00:00Z'), d = (n) => new Date(T0 + n * DAY).toISOString().slice(0, 10), ts = (n) => new Date(T0 + n * DAY).toISOString();
async function setup(t) {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true, now: () => T0, python: PY, eccFacts: async () => FACTS() });
  const call = (m, p, b, who) => e.req(m, p, Object.assign(b !== undefined ? { body: b } : {}, who));
  const acts = e.app.store.collection('grc_actions');
  const seed = (id, o) => acts.put(Object.assign({ id, title: 'Synthetic action ' + id, source: 'manual', ref: '', priority: 'medium', status: 'open', owner: '', due: null, framework: '', evidence: [], history: [], created_by: 'seed', created_at: ts(-200) }, o));
  return { e, seed, post: (p, b, who = OP) => call('POST', p, b, who), get: (p, who = OP) => call('GET', p, undefined, who), audit: (a) => e.app.store.auditTail(500).filter((x) => x.action === a) };
}

test('quarters, lanes, one item per gap with its tracking action, learning and the proposal', async (t) => {
  const s = await setup(t);
  assert.equal(quarterOf('2026-11-02'), '2026-Q4'); assert.equal(quarterEnd('2027-Q1'), '2027-03-31'); assert.equal(nextQuarter('2026-Q4'), '2027-Q1');
  const xw = (await s.get('/gap-analysis')).json; assert.ok(xw.items.length > 3, 'synthetic facts give ECC gaps');
  const g0 = xw.items[0], ref = g0.refs[0];
  // history: six closed in the last 12 weeks; nora.syn late on 2 of 3, omar.syn on time on 3 of 3
  const closed = [['ACT-9001', 'nora.syn', -60, -50, -40], ['ACT-9002', 'nora.syn', -50, -45, -30], ['ACT-9003', 'nora.syn', -40, -20, -25],
    ['ACT-9004', 'omar.syn', -60, -30, -35], ['ACT-9005', 'omar.syn', -50, -20, -25], ['ACT-9006', 'omar.syn', -40, -10, -15]];
  for (const [id, owner, c, due, cl] of closed) s.seed(id, { owner, created_at: ts(c), due: d(due), status: 'closed', closed_at: ts(cl), done_by: owner, closed_by: 'syed' });
  s.seed('ACT-9010', { title: 'Tracks ' + g0.key, source: 'nca', ref: ref.fw + ':' + ref.id, framework: 'NCA ECC', owner: 'omar.syn', due: d(20), priority: 'high' });
  s.seed('ACT-9011', { owner: 'nora.syn', due: d(10), priority: 'medium' });               // not started, due in 10 days
  s.seed('ACT-9012', { owner: 'lina.syn', due: d(-5), priority: 'low' });                  // overdue
  s.seed('ACT-9013', { priority: 'high' });                                                // unscheduled, unowned
  const r = await s.get('/roadmap', VIEW); assert.equal(r.status, 200, r.raw); const v = r.json;
  const all = Object.values(v.lanes).flat();
  const gi = all.find((i) => i.id === g0.key); assert.equal(gi.tracking, 'ACT-9010'); assert.equal(gi.due, d(20)); assert.equal(gi.owner, 'omar.syn');
  assert.ok(!all.some((i) => i.id === 'ACT-9010'), 'the tracking action is not shown twice');
  assert.ok(v.lanes.overdue.some((i) => i.id === 'ACT-9012')); assert.ok(v.lanes.this.some((i) => i.id === 'ACT-9011'));
  assert.ok(v.lanes.unscheduled.some((i) => i.id === 'ACT-9013')); assert.equal(v.lanes.done.length, 6);
  assert.ok(v.lanes.unscheduled.length > 1, 'gaps never planned are unscheduled');
  const L = v.learning; assert.equal(L.closed_12w, 6); assert.equal(L.velocity, 0.5); assert.equal(L.capacity_per_quarter, 6.5);
  const sl = L.slip.find((x) => x.id === 'ACT-9011'); assert.equal(sl.p_late, 0.8, '(2+1)/(3+2) = 0.6, +0.2 not started and due in 10 days');
  assert.ok(sl.why.some((w) => /nora.syn: 3 earlier/.test(w)) && sl.why.some((w) => /\+20 points/.test(w)));
  assert.equal(L.slip.find((x) => x.id === g0.key).p_late, 0.2, 'omar.syn: (0+1)/(3+2)');
  assert.ok(L.burn.weeks > 0 && L.burn.date && /projection/.test(L.burn.why));
  assert.ok(v.proposal.length > 0 && v.proposal.every((p) => p.due >= v.today && /room/.test(p.why)));
  const perQ = {}; for (const p of v.proposal) perQ[p.quarter] = (perQ[p.quarter] || 0) + 1;
  for (const q of v.quarters) assert.ok((perQ[q.quarter] || 0) + q.due <= Math.max(6, q.due), 'the proposal never fills a quarter past capacity');
  assert.equal(v.proposal[0].priority, v.lanes.unscheduled[0].priority, 'highest priority placed first');
  assert.ok(v.kpis.open >= 4 && v.kpis.overdue === 1 && v.kpis.unowned >= 1);
  assert.match(v.note, /written where the item lives/);
});

test('no history: velocity 0, no capacity, burn-down says never; accept writes where the item lives', async (t) => {
  const s = await setup(t);
  s.seed('ACT-9020', { owner: 'nora.syn', priority: 'high' });
  let v = (await s.get('/roadmap')).json;
  assert.equal(v.learning.velocity, 0); assert.equal(v.proposal.length, 0); assert.match(v.proposal_why, /no action was closed/); assert.match(v.learning.burn.why, /never cleared/);
  const gap = v.lanes.unscheduled.find((i) => i.kind === 'gap');
  // roles and validation
  assert.equal((await s.post('/roadmap/accept', { kind: 'action', id: 'ACT-9020', due: d(30) }, VIEW)).status, 403);
  assert.equal((await s.post('/roadmap/accept', { kind: 'action', id: 'ACT-9020', due: d(30) }, BOT)).status, 403, 'a service identity never sets a date');
  let r = await s.post('/roadmap/accept', { kind: 'risk', id: 'ACT-9020', due: d(30) }); assert.equal(r.status, 400); assert.match(r.json.error, /kind/);
  r = await s.post('/roadmap/accept', { kind: 'action', id: 'ACT 9020;', due: d(30) }); assert.equal(r.status, 400); assert.match(r.json.error, /id/);
  r = await s.post('/roadmap/accept', { kind: 'action', id: 'ACT-9020', due: '2026-13-01' }); assert.equal(r.status, 400); assert.match(r.json.error, /due/);
  r = await s.post('/roadmap/accept', { kind: 'action', id: 'ACT-9020', due: d(-1) }); assert.equal(r.status, 400); assert.match(r.json.error, /past/);
  // action: the GRC action gets the date (and its own history)
  r = await s.post('/roadmap/accept', { kind: 'action', id: 'ACT-9020', due: d(30) }); assert.equal(r.status, 200, r.raw);
  assert.equal(s.e.app.store.collection('grc_actions').get('ACT-9020').due, d(30));
  // gap: the crosswalk plan gets the date
  r = await s.post('/roadmap/accept', { kind: 'gap', id: gap.id, due: d(60) }); assert.equal(r.status, 200, r.raw);
  v = (await s.get('/roadmap')).json; const moved = Object.values(v.lanes).flat().find((i) => i.id === gap.id); assert.equal(moved.due, d(60));
  assert.equal(s.audit('roadmap.accept').length, 2); assert.equal(s.audit('roadmap.accept')[0].by, 'nora.syn');
  assert.ok(s.audit('gap.plan').length >= 1 || s.audit('crosswalk.gap.plan').length >= 1, 'the crosswalk records its own plan change');
  // planner
  assert.equal((await s.post('/roadmap/ask', { question: 'what should we schedule?' }, VIEW)).status, 403);
  r = await s.post('/roadmap/ask', { question: 'x' }); assert.equal(r.status, 400); assert.match(r.json.error, /question/);
  assert.equal((await s.post('/roadmap/ask', { question: 'what should we schedule first?' })).status, 424, 'off until external AI is allowed');
  assert.equal(v.ai.enabled, false);
});
