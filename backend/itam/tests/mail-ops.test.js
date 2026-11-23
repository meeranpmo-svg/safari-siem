// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// 24/7 Email Availability programme (engine/mail-ops.js) with SYNTHETIC measurements (the mail modules are stubbed): the nine steps
// from the facts and the people's records; profile validated (two on-call engineers at least, admin only); runbooks per standard
// failure, a draft approved by a different person; maintenance windows and failover tests approved four-eyes (a failed test or one
// over the RTO does not count); each outage of the last 90 days needs an approved review; the monthly report; roles; audit.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');

const DAY = 86400000, T = Date.parse('2026-11-22T08:00:00Z');
const ADM = { user: 'syed', role: 'admin' }, OP = { user: 'omar.syn', role: 'operator' }, OP2 = { user: 'nora.syn', role: 'operator' }, VW = { user: 'v.syn', role: 'viewer' }, BOT = { user: 'ai:mail', role: 'admin' };

test('24/7 email availability: steps from facts, people records approved four-eyes', async (t) => {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true, now: () => T, python: process.env.PYTHON || 'python3' });
  const audits = []; const orig = e.app.audit; e.app.audit = (a) => { audits.push(a); return orig ? orig.call(e.app, a) : undefined; };
  // the mail modules' measurements, synthetic
  const F = { av: { target: 99.99, windows: [{ label: 'Last 30 days', availability: 99.98, state: 'met', budget_left_minutes: 2 }], outages: [{ start: T - 10 * DAY, end: T - 10 * DAY + 600000, minutes: 10, hosts: ['mx1.syn'] }],
    gaps: [{ severity: 'high', title: 'syn.test has one MX host - any outage of it stops inbound mail' }], current: { up: true, last_at: T - 60000 } },
    route: { lanes: null }, alerts: { open: [{ severity: 'critical', title: 'SMTP certificate expires in 3 days', source: 'cert', first_seen: T - DAY }], state: null }, reports: [] };
  e.app.addons.mailReputation = { availability: async () => F.av, routeView: async () => F.route, alertView: () => F.alerts, reports: () => F.reports };
  const post = (p, b, who) => e.req('POST', p, Object.assign({ body: b }, who || OP)), get = (p, who) => e.req('GET', p, who || OP);
  let r = await get('/mail-ops'); assert.equal(r.status, 200, r.text); assert.equal(r.json.steps.length, 9); assert.equal(r.json.readiness, 0);
  assert.match(r.json.steps[0].block, /at least two on-call/); assert.match(r.json.steps[1].block, /Route Map/); assert.match(r.json.steps[3].block, /one MX host/);
  assert.equal((await get('/mail-ops', VW)).status, 403, 'viewer refused: names people');
  // 1 profile: admin only, two on-call at least
  const PR = { service_owner: 'karim.syn', escalation: 'syed', oncall: ['omar.syn', 'nora.syn'], rto_min: 30, rpo_min: 0 };
  assert.equal((await post('/mail-ops/profile', PR, OP)).status, 403);
  assert.equal((await post('/mail-ops/profile', Object.assign({}, PR, { oncall: ['omar.syn'] }), ADM)).status, 400, 'one person cannot cover 24/7');
  assert.equal((await post('/mail-ops/profile', PR, BOT)).status, 403);
  r = await post('/mail-ops/profile', PR, ADM); assert.equal(r.status, 200, r.text); assert.equal(r.json.steps[0].done, true);
  // 2-4 from the facts
  F.route = { lanes: { inbound: [] } }; F.alerts.state = { at: T - 30 * 60000, gaps: [] };
  r = await get('/mail-ops'); assert.equal(r.json.steps[1].done, true); assert.equal(r.json.steps[2].done, true, JSON.stringify(r.json.steps[2])); assert.equal(r.json.steps[3].done, false);
  F.alerts.state.gaps = ['Exchange health (SIEM): not reachable']; r = await get('/mail-ops'); assert.equal(r.json.steps[2].done, false); assert.match(r.json.steps[2].block, /monitoring gap/);
  F.alerts.state.gaps = []; F.av.gaps = []; F.alerts.open = []; r = await get('/mail-ops'); assert.equal(r.json.steps[3].done, true);
  // 5 runbooks: draft, then a different person approves
  assert.equal((await post('/mail-ops/runbooks/nope', { owner: 'omar.syn', steps: 'x'.repeat(50), escalation: 'call the escalation manager' })).status, 404);
  assert.equal((await post('/mail-ops/runbooks/gateway-down', { owner: 'omar.syn', steps: 'too short', escalation: 'call the escalation manager' })).status, 400);
  const RBK = r.json.runbooks.map((x) => x.key); assert.equal(RBK.length, 9);
  for (const k of RBK) { const x = await post('/mail-ops/runbooks/' + k, { owner: 'omar.syn', steps: '1. Check the node. 2. Fail over to the second node. 3. Confirm mail flows (synthetic).', escalation: 'After 15 minutes call the escalation manager' }); assert.equal(x.status, 200, x.text); }
  assert.equal((await post('/mail-ops/runbooks/gateway-down/approve', {}, OP)).status, 403, 'the author never approves');
  for (const k of RBK) assert.equal((await post('/mail-ops/runbooks/' + k + '/approve', {}, OP2)).status, 200);
  r = await get('/mail-ops'); assert.equal(r.json.steps[4].done, true);
  // a new version goes back to draft
  await post('/mail-ops/runbooks/disk-full', { owner: 'nora.syn', steps: '1. Free space on the transport queue disk. 2. Move logs (synthetic).', escalation: 'Escalate after 10 minutes' }, OP2);
  r = await get('/mail-ops'); assert.equal(r.json.steps[4].done, false); await post('/mail-ops/runbooks/disk-full/approve', {}, OP);
  // 6 maintenance window
  assert.equal((await post('/mail-ops/windows', { title: 'Patch gateway node 2', start: '2026-12-05T01:00', end: '2026-12-05T00:00', systems: ['esg2'], impact: 'none expected - node 1 carries mail', rollback: 'restore the node snapshot' })).status, 400, 'end after start');
  r = await post('/mail-ops/windows', { title: 'Patch gateway node 2', start: '2026-12-05T01:00', end: '2026-12-05T03:00', systems: ['esg2'], impact: 'none expected - node 1 carries mail', rollback: 'restore the node snapshot' }); const wid = r.json.windows[0].id;
  assert.equal((await post('/mail-ops/windows/' + wid + '/approve', {}, OP)).status, 403); assert.equal((await post('/mail-ops/windows/' + wid + '/approve', {}, OP2)).status, 200);
  // 7 failover test: failed or over the RTO does not count
  assert.equal((await post('/mail-ops/tests', { date: '2026-12-30', scenario: 'take gateway node 1 down', result: 'passed', rto_achieved_min: 5, evidence: 'change CHG-1 (synthetic)' })).status, 400, 'not in the future');
  r = await post('/mail-ops/tests', { date: '2026-11-15', scenario: 'take gateway node 1 down', result: 'passed', rto_achieved_min: 45, evidence: 'change CHG-1 (synthetic)' }); let tid = r.json.tests[0].id; await post('/mail-ops/tests/' + tid + '/approve', {}, OP2);
  r = await get('/mail-ops'); assert.equal(r.json.steps[6].done, false, 'over the 30-minute RTO');
  r = await post('/mail-ops/tests', { date: '2026-11-20', scenario: 'DAG failover of DB01', result: 'passed', rto_achieved_min: 4, evidence: 'change CHG-2 (synthetic)' }); tid = r.json.tests[0].id;
  assert.equal((await post('/mail-ops/tests/' + tid + '/approve', {}, OP)).status, 403); await post('/mail-ops/tests/' + tid + '/approve', {}, OP2);
  r = await get('/mail-ops'); assert.equal(r.json.steps[6].done, true);
  // 8 the outage of 10 days ago needs a review
  assert.equal(r.json.steps[7].done, false); const oid = r.json.outages[0].id; assert.match(oid, /^O-\d+$/);
  assert.equal((await post('/mail-ops/reviews/O-123', { root_cause: 'x'.repeat(12), actions: 'y'.repeat(12), owner: 'omar.syn' })).status, 400);
  assert.equal((await post('/mail-ops/reviews/O-1234567890123', { root_cause: 'x'.repeat(12), actions: 'y'.repeat(12), owner: 'omar.syn' })).status, 404);
  assert.equal((await post('/mail-ops/reviews/' + oid, { root_cause: 'MX1 rebooted for patching outside a window', actions: 'Second MX; patch only in approved windows', owner: 'omar.syn' })).status, 200);
  assert.equal((await post('/mail-ops/reviews/' + oid + '/approve', {}, OP)).status, 403); assert.equal((await post('/mail-ops/reviews/' + oid + '/approve', {}, OP2)).status, 200);
  // 9 the monthly report
  r = await get('/mail-ops'); assert.equal(r.json.steps[8].done, false);
  F.reports = [{ id: 'MR-0001', state: 'approved', approved_at: T - 3 * DAY, approved_by: 'karim.syn' }];
  r = await get('/mail-ops'); assert.ok(r.json.steps.every((s) => s.done), JSON.stringify(r.json.steps.filter((s) => !s.done))); assert.equal(r.json.readiness, 100); assert.equal(r.json.current_step, null);
  for (const a of ['profile', 'runbook.save', 'runbook.approve', 'window.request', 'window.approve', 'test.record', 'test.approve', 'review.save', 'review.approve']) assert.ok(audits.some((x) => x.action === 'mailops.' + a), 'audited: ' + a);
  // the mail modules missing: said, not hidden
  delete e.app.addons.mailReputation; r = await get('/mail-ops'); assert.match(r.json.errors[0], /not installed/); assert.equal(r.json.steps[1].done, false);
});
