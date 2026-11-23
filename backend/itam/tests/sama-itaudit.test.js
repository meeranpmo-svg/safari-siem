// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// SAMA IT Audit readiness (engine/sama-itaudit.js, pyengine/sama_itaudit_rules.py): checks read from the platform's own modules, a
// source that is not there is NOT MEASURED (never a pass), weighted readiness per area, daily history, draft findings for every gap
// sent into an IT Audit engagement by a person only, the regulator pack (HTML escaped, CSV formula-safe), roles, audit. SYNTHETIC data.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');

const PY = process.env.PYTHON || 'python3';
const ADM = { user: 'syed', role: 'admin' }, OP = { user: 'nora.syn', role: 'operator' }, VW = { user: 'vera.syn', role: 'viewer' };
async function setup(t) {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true, now: () => Date.parse('2026-10-31T08:00:00Z'), python: PY });
  const sent = [];
  const A = e.app.addons;
  A.auditEngage = { plans: () => [{ year: 2026, state: 'approved' }], listEngagements: () => [{ id: 'IA-ENG-001', title: 'ITGC 2026 (synthetic)', state: 'fieldwork', start: '2026-09-01', auditee_owner: 'it.head.syn' }],
    addFinding: async (id, b, who) => { sent.push({ id, b, who }); return { id: 'IA-FND-001' }; } };
  A.vaptCenter = { analysis: async () => ({ ok: true, open: 12, counts: { critical: 2 }, sla: { breached: 7 } }) };
  A.certs = { view: () => ({ counts: { expired: 1, expiring: 2 } }) };
  e.app.store.collection('assets').put({ id: 'a1', name: 'CORE-SQL <b>x</b>', mgmt_ip: '10.1.1.5', tags: ['business-critical'], status: 'active' });
  return { e, sent };
}

test('readiness from the platform\'s own evidence; not measured is never a pass; roles; daily history', async (t) => {
  const { e } = await setup(t);
  assert.equal((await e.req('GET', '/sama-itaudit', VW)).status, 403, 'audit gaps name weaknesses: operators only');
  const v = (await e.req('GET', '/sama-itaudit', OP)).json;
  assert.ok(v.ok, JSON.stringify(v).slice(0, 300));
  const c = (id) => v.checks.find((x) => x.id === id);
  assert.equal(c('gov-plan').state, 'met'); assert.match(c('gov-plan').evidence, /approved plan for 2026/);
  assert.equal(c('gov-critical').state, 'met');
  assert.equal(c('risk-vuln').state, 'gap'); assert.match(c('risk-vuln').evidence, /2 critical, 7 past the SLA/);
  assert.equal(c('data-encryption').state, 'gap');
  assert.equal(c('data-mfa').state, 'not_measured', 'no MFA source: not measured, never met');
  assert.equal(c('proc-report').state, 'gap', 'no final report this year');
  assert.ok(v.areas.every((a) => a.checks > 0)); assert.ok(v.readiness.measured < v.readiness.checks);
  assert.ok(v.readiness.score >= 0 && v.readiness.score <= 100);
  assert.ok(v.findings.some((f) => f.check === 'risk-vuln' && f.rating === 'high' && /SAMA CSF 3.3.8/.test(f.criteria)));
  assert.equal(v.engagements[0].id, 'IA-ENG-001');
  assert.equal(e.app.store.collection('sama_itaudit_hist').all(() => true).length, 1, 'today recorded for the trend');
});

test('draft findings go into an IT Audit engagement by a person only; validation; audit', async (t) => {
  const { e, sent } = await setup(t);
  const post = (body, who) => e.req('POST', '/sama-itaudit/findings/send', Object.assign({ body }, who));
  assert.equal((await post({ check: 'risk-vuln', engagement: 'IA-ENG-001', owner: 'it.head.syn' }, VW)).status, 403);
  assert.equal((await post({ check: 'risk-vuln', engagement: 'IA-ENG-001', owner: 'it.head.syn' }, { user: 'ai:auditor', role: 'operator' })).status, 403, 'an AI identity never raises a finding');
  let r = await post({ check: 'Risk Vuln!', engagement: 'IA-ENG-001', owner: 'x' }, OP); assert.equal(r.status, 400); assert.match(r.json.error, /check has an invalid format/);
  r = await post({ check: 'gov-plan', engagement: 'IA-ENG-001', owner: 'x' }, OP); assert.equal(r.status, 404, 'a met check has no gap to raise');
  r = await post({ check: 'risk-vuln', engagement: 'IA-ENG-001', owner: 'it.head.syn' }, OP);
  assert.equal(r.status, 200, r.raw); assert.equal(r.json.finding.id, 'IA-FND-001');
  assert.equal(sent[0].id, 'IA-ENG-001'); assert.equal(sent[0].who.user, 'nora.syn');
  assert.match(sent[0].b.title, /^SAMA IT audit: Vulnerabilities remediated within the SLA/); assert.equal(sent[0].b.rating, 'high');
  for (const k of ['condition', 'criteria', 'cause', 'effect', 'recommendation']) assert.ok(sent[0].b[k] && sent[0].b[k].length > 5, k + ' filled');
  assert.ok(e.app.store.auditTail(20).some((x) => x.action === 'sama.itaudit.finding.send' && x.by === 'nora.syn' && x.detail.check === 'risk-vuln'));
});

test('regulator pack: HTML escaped, CSV formula-safe, audited', async (t) => {
  const { e } = await setup(t);
  e.app.addons.vaptCenter = { analysis: async () => ({ ok: true, open: 1, counts: { critical: 0 }, sla: { breached: 0 } }) };
  const PDR = e.app.addons.pdpl, real = PDR && PDR.records;
  if (PDR) PDR.records = (k) => (k === 'breach' ? [{ id: 'b1', regulators: { SAMA: { required: true } } }] : real.call(PDR, k));
  const h = await e.req('GET', '/sama-itaudit/pack?format=html', OP);
  assert.equal(h.status, 200, h.raw); assert.match(h.json.html, /SAMA IT audit readiness/); assert.match(h.json.html, /not measured/);
  if (PDR) assert.match(h.json.html, /1 notified late or not at all/);
  const c = await e.req('GET', '/sama-itaudit/pack?format=csv', OP); assert.equal(c.status, 200); assert.match(c.json.filename, /^sama-it-audit-\d{4}-\d{2}-\d{2}\.csv$/);
  assert.ok(!/(^|,)"[=+\-@]/m.test(c.json.csv), 'no cell starts with a formula character');
  assert.equal((await e.req('GET', '/sama-itaudit/pack?format=pdf', OP)).status, 400);
  assert.ok(e.app.store.auditTail(20).filter((x) => x.action === 'sama.itaudit.pack').length === 2);
});
