// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const ZYB_ORG = require('../engine/brand');
// Process Risk Assessment (engine/process-assessment.js) with SYNTHETIC data: a standalone procurement assessment with findings
// (likelihood x impact rating and band), a finding raising a GRC action, the overall rating = highest open finding, the workflow
// (draft -> in_review -> approved by a different person; the author cannot approve; a service identity never), validation, reopen,
// the standalone report (white background, logo, print-safe, audited), roles.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');
const VIEW = { user: 'vera.syn', role: 'viewer' }, RO = { user: 'ro.syn', role: 'operator' }, RISK = { user: 'risk.syn', role: 'admin' }, BOT = { user: 'ai:risk', role: 'admin' };

test('Process Risk Assessment: findings, rating, GRC action, four-eyes workflow, report', async (t) => {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true, python: process.env.PYTHON || 'python3' });
  const call = (m, p, b, who) => e.req(m, p, Object.assign(b !== undefined ? { body: b } : {}, who || RISK));
  // empty + templates
  let r = await call('GET', '/process-assessment', undefined, RO); assert.equal(r.status, 200, r.text); assert.deepEqual(r.json.assessments, []);
  assert.ok(r.json.processes.find((x) => x.key === 'procurement').areas.length > 0, 'procurement focus areas offered');
  assert.equal((await call('GET', '/process-assessment', undefined, VIEW)).status, 403);
  // validation + roles
  assert.equal((await call('POST', '/process-assessment', { title: 'x', process: 'procurement' }, RO)).status, 400, 'title too short');
  assert.equal((await call('POST', '/process-assessment', { title: 'Procurement review 2026', process: 'space' }, RO)).status, 400, 'unknown process');
  assert.equal((await call('POST', '/process-assessment', { title: 'Procurement review 2026', process: 'procurement' }, BOT)).status, 403, 'a service identity never creates');
  r = await call('POST', '/process-assessment', { title: 'Procurement deep-dive Q1', process: 'procurement', owner: 'proc.head', period: '2026-Q1', objective: 'Assess procurement controls', scope: 'All purchases > SAR 100k' }, RO);
  assert.equal(r.status, 200, r.text); const id = r.json.id; assert.equal(r.json.band, 'not_rated'); assert.ok(r.json.areas.length);
  // cannot submit with no finding
  assert.equal((await call('POST', '/process-assessment/' + id + '/submit', {}, RO)).status, 409);
  // findings
  assert.equal((await call('POST', '/process-assessment/' + id + '/findings', { area: 'x', observation: 'short', likelihood: 3, impact: 3, recommendation: 'ok' }, RO)).status, 400, 'observation too short');
  r = await call('POST', '/process-assessment/' + id + '/findings', { area: 'Single-source buys', observation: 'Three emergency single-source purchases above the limit with no committee sign-off (synthetic).', likelihood: 4, impact: 4, root_cause: 'No enforced control', recommendation: 'Require committee approval for single-source above SAR 100k', owner: 'proc.head', due: '2026-03-31' }, RO);
  assert.equal(r.status, 200, r.text); const f1 = r.json.findings[0]; assert.equal(f1.rating, 16); assert.equal(f1.band, 'critical');
  r = await call('POST', '/process-assessment/' + id + '/findings', { area: 'Three-way match', observation: 'Match performed but not evidenced in 2 of 20 sampled (synthetic).', likelihood: 2, impact: 2, recommendation: 'Attach the match evidence' }, RO);
  assert.equal(r.json.rating, 16, 'overall rating = highest open finding'); assert.equal(r.json.band, 'critical');
  // raise a GRC action for the critical finding
  r = await call('POST', '/process-assessment/' + id + '/findings/' + f1.id + '/action', {}, RO); assert.equal(r.status, 200, r.text);
  const gf = r.json.findings.find((x) => x.id === f1.id); assert.match(gf.grc_action, /^ACT-/);
  assert.ok(e.app.store.collection('grc_actions').get(gf.grc_action), 'the GRC action exists');
  assert.equal((await call('POST', '/process-assessment/' + id + '/findings/' + f1.id + '/action', {}, RO)).status, 409, 'one action per finding');
  // workflow four eyes
  r = await call('POST', '/process-assessment/' + id + '/submit', {}, RO); assert.equal(r.json.status, 'in_review');
  assert.equal((await call('POST', '/process-assessment/' + id + '/approve', {}, Object.assign({}, RO, { role: 'admin' }))).status, 403, 'the author cannot approve');
  assert.equal((await call('POST', '/process-assessment/' + id + '/approve', {}, BOT)).status, 403);
  r = await call('POST', '/process-assessment/' + id + '/approve', {}, RISK); assert.equal(r.status, 200, r.text); assert.equal(r.json.status, 'approved');
  assert.equal((await call('POST', '/process-assessment/' + id + '/findings', { area: 'x', observation: 'late change', likelihood: 1, impact: 1, recommendation: 'no' }, RO)).status, 409, 'approved is frozen');
  // report
  e.app.store.collection('pentest_settings').put({ id: 'report_brand', values: { org_name: (ZYB_ORG.short + ' (synthetic)'), letterhead: 'data:image/png;base64,AAAA' } });
  r = await call('GET', '/process-assessment/' + id + '/report?format=html', undefined, RO); assert.equal(r.status, 200);
  assert.match(r.json.html, /background:#fff/); assert.match(r.json.html, /print-color-adjust:exact/); assert.match(r.json.html, new RegExp('data:image\\/png|' + ZYB_ORG.short)); assert.match(r.json.html, /Single-source buys/); assert.match(r.json.html, /Action plan/);
  r = await call('GET', '/process-assessment/' + id + '/report?format=csv', undefined, RO); assert.match(r.json.csv, /Three-way match/); assert.ok(!/\n=/.test(r.json.csv));
  // reopen
  r = await call('POST', '/process-assessment/' + id + '/reopen', { reason: 'new evidence (synthetic)' }, RISK); assert.equal(r.json.status, 'draft');
  const au = e.app.store.auditTail(100).filter((a) => /^procassess\./.test(a.action));
  for (const a of ['create', 'finding', 'action', 'submit', 'approve', 'reopen', 'report']) assert.ok(au.some((x) => x.action === 'procassess.' + a), 'audited: ' + a);
});
