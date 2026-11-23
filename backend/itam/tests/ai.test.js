// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp, S } = require('./helpers');
const { validateOutput } = require('../engine/ai/validate');

const admin = { user: 'adm', role: 'admin' };

test("provider 'not configured' until private_url is set; runs are refused 409", async (t) => {
  const h = await startApp({ noAi: true }); // private_url = ''
  t.after(() => h.close());
  const st = (await h.req('GET', '/status', { role: 'viewer' })).json;
  assert.equal(st.ai.state, 'not_configured');
  await h.req('POST', '/assets', { body: { name: 'x', type: 'other', serial: 'SX' } });
  const r = await h.req('POST', '/ai/run/classify', {});
  assert.equal(r.status, 409); assert.equal(r.json.code, 'not_configured');
  assert.equal(h.fake.requests.length, 0, 'nothing reached the model');
});

test('validateOutput drops refs that were not supplied (anti-hallucination)', () => {
  const out = validateOutput('relate', '```json\n{"relationships":[{"from":"as_1","to":"as_2","type":"runs_on"},{"from":"as_1","to":"as_X","type":"depends_on"}]}\n```', { ids: ['as_1', 'as_2'] });
  assert.equal(out.validation.ok, true);
  assert.equal(out.ai.relationships.length, 1);
  assert.ok(out.validation.warnings.some((w) => /unknown id/.test(w)));
});

test('AI classify: produces advisory findings; bogus ref from model is dropped', async (t) => {
  const h = await startApp({});
  t.after(() => h.close());
  await h.req('POST', '/assets', { body: { name: 'srv-a', type: 'other', serial: 'SA1' } });
  await h.req('POST', '/assets', { body: { name: 'srv-b', type: 'other', serial: 'SB1' } });
  const st = (await h.req('GET', '/status', { role: 'viewer' })).json;
  assert.equal(st.ai.state, 'ready');
  const job = await h.runAI('classify');
  assert.equal(job.status, 'done');
  const findings = (await h.req('GET', '/ai/findings?status=open', { role: 'viewer' })).json.findings;
  assert.ok(findings.some((f) => f.kind === 'ai_classify'), 'classification suggestions recorded');
  assert.ok(findings.every((f) => f.ai_label === 'AI — verify'), 'all AI findings labelled');
  const res = (await h.req('GET', `/ai/results/${job.result_ref}`, { role: 'viewer' })).json;
  assert.ok(res.validation.warnings.some((w) => /was not supplied/.test(w)), 'invented ref flagged');
});

test('AI relate: proposes CMDB relationships (status proposed, needs human confirm)', async (t) => {
  const h = await startApp({});
  t.after(() => h.close());
  const a = (await h.req('POST', '/assets', { body: { name: 'vm1', type: 'vm', serial: 'VM1' } })).json.asset;
  const b = (await h.req('POST', '/assets', { body: { name: 'host1', type: 'server', serial: 'H1' } })).json.asset;
  const job = await h.runAI('relate');
  assert.equal(job.status, 'done');
  const rels = (await h.req('GET', '/cmdb', { role: 'viewer' })).json.relationships;
  const proposed = rels.find((r) => r.source === 'ai');
  assert.ok(proposed, 'an AI relationship was proposed');
  assert.equal(proposed.status, 'proposed', 'high-impact AI link is not auto-confirmed');
  // operator confirms it
  const conf = (await h.req('POST', '/cmdb', { body: { from: proposed.from, to: proposed.to, type: proposed.type, confirm: true } })).json;
  assert.equal(conf.relationship.status, 'confirmed');
});

test('AI refresh plan is stored and advisory', async (t) => {
  const h = await startApp({});
  t.after(() => h.close());
  await h.req('POST', '/assets', { body: { name: 'old1', type: 'server', serial: 'O1', eol: '2025-01-01' } });
  const job = await h.runAI('refresh');
  assert.equal(job.status, 'done');
  const plan = (await h.req('GET', '/ai/refresh-plan', { role: 'viewer' })).json;
  assert.ok(plan.summary.includes(S)); assert.ok(plan.items.length >= 1);
  assert.equal(plan.ai_label, 'AI — verify');
});

test('deterministic findings work with NO model: EOL, warranty, missing owner, licence over', async (t) => {
  const h = await startApp({ noAi: true });
  t.after(() => h.close());
  // past-EOL server, no owner
  await h.req('POST', '/assets', { body: { name: 'eol-srv', type: 'server', serial: 'E1', eol: '2020-01-01' } });
  // over-deployed licence
  await h.req('POST', '/assets', { body: { name: 'c1', type: 'workstation', serial: 'C1', software: [{ name: 'Acme CAD', publisher: 'Acme' }] } });
  await h.req('POST', '/assets', { body: { name: 'c2', type: 'workstation', serial: 'C2', software: [{ name: 'Acme CAD', publisher: 'Acme' }] } });
  await h.req('POST', '/licences', { body: { id: 'L1', product: 'Acme CAD', seats: 1 } });
  const regen = (await h.req('POST', '/ai/findings/regenerate', {})).json;
  assert.ok(regen.created >= 3);
  const findings = (await h.req('GET', '/ai/findings?status=open', { role: 'viewer' })).json.findings;
  assert.ok(findings.some((f) => f.kind === 'eol_passed'));
  assert.ok(findings.some((f) => f.kind === 'missing_owner'));
  assert.ok(findings.some((f) => f.kind === 'licence_over'));
  // dismiss one and confirm regenerate does not resurface it
  const eol = findings.find((f) => f.kind === 'eol_passed');
  await h.req('POST', `/ai/findings/${eol.id}/dismiss`, { body: { reason: 'accepted risk' } });
  await h.req('POST', '/ai/findings/regenerate', {});
  const after = (await h.req('GET', '/ai/findings?status=open', { role: 'viewer' })).json.findings;
  assert.ok(!after.some((f) => f.id === eol.id), 'dismissed finding stays dismissed');
});
