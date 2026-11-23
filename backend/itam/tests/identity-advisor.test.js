// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// AI identity advisor (engine/identity-advisor.js, Identity & Sign-in studio): admins only and a person; the page's summary is
// validated (undeclared fields dropped, sizes capped), IP addresses masked to /24, secrets redacted, framed untrusted; external AI
// must be allowed; one budgeted model call with NO tools; the answer is labelled an AI draft; validation errors name the field;
// audited. SYNTHETIC accounts and a fake model.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');
const { cleanFacts, maskIp } = require('../engine/identity-advisor');

const ADM = { user: 'syed', role: 'admin' }, OP = { user: 'nora.syn', role: 'operator' }, BOT = { user: 'ai:identity', role: 'admin' };
const FACTS = { kpis: { active: 12, admins: 3, mfa_pct: 75, admins_no_mfa: 1, dormant: 2, attacks: 1, attacks_followed_by_success: 0, posture: 62, sso_enabled: true, extra_kpi: 9 },
  accounts: [{ user: 'omar.syn', role: 'admin', mfa: false, risk: 55, why: ['administrator without MFA', 'first sign-in from 10.9.8.77'], password: 'Hunter2-synthetic' }],
  unusual: [{ user: 'omar.syn', at: '2026-11-05T22:10:00Z', score: 65, why: ['first sign-in from 203.0.113.45'] }],
  attacks: [{ kind: 'Password spraying', who: '198.51.100.23', at: '2026-11-05T20:00:00Z', detail: '7 accounts from one address', ok: false }],
  posture_points: ['MFA coverage 75%'], secret_field: 'should be dropped' };

test('cleanFacts keeps only declared fields, masks addresses to /24, caps sizes', () => {
  const o = cleanFacts(FACTS);
  assert.ok(!('secret_field' in o)); assert.ok(!('extra_kpi' in o.kpis)); assert.ok(!('password' in o.accounts[0]));
  assert.equal(o.accounts[0].why[1], 'first sign-in from 10.9.8.x'); assert.equal(o.attacks[0].who, '198.51.100.x');
  assert.equal(maskIp('2001:db8:85a3:8d3:1319:8a2e:370:7348'), '2001:db8:85a3::');
  assert.throws(() => cleanFacts(null), /facts/); assert.throws(() => cleanFacts([1]), /facts/);
  const big = { accounts: Array.from({ length: 500 }, (_, i) => ({ user: 'u' + i + '.syn', why: ['x'.repeat(200)] })) };
  assert.equal(cleanFacts(big).accounts.length, 60, 'at most 60 accounts');
});

test('roles, validation, AI off, then one guarded call with no tools; audited', async (t) => {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  const seen = [];
  const sdk = class { constructor() { this.messages = { create: async (p) => { seen.push(JSON.parse(JSON.stringify(p))); return { model: 'claude-opus-5-5', stop_reason: 'end_turn', content: [{ type: 'text', text: 'Turn MFA on for omar.syn first.' }], usage: { input_tokens: 50, output_tokens: 12 } }; } }; } };
  registerDuty(e.app.srv, e.app, { noTimer: true, python: process.env.PYTHON || 'python3', identityAiSdk: sdk, identityAiKey: () => 'sk-ant-synthetic-itam' });
  const call = (m, p, b, who) => e.req(m, p, Object.assign(b !== undefined ? { body: b } : {}, who));
  assert.equal((await call('POST', '/identity-advisor/ask', { facts: FACTS }, OP)).status, 403, 'operators cannot read every account');
  assert.equal((await call('GET', '/identity-advisor/status', undefined, OP)).status, 403);
  let r = await call('POST', '/identity-advisor/ask', { facts: FACTS }, BOT); assert.equal(r.status, 403); assert.match(r.json.error, /person/);
  r = await call('POST', '/identity-advisor/ask', {}, ADM); assert.equal(r.status, 400); assert.match(r.json.error, /^facts/);
  r = await call('POST', '/identity-advisor/ask', { question: 'hi', facts: FACTS }, ADM); assert.equal(r.status, 400); assert.match(r.json.error, /^question/);
  r = await call('POST', '/identity-advisor/ask', { facts: FACTS }, ADM); assert.equal(r.status, 424, 'external AI not allowed yet'); assert.match(r.json.error, /external_ai_allowed/);
  assert.equal(seen.length, 0, 'no model call while AI is not allowed');
  e.app.settings.update({ external_ai_allowed: true }, ADM);
  assert.equal((await call('GET', '/identity-advisor/status', undefined, ADM)).json.enabled, true);
  r = await call('POST', '/identity-advisor/ask', { facts: FACTS }, ADM); assert.equal(r.status, 200, r.raw);
  assert.match(r.json.label, /AI draft/); assert.match(r.json.answer, /omar\.syn/);
  assert.equal(seen.length, 1); assert.ok(!seen[0].tools || !seen[0].tools.length, 'no tools: the advisor can change nothing');
  const sent = JSON.stringify(seen[0].messages);
  assert.ok(!/Hunter2-synthetic|should be dropped/.test(sent), 'undeclared fields never reach the model');
  assert.ok(!/10\.9\.8\.77|203\.0\.113\.45|198\.51\.100\.23/.test(sent), 'addresses masked to /24');
  assert.match(sent, /<untrusted source=/); assert.match(seen[0].system, /never turn MFA off/);
  const a = e.app.store.auditTail(50).find((x) => x.action === 'identity_advisor.ask'); assert.ok(a && a.by === ADM.user && a.role === 'admin' && a.detail.accounts === 1);
});
