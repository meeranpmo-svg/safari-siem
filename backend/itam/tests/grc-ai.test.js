// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Claude for the AI GRC Consultant (and every ITAM AI feature): ai/anthropic.js behind the model provider. The private
// endpoint not configured + a key stored = direct Claude, still gated by external_ai_allowed; "ask the consultant" and
// "Investigate with AI" on a GRC work item get Claude's answer with invented record ids stripped; a refused key is named.
// The SDK is a fake: no network, no key.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');
const { createProvider } = require('../engine/ai/provider');
const { createAnthropic } = require('../engine/ai/anthropic');

const ADM = { user: 'syed', role: 'admin', ip: '' };
const now = () => Date.parse('2026-10-15T08:00:00Z');

function fakeSdk(reply, seen) {
  const create = async (p) => { seen.push(JSON.parse(JSON.stringify(p))); return reply(p); };
  return class { constructor() { this.messages = { create }; this.beta = { messages: { create } }; } };
}
const textReply = (t) => () => ({ model: 'claude-opus-5-5', stop_reason: 'end_turn', content: [{ type: 'thinking', thinking: '', signature: 's' }, { type: 'text', text: t }], usage: { input_tokens: 100, output_tokens: 20 } });

function useClaude(e, reply, seen, key = 'sk-ant-test') {
  e.app.provider = createProvider({ config: e.app.config, secrets: {}, getSettings: e.app.settings.get, anthropic: createAnthropic({ config: e.app.config, getKey: () => key, sdk: fakeSdk(reply, seen) }) });
}

test('provider: no private endpoint + key → Claude, only once external AI is allowed', async (t) => {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  const seen = [];
  useClaude(e, textReply('hello'), seen);
  let s = await e.app.provider.status();
  assert.equal(s.provider, 'anthropic'); assert.equal(s.state, 'external_not_allowed');
  assert.equal(e.app.provider.statusSync().enabled, false);
  assert.equal((await e.app.provider.call({ system: 's', prompt: 'p' })).ok, false, 'nothing sent before it is allowed');
  assert.equal(seen.length, 0);
  e.app.settings.update({ external_ai_allowed: true }, ADM);
  s = await e.app.provider.status(); assert.equal(s.state, 'ready'); assert.equal(s.model, 'claude-opus-5-5');
  const r = await e.app.provider.call({ system: 'sys', prompt: 'pp' });
  assert.equal(r.ok, true); assert.equal(r.text, 'hello'); assert.deepEqual(r.usage, { input: 100, output: 20 });
  assert.equal(seen[0].model, 'claude-opus-5-5'); assert.deepEqual(seen[0].thinking, { type: 'adaptive' }); assert.match(seen[0].system, /^sys\n\nSECURITY RULES/, 'the caller system prompt, then the untrusted-data rule (engine/ai-guard.js)');
  // no key: stays on the "not configured" message, never on Claude
  useClaude(e, textReply('x'), seen, '');
  s = await e.app.provider.status(); assert.equal(s.provider, 'private'); assert.equal(s.state, 'not_configured');
  // a refused key is named
  useClaude(e, () => { throw Object.assign(new Error('invalid x-api-key'), { status: 401 }); }, seen);
  const bad = await e.app.provider.call({ system: 's', prompt: 'p' });
  assert.equal(bad.ok, false); assert.match(bad.message, /key was refused/);
});

test('GRC consultant with Claude: ask + Investigate with AI on a work item; invented refs stripped', async (t) => {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  const D = registerDuty(e.app.srv, e.app, { noTimer: true, now });
  e.app.addons.grc.drillPut({ title: 'Core insurance DR', system: 'Core Insurance', type: 'failover', scheduled: '2025-01-10', frequency_months: 12 }, ADM);
  await D.patrol('grc');
  const gap = D.list({ engineer: 'grc' }).items.find((x) => x.kind === 'drill-overdue');
  const ref = 'gap:' + gap.key, seen = [];
  useClaude(e, textReply(JSON.stringify({ answer: 'The core insurance system has never had a recovery test.', actions: [{ action: 'Run a DR failover test with RTO/RPO targets', owner_role: 'IT DR lead', refs: [ref, 'policy:INVENTED-9'] }], refs: [ref, 'control:made-up'] })), seen);
  e.app.settings.update({ external_ai_allowed: true }, ADM);
  const a = await e.req('POST', '/grc/consult', { user: 'ali', role: 'operator', body: { question: 'What is our biggest BCM gap?' } });
  assert.equal(a.status, 200, a.text);
  assert.equal(a.json.kind, 'ai'); assert.equal(a.json.model, 'claude-opus-5-5');
  assert.deepEqual(a.json.refs, [ref]); assert.deepEqual(a.json.actions[0].refs, [ref]); assert.equal(a.json.refs_dropped, 2);
  assert.match(seen[0].messages[0].content, /What is our biggest BCM gap/);
  // the duty desk: AI on, Investigate with AI writes the analysis, nothing approved or changed
  assert.equal(D.engineers().find((x) => x.id === 'grc').ai.enabled, true);
  const r = await e.req('POST', `/duty/items/${gap.id}/investigate`, { user: 'ali', role: 'operator', body: { ai: true } });
  assert.equal(r.status, 200, r.text);
  const it = D.get(gap.id);
  assert.match(it.ai.answer, /never had a recovery test/); assert.match(it.ai.answer, /Next steps:\n1\. Run a DR failover test/);
  assert.equal(it.status, 'needs-human'); assert.deepEqual(it.changes || [], []);
  const rd = (await e.req('GET', '/duty/readiness', { role: 'viewer' })).json.engineers.find((x) => x.id === 'grc');
  assert.ok(rd.checks.some((c) => c.name === 'AI answers' && c.ok === true && /Claude/.test(c.detail)));
  const audit = (await e.req('GET', '/audit?limit=200', { role: 'admin' })).json.audit;
  assert.ok(audit.some((x) => x.action === 'ai.call' && x.detail && x.detail.feature === 'grc_consult' && x.detail.status === 'ok'));
});
