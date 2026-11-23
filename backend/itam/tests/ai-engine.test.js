// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// AI Engine switch (engine/ai-engine.js + engine/ai-backend.js): the Messages <-> chat-completions translation (tools both
// ways, tool results, <think> stripped, bad tool arguments), each mode (local through a fake OpenAI-compatible gateway, Claude
// through a fake SDK, off), the placeholder key never sent to Anthropic, "external AI allowed" per mode, the routes (operator
// read, admin change, AI identity refused, validation errors naming the field, public address refused, audit), the probe, and a
// real AI feature (NCA IT Audit advisor, no SDK installed) answering through the local model. Synthetic data only.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');
const B = require('../engine/ai-backend');

const VIEW = { user: 'vera.syn', role: 'viewer' }, OP = { user: 'nora.syn', role: 'operator' }, ADM = { user: 'syed', role: 'admin' }, BOT = { user: 'ai:engine-bot', role: 'admin' };
const LOCAL = { mode: 'local', local: { api: 'openai', base_url: 'http://10.20.0.40:8000/v1', model: 'synthetic-local-7b' } };

// a fake OpenAI-compatible gateway: records each request, answers by script
function gateway(script) {
  const seen = [];
  const fetch = async (url, init) => {
    const req = JSON.parse(init.body); seen.push({ url, headers: init.headers, req });
    const r = script(req, seen.length);
    return { status: r.status || 200, text: async () => (typeof r.body === 'string' ? r.body : JSON.stringify(r.body)) };
  };
  return { fetch, seen };
}
const say = (text, extra) => ({ body: Object.assign({ id: 'cmpl-syn', model: 'synthetic-local-7b', choices: [{ index: 0, finish_reason: 'stop', message: { role: 'assistant', content: text } }], usage: { prompt_tokens: 11, completion_tokens: 3 } }, extra || {}) });
const call = (name, args, id) => ({ body: { id: 'cmpl-syn', model: 'synthetic-local-7b', choices: [{ index: 0, finish_reason: 'tool_calls', message: { role: 'assistant', content: null, tool_calls: [{ id: id || 'call_1', type: 'function', function: { name, arguments: typeof args === 'string' ? args : JSON.stringify(args) } }] } }], usage: { prompt_tokens: 20, completion_tokens: 8 } } });

test('the two copies of ai-backend.js are the same file (IT Asset Management and SIEM)', () => {
  const siem = path.join(__dirname, '..', '..', 'siem', 'engine', 'util', 'ai-backend.js');
  if (!fs.existsSync(siem)) return;   // the SIEM repository is not beside this one here
  assert.equal(fs.readFileSync(siem, 'utf8'), fs.readFileSync(path.join(__dirname, '..', 'engine', 'ai-backend.js'), 'utf8'));
});

test('the two copies of ai-schema.js are the same file (IT Asset Management and SIEM)', () => {
  const siem = path.join(__dirname, '..', '..', 'siem', 'engine', 'util', 'ai-schema.js');
  if (!fs.existsSync(siem)) return;   // the SIEM repository is not beside this one here
  assert.equal(fs.readFileSync(siem, 'utf8'), fs.readFileSync(path.join(__dirname, '..', 'engine', 'ai-schema.js'), 'utf8'));
});

test('translation: system, tools, tool_use / tool_result both ways, thinking dropped, <think> stripped, bad tool arguments contained', () => {
  const L = { model: 'm', max_tokens: 2048 };
  const o = B.toOpenAI({ model: 'claude-opus-5-5', max_tokens: 9000, thinking: { type: 'adaptive' }, system: [{ type: 'text', text: 'You are synthetic.' }],
    tools: [{ name: 'lookup', description: 'd', input_schema: { type: 'object', properties: { q: { type: 'string' } } } }], tool_choice: { type: 'any' },
    messages: [{ role: 'user', content: 'hello' }, { role: 'assistant', content: [{ type: 'thinking', thinking: 'x' }, { type: 'text', text: 'checking' }, { type: 'tool_use', id: 't1', name: 'lookup', input: { q: 'a' } }] },
      { role: 'user', content: [{ type: 'tool_result', tool_use_id: 't1', content: 'found 3' }, { type: 'tool_result', tool_use_id: 't2', content: [{ type: 'text', text: 'nope' }], is_error: true }] }] }, L);
  assert.equal(o.model, 'm'); assert.equal(o.max_tokens, 2048, 'capped to the local maximum'); assert.equal(o.thinking, undefined);
  assert.deepEqual(o.messages[0], { role: 'system', content: 'You are synthetic.' });
  assert.equal(o.messages[2].tool_calls[0].function.name, 'lookup'); assert.equal(o.messages[2].content, 'checking');
  assert.deepEqual(o.messages[3], { role: 'tool', tool_call_id: 't1', content: 'found 3' }); assert.equal(o.messages[4].content, 'ERROR: nope');
  assert.equal(o.tools[0].function.parameters.properties.q.type, 'string'); assert.equal(o.tool_choice, 'required');
  const r = B.fromOpenAI(call('lookup', { q: 'b' }).body, L); assert.equal(r.stop_reason, 'tool_use'); assert.deepEqual(r.content[0], { type: 'tool_use', id: 'call_1', name: 'lookup', input: { q: 'b' } });
  assert.equal(B.fromOpenAI(say('<think>private</think>The answer.').body, L).content[0].text, 'The answer.', 'reasoning is not the answer');
  assert.ok(B.fromOpenAI(call('lookup', '{not json').body, L).content[0].input._invalid_arguments, 'bad arguments are passed as invalid, not executed as {}');
  assert.equal(B.fromOpenAI(say('x', { choices: [{ finish_reason: 'length', message: { content: 'x' } }] }).body, L).stop_reason, 'max_tokens');
});

test('modes: local through the gateway, Claude through the SDK (placeholder key refused), off refused; allowed() per mode', async () => {
  let cfg = LOCAL; const g = gateway(() => say('OK'));
  const anth = []; class FakeSdk { constructor(o) { this.o = o; this.messages = { create: async (p) => { anth.push({ o: this.o, p }); return { model: 'claude-opus-5-5', content: [{ type: 'text', text: 'from claude' }], stop_reason: 'end_turn', usage: {} }; } }; } }
  const prevKey = process.env.ANTHROPIC_API_KEY; delete process.env.ANTHROPIC_API_KEY;
  B.configure({ get: () => cfg, localKey: () => 'sk-local-synthetic', fetch: g.fetch });
  try {
    assert.equal(process.env.ANTHROPIC_API_KEY, B.PLACEHOLDER, 'local mode: key checks pass without a real key');
    const C = B.wrap(FakeSdk), c = new C({ apiKey: process.env.ANTHROPIC_API_KEY });
    let r = await c.messages.create({ model: 'claude-opus-5-5', max_tokens: 100, thinking: { type: 'adaptive' }, messages: [{ role: 'user', content: 'hi' }] });
    assert.equal(r.content[0].text, 'OK'); assert.equal(anth.length, 0, 'nothing went to Anthropic');
    assert.equal(g.seen[0].url, 'http://10.20.0.40:8000/v1/chat/completions'); assert.equal(g.seen[0].req.model, 'synthetic-local-7b'); assert.equal(g.seen[0].headers.Authorization, 'Bearer sk-local-synthetic');
    assert.equal(B.allowed({ external_ai_allowed: false }), true, 'local keeps data inside: allowed without the external switch');
    cfg = { mode: 'anthropic' }; B.configure({});
    assert.equal(process.env.ANTHROPIC_API_KEY, undefined, 'the placeholder is removed again');
    assert.equal(B.allowed({ external_ai_allowed: false }), false); assert.equal(B.allowed({ external_ai_allowed: true }), true);
    await assert.rejects(new C({ apiKey: B.PLACEHOLDER }).messages.create({ model: 'x', max_tokens: 1, messages: [] }), /no Anthropic API key/);
    r = await new C({ apiKey: 'sk-ant-synthetic' }).messages.create({ model: 'claude-opus-5-5', max_tokens: 1, messages: [] }); assert.equal(r.content[0].text, 'from claude');
    await assert.rejects(new (B.wrap(null))({ apiKey: 'sk-ant-synthetic' }).messages.create({ model: 'x', max_tokens: 1, messages: [] }), /SDK not installed/);
    cfg = { mode: 'off' }; B.configure({});
    await assert.rejects(new C({ apiKey: 'sk-ant-synthetic' }).messages.create({ model: 'x', max_tokens: 1, messages: [] }), /switched off/); assert.equal(B.allowed({ external_ai_allowed: true }), false);
    // gateway errors name the cause
    cfg = LOCAL; B.configure({ fetch: gateway(() => ({ status: 404, body: { error: { message: 'no route' } } })).fetch });
    await assert.rejects(new C({}).messages.create({ model: 'x', max_tokens: 1, messages: [{ role: 'user', content: 'x' }] }), /no \/v1\/chat\/completions/);
    B.configure({ fetch: async () => { throw Object.assign(new Error('connect'), { cause: { code: 'ECONNREFUSED' } }); } });
    await assert.rejects(new C({}).messages.create({ model: 'x', max_tokens: 1, messages: [{ role: 'user', content: 'x' }] }), /not reachable \(ECONNREFUSED\)/);
  } finally { B.configure({ get: () => null, fetch: (...a) => globalThis.fetch(...a) }); if (prevKey === undefined) delete process.env.ANTHROPIC_API_KEY; else process.env.ANTHROPIC_API_KEY = prevKey; }
});

async function setup(t, script) {
  const e = await startApp({ noAi: true }); t.after(() => { B.configure({ get: () => null }); return e.close(); });
  const g = gateway(script || (() => say('OK')));
  registerDuty(e.app.srv, e.app, { noTimer: true, python: process.env.PYTHON || 'python3', aiFetch: g.fetch, aiEngineSdk: null, aiLocalKey: () => '', aiAnthropicKey: () => '' });
  const req = (m, p, b, who) => e.req(m, p, Object.assign(b !== undefined ? { body: b } : {}, who));
  return { e, g, req };
}

test('routes: operator reads, admin switches, AI identity refused, validation names the field, public address refused, audited', async (t) => {
  const { e, req } = await setup(t);
  assert.equal((await req('GET', '/ai-engine', undefined, VIEW)).status, 403);
  let r = await req('GET', '/ai-engine', undefined, OP); assert.equal(r.status, 200, r.text); assert.equal(r.json.mode, 'anthropic'); assert.equal(r.json.data_leaves_network, true);
  assert.equal((await req('PUT', '/ai-engine', LOCAL, OP)).status, 403);
  assert.equal((await req('PUT', '/ai-engine', LOCAL, BOT)).status, 403, 'an AI identity never changes the AI engine');
  r = await req('PUT', '/ai-engine', { mode: 'cloud' }, ADM); assert.equal(r.status, 400); assert.match(r.text, /mode/);
  r = await req('PUT', '/ai-engine', { mode: 'local', local: { base_url: 'http://10.20.0.40:8000/v1' } }, ADM); assert.equal(r.status, 400); assert.match(r.text, /model/);
  r = await req('PUT', '/ai-engine', { mode: 'local', local: { base_url: 'http://8.8.8.8:8000/v1', model: 'm' } }, ADM); assert.equal(r.status, 400); assert.match(r.text, /public address/);
  r = await req('PUT', '/ai-engine', { mode: 'local', local: { base_url: 'http://user:pw@10.0.0.1/v1', model: 'm' } }, ADM); assert.equal(r.status, 400); assert.match(r.text, /user or password/);
  r = await req('PUT', '/ai-engine', { mode: 'local', local: { api: 'grpc', base_url: 'http://10.0.0.1/v1', model: 'm' } }, ADM); assert.equal(r.status, 400); assert.match(r.text, /api/);
  r = await req('PUT', '/ai-engine', LOCAL, ADM); assert.equal(r.status, 200, r.text);
  assert.equal(r.json.mode, 'local'); assert.equal(r.json.data_leaves_network, false); assert.equal(r.json.local.host, '10.20.0.40:8000'); assert.match(r.json.effective, /nothing leaves the network/);
  const a = e.app.store.auditTail(30).find((x) => x.action === 'ai.engine.save');
  assert.ok(a && a.by === 'syed' && a.detail.from.mode === 'anthropic' && a.detail.to.mode === 'local' && a.detail.to.model === 'synthetic-local-7b');
});

test('probe: a plain answer then a tool call; a model that will not call tools is reported; recorded and audited', async (t) => {
  let tools = true;
  const { e, req } = await setup(t, (q) => (q.tools ? (tools ? call('get_asset_count', { site: 'HQ' }) : say('I think about 40.')) : say('OK')));
  assert.equal((await req('POST', '/ai-engine/test', undefined, ADM)).status, 424, 'Claude selected with no SDK here: said');
  await req('PUT', '/ai-engine', LOCAL, ADM);
  assert.equal((await req('POST', '/ai-engine/test', undefined, OP)).status, 403);
  let r = await req('POST', '/ai-engine/test', undefined, ADM); assert.equal(r.status, 200, r.text);
  assert.equal(r.json.ok, true); assert.equal(r.json.steps[0].text, 'OK'); assert.equal(r.json.steps[1].ok, true); assert.equal(r.json.steps[1].tool, 'get_asset_count');
  tools = false; r = await req('POST', '/ai-engine/test', undefined, ADM); assert.equal(r.json.steps[1].ok, false); assert.match(r.json.steps[1].error, /did not call the tool/);
  assert.equal((await req('GET', '/ai-engine', undefined, OP)).json.last_test.steps[1].ok, false);
  assert.ok(e.app.store.auditTail(30).some((x) => x.action === 'ai.engine.test' && x.by === 'syed'));
  await req('PUT', '/ai-engine', { mode: 'off' }, ADM); assert.equal((await req('POST', '/ai-engine/test', undefined, ADM)).status, 409);
});

test('a real AI feature answers through the local model with no Anthropic SDK and no "external AI allowed"', async (t) => {
  const { e, g, req } = await setup(t, (q, n) => (n === 1 ? call('audit', {}) : say('The audit plan is on track (synthetic).')));
  let r = await req('POST', '/nca-itaudit-intel/ask', { question: 'Where does the audit plan stand?' }, OP); assert.equal(r.status, 424, 'Claude selected, nothing allowed: refused as before');
  await req('PUT', '/ai-engine', LOCAL, ADM);
  r = await req('POST', '/nca-itaudit-intel/ask', { question: 'Where does the audit plan stand?' }, OP); assert.equal(r.status, 200, r.text);
  assert.match(JSON.stringify(r.json), /on track \(synthetic\)/);
  assert.equal(g.seen[0].req.model, 'synthetic-local-7b'); assert.ok(g.seen[0].req.tools.some((x) => x.function.name === 'audit'), 'the feature\'s tools were offered to the local model');
  assert.ok(g.seen[1].req.messages.some((m) => m.role === 'tool' && /untrusted|<untrusted/i.test(m.content)), 'tool output still wrapped as untrusted (ai-guard)');
  assert.equal((await req('GET', '/ai-engine', undefined, OP)).json.calls_today.by_mode.local >= 2, true);
  void e;
});

test('per-feature routing: a feature routed to the local model works while Claude stays the default and "external AI allowed" is off; rules saved and audited', async (t) => {
  const { e, g, req } = await setup(t, (q, n) => (n === 1 ? call('audit', {}) : say('Routed to the local model (synthetic).')));
  const ROUTED = { mode: 'anthropic', local: LOCAL.local, routes: [{ match: 'itam.nca-itaudit-advisor', engine: 'local' }] };
  let r = await req('PUT', '/ai-engine', Object.assign({}, ROUTED, { routes: [{ match: 'not valid!', engine: 'local' }] }), ADM); assert.equal(r.status, 400); assert.match(r.json.error, /routes\[0\]\.match/);
  assert.equal((await req('PUT', '/ai-engine', ROUTED, OP)).status, 403, 'an administrator sets the routing');
  r = await req('PUT', '/ai-engine', ROUTED, ADM); assert.equal(r.status, 200, r.text); assert.equal(r.json.routes.length, 1); assert.equal(r.json.data_leaves_network, true, 'Claude is still the default for every other feature');
  assert.match(r.json.effective, /1 routing rule\(s\); every other feature uses Claude - features routed to Claude are refused until "external AI allowed" is on/);
  assert.ok(e.app.store.auditTail(20).some((x) => x.action === 'ai.engine.save' && JSON.stringify(x.detail.routes) === JSON.stringify(ROUTED.routes)));
  r = await req('POST', '/nca-itaudit-intel/ask', { question: 'Where does the audit plan stand?' }, OP); assert.equal(r.status, 200, r.text);
  assert.match(JSON.stringify(r.json), /Routed to the local model \(synthetic\)/); assert.equal(g.seen[0].req.model, 'synthetic-local-7b');
  const v = (await req('GET', '/ai-engine', undefined, OP)).json; const f = v.features_today.find((x) => x.feature === 'itam.nca-itaudit-advisor');
  assert.ok(f && f.engine === 'local' && f.rule === 'itam.nca-itaudit-advisor', 'the call is counted under its feature and rule');
});
