// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Per-feature AI routing (util/ai-backend.js + util/ai-guard.js, the same files as IT Asset Management's): rules matched exact ->
// longest "prefix.*" -> "*" -> the mode; the feature named by the AI budget's admit() just before the call (AsyncLocalStorage, so
// two requests at once never borrow each other's feature); a feature routed to Claude refused - never sent - while "external AI
// allowed" is off, and allowed() answering per feature; a rule to "off" named in the refusal; validation of the rules naming the
// field; the status (data leaves the network when any rule sends to Claude); the AI Engine routes saving the rules (audited),
// counting calls per feature and testing every engine in use. SYNTHETIC prompts only.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const B = require('../engine/util/ai-backend');
const G = require('../engine/util/ai-guard');
const { createState } = require('../engine/soc/state');
const routes = require('../engine/aiengine/routes');

const LOCAL = { api: 'openai', base_url: 'http://10.20.0.40:8000/v1', model: 'synthetic-local-7b' };
const say = (text) => ({ id: 'c', model: 'synthetic-local-7b', choices: [{ finish_reason: 'stop', message: { role: 'assistant', content: text } }], usage: { prompt_tokens: 5, completion_tokens: 2 } });
function world(cfg, ext) {
  let C = Object.assign({ mode: 'anthropic', local: LOCAL, routes: [] }, cfg);
  const local = [], claude = [];
  class FakeAnthropic { constructor(o) { this.o = o; this.messages = { create: async (p) => { claude.push(p); return { id: 'm', model: 'claude-synthetic', content: [{ type: 'text', text: 'from claude' }], stop_reason: 'end_turn', usage: { input_tokens: 1, output_tokens: 1 } }; } }; } }
  B.configure({ get: () => C, localKey: () => '', fetch: async (url, init) => { local.push(JSON.parse(init.body)); return { status: 200, text: async () => JSON.stringify(say('from local')) }; }, onCall: null, externalAllowed: () => ext !== false });
  const Client = B.wrap(FakeAnthropic), budget = G.sharedBudget({ limits: () => ({ per_user_hour: 1000, per_user_day: 10000, daily_tokens: 1e9, max_prompt_chars: 1e6 }) });
  // what every AI feature does: admit (names the feature) then call the model
  const ask = async (feature) => { if (feature) budget.admit('ali.syn', feature, 10); const r = await new Client({ apiKey: 'sk-ant-synthetic' }).messages.create({ model: 'claude-opus-5-5', max_tokens: 50, messages: [{ role: 'user', content: 'hi' }] }); return r.content[0].text; };
  return { ask, local, claude, set: (c) => { C = Object.assign({}, C, c); } };
}
test.afterEach(() => { B.configure({ get: () => null, fetch: (...a) => globalThis.fetch(...a), externalAllowed: () => true }); if (process.env.ANTHROPIC_API_KEY === B.PLACEHOLDER) delete process.env.ANTHROPIC_API_KEY; });

test('matching: exact, then the longest prefix.*, then *, then the mode', () => {
  const c = B._norm({ mode: 'anthropic', local: LOCAL, routes: [{ match: 'dfir.*', engine: 'local' }, { match: 'dfir.ask.deep', engine: 'anthropic' }, { match: 'itam.*', engine: 'local' }, { match: 'itam.audit.*', engine: 'off' }, { match: 'bad pattern!', engine: 'local' }] });
  assert.equal(c.routes.length, 4, 'an invalid stored rule is ignored');
  const e = (f) => B.engineFor(f, c);
  assert.deepEqual(e('dfir.ask'), { engine: 'local', rule: 'dfir.*' }); assert.deepEqual(e('dfir.ask.deep'), { engine: 'anthropic', rule: 'dfir.ask.deep' });
  assert.equal(e('dfir').engine, 'local', 'dfir.* covers dfir itself'); assert.equal(e('dfirx.ask').engine, 'anthropic', 'a prefix stops at the dot');
  assert.deepEqual(e('itam.audit.plan'), { engine: 'off', rule: 'itam.audit.*' }, 'the longer prefix wins'); assert.equal(e('itam.cmdb').engine, 'local');
  assert.deepEqual(e('soc.copilot'), { engine: 'anthropic', rule: null }); assert.deepEqual(e(''), { engine: 'anthropic', rule: null });
  assert.equal(B.engineFor('soc.copilot', B._norm({ mode: 'anthropic', routes: [{ match: '*', engine: 'local' }] })).engine, 'local');
});

test('dispatch follows the feature named by admit(); requests at the same time keep their own feature', async () => {
  const w = world({ mode: 'anthropic', routes: [{ match: 'dfir.*', engine: 'local' }, { match: 'netops.*', engine: 'off' }] });
  assert.equal(await w.ask('dfir.ask'), 'from local'); assert.equal(w.local.length, 1); assert.equal(w.local[0].model, 'synthetic-local-7b');
  assert.equal(await w.ask('soc.copilot'), 'from claude'); assert.equal(w.claude.length, 1);
  await assert.rejects(w.ask('netops.ai'), (e) => e.status === 503 && /switched off for netops.ai \(AI Engine routing rule "netops\.\*"\)/.test(e.message));
  // ten requests at once, alternating features: none borrows another's engine
  const out = await Promise.all(Array.from({ length: 10 }, (_, i) => (async () => { await new Promise((r) => setTimeout(r, (i * 7) % 5)); return w.ask(i % 2 ? 'dfir.ask' : 'soc.copilot'); })()));
  out.forEach((t, i) => assert.equal(t, i % 2 ? 'from local' : 'from claude', 'request ' + i));
});

test('a feature routed to Claude is refused while external AI is not allowed; allowed() answers per feature', async () => {
  const w = world({ mode: 'local', routes: [{ match: 'soc.copilot', engine: 'anthropic' }] }, false);
  assert.equal(await w.ask('dfir.ask'), 'from local');
  await assert.rejects(w.ask('soc.copilot'), (e) => e.status === 403 && /soc\.copilot is routed to Claude, but "external AI allowed" is off/.test(e.message));
  assert.equal(w.claude.length, 0, 'nothing was sent');
  B.setFeature(''); assert.equal(B.allowed({ external_ai_allowed: false }), true, 'without a feature: true because the local model can serve');
  G.sharedBudget({}).admit('ali.syn', 'soc.copilot', 1); assert.equal(B.allowed({ external_ai_allowed: false }), false, 'for the Claude-routed feature: no');
  assert.equal(B.allowed({ external_ai_allowed: true }), true);
  G.sharedBudget({}).admit('ali.syn', 'dfir.ask', 1); assert.equal(B.allowed({ external_ai_allowed: false }), true);
});

test('validation of the rules, and the status they produce', () => {
  const v = (routes, mode) => B.validate({ mode: mode || 'anthropic', local: LOCAL, routes });
  assert.deepEqual(v([{ match: 'DFIR.*', engine: 'local' }]).routes, [{ match: 'dfir.*', engine: 'local' }]);
  assert.throws(() => v([{ match: 'dfir.*', engine: 'gpt' }]), /routes\[0\]\.engine must be one of/);
  assert.throws(() => v([{ match: '*.ask', engine: 'local' }]), /routes\[0\]\.match must be a feature name/);
  assert.throws(() => v([{ match: 'a b', engine: 'local' }]), /routes\[0\]\.match/);
  assert.throws(() => v([{ match: 'x.*', engine: 'local' }, { match: 'X.*', engine: 'off' }]), /routes\[1\]: x\.\* is listed twice/);
  assert.throws(() => v('dfir'), /routes must be a list/);
  assert.throws(() => B.validate({ mode: 'anthropic', local: {}, routes: [{ match: 'x', engine: 'local' }] }), /local\.base_url and local\.model are required/, 'a rule to the local model needs it set up');
  B.configure({ get: () => ({ mode: 'local', local: LOCAL, routes: [{ match: 'soc.copilot', engine: 'anthropic' }] }) });
  const s = B.status(); assert.equal(s.data_leaves_network, true, 'one Claude rule means data can leave'); assert.equal(s.routed, true); assert.equal(s.routes.length, 1);
  B.configure({ get: () => ({ mode: 'anthropic', local: LOCAL, routes: [{ match: 'dfir.*', engine: 'local' }] }) });
  assert.equal(process.env.ANTHROPIC_API_KEY ? true : false, true, 'a local rule sets the placeholder key so local features are not refused for a missing key');
});

test('the AI Engine routes save the rules (audited), count calls per feature and test every engine in use', async () => {
  const state = await createState({ dir: fs.mkdtempSync(path.join(os.tmpdir(), 'sentra-airoute-')) }), r = {}, gw = [];
  routes.register({ route: (m, p, h) => { r[m + ' ' + p] = h; } }, { state, config: { secrets: {} }, log: { error() {} }, aiEngineSdk: null, aiLocalKey: () => '', aiAnthropicKey: () => '',
    aiFetch: async (url, init) => { const q = JSON.parse(init.body); gw.push(q); return { status: 200, text: async () => JSON.stringify(q.tools ? { id: 'c', model: 'synthetic-local-7b', choices: [{ finish_reason: 'tool_calls', message: { role: 'assistant', content: null, tool_calls: [{ id: 't', type: 'function', function: { name: 'get_asset_count', arguments: '{"site":"HQ"}' } }] } }] } : say('OK')) }; } });
  const RANK = { viewer: 0, analyst: 1, operator: 2, admin: 3 };
  const run = async (key, user, role, b) => { const out = { status: 200, audits: [] }; await r[key]({ user, role, body: b, need: (x) => { if (RANK[role] < RANK[x]) { out.status = 403; return false; } return true; }, ok: (j) => { out.body = j; return j; }, fail: (c, m) => { out.status = c; out.body = { error: m }; }, audit: (a, t, d) => out.audits.push({ action: a, detail: d }) }).catch((e) => { out.status = e.status || 500; out.body = { error: e.message }; }); return out; };
  let o = await run('PUT /api/soc/ai-engine', 'syed', 'admin', { mode: 'local', local: LOCAL, routes: [{ match: 'dfir.*', engine: 'off' }, { match: 'netops.*', engine: 'local' }] });
  assert.equal(o.status, 200, JSON.stringify(o.body)); assert.equal(o.body.routes.length, 2); assert.match(o.body.effective, /2 routing rule\(s\); every other feature uses the local model/);
  assert.deepEqual(o.audits[0].detail.routes, [{ match: 'dfir.*', engine: 'off' }, { match: 'netops.*', engine: 'local' }]);
  o = await run('PUT /api/soc/ai-engine', 'syed', 'admin', { mode: 'local', local: LOCAL, routes: [{ match: 'bad pattern', engine: 'local' }] }); assert.equal(o.status, 400); assert.match(o.body.error, /routes\[0\]\.match/);
  // a call per feature is counted
  const Client = B.wrap(null); G.sharedBudget({}).admit('ali.syn', 'netops.ai', 1); await new Client({}).messages.create({ model: 'x', max_tokens: 10, messages: [{ role: 'user', content: 'hi' }] });
  o = await run('GET /api/soc/ai-engine', 'nora.syn', 'operator'); const f = o.body.features_today.find((x) => x.feature === 'netops.ai'); assert.ok(f && f.engine === 'local' && f.rule === 'netops.*' && f.n === 1);
  // the test probes every engine in use (here only the local model: dfir.* is off)
  o = await run('POST /api/soc/ai-engine/test', 'syed', 'admin'); assert.equal(o.status, 200, JSON.stringify(o.body)); assert.deepEqual(o.body.engines.map((e) => e.engine), ['local']); assert.equal(o.body.ok, true);
  // a Claude rule with no SDK installed: the test says so
  await run('PUT /api/soc/ai-engine', 'syed', 'admin', { mode: 'local', local: LOCAL, routes: [{ match: 'soc.copilot', engine: 'anthropic' }] });
  o = await run('POST /api/soc/ai-engine/test', 'syed', 'admin'); assert.equal(o.status, 424); assert.match(o.body.error, /needed for anthropic/);
});
