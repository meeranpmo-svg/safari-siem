// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const ZYB_ORG = require('./brand');
/*
 * AI backend switch - which model every AI feature of this engine talks to. The SAME file is in IT Asset Management
 * (engine/ai-backend.js) and in the SIEM (engine/util/ai-backend.js); a test fails if the two copies differ.
 *
 *   anthropic  Claude through the Anthropic API (the official SDK, as before). Data leaves the organisation, so the features
 *              still require "external AI allowed" in the settings.
 *   local      a model on the organisation's own AI server (AI-01). Nothing leaves the network, so "external AI allowed" is not
 *              needed. Two gateway kinds:
 *                openai     an OpenAI-compatible /v1/chat/completions endpoint (vLLM, Ollama, LM Studio, LiteLLM, TGI ...).
 *                           Claude's Messages request is translated: system, messages, tools (input_schema -> parameters),
 *                           tool_use / tool_result <-> tool_calls / role "tool"; the answer is translated back.
 *                anthropic  a gateway that already speaks the Messages API (LiteLLM /v1/messages, vLLM): the SDK is pointed at it.
 *              Options a local model does not take are dropped: thinking, output_config, cache_control, betas, metadata.
 *              The model name is the one set here, whatever the feature asked for.
 *   off        no AI at all: every AI feature says it is not available; every other feature keeps working.
 *
 * Per-feature routing: routes [{match, engine}] send chosen features to a different engine than the mode (the default) - e.g.
 * "dfir.*" -> local, "soc.copilot" -> anthropic. A feature is known by the name it gives the AI budget (ai-guard.js admit(user,
 * feature) runs just before each model call and tags the request through AsyncLocalStorage). Matching: an exact name first, then
 * the longest "prefix.*", then "*"; a call made without a feature name uses the mode. A feature routed to Claude still needs
 * "external AI allowed" where the engine has that setting (IT Asset Management) - it is refused, never silently sent.
 * How it plugs in: every AI feature loads the SDK constructor and passes it through wrap(Ctor). The wrapped constructor
 * has the same shape (new X(opts).messages.create(params) and .beta.messages.create) and asks this module, at each call,
 * which backend is selected - so switching needs no restart and no change in the 60 feature files. An SDK injected by a
 * test (opts.sdk) is not wrapped. allowed(settings) replaces the "external AI allowed" check at those features.
 * In local mode a placeholder ANTHROPIC_API_KEY is set when none exists, so features that check for a key before calling
 * do not refuse; the wrapper never sends that placeholder to Anthropic (a call in anthropic mode with it is refused here).
 */
const MODES = ['anthropic', 'local', 'off'];
const APIS = ['openai', 'anthropic'];
const PLACEHOLDER = 'zyb-local-model-no-key';
const DROP = ['thinking', 'output_config', 'cache_control', 'betas', 'metadata', 'service_tier', 'container', 'mcp_servers', 'context_management'];
const DEFAULTS = { mode: 'anthropic', local: { api: 'openai', base_url: '', model: '', timeout_s: 180, max_tokens: 4096, tools: true }, routes: [] };
const MATCH_RE = /^(\*|[a-z0-9_:-]+(\.[a-z0-9_:-]+)*(\.\*)?)$/;
const { AsyncLocalStorage } = require('node:async_hooks');
const ALS = new AsyncLocalStorage();

let getCfg = () => null, localKey = () => '', fetchFn = (...a) => globalThis.fetch(...a), onCall = null, externalAllowed = () => true;

// the feature a model call is made for: set by ai-guard admit() just before the call, read here at dispatch
function setFeature(f) { try { ALS.enterWith({ feature: String(f || '').slice(0, 80) }); } catch (e) { /* no async context (very old Node): calls use the default engine */ } }
function currentFeature() { const s = ALS.getStore(); return (s && s.feature) || ''; }

function err(status, msg) { return Object.assign(new Error(msg), { status }); }
function norm(c0) {
  const c = c0 && typeof c0 === 'object' ? c0 : {}, L = Object.assign({}, DEFAULTS.local, c.local || {});
  const routes = (Array.isArray(c.routes) ? c.routes : []).filter((r) => r && MATCH_RE.test(String(r.match)) && MODES.includes(r.engine)).map((r) => ({ match: String(r.match), engine: r.engine }));
  return { mode: MODES.includes(c.mode) ? c.mode : DEFAULTS.mode, local: L, routes, updated_by: c.updated_by || null, updated_at: c.updated_at || null };
}
function cfg() { let c = null; try { c = getCfg(); } catch (e) { c = null; /* the settings store could not be read: defaults (anthropic, unchanged behaviour) */ } return norm(c); }
// which engine serves a feature: the exact rule, else the longest "prefix.*", else "*", else the mode
function engineFor(feature, c0) {
  const c = c0 || cfg(), f = String(feature || '');
  if (f) {
    const exact = c.routes.find((r) => r.match === f); if (exact) return { engine: exact.engine, rule: exact.match };
    const pre = c.routes.filter((r) => r.match.endsWith('.*') && (f === r.match.slice(0, -2) || f.startsWith(r.match.slice(0, -1)))).sort((a, b) => b.match.length - a.match.length)[0];
    if (pre) return { engine: pre.engine, rule: pre.match };
  }
  const star = c.routes.find((r) => r.match === '*'); if (star) return { engine: star.engine, rule: '*' };
  return { engine: c.mode, rule: null };
}
const usesEngine = (c, e) => c.mode === e || c.routes.some((r) => r.engine === e);
// local mode: make "is there a key?" checks pass without a real key; anthropic / off: remove the placeholder again
function syncKeyEnv() {
  const local = usesEngine(cfg(), 'local');
  if (local && !process.env.ANTHROPIC_API_KEY) process.env.ANTHROPIC_API_KEY = PLACEHOLDER;
  else if (!local && process.env.ANTHROPIC_API_KEY === PLACEHOLDER) delete process.env.ANTHROPIC_API_KEY;
}
function configure(o = {}) {
  if (typeof o.get === 'function') getCfg = o.get;
  if (typeof o.localKey === 'function') localKey = o.localKey;
  if (typeof o.fetch === 'function') fetchFn = o.fetch;
  if (o.onCall === null || typeof o.onCall === 'function') onCall = o.onCall;
  if (typeof o.externalAllowed === 'function') externalAllowed = o.externalAllowed;
  syncKeyEnv();
  return status();
}
function status() {
  const c = cfg(), L = c.local;
  let host = ''; try { host = L.base_url ? new URL(L.base_url).host : ''; } catch (e) { host = ''; /* not a URL: shown as not set */ }
  return { mode: c.mode, data_leaves_network: usesEngine(c, 'anthropic'), routes: c.routes, routed: c.routes.length > 0, local: { api: L.api, base_url: L.base_url || '', host, model: L.model || '', timeout_s: L.timeout_s, max_tokens: L.max_tokens, tools: L.tools !== false, key_set: !!localKey() },
    ready: c.mode === 'off' && !c.routes.some((r) => r.engine !== 'off') ? false : usesEngine(c, 'local') ? !!(L.base_url && L.model) : true, updated_by: c.updated_by, updated_at: c.updated_at };
}
// the "external AI allowed" check at each feature: local keeps data in the network, so it is allowed; off never is
// with routes: allowed when at least one engine can serve; the exact per-feature decision is made at dispatch (refused there)
function allowed(settings) {
  const c = cfg(), f = currentFeature(), ext = !!(settings && settings.external_ai_allowed);
  if (f) { const e = engineFor(f, c).engine; return e === 'local' || (e === 'anthropic' && ext); }
  return usesEngine(c, 'local') || (usesEngine(c, 'anthropic') && ext);
}

// ---- Anthropic Messages <-> OpenAI chat completions -------------------------------------------------------------------
const textOf = (content) => (typeof content === 'string' ? content : Array.isArray(content) ? content.filter((b) => b && b.type === 'text').map((b) => b.text).join('\n') : '');
function toOpenAI(p, L) {
  const msgs = [], sys = textOf(p.system);
  if (sys) msgs.push({ role: 'system', content: sys });
  for (const m of p.messages || []) {
    if (typeof m.content === 'string') { msgs.push({ role: m.role === 'assistant' ? 'assistant' : 'user', content: m.content }); continue; }
    const blocks = Array.isArray(m.content) ? m.content : [];
    if (m.role === 'assistant') {
      const calls = blocks.filter((b) => b && b.type === 'tool_use').map((b) => ({ id: String(b.id), type: 'function', function: { name: String(b.name), arguments: JSON.stringify(b.input || {}) } }));
      const o = { role: 'assistant', content: textOf(blocks) || (calls.length ? null : '') }; if (calls.length) o.tool_calls = calls; msgs.push(o);
    } else {
      for (const b of blocks.filter((x) => x && x.type === 'tool_result')) msgs.push({ role: 'tool', tool_call_id: String(b.tool_use_id), content: (b.is_error ? 'ERROR: ' : '') + (typeof b.content === 'string' ? b.content : textOf(b.content)) });
      const t = textOf(blocks); if (t) msgs.push({ role: 'user', content: t });
    }
  }
  const body = { model: L.model, messages: msgs, max_tokens: Math.max(1, Math.min(Number(p.max_tokens) || 1024, Number(L.max_tokens) || 4096)), stream: false };
  if (typeof p.temperature === 'number') body.temperature = p.temperature;
  if (Array.isArray(p.stop_sequences) && p.stop_sequences.length) body.stop = p.stop_sequences.slice(0, 4);
  const tools = (p.tools || []).filter((t) => t && t.name && t.input_schema);
  if (tools.length && L.tools !== false) {
    body.tools = tools.map((t) => ({ type: 'function', function: { name: t.name, description: t.description || '', parameters: t.input_schema } }));
    const tc = p.tool_choice;
    if (tc && tc.type === 'tool' && tc.name) body.tool_choice = { type: 'function', function: { name: tc.name } };
    else if (tc && tc.type === 'any') body.tool_choice = 'required';
    else if (tc && tc.type === 'none') body.tool_choice = 'none';
  }
  return body;
}
const STOP = { tool_calls: 'tool_use', function_call: 'tool_use', length: 'max_tokens', stop: 'end_turn', content_filter: 'refusal' };
function fromOpenAI(j, L) {
  const ch = (j && Array.isArray(j.choices) && j.choices[0]) || null;
  if (!ch || !ch.message) throw err(502, 'the local model answered without a message');
  const msg = ch.message, content = [];
  // reasoning models put their thinking in <think>…</think>: it is not the answer
  const text = String(msg.content == null ? '' : msg.content).replace(/<think>[\s\S]*?<\/think>/g, '').trim();
  if (text) content.push({ type: 'text', text });
  (msg.tool_calls || []).forEach((c, i) => {
    let input = {}; try { input = c.function && c.function.arguments ? (typeof c.function.arguments === 'string' ? JSON.parse(c.function.arguments) : c.function.arguments) : {}; } catch (e) { input = { _invalid_arguments: String(c.function.arguments).slice(0, 500) }; /* the feature validates tool input and refuses it */ }
    content.push({ type: 'tool_use', id: String(c.id || 'call_' + i), name: String((c.function && c.function.name) || ''), input: input && typeof input === 'object' && !Array.isArray(input) ? input : {} });
  });
  const hasTool = content.some((b) => b.type === 'tool_use'), u = j.usage || {};
  return { id: String(j.id || 'local'), type: 'message', role: 'assistant', model: String(j.model || L.model), content,
    stop_reason: hasTool ? 'tool_use' : (STOP[ch.finish_reason] || 'end_turn'), stop_sequence: null,
    usage: { input_tokens: Number(u.prompt_tokens) || 0, output_tokens: Number(u.completion_tokens) || 0 } };
}
function endpoint(base, path) { const b = String(base).replace(/\/+$/, ''); return /\/v1$/.test(b) ? b + path : b + '/v1' + path; }
async function localOpenAI(p, L, ro) {
  const ctl = new AbortController(), ms = (Number(L.timeout_s) || 180) * 1000, t = setTimeout(() => ctl.abort(), ms);
  if (ro && ro.signal) ro.signal.addEventListener('abort', () => ctl.abort(), { once: true });
  const key = localKey(), headers = { 'Content-Type': 'application/json', Accept: 'application/json' }; if (key) headers.Authorization = 'Bearer ' + key;
  let r;
  try {
    r = await fetchFn(endpoint(L.base_url, '/chat/completions'), { method: 'POST', headers, body: JSON.stringify(toOpenAI(p, L)), signal: ctl.signal });
  } catch (e) { throw err(424, e.name === 'AbortError' ? 'the local model did not answer within ' + (ms / 1000) + ' s' : 'the local model is not reachable (' + String(e.cause && e.cause.code || e.code || e.message).slice(0, 80) + ')'); }
  finally { clearTimeout(t); }
  let j = null; const txt = await r.text(); try { j = JSON.parse(txt); } catch (e) { j = null; /* not JSON: reported with the HTTP status below */ }
  if (r.status === 401 || r.status === 403) throw err(424, 'the local model gateway refused the key (HTTP ' + r.status + ')');
  if (r.status === 404) throw err(424, 'the local model gateway has no /v1/chat/completions (HTTP 404) - check the address and the gateway kind');
  if (r.status < 200 || r.status >= 300 || !j) throw err(424, 'the local model answered HTTP ' + r.status + (j && j.error ? ': ' + String(j.error.message || j.error).slice(0, 200) : ''));
  return fromOpenAI(j, L);
}
function stripForLocal(p, L) {
  const q = Object.assign({}, p, { model: L.model, max_tokens: Math.max(1, Math.min(Number(p.max_tokens) || 1024, Number(L.max_tokens) || 4096)) });
  for (const k of DROP) delete q[k];
  if (L.tools === false) { delete q.tools; delete q.tool_choice; }
  return q;
}
async function dispatch(Ctor, opts, p, ro) {
  const c = cfg(), L = c.local, t0 = Date.now(), st = ALS.getStore() || {}, feature = st.feature || '';
  const r = st.force ? { engine: st.force, rule: 'test' } : engineFor(feature, c), mode = r.engine;
  if (mode === 'off') throw err(503, r.rule ? 'AI is switched off for ' + (feature || 'this feature') + ' (AI Engine routing rule "' + r.rule + '")' : 'AI is switched off (Platform Administration -> AI Engine)');
  if (mode === 'anthropic' && !st.force && !externalAllowed()) throw err(403, (feature || 'this feature') + ' is routed to Claude, but "external AI allowed" is off in Settings - route it to the local model or allow external AI');
  let out;
  try {
  if (mode === 'local') {
    if (!L.base_url || !L.model) throw err(424, 'the local model is not set up (Platform Administration -> AI Engine: address and model)');
    if (L.api === 'anthropic') {
      if (!Ctor) throw err(424, 'the Anthropic SDK is not installed (needed for an Anthropic-compatible gateway)');
      const client = new Ctor(Object.assign({}, opts, { apiKey: localKey() || 'local', baseURL: String(L.base_url).replace(/\/+$/, ''), timeout: (Number(L.timeout_s) || 180) * 1000 }));
      out = await client.messages.create(stripForLocal(p, L), ro);
    } else out = await localOpenAI(p, L, ro);
  } else {
    if (!Ctor) throw err(424, 'Anthropic SDK not installed');
    if (!opts || !opts.apiKey || opts.apiKey === PLACEHOLDER) throw err(424, 'no Anthropic API key - set one, or switch the AI engine to the local model');
    const client = new Ctor(opts);
    out = await (p && p.betas && client.beta ? client.beta.messages.create(p, ro) : client.messages.create(p, ro));
  }
  } catch (e) { emit({ ok: false, mode, feature: st.force ? '' : feature, model: mode === 'local' ? L.model : (p && p.model) || '', ms: Date.now() - t0, status: e.status || 500, error: String(e.message || e).slice(0, 200) }); throw e; }
  const u = (out && out.usage) || {};
  emit({ ok: true, mode, feature: st.force ? '' : feature, model: (out && out.model) || '', ms: Date.now() - t0, input_tokens: Number(u.input_tokens) || 0, output_tokens: Number(u.output_tokens) || 0 });
  if (onCall) { try { onCall({ mode, feature: st.force ? '' : feature, rule: st.force ? null : r.rule, model: out && out.model, ms: Date.now() - t0 }); } catch (e) { /* statistics only: never fail a call over them */ } }
  return out;
}
// every call through the switch, answered or failed, for the health pages (Private AI Server): {ok, mode, feature, model, ms,
// input_tokens, output_tokens} or {ok:false, ..., status, error}. A listener never sees the prompt or the answer.
const listeners = new Set();
function listen(fn) { listeners.add(fn); return () => listeners.delete(fn); }
function emit(rec) { rec.at = Date.now(); for (const fn of listeners) { try { fn(rec); } catch (e) { /* statistics only: a listener never fails a call */ } } }
function wrap(Ctor) {
  if (Ctor && Ctor.__zybWrapped) return Ctor;
  class Wrapped {
    constructor(opts) { const o = opts || {}; this.messages = { create: (p, ro) => dispatch(Ctor, o, p, ro) }; this.beta = { messages: { create: (p, ro) => dispatch(Ctor, o, p, ro) } }; }
  }
  Wrapped.__zybWrapped = true; Wrapped.Anthropic = Wrapped; Wrapped.default = Wrapped;
  return Wrapped;
}

// ---- validation of a new setting (both engines' routes use it) --------------------------------------------------------
const PRIVATE = [/^10\./, /^192\.168\./, /^172\.(1[6-9]|2\d|3[01])\./, /^127\./, /^169\.254\./];
function validate(b0) {
  const b = b0 && typeof b0 === 'object' && !Array.isArray(b0) ? b0 : null;
  if (!b) throw err(400, 'the request body must be a JSON object');
  if (!MODES.includes(b.mode)) throw err(400, 'mode must be one of: ' + MODES.join(', '));
  const L0 = b.local && typeof b.local === 'object' && !Array.isArray(b.local) ? b.local : {}, L = {};
  L.api = L0.api == null ? 'openai' : L0.api; if (!APIS.includes(L.api)) throw err(400, 'local.api must be one of: ' + APIS.join(', '));
  L.base_url = String(L0.base_url == null ? '' : L0.base_url).trim();
  if (L.base_url) {
    let u; try { u = new URL(L.base_url); } catch (e) { throw err(400, 'local.base_url is not a URL (for example http://10.20.0.40:8000/v1)'); }
    if (!/^https?:$/.test(u.protocol)) throw err(400, 'local.base_url must start with http:// or https://');
    if (u.username || u.password) throw err(400, 'local.base_url must not carry a user or password - the key is set on the server');
    if (u.search || u.hash) throw err(400, 'local.base_url must not carry a query or fragment');
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(u.hostname) && !PRIVATE.some((r) => r.test(u.hostname))) throw err(400, ('local.base_url is a public address - the local model must be inside ' + ZYB_ORG.short + '\'s network'));
    if (L.base_url.length > 300) throw err(400, 'local.base_url is longer than 300 characters');
  }
  L.model = String(L0.model == null ? '' : L0.model).trim();
  if (L.model && !/^[A-Za-z0-9._:/@+-]{1,120}$/.test(L.model)) throw err(400, 'local.model may hold letters, digits and . _ : / @ + - only (120 at most)');
  const int = (k, lo, hi, d) => { const v = L0[k] == null || L0[k] === '' ? d : Number(L0[k]); if (!Number.isInteger(v) || v < lo || v > hi) throw err(400, 'local.' + k + ' must be a whole number from ' + lo + ' to ' + hi); return v; };
  L.timeout_s = int('timeout_s', 10, 600, 180); L.max_tokens = int('max_tokens', 256, 32768, 4096);
  if (L0.tools != null && typeof L0.tools !== 'boolean') throw err(400, 'local.tools must be true or false'); L.tools = L0.tools !== false;
  if (b.routes != null && !Array.isArray(b.routes)) throw err(400, 'routes must be a list of {match, engine}');
  const routes = [], seen = new Set();
  (b.routes || []).forEach((r0, i) => {
    if (!r0 || typeof r0 !== 'object' || Array.isArray(r0)) throw err(400, 'routes[' + i + '] must be {match, engine}');
    const m = String(r0.match == null ? '' : r0.match).trim().toLowerCase();
    if (!MATCH_RE.test(m) || m.length > 80) throw err(400, 'routes[' + i + '].match must be a feature name (soc.copilot), a group (dfir.*) or * - letters, digits and . _ : - only');
    if (!MODES.includes(r0.engine)) throw err(400, 'routes[' + i + '].engine must be one of: ' + MODES.join(', '));
    if (seen.has(m)) throw err(400, 'routes[' + i + ']: ' + m + ' is listed twice'); seen.add(m);
    routes.push({ match: m, engine: r0.engine });
  });
  if (routes.length > 100) throw err(400, 'routes: at most 100 rules');
  if ((b.mode === 'local' || routes.some((r) => r.engine === 'local')) && (!L.base_url || !L.model)) throw err(400, 'local.base_url and local.model are required to switch to the local model');
  return { mode: b.mode, local: L, routes };
}
// a short probe: a plain answer, then whether the model calls a tool when asked to
async function probe(Ctor, apiKey, engine) {
  if (engine) return ALS.run({ force: engine, feature: 'engine.test' }, () => probe1(Ctor, apiKey, engine));
  return probe1(Ctor, apiKey, cfg().mode);
}
async function probe1(Ctor, apiKey, engine) {
  const C = wrap(Ctor), client = new C({ apiKey: apiKey || process.env.ANTHROPIC_API_KEY || '', maxRetries: 0, timeout: 60000 }), out = { ok: false, steps: [] };
  const step = async (name, fn) => { const t0 = Date.now(); try { const r = await fn(); out.steps.push(Object.assign({ name, ok: true, ms: Date.now() - t0 }, r)); return true; } catch (e) { out.steps.push({ name, ok: false, ms: Date.now() - t0, error: String(e.message).slice(0, 300) }); return false; } };
  const model = engine === 'anthropic' ? 'claude-opus-5-5' : cfg().local.model;
  if (!(await step('answer', async () => { const r = await client.messages.create({ model, max_tokens: 64, messages: [{ role: 'user', content: 'Reply with the single word OK.' }] }); out.model = r.model; return { text: textOf(r.content).slice(0, 80) }; }))) return out;
  out.ok = true;
  await step('tool use', async () => {
    const r = await client.messages.create({ model, max_tokens: 256, tools: [{ name: 'get_asset_count', description: 'Returns how many assets the register holds.', input_schema: { type: 'object', properties: { site: { type: 'string' } }, required: ['site'] } }],
      tool_choice: { type: 'any' }, messages: [{ role: 'user', content: 'How many assets are at site HQ? Use the tool.' }] });
    const u = (r.content || []).find((b) => b.type === 'tool_use'); if (!u) throw err(422, 'the model did not call the tool - AI features that look things up will not work well with it');
    return { tool: u.name, input: u.input };
  });
  return out;
}

module.exports = { MODES, APIS, PLACEHOLDER, DEFAULTS, configure, status, allowed, wrap, listen, validate, probe, toOpenAI, fromOpenAI, setFeature, currentFeature, engineFor, _norm: norm };
