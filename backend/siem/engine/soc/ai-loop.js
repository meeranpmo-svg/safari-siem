// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const path = require('node:path');
const G = require('../util/ai-guard');
const S = require('../util/ai-schema');
/*
 * ai-loop.js - the guarded tool loop shared by the Security Operations AI features (case brief, hunt assistant).
 *
 *   createModel({ config, deps, log }) → { status(), client() }   the Anthropic SDK + key, as the AI Network Engineer reads them
 *   runLoop({ client, model, effort, system, tools, role, user, feature, prompt, run(name, input, seen), final, maxSteps, log, config })
 *     → { result (the final tool's input) | null, note, steps[], usage, flags[], seen:Set }
 *
 * What the code (not the prompt) guarantees, docs/AI-SECURITY.md:
 *   - the tools are filtered by the asker's role BEFORE the model sees them (tools[].role) and re-checked on every call;
 *   - every tool input is checked against its schema before it runs (util/ai-schema.js: no extra keys, types, enums, ranges,
 *     lengths, patterns; fails closed);
 *   - tool output is DATA: secrets redacted, framed with G.untrusted, flagged when it looks like instructions;
 *   - UNTRUSTED_RULE ends the system prompt; G.sharedBudget admits before the first call and records after the last
 *     (tokens spent before a failure count too);
 *   - `seen` collects every id / value a tool returned, so a feature can mark output that cites anything else as unverified.
 */
const RANK = { viewer: 0, analyst: 1, operator: 2, admin: 3 };
const MAX_RESULT = 20000;

// the model's arguments against the tool's schema - the shared checker (util/ai-schema.js, the same file as IT Asset Management's)
const check = (schema, v, at = 'input') => S.checkInput(schema, v, at);
const allowed = (t, role) => !t.role || (RANK[role] || 0) >= RANK[t.role];

function createModel({ config, deps, log } = {}) {
  const sect = () => (config && config.soc_analyst) || {};
  let Ctor = null, loadError = '';
  function loadSdk() {
    if (deps && deps.sdk) return deps.sdk; if (Ctor) return Ctor;
    const tries = ['@anthropic-ai/sdk', sect().sdk_path || '/opt/sentra-siem/vendor/node_modules/@anthropic-ai/sdk', path.join(__dirname, '..', '..', 'vendor', 'node_modules', '@anthropic-ai', 'sdk'), require('path').join(__dirname, '..', 'util', 'ai-sdk-shim.js')];
    for (const p of tries) { try { const m = require(p); Ctor = require('../util/ai-backend').wrap(m.Anthropic || m.default || m); return Ctor; } catch (e) { loadError = e.code === 'MODULE_NOT_FOUND' ? 'Anthropic SDK not installed (run install/netops-ai-sdk)' : e.message; } }
    return null;
  }
  const key = () => { const s = config && config.secrets; return (s && s.netops && s.netops.anthropic_api_key) || process.env.ANTHROPIC_API_KEY || ''; };
  const model = () => sect().model || 'claude-opus-5-5';
  function status() {
    if (sect().enabled === false) return { enabled: false, reason: 'the SOC AI features are switched off (config soc_analyst.enabled)', model: model() };
    if (!loadSdk()) return { enabled: false, reason: loadError || 'Anthropic SDK not installed', model: model() };
    if (!key()) return { enabled: false, reason: 'no Anthropic API key (secrets.json netops.anthropic_api_key)', model: model() };
    return { enabled: true, model: model() };
  }
  function client() { const A = loadSdk(); return new A({ apiKey: key(), timeout: (sect().timeout_s || 180) * 1000, maxRetries: 2, baseURL: sect().base_url || undefined }); }
  void log;
  return { status, client, model, effort: () => sect().effort || 'high' };
}

async function runLoop(o) {
  const L = o.log || { info() {}, warn() {} };
  S.assertSchemas(o.tools, o.feature || 'ai-loop');   // a rule the checker cannot enforce is refused, never silently ignored
  const tools = o.tools.filter((t) => allowed(t, o.role)), offered = new Set(tools.map((t) => t.name));
  const api = tools.map((t) => ({ name: t.name, description: t.description, input_schema: t.input_schema }));
  const budget = G.sharedBudget({ log: L, limits: () => (o.config && o.config.ai_limits) || {} });
  budget.admit(o.user, o.feature, String(o.prompt).length);
  const messages = [{ role: 'user', content: o.prompt }], steps = [], flags = [], seen = new Set();
  let usage = { input_tokens: 0, output_tokens: 0, cache_read_input_tokens: 0 }, result = null, note = '', invalid = '';
  try {
    for (let s = 0; s < (o.maxSteps || 10) && !result; s++) {
      const resp = await o.client.messages.create({ model: o.model, max_tokens: 8000, thinking: { type: 'adaptive' }, output_config: { effort: o.effort || 'high' },
        system: o.system + '\n\n' + G.UNTRUSTED_RULE, tools: api, messages, cache_control: { type: 'ephemeral' } });
      for (const k of Object.keys(usage)) usage[k] += (resp.usage && resp.usage[k]) || 0;
      messages.push({ role: 'assistant', content: resp.content });
      if (resp.stop_reason === 'refusal') { note = 'the AI declined the request'; break; }
      if (resp.stop_reason === 'pause_turn') continue;
      const uses = resp.content.filter((b) => b.type === 'tool_use');
      if (!uses.length) { note = 'the AI answered without submitting a result'; break; }
      const out = [];
      for (const b of uses) {
        const def = o.tools.find((t) => t.name === b.name), t0 = Date.now();
        if (!def || !offered.has(b.name) || !allowed(def, o.role)) { out.push({ type: 'tool_result', tool_use_id: b.id, content: `not allowed: ${b.name} is not available to the ${o.role} role`, is_error: true }); steps.push({ tool: b.name, ok: false, refused: true }); continue; }
        const err = check(def.input_schema, b.input);
        if (err) { out.push({ type: 'tool_result', tool_use_id: b.id, content: 'invalid input: ' + err, is_error: true }); steps.push({ tool: b.name, ok: false, error: err }); if (b.name === o.final) invalid = err; continue; }
        if (b.name === o.final) { result = b.input; out.push({ type: 'tool_result', tool_use_id: b.id, content: 'received' }); steps.push({ tool: b.name, ok: true, ms: 0 }); continue; }
        try {
          let text = JSON.stringify(await o.run(b.name, b.input, seen)); if (text.length > MAX_RESULT) text = text.slice(0, MAX_RESULT) + ' …[truncated]';
          const f = G.injectionSignals(text); if (f.length) flags.push(...f);
          out.push({ type: 'tool_result', tool_use_id: b.id, content: G.untrusted('tool:' + b.name, text) });
          steps.push({ tool: b.name, input: b.input, ok: true, ms: Date.now() - t0, injection_signals: f.length ? f : undefined });
        } catch (e) {
          out.push({ type: 'tool_result', tool_use_id: b.id, content: G.untrusted('tool-error:' + b.name, 'error: ' + String(e.message || e).slice(0, 300)), is_error: true });
          steps.push({ tool: b.name, input: b.input, ok: false, ms: Date.now() - t0, error: String(e.message || e).slice(0, 200) });
        }
      }
      if (result) break;
      messages.push({ role: 'user', content: out });
    }
  } finally { budget.record(o.user, o.feature, usage, [...new Set(flags)]); }
  if (!result && !note) note = invalid ? 'invalid result: ' + invalid : 'it ran out of steps';
  return { result, note, steps, usage, flags: [...new Set(flags)], seen };
}

module.exports = { createModel, runLoop, check, allowed, RANK };
