// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * AI Engine for the SIEM ({P} = /api/soc): the switch between Claude (Anthropic API), the local model on the organisation's AI
 * server, and no AI - for every AI feature of the SIEM (SOC analyst and Copilot, AI engineers, DBA tuning, NAC, port map,
 * live status, device configuration, Microsoft 365 insights, browsing). util/ai-backend.js does the work (the same file as
 * IT Asset Management's engine/ai-backend.js); the Platform Administration -> AI Engine page sets both engines.
 *   GET  {P}/ai-engine        operator  mode, local model address / model / kind, whether data leaves the network, last test
 *   PUT  {P}/ai-engine        admin     {mode, local: {api, base_url, model, timeout_s, max_tokens, tools}}  a person; audited
 *   POST {P}/ai-engine/test   admin     a plain answer, then a tool call, through the selected backend; audited
 * The local gateway key, if one is needed, is set on the server only: secrets.json local_ai_key (secure-secrets.sh) or
 * ZYB_LOCAL_AI_KEY. Never returned, logged or audited.
 */
const fs = require('node:fs');
const B = require('../util/ai-backend');
const { HttpError, wrap, audit, body, prefixOf } = require('../soc/routeutil');
const { isHuman } = require('../approvers/scopes');

function register(api, deps) {
  if (!deps.state) return;
  const P = prefixOf(deps), col = deps.state.collection('ai_backend'), cfg = deps.config || {}, sec = cfg.secrets || {};
  const localKey = deps.aiLocalKey || (() => sec.local_ai_key || process.env.ZYB_LOCAL_AI_KEY || '');
  const anthropicKey = deps.aiAnthropicKey || (() => (sec.netops && sec.netops.anthropic_api_key) || sec.anthropic_api_key || (process.env.ANTHROPIC_API_KEY !== B.PLACEHOLDER ? process.env.ANTHROPIC_API_KEY : '') || '');
  const calls = { day: '', n: 0, by: {}, features: {} };
  B.configure({ get: () => col.get('cfg'), localKey, fetch: deps.aiFetch, onCall: (c) => { const d = new Date().toISOString().slice(0, 10); if (calls.day !== d) { calls.day = d; calls.n = 0; calls.by = {}; calls.features = {}; } calls.n++; calls.by[c.mode] = (calls.by[c.mode] || 0) + 1; if (c.feature) { const f = calls.features[c.feature] = calls.features[c.feature] || { feature: c.feature, n: 0 }; f.n++; f.engine = c.mode; f.rule = c.rule; } } });
  let Ctor = null;
  const loadSdk = () => {
    if (deps.aiEngineSdk !== undefined) return deps.aiEngineSdk; if (Ctor) return Ctor;
    for (const p of [((cfg.netops || {}).ai || {}).sdk_path, '@anthropic-ai/sdk', '/opt/sentra-siem/vendor/node_modules/@anthropic-ai/sdk'].filter(Boolean)) {
      try { if (p.startsWith('/') && !fs.existsSync(p)) continue; const m = require(p); Ctor = m.Anthropic || m.default || m; return Ctor; } catch (e) { Ctor = null; /* next location; none = SDK not installed, said by the test */ }
    }
    return null;
  };
  const view = () => {
    const st = B.status(), last = (col.get('last_test') || {}).value || null, k = !!anthropicKey();
    const today = calls.day === new Date().toISOString().slice(0, 10);
    return Object.assign(st, { engine: 'SIEM', features_today: today ? Object.values(calls.features).sort((a, b) => b.n - a.n) : [], anthropic: { key_set: k, ready: k, sdk_installed: !!loadSdk() },
      effective: st.routed ? st.routes.length + ' routing rule(s); every other feature uses ' + (st.mode === 'local' ? 'the local model' : st.mode === 'off' ? 'no AI' : 'Claude')
        : st.mode === 'off' ? 'AI is off: every AI feature says it is not available; collection, detection and alerting keep working'
        : st.mode === 'local' ? (st.ready ? 'every AI feature uses the local model ' + st.local.model + ' at ' + st.local.host + '; nothing leaves the network' : 'local model selected but its address or model is not set')
          : (k ? 'every AI feature uses Claude through the Anthropic API; sanitised content leaves the network' : 'Claude selected but no Anthropic API key is set'),
      last_test: last, calls_today: calls.day === new Date().toISOString().slice(0, 10) ? { total: calls.n, by_mode: calls.by } : { total: 0, by_mode: {} } });
  };
  api.route('GET', `${P}/ai-engine`, wrap(deps, 'operator', (ctx) => ctx.ok(view())));
  api.route('PUT', `${P}/ai-engine`, wrap(deps, 'admin', (ctx) => {
    if (!isHuman(ctx.user)) throw new HttpError(403, 'a person changes the AI engine, not a service or AI identity');
    const b = body(ctx), loc = b.local && typeof b.local === 'object' && !Array.isArray(b.local) ? b.local : {};
    let v; try { v = B.validate({ mode: b.mode, local: { api: loc.api, base_url: loc.base_url, model: loc.model, timeout_s: loc.timeout_s, max_tokens: loc.max_tokens, tools: loc.tools }, routes: b.routes }); } catch (e) { throw new HttpError(e.status || 400, e.message); }
    const prev = B.status();
    col.put(Object.assign({ id: 'cfg' }, v, { updated_by: ctx.user, updated_at: new Date().toISOString() }));
    B.configure({});
    audit(ctx, 'ai.engine.save', 'ai-engine', { from: { mode: prev.mode, model: prev.local.model, host: prev.local.host, api: prev.local.api }, routes: v.routes, to: { mode: v.mode, model: v.local.model, host: v.local.base_url ? new URL(v.local.base_url).host : '', api: v.local.api } });
    return ctx.ok(view());
  }));
  api.route('POST', `${P}/ai-engine/test`, wrap(deps, 'admin', async (ctx) => {
    if (!isHuman(ctx.user)) throw new HttpError(403, 'a person runs the test, not a service or AI identity');
    const st = B.status(), engines = [...new Set([st.mode].concat(st.routes.map((r) => r.engine)))].filter((e) => e !== 'off');
    if (!engines.length) throw new HttpError(409, 'the AI engine is off - choose the local model or Claude first');
    if (engines.includes('local') && !(st.local.base_url && st.local.model)) throw new HttpError(409, 'set the local model address and model name, then save, then test');
    const results = [];
    for (const e of engines) {   // every engine in use: the default and each one a routing rule sends features to
      const sdk = e === 'local' && st.local.api === 'openai' ? null : loadSdk();
      if ((e !== 'local' || st.local.api === 'anthropic') && !sdk) throw new HttpError(424, 'the Anthropic SDK is not installed on this server (the update installs it)' + (engines.length > 1 ? ' - needed for ' + e : ''));
      const r = await B.probe(sdk, e === 'anthropic' ? anthropicKey() : '', e);
      results.push({ engine: e, ok: r.ok, model: r.model || (e === 'local' ? st.local.model : null), steps: r.steps });
    }
    const rec = { at: new Date().toISOString(), by: ctx.user, mode: st.mode, model: results[0].model || null, ok: results.every((r) => r.ok), steps: results[0].steps, engines: results };
    col.put({ id: 'last_test', value: rec });
    audit(ctx, 'ai.engine.test', 'ai-engine', { mode: st.mode, ok: rec.ok, engines: results.map((r) => ({ engine: r.engine, ok: r.ok, steps: r.steps.map((s) => ({ name: s.name, ok: s.ok, ms: s.ms })) })) });
    return ctx.ok(rec);
  }));
}
module.exports = { register };
