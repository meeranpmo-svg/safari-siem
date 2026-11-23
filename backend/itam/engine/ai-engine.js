// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const fs = require('node:fs');
const { body } = require('./check');
const { isHuman } = require('./approve-scopes');
const B = require('./ai-backend');
/*
 * AI Engine ({P} = /api/itam, Platform Administration -> AI Engine): the switch between Claude (Anthropic API), the local model
 * on the organisation's AI server, and no AI - for every AI feature of IT Asset Management (engine/ai-backend.js does the work).
 * The SIEM has the same routes under /api/soc for its own AI features; the page sets both.
 *   GET  /ai-engine          operator  mode, local model address / model / kind, whether data leaves the network, last test, calls today
 *   PUT  /ai-engine          admin     {mode: anthropic|local|off, local: {api: openai|anthropic, base_url, model, timeout_s, max_tokens, tools}}
 *                                      a person (not a service / AI identity); audited with the before and after
 *   POST /ai-engine/test     admin     a short probe through the selected backend: a plain answer, then a tool call - audited
 * The local gateway key (if the gateway needs one) is never entered on the page: sudo itam-secrets set local_ai_key (stdin,
 * sealed in secrets.json), or ZYB_LOCAL_AI_KEY in the service environment. It is never returned, logged or audited.
 */
const httpErr = (status, msg) => Object.assign(new Error(msg), { status });

function createAiEngine(app, opts = {}) {
  const now = opts.now || Date.now, store = app.store, col = () => store.collection('ai_backend');
  const dc = (app.config && app.config.discovery) || {}, cfgA = (app.config && app.config.ai) || {};
  const secrets = process.env.SENTRA_ITAM_SECRETS || '/etc/sentra-itam/secrets.json';
  const fileKey = (name) => { try { return require('./secret-values').fileValue(secrets, name, dc.vault_key_file)() || ''; } catch (e) { return ''; /* no secrets file: the environment is the only source */ } };
  const localKey = opts.localKey || (() => fileKey('local_ai_key') || process.env.ZYB_LOCAL_AI_KEY || '');
  const anthropicKey = opts.anthropicKey || (() => fileKey('anthropic_api_key') || (process.env.ANTHROPIC_API_KEY !== B.PLACEHOLDER ? process.env.ANTHROPIC_API_KEY : '') || '');
  const calls = { day: '', n: 0, by: {}, features: {} };
  B.configure({ get: () => col().get('cfg'), localKey, fetch: opts.fetch, onCall: (c) => { const d = new Date(now()).toISOString().slice(0, 10); if (calls.day !== d) { calls.day = d; calls.n = 0; calls.by = {}; calls.features = {}; } calls.n++; calls.by[c.mode] = (calls.by[c.mode] || 0) + 1; if (c.feature) { const f = calls.features[c.feature] = calls.features[c.feature] || { feature: c.feature, n: 0 }; f.n++; f.engine = c.mode; f.rule = c.rule; } },
    // a feature routed to Claude needs "external AI allowed" (Settings); refused at the call, never silently sent
    externalAllowed: () => { try { return !!(app.settings && app.settings.get().external_ai_allowed); } catch (e) { return false; /* settings unreadable = not allowed */ } } });
  const audit = (who, action, detail) => { if (app.audit) app.audit({ by: who.user, role: who.role || '', ip: who.ip || '', action: 'ai.engine.' + action, target: 'ai-engine', detail }); };
  let Ctor = null;
  function loadSdk() {
    if (opts.sdk !== undefined) return opts.sdk; if (Ctor) return Ctor;
    for (const p of [cfgA.sdk_path, '@anthropic-ai/sdk', '/opt/sentra-itam/vendor/node_modules/@anthropic-ai/sdk', '/opt/sentra-siem/vendor/node_modules/@anthropic-ai/sdk'].filter(Boolean)) {
      try { if (p.startsWith('/') && !fs.existsSync(p)) continue; const m = require(p); Ctor = m.Anthropic || m.default || m; return Ctor; } catch (e) { Ctor = null; /* try the next location; none = SDK not installed, said by the probe */ }
    }
    return null;
  }
  function view() {
    const st = B.status(), last = (col().get('last_test') || {}).value || null;
    let ext = false; try { ext = !!(app.settings && app.settings.get().external_ai_allowed); } catch (e) { ext = false; /* settings unreadable = not allowed */ }
    const anthropicReady = !!anthropicKey() && ext;
    const today = calls.day === new Date(now()).toISOString().slice(0, 10);
    return Object.assign(st, { engine: 'IT Asset Management', features_today: today ? Object.values(calls.features).sort((a, b) => b.n - a.n) : [], anthropic: { key_set: !!anthropicKey(), external_ai_allowed: ext, ready: anthropicReady, sdk_installed: !!loadSdk() },
      effective: st.routed ? st.routes.length + ' routing rule(s); every other feature uses ' + (st.mode === 'local' ? 'the local model' : st.mode === 'off' ? 'no AI' : 'Claude') + (st.data_leaves_network && !ext ? ' - features routed to Claude are refused until "external AI allowed" is on' : '')
        : st.mode === 'off' ? 'AI is off: every AI feature says it is not available; everything else works'
        : st.mode === 'local' ? (st.ready ? 'every AI feature uses the local model ' + st.local.model + ' at ' + st.local.host + '; nothing leaves the network' : 'local model selected but its address or model is not set')
          : (anthropicReady ? 'every AI feature uses Claude through the Anthropic API; sanitised content leaves the network' : 'Claude selected but ' + (!ext ? '"external AI allowed" is off in Settings' : 'no Anthropic API key is set')),
      last_test: last, calls_today: calls.day === new Date(now()).toISOString().slice(0, 10) ? { total: calls.n, by_mode: calls.by } : { total: 0, by_mode: {} } });
  }
  function save(input, who) {
    if (!isHuman(who.user)) throw httpErr(403, 'a person changes the AI engine, not a service or AI identity');
    const pre = body(input).oneOf('mode', B.MODES, { required: true }).done();
    const raw = input && input.local && typeof input.local === 'object' && !Array.isArray(input.local) ? input.local : {};
    const loc = body(raw).oneOf('api', B.APIS, { def: 'openai' }).str('base_url', { max: 300 }).str('model', { max: 120 }).int('timeout_s', { min: 10, max: 600, def: 180 }).int('max_tokens', { min: 256, max: 32768, def: 4096 }).bool('tools', { def: true }).done();
    let v; try { v = B.validate({ mode: pre.mode, local: loc, routes: input && input.routes }); } catch (e) { throw httpErr(e.status || 400, e.message); }
    const prev = B.status();
    col().put(Object.assign({ id: 'cfg' }, v, { updated_by: who.user, updated_at: new Date(now()).toISOString() }));
    B.configure({});   // re-apply the key placeholder for the new mode
    audit(who, 'save', { from: { mode: prev.mode, model: prev.local.model, host: prev.local.host, api: prev.local.api }, routes: v.routes, to: { mode: v.mode, model: v.local.model, host: v.local.base_url ? new URL(v.local.base_url).host : '', api: v.local.api } });
    return view();
  }
  async function test(who) {
    if (!isHuman(who.user)) throw httpErr(403, 'a person runs the test, not a service or AI identity');
    const st = B.status(), engines = [...new Set([st.mode].concat(st.routes.map((r) => r.engine)))].filter((e) => e !== 'off');
    if (!engines.length) throw httpErr(409, 'the AI engine is off - choose the local model or Claude first');
    if (engines.includes('local') && !(st.local.base_url && st.local.model)) throw httpErr(409, 'set the local model address and model name, then save, then test');
    const results = [];
    for (const e of engines) {   // every engine in use: the default and each one a routing rule sends features to
      const sdk = e === 'local' && st.local.api === 'openai' ? null : loadSdk();
      if ((e !== 'local' || st.local.api === 'anthropic') && !sdk) throw httpErr(424, 'the Anthropic SDK is not installed on this server (the update installs it)' + (engines.length > 1 ? ' - needed for ' + e : ''));
      const r = await B.probe(sdk, e === 'anthropic' ? anthropicKey() : '', e);
      results.push({ engine: e, ok: r.ok, model: r.model || (e === 'local' ? st.local.model : null), steps: r.steps });
    }
    const rec = { at: new Date(now()).toISOString(), by: who.user, mode: st.mode, model: results[0].model || null, ok: results.every((r) => r.ok), steps: results[0].steps, engines: results };
    col().put({ id: 'last_test', value: rec });
    audit(who, 'test', { mode: st.mode, ok: rec.ok, engines: results.map((r) => ({ engine: r.engine, ok: r.ok, steps: r.steps.map((s) => ({ name: s.name, ok: s.ok, ms: s.ms })) })) });
    return rec;
  }
  // gatewayKey: the local gateway's key for the Private AI Server health poll (engine/private-ai.js) - in process only, never returned
  return { view, save, test, gatewayKey: localKey };
}

function registerAiEngine(srv, app, E0) {
  const E = E0 && E0.view ? E0 : createAiEngine(app, E0 && !E0.view ? E0 : {});
  app.addons = app.addons || {}; app.addons.aiEngine = E;
  srv.route('GET', '/ai-engine', (ctx) => { ctx.need('operator'); return E.view(); });
  srv.route('PUT', '/ai-engine', (ctx) => { ctx.need('admin'); return E.save(ctx.body, ctx.who); });
  srv.route('POST', '/ai-engine/test', async (ctx) => { ctx.need('admin'); return E.test(ctx.who); });
  return E;
}
module.exports = { createAiEngine, registerAiEngine };
