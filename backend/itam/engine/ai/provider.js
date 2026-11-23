// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Model provider — speaks the sentra-ai /draft contract (same as sentra-grcai):
//   request  {apiKey?, model, effort, system, prompt}
//   response {ok:true, text, model, usage:{input,output}, truncated, stop_reason} | {ok:false, code, message}
// private (production, default): POST <config.ai.private_url>/draft on S1, optional Bearer secrets.private_token.
//     'not_configured' until ai.private_url is set.
// anthropic: Claude directly with the official SDK (ai/anthropic.js), key in /etc/sentra-itam/secrets.json anthropic_api_key.
//     Chosen explicitly (ai.provider = 'anthropic') or automatically when the private endpoint is not configured and a key
//     is stored. Like the claude connector it requires settings.external_ai_allowed.
// claude  (staging): POST config.ai.claude_url (127.0.0.1:9093/draft), key from the portal connector; requires
//     settings.external_ai_allowed (sanitised asset content leaves the platform).
// All ITAM AI output is ADVISORY ("AI — verify"); the model never changes an asset or a relationship by itself.
const http = require('node:http');
const { createAnthropic } = require('./anthropic');
const G = require('../ai-guard');
const https = require('node:https');

const MSG = {
  not_configured_private: 'The private model endpoint is not configured. An administrator must set ai.private_url in config.json.',
  not_configured_claude: 'The staging Claude connector is not configured in the Integrations Hub.',
  not_configured_anthropic: 'No Anthropic API key is stored on the server (sudo zyb-virt-ai --set-key).',
  external_not_allowed: 'Sending sanitised asset content to the external Claude API is not allowed. An administrator can allow it in ITAM settings (external_ai_allowed).',
  disabled: 'AI analysis is disabled on this server (config.json ai.provider = none).',
};
const MAX_RESPONSE = 4 * 1024 * 1024;

function postJson(url, body, headers, timeoutMs) {
  return new Promise((resolve) => {
    let u;
    try { u = new URL(url); } catch { return resolve({ ok: false, code: 'bad_url', message: 'The AI endpoint URL is invalid.' }); }
    const data = Buffer.from(JSON.stringify(body));
    const mod = u.protocol === 'https:' ? https : http;
    const r = mod.request({
      protocol: u.protocol, hostname: u.hostname, port: u.port, path: u.pathname + u.search, method: 'POST', timeout: timeoutMs,
      headers: Object.assign({ 'Content-Type': 'application/json', 'Content-Length': data.length }, headers || {}),
    }, (res) => {
      const chunks = []; let size = 0; let over = false;
      res.on('data', (c) => { size += c.length; if (size > MAX_RESPONSE) { over = true; res.destroy(); return; } chunks.push(c); });
      res.on('end', () => {
        if (over) return resolve({ ok: false, code: 'bad_response', message: 'The AI service response was too large.' });
        let j; try { j = JSON.parse(Buffer.concat(chunks).toString('utf8')); } catch { return resolve({ ok: false, code: 'bad_response', message: `The AI service returned an unreadable response (HTTP ${res.statusCode}).` }); }
        if (!j || typeof j !== 'object') return resolve({ ok: false, code: 'bad_response', message: 'The AI service returned an unexpected response.' });
        resolve(j);
      });
      res.on('error', () => resolve({ ok: false, code: 'bad_response', message: 'The AI service connection failed mid-response.' }));
    });
    r.on('timeout', () => r.destroy(Object.assign(new Error('timeout'), { code: 'ETIMEDOUT' })));
    r.on('error', (e) => resolve(e.code === 'ETIMEDOUT'
      ? { ok: false, code: 'timeout', message: `The AI service did not answer within ${Math.round(timeoutMs / 1000)} s.` }
      : { ok: false, code: 'ai_service_down', message: `The AI service is not reachable (${e.code || 'error'}).` }));
    r.end(data);
  });
}

function normalise(res) {
  if (!res || res.ok !== true) {
    return { ok: false, code: String((res && res.code) || 'error').slice(0, 60), message: String((res && res.message) || 'The AI call failed.').slice(0, 500), model: res && res.model };
  }
  const usage = res.usage && typeof res.usage === 'object' ? { input: Number(res.usage.input) || 0, output: Number(res.usage.output) || 0 } : { input: 0, output: 0 };
  return { ok: true, text: String(res.text || ''), model: String(res.model || ''), usage, truncated: !!res.truncated, stop_reason: res.stop_reason || null };
}

// createProvider({config, secrets, getSettings, connector?, log})
function createProvider({ config, secrets, getSettings, connector, log, anthropic }) {
  const ai = config.ai || {};
  const kind = ai.provider || 'private';
  const A = anthropic || createAnthropic({ config });
  function direct() {
    const r = A.ready();
    if (!r.ok) return { provider: 'anthropic', state: 'not_configured', model: A.model(), message: A.hasKey() ? r.reason : MSG.not_configured_anthropic };
    if (!require('../ai-backend').allowed(getSettings())) return { provider: 'anthropic', state: 'external_not_allowed', model: A.model(), message: MSG.external_not_allowed };
    return { provider: 'anthropic', state: 'ready', model: A.model() };
  }

  async function resolve() {
    if (kind === 'none') return { provider: kind, state: 'disabled', model: null, message: MSG.disabled };
    if (kind === 'anthropic') return direct();
    if (kind === 'private') {
      const base = String(ai.private_url || '').replace(/\/+$/, '');
      if (!base) return A.hasKey() ? direct() : { provider: kind, state: 'not_configured', model: ai.model, message: MSG.not_configured_private };
      return { provider: kind, state: 'ready', model: ai.model, url: `${base}/draft` };
    }
    // claude (staging)
    if (!connector) return { provider: 'claude', state: 'not_configured', model: ai.model, message: MSG.not_configured_claude };
    const c = await connector.read();
    if (!c.configured) {
      if (log) log.every('connector-state', 300000, 'info', 'provider: Claude connector not configured', { reason: c.reason });
      return { provider: 'claude', state: 'not_configured', model: ai.model, message: MSG.not_configured_claude, reason: c.reason };
    }
    const model = c.model || ai.model;
    if (!require('../ai-backend').allowed(getSettings())) return { provider: 'claude', state: 'external_not_allowed', model, message: MSG.external_not_allowed };
    return { provider: 'claude', state: 'ready', model, url: ai.claude_url, apiKey: c.apiKey };
  }

  async function callModel(r, system, prompt) {
      if (r.provider === 'anthropic') return normalise(await A.call({ effort: ai.effort || 'high', system, prompt }));
      const body = { model: r.model, effort: ai.effort || 'high', system, prompt };
      const headers = {};
      if (r.provider === 'claude') body.apiKey = r.apiKey;
      else if (secrets && secrets.private_token) headers.Authorization = `Bearer ${secrets.private_token}`;
      const res = normalise(await postJson(r.url, body, headers, ai.timeout_ms || 360000));
      if (!res.model) res.model = r.model;
      return res;
    }

  return {
    async status() {
      const r = await resolve();
      return { provider: r.provider, state: r.state, model: r.model || null, message: r.state === 'ready' ? null : r.message };
    },
    // call({system, prompt}) — system/prompt MUST already be sanitised by the caller (jobs.js)
    async call({ system, prompt, who, feature }) {
      const r = await resolve();
      if (r.state !== 'ready') return { ok: false, code: r.state, message: r.message, model: r.model };
      /* the deterministic guard rails (engine/ai-guard.js): secrets masked whatever the caller sent, the untrusted-data rule
         added to the system prompt, the platform's daily token budget and the prompt-size cap checked before any token is
         spent (each feature keeps its own per-user / daily call caps on top), every call recorded with its injection flags */
      prompt = G.redactSecrets(prompt); system = G.redactSecrets(system) + '\n\n' + G.UNTRUSTED_RULE;
      const user = (who && who.user) || 'system', feat = String(feature || 'itam.ai'), flags = G.injectionSignals(prompt);
      const budget = G.sharedBudget({ log, limits: () => ai.limits || {} });
      try { budget.admit(user, feat, prompt.length + system.length); } catch (e) { return { ok: false, code: e.status === 413 ? 'too_large' : 'budget', message: e.message, model: r.model }; }
      let out;
      try { out = await callModel(r, system, prompt); } finally { budget.record(user, feat, out && out.usage, flags); }
      // what the model actually received (after masking and the added rule): the audit trail hashes THIS, not the draft
      if (out) { out.sent_system_sha256 = G.sha256(system); out.sent_prompt_sha256 = G.sha256(prompt); out.sent_chars = system.length + prompt.length; }
      return out;
    },
    usage: () => G.sharedBudget({ log, limits: () => ai.limits || {} }).view(),
    kind,
    // synchronous view for the duty desk (aiStatus must not wait): exact for 'anthropic' / 'private', best effort otherwise
    statusSync() {
      if (kind === 'none') return { enabled: false, reason: MSG.disabled };
      if (kind === 'anthropic' || (kind === 'private' && !String(ai.private_url || '').trim() && A.hasKey())) { const r = direct(); return { enabled: r.state === 'ready', reason: r.message, model: r.model }; }
      if (kind === 'private') return String(ai.private_url || '').trim() ? { enabled: true, model: ai.model } : { enabled: false, reason: MSG.not_configured_private };
      return { enabled: !!connector, reason: connector ? null : MSG.not_configured_claude };
    },
  };
}

module.exports = { createProvider, postJson, MSG };
