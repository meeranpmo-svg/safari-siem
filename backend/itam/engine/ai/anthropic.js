// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Direct Claude for the ITAM model provider (provider.js kind 'anthropic'), with the official SDK. Same /draft-shaped
// answer as the private model, so every ITAM AI feature (GRC consultant, classification jobs, …) works unchanged.
//   createAnthropic({ config, getKey?, sdk? }) → { ready() → {ok, reason}, call({model, effort, system, prompt}) → normalised }
// Key: /etc/sentra-itam/secrets.json "anthropic_api_key" (re-read when the file changes; sudo zyb-virt-ai --set-key) or
// ANTHROPIC_API_KEY. SDK: the SIEM's pinned bundle (/opt/sentra-siem/vendor) or /opt/sentra-itam/vendor. The key is never
// logged or returned.
const fs = require('node:fs');
const path = require('node:path');

const MODEL = 'claude-opus-5-5';

function fileKey(file, keyFile) {
  const get = require('../secret-values').fileValue(file, 'anthropic_api_key', keyFile);   // sealed at rest (engine/secret-values.js)
  return () => get() || process.env.ANTHROPIC_API_KEY || '';
}

function createAnthropic({ config, getKey, sdk } = {}) {
  const ai = (config && config.ai) || {};
  const key = getKey || fileKey(process.env.SENTRA_ITAM_SECRETS || '/etc/sentra-itam/secrets.json', config && config.discovery && config.discovery.vault_key_file);
  let Ctor = null, loadError = '';
  function loadSdk() {
    if (sdk) return sdk; if (Ctor) return Ctor;
    const tries = [ai.sdk_path, '@anthropic-ai/sdk', '/opt/sentra-itam/vendor/node_modules/@anthropic-ai/sdk', '/opt/sentra-siem/vendor/node_modules/@anthropic-ai/sdk', path.join(__dirname, '..', '..', 'vendor', 'node_modules', '@anthropic-ai', 'sdk'), require('path').join(__dirname, '..', 'ai-sdk-shim.js')].filter(Boolean);
    for (const p of tries) { try { const m = require(p); Ctor = require('../ai-backend').wrap(m.Anthropic || m.default || m); return Ctor; } catch (e) { loadError = e.code === 'MODULE_NOT_FOUND' ? 'Anthropic SDK not installed (the update installs it with netops-setup.sh)' : e.message; } }
    return null;
  }
  const hasKey = () => !!key();
  function ready() {
    if (!key()) return { ok: false, reason: 'no Anthropic API key (sudo zyb-virt-ai --set-key)' };
    if (!loadSdk()) return { ok: false, reason: loadError || 'Anthropic SDK not installed' };
    return { ok: true };
  }
  const model = () => ai.anthropic_model || MODEL;
  async function call({ effort, system, prompt }) {
    const r = ready(); if (!r.ok) return { ok: false, code: 'not_configured', message: r.reason, model: model() };
    const Anthropic = loadSdk();
    const client = new Anthropic({ apiKey: key(), timeout: ai.timeout_ms || 360000, maxRetries: 2, baseURL: ai.anthropic_base_url || undefined });
    const params = { model: model(), max_tokens: 16000, thinking: { type: 'adaptive' }, output_config: { effort: effort || ai.effort || 'high' }, system, messages: [{ role: 'user', content: prompt }] };
    if (ai.fallbacks !== false) { params.betas = ['server-side-fallback-2026-07-01']; params.fallbacks = 'default'; }
    let resp;
    try { resp = await (params.betas ? client.beta.messages.create(params) : client.messages.create(params)); }
    catch (e) { return { ok: false, code: e.status === 401 ? 'bad_key' : e.status === 429 ? 'rate_limited' : 'ai_error', message: e.status === 401 ? 'The Anthropic API key was refused (401) - store a valid key with: sudo zyb-virt-ai --set-key' : String(e.message || e).slice(0, 300), model: model() }; }
    if (resp.stop_reason === 'refusal') return { ok: false, code: 'refused', message: 'The AI declined this request.', model: resp.model || model() };
    const text = (resp.content || []).filter((b) => b.type === 'text').map((b) => b.text).join('\n').trim();
    const u = resp.usage || {};
    return { ok: true, text, model: resp.model || model(), usage: { input: (u.input_tokens || 0) + (u.cache_read_input_tokens || 0), output: u.output_tokens || 0 }, truncated: resp.stop_reason === 'max_tokens', stop_reason: resp.stop_reason || null };
  }
  return { ready, call, hasKey, model };
}

module.exports = { createAnthropic, fileKey, MODEL };
