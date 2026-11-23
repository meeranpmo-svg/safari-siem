// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Zscaler Internet Access (ZIA) — read-only posture over the ZIA Admin API.
 *   https://<ziaCloud>/api/v1/...   (ziaCloud e.g. zsapi.zscalerbeta.net, zsapi.zscalertwo.net)
 * Auth (documented): POST /authenticatedSession { apiKey:<obfuscated>, username, password, timestamp } → JSESSIONID cookie.
 * READ-ONLY: only the GET endpoints below (and the login/logout session calls) are ever called — never a POST/PUT/DELETE
 * that changes configuration. A caller that asks for anything else gets nothing: this module exposes posture, not control.
 * Fields a given tenant/subscription does not return are left absent (a firewall rule set needs the Cloud Firewall
 * subscription; without it the endpoint answers 403 and we record "not available", never a guessed value).
 */
const { request } = require('../secops/https');

// the documented ZIA API-key obfuscation: interleave key characters chosen by the last 6 digits of the timestamp
function obfuscate(apiKey, nowMs) {
  const n = String(nowMs), r = n.substr(n.length - 6);
  let key = '';
  for (let i = 0; i < r.length; i++) key += apiKey.charAt(Number(r.charAt(i)));
  for (let j = 0; j < r.length; j++) key += apiKey.charAt(Number(r.charAt(j)) + 2);
  return key;
}

function cloudBase(cfg) {
  let h = String(cfg.cloud || cfg.base_url || '').trim().replace(/^https?:\/\//, '').replace(/\/+$/, '');
  if (!h) throw new Error('ZIA cloud host required (e.g. zsapi.zscalertwo.net)');
  return 'https://' + h;
}

async function session(cfg) {
  const base = cloudBase(cfg), tls = cfg.tls || {}, now = Date.now();
  const body = { apiKey: obfuscate(String(cfg.apiKey || ''), now), username: cfg.username, password: cfg.password, timestamp: now };
  const r = await request({ url: base + '/api/v1/authenticatedSession', method: 'POST', body, tls, timeoutMs: cfg.timeoutMs || 20000 });
  if (r.status === 401 || r.status === 403) throw new Error('ZIA API refused the credentials (HTTP ' + r.status + ') — check the API key, admin login and that API access is enabled');
  if (r.status >= 400 || !r.cookie) throw new Error('ZIA login failed (HTTP ' + r.status + ')');
  const cookie = r.cookie;
  const get = async (path) => {
    const g = await request({ url: base + '/api/v1' + path, headers: { Cookie: cookie }, tls, timeoutMs: cfg.timeoutMs || 20000 });
    if (g.status === 401 || g.status === 403) { const e = new Error('forbidden'); e.forbidden = true; throw e; }
    if (g.status === 404) { const e = new Error('not found'); e.missing = true; throw e; }
    if (g.status >= 400) throw new Error('ZIA HTTP ' + g.status + ' on ' + path);
    return g.json;
  };
  const logout = () => request({ url: base + '/api/v1/authenticatedSession', method: 'DELETE', headers: { Cookie: cookie }, tls, timeoutMs: 8000 }).catch(() => { /* logout is best effort: the session expires on ZIA */ });
  return { get, logout };
}

// one read-only endpoint → { ok, data } | { available:false } (403) | { error }
async function step(s, path, out, key) {
  try { out[key] = { ok: true, data: await s.get(path) }; }
  catch (e) { if (e.forbidden) out[key] = { available: false, reason: 'subscription or role does not allow it' }; else if (e.missing) out[key] = { available: false, reason: 'not available on this tenant' }; else out[key] = { error: e.message }; }
}

async function snapshot(cfg) {
  const s = await session(cfg), raw = {};
  try {
    await step(s, '/status', raw, 'status');
    await step(s, '/locations', raw, 'locations');
    await step(s, '/firewallFilteringRules', raw, 'fwRules');
    await step(s, '/urlFilteringRules', raw, 'urlRules');
    await step(s, '/adminUsers', raw, 'admins');
    await step(s, '/security/advanced', raw, 'advanced');
  } finally { await s.logout(); }
  return model(raw);
}

// normalise into posture the page and the findings read; only clearly-defined conditions are flagged
function model(raw) {
  const arr = (x) => (x && x.ok && Array.isArray(x.data) ? x.data : []);
  const locations = arr(raw.locations), fwRules = arr(raw.fwRules), urlRules = arr(raw.urlRules), admins = arr(raw.admins);
  const availability = {};
  for (const k of ['status', 'locations', 'fwRules', 'urlRules', 'admins', 'advanced']) availability[k] = raw[k] && raw[k].ok ? 'ok' : (raw[k] && raw[k].available === false ? 'not-available' : (raw[k] && raw[k].error) || 'unknown');

  // Cloud Firewall hygiene: an ALLOW rule with logging off is a blind spot (enableLogging is a documented field)
  const fwNoLog = fwRules.filter((r) => /allow/i.test(r.action || '') && r.enableLogging === false && /enabled/i.test(r.state || 'ENABLED'));
  // URL filtering: enabled ALLOW rules with no logging-equivalent are modest; flag disabled security rules only when named so
  const urlDisabled = urlRules.filter((r) => /disabled/i.test(r.state || ''));
  // Locations with enforcement switched off (documented booleans)
  const locUnprotected = locations.filter((l) => l.ofwEnabled === false || l.ipsControl === false);

  const activation = raw.status && raw.status.ok ? (raw.status.data && (raw.status.data.status || raw.status.data)) : null;
  return {
    source: 'zscaler-zia', at: Date.now(), availability,
    counts: { locations: locations.length, fwRules: fwRules.length, urlRules: urlRules.length, admins: admins.length },
    activation: activation ? String(activation).slice(0, 40) : null,
    fwNoLog: fwNoLog.map((r) => ({ id: r.id, name: String(r.name || r.id || '').slice(0, 80) })),
    urlDisabled: urlDisabled.map((r) => ({ id: r.id, name: String(r.name || r.id || '').slice(0, 80) })),
    locUnprotected: locUnprotected.map((l) => ({ id: l.id, name: String(l.name || l.id || '').slice(0, 80), ofw: l.ofwEnabled !== false, ips: l.ipsControl !== false })),
  };
}

module.exports = { snapshot, model, obfuscate };
