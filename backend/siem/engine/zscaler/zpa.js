// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Zscaler Private Access (ZPA) — read-only posture over the ZPA Config API.
 *   auth: POST <base>/signin  (form) client_id / client_secret → { access_token } (Bearer, ~1h)
 *   data: GET  <base>/mgmtconfig/v1/admin/customers/<customerId>/<resource>
 *   base e.g. https://config.private.zscaler.com
 * READ-ONLY: only the GET resources below are ever read (app segments, access policy, App Connectors + groups). Nothing
 * is created or changed. A page of results is followed to pagesize; totals come from the API's own `totalPages`.
 */
const { request } = require('../secops/https');

function base(cfg) {
  const b = String(cfg.base_url || 'https://config.private.zscaler.com').trim().replace(/\/+$/, '');
  if (!/^https:\/\//.test(b)) throw new Error('ZPA base_url must be https');
  return b;
}

async function token(cfg) {
  const url = base(cfg) + '/signin';
  const form = 'client_id=' + encodeURIComponent(cfg.clientId || '') + '&client_secret=' + encodeURIComponent(cfg.clientSecret || '');
  const r = await request({ url, method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: form, tls: cfg.tls || {}, timeoutMs: cfg.timeoutMs || 20000 });
  if (r.status === 401 || r.status === 403) throw new Error('ZPA API refused the credentials (HTTP ' + r.status + ') — check the client id and secret');
  if (r.status >= 400 || !r.json || !r.json.access_token) throw new Error('ZPA sign-in failed (HTTP ' + r.status + ')');
  return r.json.access_token;
}

async function session(cfg) {
  if (!cfg.customerId) throw new Error('ZPA customerId required');
  const tok = await token(cfg), root = base(cfg) + '/mgmtconfig/v1/admin/customers/' + encodeURIComponent(cfg.customerId);
  const getPage = async (resource, page) => {
    const sep = resource.includes('?') ? '&' : '?';
    const g = await request({ url: root + resource + sep + 'page=' + page + '&pagesize=500', headers: { Authorization: 'Bearer ' + tok }, tls: cfg.tls || {}, timeoutMs: cfg.timeoutMs || 20000 });
    if (g.status === 401 || g.status === 403) { const e = new Error('forbidden'); e.forbidden = true; throw e; }
    if (g.status >= 400) throw new Error('ZPA HTTP ' + g.status + ' on ' + resource);
    return g.json || {};
  };
  const getAll = async (resource) => {
    const out = []; let page = 1, pages = 1;
    do { const j = await getPage(resource, page); const list = j.list || j.items || []; out.push(...list); pages = Number(j.totalPages || 1); page++; } while (page <= pages && page <= 20);
    return out;
  };
  return { getAll };
}

async function step(s, resource, out, key) {
  try { out[key] = { ok: true, data: await s.getAll(resource) }; }
  catch (e) { if (e.forbidden) out[key] = { available: false, reason: 'role does not allow it' }; else out[key] = { error: e.message }; }
}

async function snapshot(cfg) {
  const s = await session(cfg), raw = {};
  await step(s, '/application', raw, 'segments');
  await step(s, '/connector', raw, 'connectors');
  await step(s, '/policySet/rules/policyType/ACCESS_POLICY', raw, 'access');
  return model(raw);
}

function model(raw) {
  const arr = (x) => (x && x.ok && Array.isArray(x.data) ? x.data : []);
  const segments = arr(raw.segments), connectors = arr(raw.connectors), access = arr(raw.access);
  const availability = {};
  for (const k of ['segments', 'connectors', 'access']) availability[k] = raw[k] && raw[k].ok ? 'ok' : (raw[k] && raw[k].available === false ? 'not-available' : (raw[k] && raw[k].error) || 'unknown');
  // an App Connector not in a healthy/connected control-channel state is a reachability risk for its apps.
  // match the UP states exactly — "ZPN_STATUS_DISCONNECTED" contains the substring "connected" (the /edr/-in-OneDrive trap)
  const isUp = (s) => /^(zpn_status_connected|connected|up)$/i.test(String(s).trim());
  const down = connectors.filter((c) => c.controlChannelStatus && !isUp(c.controlChannelStatus));
  const disabledSeg = segments.filter((seg) => seg.enabled === false);
  const disabledRules = access.filter((r) => /disabled/i.test(String(r.ruleState || r.state || '')));
  return {
    source: 'zscaler-zpa', at: Date.now(), availability,
    counts: { segments: segments.length, connectors: connectors.length, access: access.length },
    connectorsDown: down.map((c) => ({ id: c.id, name: String(c.name || c.id || '').slice(0, 80), status: String(c.controlChannelStatus || '').slice(0, 40) })),
    disabledSegments: disabledSeg.map((seg) => ({ id: seg.id, name: String(seg.name || seg.id || '').slice(0, 80) })),
    disabledRules: disabledRules.map((r) => ({ id: r.id, name: String(r.name || r.id || '').slice(0, 80) })),
  };
}

module.exports = { snapshot, model };
