// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const { body } = require('./check');
const { createSealer } = require('./discovery/vault');
const httpc = require('./discovery/httpc');
/*
 * The MDM the leaver device step (engine/offboarding.js) works through. One setting picks it:
 *   manageengine  ManageEngine Mobile Device Manager Plus (on-premises) REST API - /api/v1/mdm, "Authorization: <API token>".
 *                 A full wipe is complete_wipe, a retire is corporate_wipe. The token is sealed in the vault; a self-signed
 *                 server certificate is trusted only by its SHA-256 fingerprint (cert_pin), never by switching checks off
 *   intune        Microsoft Intune through Graph (engine/m365-licensing.js, "leavers' devices" there)
 * The same adapter shape for both - userDevices(upn), deviceGet(id), deviceAction(id, wipe|retire) - so moving from
 * ManageEngine to Intune is this one setting; the step, the approvals and the rules do not change.
 * Devices are matched to the leaver by the user's e-mail address as the MDM reports it - never by name.
 *   GET  /offboarding/mdm          operator  settings (never the token)
 *   POST /offboarding/mdm          admin     {provider: none|manageengine|intune, base_url?, api_token?, cert_pin?}   audited
 *   POST /offboarding/mdm/test     admin     read one page of devices (read-only)                                   audited
 */
const httpErr = (status, msg) => Object.assign(new Error(msg), { status });
const low = (s) => String(s || '').trim().toLowerCase();
const isService = (u) => /^(duty|system|core|ai|svc|service|agent|bot)[:._-]/i.test(String(u || ''));
const ME_ID = /^\d{1,20}$/;
const ME_ACT = { wipe: 'complete_wipe', retire: 'corporate_wipe' };
const PLATFORM = { 1: 'iOS', 2: 'Android', 3: 'Windows', 4: 'Chrome OS', 6: 'macOS', 7: 'tvOS' };

function createMdm(app, opts = {}) {
  const now = opts.now || Date.now, store = app.store, request = opts.request || httpc.request;
  const iso = () => new Date(now()).toISOString();
  const dc = (app.config && app.config.discovery) || {};
  const sealer = opts.sealer || createSealer({ keyFile: dc.vault_key_file, createKey: dc.vault_create_key !== false, purpose: 'sentra-itam-mdm' });
  const cfgC = () => store.collection('mdm_cfg');
  const cfg = () => Object.assign({ provider: 'none' }, cfgC().get('cfg') || {});
  const LIC = () => opts.lic ? opts.lic() : (app.addons && app.addons.onboarding && app.addons.onboarding.lic) || null;
  const audit = (who, action, target, detail) => { if (app.audit) app.audit({ by: who.user, role: who.role || '', ip: who.ip || '', action, target, detail }); };
  const meReady = () => { const c = cfg(); return c.provider === 'manageengine' && !!(c.base_url && c.token_enc); };
  const intuneReady = () => { const L = LIC(); return cfg().provider === 'intune' && !!(L && L.devicesEnabled && L.devicesEnabled()); };

  function view() {
    const c = cfg();
    return { provider: c.provider, base_url: c.base_url || '', api_token_set: !!c.token_enc, cert_pin: c.cert_pin || '', ready: meReady() || intuneReady(),
      intune_ready: !!(LIC() && LIC().devicesEnabled && LIC().devicesEnabled()), last_test: c.last_test || null, updated_by: c.updated_by || null, updated_at: c.updated_at || null,
      vault: sealer.available() ? 'available' : 'unavailable: ' + sealer.unavailableReason(),
      requirements: c.provider === 'intune' ? 'Intune: tick "leavers\' devices" in Microsoft 365 licensing settings; Graph DeviceManagementManagedDevices.Read.All and .PrivilegedOperations.All'
        : 'ManageEngine MDM Plus: an API token from Admin -> API (a technician with the device actions permission), the server address (https), and its certificate fingerprint if it is self-signed' };
  }
  function configure(input, who) {
    if (isService(who.user)) throw httpErr(403, 'a service or AI identity cannot change these settings');
    const b = body(input || {}).oneOf('provider', ['none', 'manageengine', 'intune'])
      .str('base_url', { max: 200, re: /^$|^https:\/\/[A-Za-z0-9.-]{1,190}(:\d{1,5})?\/?$/, msg: 'base_url must be the MDM server address, https://host[:port]' })
      .str('api_token', { max: 300 }).str('cert_pin', { max: 100, re: /^$|^([0-9A-Fa-f]{2}:?){31}[0-9A-Fa-f]{2}$/, msg: 'cert_pin must be the SHA-256 fingerprint of the server certificate (64 hex digits)' }).done();
    const c = Object.assign({}, cfg());
    for (const k of ['provider', 'base_url', 'cert_pin']) if (b[k] !== undefined) c[k] = b[k];
    if (c.base_url) c.base_url = c.base_url.replace(/\/$/, '');
    if (b.api_token) { if (!sealer.available()) throw httpErr(503, 'credential vault unavailable: ' + sealer.unavailableReason()); c.token_enc = sealer.seal('me-token', b.api_token); c.token_at = iso(); }
    if (c.provider === 'manageengine' && !(c.base_url && c.token_enc)) throw httpErr(400, 'provider manageengine needs base_url and api_token');
    if (c.provider === 'intune' && !(LIC() && LIC().devicesEnabled && LIC().devicesEnabled())) throw httpErr(400, 'provider intune needs "leavers\' devices" switched on in Microsoft 365 licensing settings (HR Onboarding)');
    Object.assign(c, { id: 'cfg', updated_by: who.user, updated_at: iso() });
    cfgC().put(c);
    audit(who, 'offboarding.mdm.settings', 'mdm', { provider: c.provider, base_url: c.base_url || null, cert_pin: c.cert_pin ? 'set' : null, api_token: b.api_token ? 'changed' : 'unchanged' });
    return view();
  }

  // ---- ManageEngine MDM Plus
  async function me(method, path, payload) {
    const c = cfg();
    let tok; try { tok = sealer.unseal('me-token', c.token_enc); } catch (e) { throw httpErr(503, 'the ManageEngine API token cannot be opened from the vault - save it again'); }
    const r = await request(c.base_url + path, { method, headers: Object.assign({ Authorization: tok, Accept: 'application/json' }, payload ? { 'Content-Type': 'application/json' } : {}), body: payload ? JSON.stringify(payload) : undefined, timeoutMs: 30000, pin: c.cert_pin || undefined });
    tok = null;
    if (r.status === 404) return null;
    if (r.status >= 300) { const m = r.json && (r.json.error_description || r.json.message || r.json.error) ? String(r.json.error_description || r.json.message || r.json.error).slice(0, 160) : 'HTTP ' + r.status; throw Object.assign(new Error('ManageEngine ' + method + ' ' + path.split('?')[0] + ' - ' + m), { http: r.status }); }
    return r.json || {};
  }
  const owner = (v) => { const s = low(v); return ['1', 'corporate', 'company'].includes(s) ? 'company' : ['2', 'personal', 'byod'].includes(s) ? 'personal' : 'unknown'; };
  const meRow = (d) => {
    const u = d.user || {};
    return { id: String(d.device_id), name: String(d.device_name || '').slice(0, 120), os: String(d.platform_type || PLATFORM[d.platform_type_id] || 'unknown').slice(0, 40), os_version: String(d.os_version || '').slice(0, 40),
      serial: String(d.serial_number || '').slice(0, 80), owner_type: owner(d.owned_by), upn: low(u.user_email || d.user_email), last_sync: d.last_contact_time ? new Date(Number(d.last_contact_time) || d.last_contact_time).toISOString() : null,
      compliance: null, model: String(d.model || d.product_name || '').slice(0, 120), state: d.managed_status != null ? String(d.managed_status) : null };
  };
  const meAdapter = {
    name: 'manageengine',
    async userDevices(upn) {
      const out = []; let skip = null, n = 0;
      do {
        const j = await me('GET', '/api/v1/mdm/devices?include_all=true&limit=500' + (skip ? '&skip_token=' + encodeURIComponent(skip) : ''));
        for (const d of (j && j.devices) || []) if (ME_ID.test(String(d.device_id))) out.push(meRow(d));
        skip = j && j.paging && j.paging.next_token ? String(j.paging.next_token) : null;
      } while (skip && ++n < 20);
      return { found: true, devices: out.filter((d) => d.upn === low(upn)).slice(0, 100) };
    },
    // the whole managed estate, read only (Endpoint & Mobile Management page) - at most 20 pages of 500
    async allDevices() {
      const out = []; let skip = null, n = 0, total = null;
      do {
        const j = await me('GET', '/api/v1/mdm/devices?include_all=true&limit=500' + (skip ? '&skip_token=' + encodeURIComponent(skip) : ''));
        if (j && j.metadata && j.metadata.total_record_count != null) total = Number(j.metadata.total_record_count);
        for (const d of (j && j.devices) || []) if (ME_ID.test(String(d.device_id))) out.push(meRow(d));
        skip = j && j.paging && j.paging.next_token ? String(j.paging.next_token) : null;
      } while (skip && ++n < 20);
      return { devices: out, total, truncated: !!skip };
    },
    async deviceGet(id) {
      if (!ME_ID.test(String(id))) throw new Error('device id must be a ManageEngine device id');
      const j = await me('GET', '/api/v1/mdm/devices/' + id); if (!j) return null;
      const d = j.device || j, acts = await me('GET', '/api/v1/mdm/devices/' + id + '/actions');
      const name = (a) => Object.keys(ME_ACT).find((k) => ME_ACT[k] === low(a)) || low(a);
      const state = (s) => { const x = low(s); return /success|completed|done/.test(x) || x === '2' ? 'done' : /fail|error/.test(x) || x === '3' ? 'failed' : 'pending'; };
      return Object.assign(meRow(Object.assign({ device_id: id }, d)), { actions: ((acts && acts.actions) || []).map((a) => ({ name: name(a.action_name || a.name), state: state(a.status || a.status_code), started: a.initiated_time || null })) });
    },
    async deviceAction(id, action) {
      if (!ME_ID.test(String(id))) throw new Error('device id must be a ManageEngine device id');
      if (!ME_ACT[action]) throw new Error('only wipe or retire');
      await me('POST', '/api/v1/mdm/devices/' + id + '/actions/' + ME_ACT[action], {});
      return true;
    },
  };
  async function test(who) {
    let rec;
    try {
      if (cfg().provider === 'manageengine') { const j = await me('GET', '/api/v1/mdm/devices?limit=1'); rec = { ok: true, provider: 'manageengine', devices: j && j.metadata && j.metadata.total_record_count != null ? j.metadata.total_record_count : ((j && j.devices) || []).length }; }
      else if (cfg().provider === 'intune') rec = { ok: intuneReady(), provider: 'intune' };
      else rec = { ok: false, error: 'no MDM chosen' };
    } catch (e) { rec = { ok: false, error: String(e.message).slice(0, 240) }; }
    cfgC().put(Object.assign({}, cfg(), { id: 'cfg', last_test: Object.assign({ at: iso(), by: who.user }, rec) }));
    audit(who, 'offboarding.mdm.test', 'mdm', rec);
    return rec;
  }
  // the adapter the device step uses: null when none is ready
  function adapter() {
    if (meReady()) return meAdapter;
    if (intuneReady()) { const L = LIC(); return { name: 'intune', userDevices: L.userDevices, deviceGet: L.deviceGet, deviceAction: L.deviceAction }; }
    return null;
  }
  /* ---- Endpoint & Mobile Management: the managed estate as the MDM reports it (read only, cached 15 min). Counted by platform and
   * ownership; a device that has not checked in for STALE_DAYS is stale (lost, off, or the agent removed). The MDM API gives no
   * compliance verdict in this read, so none is shown - never inferred. Personal devices are managed by container only. */
  const invC = () => store.collection('mdm_inventory'), STALE_DAYS = 14, TTL = 15 * 60000;
  let invRunning = null;
  async function readInventory(who) {
    if (invRunning) return invRunning;
    invRunning = (async () => {
      const at = iso(); let rec;
      try {
        if (meReady()) { const r = await meAdapter.allDevices(); rec = { id: 'last', at, provider: 'manageengine', devices: r.devices.slice(0, 10000), total: r.total, truncated: r.truncated, error: null }; }
        else rec = { id: 'last', at, provider: cfg().provider, devices: [], total: null, truncated: false, error: cfg().provider === 'intune' ? 'Intune devices are read per leaver only from here - the full Intune estate is on Microsoft 365, Users & Endpoints' : null };
      } catch (e) { const prev = invC().get('last'); rec = Object.assign({}, prev || { devices: [], total: null }, { id: 'last', at: prev ? prev.at : null, provider: 'manageengine', error: String(e.message).slice(0, 240), error_at: at }); }
      invC().put(rec);
      if (who) audit(who, 'mdm.inventory.refresh', 'mdm', { devices: rec.devices.length, error: rec.error || null });
      return rec;
    })();
    try { return await invRunning; } finally { invRunning = null; }
  }
  async function inventory(opts2 = {}) {
    const c = cfg(); let rec = invC().get('last');
    if (meReady() && (!rec || !rec.at || now() - Date.parse(rec.at) > TTL)) rec = await readInventory(null);
    const D = (rec && rec.devices) || [], t = now();
    const by = (f) => D.reduce((m, d) => { const k = f(d) || 'unknown'; m[k] = (m[k] || 0) + 1; return m; }, {});
    const ageDays = (d) => (d.last_sync ? Math.floor((t - Date.parse(d.last_sync)) / 86400000) : null);
    const rows = D.map((d) => Object.assign({}, d, { age_days: ageDays(d), stale: ageDays(d) == null || ageDays(d) > STALE_DAYS }));
    const kpis = { devices: D.length, total_reported: rec ? rec.total : null, company: rows.filter((d) => d.owner_type === 'company').length, personal: rows.filter((d) => d.owner_type === 'personal').length,
      stale: rows.filter((d) => d.stale).length, never: rows.filter((d) => d.age_days == null).length, no_user: rows.filter((d) => !d.upn).length };
    return { configured: meReady() || intuneReady(), provider: c.provider, read_at: rec ? rec.at : null, error: rec ? rec.error || null : null, truncated: !!(rec && rec.truncated), stale_days: STALE_DAYS, kpis,
      by_os: by((d) => d.os), by_owner: by((d) => d.owner_type), devices: rows.sort((a, b) => (b.stale - a.stale) || ((b.age_days || 0) - (a.age_days || 0))).slice(0, opts2.limit || 5000),
      reason: meReady() || intuneReady() ? null : 'No MDM is connected. An administrator connects ManageEngine Mobile Device Manager Plus (server address + API token) on HR Offboarding -> MDM.',
      note: 'As the MDM reports it, read only. Compliance verdicts are not part of this read and are not inferred. Personal devices are managed by container only - their personal data is never read.' };
  }
  return { view, configure, test, adapter, inventory, readInventory };
}

function registerMdmRoutes(srv, app, M) {
  srv.route('GET', '/offboarding/mdm', (ctx) => { ctx.need('operator'); return M.view(); });
  srv.route('POST', '/offboarding/mdm', (ctx) => { ctx.need('admin'); return M.configure(ctx.body, ctx.who); });
  // Endpoint & Mobile Management (read only): device names and user e-mail addresses are personal data (PDPL) - operators and above
  srv.route('GET', '/mdm/devices', async (ctx) => { ctx.need('operator'); return M.inventory(); });
  srv.route('POST', '/mdm/devices/refresh', async (ctx) => { ctx.need('operator'); body(ctx.body).done(); if (isService(ctx.who.user)) throw httpErr(403, 'a person does this'); await M.readInventory(ctx.who); return M.inventory(); });
  srv.route('POST', '/offboarding/mdm/test', (ctx) => { ctx.need('admin'); body(ctx.body).done(); if (isService(ctx.who.user)) throw httpErr(403, 'a person does this'); return M.test(ctx.who); });
}

module.exports = { createMdm, registerMdmRoutes };
