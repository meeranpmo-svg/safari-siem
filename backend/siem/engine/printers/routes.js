// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const { guard: guardJob } = require('../util/errors');
/*
 * Printers API (prefix {P} = /api/soc): Xerox fleet health over SNMP + YSoft SAFEQ 6 usage reports.
 *   GET    {P}/printers                    list + summary + settings (no secrets)                     viewer
 *   GET    {P}/printers/usage              imported SAFEQ usage by period / user / department / printer viewer
 *   GET    {P}/printers/:id                one printer with its latest snapshot                       viewer
 *   POST   {P}/printers/:id/poll           poll now                                                   operator
 *   POST   {P}/printers                    add / edit {id?, ip, name, site, department, safeq_name}     admin
 *   DELETE {P}/printers/:id                                                                            admin
 *   POST   {P}/printers/sync               import printers from IT Asset Management                   admin
 *   PUT    {P}/printers/settings           {snmp:{version, community | user/authKey/privKey}, toner_warn_pct, …} admin
 *   POST   {P}/printers/usage/import       {csv, period}  (CSV exported from a SAFEQ report)          admin
 *   GET    {P}/printers/safeq              SAFEQ 6 link + pull settings (no secret), last pulls        operator
 *   PUT    {P}/printers/safeq              {console_url, usage_url, devices_url, auth, header_name, username, secret,
 *                                           interval_min, fingerprint256, ca_file}                        admin
 *   POST   {P}/printers/safeq/test         {which: usage|devices}  fetch once, show columns + first rows     admin
 *   POST   {P}/printers/safeq/pull         {which: usage|devices|all}  pull now                            admin
 * GET usage returns per-user rows only to operators / admins (personal data, PDPL); viewers get departments / printers.
 */
const { HttpError, wrap, audit, prefixOf } = require('../soc/routeutil');
const { createPrinters } = require('./printers');
const { createSafeq } = require('./safeq');

function register(api, deps) {
  if (!deps.state) throw new Error('printers need deps.state');
  const P = prefixOf(deps), cfg = deps.config;
  let discovery = deps.discovery || null;
  if (!discovery && cfg.onboard && cfg.onboard.discovery && cfg.onboard.discovery.secret_file) { try { discovery = require('../onboard/discovery-client').createDiscoveryClient({ config: cfg, log: deps.log }); } catch { discovery = null; } }
  const PR = deps.printers || createPrinters({ state: deps.state, config: cfg, log: deps.log, ch: deps.ch, discovery, snmp: deps.printerSnmp, writeJson: require('../onboard/store').writeJsonAtomic });
  if (!deps.printers && !(cfg.printers && cfg.printers.enabled === false)) PR.start();
  const SQ = deps.safeq || createSafeq({ state: deps.state, config: cfg, printers: PR, writeJson: require('../onboard/store').writeJsonAtomic, getRaw: deps.safeqFetch, log: deps.log });
  if (!deps.safeq && !(cfg.printers && cfg.printers.enabled === false)) { const t = setInterval(guardJob('printers.routes.tick', () => SQ.tick()), 60000); if (t.unref) t.unref(); }
  const elevated = (ctx) => /^(operator|admin)$/i.test(String(ctx.role || ''));
  const err = (e) => { throw new HttpError(e.status || e.code || 500, e.message); };
  const run = (fn) => async (ctx) => { try { return await fn(ctx); } catch (e) { if (e instanceof HttpError) throw e; err(e); } };
  // Print to Digital (digital.js): registered before /printers/:id so its path is not taken for a printer id
  deps.printDigital = require('./digital').register(api, deps, PR);

  api.route('GET', `${P}/printers`, wrap(deps, null, run(async () => { const v = await PR.view(); v.safeq_console = SQ.settings().console_url || ''; return v; })));
  api.route('GET', `${P}/printers/usage`, wrap(deps, null, run((ctx) => PR.usage({ users: elevated(ctx) }))));
  api.route('GET', `${P}/printers/safeq`, wrap(deps, 'operator', run(() => SQ.settings())));
  api.route('PUT', `${P}/printers/safeq`, wrap(deps, 'admin', run((ctx) => { const b = ctx.body || {}; const r = SQ.setSettings(b, ctx.user); audit(ctx, 'printers.safeq.settings', '', { console: !!r.console_url, usage: !!r.usage_url, devices: !!r.devices_url, auth: r.auth, secret_changed: !!b.secret }); return r; })));
  api.route('POST', `${P}/printers/safeq/test`, wrap(deps, 'admin', run(async (ctx) => { const w = (ctx.body || {}).which === 'devices' ? 'devices' : 'usage'; const r = await SQ.test(w); audit(ctx, 'printers.safeq.test', w, { rows: r.rows, format: r.format }); return r; })));
  api.route('POST', `${P}/printers/safeq/pull`, wrap(deps, 'admin', run(async (ctx) => { const w = (ctx.body || {}).which || 'all', r = {};
    if (w === 'devices' || w === 'all') r.devices = await SQ.pullDevices(ctx.user); if (w === 'usage' || w === 'all') r.usage = await SQ.pullUsage(ctx.user);
    audit(ctx, 'printers.safeq.pull', w, { devices: r.devices && { ok: r.devices.ok, added: r.devices.added, updated: r.devices.updated }, usage: r.usage && { ok: r.usage.ok, periods: r.usage.periods } }); return r; })));
  api.route('POST', `${P}/printers/sync`, wrap(deps, 'admin', run(async (ctx) => { const r = await PR.syncFromInventory({ user: ctx.user, role: 'viewer' }); audit(ctx, 'printers.sync', 'inventory', { added: r.added, removed: r.removed }); return r; })));
  api.route('PUT', `${P}/printers/settings`, wrap(deps, 'admin', run((ctx) => { const b = ctx.body || {}; const r = PR.setSettings(b, ctx.user); audit(ctx, 'printers.settings', '', { snmp: !!b.snmp, sync_inventory: r.sync_inventory }); return r; })));
  api.route('POST', `${P}/printers/usage/import`, wrap(deps, 'admin', run((ctx) => { const b = ctx.body || {}; const r = PR.importUsage(b.csv, { period: b.period }, ctx.user); audit(ctx, 'printers.usage.import', r.period, { rows: r.rows, pages: r.pages }); return r; })));
  api.route('GET', `${P}/printers/:id`, wrap(deps, null, run(async (ctx) => { const d = await PR.detail(ctx.params.id); if (!d) throw new HttpError(404, 'printer not found'); return d; })));
  api.route('POST', `${P}/printers/:id/poll`, wrap(deps, 'operator', run((ctx) => PR.pollNow(ctx.params.id))));
  api.route('POST', `${P}/printers`, wrap(deps, 'admin', run((ctx) => { const p = PR.put(ctx.body || {}, ctx.user); audit(ctx, 'printers.put', p.id, { ip: p.ip }); return p; })));
  api.route('DELETE', `${P}/printers/:id`, wrap(deps, 'admin', run((ctx) => { const r = PR.remove(ctx.params.id); audit(ctx, 'printers.remove', ctx.params.id); return r; })));
  return PR;
}

module.exports = { register };
