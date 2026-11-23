// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * ManageEngine Applications Manager routes (engine/integrations/me-apm.js). Registered after db-audit/dba-routes.js so the
 * coverage view can compare APM's database monitors with the SIEM's Database Dashboard.
 *
 *   GET  {P}/integrations/apm/status | monitors?db=1&q= | alarms?db=1&all=1 | coverage        any signed-in role
 *   GET  {P}/integrations/apm/monitors/:id                       one monitor's attributes (GetMonitorData)    operator
 *   GET  {P}/integrations/apm/settings                           admin → settings + key state (never the key)
 *   POST {P}/integrations/apm/settings  {base_url, enabled, poll_min, verify_tls, ca_file, fingerprint256}    admin
 *   POST {P}/integrations/apm/key {api_key}  ·  DELETE {P}/integrations/apm/key                              admin (write-only)
 *   POST {P}/integrations/apm/test  (admin)  ·  /sync (operator)
 *   GET  {P}/integrations/apm/actions?status=                    operator
 *   POST {P}/integrations/apm/actions {action: poll|unmanage|manage, resource_id, hours?, suppress?, reason}   operator
 *   POST {P}/integrations/apm/actions/:id/decide {decision: approve|reject, comment}
 *        an administrator or the human approver of the monitor's area (database: eng:dba, other: infra), never the requester
 */
const { createMeApm } = require('./me-apm');
const { HttpError, wrap, audit, body, prefixOf } = require('../soc/routeutil');

function register(api, deps) {
  if (!deps.state) return null;
  const P = prefixOf(deps);
  const log = deps.log && deps.log.child ? deps.log.child({ mod: 'me-apm' }) : (deps.log || { info() {}, warn() {}, error() {} });
  const A = deps.meApm || createMeApm({ state: deps.state, config: deps.config || {}, log, now: deps.now, transport: deps.apmTransport,
    dbInstances: () => { try { return deps.dbaAlerts ? deps.dbaAlerts.status().instances : []; } catch (e) { return []; } } });
  deps.meApm = A;   // read by integrations/webtier-routes.js (Applications, Web Servers & APIs)

  api.route('GET', `${P}/integrations/apm/status`, wrap(deps, null, (ctx) => ctx.ok(A.status())));
  api.route('GET', `${P}/integrations/apm/monitors`, wrap(deps, null, (ctx) => ctx.ok({ items: A.monitors(ctx.query || {}) })));
  api.route('GET', `${P}/integrations/apm/alarms`, wrap(deps, null, (ctx) => ctx.ok({ items: A.alarms(ctx.query || {}) })));
  api.route('GET', `${P}/integrations/apm/coverage`, wrap(deps, null, (ctx) => ctx.ok(A.coverage())));
  api.route('GET', `${P}/integrations/apm/monitors/:id`, wrap(deps, 'operator', async (ctx) => ctx.ok(await A.monitorData(ctx.params.id))));
  api.route('GET', `${P}/integrations/apm/settings`, wrap(deps, 'admin', (ctx) => ctx.ok({ settings: A.settings(), key: A.keyState() })));
  api.route('POST', `${P}/integrations/apm/settings`, wrap(deps, 'admin', (ctx) => {
    const before = A.settings(); const s = A.setSettings(body(ctx), ctx.user);
    audit(ctx, 'apm.settings', 'me-apm', { base_url: [before.base_url, s.base_url], enabled: [before.enabled, s.enabled], poll_min: s.poll_min, verify_tls: s.verify_tls });
    return ctx.ok({ settings: s, key: A.keyState() });
  }));
  api.route('POST', `${P}/integrations/apm/key`, wrap(deps, 'admin', (ctx) => { const k = A.setKey(body(ctx).api_key, ctx.user); audit(ctx, 'apm.key.set', 'me-apm', { fingerprint: k.key_fingerprint }); return ctx.ok(k); }));
  api.route('DELETE', `${P}/integrations/apm/key`, wrap(deps, 'admin', (ctx) => { const k = A.clearKey(ctx.user); audit(ctx, 'apm.key.clear', 'me-apm', {}); return ctx.ok(k); }));
  api.route('POST', `${P}/integrations/apm/test`, wrap(deps, 'admin', async (ctx) => { const r = await A.test(); audit(ctx, 'apm.test', 'me-apm', r); return ctx.ok(r); }));
  api.route('POST', `${P}/integrations/apm/sync`, wrap(deps, 'operator', async (ctx) => ctx.ok(await A.sync())));
  api.route('GET', `${P}/integrations/apm/actions`, wrap(deps, 'operator', (ctx) => ctx.ok({ items: A.actions(ctx.query || {}) })));
  api.route('POST', `${P}/integrations/apm/actions`, wrap(deps, 'operator', async (ctx) => ctx.ok(await A.request(body(ctx), ctx.user))));
  api.route('POST', `${P}/integrations/apm/actions/:id/decide`, wrap(deps, (ctx) => `approve:${A.scopeFor(ctx.params.id)}`, async (ctx) => {
    const b = body(ctx);
    if (!['approve', 'reject'].includes(b.decision)) throw new HttpError(400, 'decision must be approve or reject');
    return ctx.ok(await A.decide(ctx.params.id, b.decision, ctx.user, b.comment));
  }));

  A.start();
  deps.meApm = A;
  return A;
}

module.exports = { register };
