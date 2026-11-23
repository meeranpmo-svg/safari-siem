// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * AI Security Engineer — Zscaler (prefix {P} = /api/soc). Read-only posture for ZIA + ZPA; four-eyes change plans.
 *   GET  {P}/zscaler/overview                 viewer   tenants + last poll + findings + pending changes
 *   GET  {P}/zscaler/tenants                  viewer   connection records (never secret values)
 *   POST {P}/zscaler/tenants                  admin    add / update a tenant
 *   DELETE {P}/zscaler/tenants/:id            admin
 *   PUT  {P}/zscaler/tenants/:id/credentials  admin    { zia:{apiKey,password,fingerprint256?,insecure?}, zpa:{clientSecret,…} } → secrets.json
 *   POST {P}/zscaler/tenants/:id/test         admin    live read-only login test (counts only)
 *   POST {P}/zscaler/tenants/:id/sync         operator poll now
 *   GET  {P}/zscaler/findings                 viewer
 *   GET  {P}/zscaler/changes                  viewer   POST {P}/zscaler/changes/:id/decide (admin)  POST …/applied (operator)
 */
const { HttpError, wrap, audit, body, prefixOf } = require('../soc/routeutil');
const { createZscaler } = require('./index');

function register(api, deps) {
  if (!deps.state) throw new Error('zscaler needs deps.state');
  const P = prefixOf(deps), Z = deps.zscaler || createZscaler(deps);
  deps.zscalerInstance = Z;                           // the duty desk (registered after) reads this
  if (!(deps.config && deps.config.zscaler && deps.config.zscaler.enabled === false) && !deps.zscaler) Z.start();

  api.route('GET', `${P}/zscaler/overview`, wrap(deps, null, () => Z.overview()));
  api.route('GET', `${P}/zscaler/tenants`, wrap(deps, null, () => ({ items: Z.list() })));
  api.route('POST', `${P}/zscaler/tenants`, wrap(deps, 'admin', (ctx) => { const t = Z.put(body(ctx), ctx.user); audit(ctx, 'zscaler.tenant.put', t.id, { zia: !!(t.zia && t.zia.enabled), zpa: !!(t.zpa && t.zpa.enabled) }); return t; }));
  api.route('DELETE', `${P}/zscaler/tenants/:id`, wrap(deps, 'admin', (ctx) => { const r = Z.remove(ctx.params.id, ctx.user); audit(ctx, 'zscaler.tenant.remove', ctx.params.id); return r; }));
  api.route('PUT', `${P}/zscaler/tenants/:id/credentials`, wrap(deps, 'admin', (ctx) => { const b = body(ctx); const r = Z.setCredentials(ctx.params.id, { zia: b.zia, zpa: b.zpa }, ctx.user); audit(ctx, 'zscaler.tenant.credentials', ctx.params.id, { set: Object.keys(b).filter((k) => b[k]) }); return r; }));
  api.route('POST', `${P}/zscaler/tenants/:id/test`, wrap(deps, 'admin', async (ctx) => { const r = await Z.test(ctx.params.id, ctx.user); audit(ctx, 'zscaler.tenant.test', ctx.params.id, { zia: r.zia && r.zia.ok, zpa: r.zpa && r.zpa.ok }); return r; }));
  api.route('POST', `${P}/zscaler/tenants/:id/sync`, wrap(deps, 'operator', async (ctx) => { if (!Z.get(ctx.params.id)) throw new HttpError(404, 'tenant not found'); const s = await Z.sync(ctx.params.id); return { synced: !!s, errors: (s && s.errors) || [] }; }));
  api.route('GET', `${P}/zscaler/findings`, wrap(deps, null, () => ({ items: Z.findings() || [], connected: Z.findings() !== null })));
  api.route('GET', `${P}/zscaler/changes`, wrap(deps, null, (ctx) => ({ items: Z.changes.list({ status: (ctx.query || {}).status }) })));
  api.route('POST', `${P}/zscaler/changes/:id/decide`, wrap(deps, 'approve:eng:zscaler', (ctx) => { const b = body(ctx); const c = Z.changes.decide(ctx.params.id, b.decision, ctx.user, b.comment); audit(ctx, 'zscaler.change.' + b.decision, c.id); return c; }));
  api.route('POST', `${P}/zscaler/changes/:id/applied`, wrap(deps, 'operator', (ctx) => { const c = Z.changes.markApplied(ctx.params.id, ctx.user, body(ctx).note); audit(ctx, 'zscaler.change.applied', c.id); return c; }));
}

module.exports = { register, createZscaler };
