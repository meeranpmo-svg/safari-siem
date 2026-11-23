// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * AI engineer — Kaspersky Security Center (prefix {P} = /api/soc). Read-only endpoint posture; four-eyes change plans.
 *   GET  {P}/ksc/overview                 viewer   servers + last poll summary + findings + pending changes
 *   GET  {P}/ksc/servers                  viewer   connection records (never the password)
 *   POST {P}/ksc/servers                  admin    add / update a KSC server
 *   DELETE {P}/ksc/servers/:id            admin
 *   PUT  {P}/ksc/servers/:id/credentials  admin    { password, fingerprint256?, insecure? } → secrets.json
 *   POST {P}/ksc/servers/:id/test         admin    live read-only probe (host count + fields returned)
 *   POST {P}/ksc/servers/:id/sync         operator poll now
 *   GET  {P}/ksc/findings                 viewer
 *   GET  {P}/ksc/changes                  viewer   POST {P}/ksc/changes/:id/decide (admin)  POST …/applied (operator)
 */
const { HttpError, wrap, audit, body, prefixOf } = require('../soc/routeutil');
const { createKsc } = require('./index');

function register(api, deps) {
  if (!deps.state) throw new Error('ksc needs deps.state');
  const P = prefixOf(deps), K = deps.ksc || createKsc(deps);
  deps.kscInstance = K;
  if (!(deps.config && deps.config.ksc && deps.config.ksc.enabled === false) && !deps.ksc) K.start();

  api.route('GET', `${P}/ksc/overview`, wrap(deps, null, () => K.overview()));
  api.route('GET', `${P}/ksc/servers`, wrap(deps, null, () => ({ items: K.list() })));
  api.route('POST', `${P}/ksc/servers`, wrap(deps, 'admin', (ctx) => { const s = K.put(body(ctx), ctx.user); audit(ctx, 'ksc.server.put', s.id, { host: s.host, port: s.port }); return s; }));
  api.route('DELETE', `${P}/ksc/servers/:id`, wrap(deps, 'admin', (ctx) => { const r = K.remove(ctx.params.id, ctx.user); audit(ctx, 'ksc.server.remove', ctx.params.id); return r; }));
  api.route('PUT', `${P}/ksc/servers/:id/credentials`, wrap(deps, 'admin', (ctx) => { const b = body(ctx); const r = K.setCredentials(ctx.params.id, { password: b.password, fingerprint256: b.fingerprint256, insecure: b.insecure }, ctx.user); audit(ctx, 'ksc.server.credentials', ctx.params.id, { set: !!b.password }); return r; }));
  api.route('POST', `${P}/ksc/servers/:id/test`, wrap(deps, 'admin', async (ctx) => { const r = await K.test(ctx.params.id, ctx.user); audit(ctx, 'ksc.server.test', ctx.params.id, { ok: r.ok }); return r; }));
  api.route('POST', `${P}/ksc/servers/:id/sync`, wrap(deps, 'operator', async (ctx) => { if (!K.get(ctx.params.id)) throw new HttpError(404, 'server not found'); const s = await K.sync(ctx.params.id); return { synced: !!(s && s.data), errors: (s && s.errors) || [] }; }));
  api.route('GET', `${P}/ksc/findings`, wrap(deps, null, () => ({ items: K.findings() || [], connected: K.findings() !== null })));
  api.route('GET', `${P}/ksc/changes`, wrap(deps, null, (ctx) => ({ items: K.changes.list({ status: (ctx.query || {}).status }) })));
  api.route('POST', `${P}/ksc/changes/:id/decide`, wrap(deps, 'approve:eng:ksc', (ctx) => { const b = body(ctx); const c = K.changes.decide(ctx.params.id, b.decision, ctx.user, b.comment); audit(ctx, 'ksc.change.' + b.decision, c.id); return c; }));
  api.route('POST', `${P}/ksc/changes/:id/applied`, wrap(deps, 'operator', (ctx) => { const c = K.changes.markApplied(ctx.params.id, ctx.user, body(ctx).note); audit(ctx, 'ksc.change.applied', c.id); return c; }));
}

module.exports = { register, createKsc };
