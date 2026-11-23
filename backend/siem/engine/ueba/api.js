// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * UEBA API routes — register(api, deps), deps = { ueba, config, log } (deps.ueba = engine/ueba/index.js createUeba()).
 * {P} = config.api_prefix || '/api/soc'. Uses the same session + proxy-secret auth and roles as the other SOC routes
 * (viewer: read, operator: benign/confirm, admin: settings). Every write is audited via ctx.audit.
 *
 *   GET  {P}/ueba/summary                 risk tiers, top risky entities, new findings, detector health, learning status
 *   GET  {P}/ueba/entities ?type=&tier=&state=&peer=&q=&limit=&offset=
 *   GET  {P}/ueba/entities/:id            profile: baseline vs current per feature, risk timeline, findings, peers, alerts
 *   GET  {P}/ueba/findings ?entity_id=&type=&status=&severity_min=&entity_type=&from=&to=&q=&sort=&limit=&offset=
 *   POST {P}/ueba/findings/:id/benign     operator  {note?}  → marks benign + per-entity+detector allow-list, re-scores
 *   POST {P}/ueba/findings/:id/confirm    operator  {note?}  → raises weight, re-scores
 *   GET  {P}/ueba/settings                admin     → {settings, defaults, detectors}
 *   POST {P}/ueba/settings                admin     {patch}  → {settings}
 *   GET  {P}/ueba/tuning                  admin     → {items}
 *   GET  {P}/ueba/health
 */
const { HttpError, wrap, audit, body, prefixOf } = require('../soc/routeutil');

function register(api, deps) {
  const P = prefixOf(deps);
  const ueba = deps.ueba;
  if (!ueba) throw new Error('ueba routes need deps.ueba');

  api.route('GET', `${P}/ueba/summary`, wrap(deps, null, (ctx) => ctx.ok(ueba.summary(ctx.query || {}))));
  api.route('GET', `${P}/ueba/entities`, wrap(deps, null, (ctx) => ctx.ok(ueba.entities(ctx.query || {}))));
  api.route('GET', `${P}/ueba/entities/:id`, wrap(deps, null, (ctx) => {
    const e = ueba.entity(ctx.params.id);
    if (!e) throw new HttpError(404, 'entity not found');
    return ctx.ok(e);
  }));
  api.route('GET', `${P}/ueba/findings`, wrap(deps, null, (ctx) => ctx.ok(ueba.findings(ctx.query || {}))));

  const review = (action) => wrap(deps, 'operator', (ctx) => {
    const b = body(ctx);
    const r = ueba.markFinding(ctx.params.id, action, ctx.user, b.note);
    if (r && r.code) throw new HttpError(r.code, r.error);
    audit(ctx, `ueba.finding.${action}`, ctx.params.id, { note: b.note || '' });
    return ctx.ok(r);
  });
  api.route('POST', `${P}/ueba/findings/:id/benign`, review('benign'));
  api.route('POST', `${P}/ueba/findings/:id/confirm`, review('confirm'));

  api.route('GET', `${P}/ueba/settings`, wrap(deps, 'admin', (ctx) => ctx.ok(ueba.getSettings())));
  api.route('POST', `${P}/ueba/settings`, wrap(deps, 'admin', (ctx) => {
    const b = body(ctx);
    const patch = b.settings && typeof b.settings === 'object' ? b.settings : b;
    let r;
    try { r = ueba.setSettings(patch, ctx.user); } catch (e) { throw new HttpError(400, e.message, [e.message]); }
    audit(ctx, 'ueba.settings.update', '-', { keys: Object.keys(patch || {}) });
    return ctx.ok(r);
  }));
  api.route('GET', `${P}/ueba/tuning`, wrap(deps, 'admin', (ctx) => ctx.ok({ items: ueba.listTuning() })));

  api.route('GET', `${P}/ueba/health`, wrap(deps, null, (ctx) => ctx.ok(ueba.health())));
}

module.exports = { register };
