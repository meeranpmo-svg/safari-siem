// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * XDR API (engine/xdr/xdr.js) - under the SOC prefix, same auth as the SOC routes.
 *   GET  {P}/xdr/incidents        ?scope=correlated|multi|all &status=open|closed|all &domain= &min_score= &q= &limit=
 *   GET  {P}/xdr/incidents/:id    incident + alert timeline + suggested playbook + recommended (not executed) actions
 *   POST {P}/xdr/incidents/:id/case   open a case with the incident's alerts (or add them to its existing case) (operator)
 *   GET  {P}/xdr/coverage         alerts per security domain in the last 72 h
 *   GET  {P}/xdr/leads            UEBA findings with no alert + low-severity chains that cross domains
 *   GET  {P}/xdr/hunts            the hunt library        POST {P}/xdr/hunts/:id/run {from?, to?}  (operator; read-only search)
 *   GET  {P}/xdr/beacons          ?hours=24  periodic outbound connections (statistics over the event store)
 *   GET  {P}/xdr/status           readiness: alerts to correlate, domains reporting, UEBA / search / store, auto-case last run
 *   GET  {P}/xdr/settings         PUT {P}/xdr/settings {auto_case_score (0 = off, 40-100), lookback_h, link_window_h, hub_max,
 *                                 internal_domains[]}  (admin; saved in the SOC state, overrides config.json "xdr")
 * Nothing here executes a response action: a case raises the playbook's approval requests and a person decides.
 */
const { createXdr } = require('./xdr');
const playbooks = require('../soc/playbooks');
const { HttpError, wrap, audit, body, timeParam, prefixOf } = require('../soc/routeutil');

let TIMER = null;

function register(api, deps) {
  if (!deps.alerts || !deps.cases) return;
  const P = prefixOf(deps);
  const x = createXdr(Object.assign({}, deps, { playbooks }));
  deps.xdr = x;

  api.route('GET', `${P}/xdr/incidents`, wrap(deps, null, (ctx) => ctx.ok(x.incidents(ctx.query || {}))));
  api.route('GET', `${P}/xdr/incidents/:id`, wrap(deps, null, (ctx) => {
    const i = x.incident(ctx.params.id); if (!i) throw new HttpError(404, 'incident not found (it may have merged into another one - reload the list)');
    return ctx.ok(i);
  }));
  api.route('POST', `${P}/xdr/incidents/:id/case`, wrap(deps, 'operator', (ctx) => {
    const r = x.promote(ctx.params.id, ctx.user);
    audit(ctx, 'xdr.case', ctx.params.id, r);
    return ctx.ok(r);
  }));
  api.route('GET', `${P}/xdr/coverage`, wrap(deps, null, (ctx) => ctx.ok(x.coverage())));
  api.route('GET', `${P}/xdr/leads`, wrap(deps, null, (ctx) => ctx.ok(x.leads())));
  api.route('GET', `${P}/xdr/hunts`, wrap(deps, null, (ctx) => ctx.ok(x.hunts())));
  api.route('POST', `${P}/xdr/hunts/:id/run`, wrap(deps, 'operator', async (ctx) => {
    const b = body(ctx), to = timeParam(b.to, Date.now()), from = timeParam(b.from, to - 7 * 864e5);
    if (to - from > 31 * 864e5) throw new HttpError(400, 'a hunt covers at most 31 days');
    const r = await x.runHunt(ctx.params.id, { from, to });
    audit(ctx, 'xdr.hunt', ctx.params.id, { from, to, hits: r.total });
    return ctx.ok(r);
  }));
  api.route('GET', `${P}/xdr/status`, wrap(deps, null, (ctx) => ctx.ok(x.status())));
  api.route('GET', `${P}/xdr/settings`, wrap(deps, null, (ctx) => ctx.ok({ settings: x.settings() })));
  api.route('PUT', `${P}/xdr/settings`, wrap(deps, 'admin', (ctx) => {
    let r; try { r = x.putSettings(body(ctx), ctx.user); } catch (e) { throw new HttpError(e.code || 400, e.message); }
    audit(ctx, 'xdr.settings', 'settings', r.changed);
    return ctx.ok(r);
  }));
  api.route('GET', `${P}/xdr/intel`, wrap(deps, 'analyst', (ctx) => ctx.ok(x.intel())));   // next tactic, similar past incidents, trend (xdr-ml.js): names people and hosts
  api.route('GET', `${P}/xdr/beacons`, wrap(deps, 'analyst', async (ctx) => ctx.ok(await x.beacons(ctx.query || {}))));

  if (TIMER) clearInterval(TIMER);
  TIMER = setInterval(() => { try { x.autoTick(); } catch (e) { (deps.log || console).error('xdr auto-case tick failed', { err: e && e.message }); } }, 60000);
  if (TIMER.unref) TIMER.unref();
}

module.exports = { register };
