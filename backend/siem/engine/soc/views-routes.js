// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const { body } = require('../util/check');
/*
 * User Behaviour (engine/soc/behaviour.js) and Threat Intelligence (engine/soc/intel-view.js), under the SOC prefix.
 *   GET  {P}/soc/ueba/insights           any signed-in user   trend, detector precision from reviews, risk distribution, peers
 *   GET  {P}/soc/ueba/assess/:id         operator             the last AI behaviour assessment of an entity (or 404)
 *   POST {P}/soc/ueba/assess/:id         operator             the AI behaviour assessment (budgeted; changes nothing)  audited
 *   GET  {P}/soc/intel/overview          any signed-in user   lists, totals, sightings in alerts (30 days)
 *   POST {P}/soc/intel/retro             analyst              {hours 1-168} recent traffic checked against the lists   audited (read)
 * Behaviour profiles are personal data (PDPL): the AI assessment is operator and above and every run is audited.
 */
const { createBehaviour } = require('./behaviour');
const { createIntelView } = require('./intel-view');
const { HttpError, wrap, audit, prefixOf } = require('./routeutil');

function register(api, deps) {
  if (!deps.state) return;
  const P = prefixOf(deps);
  const B = createBehaviour(deps), V = createIntelView(deps);
  deps.behaviour = B; deps.intelView = V;
  const EID = /^(user|host|service_account|ai_agent):[^\s/\\]{1,200}$/;
  const eid = (ctx) => { const id = decodeURIComponent(String(ctx.params.id || '')); if (!EID.test(id)) throw new HttpError(400, 'id must be an entity key such as user:alice or host:pc-17'); return id; };

  api.route('GET', `${P}/soc/ueba/insights`, wrap(deps, null, (ctx) => ctx.ok(B.insights())));
  api.route('GET', `${P}/soc/ueba/assess/:id`, wrap(deps, 'operator', (ctx) => {
    const r = B.lastAssessment(eid(ctx)); if (!r) throw new HttpError(404, 'no AI assessment for this entity yet');
    return ctx.ok(r);
  }));
  api.route('POST', `${P}/soc/ueba/assess/:id`, wrap(deps, 'operator', async (ctx) => {
    const id = eid(ctx), r = await B.assess(id, { user: ctx.user, role: ctx.role });
    audit(ctx, 'soc.ueba.assess', id, { recommendation: r.recommendation, unverified: r.unverified, steps: r.steps.length });
    return ctx.ok(r);
  }));
  api.route('GET', `${P}/soc/intel/overview`, wrap(deps, null, (ctx) => ctx.ok(V.overview())));
  api.route('POST', `${P}/soc/intel/retro`, wrap(deps, 'analyst', async (ctx) => {
    const b = body(ctx.body).int('hours', { min: 1, max: 168, def: 24 }).done();
    const r = await V.retro(b);
    audit(ctx, 'soc.intel.retro', 'traffic', { hours: r.hours, hits: r.hits.length });
    return ctx.ok(r);
  }));
}

module.exports = { register };
