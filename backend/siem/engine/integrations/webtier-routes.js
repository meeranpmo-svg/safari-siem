// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Applications, Web Servers & APIs (engine/integrations/webtier.js), read-only over ManageEngine Applications Manager. Registered after
 * apm-routes.js, which leaves its engine on deps.meApm.
 *   GET  {P}/webtier          any signed-in role   tiers, probable-cause hosts, problems, learning per monitor
 *   POST {P}/webtier/ask      operator {question?} the AI application operations advisor (read-only, proposes)            audited
 * A 5-minute sample of every monitor runs through guard('webtier.sample') and reschedules in finally.
 */
const { body: check } = require('../util/check');
const { guard: guardJob } = require('../util/errors');
const SC = require('../approvers/scopes');
const { createWebTier } = require('./webtier');
const { HttpError, wrap, audit, prefixOf } = require('../soc/routeutil');

function register(api, deps) {
  if (!deps.state) return null;
  const P = prefixOf(deps);
  const W = createWebTier(Object.assign({}, deps, { apm: deps.meApm || null }));
  deps.webTier = W;
  api.route('GET', `${P}/webtier`, wrap(deps, null, (ctx) => ctx.ok(W.view())));
  api.route('POST', `${P}/webtier/ask`, wrap(deps, 'operator', async (ctx) => {
    const b = check(ctx.body || {}).str('question', { max: 1500 }).done();
    if (!SC.isHuman(ctx.user)) throw new HttpError(403, 'a service or AI identity cannot ask the advisor: a person does');
    let r; try { r = await W.advise(b.question || '', { user: ctx.user, role: ctx.role }); } catch (e) { if (e && Number.isInteger(e.code)) throw new HttpError(e.code, e.message); throw e; }
    audit(ctx, 'webtier.ask', 'advisor', { chars: (b.question || '').length, steps: r.steps.length, unverified: r.unverified });
    return ctx.ok(r);
  }));
  let TIMER = null;
  const tick = guardJob('webtier.sample', async () => { try { W.sample(); } finally { TIMER = setTimeout(tick, 5 * 60000); if (TIMER.unref) TIMER.unref(); } });
  if (!deps.noTimers) { TIMER = setTimeout(tick, 90000); if (TIMER.unref) TIMER.unref(); }
  return W;
}

module.exports = { register };
