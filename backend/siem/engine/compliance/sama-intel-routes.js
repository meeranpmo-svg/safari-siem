// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * SAMA coverage intelligence (compliance/sama-intel.js). Registered after compliance/routes.js, which leaves its engine on
 * deps.samaCoverage.
 *   GET  {P}/compliance/sama-intel            any signed-in role  ?days=1-400  coverage + history, regressions, leverage, quick wins, forecast
 *   POST {P}/compliance/sama-intel/settings   admin {target_pct 10-100, target_date?, version} - a person                      audited
 *   POST {P}/compliance/sama-intel/ask        operator {question?} the AI compliance advisor (read-only, proposes)             audited
 * One snapshot a day through guard('sama-intel.snapshot'), rescheduled in finally.
 */
const { body: check } = require('../util/check');
const { guard: guardJob } = require('../util/errors');
const SC = require('../approvers/scopes');
const { createSamaIntel } = require('./sama-intel');
const { HttpError, wrap, audit, prefixOf } = require('../soc/routeutil');

const rethrow = (e) => { if (e && Number.isInteger(e.code)) throw new HttpError(e.code, e.message); throw e; };

function register(api, deps) {
  if (!deps.state) return null;
  const P = prefixOf(deps), B = `${P}/compliance/sama-intel`;
  const X = createSamaIntel(Object.assign({}, deps, { sama: deps.samaCoverage || null }));
  deps.samaIntel = X;
  api.route('GET', B, wrap(deps, null, async (ctx) => {
    const q = check(ctx.query || {}).int('days', { min: 1, max: 400 }).done();
    try { return ctx.ok(await X.view(q.days ? { days: q.days } : {})); } catch (e) { return rethrow(e); }
  }));
  api.route('POST', `${B}/settings`, wrap(deps, 'admin', (ctx) => {
    const b = check(ctx.body || {}).int('target_pct', { min: 10, max: 100 }).date('target_date').int('version', { min: 0, required: true }).done();
    let r; try { r = X.saveSettings(b, { user: ctx.user, role: ctx.role }); } catch (e) { rethrow(e); }
    audit(ctx, 'compliance.sama-intel.settings', 'target', { target_pct: r.target_pct, target_date: r.target_date, version: r.version });
    return ctx.ok(r);
  }));
  api.route('POST', `${B}/ask`, wrap(deps, 'operator', async (ctx) => {
    const b = check(ctx.body || {}).str('question', { max: 1500 }).done();
    if (!SC.isHuman(ctx.user)) throw new HttpError(403, 'a service or AI identity cannot ask the advisor: a person does');
    let r; try { r = await X.advise(b.question || '', { user: ctx.user, role: ctx.role }); } catch (e) { rethrow(e); }
    audit(ctx, 'compliance.sama-intel.ask', 'advisor', { chars: (b.question || '').length, steps: r.steps.length, unverified: r.unverified });
    return ctx.ok(r);
  }));
  let TIMER = null;
  const tick = guardJob('sama-intel.snapshot', async () => { try { await X.snapshot(); } finally { TIMER = setTimeout(tick, 3600000); if (TIMER.unref) TIMER.unref(); } });
  if (!deps.noTimers) { TIMER = setTimeout(tick, 150000); if (TIMER.unref) TIMER.unref(); }
  return X;
}

module.exports = { register };
