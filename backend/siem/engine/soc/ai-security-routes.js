// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const { guard: guardJob } = require('../util/errors');
/*
 * AI Security (engine/soc/ai-security.js), under the SOC prefix.
 *   GET  {P}/soc/ai-security/overview   operator   inventory, usage history, quality, unusual use per person, flags, red team
 *   POST {P}/soc/ai-security/redteam    admin      run the guard-rail red team now (no model call)                    audited
 * The red team also runs every 24 h (a self-rescheduling guarded loop). Operator is the floor because the page names people.
 */
const { createAiSecurity } = require('./ai-security');
const { wrap, audit, prefixOf } = require('./routeutil');

let TIMER = null;

function register(api, deps) {
  if (!deps.state) return;
  const P = prefixOf(deps);
  const A = createAiSecurity(deps);
  deps.aiSecurity = A;
  api.route('GET', `${P}/soc/ai-security/overview`, wrap(deps, 'operator', (ctx) => ctx.ok(A.overview())));
  api.route('POST', `${P}/soc/ai-security/redteam`, wrap(deps, 'admin', (ctx) => {
    const r = A.redteam(ctx.user);
    audit(ctx, 'soc.ai.redteam', 'guard-rails', { passed: r.passed, total: r.total });
    return ctx.ok(r);
  }));
  if (TIMER) clearTimeout(TIMER);
  const tick = guardJob('soc.ai-redteam', async () => { try { A.redteam('schedule'); } finally { TIMER = setTimeout(tick, 24 * 3600000); if (TIMER.unref) TIMER.unref(); } });
  if (!deps.noTimers) { TIMER = setTimeout(tick, 60000); if (TIMER.unref) TIMER.unref(); }
}

module.exports = { register };
