// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * SOAR - Automated Response (engine/soc/soar.js), under the SOC prefix.
 *   GET  {P}/soc/soar                       any signed-in user   matches with itemised confidence, runs + approval status, playbooks,
 *                                                                 learning, KPIs, time saved
 *   POST {P}/soc/soar/matches/:key/run      operator, a person   open a case with the playbook -> pending approvals          audited
 *   POST {P}/soc/soar/matches/:key/dismiss  operator, a person   {reason} hide the match for 24 h                            audited
 *   POST {P}/soc/soar/matches/:key/ask      operator, a person   AI response brief (a draft; budgeted)                       audited
 *   PUT  {P}/soc/soar/config                admin, a person      {baseVersion, auto, playbooks:{id:{mode, min_severity, min_confidence}}}  audited
 * Approving or rejecting an action uses the existing POST {P}/approvals/:id/decide (approve:eng:soc, never the requester).
 * Background: the auto-propose scan every 2 minutes (guard 'soc.soar.scan', rescheduled in finally); it does nothing while
 * automation is off.
 */
const { body } = require('../util/check');
const { guard } = require('../util/errors');
const playbooks = require('./playbooks');
const { createSoar } = require('./soar');
const { HttpError, wrap, audit, prefixOf } = require('./routeutil');

function register(api, deps) {
  if (!deps.cases || !deps.alerts || !deps.state) return;
  const P = prefixOf(deps), S = createSoar(deps); deps.soar = S;
  const KEY = /^[a-f0-9]{12}$/;
  const keyOf = (ctx) => { const k = String(ctx.params.key || ''); if (!KEY.test(k)) throw new HttpError(400, 'key is not valid'); return k; };
  const who = (ctx) => ({ user: ctx.user, role: String(ctx.role || '').toLowerCase() });
  const fail = (e) => { if (e && e.status && !(e instanceof HttpError)) throw new HttpError(e.status, e.message); throw e; };

  api.route('GET', `${P}/soc/soar`, wrap(deps, null, (ctx) => ctx.ok(S.view())));
  api.route('POST', `${P}/soc/soar/matches/:key/run`, wrap(deps, 'operator', (ctx) => {
    const k = keyOf(ctx); body(ctx.body || {}).done(); let r; try { r = S.run(k, who(ctx)); } catch (e) { fail(e); }
    audit(ctx, 'soc.soar.run', k, { playbook: r.playbook_id, case_id: r.case_id, confidence: r.confidence, approvals: r.approvals.length });
    return ctx.ok(r);
  }));
  api.route('POST', `${P}/soc/soar/matches/:key/dismiss`, wrap(deps, 'operator', (ctx) => {
    const k = keyOf(ctx), b = body(ctx.body || {}).str('reason', { required: true, min: 3, max: 500 }).done(); let r; try { r = S.dismiss(k, b.reason, who(ctx)); } catch (e) { fail(e); }
    audit(ctx, 'soc.soar.dismiss', k, { reason: b.reason });
    return ctx.ok(r);
  }));
  api.route('POST', `${P}/soc/soar/matches/:key/ask`, wrap(deps, 'operator', async (ctx) => {
    const k = keyOf(ctx); body(ctx.body || {}).done(); let r; try { r = await S.ask(k, who(ctx)); } catch (e) { fail(e); }
    audit(ctx, 'soc.soar.ask', k, { ok: r.ok, actions: r.actions ? r.actions.length : 0, unverified: r.unverified || 0, tokens: r.usage ? (r.usage.input_tokens || 0) + (r.usage.output_tokens || 0) : 0 });
    return ctx.ok(r);
  }));
  api.route('PUT', `${P}/soc/soar/config`, wrap(deps, 'admin', (ctx) => {
    const b = body(ctx.body || {}).int('baseVersion', { min: 0 }).bool('auto').done();
    const raw = (ctx.body || {}).playbooks, pbs = {};
    if (raw != null) { if (typeof raw !== 'object' || Array.isArray(raw)) throw new HttpError(400, 'playbooks must be an object');
      for (const id of Object.keys(raw)) { if (!playbooks.get(id)) throw new HttpError(400, 'playbooks.' + id + ': unknown playbook');
        try { pbs[id] = body(raw[id] || {}).oneOf('mode', ['off', 'propose']).int('min_severity', { min: 0, max: 4 }).int('min_confidence', { min: 50, max: 100 }).done(); } catch (e) { throw new HttpError(400, 'playbooks.' + id + '.' + e.message); } } }
    let r; try { r = S.putConfig(Object.assign({}, b, raw != null ? { playbooks: pbs } : {}), who(ctx)); } catch (e) { fail(e); }
    audit(ctx, 'soc.soar.config', 'soar', { version: r.version, auto: b.auto, playbooks: Object.keys(pbs) });
    return ctx.ok(r);
  }));

  if (!deps.noTimer) { let t = null; const tick = guard('soc.soar.scan', async () => { try { S.scan(); } finally { t = setTimeout(tick, 120000); if (t.unref) t.unref(); } }); t = setTimeout(tick, 60000); if (t.unref) t.unref(); }
}

module.exports = { register };
