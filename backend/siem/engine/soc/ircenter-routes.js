// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const { body } = require('../util/check');
/*
 * Incident Response Center (engine/soc/ircenter.js), under the SOC prefix.
 *   GET  {P}/soc/ir/board               any signed-in user   incidents by phase, KPIs, attention, workload, XDR without a case, metrics
 *   GET  {P}/soc/ir/cases/:id           any signed-in user   one incident: SLA, breach risk, next steps, approvals, clocks, similar past cases
 *   POST {P}/soc/ir/cases/:id/ask       operator             {mode: plan|update, question?} the AI incident commander (a draft; budgeted)  audited
 *   POST {P}/soc/ir/cases/:id/ask/decide operator, a person  {decision: add|discard} - add = a case note in the person's name           audited
 * Owner, status, playbook and approval changes use the existing case routes ({P}/cases/:id/…, {P}/approvals/:id/decide),
 * which validate, check the role and write the audit record themselves. The case list is what GET {P}/cases already shows
 * every signed-in user.
 */
const { createIrCenter } = require('./ircenter');
const { HttpError, wrap, audit, prefixOf } = require('./routeutil');

function register(api, deps) {
  if (!deps.cases || !deps.state) return;
  const P = prefixOf(deps);
  const R = createIrCenter(Object.assign({}, deps, { xdr: () => deps.xdr, forensics: () => deps.forensics }));
  deps.ircenter = R;
  const ID = /^[A-Za-z0-9_.:-]{1,40}$/;
  const idOf = (ctx) => { const id = String(ctx.params.id || ''); if (!ID.test(id)) throw new HttpError(400, 'id is not valid'); return id; };
  const who = (ctx) => ({ user: ctx.user, role: ctx.role });

  api.route('GET', `${P}/soc/ir/board`, wrap(deps, null, (ctx) => ctx.ok(R.board())));
  api.route('GET', `${P}/soc/ir/cases/:id`, wrap(deps, null, (ctx) => ctx.ok(R.incident(idOf(ctx)))));
  api.route('POST', `${P}/soc/ir/cases/:id/ask`, wrap(deps, 'operator', async (ctx) => {
    const id = idOf(ctx), b = body(ctx.body).oneOf('mode', ['plan', 'update'], { required: true }).str('question', { max: 1500 }).done();
    const r = await R.ask(id, b.mode, b.question, who(ctx));
    audit(ctx, 'soc.ir.ask', id, { mode: b.mode, steps: r.steps.length, unverified: r.unverified, tokens: (r.usage.input_tokens || 0) + (r.usage.output_tokens || 0) });
    return ctx.ok(r);
  }));
  api.route('POST', `${P}/soc/ir/cases/:id/ask/decide`, wrap(deps, 'operator', (ctx) => {
    const id = idOf(ctx), b = body(ctx.body).oneOf('decision', ['add', 'discard'], { required: true }).done();
    const r = R.decide(id, b.decision, who(ctx));
    audit(ctx, 'soc.ir.decide', id, { decision: b.decision, mode: r.mode });
    return ctx.ok(r);
  }));
}

module.exports = { register };
