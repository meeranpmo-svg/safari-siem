// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const { body } = require('../util/check');
/*
 * Insider Risk (engine/soc/insider.js), under the SOC prefix. The programme names people's behaviour (PDPL): operators and
 * administrators only - viewers and analysts are refused; people are pseudonymised; a name is shown only inside an authorised case.
 *   GET  {P}/soc/insider                        operator  pseudonymised people, departments, watchlist, cases, KPIs
 *   GET  {P}/soc/insider/people/:p              operator  one pseudonymised person: indicators, context, cases
 *   POST {P}/soc/insider/watch                  operator  {user, context, until, last_day?, reason}                     audited
 *   POST {P}/soc/insider/watch/:id/decide       admin     {decision: approve|reject, note?} - not the requester        audited
 *   POST {P}/soc/insider/cases                  operator  {pseudonym, basis, reason}                                    audited
 *   POST {P}/soc/insider/cases/:id/decide       admin     {decision: authorise|reject, note?} - not the requester      audited
 *   GET  {P}/soc/insider/cases/:id/subject      operator  the name - authorised case, case team only                    audited
 *   POST {P}/soc/insider/cases/:id/note         operator  {text} - case team                                            audited
 *   POST {P}/soc/insider/cases/:id/close        operator  {outcome, note} - case team                                   audited
 *   POST {P}/soc/insider/people/:p/ask          operator  {question?} the AI insider-risk analyst (pseudonyms only)    audited
 */
const { createInsider, BASES, OUTCOMES, CONTEXTS } = require('./insider');
const { HttpError, wrap, audit, prefixOf } = require('./routeutil');

function register(api, deps) {
  if (!deps.state) return;
  const P = prefixOf(deps);
  const X = createInsider(Object.assign({}, deps, { dlp: deps.dlp ? (deps.dlp.api || deps.dlp) : null }));
  deps.insider = X;
  const ID = /^[A-Za-z0-9_.:-]{1,40}$/, PS = /^P-[0-9a-f]{8}$/;
  const idOf = (ctx) => { const id = String(ctx.params.id || ''); if (!ID.test(id)) throw new HttpError(400, 'id is not valid'); return id; };
  const pOf = (ctx) => { const p = String(ctx.params.p || ''); if (!PS.test(p)) throw new HttpError(400, 'pseudonym must look like P-1a2b3c4d'); return p; };
  const who = (ctx) => ({ user: ctx.user, role: ctx.role });
  const day = (k) => ({ re: /^\d{4}-\d{2}-\d{2}$/, msg: k + ' must be a date (YYYY-MM-DD)' });

  api.route('GET', `${P}/soc/insider`, wrap(deps, 'operator', async (ctx) => ctx.ok(await X.view())));
  api.route('GET', `${P}/soc/insider/people/:p`, wrap(deps, 'operator', async (ctx) => ctx.ok(await X.person(pOf(ctx)))));
  api.route('POST', `${P}/soc/insider/watch`, wrap(deps, 'operator', (ctx) => {
    const b = body(ctx.body).str('user', { required: true, max: 120, re: /^[A-Za-z0-9._@\\-]{2,120}$/, msg: 'user must be a sign-in name' }).oneOf('context', CONTEXTS, { required: true })
      .str('until', Object.assign({ required: true }, day('until'))).str('last_day', day('last_day')).str('reason', { required: true, min: 10, max: 1000 }).done();
    const r = X.watchAdd(b, who(ctx)); audit(ctx, 'insider.watch.request', r.id, { pseudonym: r.pseudonym, context: b.context, until: b.until }); return ctx.ok(r);
  }));
  api.route('POST', `${P}/soc/insider/watch/:id/decide`, wrap(deps, 'admin', (ctx) => {
    const id = idOf(ctx), b = body(ctx.body).oneOf('decision', ['approve', 'reject'], { required: true }).str('note', { max: 1000 }).rule((o) => (o.decision === 'reject' && !o.note ? 'note is required: say why it is rejected' : null)).done();
    const r = X.watchDecide(id, b, who(ctx)); audit(ctx, 'insider.watch.' + b.decision, id, { pseudonym: r.pseudonym }); return ctx.ok(r);
  }));
  api.route('POST', `${P}/soc/insider/cases`, wrap(deps, 'operator', async (ctx) => {
    const b = body(ctx.body).str('pseudonym', { required: true, max: 12, re: PS, msg: 'pseudonym must look like P-1a2b3c4d' }).oneOf('basis', BASES, { required: true }).str('reason', { required: true, min: 20, max: 2000 }).done();
    const r = await X.caseOpen(b, who(ctx)); audit(ctx, 'insider.case.request', r.id, { pseudonym: b.pseudonym, basis: b.basis }); return ctx.ok(r);
  }));
  api.route('POST', `${P}/soc/insider/cases/:id/decide`, wrap(deps, 'admin', (ctx) => {
    const id = idOf(ctx), b = body(ctx.body).oneOf('decision', ['authorise', 'reject'], { required: true }).str('note', { max: 1000 }).rule((o) => (o.decision === 'reject' && !o.note ? 'note is required: say why it is rejected' : null)).done();
    const r = X.caseDecide(id, b, who(ctx)); audit(ctx, 'insider.case.' + b.decision, id, { pseudonym: r.pseudonym }); return ctx.ok(r);
  }));
  api.route('GET', `${P}/soc/insider/cases/:id/subject`, wrap(deps, 'operator', (ctx) => {
    const id = idOf(ctx), r = X.caseSubject(id, who(ctx)); audit(ctx, 'insider.case.reveal', id, { pseudonym: r.pseudonym }); return ctx.ok(r);   // who looked at a name, never the name itself
  }));
  api.route('POST', `${P}/soc/insider/cases/:id/note`, wrap(deps, 'operator', (ctx) => {
    const id = idOf(ctx), b = body(ctx.body).str('text', { required: true, min: 3, max: 4000 }).done();
    const r = X.caseNote(id, b, who(ctx)); audit(ctx, 'insider.case.note', id, { chars: b.text.length }); return ctx.ok(r);
  }));
  api.route('POST', `${P}/soc/insider/cases/:id/close`, wrap(deps, 'operator', (ctx) => {
    const id = idOf(ctx), b = body(ctx.body).oneOf('outcome', OUTCOMES, { required: true }).str('note', { required: true, min: 10, max: 2000 }).done();
    const r = X.caseClose(id, b, who(ctx)); audit(ctx, 'insider.case.close', id, { outcome: b.outcome }); return ctx.ok(r);
  }));
  api.route('POST', `${P}/soc/insider/people/:p/ask`, wrap(deps, 'operator', async (ctx) => {
    const p = pOf(ctx), b = body(ctx.body).str('question', { max: 1500 }).done();
    const r = await X.ask(p, b.question, who(ctx)); audit(ctx, 'insider.ask', p, { steps: r.steps.length, unverified: r.unverified, recommendation: r.recommendation }); return ctx.ok(r);
  }));
}

module.exports = { register };
