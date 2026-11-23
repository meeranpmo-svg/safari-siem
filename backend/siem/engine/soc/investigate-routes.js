// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const { body } = require('../util/check');
/*
 * Investigations & Cases and Threat Hunting & Search (engine/soc/investigate.js), under the SOC prefix.
 *   GET    {P}/soc/cases/summary            any signed-in user   cases at a glance (SLA, workload, 14-day trend)
 *   GET    {P}/soc/cases/insights           analyst              time-to-close forecast and SLA breach risk, stalled cases,
 *                                                                stage bottleneck, duplicate candidates, suggested owners (case-insights.js)
 *   GET    {P}/soc/cases/:id/workspace      any signed-in user   case + alerts with priority, merged timeline, scope, suggested alerts
 *   POST   {P}/soc/cases/:id/brief          operator             the AI investigation brief (a draft; budgeted)        audited
 *   POST   {P}/soc/cases/:id/brief/decide   operator, a person   {decision: add|discard, note?} - add = a case note in the
 *                                                                person's name                                         audited
 *   GET    {P}/soc/hunt/status              any signed-in user   what hunting can use (event store, AI, fields, hunt library)
 *   GET    {P}/soc/hunt/saved               analyst              the analyst's saved hunts + the team's shared ones
 *   POST   {P}/soc/hunt/saved               analyst              {name, q, hours?, field?, shared?, description?}       audited
 *   DELETE {P}/soc/hunt/saved/:id           analyst              the owner or an administrator                         audited
 *   POST   {P}/soc/hunt/rare                analyst              {q?, field, hours?, limit?}   least frequent values      audited (read)
 *   POST   {P}/soc/hunt/new                 analyst              {q?, field, hours?, baseline_days?, limit?}  first-seen  audited (read)
 *   POST   {P}/soc/hunt/assist              analyst              {question} - the AI proposes queries; a person runs them   audited
 *   POST   {P}/soc/hunt/ml                  analyst              {kinds?: [dga, lineage, fanout]} machine-learning hunts:
 *                                                                DGA-like domains, rare / Office-to-shell process lineage, logon
 *                                                                fan-out (hunt-ml.js) - leads with their features and query  audited (read)
 *   POST   {P}/soc/hunt/entity              analyst              {entity, hours?, limit?} one user / host / IP across every source  audited
 * Raw events are personal data (PDPL): every hunting read is analyst and above and written to the audit trail.
 */
const { createInvestigate, HUNT_FIELDS, RARE_FIELDS } = require('./investigate');
const { HttpError, wrap, audit, prefixOf } = require('./routeutil');

function register(api, deps) {
  if (!deps.alerts || !deps.cases || !deps.state) return;
  const P = prefixOf(deps);
  const I = createInvestigate(deps);
  deps.investigate = I;
  const ID = /^[A-Za-z0-9_.:-]{1,40}$/;
  const idOf = (ctx) => { const id = String(ctx.params.id || ''); if (!ID.test(id)) throw new HttpError(400, 'id is not valid'); return id; };
  const who = (ctx) => ({ user: ctx.user, role: ctx.role });

  api.route('GET', `${P}/soc/cases/summary`, wrap(deps, null, (ctx) => ctx.ok(I.summary())));
  api.route('GET', `${P}/soc/cases/insights`, wrap(deps, 'analyst', (ctx) => ctx.ok(I.insights())));
  api.route('GET', `${P}/soc/cases/:id/workspace`, wrap(deps, null, (ctx) => ctx.ok(I.workspace(idOf(ctx)))));
  api.route('POST', `${P}/soc/cases/:id/brief`, wrap(deps, 'operator', async (ctx) => {
    const id = idOf(ctx), r = await I.brief(id, who(ctx));
    audit(ctx, 'soc.case.brief', id, { unverified: r.unverified, steps: r.steps.length, tokens: (r.usage.input_tokens || 0) + (r.usage.output_tokens || 0) });
    return ctx.ok(r);
  }));
  api.route('POST', `${P}/soc/cases/:id/brief/decide`, wrap(deps, 'operator', (ctx) => {
    const id = idOf(ctx);
    const b = body(ctx.body).oneOf('decision', ['add', 'discard'], { required: true }).str('note', { max: 1000 }).done();
    const r = I.decideBrief(id, b, who(ctx));
    audit(ctx, 'soc.case.brief.decide', id, { decision: b.decision });
    return ctx.ok(r);
  }));

  // entity timeline (entity-timeline.js): one user / host / IP across events, alerts, cases, UEBA, intel, network device and changes
  const ET = require('./entity-timeline').createEntityTimeline(deps);
  api.route('POST', `${P}/soc/hunt/ml`, wrap(deps, 'analyst', async (ctx) => {
    const b = body(ctx.body || {}).list('kinds', { max: 3 }).rule((o) => (o.kinds && o.kinds.some((k) => !['dga', 'lineage', 'fanout'].includes(k)) ? 'kinds must be among: dga, lineage, fanout' : null)).done();
    const r = await I.mlHunts(b);
    audit(ctx, 'soc.hunt.ml', (b.kinds || ['dga', 'lineage', 'fanout']).join(','), { dga: r.dga && r.dga.items ? r.dga.items.length : null, lineage: r.lineage && r.lineage.items ? r.lineage.items.length : null, fanout: r.fanout && r.fanout.items ? r.fanout.items.length : null });
    return ctx.ok(r);
  }));
  api.route('POST', `${P}/soc/hunt/entity`, wrap(deps, 'analyst', async (ctx) => {
    const b = body(ctx.body || {}).str('entity', { required: true, min: 2, max: 200, re: /^[^\u0000-\u001f"<>]+$/, msg: 'entity must be a user, host name or IP address (no quotes or angle brackets)' })
      .int('hours', { min: 1, max: 720, def: 168 }).int('limit', { min: 10, max: 1000, def: 200 }).done();
    const r = await ET.timeline(b); audit(ctx, 'soc.hunt.entity', b.entity, { hours: b.hours, kind: r.kind, records: r.items.length });
    return ctx.ok(r);
  }));
  api.route('GET', `${P}/soc/hunt/status`, wrap(deps, null, (ctx) => ctx.ok(I.huntStatus())));
  api.route('GET', `${P}/soc/hunt/saved`, wrap(deps, 'analyst', (ctx) => ctx.ok({ items: I.savedList(who(ctx)) })));
  api.route('POST', `${P}/soc/hunt/saved`, wrap(deps, 'analyst', (ctx) => {
    const b = body(ctx.body).str('name', { required: true, max: 120 }).str('q', { required: true, max: 4000 }).int('hours', { min: 1, max: 2160 })
      .oneOf('field', HUNT_FIELDS).bool('shared', { def: false }).str('description', { max: 1000 }).done();
    const r = I.save(b, who(ctx));
    audit(ctx, 'soc.hunt.save', r.id, { name: r.name, shared: r.shared });
    return ctx.ok(r);
  }));
  api.route('DELETE', `${P}/soc/hunt/saved/:id`, wrap(deps, 'analyst', (ctx) => {
    const r = I.remove(idOf(ctx), who(ctx));
    audit(ctx, 'soc.hunt.delete', r.removed, { name: r.name, owner: r.owner });
    return ctx.ok(r);
  }));
  const statBody = (ctx, extra) => {
    let v = body(ctx.body).str('q', { max: 4000 }).oneOf('field', RARE_FIELDS, { required: true }).int('hours', { min: 1, max: 720 }).int('limit', { min: 1, max: 200 });
    if (extra) v = v.int('baseline_days', { min: 1, max: 90 });
    return v.done();
  };
  api.route('POST', `${P}/soc/hunt/rare`, wrap(deps, 'analyst', async (ctx) => {
    const b = statBody(ctx, false), r = await I.stat('rare', b);
    audit(ctx, 'soc.hunt.rare', b.field, { q: b.q || '', hours: b.hours || 24, values: r.values.length });
    return ctx.ok(r);
  }));
  api.route('POST', `${P}/soc/hunt/new`, wrap(deps, 'analyst', async (ctx) => {
    const b = statBody(ctx, true), r = await I.stat('new', b);
    audit(ctx, 'soc.hunt.first-seen', b.field, { q: b.q || '', hours: b.hours || 24, baseline_days: r.baseline_days, values: r.values.length });
    return ctx.ok(r);
  }));
  api.route('POST', `${P}/soc/hunt/assist`, wrap(deps, 'analyst', async (ctx) => {
    const b = body(ctx.body).str('question', { required: true, max: 2000 }).done();
    const r = await I.assist(b.question, who(ctx));
    audit(ctx, 'soc.hunt.assist', 'ai', { queries: r.queries.length, dropped: r.dropped.length, steps: r.steps.length });
    return ctx.ok(r);
  }));
}

module.exports = { register };
