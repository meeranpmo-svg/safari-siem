// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const { guard: guardJob } = require('../util/errors');
const { body } = require('../util/check');
/*
 * Security Operations Overview, Alert Queue and the AI SOC analyst (engine/soc/analyst.js), under the SOC prefix.
 *   GET  {P}/soc/overview                 any signed-in user   the SOC at a glance (counts, trends, MTTA / MTTR, top rules,
 *                                                              entities, tactics, XDR, UEBA, AI analyst agreement)
 *   GET  {P}/soc/queue                    any signed-in user   ?status=open|closed|all &label= &min_priority= &severity=
 *                                                              &triage=none|draft|accepted|rejected &assignee= &q= &collapse=1
 *                                                              &sort=-priority|-ts|-severity &limit= &offset=
 *   GET  {P}/soc/overview/insights        analyst              7-day volume forecast, rules new / surging / silent, rule
 *                                                              precision and time to close, entities most at risk now, SLA
 *                                                              attainment per week (overview-insights.js)
 *   GET  {P}/soc/queue/insights           analyst              campaigns across rules (shared entities), backlog flow and
 *                                                              7-day forecast, SLA due / breached, how similar alerts were
 *                                                              closed before (queue-insights.js) - names people and hosts
 *   GET  {P}/soc/triage/:id               any signed-in user   the AI triage draft for one alert (or 404)
 *   POST {P}/soc/triage/:id               operator             run the AI analyst on one alert (budgeted)        audited
 *   POST {P}/soc/triage/:id/decide        operator, a person   {decision: accept|reject, note, close?: true-positive|
 *                                                              false-positive|benign, open_case?}                audited
 *   GET  {P}/soc/analyst/settings         any signed-in user   auto-triage settings and the AI status
 *   PUT  {P}/soc/analyst/settings         admin                {auto, min_severity 2-4, max_per_hour 1-60}       audited
 * The AI never closes, assigns or contains: a person accepts its draft, and a case's containment steps are approval requests
 * that a named approver decides (cases.js).
 */
const { createAnalyst } = require('./analyst');
const { HttpError, wrap, audit, prefixOf } = require('./routeutil');

let TIMER = null;

function register(api, deps) {
  if (!deps.alerts || !deps.state) return;
  const P = prefixOf(deps);
  // watchlist, asset criticality, response times (watchlist.js) - created first: the alert priority reads it
  const WL = deps.watchlist || (deps.watchlist = require('./watchlist').createWatchlist(deps));
  if (!deps.noTimers) WL.start();
  const A = createAnalyst(deps);
  deps.analyst = A;
  const ID = /^[A-Za-z0-9_.:-]{1,40}$/;
  const idOf = (ctx) => { const id = String(ctx.params.id || ''); if (!ID.test(id)) throw new HttpError(400, 'id is not a valid alert id'); return id; };

  api.route('GET', `${P}/soc/overview`, wrap(deps, null, (ctx) => ctx.ok(A.overview(ctx.query || {}))));
  api.route('GET', `${P}/soc/queue`, wrap(deps, null, (ctx) => {
    const q = body(ctx.query || {}).oneOf('status', ['open', 'closed', 'all']).oneOf('label', ['act-now', 'investigate', 'review', 'low', 'likely-noise'])
      .int('min_priority', { min: 0, max: 100 }).str('severity', { max: 20, re: /^[0-4](,[0-4])*$/, msg: 'severity must be a comma list of 0-4' })
      .oneOf('triage', ['none', 'draft', 'accepted', 'rejected']).str('assignee', { max: 120 }).str('q', { max: 200 }).oneOf('collapse', ['0', '1'])
      .oneOf('sort', ['-priority', 'priority', '-ts', 'ts', '-severity', 'severity']).int('limit', { min: 1, max: 500 }).int('offset', { min: 0, max: 100000 }).done();
    if (q.assignee === 'me') q.assignee = ctx.user || '';
    return ctx.ok(A.queue(q));
  }));
  api.route('GET', `${P}/soc/overview/insights`, wrap(deps, 'analyst', (ctx) => ctx.ok(A.overviewInsights())));
  api.route('GET', `${P}/soc/queue/insights`, wrap(deps, 'analyst', (ctx) => ctx.ok(A.insights())));
  api.route('GET', `${P}/soc/triage/:id`, wrap(deps, 'analyst', (ctx) => {   // the AI's reading of an alert names people and hosts: analysts, like the alert itself
    const t = A.getTriage(idOf(ctx)); if (!t) throw new HttpError(404, 'no AI triage for this alert yet');
    return ctx.ok(t);
  }));
  api.route('POST', `${P}/soc/triage/:id`, wrap(deps, 'operator', async (ctx) => {
    const id = idOf(ctx);
    const r = await A.triage(id, { user: ctx.user, role: ctx.role });
    audit(ctx, 'soc.triage', id, { verdict: r.draft.verdict, confidence: r.draft.confidence, unverified: r.unverified, steps: r.steps.length, tokens: (r.usage.input_tokens || 0) + (r.usage.output_tokens || 0) });
    return ctx.ok(r);
  }));
  api.route('POST', `${P}/soc/triage/:id/decide`, wrap(deps, 'operator', (ctx) => {
    const id = idOf(ctx);
    const b = body(ctx.body).oneOf('decision', ['accept', 'reject'], { required: true }).str('note', { max: 1000 })
      .oneOf('close', ['true-positive', 'false-positive', 'benign']).bool('open_case', { def: false })
      .rule((o) => (o.decision === 'reject' && !o.note ? 'note is required: say why the AI triage is wrong (it is how the analyst is measured)' : null))
      .rule((o) => (o.decision === 'reject' && (o.close || o.open_case) ? 'close / open_case go with accept - reject the draft, then work the alert as usual' : null)).done();
    const r = A.decide(id, b, { user: ctx.user, role: ctx.role });
    audit(ctx, 'soc.triage.decide', id, { decision: b.decision, close: b.close || null, case_id: r.case_id, verdict: r.triage.draft.verdict });
    return ctx.ok(r);
  }));
  // ---- SOC Performance & Operations (watchlist.js): watchlist and asset criticality (named systems / people: analyst and above),
  // response times (counts and minutes only: any role)
  const WID = /^(WL|AC)-\d{5}$/;
  const wid = (ctx, p) => { const id = String((ctx.params || {}).id || ''); if (!WID.test(id) || !id.startsWith(p)) throw new HttpError(400, 'id is not a ' + (p === 'WL' ? 'watchlist' : 'criticality') + ' entry'); return id; };
  const VAL = { host: /^[A-Za-z0-9][A-Za-z0-9._-]{0,252}$/, ip: /^[0-9a-fA-F:.]{3,45}$/, user: /^[^\s"<>]{1,200}$/, domain: /^[A-Za-z0-9][A-Za-z0-9.-]{1,252}$/, hash: /^[0-9a-fA-F]{32,128}$/, cve: /^CVE-\d{4}-\d{4,7}$/i };
  api.route('GET', `${P}/soc/performance`, wrap(deps, null, (ctx) => ctx.ok(WL.performance())));
  api.route('GET', `${P}/soc/watchlist`, wrap(deps, 'analyst', (ctx) => ctx.ok({ items: WL.list(), criticality: WL.criticality() })));
  api.route('POST', `${P}/soc/watchlist`, wrap(deps, 'operator', (ctx) => {
    const src = ctx.body || {};
    const b = body(src).oneOf('kind', WL.KINDS, { required: true }).str('value', { required: true, max: 253 }).str('reason', { required: true, min: 3, max: 500 }).int('days', { min: 1, max: 365 })
      .rule((o) => (VAL[o.kind] && !VAL[o.kind].test(o.value) ? 'value is not a valid ' + o.kind : null)).done();
    const r = WL.add(b, { user: ctx.user }); audit(ctx, 'soc.watchlist.add', r.id, { kind: r.kind, value: r.value, until: r.until }); return ctx.ok(r);
  }));
  api.route('POST', `${P}/soc/watchlist/:id/remove`, wrap(deps, 'operator', (ctx) => {
    const id = wid(ctx, 'WL'), b = body(ctx.body || {}).str('reason', { required: true, min: 3, max: 500 }).done();
    const r = WL.remove(id, b.reason, { user: ctx.user }); audit(ctx, 'soc.watchlist.remove', id, { kind: r.kind, value: r.value, reason: b.reason }); return ctx.ok(r);
  }));
  api.route('POST', `${P}/soc/criticality`, wrap(deps, 'admin', (ctx) => {
    const b = body(ctx.body || {}).str('value', { required: true, max: 253, re: /^[A-Za-z0-9][A-Za-z0-9._:-]{0,252}$/, msg: 'value must be a host name or an IP address' }).oneOf('level', WL.LEVELS, { required: true }).str('reason', { required: true, min: 3, max: 500 }).done();
    const r = WL.rate(b, { user: ctx.user }); audit(ctx, 'soc.criticality.rate', r.id, { value: r.value, level: r.level, replaced: r.replaced }); return ctx.ok(r);
  }));
  api.route('POST', `${P}/soc/criticality/:id/remove`, wrap(deps, 'admin', (ctx) => {
    const id = wid(ctx, 'AC'); body(ctx.body || {}).done();
    const r = WL.unrate(id, { user: ctx.user }); audit(ctx, 'soc.criticality.remove', id, { value: r.value, level: r.level }); return ctx.ok(r);
  }));
  api.route('GET', `${P}/soc/analyst/settings`, wrap(deps, null, (ctx) => ctx.ok({ settings: A.settings(), status: A.status() })));
  api.route('PUT', `${P}/soc/analyst/settings`, wrap(deps, 'admin', (ctx) => {
    const b = body(ctx.body).bool('auto').int('min_severity', { min: 2, max: 4 }).int('max_per_hour', { min: 1, max: 60 }).done();
    if (!Object.keys(b).length) throw new HttpError(400, 'nothing to change: send auto, min_severity or max_per_hour');
    const r = A.putSettings(b, ctx.user);
    audit(ctx, 'soc.analyst.settings', 'settings', { changed: r.changed, settings: r.settings });
    return ctx.ok(r);
  }));

  // auto-triage (off unless an administrator switches it on): a self-rescheduling loop that reschedules in finally
  if (TIMER) clearTimeout(TIMER);
  const tick = guardJob('soc.analyst.auto', async () => { try { await A.autoTick(); } finally { TIMER = setTimeout(tick, 120000); if (TIMER.unref) TIMER.unref(); } });
  if (!deps.noTimers) { TIMER = setTimeout(tick, 120000); if (TIMER.unref) TIMER.unref(); }
}

module.exports = { register };
