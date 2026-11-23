// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const ZYB_ORG = require('../util/brand');
/*
 * After-hours mode routes (engine/afterhours/mode.js). Registered after reports/routes.js, which owns the business-hours
 * calendar and the SMTP relay (deps.reports). Runs, briefs and settings name people and hosts, so a viewer gets status only.
 *
 *   GET  {P}/after-hours/mode/status                 any role   → enabled, after hours now, tonight's counts, mail problems
 *   GET  {P}/after-hours/mode/config                 operator   → settings incl. version
 *   POST {P}/after-hours/mode/config                 admin      {enabled?, page?, oncall?, prepare?, brief?, base_version} → settings (409 on a race)
 *   GET  {P}/after-hours/mode/runs                   operator   ?limit → { items[] }
 *   GET  {P}/after-hours/mode/briefs                 operator   → { items[] }
 *   GET  {P}/after-hours/mode/briefs/:day            operator   → brief incl. text + html (the page shows the html in a sandboxed frame)
 *   POST {P}/after-hours/mode/brief-now              admin      {send: false} preview | {send: true} build, store and e-mail
 *   POST {P}/after-hours/mode/test-page              admin      → sends a test page to tonight's recipients
 * Acknowledging is the ordinary POST {P}/alerts/:id/ack: the page's e-mail links to the portal, never to a token URL.
 */
const { createAfterHoursMode } = require('./mode');
const playbooks = require('../soc/playbooks');
const { HttpError, wrap, audit, body, prefixOf } = require('../soc/routeutil');

function register(api, deps) {
  if (!deps.state) return null;
  const P = prefixOf(deps);
  const cfg = deps.config || {};
  const log = deps.log && deps.log.child ? deps.log.child({ mod: 'after-hours-mode' }) : (deps.log || { info() {}, warn() {}, error() {} });
  const rep = deps.reports || {};
  const sched = rep.schedules || null;
  const ah = cfg.afterhours || {};
  const mode = createAfterHoursMode({
    state: deps.state, alerts: deps.alerts, cases: deps.cases, playbooks, log,
    calendar: () => (rep.businessHours ? rep.businessHours.calendar() : null),
    mail: sched ? (m) => sched.mail(m) : null,
    mailProblems: sched ? () => sched.mailProblems() : () => ['report scheduling (SMTP relay) is not running'],
    portalUrl: ah.portal_url || cfg.portal_url || ('https://' + ZYB_ORG.portal_host + '/dashboards'),
  });

  api.route('GET', `${P}/after-hours/mode/status`, wrap(deps, null, (ctx) => ctx.ok(mode.status())));
  api.route('GET', `${P}/after-hours/mode/config`, wrap(deps, 'operator', (ctx) => ctx.ok(mode.config())));
  api.route('POST', `${P}/after-hours/mode/config`, wrap(deps, 'admin', (ctx) => {
    const b = body(ctx); const before = mode.config();
    const patch = {}; for (const k of ['enabled', 'page', 'oncall', 'prepare', 'brief']) if (b[k] !== undefined) patch[k] = b[k];
    const after = mode.save(patch, ctx.user, b.base_version);
    audit(ctx, 'after-hours.mode.save', 'after-hours-mode', {
      version: after.version, enabled: [before.enabled, after.enabled], prepare: [before.prepare.mode, after.prepare.mode],
      page_recipients: after.page.to.length, rota: after.oncall.length, min_severity: after.page.min_severity, brief_at: after.brief.at,
    });
    return ctx.ok(after);
  }));
  api.route('GET', `${P}/after-hours/mode/runs`, wrap(deps, 'operator', (ctx) => ctx.ok({ items: mode.runs((ctx.query || {}).limit) })));
  api.route('GET', `${P}/after-hours/mode/briefs`, wrap(deps, 'operator', (ctx) => ctx.ok({ items: mode.briefs() })));
  api.route('GET', `${P}/after-hours/mode/briefs/:day`, wrap(deps, 'operator', (ctx) => {
    const b = mode.brief(ctx.params.day); if (!b) throw new HttpError(404, 'no brief for that day');
    return ctx.ok(b);
  }));
  api.route('POST', `${P}/after-hours/mode/brief-now`, wrap(deps, 'admin', async (ctx) => {
    const b = body(ctx);
    if (b.send !== true) return ctx.ok(mode.makeBrief());
    const r = await mode.sendBrief(ctx.user);
    audit(ctx, 'after-hours.brief.send-now', r.id, { status: r.sent && r.sent.status });
    return ctx.ok(r);
  }));
  api.route('POST', `${P}/after-hours/mode/test-page`, wrap(deps, 'admin', async (ctx) => {
    let r;
    try { r = await mode.testPage(ctx.user); } catch (e) { if (e.code) throw e; throw new HttpError(502, `test page failed: ${e.stage ? e.stage + ': ' : ''}${String(e.message).slice(0, 200)}`); }
    audit(ctx, 'after-hours.test-page', 'after-hours-mode', { recipients: r.recipients });
    return ctx.ok(r);
  }));

  if (!(ah.scheduler === false)) mode.start(Number(ah.tick_ms) || 30000);
  deps.afterHoursMode = mode;
  return mode;
}

module.exports = { register };
