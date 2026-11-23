// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Reports API — Attack Summary (dashboard JSON, printable HTML, scheduled e-mail) and After-hours activity monitoring.
 * register(api, deps) (deps as for soc/routes.js; detect/routes.js must be registered first for deps.ruleAdmin).
 * {P} = config.api_prefix || '/api/soc'. Same proxy-secret + portal-session auth as every SOC route.
 * Reads: any authenticated user (viewer). Schedules / SMTP / history / settings / alerting toggles: admin. Writes audited.
 *
 * Attack Summary
 *   GET  {P}/reports/attack-summary            ?period=24h|7d|30d | from=&to= (ISO or epoch ms, ≤ 400 days) &refresh=1 → report JSON
 *                                              (shape: engine/reports/attack-summary.js)
 *   GET  {P}/reports/attack-summary.html       same query + lang=en|ar &download=1 → self-contained printable HTML (RTL for ar)
 *   GET  {P}/reports/schedules                 admin → { schedules[{…, next_at}], smtp{…, password_set, password_set_at, password_set_by},
 *                                              problems[], history[], timezone, utc_offset_min, retry_ms[] }   (never the password)
 *   POST {P}/reports/schedules                 admin { schedules?: [{id?, name, period: daily|weekly|monthly, at: 'HH:MM', weekday?,
 *                                              day_of_month?, recipients[], lang: en|ar, enabled}] (full replace),
 *                                              smtp?: {host, port, tls, starttls, user, from, from_name, ca_file, reject_unauthorized,
 *                                              timeout_ms, helo, allow_insecure_auth, password? (write-only), clear_password?} } → same as GET
 *   POST {P}/reports/schedules/:id/send-now    admin → the run {id, status ok|failed|retrying|running, attempts, error, …}
 *                                              (answers after the first attempt or 45 s; retries continue in the engine)
 *   POST {P}/reports/smtp/test                 admin → { ok, tls, auth, stages[], error?, stage? }  (connect, EHLO, STARTTLS, AUTH, QUIT; no mail)
 *   GET  {P}/reports/history                   admin ?limit= → { items[] }
 * After-hours
 *   GET  {P}/after-hours/summary               ?period|from&to → engine/reports/after-hours.js summary
 *   GET  {P}/after-hours/events                ?period|from&to &user= &host= &group=logon|admin|file &limit= → { items[] } (drill-down)
 *   GET  {P}/after-hours/settings              → { business_hours, mass_download_threshold, defaults, sites[], effective }
 *   POST {P}/after-hours/settings              admin { business_hours?: {days, start, end, holidays, sites, utc_offset_min}, mass_download_threshold? }
 *   GET  {P}/after-hours/alerting              → { items[{id, kind, title, available, enabled, severity, uses_business_hours, alerts_7d}] }
 *   POST {P}/after-hours/alerting              admin { id, enabled } → item (rule toggles = ordinary rule overrides)
 */
const { createAttackSummary } = require('./attack-summary');
const { renderHtml, renderText, subjectOf } = require('./attack-summary-html');
const { createReportSchedules } = require('./schedule');
const { createAfterHours } = require('./after-hours');
const smtp = require('./smtp');
const { createBusinessHoursStore } = require('../util/business-hours');
const { HttpError, wrap, audit, body, prefixOf } = require('../soc/routeutil');
const { body: vbody } = require('../util/check');   // validation at the boundary (routeutil's body() only reads ctx.body)

function sendHtml(ctx, html, download, name) {
  const res = ctx.res;
  if (!res || typeof res.writeHead !== 'function') return ctx.ok({ content_type: 'text/html', html, filename: name });
  ctx.sent = true;
  const buf = Buffer.from(html, 'utf8');
  res.writeHead(200, {
    'Content-Type': 'text/html; charset=utf-8', 'Content-Length': buf.length, 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff',
    'Content-Security-Policy': "default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'; frame-ancestors 'self'",
    'Content-Disposition': `${download ? 'attachment' : 'inline'}; filename="${name}"`,
  });
  res.end(buf);
  return undefined;
}

function register(api, deps) {
  const P = prefixOf(deps);
  const cfg = deps.config || {};
  const log = deps.log && deps.log.child ? deps.log.child({ mod: 'reports' }) : (deps.log || { info() {}, warn() {}, error() {} });
  const org = (cfg.reports && cfg.reports.org_name) || '';
  const rules = () => (deps.ruleAdmin ? deps.ruleAdmin.list() : deps.detector && typeof deps.detector.rules === 'function' ? deps.detector.rules() : []);

  const businessHours = (deps.reports && deps.reports.businessHours) || createBusinessHoursStore({ state: deps.state, config: cfg, log });
  const attack = createAttackSummary({ ch: deps.ch, alerts: deps.alerts, cases: deps.cases, rules, config: cfg, log });
  const summaryFor = async (q) => {
    const rep = await attack.summary(q);
    return q.label && q.label !== rep.period.label ? Object.assign({}, rep, { period: Object.assign({}, rep.period, { label: q.label }) }) : rep;
  };
  const schedules = deps.state ? createReportSchedules({
    state: deps.state, config: cfg, log,
    summary: summaryFor,
    render: (rep, o) => ({ html: renderHtml(rep, { lang: o.lang, org }), text: renderText(rep, { lang: o.lang, org }), subject: subjectOf(rep, { lang: o.lang, period: o.period, org }) }),
    send: (s, msg) => smtp.sendMail(s, msg),
  }) : null;
  const afterHours = createAfterHours({ ch: deps.ch, state: deps.state, config: cfg, log, store: businessHours, ruleAdmin: () => deps.ruleAdmin, ueba: deps.ueba, alerts: deps.alerts, detector: deps.detector });
  const needSched = () => { if (!schedules) throw new HttpError(503, 'report scheduling needs the engine state store'); return schedules; };

  // ---------------- Attack Summary
  api.route('GET', `${P}/reports/attack-summary`, wrap(deps, null, async (ctx) => ctx.ok(await attack.summary(ctx.query || {}))));
  api.route('GET', `${P}/reports/attack-summary.html`, wrap(deps, null, async (ctx) => {
    const q = ctx.query || {};
    const lang = q.lang === 'ar' ? 'ar' : 'en';
    const rep = await attack.summary(q);
    const off = rep.period.utc_offset_min || 180;
    const day = new Date(rep.period.to - 1 + off * 60000).toISOString().slice(0, 10);
    audit(ctx, 'report.attack-summary.download', rep.period.label, { from: rep.period.from, to: rep.period.to, lang, ok: rep.clickhouse.ok });
    return sendHtml(ctx, renderHtml(rep, { lang, org, generatedBy: ctx.user }), q.download === '1', `attack-summary-${day}${lang === 'ar' ? '-ar' : ''}.html`);
  }));

  api.route('GET', `${P}/reports/schedules`, wrap(deps, 'admin', (ctx) => ctx.ok(needSched().view())));
  api.route('POST', `${P}/reports/schedules`, wrap(deps, 'admin', (ctx) => {
    const b = body(ctx);
    const before = needSched().view();
    const r = schedules.save(b, ctx.user);
    const changedSmtp = b.smtp && typeof b.smtp === 'object' ? Object.keys(b.smtp).filter((k) => k !== 'password' && k !== 'clear_password' && JSON.stringify(before.smtp[k]) !== JSON.stringify(r.view.smtp[k])) : [];
    audit(ctx, 'report.schedules.save', 'attack-summary', {
      schedules: r.view.schedules.map((s) => ({ id: s.id, period: s.period, at: s.at, enabled: s.enabled, recipients: s.recipients.length, lang: s.lang })),
      smtp_changed: changedSmtp, smtp_host: r.view.smtp.host, password: r.password_changed, // never the password or addresses
    });
    return ctx.ok(r.view);
  }));
  api.route('POST', `${P}/reports/schedules/:id/send-now`, wrap(deps, 'admin', async (ctx) => {
    const id = String(ctx.params.id || '');
    const p = needSched().sendNow(id, ctx.user);
    audit(ctx, 'report.schedules.send-now', id, {});
    let timer;
    const first = await Promise.race([p, new Promise((r) => { timer = setTimeout(() => r(null), 45000); if (timer.unref) timer.unref(); })]);
    clearTimeout(timer);
    if (first) return ctx.ok(first);
    const h = schedules.history(20).find((x) => x.schedule_id === id && x.reason === 'send-now');
    return ctx.ok(h ? Object.assign({}, h, { status: h.status === 'running' ? 'running' : h.status }) : { status: 'running', schedule_id: id });
  }));
  api.route('POST', `${P}/reports/smtp/test`, wrap(deps, 'admin', async (ctx) => {
    const s = needSched();
    const conf = Object.assign({}, s.smtpSettings(), { password: (cfg.secrets && cfg.secrets.reports && cfg.secrets.reports.smtp_password) || '' });
    let out;
    try { const r = await smtp.verify(conf); out = { ok: true, tls: r.tls, auth: r.auth, stages: r.stages }; } catch (e) { out = { ok: false, error: String(e.message).slice(0, 300), stage: e.stage || '', code: e.code || 0 }; }
    audit(ctx, 'report.smtp.test', conf.host || '-', { ok: out.ok, stage: out.stage || '', error: out.error || '' });
    return ctx.ok(out);
  }));
  api.route('GET', `${P}/reports/history`, wrap(deps, 'admin', (ctx) => ctx.ok({ items: needSched().history((ctx.query || {}).limit) })));

  // ---------------- the same relay for IT Asset Management's Reporting Center and Notification centre (one SMTP setting, here)
  // Only the named platform services may send; a person uses the pages, which call these services. Recipients are counted in the
  // audit, never listed (PDPL). Attachments: CSV / HTML only, small.
  const RELAY_CALLERS = new Set(['system:itam-report-center', 'system:itam-notify']);
  const ADDR = /^[^\s@<>"',;]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,}$/;
  api.route('GET', `${P}/reports/relay`, wrap(deps, 'admin', (ctx) => {
    const s = schedules; const p = s ? s.mailProblems() : ['report scheduling needs the engine state store'];
    return ctx.ok({ ok: !p.length, problems: p });
  }));
  api.route('POST', `${P}/reports/deliver`, wrap(deps, 'admin', async (ctx) => {
    if (!RELAY_CALLERS.has(String(ctx.user || ''))) throw new HttpError(403, 'only the IT Asset Management Reporting Center or Notification centre sends through this relay');
    const b = vbody(ctx.body).str('id', { required: true, max: 80, re: /^[A-Za-z0-9_.:-]+$/, msg: 'id has an invalid format' }).str('subject', { required: true, max: 200 })
      .str('text', { required: true, max: 200000 }).str('html', { max: 1500000 }).list('recipients', { required: true, max: 50, item: 'str', itemMax: 254, unique: true })
      .list('attachments', { max: 3 }).done();
    const to = b.recipients.map((x) => x.toLowerCase()); const badA = to.find((x) => !ADDR.test(x));
    if (badA) throw new HttpError(400, `recipients: "${badA.slice(0, 60)}" is not an e-mail address`);
    const att = (b.attachments || []).map((a, i) => {
      if (!a || typeof a !== 'object' || Array.isArray(a)) throw new HttpError(400, `attachments[${i}] must be an object {filename, content, contentType}`);
      const fn = String(a.filename || ''), ct = String(a.contentType || ''), c = a.content;
      if (!/^[A-Za-z0-9 ._-]{1,100}\.(csv|html)$/.test(fn)) throw new HttpError(400, `attachments[${i}].filename must be a .csv or .html file name`);
      if (!['text/csv', 'text/html'].includes(ct)) throw new HttpError(400, `attachments[${i}].contentType must be text/csv or text/html`);
      if (typeof c !== 'string' || c.length > 2000000) throw new HttpError(400, `attachments[${i}].content must be text up to 2 MB`);
      return { filename: fn, content: c, contentType: ct + '; charset=utf-8' };
    });
    const s = needSched();
    try {
      const r = await s.mail({ to, subject: b.subject.replace(/[\r\n]+/g, ' '), text: b.text, html: b.html || undefined, attachments: att });
      audit(ctx, 'report.relay.deliver', b.id, { recipients: to.length, attachments: att.length, ok: true });
      return ctx.ok({ ok: true, id: b.id, accepted: (r && r.accepted ? r.accepted.length : to.length), rejected: (r && r.rejected ? r.rejected.length : 0) });
    } catch (e) {
      audit(ctx, 'report.relay.deliver', b.id, { recipients: to.length, ok: false, stage: e.stage || '' });
      throw new HttpError(e.stage === 'config' ? 424 : 502, 'the e-mail relay did not send it: ' + String(e.message || 'error').slice(0, 300));
    }
  }));

  // ---------------- After-hours
  api.route('GET', `${P}/after-hours/summary`, wrap(deps, null, async (ctx) => ctx.ok(await afterHours.summary(ctx.query || {}))));
  api.route('GET', `${P}/after-hours/events`, wrap(deps, null, async (ctx) => ctx.ok(await afterHours.events(ctx.query || {}))));
  api.route('GET', `${P}/after-hours/settings`, wrap(deps, null, (ctx) => ctx.ok(afterHours.settings())));
  api.route('POST', `${P}/after-hours/settings`, wrap(deps, 'admin', (ctx) => {
    const b = body(ctx);
    const before = afterHours.settings();
    const after = afterHours.setSettings(b, ctx.user);
    const bh = (s) => ({ days: s.business_hours.days, start: s.business_hours.start, end: s.business_hours.end, holidays: s.business_hours.holidays.length, sites: Object.keys(s.business_hours.sites), mass_download_threshold: s.mass_download_threshold });
    audit(ctx, 'after-hours.settings', 'business-hours', { from: bh(before), to: bh(after) });
    return ctx.ok(after);
  }));
  api.route('GET', `${P}/after-hours/alerting`, wrap(deps, null, (ctx) => ctx.ok({ items: afterHours.alerting() })));
  api.route('POST', `${P}/after-hours/alerting`, wrap(deps, 'admin', (ctx) => {
    const b = body(ctx);
    if (typeof b.id !== 'string' || !b.id) throw new HttpError(400, 'id required');
    const item = afterHours.setAlerting(b.id, b.enabled, ctx.user);
    audit(ctx, b.enabled ? 'after-hours.alerting.enable' : 'after-hours.alerting.disable', b.id, { enabled: b.enabled });
    return ctx.ok(item);
  }));

  if (schedules && !(cfg.reports && cfg.reports.scheduler === false)) schedules.start();
  deps.reports = { attackSummary: attack, schedules, afterHours, businessHours };
  return deps.reports;
}

module.exports = { register };
