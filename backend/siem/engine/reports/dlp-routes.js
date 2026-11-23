// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const ZYB_ORG = require('../util/brand');
const { guard: guardJob } = require('../util/errors');
/*
 * DLP analysis routes (engine/reports/dlp.js). Registered after reports/routes.js (business-hours calendar + SMTP relay).
 * DLP incidents name employees and files: PDPL personal data. A viewer gets totals, channels, policies and data classes
 * only - no person, device, destination or file. Every download, export and e-mail is written to the audit log.
 *
 *   GET  {P}/dlp/summary          ?period|from&to           any role (names only for operator / admin)
 *   GET  {P}/dlp/events           ?…&user&host&policy&channel&class&left=1&limit   operator → { items[] }
 *   GET  {P}/dlp/events.csv       same filters, ≤ 5000 rows                         operator (audited)
 *   GET  {P}/dlp/report.html      ?period|from&to&download=1                        operator (audited)
 *   GET  {P}/dlp/schedule         admin → { schedule, last, next_at, mail }
 *   POST {P}/dlp/schedule         admin { enabled, period: weekly|monthly, at, weekday, day_of_month, recipients[] }
 *   POST {P}/dlp/send-now         admin { period?: 7d|30d } → e-mails the report to the schedule's recipients now
 */
const { createDlp } = require('./dlp');
const { nextRun, reportPeriod, normSchedule } = require('./schedule');
const { HttpError, wrap, audit, body, prefixOf } = require('../soc/routeutil');

const RANK = { viewer: 0, analyst: 1, operator: 2, admin: 3 };
const atLeast = (ctx, r) => (RANK[String(ctx.role || '').toLowerCase()] || 0) >= RANK[r];

function register(api, deps) {
  const P = prefixOf(deps);
  const cfg = deps.config || {};
  const log = deps.log && deps.log.child ? deps.log.child({ mod: 'dlp' }) : (deps.log || { info() {}, warn() {}, error() {} });
  const rep = deps.reports || {};
  const now = deps.now || Date.now;
  const org = (cfg.reports && cfg.reports.org_name) || ZYB_ORG.short;
  const dlp = createDlp({ ch: deps.ch, config: cfg, log, now, calendar: () => (rep.businessHours ? rep.businessHours.calendar() : null) });
  const col = deps.state ? deps.state.collection('dlp_settings') : null;
  const off = () => { const c = rep.businessHours && rep.businessHours.calendar(); return (c && c.config && c.config.utc_offset_min) || 180; };
  // raw responses the same way reports/routes.js sends the Attack Summary (CSP: no script can run in the report)
  const sendRaw = (ctx, type, text, name, download, fallback) => {
    const res = ctx.res;
    if (!res || typeof res.writeHead !== 'function') return ctx.ok(fallback);
    ctx.sent = true; const buf = Buffer.from(text, 'utf8');
    res.writeHead(200, { 'Content-Type': type, 'Content-Length': buf.length, 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff',
      'Content-Security-Policy': "default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'; frame-ancestors 'self'",
      'Content-Disposition': `${download ? 'attachment' : 'inline'}; filename="${name}"` });
    res.end(buf); return undefined;
  };
  api.route('GET', `${P}/dlp/summary`, wrap(deps, null, async (ctx) => ctx.ok(await dlp.summary(ctx.query || {}, { names: atLeast(ctx, 'operator') }))));
  api.route('GET', `${P}/dlp/events`, wrap(deps, 'operator', async (ctx) => {
    const q = ctx.query || {}; const r = await dlp.events(q);
    audit(ctx, 'dlp.events.view', q.user || q.host || 'dlp', { rows: r.items.length, user: q.user || '', host: q.host || '' });
    return ctx.ok(r);
  }));
  api.route('GET', `${P}/dlp/events.csv`, wrap(deps, 'operator', async (ctx) => {
    const q = ctx.query || {}; const r = await dlp.csv(q);
    audit(ctx, 'dlp.events.export', q.user || q.host || 'dlp', { rows: r.rows });
    return sendRaw(ctx, 'text/csv; charset=utf-8', '\ufeff' + r.text, `dlp-incidents-${new Date().toISOString().slice(0, 10)}.csv`, true, { csv: r.text, rows: r.rows });
  }));
  api.route('GET', `${P}/dlp/report.html`, wrap(deps, 'operator', async (ctx) => {
    const q = ctx.query || {}; const r = await dlp.report(q, { org, by: ctx.user });
    audit(ctx, 'dlp.report.download', r.summary.period.label, { from: r.summary.period.from, to: r.summary.period.to, incidents: (r.summary.totals || {}).incidents || 0 });
    return sendRaw(ctx, 'text/html; charset=utf-8', r.html, `dlp-report-${new Date().toISOString().slice(0, 10)}.html`, q.download === '1', { html: r.html, subject: r.subject });
  }));

  // ---------------- scheduled report (weekly / monthly), e-mailed through the Attack Summary relay
  function sched() { const d = col && col.get('schedule'); return d || { id: 'schedule', schedule: null, last: null, next_at: null }; }
  async function deliver(period, reason, by) {
    const d = sched(); const s = d.schedule;
    const to = s && s.recipients ? s.recipients : [];
    const last = { at: now(), reason, by: by || 'scheduler', status: 'failed', error: '', recipients: to.length };
    try {
      if (!to.length) throw new Error('no recipients - set them in the DLP report schedule');
      if (!rep.schedules || typeof rep.schedules.mail !== 'function') throw new Error('the SMTP relay (Reports) is not running');
      const r = await dlp.report(period, { org, by: by || 'scheduler' });
      const day = new Date(now() + off() * 60000).toISOString().slice(0, 10);
      await rep.schedules.mail({ to, subject: r.subject, text: r.text, html: r.html, attachments: [{ filename: `dlp-report-${day}.html`, content: r.html, contentType: 'text/html; charset=utf-8' }] });
      Object.assign(last, { status: 'ok', incidents: (r.summary.totals || {}).incidents || 0 });
    } catch (e) { last.error = `${e.stage ? e.stage + ': ' : ''}${String(e.message).slice(0, 240)}`; log.warn('dlp report delivery failed', { reason, stage: e.stage || '' }); }
    if (col) col.put(Object.assign({}, sched(), { last }));
    if (deps.state && typeof deps.state.audit === 'function') { try { deps.state.audit({ at: now(), user: by || 'system:dlp-report', action: 'dlp.report.send', target: reason, detail: { status: last.status, recipients: to.length } }); } catch (e) { /* audit must not stop delivery */ } }
    return last;
  }
  let timer = null; let busy = false;
  async function tick() {
    if (busy || !col) return; const d = sched(); const s = d.schedule;
    if (!s || !s.enabled) return;
    const due = d.next_at || nextRun(s, now() - 60000, off());
    if (!due || now() < due) { if (!d.next_at && due) col.put(Object.assign({}, d, { next_at: due })); return; }
    busy = true;
    try {
      const per = reportPeriod(s, due, off());
      await deliver({ from: per.from, to: per.to }, `scheduled-${s.period}`, 'scheduler');
      col.put(Object.assign({}, sched(), { next_at: nextRun(s, Math.max(due, now()), off()) }));
    } finally { busy = false; }
  }
  api.route('GET', `${P}/dlp/schedule`, wrap(deps, 'admin', (ctx) => {
    const d = sched(); let mail = [];
    try { mail = rep.schedules && rep.schedules.mailProblems ? rep.schedules.mailProblems() : ['the SMTP relay (Reports) is not running']; } catch (e) { mail = [e.message]; }
    return ctx.ok({ schedule: d.schedule, last: d.last, next_at: d.schedule && d.schedule.enabled ? d.next_at || nextRun(d.schedule, now(), off()) : null, mail: { ok: !mail.length, problems: mail } });
  }));
  api.route('POST', `${P}/dlp/schedule`, wrap(deps, 'admin', (ctx) => {
    if (!col) throw new HttpError(503, 'the DLP report schedule needs the engine state store');
    const b = body(ctx);
    if (!['weekly', 'monthly'].includes(b.period)) throw new HttpError(400, 'period must be weekly or monthly');
    const { s, errs } = normSchedule(Object.assign({}, b, { id: 'dlp', name: 'DLP report', lang: 'en' }), 0);
    if (errs.length) throw new HttpError(400, errs[0].replace('schedules[0]', 'schedule'), errs.map((e) => e.replace('schedules[0]', 'schedule')));
    col.put(Object.assign({}, sched(), { schedule: s, next_at: s.enabled ? nextRun(s, now(), off()) : null, updated: now(), by: ctx.user }));
    audit(ctx, 'dlp.schedule.save', 'dlp-report', { enabled: s.enabled, period: s.period, at: s.at, recipients: s.recipients.length });
    return ctx.ok(Object.assign({}, sched()));
  }));
  api.route('POST', `${P}/dlp/send-now`, wrap(deps, 'admin', async (ctx) => {
    const b = body(ctx); const label = b.period === '7d' ? '7d' : '30d';
    const last = await deliver({ period: label }, `send-now-${label}`, ctx.user);
    audit(ctx, 'dlp.report.send-now', label, { status: last.status, recipients: last.recipients });
    if (last.status !== 'ok') throw new HttpError(502, `not sent: ${last.error}`);
    return ctx.ok(last);
  }));

  if (col && !(cfg.dlp && cfg.dlp.scheduler === false)) { timer = setInterval(guardJob('reports.dlp-routes.tick', () => tick()), 60000); if (timer.unref) timer.unref(); }
  deps.dlp = { api: dlp, tick, stop() { if (timer) clearInterval(timer); timer = null; } };
  return deps.dlp;
}

module.exports = { register };
