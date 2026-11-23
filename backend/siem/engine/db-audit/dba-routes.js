// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const ZYB_ORG = require('../util/brand');
/*
 * DBA alert center routes (engine/db-audit/dba-alerts.js). Registered after reports/routes.js (calendar + SMTP relay).
 * Reading is open to every signed-in role (database health is not personal data). Changing what alerts - thresholds,
 * notifications, snoozes, maintenance windows - needs an administrator or the human DBA approver (scope eng:dba, set in
 * IT Asset Management → Roles & Functions); acknowledging needs an operator. Every change is in the audit log.
 *
 *   GET  {P}/db/dba/intel (viewer) · POST {P}/db/dba/intel/ask (operator) - database intelligence, see dba-intel.js
 *   GET  {P}/db/dba/status | conditions?status=open|cleared|all&instance= | errors | thresholds | catalog | notify
 *   POST {P}/db/dba/thresholds      {metrics?, overrides?, errors?, reason, base_version}     admin | DBA
 *   POST {P}/db/dba/notify          {recipients?, warn_mode?, renotify_h?, recovery?, digest?}  admin | DBA
 *   POST {P}/db/dba/conditions/ack  {id, note?}                                               operator
 *   POST {P}/db/dba/conditions/snooze {id, hours, reason}  ·  /unsnooze {id}                   admin | DBA
 *   POST {P}/db/dba/maintenance     {instance, hours, reason}  ·  /maintenance/end {instance}  admin | DBA
 *   POST {P}/db/dba/evaluate (operator: run now) · /digest {send: false|true} (admin | DBA) · /test-mail (admin | DBA)
 * Condition ids contain '|' and '@', so they travel in the body, not the path.
 */
const { createDbaAlerts } = require('./dba-alerts');
const { HttpError, wrap, audit, body, prefixOf } = require('../soc/routeutil');

const DBA = 'approve:eng:dba';

function register(api, deps) {
  if (!deps.state) return null;
  const P = prefixOf(deps);
  const cfg = deps.config || {};
  const log = deps.log && deps.log.child ? deps.log.child({ mod: 'dba-alerts' }) : (deps.log || { info() {}, warn() {}, error() {} });
  const rep = deps.reports || {};
  const sched = rep.schedules || null;
  const D = createDbaAlerts({
    ch: deps.ch, state: deps.state, log, now: deps.now,
    table: `${(cfg.clickhouse && cfg.clickhouse.database) || 'siem'}.events`,
    calendar: () => (rep.businessHours ? rep.businessHours.calendar() : null),
    mail: sched ? (m) => sched.mail(m) : null,
    mailProblems: sched ? () => sched.mailProblems() : () => ['the SMTP relay (Reports) is not running'],
    portalUrl: (cfg.dba && cfg.dba.portal_url) || (cfg.afterhours && cfg.afterhours.portal_url) || cfg.portal_url || ('https://' + ZYB_ORG.portal_host + '/dashboards'),
  });
  const needId = (b) => { if (typeof b.id !== 'string' || !b.id || b.id.length > 300) throw new HttpError(400, 'id required'); return b.id; };

  // Database intelligence (dba-intel.js): health index, capacity runway, problems learned from 30 days, unusual instances, worklist, AI DBA advisor
  require('./dba-intel').register(api, deps, D, P);
  api.route('GET', `${P}/db/dba/status`, wrap(deps, null, (ctx) => ctx.ok(D.status())));
  api.route('GET', `${P}/db/dba/conditions`, wrap(deps, null, (ctx) => ctx.ok({ items: D.conditions(ctx.query || {}) })));
  api.route('GET', `${P}/db/dba/errors`, wrap(deps, null, (ctx) => ctx.ok(D.errors())));
  api.route('GET', `${P}/db/dba/thresholds`, wrap(deps, null, (ctx) => ctx.ok(D.policy())));
  api.route('GET', `${P}/db/dba/catalog`, wrap(deps, null, (ctx) => ctx.ok(D.catalog())));
  api.route('GET', `${P}/db/dba/notify`, wrap(deps, 'operator', (ctx) => ctx.ok(D.notifySettings())));

  api.route('POST', `${P}/db/dba/thresholds`, wrap(deps, DBA, (ctx) => {
    const b = body(ctx); const before = D.policy(); const after = D.savePolicy(b, ctx.user);
    const prev = Object.fromEntries(before.metrics.map((m) => [m.id, m]));
    const changed = after.metrics.filter((m) => m.warn !== prev[m.id].warn || m.crit !== prev[m.id].crit || m.enabled !== prev[m.id].enabled)
      .map((m) => ({ metric: m.id, from: { warn: prev[m.id].warn, crit: prev[m.id].crit, enabled: prev[m.id].enabled }, to: { warn: m.warn, crit: m.crit, enabled: m.enabled } }));
    audit(ctx, 'dba.thresholds.save', 'db-thresholds', { version: after.version, reason: String(b.reason || '').slice(0, 200), changed, overrides: [before.overrides.length, after.overrides.length], ignore: after.errors.ignore });
    return ctx.ok(after);
  }));
  api.route('POST', `${P}/db/dba/notify`, wrap(deps, DBA, (ctx) => {
    const r = D.saveNotify(body(ctx), ctx.user);
    audit(ctx, 'dba.notify.save', 'db-notify', { recipients: r.recipients.length, warn_mode: r.warn_mode, renotify_h: r.renotify_h, digest: r.digest });
    return ctx.ok(r);
  }));
  api.route('POST', `${P}/db/dba/conditions/ack`, wrap(deps, 'operator', (ctx) => { const b = body(ctx); const c = D.ack(needId(b), ctx.user, b.note); audit(ctx, 'dba.condition.ack', c.id, {}); return ctx.ok(c); }));
  api.route('POST', `${P}/db/dba/conditions/snooze`, wrap(deps, DBA, (ctx) => { const b = body(ctx); const c = D.snooze(needId(b), b.hours, ctx.user, b.reason); audit(ctx, 'dba.condition.snooze', c.id, { hours: Number(b.hours), reason: String(b.reason || '').slice(0, 200) }); return ctx.ok(c); }));
  api.route('POST', `${P}/db/dba/conditions/unsnooze`, wrap(deps, DBA, (ctx) => { const b = body(ctx); const c = D.unsnooze(needId(b), ctx.user); audit(ctx, 'dba.condition.unsnooze', c.id, {}); return ctx.ok(c); }));
  api.route('POST', `${P}/db/dba/maintenance`, wrap(deps, DBA, (ctx) => { const b = body(ctx); const l = D.maintenance(b.instance, b.hours, ctx.user, b.reason); audit(ctx, 'dba.maintenance.start', String(b.instance || '').toUpperCase(), { hours: Number(b.hours), reason: String(b.reason || '').slice(0, 200) }); return ctx.ok({ maintenance: l }); }));
  api.route('POST', `${P}/db/dba/maintenance/end`, wrap(deps, DBA, (ctx) => { const b = body(ctx); D.endMaintenance(b.instance, ctx.user); audit(ctx, 'dba.maintenance.end', String(b.instance || '').toUpperCase(), {}); return ctx.ok({ ok: true }); }));
  api.route('POST', `${P}/db/dba/evaluate`, wrap(deps, 'operator', async (ctx) => { const r = await D.tick(); if (r.error) throw new HttpError(502, `evaluation failed: ${r.error}`); return ctx.ok({ opened: r.opened.length, cleared: r.cleared.length, instances: r.instances, errors: r.errors, notified: r.notified }); }));
  api.route('POST', `${P}/db/dba/digest`, wrap(deps, DBA, async (ctx) => {
    const b = body(ctx);
    if (b.send !== true) return ctx.ok(D.digest());
    const d = await D.sendDigest(ctx.user); audit(ctx, 'dba.digest.send-now', d.id, { status: d.sent.status });
    return ctx.ok(d);
  }));
  api.route('POST', `${P}/db/dba/test-mail`, wrap(deps, DBA, async (ctx) => {
    let r; try { r = await D.testMail(ctx.user); } catch (e) { throw new HttpError(e.code || 502, `test mail failed: ${e.stage ? e.stage + ': ' : ''}${String(e.message).slice(0, 200)}`); }
    audit(ctx, 'dba.test-mail', 'db-notify', { recipients: r.recipients }); return ctx.ok(r);
  }));

  // IT Asset Management's morning health check and Oracle licence compliance e-mails (only its own service identities may
  // send through this; audience 'dba+managers' adds the infrastructure managers set on the Database Dashboard)
  api.route('POST', `${P}/db/dba/morning-report`, wrap(deps, 'admin', async (ctx) => {
    if (!/^system:itam-(db-health|db-morning|oracle-licences)$/.test(String(ctx.user || ''))) throw new HttpError(403, 'only IT Asset Management (morning health check, Oracle licence report) sends this');
    const b = body(ctx); if (typeof b.html !== 'string' && typeof b.text !== 'string') throw new HttpError(400, 'text or html required');
    let r; try { r = await D.mailReport(b); } catch (e) { throw new HttpError(e.code || 502, `not sent: ${String(e.message).slice(0, 200)}`); }
    audit(ctx, 'dba.morning-report', String(b.id || 'morning').slice(0, 40), { day: String(b.day || '').slice(0, 10), recipients: r.recipients }); return ctx.ok(r);
  }));

  if (!(cfg.dba && cfg.dba.scheduler === false)) D.start(Number(cfg.dba && cfg.dba.tick_ms) || 300000);
  deps.dbaAlerts = D;
  return D;
}

module.exports = { register };
