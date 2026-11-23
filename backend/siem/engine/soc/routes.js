// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * SOC workflow API routes — register(api, deps), deps = { ch, state, detector, alerts, cases, config, log, search }.
 * {P} = config.api_prefix || '/api/soc'. Reads: any authenticated user. Writes: operator (admin for approvals).
 * Every write calls ctx.audit(action, target, detail). Times (from/to) accept ISO-8601 or epoch ms.
 * Validation errors → ctx.fail(400, message, {errors:[…]}).
 *
 * Alerts (portal contract)
 *   GET  {P}/alerts            ?status=new|acknowledged|in-progress|open|closed|all|closed-…(comma list) &min_severity=
 *                              &rule_id= &assignee=<name>|me &unassigned=1 &case_id= &from= &to= &q= &source= &sort=-ts_last
 *                              &limit= &offset=   → {total, items[]}   (LogRhythm-imported alerts only with source=logrhythm)
 *   GET  {P}/alerts/:id
 *   POST {P}/alerts/:id/ack | /assign {assignee} | /close {reason: true-positive|false-positive|benign, note} | /note {text}
 *        also /status {status, detail}, /reopen
 *   POST {P}/alerts/bulk       {ids[], action: ack|assign|close|note|status|reopen, assignee?, reason?, note?, text?, status?}
 *   POST {P}/alerts            manual alert {rule_name, severity, summary, group?, fields?}
 * Cases
 *   GET  {P}/cases             ?status=active|all|open|investigating|…&owner=&severity_min=&breached=true&q=&limit=&offset=
 *   GET  {P}/cases/:id         case + playbook_name + recommended_actions[] + alert_details[]
 *   POST {P}/cases             {title, severity, alert_ids[], playbook_id?, owner?, description?}
 *   POST {P}/cases/:id/alerts {alert_ids[]} | /status {status, resolution?, note?} | /owner {owner} | /notes {text}
 *        | /evidence {name, ref, kind?} | /tasks {title, phase?} | /tasks/:taskId {done} | /playbook {playbook_id}
 *        | /update {title?, description?, severity?}          (aliases: /assign = /owner, /note = /notes)
 *   GET  {P}/playbooks, {P}/playbooks/:id
 *   GET  {P}/approvals ?status=&case_id=       POST {P}/approvals/:id/decide {decision: approved|rejected, comment} (admin)
 *        (recording a decision never executes anything)
 * Metrics / parallel run
 *   GET  {P}/metrics           ?from=&to= (default last 30 days)
 *   GET  {P}/lr-compare        ?from=&to=&window_s=900&bucket_s=3600
 *   POST {P}/lr/alarms         {alarms:[…]} LogRhythm alarm import (shape: engine/soc/lrcompare.js)   (operator)
 *   GET  {P}/audit             ?limit=&action=&since=   (admin; since= reads the monthly journals, else the recent in-memory tail)
 */
const playbooks = require('./playbooks');
const { computeMetrics } = require('./metrics');
const lrc = require('./lrcompare');
const { HttpError, wrap, audit, body, timeParam, prefixOf } = require('./routeutil');

function register(api, deps) {
  const P = prefixOf(deps);
  const { alerts, cases } = deps;
  if (!alerts || !cases) throw new Error('soc routes need deps.alerts and deps.cases');
  const cfg = deps.config || {};

  const needStr = (v, name) => { if (typeof v !== 'string' || !v.trim()) throw new HttpError(400, `${name} required`); return v.trim(); };
  const me = (ctx, v) => (v === 'me' ? (ctx.user || '') : v);

  // ---------------- alerts
  api.route('GET', `${P}/alerts`, wrap(deps, null, (ctx) => {
    const q = Object.assign({}, ctx.query || {});
    if (q.assignee === 'me') q.assignee = ctx.user || '';
    return ctx.ok(alerts.list(q));
  }));
  api.route('GET', `${P}/alerts/:id`, wrap(deps, null, (ctx) => {
    const a = alerts.get(ctx.params.id);
    if (!a) throw new HttpError(404, 'alert not found');
    return ctx.ok(a);
  }));
  api.route('POST', `${P}/alerts`, wrap(deps, 'operator', (ctx) => {
    const b = body(ctx);
    const name = needStr(b.rule_name || b.title, 'rule_name');
    const sev = Number(b.severity === undefined ? 2 : b.severity);
    if (!(sev >= 0 && sev <= 4)) throw new HttpError(400, 'severity must be 0-4');
    const t = Date.now();
    const r = alerts.raise({
      rule_id: 'MANUAL', rule_name: name, rule_type: 'manual', severity: sev, summary: String(b.summary || name),
      group: b.group && typeof b.group === 'object' ? b.group : {}, group_key: `manual:${t}:${ctx.user || ''}`,
      fields: b.fields && typeof b.fields === 'object' ? b.fields : {}, ts_first: timeParam(b.ts_first, t), ts_last: timeParam(b.ts_last, t),
      source: 'manual', count: 1,
    });
    alerts.note(r.alert.id, `manual alert raised by ${ctx.user || 'unknown'}`, ctx.user);
    audit(ctx, 'alert.create', r.alert.id, { rule_name: name, severity: sev });
    return ctx.ok(alerts.get(r.alert.id));
  }));

  const alertOp = (action, fn) => wrap(deps, 'operator', (ctx) => {
    const id = ctx.params.id;
    const b = body(ctx);
    const res = fn(id, b, ctx);
    audit(ctx, `alert.${action}`, id, b);
    return ctx.ok(res);
  });
  api.route('POST', `${P}/alerts/bulk`, wrap(deps, 'operator', (ctx) => {
    const b = body(ctx);
    const op = needStr(b.action || b.op, 'action');
    const args = Object.assign({ assignee: b.assignee, reason: b.reason, note: b.note, text: b.text, status: b.status, detail: b.detail }, b.args || {});
    if (args.assignee === 'me') args.assignee = ctx.user;
    const res = alerts.bulk(b.ids, op, args, ctx.user);
    audit(ctx, `alert.bulk.${op}`, `${(b.ids || []).length} alerts`, { ids: (b.ids || []).slice(0, 1000), assignee: args.assignee, reason: args.reason, ok: res.ok, failed: res.failed });
    return ctx.ok(res);
  }));
  api.route('POST', `${P}/alerts/:id/ack`, alertOp('ack', (id, b, ctx) => alerts.ack(id, ctx.user)));
  api.route('POST', `${P}/alerts/:id/assign`, alertOp('assign', (id, b, ctx) => alerts.assign(id, me(ctx, b.assignee || ''), ctx.user)));
  api.route('POST', `${P}/alerts/:id/note`, alertOp('note', (id, b, ctx) => alerts.note(id, b.text, ctx.user)));
  api.route('POST', `${P}/alerts/:id/status`, alertOp('status', (id, b, ctx) => alerts.setStatus(id, needStr(b.status, 'status'), ctx.user, b.detail)));
  api.route('POST', `${P}/alerts/:id/close`, alertOp('close', (id, b, ctx) => alerts.close(id, needStr(b.reason, 'reason'), ctx.user, b.note)));
  api.route('POST', `${P}/alerts/:id/reopen`, alertOp('reopen', (id, b, ctx) => alerts.reopen(id, ctx.user)));

  // ---------------- cases
  api.route('GET', `${P}/cases`, wrap(deps, null, (ctx) => {
    const q = Object.assign({}, ctx.query || {});
    if (q.owner === 'me') q.owner = ctx.user || '';
    return ctx.ok(cases.list(q));
  }));
  api.route('GET', `${P}/cases/:id`, wrap(deps, null, (ctx) => {
    const c = cases.get(ctx.params.id);
    if (!c) throw new HttpError(404, 'case not found');
    const linked = (c.alerts || []).map((id) => alerts.get(id)).filter(Boolean)
      .map((a) => ({ id: a.id, rule_id: a.rule_id, rule_name: a.rule_name, severity: a.severity, status: a.status, count: a.count, ts_first: a.ts_first, ts_last: a.ts_last, summary: a.summary, group: a.group }));
    return ctx.ok(Object.assign({}, c, { alert_details: linked }));
  }));
  api.route('POST', `${P}/cases`, wrap(deps, 'operator', (ctx) => {
    const b = body(ctx);
    const c = cases.create({
      title: b.title, description: b.description, severity: b.severity, owner: me(ctx, b.owner),
      alert_ids: Array.isArray(b.alert_ids) ? b.alert_ids : [], playbook_id: b.playbook_id, auto_playbook: b.auto_playbook,
    }, ctx.user);
    audit(ctx, 'case.create', c.id, { alerts: c.alerts, severity: c.severity, playbook_id: c.playbook_id });
    return ctx.ok(cases.get(c.id));
  }));
  const caseOp = (action, fn) => wrap(deps, 'operator', (ctx) => {
    const b = body(ctx);
    fn(ctx.params.id, b, ctx);
    audit(ctx, `case.${action}`, ctx.params.id, Object.assign({}, b, ctx.params.taskId ? { task: ctx.params.taskId } : {}));
    return ctx.ok(cases.get(ctx.params.id));
  });
  const setOwner = caseOp('owner', (id, b, ctx) => cases.assign(id, me(ctx, b.owner || ''), ctx.user));
  const addNote = caseOp('note', (id, b, ctx) => cases.note(id, b.text, ctx.user));
  api.route('POST', `${P}/cases/:id/alerts`, caseOp('alerts', (id, b, ctx) => cases.addAlerts(id, b.alert_ids, ctx.user)));
  api.route('POST', `${P}/cases/:id/status`, caseOp('status', (id, b, ctx) => cases.setStatus(id, needStr(b.status, 'status'), ctx.user, { resolution: b.resolution, note: b.note, close_alerts: b.close_alerts })));
  api.route('POST', `${P}/cases/:id/owner`, setOwner);
  api.route('POST', `${P}/cases/:id/assign`, setOwner);
  api.route('POST', `${P}/cases/:id/notes`, addNote);
  api.route('POST', `${P}/cases/:id/note`, addNote);
  api.route('POST', `${P}/cases/:id/evidence`, caseOp('evidence', (id, b, ctx) => cases.addEvidence(id, { name: b.name, ref: b.ref, kind: b.kind }, ctx.user)));
  api.route('POST', `${P}/cases/:id/tasks`, caseOp('task.add', (id, b, ctx) => cases.addTask(id, { title: b.title, phase: b.phase }, ctx.user)));
  api.route('POST', `${P}/cases/:id/tasks/:taskId`, caseOp('task.set', (id, b, ctx) => cases.setTask(id, ctx.params.taskId, b.done !== false, ctx.user)));
  api.route('POST', `${P}/cases/:id/playbook`, caseOp('playbook', (id, b, ctx) => cases.applyPlaybook(id, needStr(b.playbook_id, 'playbook_id'), ctx.user)));
  api.route('POST', `${P}/cases/:id/update`, caseOp('update', (id, b, ctx) => cases.update(id, { title: b.title, description: b.description, severity: b.severity, owner: b.owner === undefined ? undefined : me(ctx, b.owner) }, ctx.user)));

  // ---------------- playbooks / approvals
  api.route('GET', `${P}/playbooks`, wrap(deps, null, (ctx) => ctx.ok({ items: playbooks.list(), actions: playbooks.ACTIONS })));
  api.route('GET', `${P}/playbooks/:id`, wrap(deps, null, (ctx) => {
    const pb = playbooks.get(ctx.params.id);
    if (!pb) throw new HttpError(404, 'playbook not found');
    return ctx.ok(pb);
  }));
  api.route('GET', `${P}/approvals`, wrap(deps, null, (ctx) => ctx.ok({ items: cases.approvals.list(ctx.query || {}) })));
  api.route('POST', `${P}/approvals/:id/decide`, wrap(deps, 'approve:eng:soc', (ctx) => {
    const b = body(ctx);
    const r = cases.approvals.decide(ctx.params.id, needStr(b.decision, 'decision'), ctx.user, b.comment);
    audit(ctx, `approval.${r.status}`, r.id, { case_id: r.case_id, action_id: r.action_id, targets: r.targets, comment: b.comment || '' });
    return ctx.ok(r);
  }));

  // ---------------- metrics
  api.route('GET', `${P}/metrics`, wrap(deps, null, (ctx) => {
    const q = ctx.query || {};
    const to = timeParam(q.to, Date.now());
    const from = timeParam(q.from, to - 30 * 86400000);
    if (!(from < to)) throw new HttpError(400, 'from must be before to');
    const m = computeMetrics({
      alerts: alerts.all(), cases: cases.all(), from, to, slaState: cases.slaState,
      tzOffsetMin: cfg.tz_offset_min !== undefined ? cfg.tz_offset_min : 180, noisyPerDay: cfg.noisy_alerts_per_day || 20,
    });
    if (deps.detector) {
      const ds = deps.detector.stats();
      m.detector = { events: ds.events, eps: ds.eps, alerts: ds.alerts, rules_loaded: ds.rules_loaded, errors: ds.errors };
    }
    return ctx.ok(m);
  }));

  // ---------------- LogRhythm parallel run
  api.route('GET', `${P}/lr-compare`, wrap(deps, null, (ctx) => {
    const q = ctx.query || {};
    const to = timeParam(q.to, Date.now());
    const from = timeParam(q.from, to - 7 * 86400000);
    const all = alerts.all();
    return ctx.ok(lrc.compare({
      ours: all.filter((a) => a.source !== 'logrhythm'), lr: all.filter((a) => a.source === 'logrhythm'),
      from, to, windowS: Number(q.window_s) || cfg.lr_match_window_s || 900, bucketS: Number(q.bucket_s) || 3600,
      ruleMap: cfg.lr_rule_map || {},
    }));
  }));
  api.route('POST', `${P}/lr/alarms`, wrap(deps, 'operator', (ctx) => {
    const b = body(ctx);
    const list = Array.isArray(ctx.body) ? ctx.body : b.alarms;
    if (!Array.isArray(list) || !list.length) throw new HttpError(400, 'alarms[] required');
    if (list.length > 10000) throw new HttpError(413, 'at most 10000 alarms per request');
    const res = lrc.importAlarms(alerts, list);
    audit(ctx, 'lr.import', `${list.length} alarms`, { imported: res.imported, skipped: res.skipped, errors: res.errors.length });
    return ctx.ok(res);
  }));

  // ---------------- UEBA (engine/ueba/api.js) — registered here so it shares the SOC prefix + auth
  if (deps.ueba) {
    try { require('../ueba/api').register(api, deps); } catch (e) { (deps.log || console).error('ueba routes registration failed', { err: e && e.message }); }
  }

  // ---------------- audit (read)
  api.route('GET', `${P}/audit`, wrap(deps, 'admin', (ctx) => {
    const q = ctx.query || {};
    const lim = Math.min(1000, Number(q.limit) || 100), f = q.action ? (e) => String(e.action || '').startsWith(q.action) : null;
    // ?since= reads the monthly journals (survives restarts, up to 5000 entries); without it, the recent in-memory tail
    if (q.since && typeof deps.state.auditSince === 'function') { const r = deps.state.auditSince(timeParam(q.since) || 0, Math.min(5000, Number(q.limit) || 5000), f); return ctx.ok({ items: r.items, capped: r.capped, source: 'journal' }); }
    const items = typeof deps.state.auditTail === 'function' ? deps.state.auditTail(lim, f) : [];
    return ctx.ok({ items, source: 'memory' });
  }));
}

module.exports = { register };
