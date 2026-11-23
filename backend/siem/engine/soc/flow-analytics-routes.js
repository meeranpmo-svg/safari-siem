// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * NetFlow Analytics API (the NetFlow Analytics page, dashboards/server/netflow.html) + the flow collector's lifecycle.
 * register() creates the analytics (engine/soc/flow-analytics.js) and the collector (engine/collect/flow-collector.js),
 * starts the UDP listeners when an administrator enabled them, and leaves deps.netflow.stop() for the shutdown.
 *
 *   GET    {P}/netflow/status                 any role   collector, listeners, exporters (+ unknown senders), settings
 *   GET    {P}/netflow/live                   any role   the last 60 minutes from memory; top talkers analyst+
 *   GET    {P}/netflow/interfaces             any role   ?range&exporter&if  in / out, utilisation (poller ifSpeed)
 *   GET    {P}/netflow/top                    any role   ?by=app|proto|dscp|port|exporter|if_in|if_out&range&exporter&if
 *   GET    {P}/netflow/talkers                analyst    ?by=src|dst|conv&range&exporter&if&group   (names addresses) audited
 *   GET    {P}/netflow/groups                 any role   ?range=1440|10080|43200  usage per IP group
 *   GET    {P}/netflow/billing                operator   ?month=YYYY-MM&exporter  bill per group from the admin's rates  audited
 *   POST   {P}/netflow/groups                 admin      {id?, name, kind, cidrs[], rate_per_gb?, currency}   audited
 *   DELETE {P}/netflow/groups/:id             admin      audited
 *   GET    {P}/netflow/apps                   any role   the custom application table
 *   POST   {P}/netflow/apps                   admin      {id?, name, proto, ports[], cidrs[]}   audited
 *   DELETE {P}/netflow/apps/:id               admin      audited
 *   GET    {P}/netflow/alarms                 any role   alarms, state, templates, recent events
 *   POST   {P}/netflow/alarms                 operator   {id?, name, scope, target, metric, dir, threshold, for_min, severity, template_id, recipients[], enabled}  audited
 *   DELETE {P}/netflow/alarms/:id             operator   audited
 *   POST   {P}/netflow/templates              operator   {id?, name, subject, body}   audited
 *   DELETE {P}/netflow/templates/:id          operator   audited
 *   POST   {P}/netflow/templates/preview      operator   renders a template with example values (changes nothing)
 *   GET    {P}/netflow/forecast               any role   ?exporter&if&days   daily peaks → 80 % / 100 % (linear + Holt)
 *   GET    {P}/netflow/patterns               any role   ?exporter&if&weeks  hour-of-week baseline and deviations
 *   GET    {P}/netflow/security               analyst    ?kind&limit  detections (they name addresses)   audited
 *   POST   {P}/netflow/detection              admin      thresholds, exclusions, intel on / off   audited
 *   POST   {P}/netflow/settings               admin      {enabled, ports{netflow, ipfix, sflow}, raw_per_minute, template_ttl_s}  audited, restarts the listeners
 *   POST   {P}/netflow/exporters              admin      {ip, name, sampling?, if_speeds[{if_index, mbps, name}]}   audited (the allow-list)
 *   DELETE {P}/netflow/exporters/:id          admin      audited
 */
const { wrap, audit, prefixOf, HttpError } = require('./routeutil');
const { createFlowAnalytics } = require('./flow-analytics');
const { createFlowCollector } = require('../collect/flow-collector');

const RANK = { viewer: 0, analyst: 1, operator: 2, admin: 3 };
const r2 = (v) => Math.round(v * 100) / 100;

function register(api, deps) {
  if (!deps.state) throw new Error('NetFlow analytics needs deps.state');
  const P = prefixOf(deps), log = deps.log || { info() {}, warn() {}, error() {} };
  const A = deps.flowAnalytics || createFlowAnalytics({ state: deps.state, ch: deps.ch, config: deps.config || {}, log, alerts: deps.alerts, intel: deps.intel, now: deps.now,
    netops: () => deps.netopsInstance,
    mail: (m) => { const s = deps.reports && deps.reports.schedules; if (!s || typeof s.mail !== 'function') throw new Error('the Reports SMTP relay is not running'); return s.mail(m); } });
  const C = deps.flowCollector || createFlowCollector({ ch: deps.ch, config: deps.config || {}, log, now: deps.now, getSettings: A.collectorSettings, mapper: A.mapper, billable: A.billable,
    observers: [A.observe], onMinute: A.onMinute });
  A.setOnChange(() => C.reload());
  if (!deps.noTimers) C.start().catch((e) => log.error('netflow: collector did not start', { err: e.message }));
  deps.netflow = { analytics: A, collector: C, stop: () => C.stop() };

  const ok = (fn) => async (ctx) => ctx.ok(await fn(ctx));
  const restart = async () => { try { await C.restart(); return null; } catch (e) { log.error('netflow: listener restart failed', { err: e.message }); return e.message; } };

  api.route('GET', `${P}/netflow/status`, wrap(deps, null, ok(() => {
    const st = C.stats(), s = A.settings(), ex = A.exporters(), t = (deps.now || Date.now)();
    const statOf = new Map(st.exporters.map((x) => [x.ip, x]));
    const exporters = ex.map((e) => Object.assign({ id: e.id, ip: e.ip, name: e.name, sampling_set: e.sampling, if_speeds: e.if_speeds || [], from: e.from }, (() => { const x = statOf.get(e.ip) || {}; return { datagrams: x.datagrams || 0, records: x.records || 0, bytes: x.bytes || 0, errors: x.errors || 0, invalid: x.invalid || 0, no_template: x.no_template || 0, last_error: x.last_error || '', last_seen: x.last_seen || 0, versions: x.versions || {}, sampling_seen: x.sampling || null, templates: x.templates || 0, agent: x.agent || '' }; })()));
    const receiving = exporters.some((e) => e.last_seen && t - e.last_seen < 300000);
    const todo = [];
    if (!ex.length) todo.push('Add the routers / firewalls / switches that export flows to the exporter allow-list.');
    if (!s.enabled) todo.push('Enable the flow listeners (UDP ' + [s.ports.netflow, s.ports.ipfix, s.ports.sflow].filter(Boolean).join(', ') + ').');
    if (s.enabled && ex.length && !receiving) todo.push('Point each exporter at this server (NetFlow v5 / v9 or IPFIX to UDP ' + s.ports.netflow + ' / ' + s.ports.ipfix + ', sFlow to ' + s.ports.sflow + ') and allow the UDP ports in the server firewall.');
    return { settings: s, collector: { enabled: st.enabled, running: st.running, listeners: st.listeners, listen_errors: st.listen_errors, counters: st.counters, templates: st.templates, open_rows: st.open_rows, limits: st.limits },
      exporters, unknown_senders: st.unknown, receiving, configured: s.enabled && ex.length > 0, todo, groups: A.groups().length, apps: A.apps().length, alarms: A.alarms().length };
  })));
  api.route('GET', `${P}/netflow/live`, wrap(deps, null, ok((ctx) => {
    const ring = C.live(), sp = A.speeds(), full = (RANK[ctx.role] || 0) >= RANK.analyst, last = ring[ring.length - 1] || null;
    const names = new Map(A.exporters().map((e) => [e.ip, e.name]));
    const ifs = new Map();
    for (const x of last ? last.interfaces : []) {
      const k = x.exporter + '#' + x.if_index; let r = ifs.get(k); const s = sp.get(k);
      if (!r) { r = { exporter: x.exporter, exporter_name: names.get(x.exporter) || '', if_index: x.if_index, if_name: s ? s.name : '', speed_mbps: s ? s.mbps : null, in_mbps: 0, out_mbps: 0 }; ifs.set(k, r); }
      r[x.dir === 'out' ? 'out_mbps' : 'in_mbps'] = r2(x.bytes * 8 / 60 / 1e6);
    }
    const rows = [...ifs.values()].map((r) => Object.assign(r, { util_in: r.speed_mbps ? Math.round(r.in_mbps / r.speed_mbps * 1000) / 10 : null, util_out: r.speed_mbps ? Math.round(r.out_mbps / r.speed_mbps * 1000) / 10 : null }))
      .sort((a, b) => Math.max(b.in_mbps, b.out_mbps) - Math.max(a.in_mbps, a.out_mbps)).slice(0, 200);
    return { minutes: ring.map((m) => ({ t: m.minute, mbps: r2(m.bytes * 8 / 60 / 1e6), flows: m.flows, packets: m.packets, exporters: Object.fromEntries(Object.entries(m.exporters).map(([k, v]) => [k, r2(v.bytes * 8 / 60 / 1e6)])) })),
      last_minute: last ? last.minute : null, interfaces: rows, apps: last ? last.apps.map((a) => ({ app: a.app, mbps: r2(a.bytes * 8 / 60 / 1e6) })) : [],
      talkers: full && last ? last.talkers.map((x) => ({ ip: x.ip, mbps: r2(x.bytes * 8 / 60 / 1e6) })) : null, addresses_included: full, running: C.running };
  })));
  api.route('GET', `${P}/netflow/interfaces`, wrap(deps, null, ok((ctx) => A.interfaces(ctx.query))));
  api.route('GET', `${P}/netflow/top`, wrap(deps, null, ok((ctx) => A.top(ctx.query))));
  api.route('GET', `${P}/netflow/talkers`, wrap(deps, 'analyst', async (ctx) => {
    const r = await A.talkers(ctx.query); audit(ctx, 'netflow.talkers.view', r.by, { range: r.range, group: r.group }); return ctx.ok(r);
  }));
  api.route('GET', `${P}/netflow/groups`, wrap(deps, null, ok((ctx) => A.groupsUsage(ctx.query))));
  api.route('GET', `${P}/netflow/billing`, wrap(deps, 'operator', async (ctx) => {
    const r = await A.billing(ctx.query); audit(ctx, 'netflow.billing.view', r.month, { exporter: r.exporter, groups: r.lines.length }); return ctx.ok(r);
  }));
  api.route('POST', `${P}/netflow/groups`, wrap(deps, 'admin', (ctx) => {
    const r = A.saveGroup(ctx.body, ctx.user); audit(ctx, r.created ? 'netflow.group.create' : 'netflow.group.update', r.group.id, r.detail); return ctx.ok(r);
  }));
  api.route('DELETE', `${P}/netflow/groups/:id`, wrap(deps, 'admin', (ctx) => {
    const g = A.deleteGroup(ctx.params && ctx.params.id); audit(ctx, 'netflow.group.delete', g.id, { name: g.name }); return ctx.ok({ ok: true });
  }));
  api.route('GET', `${P}/netflow/apps`, wrap(deps, null, ok(() => ({ apps: A.apps() }))));
  api.route('POST', `${P}/netflow/apps`, wrap(deps, 'admin', (ctx) => {
    const r = A.saveApp(ctx.body, ctx.user); audit(ctx, r.created ? 'netflow.app.create' : 'netflow.app.update', r.app.id, { name: r.app.name, proto: r.app.proto, ports: r.app.ports.length, cidrs: r.app.cidrs.length }); return ctx.ok(r);
  }));
  api.route('DELETE', `${P}/netflow/apps/:id`, wrap(deps, 'admin', (ctx) => {
    const a = A.deleteApp(ctx.params && ctx.params.id); audit(ctx, 'netflow.app.delete', a.id, { name: a.name }); return ctx.ok({ ok: true });
  }));
  api.route('GET', `${P}/netflow/alarms`, wrap(deps, null, ok(() => A.alarmView())));
  api.route('POST', `${P}/netflow/alarms`, wrap(deps, 'operator', (ctx) => {
    const r = A.saveAlarm(ctx.body, ctx.user), a = r.alarm;
    audit(ctx, r.created ? 'netflow.alarm.create' : 'netflow.alarm.update', a.id, { name: a.name, scope: a.scope, target: a.target, metric: a.metric, threshold: a.threshold, for_min: a.for_min, enabled: a.enabled, recipients: a.recipients.length });
    return ctx.ok(r);
  }));
  api.route('DELETE', `${P}/netflow/alarms/:id`, wrap(deps, 'operator', (ctx) => {
    const a = A.deleteAlarm(ctx.params && ctx.params.id); audit(ctx, 'netflow.alarm.delete', a.id, { name: a.name }); return ctx.ok({ ok: true });
  }));
  api.route('POST', `${P}/netflow/templates`, wrap(deps, 'operator', (ctx) => {
    const r = A.saveTemplate(ctx.body, ctx.user); audit(ctx, r.created ? 'netflow.template.create' : 'netflow.template.update', r.template.id, { name: r.template.name }); return ctx.ok(r);
  }));
  api.route('DELETE', `${P}/netflow/templates/:id`, wrap(deps, 'operator', (ctx) => {
    const t = A.deleteTemplate(ctx.params && ctx.params.id); audit(ctx, 'netflow.template.delete', t.id, { name: t.name }); return ctx.ok({ ok: true });
  }));
  api.route('POST', `${P}/netflow/templates/preview`, wrap(deps, 'operator', (ctx) => ctx.ok(A.preview(ctx.body))));
  api.route('GET', `${P}/netflow/forecast`, wrap(deps, null, ok((ctx) => A.forecast(ctx.query))));
  api.route('GET', `${P}/netflow/patterns`, wrap(deps, null, ok((ctx) => A.patterns(ctx.query))));
  api.route('GET', `${P}/netflow/security`, wrap(deps, 'analyst', (ctx) => {
    const r = A.detections(ctx.query); audit(ctx, 'netflow.security.view', 'detections', { items: r.items.length }); return ctx.ok(r);
  }));
  api.route('POST', `${P}/netflow/detection`, wrap(deps, 'admin', (ctx) => {
    const r = A.saveDetection(ctx.body, ctx.user); audit(ctx, 'netflow.detection.save', 'detection', { changed: r.changed, enabled: r.detection.enabled }); return ctx.ok(r);
  }));
  api.route('POST', `${P}/netflow/settings`, wrap(deps, 'admin', async (ctx) => {
    const r = A.saveSettings(ctx.body, ctx.user);
    const err = deps.noTimers ? null : await restart();
    audit(ctx, 'netflow.settings.save', 'collector', { changed: r.changed, enabled: r.settings.enabled, ports: r.settings.ports, restart_error: err });
    if (err) throw new HttpError(502, 'saved, but the listeners did not restart: ' + err);
    return ctx.ok(Object.assign(r, { listeners: C.stats().listeners, listen_errors: C.stats().listen_errors }));
  }));
  api.route('POST', `${P}/netflow/exporters`, wrap(deps, 'admin', (ctx) => {
    const r = A.saveExporter(ctx.body, ctx.user), e = r.exporter;
    audit(ctx, r.created ? 'netflow.exporter.add' : 'netflow.exporter.update', e.ip, { name: e.name, sampling: e.sampling, if_speeds: e.if_speeds.length }); return ctx.ok(r);
  }));
  api.route('DELETE', `${P}/netflow/exporters/:id`, wrap(deps, 'admin', (ctx) => {
    const e = A.deleteExporter(ctx.params && ctx.params.id); audit(ctx, 'netflow.exporter.remove', e.ip, { name: e.name }); return ctx.ok({ ok: true });
  }));
  return deps.netflow;
}

module.exports = { register };
