// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Data Optimizer HTTP API (DATAOPT.md "API"). Mounted under {P} = config.api_prefix || '/api/soc', behind the same SOC
 * session + proxy secret. Roles: reads = any authenticated user; writes = operator; enable/disable + destinations +
 * settings writes = admin. register(api, deps), deps = { dataopt, config, log }.
 *
 *   GET  {P}/dataopt/summary            volume & cost by source/type, savings, top talkers, suggestions, coverage
 *   GET  {P}/dataopt/pipelines          list   · POST (operator) create
 *   GET  {P}/dataopt/pipelines/:id      detail (+ versions) · POST (operator) update · DELETE (admin)
 *   POST {P}/dataopt/pipelines/:id/simulate {window_hours|from|to, pipeline?}   dry-run (operator: runs regexes on real events)
 *   POST {P}/dataopt/pipelines/:id/enable {point?, overrides?} (admin) · /disable {point?} (admin)
 *   POST {P}/dataopt/simulate {pipeline, window_hours}   dry-run a draft (operator)
 *   GET  {P}/dataopt/drops              what is being dropped/sampled/trimmed, per rule, with counts
 *   GET  {P}/dataopt/sources            source health + volume
 *   GET  {P}/dataopt/destinations (admin) list · POST create · POST/:id update · DELETE/:id
 *   GET  {P}/dataopt/settings           read · POST (admin) update
 *   GET  {P}/dataopt/archive/search     query the cold tier on demand
 *   GET  {P}/dataopt/health
 */
const { HttpError, wrap, audit, body, timeParam, prefixOf } = require('../soc/routeutil');

function register(api, deps) {
  const P = prefixOf(deps) + '/dataopt';
  const d = deps.dataopt;
  if (!d) throw new Error('dataopt routes need deps.dataopt');

  const win = (q) => {
    const to = timeParam(q.to, Date.now());
    const from = q.from !== undefined ? timeParam(q.from, to) : (q.window_hours ? to - Number(q.window_hours) * 3600000 : undefined);
    return { from, to };
  };

  // ---- summary
  api.route('GET', `${P}/summary`, wrap(deps, null, async (ctx) => ctx.ok(await d.summary(win(ctx.query || {})))));

  // ---- pipelines
  api.route('GET', `${P}/pipelines`, wrap(deps, null, (ctx) => ctx.ok({ items: d.listPipelines() })));
  api.route('POST', `${P}/pipelines`, wrap(deps, 'operator', (ctx) => {
    const p = d.createPipeline(body(ctx), ctx.user);
    audit(ctx, 'dataopt.pipeline.create', p.id, { rules: p.rule_count });
    return ctx.ok(p);
  }));
  api.route('GET', `${P}/pipelines/:id`, wrap(deps, null, (ctx) => {
    const p = d.getPipeline(ctx.params.id);
    if (!p) throw new HttpError(404, 'pipeline not found');
    return ctx.ok(p);
  }));
  const updateP = wrap(deps, 'operator', (ctx) => {
    const p = d.updatePipeline(ctx.params.id, body(ctx), ctx.user, ctx.role);
    audit(ctx, 'dataopt.pipeline.update', ctx.params.id, { version: p.version, enabled: !!p.enabled });
    return ctx.ok(p);
  });
  api.route('POST', `${P}/pipelines/:id`, updateP);
  api.route('PUT', `${P}/pipelines/:id`, updateP);
  api.route('DELETE', `${P}/pipelines/:id`, wrap(deps, 'admin', (ctx) => {
    const r = d.deletePipeline(ctx.params.id, ctx.user);
    audit(ctx, 'dataopt.pipeline.delete', ctx.params.id, {});
    return ctx.ok(r);
  }));

  // ---- simulate
  // operator: a dry run compiles the caller's own conditions (regexes) and runs them over up to 20 000 stored events
  const simulate = wrap(deps, 'operator', async (ctx) => {
    const b = body(ctx);
    const opts = { window_hours: b.window_hours || b.window, from: b.from !== undefined ? timeParam(b.from) : undefined, to: b.to !== undefined ? timeParam(b.to) : undefined, limit: b.limit };
    const target = b.pipeline ? b.pipeline : ctx.params.id;
    return ctx.ok(await d.simulate(target, opts));
  });
  api.route('POST', `${P}/pipelines/:id/simulate`, simulate);
  api.route('POST', `${P}/simulate`, wrap(deps, 'operator', async (ctx) => {
    const b = body(ctx);
    if (!b.pipeline) throw new HttpError(400, 'pipeline (draft) required');
    return ctx.ok(await d.simulate(b.pipeline, { window_hours: b.window_hours || b.window, from: b.from !== undefined ? timeParam(b.from) : undefined, to: b.to !== undefined ? timeParam(b.to) : undefined, limit: b.limit }));
  }));

  // ---- enable / disable (admin; enable resolves detection conflicts via overrides)
  api.route('POST', `${P}/pipelines/:id/enable`, wrap(deps, 'admin', (ctx) => {
    const b = body(ctx);
    const p = d.enable(ctx.params.id, { point: b.point || 'ingest', overrides: b.overrides, user: ctx.user });
    audit(ctx, 'dataopt.pipeline.enable', ctx.params.id, { point: b.point || 'ingest', overrides: b.overrides ? Object.keys(b.overrides) : [] });
    return ctx.ok(p);
  }));
  api.route('POST', `${P}/pipelines/:id/disable`, wrap(deps, 'admin', (ctx) => {
    const b = body(ctx);
    const p = d.disable(ctx.params.id, { point: b.point || 'both', user: ctx.user });
    audit(ctx, 'dataopt.pipeline.disable', ctx.params.id, { point: b.point || 'both' });
    return ctx.ok(p);
  }));

  // ---- drops / sources
  api.route('GET', `${P}/drops`, wrap(deps, null, (ctx) => ctx.ok(d.drops())));
  api.route('GET', `${P}/sources`, wrap(deps, null, async (ctx) => ctx.ok(await d.sources(win(ctx.query || {})))));

  // ---- destinations (admin; credentials write-only)
  api.route('GET', `${P}/destinations`, wrap(deps, 'admin', (ctx) => ctx.ok({ items: d.destinations.list() })));
  api.route('POST', `${P}/destinations`, wrap(deps, 'admin', (ctx) => {
    const r = d.destinations.create(body(ctx), ctx.user);
    audit(ctx, 'dataopt.destination.create', r.id, { kind: r.kind, credentials_set: r.credentials && r.credentials.set });
    return ctx.ok(r);
  }));
  api.route('POST', `${P}/destinations/:id`, wrap(deps, 'admin', (ctx) => {
    const before = d.destinations.get ? d.destinations.get(ctx.params.id) : null;
    const r = d.destinations.update(ctx.params.id, body(ctx), ctx.user);
    // where the events go is the change that matters: the endpoint before and after is in the audit record
    audit(ctx, 'dataopt.destination.update', ctx.params.id, { credentials_set: r.credentials && r.credentials.set, endpoint: r.url || ((r.host || '') + (r.port ? ':' + r.port : '')), was: before ? (before.url || ((before.host || '') + (before.port ? ':' + before.port : ''))) : null });
    return ctx.ok(r);
  }));
  api.route('DELETE', `${P}/destinations/:id`, wrap(deps, 'admin', (ctx) => {
    const ok = d.destinations.remove(ctx.params.id, ctx.user);
    if (!ok) throw new HttpError(404, 'destination not found');
    audit(ctx, 'dataopt.destination.delete', ctx.params.id, {});
    return ctx.ok({ ok: true, id: ctx.params.id });
  }));

  // ---- settings
  api.route('GET', `${P}/settings`, wrap(deps, null, (ctx) => ctx.ok(d.settings.get())));
  api.route('POST', `${P}/settings`, wrap(deps, 'admin', (ctx) => {
    const r = d.settings.set(body(ctx), ctx.user);
    audit(ctx, 'dataopt.settings.update', 'settings', Object.keys(body(ctx)));
    return ctx.ok(r);
  }));

  // ---- archive search + health
  // raw archived events name people (user, source IP, message): analyst and above, every search audited, at most 31 days
  api.route('GET', `${P}/archive/search`, wrap(deps, 'analyst', async (ctx) => {
    const q = ctx.query || {};
    const to = timeParam(q.to, Date.now());
    const from = timeParam(q.from, to - 7 * 86400000);
    if (to - from > 31 * 86400000) throw new HttpError(400, 'from/to: search at most 31 days of the archive at a time');
    return ctx.ok(await d.archiveSearch({ from, to, q: q.q, src_id: q.src_id, src_type: q.src_type, stub: q.stub, limit: Math.min(Number(q.limit) || 200, 5000) }));
  }), { auditRead: true });
  api.route('GET', `${P}/health`, wrap(deps, null, (ctx) => ctx.ok(d.health())));
}

module.exports = { register };
