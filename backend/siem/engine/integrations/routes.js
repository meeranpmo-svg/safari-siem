// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * ITSM integration API — register(api, deps) (deps as for soc/routes.js; deps.integrations.manageengine is created here
 * when absent and exposed back on deps for main.js shutdown). {P} = config.api_prefix || '/api/soc'.
 * Same proxy-secret + portal session auth as every SOC route. Reads: any authenticated user (viewer). Settings and
 * credential: admin. Ticket actions: operator. Every write is audited; the API key is never returned or logged.
 *
 *   GET  {P}/integrations/manageengine/settings      → { settings (no key), credential {api_key_set, key_fingerprint, key_set_at, key_set_by}, defaults }
 *   POST {P}/integrations/manageengine/settings      admin  {enabled?, base_url?, ca_file?, ca_pin?, default_requester?, site?, group?, technician?,
 *                                                     priority_map?, category?, subcategory?, item?, template_id?, dedupe_window_h?, on_recurrence?,
 *                                                     auto_create?, sync_interval_s?, status_map?, close_reason_default?, portal_url?, …} → same as GET
 *   POST {P}/integrations/manageengine/credential    admin  {api_key}  (write-only; stored in secrets.json integrations.manageengine.api_key)
 *   DELETE {P}/integrations/manageengine/credential  admin
 *   POST {P}/integrations/manageengine/test          admin  → { ok, ms, error?, requests_visible?, base_url, variant, api_key_set }
 *   GET  {P}/integrations/manageengine/status        → { enabled, configured, credential, queue{depth,dead,next_at,items[]}, tickets{total,open,closed,linked},
 *                                                     last_sync, last_sync_error, last_test, counters{}, mappings{}, sync_interval_s, running }
 *   POST {P}/integrations/manageengine/sync          operator → sync result (runs auto-create, recurrence, read-back now)
 *   POST {P}/integrations/manageengine/queue/retry   admin  → {retried}      POST …/queue/purge  admin → {purged}
 *   GET  {P}/integrations/manageengine/tickets       ?kind=alert|case&ref_id=&open=1&limit=   → {total, items[]}
 *   GET  {P}/integrations/manageengine/alerts-without-tickets ?min_severity=&limit=          → {total, items[]}
 *   POST {P}/integrations/manageengine/link          operator {items:[{kind, id, request_id}]} → {ok, failed, results[]}
 *   POST {P}/integrations/manageengine/tickets/:id/comment operator {text} → {ok, queued?}
 *   POST {P}/alerts/:id/ticket                       operator {request_id?, force?} → { ticket:{request_id, url, …}, created, existing?, queued?, queue_id? }
 *   POST {P}/cases/:id/ticket                        operator  same
 *   GET  {P}/alerts/:id/ticket, GET {P}/cases/:id/ticket → ticket or 404
 */
const { createManageEngine } = require('./manageengine');
const { HttpError, wrap, audit, body, prefixOf } = require('../soc/routeutil');

function register(api, deps) {
  const P = prefixOf(deps);
  const log = deps.log && deps.log.child ? deps.log.child({ mod: 'manageengine' }) : deps.log;
  if (!deps.state) throw new Error('integrations routes need deps.state');
  deps.integrations = deps.integrations || {};
  const me = deps.integrations.manageengine || createManageEngine({
    state: deps.state, alerts: deps.alerts, cases: deps.cases, config: deps.config, log,
    ruleLookup: (id) => { try { const list = deps.detector && typeof deps.detector.rules === 'function' ? deps.detector.rules() : []; return (list || []).find((r) => r && r.id === id) || null; } catch { return null; } },
  });
  deps.integrations.manageengine = me;
  const B = `${P}/integrations/manageengine`;
  const view = () => ({ settings: me.settings(), credential: me.credentialState(), defaults: me.DEFAULTS });

  api.route('GET', `${B}/settings`, wrap(deps, null, (ctx) => ctx.ok(view())));
  api.route('POST', `${B}/settings`, wrap(deps, 'admin', (ctx) => {
    const b = body(ctx);
    const before = me.settings();
    me.setSettings(b, ctx.user);
    const after = me.settings();
    const changed = Object.keys(b).filter((k) => JSON.stringify(before[k]) !== JSON.stringify(after[k]));
    audit(ctx, 'integrations.manageengine.settings', 'manageengine', { changed, enabled: after.enabled, base_url: after.base_url });
    return ctx.ok(view());
  }));
  api.route('POST', `${B}/credential`, wrap(deps, 'admin', (ctx) => {
    const b = body(ctx);
    const key = typeof b.api_key === 'string' ? b.api_key : typeof b.authtoken === 'string' ? b.authtoken : '';
    const r = me.setCredential(key, ctx.user);
    audit(ctx, 'integrations.manageengine.credential', 'manageengine', { set: true, fingerprint: r.key_fingerprint }); // never the key
    return ctx.ok({ ok: true, credential: r });
  }));
  api.route('DELETE', `${B}/credential`, wrap(deps, 'admin', (ctx) => {
    const r = me.clearCredential(ctx.user);
    audit(ctx, 'integrations.manageengine.credential', 'manageengine', { set: false });
    return ctx.ok({ ok: true, credential: r });
  }));
  api.route('POST', `${B}/test`, wrap(deps, 'admin', async (ctx) => {
    const r = await me.test();
    audit(ctx, 'integrations.manageengine.test', 'manageengine', { ok: r.ok, ms: r.ms, error: r.error || '' });
    return ctx.ok(r);
  }));
  api.route('GET', `${B}/status`, wrap(deps, null, (ctx) => ctx.ok(me.status())));
  api.route('POST', `${B}/sync`, wrap(deps, 'operator', async (ctx) => {
    const r = await me.sync();
    audit(ctx, 'integrations.manageengine.sync', 'manageengine', { auto_created: r.auto_created, readback: r.readback, error: r.error || '' });
    return ctx.ok(r);
  }));
  api.route('POST', `${B}/queue/retry`, wrap(deps, 'admin', (ctx) => { const n = me.retryDead(); audit(ctx, 'integrations.manageengine.queue.retry', 'manageengine', { retried: n }); return ctx.ok({ retried: n }); }));
  api.route('POST', `${B}/queue/purge`, wrap(deps, 'admin', (ctx) => { const n = me.purgeQueue(); audit(ctx, 'integrations.manageengine.queue.purge', 'manageengine', { purged: n }); return ctx.ok({ purged: n }); }));
  api.route('GET', `${B}/tickets`, wrap(deps, null, (ctx) => ctx.ok(me.tickets(ctx.query || {}))));
  api.route('GET', `${B}/alerts-without-tickets`, wrap(deps, null, (ctx) => ctx.ok(me.alertsWithoutTickets(ctx.query || {}))));
  api.route('POST', `${B}/link`, wrap(deps, 'operator', (ctx) => {
    const b = body(ctx);
    const r = me.linkBulk(b.items, ctx.user);
    audit(ctx, 'integrations.manageengine.link', `${(b.items || []).length} items`, { ok: r.ok, failed: r.failed, items: (b.items || []).slice(0, 200).map((x) => ({ id: x.id, request_id: x.request_id })) });
    return ctx.ok(r);
  }));
  api.route('POST', `${B}/tickets/:id/comment`, wrap(deps, 'operator', async (ctx) => {
    const b = body(ctx);
    const r = await me.comment(ctx.params.id, b.text, ctx.user);
    audit(ctx, 'integrations.manageengine.comment', ctx.params.id, { queued: !!r.queued });
    return ctx.ok(r);
  }));

  const ticketOp = (kind) => wrap(deps, 'operator', async (ctx) => {
    const b = body(ctx);
    const id = ctx.params.id;
    let r;
    if (b.request_id !== undefined && b.request_id !== '') {
      const t = me.linkTicket({ kind, id, request_id: b.request_id, by: ctx.user });
      r = { ticket: t, created: false, linked: true };
    } else r = await me.createTicket({ kind, id, by: ctx.user, force: b.force === true });
    audit(ctx, `${kind}.ticket`, id, { request_id: r.ticket ? r.ticket.request_id : '', created: !!r.created, linked: !!r.linked, queued: !!r.queued, queue_id: r.queue_id || '' });
    return ctx.ok(Object.assign({}, r, r.ticket ? { request_id: r.ticket.request_id, url: r.ticket.url } : {}));
  });
  const ticketGet = (kind) => wrap(deps, null, (ctx) => {
    const t = me.ticketFor(kind, ctx.params.id);
    if (!t) throw new HttpError(404, `no ticket for ${kind} ${ctx.params.id}`);
    return ctx.ok(t);
  });
  api.route('POST', `${P}/alerts/:id/ticket`, ticketOp('alert'));
  api.route('POST', `${P}/cases/:id/ticket`, ticketOp('case'));
  api.route('GET', `${P}/alerts/:id/ticket`, ticketGet('alert'));
  api.route('GET', `${P}/cases/:id/ticket`, ticketGet('case'));

  if (deps.config && deps.config.integrations && deps.config.integrations.manageengine && deps.config.integrations.manageengine.autostart === false) return me;
  me.start();
  return me;
}

module.exports = { register };
