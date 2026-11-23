// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * AD change auditing API (AD Audit page tabs "AD changes", "Lockout analyzer", "Policy changes") - engine/soc/adchanges.js.
 * register(api, deps): {P} = config.api_prefix || '/api/soc'. Register AFTER sysadmin/routes.js (it reads deps.sysadminInstance
 * for the read-only GPO report check; without it the GPO snapshots say so and everything else works).
 *
 * Reads name people (who changed what, whose account locked out): analyst and above - the same as the raw event search the
 * page's Change audit tab already uses - and every read is itself audited with its filter.
 *   GET  {P}/ad/changes            analyst  ?hours=1-2160 &kind=acl|gpo|gpo-link|dns|schema|attribute|object|access &object_class= &who= &q= &privileged=1 &risky=1 &limit=1-5000
 *        → {available, hours, capped, counts{total, acl, gpo, gpo-link, dns, schema, attribute, object, access, privileged, risky}, classes[{name,count}], total,
 *           items[{ts, at, dc, event_code, op, kind, object_class, object_type, object_dn, object_name, attribute, who, old, new, old_values[], new_values[], masked,
 *                  summary, severity, privileged_object, gpo_guid, gpo_name?, detail{acl|gpo|gpo_link|dns|uac}|null}], note}
 *   GET  {P}/ad/lockouts           analyst  ?hours= &window_min=5-240 (default 30) &account=
 *        → {available, hours, window_min, total, items[{at, account, dc, caller_computer, likely{computer, ip, process, logon_type, basis, confidence}, evidence{…counts}, hints[]}], ranking[…]}
 *   GET  {P}/ad/lockouts/:account  analyst  one account's lockout history (same shape, ?hours= default 720)
 *   GET  {P}/ad/policy-changes     analyst  ?hours=  → {items[4739 / 4719 with old/new], gpo_changes[…], gpo_snapshots[…], snapshot{enabled, server, reason}}
 *   GET  {P}/ad/gpo/snapshots      analyst  ?guid=   GET {P}/ad/gpo/snapshots/:id  analyst  one snapshot with its setting-level diff
 *   POST {P}/ad/gpo/snapshot       operator {guid?, server?}  take a GPO report snapshot now (read-only check gpo_report) - audited
 * Background: when ad_changes.gpo_server is set, every ad_changes.gpo_poll_min (10) a guarded round snapshots each GPO whose AD
 * object changed since the last round (guard('adchanges.gpo-snapshot'), rescheduled in finally).
 */
const { body: check, param } = require('../util/check');
const { guard } = require('../util/errors');
const { createAdChanges } = require('./adchanges');
const { wrap, audit, prefixOf } = require('./routeutil');

const KINDS = ['acl', 'gpo', 'gpo-link', 'dns', 'schema', 'attribute', 'object', 'access'];
const ACCOUNT_RE = /^[A-Za-z0-9._@\\$' -]{1,128}$/;
const GUID_RE = /^\{?[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}?$/;
let TIMER = null;

function register(api, deps) {
  const P = prefixOf(deps), log = deps.log && deps.log.child ? deps.log.child({ mod: 'adchanges' }) : deps.log;
  const X = deps.adChanges || createAdChanges({ ch: deps.ch, state: deps.state, config: deps.config, log, sysadmin: () => deps.sysadminInstance || deps.sysadmin || null });
  deps.adChanges = X;
  const hoursQ = (b, def) => b.int('hours', { min: 1, max: 2160, def });

  api.route('GET', `${P}/ad/changes`, wrap(deps, 'analyst', async (ctx) => {
    const q = hoursQ(check(ctx.query || {}), 168).oneOf('kind', KINDS).str('object_class', { max: 64, re: /^[A-Za-z0-9-]+$/, msg: 'object_class must be an AD class name' })
      .str('who', { max: 128 }).str('q', { max: 200 }).oneOf('privileged', ['1', 'true']).oneOf('risky', ['1', 'true']).int('limit', { min: 1, max: 5000 }).done();
    const r = await X.changes(q);
    audit(ctx, 'ad.changes.view', q.kind || 'all', { hours: q.hours, filter: { kind: q.kind || null, object_class: q.object_class || null, who: q.who || null, q: q.q || null }, rows: (r.items || []).length });
    return ctx.ok(r);
  }));
  api.route('GET', `${P}/ad/lockouts`, wrap(deps, 'analyst', async (ctx) => {
    const q = hoursQ(check(ctx.query || {}), 168).int('window_min', { min: 5, max: 240 }).str('account', { max: 128, re: ACCOUNT_RE, msg: 'account must be an account name' }).done();
    const r = await X.lockouts(q);
    audit(ctx, 'ad.lockouts.view', q.account || 'all', { hours: q.hours, window_min: r.window_min || null, lockouts: r.total || 0 });
    return ctx.ok(r);
  }));
  api.route('GET', `${P}/ad/lockouts/:account`, wrap(deps, 'analyst', async (ctx) => {
    const q = hoursQ(check(Object.assign({}, ctx.query || {}, { account: ctx.params.account })), 720).int('window_min', { min: 5, max: 240 })
      .str('account', { required: true, max: 128, re: ACCOUNT_RE, msg: 'account must be an account name' }).done();
    const r = await X.lockouts(q);
    audit(ctx, 'ad.lockouts.account', q.account, { hours: q.hours, lockouts: r.total || 0 });
    return ctx.ok(r);
  }));
  api.route('GET', `${P}/ad/policy-changes`, wrap(deps, 'analyst', async (ctx) => {
    const q = hoursQ(check(ctx.query || {}), 720).done();
    const r = await X.policy(q);
    audit(ctx, 'ad.policy.view', 'all', { hours: q.hours, rows: (r.items || []).length });
    return ctx.ok(r);
  }));
  api.route('GET', `${P}/ad/gpo/snapshots`, wrap(deps, 'analyst', (ctx) => {
    const q = check(ctx.query || {}).str('guid', { max: 40, re: GUID_RE, msg: 'guid must be a GPO GUID' }).done();
    return ctx.ok({ status: X.status(), items: X.listSnapshots(q.guid) });
  }));
  api.route('GET', `${P}/ad/gpo/snapshots/:id`, wrap(deps, 'analyst', (ctx) => {
    const id = param(ctx.params.id, 'id'), s = X.getSnapshot(id);
    if (!s) throw Object.assign(new Error('snapshot not found'), { status: 404 });
    audit(ctx, 'ad.gpo.snapshot.view', id, { guid: s.guid });
    return ctx.ok(s);
  }));
  api.route('POST', `${P}/ad/gpo/snapshot`, wrap(deps, 'operator', async (ctx) => {
    const b = check(ctx.body).str('guid', { max: 40, re: GUID_RE, msg: 'guid must be a GPO GUID' }).str('server', { max: 40, re: /^[a-z0-9][a-z0-9-]{1,39}$/, msg: 'server must be a server id from the Windows server list' }).done();
    try {
      const r = await X.snapshot(b.guid || '', { by: ctx.user, via: 'portal', serverRef: b.server });
      audit(ctx, 'ad.gpo.snapshot', b.guid || 'changed-24h', { server: r.server, snapshots: r.snapshots.map((s) => ({ id: s.id, guid: s.guid, changes: (s.diff || []).length, unchanged: !!s.unchanged })) });
      return ctx.ok(r);
    } catch (e) {
      audit(ctx, 'ad.gpo.snapshot', b.guid || 'changed-24h', { ok: false, error: String(e.message).slice(0, 200) });
      throw e;
    }
  }));

  const every = Math.max(5, Number(((deps.config || {}).ad_changes || {}).gpo_poll_min) || 10) * 60000;
  const tick = guard('adchanges.gpo-snapshot', async () => {
    try { await X.autoRound(); } finally { if (!deps.noTimers) { TIMER = setTimeout(tick, every); if (TIMER.unref) TIMER.unref(); } }
  });
  if (!deps.noTimers) { if (TIMER) clearTimeout(TIMER); TIMER = setTimeout(tick, 120000); if (TIMER.unref) TIMER.unref(); }
  return X;
}

module.exports = { register };
