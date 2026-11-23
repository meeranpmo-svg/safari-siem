// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * AD identity API — register(api, deps), deps = { identity, adSync, config, log } (engine/ad/identity.js, engine/ad/sync.js).
 * {P} = config.api_prefix || '/api/soc'. Same session + proxy-secret auth as the other SOC routes; ADMIN only (directory data).
 *
 *   GET  {P}/identity/summary          counts (users / disabled / privileged / dormant / service accounts / adminCount orphans),
 *                                      privileged groups with member counts, top departments, sync status
 *   GET  {P}/identity/users            ?privileged=1&disabled=1&dormant=1&service=1&department=&q=&limit=100&offset=0
 *                                      (each filter also accepts 0 = "not") → {total, synced, items[]}
 *   GET  {P}/identity/users/:name      one account (sAMAccountName, UPN or DOMAIN\name)
 *   POST {P}/identity/sync             admin: run a sync now (used by `sentra-siem-ad sync-now`) → sync result
 *   GET  {P}/identity/nhi              analyst: Non-Human Identities only - directory service accounts (name pattern, SPN), gMSA /
 *                                      sMSA, and Entra app registrations with the end dates of their secrets / certificates (never a
 *                                      value). No person is listed, so analyst is enough (IT Asset Management's NHI register reads it)
 *   GET  {P}/identity/exchange-servers  analyst: the Exchange servers AD lists (configuration partition) - name, FQDN, version,
 *                                      roles; server objects, no personal data. IT Asset Management marks those assets Exchange.
 */
const { HttpError, wrap, audit, prefixOf } = require('../soc/routeutil');

function register(api, deps) {
  const P = prefixOf(deps);
  const { identity, adSync } = deps;
  if (!identity) throw new Error('identity routes need deps.identity');

  api.route('GET', `${P}/identity/summary`, wrap(deps, 'admin', (ctx) => ctx.ok(Object.assign(identity.summary(), { sync: adSync ? adSync.status() : null }))));
  api.route('GET', `${P}/identity/nhi`, wrap(deps, 'analyst', (ctx) => {
    const g = deps.m365Graph && typeof deps.m365Graph.data === 'function' ? deps.m365Graph.data() : null;
    const b = g && g.blocks ? g.blocks.apps : null;
    const entra = !g || g.configured === false ? { available: false, reason: (g && g.reason) || 'Microsoft Graph is not configured on the SIEM' }
      : b && b.ok ? { available: true, updated: g.updated, stale_since: b.stale_since || null, apps: g.apps || [] }
        : { available: false, reason: b ? (b.error === 'permission not granted' ? 'grant ' + (b.perm || 'Application.Read.All') + ' to the SIEM app registration' : 'app registrations not read: ' + (b.error || 'unknown')) : 'app registrations not read yet (next Graph sync)' };
    const ad = identity.size() ? Object.assign({ available: true }, identity.nhi()) : { available: false, reason: 'no Active Directory sync yet (Identity & Sign-in -> AD settings)' };
    return ctx.ok({ ad, entra });
  }));
  api.route('GET', `${P}/identity/exchange-servers`, wrap(deps, 'analyst', (ctx) => {
    const snap = identity.snapshot() || {};
    return ctx.ok({ synced: snap.synced || null, available: Array.isArray(snap.exchange_servers), items: snap.exchange_servers || [] });
  }));
  api.route('GET', `${P}/identity/users`, wrap(deps, 'admin', (ctx) => ctx.ok(identity.list(ctx.query || {}))));
  api.route('GET', `${P}/identity/users/:name`, wrap(deps, 'admin', (ctx) => {
    let name = String(ctx.params.name || '');
    try { name = decodeURIComponent(name); } catch { /* already decoded */ }
    const r = identity.lookup(name, '');
    if (!r) throw new HttpError(404, 'no such directory account');
    return ctx.ok(identity.list({ q: r.sam, limit: 1000 }).items.find((x) => x.sam === r.sam));
  }));
  // AD & Exchange settings from the portal (admin; secrets are write-only) - engine/ad/settings.js
  const settings = deps.adSettings || require('./settings').createAdSettings({ config: deps.config, adSync, writeJson: require('../onboard/store').writeJsonAtomic, reloadM365: deps.reloadM365, log: deps.log });
  api.route('GET', `${P}/identity/config`, wrap(deps, 'admin', (ctx) => ctx.ok(settings.view())));
  api.route('PUT', `${P}/identity/config`, wrap(deps, 'admin', async (ctx) => {
    const r = await settings.save(ctx.body || {}, ctx.user);
    audit(ctx, 'identity.config', 'ad-exchange', { saved: r.saved });
    return ctx.ok(r);
  }));
  api.route('POST', `${P}/identity/test`, wrap(deps, 'admin', async (ctx) => {
    const r = await settings.test(ctx.body || {});
    audit(ctx, 'identity.test', 'ad', { ok: r.ok });
    return ctx.ok(r);
  }));
  api.route('POST', `${P}/identity/sync`, wrap(deps, 'admin', async (ctx) => {
    if (!adSync) throw new HttpError(503, 'AD sync module not loaded');
    audit(ctx, 'identity.sync', '-', {});
    const r = await adSync.syncNow('api:' + (ctx.user || 'unknown'));
    if (!r.ok) throw new HttpError(502, 'AD sync failed: ' + r.error);
    return ctx.ok(r);
  }));
}

module.exports = { register };
