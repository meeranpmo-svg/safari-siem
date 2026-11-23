// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const { guard: guardJob } = require('../util/errors');
/*
 * Microsoft 365 settings + data for the portal (deps.m365Graph = collect/m365-graph.js, deps.adSettings or ad/settings.js):
 *   GET  {P}/m365/graph     licences, users, sign-ins, Intune, service health, security posture (portal /api/m365 shape)   signed-in
 *   GET  {P}/m365/config    tenant, client ID, secret set?, audit + Graph switches, sync status, permissions per block       admin
 *   PUT  {P}/m365/config    {tenant, client_id, client_secret?, enabled (Exchange Online audit), graph}                    admin
 *   POST {P}/m365/sync      run the Graph sync now and return the status                                                     admin
 * The client secret is write-only: never returned, never logged.
 */
const { HttpError, wrap, audit, prefixOf } = require('../soc/routeutil');

function register(api, deps) {
  const P = prefixOf(deps), graph = deps.m365Graph;
  if (!graph) return;
  const settings = deps.adSettings || require('../ad/settings').createAdSettings({ config: deps.config, adSync: deps.adSync, writeJson: require('../onboard/store').writeJsonAtomic, reloadM365: deps.reloadM365, log: deps.log });
  const view = () => {
    const v = settings.view();
    return { m365: v.m365, writable: v.writable, graph: graph.status(), audit: deps.extras && deps.extras.m365 ? deps.extras.m365() : null, permissions: graph.PERMS };
  };
  api.route('GET', `${P}/m365/graph`, wrap(deps, null, () => graph.data()));
  api.route('GET', `${P}/m365/config`, wrap(deps, 'admin', () => view()));
  api.route('PUT', `${P}/m365/config`, wrap(deps, 'admin', async (ctx) => {
    const b = ctx.body || {}, m = {};
    ['tenant', 'client_id', 'client_secret', 'enabled', 'graph'].forEach((k) => { if (k in b) m[k] = b[k]; });
    if (!Object.keys(m).length) throw new HttpError(400, 'nothing to save');
    const r = await settings.save({ m365: m }, ctx.user);
    audit(ctx, 'm365.config', 'microsoft-365', { saved: r.saved });
    if (graph.enabled()) guardJob('collect.m365-graph.sync', () => graph.syncNow())();   // first pull in the background; the page polls the status
    return Object.assign(view(), { saved: r.saved, m365_applied: r.m365_applied, m365_error: r.m365_error });
  }));
  api.route('POST', `${P}/m365/sync`, wrap(deps, 'admin', async (ctx) => {
    if (!graph.status().ready) throw new HttpError(409, 'enter the tenant ID, application (client) ID and client secret first');
    await graph.syncNow();
    audit(ctx, 'm365.sync', 'microsoft-365', { error: graph.status().last_error || undefined });
    return view();
  }));
}

module.exports = { register };
