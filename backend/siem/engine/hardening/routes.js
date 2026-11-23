// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Baseline-hardening snapshots ({P} = /api/soc). Read by IT Asset Management's baseline scan as system:itam-hardening.
 *   GET {P}/hardening/snapshots[?host=]   analyst  { available, hosts[{host, ip, at, received, agent_version, settings}],
 *                                                  stats{hosts, rejected} }   every read audited
 * Analyst and above: a snapshot describes how a server is defended (which protections are off) - not for every viewer.
 * The snapshots themselves arrive with the agent's events (POST /ingest/<src>, the source's token) - no route here writes.
 */
const { HttpError, wrap, audit, prefixOf } = require('../soc/routeutil');
const { body } = require('../util/check');

function register(api, deps) {
  const P = prefixOf(deps);
  api.route('GET', `${P}/hardening/snapshots`, wrap(deps, 'analyst', (ctx) => {
    const q = body(ctx.query || {}).str('host', { max: 253 }).done();
    const H = deps.hardening;
    if (!H) return { available: false, reason: 'the hardening snapshot store is not running on the SIEM', hosts: [] };
    let hosts = H.list();
    if (q.host) { const one = H.get(q.host); if (!one) throw new HttpError(404, 'no hardening snapshot for ' + q.host); hosts = [one]; }
    audit(ctx, 'hardening.snapshots.read', q.host || 'all', { hosts: hosts.length });
    return { available: true, hosts, stats: H.stats() };
  }));
}

module.exports = { register };
