// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * The name behind an IP address, for the forms that add a server or a device ({P} = /api/itam): a reverse lookup (PTR) through the
 * platform server's own DNS - in an Active Directory network, the domain's DNS - then a FORWARD lookup of that name to confirm it
 * points back to the same address (a stale PTR record is said, not trusted silently). Read-only: one DNS question each way, no
 * connection to the address itself, nothing stored.
 *   GET /discovery/resolve?ip=10.0.1.12    operator   {ip, found, name, fqdn, names[], confirmed, why}
 */
const dns = require('node:dns');
const { isIp } = require('./check');

const httpErr = (status, msg) => Object.assign(new Error(msg), { status });
const HOST = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*\.?$/;

function createResolve(opts = {}) {
  // the resolver can be replaced in tests; by default the system's DNS servers, 2 s, one try
  const R = opts.resolver || new dns.promises.Resolver({ timeout: 2000, tries: 1 });
  async function lookup(ip0) {
    const ip = String(ip0 == null ? '' : ip0).trim();
    if (!ip) throw httpErr(400, 'ip is required');
    if (!isIp(ip)) throw httpErr(400, 'ip: "' + ip.slice(0, 45) + '" is not an IP address');
    let names = [];
    try { names = (await R.reverse(ip)).filter((n) => HOST.test(n)).map((n) => n.replace(/\.$/, '').toLowerCase()); }
    catch (e) {
      const code = e && e.code;
      if (code === 'ENOTFOUND' || code === 'ENODATA') return { ip, found: false, names: [], why: 'DNS has no name (PTR record) for ' + ip + ' - type the name, or add the record in the reverse lookup zone' };
      return { ip, found: false, names: [], why: 'DNS did not answer (' + (code || 'error') + ') - type the name; check the platform server\'s DNS settings point to the domain DNS' };
    }
    if (!names.length) return { ip, found: false, names: [], why: 'DNS has no usable name for ' + ip };
    const fqdn = names[0];
    let confirmed = false;
    try { const back = ip.includes(':') ? await R.resolve6(fqdn) : await R.resolve4(fqdn); confirmed = back.map(String).includes(ip); }
    catch (e) { confirmed = false; /* the forward lookup failing is reported as "not confirmed" below */ }
    return { ip, found: true, name: fqdn.split('.')[0].toUpperCase(), fqdn, names: names.slice(0, 10), confirmed,
      why: confirmed ? fqdn + ' points back to ' + ip : 'the PTR record says ' + fqdn + ', but that name does not point back to ' + ip + ' - the record may be stale; check before relying on it' };
  }
  return { lookup };
}

function registerResolve(srv, app, X) {
  srv.route('GET', '/discovery/resolve', (ctx) => { ctx.need('operator'); return X.lookup((ctx.query || {}).ip); });
}

module.exports = { createResolve, registerResolve };
