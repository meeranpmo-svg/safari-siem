// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Host name → IP / MAC lookup for ITAM discovery: names cleaned, ::ffff: stripped, MAC from firewall logs, errors.
const test = require('node:test');
const assert = require('node:assert/strict');
const H = require('../engine/soc/hostmap');

test('hostmap: kerberos / firewall sources, MAC join, input cleaning', async () => {
  const calls = [];
  const ch = { query: async (sql, p) => { calls.push([sql, p]);
    if (/argMax\(s\.ip, s\.ts\)/.test(sql)) return [{ name: 'jb-sa2051-lt', ip: '::ffff:192.168.40.21', seen: '2026-10-11 17:30:00', via: 'kerberos' }, { name: 'ho-sa1914-lt', ip: '10.10.8.5', seen: '2026-10-11 17:00:00', via: 'firewall' }, { name: 'x', ip: '127.0.0.1' }];
    return [{ ip: '10.10.8.5', mac: '00-1A-2B-3C-4D-5E' }]; } };
  const R = {}; H.register({ route: (m, p, h) => { R[m + ' ' + p] = h; } }, { ch, config: { clickhouse: { database: 'siem' } }, log: { error() {} } });
  const call = async (b) => { const o = {}; await R['POST /api/soc/hostmap']({ body: b, ok(x) { o.s = 200; o.b = x; }, fail(c, m) { o.s = c; o.e = m; } }); return o; };
  const r = await call({ names: [('JB-SA2051-LT.' + 'corp-hq.com'), 'ho-sa1914-lt', 'bad name;drop', 'x'] });
  assert.equal(r.s, 200, r.e);
  assert.deepEqual(calls[0][1].names, ['jb-sa2051-lt', 'ho-sa1914-lt', 'x']);
  assert.match(calls[0][0], /FROM siem\.events/); assert.match(calls[0][0], /endsWith\(user, '\$'\)/);
  assert.deepEqual(r.b.hosts['jb-sa2051-lt'], { ip: '192.168.40.21', mac: '', seen: '2026-10-11 17:30:00', via: 'kerberos' });
  assert.equal(r.b.hosts['ho-sa1914-lt'].mac, '00:1a:2b:3c:4d:5e'); assert.equal(r.b.hosts.x, undefined);
  assert.equal((await call({})).s, 400);
  assert.deepEqual((await call({ names: ['!!'] })).b, { hosts: {} });
});

test('reporting-hosts: every host that sent logs, last seen per host, hours clamped, cached', async () => {
  let n = 0; const seen = [];
  const ch = { query: async (sql, p) => { n++; seen.push([sql, p]); return [{ host: 'srv-dc1', ip: '::ffff:10.1.1.10', src_id: 'win-servers-trial', last_seen: '2026-10-13T20:00:00Z', events: '1200' }, { host: 'srv-exch1', ip: '', src_id: 'win-servers-trial', last_seen: '2026-10-10T08:00:00Z', events: 40 }]; } };
  const R = {}; H.register({ route: (m, p, h) => { R[m + ' ' + p] = h; } }, { ch, config: {}, log: { error() {} } });
  const call = async (q) => { const o = {}; await R['GET /api/soc/reporting-hosts']({ query: q, ok(x) { o.s = 200; o.b = x; }, fail(c, m) { o.s = c; o.e = m; } }); return o; };
  const r = await call({ hours: '99999' });
  assert.equal(r.s, 200, r.e);
  assert.equal(seen[0][1].h.value, 720, 'at most 30 days');
  assert.match(seen[0][0], /FROM siem\.events/); assert.match(seen[0][0], /GROUP BY host/);
  assert.deepEqual(r.b.hosts[0], { host: 'srv-dc1', ip: '10.1.1.10', src_id: 'win-servers-trial', last_seen: '2026-10-13T20:00:00Z', events: 1200 });
  await call({ hours: '99999' }); assert.equal(n, 1, 'cached for 60 s');
  await call({}); assert.equal(n, 2); assert.equal(seen[1][1].h.value, 168, 'default 7 days');
  const R2 = {}; H.register({ route: (m, p, h) => { R2[m + ' ' + p] = h; } }, { config: {}, log: { error() {} } });
  const o = {}; await R2['GET /api/soc/reporting-hosts']({ query: {}, ok() {}, fail(c) { o.s = c; } }); assert.equal(o.s, 503);
});
