// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Portal traffic (engine/soc/webtraffic.js): sites from the nginx access logs, totals, series per bucket, pages, error paths,
// latency only when the log format carries request time, countries as the firewall logged each client IP (unseen counted,
// never guessed), client IPs only for operators (PDPL), parameters only, audit. Stub ClickHouse answering by tag.
const test = require('node:test');
const assert = require('node:assert/strict');
const wt = require('../engine/soc/webtraffic');

const NOW = Date.UTC(2026, 9, 26, 10, 0);
function harness(answers) {
  const calls = [], routes = {}, audits = [];
  const ch = { query: async (sql, p) => { const tag = /^\/\*q:([a-z_0-9]+)\*\//.exec(sql)[1]; calls.push({ tag, sql, p }); return (answers[tag] || []).map((r) => Object.assign({}, r)); } };
  wt.register({ route: (m, p, fn) => { routes[m + ' ' + p] = fn; } }, { ch, now: () => NOW, config: {} });
  const call = async (query, role = 'viewer') => { let out = null; const ctx = { query, role, user: 'u.syn', ok: (b) => { out = { status: 200, body: b }; return out; }, fail: (s, m) => { out = { status: s, error: m }; return out; }, audit: (a, t, d) => audits.push({ a, t, d }) };
    await routes['GET /api/soc/web/traffic'](ctx); return out; };
  return { call, calls, audits };
}
const A = {
  wt_sites: [{ site: 'portal.corpgroup.test', n: 12000 }, { site: 'intranet.corpgroup.test', n: 400 }],
  wt_tot: [{ n: 12000, u: 3100, now5: 42, by: 900000000, s2: 10800, s3: 600, s4: 500, s5: 100 }],
  wt_rt: [{ n: 11000, p50: 0.12, p95: 1.84, mx: 9.3 }],
  wt_series: [{ k: 0, s2: 100, s3: 5, s4: 4, s5: 1, by: 1000, p95: 1.5 }, { k: 3, s2: 50, s3: 0, s4: 0, s5: 9, by: 500, p95: 4.2 }],
  wt_pages: [{ pth: '/claims/new', n: 3000, e5: 40, u: 900 }], wt_errs: [{ pth: '/api/quote', e4: 120, e5: 60, cs: ['404', '502'] }],
  wt_codes: [{ c: '200', n: 10800 }, { c: '502', n: 60 }],
  wt_ips: [{ ip: '203.0.113.50', e4: 300, e5: 0, n: 320 }],
  wt_vis: [{ ip: '198.51.100.7', n: 50 }, { ip: '198.51.100.8', n: 20 }, { ip: '203.0.113.50', n: 320 }, { ip: '192.0.2.99', n: 5 }],
  wt_geo: [{ ip: '198.51.100.7', c: 'Saudi Arabia' }, { ip: '198.51.100.8', c: 'Saudi Arabia' }, { ip: '203.0.113.50', c: 'Netherlands' }],
};

test('sites first, then one site: totals, latency, series, pages, errors, countries from the firewall', async () => {
  const h = harness(A);
  const s0 = (await h.call({})).body; assert.equal(s0.site, null); assert.equal(s0.sites[0].site, 'portal.corpgroup.test');
  const v = (await h.call({ site: 'portal.corpgroup.test', hours: '24' }, 'operator')).body;
  assert.equal(v.totals.requests, 12000); assert.equal(v.totals.visitors, 3100); assert.equal(v.totals.visitors_5min, 42); assert.equal(v.totals.ok_pct, 99.17);
  assert.deepEqual(v.latency, { p50_s: 0.12, p95_s: 1.84, max_s: 9.3, measured: 11000 });
  assert.equal(v.series.length, 96, '15-minute buckets for 24 h'); assert.equal(v.series[3].s5, 9); assert.equal(v.series[3].p95_s, 4.2); assert.equal(v.series[1].s2, 0);
  assert.equal(v.pages[0].path, '/claims/new'); assert.equal(v.error_paths[0].e5, 60);
  assert.deepEqual(v.countries.map((c) => [c.name, c.visitors]), [['Saudi Arabia', 2], ['Netherlands', 1]]);
  assert.deepEqual(v.not_seen_by_firewall, { visitors: 1, requests: 5 }, 'an IP the firewall did not log is counted, not guessed');
  assert.equal(v.error_ips[0].ip, '203.0.113.50'); assert.equal(v.error_ips[0].country, 'Netherlands');
  const tq = h.calls.find((c) => c.tag === 'wt_tot'); assert.equal(tq.p.s.value, 'portal.corpgroup.test'); assert.ok(!tq.sql.includes('portal.corpgroup.test'), 'site is a parameter');
  assert.deepEqual(h.calls.find((c) => c.tag === 'wt_geo').p.ips.value.sort(), ['192.0.2.99', '198.51.100.7', '198.51.100.8', '203.0.113.50']);
  assert.deepEqual(h.audits.at(-1), { a: 'web.traffic.view', t: 'portal.corpgroup.test', d: { hours: 24, ips: true } });
});

test('a viewer gets aggregates without client IPs; no request time in the log = latency not reported, never 0', async () => {
  const h = harness(Object.assign({}, A, { wt_rt: [{ n: 0 }] }));
  const v = (await h.call({ site: 'portal.corpgroup.test', hours: '168' })).body;
  assert.equal(v.error_ips, null); assert.ok(!h.calls.some((c) => c.tag === 'wt_ips'), 'the IP query is not even run');
  assert.equal(v.latency, null); assert.match(v.note, /add \$request_time/); assert.equal(v.series[0].p95_s, null);
  assert.equal(v.series.length, 168, 'hourly for 7 days');
  assert.equal((await h.call({ site: "x' OR 1=1" })).status, 400);
});
