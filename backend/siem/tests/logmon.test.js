// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Log Monitor & Analysis (engine/api/logmon.js): message templates (variable parts masked, constant words kept), pattern mining per
// source type with NEW / SPIKE / steady / DROPPED against the previous window of the same length, the sample notice when the window
// holds more than was mined, overview figures (rate against the median, warning share, stacked series of the busiest sources),
// roles (analyst and above; viewer refused) and validation errors that name the field. SYNTHETIC events through a stub search.
const test = require('node:test');
const assert = require('node:assert/strict');
const LM = require('../engine/api/logmon');

const H = 3600000, NOW = Date.parse('2026-11-14T08:00:00Z');
function ev(ts, src_type, message, host = 'fw-syn', severity = 0) { return { ts, src_type, message, host, severity }; }
function stubSearch(events) {
  const inRange = (from, to, q) => events.filter((e) => e.ts >= from && e.ts < to && (!q || !/src_type:"([^"]+)"/.test(q) || e.src_type === /src_type:"([^"]+)"/.exec(q)[1]));
  return {
    calls: [],
    async histogram({ q, from, to, buckets }) { const step = Math.ceil((to - from) / buckets), out = Array.from({ length: buckets }, (_, i) => ({ t: from + i * step, n: 0 })); for (const e of inRange(from, to, q)) out[Math.min(buckets - 1, Math.floor((e.ts - from) / step))].n++; return { buckets: out, step_ms: step }; },
    async top({ q, from, to, field, limit }) { const m = new Map(); for (const e of inRange(from, to, q)) m.set(e[field], (m.get(e[field]) || 0) + 1); return { values: [...m].map(([v, n]) => ({ v, n })).sort((a, b) => b.n - a.n).slice(0, limit) }; },
    async fetchEvents({ q, from, to, limit }) { return inRange(from, to, q).sort((a, b) => b.ts - a.ts).slice(0, limit); },
  };
}
function routes(search) {
  const R = {}; LM.register({ route: (m, p, h) => { R[m + ' ' + p] = h; } }, { search, now: () => NOW });
  const RANK = { viewer: 0, analyst: 1, operator: 2, admin: 3 };
  return async (p, role, body) => {
    const ctx = { role, body, need(r) { if (RANK[role] < RANK[r]) throw Object.assign(new Error('requires ' + r), { status: 403 }); } };
    try { return { status: 200, body: await R['POST ' + p](ctx) }; } catch (e) { return { status: e.status || 500, error: e.message }; }
  };
}

test('template: IPs, MACs, GUIDs, e-mail, numbers, times and variable key=value values are masked; words stay', () => {
  assert.equal(LM.template('Accepted password for root from 10.1.2.3 port 52144 ssh2'), 'Accepted password for root from <ip> port <n> ssh2');
  assert.equal(LM.template('Accepted password for root from 10.9.9.9 port 1 ssh2'), LM.template('Accepted password for root from 10.1.2.3 port 52144 ssh2'));
  assert.equal(LM.template('Interface Gi1/0/24 changed state to up'), 'Interface Gi<n>/<n>/<n> changed state to up');
  assert.equal(LM.template('srcip=10.0.0.5 dstport=443 action=deny policy="Block social"'), 'srcip=<ip> dstport=<*> action=deny policy=<*>');
  assert.equal(LM.template('device 3c52.82aa.0001 id 1b4e28ba-2fa1-11d2-883f-0016d3cca427 user a.syn@as.example at 2026-11-14 07:01:02'), 'device <mac> id <guid> user <email> at <time>');
  assert.equal(LM.template(''), '(empty message)');
});

test('patterns: NEW, SPIKE, steady and DROPPED against the previous window; worst severity, hosts, sample', async () => {
  const E = [];
  for (let i = 0; i < 20; i++) E.push(ev(NOW - 30 * H + i * 60000, 'linux', 'Accepted password for svc from 10.0.0.' + i + ' port ' + (4000 + i) + ' ssh2', 'srv-a'));   // previous window
  for (let i = 0; i < 20; i++) E.push(ev(NOW - 6 * H + i * 60000, 'linux', 'Accepted password for svc from 10.0.1.' + i + ' port ' + (5000 + i) + ' ssh2', 'srv-a'));    // steady
  for (let i = 0; i < 3; i++) E.push(ev(NOW - 30 * H + i * 60000, 'fortigate', 'srcip=10.0.0.' + i + ' action=deny policy="geo"'));                                        // spike: 3 -> 40
  for (let i = 0; i < 40; i++) E.push(ev(NOW - 5 * H + i * 30000, 'fortigate', 'srcip=10.2.0.' + (i % 7) + ' action=deny policy="geo"', 'fw-' + (i % 2), i === 5 ? 3 : 1));
  for (let i = 0; i < 12; i++) E.push(ev(NOW - 40 * H + i * 60000, 'windows', 'The backup job ' + i + ' finished'));                                                         // dropped
  E.push(ev(NOW - 1 * H, 'windows', 'Audit log was cleared by admin.syn', 'dc-syn', 4));                                                                                     // new + rare
  const call = routes(stubSearch(E));
  const r = await call('/api/soc/logmon/patterns', 'analyst', {}); assert.equal(r.status, 200, r.error);
  const P = r.body, find = (re) => P.patterns.find((p) => re.test(p.template));
  assert.equal(P.total, 61); assert.equal(P.mined, 61); assert.equal(P.sampled, false); assert.equal(P.note, null);
  const nw = find(/Audit log was cleared/); assert.equal(nw.status, 'new'); assert.equal(nw.severity, 'critical'); assert.equal(nw.hosts, 1);
  const sp = find(/action=deny/); assert.equal(sp.status, 'spike'); assert.equal(sp.n, 40); assert.equal(sp.before, 3); assert.equal(sp.hosts, 2); assert.equal(sp.severity, 'high');
  const st = find(/Accepted password/); assert.equal(st.status, 'steady'); assert.equal(st.n, 20); assert.equal(st.before, 20); assert.match(st.sample, /10\.0\.1\.19/, 'the newest line is the sample');
  assert.equal(P.patterns[0].status, 'new', 'new first, then spikes');
  assert.ok(P.dropped.some((d) => /backup job <n> finished/.test(d.template) && d.before === 12));
  assert.deepEqual(P.summary, { patterns: 3, new: 1, spike: 1, dropped: 1, rare: 1 });
});

test('patterns: a window larger than the mining limit says it is a sample', async () => {
  const E = []; for (let i = 0; i < 400; i++) E.push(ev(NOW - 2 * H + i * 1000, 'syslog', 'link flap on port ' + i));
  const r = await routes(stubSearch(E))('/api/soc/logmon/patterns', 'analyst', { limit: 100 });
  assert.equal(r.body.mined, 100); assert.equal(r.body.sampled, true); assert.match(r.body.note, /newest 100 of 400 events/);
});

test('overview: totals, rate against the median, warning share, top values and the busiest sources stacked', async () => {
  const E = [];
  for (let i = 0; i < 48; i++) for (let j = 0; j < 10; j++) E.push(ev(NOW - 24 * H + i * 1800000 + j, j < 7 ? 'fortigate' : 'windows', 'x', j < 5 ? 'fw-syn' : 'dc-syn', j === 9 ? 2 : 0));
  const r = await routes(stubSearch(E))('/api/soc/logmon/overview', 'analyst', {}); assert.equal(r.status, 200, r.error);
  const O = r.body;
  assert.equal(O.total, 480); assert.equal(O.severity.medium, 48); assert.equal(O.warn_share_pct, 10);
  assert.deepEqual(O.top.sources.map((x) => x.v), ['fortigate', 'windows']);
  assert.equal(O.series.length, 2); assert.equal(O.series[0].buckets.reduce((s, n) => s + n, 0), 336);
  assert.equal(O.rate.median_per_min, O.rate.last_per_min, 'an even flow reads as normal');
  assert.equal(O.rate.partial, true, 'a window ending now has a filling last bucket');
});

test('roles and validation: viewer refused; bad times, inverted and over-long windows, limit out of range name the field', async () => {
  const call = routes(stubSearch([]));
  assert.equal((await call('/api/soc/logmon/overview', 'viewer', {})).status, 403);
  assert.equal((await call('/api/soc/logmon/patterns', 'viewer', {})).status, 403);
  let r = await call('/api/soc/logmon/overview', 'analyst', { from: 'yesterday-ish' }); assert.equal(r.status, 400); assert.match(r.error, /from must be a time/);
  r = await call('/api/soc/logmon/overview', 'analyst', { from: NOW, to: NOW - H }); assert.equal(r.status, 400); assert.match(r.error, /from must be before to/);
  r = await call('/api/soc/logmon/overview', 'analyst', { from: NOW - 40 * 24 * H, to: NOW }); assert.equal(r.status, 400); assert.match(r.error, /at most 31 days/);
  r = await call('/api/soc/logmon/patterns', 'analyst', { limit: 5 }); assert.equal(r.status, 400); assert.match(r.error, /limit/);
  r = await call('/api/soc/logmon/overview', 'analyst', { q: 'x'.repeat(5000) }); assert.equal(r.status, 400); assert.match(r.error, /q/);
  r = await call('/api/soc/logmon/overview', 'operator', { from: '2026-11-13T08:00:00Z', to: '2026-11-14T08:00:00Z', extra: 'dropped' }); assert.equal(r.status, 200); assert.equal(r.body.total, 0);
});
