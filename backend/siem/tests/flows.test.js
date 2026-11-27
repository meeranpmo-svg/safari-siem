// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Network flows (engine/soc/flows.js): the Network Flows page's data from the firewalls' traffic logs. Checked against a
// stub ClickHouse that answers each query by its tag: the summary's shape (empty buckets filled, countries / zones /
// ports / apps / dev shares), addresses only for analyst and above, the drill-down's slices and their validation, every
// user value passed as a ClickHouse parameter (never in the SQL text), an audit entry per view, and "not connected" when
// no firewall has sent a traffic log.
const test = require('node:test');
const assert = require('node:assert/strict');
const flows = require('../engine/soc/flows');

const NOW = Date.UTC(2026, 9, 20, 9, 0);
function fakeCh(answers) {
  const calls = [];
  return { calls, query: async (sql, params) => { const tag = /^\/\*q:([a-z_]+)\*\//.exec(sql)[1]; calls.push({ tag, sql, params }); return (answers[tag] || []).map((r) => Object.assign({}, r)); } };
}
function harness(answers) {
  const ch = fakeCh(answers), routes = {}, audits = [];
  flows.register({ route: (m, p, fn) => { routes[m + ' ' + p] = fn; } }, { ch, now: () => NOW, config: {} });
  const call = async (path, query, role = 'analyst') => {
    let out = null;
    const ctx = { query, role, user: 'syed', path, ok: (b) => { out = { status: 200, body: b }; return out; }, fail: (s, m) => { out = { status: s, error: m }; return out; }, audit: (a, t, d) => audits.push({ a, t, d }) };
    await routes['GET /api/soc' + path](ctx);
    return out;
  };
  return { ch, call, audits };
}
const ANSWERS = {
  hist: [{ b: 0, a: 10, d: 2, by: 5000 }, { b: 3, a: 4, d: 6, by: 0 }],
  countries: [{ c: 'United States', a: 8, d: 1, by: 4000 }, { c: 'RU', a: 0, d: 5, by: 0 }, { c: '', a: 1, d: 0, by: 0 }],
  zsrc: [{ z: 'wan', a: 9, d: 8 }], zdst: [{ z: 'lan', a: 14, d: 8 }],
  ports: [{ action: 'allowed', proto: 'tcp', port: 443, n: 12 }, { action: 'blocked', proto: 'tcp', port: 3389, n: 6 }],
  apps: [{ action: 'allowed', app: 'HTTPS', n: 12 }],
  firewalls: [{ host: 'FGT-HQ', src_type: 'fortigate', n: 22, last: NOW - 60000 }],
  talkers: [{ src_ip: '198.51.100.7', c: 'RU', dst_ip: '10.0.0.5', proto: 'tcp', port: 3389, app: '', flows: 5, deny: 5, by: 0 }],
  conv: [{ src_ip: '10.0.0.9', fw: 'FGT-HQ', app: 'HTTPS', dst_ip: '203.0.113.4', flows: 3, by: 9000 }],
  dev_port: [{ cur: 1, v: '443', n: 8 }, { cur: 1, v: '3389', n: 2 }, { cur: 0, v: '443', n: 5 }, { cur: 0, v: '22', n: 5 }],
  dev_country: [], dev_app: [{ cur: 1, v: 'HTTPS', n: 4 }],
  d_total: [{ a: 3, d: 2, by: 100, first: NOW - 1000, last: NOW }], d_src: [{ v: '198.51.100.7', n: 5, d: 2 }], d_dst: [], d_svc: [{ v: 'tcp/3389', n: 5, d: 2 }], d_country: [], d_zones: [],
};

test('network flows: summary from the firewalls\' logs, addresses only for analysts, drill-down, parameters only', async () => {
  const h = harness(ANSWERS);
  const r = await h.call('/flows/summary', { range: '60', dir: 'in', fw: 'FGT-HQ' });
  assert.equal(r.status, 200);
  const s = r.body;
  assert.equal(s.connected, true); assert.equal(s.fw, 'FGT-HQ'); assert.equal(s.range, 60);
  assert.equal(s.hist.length, 60, 'every bucket present'); assert.deepEqual(s.hist[3], { i: 3, t: s.from + 3 * s.step_ms, allow: 4, deny: 6, bytes: 0 }); assert.equal(s.hist[1].allow, 0);
  assert.equal(s.total, 22); assert.equal(s.denied, 8); assert.equal(s.bytes_reported, true);
  assert.deepEqual(s.countries.map((c) => c.name), ['United States', 'RU', ''], 'names as the firewall sent them (the page maps them)');
  assert.equal(s.talkers[0].svc, 'tcp/3389'); assert.equal(s.conv[0].bytes, 9000);
  assert.equal(s.dev[0].rows[0].v, '443'); assert.equal(s.dev[0].rows[0].now, 80); assert.equal(s.dev[0].rows[0].before, 50); assert.equal(s.dev[0].rows[1].before, 0);
  assert.deepEqual(s.dev[1].rows, [], 'no country data: nothing invented');
  assert.equal(s.dev[2].rows[0].before, null, 'no flows at all in the earlier window: "no earlier data", never 0 %');
  assert.equal(s.dev[2].previous_flows, 0);
  // parameters, never values in the SQL text
  for (const c of h.ch.calls) { assert.ok(!c.sql.includes('FGT-HQ'), c.tag + ': the device name is a parameter'); }
  assert.equal(h.ch.calls.find((c) => c.tag === 'hist').params.fw.value, 'FGT-HQ');
  assert.match(h.ch.calls.find((c) => c.tag === 'countries').sql, /isIPAddressInRange\(dst_ip, '10\.0\.0\.0\/8'\)/, 'inbound = to a private address');
  assert.deepEqual(h.audits.at(-1), { a: 'flows.view', t: 'FGT-HQ', d: { range: 60, dir: 'in', addresses: true } });

  // a viewer: the aggregates, no addresses, and no address query is even run
  const n0 = h.ch.calls.length;
  const v = (await h.call('/flows/summary', { range: '1440', dir: 'out' }, 'viewer')).body;
  assert.equal(v.talkers, null); assert.equal(v.conv, null); assert.equal(v.addresses_included, false); assert.equal(v.hist.length, 48); assert.equal(v.fw, 'all');
  assert.ok(!h.ch.calls.slice(n0).some((c) => c.tag === 'talkers' || c.tag === 'conv'));
  assert.match(h.ch.calls.slice(n0).find((c) => c.tag === 'countries').sql, /dst_country/, 'outbound: the destination country');
  assert.equal((await h.call('/flows/drill', { country: 'RU' }, 'viewer')).status, 403, 'the drill-down names addresses');

  // drill-downs
  const d = (await h.call('/flows/drill', { range: '60', country: 'RU', action: 'blocked', proto: 'TCP', port: '3389' })).body;
  assert.equal(d.allow, 3); assert.equal(d.top_src[0].v, '198.51.100.7'); assert.equal(d.top_svc[0].deny, 2);
  const dc = h.ch.calls.find((c) => c.tag === 'd_total');
  assert.equal(dc.params.v_country.value, 'RU'); assert.equal(dc.params.port.value, 3389); assert.equal(dc.params.proto.value, 'tcp'); assert.ok(!dc.sql.includes("'RU'"));
  const b = (await h.call('/flows/drill', { range: '60', bucket: '3' })).body;
  assert.equal(b.from, NOW - 3600000 + 3 * 60000); assert.equal(b.to, NOW - 3600000 + 4 * 60000);
  for (const [q, msg] of [[{}, /choose a slice/], [{ bucket: '60' }, /invalid bucket/], [{ port: '70000' }, /invalid port/], [{ action: 'maybe' }, /invalid action/]]) {
    const x = await h.call('/flows/drill', Object.assign({ range: '60' }, q));
    assert.equal(x.status, 400); assert.match(x.error, msg);
  }
  assert.equal(h.audits.filter((x) => x.a === 'flows.drill').length, 2);
});

test('network flows: no firewall traffic logs → not connected, nothing drawn', async () => {
  const h = harness({});
  const s = (await h.call('/flows/summary', {})).body;
  assert.equal(s.connected, false); assert.equal(s.total, 0); assert.equal(s.hist.length, 60);
  assert.deepEqual(s.countries, []); assert.deepEqual(s.talkers, []); assert.equal(s.bytes_reported, false);
  assert.equal(s.range, 60, 'an unknown range falls back to one hour');
});

test('mail on the wire: SMTP sessions by country inbound and outbound, sending addresses only for analysts, audited', async () => {
  const h = harness({ mail_hist: [{ b: 1, i: 7, o: 3, d: 2 }], mail_in: [{ c: 'United States', a: 5, d: 0 }, { c: 'CN', a: 0, d: 2 }], mail_out: [{ c: 'Germany', a: 3, d: 0 }],
    mail_fw: [{ n: 40 }], mail_src: [{ src_ip: '198.51.100.9', c: 'CN', n: 2, d: 2 }] });
  let r = await h.call('/flows/mail', { range: '1440' });
  assert.equal(r.status, 200); const m = r.body;
  assert.equal(m.connected, true); assert.equal(m.range, 1440); assert.equal(m.hist.length, 48); assert.deepEqual(m.hist[1], { i: 1, t: m.from + m.step_ms, inbound: 7, outbound: 3, deny: 2 });
  assert.deepEqual(m.inbound, { total: 7, denied: 2, countries: [{ name: 'United States', allow: 5, deny: 0 }, { name: 'CN', allow: 0, deny: 2 }] });
  assert.equal(m.outbound.total, 3); assert.equal(m.top_sources[0].src, '198.51.100.9');
  assert.match(h.ch.calls.find((c) => c.tag === 'mail_in').sql, /dst_port IN \(25, 465, 587\)/, 'SMTP ports only');
  assert.match(h.ch.calls.find((c) => c.tag === 'mail_out').sql, /isIPAddressInRange\(src_ip, '10\.0\.0\.0\/8'\)/, 'outbound = from a private address');
  assert.deepEqual(h.audits.at(-1), { a: 'flows.mail.view', t: 'smtp', d: { range: 1440, addresses: true } });
  r = await h.call('/flows/mail', { range: '60' }, 'viewer');
  assert.equal(r.body.top_sources, null, 'viewer: countries only, no addresses'); assert.equal(r.body.addresses_included, false);
  const empty = harness({});
  r = await empty.call('/flows/mail', {}); assert.equal(r.body.connected, false, 'no firewall logs: not connected'); assert.deepEqual(r.body.inbound.countries, []);
});

test('analysis: a minute of denies far above the window’s usual, the deny ratio, one country holding the denies, a moved share', () => {
  const F = require('../engine/soc/flows');
  const hist = Array.from({ length: 60 }, (_, i) => ({ i, t: i * 60000, allow: 100 + (i % 5), deny: i === 42 ? 900 : 40 + (i % 3), bytes: 1000 }));
  const total = hist.reduce((n, h) => n + h.allow + h.deny, 0), denied = hist.reduce((n, h) => n + h.deny, 0);
  const v = F.analyse({ hist, total, denied, countries: [{ name: 'SynLand', allow: 0, deny: Math.round(denied * 0.7), bytes: 0 }, { name: 'Other', allow: 0, deny: 100, bytes: 0 }],
    talkers: [{ svc: 'tcp/445 backup', bytes: 900 }, { svc: 'tcp/443', bytes: 100 }], dev: [{ label: 'Destination port', rows: [{ v: '3389', now: 30, before: 5 }] }] });
  assert.equal(v.anomalies[0].i, 42); assert.equal(v.anomalies[0].kind, 'denied'); assert.ok(v.anomalies[0].z >= 3.5);
  assert.ok(v.insights.some((s) => /minute\(s\) with denied traffic far above usual/.test(s)) && v.insights.some((s) => /SynLand is the source of 70%/.test(s)));
  assert.ok(v.insights.some((s) => /One conversation carries 90%/.test(s)) && v.insights.some((s) => /Destination port 3389 went up by 25 points/.test(s)));
  assert.deepEqual(F.analyse({ hist: [] }).anomalies, []);
});
