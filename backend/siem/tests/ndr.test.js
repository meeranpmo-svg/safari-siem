// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// NDR over the traffic logs: beacon regularity (a jittery series is not a beacon), exfiltration and lateral movement against the
// host's own history, a new destination country, the itemised host risk, one alert per host + kind + destination a day, a failing
// query said and the rest still run, four-eyes suppressions; routes: roles and the refused case, validation, audit.
// Addresses are SYNTHETIC (RFC 1918 / RFC 5737).
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { createState } = require('../engine/soc/state');
const N = require('../engine/soc/ndr');

const NOW = Date.parse('2026-11-25T12:00:00Z'), TODAY = '2026-11-25';
const days = (n) => Array.from({ length: n }, (_, i) => new Date(NOW - (i + 1) * 86400000).toISOString().slice(0, 10));
function fakeCh({ failOn } = {}) {
  const seen = [];
  const t0 = NOW / 1000 - 86400;
  return { seen, query: async (sql) => {
    const tag = (sql.match(/q:ndr_(\w+)/) || [])[1]; seen.push(tag);
    if (tag === failOn) throw new Error('synthetic ClickHouse error');
    if (tag === 'beacon') return [
      { src_ip: '10.1.1.5', dst_ip: '203.0.113.9', dst_port: 443, n: 40, t: Array.from({ length: 40 }, (_, i) => t0 + i * 300 + (i % 2)) },
      { src_ip: '10.1.1.6', dst_ip: '198.51.100.4', dst_port: 443, n: 30, t: Array.from({ length: 30 }, (_, i) => t0 + i * 300 + ((i * 7919) % 600)) }];
    if (tag === 'exfil') return days(14).map((d) => ({ src_ip: '10.1.1.7', d, b: 20e6 + (d.charCodeAt(9) % 3) * 1e6 })).concat([{ src_ip: '10.1.1.7', d: TODAY, b: 900e6 }, { src_ip: '10.1.1.8', d: TODAY, b: 900e6 }]);
    if (tag === 'lateral') return days(14).map((d) => ({ src_ip: '10.1.1.9', d, n: 0 })).concat([{ src_ip: '10.1.1.9', d: TODAY, n: 12 }], days(14).map((d) => ({ src_ip: '10.1.1.10', d, n: 30 })), [{ src_ip: '10.1.1.10', d: TODAY, n: 31 }]);
    if (tag === 'country') return [{ c: 'Synthetica', fresh: 1, n: 3, host: '10.1.1.5', b: 4000 }];
    return [];
  } };
}
function mk(opts = {}) {
  const state = createState({ dir: fs.mkdtempSync(path.join(os.tmpdir(), 'ndr-')) }), raised = [], ch = fakeCh(opts);
  const X = N.createNdr({ ch, db: 'siem', state, alerts: { raise: (a) => raised.push(a) }, now: () => NOW });
  return { X, raised, state, ch };
}

test('beacon: regular gaps are a beacon, jittery ones are not', () => {
  const base = 1e9;
  assert.equal(N.beacon(Array.from({ length: 20 }, (_, i) => base + i * 60)).regular, true);
  const jit = (i) => Math.floor(Math.abs(Math.sin(i * 12.9898) * 43758.5453) % 50);
  assert.equal(N.beacon(Array.from({ length: 20 }, (_, i) => base + i * 60 + jit(i))).regular, false);
  assert.equal(N.beacon([base, base + 5]), null, 'too few connections');
  assert.equal(N.beacon(Array.from({ length: 20 }, (_, i) => base + i * 2)).regular, false, 'every 2 s is a stream, not a beacon');
});

test('run: detections against each host\'s own history, risk itemised, alerts once a day, failures said', async () => {
  const { X, raised } = mk();
  const r = await X.run();
  const k = (kind) => r.detections.filter((d) => d.kind === kind).map((d) => d.host);
  assert.deepEqual(k('beacon'), ['10.1.1.5'], 'only the regular series');
  assert.deepEqual(k('exfil'), ['10.1.1.7'], 'a host without 7 days of history is not judged');
  assert.deepEqual(k('lateral'), ['10.1.1.9'], 'a host that always does it (an admin jump box) is not flagged');
  assert.deepEqual(k('country'), ['10.1.1.5']);
  const h5 = r.hosts.find((h) => h.host === '10.1.1.5'); assert.equal(h5.risk, 45); assert.deepEqual(h5.reasons.map((x) => x.kind).sort(), ['beacon', 'country']);
  assert.equal(r.hosts[0].host, '10.1.1.5', 'ranked by risk');
  assert.equal(raised.length, 3, 'beacon, exfil, lateral raise; a new country does not');
  assert.ok(raised.every((a) => a.rule_type === 'ndr' && a.tags.includes('ndr')) && raised.find((a) => a.rule_id === 'ndr-beacon').tags.includes('T1071'));
  await X.run(); assert.equal(raised.length, 3, 'not raised again the same day');
  const tr = X.view().trend; assert.equal(tr.length, 1, 'one day of history'); assert.equal(tr[0].date, new Date(NOW).toISOString().slice(0, 10)); assert.equal(tr[0].beacon + tr[0].exfil + tr[0].lateral + tr[0].country, r.detections.length, 'the day counts every detection by kind');
  const f = mk({ failOn: 'exfil' }), r2 = await f.X.run();
  assert.match(r2.errors.join(), /exfil: synthetic ClickHouse error/); assert.ok(r2.detections.some((d) => d.kind === 'beacon'), 'the other detections still run');
});

test('routes: roles, validation, four-eyes suppression that then hides the detection, audit', async () => {
  const { state, ch } = mk();
  const R = {}, audits = [], RANK = { viewer: 1, analyst: 2, operator: 3, admin: 4 };
  N.register({ route: (m, p, h) => { R[m + ' ' + p] = h; } }, { config: { clickhouse: { database: 'siem' } }, state, ch, alerts: { raise() {} }, log: { warn() {}, info() {}, error() {} }, noTimer: true, now: () => NOW });
  const call = async (m, p, b, role = 'analyst', user) => {
    const o = {}, u = user || role + '.syn', params = {}; let key = '/api/soc' + p; const mm = p.match(/^\/ndr\/suppressions\/([^/]+)\/decide$/); if (mm) { params.id = mm[1]; key = '/api/soc/ndr/suppressions/:id/decide'; }
    const ctx = { role, user: u, body: b, params, audit: (a, t, d) => audits.push({ a, t, d, by: u }), ok(x) { o.s = 200; o.b = x; }, fail(c, msg) { o.s = c; o.e = msg; }, need(r) { if ((RANK[role] || 0) >= (RANK[r] || 0)) return true; this.fail(403, 'forbidden'); return false; } };
    const rv = await R[m + ' ' + key](ctx); if (o.s === undefined) { o.s = 200; o.b = rv; } return o;
  };
  assert.equal((await call('GET', '/ndr', undefined, 'viewer')).s, 403, 'it names hosts');
  assert.equal((await call('GET', '/ndr')).b.ran, false);
  assert.equal((await call('POST', '/ndr/run', {}, 'analyst')).s, 403);
  assert.equal((await call('POST', '/ndr/run', {}, 'operator')).s, 200);
  assert.ok((await call('GET', '/ndr')).b.detections.some((d) => d.kind === 'beacon'));
  let r = await call('POST', '/ndr/suppressions', { host: 'not-an-ip', kind: 'beacon', reason: 'synthetic reason here' }); assert.equal(r.s, 400); assert.match(r.e, /host/);
  r = await call('POST', '/ndr/suppressions', { host: '10.1.1.5', reason: 'synthetic reason here' }); assert.equal(r.s, 400); assert.match(r.e, /dst or kind/);
  r = await call('POST', '/ndr/suppressions', { host: '10.1.1.5', dst: '203.0.113.9:443', reason: 'the vendor update check (synthetic)' }, 'analyst', 'ana.syn'); assert.equal(r.s, 200, r.e); const sid = r.b.id;
  assert.equal((await call('POST', `/ndr/suppressions/${sid}/decide`, { decision: 'approved' }, 'admin', 'ana.syn')).s, 403, 'proposer');
  r = await call('POST', `/ndr/suppressions/${sid}/decide`, { decision: 'approved' }, 'admin', 'ai:soc'); assert.equal(r.s, 403); assert.match(r.e, /only a person/);
  assert.equal((await call('POST', `/ndr/suppressions/${sid}/decide`, { decision: 'approved' }, 'operator', 'op.syn')).s, 403, 'no security scope');
  assert.equal((await call('POST', `/ndr/suppressions/${sid}/decide`, { decision: 'approved' }, 'admin', 'sec.syn')).s, 200);
  const after = (await call('POST', '/ndr/run', {}, 'operator')).b; assert.ok(!after.detections.some((d) => d.kind === 'beacon')); assert.equal(after.suppressed, 1);
  for (const a of ['ndr.run', 'ndr.suppression.propose', 'ndr.suppression.approve']) assert.ok(audits.some((x) => x.a === a), 'audited: ' + a);
});
