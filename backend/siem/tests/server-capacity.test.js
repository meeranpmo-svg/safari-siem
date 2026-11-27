// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Server capacity (engine/ops/server-capacity.js) over SYNTHETIC daily agent readings: a disk filling at a steady rate gets its date,
// memory rising gets its date, a flat server none; oversized, undersized and still learning; the last day's jump against the server's
// own history (robust z); the route: viewer reads, days validated, the query is read-only on the heartbeat, no store -> 503.
const test = require('node:test');
const assert = require('node:assert/strict');
const S = require('../engine/ops/server-capacity');
const { fakeApi } = require('./soc-fakes');

const day = (k) => new Date(Date.parse('2026-11-01T00:00:00Z') + k * 864e5).toISOString().slice(0, 10);
function rows() {
  const R = [];
  for (let k = 0; k < 20; k++) {
    R.push({ host: 'SRV-FILE-SYN', d: day(k), cpu95: 30, mem95: 50 + k, mem_gb: 64, disks: 'C:|100|60;D:|1000|' + (400 - k * 15) });          // D: +1.5 % a day, memory +1 a day
    R.push({ host: 'SRV-IDLE-SYN', d: day(k), cpu95: 5 + (k % 3), mem95: 25, mem_gb: 128, disks: 'C:|200|150' });
    R.push({ host: 'SRV-HOT-SYN', d: day(k), cpu95: 92, mem95: 70, mem_gb: 32, disks: 'C:|100|' + (k === 19 ? 20 : 50) });                     // last day: C: jumps
  }
  for (let k = 0; k < 3; k++) R.push({ host: 'SRV-NEW-SYN', d: day(k), cpu95: 40, mem95: 40, disks: 'C:|100|50' });
  return R;
}

test('forecasts, fit and the unusual day', () => {
  const r = S.analyse(rows(), { days: 30 }), by = Object.fromEntries(r.servers.map((s) => [s.host, s]));
  const d = by['SRV-FILE-SYN'].disks.find((k) => k.dev === 'D:'); assert.equal(d.days_to_95, 4, 'D: at 88.5 % growing 1.5 points a day');
  assert.ok(by['SRV-FILE-SYN'].mem_days_to_90 >= 20 && by['SRV-FILE-SYN'].mem_days_to_90 <= 22, 'memory 69 % +1 a day');
  assert.equal(by['SRV-IDLE-SYN'].cpu_days_to_90, null); assert.equal(by['SRV-IDLE-SYN'].fit, 'oversized'); assert.equal(by['SRV-HOT-SYN'].fit, 'undersized'); assert.equal(by['SRV-NEW-SYN'].fit, 'learning');
  assert.ok(r.findings.some((f) => f.code === 'disk-jump' && f.host === 'SRV-HOT-SYN'), 'the last-day jump against its own history');
  assert.ok(r.findings.some((f) => f.code === 'disk-trend' && f.host === 'SRV-FILE-SYN'));
  assert.equal(r.servers[0].host, 'SRV-FILE-SYN', 'what runs out first, first');
  assert.equal(S.daysTo([[0, 10], [1, 10]], 90), null);
});

test('route: viewer, days validated, read-only query on the heartbeat', async () => {
  const asked = []; const ch = { query: async (sql, params, opts) => { asked.push({ sql, opts }); return rows(); } };
  const api = fakeApi({ realRanks: true }); S.register(api, { ch, now: () => Date.parse('2026-11-21T00:00:00Z') });
  let r = await api.call('GET', '/api/soc/capacity/servers?days=3', { role: 'viewer' }); assert.equal(r.status, 400); assert.match(r.body.error, /days must be/);
  r = await api.call('GET', '/api/soc/capacity/servers', { role: 'viewer' }); assert.equal(r.status, 200, JSON.stringify(r.body)); assert.equal(r.body.kpis.servers, 4);
  assert.match(asked[0].sql, /action = 'agent-heartbeat'/); assert.equal(asked[0].opts.readonly, true); assert.ok(!/INSERT|ALTER|DROP/i.test(asked[0].sql));
  const api2 = fakeApi({ realRanks: true }); S.register(api2, {}); r = await api2.call('GET', '/api/soc/capacity/servers', { role: 'viewer' }); assert.equal(r.status, 503);
});
