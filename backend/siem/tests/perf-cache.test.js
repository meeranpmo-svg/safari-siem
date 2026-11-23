// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Database Dashboard loading: the fleet-wide ClickHouse aggregations behind capacity (instances 8 days, capacity 8 days, tablespace
// growth 60 days) ran on every request. They are now cached for 5 minutes, shared by callers that arrive together, served stale
// (up to an hour) while one refresh runs, and a failed query is never cached. Synthetic rows only.
const test = require('node:test');
const assert = require('node:assert/strict');
const { createOraclePerf } = require('../engine/db-audit/perf-api');

function fakeCh() {
  const calls = {}; let fail = false, gate = null;
  const kind = (sql) => (/perf:capacity/.test(sql) ? 'capacity' : /perf:growth/.test(sql) ? 'growth' : /perf:instances/.test(sql) ? 'instances' : 'other');
  return {
    calls, setFail(v) { fail = v; }, hold() { let open; gate = new Promise((r) => { open = r; }); return () => { const g = open; gate = null; g(); }; },
    async query(sql) {
      const k = kind(sql); calls[k] = (calls[k] || 0) + 1;
      if (gate) await gate;
      if (fail) throw new Error('clickhouse down (synthetic)');
      if (k === 'instances') return [{ host: 'db-syn-1', inst_v: 'SYNDB', db_v: 'SYNDB', last_v: '2026-11-20 08:00:00' }];
      if (k === 'growth') return [{ host: 'db-syn-1', inst_v: 'SYNDB', tbs_v: 'USERS', day_v: '2026-11-19', used_v: 100, max_v: 1000 }];
      return [];
    },
  };
}

test('capacity: the heavy ClickHouse queries run once per 5 minutes, not once per page load', async () => {
  let t = Date.parse('2026-11-20T08:00:00Z'); const ch = fakeCh();
  const P = createOraclePerf({ ch, now: () => t });
  await P.capacity({ role: 'viewer' });
  for (let i = 0; i < 5; i++) await P.capacity({ role: 'viewer' });
  assert.equal(ch.calls.capacity, 1); assert.equal(ch.calls.growth, 1); assert.equal(ch.calls.instances, 1);
  t += 5 * 60000 + 1;
  await P.capacity({ role: 'viewer' });   // stale: served at once, one refresh started
  await new Promise((r) => setImmediate(r));
  assert.equal(ch.calls.capacity, 2, 'refreshed after 5 minutes');
  const s = P.stats ? P.stats() : null; if (s) assert.ok(s.ch_cache_hits >= 5);
});

test('capacity: callers that arrive together share one query', async () => {
  const ch = fakeCh(); const P = createOraclePerf({ ch, now: () => Date.parse('2026-11-20T08:00:00Z') });
  const open = ch.hold();
  const all = Promise.all([P.capacity({}), P.capacity({}), P.capacity({})]);
  await new Promise((r) => setImmediate(r)); open(); await all;
  assert.equal(ch.calls.capacity, 1); assert.equal(ch.calls.growth, 1);
});

test('capacity: a failed query is not cached; the last good answer is served while ClickHouse is down', async () => {
  let t = Date.parse('2026-11-20T08:00:00Z'); const ch = fakeCh(); const P = createOraclePerf({ ch, now: () => t });
  const first = await P.capacity({});
  ch.setFail(true); t += 6 * 60000;
  const second = await P.capacity({});
  assert.deepEqual(second.instances.map((i) => i.instance), first.instances.map((i) => i.instance), 'last good answer served');
  await new Promise((r) => setImmediate(r));
  ch.setFail(false); t += 1000;
  await P.capacity({}); await new Promise((r) => setImmediate(r));
  assert.ok(ch.calls.capacity >= 3, 'the failure was not cached - it is asked again');
  // beyond an hour without a good answer the caller waits for a fresh query instead of old data
  ch.setFail(true); t += 2 * 3600000; const n = ch.calls.capacity;
  await P.capacity({}); assert.equal(ch.calls.capacity, n + 1);
});
