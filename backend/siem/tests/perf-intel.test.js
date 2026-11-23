// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Database performance intelligence (engine/db-audit/perf-intel.js) over SYNTHETIC perf series, wait classes and Top SQL: the normal band
// per hour of day (3+ earlier days), CPU saturation only when CPU dominates, an unusual load episode with its dominant wait class, the bottleneck diagnosis (CPU, I/O, commit,
// concurrency, row locks, parsing) with evidence, SQL regressions against 7 days (slower, plan change, new), CPU headroom trend and date,
// itemised health; not measured without a series; routes: viewer reads, validation, the advisor refuses a viewer, a service identity and AI off.
const test = require('node:test');
const assert = require('node:assert/strict');
const PI = require('../engine/db-audit/perf-intel');
const { fakeApi } = require('./soc-fakes');

const H = 3600000, DAY = 86400000, NOW = Date.parse('2026-11-19T09:00:00Z'), STEP = 15 * 60000;
function perf(spike) {
  const ts = [], aas = [], cpuc = [], io = [], cpu = [];
  for (let t = NOW - 7 * DAY; t <= NOW; t += STEP) {
    const h = new Date(t + 3 * H).getUTCHours(), base = h >= 8 && h <= 16 ? 3 + (t / STEP % 3) * 0.1 : 1 + (t / STEP % 2) * 0.1, day = Math.floor((NOW - t) / DAY);
    let v = base * (1 + (6 - day) * 0.04); if (spike && NOW - t <= 2 * H && NOW - t >= H) v = 14;
    ts.push(t); aas.push(v); cpuc.push(4); cpu.push(v * 0.3); io.push(v * 0.6);
  }
  return { step_s: 900, series: { ts, aas, cpu_count: cpuc }, summary: { cpu_count: 4, executions_s_avg: 100, hard_parses_s_avg: 9 }, thresholds: { seq_read_ms: 10, log_file_sync_ms: 5 },
    aas_by_class: { ts, classes: [{ key: 'cpu', name: 'CPU', values: cpu }, { key: 'uio', name: 'User I/O', values: io }] },
    wait_classes: [{ class: 'User I/O', dbtime_pct: 62 }, { class: 'CPU', dbtime_pct: 30 }, { class: 'Commit', dbtime_pct: 3 }],
    wait_events: [{ event: 'db file sequential read', avg_ms: 18 }, { event: 'log file sync', avg_ms: 9 }], efficiency: { latest: { soft_parse_pct: 95 } }, instance: { key: 'db1|PRD', instance: 'PRD', host: 'db1' }, instances: [{ key: 'db1|PRD' }] };
}
const sqlNow = { sql: [{ sql_id: 'a1', executions: 500, ela_ms_exec: 80, elapsed_s: 40, plan_change: { worse: true } }, { sql_id: 'b2', executions: 100, ela_ms_exec: 10, elapsed_s: 1 }, { sql_id: 'n9', executions: 5, ela_ms_exec: 900, elapsed_s: 4.5 }], plan_changes: [] };
const sqlBase = { sql: [{ sql_id: 'a1', executions: 3000, ela_ms_exec: 20 }, { sql_id: 'b2', executions: 700, ela_ms_exec: 9 }] };

test('baseline, unusual episode, diagnosis, regressions, headroom and health', () => {
  const v = PI.analyse({ perf: perf(true), sqlNow, sqlBase, now: NOW });
  assert.equal(v.baseline.hours, 24); assert.ok(v.baseline.days >= 6);
  assert.ok(v.last24.length > 90 && v.last24.every((p) => p.median != null), 'normal band behind the last 24 hours');
  assert.equal(v.episodes.length, 1); assert.equal(v.episodes[0].peak, 14); assert.equal(v.episodes[0].dominant, 'User I/O'); assert.match(v.episodes[0].why, /usual/);
  const d = v.diagnosis.map((x) => x.title); assert.ok(!d.includes('CPU saturation') && d.includes('I/O bound') && d.includes('Slow commits') && d.includes('Too much parsing'), d.join(','));
  assert.equal(v.diagnosis[0].severity, 'high'); assert.match(v.diagnosis.find((x) => x.title === 'I/O bound').evidence, /18 ms \(threshold 10\)/);
  assert.equal(v.regressions[0].sql_id, 'a1'); assert.equal(v.regressions[0].kind, 'plan'); assert.equal(v.regressions[0].ratio, 4); assert.equal(v.regressions[0].extra_s, 30);
  assert.ok(!v.regressions.some((r) => r.sql_id === 'b2'), '10 ms against 9 ms is not a regression'); assert.ok(v.regressions.some((r) => r.sql_id === 'n9' && r.kind === 'new'));
  assert.ok(v.headroom && v.headroom.peak_pct_by_day.length >= 7 && v.headroom.slope_pct_day > 0, JSON.stringify(v.headroom));
  assert.ok(v.health.score < 100 && v.health.items.some((i) => /unusual load/.test(i.label)));
  const quiet = PI.analyse({ perf: perf(false), sqlNow: null, sqlBase: null, now: NOW }); assert.equal(quiet.episodes.length, 0, 'no spike, no episode');
  const none = PI.analyse({ perf: { series: {} }, now: NOW }); assert.equal(none.health.score, null); assert.match(none.baseline.why, /needs 3 earlier days/);
});

test('routes: viewer reads, validation, the advisor refuses a viewer, a service identity and AI off', async () => {
  const api = fakeApi({ realRanks: true }); const asked = [];
  const deps = { now: () => NOW, config: { netops: { ai: { enabled: false } } }, oracle_perf: { perf: async (q) => { asked.push(q); return perf(true); }, topsql: async (q) => (q.period === '24h' ? sqlNow : sqlBase) } };
  PI.register(api, deps, '/api/soc', (ctx) => Object.assign({}, ctx.query || {}, { _sql_text: false }));
  let r = await api.call('GET', '/api/soc/db/oracle/perf-intel?instance=db1|PRD', { role: 'viewer' }); assert.equal(r.status, 200, JSON.stringify(r.body));
  assert.equal(r.body.instance.instance, 'PRD'); assert.equal(asked[0].from, NOW - 7 * DAY); assert.equal(r.body.ai.enabled, false);
  r = await api.call('GET', '/api/soc/db/oracle/perf-intel?instance=' + 'x'.repeat(300), { role: 'viewer' }); assert.equal(r.status, 400); assert.match(r.body.error, /instance/);
  r = await api.call('POST', '/api/soc/db/oracle/perf-intel/ask', { role: 'viewer', body: { question: 'why is it slow?' } }); assert.equal(r.status, 403);
  r = await api.call('POST', '/api/soc/db/oracle/perf-intel/ask', { role: 'operator', user: 'svc:bot', body: { question: 'why is it slow?' } }); assert.equal(r.status, 403);
  r = await api.call('POST', '/api/soc/db/oracle/perf-intel/ask', { role: 'operator', user: 'ali', body: { question: 'why is it slow?' } }); assert.equal(r.status, 503); assert.match(r.body.error, /AI switched off/);
});

test('CPU saturation is called when the load passes the CPU count and CPU dominates', () => {
  const p = perf(true); p.wait_classes = [{ class: 'CPU', dbtime_pct: 75 }, { class: 'User I/O', dbtime_pct: 10 }]; p.wait_events = [];
  const v = PI.analyse({ perf: p, now: NOW }); const c = v.diagnosis.find((x) => x.title === 'CPU saturation');
  assert.ok(c); assert.equal(c.severity, 'high'); assert.match(c.evidence, /peak load 14 AAS on 4 CPUs; CPU is 75% of DB time/);
});
