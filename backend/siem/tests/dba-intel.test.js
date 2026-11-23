// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Database intelligence (engine/db-audit/dba-intel.js) over SYNTHETIC DBA status, conditions, capacity and snapshots: per-instance
// health itemised and an instance without a fresh reading not measured (left out of the fleet score); the capacity runway sorted by
// the date a tablespace fills; flapping (5+ openings in 7 days, each cleared within an hour) and recurring problems learned from 30
// days; an instance with more trouble than its own usual (robust z); the ranked worklist; routes: the viewer reads, the advisor
// refuses a viewer, a service identity and AI-off with the reason; the analysis is reproducible.
const test = require('node:test');
const assert = require('node:assert/strict');
const I = require('../engine/db-audit/dba-intel');
const routes = require('../engine/db-audit/dba-routes');
const { createState } = require('../engine/soc/state');
const { fakeApi, tmpDir, quietLog } = require('./soc-fakes');

const H = 3600000, DAY = 86400000, NOW = Date.parse('2026-11-19T08:00:00Z');
const inst = (o) => Object.assign({ instance: 'ORCLPRD', host: 'db1', db_name: 'PRD', role: 'PRIMARY', level: 'ok', open: { crit: 0, warn: 0 }, backup_age_h: 10, min_days_to_full: null, fra_pct: 40, sessions_pct: 30, dg_lag_s: 5 }, o);
function data() {
  const status = { instances: [inst({ instance: 'ORCLPRD', level: 'crit', open: { crit: 1, warn: 2 }, backup_age_h: 60, min_days_to_full: 9 }), inst({ instance: 'HRDB', host: 'db2' }), inst({ instance: 'OLD', host: 'db3', level: 'unknown' })] };
  const conditions = [];
  for (let i = 0; i < 6; i++) conditions.push({ metric: 'sessions_pct', instance: 'HRDB', host: 'db2', title: 'Sessions of the limit', since: NOW - (i + 1) * DAY, cleared: NOW - (i + 1) * DAY + 20 * 60000, status: 'cleared' });
  for (let i = 0; i < 3; i++) conditions.push({ metric: 'backup_age_h', instance: 'ORCLPRD', host: 'db1', title: 'Hours since the last good backup', since: NOW - (i * 9 + 2) * DAY, cleared: NOW - (i * 9 + 1) * DAY, status: 'cleared' });
  const capacity = { instances: [{ instance: 'ORCLPRD', host: 'db1', tablespaces: [{ name: 'USERS', used_pct: 91, growth_mb_day: 800, days_to_full: 9, history_days: 30 }, { name: 'IDX', used_pct: 50, growth_mb_day: 20, days_to_full: 400, history_days: 30 }, { name: 'FLAT', used_pct: 60, growth_mb_day: 0, days_to_full: null }], asm: [{ name: 'DATA', free_pct: 12 }] }] };
  const snaps = []; for (let d = 14; d >= 1; d--) { const day = new Date(NOW - d * DAY + 3 * H).toISOString().slice(0, 10); snaps.push({ id: day, day, at: NOW - d * DAY, fleet: 80, open: 1, inst: { 'ORCLPRD@db1': { open: d % 2 }, 'HRDB@db2': { open: 0 } } }); }
  return { status, conditions, capacity, snaps, now: NOW };
}

test('health, runway, learning, unusual and the worklist', () => {
  const v = I.analyse(data()), h = Object.fromEntries(v.health.map((x) => [x.instance, x]));
  assert.equal(h.OLD.score, null); assert.match(h.OLD.why, /not measured/);
  assert.equal(v.fleet.measured, 2); assert.equal(v.fleet.score, Math.round((h.ORCLPRD.score + 100) / 2));
  assert.equal(h.ORCLPRD.score, 100 - 18 - 12 - 20 - 20); assert.ok(h.ORCLPRD.items.some((i) => /last good backup 60 h ago/.test(i.label)));
  assert.equal(v.runway[0].name, 'USERS'); assert.equal(v.runway[0].date, '2026-11-28'); assert.ok(!v.runway.some((r) => r.name === 'FLAT'), 'no growth, no forecast'); assert.ok(v.runway.some((r) => r.kind === 'asm' && r.name === 'DATA'));
  const fl = v.learned.find((l) => l.metric === 'sessions_pct'); assert.equal(fl.flapping, true); assert.equal(fl.median_clear_min, 20); assert.match(fl.why, /threshold may be too tight/);
  const rc = v.learned.find((l) => l.metric === 'backup_age_h'); assert.equal(rc.recurring, true);
  assert.ok(v.unusual.some((u) => u.instance === 'ORCLPRD' && u.open === 3), JSON.stringify(v.unusual)); assert.ok(!v.unusual.some((u) => u.instance === 'HRDB'));
  assert.equal(v.worklist[0].title, 'ORCLPRD: 1 critical problem(s)'); assert.ok(v.worklist.some((w) => /USERS fills around 2026-11-28/.test(w.title))); assert.ok(v.worklist.some((w) => /is flapping/.test(w.title)));
  assert.deepEqual(I.analyse(data()), v, 'reproducible');
});

test('routes: viewer reads; the advisor refuses a viewer, a service identity, and says why when AI is off', async () => {
  const dir = tmpDir(), state = createState({ dir, log: quietLog });
  const ch = { async query() { return []; } };
  const api = fakeApi({ realRanks: true });
  const deps = { state, ch, now: () => NOW, noTimers: true, config: { dba: { scheduler: false }, netops: { ai: { enabled: false } } }, log: quietLog, reports: {} };
  try {
    routes.register(api, deps);
    let r = await api.call('GET', '/api/soc/db/dba/intel', { role: 'viewer' }); assert.equal(r.status, 200, JSON.stringify(r.body));
    assert.equal(r.body.fleet.score, null); assert.match(r.body.fleet.why, /no instance/); assert.equal(r.body.ai.enabled, false);
    assert.ok(state.collection('dba_intel_snaps').get('2026-11-19'), 'today snapshotted');
    r = await api.call('POST', '/api/soc/db/dba/intel/ask', { role: 'viewer', body: { question: 'what fills first?' } }); assert.equal(r.status, 403);
    r = await api.call('POST', '/api/soc/db/dba/intel/ask', { role: 'operator', user: 'svc:bot', body: { question: 'what fills first?' } }); assert.equal(r.status, 403);
    r = await api.call('POST', '/api/soc/db/dba/intel/ask', { role: 'operator', user: 'ali', body: { question: 'x' } }); assert.equal(r.status, 400); assert.match(r.body.error, /question/);
    r = await api.call('POST', '/api/soc/db/dba/intel/ask', { role: 'operator', user: 'ali', body: { question: 'what fills first?' } }); assert.equal(r.status, 503); assert.match(r.body.error, /AI switched off/);
  } finally { state.close(); require('fs').rmSync(dir, { recursive: true, force: true }); }
});

test('history: calendar per instance, MTTA / MTTR, noisy checks; the grid coloured against each threshold, grey when not sent', () => {
  const d = data();
  d.conditions.push({ metric: 'ts_used_pct', instance: 'ORCLPRD', host: 'db1', level: 'crit', title: 'Tablespace used', since: NOW - 2 * DAY, cleared: NOW - 2 * DAY + 3 * H, ack: { at: NOW - 2 * DAY + 10 * 60000, by: 'ahmed' }, status: 'cleared' });
  d.conditions.push({ metric: 'fra_pct', instance: 'ORCLPRD', host: 'db1', level: 'crit', title: 'Recovery area', since: NOW - 3 * H, status: 'open' });
  d.conditions.forEach((c) => { if (!c.level) c.level = 'warn'; });
  const thr = (id, inst) => ({ ts_used_pct: { warn: 87, crit: 95, enabled: true }, ts_days_to_full: { warn: 14, crit: 7, enabled: true }, backup_age_h: { warn: 26, crit: inst === 'HRDB' ? 100 : 48, enabled: true } }[id] || { warn: 80, crit: 90, enabled: true });
  d.status.instances[0].max_ts = { key: 'USERS', value: 96 }; d.status.instances[1].backup_age_h = 60; d.status.instances[1].fra_pct = null;
  const v = I.analyse(Object.assign(d, { thr }));
  assert.equal(v.history.days.length, 30);
  const cal = v.history.calendar.find((c) => c.instance === 'ORCLPRD'); assert.equal(cal.cells.length, 30); assert.ok(cal.bad_days >= 2, 'the critical days are marked');
  assert.equal(v.history.response.crit.opened, 2); assert.equal(v.history.response.crit.mtta_min, 10); assert.equal(v.history.response.crit.mttr_min, 180); assert.equal(v.history.response.crit.open_unacked, 1);
  const n = v.history.noisy.find((x) => x.metric === 'sessions_pct'); assert.equal(n.openings, 6); assert.equal(n.short_pct, 100); assert.match(n.why, /threshold to review/);
  const row = (i) => v.grid.rows.find((r) => r.instance === i), col = (id) => v.grid.columns.findIndex((c) => c.id === id);
  assert.equal(row('ORCLPRD').cells[col('ts_used_pct')].level, 'crit'); assert.equal(row('ORCLPRD').cells[col('ts_days_to_full')].level, 'warn', '9 days: under 14, above 7');
  assert.equal(row('ORCLPRD').cells[col('backup_age_h')].level, 'crit');
  assert.equal(row('HRDB').cells[col('backup_age_h')].level, 'warn', 'its own override (crit 100) applies');
  assert.equal(row('HRDB').cells[col('fra_pct')].level, 'na', 'not sent = grey, never green');
});

test('health counts kinds of problem: 218 long-query rows are one noisy kind, not a zero score; Do first names what they are', () => {
  const st = { instances: [{ instance: 'ESP1', host: 'ashs7a', level: 'crit', open: { crit: 219, warn: 0 }, backup_age_h: 5 }, { instance: 'HR', host: 'h2', level: 'crit', open: { crit: 1, warn: 0 } }] };
  const conds = [];
  for (let i = 0; i < 218; i++) conds.push({ metric: 'long_query_s', instance: 'ESP1', host: 'ashs7a', level: 'crit', status: 'open', since: NOW - (i % 29) * DAY - H });
  for (let i = 0; i < 60; i++) conds.push({ metric: 'long_query_s', instance: 'ESP1', host: 'ashs7a', level: 'crit', status: 'cleared', since: NOW - (i % 29) * DAY - 2 * H, cleared: NOW - (i % 29) * DAY - H });
  conds.push({ metric: 'fra_pct', instance: 'ESP1', host: 'ashs7a', level: 'crit', status: 'open', since: NOW - H });
  conds.push({ metric: 'instance_down', instance: 'HR', host: 'h2', level: 'crit', status: 'open', since: NOW - H });
  const v = I.analyse({ status: st, conditions: conds, now: NOW, labels: { long_query_s: 'Long-running query', fra_pct: 'Recovery area (FRA) used', instance_down: 'Instance down' } });
  const e = v.health.find((h) => h.instance === 'ESP1');
  assert.equal(e.score, 100 - 9 - 18, 'one noisy kind (half of 18) and one real kind - not 0');
  assert.ok(e.items.some((i) => /critical: Long-running query \(218 open\) - noisy check, counted half/.test(i.label)));
  assert.equal(v.health.find((h) => h.instance === 'HR').score, 82);
  const w = v.worklist.find((x) => /ESP1: 219 critical problem\(s\) of 2 kind/.test(x.title)); assert.ok(w, JSON.stringify(v.worklist.map((x) => x.title)));
  assert.match(w.why, /218 Long-running query \(noisy\), 1 Recovery area \(FRA\) used/);
  const f = v.worklist.find((x) => /ESP1: Long-running query fires constantly/.test(x.title)); assert.ok(f); assert.match(f.why, /review its threshold/);
  assert.ok(!v.worklist.some((x) => /long_query_s/.test(x.title)), 'never a raw metric id');
});
