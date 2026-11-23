// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Security Operations Overview insights (engine/soc/overview-insights.js, GET {P}/soc/overview/insights): the 7-day volume forecast
// (withheld below 14 days, weekday pattern and level), rules new / surging / silent against their own 14 days (judged from 7),
// rule precision smoothed from 3 closures, entities ranked by the summed priority of their open alerts, SLA attainment per week,
// the analyst role (viewer refused). SYNTHETIC data only.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const OI = require('../engine/soc/overview-insights');
const { createState } = require('../engine/soc/state');
const { createAlerts } = require('../engine/soc/alerts');
const { createCases, DEFAULT_SLA } = require('../engine/soc/cases');
const routes = require('../engine/soc/analyst-routes');
const { fakeApi, tmpDir, quietLog } = require('./soc-fakes');

const H = 3600e3, DAY = 864e5, NOW = Date.parse('2026-11-18T09:00:00Z');   // a Wednesday in Riyadh
let seq = 0;
const al = (o) => Object.assign({ id: 'A' + (++seq), rule_id: 'R1', rule_name: 'Rule 1', severity: 2, status: 'new', entities: [], created: NOW - H }, o);

test('forecast: withheld below 14 days; a weekday pattern and the recent level carried into 7 days', () => {
  assert.match(OI.forecast([al({})], NOW).why, /needs 14 days/);
  const all = [];
  for (let d = 1; d <= 42; d++) { const t = NOW - d * DAY, wd = new Date(t + 3 * H).getUTCDay(), n = (wd === 5 || wd === 6) ? 2 : 10; for (let i = 0; i < n; i++) all.push(al({ created: t })); }
  const f = OI.forecast(all, NOW);
  assert.equal(f.forecast.length, 7);
  const fri = f.forecast.find((x) => new Date(x.day + 'T00:00:00Z').getUTCDay() === 5), sun = f.forecast.find((x) => new Date(x.day + 'T00:00:00Z').getUTCDay() === 0);
  assert.equal(fri.alerts, 2, 'Friday (weekend in the Kingdom) stays low'); assert.equal(sun.alerts, 10, 'Sunday is a working day');
  assert.equal(f.level, 1); assert.match(f.why, /a projection, not a promise/);
});

test('shifts: new, surging and silent rules against their own 14 days; judged from 7', () => {
  assert.match(OI.shifts([al({ created: NOW - 2 * DAY })], NOW).why, /from 7 days/);
  const all = [];
  for (let d = 1; d <= 14; d++) { for (let i = 0; i < 6; i++) all.push(al({ rule_id: 'QUIET', rule_name: 'Firewall deny', created: NOW - d * DAY - H })); all.push(al({ rule_id: 'BF', rule_name: 'Brute force', created: NOW - d * DAY - H }));
    for (let i = 0; i < 2; i++) all.push(al({ rule_id: 'STEADY', created: NOW - d * DAY - H })); }
  for (let i = 0; i < 9; i++) all.push(al({ rule_id: 'BF', rule_name: 'Brute force', created: NOW - 2 * H }));
  for (let i = 0; i < 4; i++) all.push(al({ rule_id: 'NEW', rule_name: 'Synthetic new detection', created: NOW - 3 * H }));
  for (let i = 0; i < 2; i++) all.push(al({ rule_id: 'STEADY', created: NOW - 2 * H }));
  const s = OI.shifts(all, NOW), k = Object.fromEntries(s.items.map((x) => [x.rule_id, x]));
  assert.equal(k.QUIET.kind, 'silent'); assert.match(k.QUIET.why, /check the detection and its log source/);
  assert.equal(k.BF.kind, 'surging'); assert.equal(k.BF.usual, 1);
  assert.equal(k.NEW.kind, 'new'); assert.ok(!k.STEADY, 'a steady rule is not listed');
  assert.equal(s.items[0].kind, 'silent', 'a silent rule first: a blind spot');
});

test('efficacy, entities, SLA attainment', () => {
  const all = [];
  for (let i = 0; i < 5; i++) all.push(al({ rule_id: 'RANSOM', rule_name: 'Ransomware', status: 'closed-true-positive', created: NOW - 2 * DAY, closed_at: NOW - 2 * DAY + 30 * 60000 }));
  for (let i = 0; i < 6; i++) all.push(al({ rule_id: 'SCAN', rule_name: 'Port scan', status: 'closed-false-positive', created: NOW - 2 * DAY, closed_at: NOW - 2 * DAY + 4 * H }));
  all.push(al({ rule_id: 'FEW', status: 'closed-false-positive', closed_at: NOW - DAY }));
  const e = OI.efficacy(all, NOW);
  assert.deepEqual(e.rules.map((r) => [r.rule_id, r.grade, r.precision]), [['RANSOM', 'high value', 86], ['SCAN', 'noise', 13]]);
  assert.equal(e.rules[0].median_close_min, 30);
  const ents = OI.entities([{ rule_name: 'A', priority: 80, entities: ['host:pc-syn'], tactic: 'execution' }, { rule_name: 'B', priority: 70, entities: ['host:pc-syn', 'user:syn.x'], tactic: 'credential-access' }, { rule_name: 'C', priority: 20, entities: ['host:noisy-syn'] }, { rule_name: 'C', priority: 20, entities: ['host:noisy-syn'] }]);
  assert.equal(ents[0].entity, 'host:pc-syn'); assert.equal(ents[0].risk, 150); assert.deepEqual(ents[0].tactics, ['execution', 'credential-access']);
  // SLA: two criticals last week, one acknowledged in 30 min, one in 3 h (policy: 1 h)
  const s = OI.sla([al({ severity: 4, created: NOW - 2 * DAY, ack_at: NOW - 2 * DAY + 30 * 60000 }), al({ severity: 4, created: NOW - 2 * DAY, ack_at: NOW - 2 * DAY + 3 * H }), al({ severity: 1, created: NOW - H })], DEFAULT_SLA, NOW);
  assert.equal(s.weeks.length, 4); assert.equal(s.weeks[3].ack_pct, 50); assert.equal(s.weeks[3].ack_judged, 2, 'a low alert still inside its time is not judged');
});

test('route: GET /soc/overview/insights is analyst and above (viewer refused)', async () => {
  const dir = tmpDir(), state = createState({ dir, log: quietLog });
  const alerts = createAlerts({ state, log: quietLog }), cases = createCases({ state, alerts, log: quietLog });
  const api = fakeApi({ realRanks: true }); routes.register(api, { state, alerts, cases, config: { soc_analyst: {} }, log: quietLog, noTimers: true });
  try {
    alerts.raise({ rule_id: 'SENTRA-SYN-1', rule_name: 'Synthetic', severity: 3, group: { user: 'syn.dave' }, fields: {}, summary: 'synthetic', ts_first: Date.now() - H, ts_last: Date.now() - H, source: 'engine', count: 1 });
    let r = await api.call('GET', '/api/soc/soc/overview/insights', { role: 'viewer' }); assert.equal(r.status, 403);
    r = await api.call('GET', '/api/soc/soc/overview/insights', { role: 'analyst' }); assert.equal(r.status, 200, JSON.stringify(r.body));
    assert.equal(r.body.entities[0].entity, 'user:syn.dave'); assert.equal(r.body.forecast.forecast, null); assert.equal(r.body.shifts.judged, false); assert.equal(r.body.sla.weeks.length, 4);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('forecast: days before the first alert do not count as quiet days (level stays 1 on steady data)', () => {
  const all = []; for (let d = 1; d <= 20; d++) for (let i = 0; i < 6; i++) all.push(al({ created: NOW - d * DAY - H }));
  const f = OI.forecast(all, NOW); assert.equal(f.level, 1, JSON.stringify(f.level)); assert.ok(f.forecast.every((x) => x.alerts === 6));
});
