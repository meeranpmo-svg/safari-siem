// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Alert Queue insights (engine/soc/queue-insights.js, analyst.js insights(), GET {P}/soc/queue/insights): campaigns of different
// rules joined through a shared entity (a hub entity left out and named), the kill-chain order, the backlog flow and forecast
// withheld without history, SLA due / breached from the case policy, precedent from 3 past closures, the analyst role (viewer
// refused). SYNTHETIC data only.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const QI = require('../engine/soc/queue-insights');
const { createState } = require('../engine/soc/state');
const { createAlerts } = require('../engine/soc/alerts');
const { createCases } = require('../engine/soc/cases');
const routes = require('../engine/soc/analyst-routes');
const { fakeApi, tmpDir, quietLog } = require('./soc-fakes');

const H = 3600e3, DAY = 864e5, NOW = Date.parse('2026-11-18T09:00:00Z');
const al = (o) => Object.assign({ id: 'A' + Math.random().toString(36).slice(2, 8), rule_id: 'R1', rule_name: 'Rule 1', severity: 2, priority: 40, status: 'new', entities: [], ts_first: NOW - H, created: NOW - H }, o);

test('campaigns: different rules joined through a shared entity, kill-chain order, a hub entity left out and named', () => {
  const open = [
    al({ id: 'C1', rule_id: 'PHISH', rule_name: 'Phishing click', tactic: 'initial-access', priority: 50, entities: ['user:syn.alice', 'host:pc-syn-1'] }),
    al({ id: 'C2', rule_id: 'PS', rule_name: 'Encoded PowerShell', mitre: [{ tactic: 'execution' }], priority: 60, entities: ['host:pc-syn-1'] }),
    al({ id: 'C3', rule_id: 'LSASS', rule_name: 'LSASS read', tactic: 'TA0006', priority: 70, entities: ['host:pc-syn-1', 'host:dc-syn'] }),
    al({ id: 'S1', rule_id: 'PS', entities: ['host:pc-syn-9'] }),   // same rule only, alone: not a campaign
  ];
  // the domain controller is on every one of 12 more alerts: a hub, so it must not join them all together
  for (let i = 0; i < 12; i++) open.push(al({ id: 'D' + i, rule_id: 'R' + i, entities: ['host:dc-syn', 'user:syn.u' + i] }));
  const c = QI.campaigns(open);
  assert.ok(c.hubs.some((h) => h.entity === 'host:dc-syn'), 'the hub is named');
  assert.equal(c.items.length, 1, 'one campaign: ' + JSON.stringify(c.items.map((x) => x.alert_ids)));
  const k = c.items[0];
  assert.deepEqual(k.alert_ids.sort(), ['C1', 'C2', 'C3']);
  assert.deepEqual(k.tactics, ['initial-access', 'execution', 'credential-access'], 'kill-chain order, a tactic id mapped');
  assert.equal(k.progression, true);
  assert.equal(k.score, Math.round(100 * (1 - 0.5 * 0.4 * 0.3)), 'combined score 1 - prod(1 - p)');
  assert.ok(k.entities.includes('host:pc-syn-1') && !k.entities.includes('host:dc-syn'));
  assert.match(k.why, /3 open alerts from 3 different rules share host:pc-syn-1/);
});

test('flow: forecast withheld below 7 days of history; a growing backlog is projected and said', () => {
  let f = QI.flow([al({ created: NOW - H })], NOW);
  assert.equal(f.forecast, null); assert.match(f.note, /needs 7 days/); assert.equal(f.series.length, 30);
  const all = [];
  for (let d = 0; d < 14; d++) {
    for (let i = 0; i < 6; i++) all.push(al({ created: NOW - d * DAY - H }));
    for (let i = 0; i < 2; i++) all.push(al({ created: NOW - d * DAY - 2 * H, status: 'closed-false-positive', closed_at: NOW - d * DAY - H }));
  }
  f = QI.flow(all, NOW);
  assert.equal(f.trend, 'growing'); assert.equal(f.open, 84); assert.equal(f.forecast.length, 7);
  assert.ok(f.forecast[6].open > f.open && f.forecast[6].high >= f.forecast[6].open && f.forecast[6].low <= f.forecast[6].open);
  assert.match(f.note, /grows by about 6 a day/); assert.equal(f.days_to_clear, null);
});

test('sla: acknowledge and resolve clocks from the case policy; breached and at risk', () => {
  const policy = { critical: { ack_h: 1, resolve_h: 24 }, high: { ack_h: 4, resolve_h: 72 }, medium: { ack_h: 24, resolve_h: 168 }, low: { ack_h: 72, resolve_h: 720 } };
  const s = QI.sla([
    al({ id: 'CRIT', severity: 4, created: NOW - 2 * H }),                      // ack breached by 1 h, resolve not yet at risk
    al({ id: 'HIGH', severity: 3, created: NOW - 3.5 * H }),                    // 0.5 h of 4 left: at risk
    al({ id: 'OWNED', severity: 4, created: NOW - 2 * H, assignee: 'syn.ana' }),  // acknowledged by an owner: only resolve counts
    al({ id: 'FRESH', severity: 2, created: NOW - H }),
  ], policy, NOW);
  assert.equal(s.breached, 1); assert.equal(s.at_risk, 1);
  assert.equal(s.items[0].id, 'CRIT'); assert.equal(s.items[0].kind, 'acknowledge'); assert.equal(s.items[0].hours_left, -1);
  assert.equal(s.items[1].id, 'HIGH'); assert.ok(!s.items.some((x) => x.id === 'OWNED' || x.id === 'FRESH'));
});

test('precedent: only from 3 closures of the same rule on a shared entity, smoothed', () => {
  const closed = [
    al({ id: 'P1', rule_id: 'VPN', status: 'closed-false-positive', entities: ['user:syn.bob'] }),
    al({ id: 'P2', rule_id: 'VPN', status: 'closed-false-positive', entities: ['user:syn.bob'] }),
    al({ id: 'P3', rule_id: 'VPN', status: 'closed-benign', entities: ['user:syn.bob', 'ip:10.0.0.5'] }),
    al({ id: 'P4', rule_id: 'OTHER', status: 'closed-true-positive', entities: ['user:syn.bob'] }),
  ];
  const p = QI.precedent([al({ id: 'O1', rule_id: 'VPN', entities: ['user:syn.bob'] }), al({ id: 'O2', rule_id: 'VPN', entities: ['user:syn.carol'] })], closed);
  assert.ok(p.O1 && !p.O2, 'no precedent without 3 closures on the entity');
  assert.equal(p.O1.n, 3); assert.equal(p.O1.likely, 'fp'); assert.deepEqual(p.O1.shares, { tp: 17, fp: 50, benign: 33 });
  assert.match(p.O1.why, /closed 3 times: 0 true positive, 2 false positive, 1 benign/);
  assert.equal(QI.histogram([al({ priority: 95 }), al({ priority: 100 }), al({ priority: 3 })])[9].n, 2);
});

test('route: GET /soc/queue/insights is analyst and above (viewer refused), built from the stores', async () => {
  const dir = tmpDir(), state = createState({ dir, log: quietLog });
  const alerts = createAlerts({ state, log: quietLog }), cases = createCases({ state, alerts, log: quietLog });
  const deps = { state, alerts, cases, config: { soc_analyst: {} }, log: quietLog, noTimers: true };
  const api = fakeApi({ realRanks: true }); routes.register(api, deps);
  const raise = (o) => alerts.raise(Object.assign({ severity: 3, group: {}, fields: {}, summary: 'synthetic', ts_first: Date.now() - H, ts_last: Date.now() - H, source: 'engine', count: 1 }, o)).alert;
  try {
    raise({ rule_id: 'SENTRA-SYN-1', rule_name: 'Synthetic sign-in', group: { user: 'syn.dave' } });
    raise({ rule_id: 'SENTRA-SYN-2', rule_name: 'Synthetic mailbox rule', tactic: 'persistence', group: { user: 'syn.dave' } });
    for (let i = 0; i < 3; i++) { const a = raise({ rule_id: 'SENTRA-SYN-3', rule_name: 'Synthetic VPN', group_key: 'v' + i, group: { user: 'syn.erin' } }); alerts.setStatus(a.id, 'closed-false-positive', 'syn.ana', 'synthetic'); }
    const o = raise({ rule_id: 'SENTRA-SYN-3', rule_name: 'Synthetic VPN', group_key: 'v9', group: { user: 'syn.erin' } });
    let r = await api.call('GET', '/api/soc/soc/queue/insights', { role: 'viewer' }); assert.equal(r.status, 403);
    r = await api.call('GET', '/api/soc/soc/queue/insights', { role: 'analyst' }); assert.equal(r.status, 200, JSON.stringify(r.body));
    assert.equal(r.body.open, 3);
    assert.equal(r.body.campaigns.items.length, 1); assert.deepEqual(r.body.campaigns.items[0].entities, ['user:syn.dave']);
    assert.equal(r.body.precedent[o.id].likely, 'fp'); assert.equal(r.body.flow.series.at(-1).closed, 3);
    assert.ok(r.body.sla.policy.critical.ack_h >= 1); assert.equal(r.body.top.length, 3);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

const closedBy = (o, by, note) => al(Object.assign({ status: 'closed-false-positive', closed_at: NOW - DAY, history: [{ at: NOW - DAY, by, action: 'status', detail: 'new→' + (o.status || 'closed-false-positive') + (note ? ': ' + note : '') }] }, o));
const human = (u) => !/^(ai:|system|svc[-:])/.test(u);

test('owners: who closed this rule before, less their open load; never a service / AI identity', () => {
  const closed = [];
  for (let i = 0; i < 4; i++) closed.push(closedBy({ rule_id: 'VPN' }, 'syn.huda'));
  closed.push(closedBy({ rule_id: 'VPN' }, 'syn.omar'));
  for (let i = 0; i < 9; i++) closed.push(closedBy({ rule_id: 'VPN' }, 'ai:soc-analyst'));
  const open = [al({ id: 'O1', rule_id: 'VPN' }), al({ id: 'O2', rule_id: 'NEW' }), al({ id: 'O3', rule_id: 'VPN', assignee: 'syn.omar' })];
  let o = QI.owners(open, closed, human);
  assert.equal(o.O1.user, 'syn.huda'); assert.match(o.O1.why, /closed 4 alert\(s\) of this rule in 90 days and holds 0 open/);
  assert.ok(!o.O2 && !o.O3, 'no history: no suggestion; assigned: none');
  assert.ok(!JSON.stringify(o).includes('ai:soc-analyst'), 'an AI identity is never suggested');
  for (let i = 0; i < 12; i++) open.push(al({ id: 'H' + i, rule_id: 'X', assignee: 'syn.huda' }));
  o = QI.owners(open, closed, human);
  assert.equal(o.O1.user, 'syn.omar', 'a busy expert loses to a free one: ' + JSON.stringify(o.O1));
});

test('tuning: noisy rules from 30-day closures, the dominant entity named, proposed only', () => {
  const closed = [];
  for (let i = 0; i < 8; i++) closed.push(closedBy({ rule_id: 'SCAN', rule_name: 'Port scan', entities: ['host:scanner-syn'] }, 'syn.ana'));
  closed.push(closedBy({ rule_id: 'SCAN', rule_name: 'Port scan', entities: ['host:pc-syn'] }, 'syn.ana'));
  for (let i = 0; i < 5; i++) closed.push(closedBy({ rule_id: 'RANSOM', status: 'closed-true-positive' }, 'syn.ana'));
  for (let i = 0; i < 4; i++) closed.push(closedBy({ rule_id: 'FEW' }, 'syn.ana'));
  const t = QI.tuning(closed, NOW);
  assert.deepEqual(t.map((x) => x.rule_id), ['SCAN']);
  assert.equal(t[0].entity, 'host:scanner-syn'); assert.equal(t[0].entity_share, 89); assert.match(t[0].why, /consider an exclusion/);
});

test('surge: the last hour against the same hour on 14 days; withheld without 7 days', () => {
  const all = [];
  assert.match(QI.surge(all, NOW).why, /needs 7 days/);
  for (let d = 1; d <= 14; d++) for (let i = 0; i < 2 + (d % 2); i++) all.push(al({ created: NOW - d * DAY - 10 * 60000 }));
  let s = QI.surge(all, NOW); assert.equal(s.surge, false); assert.equal(s.usual, 2.5);
  for (let i = 0; i < 12; i++) all.push(al({ created: NOW - 5 * 60000, rule_name: 'Synthetic brute force' }));
  s = QI.surge(all, NOW); assert.equal(s.surge, true); assert.match(s.why, /12 alerts in the last hour against a usual 2\.5 .*Synthetic brute force \(12\)/);
});

test('similar: closed alerts of any rule by masked words and entities, with how they were closed', () => {
  const closed = [closedBy({ id: 'C1', rule_id: 'R-OLD', rule_name: 'Old rule', summary: 'Mailbox rule forwards mail to 203.0.113.9 for syn.lina', entities: ['user:syn.lina'] }, 'syn.huda', 'travel auto-forward approved by HR'),
    closedBy({ id: 'C2', rule_id: 'R-X', summary: 'Disk full on srv-syn', entities: ['host:srv-syn'] }, 'syn.huda')];
  const s = QI.similar([al({ id: 'O1', rule_id: 'R-NEW', summary: 'Mailbox rule forwards mail to 198.51.100.4 for syn.lina', entities: ['user:syn.lina'] })], closed);
  assert.equal(s.O1.length, 1); assert.equal(s.O1[0].id, 'C1'); assert.equal(s.O1[0].same_rule, false);
  assert.ok(s.O1[0].similarity >= 50); assert.equal(s.O1[0].closed_by, 'syn.huda'); assert.equal(s.O1[0].note, 'travel auto-forward approved by HR');
});
