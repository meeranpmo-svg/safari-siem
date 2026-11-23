// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// SOC API routes against a fake createApi (portal contract), plus LogRhythm import / comparison.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const { createState } = require('../engine/soc/state');
const { createAlerts } = require('../engine/soc/alerts');
const { createCases } = require('../engine/soc/cases');
const socRoutes = require('../engine/soc/routes');
const lrc = require('../engine/soc/lrcompare');
const { fakeApi, tmpDir, quietLog } = require('./soc-fakes');

const T0 = Date.now() - 2 * 3600000;

function setup(config) {
  const dir = tmpDir('sentra-socapi-');
  const state = createState({ dir, log: quietLog });
  const alerts = createAlerts({ state, log: quietLog });
  const cases = createCases({ state, alerts, log: quietLog });
  const api = fakeApi();
  socRoutes.register(api, { state, alerts, cases, config: config || {}, log: quietLog });
  return { api, alerts, cases, state, done: () => { alerts.stop(); state.close(); fs.rmSync(dir, { recursive: true, force: true }); } };
}
const raise = (alerts, o) => alerts.raise(Object.assign({ rule_id: 'SENTRA-AUTH-001', rule_name: 'Brute force', severity: 3, mitre: ['T1110.001'], group: { user: 'alice' },
  group_key: `k${Math.random()}`, count: 10, ts_first: T0, ts_last: T0 + 1000, sample_event_ids: ['e1'], summary: 'Brute force — user=alice', src_id: 'dc01', fields: { src_ip: '203.0.113.9' } }, o)).alert;

test('portal routes are all registered under /api/soc', () => {
  const s = setup();
  try {
    const expect = [
      ['GET', '/api/soc/alerts'], ['GET', '/api/soc/alerts/:id'], ['POST', '/api/soc/alerts/:id/ack'], ['POST', '/api/soc/alerts/:id/assign'],
      ['POST', '/api/soc/alerts/:id/close'], ['POST', '/api/soc/alerts/:id/note'], ['POST', '/api/soc/alerts/bulk'],
      ['GET', '/api/soc/cases'], ['GET', '/api/soc/cases/:id'], ['POST', '/api/soc/cases'], ['POST', '/api/soc/cases/:id/alerts'],
      ['POST', '/api/soc/cases/:id/status'], ['POST', '/api/soc/cases/:id/owner'], ['POST', '/api/soc/cases/:id/notes'],
      ['POST', '/api/soc/cases/:id/evidence'], ['POST', '/api/soc/cases/:id/tasks/:taskId'], ['GET', '/api/soc/metrics'], ['GET', '/api/soc/lr-compare'],
    ];
    for (const [m, p] of expect) assert.ok(s.api.has(m, p), `${m} ${p}`);
    const custom = fakeApi();
    socRoutes.register(custom, { state: s.state, alerts: s.alerts, cases: s.cases, config: { api_prefix: '/soc/' } });
    assert.ok(custom.has('GET', '/soc/alerts'));
  } finally { s.done(); }
});

test('alerts API: list filters, ack/assign/note/close, bulk {action}, roles, audit, 400 {error, errors}', async () => {
  const s = setup();
  try {
    const a = raise(s.alerts, {});
    const b = raise(s.alerts, { severity: 1, rule_id: 'R2' });
    const c = raise(s.alerts, { severity: 4 });
    let r = await s.api.call('GET', `/api/soc/alerts?status=new&min_severity=3&from=${encodeURIComponent(new Date(T0 - 1000).toISOString())}&limit=10`);
    assert.equal(r.status, 200);
    assert.equal(r.body.total, 2);
    r = await s.api.call('GET', '/api/soc/alerts?status=all&unassigned=1');
    assert.equal(r.body.total, 3);
    r = await s.api.call('POST', `/api/soc/alerts/${a.id}/ack`, { role: 'viewer' });
    assert.equal(r.status, 403, 'viewers cannot write');
    r = await s.api.call('POST', `/api/soc/alerts/${a.id}/ack`, { role: 'operator', user: 'ana' });
    assert.equal(r.body.status, 'acknowledged');
    assert.equal(r.body.assignee, 'ana');
    r = await s.api.call('POST', `/api/soc/alerts/${b.id}/assign`, { role: 'operator', body: { assignee: 'bob' } });
    assert.equal(r.body.assignee, 'bob');
    r = await s.api.call('POST', `/api/soc/alerts/${b.id}/note`, { role: 'operator', body: { text: 'looking' } });
    assert.equal(r.body.notes.length, 1);
    r = await s.api.call('POST', `/api/soc/alerts/${b.id}/close`, { role: 'operator', body: { reason: 'probably-fine' } });
    assert.equal(r.status, 400);
    assert.ok(r.body.error && Array.isArray(r.body.errors) && r.body.errors.length);
    r = await s.api.call('POST', `/api/soc/alerts/${b.id}/close`, { role: 'operator', body: { reason: 'false-positive', note: 'test account' } });
    assert.equal(r.body.status, 'closed-false-positive');
    r = await s.api.call('GET', '/api/soc/alerts/ALR-0000000');
    assert.equal(r.status, 404);
    r = await s.api.call('POST', '/api/soc/alerts/bulk', { role: 'operator', body: { ids: [a.id, c.id], action: 'close', reason: 'true-positive', note: 'confirmed' } });
    assert.equal(r.body.ok, 2);
    r = await s.api.call('POST', '/api/soc/alerts/bulk', { role: 'operator', body: { ids: [a.id], action: 'nuke' } });
    assert.equal(r.status, 400);
    r = await s.api.call('GET', '/api/soc/alerts?status=closed');
    assert.equal(r.body.total, 3);
    r = await s.api.call('GET', '/api/soc/alerts?assignee=me', { user: 'bob' });
    assert.equal(r.body.total, 1);
    const acts = s.api.audits.map((x) => x.action);
    assert.deepEqual(acts, ['alert.ack', 'alert.assign', 'alert.note', 'alert.close', 'alert.bulk.close']);
    assert.ok(s.api.audits.every((x) => x.user));
  } finally { s.done(); }
});

test('cases API: create, owner, notes, evidence, tasks, alerts, status (resolution), recommended_actions, playbook_name', async () => {
  const s = setup();
  try {
    const a = raise(s.alerts, {});
    const a2 = raise(s.alerts, {});
    let r = await s.api.call('POST', '/api/soc/cases', { role: 'operator', user: 'ana', body: { title: 'Brute force on alice', severity: 3, alert_ids: [a.id] } });
    assert.equal(r.status, 200);
    const id = r.body.id;
    assert.match(id, /^CASE-/);
    assert.equal(r.body.playbook_name, 'Brute force / password spraying');
    assert.ok(Array.isArray(r.body.recommended_actions) && r.body.recommended_actions.length === 2);
    assert.deepEqual(Object.keys(r.body.recommended_actions[0]).filter((k) => ['id', 'title', 'action', 'requires_approval'].includes(k)).sort(), ['action', 'id', 'requires_approval', 'title']);
    assert.equal(r.body.recommended_actions[0].requires_approval, true);
    r = await s.api.call('POST', `/api/soc/cases/${id}/owner`, { role: 'operator', body: { owner: 'bob' } });
    assert.equal(r.body.owner, 'bob');
    r = await s.api.call('POST', `/api/soc/cases/${id}/notes`, { role: 'operator', body: { text: 'contacted user' } });
    assert.ok(r.body.timeline.some((t) => t.kind === 'note' && t.text === 'contacted user'));
    r = await s.api.call('POST', `/api/soc/cases/${id}/evidence`, { role: 'operator', body: { name: 'firewall log', ref: 'event:abc' } });
    assert.equal(r.body.evidence.length, 1);
    r = await s.api.call('POST', `/api/soc/cases/${id}/tasks/T1`, { role: 'operator', body: { done: true } });
    assert.equal(r.body.tasks.find((t) => t.id === 'T1').done, true);
    r = await s.api.call('POST', `/api/soc/cases/${id}/alerts`, { role: 'operator', body: { alert_ids: [a2.id] } });
    assert.deepEqual(r.body.alerts, [a.id, a2.id]);
    r = await s.api.call('POST', `/api/soc/cases/${id}/status`, { role: 'operator', body: { status: 'closed' } });
    assert.equal(r.status, 400, 'closing requires resolution');
    r = await s.api.call('POST', `/api/soc/cases/${id}/status`, { role: 'operator', body: { status: 'closed', resolution: 'true-positive' } });
    assert.equal(r.body.status, 'closed');
    r = await s.api.call('GET', `/api/soc/cases/${id}`);
    assert.equal(r.body.alert_details.length, 2);
    assert.ok(r.body.alert_details.every((x) => x.status === 'closed-true-positive'));
    r = await s.api.call('GET', '/api/soc/cases?status=active');
    assert.equal(r.body.total, 0);
    r = await s.api.call('GET', '/api/soc/cases?status=all');
    assert.equal(r.body.total, 1);
    r = await s.api.call('POST', `/api/soc/approvals/${(await s.api.call('GET', `/api/soc/cases/${id}`)).body.recommended_actions[0].id}/decide`, { role: 'operator', body: { decision: 'approved' } });
    assert.equal(r.status, 403, 'approvals need admin');
    r = await s.api.call('GET', '/api/soc/playbooks');
    assert.equal(r.body.items.length, 6);
  } finally { s.done(); }
});

test('metrics API shape (portal contract)', async () => {
  const s = setup();
  try {
    raise(s.alerts, {});
    raise(s.alerts, { severity: 1, rule_id: 'R2', group: { host: 'web01', user: 'bob' } });
    const r = await s.api.call('GET', '/api/soc/metrics');
    assert.equal(r.status, 200);
    const m = r.body;
    for (const k of ['open_by_severity', 'alerts_by_day', 'mttd_s', 'mttr_s', 'sla', 'top_rules', 'top_sources', 'top_hosts', 'top_users', 'noisy_rules', 'mitre']) assert.ok(k in m, k);
    assert.deepEqual(Object.keys(m.open_by_severity), ['0', '1', '2', '3', '4']);
    assert.ok(['s0', 's1', 's2', 's3', 's4', 'day'].every((k) => k in m.alerts_by_day[0]));
    assert.ok('breached' in m.sla && 'at_risk' in m.sla);
    assert.equal(m.mitre['T1110.001'], 2);
    const bad = await s.api.call('GET', '/api/soc/metrics?from=not-a-date');
    assert.equal(bad.status, 400);
  } finally { s.done(); }
});

test('LogRhythm: alarm import (idempotent) and lr-compare (rule map + shared entity, time window)', async () => {
  const s = setup({ lr_rule_map: { 'AIE: Brute Force Attack': 'SENTRA-AUTH-001' } });
  try {
    const ours1 = raise(s.alerts, { ts_first: T0, ts_last: T0 + 60000, group: { user: 'alice' } });
    raise(s.alerts, { rule_id: 'SENTRA-WEB-002', rule_name: 'SQLi', ts_first: T0 + 600000, ts_last: T0 + 600000, group: { src_ip: '198.51.100.5' }, src_id: 'www01' });
    raise(s.alerts, { rule_id: 'SENTRA-IAM-001', rule_name: 'Priv group', ts_first: T0, ts_last: T0, group: { target_user: 'mallory' } });
    const alarms = [
      { alarm_id: 1001, alarm_rule_id: 555, alarm_rule_name: 'AIE: Brute Force Attack', alarm_date: new Date(T0 + 120000).toISOString(), priority: 75, log_source: 'DC01 Security', user: 'someone-else' },
      { alarm_id: 1002, alarm_rule_name: 'AIE: SQL Injection', alarm_date: T0 + 610000, priority: 92, src_ip: '198.51.100.5', log_source: 'WWW01' },
      { alarm_id: 1003, alarm_rule_name: 'AIE: Port Scan', alarm_date: T0 + 30000, priority: 40, src_ip: '10.9.9.9', log_source: 'FW-HQ' },
      { alarm_id: 1004, alarm_rule_name: 'AIE: SQL Injection', alarm_date: T0 + 5 * 3600000, priority: 92, src_ip: '198.51.100.5' },
      { alarm_rule_name: 'broken' },
    ];
    let r = await s.api.call('POST', '/api/soc/lr/alarms', { role: 'operator', body: { alarms } });
    assert.equal(r.body.imported, 4);
    assert.equal(r.body.errors.length, 1);
    r = await s.api.call('POST', '/api/soc/lr/alarms', { role: 'operator', body: { alarms: alarms.slice(0, 2) } });
    assert.equal(r.body.imported, 0);
    assert.equal(r.body.skipped, 2, 're-import is idempotent');
    const lrAlert = s.alerts.list({ source: 'logrhythm' }).items.find((x) => x.lr_alarm_id === '1002');
    assert.equal(lrAlert.severity, 4);
    assert.equal(lrAlert.rule_id, 'LR-AIE: SQL Injection');
    r = await s.api.call('GET', `/api/soc/lr-compare?from=${encodeURIComponent(new Date(T0 - 3600000).toISOString())}&to=${encodeURIComponent(new Date(T0 + 3 * 3600000).toISOString())}&window_s=900`);
    const cmp = r.body;
    assert.equal(cmp.totals.ours, 3);
    assert.equal(cmp.totals.lr, 3, 'alarm 1004 is outside the range');
    assert.equal(cmp.totals.both_lr, 2);
    assert.equal(cmp.totals.only_lr, 1);
    assert.equal(cmp.totals.only_ours, 1);
    const viaMap = cmp.pairs.find((p) => p.lr_rule === 'AIE: Brute Force Attack');
    assert.equal(viaMap.our_id, ours1.id);
    assert.equal(viaMap.via, 'rule-map');
    assert.equal(cmp.pairs.find((p) => p.lr_rule === 'AIE: SQL Injection').via, 'entity:src_ip');
    assert.ok(cmp.by_rule.find((x) => x.rule_id === 'SENTRA-IAM-001').only_ours === 1);
    assert.ok(cmp.by_lr_rule.find((x) => x.lr_rule === 'AIE: Port Scan').only_lr === 1);
    assert.ok(cmp.by_source.length >= 3 && cmp.by_bucket.length >= 1);
    assert.deepEqual([cmp.lr_high.total, cmp.lr_high.matched, cmp.lr_high.pct], [2, 2, 100], 'priority >= 70: 1001 and 1002, both matched; 1003 (40) is not high');
    const wide = (await s.api.call('GET', `/api/soc/lr-compare?from=${T0 - 3600000}&to=${T0 + 6 * 3600000}`)).body;
    assert.deepEqual([wide.lr_high.total, wide.lr_high.unmatched], [3, 1], '1004 (92) has no match of ours');
    assert.equal(wide.lr_high.unmatched_ids.length, 1);
    // LR alerts do not pollute the SOC queue or metrics
    assert.equal((await s.api.call('GET', '/api/soc/alerts?status=all')).body.total, 3);
    assert.equal((await s.api.call('GET', '/api/soc/metrics')).body.totals.alerts, 3);
    assert.throws(() => lrc.lrAlarmToPartial({ alarm_id: 1, alarm_rule_name: 'x', alarm_date: 'garbage' }), /alarm_date/);
    assert.equal(lrc.prioToSeverity(95), 4);
    assert.equal(lrc.prioToSeverity(10), 0);
  } finally { s.done(); }
});
