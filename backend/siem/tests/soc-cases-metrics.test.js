// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const { createState } = require('../engine/soc/state');
const { createAlerts } = require('../engine/soc/alerts');
const { createCases, DEFAULT_SLA } = require('../engine/soc/cases');
const playbooks = require('../engine/soc/playbooks');
const { computeMetrics } = require('../engine/soc/metrics');
const { tmpDir, quietLog } = require('./soc-fakes');

const T0 = Date.UTC(2026, 8, 29, 10, 0, 0);
const H = 3600000;

function setup(sla) {
  const dir = tmpDir('sentra-cases-');
  const state = createState({ dir, log: quietLog });
  let now = T0;
  const clock = () => now;
  const alerts = createAlerts({ state, log: quietLog, now: clock });
  const cases = createCases({ state, alerts, log: quietLog, now: clock, sla });
  return { alerts, cases, state, setNow: (t) => { now = t; }, done: () => { alerts.stop(); state.close(); fs.rmSync(dir, { recursive: true, force: true }); } };
}
const raise = (alerts, o) => alerts.raise(Object.assign({ rule_id: 'SENTRA-AUTH-001', rule_name: 'Brute force', severity: 3, mitre: ['T1110.001'], group: { user: 'alice', src_ip: '203.0.113.9' },
  group_key: `k${Math.random()}`, count: 12, ts_first: T0 - 120000, ts_last: T0 - 1000, sample_event_ids: ['e1'], summary: 'Brute force — user=alice', fields: { host: 'dc01', src_ip: '203.0.113.9', user: 'alice' } }, o)).alert;

test('playbooks: six templates, suggestion by rule/MITRE, tasks, entities, recommendations only', () => {
  const ids = playbooks.list().map((p) => p.id);
  for (const id of ['PB-BRUTE-FORCE', 'PB-MALWARE', 'PB-PHISHING', 'PB-ACCOUNT-COMPROMISE', 'PB-WEB-ATTACK', 'PB-DATA-EXFIL']) assert.ok(ids.includes(id), id);
  for (const pb of playbooks.PLAYBOOKS) {
    for (const t of pb.tasks) {
      assert.ok(['manual', 'automatable'].includes(t.kind));
      if (t.kind === 'automatable') assert.ok(playbooks.ACTIONS[t.action_id], `${pb.id}: unknown action ${t.action_id}`);
    }
  }
  assert.equal(playbooks.suggest([{ rule_id: 'SENTRA-WEB-002', mitre: ['T1190'], severity: 3 }]), 'PB-WEB-ATTACK');
  assert.equal(playbooks.suggest([{ rule_id: 'X', mitre: ['T1566.001'], severity: 2 }]), 'PB-PHISHING');
  assert.equal(playbooks.suggest([{ rule_id: 'X', mitre: [], severity: 2 }]), null);
  const ents = playbooks.entitiesFrom([{ group: { src_ip: '203.0.113.9', user: 'alice' }, fields: { host: 'dc01', dst_ip: '10.0.0.5', hash: 'SHA256=' + 'a'.repeat(64), user: 'pc1$' } }]);
  assert.deepEqual(ents.ips_external, ['203.0.113.9']);
  assert.deepEqual(ents.ips_internal, ['10.0.0.5']);
  assert.deepEqual(ents.users, ['alice']);
  assert.deepEqual(ents.hashes, ['a'.repeat(64)]);
  const recs = playbooks.recommendations(playbooks.instantiate('PB-BRUTE-FORCE'), ents);
  assert.deepEqual(recs.map((r) => r.action_id), ['fw.block_ip', 'ad.reset_password']);
  assert.deepEqual(recs[0].targets, ['203.0.113.9']);
});

test('cases: create from alerts (auto playbook, severity, SLA), links alerts, approvals are recommendations only', () => {
  const s = setup();
  try {
    const a1 = raise(s.alerts, {});
    const a2 = raise(s.alerts, { severity: 4, rule_id: 'SENTRA-AUTH-003', rule_name: 'Success after failures' });
    const c = s.cases.create({ alert_ids: [a1.id, a2.id] }, 'ana');
    assert.match(c.id, /^CASE-\d{6}$/);
    assert.equal(c.status, 'open');
    assert.equal(c.severity, 4);
    assert.equal(c.title, a1.summary);
    assert.equal(c.playbook_id, 'PB-BRUTE-FORCE');
    assert.equal(c.sla.ack_due, T0 + 1 * H);
    assert.equal(c.sla.resolve_due, T0 + 24 * H);
    assert.ok(c.tasks.length >= 5 && c.tasks.every((t) => t.done === false));
    assert.equal(s.alerts.get(a1.id).case_id, c.id);
    assert.equal(s.alerts.get(a1.id).status, 'in-progress');
    const v = s.cases.get(c.id);
    assert.equal(v.playbook_name, 'Brute force / password spraying');
    assert.equal(v.recommended_actions.length, 2);
    for (const r of v.recommended_actions) {
      assert.equal(r.requires_approval, true);
      assert.equal(r.status, 'pending');
      assert.equal(r.execution, 'not-executed-by-engine');
      assert.ok(r.id && r.title && r.action);
    }
    assert.throws(() => s.cases.create({ alert_ids: [a1.id] }, 'ana'), (e) => e.code === 409, 'alert already in a case');
    assert.throws(() => s.cases.create({ alert_ids: ['ALR-404'] }, 'ana'), (e) => e.code === 404);
    assert.throws(() => s.cases.create({}, 'ana'), (e) => e.code === 400);
    // approval decisions are recorded, never executed
    const apr = s.cases.approvals.decide(v.recommended_actions[0].id, 'approved', 'lead', 'go');
    assert.equal(apr.status, 'approved');
    assert.throws(() => s.cases.approvals.decide(apr.id, 'rejected', 'lead'), (e) => e.code === 409);
    // four-eyes: the requester of a response action may not decide it
    const second = s.cases.approvals.get(v.recommended_actions[1].id);
    assert.ok(second.requested_by, 'the requester is recorded');
    assert.throws(() => s.cases.approvals.decide(second.id, 'approved', second.requested_by), (e) => e.code === 403);
    assert.throws(() => s.cases.approvals.decide(second.id, 'rejected', String(second.requested_by).toUpperCase()), (e) => e.code === 403, 'case-insensitive');
    assert.ok(s.cases.get(c.id).timeline.some((t) => t.kind === 'approval' && /does not execute/.test(t.text)));
  } finally { s.done(); }
});

test('cases: SLA by severity (defaults + configurable), ack on owner/status, breaches', () => {
  assert.deepEqual(DEFAULT_SLA, { critical: { ack_h: 1, resolve_h: 24 }, high: { ack_h: 4, resolve_h: 72 }, medium: { ack_h: 24, resolve_h: 168 }, low: { ack_h: 72, resolve_h: 720 } });
  const s = setup({ medium: { ack_h: 2 } });
  try {
    const hi = s.cases.create({ title: 'High', severity: 3 }, 'ana');
    assert.equal(hi.sla.ack_due - hi.created, 4 * H);
    assert.equal(hi.sla.resolve_due - hi.created, 72 * H);
    const med = s.cases.create({ title: 'Med', severity: 2 }, 'ana');
    assert.equal(med.sla.ack_due - med.created, 2 * H, 'configured');
    assert.equal(med.sla.resolve_due - med.created, 168 * H);
    const low = s.cases.create({ title: 'Low', severity: 0 }, 'ana');
    assert.equal(low.sla.resolve_due - low.created, 720 * H);
    s.setNow(T0 + 3 * H);
    s.cases.assign(med.id, 'bob', 'lead');       // acked late
    s.cases.setStatus(hi.id, 'investigating', 'ana');
    assert.equal(s.cases.slaState(s.cases.get(med.id)).ack_breached, true);
    assert.equal(s.cases.slaState(s.cases.get(hi.id)).ack_breached, false);
    s.setNow(T0 + 100 * H);
    assert.equal(s.cases.slaState(s.cases.get(hi.id)).resolve_breached, true);
    // severity change recomputes SLA from creation time
    const up = s.cases.update(low.id, { severity: 4 }, 'lead');
    assert.equal(up.sla.ack_due, low.created + 1 * H);
    assert.equal(s.cases.list({ breached: 'true' }).total, 3);
  } finally { s.done(); }
});

test('cases: status workflow, resolution required, closing closes linked alerts, reopen, tasks, evidence, notes, addAlerts', () => {
  const s = setup();
  try {
    const a1 = raise(s.alerts, {});
    const a2 = raise(s.alerts, { rule_id: 'SENTRA-WEB-002', mitre: ['T1190'] });
    const c = s.cases.create({ title: 'Incident', severity: 2, alert_ids: [a1.id], playbook_id: 'PB-WEB-ATTACK', owner: 'ana' }, 'ana');
    assert.equal(c.acked_at, T0, 'owner at creation counts as ack');
    assert.throws(() => s.cases.setStatus(c.id, 'bogus', 'ana'), (e) => e.code === 400);
    s.cases.setStatus(c.id, 'contained', 'ana');
    s.cases.setStatus(c.id, 'investigating', 'ana');
    assert.throws(() => s.cases.setStatus(c.id, 'closed', 'ana'), /resolution/);
    s.cases.addTask(c.id, { title: 'Call the vendor' }, 'ana');
    const t = s.cases.setTask(c.id, 'T1', true, 'ana').tasks.find((x) => x.id === 'T1');
    assert.equal(t.done, true); assert.equal(t.by, 'ana');
    assert.throws(() => s.cases.setTask(c.id, 'T99', true, 'ana'), (e) => e.code === 404);
    s.cases.addEvidence(c.id, { name: 'nginx access log extract', ref: 'search: src_ip:203.0.113.9' }, 'ana');
    assert.throws(() => s.cases.addEvidence(c.id, { name: 'x' }, 'ana'), (e) => e.code === 400);
    s.cases.note(c.id, 'WAF rule deployed', 'ana');
    s.cases.addAlerts(c.id, [a2.id], 'ana');
    assert.equal(s.alerts.get(a2.id).case_id, c.id);
    const pb2 = s.cases.applyPlaybook(c.id, 'PB-DATA-EXFIL', 'ana');
    assert.ok(pb2.tasks.some((x) => x.playbook_id === 'PB-DATA-EXFIL'));
    assert.equal(new Set(pb2.tasks.map((x) => x.id)).size, pb2.tasks.length, 'task ids stay unique');
    s.setNow(T0 + 5 * H);
    const closed = s.cases.setStatus(c.id, 'closed', 'ana', { resolution: 'true-positive', note: 'blocked' });
    assert.equal(closed.closed, T0 + 5 * H);
    assert.equal(closed.resolution, 'true-positive');
    assert.equal(s.alerts.get(a1.id).status, 'closed-true-positive');
    assert.equal(s.alerts.get(a2.id).status, 'closed-true-positive');
    assert.throws(() => s.cases.setStatus(c.id, 'contained', 'ana'), (e) => e.code === 409);
    const re = s.cases.setStatus(c.id, 'investigating', 'lead');
    assert.equal(re.closed, 0);
    const kinds = s.cases.get(c.id).timeline.map((x) => x.kind);
    for (const k of ['created', 'status', 'task', 'evidence', 'note', 'alerts', 'playbook', 'approval']) assert.ok(kinds.includes(k), k);
    assert.equal(s.cases.list({ status: 'active' }).total, 1);
    assert.equal(s.cases.list({ status: 'all' }).total, 1);
    assert.equal(s.cases.list({ status: 'closed' }).total, 0);
  } finally { s.done(); }
});

test('metrics: by day/severity, MTTD, MTTR, SLA, top rules/sources/hosts/users, noisy rules, FP rate, MITRE', () => {
  const s = setup();
  try {
    const mk = (i, o) => { s.setNow(T0 + i * 60000); return raise(s.alerts, Object.assign({ group_key: `g${i}`, ts_first: T0 + i * 60000 - 30000 }, o)); };
    const al = [];
    for (let i = 0; i < 30; i++) al.push(mk(i, { rule_id: 'NOISY', rule_name: 'Noisy rule', severity: 1, src_id: 'fw-hq-01', group: { user: 'svc' }, fields: { host: 'fw' } }));
    for (let i = 30; i < 34; i++) al.push(mk(i, { rule_id: 'SENTRA-AUTH-001', severity: 3, src_id: 'dc01', mitre: ['T1110.001'] }));
    al.push(mk(40, { rule_id: 'LR-1', source: 'logrhythm' }));
    s.setNow(T0 + 2 * H);
    for (let i = 0; i < 10; i++) s.alerts.close(al[i].id, i < 7 ? 'false-positive' : 'benign', 'ana');
    s.alerts.close(al[30].id, 'true-positive', 'ana');
    s.setNow(T0 + 3 * H);
    const c = s.cases.create({ alert_ids: [al[31].id] }, 'ana');
    s.setNow(T0 + 7 * H);
    s.cases.setStatus(c.id, 'closed', 'ana', { resolution: 'true-positive' });
    s.cases.create({ title: 'old open critical', severity: 4 }, 'ana');
    s.setNow(T0 + 30 * H);
    const m = computeMetrics({ alerts: s.alerts.all(), cases: s.cases.all(), from: T0 - H, to: T0 + 30 * H, now: T0 + 30 * H, slaState: s.cases.slaState, noisyPerDay: 20 });
    assert.equal(m.totals.alerts, 34, 'LogRhythm alerts excluded');
    assert.equal(m.alerts_by_severity[1], 30);
    const day = m.alerts_by_day.find((d) => d.day === '2026-09-29');
    assert.equal(day.s1, 30); assert.equal(day.s3, 4);
    assert.equal(m.mttd.n, 34);
    assert.equal(m.mttd_s, 30);
    assert.equal(m.mttr.cases.n, 1);
    assert.equal(m.mttr_s, 4 * 3600);
    assert.equal(m.top_rules[0].rule_id, 'NOISY');
    assert.equal(m.top_sources[0].source, 'fw-hq-01');
    assert.equal(m.top_hosts[0].host, 'fw');
    assert.equal(m.top_users[0].user, 'svc');
    assert.equal(m.mitre['T1110.001'], 34);
    const noisy = m.noisy_rules.find((r) => r.rule_id === 'NOISY');
    assert.ok(noisy.noisy);
    const fp = m.fp_rate.find((r) => r.rule_id === 'NOISY');
    assert.equal(fp.closed, 10); assert.equal(fp.false_positive, 7); assert.equal(fp.fp_rate, 0.7); assert.equal(fp.benign_rate, 0.3);
    assert.equal(m.fp_rate.find((r) => r.rule_id === 'SENTRA-AUTH-001').fp_rate, 0);
    assert.equal(m.open_by_severity[1], 20);
    assert.equal(m.sla.breached, 1, 'the open critical case breached its ack SLA');
    assert.equal(typeof m.sla.at_risk, 'number');
    assert.equal(m.sla.cases, 2);
    assert.equal(m.totals.cases_closed, 1);
  } finally { s.done(); }
});
