// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Security Operations Overview, Alert Queue and the AI SOC analyst (engine/soc/alert-ml.js, analyst.js, analyst-routes.js):
// the explainable priority (severity, rarity, UEBA, intel, XDR, learned noise withheld below 3 closures), clusters, the queue
// filters, the overview figures, the AI triage with a scripted model (role-filtered tools, schema-checked draft, evidence
// cited or marked unverified), a person deciding (close / open a case with the playbook's approval requests), roles, validation
// errors naming the field, audit records and the off-by-default auto-triage. SYNTHETIC data only.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const { createState } = require('../engine/soc/state');
const { createAlerts } = require('../engine/soc/alerts');
const { createCases } = require('../engine/soc/cases');
const ML = require('../engine/soc/alert-ml');
const routes = require('../engine/soc/analyst-routes');
const { createAnalyst, TOOLS } = require('../engine/soc/analyst');
const { fakeApi, tmpDir, quietLog } = require('./soc-fakes');

const H = 3600e3, NOW = Date.now();
const use = (id, name, input) => ({ type: 'tool_use', id, name, input });
const turn = (content, stop = 'tool_use') => ({ content, stop_reason: stop, usage: { input_tokens: 100, output_tokens: 20 } });

function world({ script = [], intel = null, ueba = null } = {}) {
  const dir = tmpDir(); const state = createState({ dir, log: quietLog });
  const alerts = createAlerts({ state, log: quietLog }), cases = createCases({ state, alerts, log: quietLog });
  const calls = [];
  class FakeAnthropic { constructor() { this.messages = { create: async (p) => { calls.push(JSON.parse(JSON.stringify(p))); const r = script.shift(); if (!r) throw new Error('script ended'); return r; } }; } }
  const config = { soc_analyst: {}, secrets: { netops: { anthropic_api_key: 'sk-ant-synthetic-key-for-tests' } }, ai_limits: { per_user_hour: 100, per_user_day: 1000, daily_tokens: 1e9, max_prompt_chars: 1e6 } };
  const deps = { state, alerts, cases, config, log: quietLog, sdk: FakeAnthropic, intel, ueba, noTimers: true };
  const api = fakeApi(); routes.register(api, deps);
  const raise = (o) => alerts.raise(Object.assign({ rule_id: 'SENTRA-AUTH-001', rule_name: 'Brute force then success', severity: 3, group: {}, fields: {}, summary: 'synthetic', ts_first: NOW - H, ts_last: NOW - H, source: 'engine', count: 1 }, o)).alert;
  return { state, alerts, cases, api, deps, calls, raise, setScript: (s) => { script.splice(0, script.length, ...s); }, cleanup: () => fs.rmSync(dir, { recursive: true, force: true }) };
}

test('alert-ml: learned noise is withheld below 3 closures, rarity and clusters are explained', () => {
  const ents = (a) => (a.group.user ? ['user:' + a.group.user] : []);
  const base = { rule_id: 'R-NOISY', rule_name: 'Noisy rule', severity: 2, group: { user: 'alice' }, summary: 'Login failed for alice from 10.0.0.1' };
  const hist = [Object.assign({}, base, { id: 'A1', status: 'closed-false-positive', ts_first: NOW - 5 * 864e5 }), Object.assign({}, base, { id: 'A2', status: 'closed-benign', ts_first: NOW - 4 * 864e5 })];
  let m = ML.learn(hist, { now: NOW, entitiesOf: ents });
  assert.equal(m.rules.get('R-NOISY').noise, null, 'two closures: not learned yet');
  let s = ML.score(Object.assign({}, base, { id: 'X', status: 'new', ts_first: NOW }), m, { entities: ents(base) });
  assert.ok(s.why.some((w) => /not learned yet/.test(w.reason)));
  hist.push(Object.assign({}, base, { id: 'A3', status: 'closed-false-positive', ts_first: NOW - 3 * 864e5 }), Object.assign({}, base, { id: 'A4', status: 'closed-false-positive', ts_first: NOW - 2 * 864e5 }));
  m = ML.learn(hist, { now: NOW, entitiesOf: ents });
  assert.ok(m.rules.get('R-NOISY').noise >= 0.8, 'four FP/benign closures: noisy');
  s = ML.score(Object.assign({}, base, { id: 'X', status: 'new', ts_first: NOW }), m, { entities: ents(base) });
  assert.equal(s.label, 'likely-noise'); assert.ok(s.why.some((w) => w.factor === 'learned from closures' && w.points < 0));
  assert.ok(s.why.some((w) => w.factor === 'rarity' && /seen before/.test(w.reason)), 'alice already triggered this rule');
  const fresh = ML.score(Object.assign({}, base, { id: 'Y', group: { user: 'bob' }, status: 'new', ts_first: NOW }), m, { entities: ['user:bob'] });
  assert.ok(fresh.why.some((w) => w.factor === 'rarity' && w.points === 15), 'first time for bob');
  assert.ok(s.why.some((w) => /UEBA not available/.test(w.reason)) && s.why.some((w) => /threat intel not available/.test(w.reason)), 'missing inputs say so, at 0 points');
  assert.equal(ML.shape('Login failed for alice from 10.0.0.1 port 51515'), ML.shape('Login failed for alice from 10.0.0.9 port 4444'), 'IPs and numbers masked for clustering');
});

test('queue: priority sorted, intel / UEBA / clusters explained, filters validated; overview figures', async () => {
  const intel = { lookup: (v) => (v === '203.0.113.66' ? ['abuse-ch-synthetic'] : []) };
  const ueba = { entities: () => ({ items: [{ id: 'user:carol', tier: 'critical' }] }), summary: () => ({ tiers: { critical: 1, high: 0, elevated: 0, low: 3 }, top_risky: [{ id: 'user:carol', name: 'carol', type: 'user', risk_score: 91, tier: 'critical' }], new_findings: [] }) };
  const w = world({ intel, ueba }); try {
    for (let i = 0; i < 5; i++) w.raise({ rule_id: 'SENTRA-NET-009', rule_name: 'Port scan', severity: 1, group_key: 'scan' + i, group: { src: 'h' + i }, summary: 'Port scan from 10.1.1.' + i + ' to 40 ports' });
    const hot = w.raise({ rule_id: 'SENTRA-M365-001', rule_name: 'Risky sign-in', severity: 3, group: { user: 'carol' }, fields: { src_ip: '203.0.113.66' }, summary: 'Risky sign-in for carol <img src=x onerror=alert(1)>' });
    let r = await w.api.call('GET', '/api/soc/soc/queue', { role: 'viewer' }); assert.equal(r.status, 200, JSON.stringify(r.body));
    assert.equal(r.body.items[0].id, hot.id, 'intel + critical UEBA + severity float to the top');
    const why = r.body.items[0].why.map((x) => x.factor);
    assert.ok(why.includes('threat intel') && why.includes('behaviour (UEBA)'));
    assert.ok(r.body.items[0].priority >= 70 && r.body.items[0].label === 'act-now');
    assert.equal(r.body.items.find((x) => x.rule_id === 'SENTRA-NET-009').cluster.size, 5, 'five port scans are one cluster');
    r = await w.api.call('GET', '/api/soc/soc/queue?collapse=1', { role: 'viewer' }); assert.equal(r.body.items.length, 2, 'collapsed to one row per cluster');
    r = await w.api.call('GET', '/api/soc/soc/queue?label=act-now', { role: 'viewer' }); assert.equal(r.body.items.length, 1);
    r = await w.api.call('GET', '/api/soc/soc/queue?severity=9', { role: 'viewer' }); assert.equal(r.status, 400); assert.match(r.body.error, /severity must be/);
    r = await w.api.call('GET', '/api/soc/soc/queue?label=urgent', { role: 'viewer' }); assert.equal(r.status, 400); assert.match(r.body.error, /^label must be one of/);
    r = await w.api.call('GET', '/api/soc/soc/overview', { role: 'viewer' }); assert.equal(r.status, 200);
    const o = r.body;
    assert.equal(o.open.total, 6); assert.equal(o.open.by_severity[1], 5); assert.equal(o.series.length, 14);
    assert.equal(o.series.at(-1).raised, 6, 'raised today'); assert.equal(o.act_now[0].id, hot.id);
    assert.equal(o.ueba.top[0].id, 'user:carol'); assert.equal(o.ai.agreement_pct, null, 'no agreement figure before 3 closed triages');
    assert.ok(o.top_rules.some((x) => x.key === 'Port scan' && x.count === 5));
  } finally { w.cleanup(); }
});

test('AI triage: role-filtered tools, re-checked per call, evidence must cite what a tool returned; a person decides', async () => {
  const ueba = { entities: () => ({ items: [] }), entity: () => ({ entity: { id: 'user:dave' }, risk: { score: 40, tier: 'elevated', contributions: [] }, findings: [], peer_comparison: [] }) };
  const w = world({ ueba }); try {
    const a = w.raise({ rule_id: 'SENTRA-AUTH-001', group: { user: 'dave' }, fields: { src_ip: '198.51.100.9' }, summary: 'Brute force then success for dave' });
    w.setScript([
      turn([use('t1', 'get_alert', { id: a.id }), use('t2', 'related_alerts', { id: a.id, hours: 24 }), use('t3', 'rule_history', { rule_id: 'SENTRA-AUTH-001' })]),
      turn([use('t4', 'submit_triage', { verdict: 'true_positive', confidence: 'medium', severity: 3, summary: 'Ten failures then a success for dave from an external IP.', reasoning: 'synthetic',
        evidence: [{ ref: a.id, fact: 'brute force then success' }, { ref: 'user:dave', fact: 'the account' }, { ref: 'ALR-9999999', fact: 'made up' }], next_steps: ['Confirm with dave'], mitre: ['T1110', 'not-a-technique'], playbook: 'PB-ACCOUNT-COMPROMISE' })]),
    ]);
    let r = await w.api.call('POST', '/api/soc/soc/triage/' + a.id, { role: 'viewer', user: 'v.syn' }); assert.equal(r.status, 403, 'a viewer cannot spend AI budget');
    r = await w.api.call('POST', '/api/soc/soc/triage/' + a.id, { role: 'operator', user: 'omar.syn' }); assert.equal(r.status, 200, JSON.stringify(r.body));
    const t = r.body;
    assert.equal(t.state, 'draft'); assert.equal(t.draft.verdict, 'true_positive');
    assert.deepEqual(t.draft.evidence.map((e) => e.verified), [true, true, false], 'an id no tool returned is marked unverified');
    assert.equal(t.unverified, 1); assert.deepEqual(t.draft.mitre, ['T1110']);
    assert.ok(w.calls[0].tools.some((x) => x.name === 'entity_profile'), 'an operator is offered the UEBA profile');
    assert.match(w.calls[0].system, /SECURITY RULES/); assert.match(w.calls[1].messages.at(-1).content[0].content, /^<untrusted source="tool:get_alert">/);
    assert.equal(w.alerts.get(a.id).status, 'new', 'the AI changed nothing');
    assert.ok(w.api.audits.some((x) => x.action === 'soc.triage' && x.target === a.id));
    // decisions: validation, service identity refused, then accept with a case (approval requests raised, nothing executed)
    r = await w.api.call('POST', '/api/soc/soc/triage/' + a.id + '/decide', { role: 'operator', user: 'omar.syn', body: { decision: 'reject' } }); assert.equal(r.status, 400); assert.match(r.body.error, /note is required/);
    r = await w.api.call('POST', '/api/soc/soc/triage/' + a.id + '/decide', { role: 'operator', user: 'omar.syn', body: { decision: 'maybe' } }); assert.equal(r.status, 400); assert.match(r.body.error, /^decision must be one of/);
    r = await w.api.call('POST', '/api/soc/soc/triage/' + a.id + '/decide', { role: 'operator', user: 'ai:bot', body: { decision: 'accept' } }); assert.equal(r.status, 403); assert.match(r.body.error, /only a person/);
    r = await w.api.call('POST', '/api/soc/soc/triage/' + a.id + '/decide', { role: 'viewer', user: 'v.syn', body: { decision: 'accept' } }); assert.equal(r.status, 403);
    r = await w.api.call('POST', '/api/soc/soc/triage/' + a.id + '/decide', { role: 'operator', user: 'omar.syn', body: { decision: 'accept', open_case: true } }); assert.equal(r.status, 200, JSON.stringify(r.body));
    const cs = w.cases.get(r.body.case_id); assert.equal(cs.playbook_id, 'PB-ACCOUNT-COMPROMISE'); assert.ok(r.body.approvals > 0, 'containment steps are approval requests');
    r = await w.api.call('POST', '/api/soc/soc/triage/' + a.id + '/decide', { role: 'operator', user: 'omar.syn', body: { decision: 'accept' } }); assert.equal(r.status, 409, 'decided once');
    assert.ok(w.api.audits.some((x) => x.action === 'soc.triage.decide' && x.detail.case_id === cs.id));
    r = await w.api.call('GET', '/api/soc/soc/triage/' + a.id, { role: 'viewer' }); assert.equal(r.body.state, 'accepted'); assert.equal(r.body.decided_by, 'omar.syn');
    assert.equal((await w.api.call('GET', '/api/soc/soc/triage/' + 'nope', { role: 'viewer' })).status, 404);
  } finally { w.cleanup(); }
});

test('accepting with a closure closes the alert in the person\'s name; agreement is measured', async () => {
  const w = world(); try {
    const ids = [];
    for (let i = 0; i < 3; i++) {
      const a = w.raise({ rule_id: 'SENTRA-WIN-007', rule_name: 'Admin share access', group_key: 'g' + i, group: { host: 'pc-' + i }, summary: 'synthetic ' + i });
      w.setScript([turn([use('s' + i, 'submit_triage', { verdict: 'false_positive', confidence: 'high', summary: 'backup job (synthetic)', evidence: [] })])]);
      assert.equal((await w.api.call('POST', '/api/soc/soc/triage/' + a.id, { role: 'operator', user: 'nora.syn' })).status, 200);
      const r = await w.api.call('POST', '/api/soc/soc/triage/' + a.id + '/decide', { role: 'operator', user: 'nora.syn', body: { decision: 'accept', close: 'false-positive', note: 'backup window' } });
      assert.equal(r.status, 200, JSON.stringify(r.body)); assert.equal(r.body.closed, 'false-positive'); ids.push(a.id);
    }
    assert.equal(w.alerts.get(ids[0]).status, 'closed-false-positive');
    assert.ok((w.alerts.get(ids[0]).history || []).some((h) => h.by === 'nora.syn'), 'closed by the person, not the AI');
    const o = (await w.api.call('GET', '/api/soc/soc/overview', { role: 'viewer' })).body;
    assert.equal(o.ai.agreement_pct, 100); assert.equal(o.ai.accepted, 3);
    const r = await w.api.call('POST', '/api/soc/soc/triage/' + ids[0] + '/decide', { role: 'operator', user: 'nora.syn', body: { decision: 'reject', note: 'x', close: 'benign' } });
    assert.equal(r.status, 400, 'close goes with accept only - and validation runs before the state check');
  } finally { w.cleanup(); }
});

test('the model gets no draft through without the schema; no SDK / key reads as unavailable; settings are admin-only', async () => {
  const w = world(); try {
    const a = w.raise({});
    w.setScript([turn([use('b1', 'submit_triage', { verdict: 'pwned', confidence: 'high', summary: 'x', evidence: [] })]), turn([{ type: 'text', text: 'I will not submit.' }], 'end_turn')]);
    let r = await w.api.call('POST', '/api/soc/soc/triage/' + a.id, { role: 'operator', user: 'nora.syn' });
    assert.equal(r.status, 502); assert.match(r.body.error, /did not return a triage/);
    w.deps.config.secrets = {}; const prev = process.env.ANTHROPIC_API_KEY; delete process.env.ANTHROPIC_API_KEY;
    r = await w.api.call('POST', '/api/soc/soc/triage/' + a.id, { role: 'operator', user: 'nora.syn' }); assert.equal(r.status, 503); assert.match(r.body.error, /no Anthropic API key/);
    if (prev !== undefined) process.env.ANTHROPIC_API_KEY = prev;
    r = await w.api.call('PUT', '/api/soc/soc/analyst/settings', { role: 'operator', body: { auto: true } }); assert.equal(r.status, 403);
    r = await w.api.call('PUT', '/api/soc/soc/analyst/settings', { role: 'admin', body: { min_severity: 9 } }); assert.equal(r.status, 400); assert.match(r.body.error, /min_severity must be at most 4/);
    r = await w.api.call('PUT', '/api/soc/soc/analyst/settings', { role: 'admin', body: {} }); assert.equal(r.status, 400);
    r = await w.api.call('PUT', '/api/soc/soc/analyst/settings', { role: 'admin', user: 'syed', body: { auto: true, min_severity: 3 } }); assert.equal(r.status, 200);
    assert.equal(r.body.settings.auto, true); assert.ok(w.api.audits.some((x) => x.action === 'soc.analyst.settings'));
    assert.equal((await w.api.call('GET', '/api/soc/soc/analyst/settings', { role: 'viewer' })).body.settings.auto, true);
  } finally { w.cleanup(); }
});

test('auto-triage runs as the service identity with the analyst role: no UEBA profile tool, capped per hour', async () => {
  const w = world(); try {
    const A = w.deps.analyst;
    A.putSettings({ auto: true, min_severity: 3, max_per_hour: 1 }, 'syed');
    w.raise({ group_key: 'a1', created: NOW }); w.raise({ group_key: 'a2', created: NOW });
    w.setScript([turn([use('u1', 'entity_profile', { entity: 'user:x' }), use('u2', 'submit_triage', { verdict: 'needs_more_data', confidence: 'low', summary: 'synthetic', evidence: [] })])]);
    const r = await A.autoTick();
    assert.equal(r.ran, 1, 'capped at one per hour');
    assert.ok(!w.calls[0].tools.some((t) => t.name === 'entity_profile'), 'the analyst role is not offered personal behaviour profiles');
    const t = w.state.collection('soc_ai_triage').all()[0];
    assert.equal(t.requested_by, 'ai:soc-analyst'); assert.ok(t.steps.some((s) => s.tool === 'entity_profile' && s.refused), 'and a call to it anyway is refused in code');
    assert.ok(TOOLS.find((x) => x.name === 'submit_triage'));
  } finally { w.cleanup(); }
});

test('createAnalyst needs state and alerts', () => { assert.throws(() => createAnalyst({}), /needs state and alerts/); });
