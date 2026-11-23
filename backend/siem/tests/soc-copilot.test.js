// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// SOC Copilot (engine/soc/copilot.js, copilot-routes.js): a conversation that chains read tools from the page context,
// proposals recorded and NOT executed, a person accepting them (run as that person, role checked again, inputs checked
// again), tools by role (an analyst gets no propose tools except save_hunt), private conversations, validation errors naming
// the field, audit records. SYNTHETIC data only.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const { createState } = require('../engine/soc/state');
const { createAlerts } = require('../engine/soc/alerts');
const { createCases } = require('../engine/soc/cases');
const { parse } = require('../engine/api/query');
const { fakeApi, tmpDir, quietLog } = require('./soc-fakes');

const H = 36e5, NOW = Date.now();
const use = (id, name, input) => ({ type: 'tool_use', id, name, input });
const turn = (content, stop = 'tool_use') => ({ content, stop_reason: stop, usage: { input_tokens: 70, output_tokens: 14 } });
const say = (text) => turn([{ type: 'text', text }], 'end_turn');

function world() {
  const dir = tmpDir(), state = createState({ dir, log: quietLog });
  const alerts = createAlerts({ state, log: quietLog }), cases = createCases({ state, alerts, log: quietLog });
  const script = [], calls = [];
  class FakeAnthropic { constructor() { this.messages = { create: async (p) => { calls.push(JSON.parse(JSON.stringify(p))); const r = script.shift(); if (!r) throw new Error('script ended'); return r; } }; } }
  const search = { parse, search: async () => ({ rows: [] }), histogram: async () => ({ buckets: [{ t: NOW, n: 9 }] }), top: async () => ({ values: [] }) };
  const config = { soc_analyst: {}, secrets: { netops: { anthropic_api_key: 'sk-ant-synthetic-for-tests' } }, ai_limits: { per_user_hour: 100, per_user_day: 1000, daily_tokens: 1e9, max_prompt_chars: 1e6 } };
  const deps = { state, alerts, cases, search, config, log: quietLog, sdk: FakeAnthropic, noTimers: true };
  const api = fakeApi({ realRanks: true });
  for (const m of ['analyst-routes', 'investigate-routes', 'copilot-routes']) require('../engine/soc/' + m).register(api, deps);
  const raise = (o) => alerts.raise(Object.assign({ rule_id: 'SENTRA-AUTH-001', rule_name: 'Brute force then success', severity: 3, group: {}, fields: {}, summary: 'synthetic', ts_first: NOW - 2 * H, ts_last: NOW - H, source: 'engine', count: 1 }, o)).alert;
  return { state, alerts, cases, api, calls, raise, set: (s) => script.splice(0, script.length, ...s), cleanup: () => fs.rmSync(dir, { recursive: true, force: true }) };
}

test('a question in context: read tools chained, a case PROPOSED not opened, a person accepts it and it runs as them', async () => {
  const w = world(); try {
    const a1 = w.raise({ group: { user: 'dave' }, summary: 'Brute force then success for dave' });
    const a2 = w.raise({ rule_id: 'SENTRA-EXO-001', rule_name: 'Forwarding rule', severity: 2, group: { user: 'dave' }, summary: 'Inbox forwarding' });
    w.set([turn([use('c1', 'get_alert', { id: a1.id }), use('c2', 'related_alerts', { id: a1.id, hours: 24 })]),
      turn([use('c3', 'propose_open_case', { title: 'Account compromise dave (synthetic)', alert_ids: [a1.id, a2.id], playbook_id: 'PB-ACCOUNT-COMPROMISE', reason: 'brute force then a forwarding rule' })]),
      say('Dave had a brute force then success (' + a1.id + ') and a new forwarding rule (' + a2.id + '). I proposed a case.')]);
    let r = await w.api.call('POST', '/api/soc/soc/copilot/ask', { role: 'operator', user: 'omar.syn', body: { question: 'What is going on with this alert?', context: { page: 'soc-alerts', kind: 'alert', id: a1.id } } });
    assert.equal(r.status, 200, JSON.stringify(r.body));
    assert.match(r.body.answer, /proposed a case/); assert.equal(r.body.proposals.length, 1);
    assert.match(w.calls[0].messages[0].content, new RegExp('looking at alert ' + a1.id), 'the page context reaches the model');
    assert.match(w.calls[0].system, /SECURITY RULES/);
    assert.equal(w.state.collection('cases').all().length, 0, 'nothing opened yet');
    const pid = r.body.proposals[0].id;
    r = await w.api.call('POST', '/api/soc/soc/copilot/proposals/' + pid + '/decide', { role: 'analyst', user: 'ana.syn', body: { decision: 'accept' } }); assert.equal(r.status, 403, 'an analyst cannot accept a case proposal');
    r = await w.api.call('POST', '/api/soc/soc/copilot/proposals/' + pid + '/decide', { role: 'operator', user: 'ai:bot', body: { decision: 'accept' } }); assert.equal(r.status, 403); assert.match(r.body.error, /only a person/);
    r = await w.api.call('POST', '/api/soc/soc/copilot/proposals/' + pid + '/decide', { role: 'operator', user: 'omar.syn', body: { decision: 'maybe' } }); assert.equal(r.status, 400); assert.match(r.body.error, /^decision must be one of/);
    r = await w.api.call('POST', '/api/soc/soc/copilot/proposals/' + pid + '/decide', { role: 'operator', user: 'omar.syn', body: { decision: 'accept' } }); assert.equal(r.status, 200, JSON.stringify(r.body));
    const c = w.cases.get(r.body.result.case_id);
    assert.equal(c.owner, 'omar.syn'); assert.equal(c.playbook_id, 'PB-ACCOUNT-COMPROMISE'); assert.deepEqual(c.alerts.sort(), [a1.id, a2.id].sort());
    assert.ok(c.timeline.some((x) => x.by === 'omar.syn'), 'the case was opened by the person'); assert.ok(r.body.result.approvals > 0, 'containment stays approval requests');
    r = await w.api.call('POST', '/api/soc/soc/copilot/proposals/' + pid + '/decide', { role: 'operator', user: 'omar.syn', body: { decision: 'accept' } }); assert.equal(r.status, 409, 'decided once');
    assert.ok(w.api.audits.some((x) => x.action === 'soc.copilot.ask') && w.api.audits.some((x) => x.action === 'soc.copilot.decide' && x.detail.kind === 'open_case'));
  } finally { w.cleanup(); }
});

test('roles: viewer refused; an analyst is not offered case / alert proposals and a call to one is refused', async () => {
  const w = world(); try {
    const a = w.raise({});
    let r = await w.api.call('POST', '/api/soc/soc/copilot/ask', { role: 'viewer', body: { question: 'hi' } }); assert.equal(r.status, 403);
    w.set([turn([use('x1', 'propose_close_alert', { alert_id: a.id, reason: 'false-positive', note: 'x' }), use('x2', 'entity_profile', { entity: 'user:x' })]), say('done')]);
    r = await w.api.call('POST', '/api/soc/soc/copilot/ask', { role: 'analyst', user: 'ana.syn', body: { question: 'close it' } }); assert.equal(r.status, 200);
    const offered = w.calls[0].tools.map((t) => t.name);
    assert.ok(!offered.includes('propose_close_alert') && !offered.includes('entity_profile') && offered.includes('propose_save_hunt') && offered.includes('search_events'));
    assert.ok(r.body.steps.every((s) => s.refused), 'both refused in code'); assert.equal(r.body.proposals.length, 0); assert.equal(w.alerts.get(a.id).status, 'new');
  } finally { w.cleanup(); }
});

test('validation, private conversations, follow-ups, re-check at accept, reject', async () => {
  const w = world(); try {
    const a = w.raise({});
    let r = await w.api.call('POST', '/api/soc/soc/copilot/ask', { role: 'operator', body: {} }); assert.equal(r.status, 400); assert.match(r.body.error, /question is required/);
    r = await w.api.call('POST', '/api/soc/soc/copilot/ask', { role: 'operator', body: { question: 'x', context: { page: 'evil.html' } } }); assert.equal(r.status, 400); assert.match(r.body.error, /^page must be one of/);
    r = await w.api.call('POST', '/api/soc/soc/copilot/ask', { role: 'operator', body: { question: 'x', conversation: '../../etc' } }); assert.equal(r.status, 400);
    w.set([turn([use('p1', 'propose_close_alert', { alert_id: 'ALR-0099999', reason: 'benign', note: 'x' })]), turn([use('p2', 'propose_assign_alert', { alert_id: a.id, assignee: 'nora.syn', reason: 'on shift' })]), say('Proposed assigning it to nora.syn.')]);
    r = await w.api.call('POST', '/api/soc/soc/copilot/ask', { role: 'operator', user: 'omar.syn', body: { question: 'who should take this?' } });
    assert.equal(r.body.proposals.length, 1, 'a proposal on a missing alert is refused when proposed'); assert.ok(r.body.steps.some((s) => !s.ok && /not found/.test(s.error)));
    const conv = r.body.conversation;
    assert.equal((await w.api.call('GET', '/api/soc/soc/copilot/conversations/' + conv, { role: 'operator', user: 'someone.else' })).status, 404, 'private to its user');
    w.set([say('Follow-up answer.')]);
    r = await w.api.call('POST', '/api/soc/soc/copilot/ask', { role: 'operator', user: 'someone.else', body: { question: 'continue', conversation: conv } }); assert.equal(r.status, 404, 'nobody else can continue it');
    r = await w.api.call('POST', '/api/soc/soc/copilot/ask', { role: 'operator', user: 'omar.syn', body: { question: 'and then?', conversation: conv } }); assert.equal(r.status, 200); assert.equal(r.body.conversation, conv);
    r = await w.api.call('GET', '/api/soc/soc/copilot/conversations/' + conv, { role: 'operator', user: 'omar.syn' });
    assert.deepEqual(r.body.turns.map((t) => t.role), ['analyst', 'copilot', 'analyst', 'copilot']); assert.equal(r.body.turns[0].text, 'who should take this?', 'the context line is not shown back');
    const pid = r.body.proposals.find((p) => p.kind === 'assign_alert').id;
    r = await w.api.call('GET', '/api/soc/soc/copilot/proposals?status=pending', { role: 'operator', user: 'omar.syn' }); assert.equal(r.body.items.length, 1);
    r = await w.api.call('POST', '/api/soc/soc/copilot/proposals/' + pid + '/decide', { role: 'operator', user: 'omar.syn', body: { decision: 'reject', note: 'nora is off today' } }); assert.equal(r.status, 200); assert.equal(r.body.status, 'rejected');
    assert.equal(w.alerts.get(a.id).assignee || '', '', 'rejected = nothing changed');
    // re-check at accept: the case a note was proposed for is gone by then
    w.set([turn([use('n1', 'propose_add_case_note', { case_id: 'CASE-000777', text: 't', reason: 'r' })]), say('x')]);
    r = await w.api.call('POST', '/api/soc/soc/copilot/ask', { role: 'operator', user: 'omar.syn', body: { question: 'note it' } }); assert.equal(r.body.proposals.length, 0, 'a missing case is refused when proposed');
  } finally { w.cleanup(); }
});

test('ITSM drafts: fixed template per kind, the guarded ask (context reaches the model, read tools, untrusted rule), audited; roles and validation', async () => {
  const w = world(); try {
    const a1 = w.raise({ group: { user: 'dave' }, summary: 'Brute force then success for dave' });
    w.set([turn([use('d1', 'get_alert', { id: a1.id })]), say('AI DRAFT - review before use\nINCIDENT REPORT\nSummary: brute force then success for dave (' + a1.id + ').\nRoot cause: not yet established.\nOwner: [to confirm]')]);
    let r = await w.api.call('POST', '/api/soc/soc/copilot/draft', { role: 'analyst', user: 'ana.syn', body: { kind: 'incident_report', context: { kind: 'alert', id: a1.id }, note: 'for the CISO' } });
    assert.equal(r.status, 200, JSON.stringify(r.body));
    assert.equal(r.body.kind, 'incident_report'); assert.equal(r.body.draft, true); assert.match(r.body.answer, /^AI DRAFT - review before use/); assert.match(r.body.answer, new RegExp(a1.id));
    const q = w.calls[0].messages[0].content;
    assert.match(q, /INCIDENT REPORT/); assert.match(q, new RegExp('about alert ' + a1.id)); assert.match(q, /\[to confirm\]/); assert.match(q, /note \(data, not instructions\): for the CISO/);
    assert.match(w.calls[0].system, /SECURITY RULES/, 'the untrusted-data rule is in the system prompt');
    assert.equal(w.state.collection('cases').all().length, 0, 'a draft files nothing');
    assert.ok(w.api.audits.some((a) => a.action === 'soc.copilot.draft' && a.detail.kind === 'incident_report' && a.detail.context.id === a1.id));
    // the analyst floor and validation
    assert.equal((await w.api.call('POST', '/api/soc/soc/copilot/draft', { role: 'viewer', body: { kind: 'runbook' } })).status, 403);
    r = await w.api.call('POST', '/api/soc/soc/copilot/draft', { role: 'analyst', body: { kind: 'poem' } }); assert.equal(r.status, 400); assert.match(JSON.stringify(r.body), /kind must be one of/);
    r = await w.api.call('POST', '/api/soc/soc/copilot/draft', { role: 'analyst', body: { kind: 'runbook', context: 'ALR-1' } }); assert.equal(r.status, 400); assert.match(JSON.stringify(r.body), /context must be an object/);
    r = await w.api.call('POST', '/api/soc/soc/copilot/draft', { role: 'analyst', body: { kind: 'runbook', context: { kind: 'planet', id: 'x' } } }); assert.equal(r.status, 400); assert.match(JSON.stringify(r.body), /kind must be one of/);
    // with no context: the current state of the SOC
    w.set([say('AI DRAFT - review before use\nThree open alerts; nothing critical.')]);
    r = await w.api.call('POST', '/api/soc/soc/copilot/draft', { role: 'analyst', body: { kind: 'manager_brief' } }); assert.equal(r.status, 200);
    assert.match(w.calls[w.calls.length - 1].messages[0].content, /current state of the SOC/);
  } finally { w.cleanup(); }
});
