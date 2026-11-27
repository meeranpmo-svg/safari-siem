// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Agent Workspace (engine/soc/workspace.js) over SYNTHETIC alerts, rules and cases with an injected model: a workflow is checked
// against the catalogue (undeclared fields dropped, a change without an approval step refused, named errors); a template makes a
// draft; four-eyes publishing (the author cannot, a service identity cannot, a reject needs a reason, any edit makes it a draft
// again); a test run describes actions and passes approvals; a real run reads data, runs the agent through the guard, stops on a
// failed condition, waits for a person who is neither the author nor the starter, then creates the case; a rejected run takes no
// action; the schedule and new-alert triggers start runs, one at a time; roles (viewer refused, operator builds, admin publishes);
// every state change audited.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs'), os = require('node:os'), path = require('node:path');
const W = require('../engine/soc/workspace');
const { createState } = require('../engine/soc/state');
const { fakeApi } = require('./soc-fakes');

const NOW0 = Date.parse('2026-11-27T09:00:00Z'), H = 36e5, MIN = 60000;
async function world(t, o = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ws-')); t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const state = await createState({ dir, log: { info() {}, warn() {}, error() {} } });
  let now = NOW0; const clock = () => now;
  const A = new Map([['AL-1', { id: 'AL-1', created: NOW0 - H, severity: 4, rule_name: 'Brute force on DC', summary: 'brute force dc-syn-01', status: 'new' }],
    ['AL-2', { id: 'AL-2', created: NOW0 - 2 * H, severity: 3, rule_name: 'Brute force on DC', summary: 'brute force dc-syn-02', status: 'new' }],
    ['AL-3', { id: 'AL-3', created: NOW0 - 50 * H, severity: 1, rule_name: 'Info', summary: 'old', status: 'closed-benign' }]]);
  const notes = [], cases = [], prompts = [];
  const deps = { state, now: clock, noTimer: true, log: { info() {}, warn() {}, error() {}, every() {} }, config: { org: 'Safari (synthetic)' },
    alerts: { all: (f) => [...A.values()].filter((a) => !f || f(a)), get: (id) => A.get(id), note: (id, text, by) => notes.push({ id, text, by }) },
    cases: { create: (input, by) => { const c = { id: 'CASE-' + (cases.length + 1), input, by }; cases.push(c); input.alert_ids.forEach((i) => { A.get(i).case_id = c.id; }); return c; } },
    detector: { stats: () => ({ rules: [{ id: 'r1', name: 'Brute force on DC', matches: 900, suppressed: 850, alerts: 12 }, { id: 'r2', name: 'Quiet', matches: 0, alerts: 0 }] }) },
    model: o.model || (async ({ system, prompt }) => { prompts.push({ system, prompt }); return { text: 'Two alerts look real. Check dc-syn-01 first.', usage: { input_tokens: 10, output_tokens: 5 } }; }) };
  const api = fakeApi({ realRanks: true }); W.register(api, deps);
  const call = (m, p, who, b) => api.call(m, '/api/soc' + p, Object.assign({ body: b }, who));
  return { deps, api, call, A, notes, cases, prompts, state, setNow: (x) => { now = x; } };
}
const OP = { user: 'nora.syn', role: 'operator' }, OP2 = { user: 'omar.syn', role: 'operator' }, ADM = { user: 'syed.syn', role: 'admin' }, ADM2 = { user: 'lina.syn', role: 'admin' }, VW = { user: 'vera.syn', role: 'viewer' }, BOT = { user: 'ai:desk', role: 'admin' };

test('validation: catalogue only, named errors, undeclared fields dropped, a change needs an approval before it', () => {
  const ok = W.cleanWorkflow({ name: 'Syn flow', trigger: { type: 'manual', extra: 1 }, steps: [{ type: 'alerts', window_h: 4, evil: 'x' }, { type: 'agent', agent: 'triage' }, { type: 'action', action: 'report' }], owner: 'x' });
  assert.deepEqual(ok.trigger, { type: 'manual' }); assert.equal(ok.steps[0].evil, undefined); assert.equal(ok.owner, undefined); assert.equal(ok.steps[0].window_h, 4);
  assert.throws(() => W.cleanWorkflow({ name: 'Syn', trigger: { type: 'manual' }, steps: [{ type: 'shell', cmd: 'rm' }] }), /type must be one of/);
  assert.throws(() => W.cleanWorkflow({ name: 'Syn', trigger: { type: 'manual' }, steps: [{ type: 'alerts', window_h: 9999 }] }), /steps\[0\]\.window_h must be at most 720/);
  assert.throws(() => W.cleanWorkflow({ name: 'Syn', trigger: { type: 'manual' }, steps: [{ type: 'alerts' }, { type: 'action', action: 'create_case' }] }), /put a "Person approves" step before it/);
  assert.throws(() => W.cleanWorkflow({ name: 'Syn', trigger: { type: 'schedule', every_min: 7 }, steps: [{ type: 'rules' }] }), /every_min must be one of/);
  assert.throws(() => W.cleanWorkflow({ name: 'Syn', trigger: { type: 'manual' }, steps: [{ type: 'agent', agent: 'triage' }] }), /needs a data step before it/);
  assert.throws(() => W.cleanWorkflow({ name: 'Syn', trigger: { type: 'manual' }, steps: [{ type: 'alerts', from_trigger: true }] }), /needs the new-alerts trigger/);
  assert.throws(() => W.cleanWorkflow({ name: 'Syn', trigger: { type: 'manual' }, steps: [{ type: 'agent', agent: 'hacker' }] }), /agent must be one of/);
});

test('roles and four-eyes publishing; any edit makes it a draft again; audited', async (t) => {
  const w = await world(t);
  assert.equal((await w.call('GET', '/workspace', VW)).status, 403, 'a viewer is refused');
  assert.equal((await w.call('POST', '/workspace/workflows', VW, { template: 'tuning' })).status, 403);
  let r = await w.call('POST', '/workspace/workflows', OP, { template: 'tuning' }); assert.equal(r.status, 200, JSON.stringify(r.body)); const id = r.body.id;
  assert.equal(r.body.status, 'draft'); assert.equal(r.body.author, 'nora.syn');
  assert.equal((await w.call('POST', '/workspace/workflows', OP, { template: 'nope' })).status, 400);
  assert.equal((await w.call('POST', '/workspace/workflows/' + id + '/decide', ADM, { decision: 'publish' })).status, 409, 'not submitted yet');
  assert.equal((await w.call('POST', '/workspace/workflows/' + id + '/submit', OP)).status, 200);
  assert.equal((await w.call('POST', '/workspace/workflows/' + id + '/decide', OP2, { decision: 'publish' })).status, 403, 'an operator does not publish');
  assert.equal((await w.call('POST', '/workspace/workflows/' + id + '/decide', BOT, { decision: 'publish' })).status, 403, 'a service / AI identity does not publish');
  assert.equal((await w.call('POST', '/workspace/workflows/' + id + '/decide', { user: 'nora.syn', role: 'admin' }, { decision: 'publish' })).status, 403, 'the author does not publish');
  assert.equal((await w.call('POST', '/workspace/workflows/' + id + '/decide', ADM, { decision: 'reject' })).status, 400, 'a reject needs a reason');
  r = await w.call('POST', '/workspace/workflows/' + id + '/decide', ADM, { decision: 'publish', comment: 'ok' }); assert.equal(r.body.status, 'published'); assert.equal(r.body.published_by, 'syed.syn');
  r = await w.call('PUT', '/workspace/workflows/' + id, OP2, { name: 'Tuning v2', trigger: { type: 'manual' }, steps: [{ type: 'rules' }] }); assert.equal(r.body.status, 'draft'); assert.equal(r.body.version, 2);
  assert.equal((await w.call('POST', '/workspace/workflows/' + id + '/run', OP, {})).status, 409, 'a draft runs only as a test');
  const acts = w.api.audits.map((a) => a.action);
  for (const a of ['workspace.workflow.create', 'workspace.workflow.submit', 'workspace.workflow.publish', 'workspace.workflow.update']) assert.ok(acts.includes(a), a);
});

test('a test run describes actions and passes approvals; a real run waits for a person, then creates the case', async (t) => {
  const w = await world(t);
  const wf = (await w.call('POST', '/workspace/workflows', OP, { name: 'Syn triage', trigger: { type: 'manual' }, steps: [{ type: 'alerts', window_h: 24, min_severity: 3 }, { type: 'condition', field: 'count', op: '>', value: 0 }, { type: 'agent', agent: 'triage', instructions: 'be brief' }, { type: 'approval', role: 'operator' }, { type: 'action', action: 'create_case' }] })).body;
  let r = await w.call('POST', '/workspace/workflows/' + wf.id + '/run', OP, { test: true }); assert.equal(r.status, 200, JSON.stringify(r.body));
  assert.equal(r.body.status, 'done'); assert.equal(r.body.steps[0].out.count, 2); assert.match(r.body.steps[3].out.would_wait, /neither nora\.syn/); assert.match(r.body.steps[4].out.would, /Create a case .*2 alert/); assert.equal(w.cases.length, 0, 'a test run changes nothing');
  await w.call('POST', '/workspace/workflows/' + wf.id + '/submit', OP); await w.call('POST', '/workspace/workflows/' + wf.id + '/decide', ADM, { decision: 'publish' });
  r = await w.call('POST', '/workspace/workflows/' + wf.id + '/run', OP2, {}); assert.equal(r.body.status, 'waiting'); const run = r.body.id;
  assert.equal(r.body.steps[2].out.text, 'Two alerts look real. Check dc-syn-01 first.');
  assert.equal((await w.call('POST', '/workspace/workflows/' + wf.id + '/run', OP2, {})).status, 409, 'one run at a time');
  assert.equal((await w.call('POST', '/workspace/runs/' + run + '/decide', OP, { decision: 'approve' })).status, 403, 'the author does not approve');
  assert.equal((await w.call('POST', '/workspace/runs/' + run + '/decide', OP2, { decision: 'approve' })).status, 403, 'the starter does not approve');
  assert.equal((await w.call('POST', '/workspace/runs/' + run + '/decide', { user: 'svc:soar', role: 'admin' }, { decision: 'approve' })).status, 403, 'a service identity does not approve');
  assert.equal((await w.call('POST', '/workspace/runs/' + run + '/decide', VW, { decision: 'approve' })).status, 403, 'a viewer does not approve');
  assert.equal(w.cases.length, 0);
  r = await w.call('POST', '/workspace/runs/' + run + '/decide', ADM, { decision: 'approve' }); assert.equal(r.status, 200, JSON.stringify(r.body)); assert.equal(r.body.status, 'done');
  assert.equal(w.cases.length, 1); assert.deepEqual(w.cases[0].input.alert_ids, ['AL-1', 'AL-2']); assert.equal(w.cases[0].by, 'system:workspace'); assert.deepEqual(r.body.steps[4].out.approved_by, ['syed.syn']);
  assert.ok(w.api.audits.some((a) => a.action === 'workspace.run.approve'));
  const g = await w.call('GET', '/workspace/runs/' + run, { user: 'ana.syn', role: 'analyst' }); assert.equal(g.status, 200); assert.equal(g.body.steps.length, 5);
});

test('a failed condition stops the run; a rejected run takes no action', async (t) => {
  const w = await world(t);
  const mk = async (steps) => { const x = (await w.call('POST', '/workspace/workflows', OP, { name: 'Syn ' + steps.length, trigger: { type: 'manual' }, steps })).body; await w.call('POST', '/workspace/workflows/' + x.id + '/submit', OP); await w.call('POST', '/workspace/workflows/' + x.id + '/decide', ADM, { decision: 'publish' }); return x; };
  const a = await mk([{ type: 'alerts', min_severity: 4, window_h: 1 }, { type: 'condition', field: 'count', op: '>=', value: 5 }, { type: 'action', action: 'report' }]);
  let r = await w.call('POST', '/workspace/workflows/' + a.id + '/run', OP2, {}); assert.equal(r.body.status, 'stopped'); assert.equal(r.body.steps.length, 2);
  const b = await mk([{ type: 'alerts' }, { type: 'approval' }, { type: 'action', action: 'note_alerts', note: 'syn note' }]);
  r = await w.call('POST', '/workspace/workflows/' + b.id + '/run', OP2, {});
  assert.equal((await w.call('POST', '/workspace/runs/' + r.body.id + '/decide', ADM, { decision: 'reject' })).status, 400, 'a reject needs a reason');
  r = await w.call('POST', '/workspace/runs/' + r.body.id + '/decide', ADM, { decision: 'reject', comment: 'not now, synthetic' }); assert.equal(r.body.status, 'rejected'); assert.equal(w.notes.length, 0);
});

test('triggers: the schedule and new alerts start runs; AI not available is said and the run goes on', async (t) => {
  const w = await world(t, { model: async () => { throw Object.assign(new Error('AI budget used up (synthetic)'), { status: 429 }); } });
  const X = w.deps.workspace;
  const s = (await w.call('POST', '/workspace/workflows', OP, { template: 'shift' })).body; await w.call('POST', '/workspace/workflows/' + s.id + '/submit', OP); await w.call('POST', '/workspace/workflows/' + s.id + '/decide', ADM, { decision: 'publish' });
  const a = (await w.call('POST', '/workspace/workflows', OP, { name: 'Syn new alerts', trigger: { type: 'alert', min_severity: 3 }, steps: [{ type: 'alerts', from_trigger: true }, { type: 'action', action: 'report' }] })).body;
  await w.call('POST', '/workspace/workflows/' + a.id + '/submit', OP); await w.call('POST', '/workspace/workflows/' + a.id + '/decide', ADM2, { decision: 'publish' });
  await X.tick(); let runs = (await w.call('GET', '/workspace', OP)).body.runs; assert.equal(runs.length, 0, 'not due yet, no new alert');
  w.A.set('AL-9', { id: 'AL-9', created: NOW0 + 5 * MIN, severity: 4, rule_name: 'Syn', summary: 'new', status: 'new' }); w.A.set('AL-8', { id: 'AL-8', created: NOW0 + 5 * MIN, severity: 1, rule_name: 'Syn', summary: 'low', status: 'new' });
  w.setNow(NOW0 + 13 * H); await X.tick();
  runs = (await w.call('GET', '/workspace', OP)).body.runs; assert.equal(runs.length, 2);
  const ar = (await w.call('GET', '/workspace/runs/' + runs.find((r) => r.wf === a.id).id, OP)).body; assert.deepEqual(ar.trigger.alert_ids, ['AL-9']); assert.equal(ar.steps[0].out.count, 1); assert.equal(ar.by_user, 'system:workspace');
  const sr = (await w.call('GET', '/workspace/runs/' + runs.find((r) => r.wf === s.id).id, OP)).body; assert.equal(sr.status, 'done'); assert.match(sr.steps[1].out.why, /AI not used: AI budget used up/);
});
