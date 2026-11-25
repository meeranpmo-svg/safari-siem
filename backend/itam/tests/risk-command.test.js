// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Risk Command Center (engine/risk-command.js) over the REAL risk register (engine/grc-registers.js through Risk Studio) and the scenario
// assessment, with SYNTHETIC risks: posture withheld on an empty register, then itemised; categories against appetite; treatment
// effectiveness and "mitigate" without a reduction; owner concentration; the Monte Carlo re-performs from its seed and moves with the
// ratings; history and movement; any role reads; the advisor refused to a viewer and off until allowed.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');
const { simulate, PROB } = require('../engine/risk-command');

const DAY = 86400000, VIEW = { user: 'vera.syn', role: 'viewer' }, OP = { user: 'nora.syn', role: 'operator' };
const RISKS = [['Ransomware on claims servers (synthetic)', 4, 5, 3, 5, 'mitigate', 'ali.syn'], ['Leaver accounts not disabled (synthetic)', 4, 4, 2, 3, 'mitigate', 'ali.syn'],
  ['Vendor outage of the policy system (synthetic)', 3, 5, 3, 5, 'mitigate', 'sara.syn'], ['PDPL breach notified late (synthetic)', 2, 5, null, null, 'accept', 'omar.syn']];

async function setup(t, now) {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true, now, python: process.env.PYTHON || 'python3' });
  return e;
}
async function seed(e) {
  for (const [title, likelihood, impact, rl, ri, treatment, owner] of RISKS) {
    const b = { title, likelihood, impact, treatment, owner, description: 'synthetic' }; if (rl) Object.assign(b, { residual_likelihood: rl, residual_impact: ri });
    const r = await e.req('POST', '/grc/risks', Object.assign({ body: b }, OP)); assert.equal(r.status, 200, r.raw);
  }
}

test('empty register: posture withheld, not safe', async (t) => {
  const e = await setup(t);
  const v = (await e.req('GET', '/risk-command', VIEW)).json;
  assert.equal(v.posture.value, null); assert.match(v.posture.why, /must not read as safe/); assert.equal(v.simulation, null);
  assert.equal(v.scenarios.length, 10, 'the ten insurer scenarios are listed');
});

test('posture itemised, categories, treatment effectiveness, owners, simulation, roles', async (t) => {
  const e = await setup(t); await seed(e);
  const v = (await e.req('GET', '/risk-command', VIEW)).json;
  assert.equal(v.kpis.open, 4); assert.equal(v.kpis.high, 2, 'two residual scores of 15');
  const sum = v.posture.items.reduce((s, x) => s + x.points, 0); assert.equal(v.posture.value, 100 + sum, 'posture = 100 less the itemised points');
  assert.ok(v.posture.items.some((x) => /open risks rated high \(2 x 6/.test(x.label)));
  assert.ok(v.categories.every((c) => typeof c.category === 'string' && c.category !== '[object Object]'));
  const mit = v.treatments.find((x) => x.treatment === 'mitigate'); assert.equal(mit.risks, 3); assert.equal(mit.reduced, 2); assert.equal(mit.reduction, (20 - 15) + (16 - 6) + 0);
  assert.deepEqual(v.no_reduction.map((x) => x.title), ['Vendor outage of the policy system (synthetic)'], 'mitigate with no reduction recorded');
  assert.equal(v.owners[0].owner, 'ali.syn'); assert.match(v.owner_concentration.why, /carry \d+ % of the residual score/);
  assert.ok(v.simulation.expected > 0 && v.simulation.p90 >= v.simulation.p50 && v.simulation.p_any_high > 0); assert.match(v.simulation.why, /not a forecast/);
  assert.ok(v.urgent.length >= 2 && v.urgent[0].score >= v.urgent[1].score);
  assert.equal((await e.req('POST', '/risk-command/ask', { body: { question: 'which risks first?' }, user: VIEW.user, role: VIEW.role })).status, 403);
  assert.equal((await e.req('POST', '/risk-command/ask', { body: { question: 'which risks first?' }, user: OP.user, role: OP.role })).status, 424);
});

test('Monte Carlo: re-performable from the seed, follows the ratings', () => {
  const a = simulate([{ l: 3, i: 5 }, { l: 2, i: 3 }], 4000, 7), b = simulate([{ l: 3, i: 5 }, { l: 2, i: 3 }], 4000, 7);
  assert.deepEqual(a, b, 'the same seed gives the same result');
  assert.ok(Math.abs(a.expected - (PROB[3] + PROB[2])) < 0.06, 'the mean is the sum of the probabilities: ' + a.expected);
  assert.ok(Math.abs(a.p_any_high - PROB[3] * 100) < 3, 'P(any high-impact) is the high risk\'s probability');
  const hi = simulate([{ l: 5, i: 5 }, { l: 5, i: 5 }], 4000, 7); assert.ok(hi.expected > a.expected);
  assert.equal(simulate([]), null);
});

test('history: a daily snapshot, movement against 30 days ago', async (t) => {
  let clock = Date.parse('2027-01-01T08:00:00Z');
  const e = await setup(t, () => clock); await seed(e);
  const X = e.app.addons.riskCommand;
  for (let d = 0; d < 32; d++) { assert.ok(await X.snapshot()); clock += DAY; }
  const v = (await e.req('GET', '/risk-command', OP)).json;
  assert.ok(v.posture.history.length >= 32); assert.equal(v.posture.move_30d, 0, 'unchanged register: no movement');
  assert.ok(v.posture.projection.why);
});

test('my brief: my risks and actions, the team\'s overdue work, compliance, ranked priorities with reasons; operator only', async (t) => {
  const e = await setup(t); await seed(e);   // the GRC register keeps real time: dates are relative to today
  const d = (n) => new Date(Date.now() + n * DAY).toISOString().slice(0, 10), RK = { user: 'risk', role: 'operator' };
  assert.equal((await e.req('POST', '/grc/risks', Object.assign({ body: { title: 'Regulatory reporting to SAMA late (synthetic)', likelihood: 4, impact: 5, treatment: 'mitigate', owner: 'risk', description: 'synthetic' } }, OP))).status, 200);
  for (const [title, owner, due] of [['Approve the risk appetite statement (synthetic)', 'risk', d(-7)], ['Update the committee pack (synthetic)', 'risk', d(5)], ['Close the access review gap (synthetic)', 'ali.syn', d(-20)]])
    assert.equal((await e.req('POST', '/grc/actions', Object.assign({ body: { title, owner, due, source: 'manual' } }, OP))).status, 200);
  assert.equal((await e.req('GET', '/risk-command/my', VIEW)).status, 403, 'names owners and their work: no viewers');
  const v = (await e.req('GET', '/risk-command/my', RK)).json;
  assert.equal(v.my_risks.length, 1); assert.equal(v.my_risks[0].band, 'high');
  assert.equal(v.my_actions.length, 2); assert.ok(v.my_actions.some((a) => a.overdue) && v.my_actions.some((a) => a.due_soon), JSON.stringify(v.my_actions));
  assert.equal(v.team_overdue_total, 1); assert.equal(v.team_overdue[0].owner, 'ali.syn');
  assert.ok(v.priorities.length >= 3 && v.priorities.every((p, i, L) => !i || L[i - 1].score >= p.score), 'ranked');
  assert.equal(v.priorities[0].kind, 'my action', 'my overdue action first: ' + JSON.stringify(v.priorities[0]));
  assert.ok(v.priorities.every((p) => p.why.length && p.why.every((w) => /\+\d+$/.test(w))), 'every point has its reason');
  assert.ok(v.brief.some((l) => /You own 1 open risk/.test(l)) && v.brief.some((l) => /1 overdue/.test(l)), v.brief.join(' | '));
  const off = require('../engine/brand').modules_off || [], expect = 6 - (off.includes('fw-sama') ? 1 : 0) - (off.includes('fw-ia') ? 1 : 0);
  assert.ok(v.compliance && v.compliance.frameworks.length === expect, 'the organisation\'s frameworks: ' + (v.compliance && v.compliance.frameworks.map((f) => f.id)));
});

test('Head of Risk brief: Workflow Automation - what the risk function asked the IT teams for that is late, results to accept; failure named', async (t) => {
  const e = await setup(t);
  const W = e.app.addons.workflow, HOR = { user: 'hor.syn', role: 'operator' }, me = Object.assign({ ip: '' }, HOR), col = e.app.store.collection('wf_requests');
  W.settingsSave({ version: 0, functions: { risk: ['hor.syn', 'risk2.syn'] }, teams: { backup: ['bk.syn'], security: ['sec.syn'] } }, { user: 'adam.syn', role: 'admin', ip: '' });
  const late = W.create({ type: 'dr-test', from: 'risk', title: 'DR test evidence for the claims system', details: 'last test', priority: 'high' }, { user: 'risk2.syn', role: 'viewer', ip: '' });
  const lr = col.get(late.id); lr.due = new Date(Date.now() - 3600000).toISOString(); col.put(lr);
  const done = W.create({ type: 'vuln-remediation', from: 'risk', title: 'Critical vulnerabilities for the KRI', details: 'count by system' }, me);
  W.act(done.id, 'start', {}, { user: 'sec.syn', role: 'operator', ip: '' }); W.act(done.id, 'fulfil', { response: 'attached' }, { user: 'sec.syn', role: 'operator', ip: '' });
  const v = (await e.req('GET', '/risk-command/my', HOR)).json;
  assert.deepEqual([v.wf.raised_open, v.wf.raised_late, v.wf.to_accept], [1, 1, 1], JSON.stringify(v.wf));
  const P = v.priorities.filter((p) => /^Request /.test(p.kind));
  const l = P.find((p) => p.ref === late.id), a = P.find((p) => p.ref === done.id);
  assert.equal(l.kind, 'Request late'); assert.equal(l.score, 45); assert.ok(l.why.includes('high priority +10')); assert.match(l.text, /Backup & DR/);
  assert.equal(a.kind, 'Request to accept'); assert.equal(a.score, 25); assert.equal(a.page, 'workflow-automation.html#req=' + done.id);
  assert.ok(v.brief.some((x) => /Workflow Automation: 1 request\(s\) from you and the risk function open with the IT teams, 1 late, 1 result\(s\) waiting for your acceptance; 1 overdue across the IT teams\./.test(x)), v.brief.join(' / '));
  e.app.addons.workflow = { attention: () => { throw new Error('synthetic failure'); } };
  const v2 = (await e.req('GET', '/risk-command/my', HOR)).json; assert.ok(v2.notes.includes('Workflow Automation could not be read')); assert.equal(v2.wf, null);
});
