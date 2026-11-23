// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// AI Risk Officer (engine/risk-officer.js) on the duty desk, over SYNTHETIC workbooks (tests/brisk-fixture.js) and synthetic risks:
// the work it finds (each with evidence and one proposed step), the supervisor's verdicts (passed / flagged / held, re-checked at
// decision time), decisions by a person only (roles, a service identity refused, a reason to reject, audit), each step applied through
// the module that owns it, learning from decisions (a kind lowered, the link threshold moved), the outcome scorecard.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');
const F = require('./brisk-fixture');

const VIEW = { user: 'vera.syn', role: 'viewer' }, OP = { user: 'nora.syn', role: 'operator' }, ADM = { user: 'adam.syn', role: 'admin' }, SVC = { user: 'svc-sync', role: 'admin' };
const T0 = Date.parse('2026-11-11T08:00:00Z');

async function setup(t) {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true, now: () => T0, python: process.env.PYTHON || 'python3' });
  const call = (m, p, b, who) => e.req(m, p, Object.assign(b !== undefined ? { body: b } : {}, who || OP));
  await call('POST', '/brisk/import/register', { filename: 'reg.xlsx', xlsx_b64: await F.registerB64(), apply: true }, ADM);
  await call('POST', '/brisk/import/ras', { filename: 'ras.xlsx', xlsx_b64: await F.rasB64(), apply: true }, ADM);
  const risk = async (o) => (await call('POST', '/brisk/risks', Object.assign({ likelihood: 4, impact: 4, exposure: 3, owner: 'syn.owner' }, o))).json;
  const solv = await risk({ department: 'Synthetic Finance', title: 'Solvency ratio falls below the regulatory capital margin', description: 'Synthetic: regulatory capital over the required margin drops', area: 'Strategic_Risk' });
  const comb = await risk({ department: 'Synthetic Finance', title: 'Combined ratio above plan from large claims', description: 'Synthetic: claims and expenses over earned premium', area: 'Strategic_Risk' });
  // a breach outside tolerance (raised automatically), a falling solvency ratio (early warning), a yes / no breach (no action yet)
  await call('POST', '/brisk/ras/RAS-01.02/links', { risk: comb.id, op: 'add' });
  await call('POST', '/brisk/ras/actuals', { rows: [{ metric: 'RAS-01.02', period: '2026-10', value: '99%', note: 'synthetic large claims' }, { metric: 'RAS-02.03', period: '2026-10', value: 'no', note: 'synthetic: one policy above treaty' }]
    .concat(['320%', '300%', '290%', '275%', '262%'].map((v, i) => ({ metric: 'RAS-01.01', period: '2026-' + String(6 + i).padStart(2, '0'), value: v }))) });
  const O = e.app.addons.riskOfficer;
  const audits = () => e.app.store.auditTail(800);
  let n = 0; const items = async () => (await O.current()).map((x) => Object.assign({ id: 'DI-' + (++n) }, x));
  return { e, call, O, solv, comb, items, audits };
}

test('on the duty desk: the work it finds, each with evidence and one proposed step', async (t) => {
  const { call, O, solv, comb, items } = await setup(t);
  const eng = (await call('GET', '/duty/engineers', undefined, VIEW)).json.engineers.map((x) => x.id || x.engineer || x);
  assert.ok(JSON.stringify(eng).includes('riskofficer'), 'the AI Risk Officer is one of the engineers');
  const I = await items(), by = (k) => I.filter((x) => x.kind === k);
  assert.ok(by('ras-unreported').some((x) => /Synthetic IT/.test(x.title)), 'a department that has not reported');
  const br = by('ras-breach'); assert.equal(br.length, 1, 'one breach without an action (RAS-01.02 got its action automatically)'); assert.equal(br[0].proposal.params.metric, 'RAS-02.03'); assert.equal(br[0].proposal.step, 'action');
  assert.ok(by('ras-warning').some((x) => x.proposal.params.metric === 'RAS-01.01'), 'the falling solvency ratio');
  const uw = by('risk-unwatched').find((x) => x.proposal.params.risk === solv.id); assert.ok(uw && uw.proposal.params.metric === 'RAS-01.01' && uw.proposal.step === 'link', 'a Class III risk no metric watches, with its best match');
  assert.ok(by('risk-kri').some((x) => x.proposal.params.risk === comb.id), 'the risk whose KRI is outside tolerance');
  assert.ok(by('ras-limits').some((x) => x.proposal.params.metric === 'RAS-01.03'), 'a limit correction ready');
  for (const x of I) { assert.ok(x.evidence.length >= 1 && x.recommendation && x.proposal.step, x.key + ' has evidence, a recommendation, a step'); }
  assert.equal((await call('GET', '/brisk/officer', undefined, { user: 'x', role: 'none' })).status >= 401, true);
});

test('supervisor, decisions by a person, each step applied by its owning module, audit', async (t) => {
  const { call, O, solv, items, audits } = await setup(t);
  const I = await items(), get = (k, f) => I.find((x) => x.kind === k && (!f || f(x)));
  for (const x of I) await O.propose(x);
  let V = (await call('GET', '/brisk/officer', undefined, VIEW)).json;
  const link = V.queue.find((p) => p.step === 'link' && p.params.risk === solv.id), act = V.queue.find((p) => p.step === 'action'), lim = V.queue.find((p) => p.step === 'limits'), rem = V.queue.find((p) => p.step === 'reminder');
  assert.ok(link && act && lim && rem, 'link, action, limits and reminder proposals queued');
  assert.equal(link.supervisor.verdict, 'passed'); assert.ok(link.supervisor.checks.every((c) => c.ok), 'every check named and passed: ' + link.supervisor.checks.map((c) => c.name).join(', '));
  // a proposal citing a record that does not exist is held and escalated, never offered for approval
  const fake = Object.assign({}, get('ras-breach'), { id: 'DI-x', key: 'ras-breach:RAS-99.99:2026-10', proposal: { step: 'action', params: { metric: 'RAS-99.99', period: '2026-10', level: 1 } } });
  assert.match((await O.propose(fake)).note, /held by the supervisor .*RAS-99\.99 is not in the RAS/);
  V = (await call('GET', '/brisk/officer', undefined, VIEW)).json; const held = V.held.find((p) => /RAS-99/.test(p.id)); assert.ok(held && held.escalated_to);
  assert.equal((await call('POST', '/brisk/officer/' + held.id + '/decide', { decision: 'approve' })).status, 409, 'a held proposal cannot be approved');
  // who may decide
  const dec = (p, b, who) => call('POST', '/brisk/officer/' + encodeURIComponent(p.id) + '/decide', b, who);
  assert.equal((await dec(link, { decision: 'approve' }, VIEW)).status, 403, 'a viewer cannot decide');
  assert.equal((await dec(link, { decision: 'approve' }, SVC)).status, 403, 'a service identity cannot decide');
  let r = await dec(link, { decision: 'reject' }); assert.equal(r.status, 400); assert.match(r.text, /note is required to reject/);
  r = await dec(link, { decision: 'maybe' }); assert.equal(r.status, 400); assert.match(r.text, /decision must be one of/);
  // approve: each step through the module that owns it
  r = await dec(link, { decision: 'approve', extra: 'dropped' }); assert.equal(r.status, 200); assert.equal(r.json.status, 'approved');
  assert.ok((await call('GET', '/brisk/ras', undefined, VIEW)).json.metrics.find((m) => m.id === 'RAS-01.01').links.includes(solv.id), 'linked in Business Risk');
  // the supervisor re-checks at decision time: a person raised the action by hand meanwhile -> a duplicate, held, not applied
  assert.equal((await call('POST', '/brisk/ras/RAS-02.03/action', {})).status, 200);
  r = await dec(act, { decision: 'approve' }); assert.equal(r.status, 409); assert.match(r.text, /the supervisor holds it now: .*an? open action tracks|no open action tracks/);
  V = (await call('GET', '/brisk/officer', undefined, VIEW)).json; assert.ok(V.held.some((p) => p.id === act.id), 'now held'); assert.ok(audits().some((x) => x.action === 'risk-officer.held'));
  // the breach step itself, applied through the GRC register, on a fresh breach
  await call('POST', '/brisk/ras/RAS-02.01/actuals', { period: '2026-10', value: '0.9', note: 'synthetic outage' });
  const fresh = (await O.current()).find((x) => x.kind === 'ras-breach' && x.proposal.params.metric === 'RAS-02.01'); assert.ok(fresh, 'a new breach found');
  await O.propose(Object.assign({ id: 'DI-fresh' }, fresh)); const fp = (await call('GET', '/brisk/officer', undefined, VIEW)).json.queue.find((p) => p.step === 'action' && p.params.metric === 'RAS-02.01');
  r = await dec(fp, { decision: 'approve' }); assert.equal(r.status, 200); assert.match(r.json.result.action, /^ACT-/, 'a GRC action raised');
  r = await dec(lim, { decision: 'approve', note: 'synthetic: agreed' }); assert.equal(r.status, 200);
  const m3 = (await call('GET', '/brisk/ras', undefined, VIEW)).json.metrics.find((m) => m.id === 'RAS-01.03');
  assert.deepEqual([m3.limit_change.status, m3.limit_change.by], ['pending', 'nora.syn'], 'a limit change REQUEST by the approver - a second administrator still decides');
  r = await dec(rem, { decision: 'approve' }); assert.match(r.json.result.mailto, /^mailto:\?subject=RAS%20reporting%20due/, 'a reminder drafted for a person to send');
  assert.equal((await dec(link, { decision: 'approve' })).status, 409, 'decided once');
  // a re-assessment becomes a GRC action for the owners of the linked risks
  const rw = V.queue.find((p) => p.step === 'reassess' && p.kind === 'risk-kri'); r = await dec(rw, { decision: 'approve' }); assert.equal(r.status, 200); assert.match(r.json.result.action, /^ACT-/);
  const a = audits().find((x) => x.action === 'risk-officer.approve'); assert.equal(a.by, 'nora.syn'); assert.equal(a.role, 'operator'); assert.ok(a.ip !== undefined); assert.match(JSON.stringify(a.detail), /step/);
  assert.ok(audits().some((x) => x.action === 'risk-officer.propose' && x.by === 'ai:risk-officer'), 'proposals audited as the officer');
});

test('learns from decisions, graded on outcomes', async (t) => {
  const { call, O, items } = await setup(t);
  for (const x of await items()) await O.propose(x);
  let V = (await call('GET', '/brisk/officer', undefined, VIEW)).json;
  assert.equal(V.learning.link_threshold.value, 0.45); assert.match(V.learning.link_threshold.why, /no link decided yet/);
  // a rejected link moves the threshold above its score
  const link = V.queue.find((p) => p.step === 'link');
  await call('POST', '/brisk/officer/' + encodeURIComponent(link.id) + '/decide', { decision: 'reject', note: 'synthetic: not this metric' });
  V = (await call('GET', '/brisk/officer', undefined, VIEW)).json;
  assert.ok(V.learning.link_threshold.value > 0.45, 'the link threshold rose: ' + V.learning.link_threshold.value); assert.match(V.learning.link_threshold.why, /moved by 1 decision/);
  assert.equal(V.learning.kinds['risk-unwatched'].rejected, 1);
  // five rejections of one kind lower it one severity
  for (let i = 0; i < 5; i++) await O.propose({ id: 'DI-r' + i, key: 'ras-unreported:Synthetic Dept ' + i, kind: 'ras-unreported', severity: 'medium', title: 'Synthetic', evidence: ['e'], proposal: { step: 'reminder', params: { department: 'Synthetic Finance', metrics: ['RAS-01.01', 'RAS-02.01'], period: '2026-10' } } });
  V = (await call('GET', '/brisk/officer', undefined, VIEW)).json;
  for (const p of V.queue.filter((x) => x.kind === 'ras-unreported').slice(0, 5)) await call('POST', '/brisk/officer/' + encodeURIComponent(p.id) + '/decide', { decision: 'reject', note: 'synthetic: not useful' });
  V = (await call('GET', '/brisk/officer', undefined, VIEW)).json;
  assert.equal(V.learning.kinds['ras-unreported'].lowered, true); assert.match(V.learning.kinds['ras-unreported'].why, /lower until people approve more/);
  const lowered = (await O.current()).filter((x) => x.kind === 'ras-unreported');
  assert.ok(lowered.length && lowered.every((x) => x.severity === 'low' || x.severity === 'medium'), 'raised one severity lower now');
  // the scorecard: every measure with its target and the evidence behind it
  const S = Object.fromEntries(V.scorecard.map((x) => [x.key, x]));
  assert.deepEqual(Object.keys(S).sort(), ['actioned', 'approval', 'caught_early', 'current', 'decision_days', 'reported', 'watched']);
  assert.equal(S.actioned.value, 50, 'one of the two breaches is tracked by an action'); assert.equal(S.actioned.met, false); assert.match(S.actioned.why, /1 of 2/);
  assert.equal(S.approval.value, 0, 'nothing approved yet'); assert.equal(S.reported.target, 90);
  assert.ok(S.caught_early.value === 0 && S.watched.value != null && S.current.value === 100);
  assert.ok(V.scorecard.every((x) => Array.isArray(x.history)), 'with its daily history');
});
