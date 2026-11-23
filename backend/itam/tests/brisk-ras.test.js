// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Risk Appetite automation (engine/brisk-ras.js through engine/business-risk.js) on SYNTHETIC workbooks (tests/brisk-fixture.js) and
// synthetic risks: risk coverage (the four signals and their evidence, learning from a confirmed link, a rejected suggestion never
// offered again), bulk link approval (roles, validation, all or nothing, audit), automatic escalation of a value outside tolerance,
// limit proposals (correction, history, similar) and the four-eyes limit change that survives a re-import, the per-department due list.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');
const RAS = require('../engine/brisk-ras');
const F = require('./brisk-fixture');

const VIEW = { user: 'vera.syn', role: 'viewer' }, OP = { user: 'nora.syn', role: 'operator' }, ADM = { user: 'adam.syn', role: 'admin' }, ADM2 = { user: 'aisha.syn', role: 'admin' }, SVC = { user: 'svc-sync', role: 'admin' };
const T0 = Date.parse('2026-11-11T08:00:00Z');

async function setup(t) {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true, now: () => T0, python: process.env.PYTHON || 'python3' });
  const call = (m, p, b, who) => e.req(m, p, Object.assign(b !== undefined ? { body: b } : {}, who || OP));
  const audits = () => e.app.store.auditTail(800);
  await call('POST', '/brisk/import/register', { filename: 'reg.xlsx', xlsx_b64: await F.registerB64(), apply: true }, ADM);
  await call('POST', '/brisk/import/ras', { filename: 'ras.xlsx', xlsx_b64: await F.rasB64(), apply: true }, ADM);
  return { e, call, audits };
}
const mkRisk = (call, o) => call('POST', '/brisk/risks', Object.assign({ likelihood: 4, impact: 4, exposure: 3, owner: 'Synthetic owner' }, o));

test('signals: department and family of risk match loosely, unrelated ones do not', () => {
  assert.ok(RAS.deptMatch('Synthetic Finance Department', 'synthetic finance'));
  assert.ok(RAS.deptMatch('Finance & Accounts', 'Finance and Accounts'));
  assert.ok(!RAS.deptMatch('Synthetic IT', 'Synthetic Finance'), 'one shared word of three is not the same department');
  assert.ok(!RAS.deptMatch('', 'Synthetic Finance'));
  assert.deepEqual([...RAS.familyOf('Insurance_Risk')], ['insurance']);
  assert.deepEqual([...RAS.familyOf('OPERATIONAL RISK - COMPLIANCE')].sort(), ['compliance', 'operational']);
  assert.equal(RAS.familyOf('Synthetic other').size, 0);
  assert.equal(RAS.fmt(0.975, 'ratio'), '97.5%'); assert.equal(RAS.fmt(48, 'hours'), '2 days'); assert.equal(RAS.fmt(0.5, 'hours'), '30 min');
});

test('coverage: suggestions with evidence, bulk approval, learning, rejection, roles, validation, audit', async (t) => {
  const { call, audits } = await setup(t);
  // open risks (the fixture's register rows are solved): one a solvency metric watches, one like it, one nothing watches
  const a = (await mkRisk(call, { department: 'Synthetic Finance', title: 'Solvency ratio falls below the regulatory capital margin', description: 'Synthetic: regulatory capital over the required margin drops', area: 'Strategic_Risk' })).json;
  const b = (await mkRisk(call, { department: 'Synthetic Finance', title: 'Regulatory capital margin shortfall against solvency', description: 'Synthetic: solvency capital margin below the regulatory requirement', area: 'Strategic_Risk' })).json;
  const c = (await mkRisk(call, { department: 'Synthetic Facilities', title: 'Office pantry supplies run short', description: 'Synthetic: coffee and tea stock', area: 'Projects_Risks' })).json;
  assert.ok(a.id && b.id && c.id);
  assert.ok([401, 403].includes((await call('GET', '/brisk/ras/coverage', undefined, { user: 'x', role: 'none' })).status), 'no role, no coverage');
  let C = (await call('GET', '/brisk/ras/coverage', undefined, VIEW)).json;
  const ra = C.risks.find((r) => r.id === a.id), rc = C.risks.find((r) => r.id === c.id);
  assert.equal(ra.state, 'strong', 'the solvency risk has a strong suggestion');
  const top = ra.suggestions[0]; assert.equal(top.metric, 'RAS-01.01'); assert.ok(top.dept && top.family && top.words.includes('capital') && top.text >= 0.3, 'evidence: same department, same family, shared words: ' + JSON.stringify(top));
  assert.equal(rc.state, 'uncovered', 'nothing watches the pantry'); assert.equal(rc.suggestions.length, 0);
  assert.equal(C.summary.open, 4, 'three new risks + the open fixture row'); assert.ok(C.summary.uncovered >= 1); assert.match(C.method, /a person confirms every link/i);
  assert.ok(C.by_area.find((x) => x.area === 'Projects_Risks').serious_uncovered === 1, 'a Class III / IV risk no metric watches is counted');
  assert.ok(C.metrics.some((m) => m.state === 'suggested') && C.metrics.every((m) => ['linked', 'suggested', 'orphan'].includes(m.state)));

  // bulk approval: roles, validation, all or nothing
  const pairs = [{ metric: 'RAS-01.01', risk: a.id }];
  assert.equal((await call('POST', '/brisk/ras/links/bulk', { pairs }, VIEW)).status, 403, 'a viewer cannot link');
  assert.equal((await call('POST', '/brisk/ras/links/bulk', { pairs }, SVC)).status, 403, 'a service identity cannot link');
  let r = await call('POST', '/brisk/ras/links/bulk', {}); assert.equal(r.status, 400); assert.match(r.text, /pairs is required/);
  r = await call('POST', '/brisk/ras/links/bulk', { pairs: ['x'] }); assert.equal(r.status, 400); assert.match(r.text, /pairs\[0\] must be/);
  r = await call('POST', '/brisk/ras/links/bulk', { pairs: [{ metric: 'RAS-01.01' }] }); assert.equal(r.status, 400); assert.match(r.text, /pairs\[0\]: risk is required/);
  r = await call('POST', '/brisk/ras/links/bulk', { pairs: [{ metric: 'RAS-01.01', risk: a.id }, { metric: 'RAS-99.99', risk: a.id }] }); assert.equal(r.status, 400); assert.match(r.text, /pairs\[1\]: no metric RAS-99.99/);
  assert.equal((await call('GET', '/brisk/ras/coverage', undefined, VIEW)).json.summary.covered, 0, 'nothing linked from a refused batch');
  r = await call('POST', '/brisk/ras/links/bulk', { pairs, extra: 'dropped' }); assert.equal(r.status, 200); assert.deepEqual([r.json.added, r.json.already], [1, 0]);
  r = await call('POST', '/brisk/ras/links/bulk', { pairs }); assert.deepEqual([r.json.added, r.json.already], [0, 1], 'linking twice adds nothing');
  const au = audits().find((x) => x.action === 'brisk.ras.link.bulk'); assert.equal(au.by, 'nora.syn'); assert.equal(au.role, 'operator'); assert.ok(au.ip !== undefined); assert.match(JSON.stringify(au.detail), /RAS-01.01>BR-/);

  // learning: the confirmed link teaches the model - the risk like it now carries that evidence
  C = (await call('GET', '/brisk/ras/coverage', undefined, VIEW)).json;
  assert.equal(C.risks.find((x) => x.id === a.id).state, 'covered'); assert.deepEqual(C.risks.find((x) => x.id === a.id).linked, ['RAS-01.01']);
  const rb = C.risks.find((x) => x.id === b.id).suggestions.find((s) => s.metric === 'RAS-01.01');
  assert.ok(rb && rb.learned && rb.learned.risk === a.code, 'learned from the confirmed link: ' + JSON.stringify(rb));
  // rejection: not this risk - never suggested again, and a later add clears it
  assert.equal((await call('POST', '/brisk/ras/RAS-01.01/links', { risk: b.id, op: 'reject' })).status, 200);
  C = (await call('GET', '/brisk/ras/coverage', undefined, VIEW)).json;
  assert.ok(!C.risks.find((x) => x.id === b.id).suggestions.some((s) => s.metric === 'RAS-01.01'), 'a rejected suggestion is not offered again');
  assert.ok(audits().some((x) => x.action === 'brisk.ras.link.reject' && x.by === 'nora.syn'));
  await call('POST', '/brisk/ras/links/bulk', { pairs: [{ metric: 'RAS-01.01', risk: b.id }] });
  const m = (await call('GET', '/brisk/ras', undefined, VIEW)).json.metrics.find((x) => x.id === 'RAS-01.01');
  assert.deepEqual([m.links.includes(b.id), m.rejected.includes(b.id)], [true, false], 'approving a rejected pair later clears the rejection');
  assert.equal((await call('POST', '/brisk/ras/RAS-01.01/links', { risk: b.id, op: 'ignore' })).status, 400, 'op is checked');
});

test('escalation: outside tolerance raises one GRC action at once; outside appetite does not', async (t) => {
  const { call, audits } = await setup(t);
  let r = await call('POST', '/brisk/ras/RAS-01.02/actuals', { period: '2026-10', value: '97.5%', note: 'synthetic: just above appetite' });
  assert.equal(r.status, 200); assert.equal(r.json.latest.zone, 'outside_appetite'); assert.equal(r.json.auto_action, null, 'outside appetite: the action stays a choice');
  r = await call('POST', '/brisk/ras/RAS-01.02/actuals', { period: '2026-10', value: '99%', note: 'synthetic: large claims' });
  assert.equal(r.json.latest.zone, 'outside_tolerance'); assert.match(r.json.auto_action.action, /^ACT-/, 'outside tolerance: raised at once');
  r = await call('POST', '/brisk/ras/RAS-01.02/actuals', { period: '2026-10', value: '99.5%', note: 'synthetic: corrected' }); assert.equal(r.json.auto_action.existing, true, 'a correction does not raise a second action');
  assert.equal((await call('POST', '/brisk/ras/RAS-01.02/action', {})).status, 409, 'and the manual button sees the open one');
  r = await call('POST', '/brisk/ras/actuals', { rows: [{ metric: 'RAS-02.02', period: '2026-10', value: '2 days', note: 'synthetic outage' }, { metric: 'RAS-02.01', period: '2026-10', value: '0.99' }] });
  assert.equal(r.status, 200); assert.equal(r.json.auto_actions.length, 1); assert.equal(r.json.auto_actions[0].metric, 'RAS-02.02');
  const au = audits().filter((x) => x.action === 'brisk.ras.action.auto'); assert.equal(au.length, 2); assert.equal(au[0].by, 'nora.syn'); assert.match(JSON.stringify(au.map((x) => x.detail)), /capacity_breach/);
});

test('limits: proposals, four-eyes change, validation, roles, audit, kept across a re-import', async (t) => {
  const { call, audits } = await setup(t);
  let L = (await call('GET', '/brisk/ras/limits', undefined, VIEW)).json;
  const p = L.proposals.find((x) => x.id === 'RAS-01.03');
  assert.ok(p && p.basis === 'correction', 'the out-of-order ceilings get a correction'); assert.deepEqual([p.limits.app_ceil, p.limits.tol_ceil, p.limits.cap_ceil], [0.9, 0.95, 0.98]); assert.match(p.why.join(' '), /ceilings are put in order/);
  assert.ok(L.without.some((x) => x.id === 'RAS-02.04'), 'limits written as text: no proposal, said'); assert.equal(L.no_limits, 1);
  // history: six reported values on the metric without limits
  await call('POST', '/brisk/ras/actuals', { rows: ['0.4', '0.42', '0.45', '0.43', '0.47', '0.5'].map((v, i) => ({ metric: 'RAS-02.05', period: '2026-0' + (4 + i), value: v })) });
  const h = (await call('GET', '/brisk/ras/limits', undefined, VIEW)).json.proposals.find((x) => x.id === 'RAS-02.05');
  assert.equal(h.basis, 'history'); assert.equal(h.kind, 'band'); assert.ok(h.limits.app_floor >= 0.4 && h.limits.app_ceil <= 0.5); assert.match(h.why[0], /6 values/);

  // the change: an operator requests, the same person cannot approve, a different administrator does
  const req = (who, b) => call('POST', '/brisk/ras/RAS-01.03/limits', b, who), dec = (who, b) => call('POST', '/brisk/ras/RAS-01.03/limits/decision', b, who);
  assert.equal((await req(VIEW, { raw: p.proposed, note: 'synthetic fix' })).status, 403, 'a viewer cannot request');
  let r = await req(OP, { raw: p.proposed }); assert.equal(r.status, 400); assert.match(r.text, /note is required/);
  r = await req(OP, { note: 'synthetic fix' }); assert.equal(r.status, 400); assert.match(r.text, /raw must be/);
  r = await req(OP, { raw: { app_ceil: '<95%', tol_ceil: '0.9' }, note: 'synthetic fix' }); assert.equal(r.status, 400); assert.match(r.text, /raw: ceilings out of order/);
  r = await req(OP, { raw: { app_ceil: 'x'.repeat(81) }, note: 'synthetic fix' }); assert.equal(r.status, 400); assert.match(r.text, /app_ceil is longer/);
  r = await req(OP, { raw: {}, note: 'synthetic fix' }); assert.equal(r.status, 400); assert.match(r.text, /at least one limit/);
  r = await req(OP, { raw: p.proposed, note: 'synthetic: ceilings in order', basis: 'correction' }); assert.equal(r.status, 200); assert.equal(r.json.limit_change.status, 'pending');
  assert.equal((await req(ADM, { raw: p.proposed, note: 'synthetic again' })).status, 409, 'one waiting change at a time');
  assert.equal((await call('GET', '/brisk/ras/limits', undefined, VIEW)).json.pending[0].id, 'RAS-01.03');
  assert.equal((await dec(OP, { decision: 'approve' })).status, 403, 'an operator cannot approve');
  assert.equal((await dec(SVC, { decision: 'approve' })).status, 403, 'a service identity cannot approve');
  r = await dec(ADM2, { decision: 'reject' }); assert.equal(r.status, 400); assert.match(r.text, /note is required to reject/);
  r = await dec(ADM2, { decision: 'approve', note: 'synthetic: agreed' }); assert.equal(r.status, 200);
  assert.deepEqual([r.json.issues.length, r.json.limits.app_ceil, r.json.limits_override.approved_by, r.json.limits_override.requested_by], [0, 0.9, 'aisha.syn', 'nora.syn']);
  assert.equal((await dec(ADM2, { decision: 'approve' })).status, 409, 'nothing waits any more');
  const a1 = audits().find((x) => x.action === 'brisk.ras.limits.request'), a2 = audits().find((x) => x.action === 'brisk.ras.limits.approve');
  assert.equal(a1.by, 'nora.syn'); assert.equal(a2.by, 'aisha.syn'); assert.equal(a2.role, 'admin'); assert.match(JSON.stringify(a2.detail), /0\.9/);
  // four eyes the other way: the administrator who requests cannot approve
  await call('POST', '/brisk/ras/RAS-01.02/limits', { raw: { app_ceil: '<96%', tol_ceil: '0.98', cap_ceil: '>100%' }, note: 'synthetic tighter appetite' }, ADM);
  r = await call('POST', '/brisk/ras/RAS-01.02/limits/decision', { decision: 'approve' }, ADM); assert.equal(r.status, 403); assert.match(r.text, /four eyes/);
  // re-importing the same workbook keeps the approved change; the zone of a value follows the approved limits
  r = await call('POST', '/brisk/import/ras', { filename: 'ras.xlsx', xlsx_b64: await F.rasB64(), apply: true }, ADM);
  assert.equal(r.json.preview.limit_changes_kept, 1);
  const m = (await call('GET', '/brisk/ras', undefined, VIEW)).json.metrics.find((x) => x.id === 'RAS-01.03');
  assert.deepEqual([m.limits.app_ceil, m.issues.length, m.limits_override.workbook.app_ceil], [0.9, 0, '<95%']);
  r = await call('POST', '/brisk/ras/RAS-01.03/actuals', { period: '2026-10', value: '92%', note: 'synthetic' }); assert.equal(r.json.latest.zone, 'outside_appetite', 'zoned on the approved limits');
});

test('due: what each department owes for the last closed period', async (t) => {
  const { call } = await setup(t);
  let D = (await call('GET', '/brisk/ras/due', undefined, VIEW)).json.departments;
  const fin = D.find((d) => d.department === 'Synthetic Finance'), it = D.find((d) => d.department === 'Synthetic IT');
  assert.ok(fin && it); assert.equal(it.due.length, 3); assert.equal(it.reported, 0); assert.equal(it.due[0].due_period, '2026-10');
  assert.ok(!D.some((d) => d.due.some((x) => x.id === 'RAS-02.05')), 'a metric with no limits is not chased');
  assert.ok([401, 403].includes((await call('GET', '/brisk/ras/due', undefined, { user: 'x', role: 'none' })).status), 'no role, no due list');
  await call('POST', '/brisk/ras/RAS-02.01/actuals', { period: '2026-10', value: '0.99' });
  D = (await call('GET', '/brisk/ras/due', undefined, VIEW)).json.departments;
  assert.deepEqual([D.find((d) => d.department === 'Synthetic IT').due.length, D.find((d) => d.department === 'Synthetic IT').reported], [2, 1]);
});
