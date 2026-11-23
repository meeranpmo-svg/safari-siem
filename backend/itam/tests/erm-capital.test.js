// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Capital, ORSA & Stress Testing (engine/erm-capital.js) through the real routes, SYNTHETIC figures only:
//  - a position entered by one person and confirmed by another; ratios judged against the linked RAS metrics (and "not judged" without a link)
//  - stress scenarios: proposed, approved by a different administrator; results before / after shock / after contingency actions; reverse stress
//  - the ORSA: what it still needs, frozen with a fingerprint on submit, the Board approval by someone other than the submitter, the report
//  - return on risk capital per line of business against the hurdle; initiatives reviewed by the risk function and decided by a third person
//  - roles (viewer reads, operator / admin writes, refused cases), an AI identity refused, validation 400s, the audit, Notification signals
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { createErmCapital, registerErmCapital } = require('../engine/erm-capital');

const FIN = { user: 'fin.syn', role: 'operator' }, ACT = { user: 'actuary.syn', role: 'operator' }, CRO = { user: 'cro.syn', role: 'admin' }, CFO = { user: 'cfo.syn', role: 'admin' }, VW = { user: 'vera.syn', role: 'viewer' }, BOT = { user: 'ai:risk-officer', role: 'admin' };
async function setup(t) {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  const clock = { t: Date.parse('2026-11-10T08:00:00Z') };
  const X = createErmCapital(e.app, { now: () => clock.t }); registerErmCapital(e.app.srv, e.app, X);
  // the Board-approved RAS: solvency floor 150 % appetite, 120 % tolerance, 100 % capacity; liquidity floor 1.5x / 1.2x / 1x (SYNTHETIC limits)
  e.app.store.collection('br_metrics').put({ id: 'M-SOL', component: 'Solvency coverage ratio', kind: 'floor', unit: 'ratio', limits: { app_floor: 1.5, tol_floor: 1.2, cap_floor: 1.0 } });
  e.app.store.collection('br_metrics').put({ id: 'M-LIQ', component: 'Liquid assets against expected outflows', kind: 'floor', unit: 'x', limits: { app_floor: 1.5, tol_floor: 1.2, cap_floor: 1.0 } });
  e.app.store.collection('br_risks').put({ id: 'BR-0001', title: 'Motor reserve deficiency SYN', likelihood: 3, impact: 4, exposure: 'medium', status: 'open', ins_cat: 'reserving' });
  const call = (m, p, b, who) => e.req(m, p, Object.assign(b !== undefined ? { body: b } : {}, who));
  const audits = (a) => e.app.store.auditTail(500).filter((x) => x.action === 'erm-capital.' + a);
  return { e, X, call, clock, audits };
}
const POS = { period: '2026-Q3', available_capital: 900e6, required_capital: 500e6, liquid_assets: 600e6, outflows_3m: 300e6, source: 'Q3 management accounts SYN',
  lines: [{ name: 'Motor SYN', gwp: 800e6, nep: 700e6, net_claims: 600e6, expenses: 150e6, net_profit: -20e6, allocated_capital: 250e6 }, { name: 'Medical SYN', gwp: 1200e6, nep: 1100e6, net_claims: 850e6, expenses: 160e6, net_profit: 90e6, allocated_capital: 300e6 }] };

test('position: entered, confirmed by a second person, ratios judged against the RAS only when linked', async (t) => {
  const { call, audits } = await setup(t);
  assert.equal((await call('POST', '/erm-cap/positions', POS, VW)).status, 403);
  assert.equal((await call('POST', '/erm-cap/positions', POS, BOT)).status, 403, 'an AI identity does not enter figures');
  let r = await call('POST', '/erm-cap/positions', Object.assign({}, POS, { period: '2026-Q5' }), FIN); assert.equal(r.status, 400); assert.match(r.json.error, /period must be like 2026-Q3/);
  r = await call('POST', '/erm-cap/positions', Object.assign({}, POS, { required_capital: 0 }), FIN); assert.equal(r.status, 400); assert.match(r.json.error, /required_capital must be at least/);
  r = await call('POST', '/erm-cap/positions', Object.assign({}, POS, { lines: [POS.lines[0], POS.lines[0]] }), FIN); assert.match(r.json.error, /appears twice/);
  r = await call('POST', '/erm-cap/positions', POS, FIN); assert.equal(r.status, 200, r.text);
  assert.equal(r.json.ratios.solvency, 1.8); assert.equal(r.json.ratios.liquidity, 2); assert.equal(r.json.is_confirmed, false);
  assert.match(r.json.ratios.solvency_judged.why, /link the RAS metric/, 'not judged without a link - never a guessed limit');
  assert.equal((await call('POST', '/erm-cap/positions/pos-2026-Q3/confirm', {}, FIN)).status, 403);
  assert.equal((await call('POST', '/erm-cap/positions/pos-2026-Q3/confirm', {}, ACT)).status, 403, 'an operator does not confirm');
  r = await call('POST', '/erm-cap/positions/pos-2026-Q3/confirm', { note: 'agreed to the trial balance SYN' }, CFO); assert.equal(r.status, 200); assert.equal(r.json.is_confirmed, true); assert.equal(r.json.confirmed.by, 'cfo.syn', 'who confirmed it is kept');
  assert.equal((await call('POST', '/erm-cap/positions/pos-2026-Q3/confirm', {}, CRO)).status, 409);
  assert.equal((await call('PUT', '/erm-cap/settings', { solvency_metric: 'M-NONE' }, CRO)).json.error, 'solvency_metric: no RAS metric M-NONE');
  assert.equal((await call('PUT', '/erm-cap/settings', { solvency_metric: 'M-SOL' }, FIN)).status, 403);
  r = await call('PUT', '/erm-cap/settings', { solvency_metric: 'M-SOL', liquidity_metric: 'M-LIQ', hurdle_pct: 12 }, CRO); assert.equal(r.status, 200);
  const v = (await call('GET', '/erm-cap', undefined, VW)).json;
  assert.equal(v.latest.ratios.solvency_judged.zone, 'within_appetite'); assert.equal(v.latest.ratios.liquidity_judged.zone, 'within_appetite');
  // re-entered: history kept, a new confirmation needed
  r = await call('POST', '/erm-cap/positions', Object.assign({}, POS, { available_capital: 700e6 }), FIN);
  assert.equal(r.json.is_confirmed, false); assert.equal(r.json.confirmed, null); assert.equal(r.json.history.length, 1); assert.equal(r.json.history[0].confirmed_by, 'cfo.syn');
  assert.equal(r.json.ratios.solvency_judged.zone, 'outside_appetite', '140 % is outside appetite, within tolerance');
  assert.ok(audits('position.enter').length === 1 && audits('position.update').length === 1 && audits('position.confirm').some((a) => a.by === 'cfo.syn' && a.role === 'admin'));
  assert.equal(audits('settings')[0].by, 'cro.syn');
  // the performance per line of business against the 12 % hurdle
  await call('POST', '/erm-cap/positions/pos-2026-Q3/confirm', {}, CFO);
  const pf = (await call('GET', '/erm-cap', undefined, VW)).json.performance;
  assert.deepEqual(pf.lines.map((l) => [l.name, l.rorc]), [['Medical SYN', 0.3], ['Motor SYN', -0.08]]);
  assert.ok(pf.lines[1].flags.some((f) => /below the hurdle of 12%/.test(f)) && pf.lines[1].flags.some((f) => /combined ratio above 100%/.test(f)));
  assert.deepEqual(pf.lines[0].flags, []);
});

test('stress: four eyes on scenarios, shock and contingency results, reverse stress, sensitivity, signals', async (t) => {
  const { X, call, audits } = await setup(t);
  await call('POST', '/erm-cap/positions', POS, FIN); await call('POST', '/erm-cap/positions/pos-2026-Q3/confirm', {}, CFO);
  await call('PUT', '/erm-cap/settings', { solvency_metric: 'M-SOL', liquidity_metric: 'M-LIQ' }, CRO);
  const sc = { name: 'Severe cat + market fall SYN', category: 'combined', description: 'a 1-in-200 flood with equity markets down 30 % (synthetic)', shocks: { capital_pct: -45, required_pct: 10, liquid_pct: -30, outflow_pct: 40 },
    actions: [{ action: 'Suspend the dividend SYN', trigger: 'solvency below 130 %', owner: 'cfo.syn', capital_amount: 80e6 }, { action: 'Quota share reinsurance SYN', trigger: 'solvency below 120 %', owner: 'cro.syn', required_amount: -60e6 }] };
  let r = await call('POST', '/erm-cap/scenarios', Object.assign({}, sc, { shocks: {} }), ACT); assert.equal(r.status, 400); assert.match(r.json.error, /at least one shock/);
  r = await call('POST', '/erm-cap/scenarios', Object.assign({}, sc, { category: 'weather' }), ACT); assert.match(r.json.error, /category must be one of/);
  r = await call('POST', '/erm-cap/scenarios', Object.assign({}, sc, { shocks: { capital_pct: -150 } }), ACT); assert.match(r.json.error, /capital_pct must be at least -100/);
  r = await call('POST', '/erm-cap/scenarios', sc, ACT); assert.equal(r.status, 200, r.text); const id = r.json.id; assert.equal(r.json.status, 'proposed');
  assert.equal((await call('POST', `/erm-cap/scenarios/${id}/decision`, { decision: 'approve', note: 'ok' }, ACT)).status, 403, 'an operator does not approve');
  assert.equal((await call('POST', `/erm-cap/scenarios/${id}/decision`, { decision: 'approve', note: 'ok' }, BOT)).status, 403, 'an AI identity never approves');
  assert.equal((await call('POST', `/erm-cap/scenarios/${id}/decision`, { decision: 'approve' }, CRO)).json.error, 'note is required');
  r = await call('POST', `/erm-cap/scenarios/${id}/decision`, { decision: 'approve', note: 'reviewed by the risk committee SYN' }, CRO); assert.equal(r.json.status, 'approved');
  const s = (await call('GET', '/erm-cap', undefined, VW)).json.scenarios.find((x) => x.id === id).result;
  // 900 x 0.55 = 495 against 500 x 1.1 = 550 -> 0.9; actions: (495 + 80) / (550 - 60) = 1.1735
  assert.deepEqual(s.solvency, [1.8, 0.9, 1.1735]); assert.equal(s.judged.after_shock.zone, 'capacity_breach'); assert.equal(s.judged.after_actions.zone, 'outside_tolerance');
  assert.equal(s.liquidity[1], 1); assert.equal(s.below_100_after_actions, false);
  assert.deepEqual(s.reverse, { to_100: -38.89, to_capacity_floor: -38.89 }, 'the capital fall that brings solvency to 100 %');
  assert.deepEqual(X.sensitivity({ available_capital: 900, required_capital: 500 }).map((x) => x.solvency), [1.62, 1.44, 1.26, 1.08, 0.9]);
  // a changed scenario is proposed again; a scenario that stays below 100 % is signalled
  r = await call('POST', '/erm-cap/scenarios', Object.assign({}, sc, { id, actions: [] }), ACT); assert.equal(r.json.status, 'proposed'); assert.equal(r.json.history.length, 1);
  assert.equal((await call('POST', `/erm-cap/scenarios/${id}/decision`, { decision: 'approve', note: 'again SYN' }, CRO)).json.status, 'approved');
  assert.ok(X.signals().some((g) => /solvency below 100% after the contingency actions/.test(g.title) && g.severity === 3));
  assert.ok(audits('scenario.propose').length === 1 && audits('scenario.change').length === 1 && audits('scenario.approve').every((a) => a.by === 'cro.syn'));
});

test('ORSA: what it needs, frozen on submit, Board approval by another person, the report', async (t) => {
  const { call, clock, audits, X } = await setup(t);
  await call('POST', '/erm-cap/positions', POS, FIN);
  assert.equal((await call('POST', '/erm-cap/orsa', { year: 2026, position: 'pos-2026-Q3', due: '2027-04-30' }, ACT)).status, 403, 'an administrator opens it');
  assert.match((await call('POST', '/erm-cap/orsa', { year: 2026, position: 'pos-2025-Q4', due: '2027-04-30' }, CRO)).json.error, /no capital position pos-2025-Q4/);
  let r = await call('POST', '/erm-cap/orsa', { year: 2026, position: 'pos-2026-Q3', due: '2027-04-30' }, CRO); assert.equal(r.status, 200);
  assert.equal((await call('POST', '/erm-cap/orsa', { year: 2026, position: 'pos-2026-Q3', due: '2027-04-30' }, CRO)).status, 409);
  r = await call('POST', '/erm-cap/orsa/ORSA-2026/submit', {}, ACT); assert.equal(r.status, 400);
  for (const need of [/second person to confirm/, /approved stress scenario/, /capital projection/, /conclusions/, /business plan/]) assert.match(r.json.error, need);
  await call('POST', '/erm-cap/positions/pos-2026-Q3/confirm', {}, CFO);
  const sid = (await call('POST', '/erm-cap/scenarios', { name: 'Reserve deterioration SYN', category: 'insurance', description: 'motor reserves 20 % short (synthetic)', shocks: { capital_pct: -15 } }, ACT)).json.id;
  await call('POST', `/erm-cap/scenarios/${sid}/decision`, { decision: 'approve', note: 'risk committee SYN' }, CRO);
  r = await call('POST', '/erm-cap/orsa/ORSA-2026', { projection: [{ year: 2027, available_capital: 950e6, required_capital: 540e6 }, { year: 2028, available_capital: 1000e6 }] }, ACT);
  assert.equal(r.status, 400); assert.match(r.json.error, /required_capital is required/);
  r = await call('POST', '/erm-cap/orsa/ORSA-2026', { business_plan: 'Grow medical 8 % a year, hold motor flat (synthetic plan)', conclusions: 'Capital covers the plan and every approved stress after actions (synthetic).',
    projection: [{ year: 2027, available_capital: 950e6, required_capital: 540e6 }] }, ACT);
  assert.equal(r.status, 200, r.text);
  r = await call('POST', '/erm-cap/orsa/ORSA-2026/submit', { note: 'for the Board SYN' }, ACT); assert.equal(r.status, 200, r.text);
  assert.equal(r.json.state, 'submitted'); assert.match(r.json.frozen.fingerprint, /^sha256:[0-9a-f]{64}$/);
  const snap = r.json.frozen.snapshot; assert.equal(snap.stress.length, 1); assert.equal(snap.risk_profile.open, 1); assert.equal(snap.projection[0].solvency, 1.7593);
  assert.equal((await call('POST', '/erm-cap/orsa/ORSA-2026', { conclusions: 'changed after submit (synthetic)' }, ACT)).status, 409, 'frozen');
  assert.match((await call('POST', '/erm-cap/orsa/ORSA-2026/decision', { decision: 'approve', note: 'approved' }, CRO)).json.error, /board_ref is required/);
  // the submitter cannot record the approval - make the submitter an admin to prove it is the person, not the role
  assert.equal((await call('POST', '/erm-cap/orsa/ORSA-2026/decision', { decision: 'approve', board_ref: 'BRD-2026-11 SYN', note: 'approved SYN' }, { user: 'actuary.syn', role: 'admin' })).status, 403);
  assert.equal((await call('POST', '/erm-cap/orsa/ORSA-2026/decision', { decision: 'approve', board_ref: 'BRD-2026-11 SYN', note: 'approved SYN' }, BOT)).status, 403);
  r = await call('POST', '/erm-cap/orsa/ORSA-2026/decision', { decision: 'approve', board_ref: 'BRD-2026-11 SYN', note: 'approved by the Board (synthetic)' }, CFO);
  assert.equal(r.json.state, 'approved'); assert.equal(r.json.decisions[0].fingerprint, snap && r.json.frozen.fingerprint);
  assert.equal((await call('GET', '/erm-cap/orsa/ORSA-2026/report', undefined, VW)).status, 403, 'the report exports the position: operator and up');
  r = await call('GET', '/erm-cap/orsa/ORSA-2026/report', undefined, ACT); assert.equal(r.status, 200); assert.equal(r.json.decisions[0].board_ref, 'BRD-2026-11 SYN');
  assert.ok(audits('orsa.open')[0].by === 'cro.syn' && audits('orsa.submit').length === 1 && audits('orsa.approve')[0].by === 'cfo.syn' && audits('orsa.report')[0].by === 'actuary.syn');
  // overdue: a 2027 ORSA past its due date is signalled until approved
  await call('POST', '/erm-cap/orsa', { year: 2027, position: 'pos-2026-Q3', due: '2027-04-30' }, CRO);
  clock.t = Date.parse('2027-05-02T08:00:00Z');
  assert.ok(X.signals().some((g) => /ORSA-2027 is past its due date/.test(g.title)));
  // returned: unfrozen and editable again
  await call('POST', '/erm-cap/orsa/ORSA-2027', { business_plan: 'Plan for 2027 (synthetic) - longer text', conclusions: 'Conclusions for 2027 (synthetic) - long enough', projection: [{ year: 2028, available_capital: 1e9, required_capital: 6e8 }] }, ACT);
  await call('POST', '/erm-cap/orsa/ORSA-2027/submit', {}, ACT);
  r = await call('POST', '/erm-cap/orsa/ORSA-2027/decision', { decision: 'return', note: 'add the IFRS 17 view (synthetic)' }, CFO);
  assert.equal(r.json.state, 'returned'); assert.equal(r.json.frozen, null);
  assert.equal((await call('POST', '/erm-cap/orsa/ORSA-2027', { conclusions: 'Updated after the Board return (synthetic).' }, ACT)).status, 200);
});

test('initiatives: pro-forma solvency, a risk review by the risk function, a decision by a third person', async (t) => {
  const { call, audits } = await setup(t);
  await call('POST', '/erm-cap/positions', POS, FIN); await call('POST', '/erm-cap/positions/pos-2026-Q3/confirm', {}, CFO);
  await call('PUT', '/erm-cap/settings', { solvency_metric: 'M-SOL' }, CRO);
  const ini = { title: 'Acquire a takaful portfolio SYN', kind: 'm_and_a', description: 'buy a medical takaful book (synthetic)', sponsor: 'ceo.syn', capital_impact: -150e6, required_impact: 80e6, decision_due: '2026-12-31' };
  assert.match((await call('POST', '/erm-cap/initiatives', Object.assign({}, ini, { kind: 'merger' }), FIN)).json.error, /kind must be one of/);
  assert.match((await call('POST', '/erm-cap/initiatives', Object.assign({}, ini, { decision_due: '31/12/2026' }), FIN)).json.error, /decision_due must be a date/);
  let r = await call('POST', '/erm-cap/initiatives', ini, FIN); assert.equal(r.status, 200); const id = r.json.id;
  assert.equal(r.json.pro_forma.solvency_after, 1.2931); assert.equal(r.json.pro_forma.judged.zone, 'outside_appetite');
  assert.equal((await call('POST', `/erm-cap/initiatives/${id}/decision`, { decision: 'approve', note: 'go ahead SYN' }, CRO)).status, 409, 'the risk review comes first');
  assert.equal((await call('POST', `/erm-cap/initiatives/${id}/review`, { appetite: 'within', risks: 'integration and reserving of the acquired book' }, FIN)).status, 403, 'not the person who raised it');
  assert.equal((await call('POST', `/erm-cap/initiatives/${id}/review`, { appetite: 'within', risks: 'integration and reserving of the acquired book' }, { user: 'ceo.syn', role: 'admin' })).status, 403, 'not the sponsor');
  assert.match((await call('POST', `/erm-cap/initiatives/${id}/review`, { appetite: 'conditional', risks: 'integration and reserving of the acquired book' }, ACT)).json.error, /conditions are required/);
  assert.match((await call('POST', `/erm-cap/initiatives/${id}/review`, { appetite: 'outside', risks: 'integration and reserving of the acquired book', linked_risks: ['BR-9999'] }, ACT)).json.error, /not in the register: BR-9999/);
  r = await call('POST', `/erm-cap/initiatives/${id}/review`, { appetite: 'outside', risks: 'solvency falls to 130 %, outside appetite; reserving of the acquired book', linked_risks: ['BR-0001'] }, ACT);
  assert.equal(r.json.state, 'awaiting_decision');
  assert.equal((await call('POST', `/erm-cap/initiatives/${id}/decision`, { decision: 'approve', note: 'go ahead SYN' }, { user: 'actuary.syn', role: 'admin' })).status, 403, 'not the reviewer');
  assert.match((await call('POST', `/erm-cap/initiatives/${id}/decision`, { decision: 'approve', note: 'go ahead' }, CRO)).json.error, /outside appetite needs the reason/);
  r = await call('POST', `/erm-cap/initiatives/${id}/decision`, { decision: 'approve', note: 'Board accepted the temporary breach with a capital plan (synthetic)' }, CRO);
  assert.equal(r.json.state, 'approved'); assert.equal(r.json.decision.outside_appetite, true);
  assert.ok(audits('initiative.raise').length === 1 && audits('initiative.review')[0].by === 'actuary.syn' && audits('initiative.approve')[0].detail.outside_appetite === true);
});
