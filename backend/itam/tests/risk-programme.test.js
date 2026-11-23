// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Enterprise Risk Programme (engine/risk-programme.js) through the real routes on SYNTHETIC workbooks (tests/brisk-fixture.js):
// 1 the change log, close and merge (four-eyes for Class III / IV and merges, links moved), a Class III close refused as a plain edit;
// 2 the assessment cycle (open, submit / unchanged, sign-off by a non-assessor, committee approval by neither opener nor signer,
//   return with a reason, the frozen snapshot, comparison with the previous cycle);
// 3 RAS proposals (new from a template, edit, retire; four-eyes; limits of an existing metric refused here) and the Board approval
//   (frozen, fingerprint, changed-since, refused when the RAS changed in between);
// 4 categories suggested and confirmed, templates without limits, emerging risks recorded, dismissed with a reason and promoted;
// 5 the committee, Board and regulator reports; roles (viewer reads, operator / admin writes, refused cases), validation, audit.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');
const { TEMPLATES } = require('../engine/risk-programme');
const F = require('./brisk-fixture');

const VIEW = { user: 'vera.syn', role: 'viewer' }, OP = { user: 'nora.syn', role: 'operator' }, OP2 = { user: 'omar.syn', role: 'operator' }, ADM = { user: 'adam.syn', role: 'admin' }, ADM2 = { user: 'aisha.syn', role: 'admin' };
const AI = { user: 'ai:risk-officer', role: 'admin' };
const T0 = Date.parse('2026-11-11T08:00:00Z');

async function setup(t) {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true, now: () => T0, python: process.env.PYTHON || 'python3' });
  const call = (m, p, b, who) => e.req(m, p, Object.assign(b !== undefined ? { body: b } : {}, who || OP));
  const acts = () => e.app.store.auditTail(800).map((a) => a.action);
  await call('POST', '/brisk/import/register', { filename: 'reg.xlsx', xlsx_b64: await F.registerB64(), apply: true }, ADM);
  await call('POST', '/brisk/import/ras', { filename: 'ras.xlsx', xlsx_b64: await F.rasB64(), apply: true }, ADM);
  // the synthetic workbook marks its risks solved: reopen them, as the risk team would for a live register
  for (const r of (await call('GET', '/brisk/risks', undefined, VIEW)).json.risks) if (r.status === 'solved') await call('POST', '/brisk/risks', { id: r.id, status: 'open' });
  const risks = (await call('GET', '/brisk/risks', undefined, VIEW)).json.risks, byCode = Object.fromEntries(risks.map((r) => [r.code, r]));
  return { e, call, acts, risks, byCode };
}

test('1 register: change log, close, merge with four eyes, links moved', async (t) => {
  const { call, acts, byCode } = await setup(t);
  const a = byCode['FIN-1'], b = byCode['FIN-2'];
  let r = await call('POST', '/brisk/risks', { id: a.id, owner: 'Synthetic Treasurer', change_note: 'owner moved' }); assert.equal(r.status, 200);
  let c = (await call('GET', '/brisk/risks/' + a.id + '/changes', undefined, VIEW)).json;
  assert.equal(c.changes[0].what, 'edited'); assert.deepEqual(c.changes[0].changes[0], { field: 'owner', from: 'Head of Finance', to: 'Synthetic Treasurer' }); assert.equal(c.changes[0].by, 'nora.syn'); assert.equal(c.changes[0].note, 'owner moved');
  r = await call('POST', '/brisk/risks/' + a.id + '/assess', { likelihood: 4, impact: 4, exposure: 3, note: 'synthetic re-rating' }); assert.equal(r.status, 200);
  c = (await call('GET', '/brisk/risks/' + a.id + '/changes', undefined, VIEW)).json; assert.equal(c.changes[0].what, 'assessed'); assert.ok(c.changes[0].changes.some((x) => x.field === 'rating' && /Class III/.test(x.to)));
  assert.equal((await call('GET', '/brisk/risks', undefined, VIEW)).json.risks.find((x) => x.id === a.id).changelog, undefined, 'the list carries no change log');
  // a Class III risk is not closed by a plain edit
  r = await call('POST', '/brisk/risks', { id: a.id, status: 'solved' }); assert.equal(r.status, 409); assert.match(r.text, /Class III.*use Close/);
  // validation and roles
  r = await call('POST', '/brisk/risks/' + a.id + '/close', { reason: 'merged', note: 'synthetic merge' }); assert.equal(r.status, 400); assert.match(r.text, /into is required/);
  r = await call('POST', '/brisk/risks/' + a.id + '/close', { reason: 'gone', note: 'synthetic' }); assert.equal(r.status, 400); assert.match(r.text, /reason must be one of/);
  r = await call('POST', '/brisk/risks/' + a.id + '/close', { reason: 'treated' }); assert.equal(r.status, 400); assert.match(r.text, /note is required/);
  assert.equal((await call('POST', '/brisk/risks/' + a.id + '/close', { reason: 'treated', note: 'synthetic close' }, VIEW)).status, 403);
  assert.equal((await call('POST', '/brisk/risks/' + a.id + '/close', { reason: 'treated', note: 'synthetic close' }, AI)).status, 403, 'an AI identity does not close risks');
  // Class III: waits for a second person
  r = await call('POST', '/brisk/risks/' + a.id + '/close', { reason: 'treated', note: 'synthetic: controls in place' }); assert.equal(r.status, 200); assert.equal(r.json.pending, true);
  assert.equal((await call('POST', '/brisk/risks/' + a.id + '/close/decision', { decision: 'approve' }, OP2)).status, 403, 'admin only');
  r = await call('POST', '/brisk/risks/' + a.id + '/close/decision', { decision: 'reject' }, ADM); assert.equal(r.status, 400); assert.match(r.text, /note is required to reject/);
  r = await call('POST', '/brisk/risks/' + a.id + '/close/decision', { decision: 'reject', note: 'synthetic: not yet treated' }, ADM); assert.equal(r.status, 200); assert.equal(r.json.status, 'open');
  // merge: the duplicate goes, its metric links move to the risk that stays
  const met = (await call('GET', '/brisk/ras', undefined, VIEW)).json.metrics[0];
  await call('POST', '/brisk/ras/' + met.id + '/links', { risk: b.id, op: 'add' });
  r = await call('POST', '/brisk/risks/' + b.id + '/close', { reason: 'merged', into: b.id, note: 'synthetic self merge' }); assert.equal(r.status, 400); assert.match(r.text, /into itself/);
  r = await call('POST', '/brisk/risks/' + b.id + '/close', { reason: 'merged', into: a.id, note: 'synthetic duplicate of FIN-1' }, { user: 'adam.syn', role: 'admin' }); assert.equal(r.json.pending, true, 'a merge always waits');
  r = await call('POST', '/brisk/risks/' + b.id + '/close/decision', { decision: 'approve' }, ADM); assert.equal(r.status, 403); assert.match(r.text, /four eyes/);
  r = await call('POST', '/brisk/risks/' + b.id + '/close/decision', { decision: 'approve' }, ADM2); assert.equal(r.status, 200); assert.equal(r.json.status, 'solved'); assert.equal(r.json.merged_into, a.id); assert.equal(r.json.closed.approved_by, 'aisha.syn');
  const links = (await call('GET', '/brisk/ras', undefined, VIEW)).json.metrics.find((m) => m.id === met.id).links;
  assert.ok(links.includes(a.id) && !links.includes(b.id), 'the link moved to the risk that stays: ' + links);
  assert.ok((await call('GET', '/brisk/risks/' + a.id + '/changes', undefined, VIEW)).json.changes.some((x) => x.what === 'merged in'));
  r = await call('POST', '/brisk/risks/' + b.id + '/close', { reason: 'treated', note: 'synthetic again' }); assert.equal(r.status, 409);
  // a low risk closes at once
  const low = byCode['FIN-3']; r = await call('POST', '/brisk/risks/' + low.id + '/close', { reason: 'no_longer_applicable', note: 'synthetic: product withdrawn' }); assert.equal(r.json.pending, false); assert.equal(r.json.risk.status, 'solved');
  for (const x of ['risk-programme.risk.close.request', 'risk-programme.risk.close.reject', 'risk-programme.risk.close.approve', 'risk-programme.risk.close']) assert.ok(acts().includes(x), 'audited: ' + x);
});

test('2 assessment cycle: submit, sign off, committee, return, freeze, compare', async (t) => {
  const { call, acts } = await setup(t);
  assert.equal((await call('POST', '/brisk/cycles', { period: '2026-Q4', due: '2026-12-15' }, OP)).status, 403, 'opening is admin');
  let r = await call('POST', '/brisk/cycles', { period: '2026-13', due: '2026-12-15' }, ADM); assert.equal(r.status, 400); assert.match(r.text, /period must be/);
  r = await call('POST', '/brisk/cycles', { period: '2026-Q4', due: '2026-01-01' }, ADM); assert.equal(r.status, 400); assert.match(r.text, /due cannot be in the past/);
  r = await call('POST', '/brisk/cycles', { period: '2026-Q4', due: '2026-12-15', departments: ['Synthetic Finance', 'Synthetic IT'] }, ADM); assert.equal(r.status, 200);
  const C = r.json, id = C.id; assert.equal(id, 'RC-2026-Q4'); assert.equal(C.state, 'open'); assert.ok(C.items.length > 10 && C.items.every((i) => ['Synthetic Finance', 'Synthetic IT'].includes(i.department)));
  assert.equal((await call('POST', '/brisk/cycles', { period: '2027-Q1', due: '2027-03-15' }, ADM)).status, 409, 'one cycle at a time');
  const fin = C.items.filter((i) => i.department === 'Synthetic Finance'), it = C.items.filter((i) => i.department === 'Synthetic IT');
  r = await call('POST', '/brisk/cycles/' + id + '/submit', { risk: fin[0].risk, note: 'synthetic' }); assert.equal(r.status, 400); assert.match(r.text, /likelihood, impact and exposure are required/);
  r = await call('POST', '/brisk/cycles/' + id + '/submit', { risk: 'BR-9999', unchanged: true, note: 'synthetic' }); assert.equal(r.status, 400); assert.match(r.text, /not in this cycle/);
  assert.equal((await call('POST', '/brisk/cycles/' + id + '/submit', { risk: fin[0].risk, unchanged: true, note: 'synthetic' }, VIEW)).status, 403);
  r = await call('POST', '/brisk/cycles/' + id + '/submit', { risk: fin[0].risk, likelihood: 5, impact: 4, exposure: 4, note: 'synthetic: worse this quarter' }); assert.equal(r.status, 200);
  assert.equal(r.json.items.find((i) => i.risk === fin[0].risk).movement, 'up');
  const hist = (await call('GET', '/brisk/risks/' + fin[0].risk, undefined, VIEW)).json.history; assert.match(hist[hist.length - 1].note, /2026-Q4 self-assessment: synthetic: worse/, 'the register is the record');
  for (const i of fin.slice(1)) await call('POST', '/brisk/cycles/' + id + '/submit', { risk: i.risk, unchanged: true, note: 'synthetic: no change' });
  for (const i of it.slice(0, -1)) await call('POST', '/brisk/cycles/' + id + '/submit', { risk: i.risk, unchanged: true, note: 'synthetic: no change' }, OP2);
  r = await call('POST', '/brisk/cycles/' + id + '/signoff', { department: 'Synthetic IT' }, OP); assert.equal(r.status, 409); assert.match(r.text, /1 risk\(s\) not assessed/);
  await call('POST', '/brisk/cycles/' + id + '/submit', { risk: it[it.length - 1].risk, unchanged: true, note: 'synthetic: no change' }, OP2);
  r = await call('POST', '/brisk/cycles/' + id + '/signoff', { department: 'Synthetic Finance' }, OP); assert.equal(r.status, 403); assert.match(r.text, /four eyes.*assessed/);
  r = await call('POST', '/brisk/cycles/' + id + '/signoff', { department: 'Synthetic Finance', note: 'synthetic sign-off' }, OP2); assert.equal(r.status, 200);
  r = await call('POST', '/brisk/cycles/' + id + '/submit', { risk: fin[1].risk, unchanged: true, note: 'synthetic late change' }); assert.equal(r.status, 409, 'a signed-off department is locked');
  r = await call('POST', '/brisk/cycles/' + id + '/decision', { decision: 'approve' }, ADM2); assert.equal(r.status, 409, 'not every department is signed off');
  r = await call('POST', '/brisk/cycles/' + id + '/signoff', { department: 'Synthetic IT' }, OP); assert.equal(r.status, 200); assert.equal(r.json.state, 'review');
  r = await call('POST', '/brisk/cycles/' + id + '/decision', { decision: 'approve' }, ADM); assert.equal(r.status, 403); assert.match(r.text, /opened this cycle/);
  r = await call('POST', '/brisk/cycles/' + id + '/decision', { decision: 'return' }, ADM2); assert.equal(r.status, 400); assert.match(r.text, /note is required to return/);
  r = await call('POST', '/brisk/cycles/' + id + '/decision', { decision: 'return', note: 'synthetic: explain the Finance increase' }, ADM2); assert.equal(r.json.state, 'open'); assert.equal(r.json.progress.signed, 0);
  await call('POST', '/brisk/cycles/' + id + '/signoff', { department: 'Synthetic Finance' }, OP2); await call('POST', '/brisk/cycles/' + id + '/signoff', { department: 'Synthetic IT' }, OP);
  r = await call('POST', '/brisk/cycles/' + id + '/decision', { decision: 'approve', note: 'synthetic committee' }, ADM2); assert.equal(r.status, 200); assert.equal(r.json.state, 'approved');
  assert.equal(r.json.snapshot.risks, C.items.length); assert.equal(r.json.snapshot.classes.reduce((a, b) => a + b, 0), C.items.length); assert.match(r.json.snapshot.fingerprint, /^[0-9a-f]{16}$/);
  assert.equal(r.json.compare.previous, null, 'the first cycle compares with its own start');
  r = await call('POST', '/brisk/cycles/' + id + '/submit', { risk: fin[1].risk, unchanged: true, note: 'synthetic after approval' }); assert.equal(r.status, 409, 'approved is frozen');
  // the next cycle compares with this one
  const D = (await call('POST', '/brisk/cycles', { period: '2027-Q1', due: '2027-03-15', departments: ['Synthetic Finance'] }, ADM)).json;
  const cmp = (await call('GET', '/brisk/cycles/' + D.id, undefined, VIEW)).json.compare;
  assert.equal(cmp.previous.id, id); assert.ok(cmp.summary.left >= it.length, 'the IT risks are not in this cycle: ' + JSON.stringify(cmp.summary));
  r = await call('POST', '/brisk/cycles/' + D.id + '/cancel', { note: 'x' }, ADM); assert.equal(r.status, 400);
  r = await call('POST', '/brisk/cycles/' + D.id + '/cancel', { note: 'synthetic: wrong scope' }, ADM); assert.equal(r.json.state, 'cancelled');
  assert.equal((await call('GET', '/brisk/cycles', undefined, VIEW)).json.cycles.length, 2, 'a viewer reads the cycles');
  for (const x of ['open', 'submit', 'signoff', 'return', 'approve', 'cancel']) assert.ok(acts().includes('risk-programme.cycle.' + x), 'audited: cycle.' + x);
});

test('3 RAS in the system: proposals with four eyes, Board approval frozen, changed since', async (t) => {
  const { call, acts } = await setup(t);
  const T = TEMPLATES.find((x) => x.id === 'T-UW-01');
  let r = await call('POST', '/brisk/ras/proposals', { kind: 'new', fields: { component: 'x' }, note: 'synthetic new' }); assert.equal(r.status, 400); assert.match(r.text, /fields.section_title is required/);
  r = await call('POST', '/brisk/ras/proposals', { kind: 'new', template: 'T-NOPE', fields: {}, note: 'synthetic' }); assert.equal(r.status, 400); assert.match(r.text, /no template/);
  r = await call('POST', '/brisk/ras/proposals', { kind: 'new', fields: { section_title: 'INSURANCE RISK', component: 'Synthetic ' + T.component, description: T.description, formula: T.formula, responsibility: 'Synthetic Finance', frequency: 'monthly' }, raw: { app_ceil: '<60%', tol_ceil: '70%', cap_ceil: '>80%' }, template: T.id, note: 'synthetic: committee asked for it' }, VIEW);
  assert.equal(r.status, 403);
  r = await call('POST', '/brisk/ras/proposals', { kind: 'new', fields: { section_title: 'INSURANCE RISK', component: 'Synthetic ' + T.component, description: T.description, formula: T.formula, responsibility: 'Synthetic Finance', frequency: 'monthly' }, raw: { app_ceil: '<60%', tol_ceil: '70%', cap_ceil: '>80%' }, template: T.id, note: 'synthetic: committee asked for it' });
  assert.equal(r.status, 200); const P1 = r.json; assert.equal(P1.state, 'pending'); assert.equal(P1.limits_kind, 'ceiling');
  assert.equal((await call('GET', '/brisk/ras', undefined, VIEW)).json.metrics.length, 8, 'nothing changes before the approval');
  assert.equal((await call('POST', '/brisk/ras/proposals/' + P1.id + '/decision', { decision: 'approve' }, OP)).status, 403, 'admin only');
  r = await call('POST', '/brisk/ras/proposals/' + P1.id + '/decision', { decision: 'approve' }, { user: 'nora.syn', role: 'admin' }); assert.equal(r.status, 403); assert.match(r.text, /four eyes/);
  r = await call('POST', '/brisk/ras/proposals/' + P1.id + '/decision', { decision: 'approve' }, ADM); assert.equal(r.status, 200); assert.equal(r.json.state, 'approved'); assert.equal(r.json.metric, 'RAS-03.01', 'a new section after the two of the workbook');
  const M = (await call('GET', '/brisk/ras', undefined, VIEW)).json.metrics, nm = M.find((m) => m.id === 'RAS-03.01');
  assert.equal(nm.kind, 'ceiling'); assert.equal(nm.section_title, 'INSURANCE RISK'); assert.equal(M.length, 9);
  r = await call('POST', '/brisk/ras/RAS-03.01/actuals', { period: '2026-10', value: '55%' }); assert.equal(r.status, 200, 'the new metric takes values'); assert.equal(r.json.latest.zone, 'within_appetite');
  // edit: definition only; limits go through the limit change
  r = await call('POST', '/brisk/ras/proposals', { kind: 'edit', metric: 'RAS-03.01', raw: { app_ceil: '<50%' }, fields: { description: 'x' }, note: 'synthetic edit' }); assert.equal(r.status, 400); assert.match(r.text, /limit change/);
  r = await call('POST', '/brisk/ras/proposals', { kind: 'edit', metric: 'RAS-03.01', fields: { responsibility: 'Synthetic IT' }, note: 'synthetic owner change' }); const P2 = r.json; assert.deepEqual(P2.fields, { responsibility: 'Synthetic IT' });
  assert.equal((await call('POST', '/brisk/ras/proposals', { kind: 'retire', metric: 'RAS-03.01', note: 'synthetic retire' })).status, 409, 'one proposal per metric at a time');
  r = await call('POST', '/brisk/ras/proposals/' + P2.id + '/decision', { decision: 'reject' }, ADM); assert.equal(r.status, 400);
  await call('POST', '/brisk/ras/proposals/' + P2.id + '/decision', { decision: 'approve' }, ADM2);
  assert.equal((await call('GET', '/brisk/ras', undefined, VIEW)).json.metrics.find((m) => m.id === 'RAS-03.01').responsibility, 'Synthetic IT');
  // the Board approval
  r = await call('POST', '/brisk/ras/approvals', { year: 2026, note: 'x' }); assert.equal(r.status, 400);
  r = await call('POST', '/brisk/ras/approvals', { year: 2026, note: 'synthetic: for the December Board' }); assert.equal(r.status, 200); const A1 = r.json; assert.equal(A1.count, 9); assert.match(A1.fingerprint, /^[0-9a-f]{16}$/);
  assert.equal((await call('POST', '/brisk/ras/approvals', { year: 2026, note: 'synthetic again' })).status, 409);
  r = await call('POST', '/brisk/ras/approvals/' + A1.id + '/decision', { decision: 'approve' }, ADM); assert.equal(r.status, 400); assert.match(r.text, /board_ref is required/);
  r = await call('POST', '/brisk/ras/approvals/' + A1.id + '/decision', { decision: 'approve', board_ref: 'Synthetic Board 2026/7' }, { user: 'nora.syn', role: 'admin' }); assert.equal(r.status, 403);
  // the RAS changes in between: the Board would approve something else
  const P3 = (await call('POST', '/brisk/ras/proposals', { kind: 'retire', metric: 'RAS-03.01', note: 'synthetic: replaced' })).json;
  await call('POST', '/brisk/ras/proposals/' + P3.id + '/decision', { decision: 'approve' }, ADM);
  assert.equal((await call('GET', '/brisk/ras', undefined, VIEW)).json.metrics.length, 8, 'a retired metric leaves the active RAS');
  assert.equal((await call('POST', '/brisk/ras/RAS-03.01/actuals', { period: '2026-10', value: '50%' })).status, 409, 'a retired metric takes no values');
  r = await call('POST', '/brisk/ras/approvals/' + A1.id + '/decision', { decision: 'approve', board_ref: 'Synthetic Board 2026/7' }, ADM); assert.equal(r.status, 409); assert.match(r.text, /changed after/);
  await call('POST', '/brisk/ras/approvals/' + A1.id + '/decision', { decision: 'reject', note: 'synthetic: RAS changed' }, ADM);
  const A2 = (await call('POST', '/brisk/ras/approvals', { year: 2026, note: 'synthetic: again' })).json; assert.equal(A2.id, 'RY-2026-v2');
  r = await call('POST', '/brisk/ras/approvals/' + A2.id + '/decision', { decision: 'approve', board_ref: 'Synthetic Board 2026/8' }, ADM); assert.equal(r.status, 200); assert.equal(r.json.state, 'approved');
  let V = (await call('GET', '/brisk/ras/approvals', undefined, VIEW)).json; assert.equal(V.current.id, A2.id); assert.equal(V.current.drift.unchanged, true);
  await call('POST', '/brisk/ras/RAS-01.01/limits', { raw: { cap_floor: '2', tol_floor: '2.25', app_floor: '>=260%' }, note: 'synthetic limit change', basis: 'manual' }, OP);
  await call('POST', '/brisk/ras/RAS-01.01/limits/decision', { decision: 'approve' }, ADM);
  V = (await call('GET', '/brisk/ras/approvals', undefined, VIEW)).json; assert.equal(V.current.drift.unchanged, false); assert.equal(V.current.drift.limits_changed[0].id, 'RAS-01.01', 'what changed since the Board approved it');
  for (const x of ['ras.propose.new', 'ras.propose.edit', 'ras.propose.retire', 'ras.proposal.approve', 'ras.approval.request', 'ras.approval.approve', 'ras.approval.reject']) assert.ok(acts().includes('risk-programme.' + x), 'audited: ' + x);
});

test('4 insurance: categories suggested and confirmed, templates without limits, emerging risks', async (t) => {
  const { call, acts, byCode } = await setup(t);
  let C = (await call('GET', '/brisk/catalogue', undefined, VIEW)).json;
  assert.equal(C.categories.length, 13); assert.ok(C.categories.find((c) => c.id === 'reinsurance').desc);
  assert.ok(C.categories.every((c) => c.templates.every((t) => !('limits' in t) && !('raw' in t))), 'templates carry no limit');
  const claim = C.risks.find((r) => r.code === byCode['CLA-1'].code), srv = C.risks.find((r) => r.code === byCode['IT-3'].code);
  assert.equal(claim.suggested.id, 'reserving', 'claims risks read as reserving: ' + JSON.stringify(claim.suggested)); assert.equal(srv.suggested.id, 'technology'); assert.ok(claim.suggested.words.length);
  let r = await call('POST', '/brisk/catalogue/assign', { pairs: [{ risk: claim.id, category: 'nope' }] }); assert.equal(r.status, 400); assert.match(r.text, /pairs\[0\].*category must be one of/);
  assert.equal((await call('POST', '/brisk/catalogue/assign', { pairs: [{ risk: claim.id, category: 'underwriting' }] }, VIEW)).status, 403);
  r = await call('POST', '/brisk/catalogue/assign', { pairs: [{ risk: claim.id, category: 'underwriting' }, { risk: srv.id, category: 'technology' }] }); assert.equal(r.json.changed, 2);
  C = (await call('GET', '/brisk/catalogue', undefined, VIEW)).json; assert.equal(C.risks.find((x) => x.id === claim.id).category, 'underwriting', 'the person\'s choice, not the suggestion');
  assert.equal(C.summary.categorised, 2);
  // a re-import keeps the category
  await call('POST', '/brisk/import/register', { filename: 'reg.xlsx', xlsx_b64: await F.registerB64(), apply: true }, ADM);
  assert.equal((await call('GET', '/brisk/risks/' + claim.id, undefined, VIEW)).json.ins_cat, 'underwriting', 'a re-import keeps it');
  // emerging risks
  r = await call('POST', '/brisk/emerging', { title: 'Synthetic climate-driven flood losses', category: 'catastrophe', horizon: '3-5y', trend: 'rising', impact: 4 }); assert.equal(r.status, 400); assert.match(r.text, /owner is required/);
  r = await call('POST', '/brisk/emerging', { title: 'Synthetic climate-driven flood losses', category: 'weather', horizon: '3-5y', trend: 'rising', impact: 4, owner: 'Synthetic CRO' }); assert.equal(r.status, 400); assert.match(r.text, /category must be one of/);
  r = await call('POST', '/brisk/emerging', { title: 'Synthetic climate-driven flood losses', category: 'catastrophe', horizon: '3-5y', trend: 'rising', impact: 4, owner: 'Synthetic CRO', signals: 'synthetic: more flood claims' }); assert.equal(r.status, 200); const E1 = r.json; assert.equal(E1.id, 'ER-0001');
  const E2 = (await call('POST', '/brisk/emerging', { title: 'Synthetic AI-driven claims fraud', category: 'operational', horizon: '1-3y', trend: 'rising', impact: 3, owner: 'Synthetic CRO' })).json;
  assert.equal((await call('POST', '/brisk/emerging', { title: 'x', category: 'market', horizon: '0-1y', trend: 'stable', impact: 1, owner: 'x' }, VIEW)).status, 403);
  r = await call('POST', '/brisk/emerging/' + E2.id, { state: 'dismissed' }); assert.equal(r.status, 400); assert.match(r.text, /note is required to dismiss/);
  r = await call('POST', '/brisk/emerging/' + E2.id, { state: 'dismissed', note: 'synthetic: covered by the fraud risk' }); assert.equal(r.json.state, 'dismissed');
  r = await call('POST', '/brisk/emerging/' + E1.id + '/promote', { department: 'Synthetic Claims', likelihood: 3, impact: 4, owner: 'Head of Claims', note: 'x' }); assert.equal(r.status, 400);
  r = await call('POST', '/brisk/emerging/' + E1.id + '/promote', { department: 'Synthetic Claims', likelihood: 3, impact: 4, exposure: 3, owner: 'Head of Claims', note: 'synthetic: now material' }); assert.equal(r.status, 200);
  assert.equal(r.json.emerging.state, 'promoted'); assert.equal(r.json.risk.title, E1.title); assert.equal(r.json.risk.ins_cat, 'catastrophe'); assert.equal(r.json.risk.from_emerging, E1.id);
  assert.equal((await call('POST', '/brisk/emerging/' + E1.id + '/promote', { department: 'Synthetic Claims', likelihood: 3, impact: 4, owner: 'x', note: 'synthetic again' })).status, 409);
  const L = (await call('GET', '/brisk/emerging', undefined, VIEW)).json; assert.equal(L.emerging.length, 2); assert.deepEqual(L.horizons, ['0-1y', '1-3y', '3-5y', '5y+']);
  for (const x of ['catalogue.assign', 'emerging.create', 'emerging.update', 'emerging.promote']) assert.ok(acts().includes('risk-programme.' + x), 'audited: ' + x);
});

test('5 reports: committee, Board, regulator; operator only, audited', async (t) => {
  const { call, acts } = await setup(t);
  await call('POST', '/brisk/ras/actuals', { rows: [{ metric: 'RAS-01.02', period: '2026-10', value: '99%', note: 'synthetic over appetite' }] });
  await call('POST', '/brisk/emerging', { title: 'Synthetic cyber accumulation', category: 'catastrophe', horizon: '1-3y', trend: 'rising', impact: 5, owner: 'Synthetic CRO' });
  assert.equal((await call('GET', '/brisk/reports/committee', undefined, VIEW)).status, 403, 'the register leaves only to an operator');
  assert.equal((await call('GET', '/brisk/reports/memo', undefined, OP)).status, 404);
  const c = (await call('GET', '/brisk/reports/committee', undefined, OP)).json;
  assert.equal(c.title, 'Risk Committee pack'); assert.equal(c.generated_by, 'nora.syn'); assert.equal(c.profile.kpis.risks, 38);
  assert.ok(c.appetite.breaches.some((b) => b.id === 'RAS-01.02')); assert.equal(c.emerging[0].title, 'Synthetic cyber accumulation'); assert.equal(c.assessment.last, null); assert.equal(c.appetite.approval, null);
  assert.ok(c.profile.by_category.length >= 2, 'by insurance category (recorded or suggested)');
  assert.ok(c.profile.open_classes.reduce((a, b) => a + b, 0) <= c.profile.kpis.open, 'class counts of the open risks only');
  assert.equal((c.profile.open_classes[2] || 0) + (c.profile.open_classes[3] || 0), c.top_risks.length, 'the Class III / IV count matches the list');
  const b = (await call('GET', '/brisk/reports/board', undefined, OP)).json; assert.ok(b.top_risks.length <= 10 && b.emerging.length <= 5 && !b.profile.heat);
  const g = (await call('GET', '/brisk/reports/regulator', undefined, OP)).json; assert.equal(g.register.length, 38); assert.equal(g.ras.length, 8); assert.match(g.note, /check it against the Insurance Authority/);
  assert.ok(['report.committee', 'report.board', 'report.regulator'].every((x) => acts().includes('risk-programme.' + x)), 'every report is audited');
});
