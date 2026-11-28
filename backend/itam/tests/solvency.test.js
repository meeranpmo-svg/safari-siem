// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Solvency & Capital (engine/solvency.js + engine/xlsx-book.js) through the real routes on a SYNTHETIC workbook in the layout of the
// Insurance Authority's SCA template (tests/sca-fixture.js): reading the results Excel computed, the validations and the sign-off
// areas; roles (viewer reads, operator uploads, a plain operator cannot approve, the Risk Head's job role can); validation errors;
// four eyes (the uploader neither reviews nor approves; a service identity never acts); approval refused while an area is not
// signed off or a failed check is unexplained; the download: same workbook, sign-offs and explanations written, formulas
// untouched, recalculation on open; supersede and resubmission; changes against the previous approved return; changed formulas;
// the submission record; the audit trail; the stored file's permissions.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');
const { readBook } = require('../engine/xlsx-book');
const F = require('./sca-fixture');

const VIEW = { user: 'vera.syn', role: 'viewer' }, OP = { user: 'nora.syn', role: 'operator' }, OP2 = { user: 'omar.syn', role: 'operator' }, ADM = { user: 'adam.syn', role: 'admin' };
const RISK = { user: 'rita.syn', role: 'operator' }, SVC = { user: 'svc-risk', role: 'operator' };
const T0 = Date.parse('2026-02-20T08:00:00Z');

async function setup(t) {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true, now: () => T0, python: process.env.PYTHON || 'python3' });
  const call = (m, p, b, who) => e.req(m, p, Object.assign(b !== undefined ? { body: b } : {}, who || OP));
  return { e, call, audits: () => e.app.store.auditTail(500) };
}
const P = '/brisk/solvency';

test('import, results, roles and validation errors', async (t) => {
  const { e, call } = await setup(t);
  assert.equal((await call('POST', P + '/import', { filename: 'sca.xlsx', xlsx_b64: F.b64() }, VIEW)).status, 403, 'a viewer cannot upload');
  let r = await call('POST', P + '/import', { filename: 'sca.xlsx' }, OP); assert.equal(r.status, 400); assert.match(r.text, /xlsx_b64 is required/);
  r = await call('POST', P + '/import', { filename: 'sca.xlsx', xlsx_b64: 'not base64!' }, OP); assert.equal(r.status, 400); assert.match(r.text, /not base64/);
  r = await call('POST', P + '/import', { filename: 'sca.pdf', xlsx_b64: F.b64() }, OP); assert.equal(r.status, 400); assert.match(r.text, /\.pdf are not accepted/);
  r = await call('POST', P + '/import', { filename: 'other.xlsx', xlsx_b64: Buffer.from('PK\u0003\u0004 synthetic').toString('base64') }, OP); assert.equal(r.status, 400);
  r = await call('POST', P + '/import', { filename: 'sca.xlsx', xlsx_b64: F.b64() }, SVC); assert.equal(r.status, 403, 'a service identity never uploads'); assert.match(r.text, /only a person/);
  r = await call('POST', P + '/import', { filename: '20260226_SCA_2026_vSCA.04_SYN.xlsx', xlsx_b64: F.b64() }, OP); assert.equal(r.status, 200, r.text);
  const d = r.json;
  assert.equal(d.as_at, '2025-12-31'); assert.equal(d.version, 'SCA.04'); assert.equal(d.revision, 1); assert.equal(d.status, 'draft'); assert.equal(d.insurer, 'Synthetic Cooperative Insurance Co.');
  assert.equal(d.headline.regulatory_ratio, 2.25); assert.equal(d.headline.rbc, 420000); assert.ok(Math.abs(d.headline.rbc_ratio - 2.738) < 0.001);
  assert.deepEqual(d.regulatory.columns.map((c) => c.kind), ['actual', 'actual', 'projection']);
  assert.equal(d.tests.length, 3); assert.equal(d.tests.find((x) => x.rank_after === 1).test, 'Non life Underwriting - Premium risk');
  assert.equal(d.composition.length, 5); assert.equal(d.checks.filter((c) => c.status === 'fail').length, 1); assert.deepEqual(d.unexplained, ['C25']);
  assert.deepEqual(d.slots.map((s) => s.row), [4, 6, 7, 8]); assert.equal(d.slots[2].area, 'Market Risk', 'an area carries down to the next row');
  assert.equal(d.changes, null, 'nothing approved before: no comparison'); assert.match(d.integrity.note, /first return on template SCA.04/);
  const f = path.join(e.app.config.data_dir, 'state', 'solvency', d.id + '.xlsx');
  assert.ok(fs.existsSync(f)); assert.equal(fs.statSync(f).mode & 0o777, 0o600, 'the workbook is readable by the service only');
  // viewer reads
  r = await call('GET', P, undefined, VIEW); assert.equal(r.status, 200); assert.equal(r.json.latest.id, d.id); assert.equal(r.json.latest.unsigned, 4);
  assert.equal((await call('GET', P + '/' + d.id + '/download', undefined, VIEW)).status, 403, 'a viewer does not download the workbook');
  assert.equal((await call('GET', P + '/not-a-return', undefined, VIEW)).status, 404);
});

test('workflow: sign-off, explanation, four eyes, approval by the Risk Head, download, submission, audit', async (t) => {
  const { e, call, audits } = await setup(t);
  assert.equal((await call('POST', '/roles/assign', { user: 'rita.syn', role_id: 'risk-head' }, ADM)).status, 200);
  const id = (await call('POST', P + '/import', { filename: 'sca.xlsx', xlsx_b64: F.b64() }, OP)).json.id;
  // validation of a sign-off
  let r = await call('POST', P + '/' + id + '/signoff', { row: 4, name: 'Synthetic CFO' }, OP2); assert.equal(r.status, 400); assert.match(r.text, /title is required/);
  r = await call('POST', P + '/' + id + '/signoff', { row: 5, name: 'X', title: 'Y' }, OP2); assert.equal(r.status, 400); assert.match(r.text, /no area on row 5/);
  r = await call('POST', P + '/' + id + '/explain', { ref: 'C26', note: 'x' }, OP2); assert.equal(r.status, 400, 'a passing check needs no explanation');
  r = await call('POST', P + '/' + id + '/explain', { ref: 'c25;', note: 'x' }, OP2); assert.equal(r.status, 400); assert.match(r.text, /ref: a cell/);
  // review before sign-off is allowed, approval is not; the uploader never reviews
  assert.equal((await call('POST', P + '/' + id + '/review', {}, OP)).status, 403, 'the uploader cannot review');
  { const x = await call('POST', P + '/' + id + '/review', {}, { user: 'NORA.SYN', role: 'operator' }); assert.equal(x.status, 403); assert.match(x.text, /four eyes/, 'the uploader under another spelling of their name'); }
  for (const [row, name, title] of [[4, 'Synthetic CFO', 'CFO'], [6, 'Synthetic CFO', 'CFO'], [7, 'Synthetic Actuary <b>', 'Head of Actuarial'], [8, 'Synthetic CRO', 'CRO']]) {
    r = await call('POST', P + '/' + id + '/signoff', { row, name, title, judgement: row === 7 ? 'synthetic judgement' : '' }, OP2); assert.equal(r.status, 200, r.text);
  }
  r = await call('POST', P + '/' + id + '/review', { note: 'synthetic review' }, OP2); assert.equal(r.status, 200); assert.equal(r.json.status, 'reviewed');
  assert.equal((await call('POST', P + '/' + id + '/signoff', { row: 4, name: 'X', title: 'Y' }, OP2)).status, 409, 'a reviewed return is locked');
  // approval: a plain operator cannot; the Risk Head can, once the failed check is explained
  r = await call('POST', P + '/' + id + '/approve', {}, OP2); assert.equal(r.status, 403, 'a plain operator does not approve');
  r = await call('POST', P + '/' + id + '/approve', {}, RISK); assert.equal(r.status, 409); assert.match(r.text, /without an explanation: C25 Bonds/);
  r = await call('POST', P + '/' + id + '/return', {}, RISK); assert.equal(r.status, 400, 'a reason is required to send it back'); assert.match(r.text, /reason is required/);
  r = await call('POST', P + '/' + id + '/return', { reason: 'explain the bonds check' }, RISK); assert.equal(r.status, 200); assert.equal(r.json.status, 'draft');
  r = await call('POST', P + '/' + id + '/explain', { ref: 'C25', note: 'Synthetic: the held-to-maturity sukuk sit outside the market sub-module & are reconciled in note 7' }, OP2); assert.equal(r.status, 200);
  assert.deepEqual(r.json.unexplained, []);
  await call('POST', P + '/' + id + '/review', {}, OP2);
  r = await call('POST', P + '/' + id + '/approve', { note: 'synthetic approval' }, RISK); assert.equal(r.status, 200, r.text); assert.equal(r.json.status, 'approved'); assert.equal(r.json.approval.by, 'rita.syn');
  // the download: the same workbook, sign-offs and explanation written in, formulas untouched
  r = await call('GET', P + '/' + id + '/download', undefined, OP); assert.equal(r.status, 200); assert.equal(r.json.final, true);
  const out = Buffer.from(r.json.xlsx_b64, 'base64'), B = readBook(out), so = B.sheet('Sign-off Record'), va = B.sheet('Validations'), orig = readBook(F.build());
  assert.equal(so.cells.get('C7').v, 'Synthetic Actuary <b>'); assert.equal(so.cells.get('D8').v, 'CRO'); assert.equal(so.cells.get('E7').v, 'synthetic judgement'); assert.equal(so.cells.get('E4').v, '-');
  assert.match(va.cells.get('D25').v, /held-to-maturity sukuk sit outside/);
  for (const s of orig.sheets) for (const [ref, c] of s.cells) if (c.f !== null) assert.equal(B.sheet(s.name).cells.get(ref).f, c.f, 'formula kept ' + s.name + '!' + ref);
  assert.equal(B.sheet('Market').cells.get('C5').v, 125000, 'inputs untouched');
  // submission
  r = await call('POST', P + '/' + id + '/submitted', { date: '2026-03-01', reference: 'IA-SYN-1' }, RISK); assert.equal(r.status, 400, 'a date in the future'); assert.match(r.text, /in the future/);
  r = await call('POST', P + '/' + id + '/submitted', { date: '26/02/2026', reference: 'IA-SYN-1' }, RISK); assert.equal(r.status, 400); assert.match(r.text, /YYYY-MM-DD/);
  assert.equal((await call('POST', P + '/' + id + '/submitted', { date: '2026-02-19', reference: 'IA-SYN-1' }, OP2)).status, 403, 'recording the submission is for the approver');
  r = await call('POST', P + '/' + id + '/submitted', { date: '2026-02-19', reference: 'IA-SYN-1' }, RISK); assert.equal(r.status, 200); assert.equal(r.json.status, 'submitted');
  const A = audits().filter((x) => /^brisk\.solvency\./.test(x.action));
  for (const a of ['import', 'signoff', 'review', 'return', 'explain', 'approve', 'download', 'submitted']) assert.ok(A.some((x) => x.action === 'brisk.solvency.' + a), 'audited: ' + a);
  assert.ok(A.find((x) => x.action === 'brisk.solvency.approve').by === 'rita.syn' && A.find((x) => x.action === 'brisk.solvency.approve').ip !== undefined);
});

test('approval refused while an area is not signed off; the uploader never approves', async (t) => {
  const { call } = await setup(t);
  assert.equal((await call('POST', '/roles/assign', { user: 'rita.syn', role_id: 'risk-head' }, ADM)).status, 200);
  const id = (await call('POST', P + '/import', { filename: 'sca.xlsx', xlsx_b64: F.b64({ failComment: 'synthetic: explained in the workbook' }) }, RISK)).json.id;
  await call('POST', P + '/' + id + '/signoff', { row: 4, name: 'S', title: 'CFO' }, OP2);
  await call('POST', P + '/' + id + '/review', {}, OP2);
  let r = await call('POST', P + '/' + id + '/approve', {}, ADM); assert.equal(r.status, 409); assert.match(r.text, /not signed off yet: Market Risk \(Finance Function\); Market Risk \(Actuarial Function\); Operational Risk/);
  r = await call('POST', P + '/' + id + '/approve', {}, RISK); assert.equal(r.status, 403); assert.match(r.text, /uploaded the return cannot approve/);
});

test('supersede, resubmission, changes against the approved return, changed formulas', async (t) => {
  const { call } = await setup(t);
  const done = async (b64) => {
    const id = (await call('POST', P + '/import', { filename: 'sca.xlsx', xlsx_b64: b64 }, OP)).json.id;
    for (const row of [4, 6, 7, 8]) await call('POST', P + '/' + id + '/signoff', { row, name: 'S', title: 'T' }, OP2);
    await call('POST', P + '/' + id + '/explain', { ref: 'C25', note: 'synthetic' }, OP2);
    await call('POST', P + '/' + id + '/review', {}, OP2); const r = await call('POST', P + '/' + id + '/approve', {}, ADM); assert.equal(r.status, 200, r.text); return id;
  };
  const d1 = (await call('POST', P + '/import', { filename: 'a.xlsx', xlsx_b64: F.b64() }, OP)).json.id;
  const d2 = (await call('POST', P + '/import', { filename: 'b.xlsx', xlsx_b64: F.b64() }, OP)).json;
  assert.equal(d2.revision, 2); assert.equal((await call('GET', P + '/' + d1)).json.status, 'superseded', 'a newer upload replaces a draft');
  const a1 = await done(F.b64());
  const r = await call('POST', P + '/import', { filename: 'c.xlsx', xlsx_b64: F.b64({ marketInput: 140000, ratio: 2.1, formulaEdit: true }) }, OP);
  assert.equal(r.status, 200); assert.equal(r.json.resubmission, true); assert.equal((await call('GET', P + '/' + a1)).json.status, 'approved', 'an approved return is never superseded');
  const c = r.json.changes; assert.equal(c.against.id, a1);
  assert.ok(c.largest.some((x) => x.cell === 'Market!C5' && x.old === 125000 && x.new === 140000 && x.delta === 15000), JSON.stringify(c.largest.slice(0, 5)));
  assert.ok(c.headline.regulatory_ratio.delta < 0);
  assert.ok(r.json.integrity.changed.some((x) => x.cell === 'Market!E5' && x.now === 'different formula'), 'a changed formula is listed');
});

test('storage failure: a clear 424 naming the folder, nothing recorded', async (t) => {
  const { e, call } = await setup(t);
  fs.mkdirSync(path.join(e.app.config.data_dir, 'state'), { recursive: true });
  fs.writeFileSync(path.join(e.app.config.data_dir, 'state', 'solvency'), 'a file where the folder should be');
  const r = await call('POST', P + '/import', { filename: 'sca.xlsx', xlsx_b64: F.b64() }, OP);
  assert.equal(r.status, 424); assert.match(r.text, /could not store the workbook \((EEXIST|ENOTDIR)/);
  assert.equal((await call('GET', P, undefined, VIEW)).json.returns.length, 0, 'no return recorded without its file');
});

test('what-if: the template\'s own ratios reproduced, figures changed, validation, roles, saved scenarios audited, an older return read from its file', async (t) => {
  const { e, call, audits } = await setup(t);
  assert.equal((await call('POST', '/roles/assign', { user: 'rita.syn', role_id: 'risk-head' }, ADM)).status, 200);
  const id = (await call('POST', P + '/import', { filename: 'sca.xlsx', xlsx_b64: F.b64() }, OP)).json.id;
  let r = await call('POST', P + '/' + id + '/whatif', {}, OP);
  assert.equal(r.status, 200, r.text); assert.deepEqual(r.json.reproducible, { regulatory: true, rbc: true }, 'the parts give Excel\'s own ratios');
  assert.equal(r.json.base.regulatory_ratio, 2.25); assert.equal(r.json.base.binding, 'premium method');
  // a loss of 100,000 on admissible assets and an RBC 20 % higher
  r = await call('POST', P + '/' + id + '/whatif', { admissible: 2000000, rbc: 504000 }, OP);
  assert.equal(r.json.scenario.net_admissible, 800000); assert.equal(r.json.scenario.regulatory_ratio, 2); assert.ok(Math.abs(r.json.scenario.rbc_ratio - 1150000 / 504000) < 1e-9);
  assert.deepEqual(r.json.changed, ['admissible', 'rbc']);
  assert.ok(r.json.sensitivity.find((x) => x.part === 'rbc').plus10.rbc_ratio < r.json.base.rbc_ratio, '+10 % RBC lowers the RBC ratio');
  // the minimum capital requirement binds when the margin falls below it
  r = await call('POST', P + '/' + id + '/whatif', { claims_gh: 0, premium_gh: 0, req_ps: 0 }, OP); assert.equal(r.json.scenario.binding, 'minimum capital requirement'); assert.equal(r.json.scenario.required, 100000);
  r = await call('POST', P + '/' + id + '/whatif', { rbc: 'a lot' }, OP); assert.equal(r.status, 400); assert.match(r.text, /rbc must be a number/);
  assert.equal((await call('POST', P + '/' + id + '/whatif', {}, VIEW)).status, 403, 'a viewer does not run the what-if');
  assert.equal(e.app.store.collection('sca_returns').get(id).headline.regulatory_ratio, 2.25, 'nothing in the return changed');
  // scenarios: the Risk function saves them for the committee
  r = await call('POST', P + '/' + id + '/scenarios', { name: 'Equity -20 %', admissible: 1900000 }, OP2); assert.equal(r.status, 403, 'a plain operator does not save');
  r = await call('POST', P + '/' + id + '/scenarios', { name: 'Nothing' }, RISK); assert.equal(r.status, 400); assert.match(r.text, /changes no figure/);
  r = await call('POST', P + '/' + id + '/scenarios', { admissible: 1900000 }, RISK); assert.equal(r.status, 400); assert.match(r.text, /name is required/);
  r = await call('POST', P + '/' + id + '/scenarios', { name: 'Equity -20 % (synthetic)', admissible: 1900000, note: 'committee' }, RISK);
  assert.equal(r.status, 200); assert.equal(r.json.scenarios.length, 1); assert.equal(r.json.scenarios[0].regulatory_ratio, 1.75);
  assert.ok(audits().some((a) => a.action === 'brisk.solvency.scenario.save' && a.by === 'rita.syn' && a.detail.changes.admissible === 1900000));
  r = await call('POST', P + '/' + id + '/scenarios/delete', { name: 'equity -20 % (synthetic)' }, RISK); assert.equal(r.status, 200); assert.equal(r.json.scenarios.length, 0);
  assert.ok(audits().some((a) => a.action === 'brisk.solvency.scenario.delete'));
  // a return stored before the what-if existed: its figures are read once from the stored workbook
  const rec = e.app.store.collection('sca_returns').get(id); delete rec.parts; e.app.store.collection('sca_returns').put(rec);
  r = await call('POST', P + '/' + id + '/whatif', {}, OP); assert.equal(r.status, 200); assert.equal(r.json.reproducible.regulatory, true);
});

test('insights: history and trend (3+ returns), bridge that adds up, stress applied to today\'s capital with breaches, reverse stress, projection', async (t) => {
  const { call } = await setup(t);
  const approve = async (o) => {
    const id = (await call('POST', P + '/import', { filename: 'sca.xlsx', xlsx_b64: F.b64(o) }, OP)).json.id;
    for (const row of [4, 6, 7, 8]) await call('POST', P + '/' + id + '/signoff', { row, name: 'S', title: 'T' }, OP2);
    await call('POST', P + '/' + id + '/explain', { ref: 'C25', note: 'synthetic' }, OP2); await call('POST', P + '/' + id + '/review', {}, OP2);
    const r = await call('POST', P + '/' + id + '/approve', {}, ADM); assert.equal(r.status, 200, r.text); return id;
  };
  const a = await approve({ asAt: '2023-12-31', ratio: 2.5 });
  let i = (await call('GET', P + '/' + a + '/insights', undefined, VIEW)).json;
  assert.equal(i.trend.regulatory, null); assert.match(i.trend.note, /3 or more approved returns \(1 so far\)/); assert.equal(i.bridge, null, 'nothing approved before it');
  await approve({ asAt: '2024-12-31', ratio: 2.25 });
  const c = (await call('POST', P + '/import', { filename: 'sca.xlsx', xlsx_b64: F.b64({ asAt: '2025-12-31', ratio: 1.2 }) }, OP)).json.id;
  const r = await call('GET', P + '/' + c + '/insights', undefined, VIEW); assert.equal(r.status, 200, r.text); i = r.json;
  assert.deepEqual(i.history.map((h) => h.as_at), ['2023-12-31', '2024-12-31', '2025-12-31']);
  assert.ok(i.trend.regulatory && i.trend.regulatory.per_year < 0 && i.trend.regulatory.points === 3, 'a falling trend over 3 returns');
  // the bridge adds up from the last approved ratio to this one
  const sum = i.bridge.regulatory.steps.reduce((x, s) => x + s.delta, 0);
  assert.ok(Math.abs(i.bridge.regulatory.from + sum - i.bridge.regulatory.to) < 1e-9, 'bridge steps add up'); assert.equal(i.bridge.against.as_at, '2024-12-31');
  assert.ok(i.bridge.regulatory.steps.find((s) => s.label === 'Required margin').delta < 0, 'a larger required margin lowers the ratio');
  // stress: 900,000 net admissible, 750,000 required -> the 250,000 premium-risk loss takes the ratio to 86.7 %
  const pr = i.stress.find((s) => s.test === 'Non life Underwriting - Premium risk');
  assert.ok(Math.abs(pr.regulatory_ratio - 650000 / 750000) < 1e-9 && pr.breach === true, 'the premium-risk stress breaches 100 %');
  assert.deepEqual(i.breaches, ['Non life Underwriting - Premium risk']);
  assert.equal(i.stress[0].test, 'Non life Underwriting - Premium risk', 'largest loss first');
  assert.equal(i.reverse.regulatory, 150000, 'a loss of 150,000 takes the regulatory ratio to 100 %');
  assert.match(i.total.note, /no diversification/); assert.ok(!i.breaches.includes(i.total.test), 'the sum of the tests is never called a breach');
  assert.equal(i.projection.rbc.length, 4); assert.equal(i.projection.regulatory[2].kind, 'projection');
  assert.equal((await call('GET', P + '/nope/insights', undefined, VIEW)).status, 404);
});

// bug fix: the 2026 Q1 edition of the template labels the date "Valuation Date" (was "Data as at") - it was refused as "not a date"
test('the 2026 template\'s "Valuation Date" label is read as the as-at date', async (t) => {
  const { call } = await setup(t);
  const r = await call('POST', P + '/import', { filename: 'SCA_2026Q1_SYN.xlsx', xlsx_b64: F.b64({ atLabel: 'Valuation Date' }) }, OP);
  assert.equal(r.status, 200, r.text); assert.equal(r.json.as_at, '2025-12-31');
  const bad = await call('POST', P + '/import', { filename: 'x.xlsx', xlsx_b64: F.b64({ atLabel: 'Something else' }) }, OP);
  assert.equal(bad.status, 400); assert.match(bad.text, /Valuation Date/);
});

test('two years side by side: headline, parts, the ratio bridge, the capital mix, stress tests, notes; roles and validation', async (t) => {
  const { call } = await setup(t);
  const a = (await call('POST', P + '/import', { filename: 'sca-2024.xlsx', xlsx_b64: F.b64({ asAt: '2024-12-31', ratio: 2, version: 'SCA.03' }) })).json.id;
  const b = (await call('POST', P + '/import', { filename: 'sca-2025.xlsx', xlsx_b64: F.b64({ asAt: '2025-12-31', ratio: 2.5 }) })).json.id;
  assert.equal((await call('GET', P + '/compare?a=' + a)).status, 400, 'both returns are needed');
  assert.equal((await call('GET', P + '/compare?a=' + a + '&b=' + a)).status, 400, 'two different returns');
  assert.equal((await call('GET', P + '/compare?a=' + a + '&b=sca-nope')).status, 404);
  const r = await call('GET', P + '/compare?a=' + b + '&b=' + a, undefined, VIEW); assert.equal(r.status, 200, 'a viewer reads it: ' + r.text);
  const C = r.json; assert.equal(C.from.as_at, '2024-12-31', 'the older one is "from" whichever order was asked'); assert.equal(C.to.as_at, '2025-12-31');
  const reg = C.headline.find((x) => x.key === 'regulatory_ratio'); assert.ok(Math.abs(reg.from - 2) < 1e-9 && Math.abs(reg.to - 2.5) < 1e-9); assert.ok(Math.abs(reg.change - 0.5) < 1e-9); assert.equal(reg.change_pct, null, 'a ratio has no % change');
  const req = C.headline.find((x) => x.key === 'required_margin'); assert.equal(req.from, 450000); assert.equal(req.to, 360000); assert.ok(Math.abs(req.change_pct + 0.2) < 1e-9);
  assert.ok(C.bridge && Math.abs(C.bridge.from + C.bridge.assets + C.bridge.margin - C.bridge.to) < 1e-9, 'the two effects add up to the change'); assert.equal(C.bridge.assets, 0, 'net admissible unchanged in the fixture');
  assert.ok(C.parts.some((x) => x.key === 'admissible' && x.from === 2100000)); assert.ok(C.composition.some((x) => x.key === 'Market Risk' && x.from === 0.45 && x.change === 0));
  assert.ok(C.stress.some((x) => /Pluvial Flood/.test(x.key) && x.rank_to != null));
  assert.ok(C.notes.some((n) => /different template versions/.test(n)) && C.notes.some((n) => /not approved/.test(n)));
});
