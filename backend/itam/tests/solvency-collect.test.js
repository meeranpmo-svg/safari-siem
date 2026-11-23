// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Solvency & Capital collection round (engine/solvency-collect.js) through the real routes on a SYNTHETIC workbook in the layout of
// the Insurance Authority's template (tests/sca-fixture.js): the machine-learning checks on their own (units x1000, sign, blank,
// robust z over history, relative change, materiality, stale); opening a round from the last approved return (Risk function only,
// validation, one per date), the department packs and their GRC actions, the owner rule, a changed formula refused, only the
// department's own sheets read, flags needing an explanation, four-eyes acceptance, return and resubmission, assembly with the new
// as-at date and the values written in (formulas kept), the uploaded return closing the round, the audit trail.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');
const { readBook, patchBook } = require('../engine/xlsx-book');
const { checkValues } = require('../engine/solvency-collect');
const F = require('./sca-fixture');

const OP = { user: 'nora.syn', role: 'operator' }, OP2 = { user: 'omar.syn', role: 'operator' }, ADM = { user: 'adam.syn', role: 'admin' }, VIEW = { user: 'vera.syn', role: 'viewer' };
const RISK = { user: 'rita.syn', role: 'operator' }, RISK2 = { user: 'raed.syn', role: 'operator' }, FIN = { user: 'fin.syn', role: 'operator' }, ACT = { user: 'act.syn', role: 'operator' };
const T0 = Date.parse('2026-12-20T08:00:00Z');

test('the checks: units, sign, blank, change against history, materiality, stale', () => {
  const base = { 'S!A1': 1500, 'S!A2': 2000, 'S!A3': 3000, 'S!A4': 4000, 'S!A5': 50, 'S!A6': 10000, 'S!A7': 10000 };
  const values = { 'S!A1': 1500 * 1000, 'S!A2': -2500, 'S!A4': 4100, 'S!A5': 400, 'S!A6': 30000, 'S!A7': 16000, 'S!A3': 3000 };
  const hist = { 'S!A7': [10000, 10100, 9900, 10050] };
  const R = checkValues(Object.keys(base), base, hist, { values });
  const k = Object.fromEntries(R.flags.map((f) => [f.cell, f.kind]));
  assert.equal(k['S!A1'], 'units', 'x1000: SAR instead of SAR \'000'); assert.equal(k['S!A2'], 'sign');
  assert.equal(k['S!A4'], undefined, '+2.5 % is normal'); assert.equal(k['S!A5'], undefined, 'below materiality');
  assert.equal(k['S!A6'], 'jump', '+200 % with no history'); assert.equal(k['S!A7'], 'jump', 'robust z against 4 approved returns');
  assert.match(R.flags.find((f) => f.cell === 'S!A7').why, /robust z \d+\.\d against 4 approved returns/);
  assert.equal(R.flags[0].kind, 'units', 'units first');
  const E = checkValues(['S!A3'], { 'S!A3': 3000 }, {}, { values: {} }); assert.equal(E.flags[0].kind, 'empty');
  const many = {}, same = {}; for (let i = 0; i < 25; i++) { many['S!B' + i] = 100 + i; same['S!B' + i] = 100 + i; }
  assert.match(checkValues(Object.keys(many), many, {}, { values: same }).stale.note, /100 % of the values are the same/);
});

async function setup(t) {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true, now: () => T0, python: process.env.PYTHON || 'python3' });
  const call = (m, p, b, who) => e.req(m, p, Object.assign(b !== undefined ? { body: b } : {}, who || OP));
  for (const u of ['rita.syn', 'raed.syn']) assert.equal((await call('POST', '/roles/assign', { user: u, role_id: 'risk-head' }, ADM)).status, 200);
  // last year's approved return - the base carried forward
  const id = (await call('POST', '/brisk/solvency/import', { filename: 'sca-2025.xlsx', xlsx_b64: F.b64() }, OP)).json.id;
  for (const row of [4, 6, 7, 8]) await call('POST', '/brisk/solvency/' + id + '/signoff', { row, name: 'S', title: 'T' }, OP2);
  await call('POST', '/brisk/solvency/' + id + '/explain', { ref: 'C25', note: 'synthetic' }, OP2);
  await call('POST', '/brisk/solvency/' + id + '/review', {}, OP2);
  assert.equal((await call('POST', '/brisk/solvency/' + id + '/approve', {}, RISK)).status, 200);
  return { e, call, base: id };
}
const P = '/brisk/solvency-cycles';
const b64of = (j) => Buffer.from(j.xlsx_b64, 'base64');
const edit = (buf, edits) => patchBook(buf, edits).toString('base64');

test('a round: open, packs, owner, formula refused, own sheets only, flags explained, four eyes, return, assemble, close', async (t) => {
  const { e, call, base } = await setup(t);
  // opening is for the Risk function, validated, one per date
  let r = await call('POST', P, { as_at: '2026-12-31', due: '2027-01-20' }, OP2); assert.equal(r.status, 403, 'a plain operator does not open a round');
  r = await call('POST', P, { as_at: '31/12/2026', due: '2027-01-20' }, RISK); assert.equal(r.status, 400); assert.match(r.text, /as_at: YYYY-MM-DD/);
  r = await call('POST', P, { as_at: '2026-12-31', due: '2026-01-01' }, RISK); assert.equal(r.status, 400); assert.match(r.text, /due date is in the past/);
  r = await call('POST', P, { as_at: '2026-12-31', due: '2027-01-20', assign: { 'No such sheet': 'Finance Function' } }, RISK); assert.equal(r.status, 400); assert.match(r.json.error, /no input sheet "No such sheet"/);
  r = await call('POST', P, { as_at: '2026-12-31', due: '2027-01-20', owners: { 'Finance Function': 'fin.syn', 'Actuarial Function': 'act.syn' } }, RISK);
  assert.equal(r.status, 200, r.text);
  const c = r.json; assert.equal(c.base.id, base, 'carried forward from the last approved return'); assert.equal(c.version, 'SCA.04');
  assert.deepEqual(c.packs.map((p) => [p.department, p.sheets.join('|')]), [['Actuarial Function', 'Projected RBC'], ['Finance Function', 'Market|Regulatory Solvency']]);
  assert.equal((await call('POST', P, { as_at: '2026-12-31', due: '2027-01-20' }, RISK)).status, 409, 'one round per date');
  const acts = e.app.addons.grcRegisters.actionList ? JSON.stringify(e.app.store.collection('grc_actions').all()) : '';
  assert.match(acts, /Solvency & Capital 2026-12-31: Finance Function - fill Market, Regulatory Solvency/, 'a GRC action per department');
  assert.equal((await call('GET', P + '/' + c.id, undefined, VIEW)).status, 200, 'a viewer follows the round');
  // Finance: download, the owner rule, a changed formula refused, values in its own sheets only
  const fin = c.packs.find((p) => p.key === 'finance-function');
  assert.equal((await call('GET', P + '/' + c.id + '/packs/finance-function/download', undefined, VIEW)).status, 403);
  const pk = b64of((await call('GET', P + '/' + c.id + '/packs/finance-function/download', undefined, FIN)).json);
  assert.ok(readBook(pk).sheet('Projected RBC'), 'the whole template, for context');
  r = await call('POST', P + '/' + c.id + '/packs/finance-function/submit', { filename: 'f.xlsx', xlsx_b64: edit(pk, { Market: { C5: 125000000 } }) }, OP2);
  assert.equal(r.status, 403); assert.match(r.text, /owned by fin\.syn/);
  r = await call('POST', P + '/' + c.id + '/packs/finance-function/submit', { filename: 'f.xlsx', xlsx_b64: F.b64({ formulaEdit: true }) }, FIN);
  assert.equal(r.status, 409); assert.match(r.text, /formula cell\(s\) changed in your sheets \(Market!E5\)/);
  r = await call('POST', P + '/' + c.id + '/packs/finance-function/submit', { filename: 'f.xlsx', xlsx_b64: edit(pk, { Market: { C5: 125000000, D5: 130000 }, 'Projected RBC': { D8: 1 } }), note: 'synthetic' }, FIN);
  assert.equal(r.status, 200, r.text);
  let f = r.json.packs.find((p) => p.key === 'finance-function');
  assert.equal(f.status, 'submitted'); assert.ok(f.flags.some((x) => x.cell === 'Market!C5' && x.kind === 'units'), JSON.stringify(f.flags));
  assert.ok(!f.flags.some((x) => /^Projected RBC!/.test(x.cell)), 'another department\'s sheet is not read');
  assert.ok(JSON.stringify(e.app.store.collection('grc_actions').all()).includes('"status":"done"'), 'the GRC action is marked done on upload');
  // acceptance: four eyes, every flag explained
  r = await call('POST', P + '/' + c.id + '/packs/finance-function/accept', {}, RISK); assert.equal(r.status, 409); assert.match(r.text, /without an explanation: Market!C5 \(units\)/);
  r = await call('POST', P + '/' + c.id + '/packs/finance-function/explain', { cell: 'Market!X9', note: 'x' }, FIN); assert.equal(r.status, 400); assert.match(r.text, /not flagged/);
  r = await call('POST', P + '/' + c.id + '/packs/finance-function/explain', { cell: 'Market!C5', note: 'synthetic: typed in riyals - corrected in the next upload' }, FIN); assert.equal(r.status, 200);
  r = await call('POST', P + '/' + c.id + '/packs/finance-function/return', { reason: 'enter Market C5 in SR \'000' }, RISK); assert.equal(r.status, 200);
  r = await call('POST', P + '/' + c.id + '/packs/finance-function/submit', { filename: 'f2.xlsx', xlsx_b64: edit(pk, { Market: { C5: 126000, D5: 130000 } }) }, FIN);
  f = r.json.packs.find((p) => p.key === 'finance-function'); assert.equal(f.flags.length, 0, 'corrected: nothing flagged');
  assert.equal((await call('POST', P + '/' + c.id + '/packs/finance-function/accept', {}, OP2)).status, 403, 'only the Risk function accepts');
  r = await call('POST', P + '/' + c.id + '/packs/finance-function/accept', { note: 'synthetic' }, RISK); assert.equal(r.status, 200); assert.equal(r.json.progress.accepted, 1);
  // Actuarial: submitted by a Risk-function person, so that person cannot accept it
  const pa = b64of((await call('GET', P + '/' + c.id + '/packs/actuarial-function/download', undefined, ACT)).json);
  r = await call('POST', P + '/' + c.id + '/packs/actuarial-function/submit', { filename: 'a.xlsx', xlsx_b64: edit(pa, { 'Projected RBC': { F8: 455000 } }) }, ADM); assert.equal(r.status, 200, 'an administrator may submit for the owner');
  assert.equal((await call('POST', P + '/' + c.id + '/assemble', {}, RISK)).status, 409, 'not every department is accepted');
  r = await call('POST', P + '/' + c.id + '/packs/actuarial-function/accept', {}, ADM); assert.equal(r.status, 403); assert.match(r.text, /four eyes/);
  assert.equal((await call('POST', P + '/' + c.id + '/packs/actuarial-function/accept', {}, RISK2)).status, 200);
  // assemble: values and the new date written, formulas kept
  r = await call('POST', P + '/' + c.id + '/assemble', {}, RISK); assert.equal(r.status, 200, r.text);
  const out = readBook(b64of(r.json)), orig = readBook(F.build());
  assert.equal(out.sheet('Market').cells.get('C5').v, 126000); assert.equal(out.sheet('Projected RBC').cells.get('F8').v, 455000);
  assert.equal(out.sheet('Instructions').cells.get('C3').v, Date.parse('2026-12-31T00:00:00Z') / 864e5 + 25569, 'the new as-at date');
  for (const s of orig.sheets) for (const [ref, cl] of s.cells) if (cl.f !== null) assert.equal(out.sheet(s.name).cells.get(ref).f, cl.f);
  // the return uploaded for the date closes the round (here: the fixture for 2026-12-31)
  r = await call('POST', '/brisk/solvency/import', { filename: 'sca-2026.xlsx', xlsx_b64: F.b64({ asAt: '2026-12-31' }) }, OP); assert.equal(r.status, 200);
  assert.equal(r.json.cycle, c.id); assert.equal((await call('GET', P + '/' + c.id, undefined, VIEW)).json.status, 'returned');
  const A = e.app.store.auditTail(500).filter((a) => /^brisk\.solvency\.cycle\./.test(a.action)).map((a) => a.action);
  for (const a of ['open', 'pack.download', 'pack.submit', 'pack.explain', 'pack.return', 'pack.accept', 'assemble', 'linked']) assert.ok(A.includes('brisk.solvency.cycle.' + a), 'audited: ' + a);
});

test('cancel needs a reason; a service identity never acts', async (t) => {
  const { call } = await setup(t);
  const c = (await call('POST', P, { as_at: '2026-12-31', due: '2027-01-20' }, RISK)).json;
  assert.equal((await call('POST', P + '/' + c.id + '/packs/finance-function/submit', { filename: 'f.xlsx', xlsx_b64: F.b64() }, { user: 'svc-risk', role: 'operator' })).status, 403);
  let r = await call('POST', P + '/' + c.id + '/cancel', {}, RISK); assert.equal(r.status, 400); assert.match(r.text, /reason is required/);
  r = await call('POST', P + '/' + c.id + '/cancel', { reason: 'synthetic: wrong date' }, RISK); assert.equal(r.status, 200); assert.equal(r.json.status, 'cancelled');
  assert.equal((await call('POST', P, { as_at: '2026-12-31', due: '2027-01-20' }, RISK)).status, 200, 'a cancelled round frees the date');
});
