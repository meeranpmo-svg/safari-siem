// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Business Risk (engine/business-risk.js) through the real routes on SYNTHETIC workbooks (tests/brisk-fixture.js): the methodology
// (likelihood x impact, exposure x band -> Class I-IV), the register import (preview, apply, re-import keeps history, duplicate codes,
// rating mismatches), quality flags, the ML findings (duplicates, rating consistency), suggestions for a new risk, four-eyes acceptance
// of a Class III risk, the RAS import (limits read, issues listed), actuals (ratio guard, explanation outside appetite, future period,
// manual zone, bulk all-or-nothing), the forecast and early warning, links and the KRI flag on a risk, a GRC action, export, roles, audit.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');
const { rate } = require('../engine/business-risk');
const F = require('./brisk-fixture');

const VIEW = { user: 'vera.syn', role: 'viewer' }, OP = { user: 'nora.syn', role: 'operator' }, ADM = { user: 'adam.syn', role: 'admin' }, ADM2 = { user: 'aisha.syn', role: 'admin' };
const T0 = Date.parse('2026-11-11T08:00:00Z');

async function setup(t) {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true, now: () => T0, python: process.env.PYTHON || 'python3' });
  const call = (m, p, b, who) => e.req(m, p, Object.assign(b !== undefined ? { body: b } : {}, who || OP));
  const acts = () => e.app.store.auditTail(500).map((a) => a.action);
  return { e, call, acts };
}

test('the methodology: inherent = likelihood x impact, residual = exposure x band', () => {
  assert.deepEqual([rate(2, 3, 1).label, rate(2, 3, 1).class], ['Low-Medium (6)', 'Class I']);
  assert.deepEqual([rate(4, 3, 1).label, rate(4, 3, 1).class], ['Medium (12)', 'Class II']);
  assert.deepEqual([rate(4, 4, 2).label, rate(4, 4, 2).class], ['High (16)', 'Class III']);
  assert.equal(rate(5, 5, 5).class, 'Class IV'); assert.equal(rate(1, 4, 1).label, 'Low (4)'); assert.equal(rate(5, 1, 1).label, 'Low-Medium (5)');
  assert.equal(rate(3, 3, null).class, null, 'no exposure, no residual'); assert.equal(rate(0, 3, 1).inherent, null);
});

test('register import, quality flags, ML findings, edits, four-eyes acceptance, roles, audit', async (t) => {
  const { e, call, acts } = await setup(t);
  const xb = await F.registerB64();
  assert.equal((await call('POST', '/brisk/import/register', { filename: 'reg.xlsx', xlsx_b64: xb }, OP)).status, 403, 'import is admin only');
  let r = await call('POST', '/brisk/import/register', { filename: 'reg.xlsx', xlsx_b64: 'not base64!' }, ADM); assert.equal(r.status, 400); assert.match(r.text, /xlsx_b64/);
  r = await call('POST', '/brisk/import/register', { filename: 'reg.xlsx', xlsx_b64: await F.rasB64() }, ADM); assert.equal(r.status, 400); assert.match(r.text, /no worksheet named/);
  r = await call('POST', '/brisk/import/register', { filename: 'reg.xlsx', xlsx_b64: xb }, ADM); assert.equal(r.status, 200);
  assert.equal(r.json.applied, false, 'preview first'); assert.equal(r.json.preview.rows, 38); assert.equal(r.json.preview.duplicates, 1); assert.equal(r.json.preview.rating_mismatches, 1, "IT-90: Low-Medium (12) and Class I");
  assert.equal((await call('GET', '/brisk/risks', undefined, VIEW)).json.risks.length, 0, 'a preview writes nothing');
  r = await call('POST', '/brisk/import/register', { filename: 'reg.xlsx', xlsx_b64: xb, apply: true }, ADM); assert.equal(r.status, 200); assert.equal(r.json.preview.plan.new, 38);

  let v = (await call('GET', '/brisk', undefined, VIEW)).json;
  assert.equal(v.kpis.risks, 38); assert.equal(v.imports.register.rows, 38); assert.equal(v.imports.register.by, 'adam.syn');
  assert.equal(v.heat.inherent.flat().reduce((a, b) => a + b, 0), 38, 'every rated risk on the heat map');
  const L = (await call('GET', '/brisk/risks', undefined, VIEW)).json.risks, by = Object.fromEntries(L.map((x) => [x.code, x]));
  const f90 = by['IT-90'].flags.map((f) => f.code);
  for (const c of ['rating_mismatch', 'control_exposure', 'solved_untreated', 'target_passed']) assert.ok(f90.includes(c), 'IT-90 flags ' + c);
  assert.equal(by['IT-90'].label, 'Medium (12)', 'the methodology, not the workbook text'); assert.equal(by['IT-90'].class, 'Class II');
  assert.ok(by['IT-1#2'].flags.some((f) => f.code === 'duplicate_code'), 'a repeated code is kept and flagged');
  assert.ok(by['IT-1#2'].flags.some((f) => f.code === 'no_owner'));
  assert.ok(v.insights.duplicates.some((d) => [d.a_title, d.b_title].includes('Risk of server outage')), 'the two "server outage" risks are likely duplicates');
  assert.ok(v.insights.duplicates[0].words.length, 'a duplicate names the shared words');

  // a risk by hand: validation, roles, identities
  r = await call('POST', '/brisk/risks', { department: 'Synthetic Claims', title: 'Synthetic new risk', impact: 7, likelihood: 2, owner: 'Head of Claims' }); assert.equal(r.status, 400); assert.match(r.text, /impact/);
  r = await call('POST', '/brisk/risks', { department: 'Synthetic Claims', title: 'Synthetic new risk', likelihood: 2, owner: 'x' }); assert.equal(r.status, 400); assert.match(r.text, /impact is required/);
  assert.equal((await call('POST', '/brisk/risks', { department: 'x', title: 'Synthetic', impact: 2, likelihood: 2, owner: 'x' }, VIEW)).status, 403);
  assert.equal((await call('POST', '/brisk/risks', { department: 'x', title: 'Synthetic', impact: 2, likelihood: 2, owner: 'x' }, { user: 'ai:risk', role: 'operator' })).status, 403, 'not an AI identity');
  assert.equal((await call('POST', '/brisk/risks', { code: 'CLA-1', department: 'x', title: 'Synthetic', impact: 2, likelihood: 2, owner: 'x' })).status, 409, 'a code already used');
  r = await call('POST', '/brisk/risks', { department: 'Synthetic Claims', title: 'Synthetic catastrophe accumulation', impact: 4, likelihood: 4, exposure: 2, owner: 'Head of Claims', response: 'accept', role: 'admin' });
  assert.equal(r.status, 200); const nr = r.json; assert.equal(nr.class, 'Class III'); assert.equal(nr.acceptance.status, 'pending', 'accepting Class III waits for a second person'); assert.equal(nr.role, undefined, 'undeclared field dropped');
  // four-eyes acceptance
  assert.equal((await call('POST', '/brisk/risks/' + nr.id + '/acceptance', { decision: 'approve' }, OP)).status, 403);
  r = await call('POST', '/brisk/risks', { id: nr.id, response: 'accept' }, ADM); assert.equal(r.status, 200);
  r = await call('POST', '/brisk/risks/' + nr.id + '/acceptance', { decision: 'approve' }, ADM); assert.equal(r.status, 403); assert.match(r.text, /four eyes/);
  r = await call('POST', '/brisk/risks/' + nr.id + '/acceptance', { decision: 'reject' }, ADM2); assert.equal(r.status, 400); assert.match(r.text, /note/);
  r = await call('POST', '/brisk/risks/' + nr.id + '/acceptance', { decision: 'approve' }, ADM2); assert.equal(r.status, 200); assert.equal(r.json.acceptance.status, 'approved'); assert.equal(r.json.acceptance.decided_by, 'aisha.syn');
  // re-assessment: a note is required; history kept
  r = await call('POST', '/brisk/risks/' + by['IT-90'].id + '/assess', { likelihood: 2, impact: 4, exposure: 2 }); assert.equal(r.status, 400); assert.match(r.text, /note/);
  r = await call('POST', '/brisk/risks/' + by['IT-90'].id + '/assess', { likelihood: 2, impact: 4, exposure: 2, treatment_status: 'in_place', note: 'redundant server added (synthetic)' });
  assert.equal(r.status, 200); assert.equal(r.json.label, 'Low-Medium (8)'); assert.ok(!r.json.flags.some((f) => f.code === 'rating_mismatch'), 'a person re-assessed: the workbook text no longer applies');
  assert.equal(r.json.history.slice(-1)[0].by, 'nora.syn');
  // suggestions for a new risk
  r = await call('POST', '/brisk/suggest', { title: 'Delay in claim settlement because of slow workshop approval' }); assert.equal(r.status, 200);
  assert.equal(r.json.area[0].label, 'Insurance_Risk'); assert.ok(r.json.similar.length && r.json.likelihood && r.json.impact); assert.match(r.json.why, /risk owner decides/);
  assert.equal((await call('POST', '/brisk/suggest', { title: 'x' })).status, 400);
  // re-import: history and acceptance kept, the hand-made risk untouched, nothing deleted
  r = await call('POST', '/brisk/import/register', { filename: 'reg.xlsx', xlsx_b64: xb, apply: true }, ADM); assert.equal(r.json.preview.plan.new, 0);
  const g = (await call('GET', '/brisk/risks/' + by['IT-90'].id, undefined, VIEW)).json; assert.ok(g.history.length >= 3, 'history kept across imports');
  assert.equal((await call('GET', '/brisk/risks/' + nr.id, undefined, VIEW)).json.acceptance.status, 'approved');
  // export
  assert.equal((await call('GET', '/brisk/export', undefined, VIEW)).status, 403);
  r = await call('GET', '/brisk/export'); assert.match(r.json.csv, /^"Id","Code"/); assert.equal(r.json.csv.split('\r\n').length, 40);
  for (const a of ['brisk.import.register', 'brisk.risk.create', 'brisk.risk.update', 'brisk.risk.acceptance.approve', 'brisk.risk.assess', 'brisk.export']) assert.ok(acts().includes(a), a + ' audited');
  const au = e.app.store.auditTail(500).find((a) => a.action === 'brisk.risk.acceptance.approve'); assert.equal(au.by, 'aisha.syn'); assert.equal(au.role, 'admin');
});

test('RAS: limits, actuals, zones, forecast and early warning, links, the KRI flag, a GRC action', async (t) => {
  const { e, call, acts } = await setup(t);
  await call('POST', '/brisk/import/register', { filename: 'reg.xlsx', xlsx_b64: await F.registerB64(), apply: true }, ADM);
  let r = await call('POST', '/brisk/import/ras', { filename: 'ras.xlsx', xlsx_b64: await F.rasB64() }, ADM);
  assert.equal(r.status, 200); assert.equal(r.json.preview.metrics, 8); assert.equal(r.json.preview.sections, 2); assert.equal(r.json.preview.limit_issues, 2, "out of order + written as text");
  assert.match(JSON.stringify(r.json.issues), /ceilings out of order/);
  await call('POST', '/brisk/import/ras', { filename: 'ras.xlsx', xlsx_b64: await F.rasB64(), apply: true }, ADM);
  const M = Object.fromEntries((await call('GET', '/brisk/ras', undefined, VIEW)).json.metrics.map((m) => [m.id, m]));
  assert.deepEqual([M['RAS-01.01'].kind, M['RAS-01.01'].limits.app_floor], ['floor', 2.5]);
  assert.deepEqual([M['RAS-01.02'].kind, M['RAS-01.02'].limits.app_ceil, M['RAS-01.02'].limits.cap_ceil], ['ceiling', 0.97, 1]);
  assert.equal(M['RAS-01.03'].component, 'Synthetic combined ratio', 'a blank component inherits the one above');
  assert.deepEqual([M['RAS-02.02'].kind, M['RAS-02.02'].unit, M['RAS-02.02'].limits.cap_ceil], ['band', 'hours', 5]);
  assert.equal(M['RAS-02.03'].kind, 'boolean'); assert.equal(M['RAS-02.04'].kind, 'manual'); assert.equal(M['RAS-02.05'].kind, 'none');
  assert.equal(M['RAS-01.01'].reporting, 'due'); assert.equal(M['RAS-01.01'].due_period, '2026-10');

  const put = (id, b, who) => call('POST', '/brisk/ras/' + id + '/actuals', b, who);
  assert.equal((await put('RAS-01.02', { period: '2026-10', value: '0.9' }, VIEW)).status, 403);
  r = await put('RAS-01.02', { period: '2026-10', value: '96' }); assert.equal(r.status, 400); assert.match(r.text, /ratio - enter 96%/);
  r = await put('RAS-01.02', { period: '2026-12', value: '0.9' }); assert.equal(r.status, 400); assert.match(r.text, /future/);
  r = await put('RAS-01.02', { period: '2026-13', value: '0.9' }); assert.equal(r.status, 400); assert.match(r.text, /period/);
  r = await put('RAS-01.02', { period: '2026-10', value: '99%' }); assert.equal(r.status, 400); assert.match(r.text, /note is required: the value is outside tolerance/);
  r = await put('RAS-01.02', { period: '2026-10', value: '99%', note: 'large motor claims in October (synthetic)' }); assert.equal(r.status, 200); assert.equal(r.json.latest.zone, 'outside_tolerance');
  r = await put('RAS-02.04', { period: '2026-10', value: '1%' }); assert.equal(r.status, 400); assert.match(r.text, /zone/);
  assert.equal((await put('RAS-02.04', { period: '2026-10', zone: 'within_appetite', value: 'above benchmark' })).status, 200);
  r = await put('RAS-02.03', { period: '2026-10', value: 'no', note: 'one policy above treaty (synthetic)' }); assert.equal(r.json.latest.zone, 'outside_appetite');
  r = await put('RAS-02.02', { period: '2026-10', value: '2 days', note: 'synthetic' }); assert.equal(r.json.latest.value, 48); assert.equal(r.json.latest.zone, 'capacity_breach');
  // bulk: all or nothing
  r = await call('POST', '/brisk/ras/actuals', { rows: [{ metric: 'RAS-01.01', period: '2026-06', value: '320%' }, { metric: 'RAS-01.01', period: '2026-07', value: 'lots' }] }); assert.equal(r.status, 400); assert.match(r.text, /RAS-01.01: value/);
  assert.equal((await call('GET', '/brisk/ras', undefined, VIEW)).json.metrics.find((m) => m.id === 'RAS-01.01').series.length, 0, 'nothing written from a failed batch');
  r = await call('POST', '/brisk/ras/actuals', { rows: ['320%', '300%', '290%', '275%', '262%'].map((v, i) => ({ metric: 'RAS-01.01', period: '2026-' + String(6 + i).padStart(2, '0'), value: v })) }); assert.equal(r.status, 200); assert.equal(r.json.recorded, 5);
  const s = (await call('GET', '/brisk/ras', undefined, VIEW)).json.metrics.find((m) => m.id === 'RAS-01.01');
  assert.equal(s.latest.zone, 'within_appetite'); assert.equal(s.reporting, 'reported'); assert.ok(s.forecast.points[0].value < 2.6);
  assert.ok(s.early_warning && s.early_warning.p >= 0.5, 'falling solvency: early warning before the appetite floor is crossed'); assert.match(s.early_warning.why, /not a promise/);
  // link to a risk: the KRI outside tolerance flags the risk
  const risk = (await call('GET', '/brisk/risks', undefined, VIEW)).json.risks.find((x) => x.code === 'FIN-1');
  const sug = (await call('GET', '/brisk/ras', undefined, VIEW)).json.metrics.find((m) => m.id === 'RAS-02.01').suggested_links;
  assert.ok(sug.length && /^(Risk of|Weak)/.test(sug[0].title) && sug[0].words.includes('availability'), 'system availability -> an IT risk, with the shared words');
  assert.equal((await call('POST', '/brisk/ras/RAS-01.02/links', { risk: 'BR-9999', op: 'add' })).status, 400);
  assert.equal((await call('POST', '/brisk/ras/RAS-01.02/links', { risk: risk.id, op: 'add' })).status, 200);
  const rk = (await call('GET', '/brisk/risks/' + risk.id, undefined, VIEW)).json; assert.ok(rk.flags.some((f) => f.code === 'kri_breach')); assert.equal(rk.metrics[0].id, 'RAS-01.02');
  // a GRC action: none for a value within appetite; outside appetite is raised by a person; outside tolerance was raised at once
  assert.equal((await call('POST', '/brisk/ras/RAS-01.01/action', {})).status, 409);
  r = await call('POST', '/brisk/ras/RAS-02.03/action', {}); assert.equal(r.status, 200); assert.match(r.json.action, /^ACT-/);
  assert.equal((await call('POST', '/brisk/ras/RAS-02.03/action', {})).status, 409, 'one open action per breach');
  r = await call('POST', '/brisk/ras/RAS-01.02/action', {}); assert.equal(r.status, 409, 'RAS-01.02 outside tolerance already has its automatic action'); assert.match(r.text, /already tracks/);
  // settings: admin, and not once values exist on another frequency
  assert.equal((await call('POST', '/brisk/ras/RAS-01.01/settings', { frequency: 'quarterly' }, OP)).status, 403);
  assert.equal((await call('POST', '/brisk/ras/RAS-01.01/settings', { frequency: 'quarterly' }, ADM)).status, 409);
  assert.equal((await call('POST', '/brisk/ras/RAS-02.05/settings', { frequency: 'quarterly' }, ADM)).status, 200);
  // re-import keeps values and links
  await call('POST', '/brisk/import/ras', { filename: 'ras.xlsx', xlsx_b64: await F.rasB64(), apply: true }, ADM);
  const m2 = (await call('GET', '/brisk/ras', undefined, VIEW)).json.metrics.find((m) => m.id === 'RAS-01.02'); assert.equal(m2.links[0], risk.id); assert.equal(m2.series.length, 1);
  const v = (await call('GET', '/brisk', undefined, VIEW)).json;
  assert.ok(v.kpis.outside_appetite >= 3); assert.ok(v.breaches[0].level >= 2); assert.ok(v.warnings.length >= 1); assert.ok(v.due['Synthetic Finance']);
  for (const a of ['brisk.import.ras', 'brisk.ras.actual', 'brisk.ras.actuals.bulk', 'brisk.ras.link.add', 'brisk.ras.action', 'brisk.ras.settings']) assert.ok(acts().includes(a), a + ' audited');
});

test('empty platform: the dashboard renders honestly with nothing imported', async (t) => {
  const { call } = await setup(t);
  const v = (await call('GET', '/brisk', undefined, VIEW)).json;
  assert.equal(v.kpis.risks, 0); assert.equal(v.imports.register, null); assert.equal(v.insights.duplicates_total, 0);
  const s = (await call('POST', '/brisk/suggest', { title: 'Synthetic risk to classify' })).json; assert.equal(s.enough, false);
});

test('the Head of Risk (job role, risk approval scope) decides business-risk acceptances; a plain operator cannot; four-eyes; a role saved before is migrated once', async (t) => {
  const { e, call, acts } = await setup(t);
  const RISK = { user: 'rita.syn', role: 'operator' };
  let r = await call('POST', '/roles/assign', { user: 'rita.syn', role_id: 'risk-head' }, ADM); assert.equal(r.status, 200, r.text);
  const role = (await call('GET', '/roles', undefined, ADM)).json.roles.find((x) => x.id === 'risk-head');
  assert.equal(role.functions.brisk, 'manage', 'the Head of Risk manages Business Risk'); assert.ok(role.approves.includes('risk'), 'and carries the risk approval scope');
  assert.ok(['audit', 'privacy', 'compliance', 'risk'].every((k) => role.functions[k] === 'manage'));
  const mk = async (who, title) => (await call('POST', '/brisk/risks', { department: 'Synthetic Claims', title, impact: 4, likelihood: 4, exposure: 2, owner: 'Head of Claims', response: 'accept' }, who)).json;
  const a = await mk(OP, 'Synthetic accumulation risk A'); assert.equal(a.acceptance.status, 'pending');
  r = await call('POST', '/brisk/risks/' + a.id + '/acceptance', { decision: 'approve' }, { user: 'otto.syn', role: 'operator' }); assert.equal(r.status, 403, 'an operator without the scope'); assert.match(r.text, /risk approvals|Business risk|Roles & Functions/i);
  r = await call('POST', '/brisk/risks/' + a.id + '/acceptance', { decision: 'approve' }, { user: 'svc-risk', role: 'operator' }); assert.equal(r.status, 403, 'never a service identity');
  r = await call('POST', '/brisk/risks/' + a.id + '/acceptance', { decision: 'approve', note: 'within appetite after treatment (synthetic)' }, RISK); assert.equal(r.status, 200, r.text); assert.equal(r.json.acceptance.decided_by, 'rita.syn');
  const b = await mk(RISK, 'Synthetic accumulation risk B');
  r = await call('POST', '/brisk/risks/' + b.id + '/acceptance', { decision: 'approve' }, RISK); assert.equal(r.status, 403); assert.match(r.text, /four eyes/, 'never their own request');
  assert.ok(e.app.store.auditTail(200).some((x) => x.action === 'brisk.risk.acceptance.approve' && x.by === 'rita.syn' && x.role === 'operator'));
  void acts;
  // a role saved before Business Risk existed (no brisk, no risk scope) gets both once; an administrator's later change stays
  const R = e.app.store.collection('job_roles'), cur = R.get('risk-head'), fn = Object.assign({}, cur.functions); delete fn.brisk;
  R.put(Object.assign({}, cur, { functions: fn, approves: [], migrations: [] }));
  const { createRoles } = require('../engine/roles'); createRoles(e.app, {});
  let m = R.get('risk-head'); assert.equal(m.functions.brisk, 'manage'); assert.deepEqual(m.approves, ['risk']); assert.ok(m.migrations.includes('brisk-1'));
  R.put(Object.assign({}, m, { approves: [] })); createRoles(e.app, {}); assert.deepEqual(R.get('risk-head').approves, [], 'the migration runs once: an administrator removing the scope is respected');
  const custom = { id: 'role-syn', name: 'Synthetic custom', base: 'operator', functions: { risk: 'manage' }, approves: [] }; R.put(custom); createRoles(e.app, {});
  assert.equal(R.get('role-syn').functions.brisk, 'none', 'a custom role does not silently gain Business Risk');
});

test('register year by year: close a year, import a past year, compare risk by risk, trend; roles, validation, audit', async (t) => {
  const { call, acts } = await setup(t);
  await call('POST', '/brisk/import/register', { filename: 'reg.xlsx', xlsx_b64: await F.registerB64(), apply: true }, ADM);
  await call('POST', '/roles/assign', { user: 'rita.syn', role_id: 'risk-head' }, ADM); const RH = { user: 'rita.syn', role: 'operator' };
  const live = (await call('GET', '/brisk/risks', undefined, VIEW)).json.risks;
  // a synthetic 2024 workbook: the first risk was not there, the second was rated lower (impact 1), one risk has since gone
  const H = F.REG_H, ci = (h) => H.indexOf(h), rows = F.registerRows().map((r) => r.slice());
  const first = rows[0][ci('Risk Code')], second = rows[1][ci('Risk Code')];
  const prev = rows.slice(1); prev[0][ci('Impact')] = '1 – Negligible'; const gone = rows[0].slice(); gone[ci('Risk Code')] = 'SYN-OLD-1'; gone[ci('Risk Title')] = 'A synthetic risk closed since 2024'; prev.push(gone);
  const x24 = await F.b64([{ name: 'Risk Register', columns: H.map((h) => ({ h })), rows: prev }]);
  // refused: a viewer / operator importing, a bad year, a non-person
  assert.equal((await call('POST', '/brisk/years/import', { year: 2024, filename: 'reg-2024.xlsx', xlsx_b64: x24 }, OP)).status, 403);
  assert.equal((await call('POST', '/brisk/years/import', { year: 1999, filename: 'reg-2024.xlsx', xlsx_b64: x24 }, ADM)).status, 400);
  assert.equal((await call('POST', '/brisk/years/import', { year: 2024, filename: 'reg-2024.xlsx', xlsx_b64: x24 }, { user: 'svc-risk', role: 'admin' })).status, 403);
  let r = await call('POST', '/brisk/years/import', { year: 2024, filename: 'reg-2024.xlsx', xlsx_b64: x24 }, ADM); assert.equal(r.status, 200, r.text); assert.equal(r.json.applied, false, 'preview first'); assert.equal(r.json.preview.risks, prev.length);
  r = await call('POST', '/brisk/years/import', { year: 2024, filename: 'reg-2024.xlsx', xlsx_b64: x24, apply: true }, ADM); assert.equal(r.status, 200); assert.equal(r.json.years.length, 1);
  assert.equal((await call('GET', '/brisk/risks', undefined, VIEW)).json.risks.length, live.length, 'the live register is untouched');
  assert.equal((await call('POST', '/brisk/years/import', { year: 2024, filename: 'reg-2024.xlsx', xlsx_b64: x24, apply: true }, ADM)).status, 409, 'once per year');
  // close 2025 from the live register: the Risk Head, not a plain operator
  assert.equal((await call('POST', '/brisk/years/close', { year: 2025 }, OP)).status, 403);
  r = await call('POST', '/brisk/years/close', { year: 2025, note: 'year-end (synthetic)' }, RH); assert.equal(r.status, 200, r.text); assert.equal(r.json.years.length, 2);
  // compare: either order, the older is "from"
  assert.equal((await call('GET', '/brisk/years/compare?a=2024', undefined, VIEW)).status, 400);
  assert.equal((await call('GET', '/brisk/years/compare?a=2024&b=2023', undefined, VIEW)).status, 404);
  r = await call('GET', '/brisk/years/compare?a=2025&b=2024', undefined, VIEW); assert.equal(r.status, 200, r.text); const C = r.json;
  assert.equal(C.from.year, 2024); assert.equal(C.to.year, 2025);
  const row = (code) => C.rows.find((x) => x.code === code);
  assert.equal(row(first).change, 'new'); assert.equal(row('SYN-OLD-1').change, 'gone'); assert.equal(row(second).change, 'worse'); assert.ok(row(second).inherent_change > 0);
  assert.equal(C.counts.new, 1); assert.equal(C.counts.gone, 1); assert.ok(C.by_area.length >= 1 && C.heat.from && C.heat.to);
  r = await call('GET', '/brisk/years/compare?a=2024&b=current', undefined, VIEW); assert.equal(r.json.to.source, 'live');
  r = await call('GET', '/brisk/years', undefined, VIEW); assert.deepEqual(r.json.trend.map((x) => x.year), [2024, 2025, 'current']);
  // remove: admin, with a reason
  assert.equal((await call('POST', '/brisk/years/2024/remove', {}, ADM)).status, 400);
  assert.equal((await call('POST', '/brisk/years/2024/remove', { reason: 'x' }, OP)).status, 403);
  r = await call('POST', '/brisk/years/2024/remove', { reason: 'wrong file (synthetic)' }, ADM); assert.equal(r.status, 200); assert.equal(r.json.years.length, 1);
  for (const a of ['year.import', 'year.close', 'year.remove']) assert.ok(acts().some((x) => /brisk.*\./.test(x) && x.endsWith(a)), 'audited: ' + a);
});
