// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Roles & RACI (engine/raci-intel.js) with SYNTHETIC people (a Team Workspace stand-in) and SYNTHETIC audit records: unheld critical roles
// are issues; an administrator assigns a holder and a deputy (named people only, deputy different, an inactive person refused, validation
// names the field, audited); one Accountable per activity (a second A refused, a removed A flagged); segregation of duties; the audit trail
// mapped to activities - conformance, a proposed assignment, key-person risk, self-approval - with per-person detail for operators only;
// roles (viewer reads, operator cannot assign, a service identity cannot); the daily snapshot; the advisor off until allowed.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');

const VIEW = { user: 'vera.syn', role: 'viewer' }, OP = { user: 'nora.syn', role: 'operator' }, ADM = { user: 'syed.syn', role: 'admin' }, BOT = { user: 'ai:grc', role: 'admin' };
const PEOPLE = [
  { id: 'p1', name: 'Amal Synthetic', user: 'amal.syn', role_name: 'CISO', active: true }, { id: 'p2', name: 'Bader Synthetic', user: 'bader.syn', active: true },
  { id: 'p3', name: 'Caro Synthetic', user: 'caro.syn', active: true }, { id: 'p4', name: 'Dana Synthetic', user: 'dana.syn', active: false },
];
async function setup(t) {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true, python: process.env.PYTHON || 'python3' });
  e.app.addons.teamWorkspace = { org: () => ({ people: PEOPLE }) };
  const call = (m, p, b, who) => e.req(m, p, Object.assign(b !== undefined ? { body: b } : {}, who));
  return { e, post: (p, b, who = ADM) => call('POST', p, b, who), get: (p, who = OP) => call('GET', p, undefined, who), audit: (a) => e.app.store.auditTail(500).filter((x) => x.action === a),
    rec: (by, action, target, n = 1) => { for (let i = 0; i < n; i++) e.app.store.audit({ by, role: 'operator', ip: '', action, target: target || 'T' + i }); } };
}
const card = (v, id) => v.sections[0].items.find((i) => i.id === id);
const row = (v, id) => v.sections[1].rows.find((r) => r.id === id);
const issue = (v, re) => v.sections[2].items.find((i) => re.test(i.title));

test('nothing assigned: critical roles not held are issues; a viewer reads roles and the matrix', async (t) => {
  const s = await setup(t);
  const r = await s.get('/raci-intel', VIEW); assert.equal(r.status, 200, r.text); const v = r.json;
  assert.equal(v.sections[0].items.length, 18); assert.ok(v.sections[1].rows.length >= 20);
  assert.ok(card(v, 'ciso').tags.includes('gap') && card(v, 'ciso').tone === 'bad');
  assert.ok(issue(v, /Critical role not held: Chief Information Security Officer/));
  assert.equal(v.kpis.find((k) => k.label === 'Roles held').value, '0 / 18');
  assert.equal(v.sections[3].items.length, 0, 'load per person is for operators');
  assert.match(row(v, 'c4').cells[3], /^CAB \(not held\)$/);
  assert.ok(v.ring.value < 100);
});

test('assign a holder and a deputy: people only, validation, audited; refused for an operator and a service identity', async (t) => {
  const s = await setup(t);
  assert.equal((await s.post('/raci-intel/assign', { role: 'ciso', person: 'p1' }, OP)).status, 403, 'administrators assign');
  assert.equal((await s.post('/raci-intel/assign', { role: 'ciso', person: 'p1' }, BOT)).status, 403, 'a service or AI identity cannot');
  let r = await s.post('/raci-intel/assign', { role: 'payroll', person: 'p1' }); assert.equal(r.status, 400); assert.match(r.text, /role/);
  r = await s.post('/raci-intel/assign', { role: 'ciso', person: 'p1', deputy: 'p1' }); assert.equal(r.status, 400); assert.match(r.text, /deputy: the deputy must be a different person/);
  r = await s.post('/raci-intel/assign', { role: 'ciso', person: 'p4' }); assert.equal(r.status, 400); assert.match(r.text, /person: Dana Synthetic is not active/);
  r = await s.post('/raci-intel/assign', { role: 'ciso', person: 'svc-backup' }); assert.equal(r.status, 400); assert.match(r.text, /service or AI identity/);
  r = await s.post('/raci-intel/assign', { role: 'ciso', person: 'p1', deputy: 'p2' }); assert.equal(r.status, 200, r.text);
  const v = (await s.get('/raci-intel', VIEW)).json, c = card(v, 'ciso');
  assert.equal(c.sub, 'Amal Synthetic · deputy Bader Synthetic'); assert.ok(c.tags.includes('ok'));
  assert.match(row(v, 'g1').cells[3], /^CISO \(Amal Synthetic\)$/, 'the matrix names the holder');
  const a = s.audit('raci-intel.assign'); assert.equal(a.length, 1); assert.equal(a[0].by, ADM.user); assert.equal(a[0].detail.holder, 'amal.syn'); assert.equal(a[0].detail.deputy, 'bader.syn');
  assert.equal((await s.post('/raci-intel/assign', { role: 'ciso', person: '' })).status, 200, 'an empty holder clears the role');
  assert.ok(card((await s.get('/raci-intel')).json, 'ciso').tags.includes('gap'));
});

test('one Accountable per activity; segregation of duties', async (t) => {
  const s = await setup(t);
  let r = await s.post('/raci-intel/cell', { activity: 'c4', role: 'ciso', value: 'A' }); assert.equal(r.status, 400); assert.match(r.text, /value: .*already has an accountable role \(Change Advisory Board/);
  assert.equal((await s.post('/raci-intel/cell', { activity: 'c4', role: 'cab', value: 'C' })).status, 200);
  let v = (await s.get('/raci-intel')).json; assert.ok(issue(v, /Approve the change \(CAB\): no accountable role/)); assert.ok(row(v, 'c4').tags.includes('issues'));
  assert.equal((await s.post('/raci-intel/cell', { activity: 'c4', role: 'ciso', value: 'A' })).status, 200);
  assert.equal(s.audit('raci-intel.cell').length, 2); assert.equal(s.audit('raci-intel.cell').find((x) => x.detail.role === 'cab').detail.was, 'A');
  assert.equal((await s.post('/raci-intel/cell', { activity: 'c4', role: 'ciso', value: 'X' })).status, 400);
  await s.post('/raci-intel/assign', { role: 'auditor', person: 'p3' }); await s.post('/raci-intel/assign', { role: 'sys', person: 'p3' });
  v = (await s.get('/raci-intel')).json; const i = issue(v, /holds both Internal Auditor and Systems/); assert.ok(i); assert.equal(i.badges[0].text, 'high');
});

test('the audit trail: conformance, a proposal an administrator accepts, key-person risk, self-approval - names for operators only', async (t) => {
  const s = await setup(t);
  await s.post('/raci-intel/assign', { role: 'sys', person: 'p2' });
  s.rec('caro.syn', 'roles.assign', null, 8); s.rec('bader.syn', 'roles.assign', null, 2);       // Grant roles: R sys (bader), A itm (none)
  s.rec('bader.syn', 'vapt.scan', null, 12);                                                     // one person does all the scanning
  s.rec('amal.syn', 'me.ticket.raise', 'TCK-1'); s.rec('amal.syn', 'me.ticket.approve', 'TCK-1'); // raised and approved by the same person
  s.rec('ai:soc', 'roles.assign', null, 20);                                                     // AI identities are left out
  let v = (await s.get('/raci-intel')).json, a1 = row(v, 'a1');
  assert.match(a1.cells[6].text, /^20 % by holders$/, 'two of ten done by the holder; the AI identity not counted');
  assert.ok(issue(v, /Grant or change platform roles: Caro Synthetic did 80 % of it but holds no role there - proposed as deputy Systems \/ Cloud Administrator/), 'proposed as deputy - never replacing the holder');
  assert.ok(issue(v, /Scan, test and report: one person did 100 % of it \(Bader Synthetic\)/));
  assert.equal(v.kpis.find((k) => k.label === 'Self-approvals').value, 1);
  const v0 = (await s.get('/raci-intel', VIEW)).json;
  assert.ok(!/Caro/.test(JSON.stringify(v0.sections[1].rows.map((r) => [r.detail.lists, r.actions])) + JSON.stringify(v0.sections[2].items)), 'who did what is for operators');
  assert.ok(v0.sections[2].items.some((i) => /a person did 80 %/.test(i.title)), 'a viewer sees the proposal without the name');
  const acc = a1.actions.find((x) => /Accept the proposal/.test(x.label)); assert.ok(acc); assert.deepEqual(acc.body, { role: 'sys', person: 'bader.syn', deputy: 'caro.syn' });
  assert.equal((await s.post(acc.path, acc.body)).status, 200);
  v = (await s.get('/raci-intel')).json; assert.match(row(v, 'a1').cells[6].text, /^100 % by holders$/, 'after accepting, the activity is done by its holders');
  const vv = (await s.get('/raci-intel', VIEW)).json;
  assert.ok(!/Caro/.test(JSON.stringify(vv.sections[1].rows.map((r) => [r.detail.lists, r.actions])) + JSON.stringify(vv.sections[2].items)), 'who did what is for operators');
  assert.ok(!row(vv, 'a1').actions.some((x) => /Accept/.test(x.label)));
  assert.ok(vv.sections[2].items.every((i) => !/\((Bader|Caro|Amal) Synthetic\)|^.*: (Caro|Bader) Synthetic did/.test(i.title)), 'a viewer does not see per-person activity');
});

test('daily snapshot and the advisor', async (t) => {
  const s = await setup(t);
  assert.ok(await s.e.app.addons.raciIntel.snapshot());
  const v = (await s.get('/raci-intel')).json; assert.equal(v.sections[4].points.length, 1);
  assert.equal((await s.post('/raci-intel/ask', { question: 'what should we fix first?' }, VIEW)).status, 403);
  assert.equal((await s.post('/raci-intel/ask', { question: 'what should we fix first?' }, OP)).status, 424);
});
