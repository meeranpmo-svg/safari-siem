// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// HR onboarding (engine/onboarding.js) through the real routes: the whole joiner flow (request, manager approval, laptop from
// stock, account proposed / approved by a second person / recorded as created, credential delivery, handover), roles (viewer
// refused - personal data; account approval admin only), four eyes, validation naming the field, privileged groups refused,
// anything that looks like a password refused, the asset register updated, cancel releasing the laptop, audit. SYNTHETIC data.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');

const HR = { user: 'hana.syn', role: 'operator' }, MGR = { user: 'faisal.syn', role: 'operator' }, DESK = { user: 'desk.syn', role: 'operator' };
const ADM = { user: 'syed', role: 'admin' }, VIEW = { user: 'vera.syn', role: 'viewer' }, BOT = { user: 'ai:desk', role: 'operator' };
const JOINER = { name: 'Sara Al-Ghamdi', employee_id: 'E-10442', job_title: 'Claims Analyst', department: 'Claims', branch: 'Riyadh HQ', start_date: '2026-11-05', manager: 'faisal.syn', laptop_profile: 'standard', vpn: true };

async function setup(t) {
  const clock = Date.parse('2026-10-28T08:00:00Z');
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true, now: () => clock, python: process.env.PYTHON || 'python3' });
  const A = e.app.store.collection('assets');
  A.put({ id: 'ast_lap1', type: 'laptop', status: 'in_stock', vendor: 'Dell', model: 'Latitude 5450', serial: 'SYN-LAP-001', asset_tag: 'ZS-L-001', lifecycle: [] });
  A.put({ id: 'ast_lap2', type: 'laptop', status: 'in_stock', vendor: 'HP', model: 'EliteBook 840', serial: 'SYN-LAP-002', lifecycle: [] });
  A.put({ id: 'ast_srv1', type: 'server', status: 'in_stock', serial: 'SYN-SRV-001', lifecycle: [] });
  A.put({ id: 'ast_lap3', type: 'laptop', status: 'in_use', serial: 'SYN-LAP-003', lifecycle: [] });
  const call = (m, p, b, who) => e.req(m, p, Object.assign(b !== undefined ? { body: b } : {}, who));
  return { e, A, post: (p, b, who) => call('POST', p, b, who), get: (p, who = DESK) => call('GET', p, undefined, who) };
}
const auditOf = (e, action) => e.app.store.auditTail(300).filter((x) => x.action === action);

test('the whole joiner flow, with the asset register and the audit trail', async (t) => {
  const { e, A, post, get } = await setup(t);
  let r = await post('/onboarding', JOINER, HR); assert.equal(r.status, 200, r.raw);
  const id = r.json.id; assert.equal(id, 'ONB-001'); assert.equal(r.json.status, 'requested'); assert.equal(r.json.next, 'approve');
  assert.equal((await post('/onboarding/' + id + '/approve', { decision: 'approve' }, HR)).status, 403, 'the requester cannot approve');
  assert.equal((await post('/onboarding/' + id + '/approve', { decision: 'approve' }, DESK)).status, 403, 'only the named manager or an admin');
  r = await post('/onboarding/' + id + '/approve', { decision: 'approve' }, MGR); assert.equal(r.status, 200, r.raw); assert.equal(r.json.status, 'in_progress');
  // laptops from stock: in-stock laptops only
  const lp = (await get('/onboarding/laptops')).json.items.map((x) => x.id).sort();
  assert.deepEqual(lp, ['ast_lap1', 'ast_lap2']);
  assert.equal((await post('/onboarding/' + id + '/laptop', { asset_id: 'ast_srv1' }, DESK)).status, 400, 'a server is not a laptop');
  assert.equal((await post('/onboarding/' + id + '/laptop', { asset_id: 'ast_lap3' }, DESK)).status, 409, 'an in-use laptop is not in stock');
  r = await post('/onboarding/' + id + '/laptop', { asset_id: 'ast_lap1' }, DESK); assert.equal(r.status, 200, r.raw);
  assert.match(A.get('ast_lap1').custodian, /Sara Al-Ghamdi \(joiner ONB-001\)/);
  assert.ok(!(await get('/onboarding/laptops')).json.items.some((x) => x.id === 'ast_lap1'), 'a reserved laptop leaves the list');
  // the account
  assert.equal((await get('/onboarding/' + id + '/username')).json.username, 'sara.ghamdi');
  r = await post('/onboarding/' + id + '/account', { username: 'sara.ghamdi', groups: ['GG-Claims-Users', 'VPN-Users'], licences: ['M365 E3'] }, DESK); assert.equal(r.status, 200, r.raw);
  assert.equal((await post('/onboarding/' + id + '/account/created', { username: 'sara.ghamdi', directory_ref: 'CN=sara.ghamdi,OU=Claims' }, DESK)).status, 409, 'not before approval');
  assert.equal((await post('/onboarding/' + id + '/account/decide', { decision: 'approve' }, MGR)).status, 403, 'account approval is admin only');
  assert.equal((await post('/onboarding/' + id + '/account/decide', { decision: 'approve' }, { user: 'desk.syn', role: 'admin' })).status, 403, 'the proposer cannot approve');
  r = await post('/onboarding/' + id + '/account/decide', { decision: 'approve' }, ADM); assert.equal(r.status, 200, r.raw);
  assert.equal((await post('/onboarding/' + id + '/account/created', { username: 'sara.g', directory_ref: 'CN=sara.g' }, DESK)).status, 400, 'not the approved name');
  r = await post('/onboarding/' + id + '/account/created', { username: 'sara.ghamdi', directory_ref: 'CN=sara.ghamdi,OU=Claims,DC=corp' }, DESK); assert.equal(r.status, 200, r.raw);
  // handover needs the credentials step? no - but the request completes only when all are done
  r = await post('/onboarding/' + id + '/credentials', { method: 'in_person', must_change: false, mfa: 'enrolled' }, DESK); assert.equal(r.status, 400); assert.match(r.json.error, /must_change/);
  r = await post('/onboarding/' + id + '/credentials', { method: 'in_person', must_change: true, mfa: 'at_first_sign_in', note: 'temp password is Winter2026!' }, DESK); assert.equal(r.status, 400); assert.match(r.json.error, /never holds one/);
  r = await post('/onboarding/' + id + '/credentials', { method: 'via_manager', must_change: true, mfa: 'at_first_sign_in', note: 'handed to the manager in a sealed envelope' }, DESK); assert.equal(r.status, 200, r.raw);
  r = await post('/onboarding/' + id + '/handover', { acknowledged: true, evidence: 'signed handover form HF-2026-118' }, DESK); assert.equal(r.status, 200, r.raw);
  assert.equal(r.json.status, 'completed');
  assert.equal(A.get('ast_lap1').status, 'in_use'); assert.equal(A.get('ast_lap1').custodian, 'sara.ghamdi');
  for (const a of ['onboarding.request', 'onboarding.approve', 'onboarding.laptop', 'onboarding.account.propose', 'onboarding.account.approve', 'onboarding.account.created', 'onboarding.credentials', 'onboarding.handover', 'onboarding.complete'])
    assert.equal(auditOf(e, a).length, 1, a + ' audited');
  assert.ok(!JSON.stringify(e.app.store.auditTail(300)).includes('Winter2026'), 'the refused password never reached the audit trail');
  assert.equal(auditOf(e, 'asset.activate').length, 1, 'the asset register recorded the activation');
});

test('roles, validation and privileged groups', async (t) => {
  const { post, get } = await setup(t);
  assert.equal((await get('/onboarding', VIEW)).status, 403, 'viewers are refused (personal data)');
  assert.equal((await post('/onboarding', JOINER, VIEW)).status, 403);
  assert.equal((await post('/onboarding', JOINER, BOT)).status, 403, 'an AI identity cannot raise a request');
  let r = await post('/onboarding', Object.assign({}, JOINER, { employee_id: 'E 1/2' }), HR); assert.equal(r.status, 400); assert.match(r.json.error, /^employee_id/);
  r = await post('/onboarding', Object.assign({}, JOINER, { start_date: '2026-10-01' }), HR); assert.match(r.json.error, /start_date cannot be in the past/);
  r = await post('/onboarding', Object.assign({}, JOINER, { laptop_profile: 'gaming' }), HR); assert.match(r.json.error, /^laptop_profile must be one of/);
  r = await post('/onboarding', Object.assign({}, JOINER, { name: 'سارة الغامدي' }), HR); assert.match(r.json.error, /English letters/);
  r = await post('/onboarding', Object.assign({}, JOINER, { manager: 'faisal syn!' }), HR); assert.match(r.json.error, /^manager must be a platform user name/);
  r = await post('/onboarding', JOINER, HR); assert.equal(r.status, 200);
  assert.equal((await post('/onboarding', JOINER, HR)).status, 409, 'one open request per employee');
  await post('/onboarding/ONB-001/approve', { decision: 'approve' }, ADM);
  r = await post('/onboarding/ONB-001/account', { username: 'Sara Ghamdi' }, DESK); assert.match(r.json.error, /^username must be/);
  r = await post('/onboarding/ONB-001/account', { username: 'sara.ghamdi', groups: ['GG-Claims-Users', 'Domain Admins'] }, DESK); assert.equal(r.status, 400); assert.match(r.json.error, /Domain Admins is privileged/);
  r = await post('/onboarding/ONB-001/account', { username: 'sara.ghamdi', groups: ['SQL-Server-Admins'] }, DESK); assert.match(r.json.error, /privileged/);
  assert.equal((await post('/onboarding/ONB-001/account/decide', { decision: 'reject', note: 'x' }, ADM)).status, 409, 'nothing proposed yet');
  r = await post('/onboarding/ONB-001/approve', { decision: 'approve' }, ADM); assert.equal(r.status, 409, 'approved once');
  assert.equal((await get('/onboarding/ONB-9')).status, 400); assert.equal((await get('/onboarding/ONB-999')).status, 404);
});

test('cancel releases the laptop; reject needs a note; the next request takes a free name', async (t) => {
  const { e, A, post, get } = await setup(t);
  await post('/onboarding', JOINER, HR); await post('/onboarding/ONB-001/approve', { decision: 'approve' }, MGR);
  await post('/onboarding/ONB-001/laptop', { asset_id: 'ast_lap2' }, DESK);
  await post('/onboarding/ONB-001/account', { username: 'sara.ghamdi' }, DESK);
  assert.equal((await post('/onboarding/ONB-001/cancel', { reason: 'offer withdrawn (synthetic)' }, DESK)).status, 403, 'the desk cannot cancel');
  let r = await post('/onboarding/ONB-001/cancel', { reason: 'offer withdrawn (synthetic)' }, MGR); assert.equal(r.status, 200, r.raw); assert.equal(r.json.status, 'cancelled');
  assert.equal(A.get('ast_lap2').custodian, null, 'the laptop is released'); assert.equal(A.get('ast_lap2').status, 'in_stock');
  assert.equal(auditOf(e, 'onboarding.laptop.release').length, 1);
  r = await post('/onboarding', Object.assign({}, JOINER, { employee_id: 'E-10443', name: 'Sara Al Ghamdi' }), HR); assert.equal(r.status, 200);
  assert.equal((await get('/onboarding/ONB-002/username')).json.username, 'sara.ghamdi', 'a cancelled request does not hold the name');
  assert.match((await post('/onboarding/ONB-002/approve', { decision: 'reject' }, MGR)).json.error, /note is required/);
  r = await post('/onboarding/ONB-002/approve', { decision: 'reject', note: 'duplicate of HR ticket (synthetic)' }, MGR); assert.equal(r.json.status, 'cancelled');
  const l = (await get('/onboarding')).json; assert.equal(l.counts.open, 0); assert.equal(l.items.length, 2);
});

test('at risk: starting within 3 days with steps open', async (t) => {
  const { post, get } = await setup(t);
  await post('/onboarding', Object.assign({}, JOINER, { start_date: '2026-10-30' }), HR);
  const l = (await get('/onboarding')).json;
  assert.equal(l.items[0].at_risk, true); assert.equal(l.items[0].days_to_start, 2); assert.equal(l.counts.at_risk, 1); assert.equal(l.counts.waiting_manager, 1);
});
