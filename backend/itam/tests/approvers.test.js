// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Approvers (engine/roles.js): a job role may carry approval scopes (infra / security). An operator with such a role
// approves that scope's plans and actions - no users, no settings; a different scope, no role, or a viewer role is
// refused; four-eyes still holds (never your own request); built-ins: Infrastructure Manager approves infra, CISO
// security (also on an install whose built-ins were stored before scopes existed); the approver list is what the SIEM
// receives, pushed on every change.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { createRoles, registerRoles } = require('../engine/roles');
const { registerDuty } = require('../engine/duty');
const { createVirtCapacity } = require('../engine/virt-capacity');
const { createSealer } = require('../engine/discovery/vault');
const { fakeVc } = require('./fixtures-vcenter-soap');

function fakeStore() {
  const cols = {};
  return { collection: (n) => cols[n] || (cols[n] = (() => { const m = new Map(); return {
    all: (f) => [...m.values()].filter((o) => !f || f(o)), get: (id) => m.get(id), put: (o) => { m.set(o.id, JSON.parse(JSON.stringify(o))); return o; }, remove: (id) => m.delete(id) }; })()) };
}
const adm = { user: 'syed', role: 'admin' };

test('approval scopes on job roles: built-ins, validation, who may approve what, the list the SIEM gets', () => {
  const store = fakeStore(), R = createRoles({ store });
  const role = (id) => R.list().roles.find((r) => r.id === id);
  assert.deepEqual(role('infra-manager').approves, ['infra']); assert.equal(role('infra-manager').base, 'operator');
  assert.deepEqual(role('ciso').approves, ['security']); assert.equal(role('ciso').base, 'operator');
  R.setUser({ user: 'Siva', role_id: 'infra-manager' }, adm); R.setUser({ user: 'Rasheed', role_id: 'ciso' }, adm);
  assert.equal(R.approves('siva', 'infra', 'operator'), true); assert.equal(R.approves('SIVA', 'security', 'operator'), false);
  assert.equal(R.approves('rasheed', 'security', 'operator'), true); assert.equal(R.approves('rasheed', 'infra', 'operator'), false);
  assert.equal(R.approves('nobody', 'infra', 'operator'), false); assert.equal(R.approves('anyone', 'infra', 'admin'), true, 'administrators approve everything');
  const AM = R.approverMap(); assert.deepEqual([AM.infra, AM.security], [['siva'], ['rasheed']]); assert.deepEqual(AM['eng:virt'], []);
  // an engineer scope: the DBA-style named approver for ONE AI engineer only; the group covers every engineer in it
  assert.equal(R.approves('siva', 'eng:virt', 'operator'), true, 'infra covers the AI Virtualization Administrator');
  assert.equal(R.approves('siva', 'eng:pentest', 'operator'), false);
  assert.equal(R.approves('system:itam', 'eng:virt', 'admin'), false, 'a service identity never approves, even as admin');
  assert.equal(R.approves('duty:virt', 'eng:virt', 'admin'), false, 'an AI engineer never approves');
  assert.deepEqual(R.me('siva').role.approves, ['infra']);
  assert.throws(() => R.save({ name: 'X', base: 'operator', approves: ['root'] }, adm), /unknown approval scope/);
  assert.throws(() => R.save({ name: 'Y', base: 'viewer', approves: ['infra'] }, adm), /viewer\) role cannot approve/);
  // an administrator removes the scope from the CISO role: Rasheed no longer approves, and the list follows
  R.save({ id: 'ciso', approves: [] }, adm);
  assert.equal(R.approves('rasheed', 'security', 'operator'), false); assert.deepEqual(R.approverMap().security, []);
  // a restart keeps an administrator's edit (the empty list is not "missing")
  assert.deepEqual(createRoles({ store }).list().roles.find((r) => r.id === 'ciso').approves, []);
});

test('an install whose built-in roles were stored before approval scopes gets the defaults once', () => {
  const store = fakeStore();
  createRoles({ store });
  const ciso = store.collection('job_roles').get('ciso'); delete ciso.approves; store.collection('job_roles').put(ciso);   // as stored by the old version
  store.collection('job_roles').remove('infra-manager');
  const R = createRoles({ store });
  assert.deepEqual(R.list().roles.find((r) => r.id === 'ciso').approves, ['security']);
  assert.ok(R.list().roles.find((r) => r.id === 'infra-manager'), 'the new built-in role appears after the update');
});

test('the approver list is pushed to the SIEM on a change (as the system, admin) and the gate answers per scope', async () => {
  const calls = [], routes = {};
  const app = { store: fakeStore(), discovery: { siem: { call: async (m, p, who, body) => { calls.push({ m, p, who, body }); return { status: 200, json: { ok: true } }; } } } };
  registerRoles({ route: (m, p, h) => { routes[m + ' ' + p] = h; } }, app, { noPush: true });
  app.roles.setUser({ user: 'siva', role_id: 'infra-manager' }, adm);
  await new Promise((r) => setTimeout(r, 10));
  const last = calls[calls.length - 1];
  assert.equal(last.m, 'POST'); assert.equal(last.p, '/approvers'); assert.equal(last.who.role, 'admin'); assert.deepEqual(last.body.scopes.infra, ['siva']);
  const ctx = (user, role) => ({ who: { user, role }, need: (r) => { if (r === 'operator' && role === 'viewer') throw Object.assign(new Error('forbidden'), { status: 403 }); return true; } });
  assert.equal(app.approveGate(ctx('siva', 'operator'), 'infra'), true);
  assert.throws(() => app.approveGate(ctx('siva', 'operator'), 'security'), (e) => e.status === 403 && /approver for Security/.test(e.message));
  assert.throws(() => app.approveGate(ctx('ali', 'operator'), 'infra'), (e) => e.status === 403);
  assert.throws(() => app.approveGate(ctx('siva', 'viewer'), 'infra'), (e) => e.status === 403, 'a viewer session never approves');
  assert.equal(app.approveGate(ctx('syed', 'admin'), 'security'), true);
  assert.deepEqual((await routes['GET /roles/approvers'](ctx('ali', 'operator'))).approvers.infra, ['siva']);
});

test('over HTTP: the Infrastructure Manager approves a virtualization plan, the CISO and a plain operator cannot; four-eyes holds', async (t) => {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  let clock = Date.parse('2026-08-01T08:00:00Z'); const now = () => clock;
  const dc = e.app.config.discovery, sealer = createSealer({ keyFile: dc.vault_key_file, createKey: true, purpose: 'sentra-itam-virt-platforms' });
  e.app.store.collection('virt_platforms').put({ id: 'vp_1', kind: 'vcenter', label: 'VC-RUH', base_url: 'https://vc1.corp.local', site: 'Riyadh HQ', enc: sealer.seal('vp_1', JSON.stringify({ username: 'svc@vsphere.local', password: 'Vc-pass-1' })) });
  const C = createVirtCapacity(e.app, { request: fakeVc([]), now, sealer }); e.app.addons = e.app.addons || {}; e.app.addons.virtCapacity = C;
  const D = registerDuty(e.app.srv, e.app, { noTimer: true, now });
  await C.run(adm); await D.patrol('virt');
  const items = D.list({ engineer: 'virt' }).items;
  const planOf = (kind) => D.get(items.find((x) => x.kind === kind).id).changes[0];
  const snapPlan = planOf('snapshot-old');
  // the administrator gives the two job roles (Roles & Functions)
  for (const [u, r] of [['siva', 'infra-manager'], ['rasheed', 'ciso']]) assert.equal((await e.req('POST', '/roles/assign', { user: 'syed', role: 'admin', body: { user: u, role_id: r } })).status, 200);
  const ap = (user, id) => e.req('POST', `/virt/changes/${id}/approve`, { user, role: 'operator', body: { comment: 'ok' } });
  assert.equal((await ap('ali', snapPlan)).status, 403, 'a plain operator cannot approve');
  const r1 = await ap('rasheed', snapPlan); assert.equal(r1.status, 403, 'the CISO approves security, not infrastructure'); assert.match(r1.json.error, /human approver for AI Virtualization Administrator/);
  assert.equal((await ap('siva', snapPlan)).status, 200, 'the Infrastructure Manager approves');
  // his own request: refused (four-eyes) even with the role
  // a plan Siva writes himself, on an item that has no open plan yet (the engineer already wrote one for the snapshot)
  // (every item the engineer can plan already has its plan: an administrator rejects one, then Siva writes his own)
  const other = items.find((x) => x.kind !== 'snapshot-old' && (D.get(x.id).changes || []).length);
  assert.ok(other, 'another item with an engineer plan');
  assert.equal((await e.req('POST', `/virt/changes/${D.get(other.id).changes[0]}/reject`, { user: 'syed', role: 'admin', body: { reason: 'Siva will plan this one himself' } })).status, 200);
  let own = null;
  for (const it of [other]) { own = await e.req('POST', '/virt/changes', { user: 'siva', role: 'operator', body: { item_id: it.id } }); if (own.status === 200 && own.json && own.json.requested_by === 'siva') break; own = null; }
  assert.ok(own, 'an item without an open plan, so that Siva is the requester'); const ownId = own.json.id;
  assert.ok(ownId, own.text); const r2 = await ap('siva', ownId); assert.equal(r2.status, 403, 'never your own request'); assert.match(r2.json.error, /four-eyes/);
  // but nothing beyond approvals: still an operator (job roles, users and settings stay with administrators)
  assert.equal((await e.req('POST', '/roles/assign', { user: 'siva', role: 'operator', body: { user: 'ali', role_id: 'system-admin' } })).status, 403);
});

test('approval scopes: identical to the SIEM copy (who approves each AI engineer, one definition)', (t) => {
  const fs = require('node:fs'), path = require('node:path');
  const siem = path.join(__dirname, '..', '..', 'siem', 'engine', 'approvers', 'scopes.js');
  if (!fs.existsSync(siem)) { t.skip('sentra-siem checkout not next to shield'); return; }
  assert.equal(fs.readFileSync(path.join(__dirname, '..', 'engine', 'approve-scopes.js'), 'utf8'), fs.readFileSync(siem, 'utf8'), 'edit engine/approvers/scopes.js in sentra-siem and copy it here');
});
