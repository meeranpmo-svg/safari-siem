// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Job roles: built-ins seeded, custom roles, validation, assignment rules (no self-lockout), my functions, audit.
const test = require('node:test');
const assert = require('node:assert/strict');
const { createRoles, FUNCTIONS } = require('../engine/roles');

function fakeStore() {
  const cols = {};
  return { collection: (n) => cols[n] || (cols[n] = (() => { const m = new Map(); return {
    all: (f) => [...m.values()].filter((o) => !f || f(o)), get: (id) => m.get(id), put: (o) => { m.set(o.id, JSON.parse(JSON.stringify(o))); return o; }, remove: (id) => m.delete(id) }; })()) };
}
const adm = { user: 'syed', role: 'admin' };

test('built-in roles are seeded; custom role validated, saved, deleted', () => {
  const audits = []; const R = createRoles({ store: fakeStore(), audit: (e) => audits.push(e) });
  const v = R.list(); assert.ok(v.roles.find((r) => r.name === 'Network Admin')); assert.ok(v.roles.find((r) => r.name === 'Penetration Engineer'));
  assert.equal(v.functions.length, FUNCTIONS.length);
  assert.throws(() => R.save({ name: '' }, adm), /name is required/);
  assert.throws(() => R.save({ name: 'X', base: 'root' }, adm), /base must be/);
  assert.throws(() => R.save({ name: 'X', base: 'viewer', functions: { network: 'manage' } }, adm), /cannot manage/);
  assert.throws(() => R.save({ name: 'network admin' }, adm), /already exists/);
  const r = R.save({ name: 'Wi-Fi Engineer', base: 'operator', functions: { network: 'manage', facilities: 'view' } }, adm).saved;
  assert.equal(r.functions.network, 'manage'); assert.equal(r.functions.soc, 'none');
  assert.throws(() => R.remove('system-admin', adm), /built-in/);
  R.setUser({ user: 'ali', role_id: r.id }, adm); assert.throws(() => R.remove(r.id, adm), /assign them another role/);
  R.setUser({ user: 'ali', role_id: null }, adm); R.remove(r.id, adm); assert.ok(!R.list().roles.find((x) => x.id === r.id));
  assert.ok(audits.some((a) => a.action === 'roles.create') && audits.some((a) => a.action === 'roles.delete'));
});

test('assignment: my functions; cannot lock yourself out', () => {
  const R = createRoles({ store: fakeStore() });
  assert.equal(R.me('nobody').role, null);
  R.setUser({ user: 'Siva', role_id: 'network-admin' }, adm);
  const m = R.me('siva'); assert.equal(m.role.name, 'Network Admin'); assert.equal(m.role.functions.network, 'manage'); assert.equal(m.role.functions.soc, 'view');
  assert.throws(() => R.setUser({ user: 'syed', role_id: 'auditor' }, adm), /yourself/);
  assert.throws(() => R.setUser({ user: 'syed', role_id: null }, adm), /your own role/);
  R.setUser({ user: 'syed', role_id: 'system-admin' }, adm); assert.equal(R.me('SYED').role.base, 'admin');
  assert.throws(() => R.setUser({ user: 'bad user!', role_id: 'auditor' }, adm), /invalid user/);
});

test('focused built-ins: Desktop Support Engineer and GRC Analyst see only their own dashboard sections', () => {
  const audits = []; const R = createRoles({ store: fakeStore(), audit: (e) => audits.push(e) });
  const d = R.list().roles.find((r) => r.id === 'desktop-engineer'), g = R.list().roles.find((r) => r.id === 'grc-analyst');
  assert.ok(d && d.builtin && d.base === 'operator' && d.functions.facilities === 'manage' && d.functions.assets === 'view' && d.functions.m365 === 'view');
  assert.equal(d.functions.dashboards, 'none', 'not every platform dashboard: only the sections of its functions');
  assert.equal(d.functions.soc, 'none'); assert.equal(d.functions.compliance, 'none');
  assert.ok(g && g.functions.compliance === 'manage' && g.functions.risk === 'manage' && g.functions.dashboards === 'none' && g.functions.servers === 'none');
  assert.deepEqual(d.approves, [], 'neither approves anything by default');
  R.setUser({ user: 'rishil.syn', role_id: 'desktop-engineer' }, adm); R.setUser({ user: 'noor.syn', role_id: 'grc-analyst' }, adm);
  assert.equal(R.me('rishil.syn').role.name, 'Desktop Support Engineer'); assert.equal(R.me('noor.syn').role.name, 'GRC Analyst');
  assert.ok(audits.filter((a) => a.action === 'roles.assign').every((a) => a.by === 'syed') && audits.some((a) => a.target === 'rishil.syn' && a.detail.to === 'desktop-engineer'));
  assert.equal(R.approves('rishil.syn', 'infra', 'operator'), false);
  assert.throws(() => R.remove('desktop-engineer', adm), /built-in/);
});

test('the Head of Risk & Compliance role: risk and compliance managed, only those sections', () => {
  const { BUILTIN } = require('../engine/roles');
  const r = BUILTIN.find((x) => x.id === 'risk-head'); assert.ok(r, 'built in');
  assert.equal(r.base, 'operator'); assert.equal(r.functions.risk, 'manage'); assert.equal(r.functions.compliance, 'manage'); assert.equal(r.functions.dashboards, 'none', 'only the sections of its own work');
  assert.equal(r.functions.soc, 'none'); assert.equal(r.functions.servers, 'none');
});

test('the Application Admin built-in: applications managed, its own sections only, editable later but not deletable', () => {
  const audits = []; const R = createRoles({ store: fakeStore(), audit: (e) => audits.push(e) });
  const a = R.list().roles.find((r) => r.id === 'application-admin');
  assert.ok(a && a.builtin, 'built in'); assert.equal(a.base, 'operator', 'never an admin by default');
  assert.equal(a.functions.servers, 'manage'); assert.equal(a.functions.vuln, 'view'); assert.equal(a.functions.soc, 'none'); assert.equal(a.functions.admin, 'none');
  assert.deepEqual(a.approves, [], 'approves nothing until an administrator says so');
  // customised later: the functions change, it stays built in and cannot be deleted
  R.save({ id: 'application-admin', name: 'Application Admin', description: 'customised', base: 'operator', functions: Object.assign({}, a.functions, { soc: 'view' }), approves: [] }, adm);
  const b = R.list().roles.find((r) => r.id === 'application-admin');
  assert.equal(b.functions.soc, 'view'); assert.equal(b.builtin, true); assert.equal(b.updated_by, 'syed');
  assert.ok(audits.some((x) => /^roles\./.test(x.action) && x.target === 'application-admin'), 'the change is audited');
  assert.throws(() => R.remove('application-admin', adm), /built-in/);
});

test('Audit and Data Privacy are their own functions; roles saved before keep the same access; DPO and Internal Auditor', () => {
  const fn = (k) => FUNCTIONS.find((f) => f.key === k);
  assert.deepEqual(fn('audit').views, ['audit']); assert.deepEqual(fn('privacy').views, ['pdpl']);
  assert.ok(!fn('compliance').views.includes('audit') && !fn('compliance').views.includes('pdpl'), 'no longer inside Compliance');
  const store = fakeStore();
  // a custom role saved before the split: its functions have no audit / privacy key
  store.collection('job_roles').put({ id: 'role-old', name: 'GRC Team (synthetic)', base: 'operator', functions: { compliance: 'manage', risk: 'view', soc: 'none' } });
  store.collection('job_roles').put({ id: 'role-ops', name: 'Ops (synthetic)', base: 'operator', functions: { compliance: 'none', network: 'manage' } });
  const R = createRoles({ store, audit() {} });
  const v = R.list();
  const old = v.roles.find((r) => r.id === 'role-old'); assert.equal(old.functions.audit, 'manage'); assert.equal(old.functions.privacy, 'manage');
  assert.equal(v.roles.find((r) => r.id === 'role-ops').functions.audit, 'none');
  const dpo = v.roles.find((r) => r.id === 'dpo'), ia = v.roles.find((r) => r.id === 'internal-auditor');
  assert.equal(dpo.functions.privacy, 'manage'); assert.equal(dpo.functions.audit, 'view'); assert.equal(dpo.functions.network, 'none');
  assert.equal(ia.functions.audit, 'manage'); assert.equal(ia.functions.privacy, 'view');
  assert.equal(v.roles.find((r) => r.id === 'grc-officer').functions.audit, 'manage', 'built-in GRC officer keeps audit');
  // separable now: an administrator can give Data Privacy without Audit
  const sep = R.save({ name: 'Privacy only (synthetic)', base: 'operator', functions: { privacy: 'manage' } }, adm).saved;
  assert.equal(sep.functions.privacy, 'manage'); assert.equal(sep.functions.audit, 'none'); assert.equal(sep.functions.compliance, 'none');
  // a second start does not re-grant what an administrator removed
  store.collection('job_roles').put(Object.assign({}, store.collection('job_roles').get('role-old'), { functions: Object.assign({}, old.functions, { audit: 'none' }) }));
  assert.equal(createRoles({ store, audit() {} }).list().roles.find((r) => r.id === 'role-old').functions.audit, 'none');
});

test('engineer roles: one engineer, one set of modules; each approves only its own AI engineer', () => {
  const store = fakeStore(); const audits = [];
  // an install from before: the new engineer roles arrive on the next start, existing roles untouched
  store.collection('job_roles').put({ id: 'network-admin', builtin: true, name: 'Network Admin', base: 'operator', functions: { network: 'manage', servers: 'view' }, approves: [] });
  const R = createRoles({ store, audit: (e) => audits.push(e) });
  const v = R.list(), get = (id) => v.roles.find((r) => r.id === id);
  const want = { 'pentest-engineer': ['vuln', 'eng:pentest'], 'network-engineer': ['network', 'eng:network'], 'virtualization-admin': ['virtualization', 'eng:virt'],
    'windows-admin': ['windows', 'eng:windows'], 'exchange-admin': ['exchange', 'eng:exchange'], 'backup-admin': ['backup', null] };
  for (const [id, [fn, scope]] of Object.entries(want)) {
    const r = get(id); assert.ok(r && r.builtin, id + ' seeded'); assert.equal(r.base, 'operator', id + ' never admin');
    const granted = Object.entries(r.functions).filter(([, lvl]) => lvl !== 'none').map(([k]) => k);
    assert.deepEqual(granted, [fn], id + ' opens only ' + fn + ' (no Command Center, no "All platform dashboards")');
    assert.deepEqual(r.approves, scope ? [scope] : [], id + ' approves only its own AI engineer');
  }
  assert.equal(get('network-admin').functions.servers, 'view', 'an existing role is left as the administrator had it');
  for (const k of ['virtualization', 'windows', 'exchange', 'backup']) assert.ok(FUNCTIONS.find((f) => f.key === k), k + ' is a function on the Roles page');
  // approvals: the Windows admin approves the AI Windows Server Administrator, not the network or virtualization engineers
  R.setUser({ user: 'fahad.syn', role_id: 'windows-admin' }, adm);
  assert.equal(R.approves('fahad.syn', 'eng:windows', 'operator'), true);
  assert.equal(R.approves('fahad.syn', 'eng:network', 'operator'), false);
  assert.equal(R.approves('fahad.syn', 'infra', 'operator'), false, 'not the whole infrastructure group');
  assert.equal(R.approves('system:duty', 'eng:windows', 'operator'), false, 'a service identity never approves');
  assert.ok(audits.some((a) => a.action === 'roles.assign' || /assign/.test(a.action)), 'the assignment is audited');
  // validation still applies to the new functions
  assert.throws(() => R.save({ name: 'Bad (synthetic)', base: 'operator', functions: { windows: 'all' } }, adm), /none, view or manage/);
  assert.throws(() => R.save({ name: 'Viewer (synthetic)', base: 'viewer', functions: { exchange: 'manage' } }, adm), /cannot manage/);
  assert.equal(R.me('fahad.syn').role.functions.windows, 'manage');
});
