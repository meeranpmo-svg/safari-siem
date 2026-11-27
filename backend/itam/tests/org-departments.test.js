// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Departments (engine/org-departments.js) and how HR onboarding and Work From Home use them, SYNTHETIC data: the register starts
// from the company setting; an administrator adds / edits (validated, privileged groups refused in the joiner template, audited),
// a rename makes the asset records follow, a merge moves them and keeps the old one inactive, a department name found in the data
// is suggested and can be merged; operators read the joiner template; once saved the register is enforced in onboarding, which
// takes the template's defaults; several joiners at once with an error per row; Work From Home lists the register; roles.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');

const ADM = { user: 'admin.syn', role: 'admin' }, OP = { user: 'hr.syn', role: 'operator' }, VIEW = { user: 'vera.syn', role: 'viewer' }, BOT = { user: 'ai:engineer', role: 'admin' };
const start = () => new Date(Date.now() + 10 * 86400000).toISOString().slice(0, 10);
async function setup(t) {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  require('../engine/duty').registerDuty(e.app.srv, e.app, { noTimer: true });
  const call = (m, p, b, who) => e.req(m, p, Object.assign(b !== undefined ? { body: b } : {}, who));
  return { e, call };
}

test('departments: from the company setting, edit with validation, rename / merge make records follow, suggestions, roles, audit', async (t) => {
  const { e, call } = await setup(t);
  let v = (await call('GET', '/org/departments', undefined, VIEW)).json;
  assert.equal(v.from_company_setting, true); assert.ok(v.departments.length >= 1); assert.equal(v.enforced, false); assert.deepEqual(v.suggestions, [], 'a viewer gets no suggestions');
  e.app.assets.create({ name: 'PC-SYN-1', type: 'workstation', status: 'in_use', department: 'Site Ops' }, ADM);
  e.app.assets.create({ name: 'PC-SYN-2', type: 'workstation', status: 'in_use', department: 'site ops' }, ADM);
  e.app.assets.create({ name: 'PC-SYN-3', type: 'workstation', status: 'in_use', department: 'Finance' }, ADM);
  v = (await call('GET', '/org/departments', undefined, OP)).json; assert.ok(v.suggestions.some((x) => /site ops/i.test(x.name) && x.assets === 2), JSON.stringify(v.suggestions));
  const D = { name: 'Field Operations', name_ar: 'العمليات الميدانية', code: 'FOPS', company: 'Safari Co. (synthetic)', head: 'mgr.syn', cost_center: 'CC-410', branches: ['Jubail', 'Yanbu'], template: { laptop_profile: 'power', vpn: true, groups: ['GG-Field-Ops'], licences: ['M365 E3'] } };
  assert.equal((await call('PUT', '/org/departments/field_ops', D, OP)).status, 403, 'operators do not edit the register');
  assert.equal((await call('PUT', '/org/departments/field_ops', D, BOT)).status, 403, 'never an AI identity');
  let r = await call('PUT', '/org/departments/Bad-ID', D, ADM); assert.equal(r.status, 400); assert.match(r.json.error, /^id/);
  r = await call('PUT', '/org/departments/field_ops', Object.assign({}, D, { template: { groups: ['Domain Admins'] } }), ADM); assert.equal(r.status, 400); assert.match(r.json.error, /template\.groups: Domain Admins is privileged/);
  r = await call('PUT', '/org/departments/field_ops', Object.assign({}, D, { template: { laptop_profile: 'gaming' } }), ADM); assert.equal(r.status, 400); assert.match(r.json.error, /laptop_profile/);
  r = await call('PUT', '/org/departments/field_ops', Object.assign({}, D, { extra: 'dropped' }), ADM); assert.equal(r.status, 200, r.text);
  v = r.json; assert.equal(v.from_company_setting, false); assert.equal(v.enforced, true);
  const F = v.departments.find((d) => d.id === 'field_ops'); assert.equal(F.template.laptop_profile, 'power'); assert.deepEqual(F.branches, ['Jubail', 'Yanbu']); assert.equal(F.extra, undefined);
  assert.equal((await call('PUT', '/org/departments/dup_syn', { name: 'field operations' }, ADM)).status, 409, 'a name is unique');
  // a suggestion merged into the register: the records follow
  r = await call('POST', '/org/departments-merge-name', { name: 'Site Ops', into: 'field_ops' }, ADM); assert.equal(r.status, 200, r.text); assert.equal(r.json.records_moved, 2);
  assert.equal(e.app.store.collection('assets').all().filter((a) => a.department === 'Field Operations').length, 2);
  // rename: the records follow
  r = await call('PUT', '/org/departments/field_ops', Object.assign({}, D, { name: 'Field & Site Operations' }), ADM); assert.equal(r.json.records_moved, 2);
  assert.equal(e.app.store.collection('assets').all().filter((a) => a.department === 'Field & Site Operations').length, 2);
  // merge Finance (from the company setting, now in the register) into Field ops - kept inactive with its target
  const fin = v.departments.find((d) => /finance/i.test(d.name)); assert.ok(fin, 'Finance came from the company setting');
  r = await call('POST', '/org/departments/' + fin.id + '/merge', { into: 'field_ops', reason: 'reorganisation (synthetic)' }, ADM); assert.equal(r.status, 200, r.text); assert.equal(r.json.records_moved, 1);
  assert.equal(r.json.departments.find((d) => d.id === fin.id).active, false);
  assert.equal((await call('POST', '/org/departments/' + fin.id + '/merge', { into: 'field_ops' }, ADM)).status, 400, 'a merge needs a reason');
  // template for HR
  assert.equal((await call('GET', '/org/departments/field_ops/template', undefined, VIEW)).status, 403);
  const tp = (await call('GET', '/org/departments/field_ops/template', undefined, OP)).json; assert.equal(tp.template.laptop_profile, 'power'); assert.equal(tp.head, 'mgr.syn');
  const au = e.app.store.auditTail(100).filter((x) => /^org\.department\./.test(x.action)).map((x) => x.action);
  assert.ok(au.includes('org.department.create') && au.includes('org.department.update') && au.includes('org.department.merge') && au.includes('org.department.merge_name'), au.join(','));
});

test('onboarding with the register: enforced once saved, template defaults, several joiners at once; Work From Home lists it', async (t) => {
  const { e, call } = await setup(t);
  await call('PUT', '/org/departments/field_ops', { name: 'Field Operations', head: 'mgr.syn', template: { laptop_profile: 'power', vpn: true, m365: true } }, ADM);
  const J = (o) => Object.assign({ name: 'Joiner Syn', employee_id: 'E' + Math.floor(Math.random() * 1e6), job_title: 'Technician', department: 'field operations', start_date: start(), manager: 'mgr.syn' }, o);
  let r = await call('POST', '/onboarding', J({ department: 'Underwater Basket Weaving' }), OP); assert.equal(r.status, 400); assert.match(r.json.error, /department: .* is not in the department register/);
  r = await call('POST', '/onboarding', J(), OP); assert.equal(r.status, 200, r.text);
  const req = e.app.store.collection('onboarding').all()[0]; assert.equal(req.department, 'Field Operations', 'the canonical name'); assert.equal(req.laptop_profile, 'power', 'from the template'); assert.equal(req.vpn, true);
  const b = await call('POST', '/onboarding-bulk', { rows: [J({ name: 'Ali Syn' }), J({ name: 'Sara Syn', laptop_profile: 'executive' }), J({ name: 'X', employee_id: 'bad id!' }), J({ name: 'Omar Syn', department: 'Nope' })] }, OP);
  assert.equal(b.status, 200, b.text); assert.equal(b.json.created.length, 2); assert.equal(b.json.failed.length, 2);
  assert.ok(b.json.failed.some((x) => /rows\[2\]: .*(name|employee_id)/.test(x.error)) && b.json.failed.some((x) => /rows\[3\]: department/.test(x.error)), JSON.stringify(b.json.failed));
  assert.equal(e.app.store.collection('onboarding').all().find((x) => x.name === 'Sara Syn').laptop_profile, 'executive', 'the person can still choose');
  assert.equal((await call('POST', '/onboarding-bulk', { rows: [] }, OP)).status, 400); assert.equal((await call('POST', '/onboarding-bulk', { rows: [J()] }, VIEW)).status, 403);
  assert.ok(e.app.store.auditTail(50).some((x) => x.action === 'onboarding.bulk' && x.detail.created === 2));
  const wf = (await call('GET', '/remote-work/policy', undefined, ADM));
  if (wf.status === 200) assert.ok(JSON.stringify(wf.json).includes('Field Operations'), 'Work From Home lists the register');
});
