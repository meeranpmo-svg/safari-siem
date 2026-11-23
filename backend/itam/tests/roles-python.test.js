// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Migration step 8b (docs/PYTHON-MIGRATION.md): pyengine/roles_rules.py reads the job roles and assignments from the store
// files itself (read-only) and must answer GET /roles, /roles/me and /roles/approvers exactly like engine/roles.js -
// built-in and custom roles in the page's order (ICU name order, built-in first), approvers per scope and per AI
// engineer (a viewer role never approves), a user without a role, a role that was deleted under an assignment, user
// names in any case. Writes stay in Node.js; Python sees each write at once because the store journals it synchronously.
const test = require('node:test');
const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const { startApp } = require('./helpers');
const { createRoles, FUNCTIONS, LEVELS, BASES, APPROVE_SCOPES } = require('../engine/roles');
const SC = require('../engine/approve-scopes');
const { createPyEngine } = require('../engine/pyengine');

const PY = process.env.PYTHON || 'python3';
const hasPy = spawnSync(PY, ['--version']).status === 0;
const ADM = { user: 'syed', role: 'admin', ip: '' };
const plain = (v) => JSON.parse(JSON.stringify(v));

test('Python roles routes answer exactly like the Node.js ones, from the store files', { skip: !hasPy && 'python3 not available' }, async (t) => {
  const e = await startApp({ noAi: true });
  t.after(() => e.close());
  const py = createPyEngine({ python: PY });
  const R = createRoles(e.app, { noPython: true });
  const cat = { functions: FUNCTIONS, levels: LEVELS, bases: BASES, approve_scopes: APPROVE_SCOPES, groups: SC.GROUPS, engineers: SC.ENGINEERS };
  const ask = (op, extra) => py.call(op, Object.assign({ dir: e.app.store.dir, catalogue: cat }, extra || {}));
  const same = async (what) => {
    assert.deepEqual(await ask('roles.list'), plain(R.list()), what + ': list');
    assert.deepEqual(await ask('roles.approvers'), plain({ scopes: APPROVE_SCOPES, groups: SC.GROUPS, approvers: R.approverMap(), engineers: R.engineerApprovers() }), what + ': approvers');
    for (const u of ['Siva', 'siva', 'RASHEED', 'nobody', 'viewer.v', 'ghost', '', undefined]) assert.deepEqual(await ask('roles.me', { user: u }), plain(R.me(u)), what + ': me ' + u);
  };
  await same('built-in roles only');
  const fn = (o) => Object.assign({}, o);
  for (const [name, base, approves, f] of [['abc', 'operator', ['eng:network'], { network: 'manage' }], ['Abc DBA', 'operator', ['eng:windows', 'infra'], { servers: 'view' }],
    ['a-b team', 'viewer', [], { soc: 'view' }], ['zeta', 'operator', ['security'], {}], ['Éclair', 'admin', [], {}], ['_under', 'operator', ['eng:pentest'], {}], ['10 digits', 'operator', [], {}]])
    R.save({ name, base, approves, functions: fn(f), description: 'test ' + name }, ADM);
  const id = (n) => R.list().roles.find((r) => r.name === n).id;
  R.setUser({ user: 'Siva', role_id: id('abc') }, ADM);
  R.setUser({ user: 'RASHEED', role_id: id('Abc DBA') }, ADM);
  R.setUser({ user: 'viewer.v', role_id: id('a-b team') }, ADM);
  R.setUser({ user: 'omar', role_id: id('zeta') }, ADM);
  R.setUser({ user: 'ali', role_id: 'infra-manager' }, ADM);
  R.setUser({ user: 'lina', role_id: 'ciso' }, ADM);
  R.setUser({ user: 'ghost', role_id: id('_under') }, ADM);
  await same('custom roles and assignments');
  // a role deleted under an assignment (stored data, not possible through the routes) and an approver demoted to viewer
  e.app.store.collection('job_roles').remove(id('_under'));
  R.save({ id: id('zeta'), base: 'viewer', approves: [], functions: {} }, ADM);
  R.setUser({ user: 'lina', role_id: null }, ADM);
  await same('after changes');
  // the routes go through Python when it is there
  const RP = createRoles(e.app, { python: PY });
  assert.deepEqual(plain(await RP.listAuto()), plain(R.list()), 'listAuto');
  assert.deepEqual(plain(await RP.meAuto('Siva')), plain(R.me('Siva')), 'meAuto');
});
