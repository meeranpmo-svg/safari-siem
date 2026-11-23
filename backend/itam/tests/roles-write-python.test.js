// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Migration step 9b (docs/PYTHON-MIGRATION.md): the Roles WRITES (save, delete, assign) decided by pyengine/roles_write.py
// and committed by engine/roles.js must do exactly what the Node.js functions do - the same records, the same audit
// entries, the same refusals word for word with the same status - over every rule: duplicate names, viewer cannot manage
// or approve, unknown scopes and levels, bad base, missing role, built-in and assigned roles cannot be deleted, nobody
// gives themselves a non-admin role or removes their own, invalid user names, names with control characters / BOM /
// emoji. Two engines run the same sequence on separate data; Python must have decided every write (none redone in
// Node.js). And a change made while Python decides makes Node.js decide again - nothing is written over.
const test = require('node:test');
const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const { startApp } = require('./helpers');
const { createRoles } = require('../engine/roles');

const PY = process.env.PYTHON || 'python3';
const hasPy = spawnSync(PY, ['--version']).status === 0;
const NOW = Date.parse('2026-10-19T09:00:00Z');
const SYED = { user: 'syed', role: 'admin', ip: '10.0.0.5' };
const strip = (e) => ({ by: e.by, role: e.role, ip: e.ip, action: e.action, target: e.target, detail: e.detail });

test('Python-decided Roles writes do exactly what Node.js does', { skip: !hasPy && 'python3 not available' }, async (t) => {
  const N = await startApp({ noAi: true }), P = await startApp({ noAi: true, config: { discovery: { python_bin: PY } } });
  t.after(async () => { await N.close(); await P.close(); });
  const ids = (p) => { let n = 0; return () => p + '-' + (++n); };
  const RN = createRoles(N.app, { noPython: true, now: () => NOW, newId: ids('role') }), RP = createRoles(P.app, { now: () => NOW, newId: ids('role') });
  assert.equal(RP.engine(), 'python');
  const run = async (R, kind, a, b) => { try { return { ok: await (kind === 'save' ? R.saveAuto(a, b) : kind === 'remove' ? R.removeAuto(a, b) : R.setUserAuto(a, b)) }; } catch (e) { return { err: e.message, status: e.status }; } };
  const steps = [
    ['save', { name: 'Network team', base: 'operator', approves: ['eng:network', 'eng:network'], functions: { network: 'manage', assets: 'view' }, description: '  routers \u0007 and switches  ' }],
    ['save', { name: 'network TEAM', base: 'operator' }],
    ['save', { name: 'Readers', base: 'viewer', functions: { soc: 'manage' } }],
    ['save', { name: 'Readers', base: 'viewer', approves: ['infra'] }],
    ['save', { name: 'Odd', base: 'operator', approves: ['root'] }],
    ['save', { name: 'Odd', base: 'operator', functions: { soc: 'write' } }],
    ['save', { name: 'Odd', base: 'superuser' }],
    ['save', { name: 'Odd', base: null }],
    ['save', { name: '   ' }],
    ['save', { id: 'nope', name: 'x' }],
    ['save', { name: '﻿ DBA\tteam \u0085' + '😀'.repeat(40), base: 'operator', approves: [null, 'infra'] }],
    ['save', { id: 'role-1', name: 'Network & Wireless', approves: ['eng:network', 'infra'] }],
    ['save', { id: 'soc-analyst', functions: { identity: 'manage' } }],
    ['save', { id: 'auditor', approves: ['security'] }],
    ['assign', { user: 'Siva', role_id: 'role-1' }, SYED],
    ['assign', { user: 'syed', role_id: 'role-1' }, SYED],
    ['assign', { user: 'SYED', role_id: 'system-admin' }, SYED],
    ['assign', { user: 'syed', role_id: null }, SYED],
    ['assign', { user: 'bad name!', role_id: 'role-1' }, SYED],
    ['assign', { user: 'rasheed', role_id: 'gone' }, SYED],
    ['assign', { user: 'rasheed', role_id: 'infra-manager' }, SYED],
    ['assign', { user: 'rasheed' }, SYED],
    ['assign', { user: 'never-assigned' }, SYED],
    ['remove', 'ciso'],
    ['remove', 'role-1'],
    ['remove', 'nope'],
    ['assign', { user: 'siva' }, SYED],
    ['remove', 'role-1'],
  ];
  for (const [kind, a, b] of steps) {
    const who = b || SYED;
    const x = await run(RN, kind, a, kind === 'remove' ? SYED : who), y = await run(RP, kind, a, kind === 'remove' ? SYED : who);
    assert.deepEqual(y, x, kind + ' ' + JSON.stringify(a));
  }
  for (const c of ['job_roles', 'role_assignments']) assert.deepEqual(P.app.store.collection(c).all(), N.app.store.collection(c).all(), c + ': the same records');
  const audits = (e) => e.app.store.auditTail(500, (r) => /^roles\./.test(r.action)).map(strip);
  assert.deepEqual(audits(P), audits(N), 'the same audit entries');
  const st = RP.writeStats();
  assert.equal(st.node, 0, 'no write was redone in Node.js: ' + JSON.stringify(st)); assert.equal(st.python, steps.length);
});

test('a change while Python decides: Node.js decides again, nothing is written over', { skip: !hasPy && 'python3 not available' }, async (t) => {
  const P = await startApp({ noAi: true, config: { discovery: { python_bin: PY } } });
  t.after(() => P.close());
  const R = createRoles(P.app, { now: () => NOW });
  const pending = R.saveAuto({ name: 'Racers', base: 'operator' }, SYED);
  R.setUser({ user: 'omar', role_id: 'auditor' }, SYED);   // another administrator, at the same moment
  const out = await pending;
  assert.ok(out.saved && out.saved.name === 'Racers');
  assert.ok(P.app.store.collection('role_assignments').get('omar'), 'the other change is still there');
  const st = R.writeStats(); assert.equal(st.changed_meanwhile, 1); assert.equal(st.node, 1, JSON.stringify(st));
});
