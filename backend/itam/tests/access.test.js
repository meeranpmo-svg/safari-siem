// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Engineer access on the server (engine/access-scopes.js, enforced by engine/roles.js through the http gate): a person whose
// job role is an engineer role may call only the routes of their functions plus their own work; anything else is refused
// with 403 before the route runs, and the refusal is audited (once per person and route group per 10 minutes). Admins,
// every other job role and people with no job role are unchanged. The list is the same file as the SIEM's.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { startApp } = require('./helpers');
const AC = require('../engine/access-scopes');

test('the same allow-list file is in the SIEM (approvers/access.js)', (t) => {
  const siem = path.join(__dirname, '..', '..', 'siem', 'engine', 'approvers', 'access.js');
  if (!fs.existsSync(siem)) return t.skip('sentra-siem checkout not next to shield');
  assert.equal(fs.readFileSync(path.join(__dirname, '..', 'engine', 'access-scopes.js'), 'utf8'), fs.readFileSync(siem, 'utf8'), 'edit engine/access-scopes.js and copy it to sentra-siem engine/approvers/access.js');
});

test('who is restricted, and what a restricted person may call', () => {
  const role = (functions) => ({ functions });
  assert.deepEqual(AC.restrictedFns(role({ windows: 'manage', dashboards: 'none' }), 'operator'), ['windows']);
  assert.deepEqual(AC.restrictedFns(role({ virtualization: 'manage', backup: 'view' }), 'operator'), ['backup', 'virtualization'], 'two engineer slices: both');
  assert.equal(AC.restrictedFns(role({ windows: 'manage' }), 'admin'), null, 'a gateway administrator is never restricted');
  assert.equal(AC.restrictedFns(role({ windows: 'manage', dashboards: 'view' }), 'operator'), null, '"All platform dashboards" on: not restricted');
  assert.equal(AC.restrictedFns(role({ windows: 'manage', servers: 'view' }), 'operator'), null, 'a role with a non-engineer function is not an engineer role');
  assert.equal(AC.restrictedFns(role({}), 'operator'), null); assert.equal(AC.restrictedFns(null, 'operator'), null, 'no job role: unchanged');
  assert.equal(AC.allows('itam', ['windows'], '/servers'), true);
  assert.equal(AC.allows('itam', ['windows'], '/servers/abc/detail'), true, 'below a prefix');
  assert.equal(AC.allows('itam', ['windows'], '/serversX'), false, 'a prefix matches whole segments only');
  assert.equal(AC.allows('itam', ['windows'], '/assets'), false);
  assert.equal(AC.allows('itam', ['windows'], '/servers/../assets'), false, 'no dot segments');
  assert.equal(AC.allows('itam', ['windows'], '/duty/items'), true, 'their own work queue');
  assert.equal(AC.allows('soc', ['windows'], '/sysadmin/targets'), true);
  assert.equal(AC.allows('soc', ['windows'], '/search'), false, 'never the SIEM log search');
  assert.equal(AC.allows('soc', ['network'], '/approvals'), false, 'never the SOC approvals');
  assert.equal(AC.allows('soc', ['network'], '/netops/overview'), true);
  assert.equal(AC.allows('soc', ['virtualization'], '/netops/overview'), false, 'virtualization: server availability only');
  assert.equal(AC.allows('soc', ['virtualization'], '/netops/avail/hosts'), true);
  for (const fn of AC.ENGINEER_FNS) assert.ok(AC.ALLOW[fn] && AC.ALLOW[fn].itam && AC.ALLOW[fn].soc, fn + ' has a list for both servers');
});

test('the ITAM server refuses an engineer outside their routes, audits it, and leaves everyone else unchanged', async () => {
  const t = await startApp({ noAi: true });
  try {
    const audits = []; const orig = t.app.audit; t.app.audit = (e) => { audits.push(e); return orig ? orig(e) : undefined; };
    const admin = t.as('syed.syn', 'admin');
    let r = await admin('POST', '/roles/assign', { body: { user: 'fahad.syn', role_id: 'windows-admin' } }); assert.equal(r.status, 200, r.text);
    r = await admin('POST', '/roles/assign', { body: { user: 'omar.syn', role_id: 'network-engineer' } }); assert.equal(r.status, 200, r.text);
    r = await admin('POST', '/roles/assign', { body: { user: 'ali.syn', role_id: 'server-admin' } }); assert.equal(r.status, 200, r.text);
    const fahad = t.as('fahad.syn', 'operator'), omar = t.as('omar.syn', 'operator'), ali = t.as('ali.syn', 'operator'), nobody = t.as('nobody.syn', 'operator');

    // the Windows admin: their own routes answer as before, the asset register is refused
    r = await fahad('GET', '/roles/me'); assert.equal(r.status, 200); assert.equal(r.json.role.id, 'windows-admin');
    r = await fahad('GET', '/servers?platform=windows'); assert.notEqual(r.status, 403, 'their own route is not refused: ' + r.text);
    r = await fahad('GET', '/assets'); assert.equal(r.status, 403); assert.match(r.json.error, /not part of your job role/);
    r = await fahad('GET', '/assets/x/../../servers'); assert.notEqual(r.json && r.json.error, undefined, 'a dot path never slips through');
    r = await fahad('POST', '/roles', { body: { name: 'Mine (synthetic)', base: 'operator' } }); assert.equal(r.status, 403, 'refused before the route (and before the body is read)');
    // the refusal is audited with who, role, IP and what; a second refusal of the same group within 10 minutes is not
    const refused = audits.filter((a) => a.action === 'access.refused');
    assert.ok(refused.some((a) => a.by === 'fahad.syn' && a.role === 'operator' && /\/api\/itam\/assets$/.test(a.target) && a.detail.functions[0] === 'windows'), JSON.stringify(refused));
    const n = refused.length; await fahad('GET', '/assets'); assert.equal(audits.filter((a) => a.action === 'access.refused').length, n, 'not audited again within 10 minutes');

    // the network engineer: assets yes (wireless page), servers no
    r = await omar('GET', '/assets'); assert.notEqual(r.status, 403, r.text);
    r = await omar('GET', '/roles'); assert.equal(r.status, 403, 'the Roles list is not a network route');
    r = await omar('GET', '/no-such-route'); assert.equal(r.status, 404, 'an unknown route stays 404 (the gate runs on routes that exist)');
    // everyone else is as before: a broad role, no job role, an administrator
    r = await ali('GET', '/assets'); assert.notEqual(r.status, 403, 'Server & Cloud Admin is not an engineer role');
    r = await nobody('GET', '/assets'); assert.notEqual(r.status, 403, 'no job role: unchanged');
    r = await admin('GET', '/assets'); assert.notEqual(r.status, 403);
    // un-assigning the engineer lifts the restriction at once (no cache to wait for)
    r = await admin('POST', '/roles/assign', { body: { user: 'fahad.syn', role_id: null } }); assert.equal(r.status, 200, r.text);
    r = await fahad('GET', '/assets'); assert.notEqual(r.status, 403);
  } finally { await t.close(); }
});

test('the list of restricted people is what the SIEM receives beside the approvers', () => {
  const { createRoles } = require('../engine/roles');
  const cols = {}; const store = { collection: (n) => cols[n] || (cols[n] = (() => { const m = new Map(); return { all: () => [...m.values()], get: (id) => m.get(id), put: (o) => { m.set(o.id, JSON.parse(JSON.stringify(o))); return o; }, remove: (id) => m.delete(id) }; })()) };
  const R = createRoles({ store, noPython: true }), adm = { user: 'syed', role: 'admin' };
  R.setUser({ user: 'Fahad.Syn', role_id: 'exchange-admin' }, adm); R.setUser({ user: 'ali.syn', role_id: 'server-admin' }, adm);
  assert.deepEqual(R.accessMap(), { 'fahad.syn': ['exchange'] }, 'only engineer roles, user names in lower case');
  assert.deepEqual(R.restrictionOf('FAHAD.SYN', 'operator'), ['exchange']); assert.equal(R.restrictionOf('fahad.syn', 'admin'), null);
});
