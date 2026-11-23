// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// User Inventory (engine/people-inventory.js) with SYNTHETIC people and devices: a directory account linked to its devices by an
// exact name (DOMAIN\user, display name), never a similar one; a server's service owner is not a user; Endpoint Central's
// signed-in user links a computer; a leaver who still holds a device, a stale account, a name with no directory account,
// remote-access and blocked software, an application unusual for the department (learned), unassigned end-user devices; the
// detail with how each device is linked and the applications, audited; roles (viewer refused) and validation; with no directory
// read the page says so and does not call anyone "not in the directory".
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');
const { norm } = require('../engine/people-inventory');

const NOW = Date.parse('2026-11-18T08:00:00Z'), OP = { user: 'nora.syn', role: 'operator' }, VIEW = { user: 'vera.syn', role: 'viewer' };
const office = { name: 'Microsoft Office Professional Plus 2021', publisher: 'Microsoft Corporation', version: '16.0' };
function seed(app, withDir) {
  const st = app.store, A = (o) => st.collection('assets').put(Object.assign({ status: 'in_use', software: [], last_seen: '2026-11-17T08:00:00Z' }, o));
  if (withDir) {
    const users = [
      { sam: 'jdoe.syn', upn: 'jdoe.syn@example.test', display_name: 'Jane Doe Syn', department: 'Finance', title: 'Accountant', enabled: true, last_logon: '2026-11-16T07:00:00Z' },
      { sam: 'asmith.syn', upn: 'asmith.syn@example.test', display_name: 'Ali Smith Syn', department: 'Finance', title: 'Analyst', enabled: false, last_logon: '2026-08-01T07:00:00Z' },
      { sam: 'mk.syn', upn: 'mk.syn@example.test', display_name: 'Mona K Syn', department: 'IT', title: 'Engineer', enabled: true, last_logon: '2026-04-01T07:00:00Z' },
      { sam: 'mohammed.a.syn', display_name: 'Mohammed A Syn', department: 'IT', enabled: true }, { sam: 'mohammed.b.syn', display_name: 'Mohammed B Syn', department: 'IT', enabled: true }];
    for (let i = 1; i <= 9; i++) users.push({ sam: 'fin' + i + '.syn', display_name: 'Finance Person ' + i + ' Syn', department: 'Finance', enabled: true, last_logon: '2026-11-15T07:00:00Z' });
    st.collection('ad_directory').put({ id: 'last', at: '2026-11-18T06:00:00Z', by: 'nora.syn', group: '', users });
  }
  A({ id: 'as_lap1', name: 'LAP-001', type: 'laptop', custodian: 'CORP-HQ\\jdoe.syn', software: [office, { name: 'AnyDesk', publisher: 'AnyDesk Software GmbH', version: '8' }, { name: 'SynCAD Pro', publisher: 'Synthetic Tools', version: '3.1' }, { name: 'Microsoft Visual C++ 2019 Redistributable', publisher: 'Microsoft' }] });
  A({ id: 'as_ws2', name: 'WS-002', type: 'workstation', owner: 'Ali Smith Syn', software: [office, { name: 'uTorrent', publisher: '' }] });
  A({ id: 'as_lap3', name: 'LAP-003', type: 'laptop', custodian: 'Ghost Person Syn', software: [office] });
  A({ id: 'as_srv', name: 'SRV-FIN', type: 'server', owner: 'Mohammed A Syn' });
  A({ id: 'as_lap4', name: 'LAP-004', type: 'laptop', custodian: 'Spare stock' });
  A({ id: 'as_ws5', name: 'WS-005', type: 'workstation' });
  A({ id: 'as_old', name: 'LAP-OLD', type: 'laptop', status: 'retired', custodian: 'jdoe.syn' });
  for (let i = 1; i <= 9; i++) A({ id: 'as_f' + i, name: 'FIN-' + i, type: 'laptop', custodian: 'fin' + i + '.syn@example.test', software: [office] });
  st.collection('me_ec_computers').put({ id: 'ec5', resource_id: 'ec5', name: 'WS-005', user: 'corp-hq\\mk.syn', asset_id: 'as_ws5', last_contact: NOW - 3600000 });
  st.collection('software_policy').put({ id: '|utorrent', status: 'blocked', reason: 'synthetic' });
}

test('norm: domain, UPN and joiner suffixes removed', () => {
  assert.equal(norm('CORP-HQ\\JDoe.Syn'), 'jdoe.syn'); assert.equal(norm('jdoe.syn@example.test'), 'jdoe.syn'); assert.equal(norm('Jane Doe Syn (joiner HR-12)'), 'jane doe syn');
});

test('people, devices and applications joined from the directory, the register and Endpoint Central', async (t) => {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true, now: () => NOW, python: process.env.PYTHON || 'python3' });
  seed(e.app, true);
  assert.equal((await e.req('GET', '/people-inventory', VIEW)).status, 403, 'a viewer is refused (personal data)');
  const r = await e.req('GET', '/people-inventory', OP); assert.equal(r.status, 200, r.text); const v = r.json;
  const P = (n) => v.people.find((p) => p.name === n);
  assert.equal(v.sources.directory.users, 14); assert.equal(v.sources.endpoint_central.with_user, 1);
  const jane = P('Jane Doe Syn'); assert.equal(jane.devices, 1, 'DOMAIN\\user matched; the retired laptop is not counted'); assert.equal(jane.sam, 'jdoe.syn');
  assert.ok(jane.flags.some((f) => f.k === 'risky' && /AnyDesk/.test(f.why)), JSON.stringify(jane.flags));
  assert.ok(jane.flags.some((f) => f.k === 'unusual' && /SynCAD Pro/.test(f.why) && /Finance/.test(f.why)), 'SynCAD on 1 of 11 Finance people is unusual');
  assert.ok(!jane.flags.some((f) => f.k === 'unusual' && /Office/.test(f.why)), 'Office is usual in Finance');
  const ali = P('Ali Smith Syn'); assert.equal(ali.devices, 1, 'linked by display name (owner of an end-user device)');
  assert.equal(ali.flags[0].k === 'leaver' || ali.flags.some((f) => f.k === 'leaver'), true); assert.ok(ali.flags.some((f) => f.k === 'blocked' && /uTorrent/.test(f.why)));
  assert.equal(v.people[0].name, 'Ali Smith Syn', 'a leaver holding a device comes first');
  const mona = P('Mona K Syn'); assert.equal(mona.devices, 1, 'linked by the Endpoint Central signed-in user'); assert.ok(mona.flags.some((f) => f.k === 'stale'));
  const ghost = P('Ghost Person Syn'); assert.ok(ghost && !ghost.in_directory && ghost.flags.some((f) => f.k === 'nodir'));
  assert.equal(P('Mohammed A Syn').devices, 0, 'a server\'s service owner is not a device user');
  assert.equal(P('Mohammed B Syn').devices, 0, 'no similar-name linking');
  assert.ok(!v.people.some((p) => /spare/i.test(p.name)), '"Spare stock" is not a person');
  assert.deepEqual(v.unassigned.map((a) => a.name), ['LAP-004'], 'the spare laptop has no person');
  assert.equal(v.kpis.leavers, 1); assert.equal(v.kpis.unassigned, 1); assert.equal(v.kpis.not_in_directory, 1);
  // detail
  assert.equal((await e.req('GET', '/people-inventory/bad%20key!', OP)).status, 400);
  assert.equal((await e.req('GET', '/people-inventory/p_0000000000000000', OP)).status, 404);
  assert.equal((await e.req('GET', '/people-inventory/' + jane.key, VIEW)).status, 403);
  const d = (await e.req('GET', '/people-inventory/' + jane.key, OP)).json;
  assert.deepEqual(d.devices.map((x) => [x.name, x.linked_by.join()]), [['LAP-001', 'custodian']]);
  assert.equal(d.apps[0].name, 'AnyDesk', 'risky first'); assert.ok(!d.apps.some((a) => /Redistributable/.test(a.name)), 'runtimes left out');
  assert.equal(d.apps.find((a) => a.name === 'SynCAD Pro').unusual, 9, '1 of 11 Finance people reporting software');
  const m = (await e.req('GET', '/people-inventory/' + mona.key, OP)).json; assert.deepEqual(m.devices[0].linked_by, ['signed in (Endpoint Central)']); assert.ok(m.devices[0].ec);
  assert.ok(e.app.store.auditTail(50).some((a) => a.action === 'people.view' && a.by === 'nora.syn' && a.target === jane.key), 'a person\'s detail read is audited');
});

test('no directory read: people from the names on devices, and the page says so', async (t) => {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true, now: () => NOW, python: process.env.PYTHON || 'python3' });
  seed(e.app, false);
  const v = (await e.req('GET', '/people-inventory', OP)).json;
  assert.equal(v.sources.directory, null); assert.match(v.note, /has not been read yet/);
  assert.ok(v.people.some((p) => p.name === 'jdoe.syn' && p.devices === 1));
  assert.ok(!v.people.some((p) => p.flags.some((f) => f.k === 'nodir')), 'nobody is "not in the directory" when it was not read');
});

test('Microsoft 365 per user: licences, apps used, services; leaver and unused flags; roles, audit, concealed names', async (t) => {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  let connected = false, concealed = false;
  const recent = '2026-11-15', old = '2026-08-01';
  const fake = { connected: () => connected, userApps: async () => ({
    skus: [{ sku_id: 'aaaaaaaa-0000-0000-0000-000000000001', part: 'SPE_E3' }],
    users: [{ userPrincipalName: 'JDoe.Syn@example.test', displayName: 'Jane Doe Syn', accountEnabled: true, assignedLicenses: [{ skuId: 'aaaaaaaa-0000-0000-0000-000000000001' }] },
      { userPrincipalName: 'asmith.syn@example.test', displayName: 'Ali Smith Syn', accountEnabled: true, assignedLicenses: [{ skuId: 'aaaaaaaa-0000-0000-0000-000000000001' }] },
      { userPrincipalName: 'fin1.syn@example.test', displayName: 'Finance Person 1 Syn', accountEnabled: true, assignedLicenses: [{ skuId: 'aaaaaaaa-0000-0000-0000-000000000001' }] },
      { userPrincipalName: 'shared.mailbox.syn@example.test', displayName: 'Shared Syn', accountEnabled: true, assignedLicenses: [] }],
    apps: [{ userPrincipalName: concealed ? 'A1B2C3' : 'jdoe.syn@example.test', lastActivityDate: recent, details: [{ reportPeriod: 30, outlook: true, teams: true, word: false, excel: true, windows: true, web: true }] }],
    act: [{ userPrincipalName: concealed ? 'D4E5F6' : 'jdoe.syn@example.test', assignedProducts: ['MICROSOFT 365 E3'], exchangeLastActivityDate: recent, teamsLastActivityDate: recent, oneDriveLastActivityDate: null },
      { userPrincipalName: concealed ? 'G7H8' : 'fin1.syn@example.test', assignedProducts: ['MICROSOFT 365 E3'], exchangeLastActivityDate: old }],
    errors: [] }) };
  registerDuty(e.app.srv, e.app, { noTimer: true, now: () => NOW, python: process.env.PYTHON || 'python3', peopleM365: fake });
  seed(e.app, true);
  let r = await e.req('POST', '/people-inventory/m365/read', Object.assign({ body: {} }, OP)); assert.equal(r.status, 409, 'not connected: says what to set'); assert.match(r.json.error, /HR Onboarding -> Microsoft 365/);
  connected = true;
  assert.equal((await e.req('POST', '/people-inventory/m365/read', Object.assign({ body: {} }, VIEW))).status, 403, 'a viewer cannot read');
  assert.equal((await e.req('POST', '/people-inventory/m365/read', Object.assign({ body: {} }, { user: 'ai:bot', role: 'operator' }))).status, 403, 'a person reads, not an AI identity');
  r = await e.req('POST', '/people-inventory/m365/read', Object.assign({ body: {} }, OP)); assert.equal(r.status, 200, r.text); assert.equal(r.json.users, 4); assert.equal(r.json.concealed, false);
  assert.ok(e.app.store.auditTail(50).some((a) => a.action === 'people.m365.read' && a.by === 'nora.syn'), 'audited');
  const v = (await e.req('GET', '/people-inventory', OP)).json, P = (n) => v.people.find((p) => p.name === n);
  assert.equal(v.sources.m365.matched, 3, 'the shared mailbox matches no person'); assert.equal(v.sources.m365_connected, true);
  const jane = P('Jane Doe Syn'); assert.deepEqual(jane.m365.used, ['outlook', 'excel', 'teams']); assert.equal(jane.m365.licences, 1);
  assert.ok(P('Ali Smith Syn').flags.some((f) => f.k === 'm365_leaver' && /SPE_E3/.test(f.why)), 'a disabled AD account with a licence');
  assert.ok(P('Finance Person 1 Syn').flags.some((f) => f.k === 'm365_unused' && /MICROSOFT 365 E3/.test(f.why)), 'licensed, no activity in 30 days');
  assert.ok(!jane.flags.some((f) => /m365/.test(f.k)), 'an active user is not flagged');
  const d = (await e.req('GET', '/people-inventory/' + jane.key, OP)).json;
  assert.deepEqual(d.m365.licences, ['MICROSOFT 365 E3']); assert.equal(d.m365.apps.outlook, true); assert.equal(d.m365.apps.word, false); assert.equal(d.m365.services.exchange, recent); assert.equal(d.m365.platforms.windows, true);
  concealed = true; r = await e.req('POST', '/people-inventory/m365/read', Object.assign({ body: {} }, OP)); assert.equal(r.json.concealed, true, 'concealed report names detected');
  const v2 = (await e.req('GET', '/people-inventory', OP)).json; assert.equal(v2.sources.m365.concealed, true);
  assert.equal(v2.people.find((p) => p.name === 'Jane Doe Syn').m365.used, null, 'no usage joined when the names are concealed - never guessed');
});

test('Microsoft 365 reads through Graph: GET only, paging, beta JSON reports, a missing permission named', async (t) => {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  const calls = [];
  const request = async (url, o) => { calls.push([o.method, url]);
    const j = (status, json) => ({ status, json });
    if (/oauth2\/v2\.0\/token/.test(url)) return j(200, { access_token: 'tok-synthetic' });
    if (/\/v1\.0\/subscribedSkus/.test(url)) return j(200, { value: [{ skuId: 's1', skuPartNumber: 'SPE_E3', prepaidUnits: { enabled: 10 }, consumedUnits: 2, servicePlans: [] }] });
    if (/skiptoken=2/.test(url)) return j(200, { value: [{ userPrincipalName: 'b@x.test' }], '@odata.nextLink': 'https://evil.example/steal' });
    if (/\/v1\.0\/users\?/.test(url)) return j(200, { value: [{ userPrincipalName: 'a@x.test' }], '@odata.nextLink': 'https://graph.microsoft.com/v1.0/users?$skiptoken=2' });
    if (/\/beta\/reports\//.test(url)) return j(403, { error: { code: 'Authorization_RequestDenied', message: 'Insufficient privileges' } });
    return j(404, {}); };
  const L = require('../engine/m365-licensing').createM365Licensing(e.app, { now: () => NOW, request, sealer: { unseal: () => 'secret-synthetic', seal: (x) => x } });
  e.app.store.collection('onboarding_m365').put({ id: 'cfg', tenant_id: '00000000-0000-0000-0000-000000000001', client_id: '00000000-0000-0000-0000-000000000002', secret_enc: 'sealed' });
  assert.equal(L.connected(), true);
  const r = await L.userApps();
  assert.deepEqual(r.users.map((u) => u.userPrincipalName), ['a@x.test', 'b@x.test'], 'paged, and a nextLink off Graph is not followed');
  assert.ok(!calls.some(([, u]) => /evil\.example/.test(u)));
  assert.ok(calls.filter(([, u]) => !/oauth2/.test(u)).every(([m]) => m === 'GET'), 'Graph is only read');
  assert.equal(r.apps, null); assert.ok(r.errors.some((x) => /Reports\.Read\.All/.test(x)), 'the missing permission is named: ' + r.errors.join(' | '));
  assert.equal(r.skus[0].part, 'SPE_E3');
});
