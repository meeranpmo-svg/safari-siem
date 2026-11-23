// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Leaver access to business applications (engine/offboarding.js + engine/m365-licensing.js) against a fake Active Directory
// (LDAPS) and a fake Microsoft Graph: the application register (admin only, validated - an Entra application checked to exist,
// no privileged group, departments named); at the disable each application is handled by its method - the leaver's Entra ID
// assignments removed and read back, the leaver taken out of the application's AD groups (other groups untouched), a manual
// application given to its owner with a due date, a department-only application left out, no access recorded, the sign-in
// sessions ended once; the owner (or an admin, never the leaver) confirms with a reference; overdue counted; decide after with
// four eyes and kept applications; a failure retried; automatic removal falls back to the owner when its connection is off.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs'), os = require('os'), path = require('path'), http = require('http');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');
const { makeCA, makeServerCert } = require('./helpers/x509');
const { startFakeLdap, makeDirectory } = require('./helpers/fake-ldap');

const BASE = 'DC=corp-hq,DC=com', STAFF = 'OU=Staff,' + BASE, GR = 'OU=Groups,' + BASE, SVC = 'CN=svc-onboarding-syn,OU=Service,' + BASE, BIND_PW = 'Synthetic-Bind-Pass-9';
const PERSON = 'CN=Person,CN=Schema,CN=Configuration,' + BASE, KH = 'CN=Khalid Al-Harbi,' + STAFF;
const HR = { user: 'hana.syn', role: 'operator' }, MGR = { user: 'faisal.syn', role: 'operator' }, DESK = { user: 'desk.syn', role: 'operator' };
const ADM = { user: 'syed', role: 'admin' }, REQ_ADMIN = { user: 'hana.syn', role: 'admin' }, VIEW = { user: 'vera.syn', role: 'viewer' }, OWNER = { user: 'olaf.syn', role: 'operator' };
const LEAVER = { name: 'Khalid Al-Harbi', employee_id: 'E-20001', username: 'khalid.harbi', department: 'Claims', last_day: '2026-10-30', manager: 'faisal.syn', reason: 'termination', immediate: true };
const TENANT = '11111111-2222-3333-4444-555555555555', APPID = '66666666-7777-8888-9999-000000000000';
const SP1 = '0000aaaa-0000-4000-8000-000000000001', SP2 = '0000aaaa-0000-4000-8000-000000000002', NOSP = '0000aaaa-0000-4000-8000-0000000000ff', UID = '0000bbbb-0000-4000-8000-000000000001';
const DAY = 86400000;

function fakeGraph() {
  const st = { calls: [], failDelete: 0, assignments: [{ id: 'asg-aaaaaaaa-1', resourceId: SP1, appRoleId: 'r1', resourceDisplayName: 'Claims Portal' }, { id: 'asg-aaaaaaaa-2', resourceId: SP1, appRoleId: 'r2', resourceDisplayName: 'Claims Portal' }, { id: 'asg-aaaaaaaa-9', resourceId: 'other', appRoleId: 'r9' }], revoked: 0 };
  const srv = http.createServer((req, res) => { let b = ''; req.on('data', (c) => { b += c; }); req.on('end', () => {
    const u = new URL(req.url, 'http://x'), J = (c, o) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(o === undefined ? '' : JSON.stringify(o)); };
    if (/oauth2\/v2\.0\/token$/.test(u.pathname)) return J(200, { access_token: 'tok' });
    const P = u.pathname.replace('/v1.0', ''); st.calls.push(req.method + ' ' + P); let m;
    if ((m = /^\/servicePrincipals\/(.+)$/.exec(P))) return [SP1, SP2].includes(m[1]) ? J(200, { id: m[1], displayName: m[1] === SP1 ? 'Claims Portal' : 'Broker Hub', appId: 'app' }) : J(404, { error: { code: 'NotFound', message: 'x' } });
    if (/^\/users\/[^/]+$/.test(P)) return J(200, { id: UID });
    if (P === '/users/' + UID + '/appRoleAssignments' && req.method === 'GET') return J(200, { value: st.assignments });
    if ((m = /^\/users\/[^/]+\/appRoleAssignments\/(.+)$/.exec(P)) && req.method === 'DELETE') { if (st.failDelete > 0) { st.failDelete--; return J(503, { error: { code: 'ServiceUnavailable', message: 'try later' } }); } st.assignments = st.assignments.filter((a) => a.id !== decodeURIComponent(m[1])); return J(204); }
    if (P === '/users/' + UID + '/revokeSignInSessions') { st.revoked++; return J(200, { value: true }); }
    J(404, { error: { code: 'x', message: P } });
  }); });
  return { st, srv };
}

async function setup(t, o = {}) {
  const clock = { t: Date.parse('2026-10-28T08:00:00Z') };
  const ca = makeCA('Synthetic AD CA apps'), leaf = makeServerCert(ca, { cn: ('dc01.' + 'corp-hq.com'), dns: [('dc01.' + 'corp-hq.com')], ip: ['127.0.0.1'] });
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'apps-ad-')); t.after(() => fs.rmSync(tmp, { recursive: true, force: true }));
  const caFile = path.join(tmp, 'ad-root.pem'); fs.writeFileSync(caFile, ca.cert);
  const dir = makeDirectory();
  for (const ou of [BASE, 'OU=Service,' + BASE, STAFF, GR, 'OU=Joiners,' + BASE]) dir.add(ou, { objectClass: [ou === BASE ? 'domain' : 'organizationalUnit'] });
  dir.add(SVC, { objectClass: ['user'], objectCategory: PERSON, sAMAccountName: 'svc-onboarding-syn' });
  dir.add(KH, { objectClass: ['top', 'person', 'organizationalPerson', 'user'], objectCategory: PERSON, sAMAccountName: 'khalid.harbi', displayName: 'Khalid Al-Harbi', userAccountControl: '512', employeeID: 'E-20001' });
  for (const g of ['GG-CoreIns-Users', 'GG-CoreIns-Approvers', 'GG-Claims-Users']) { dir.add('CN=' + g + ',' + GR, { objectClass: ['group'], sAMAccountName: g }); dir.addMember('CN=' + g + ',' + GR, KH); }
  const ldap = await startFakeLdap({ key: leaf.key, cert: leaf.cert, dir, passwords: { [SVC]: BIND_PW } }); t.after(() => ldap.close());
  const G = fakeGraph(); await new Promise((r) => G.srv.listen(0, '127.0.0.1', r)); t.after(() => G.srv.close());
  const gb = 'http://127.0.0.1:' + G.srv.address().port;
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true, now: () => clock.t, python: process.env.PYTHON || 'python3', graphLogin: gb, graphBase: gb + '/v1.0' });
  const call = (m, p, b, who) => e.req(m, p, Object.assign(b !== undefined ? { body: b } : {}, who));
  const post = (p, b, who) => call('POST', p, b, who), get = (p, who = DESK) => call('GET', p, undefined, who);
  let r = await post('/onboarding/ad', { servers: ['ldaps://127.0.0.1:' + ldap.port], ca_file: caFile, bind_dn: SVC, bind_password: BIND_PW, base_dn: BASE, ou: 'OU=Joiners,' + BASE, upn_suffix: 'corp-hq.com', leavers_enabled: true, disable_hour: 18 }, ADM);
  assert.equal(r.status, 200, JSON.stringify(r.json));
  if (o.graph !== false) { r = await post('/onboarding/m365', { tenant_id: TENANT, client_id: APPID, client_secret: 'Synthetic-Graph-Secret-1', apps_enabled: true }, ADM); assert.equal(r.status, 200, JSON.stringify(r.json)); }
  async function register() {
    const add = async (b) => { const x = await post('/offboarding/apps', b, ADM); assert.equal(x.status, 200, JSON.stringify(x.json)); return x.json.id; };
    return { claims: o.graph !== false ? await add({ name: 'Claims Portal', owner: 'olaf.syn', method: 'entra', sp_id: SP1 }) : await add({ name: 'Claims Portal', owner: 'olaf.syn', method: 'entra', sp_id: SP1 }),
      core: await add({ name: 'Core Insurance', owner: 'olaf.syn', method: 'ad_group', groups: ['GG-CoreIns-Users', 'GG-CoreIns-Approvers'] }),
      oracle: await add({ name: 'Oracle Finance', owner: 'olaf.syn', method: 'manual', applies: 'all', sla_days: 3 }),
      treasury: await add({ name: 'Treasury', owner: 'olaf.syn', method: 'manual', applies: 'departments', departments: ['Finance'] }),
      broker: o.graph !== false ? await add({ name: 'Broker Hub', owner: 'olaf.syn', method: 'entra', sp_id: SP2 }) : null };
  }
  async function leaver(approve = { decision: 'approve' }) {
    let x = await post('/offboarding', LEAVER, HR); assert.equal(x.status, 200, JSON.stringify(x.json)); const id = x.json.id;
    await post('/offboarding/' + id + '/confirm', { decision: 'confirm' }, MGR);
    x = await post('/offboarding/' + id + '/approve', approve, ADM); assert.equal(x.status, 200, JSON.stringify(x.json));
    return { id, v: (await get('/offboarding/' + id)).json };
  }
  const memberOf = () => ['GG-CoreIns-Users', 'GG-CoreIns-Approvers', 'GG-Claims-Users'].filter((g) => dir.vals(dir.get('CN=' + g + ',' + GR), 'member').includes(KH));
  return { e, G, dir, clock, post, get, register, leaver, memberOf };
}
const auditOf = (e, action) => e.app.store.auditTail(500).filter((x) => x.action === action);

test('the register: administrators only, validated, checked against Entra ID, retired with a reason', async (t) => {
  const { e, post, get } = await setup(t);
  assert.equal((await get('/offboarding/apps', VIEW)).status, 403);
  assert.equal((await post('/offboarding/apps', { name: 'X App', owner: 'olaf.syn', method: 'manual' }, DESK)).status, 403);
  const P = (b) => post('/offboarding/apps', b, ADM);
  let r = await P({ name: 'Claims Portal', owner: 'olaf.syn', method: 'entra' }); assert.equal(r.status, 400); assert.match(r.json.error, /sp_id is required/);
  r = await P({ name: 'Claims Portal', owner: 'olaf.syn', method: 'entra', sp_id: NOSP }); assert.equal(r.status, 400); assert.match(r.json.error, /no enterprise application/);
  r = await P({ name: 'Core', owner: 'olaf.syn', method: 'ad_group' }); assert.match(r.json.error, /groups: name the AD groups/);
  r = await P({ name: 'Core', owner: 'olaf.syn', method: 'ad_group', groups: ['Domain Admins'] }); assert.match(r.json.error, /not a group name the platform may change/);
  r = await P({ name: 'Treasury', owner: 'olaf.syn', method: 'manual', applies: 'departments' }); assert.match(r.json.error, /departments: name at least one/);
  r = await P({ name: '<script>', owner: 'olaf.syn', method: 'manual' }); assert.match(r.json.error, /^name must be/);
  r = await P({ name: 'Claims Portal', owner: 'olaf.syn', method: 'entra', sp_id: SP1 }); assert.equal(r.status, 200); assert.equal(r.json.id, 'APP-001'); assert.equal(r.json.sp_name, 'Claims Portal');
  assert.equal((await P({ name: 'claims portal', owner: 'x.syn', method: 'manual' })).status, 409, 'no duplicate');
  r = await post('/offboarding/apps/retire', { id: 'APP-001' }, ADM); assert.equal(r.status, 400);
  r = await post('/offboarding/apps/retire', { id: 'APP-001', reason: 'replaced by the new portal' }, ADM); assert.equal(r.json.active, false);
  assert.equal((await get('/offboarding/apps', DESK)).json.apps.length, 1);
  assert.equal(auditOf(e, 'offboarding.apps.added').length, 1); assert.equal(auditOf(e, 'offboarding.apps.retired').length, 1);
});

test('at the disable: Entra assignments and AD groups removed and read back, the owner task, sessions ended, owner confirms', async (t) => {
  const { e, G, clock, post, get, register, leaver, memberOf } = await setup(t);
  const A = await register();
  const { id, v } = await leaver();
  const st = Object.fromEntries(v.apps.items.map((i) => [i.name, i]));
  assert.equal(v.apps.decided_with, 'disable approval');
  assert.equal(st['Claims Portal'].state, 'removed'); assert.match(st['Claims Portal'].detail, /2 assignment/);
  assert.deepEqual(G.st.assignments.map((a) => a.id), ['asg-aaaaaaaa-9'], 'only that application\'s assignments');
  assert.equal(st['Core Insurance'].state, 'removed'); assert.deepEqual(memberOf(), ['GG-Claims-Users'], 'the application\'s groups only');
  assert.equal(st['Oracle Finance'].state, 'owner_task'); assert.equal(Date.parse(st['Oracle Finance'].due_at) - clock.t, 3 * DAY);
  assert.equal(st.Treasury.state, 'not_applicable'); assert.equal(st['Broker Hub'].state, 'no_access');
  assert.equal(G.st.revoked, 1, 'sign-in sessions ended once');
  assert.ok(!v.steps.find((s) => s.key === 'apps').done, 'waits for the owner');
  clock.t += 4 * DAY; let L = (await get('/offboarding')).json; assert.equal(L.counts.apps_overdue, 1); assert.equal(L.counts.apps_owner_tasks, 1);
  const C = (b, who) => post('/offboarding/' + id + '/apps/confirm', b, who);
  let r = await C({ app_id: A.oracle, outcome: 'removed', reference: 'user end-dated in Oracle, CHG-9700' }, DESK); assert.equal(r.status, 403); assert.match(r.json.error, /owner of Oracle Finance/);
  r = await C({ app_id: A.oracle, outcome: 'removed', reference: 'x' }, OWNER); assert.equal(r.status, 400);
  r = await C({ app_id: A.oracle, outcome: 'deleted', reference: 'user end-dated in Oracle' }, OWNER); assert.match(r.json.error, /^outcome must be one of/);
  r = await C({ app_id: A.oracle, outcome: 'removed', reference: 'user end-dated in Oracle, CHG-9700' }, OWNER); assert.equal(r.status, 200, JSON.stringify(r.json));
  const o2 = r.json.apps.items.find((i) => i.app_id === A.oracle); assert.equal(o2.state, 'confirmed'); assert.equal(o2.late, true);
  assert.equal(r.json.apps.status, 'done'); assert.ok(r.json.steps.find((s) => s.key === 'apps').done);
  assert.equal(auditOf(e, 'offboarding.apps.removed').length, 2); assert.equal(auditOf(e, 'offboarding.apps.sessions_revoked').length, 1); assert.equal(auditOf(e, 'offboarding.apps.confirmed')[0].detail.late, true);
  r = await post('/offboarding/' + id + '/approve', { decision: 'approve', apps: 'later' }, ADM); assert.equal(r.status, 400); assert.match(r.json.error, /^apps must be one of/);
});

test('decide after: four eyes, an application kept with a reason; a failure retried; no Graph = the owner does it', async (t) => {
  const { e, G, clock, post, get, register, leaver, memberOf } = await setup(t);
  const A = await register();
  G.st.failDelete = 1;
  const { id, v } = await leaver({ decision: 'approve', apps: 'ask' });
  assert.equal(v.apps.status, 'proposed'); assert.deepEqual(memberOf().length, 3, 'nothing removed before the decision');
  const D = (b, who) => post('/offboarding/' + id + '/apps/decide', b, who);
  assert.equal((await D({ decision: 'approve' }, DESK)).status, 403);
  let r = await D({ decision: 'approve' }, REQ_ADMIN); assert.equal(r.status, 403); assert.match(r.json.error, /four eyes/);
  r = await D({ decision: 'approve', keep: [{ app_id: A.core }] }, ADM); assert.equal(r.status, 400); assert.match(r.json.error, /reason is required/);
  r = await D({ decision: 'approve', keep: [{ app_id: 'APP-999', reason: 'not ours' }] }, ADM); assert.match(r.json.error, /not waiting for a decision/);
  r = await D({ decision: 'approve', keep: [{ app_id: A.core, reason: 'kept for the hand-over week with read-only role' }] }, ADM); assert.equal(r.status, 200, JSON.stringify(r.json));
  let it = Object.fromEntries(r.json.apps.items.map((i) => [i.name, i]));
  assert.equal(it['Core Insurance'].state, 'kept'); assert.equal(memberOf().length, 3, 'kept application untouched');
  assert.equal(it['Claims Portal'].state, 'error'); assert.match(it['Claims Portal'].error, /try later/);
  assert.equal((await get('/offboarding')).json.counts.apps_failed, 1);
  clock.t += 3601000; await e.app.addons.offboarding.runDue(null);
  it = Object.fromEntries((await get('/offboarding/' + id)).json.apps.items.map((i) => [i.name, i]));
  assert.equal(it['Claims Portal'].state, 'removed', 'retried by the job');
  assert.equal(auditOf(e, 'offboarding.apps.approved')[0].detail.kept[0].reason, 'kept for the hand-over week with read-only role');
});

test('no Graph connection: an Entra application goes to its owner instead', async (t) => {
  const { post, register, leaver } = await setup(t, { graph: false });
  await register();
  const { v } = await leaver();
  const it = Object.fromEntries(v.apps.items.map((i) => [i.name, i]));
  assert.equal(it['Claims Portal'].state, 'owner_task'); assert.match(it['Claims Portal'].note, /automatic removal is off/);
  assert.equal(it['Core Insurance'].state, 'removed');
  assert.ok(post);
});
