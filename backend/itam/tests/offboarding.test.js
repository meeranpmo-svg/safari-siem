// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const ZYB_ORG = require('../engine/brand');
// HR offboarding - leavers (engine/offboarding.js) through the real routes against an in-process fake LDAPS directory: the
// account read at request time; the manager confirms (never the requester), a DIFFERENT administrator approves the disable;
// the account is disabled on the last day at the configured hour (Riyadh) by the job, its password replaced, description set,
// moved to the leavers OU, verified, never deleted; "immediate" disables at approval; refused for a different employee
// number, a privileged account and the never-disable list; a refused write is recorded and retried; the leaver cannot act on
// their own request; equipment back to stock; re-enable needs a second administrator; roles, validation, audit. SYNTHETIC.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs'), os = require('os'), path = require('path');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');
const { makeCA, makeServerCert } = require('./helpers/x509');
const { startFakeLdap, makeDirectory } = require('./helpers/fake-ldap');

const BASE = 'DC=corp-hq,DC=com', STAFF = 'OU=Staff,' + BASE, LEAVERS = 'OU=Leavers,' + BASE, SVC = 'CN=svc-onboarding-syn,OU=Service,' + BASE, BIND_PW = 'Synthetic-Bind-Pass-9';
const PERSON = 'CN=Person,CN=Schema,CN=Configuration,' + BASE;
const HR = { user: 'hana.syn', role: 'operator' }, MGR = { user: 'faisal.syn', role: 'operator' }, DESK = { user: 'desk.syn', role: 'operator' };
const ADM = { user: 'syed', role: 'admin' }, ADM2 = { user: 'omar.syn', role: 'admin' }, VIEW = { user: 'vera.syn', role: 'viewer' }, BOT = { user: 'ai:desk', role: 'admin' };
const LEAVER = { name: 'Khalid Al-Harbi', employee_id: 'E-20001', username: 'khalid.harbi', department: 'Claims', last_day: '2026-10-30', manager: 'faisal.syn', reason: 'resignation' };
const NOW = Date.parse('2026-10-28T08:00:00Z');

async function setup(t, o = {}) {
  const clock = { t: NOW };
  const ca = makeCA('Synthetic AD CA leavers'), leaf = makeServerCert(ca, { cn: ('dc01.' + 'corp-hq.com'), dns: [('dc01.' + 'corp-hq.com')], ip: ['127.0.0.1'] });
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'off-ad-')); t.after(() => fs.rmSync(tmp, { recursive: true, force: true }));
  const caFile = path.join(tmp, 'ad-root.pem'); fs.writeFileSync(caFile, ca.cert);
  const dir = makeDirectory();
  for (const ou of [BASE, 'OU=Service,' + BASE, STAFF, LEAVERS, 'OU=Groups,' + BASE, 'OU=Joiners,' + BASE]) dir.add(ou, { objectClass: [ou === BASE ? 'domain' : 'organizationalUnit'] });
  dir.add(SVC, { objectClass: ['user'], objectCategory: PERSON, sAMAccountName: 'svc-onboarding-syn' });
  const u = (cn, sam, extra) => dir.add('CN=' + cn + ',' + STAFF, Object.assign({ objectClass: ['top', 'person', 'organizationalPerson', 'user'], objectCategory: PERSON, sAMAccountName: sam, displayName: cn, userAccountControl: '512', lastLogonTimestamp: '134060000000000000' }, extra));
  u('Khalid Al-Harbi', 'khalid.harbi', { employeeID: 'E-20001' });
  u('Other Person', 'other.person', { employeeID: 'E-99999' });
  u('Admin Person', 'admin.person', { employeeID: 'E-20003', adminCount: '1' });
  u('Break Glass', 'breakglass', {});
  dir.add('CN=GG-Claims-Users,OU=Groups,' + BASE, { objectClass: ['group'], sAMAccountName: 'GG-Claims-Users' });
  dir.addMember('CN=GG-Claims-Users,OU=Groups,' + BASE, 'CN=Khalid Al-Harbi,' + STAFF);
  const ldap = await startFakeLdap({ key: leaf.key, cert: leaf.cert, dir, passwords: { [SVC]: BIND_PW }, readOnly: o.readOnly ? [SVC] : [] });
  t.after(() => ldap.close());
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true, now: () => clock.t, python: process.env.PYTHON || 'python3' });
  const A = e.app.store.collection('assets');
  A.put({ id: 'ast_lap9', type: 'laptop', status: 'in_use', custodian: 'khalid.harbi', vendor: 'Dell', model: 'Latitude 5450', serial: 'SYN-LAP-009', lifecycle: [] });
  A.put({ id: 'ast_ph9', type: 'phone', status: 'in_use', custodian: 'khalid.harbi', serial: 'SYN-PH-009', lifecycle: [] });
  const call = (m, p, b, who) => e.req(m, p, Object.assign(b !== undefined ? { body: b } : {}, who));
  const post = (p, b, who) => call('POST', p, b, who), get = (p, who = DESK) => call('GET', p, undefined, who);
  if (o.ad !== false) {
    const r = await post('/onboarding/ad', { servers: ['ldaps://127.0.0.1:' + ldap.port], ca_file: caFile, bind_dn: SVC, bind_password: BIND_PW, base_dn: BASE, ou: 'OU=Joiners,' + BASE, upn_suffix: 'corp-hq.com',
      leavers_enabled: true, leavers_ou: LEAVERS, disable_hour: 18, never_disable: ['breakglass'] }, ADM);
    assert.equal(r.status, 200, JSON.stringify(r.json));
  }
  // request -> confirmed
  async function leaver(extra = {}) {
    let r = await post('/offboarding', Object.assign({}, LEAVER, extra), HR); assert.equal(r.status, 200, JSON.stringify(r.json));
    const id = r.json.id;
    r = await post('/offboarding/' + id + '/confirm', { decision: 'confirm' }, MGR); assert.equal(r.status, 200, JSON.stringify(r.json));
    return id;
  }
  return { e, A, dir, ldap, clock, post, get, leaver };
}
const auditOf = (e, action) => e.app.store.auditTail(500).filter((x) => x.action === action);
const acct = (dir, sam) => dir.all().find((x) => dir.vals(x, 'sAMAccountName')[0] === sam);

test('the whole leaver flow: confirmed, approved by a second administrator, disabled on the last day, equipment back', async (t) => {
  const { e, A, dir, ldap, clock, post, get } = await setup(t);
  let r = await post('/offboarding', LEAVER, HR); assert.equal(r.status, 200, JSON.stringify(r.json));
  const id = r.json.id; assert.equal(id, 'OFF-001');
  assert.equal(r.json.directory.found, true); assert.equal(r.json.directory.display_name, 'Khalid Al-Harbi'); assert.deepEqual(r.json.directory.blockers, []);
  assert.deepEqual(r.json.directory.groups, ['GG-Claims-Users']); assert.match(r.json.directory.last_logon, /^\d{4}-/);
  assert.deepEqual(r.json.assets.map((a) => a.id).sort(), ['ast_lap9', 'ast_ph9'], 'the equipment the leaver holds');
  assert.equal((await post('/offboarding/' + id + '/confirm', { decision: 'confirm' }, HR)).status, 403, 'the requester cannot confirm');
  assert.equal((await post('/offboarding/' + id + '/confirm', { decision: 'confirm' }, DESK)).status, 403, 'only the manager or an admin');
  assert.equal((await post('/offboarding/' + id + '/approve', { decision: 'approve' }, ADM)).status, 409, 'not before the manager confirms');
  r = await post('/offboarding/' + id + '/confirm', { decision: 'confirm' }, MGR); assert.equal(r.status, 200);
  assert.equal((await post('/offboarding/' + id + '/approve', { decision: 'approve' }, MGR)).status, 403, 'approval is admin only');
  assert.equal((await post('/offboarding/' + id + '/approve', { decision: 'approve' }, BOT)).status, 403, 'never an AI identity');
  r = await post('/offboarding/' + id + '/approve', { decision: 'approve' }, ADM); assert.equal(r.status, 200, JSON.stringify(r.json));
  assert.equal(r.json.due_at, '2026-10-30T15:00:00.000Z', 'the last day at 18:00 Riyadh');
  assert.equal(dir.vals(acct(dir, 'khalid.harbi'), 'userAccountControl')[0], '512', 'not disabled before the last day');
  let x = await post('/offboarding/run', {}, ADM); assert.equal(x.json.ran, 0);
  clock.t = Date.parse('2026-10-30T15:01:00Z');
  x = await post('/offboarding/run', {}, ADM); assert.equal(x.json.disabled, 1, JSON.stringify(x.json));
  const u = acct(dir, 'khalid.harbi');
  assert.equal(u.dn, 'CN=Khalid Al-Harbi,' + LEAVERS, 'moved to the leavers OU');
  assert.equal(dir.vals(u, 'userAccountControl')[0], '514', 'disabled');
  assert.match(dir.vals(u, 'description')[0], new RegExp('Disabled by ' + ZYB_ORG.short + ' offboarding OFF-001 .*approved by syed'));
  assert.ok(ldap.passwords[u.dn.toLowerCase()], 'the password was replaced by a random one');
  assert.ok(!JSON.stringify(e.app.store.auditTail(500)).includes(ldap.passwords[u.dn.toLowerCase()]), 'which is never recorded');
  r = await get('/offboarding/' + id); assert.equal(r.json.disabled.verified, true); assert.deepEqual(r.json.disabled.groups_kept, ['GG-Claims-Users']);
  assert.equal(r.json.next, 'equipment');
  // equipment
  x = await post('/offboarding/' + id + '/equipment', { returned: ['ast_lap9'] }, DESK); assert.equal(x.status, 400); assert.match(x.json.error, /^na_reason is required/);
  x = await post('/offboarding/' + id + '/equipment', { returned: ['ast_lap9', 'ast_other'] }, DESK); assert.match(x.json.error, /^returned: ast_other/);
  x = await post('/offboarding/' + id + '/equipment', { returned: ['ast_lap9'], na_reason: 'phone kept under the retirement agreement' }, DESK); assert.equal(x.status, 200, JSON.stringify(x.json));
  assert.equal(x.json.status, 'completed');
  assert.equal(A.get('ast_lap9').status, 'in_stock'); assert.ok(!A.get('ast_lap9').custodian);
  for (const a of ['offboarding.request', 'offboarding.confirm', 'offboarding.disable.approve', 'offboarding.disabled', 'offboarding.equipment', 'offboarding.complete', 'offboarding.run'])
    assert.ok(auditOf(e, a).length >= 1, a + ' audited');
  // re-enable: another administrator approves
  assert.equal((await post('/offboarding/' + id + '/reenable', { reason: 'rehired' }, MGR)).status, 403);
  x = await post('/offboarding/' + id + '/reenable', { reason: 'resignation withdrawn by HR' }, ADM); assert.equal(x.status, 200, JSON.stringify(x.json));
  assert.equal((await post('/offboarding/' + id + '/reenable/decide', { decision: 'approve' }, ADM)).status, 403, 'not the person who asked');
  x = await post('/offboarding/' + id + '/reenable/decide', { decision: 'approve' }, ADM2); assert.equal(x.status, 200); assert.match(x.json.warning, /password was replaced/);
  assert.equal(dir.vals(acct(dir, 'khalid.harbi'), 'userAccountControl')[0], '512');
});

test('four eyes: the confirmer cannot approve; immediate termination disables at approval', async (t) => {
  const { dir, post, leaver } = await setup(t);
  const id = await leaver({ reason: 'termination', immediate: true });
  // an admin manager confirming then approving
  const id2 = (await post('/offboarding', Object.assign({}, LEAVER, { username: 'other.person', employee_id: 'E-99999', manager: 'omar.syn' }), HR)).json.id;
  await post('/offboarding/' + id2 + '/confirm', { decision: 'confirm' }, ADM2);
  const r2 = await post('/offboarding/' + id2 + '/approve', { decision: 'approve' }, ADM2); assert.equal(r2.status, 403); assert.match(r2.json.error, /confirmed the leaving/);
  const r = await post('/offboarding/' + id + '/approve', { decision: 'approve' }, ADM); assert.equal(r.status, 200, JSON.stringify(r.json));
  assert.ok(r.json.disabled && r.json.disabled.at, 'disabled at once');
  assert.equal(dir.vals(acct(dir, 'khalid.harbi'), 'userAccountControl')[0], '514');
});

test('refused: someone else\'s account, a privileged account, the never-disable list; the leaver cannot act', async (t) => {
  const { post, get, leaver } = await setup(t);
  let id = await leaver({ username: 'other.person' });
  let r = await get('/offboarding/' + id); assert.match(r.json.directory.blockers[0], /belongs to employee E-99999/);
  r = await post('/offboarding/' + id + '/approve', { decision: 'approve' }, ADM); assert.equal(r.status, 409); assert.match(r.json.error, /will not disable/);
  await post('/offboarding/' + id + '/cancel', { reason: 'wrong user name typed' }, HR);
  id = await leaver({ username: 'admin.person', employee_id: 'E-20003' });
  r = await post('/offboarding/' + id + '/approve', { decision: 'approve' }, ADM); assert.equal(r.status, 409); assert.match(r.json.error, /privileged/);
  await post('/offboarding/' + id + '/cancel', { reason: 'disabled by a domain admin' }, HR);
  id = await leaver({ username: 'breakglass', employee_id: 'E-20004' });
  r = await post('/offboarding/' + id + '/approve', { decision: 'approve' }, ADM); assert.match(r.json.error, /never-disable/);
  // the leaver
  assert.equal((await post('/offboarding/' + id + '/cancel', { reason: 'I am staying after all' }, { user: 'breakglass', role: 'admin' })).status, 403);
  assert.equal((await post('/offboarding', Object.assign({}, LEAVER, { username: 'hana.syn', employee_id: 'E-1' }), HR)).status, 403, 'not for your own account');
});

test('roles and validation', async (t) => {
  const { post, get } = await setup(t);
  assert.equal((await get('/offboarding', VIEW)).status, 403, 'personal data: viewers refused');
  assert.equal((await post('/offboarding', LEAVER, VIEW)).status, 403);
  assert.equal((await post('/offboarding', LEAVER, BOT)).status, 403);
  let r = await post('/offboarding', Object.assign({}, LEAVER, { username: 'Khalid Harbi' }), HR); assert.equal(r.status, 400); assert.match(r.json.error, /^username must be/);
  r = await post('/offboarding', Object.assign({}, LEAVER, { reason: 'fired' }), HR); assert.match(r.json.error, /^reason must be one of/);
  r = await post('/offboarding', Object.assign({}, LEAVER, { last_day: '2026-08-01' }), HR); assert.match(r.json.error, /more than 30 days ago/);
  r = await post('/offboarding', Object.assign({}, LEAVER, { note: 'password is Summer2026!' }), HR); assert.match(r.json.error, /password/);
  assert.equal((await post('/offboarding', LEAVER, HR)).status, 200);
  assert.equal((await post('/offboarding', LEAVER, HR)).status, 409, 'one open request per person');
  assert.equal((await post('/offboarding/run', {}, DESK)).status, 403);
});

test('a refused write is recorded, retried hourly up to three times, then by an administrator; manual path without settings', async (t) => {
  const { e, clock, post, get, leaver } = await setup(t, { readOnly: true });
  const id = await leaver();
  await post('/offboarding/' + id + '/approve', { decision: 'approve' }, ADM);
  clock.t = Date.parse('2026-10-30T15:01:00Z');
  await e.app.addons.offboarding.runDue(null);
  let r = await get('/offboarding/' + id); assert.match(r.json.disabled.error, /refused by the directory.*50/); assert.equal(r.json.disabled.attempts, 1);
  await e.app.addons.offboarding.runDue(null); assert.equal((await get('/offboarding/' + id)).json.disabled.attempts, 1, 'not again within the hour');
  clock.t += 3601000; await e.app.addons.offboarding.runDue(null); assert.equal((await get('/offboarding/' + id)).json.disabled.attempts, 2);
  assert.equal((await post('/offboarding/' + id + '/retry', {}, DESK)).status, 403, 'retry is admin only');
  r = await post('/offboarding/' + id + '/retry', {}, ADM); assert.equal(r.json.disabled.attempts, 3);
  assert.equal((await get('/offboarding')).json.counts.failed, 1);
  assert.ok(auditOf(e, 'offboarding.disable.failed').length >= 3);
  // done by hand
  r = await post('/offboarding/' + id + '/disabled', { directory_ref: 'disabled by hand, ticket CHG-4411' }, DESK); assert.equal(r.status, 200, JSON.stringify(r.json));
  assert.equal(r.json.disabled.manual, true); assert.equal(r.json.next, 'equipment');
});

test('without directory settings: manual record after the same two approvals', async (t) => {
  const { post, leaver } = await setup(t, { ad: false });
  const id = await leaver();
  assert.equal((await post('/offboarding/' + id + '/disabled', { directory_ref: 'CHG-1' }, DESK)).status, 409, 'not before approval');
  const r = await post('/offboarding/' + id + '/approve', { decision: 'approve' }, ADM); assert.equal(r.json.disable.mode, 'manual');
  assert.equal((await post('/offboarding/' + id + '/disabled', { directory_ref: 'disabled in ADUC, CHG-4412' }, DESK)).status, 200);
});
