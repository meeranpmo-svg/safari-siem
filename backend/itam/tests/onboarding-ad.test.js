// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// HR onboarding - automatic Active Directory account creation (engine/onboarding-ad.js + engine/ad-writer.js) through the real
// routes against an in-process fake LDAPS directory (tests/helpers/fake-ldap.js, its own BER): directory settings admin only,
// validated, bind password sealed and never returned; after the four-eyes account approval the user is created DISABLED with
// the temporary password as a quoted UTF-16LE unicodePwd, pwdLastSet 0, only allowed groups added (privileged refused at
// save), read back and verified; the password revealed ONCE to the named manager only and never in the audit / history /
// stored request; handover enables the account; cancel disables it; re-issue needs a different administrator; a name taken
// in the directory and a refused write recorded and retried. SYNTHETIC data only.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs'), os = require('os'), path = require('path');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');
const { makeCA, makeServerCert } = require('./helpers/x509');
const { startFakeLdap, makeDirectory } = require('./helpers/fake-ldap');
const { tempPassword } = require('../engine/ad-writer');

const BASE = 'DC=corp-hq,DC=com', OU = 'OU=Joiners,' + BASE, SVC = 'CN=svc-onboarding-syn,OU=Service,' + BASE, BIND_PW = 'Synthetic-Bind-Pass-9';
const HR = { user: 'hana.syn', role: 'operator' }, MGR = { user: 'faisal.syn', role: 'operator' }, DESK = { user: 'desk.syn', role: 'operator' };
const ADM = { user: 'syed', role: 'admin' }, ADM2 = { user: 'omar.syn', role: 'admin' }, VIEW = { user: 'vera.syn', role: 'viewer' }, BOT = { user: 'ai:desk', role: 'admin' };
const JOINER = { name: 'Sara Al-Ghamdi', employee_id: 'E-10442', job_title: 'Claims Analyst', department: 'Claims', branch: 'Riyadh HQ', start_date: '2026-11-05', manager: 'faisal.syn', laptop_profile: 'standard' };

async function setup(t, o = {}) {
  const clock = { t: Date.parse('2026-10-28T08:00:00Z') };
  const ca = makeCA('Synthetic AD CA onboarding'), leaf = makeServerCert(ca, { cn: ('dc01.' + 'corp-hq.com'), dns: [('dc01.' + 'corp-hq.com')], ip: ['127.0.0.1'] });
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'onb-ad-')); t.after(() => fs.rmSync(tmp, { recursive: true, force: true }));
  const caFile = path.join(tmp, 'ad-root.pem'); fs.writeFileSync(caFile, ca.cert);
  const dir = makeDirectory();
  dir.add(BASE, { objectClass: ['domain'] }); dir.add('OU=Service,' + BASE, { objectClass: ['organizationalUnit'] }); dir.add(OU, { objectClass: ['organizationalUnit'], ou: 'Joiners' });
  dir.add(SVC, { objectClass: ['user'], cn: 'svc-onboarding-syn', sAMAccountName: 'svc-onboarding-syn' });
  dir.add('OU=Groups,' + BASE, { objectClass: ['organizationalUnit'] });
  dir.add('CN=GG-Claims-Users,OU=Groups,' + BASE, { objectClass: ['top', 'group'], cn: 'GG-Claims-Users', sAMAccountName: 'GG-Claims-Users' });
  dir.add('CN=VPN-Users,OU=Groups,' + BASE, { objectClass: ['top', 'group'], cn: 'VPN-Users', sAMAccountName: 'VPN-Users' });
  dir.add('CN=Existing Person,OU=Staff,' + BASE, { objectClass: ['user'], sAMAccountName: 'taken.user', userPrincipalName: ('taken.user@' + 'corp-hq.com') });
  const ldap = await startFakeLdap({ key: leaf.key, cert: leaf.cert, dir, passwords: { [SVC]: BIND_PW }, readOnly: o.readOnly ? [SVC] : [] });
  t.after(() => ldap.close());
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true, now: () => clock.t, python: process.env.PYTHON || 'python3' });
  e.app.store.collection('assets').put({ id: 'ast_lap1', type: 'laptop', status: 'in_stock', vendor: 'Dell', model: 'Latitude 5450', serial: 'SYN-LAP-001', lifecycle: [] });
  const call = (m, p, b, who) => e.req(m, p, Object.assign(b !== undefined ? { body: b } : {}, who));
  const post = (p, b, who) => call('POST', p, b, who), get = (p, who = DESK) => call('GET', p, undefined, who);
  const settings = { enabled: true, servers: [ldap.url || 'ldaps://127.0.0.1:' + ldap.port], ca_file: caFile, bind_dn: SVC, bind_password: BIND_PW, base_dn: BASE, ou: OU, upn_suffix: 'corp-hq.com', allowed_groups: ['GG-Claims-Users', 'VPN-Users'] };
  // a joiner up to the account proposal
  async function joiner(username = 'sara.ghamdi', extra = {}) {
    let r = await post('/onboarding', Object.assign({}, JOINER, extra), HR); assert.equal(r.status, 200, r.raw);
    const id = r.json.id;
    assert.equal((await post('/onboarding/' + id + '/approve', { decision: 'approve' }, MGR)).status, 200);
    r = await post('/onboarding/' + id + '/account', { username, groups: ['GG-Claims-Users', 'VPN-Users', 'GG-Finance-Readers'] }, DESK); assert.equal(r.status, 200, r.raw);
    return id;
  }
  return { e, dir, ldap, clock, post, get, settings, joiner };
}
const auditOf = (e, action) => e.app.store.auditTail(500).filter((x) => x.action === action);
const user = (dir, sam) => dir.all().find((x) => dir.vals(x, 'sAMAccountName')[0] === sam);

test('directory settings: admin only, validated, password sealed and never returned, read-only test', async (t) => {
  const { e, post, get, settings } = await setup(t);
  assert.equal((await post('/onboarding/ad', settings, DESK)).status, 403, 'operators cannot change it');
  assert.equal((await post('/onboarding/ad', settings, BOT)).status, 403, 'an AI identity cannot change it');
  assert.equal((await get('/onboarding/ad', VIEW)).status, 403);
  let r = await post('/onboarding/ad', Object.assign({}, settings, { servers: ['http://dc01'] }), ADM); assert.equal(r.status, 400); assert.match(r.json.error, /^servers/);
  r = await post('/onboarding/ad', Object.assign({}, settings, { ou: 'Joiners' }), ADM); assert.match(r.json.error, /^ou must be/);
  r = await post('/onboarding/ad', Object.assign({}, settings, { ou: 'OU=Joiners,DC=other,DC=com' }), ADM); assert.match(r.json.error, /inside base_dn/);
  r = await post('/onboarding/ad', Object.assign({}, settings, { allowed_groups: ['Domain Admins'] }), ADM); assert.equal(r.status, 400); assert.match(r.json.error, /privileged/);
  r = await post('/onboarding/ad', { enabled: true, ou: OU }, ADM); assert.match(r.json.error, /enabled needs/);
  r = await post('/onboarding/ad', Object.assign({}, settings, { extra: 'dropped' }), ADM); assert.equal(r.status, 200, r.raw);
  assert.equal(r.json.bind_password_set, true); assert.ok(!('bind_password' in r.json) && !JSON.stringify(r.json).includes(BIND_PW), 'the password is never returned');
  assert.ok(!JSON.stringify(e.app.store.collection('onboarding_ad').all()).includes(BIND_PW), 'stored sealed');
  assert.ok(!JSON.stringify(e.app.store.auditTail(100)).includes(BIND_PW));
  r = await post('/onboarding/ad/test', {}, ADM); assert.equal(r.status, 200, r.raw); assert.equal(r.json.ok, true); assert.equal(r.json.ou_found, true);
  assert.equal(auditOf(e, 'onboarding.ad.settings').length, 1); assert.equal(auditOf(e, 'onboarding.ad.test').length, 1);
  assert.equal((await get('/onboarding')).json.directory.automatic, true);
});

test('changing the directory target needs the bind password again; an unchanged target keeps it', async (t) => {
  const { e, post, settings } = await setup(t);
  assert.equal((await post('/onboarding/ad', settings, ADM)).status, 200);
  const sealed = () => e.app.store.collection('onboarding_ad').all()[0].bind_enc;
  const was = JSON.stringify(sealed());
  let r = await post('/onboarding/ad', { servers: ['ldaps://other-dc.corp-hq.com:636'] }, ADM);
  assert.equal(r.status, 400); assert.match(r.json.error, /bind_password is required when servers change/);
  r = await post('/onboarding/ad', { ca_file: '/etc/ssl/other-root.pem' }, ADM); assert.equal(r.status, 400); assert.match(r.json.error, /ca_file/);
  r = await post('/onboarding/ad', { server_ips: { 'dc01.corp-hq.com': '10.9.9.9' } }, ADM); assert.equal(r.status, 400); assert.match(r.json.error, /server_ips/);
  assert.equal(JSON.stringify(sealed()), was, 'the stored secret is untouched by the refused requests');
  r = await post('/onboarding/ad', { servers: ['ldaps://other-dc.corp-hq.com:636'], bind_password: 'Synthetic-New-Pass-1' }, ADM); assert.equal(r.status, 200, r.raw);
  assert.deepEqual(r.json.servers, ['ldaps://other-dc.corp-hq.com:636']); assert.notEqual(JSON.stringify(sealed()), was);
  const now = JSON.stringify(sealed());
  r = await post('/onboarding/ad', { servers: ['ldaps://other-dc.corp-hq.com:636'], ou: OU }, ADM); assert.equal(r.status, 200, r.raw);
  assert.equal(JSON.stringify(sealed()), now, 'an unchanged target keeps the stored password');
});

test('created automatically after the four-eyes approval: disabled, temporary password, must change, allowed groups only', async (t) => {
  const { e, dir, ldap, post, get, settings, joiner } = await setup(t);
  await post('/onboarding/ad', settings, ADM);
  const id = await joiner();
  assert.equal(user(dir, 'sara.ghamdi'), undefined, 'nothing is written before the account approval');
  assert.equal((await post('/onboarding/' + id + '/account/decide', { decision: 'approve' }, { user: 'desk.syn', role: 'admin' })).status, 403, 'the proposer cannot approve');
  const r = await post('/onboarding/' + id + '/account/decide', { decision: 'approve' }, ADM); assert.equal(r.status, 200, r.raw);
  const a = r.json.account;
  assert.equal(a.created_by, 'system:onboarding-ad'); assert.equal(a.provisioned.verified, true, JSON.stringify(a));
  assert.deepEqual(a.provisioned.groups_added, ['GG-Claims-Users', 'VPN-Users']);
  assert.ok(a.provisioned.groups_refused.some((g) => /GG-Finance-Readers/.test(g)), 'a group not on the allowed list is not added');
  const u = user(dir, 'sara.ghamdi');
  assert.equal(u.dn, 'CN=Sara Al-Ghamdi,' + OU);
  assert.equal(dir.vals(u, 'userAccountControl')[0], '514', 'created disabled');
  assert.equal(dir.vals(u, 'pwdLastSet')[0], '0', 'change at first sign-in');
  assert.equal(dir.vals(u, 'userPrincipalName')[0], ('sara.ghamdi@' + 'corp-hq.com'));
  assert.match(dir.vals(u, 'description')[0], /onboarding ONB-001/);
  const pw = ldap.passwords[u.dn.toLowerCase()]; assert.ok(pw && pw.length === 16 && /[A-Z]/.test(pw) && /[a-z]/.test(pw) && /\d/.test(pw) && /[^A-Za-z0-9]/.test(pw), 'a complex 16-character password as unicodePwd');
  assert.ok(dir.vals(u, 'memberOf').length === 2);
  assert.equal(r.json.password_waiting.waiting, true);
  assert.ok(!JSON.stringify(r.json).includes(pw), 'the password is not in the answer');
  assert.ok(!JSON.stringify(e.app.store.collection('onboarding').all()).includes(pw), 'nor in the stored request');
  assert.ok(!JSON.stringify(e.app.store.collection('onboarding_secrets').all()).includes(pw), 'sealed in the vault');
  assert.equal(auditOf(e, 'onboarding.account.provisioned').length, 1);
  // manual credentials are refused for an automatic account
  assert.equal((await post('/onboarding/' + id + '/credentials', { method: 'in_person', must_change: true, mfa: 'enrolled' }, DESK)).status, 409);
  // the reveal: the named manager only, once
  let x = await post('/onboarding/' + id + '/credentials/reveal', {}, DESK); assert.equal(x.status, 403);
  x = await post('/onboarding/' + id + '/credentials/reveal', {}, { user: 'faisal.syn', role: 'admin' }); assert.equal(x.status, 200, x.raw); assert.equal(x.json.password, pw);
  x = await post('/onboarding/' + id + '/credentials/reveal', {}, MGR); assert.equal(x.status, 410, 'shown once');
  assert.ok(!JSON.stringify(e.app.store.auditTail(500)).includes(pw), 'the password never reaches the audit trail');
  assert.ok(!JSON.stringify(e.app.store.collection('onboarding').all()).includes(pw));
  assert.equal(e.app.store.collection('onboarding_secrets').all().length, 0, 'destroyed after the reveal');
  assert.equal(auditOf(e, 'onboarding.credentials.revealed').length, 1); assert.equal(auditOf(e, 'onboarding.credentials.reveal_refused').length, 1);
  // laptop + handover enables the account and completes the request
  await post('/onboarding/' + id + '/laptop', { asset_id: 'ast_lap1' }, DESK);
  const h = await post('/onboarding/' + id + '/handover', { acknowledged: true }, DESK); assert.equal(h.status, 200, h.raw);
  assert.equal(h.json.status, 'completed'); assert.equal(dir.vals(user(dir, 'sara.ghamdi'), 'userAccountControl')[0], '512', 'enabled at handover');
  assert.equal(auditOf(e, 'onboarding.account.enabled').length, 1);
  assert.equal((await get('/onboarding/' + id)).json.credentials.method, 'manager_reveal');
});

test('re-issue needs a different administrator; cancel disables (never deletes); an expired password is destroyed', async (t) => {
  const { e, dir, ldap, clock, post, settings, joiner } = await setup(t);
  await post('/onboarding/ad', settings, ADM);
  const id = await joiner();
  await post('/onboarding/' + id + '/account/decide', { decision: 'approve' }, ADM);
  const dn = user(dir, 'sara.ghamdi').dn.toLowerCase(), first = ldap.passwords[dn];
  // 72 h pass unrevealed
  clock.t += 73 * 3600000;
  let x = await post('/onboarding/' + id + '/credentials/reveal', {}, MGR); assert.equal(x.status, 410); assert.match(x.json.error, /expired/);
  assert.equal((await post('/onboarding/' + id + '/credentials/reissue', { reason: 'lost' }, MGR)).status, 400, 'reason min length');
  assert.equal((await post('/onboarding/' + id + '/credentials/reissue', { reason: 'expired before the joiner arrived' }, DESK)).status, 403, 'manager or admin');
  x = await post('/onboarding/' + id + '/credentials/reissue', { reason: 'expired before the joiner arrived' }, ADM); assert.equal(x.status, 200, x.raw);
  assert.equal((await post('/onboarding/' + id + '/credentials/reissue/decide', { decision: 'approve' }, ADM)).status, 403, 'the requester cannot approve');
  assert.equal((await post('/onboarding/' + id + '/credentials/reissue/decide', { decision: 'approve' }, MGR)).status, 403, 'admin only');
  x = await post('/onboarding/' + id + '/credentials/reissue/decide', { decision: 'approve' }, ADM2); assert.equal(x.status, 200, x.raw);
  assert.notEqual(ldap.passwords[dn], first, 'a new password was set');
  x = await post('/onboarding/' + id + '/credentials/reveal', {}, MGR); assert.equal(x.status, 200); assert.equal(x.json.password, ldap.passwords[dn]);
  // cancel
  x = await post('/onboarding/' + id + '/cancel', { reason: 'offer withdrawn by HR' }, HR); assert.equal(x.status, 200, x.raw);
  assert.ok(!x.json.warning, x.json.warning);
  const u = user(dir, 'sara.ghamdi'); assert.ok(u, 'never deleted'); assert.equal(dir.vals(u, 'userAccountControl')[0], '514');
  assert.equal(auditOf(e, 'onboarding.account.disabled').length, 1); assert.equal(auditOf(e, 'onboarding.credentials.reissue_approve').length, 1);
});

test('a name taken in the directory and a refused write are recorded, not hidden; retry is admin only', async (t) => {
  const { e, post, get, settings, joiner } = await setup(t);
  await post('/onboarding/ad', settings, ADM);
  const id = await joiner('taken.user');
  let r = await post('/onboarding/' + id + '/account/decide', { decision: 'approve' }, ADM); assert.equal(r.status, 200, r.raw);
  assert.equal(r.json.account.created_by, undefined); assert.match(r.json.account.provision_error.error, /already exists in the directory/);
  assert.equal(auditOf(e, 'onboarding.account.provision_failed').length, 1);
  assert.equal((await post('/onboarding/' + id + '/account/provision', {}, DESK)).status, 403, 'retry is admin only');
  r = await post('/onboarding/' + id + '/account/provision', {}, ADM); assert.equal(r.status, 200); assert.ok(r.json.account.provision_error);
  // the manual record is still possible (created by hand)
  r = await post('/onboarding/' + id + '/account/created', { username: 'taken.user', directory_ref: 'CN=Sara Al-Ghamdi,OU=Claims' }, DESK); assert.equal(r.status, 200, r.raw);
  assert.equal((await get('/onboarding/' + id)).json.password_waiting, null);
});

test('a bind account without write rights: the refusal is named', async (t) => {
  const { e, post, settings, joiner } = await setup(t, { readOnly: true });
  await post('/onboarding/ad', settings, ADM);
  const id = await joiner();
  const r = await post('/onboarding/' + id + '/account/decide', { decision: 'approve' }, ADM);
  assert.match(r.json.account.provision_error.error, /refused by the directory: .*50/);
  assert.equal(e.app.store.collection('onboarding_secrets').all().length, 0, 'no password kept for an account that does not exist');
});

test('tempPassword: 16 characters, all four classes, no look-alikes', () => {
  for (let i = 0; i < 200; i++) {
    const p = tempPassword();
    assert.equal(p.length, 16); assert.ok(/[A-Z]/.test(p) && /[a-z]/.test(p) && /[2-9]/.test(p) && /[!@#$%*\-_=+?]/.test(p)); assert.ok(!/[O0Il1]/.test(p));
  }
});
