// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// AD management (engine/ad-manage.js + ad-writer.js) against an in-process fake AD over LDAPS with SYNTHETIC people:
// off until switched on; four eyes (a different administrator approves, then it is written and read back); emergency disable
// runs at once and is reviewed by a second administrator; privileged / protected / own / bind accounts are refused; create with
// a one-time temporary password for the requester; delete only for an account disabled and unchanged for 30 days; roles
// (viewer refused, operator reads, admin requests, AI identity refused), validation errors naming the field, expiry, audit;
// unlock (lockoutTime = 0) only for an account the directory shows locked out, with the lockout source from the SIEM when linked.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');
const { makeCA, makeServerCert } = require('./helpers/x509');
const { startFakeLdap, makeDirectory } = require('./helpers/fake-ldap');

const BASE = 'DC=corp-hq,DC=com', STAFF = 'OU=Staff,' + BASE, SVC = 'CN=svc-dir-syn,OU=Service,' + BASE, BIND_PW = 'Synthetic-Bind-Pass-7';
const OP = { user: 'nora.syn', role: 'operator' }, ADM = { user: 'syed', role: 'admin' }, ADM2 = { user: 'huda.syn', role: 'admin' }, VIEW = { user: 'vera.syn', role: 'viewer' }, BOT = { user: 'ai:desk', role: 'admin' };
const GT = (ms) => new Date(ms).toISOString().replace(/[-:T]/g, '').slice(0, 14) + '.0Z';
const DAY = 86400000;
const FT = (ms) => String((ms + 11644473600000) * 10000);   // ms -> AD FILETIME

async function setup(t, { connect = true, on = true } = {}) {
  let T = Date.parse('2026-11-12T08:00:00Z');
  const ca = makeCA('Synthetic AD CA manage'), leaf = makeServerCert(ca, { cn: ('dc01.' + 'corp-hq.com'), dns: [('dc01.' + 'corp-hq.com')], ip: ['127.0.0.1'] });
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'ad-mng-')); t.after(() => fs.rmSync(tmp, { recursive: true, force: true }));
  const caFile = path.join(tmp, 'ad-root.pem'); fs.writeFileSync(caFile, ca.cert);
  const dir = makeDirectory();
  dir.add(BASE, { objectClass: ['domain'] }); dir.add('OU=Service,' + BASE, { objectClass: ['organizationalUnit'] }); dir.add(STAFF, { objectClass: ['organizationalUnit'] });
  dir.add('OU=Leavers,' + BASE, { objectClass: ['organizationalUnit'] }); dir.add('OU=Groups,' + BASE, { objectClass: ['organizationalUnit'] });
  dir.add(SVC, { objectClass: ['user'], objectCategory: 'person', cn: 'svc-dir-syn', sAMAccountName: 'svc-dir-syn', userAccountControl: '512' });
  const G = (n) => dir.add('CN=' + n + ',OU=Groups,' + BASE, { objectClass: ['top', 'group'], cn: n, sAMAccountName: n });
  G('Claims-Team'); G('Domain Admins'); G('VPN-Users');
  const P = (cn, sam, extra) => dir.add('CN=' + cn + ',' + STAFF, Object.assign({ objectClass: ['top', 'person', 'organizationalPerson', 'user'], objectCategory: 'person', cn, sAMAccountName: sam, userPrincipalName: sam + ('@' + 'corp-hq.com'), displayName: cn, userAccountControl: '512', whenChanged: GT(T - 2 * DAY) }, extra));
  P('Alia Synthetic', 'alia.syn', { department: 'Claims' });
  P('Badr Synthetic', 'badr.syn', { adminCount: '1' });
  P('Coral Synthetic', 'coral.syn', { userAccountControl: '514', whenChanged: GT(T - 45 * DAY) });
  P('Dina Synthetic', 'dina.syn', { userAccountControl: '514', whenChanged: GT(T - 5 * DAY) });
  P('Eisa Synthetic', 'eisa.syn');
  P('Syed Synthetic', 'syed');
  P('Gina Synthetic', 'gina.syn', { lockoutTime: FT(T - 3600000) });                                              // locked out an hour ago
  P('Hana Synthetic', 'hana.syn', { lockoutTime: FT(T - 2 * DAY), 'msDS-User-Account-Control-Computed': '0' });   // the lockout ran out
  dir.set('CN=Badr Synthetic,' + STAFF, 'lockoutTime', [FT(T - 600000)]);
  dir.addMember('CN=Domain Admins,OU=Groups,' + BASE, 'CN=Eisa Synthetic,' + STAFF);
  const ldap = await startFakeLdap({ key: leaf.key, cert: leaf.cert, dir, passwords: { [SVC]: BIND_PW } });
  t.after(() => ldap.close());
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true, now: () => T, python: process.env.PYTHON || 'python3' });
  const call = (m, p, b, who) => e.req(m, p, Object.assign(b !== undefined ? { body: b } : {}, who));
  if (connect) {
    const r = await call('POST', '/onboarding/ad', { enabled: true, servers: [ldap.url || 'ldaps://127.0.0.1:' + ldap.port], ca_file: caFile, bind_dn: SVC, bind_password: BIND_PW, base_dn: BASE, ou: STAFF, upn_suffix: 'corp-hq.com', allowed_groups: [] }, ADM);
    assert.equal(r.status, 200, r.raw);
  }
  if (connect && on) assert.equal((await call('POST', '/ad-manage/settings', { enabled: true, delete_enabled: true, protected: [] }, ADM)).status, 200);
  const uac = (cn) => dir.vals(dir.get('CN=' + cn + ',' + STAFF), 'userAccountControl')[0];
  const audits = (a) => e.app.store.auditTail(300).filter((x) => x.action === a);
  return { e, dir, ldap, call, uac, audits, clock: (ms) => { T += ms; } };
}
const req = (call, b, who) => call('POST', '/ad-manage/requests', b, who || ADM);

test('off until set up and switched on: the reason is given; roles on the page and the settings', async (t) => {
  let s = await setup(t, { connect: false });
  let r = await req(s.call, { action: 'disable', sam: 'alia.syn', reason: 'synthetic test' }); assert.equal(r.status, 409); assert.match(r.json.error, /directory connection is not set/);
  s = await setup(t, { on: false });
  r = await req(s.call, { action: 'disable', sam: 'alia.syn', reason: 'synthetic test' }); assert.equal(r.status, 409); assert.match(r.json.error, /switched off/);
  assert.equal((await s.call('GET', '/ad-manage', undefined, VIEW)).status, 403, 'names and groups are personal data: no viewers');
  assert.equal((await s.call('GET', '/ad-manage', undefined, OP)).status, 200, 'operators read');
  assert.equal((await s.call('POST', '/ad-manage/settings', { enabled: true }, OP)).status, 403, 'operators cannot switch it on');
  assert.equal((await s.call('POST', '/ad-manage/settings', { enabled: true }, BOT)).status, 403, 'an AI identity cannot switch it on');
  r = await s.call('POST', '/ad-manage/settings', { enabled: 'yes' }, ADM); assert.equal(r.status, 400); assert.match(r.json.error, /enabled/);
  r = await s.call('POST', '/ad-manage/settings', { enabled: true, create_ou: 'OU=Elsewhere,DC=other,DC=com' }, ADM); assert.equal(r.status, 400); assert.match(r.json.error, /create_ou must be inside/);
  r = await s.call('POST', '/ad-manage/settings', { enabled: true, protected: ['bad name!'] }, ADM); assert.equal(r.status, 400); assert.match(r.json.error, /protected/);
  r = await s.call('POST', '/ad-manage/settings', { enabled: true, delete_enabled: false, protected: ['alia.syn'] }, ADM); assert.equal(r.status, 200, r.raw);
  const a = s.audits('ad_manage.settings').pop(); assert.equal(a.by, ADM.user); assert.equal(a.detail.enabled, true); assert.ok(a.detail.changed.includes('protected'));
  r = await req(s.call, { action: 'disable', sam: 'alia.syn', reason: 'synthetic test' }); assert.equal(r.status, 403); assert.match(r.json.error, /protected list/);
});

test('four eyes: a request changes nothing; the requester cannot approve; a second admin approves, it is written and read back', async (t) => {
  const s = await setup(t);
  assert.equal((await req(s.call, { action: 'disable', sam: 'alia.syn', reason: 'synthetic test' }, OP)).status, 403, 'operators do not request');
  assert.equal((await req(s.call, { action: 'disable', sam: 'alia.syn', reason: 'synthetic test' }, BOT)).status, 403, 'an AI identity does not request');
  let r = await req(s.call, { action: 'disable', sam: 'alia.syn', reason: 'left the company (synthetic)' }); assert.equal(r.status, 200, r.raw);
  const id = r.json.id; assert.equal(r.json.status, 'pending'); assert.equal(s.uac('Alia Synthetic'), '512', 'nothing written before approval');
  assert.equal(s.audits('ad_manage.request').pop().detail.id, id);
  r = await s.call('POST', '/ad-manage/requests/' + id + '/approve', {}, ADM); assert.equal(r.status, 403); assert.match(r.json.error, /four eyes/);
  r = await s.call('POST', '/ad-manage/requests/' + id + '/approve', {}, BOT); assert.equal(r.status, 403, 'an AI identity never approves');
  r = await s.call('POST', '/ad-manage/requests/' + id + '/approve', {}, ADM2); assert.equal(r.status, 200, r.raw);
  assert.equal(r.json.status, 'done'); assert.equal(r.json.result, 'disabled'); assert.equal(s.uac('Alia Synthetic'), '514');
  const a = s.audits('ad_manage.approve').pop(); assert.ok(a.by === ADM2.user && a.detail.requested_by === ADM.user && a.ip !== undefined);
  r = await s.call('POST', '/ad-manage/requests/' + id + '/approve', {}, ADM2); assert.equal(r.status, 409, 'done once');
  r = await req(s.call, { action: 'enable', sam: 'alia.syn', reason: 'came back (synthetic)' }); assert.equal(r.status, 200);
  assert.equal((await s.call('POST', '/ad-manage/requests/' + r.json.id + '/reject', {}, ADM2)).status, 400, 'a rejection needs a reason');
  assert.equal((await s.call('POST', '/ad-manage/requests/' + r.json.id + '/cancel', {}, ADM2)).status, 403, 'only the requester cancels');
  const rj = await s.call('POST', '/ad-manage/requests/' + r.json.id + '/reject', { reason: 'no ticket' }, ADM2); assert.equal(rj.json.status, 'rejected');
  assert.equal(s.uac('Alia Synthetic'), '514'); assert.equal(s.audits('ad_manage.reject').pop().detail.reason, 'no ticket');
});

test('protected: privileged (adminCount, privileged group), own account, bind account, privileged group never added', async (t) => {
  const s = await setup(t);
  const no = async (b, re) => { const r = await req(s.call, Object.assign({ reason: 'synthetic test' }, b)); assert.equal(r.status, 403, JSON.stringify(b) + ' ' + r.raw); assert.match(r.json.error, re); };
  await no({ action: 'disable', sam: 'badr.syn' }, /privileged account/);
  await no({ action: 'reset_password', sam: 'eisa.syn' }, /privileged group Domain Admins/);
  await no({ action: 'disable', sam: 'syed' }, /your own account/);
  await no({ action: 'disable', sam: 'svc-dir-syn' }, /reach the directory/);
  await no({ action: 'add_group', sam: 'alia.syn', group: 'Domain Admins' }, /privileged group/);
  await no({ action: 'create', sam: 'new.syn', given_name: 'New', surname: 'Synthetic', groups: ['Domain Admins'] }, /privileged group/);
  const v = (await s.call('GET', '/ad-manage/user/eisa.syn', undefined, OP)).json; assert.equal(v.protected, true); assert.equal(v.can_delete, false);
  assert.ok(s.audits('ad_manage.lookup').some((x) => x.target === 'eisa.syn' && x.by === OP.user));
  assert.equal((await s.call('GET', '/ad-manage/user/bad$name', undefined, OP)).status, 400);
  assert.equal((await s.call('GET', '/ad-manage/user/nobody.syn', undefined, OP)).status, 404);
});

test('create: written disabled-then-enabled with groups, must change at first sign-in; the temporary password once, to the requester only', async (t) => {
  const s = await setup(t);
  let r = await req(s.call, { action: 'create', sam: 'alia.syn', given_name: 'A', surname: 'B', reason: 'synthetic test' }); assert.equal(r.status, 409); assert.match(r.json.error, /already exists/);
  r = await req(s.call, { action: 'create', sam: 'farah.syn', given_name: 'Farah', surname: 'Synthetic', department: 'Claims', groups: ['Claims-Team', 'VPN-Users'], reason: 'new joiner (synthetic)' }); assert.equal(r.status, 200, r.raw);
  assert.match(r.json.summary, /create farah\.syn .*Claims-Team, VPN-Users, enabled/);
  r = await s.call('POST', '/ad-manage/requests/' + r.json.id + '/approve', {}, ADM2); assert.equal(r.status, 200, r.raw);
  const dn = 'CN=Farah Synthetic,' + STAFF, u = s.dir.get(dn); assert.ok(u, 'created');
  assert.equal(s.dir.vals(u, 'userAccountControl')[0], '512'); assert.equal(s.dir.vals(u, 'pwdLastSet')[0], '0'); assert.equal(s.dir.vals(u, 'userPrincipalName')[0], ('farah.syn@' + 'corp-hq.com'));
  assert.deepEqual(s.dir.vals(u, 'memberOf').map((g) => g.split(',')[0]).sort(), ['CN=Claims-Team', 'CN=VPN-Users']);
  const id = r.json.id;
  assert.equal((await s.call('POST', '/ad-manage/requests/' + id + '/reveal', {}, ADM2)).status, 403, 'the approver does not see it');
  r = await s.call('POST', '/ad-manage/requests/' + id + '/reveal', {}, ADM); assert.equal(r.status, 200, r.raw);
  assert.equal(r.json.password, s.ldap.passwords[dn.toLowerCase()], 'the password shown is the one AD holds'); assert.equal(r.json.password.length, 16);
  const pw = r.json.password;
  assert.equal((await s.call('POST', '/ad-manage/requests/' + id + '/reveal', {}, ADM)).status, 410, 'shown once');
  const all = JSON.stringify(s.e.app.store.auditTail(300)) + JSON.stringify(s.e.app.store.collection('ad_manage_requests').all()) + JSON.stringify((await s.call('GET', '/ad-manage', undefined, ADM)).json);
  assert.ok(!all.includes(pw), 'the password is in no audit record, request or page answer');
  assert.ok(s.audits('ad_manage.password_shown').some((x) => x.by === ADM.user && x.target === 'farah.syn'));
});

test('a reset password is held 72 h then destroyed; a pending request expires after 7 days', async (t) => {
  const s = await setup(t);
  let r = await req(s.call, { action: 'reset_password', sam: 'alia.syn', reason: 'forgot it (synthetic)' });
  r = await s.call('POST', '/ad-manage/requests/' + r.json.id + '/approve', {}, ADM2); assert.equal(r.status, 200, r.raw);
  assert.equal(s.dir.vals(s.dir.get('CN=Alia Synthetic,' + STAFF), 'pwdLastSet')[0], '0');
  const id = r.json.id, p = await req(s.call, { action: 'move', sam: 'alia.syn', ou: 'OU=Leavers,' + BASE, reason: 'synthetic test' });
  s.clock(8 * DAY); s.e.app.addons.adManage.tick();
  assert.equal((await s.call('POST', '/ad-manage/requests/' + id + '/reveal', {}, ADM)).status, 410);
  assert.ok(s.audits('ad_manage.password_destroyed').length);
  r = await s.call('POST', '/ad-manage/requests/' + p.json.id + '/approve', {}, ADM2); assert.equal(r.status, 409); assert.match(r.json.error, /expired/);
  assert.ok(s.dir.get('CN=Alia Synthetic,' + STAFF), 'not moved');
});

test('delete: switched on, disabled, unchanged 30 days - checked at request and again at approval', async (t) => {
  const s = await setup(t);
  let r = await req(s.call, { action: 'delete', sam: 'alia.syn', reason: 'synthetic test' }); assert.equal(r.status, 409); assert.match(r.json.error, /disable it first/);
  r = await req(s.call, { action: 'delete', sam: 'dina.syn', reason: 'synthetic test' }); assert.equal(r.status, 409); assert.match(r.json.error, /unchanged for 5 day\(s\).*after 30/);
  assert.equal((await s.call('GET', '/ad-manage/user/coral.syn', undefined, OP)).json.can_delete, true);
  r = await req(s.call, { action: 'delete', sam: 'coral.syn', reason: 'left in September (synthetic)' }); assert.equal(r.status, 200, r.raw); assert.match(r.json.summary, /DELETE coral\.syn/);
  const id = r.json.id;
  s.dir.set('CN=Coral Synthetic,' + STAFF, 'userAccountControl', ['512']);   // someone re-enabled it in AD meanwhile
  r = await s.call('POST', '/ad-manage/requests/' + id + '/approve', {}, ADM2); assert.equal(r.status, 409); assert.match(r.json.error, /cannot be deleted now/);
  assert.ok(s.dir.get('CN=Coral Synthetic,' + STAFF), 'not deleted'); assert.equal(s.audits('ad_manage.failed').pop().detail.id, id);
  s.dir.set('CN=Coral Synthetic,' + STAFF, 'userAccountControl', ['514']);
  r = await req(s.call, { action: 'delete', sam: 'coral.syn', reason: 'second try (synthetic)' });
  r = await s.call('POST', '/ad-manage/requests/' + r.json.id + '/approve', {}, ADM2); assert.equal(r.status, 200, r.raw); assert.equal(r.json.result, 'deleted');
  assert.equal(s.dir.get('CN=Coral Synthetic,' + STAFF), undefined, 'gone from the directory');
  assert.ok(s.ldap.requests.some((q) => q.op === 'delete' && /Coral/.test(q.dn)));
  await s.call('POST', '/ad-manage/settings', { enabled: true, delete_enabled: false }, ADM);
  s.clock(40 * DAY); r = await req(s.call, { action: 'delete', sam: 'dina.syn', reason: 'synthetic test' }); assert.equal(r.status, 409); assert.match(r.json.error, /switched off/);
});

test('emergency disable runs at once, then a different administrator reviews it', async (t) => {
  const s = await setup(t);
  let r = await req(s.call, { action: 'enable', sam: 'dina.syn', reason: 'synthetic test', emergency: true }); assert.equal(r.status, 400); assert.match(r.json.error, /emergency is only for disabling/);
  r = await req(s.call, { action: 'disable', sam: 'alia.syn', reason: 'phished - password sold (synthetic)', emergency: true }); assert.equal(r.status, 200, r.raw);
  assert.equal(r.json.status, 'done'); assert.equal(r.json.review, 'pending'); assert.equal(s.uac('Alia Synthetic'), '514', 'disabled at once');
  assert.equal((await s.call('GET', '/ad-manage', undefined, ADM)).json.reviews, 1);
  assert.equal((await s.call('POST', '/ad-manage/requests/' + r.json.id + '/review', { note: 'fine' }, ADM)).status, 403, 'not the requester');
  assert.equal((await s.call('POST', '/ad-manage/requests/' + r.json.id + '/review', {}, ADM2)).status, 400, 'a note is required');
  const v = await s.call('POST', '/ad-manage/requests/' + r.json.id + '/review', { note: 'confirmed with the SOC ticket' }, ADM2); assert.equal(v.json.review, 'done');
  assert.ok(s.audits('ad_manage.emergency_disable').length && s.audits('ad_manage.review').pop().by === ADM2.user);
});

test('groups, move and details; validation errors name the field', async (t) => {
  const s = await setup(t);
  const bad = async (b, re) => { const r = await req(s.call, Object.assign({ reason: 'synthetic test' }, b)); assert.equal(r.status, 400, JSON.stringify(b) + ' ' + r.raw); assert.match(r.json.error, re); };
  await bad({ action: 'explode', sam: 'alia.syn' }, /action must be one of/);
  await bad({ action: 'disable', sam: 'way.too.long.for.a.sam.name' }, /sam must be/);
  await bad({ action: 'disable', sam: 'alia.syn', reason: '' }, /reason is required/);
  await bad({ action: 'move', sam: 'alia.syn', ou: 'OU=X,DC=other,DC=com' }, /ou must be an OU inside/);
  await bad({ action: 'update', sam: 'alia.syn' }, /nothing to change/);
  await bad({ action: 'update', sam: 'alia.syn', telephoneNumber: 'call me' }, /telephoneNumber/);
  await bad({ action: 'create', sam: 'x.syn', given_name: 'X' }, /surname is required/);
  let r = await req(s.call, { action: 'add_group', sam: 'alia.syn', group: 'Claims-Team', reason: 'joined claims (synthetic)' });
  await s.call('POST', '/ad-manage/requests/' + r.json.id + '/approve', {}, ADM2);
  r = await req(s.call, { action: 'add_group', sam: 'alia.syn', group: 'Claims-Team', reason: 'again' }); assert.equal(r.status, 409, 'already a member');
  r = await req(s.call, { action: 'update', sam: 'alia.syn', title: 'Senior Claims Analyst', department: 'Claims', reason: 'promotion (synthetic)' }); assert.equal(r.status, 200, r.raw);
  r = await s.call('POST', '/ad-manage/requests/' + r.json.id + '/approve', {}, ADM2); assert.equal(r.status, 200, r.raw);
  assert.equal(s.dir.vals(s.dir.get('CN=Alia Synthetic,' + STAFF), 'title')[0], 'Senior Claims Analyst');
  r = await req(s.call, { action: 'move', sam: 'alia.syn', ou: 'OU=Leavers,' + BASE, reason: 'leaver (synthetic)' });
  r = await s.call('POST', '/ad-manage/requests/' + r.json.id + '/approve', {}, ADM2); assert.equal(r.status, 200, r.raw);
  assert.ok(s.dir.get('CN=Alia Synthetic,OU=Leavers,' + BASE), 'moved');
  r = await req(s.call, { action: 'remove_group', sam: 'alia.syn', group: 'Claims-Team', reason: 'left claims (synthetic)' }); assert.equal(r.status, 200, r.raw);
  r = await s.call('POST', '/ad-manage/requests/' + r.json.id + '/approve', {}, ADM2); assert.equal(r.status, 200, r.raw); assert.match(r.json.result, /removed from Claims-Team/);
});

test('unlock: only a locked-out account, the lockout source from the SIEM, four eyes, lockoutTime = 0 read back, the password untouched', async (t) => {
  const s = await setup(t);
  const lt = () => s.dir.vals(s.dir.get('CN=Gina Synthetic,' + STAFF), 'lockoutTime')[0];
  // no SIEM linked: the account still opens and says why there is no source
  let v = (await s.call('GET', '/ad-manage/user/gina.syn', undefined, OP)).json;
  assert.equal(v.locked, true); assert.match(v.lockout_time, /^2026-11-12T07:00/); assert.equal(v.lockout_source.available, false); assert.match(v.lockout_source.reason, /not linked/);
  assert.equal((await s.call('GET', '/ad-manage/user/hana.syn', undefined, OP)).json.locked, false, 'a lockout that ran out is not shown as locked');
  // the SIEM link (stubbed): asked as the analyst role for 4740 events of this account only
  const L = s.e.app.discovery.siem, asked = []; L.configured = () => true;
  L.call = async (m, p, who, b) => { asked.push({ m, p, who, b }); return { status: 200, json: { values: [{ v: 'WS-SYN-07', n: 4 }, { v: '', n: 1 }] } }; };
  v = (await s.call('GET', '/ad-manage/user/gina.syn', undefined, OP)).json;
  assert.deepEqual(v.lockout_source.sources, [{ computer: 'WS-SYN-07', lockouts: 4 }]);
  assert.equal(asked[0].p, '/top'); assert.equal(asked[0].who.role, 'analyst'); assert.match(asked[0].b.q, /action:account-locked AND target_user:"gina\.syn"/); assert.equal(asked[0].b.field, 'fields.caller_computer');
  // refused: not locked, privileged, operator, AI identity, no reason, emergency
  let r = await req(s.call, { action: 'unlock', sam: 'hana.syn', reason: 'synthetic test' }); assert.equal(r.status, 409); assert.match(r.json.error, /not locked out.*already run out/);
  r = await req(s.call, { action: 'unlock', sam: 'alia.syn', reason: 'synthetic test' }); assert.equal(r.status, 409); assert.match(r.json.error, /not locked out/);
  r = await req(s.call, { action: 'unlock', sam: 'badr.syn', reason: 'synthetic test' }); assert.equal(r.status, 403); assert.match(r.json.error, /privileged account/);
  assert.equal((await req(s.call, { action: 'unlock', sam: 'gina.syn', reason: 'synthetic test' }, OP)).status, 403, 'operators do not request');
  assert.equal((await req(s.call, { action: 'unlock', sam: 'gina.syn', reason: 'synthetic test' }, BOT)).status, 403, 'an AI identity does not request');
  r = await req(s.call, { action: 'unlock', sam: 'gina.syn' }); assert.equal(r.status, 400); assert.match(r.json.error, /reason is required/);
  r = await req(s.call, { action: 'unlock', sam: 'gina.syn', reason: 'synthetic test', emergency: true }); assert.equal(r.status, 400); assert.match(r.json.error, /emergency is only for disabling/);
  // requested: nothing written; the approver sees when and from where
  r = await req(s.call, { action: 'unlock', sam: 'gina.syn', reason: 'phone had the old password - removed (synthetic)' }); assert.equal(r.status, 200, r.raw);
  const id = r.json.id; assert.equal(r.json.status, 'pending'); assert.match(r.json.summary, /^unlock gina\.syn \(locked out 2026-11-12 07:00 UTC, from WS-SYN-07\)$/);
  assert.deepEqual(r.json.lockout.sources, [{ computer: 'WS-SYN-07', lockouts: 4 }]); assert.notEqual(lt(), '0', 'nothing written before approval');
  const ra = s.audits('ad_manage.request').pop(); assert.equal(ra.detail.action, 'unlock'); assert.equal(ra.by, ADM.user); assert.equal(ra.target, 'gina.syn');
  assert.equal((await s.call('POST', '/ad-manage/requests/' + id + '/approve', {}, ADM)).status, 403, 'four eyes');
  assert.equal((await s.call('POST', '/ad-manage/requests/' + id + '/approve', {}, BOT)).status, 403, 'an AI identity never approves');
  r = await s.call('POST', '/ad-manage/requests/' + id + '/approve', {}, ADM2); assert.equal(r.status, 200, r.raw);
  assert.equal(r.json.status, 'done'); assert.match(r.json.result, /^unlocked \(the password was not changed\)$/); assert.equal(lt(), '0', 'lockoutTime cleared');
  const mods = s.ldap.requests.filter((q) => q.op === 'modify' && /Gina/.test(q.dn));
  assert.deepEqual(mods.map((q) => q.changes.map((c) => c.attr + '=' + c.vals.join(','))), [['lockoutTime=0']], 'only lockoutTime is written - no password, no other attribute');
  const ap = s.audits('ad_manage.approve').pop(); assert.equal(ap.by, ADM2.user); assert.equal(ap.detail.requested_by, ADM.user); assert.equal(ap.detail.action, 'unlock');
  assert.equal((await s.call('GET', '/ad-manage/user/gina.syn', undefined, OP)).json.locked, false);
  // a SIEM that fails: the account still opens, the reason is given
  L.call = async () => { throw new Error('SIEM not reachable (ECONNREFUSED)'); };
  s.dir.set('CN=Gina Synthetic,' + STAFF, 'lockoutTime', [FT(Date.parse('2026-11-12T07:30:00Z'))]);
  v = (await s.call('GET', '/ad-manage/user/gina.syn', undefined, OP)).json; assert.equal(v.locked, true); assert.match(v.lockout_source.reason, /could not be read.*ECONNREFUSED/);
});

test('unlock: a lockout cleared in AD between request and approval is not written again', async (t) => {
  const s = await setup(t);
  let r = await req(s.call, { action: 'unlock', sam: 'gina.syn', reason: 'synthetic test' }); assert.equal(r.status, 200, r.raw);
  s.dir.set('CN=Gina Synthetic,' + STAFF, 'lockoutTime', ['0']);
  const before = s.ldap.requests.filter((q) => q.op === 'modify').length;
  r = await s.call('POST', '/ad-manage/requests/' + r.json.id + '/approve', {}, ADM2); assert.equal(r.status, 200, r.raw); assert.match(r.json.result, /already unlocked/);
  assert.equal(s.ldap.requests.filter((q) => q.op === 'modify').length, before, 'nothing written');
});
