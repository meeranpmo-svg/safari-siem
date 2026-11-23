// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Directory users (engine/ad-directory.js + ad-writer.js directoryUsers) against an in-process fake AD over LDAPS with SYNTHETIC
// people, through the same directory settings HR onboarding saves: not connected says how to connect; a person reads the directory
// (name, UPN, mail, department, title, enabled, last sign-in, privileged); the group setting narrows it; nothing is written to the
// directory; roles (viewer refused, operator reads, admin sets the group, an AI identity cannot read), validation, audit.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');
const { makeCA, makeServerCert } = require('./helpers/x509');
const { startFakeLdap, makeDirectory } = require('./helpers/fake-ldap');

const BASE = 'DC=corp-hq,DC=com', SVC = 'CN=svc-dir-syn,OU=Service,' + BASE, BIND_PW = 'Synthetic-Bind-Pass-7';
const OP = { user: 'nora.syn', role: 'operator' }, ADM = { user: 'syed', role: 'admin' }, VIEW = { user: 'vera.syn', role: 'viewer' }, BOT = { user: 'ai:desk', role: 'operator' };
const FILETIME = (ms) => String((ms + 11644473600000) * 10000);

async function setup(t, connect = true) {
  const ca = makeCA('Synthetic AD CA directory'), leaf = makeServerCert(ca, { cn: ('dc01.' + 'corp-hq.com'), dns: [('dc01.' + 'corp-hq.com')], ip: ['127.0.0.1'] });
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'ad-dir-')); t.after(() => fs.rmSync(tmp, { recursive: true, force: true }));
  const caFile = path.join(tmp, 'ad-root.pem'); fs.writeFileSync(caFile, ca.cert);
  const dir = makeDirectory();
  dir.add(BASE, { objectClass: ['domain'] }); dir.add('OU=Service,' + BASE, { objectClass: ['organizationalUnit'] }); dir.add('OU=Staff,' + BASE, { objectClass: ['organizationalUnit'] });
  dir.add(SVC, { objectClass: ['user'], cn: 'svc-dir-syn', sAMAccountName: 'svc-dir-syn' });
  dir.add('OU=Groups,' + BASE, { objectClass: ['organizationalUnit'] });
  dir.add('CN=SENTRA-Platform-Users,OU=Groups,' + BASE, { objectClass: ['top', 'group'], cn: 'SENTRA-Platform-Users', sAMAccountName: 'SENTRA-Platform-Users' });
  const P = (cn, sam, extra) => dir.add('CN=' + cn + ',OU=Staff,' + BASE, Object.assign({ objectClass: ['top', 'person', 'organizationalPerson', 'user'], objectCategory: 'person', cn, sAMAccountName: sam, userPrincipalName: sam + ('@' + 'corp-hq.com'), displayName: cn, userAccountControl: '512' }, extra));
  P('Alia Synthetic', 'alia.syn', { mail: ('alia.syn@' + 'corp-hq.com'), department: 'Claims', title: 'Claims Analyst', lastLogonTimestamp: FILETIME(Date.parse('2026-11-01T07:00:00Z')) });
  P('Badr Synthetic', 'badr.syn', { department: 'IT', title: 'Domain Administrator', adminCount: '1' });
  P('Coral Synthetic', 'coral.syn', { department: 'Finance', userAccountControl: '514' });
  dir.addMember('CN=SENTRA-Platform-Users,OU=Groups,' + BASE, 'CN=Alia Synthetic,OU=Staff,' + BASE);
  const ldap = await startFakeLdap({ key: leaf.key, cert: leaf.cert, dir, passwords: { [SVC]: BIND_PW } });
  t.after(() => ldap.close());
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true, python: process.env.PYTHON || 'python3' });
  const call = (m, p, b, who) => e.req(m, p, Object.assign(b !== undefined ? { body: b } : {}, who));
  if (connect) {
    const r = await call('POST', '/onboarding/ad', { enabled: true, servers: [ldap.url || 'ldaps://127.0.0.1:' + ldap.port], ca_file: caFile, bind_dn: SVC, bind_password: BIND_PW, base_dn: BASE, ou: 'OU=Staff,' + BASE, upn_suffix: 'corp-hq.com', allowed_groups: [] }, ADM);
    assert.equal(r.status, 200, r.raw);
  }
  return { e, dir, ldap, call };
}

test('not connected: says how to connect, refresh refused with the reason', async (t) => {
  const { call } = await setup(t, false);
  const v = (await call('GET', '/ad-directory', undefined, OP)).json;
  assert.equal(v.connection.ok, false); assert.match(v.connection.why, /HR Onboarding -> Directory settings/);
  const r = await call('POST', '/ad-directory/refresh', {}, OP); assert.equal(r.status, 409); assert.match(r.json.error, /directory connection is not set/);
});

test('a person reads the directory: every field, enabled, privileged, last sign-in; nothing written; audited', async (t) => {
  const { e, ldap, call } = await setup(t);
  const before = ldap.requests.length;
  const r = await call('POST', '/ad-directory/refresh', {}, OP); assert.equal(r.status, 200, r.raw);
  const U = r.json.users, by = (s) => U.find((u) => u.sam === s);
  assert.deepEqual(U.map((u) => u.sam), ['alia.syn', 'badr.syn', 'coral.syn'], 'person accounts, sorted by name; the service account has no person category');
  assert.equal(by('alia.syn').upn, ('alia.syn@' + 'corp-hq.com')); assert.equal(by('alia.syn').mail, ('alia.syn@' + 'corp-hq.com')); assert.equal(by('alia.syn').department, 'Claims');
  assert.equal(by('alia.syn').last_logon, '2026-11-01T07:00:00.000Z'); assert.equal(by('alia.syn').groups, 1);
  assert.equal(by('coral.syn').enabled, false, 'disabled in AD'); assert.equal(by('badr.syn').admin_count, true, 'privileged account');
  assert.ok(ldap.requests.slice(before).every((q) => /^(bind|search|unbind|extended|abandon)/i.test(String(q.op || q.type || q))), 'only binds and searches: ' + JSON.stringify(ldap.requests.slice(before).map((q) => q.op || q.type)));
  const v = (await call('GET', '/ad-directory', undefined, OP)).json; assert.equal(v.last.count, 3); assert.equal(v.last.by, OP.user); assert.match(v.note, /does not give access/);
  const a = e.app.store.auditTail(50).find((x) => x.action === 'ad_directory.refresh'); assert.ok(a && a.by === OP.user && a.detail.users === 3 && a.detail.enabled === 2);
});

test('the group setting narrows the list; roles and validation', async (t) => {
  const { e, call } = await setup(t);
  assert.equal((await call('POST', '/ad-directory/settings', { group: 'SENTRA-Platform-Users' }, OP)).status, 403, 'operators cannot change the group');
  let r = await call('POST', '/ad-directory/settings', { group: 'bad(group)*' }, ADM); assert.equal(r.status, 400); assert.match(r.json.error, /group/);
  r = await call('POST', '/ad-directory/settings', { group: 'SENTRA-Platform-Users' }, ADM); assert.equal(r.status, 200, r.raw);
  r = await call('POST', '/ad-directory/refresh', {}, OP); assert.equal(r.status, 200, r.raw); assert.deepEqual(r.json.users.map((u) => u.sam), ['alia.syn']);
  r = await call('POST', '/ad-directory/settings', { group: 'No-Such-Group' }, ADM); assert.equal(r.status, 200);
  r = await call('POST', '/ad-directory/refresh', {}, OP); assert.equal(r.status, 424); assert.match(r.json.error, /not found in the directory/);
  assert.equal((await call('GET', '/ad-directory', undefined, VIEW)).status, 403, 'names and departments are personal data: no viewers');
  assert.equal((await call('POST', '/ad-directory/refresh', {}, BOT)).status, 403, 'an AI identity cannot read the directory');
  assert.ok(e.app.store.auditTail(50).some((x) => x.action === 'ad_directory.settings' && x.by === ADM.user));
});
