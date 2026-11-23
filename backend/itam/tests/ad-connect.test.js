// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Connect Active Directory (engine/ad-connect.js) against an in-process fake AD over LDAPS with SYNTHETIC people and a throw-away CA:
// domain controllers found in DNS (stubbed resolver), the DNS failure explained; the certificate presented and the root CA in its chain
// with fingerprints, a chain without its root explained, LDAPS off explained; sign-in with user@domain, wrong password / wrong CA /
// a privileged account refused with the reason; save -> the directory connection holds the CA, the account's DN, the base DN, and the
// user import (Directory users) reads through it; the automatic re-read; roles (operator / AI refused), validation, audit (no password).
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');
const { makeCA, makeServerCert } = require('./helpers/x509');
const { startFakeLdap, makeDirectory, deadPort } = require('./helpers/fake-ldap');

const BASE = 'DC=corp-hq,DC=com', SVC = 'CN=svc-read-syn,OU=Service,' + BASE, PW = 'Synthetic-Read-Pass-3', ADMPW = 'Synthetic-Admin-Pass-9';
const ADM = { user: 'syed', role: 'admin' }, OP = { user: 'nora.syn', role: 'operator' }, BOT = { user: 'ai:desk', role: 'admin' };
let T = Date.parse('2026-11-12T08:00:00Z');

async function setup(t, { chain = true, dns, ipSan = true } = {}) {
  const ca = makeCA('Synthetic Corp Root CA'), leaf = makeServerCert(ca, { cn: ('dc01.' + 'corp-hq.com'), dns: [('dc01.' + 'corp-hq.com')], ip: ipSan ? ['127.0.0.1'] : [] });
  const dir = makeDirectory();
  dir.add(BASE, { objectClass: ['domain'] }); dir.add('OU=Service,' + BASE, { objectClass: ['organizationalUnit'] }); dir.add('OU=Staff,' + BASE, { objectClass: ['organizationalUnit'] });
  dir.add('CN=Domain Admins,OU=Service,' + BASE, { objectClass: ['top', 'group'], cn: 'Domain Admins', sAMAccountName: 'Domain Admins' });
  dir.add(SVC, { objectClass: ['top', 'person', 'organizationalPerson', 'user'], cn: 'svc-read-syn', sAMAccountName: 'svc-read-syn', userPrincipalName: ('svc-read-syn@' + 'corp-hq.com'), userAccountControl: '512' });
  dir.add('CN=Admin Syn,OU=Service,' + BASE, { objectClass: ['top', 'person', 'organizationalPerson', 'user'], cn: 'Admin Syn', sAMAccountName: 'admin.syn', userPrincipalName: ('admin.syn@' + 'corp-hq.com'), userAccountControl: '512' });
  dir.addMember('CN=Domain Admins,OU=Service,' + BASE, 'CN=Admin Syn,OU=Service,' + BASE);
  const P = (cn, sam, uac) => dir.add('CN=' + cn + ',OU=Staff,' + BASE, { objectClass: ['top', 'person', 'organizationalPerson', 'user'], objectCategory: 'person', cn, sAMAccountName: sam, userPrincipalName: sam + ('@' + 'corp-hq.com'), displayName: cn, userAccountControl: uac || '512' });
  P('Alia Synthetic', 'alia.syn'); P('Badr Synthetic', 'badr.syn'); P('Coral Synthetic', 'coral.syn', '514');
  const ldap = await startFakeLdap({ key: leaf.key, cert: chain ? leaf.cert + ca.cert : leaf.cert, dir, passwords: { [SVC]: PW, ['CN=Admin Syn,OU=Service,' + BASE]: ADMPW } });
  t.after(() => ldap.close());
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true, now: () => T, python: process.env.PYTHON || 'python3', adConnectDns: dns || { resolveSrv: async () => [{ name: ('dc02.' + 'corp-hq.com' + '.'), port: 389, priority: 10, weight: 50 }, { name: ('dc01.' + 'corp-hq.com' + '.'), port: 389, priority: 0, weight: 100 }] } });
  const call = (m, p, b, who) => e.req(m, p, Object.assign(b !== undefined ? { body: b } : {}, who || ADM));
  const server = '127.0.0.1:' + ldap.port, dc = { name: ('dc01.' + 'corp-hq.com'), ip: '127.0.0.1', port: ldap.port };
  return { e, ca, leaf, dir, ldap, call, server, dc, audits: (a) => e.app.store.auditTail(300).filter((x) => x.action === a) };
}

test('discover: domain controllers from DNS in priority order; a DNS failure says what to fix; roles and validation', async (t) => {
  const s = await setup(t);
  assert.equal((await s.call('POST', '/ad-connect/discover', { domain: 'corp-hq.com' }, OP)).status, 403);
  assert.equal((await s.call('POST', '/ad-connect/discover', { domain: 'corp-hq.com' }, BOT)).status, 403, 'an AI identity does not connect the directory');
  let r = await s.call('POST', '/ad-connect/discover', { domain: 'not a domain' }); assert.equal(r.status, 400); assert.match(r.json.error, /domain must be/);
  r = await s.call('POST', '/ad-connect/discover', { domain: 'CORP-HQ.com' }); assert.equal(r.status, 200, r.raw);
  assert.deepEqual(r.json.servers.map((x) => x.url), [('ldaps://dc01.' + 'corp-hq.com' + ':636'), ('ldaps://dc02.' + 'corp-hq.com' + ':636')]); assert.equal(r.json.base_dn, BASE);
  assert.equal(s.audits('ad_connect.discover').pop().detail.found, 2);
  const f = await setup(t, { dns: { resolveSrv: async () => { throw Object.assign(new Error('queryA EAI_AGAIN'), { code: 'EAI_AGAIN' }); } } });
  r = await f.call('POST', '/ad-connect/discover', { domain: 'corp-hq.com' }); assert.equal(r.json.servers.length, 0); assert.match(r.json.why, /DNS server must be one of your domain controllers/);
});

test('certificate: the presented certificate and the root CA with fingerprints; no root sent and LDAPS off are explained', async (t) => {
  const s = await setup(t);
  let r = await s.call('POST', '/ad-connect/certificate', { server: s.server }); assert.equal(r.status, 200, r.raw);
  const { X509Certificate } = require('node:crypto');
  assert.equal(r.json.presented.fingerprint256, new X509Certificate(s.leaf.cert).fingerprint256);
  assert.equal(r.json.root.fingerprint256, new X509Certificate(s.ca.cert).fingerprint256); assert.match(r.json.root.subject, /Synthetic Corp Root CA/);
  assert.match(r.json.root.pem, /BEGIN CERTIFICATE/); assert.equal(r.json.name_matches, true); assert.match(r.json.how_to_check, /certlm\.msc/);
  assert.ok(s.ldap.requests.every((q) => q.op !== 'bind'), 'nothing sent over the untrusted handshake');
  const n = await setup(t, { chain: false });
  r = await n.call('POST', '/ad-connect/certificate', { server: n.server }); assert.equal(r.json.root, null); assert.match(r.json.why, /did not send its root CA - export it/);
  r = await s.call('POST', '/ad-connect/certificate', { server: '127.0.0.1:' + await deadPort() }); assert.equal(r.status, 424); assert.match(r.json.error, /LDAPS \(636\) is off/);
  r = await s.call('POST', '/ad-connect/certificate', { server: 'https://x' }); assert.equal(r.status, 400);
});

test('test: sign in with user@domain over verified LDAPS; wrong password, wrong CA, a leaf instead of a CA and a privileged account refused', async (t) => {
  const s = await setup(t);
  const B = (o) => Object.assign({ servers: [s.dc], ca_pem: s.ca.cert, user: ('svc-read-syn@' + 'corp-hq.com'), password: PW }, o);
  let r = await s.call('POST', '/ad-connect/test', B({ password: 'wrong-synthetic' })); assert.equal(r.status, 401); assert.match(r.json.error, /user name or password is wrong \(AD code 52e\)/);
  r = await s.call('POST', '/ad-connect/test', B({ ca_pem: s.leaf.cert })); assert.equal(r.status, 400); assert.match(r.json.error, /not a CA certificate/);
  r = await s.call('POST', '/ad-connect/test', B({ ca_pem: makeCA('Some Other CA').cert })); assert.equal(r.status, 424); assert.match(r.json.error, /not issued by the CA you confirmed/);
  r = await s.call('POST', '/ad-connect/test', B({ user: ('admin.syn@' + 'corp-hq.com'), password: ADMPW })); assert.equal(r.status, 403); assert.match(r.json.error, /privileged account \(Domain Admins\)/);
  r = await s.call('POST', '/ad-connect/test', B({ user: 'no at sign' })); assert.equal(r.status, 400); assert.match(r.json.error, /user must be/);
  r = await s.call('POST', '/ad-connect/test', B()); assert.equal(r.status, 200, r.raw);
  assert.equal(r.json.base_dn, BASE); assert.equal(r.json.bind_dn, SVC); assert.equal(r.json.people, 3); assert.equal(r.json.enabled, 2); assert.equal(r.json.domain, 'corp-hq.com');
  assert.equal((await s.call('GET', '/onboarding/ad', undefined, OP)).json.bind_dn, '', 'a test saves nothing');
  assert.ok(!JSON.stringify(s.e.app.store.auditTail(300)).includes(PW), 'the password is in no audit record');
});

test('save: the connection is set (CA, account DN, base DN) and the user import reads through it; the automatic re-read', async (t) => {
  const s = await setup(t);
  let r = await s.call('POST', '/ad-connect/save', { servers: [s.dc], ca_pem: s.ca.cert, user: ('svc-read-syn@' + 'corp-hq.com'), password: PW }); assert.equal(r.status, 200, r.raw); assert.equal(r.json.saved, true);
  const v = (await s.call('GET', '/onboarding/ad', undefined, OP)).json;
  assert.equal(v.bind_dn, SVC); assert.equal(v.base_dn, BASE); assert.equal(v.upn_suffix, 'corp-hq.com'); assert.equal(v.bind_password_set, true); assert.deepEqual(v.servers, [('ldaps://dc01.' + 'corp-hq.com' + ':') + s.ldap.port]); assert.deepEqual(v.server_ips, { ['dc01.' + 'corp-hq.com']: '127.0.0.1' });
  assert.equal(v.ca.source, 'settings'); assert.match(v.ca.subject, /Synthetic Corp Root CA/);
  assert.ok(s.audits('ad_connect.save').length && s.audits('onboarding.ad.settings').pop().detail.ca.startsWith('certificate '));
  assert.ok(!JSON.stringify(s.e.app.store.collection('onboarding_ad').all()).includes(PW), 'the password is sealed, not stored in plain');
  r = await s.call('POST', '/ad-directory/refresh', {}, OP); assert.equal(r.status, 200, r.raw); assert.equal(r.json.users.length, 3, 'the user import reads through the new connection');
  // the automatic re-read
  r = await s.call('POST', '/ad-directory/settings', { group: '', auto_hours: 7 }); assert.equal(r.status, 400); assert.match(r.json.error, /auto_hours/);
  r = await s.call('POST', '/ad-directory/settings', { group: '', auto_hours: 24 }); assert.equal(r.status, 200); assert.equal(r.json.settings.auto_hours, 24);
  const D = s.e.app.addons.adDirectory;
  assert.equal(await D.tick(), false, 'read an hour ago: not due');
  T += 25 * 3600000; assert.equal(await D.tick(), true, 'due after 24 h');
  const a = s.audits('ad_directory.auto_refresh').pop(); assert.equal(a.by, 'system:ad-directory'); assert.equal(a.detail.users, 3);
  assert.equal((await s.call('POST', '/ad-directory/refresh', {}, { user: 'system:ad-directory', role: 'operator' })).status, 403, 'the system identity cannot use the person\'s button');
});

test('a domain controller typed as an IP address: the certificate names it, the IP is dialled and the certificate verified under that name', async (t) => {
  const s = await setup(t, { ipSan: false });   // like a real DC: the certificate carries its DNS name, not its address
  let r = await s.call('POST', '/ad-connect/certificate', { server: s.server }); assert.equal(r.status, 200, r.raw);
  assert.equal(r.json.ip, '127.0.0.1'); assert.equal(r.json.verify_as, ('dc01.' + 'corp-hq.com')); assert.equal(r.json.name_matches, true);
  assert.match(r.json.by_ip, new RegExp('You typed an IP address\\. The certificate is for dc01\\.' + 'corp-hq\\.com'));
  const B = (servers) => ({ servers, ca_pem: s.ca.cert, user: ('svc-read-syn@' + 'corp-hq.com'), password: PW });
  r = await s.call('POST', '/ad-connect/test', B(['127.0.0.1:' + s.ldap.port])); assert.equal(r.status, 400); assert.match(r.json.error, /is an IP address - give \{name, ip\}/);
  r = await s.call('POST', '/ad-connect/test', B([{ name: ('wrong.' + 'corp-hq.com' + ':') + s.ldap.port, ip: '127.0.0.1' }])); assert.equal(r.status, 400, 'the name must be a plain DC name');
  r = await s.call('POST', '/ad-connect/test', B([{ name: ('other.' + 'corp-hq.com'), ip: 'not-an-ip' }])); assert.equal(r.status, 400); assert.match(r.json.error, /is not an IP address/);
  const port = s.ldap.port;
  r = await s.call('POST', '/ad-connect/test', B([{ name: ('other.' + 'corp-hq.com'), ip: '127.0.0.1', port }])); assert.equal(r.status, 424); assert.match(r.json.error, /certificate is not for the name|not issued by the CA/, 'a name the certificate is not for is still refused');
  r = await s.call('POST', '/ad-connect/test', B([{ name: ('dc01.' + 'corp-hq.com'), ip: '127.0.0.1', port }])); assert.equal(r.status, 200, r.raw); assert.equal(r.json.base_dn, BASE);
  r = await s.call('POST', '/ad-connect/save', B([{ name: ('dc01.' + 'corp-hq.com'), ip: '127.0.0.1', port }])); assert.equal(r.status, 200, r.raw);
  const v = (await s.call('GET', '/onboarding/ad', undefined, OP)).json;
  assert.deepEqual(v.servers, [('ldaps://dc01.' + 'corp-hq.com' + ':') + port]); assert.deepEqual(v.server_ips, { ['dc01.' + 'corp-hq.com']: '127.0.0.1' });
  r = await s.call('POST', '/ad-directory/refresh', {}, OP); assert.equal(r.status, 200, r.raw); assert.equal(r.json.users.length, 3, ('the import dials the IP and verifies the certificate as dc01.' + 'corp-hq.com'));
  r = await s.call('POST', '/onboarding/ad', { server_ips: { ['dc01.' + 'corp-hq.com']: 'nope' } }); assert.equal(r.status, 400); assert.match(r.json.error, /server_ips/);
});

test('a domain controller NAME the platform cannot resolve: the failure asks for its IP; with it, the IP is dialled and the certificate verified as the name', async (t) => {
  const s = await setup(t, { ipSan: false });
  const name = ('dc01.' + 'corp-hq.com' + ':') + s.ldap.port;   // not in the test machine's DNS
  let r = await s.call('POST', '/ad-connect/certificate', { server: name }); assert.equal(r.status, 424);
  assert.match(r.json.error, new RegExp('cannot resolve dc01\\.' + 'corp-hq\\.com' + ' .* - or give its IP address: the platform connects to the IP and still verifies the certificate as dc01\\.' + 'corp-hq\\.com'));
  r = await s.call('POST', '/ad-connect/certificate', { server: name, ip: '127.0.0.1' }); assert.equal(r.status, 200, r.raw);
  assert.equal(r.json.host, ('dc01.' + 'corp-hq.com')); assert.equal(r.json.ip, '127.0.0.1'); assert.equal(r.json.verify_as, ('dc01.' + 'corp-hq.com')); assert.equal(r.json.name_matches, true); assert.equal(r.json.by_ip, '', 'a name was given: nothing to explain');
  r = await s.call('POST', '/ad-connect/certificate', { server: name, ip: 'x' }); assert.equal(r.status, 400); assert.match(r.json.error, /ip must be an IP address/);
  r = await s.call('POST', '/ad-connect/certificate', { server: '127.0.0.1:' + s.ldap.port, ip: '127.0.0.1' }); assert.equal(r.status, 400); assert.match(r.json.error, /already an address/);
  r = await s.call('POST', '/ad-connect/certificate', { server: ('other.' + 'corp-hq.com' + ':') + s.ldap.port, ip: '127.0.0.1' }); assert.equal(r.status, 200); assert.equal(r.json.name_matches, false, 'the certificate is not for that name - shown, and the sign-in test refuses it');
});
