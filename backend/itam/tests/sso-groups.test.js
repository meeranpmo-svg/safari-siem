// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// SSO access from AD (engine/sso-groups.js + ad-writer.js directoryGroups / groupMembers nested) against an in-process fake AD over
// LDAPS with SYNTHETIC groups and people: groups read with their SID and the claim value Entra ID sends; members through nested
// groups; broad groups (Domain Users ...) refused; the preview gives each person the highest role and flags distribution groups,
// privileged accounts and members without a UPN; four-eyes (the proposer can neither approve nor apply; a service / AI identity
// cannot act); "applied" is refused unless the saved role map holds exactly the approved groups; nothing is written to AD; roles,
// validation and the audit record.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');
const { makeCA, makeServerCert } = require('./helpers/x509');
const { startFakeLdap, makeDirectory } = require('./helpers/fake-ldap');

const BASE = 'DC=corp-hq,DC=com', SVC = 'CN=svc-dir-syn,OU=Service,' + BASE, BIND_PW = 'Synthetic-Bind-Pass-8';
const OP = { user: 'nora.syn', role: 'operator' }, ADM = { user: 'syed', role: 'admin' }, ADM2 = { user: 'huda.syn', role: 'admin' }, VIEW = { user: 'vera.syn', role: 'viewer' }, BOT = { user: 'ai:desk', role: 'admin' };
const DOM = [21, 1004336348, 1177238915, 682003330];
function sid(rid) { const sub = [...DOM, rid], b = Buffer.alloc(8 + 4 * sub.length); b[0] = 1; b[1] = sub.length; b[7] = 5; sub.forEach((v, i) => b.writeUInt32LE(v >>> 0, 8 + 4 * i)); return b; }
const SIDS = (rid) => 'S-1-5-' + [...DOM, rid].join('-');
const SEC_GLOBAL = String(0x80000002 | 0), DIST = '2';

async function setup(t) {
  const ca = makeCA('Synthetic AD CA sso'), leaf = makeServerCert(ca, { cn: ('dc01.' + 'corp-hq.com'), dns: [('dc01.' + 'corp-hq.com')], ip: ['127.0.0.1'] });
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'sso-grp-')); t.after(() => fs.rmSync(tmp, { recursive: true, force: true }));
  const caFile = path.join(tmp, 'ad-root.pem'); fs.writeFileSync(caFile, ca.cert);
  const dir = makeDirectory();
  dir.add(BASE, { objectClass: ['domain'] }); ['Service', 'Staff', 'Groups'].forEach((o) => dir.add('OU=' + o + ',' + BASE, { objectClass: ['organizationalUnit'] }));
  dir.add(SVC, { objectClass: ['user'], cn: 'svc-dir-syn', sAMAccountName: 'svc-dir-syn' });
  const G = (cn, rid, type) => dir.add('CN=' + cn + ',OU=Groups,' + BASE, { objectClass: ['top', 'group'], cn, sAMAccountName: cn, objectSid: sid(rid), groupType: type || SEC_GLOBAL, description: 'synthetic ' + cn });
  G('SENTRA-SOC-Operators', 3101); G('SENTRA-Platform-Admins', 3102); G('SENTRA-Admins-Nested', 3103); G('Domain Users', 513); G('SENTRA-News', 3104, DIST);
  const P = (cn, sam, extra) => dir.add('CN=' + cn + ',OU=Staff,' + BASE, Object.assign({ objectClass: ['top', 'person', 'organizationalPerson', 'user'], objectCategory: 'person', cn, sAMAccountName: sam, userPrincipalName: sam + ('@' + 'corp-hq.com'), displayName: cn, userAccountControl: '512' }, extra));
  P('Alia Synthetic', 'alia.syn'); P('Badr Synthetic', 'badr.syn', { adminCount: '1' }); P('Coral Synthetic', 'coral.syn', { userAccountControl: '514' }); P('Dana Synthetic', 'dana.syn', { userPrincipalName: [] });
  const S = (cn) => 'CN=' + cn + ',OU=Staff,' + BASE, GR = (cn) => 'CN=' + cn + ',OU=Groups,' + BASE;
  dir.addMember(GR('SENTRA-SOC-Operators'), S('Alia Synthetic')); dir.addMember(GR('SENTRA-SOC-Operators'), S('Coral Synthetic')); dir.addMember(GR('SENTRA-SOC-Operators'), S('Dana Synthetic'));
  dir.addMember(GR('SENTRA-Admins-Nested'), S('Badr Synthetic')); dir.addMember(GR('SENTRA-Platform-Admins'), GR('SENTRA-Admins-Nested')); dir.addMember(GR('SENTRA-Platform-Admins'), S('Alia Synthetic'));
  dir.addMember(GR('Domain Users'), S('Alia Synthetic')); dir.addMember(GR('SENTRA-News'), S('Alia Synthetic'));
  const ldap = await startFakeLdap({ key: leaf.key, cert: leaf.cert, dir, passwords: { [SVC]: BIND_PW } }); t.after(() => ldap.close());
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true, python: process.env.PYTHON || 'python3' });
  const call = (m, p, b, who) => e.req(m, p, Object.assign(b !== undefined ? { body: b } : {}, who));
  const r = await call('POST', '/onboarding/ad', { enabled: true, servers: [ldap.url || 'ldaps://127.0.0.1:' + ldap.port], ca_file: caFile, bind_dn: SVC, bind_password: BIND_PW, base_dn: BASE, ou: 'OU=Staff,' + BASE, upn_suffix: 'corp-hq.com', allowed_groups: [] }, ADM);
  assert.equal(r.status, 200, r.raw);
  return { e, dir, ldap, call };
}
const tail = (e, action) => e.app.store.auditTail(200).filter((x) => x.action === action);

test('groups are read from AD with SID and the claim value; members through nested groups; nothing written; audited', async (t) => {
  const { e, ldap, call } = await setup(t);
  const before = ldap.requests.length;
  let r = await call('POST', '/sso-groups/refresh', {}, OP); assert.equal(r.status, 200, r.raw);
  const g = (s) => r.json.groups.items.find((x) => x.sam === s);
  assert.equal(g('SENTRA-SOC-Operators').sid, SIDS(3101)); assert.equal(g('SENTRA-SOC-Operators').security, true); assert.equal(g('SENTRA-SOC-Operators').claim, 'SENTRA-SOC-Operators', 'default claim: sAMAccountName');
  assert.equal(g('Domain Users').broad, true); assert.equal(g('SENTRA-News').security, false);
  r = await call('GET', '/sso-groups/members?group=SENTRA-Platform-Admins', undefined, OP); assert.equal(r.status, 200, r.raw);
  assert.deepEqual(r.json.members.map((m) => m.sam).sort(), ['alia.syn', 'badr.syn'], 'the member of the nested group counts, as Entra ID counts it');
  assert.ok(ldap.requests.slice(before).every((q) => /^(bind|search|unbind|extended|abandon)/i.test(String(q.op || q.type || q))), 'only binds and searches');
  assert.ok(tail(e, 'sso_groups.refresh').some((a) => a.by === OP.user && a.detail.groups === 5));
  assert.ok(tail(e, 'sso_groups.members').some((a) => a.target === 'SENTRA-Platform-Admins' && a.detail.members === 2), 'reading members (personal data) is audited');
  // the claim setting changes the value Entra ID is matched on
  assert.equal((await call('POST', '/sso-groups/settings', { claim: 'sid' }, OP)).status, 403, 'operators cannot change the claim');
  assert.equal((await call('POST', '/sso-groups/settings', { claim: 'upn' }, ADM)).status, 400);
  r = await call('POST', '/sso-groups/settings', { claim: 'netbios' }, ADM); assert.equal(r.status, 400); assert.match(r.json.error, /^netbios/);
  r = await call('POST', '/sso-groups/settings', { claim: 'netbios', netbios: 'corphq' }, ADM); assert.equal(r.status, 200);
  assert.equal(r.json.groups.items.find((x) => x.sam === 'SENTRA-SOC-Operators').claim, 'CORPHQ\\SENTRA-SOC-Operators');
  r = await call('POST', '/sso-groups/settings', { claim: 'dns' }, ADM); assert.equal(r.json.groups.items.find((x) => x.sam === 'SENTRA-SOC-Operators').claim, ('corp-hq.com' + '\\SENTRA-SOC-Operators'));
  r = await call('POST', '/sso-groups/settings', { claim: 'sid' }, ADM); assert.equal(r.json.groups.items.find((x) => x.sam === 'SENTRA-SOC-Operators').claim, SIDS(3101));
});

test('propose: broad groups refused; preview = highest role per person with the warnings; one open proposal', async (t) => {
  const { e, call } = await setup(t);
  await call('POST', '/sso-groups/refresh', {}, OP);
  let r = await call('POST', '/sso-groups/propose', { mappings: [{ group: 'Domain Users', role: 'viewer' }] }, ADM);
  assert.equal(r.status, 400); assert.match(r.json.error, /means everyone/);
  assert.equal((await call('POST', '/sso-groups/propose', { mappings: [] }, ADM)).status, 400);
  r = await call('POST', '/sso-groups/propose', { mappings: [{ group: 'SENTRA-SOC-Operators', role: 'superuser' }] }, ADM); assert.equal(r.status, 400); assert.match(r.json.error, /role/);
  r = await call('POST', '/sso-groups/propose', { mappings: [{ group: 'No-Such', role: 'viewer' }] }, ADM); assert.equal(r.status, 404);
  r = await call('POST', '/sso-groups/propose', { mappings: [{ group: 'SENTRA-SOC-Operators', role: 'operator' }, { group: 'SENTRA-SOC-Operators', role: 'viewer' }] }, ADM); assert.equal(r.status, 400); assert.match(r.json.error, /twice/);
  assert.equal((await call('POST', '/sso-groups/propose', { mappings: [{ group: 'SENTRA-SOC-Operators', role: 'operator' }] }, OP)).status, 403, 'operators cannot propose');
  assert.equal((await call('POST', '/sso-groups/propose', { mappings: [{ group: 'SENTRA-SOC-Operators', role: 'operator' }] }, BOT)).status, 403, 'an AI identity cannot propose');
  r = await call('POST', '/sso-groups/propose', { mappings: [{ group: 'SENTRA-SOC-Operators', role: 'operator' }, { group: 'SENTRA-Platform-Admins', role: 'admin' }, { group: 'SENTRA-News', role: 'viewer' }], note: 'go-live', extra: 'dropped' }, ADM);
  assert.equal(r.status, 200, r.raw);
  const p = r.json, who = (s) => p.preview.people.find((x) => x.sam === s);
  assert.equal(who('alia.syn').role, 'admin', 'in operators and admins: the highest role wins'); assert.equal(who('alia.syn').via.length, 3);
  assert.equal(who('badr.syn').role, 'admin', 'through the nested group'); assert.equal(who('coral.syn').enabled, false);
  assert.equal(p.preview.counts.admin, 2); assert.equal(p.preview.counts.disabled, 1);
  const kinds = p.preview.warnings.map((w) => w.kind).sort();
  assert.deepEqual(kinds, ['distribution', 'no-upn', 'privileged'], JSON.stringify(p.preview.warnings));
  assert.equal(p.status, 'proposed'); assert.equal(p.by, ADM.user); assert.ok(!('extra' in p));
  assert.ok(tail(e, 'sso_groups.propose').some((a) => a.by === ADM.user && a.target === p.id && a.detail.admins === 2));
  // a second proposal supersedes the first
  const r2 = await call('POST', '/sso-groups/propose', { mappings: [{ group: 'SENTRA-SOC-Operators', role: 'operator' }] }, ADM2);
  const v = (await call('GET', '/sso-groups', undefined, OP)).json;
  assert.equal(v.open.id, r2.json.id); assert.equal(v.history.find((h) => h.id === p.id).status, 'superseded');
  assert.equal((await call('GET', '/sso-groups', undefined, VIEW)).status, 403, 'member names are personal data: no viewers');
});

test('four-eyes: the proposer neither approves nor applies; applied must hold exactly the approved map; reject needs a reason', async (t) => {
  const { e, call } = await setup(t);
  await call('POST', '/sso-groups/refresh', {}, OP);
  const p = (await call('POST', '/sso-groups/propose', { mappings: [{ group: 'SENTRA-SOC-Operators', role: 'operator' }, { group: 'SENTRA-Platform-Admins', role: 'admin' }] }, ADM)).json;
  let r = await call('POST', '/sso-groups/' + p.id + '/approve', {}, ADM); assert.equal(r.status, 403); assert.match(r.json.error, /four-eyes/);
  assert.equal((await call('POST', '/sso-groups/' + p.id + '/approve', {}, BOT)).status, 403, 'an AI identity never approves');
  assert.equal((await call('POST', '/sso-groups/' + p.id + '/approve', {}, OP)).status, 403, 'an operator never approves');
  assert.equal((await call('POST', '/sso-groups/' + p.id + '/applied', { role_map: {}, role_claim: 'groups' }, ADM2)).status, 409, 'not approved yet');
  r = await call('POST', '/sso-groups/' + p.id + '/approve', {}, ADM2); assert.equal(r.status, 200, r.raw); assert.equal(r.json.approver, ADM2.user);
  assert.equal((await call('POST', '/sso-groups/' + p.id + '/approve', {}, ADM2)).status, 409, 'approved once');
  const good = { 'SENTRA-SOC-Operators': 'operator', 'SENTRA-Platform-Admins': 'admin', 'AS.Viewer.Legacy': 'viewer' };
  r = await call('POST', '/sso-groups/' + p.id + '/applied', { role_map: good, role_claim: 'groups', verified: true }, ADM); assert.equal(r.status, 403, 'the proposer does not apply');
  r = await call('POST', '/sso-groups/' + p.id + '/applied', { role_map: { 'SENTRA-SOC-Operators': 'admin', 'SENTRA-Platform-Admins': 'admin' }, role_claim: 'groups' }, ADM2);
  assert.equal(r.status, 400); assert.match(r.json.error, /must be operator/, 'a map that differs from the approval is refused');
  r = await call('POST', '/sso-groups/' + p.id + '/applied', { role_map: good, role_claim: 'roles' }, ADM2); assert.equal(r.status, 400); assert.match(r.json.error, /role_claim/);
  r = await call('POST', '/sso-groups/' + p.id + '/applied', { role_map: 'x', role_claim: 'groups' }, ADM2); assert.equal(r.status, 400); assert.match(r.json.error, /role_map/);
  r = await call('POST', '/sso-groups/' + p.id + '/applied', { role_map: { 'SENTRA-SOC-Operators': 'operator', 'SENTRA-Platform-Admins': 'god' }, role_claim: 'groups' }, ADM2); assert.equal(r.status, 400);
  r = await call('POST', '/sso-groups/' + p.id + '/applied', { role_map: good, role_claim: 'groups', verified: true }, ADM2); assert.equal(r.status, 200, r.raw);
  assert.equal(r.json.status, 'applied'); assert.deepEqual(r.json.keys, ['SENTRA-SOC-Operators', 'SENTRA-Platform-Admins']); assert.equal(r.json.verified, true);
  const v = (await call('GET', '/sso-groups', undefined, OP)).json; assert.equal(v.applied.id, p.id); assert.equal(v.open, null);
  const a = tail(e, 'sso_groups.applied').find((x) => x.target === p.id); assert.ok(a && a.by === ADM2.user && a.role === 'admin' && a.detail.verified === true);
  assert.ok(tail(e, 'sso_groups.approve').some((x) => x.by === ADM2.user && x.detail.proposer === ADM.user));
  // reject
  const q = (await call('POST', '/sso-groups/propose', { mappings: [{ group: 'SENTRA-SOC-Operators', role: 'viewer' }] }, ADM)).json;
  r = await call('POST', '/sso-groups/' + q.id + '/reject', {}, ADM2); assert.equal(r.status, 400); assert.match(r.json.error, /^reason/);
  r = await call('POST', '/sso-groups/' + q.id + '/reject', { reason: 'viewers come from HR groups' }, ADM2); assert.equal(r.status, 200); assert.equal(r.json.status, 'rejected');
  assert.equal((await call('POST', '/sso-groups/BAD-ID/approve', {}, ADM2)).status, 400, 'a malformed id names the field');
  const ap = (await call('GET', '/sso-groups', undefined, OP)).json.applied; assert.equal(ap.id, p.id, 'a rejected proposal leaves the applied mapping alone');
});

test('not connected: says how to connect; refresh and propose refused with the reason', async (t) => {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true, python: process.env.PYTHON || 'python3' });
  const call = (m, p, b, who) => e.req(m, p, Object.assign(b !== undefined ? { body: b } : {}, who));
  const v = (await call('GET', '/sso-groups', undefined, OP)).json; assert.equal(v.connection.ok, false); assert.match(v.connection.why, /Directory settings/);
  const r = await call('POST', '/sso-groups/refresh', {}, OP); assert.equal(r.status, 409);
  assert.equal((await call('POST', '/sso-groups/refresh', { q: 'bad(*)' }, OP)).status, 400, 'a group filter with LDAP characters is refused');
});

test('job roles for SSO users: a group gives the Penetration Testing Engineer role; synced from AD; hand-made wins; leavers lose it', async (t) => {
  const { e, dir, call } = await setup(t);
  assert.ok(e.app.roles && typeof e.app.roles.syncDerived === 'function', 'Roles & Functions is installed in the test engine');
  await call('POST', '/sso-groups/refresh', {}, OP);
  // the group role must be the job role's base level; an unknown job role is refused
  let r = await call('POST', '/sso-groups/propose', { mappings: [{ group: 'SENTRA-SOC-Operators', role: 'viewer', job_role: 'pentest-engineer' }] }, ADM);
  assert.equal(r.status, 400); assert.match(r.json.error, /base level operator/);
  r = await call('POST', '/sso-groups/propose', { mappings: [{ group: 'SENTRA-SOC-Operators', role: 'operator', job_role: 'no-such-role' }] }, ADM);
  assert.equal(r.status, 400); assert.match(r.json.error, /not a job role/);
  r = await call('POST', '/sso-groups/propose', { mappings: [{ group: 'SENTRA-SOC-Operators', role: 'operator', job_role: 'bad role!' }] }, ADM); assert.equal(r.status, 400); assert.match(r.json.error, /job_role/);
  // two different job roles for one person (alia is in both groups) are refused
  r = await call('POST', '/sso-groups/propose', { mappings: [{ group: 'SENTRA-SOC-Operators', role: 'operator', job_role: 'pentest-engineer' }, { group: 'SENTRA-Admins-Nested', role: 'operator', job_role: 'penetration-engineer' }, { group: 'SENTRA-Platform-Admins', role: 'operator', job_role: 'penetration-engineer' }] }, ADM);
  assert.equal(r.status, 400); assert.match(r.json.error, /two different job roles/);
  // alia gets admin through Platform-Admins, so her pentest job role does not apply; dana and coral (disabled) are in the group
  r = await call('POST', '/sso-groups/propose', { mappings: [{ group: 'SENTRA-SOC-Operators', role: 'operator', job_role: 'pentest-engineer' }, { group: 'SENTRA-Platform-Admins', role: 'admin' }] }, ADM);
  assert.equal(r.status, 200, r.raw);
  const who = (s) => r.json.preview.people.find((x) => x.sam === s);
  assert.equal(who('dana.syn').job_role, 'pentest-engineer'); assert.equal(who('alia.syn').job_role, undefined); assert.equal(who('alia.syn').job_dropped, 'Penetration Testing Engineer');
  assert.ok(r.json.preview.warnings.some((w) => w.kind === 'job-role-dropped'));
  assert.equal(r.json.mappings[0].job_role_name, 'Penetration Testing Engineer');
  // nothing assigned before it is approved and applied
  assert.ok(!(e.app.roles.list().assignments || []).some((a) => a.source === 'sso-group'), 'no job role before the approval');
  await call('POST', '/sso-groups/' + r.json.id + '/approve', {}, ADM2);
  const ap = await call('POST', '/sso-groups/' + r.json.id + '/applied', { role_map: { 'SENTRA-SOC-Operators': 'operator', 'SENTRA-Platform-Admins': 'admin' }, role_claim: 'groups', verified: true }, ADM2);
  assert.equal(ap.status, 200, ap.raw); assert.equal(ap.json.job_role_sync.synced, true, JSON.stringify(ap.json.job_role_sync));
  let A = e.app.roles.list().assignments.filter((a) => a.source === 'sso-group');
  assert.deepEqual(A.map((a) => a.user.toLowerCase()).sort(), ['dana.syn'], 'dana (no UPN) by sAMAccountName only; alia is admin; coral is disabled: ' + JSON.stringify(A));
  assert.equal(A[0].role_id, 'pentest-engineer'); assert.equal(A[0].via, 'SENTRA-SOC-Operators');
  // the same server-side limits as a local Penetration Testing Engineer: restricted to the pentest functions
  assert.deepEqual(e.app.roles.restrictionOf('dana.syn', 'operator'), ['vuln']);
  // a derived role is changed through the group, not by hand
  r = await call('POST', '/roles/assign', { user: 'dana.syn', role_id: 'network-engineer' }, ADM); assert.equal(r.status, 409); assert.match(r.json.error, /AD group SENTRA-SOC-Operators/);
  // badr joins the group but is an administrator through the nested admin group: no job role for him (never limit an admin)
  dir.addMember('CN=SENTRA-SOC-Operators,OU=Groups,' + BASE, 'CN=Badr Synthetic,OU=Staff,' + BASE);
  // a joiner: faris is added to the group in AD; Sync now gives the role under his sAMAccountName and UPN; audited
  dir.add('CN=Faris Synthetic,OU=Staff,' + BASE, { objectClass: ['top', 'person', 'organizationalPerson', 'user'], objectCategory: 'person', cn: 'Faris Synthetic', sAMAccountName: 'faris.syn', userPrincipalName: ('faris.syn@' + 'corp-hq.com'), displayName: 'Faris Synthetic', userAccountControl: '512' });
  dir.addMember('CN=SENTRA-SOC-Operators,OU=Groups,' + BASE, 'CN=Faris Synthetic,OU=Staff,' + BASE);
  assert.equal((await call('POST', '/sso-groups/sync', {}, OP)).status, 403, 'operators do not sync');
  r = await call('POST', '/sso-groups/sync', {}, ADM); assert.equal(r.status, 200, r.raw); assert.deepEqual(r.json.added.sort(), ['faris.syn', ('faris.syn@' + 'corp-hq.com')], 'badr (admin elsewhere) gets none');
  assert.ok(tail(e, 'sso_groups.sync').some((x) => x.by === ADM.user && x.detail.added.includes('faris.syn')));
  // a hand-made assignment (another person) is never touched by the sync
  r = await call('POST', '/roles/assign', { user: 'erin.syn', role_id: 'network-engineer' }, ADM); assert.equal(r.status, 200, r.raw);
  // a leaver: dana leaves the group; the next sync removes the job role
  const g = dir.get('CN=SENTRA-SOC-Operators,OU=Groups,' + BASE); g.attrs.member.vals = g.attrs.member.vals.filter((v) => !/Dana/.test(v));
  const dn = dir.get('CN=Dana Synthetic,OU=Staff,' + BASE); dn.attrs.memberof.vals = [];
  r = await e.app.addons.ssoGroups.sync({ user: 'system:sso-groups', role: 'admin' }, 'timer');
  assert.deepEqual(r.removed, ['dana.syn']);
  A = e.app.roles.list().assignments;
  assert.ok(!A.some((a) => a.user === 'dana.syn'), 'the leaver lost the job role'); assert.ok(A.some((a) => a.user === 'erin.syn' && !a.source), 'the hand-made assignment is untouched');
  const v = (await call('GET', '/sso-groups', undefined, OP)).json; assert.equal(v.last_sync.reason, 'timer'); assert.equal(v.derived.length, 2);
  assert.ok(v.job_roles.some((x) => x.id === 'pentest-engineer' && x.base === 'operator'));
});
