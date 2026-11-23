// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Just-in-time privileged access (engine/pam.js) through the real routes against an in-process fake LDAPS directory: eligible
// groups admin-only and validated (tier-0 groups refused, hours capped); a request checks the group, the hours, the ticket,
// the requester's own AD account and an existing permanent membership; approval by the named approver or an administrator,
// never the requester; granted at the start time and read back; removed at expiry and read back; a removal the directory
// refuses is retried every minute and shown; ended early by the requester; standing members listed; roles, audit. SYNTHETIC.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs'), os = require('os'), path = require('path');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');
const { makeCA, makeServerCert } = require('./helpers/x509');
const { startFakeLdap, makeDirectory } = require('./helpers/fake-ldap');

const BASE = 'DC=corp-hq,DC=com', STAFF = 'OU=Staff,' + BASE, GR = 'OU=Groups,' + BASE, SVC = 'CN=svc-onboarding-syn,OU=Service,' + BASE, BIND_PW = 'Synthetic-Bind-Pass-9';
const PERSON = 'CN=Person,CN=Schema,CN=Configuration,' + BASE;
const ENG = { user: 'sara.ghamdi', role: 'operator' }, ENG2 = { user: 'khalid.harbi', role: 'operator' }, LEAD = { user: 'nadia.syn', role: 'operator' };
const ADM = { user: 'syed', role: 'admin' }, VIEW = { user: 'vera.syn', role: 'viewer' }, BOT = { user: 'ai:desk', role: 'admin' };
const NOW = Date.parse('2026-10-28T08:00:00Z'), H = 3600000;

async function setup(t) {
  const clock = { t: NOW };
  const ca = makeCA('Synthetic AD CA pam'), leaf = makeServerCert(ca, { cn: ('dc01.' + 'corp-hq.com'), dns: [('dc01.' + 'corp-hq.com')], ip: ['127.0.0.1'] });
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'pam-ad-')); t.after(() => fs.rmSync(tmp, { recursive: true, force: true }));
  const caFile = path.join(tmp, 'ad-root.pem'); fs.writeFileSync(caFile, ca.cert);
  const dir = makeDirectory();
  for (const ou of [BASE, 'OU=Service,' + BASE, STAFF, GR, 'OU=Joiners,' + BASE]) dir.add(ou, { objectClass: [ou === BASE ? 'domain' : 'organizationalUnit'] });
  dir.add(SVC, { objectClass: ['user'], objectCategory: PERSON, sAMAccountName: 'svc-onboarding-syn' });
  const u = (cn, sam, extra) => dir.add('CN=' + cn + ',' + STAFF, Object.assign({ objectClass: ['user'], objectCategory: PERSON, sAMAccountName: sam, displayName: cn, userAccountControl: '512' }, extra));
  u('Sara Al-Ghamdi', 'sara.ghamdi', {}); u('Khalid Al-Harbi', 'khalid.harbi', {}); u('Nadia Lead', 'nadia.syn', {}); u('Old Admin', 'old.admin', {});
  for (const g of ['GG-Server-Admins', 'GG-Firewall-Admins']) dir.add('CN=' + g + ',' + GR, { objectClass: ['group'], sAMAccountName: g });
  dir.addMember('CN=GG-Server-Admins,' + GR, 'CN=Old Admin,' + STAFF);
  dir.addMember('CN=GG-Firewall-Admins,' + GR, 'CN=Khalid Al-Harbi,' + STAFF);
  const ldap = await startFakeLdap({ key: leaf.key, cert: leaf.cert, dir, passwords: { [SVC]: BIND_PW } });
  t.after(() => ldap.close());
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true, now: () => clock.t, python: process.env.PYTHON || 'python3' });
  const call = (m, p, b, who) => e.req(m, p, Object.assign(b !== undefined ? { body: b } : {}, who));
  const post = (p, b, who) => call('POST', p, b, who), get = (p, who = ENG) => call('GET', p, undefined, who);
  let r = await post('/onboarding/ad', { servers: ['ldaps://127.0.0.1:' + ldap.port], ca_file: caFile, bind_dn: SVC, bind_password: BIND_PW, base_dn: BASE, ou: 'OU=Joiners,' + BASE, upn_suffix: 'corp-hq.com' }, ADM);
  assert.equal(r.status, 200, JSON.stringify(r.json));
  r = await post('/pam/config', { groups: [{ name: 'GG-Server-Admins', max_hours: 8, approvers: ['nadia.syn'], ticket_required: true }, { name: 'GG-Firewall-Admins', max_hours: 4 }] }, ADM);
  assert.equal(r.status, 200, JSON.stringify(r.json));
  return { e, dir, ldap, clock, post, get };
}
const auditOf = (e, action) => e.app.store.auditTail(500).filter((x) => x.action === action);
const members = (dir, g) => dir.vals(dir.get('CN=' + g + ',' + GR), 'member').map((d) => /^CN=([^,]+)/.exec(d)[1]).sort();

test('requested, approved by the named approver, granted, removed at expiry - read back both times', async (t) => {
  const { e, dir, clock, post, get } = await setup(t);
  let r = await post('/pam/requests', { group: 'GG-Server-Admins', hours: 4, reason: 'patch window for the SQL cluster' }, ENG); assert.equal(r.status, 400); assert.match(r.json.error, /^ticket is required/);
  r = await post('/pam/requests', { group: 'GG-Server-Admins', hours: 9, reason: 'patch window for the SQL cluster', ticket: 'CHG-7001' }, ENG); assert.match(r.json.error, /at most 8 hour/);
  r = await post('/pam/requests', { group: 'GG-Server-Admins', hours: 4, reason: 'patch window for the SQL cluster', ticket: 'CHG-7001' }, ENG); assert.equal(r.status, 200, JSON.stringify(r.json));
  const id = r.json.id; assert.equal(id, 'PAR-0001'); assert.equal(r.json.status, 'pending');
  assert.equal((await post('/pam/requests', { group: 'GG-Server-Admins', hours: 1, reason: 'a second request for the same', ticket: 'CHG-7002' }, ENG)).status, 409, 'one open request per group');
  assert.equal((await post('/pam/requests/' + id + '/decide', { decision: 'approve' }, ENG)).status, 403, 'never the requester');
  assert.equal((await post('/pam/requests/' + id + '/decide', { decision: 'approve' }, ADM)).status, 403, 'the named approver only (not any admin)');
  assert.equal((await post('/pam/requests/' + id + '/decide', { decision: 'approve' }, BOT)).status, 403, 'never an AI identity');
  assert.equal((await get('/pam', LEAD)).json.to_approve.length, 1, 'waiting for the approver');
  r = await post('/pam/requests/' + id + '/decide', { decision: 'approve' }, LEAD); assert.equal(r.status, 200, JSON.stringify(r.json));
  assert.equal(r.json.status, 'active'); assert.equal(r.json.expires_at, new Date(NOW + 4 * H).toISOString()); assert.equal(r.json.minutes_left, 240);
  assert.deepEqual(members(dir, 'GG-Server-Admins'), ['Old Admin', 'Sara Al-Ghamdi'], 'added in the directory');
  clock.t = NOW + 3 * H; await e.app.addons.pam.tick(null); assert.ok(members(dir, 'GG-Server-Admins').includes('Sara Al-Ghamdi'), 'still there before expiry');
  clock.t = NOW + 4 * H + 1000; const x = await post('/pam/run', {}, ADM); assert.equal(x.json.expired, 1);
  assert.deepEqual(members(dir, 'GG-Server-Admins'), ['Old Admin'], 'removed at expiry');
  assert.equal((await get('/pam')).json.mine[0].status, 'expired');
  for (const a of ['pam.config', 'pam.request', 'pam.approve', 'pam.granted', 'pam.expired', 'pam.run']) assert.ok(auditOf(e, a).length >= 1, a + ' audited');
});

test('scheduled start, ended early, a refused removal is retried and shown, standing members listed', async (t) => {
  const { e, dir, ldap, clock, post, get } = await setup(t);
  let r = await post('/pam/requests', { group: 'GG-Server-Admins', hours: 2, reason: 'weekend maintenance on file servers', ticket: 'CHG-7100', start_at: new Date(NOW + 2 * H).toISOString() }, ENG2);
  assert.equal(r.status, 200, JSON.stringify(r.json));
  r = await post('/pam/requests/' + r.json.id + '/decide', { decision: 'approve' }, LEAD); assert.equal(r.json.status, 'approved', 'not before the start time');
  assert.ok(!members(dir, 'GG-Server-Admins').includes('Khalid Al-Harbi'));
  clock.t = NOW + 2 * H; await e.app.addons.pam.tick(null);
  assert.ok(members(dir, 'GG-Server-Admins').includes('Khalid Al-Harbi'), 'granted at the start time');
  assert.equal((await post('/pam/requests/PAR-0001/end', { reason: 'done early' }, ENG)).status, 403, 'only the requester or an admin');
  r = await post('/pam/requests/PAR-0001/end', { reason: 'work finished early' }, ENG2); assert.equal(r.status, 200, JSON.stringify(r.json)); assert.equal(r.json.status, 'ended');
  assert.ok(!members(dir, 'GG-Server-Admins').includes('Khalid Al-Harbi'));
  // a removal the directory refuses
  r = await post('/pam/requests', { group: 'GG-Firewall-Admins', hours: 1, reason: 'firewall rule change tonight' }, ENG);
  await post('/pam/requests/' + r.json.id + '/decide', { decision: 'approve' }, ADM);
  ldap.readOnly.add(SVC.toLowerCase());
  clock.t += 2 * H; await e.app.addons.pam.tick(null);
  let l = (await get('/pam', ADM)).json; assert.equal(l.counts.expire_failed, 1, 'shown as failed'); assert.ok(members(dir, 'GG-Firewall-Admins').includes('Sara Al-Ghamdi'));
  ldap.readOnly.delete(SVC.toLowerCase());
  clock.t += 60000; await e.app.addons.pam.tick(null);
  l = (await get('/pam', ADM)).json; assert.equal(l.counts.expire_failed, 0, 'retried and removed'); assert.ok(!members(dir, 'GG-Firewall-Admins').includes('Sara Al-Ghamdi'));
  assert.ok(auditOf(e, 'pam.remove_failed').length >= 1);
  // standing members
  const s = await get('/pam/standing', ADM); assert.equal(s.status, 200);
  assert.deepEqual(s.json.groups.find((g) => g.group === 'GG-Server-Admins').standing.map((x) => x.user), ['old.admin']);
  assert.deepEqual(s.json.groups.find((g) => g.group === 'GG-Firewall-Admins').standing.map((x) => x.user), ['khalid.harbi']);
  assert.equal((await get('/pam/standing', ENG)).status, 403);
});

test('roles and validation: tier-0 refused, already a member, viewer refused, reject needs a note', async (t) => {
  const { post, get } = await setup(t);
  assert.equal((await get('/pam', VIEW)).status, 403);
  assert.equal((await post('/pam/config', { groups: [] }, ENG)).status, 403);
  let r = await post('/pam/config', { groups: [{ name: 'Domain Admins', max_hours: 2 }] }, ADM); assert.equal(r.status, 400); assert.match(r.json.error, /tier-0/);
  r = await post('/pam/config', { groups: [{ name: 'GG-X', max_hours: 100 }] }, ADM); assert.match(r.json.error, /max_hours/);
  r = await post('/pam/config', { groups: [{ name: 'GG-X', max_hours: 2, approvers: ['ai:bot'] }] }, ADM); assert.match(r.json.error, /approvers/);
  r = await post('/pam/requests', { group: 'GG-Unknown', hours: 1, reason: 'not an eligible group at all' }, ENG); assert.match(r.json.error, /not a group that can be requested/);
  r = await post('/pam/requests', { group: 'GG-Firewall-Admins', hours: 1, reason: 'already a permanent member' }, ENG2); assert.equal(r.status, 409); assert.match(r.json.error, /permanent member/);
  r = await post('/pam/requests', { group: 'GG-Firewall-Admins', hours: 1, reason: 'short' }, ENG); assert.match(r.json.error, /^reason/);
  r = await post('/pam/requests', { group: 'GG-Firewall-Admins', hours: 1, reason: 'urgent firewall change' }, BOT); assert.equal(r.status, 403);
  r = await post('/pam/requests', { group: 'GG-Firewall-Admins', hours: 1, reason: 'urgent firewall change' }, ENG); assert.equal(r.status, 200);
  assert.equal((await post('/pam/requests/' + r.json.id + '/decide', { decision: 'reject' }, ADM)).status, 400, 'a note to reject');
  assert.equal((await post('/pam/requests/' + r.json.id + '/decide', { decision: 'reject', note: 'use the change window' }, ADM)).json.status, 'rejected');
});
