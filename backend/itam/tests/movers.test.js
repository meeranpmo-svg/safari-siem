// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// HR movers (engine/movers.js) through the real routes against an in-process fake LDAPS directory: the account and its
// groups read before the request; groups to leave must be current memberships, groups to join only from the allowed list
// and never privileged; the receiving manager approves (never the requester), a DIFFERENT administrator approves the change;
// applied on the effective date at 06:00 Riyadh - groups left, groups joined, department / title updated, read back and
// verified; refused for a different employee number, a privileged account, the never-change list; a partial result recorded
// and retried; revert by a second administrator restores the groups and attributes; roles, validation, audit. SYNTHETIC.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs'), os = require('os'), path = require('path');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');
const { makeCA, makeServerCert } = require('./helpers/x509');
const { startFakeLdap, makeDirectory } = require('./helpers/fake-ldap');

const BASE = 'DC=corp-hq,DC=com', STAFF = 'OU=Staff,' + BASE, GR = 'OU=Groups,' + BASE, SVC = 'CN=svc-onboarding-syn,OU=Service,' + BASE, BIND_PW = 'Synthetic-Bind-Pass-9';
const PERSON = 'CN=Person,CN=Schema,CN=Configuration,' + BASE;
const HR = { user: 'hana.syn', role: 'operator' }, MGR = { user: 'nadia.syn', role: 'operator' }, DESK = { user: 'desk.syn', role: 'operator' };
const ADM = { user: 'syed', role: 'admin' }, ADM2 = { user: 'omar.syn', role: 'admin' }, VIEW = { user: 'vera.syn', role: 'viewer' }, BOT = { user: 'ai:desk', role: 'admin' };
const MOVE = { name: 'Sara Al-Ghamdi', employee_id: 'E-10442', username: 'sara.ghamdi', from_department: 'Claims', to_department: 'Underwriting', to_title: 'Underwriter', effective_date: '2026-11-01',
  manager: 'nadia.syn', remove_groups: ['GG-Claims-Users', 'SH-Claims-Files'], add_groups: ['GG-UW-Users'] };
const NOW = Date.parse('2026-10-28T08:00:00Z');

async function setup(t, o = {}) {
  const clock = { t: NOW };
  const ca = makeCA('Synthetic AD CA movers'), leaf = makeServerCert(ca, { cn: ('dc01.' + 'corp-hq.com'), dns: [('dc01.' + 'corp-hq.com')], ip: ['127.0.0.1'] });
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'mov-ad-')); t.after(() => fs.rmSync(tmp, { recursive: true, force: true }));
  const caFile = path.join(tmp, 'ad-root.pem'); fs.writeFileSync(caFile, ca.cert);
  const dir = makeDirectory();
  for (const ou of [BASE, 'OU=Service,' + BASE, STAFF, GR, 'OU=Joiners,' + BASE]) dir.add(ou, { objectClass: [ou === BASE ? 'domain' : 'organizationalUnit'] });
  dir.add(SVC, { objectClass: ['user'], objectCategory: PERSON, sAMAccountName: 'svc-onboarding-syn' });
  const u = (cn, sam, extra) => dir.add('CN=' + cn + ',' + STAFF, Object.assign({ objectClass: ['user'], objectCategory: PERSON, sAMAccountName: sam, displayName: cn, userAccountControl: '512', department: 'Claims', title: 'Claims Analyst' }, extra));
  u('Sara Al-Ghamdi', 'sara.ghamdi', { employeeID: 'E-10442' });
  u('Admin Person', 'admin.person', { employeeID: 'E-20003' });
  u('Break Glass', 'breakglass', {});
  for (const g of ['GG-Claims-Users', 'SH-Claims-Files', 'GG-UW-Users', 'GG-Finance', 'Helpdesk Admins']) dir.add('CN=' + g + ',' + GR, { objectClass: ['group'], sAMAccountName: g });
  dir.addMember('CN=GG-Claims-Users,' + GR, 'CN=Sara Al-Ghamdi,' + STAFF); dir.addMember('CN=SH-Claims-Files,' + GR, 'CN=Sara Al-Ghamdi,' + STAFF);
  dir.addMember('CN=Helpdesk Admins,' + GR, 'CN=Admin Person,' + STAFF);
  const ldap = await startFakeLdap({ key: leaf.key, cert: leaf.cert, dir, passwords: { [SVC]: BIND_PW }, readOnly: o.readOnly ? [SVC] : [] });
  t.after(() => ldap.close());
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true, now: () => clock.t, python: process.env.PYTHON || 'python3' });
  const call = (m, p, b, who) => e.req(m, p, Object.assign(b !== undefined ? { body: b } : {}, who));
  const post = (p, b, who) => call('POST', p, b, who), get = (p, who = DESK) => call('GET', p, undefined, who);
  if (o.ad !== false) {
    const r = await post('/onboarding/ad', { servers: ['ldaps://127.0.0.1:' + ldap.port], ca_file: caFile, bind_dn: SVC, bind_password: BIND_PW, base_dn: BASE, ou: 'OU=Joiners,' + BASE, upn_suffix: 'corp-hq.com',
      allowed_groups: ['GG-UW-Users', 'GG-Finance', 'GG-Claims-Users', 'SH-Claims-Files'], movers_enabled: true, never_disable: ['breakglass'] }, ADM);
    assert.equal(r.status, 200, JSON.stringify(r.json));
  }
  async function mover(extra = {}) {
    let r = await post('/movers', Object.assign({}, MOVE, extra), HR); assert.equal(r.status, 200, JSON.stringify(r.json));
    const id = r.json.id;
    r = await post('/movers/' + id + '/manager', { decision: 'approve' }, MGR); assert.equal(r.status, 200, JSON.stringify(r.json));
    return id;
  }
  return { e, dir, clock, post, get, mover };
}
const auditOf = (e, action) => e.app.store.auditTail(500).filter((x) => x.action === action);
const groupsOf = (dir, sam) => { const x = dir.all().find((y) => dir.vals(y, 'sAMAccountName')[0] === sam); return dir.vals(x, 'memberOf').map((d) => /^CN=([^,]+)/.exec(d)[1]).sort(); };
const attr = (dir, sam, a) => dir.vals(dir.all().find((y) => dir.vals(y, 'sAMAccountName')[0] === sam), a)[0];

test('the whole move: read, approved by the manager and a second administrator, applied on the effective date, reverted', async (t) => {
  const { e, dir, clock, post, get } = await setup(t);
  let r = await get('/movers/lookup?username=sara.ghamdi'); assert.equal(r.status, 200, JSON.stringify(r.json));
  assert.deepEqual(r.json.groups.sort(), ['GG-Claims-Users', 'SH-Claims-Files']); assert.ok(r.json.allowed_groups.includes('GG-UW-Users'));
  r = await post('/movers', MOVE, HR); assert.equal(r.status, 200, JSON.stringify(r.json));
  const id = r.json.id; assert.equal(id, 'MOV-001'); assert.deepEqual(r.json.directory.blockers, []);
  assert.equal((await post('/movers/' + id + '/manager', { decision: 'approve' }, HR)).status, 403, 'the requester cannot approve');
  assert.equal((await post('/movers/' + id + '/manager', { decision: 'approve' }, DESK)).status, 403, 'only the receiving manager or an admin');
  assert.equal((await post('/movers/' + id + '/approve', { decision: 'approve' }, ADM)).status, 409, 'not before the manager');
  r = await post('/movers/' + id + '/manager', { decision: 'approve' }, MGR); assert.equal(r.status, 200);
  assert.equal((await post('/movers/' + id + '/approve', { decision: 'approve' }, MGR)).status, 403, 'admin only');
  assert.equal((await post('/movers/' + id + '/approve', { decision: 'approve' }, BOT)).status, 403, 'never an AI identity');
  r = await post('/movers/' + id + '/approve', { decision: 'approve' }, ADM); assert.equal(r.status, 200, JSON.stringify(r.json));
  assert.equal(r.json.due_at, '2026-11-01T03:00:00.000Z', '06:00 Riyadh on the effective date');
  assert.deepEqual(groupsOf(dir, 'sara.ghamdi'), ['GG-Claims-Users', 'SH-Claims-Files'], 'nothing changes before the date');
  clock.t = Date.parse('2026-11-01T03:01:00Z');
  const x = await post('/movers/run', {}, ADM); assert.equal(x.json.applied, 1, JSON.stringify(x.json));
  assert.deepEqual(groupsOf(dir, 'sara.ghamdi'), ['GG-UW-Users'], 'left the old groups, joined the new one');
  assert.equal(attr(dir, 'sara.ghamdi', 'department'), 'Underwriting'); assert.equal(attr(dir, 'sara.ghamdi', 'title'), 'Underwriter');
  r = await get('/movers/' + id); assert.equal(r.json.status, 'completed'); assert.equal(r.json.applied.verified, true);
  assert.deepEqual(r.json.before.groups.sort(), ['GG-Claims-Users', 'SH-Claims-Files']);
  for (const a of ['movers.request', 'movers.manager', 'movers.change.approve', 'movers.applied', 'movers.run']) assert.ok(auditOf(e, a).length >= 1, a + ' audited');
  // revert: a second administrator
  assert.equal((await post('/movers/' + id + '/revert', { reason: 'move postponed' }, MGR)).status, 403);
  r = await post('/movers/' + id + '/revert', { reason: 'move postponed by HR' }, ADM); assert.equal(r.status, 200, JSON.stringify(r.json));
  assert.equal((await post('/movers/' + id + '/revert/decide', { decision: 'approve' }, ADM)).status, 403, 'not the person who asked');
  r = await post('/movers/' + id + '/revert/decide', { decision: 'approve' }, ADM2); assert.equal(r.status, 200, JSON.stringify(r.json));
  assert.deepEqual(groupsOf(dir, 'sara.ghamdi'), ['GG-Claims-Users', 'SH-Claims-Files'], 'restored');
  assert.equal(attr(dir, 'sara.ghamdi', 'department'), 'Claims'); assert.equal(attr(dir, 'sara.ghamdi', 'title'), 'Claims Analyst');
  assert.equal((await post('/movers/' + id + '/revert', { reason: 'again please' }, ADM)).status, 409, 'reverted once');
});

test('validation of the groups: current memberships to leave, allowed list to join, never privileged', async (t) => {
  const { post } = await setup(t);
  let r = await post('/movers', Object.assign({}, MOVE, { remove_groups: ['GG-Finance'] }), HR); assert.equal(r.status, 400); assert.match(r.json.error, /^remove_groups: sara\.ghamdi is not a member of GG-Finance/);
  r = await post('/movers', Object.assign({}, MOVE, { add_groups: ['GG-Secret-Project'] }), HR); assert.match(r.json.error, /^add_groups: GG-Secret-Project is not on the list/);
  r = await post('/movers', Object.assign({}, MOVE, { add_groups: ['Domain Admins'] }), HR); assert.match(r.json.error, /privileged/);
  r = await post('/movers', Object.assign({}, MOVE, { add_groups: ['GG-UW-Users'], remove_groups: ['GG-UW-Users'] }), HR); assert.match(r.json.error, /also in remove_groups/);
  r = await post('/movers', Object.assign({}, MOVE, { add_groups: [], remove_groups: [], update_attributes: false }), HR); assert.match(r.json.error, /nothing to change/);
  r = await post('/movers', Object.assign({}, MOVE, { username: 'Sara Ghamdi' }), HR); assert.match(r.json.error, /^username must be/);
  r = await post('/movers', Object.assign({}, MOVE, { effective_date: '2026-08-01' }), HR); assert.match(r.json.error, /more than 30 days ago/);
  r = await post('/movers', Object.assign({}, MOVE, { username: 'hana.syn' }), HR); assert.equal(r.status, 403, 'not your own account');
  r = await post('/movers', Object.assign({}, MOVE, { add_groups: ['GG-UW-Users', 'GG-Claims-Users'], remove_groups: ['SH-Claims-Files'] }), HR); assert.equal(r.status, 200);
  assert.deepEqual(r.json.add_groups, ['GG-UW-Users']); assert.deepEqual(r.json.already_member, ['GG-Claims-Users'], 'already a member is not joined twice');
  assert.equal((await post('/movers', MOVE, HR)).status, 409, 'one open request per person');
});

test('roles; refused accounts; the confirmer cannot approve; the mover cannot act', async (t) => {
  const { post, get, mover } = await setup(t);
  assert.equal((await get('/movers', VIEW)).status, 403); assert.equal((await post('/movers', MOVE, VIEW)).status, 403); assert.equal((await post('/movers', MOVE, BOT)).status, 403);
  assert.equal((await get('/movers/lookup?username=sara.ghamdi', VIEW)).status, 403);
  assert.equal((await post('/movers/run', {}, DESK)).status, 403);
  let id = await mover({ username: 'admin.person', employee_id: 'E-20003', remove_groups: [] });
  let r = await post('/movers/' + id + '/approve', { decision: 'approve' }, ADM); assert.equal(r.status, 409); assert.match(r.json.error, /privileged/);
  await post('/movers/' + id + '/cancel', { reason: 'done by a domain admin' }, HR);
  id = await mover({ username: 'breakglass', employee_id: 'E-1', remove_groups: [] });
  r = await post('/movers/' + id + '/approve', { decision: 'approve' }, ADM); assert.match(r.json.error, /never-change/);
  assert.equal((await post('/movers/' + id + '/cancel', { reason: 'my own request' }, { user: 'breakglass', role: 'admin' })).status, 403, 'the mover cannot act');
  await post('/movers/' + id + '/cancel', { reason: 'not needed' }, HR);
  r = await post('/movers', Object.assign({}, MOVE, { employee_id: 'E-99999' }), HR); assert.match(r.json.directory.blockers[0], /belongs to employee E-10442/);
  await post('/movers/' + r.json.id + '/cancel', { reason: 'wrong employee number' }, HR);
  // an admin manager approves as manager, then cannot approve the change
  r = await post('/movers', Object.assign({}, MOVE, { manager: 'omar.syn' }), HR);
  await post('/movers/' + r.json.id + '/manager', { decision: 'approve' }, ADM2);
  const x = await post('/movers/' + r.json.id + '/approve', { decision: 'approve' }, ADM2); assert.equal(x.status, 403); assert.match(x.json.error, /approved as the manager/);
});

test('a refused write is recorded, retried, then recorded by hand; an effective date in the past applies at approval', async (t) => {
  const { e, post, get, mover } = await setup(t, { readOnly: true });
  const id = await mover({ effective_date: '2026-10-27' });
  let r = await post('/movers/' + id + '/approve', { decision: 'approve' }, ADM); assert.equal(r.status, 200);
  assert.match(r.json.applied.error, /partly applied/); assert.ok(r.json.applied.results.some((x) => !x.ok && /50/.test(x.error)));
  assert.equal((await get('/movers')).json.counts.failed, 1);
  await e.app.addons.movers.runDue(null); assert.equal((await get('/movers/' + id)).json.applied.attempts, 1, 'not again within the hour');
  r = await post('/movers/' + id + '/retry', {}, ADM); assert.equal(r.json.applied.attempts, 2);
  assert.equal((await post('/movers/' + id + '/retry', {}, DESK)).status, 403);
  r = await post('/movers/' + id + '/applied', { directory_ref: 'changed in ADUC, CHG-5120' }, DESK); assert.equal(r.status, 200); assert.equal(r.json.status, 'completed');
  assert.ok(auditOf(e, 'movers.apply.failed').length >= 2 && auditOf(e, 'movers.applied.manual').length === 1);
});

test('without directory settings: manual record after the same two approvals', async (t) => {
  const { post, mover } = await setup(t, { ad: false });
  const id = await mover({ add_groups: ['Any-Group-Name'] });
  assert.equal((await post('/movers/' + id + '/applied', { directory_ref: 'CHG-1' }, DESK)).status, 409, 'not before approval');
  const r = await post('/movers/' + id + '/approve', { decision: 'approve' }, ADM); assert.equal(r.json.change.mode, 'manual');
  assert.equal((await post('/movers/' + id + '/applied', { directory_ref: 'changed in ADUC, CHG-5121' }, DESK)).status, 200);
});
