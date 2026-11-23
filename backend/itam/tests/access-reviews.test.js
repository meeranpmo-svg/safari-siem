// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Quarterly access reviews of AD groups (engine/access-reviews.js) through the real routes against an in-process fake LDAPS
// directory: scope admin-only and validated; a campaign reads each group's members with their manager (AD "manager"),
// state, last sign-in; reviewer = the manager, else the group's fallback, never the member; only the reviewer decides, a
// reason to remove and to keep a disabled / dormant account; signing needs every line decided and locks them; removals
// approved by an administrator who is not the reviewer, applied in the directory and read back - privileged groups by
// hand; reassign; reminders through the relay; close lists exceptions; the next quarter flags new members; CSV evidence
// audited; roles; the automatic quarterly start. SYNTHETIC data only.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs'), os = require('os'), path = require('path');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');
const { makeCA, makeServerCert } = require('./helpers/x509');
const { startFakeLdap, makeDirectory } = require('./helpers/fake-ldap');

const BASE = 'DC=corp-hq,DC=com', STAFF = 'OU=Staff,' + BASE, GR = 'OU=Groups,' + BASE, SVC = 'CN=svc-onboarding-syn,OU=Service,' + BASE, BIND_PW = 'Synthetic-Bind-Pass-9';
const PERSON = 'CN=Person,CN=Schema,CN=Configuration,' + BASE;
const MGR = { user: 'nadia.syn', role: 'operator' }, MGR2 = { user: 'faisal.syn', role: 'operator' }, DESK = { user: 'desk.syn', role: 'operator' };
const ADM = { user: 'syed', role: 'admin' }, ADM2 = { user: 'omar.syn', role: 'admin' }, VIEW = { user: 'vera.syn', role: 'viewer' }, BOT = { user: 'ai:desk', role: 'admin' };
const FILETIME = (ms) => String((ms + 11644473600000) * 10000);
const NOW = Date.parse('2026-10-28T08:00:00Z');

async function setup(t, o = {}) {
  const clock = { t: NOW };
  const ca = makeCA('Synthetic AD CA reviews'), leaf = makeServerCert(ca, { cn: ('dc01.' + 'corp-hq.com'), dns: [('dc01.' + 'corp-hq.com')], ip: ['127.0.0.1'] });
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'ar-ad-')); t.after(() => fs.rmSync(tmp, { recursive: true, force: true }));
  const caFile = path.join(tmp, 'ad-root.pem'); fs.writeFileSync(caFile, ca.cert);
  const dir = makeDirectory();
  for (const ou of [BASE, 'OU=Service,' + BASE, STAFF, GR, 'OU=Joiners,' + BASE]) dir.add(ou, { objectClass: [ou === BASE ? 'domain' : 'organizationalUnit'] });
  dir.add(SVC, { objectClass: ['user'], objectCategory: PERSON, sAMAccountName: 'svc-onboarding-syn' });
  const u = (cn, sam, extra) => dir.add('CN=' + cn + ',' + STAFF, Object.assign({ objectClass: ['user'], objectCategory: PERSON, sAMAccountName: sam, displayName: cn, userAccountControl: '512', lastLogonTimestamp: FILETIME(NOW - 2 * 86400000) }, extra));
  u('Nadia Manager', 'nadia.syn', {}); u('Faisal Manager', 'faisal.syn', {});
  u('Sara Al-Ghamdi', 'sara.ghamdi', { manager: 'CN=Nadia Manager,' + STAFF, employeeID: 'E-1' });
  u('Khalid Al-Harbi', 'khalid.harbi', { manager: 'CN=Nadia Manager,' + STAFF, employeeID: 'E-2', lastLogonTimestamp: FILETIME(NOW - 200 * 86400000) });
  u('Omar Old', 'omar.old', { manager: 'CN=Faisal Manager,' + STAFF, userAccountControl: '514' });
  u('No Manager', 'no.manager', {});
  for (const g of ['GG-Claims-Users', 'Helpdesk Admins']) dir.add('CN=' + g + ',' + GR, { objectClass: ['group'], sAMAccountName: g });
  for (const s of ['sara.ghamdi', 'khalid.harbi', 'omar.old', 'no.manager', 'nadia.syn']) dir.addMember('CN=GG-Claims-Users,' + GR, dir.all().find((x) => dir.vals(x, 'sAMAccountName')[0] === s).dn);
  dir.addMember('CN=Helpdesk Admins,' + GR, 'CN=Sara Al-Ghamdi,' + STAFF);
  const ldap = await startFakeLdap({ key: leaf.key, cert: leaf.cert, dir, passwords: { [SVC]: BIND_PW } });
  t.after(() => ldap.close());
  const mails = [];
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true, now: () => clock.t, python: process.env.PYTHON || 'python3', privacyOffice: { send: async (s, m) => { mails.push(m); return { accepted: m.to }; } } });
  const call = (m, p, b, who) => e.req(m, p, Object.assign(b !== undefined ? { body: b } : {}, who));
  const post = (p, b, who) => call('POST', p, b, who), get = (p, who = DESK) => call('GET', p, undefined, who);
  let r = await post('/onboarding/ad', { servers: ['ldaps://127.0.0.1:' + ldap.port], ca_file: caFile, bind_dn: SVC, bind_password: BIND_PW, base_dn: BASE, ou: 'OU=Joiners,' + BASE, upn_suffix: 'corp-hq.com' }, ADM);
  assert.equal(r.status, 200, JSON.stringify(r.json));
  r = await post('/access-reviews/config', { groups: [{ name: 'GG-Claims-Users', fallback_reviewer: 'faisal.syn' }, { name: 'Helpdesk Admins', fallback_reviewer: 'omar.syn' }], due_days: 21, auto_remove: o.autoRemove !== false }, ADM);
  assert.equal(r.status, 200, JSON.stringify(r.json));
  return { e, dir, clock, mails, post, get };
}
const auditOf = (e, action) => e.app.store.auditTail(800).filter((x) => x.action === action);
const line = (items, g, u) => items.find((x) => x.group === g && x.user === u);
const members = (dir, g) => dir.vals(dir.get('CN=' + g + ',' + GR), 'member').map((d) => /^CN=([^,]+)/.exec(d)[1]).sort();

test('a quarter end to end: members read, managers attest, removals approved and applied, closed with evidence', async (t) => {
  const { e, dir, mails, post, get } = await setup(t);
  await post('/pdpl/office/notify', { email_enabled: true, smtp: { host: 'smtp.corp.syn', port: 25, from: 'grc@corp.syn' } }, ADM);
  assert.equal((await post('/pdpl/office/contacts', { contacts: [{ user: 'nadia.syn', email: 'nadia@corp.syn' }, { user: 'faisal.syn', email: 'faisal@corp.syn' }] }, ADM)).status, 200);
  assert.equal((await post('/access-reviews', {}, DESK)).status, 403, 'starting is admin only');
  let r = await post('/access-reviews', {}, ADM); assert.equal(r.status, 200, JSON.stringify(r.json));
  const id = r.json.id; assert.equal(id, 'AR-2026-Q4'); assert.equal(r.json.counts.lines, 6);
  assert.equal((await post('/access-reviews', {}, ADM)).status, 409, 'one campaign per quarter');
  let it = (await get('/access-reviews/' + id + '/items', ADM)).json.items;
  assert.equal(line(it, 'GG-Claims-Users', 'sara.ghamdi').reviewer, 'nadia.syn', 'the manager reviews');
  assert.equal(line(it, 'GG-Claims-Users', 'no.manager').reviewer, 'faisal.syn'); assert.equal(line(it, 'GG-Claims-Users', 'no.manager').reviewer_source, 'group fallback');
  assert.equal(line(it, 'GG-Claims-Users', 'khalid.harbi').dormant, true); assert.equal(line(it, 'GG-Claims-Users', 'omar.old').enabled, false);
  assert.equal(line(it, 'Helpdesk Admins', 'sara.ghamdi').privileged_group, true);
  assert.ok(mails.some((m) => /Access review 2026-Q4/.test(m.subject)), 'reviewers are told');
  // Nadia's lines
  const mine = (await get('/access-reviews/' + id + '/items?mine=1', MGR)).json.items;
  assert.deepEqual(mine.map((x) => x.group + ':' + x.user).sort(), ['GG-Claims-Users:khalid.harbi', 'GG-Claims-Users:sara.ghamdi', 'Helpdesk Admins:sara.ghamdi']);
  const L = (g, u) => line(mine, g, u).id;
  assert.equal((await post('/access-reviews/' + id + '/decide', { decisions: [{ item: L('GG-Claims-Users', 'sara.ghamdi'), decision: 'keep' }] }, MGR2)).status, 403, 'only the assigned reviewer');
  r = await post('/access-reviews/' + id + '/decide', { decisions: [{ item: L('GG-Claims-Users', 'khalid.harbi'), decision: 'keep' }] }, MGR); assert.equal(r.status, 400); assert.match(r.json.error, /dormant/);
  r = await post('/access-reviews/' + id + '/decide', { decisions: [{ item: L('Helpdesk Admins', 'sara.ghamdi'), decision: 'remove' }] }, MGR); assert.match(r.json.error, /reason is required to remove/);
  assert.equal((await post('/access-reviews/' + id + '/sign', { statement: true }, MGR)).status, 409, 'not before every line is decided');
  r = await post('/access-reviews/' + id + '/decide', { decisions: [
    { item: L('GG-Claims-Users', 'sara.ghamdi'), decision: 'keep' },
    { item: L('GG-Claims-Users', 'khalid.harbi'), decision: 'remove', reason: 'moved to Finance in August' },
    { item: L('Helpdesk Admins', 'sara.ghamdi'), decision: 'remove', reason: 'helpdesk rota ended' }] }, MGR); assert.equal(r.status, 200, JSON.stringify(r.json));
  assert.equal((await post('/access-reviews/' + id + '/sign', { statement: false }, MGR)).status, 400);
  r = await post('/access-reviews/' + id + '/sign', { statement: true }, MGR); assert.equal(r.status, 200, JSON.stringify(r.json));
  assert.equal((await post('/access-reviews/' + id + '/decide', { decisions: [{ item: L('GG-Claims-Users', 'sara.ghamdi'), decision: 'remove', reason: 'changed my mind' }] }, MGR)).status, 409, 'signed lines are locked');
  // nadia is herself a member: reviewed by the fallback, never by herself
  it = (await get('/access-reviews/' + id + '/items', ADM)).json.items;
  assert.equal(line(it, 'GG-Claims-Users', 'nadia.syn').reviewer, 'faisal.syn');
  // removals: four eyes
  const rm = [L('GG-Claims-Users', 'khalid.harbi'), L('Helpdesk Admins', 'sara.ghamdi')];
  assert.equal((await post('/access-reviews/' + id + '/removals/decide', { items: rm, decision: 'approve' }, { user: 'nadia.syn', role: 'admin' })).status, 403, 'not the reviewer');
  r = await post('/access-reviews/' + id + '/removals/decide', { items: rm, decision: 'approve' }, ADM); assert.equal(r.status, 200, JSON.stringify(r.json));
  assert.deepEqual(r.json.result, { removed: 1, manual: 1, failed: 0 }, 'the privileged group is left to a domain administrator');
  assert.ok(!members(dir, 'GG-Claims-Users').includes('Khalid Al-Harbi'), 'removed in the directory');
  assert.ok(members(dir, 'Helpdesk Admins').includes('Sara Al-Ghamdi'), 'privileged group untouched');
  assert.equal((await post('/access-reviews/' + id + '/removals/done', { items: [rm[1]], directory_ref: 'removed in ADUC, CHG-6001' }, DESK)).status, 200);
  // the rest: faisal + reassign
  const fl = (await get('/access-reviews/' + id + '/items?mine=1', MGR2)).json.items;
  r = await post('/access-reviews/' + id + '/reassign', { items: [line(fl, 'GG-Claims-Users', 'nadia.syn').id], reviewer: 'nadia.syn', reason: 'testing self review' }, ADM); assert.equal(r.status, 400, 'never to the member herself');
  r = await post('/access-reviews/' + id + '/decide', { decisions: fl.map((x) => ({ item: x.id, decision: 'keep', reason: 'still needed for the claims system' })) }, MGR2); assert.equal(r.status, 200, JSON.stringify(r.json));
  await post('/access-reviews/' + id + '/sign', { statement: true }, MGR2);
  r = await post('/access-reviews/' + id + '/close', { note: 'Q4 done' }, ADM); assert.equal(r.status, 200);
  assert.deepEqual(r.json.exceptions, { not_decided: 0, not_signed: 0, removal_not_approved: 0, removal_not_done: 0 });
  const x = await get('/access-reviews/' + id + '/export'); assert.equal(x.status, 200); assert.match(x.json.csv, /"moved to Finance in August"/); assert.match(x.json.csv, /"attestation"/);
  for (const a of ['access-reviews.config', 'access-reviews.start', 'access-reviews.decide', 'access-reviews.attest', 'access-reviews.removals.approve', 'access-reviews.removed', 'access-reviews.removed.manual', 'access-reviews.close', 'access-reviews.export'])
    assert.ok(auditOf(e, a).length >= 1, a + ' audited');
});

test('the next quarter flags new members; close lists exceptions; automatic start on the first day', async (t) => {
  const { e, dir, clock, post, get } = await setup(t);
  let r = await post('/access-reviews', {}, ADM); const q4 = r.json.id;
  r = await post('/access-reviews/' + q4 + '/close', {}, ADM); assert.equal(r.json.exceptions.not_decided, 6, 'nothing attested is an exception');
  dir.addMember('CN=Helpdesk Admins,' + GR, 'CN=Khalid Al-Harbi,' + STAFF);
  await post('/access-reviews/config', { auto_start: true }, ADM);
  clock.t = Date.parse('2027-01-01T00:30:00Z');   // 03:30 Riyadh, 1 January
  await e.app.addons.accessReviews.tick();
  r = await get('/access-reviews/AR-2027-Q1', ADM); assert.equal(r.status, 200, 'started automatically'); assert.equal(r.json.started_by, 'system:access-reviews');
  const it = (await get('/access-reviews/AR-2027-Q1/items', ADM)).json.items;
  assert.equal(line(it, 'Helpdesk Admins', 'khalid.harbi').new_since_last, true); assert.equal(line(it, 'GG-Claims-Users', 'sara.ghamdi').new_since_last, false);
});

test('roles, scope validation, rejected removal kept as an exception, automatic removal off', async (t) => {
  const { post, get } = await setup(t, { autoRemove: false });
  assert.equal((await get('/access-reviews', VIEW)).status, 403, 'personal data: viewers refused');
  assert.equal((await post('/access-reviews/config', { groups: [] }, DESK)).status, 403);
  assert.equal((await post('/access-reviews/config', { groups: [] }, BOT)).status, 403);
  let r = await post('/access-reviews/config', { groups: [{ name: 'Bad/Group' }] }, ADM); assert.equal(r.status, 400); assert.match(r.json.error, /^groups\[0\]\.name/);
  r = await post('/access-reviews/config', { groups: [{ name: 'A' }, { name: 'a' }] }, ADM); assert.match(r.json.error, /listed twice/);
  r = await post('/access-reviews/config', { due_days: 3 }, ADM); assert.match(r.json.error, /^due_days/);
  r = await post('/access-reviews', { quarter: '2026-Q9' }, ADM); assert.match(r.json.error, /^quarter/);
  r = await post('/access-reviews', {}, ADM); const id = r.json.id;
  const mine = (await get('/access-reviews/' + id + '/items?mine=1', MGR)).json.items;
  await post('/access-reviews/' + id + '/decide', { decisions: mine.map((x) => ({ item: x.id, decision: 'remove', reason: 'not needed any more' })) }, MGR);
  await post('/access-reviews/' + id + '/sign', { statement: true }, MGR);
  const a = line(mine, 'GG-Claims-Users', 'sara.ghamdi').id, b = line(mine, 'GG-Claims-Users', 'khalid.harbi').id;
  assert.equal((await post('/access-reviews/' + id + '/removals/decide', { items: [a], decision: 'reject' }, ADM)).status, 400, 'a reason to keep');
  r = await post('/access-reviews/' + id + '/removals/decide', { items: [a], decision: 'reject', note: 'still on the claims project' }, ADM); assert.equal(r.status, 200);
  r = await post('/access-reviews/' + id + '/removals/decide', { items: [b], decision: 'approve' }, ADM2); assert.deepEqual(r.json.result, { removed: 0, manual: 1, failed: 0 }, 'automatic removal off: by hand');
  const items = (await get('/access-reviews/' + id + '/items', ADM)).json.items;
  assert.equal(items.find((x) => x.id === a).kept_by_exception, true); assert.match(items.find((x) => x.id === b).manual_reason, /automatic removal is off/);
  assert.equal((await post('/access-reviews/' + id + '/removals/done', { items: [b], directory_ref: 'CHG-1' }, { user: 'khalid.harbi', role: 'operator' })).status, 403, 'not the member');
});
