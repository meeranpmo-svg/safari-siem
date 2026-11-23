// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Licence reclaim for leavers (engine/offboarding.js + engine/m365-licensing.js) against an in-process fake Microsoft Graph:
// once the account is disabled the platform reads the leaver's licences and proposes taking them back after the hold;
// approval by an administrator who did not raise the request, with the mailbox confirmed, a reason for any licence kept; the
// licences removed at the due time (or at once) and read back; rejected = kept and recorded; a user not in Entra ID needs
// nothing; a refused removal recorded, retried, then recorded by hand; the request completes only when the licences are
// settled; settings validated; roles; audit. SYNTHETIC data only.
const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('http');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');

const HR = { user: 'hana.syn', role: 'operator' }, MGR = { user: 'faisal.syn', role: 'operator' }, DESK = { user: 'desk.syn', role: 'operator' };
const ADM = { user: 'syed', role: 'admin' }, ADM2 = { user: 'omar.syn', role: 'admin' };
const TENANT = '11111111-2222-3333-4444-555555555555', APPID = '66666666-7777-8888-9999-000000000000', SECRET = 'Synthetic-Graph-Secret-1';
const E3 = '05e9a617-0261-4cee-bb44-138d3ef5d965', VISIO = 'c5928f49-12ba-48f7-ada3-0d743a3601d5';
const DAY = 86400000, NOW = Date.parse('2026-10-28T08:00:00Z');
const LEAVER = { name: 'Khalid Al-Harbi', employee_id: 'E-20001', username: 'khalid.harbi', department: 'Claims', last_day: '2026-10-30', manager: 'faisal.syn', reason: 'resignation' };

function fakeGraph() {
  const st = { users: {}, skus: { [E3]: { part: 'SPE_E3', enabled: 50, consumed: 50 }, [VISIO]: { part: 'VISIOCLIENT', enabled: 5, consumed: 2 } }, deny: false };
  const srv = http.createServer((req, res) => { let b = ''; req.on('data', (c) => { b += c; }); req.on('end', () => {
    const u = new URL(req.url, 'http://x'), J = (c, o) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(o)); };
    if (u.pathname === '/' + TENANT + '/oauth2/v2.0/token') return new URLSearchParams(b).get('client_secret') === SECRET ? J(200, { access_token: 'tok' }) : J(401, { error: 'invalid_client' });
    if (u.pathname === '/v1.0/subscribedSkus') return J(200, { value: Object.entries(st.skus).map(([id, s]) => ({ skuId: id, skuPartNumber: s.part, consumedUnits: s.consumed, prepaidUnits: { enabled: s.enabled }, servicePlans: [] })) });
    const m = /^\/v1\.0\/users\/([^/]+)(\/assignLicense)?$/.exec(u.pathname);
    if (m) {
      const k = decodeURIComponent(m[1]).toLowerCase(), usr = Object.values(st.users).find((x) => x.id === k || x.userPrincipalName === k);
      if (!usr) return J(404, { error: { code: 'Request_ResourceNotFound', message: 'x' } });
      if (req.method === 'GET') return J(200, usr);
      if (st.deny) return J(403, { error: { code: 'Authorization_RequestDenied', message: 'Insufficient privileges to complete the operation.' } });
      const p = JSON.parse(b || '{}');
      for (const id of p.removeLicenses || []) { usr.assignedLicenses = usr.assignedLicenses.filter((l) => l.skuId !== id); st.skus[id].consumed--; }
      return J(200, usr);
    }
    J(404, {});
  }); });
  return { st, srv };
}

async function setup(t) {
  const clock = { t: NOW };
  const G = fakeGraph(); await new Promise((r) => G.srv.listen(0, '127.0.0.1', r)); t.after(() => G.srv.close());
  const gb = 'http://127.0.0.1:' + G.srv.address().port;
  G.st.users.k = { id: 'id-khalid', userPrincipalName: 'khalid.harbi@corp.syn', accountEnabled: false, assignedLicenses: [{ skuId: E3 }, { skuId: VISIO }] };
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true, now: () => clock.t, python: process.env.PYTHON || 'python3', graphLogin: gb, graphBase: gb + '/v1.0' });
  const call = (m, p, b, who) => e.req(m, p, Object.assign(b !== undefined ? { body: b } : {}, who));
  const post = (p, b, who) => call('POST', p, b, who), get = (p, who = DESK) => call('GET', p, undefined, who);
  assert.equal((await post('/onboarding/ad', { upn_suffix: 'corp.syn' }, ADM)).status, 200);
  const r = await post('/onboarding/m365', { tenant_id: TENANT, client_id: APPID, client_secret: SECRET, catalogue: [{ name: 'Microsoft 365 E3', sku_id: E3 }], reclaim_enabled: true, reclaim_hold_days: 30 }, ADM);
  assert.equal(r.status, 200, JSON.stringify(r.json));
  // a leaver up to "disabled by hand"
  async function leaver(extra = {}) {
    let x = await post('/offboarding', Object.assign({}, LEAVER, extra), HR); assert.equal(x.status, 200, JSON.stringify(x.json));
    const id = x.json.id;
    await post('/offboarding/' + id + '/confirm', { decision: 'confirm' }, MGR);
    x = await post('/offboarding/' + id + '/approve', { decision: 'approve' }, ADM); assert.equal(x.status, 200, JSON.stringify(x.json));
    x = await post('/offboarding/' + id + '/disabled', { directory_ref: 'disabled in ADUC, CHG-9001' }, DESK); assert.equal(x.status, 200, JSON.stringify(x.json));
    return { id, v: x.json };
  }
  return { e, G, clock, post, get, leaver };
}
const auditOf = (e, action) => e.app.store.auditTail(500).filter((x) => x.action === action);

test('proposed after the disable, approved with the mailbox confirmed, removed after the hold and read back', async (t) => {
  const { e, G, clock, post, get, leaver } = await setup(t);
  const { id, v } = await leaver();
  assert.equal(v.reclaim.status, 'proposed'); assert.deepEqual(v.reclaim.licences.map((l) => l.name), ['Microsoft 365 E3', 'VISIOCLIENT'], 'named from the catalogue, else the SKU');
  assert.equal(v.reclaim.due_at, new Date(NOW + 30 * DAY).toISOString(), 'after the 30-day hold');
  assert.ok(v.steps.some((s) => s.key === 'licences' && !s.done));
  assert.equal((await get('/offboarding')).json.counts.reclaim_waiting, 1);
  const D = (b, who) => post('/offboarding/' + id + '/reclaim/decide', b, who);
  assert.equal((await D({ decision: 'approve', mailbox: 'converted_to_shared' }, DESK)).status, 403, 'administrators only');
  assert.equal((await D({ decision: 'approve', mailbox: 'converted_to_shared' }, { user: 'hana.syn', role: 'admin' })).status, 403, 'not the person who raised the request');
  let r = await D({ decision: 'approve' }, ADM); assert.equal(r.status, 400); assert.match(r.json.error, /mailbox is required/);
  r = await D({ decision: 'approve', mailbox: 'converted_to_shared', remove: [E3] }, ADM); assert.match(r.json.error, /^keep_reason is required: say why VISIOCLIENT stays/);
  r = await D({ decision: 'approve', mailbox: 'converted_to_shared', remove: ['00000000-0000-0000-0000-000000000000'] }, ADM); assert.match(r.json.error, /^remove: .* is not a licence of this user/);
  r = await D({ decision: 'approve', mailbox: 'converted_to_shared', remove: [E3], keep_reason: 'Visio goes to the successor next week' }, ADM); assert.equal(r.status, 200, JSON.stringify(r.json));
  assert.equal(r.json.reclaim.status, 'approved');
  await e.app.addons.offboarding.runDue(null);
  assert.equal(G.st.users.k.assignedLicenses.length, 2, 'nothing removed before the hold ends');
  clock.t = NOW + 30 * DAY + 60000;
  await e.app.addons.offboarding.runDue(null);
  r = await get('/offboarding/' + id); assert.equal(r.json.reclaim.status, 'reclaimed'); assert.deepEqual(r.json.reclaim.freed, ['Microsoft 365 E3']);
  assert.deepEqual(G.st.users.k.assignedLicenses.map((l) => l.skuId), [VISIO], 'only the approved licence removed'); assert.equal(G.st.skus[E3].consumed, 49, 'a seat freed for joiners');
  assert.notEqual(r.json.status, 'completed', 'equipment still open');
  r = await post('/offboarding/' + id + '/equipment', { returned: [], na_reason: 'no equipment held' }, DESK); assert.equal(r.json.status, 'completed');
  for (const a of ['offboarding.reclaim.proposed', 'offboarding.reclaim.approved', 'offboarding.reclaim.done']) assert.equal(auditOf(e, a).length, 1, a + ' audited');
});

test('kept (rejected) is recorded; "now" removes at once; a user not in Entra ID needs nothing', async (t) => {
  const { G, post, leaver } = await setup(t);
  const a = await leaver();
  let r = await post('/offboarding/' + a.id + '/reclaim/decide', { decision: 'reject' }, ADM); assert.equal(r.status, 400, 'a reason to keep');
  r = await post('/offboarding/' + a.id + '/reclaim/decide', { decision: 'reject', note: 'legal hold on the mailbox until the claim closes' }, ADM); assert.equal(r.json.reclaim.status, 'kept');
  assert.ok(r.json.steps.find((s) => s.key === 'licences').done);
  G.st.users.o = { id: 'id-other', userPrincipalName: 'other.person@corp.syn', accountEnabled: false, assignedLicenses: [{ skuId: E3 }] };
  const b = await leaver({ username: 'other.person', employee_id: 'E-20002' });
  r = await post('/offboarding/' + b.id + '/reclaim/decide', { decision: 'approve', mailbox: 'on_hold', now: true }, ADM2); assert.equal(r.json.reclaim.status, 'reclaimed'); assert.equal(G.st.users.o.assignedLicenses.length, 0);
  const c = await leaver({ username: 'cloud.less', employee_id: 'E-20003' });
  assert.equal(c.v.reclaim.status, 'not_needed'); assert.match(c.v.reclaim.note, /not in Entra ID/);
});

test('a refused removal is recorded and retried hourly, then recorded by hand; settings validated', async (t) => {
  const { e, G, clock, post, get, leaver } = await setup(t);
  let r = await post('/onboarding/m365', { reclaim_hold_days: 120 }, ADM); assert.equal(r.status, 400); assert.match(r.json.error, /reclaim_hold_days/);
  const { id } = await leaver();
  G.st.deny = true;
  r = await post('/offboarding/' + id + '/reclaim/decide', { decision: 'approve', mailbox: 'not_needed', now: true }, ADM);
  assert.equal(r.json.reclaim.status, 'approved'); assert.match(r.json.reclaim.error, /Authorization_RequestDenied/); assert.equal(r.json.reclaim.attempts, 1);
  await e.app.addons.offboarding.runDue(null); assert.equal((await get('/offboarding/' + id)).json.reclaim.attempts, 1, 'not again within the hour');
  clock.t += 3601000; await e.app.addons.offboarding.runDue(null); assert.equal((await get('/offboarding/' + id)).json.reclaim.attempts, 2);
  assert.equal((await get('/offboarding')).json.counts.reclaim_failed, 1);
  assert.equal((await post('/offboarding/' + id + '/reclaim/manual', { reference: 'x' }, DESK)).status, 400);
  r = await post('/offboarding/' + id + '/reclaim/manual', { reference: 'removed in the admin center, INC-412' }, DESK); assert.equal(r.json.reclaim.status, 'reclaimed_manually');
  assert.equal(auditOf(e, 'offboarding.reclaim.failed').length, 1); assert.equal(auditOf(e, 'offboarding.reclaim.manual').length, 1);
});
