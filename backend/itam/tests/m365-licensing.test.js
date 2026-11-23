// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Automatic Microsoft 365 licence assignment for joiners (engine/m365-licensing.js + engine/onboarding.js) against an
// in-process fake Microsoft Graph: settings admin-only and validated, secret sealed and never returned; "test" reads the
// subscriptions; a proposal may only name catalogue licences (defaults when it names none); after the account exists the
// joiner is looked up in Entra ID until it has synced, the usage location set, free seats checked (no seat = blocked,
// nothing assigned), the licence assigned and read back; a missing Graph permission named; retry and manual record; the
// request completes only when licensed; audit. SYNTHETIC data only.
const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('http');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');

const HR = { user: 'hana.syn', role: 'operator' }, MGR = { user: 'faisal.syn', role: 'operator' }, DESK = { user: 'desk.syn', role: 'operator' };
const ADM = { user: 'syed', role: 'admin' }, VIEW = { user: 'vera.syn', role: 'viewer' };
const TENANT = '11111111-2222-3333-4444-555555555555', APPID = '66666666-7777-8888-9999-000000000000', SECRET = 'Synthetic-Graph-Secret-1';
const E3 = '05e9a617-0261-4cee-bb44-138d3ef5d965', E1 = '18181a46-0d4e-45cd-891e-60aabd171b4e';
const JOINER = { name: 'Sara Al-Ghamdi', employee_id: 'E-10442', job_title: 'Claims Analyst', department: 'Claims', start_date: '2026-11-05', manager: 'faisal.syn', laptop_profile: 'standard' };

function fakeGraph() {
  const st = { users: {}, skus: { [E3]: { part: 'SPE_E3', enabled: 10, consumed: 9 }, [E1]: { part: 'STANDARDPACK', enabled: 5, consumed: 5 } }, calls: [], deny: false, tokens: 0 };
  const srv = http.createServer((req, res) => {
    let b = ''; req.on('data', (c) => { b += c; }); req.on('end', () => {
      const u = new URL(req.url, 'http://x'), J = (c, o) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(o)); };
      st.calls.push(req.method + ' ' + u.pathname);
      if (u.pathname === '/' + TENANT + '/oauth2/v2.0/token') { const f = new URLSearchParams(b); if (f.get('client_secret') !== SECRET) return J(401, { error: 'invalid_client' }); st.tokens++; return J(200, { access_token: 'tok', expires_in: 3600 }); }
      if (req.headers.authorization !== 'Bearer tok') return J(401, { error: { code: 'InvalidAuthenticationToken', message: 'no' } });
      if (u.pathname === '/v1.0/subscribedSkus') return J(200, { value: Object.entries(st.skus).map(([id, s]) => ({ skuId: id, skuPartNumber: s.part, consumedUnits: s.consumed, prepaidUnits: { enabled: s.enabled }, servicePlans: [] })) });
      const m = /^\/v1\.0\/users\/([^/]+)(\/assignLicense)?$/.exec(u.pathname);
      if (m) {
        const key = decodeURIComponent(m[1]).toLowerCase(), usr = Object.values(st.users).find((x) => x.id === key || x.userPrincipalName.toLowerCase() === key);
        if (!usr) return J(404, { error: { code: 'Request_ResourceNotFound', message: 'not found' } });
        if (req.method === 'GET') return J(200, usr);
        if (st.deny) return J(403, { error: { code: 'Authorization_RequestDenied', message: 'Insufficient privileges to complete the operation.' } });
        const p = JSON.parse(b || '{}');
        if (req.method === 'PATCH') { Object.assign(usr, p); return J(204, {}); }
        if (m[2]) {
          if (!usr.usageLocation) return J(400, { error: { code: 'Request_BadRequest', message: 'License assignment cannot be done for user with invalid usage location.' } });
          for (const a of p.addLicenses) { usr.assignedLicenses.push({ skuId: a.skuId, disabledPlans: a.disabledPlans }); st.skus[a.skuId].consumed++; }
          return J(200, usr);
        }
      }
      J(404, { error: { code: 'NotFound', message: u.pathname } });
    });
  });
  return { st, srv };
}

async function setup(t) {
  const clock = { t: Date.parse('2026-10-28T08:00:00Z') };
  const G = fakeGraph(); await new Promise((r) => G.srv.listen(0, '127.0.0.1', r)); t.after(() => G.srv.close());
  const base = 'http://127.0.0.1:' + G.srv.address().port;
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true, now: () => clock.t, python: process.env.PYTHON || 'python3', graphLogin: base, graphBase: base + '/v1.0' });
  const call = (m, p, b, who) => e.req(m, p, Object.assign(b !== undefined ? { body: b } : {}, who));
  const post = (p, b, who) => call('POST', p, b, who), get = (p, who = DESK) => call('GET', p, undefined, who);
  assert.equal((await post('/onboarding/ad', { upn_suffix: 'corp.syn' }, ADM)).status, 200, 'UPN suffix known (manual accounts)');
  async function joiner(extra, licences) {
    let r = await post('/onboarding', Object.assign({}, JOINER, extra), HR); assert.equal(r.status, 200, JSON.stringify(r.json));
    const id = r.json.id;
    await post('/onboarding/' + id + '/approve', { decision: 'approve' }, MGR);
    r = await post('/onboarding/' + id + '/account', { username: extra.username, licences: licences || [] }, DESK); assert.equal(r.status, 200, JSON.stringify(r.json));
    r = await post('/onboarding/' + id + '/account/decide', { decision: 'approve' }, ADM); assert.equal(r.status, 200, JSON.stringify(r.json));
    r = await post('/onboarding/' + id + '/account/created', { username: extra.username, directory_ref: 'CN=' + extra.username + ',OU=Joiners' }, DESK); assert.equal(r.status, 200, JSON.stringify(r.json));
    return { id, r: r.json };
  }
  const configure = () => post('/onboarding/m365', { enabled: true, tenant_id: TENANT, client_id: APPID, client_secret: SECRET, usage_location: 'SA', set_usage_location: true,
    catalogue: [{ name: 'Microsoft 365 E3', sku_id: E3 }, { name: 'Microsoft 365 E1', sku_id: E1 }], default_licences: ['Microsoft 365 E3'] }, ADM);
  return { e, G, clock, post, get, joiner, configure };
}
const auditOf = (e, action) => e.app.store.auditTail(500).filter((x) => x.action === action);
const addUser = (G, upn, extra) => { G.st.users[upn] = Object.assign({ id: 'id-' + upn.split('@')[0], userPrincipalName: upn, usageLocation: null, accountEnabled: true, assignedLicenses: [] }, extra || {}); };

test('settings: admin only, validated, secret sealed; test reads the subscriptions', async (t) => {
  const { e, post, get, configure } = await setup(t);
  assert.equal((await get('/onboarding/m365', VIEW)).status, 403);
  assert.equal((await post('/onboarding/m365', { enabled: false }, DESK)).status, 403, 'admin only');
  let r = await post('/onboarding/m365', { tenant_id: 'contoso' }, ADM); assert.equal(r.status, 400); assert.match(r.json.error, /^tenant_id/);
  r = await post('/onboarding/m365', { catalogue: [{ name: 'E3', sku_id: 'SPE_E3' }] }, ADM); assert.match(r.json.error, /sku_id must be/);
  r = await post('/onboarding/m365', { catalogue: [{ name: 'Microsoft 365 E3', sku_id: E3 }], default_licences: ['Office 365 E5'] }, ADM); assert.match(r.json.error, /^default_licences/);
  r = await post('/onboarding/m365', { enabled: true, tenant_id: TENANT, client_id: APPID }, ADM); assert.match(r.json.error, /enabled needs/);
  r = await configure(); assert.equal(r.status, 200, JSON.stringify(r.json)); assert.equal(r.json.client_secret_set, true); assert.ok(!JSON.stringify(r.json).includes(SECRET));
  assert.ok(!JSON.stringify(e.app.store.collection('onboarding_m365').all()).includes(SECRET), 'sealed'); assert.ok(!JSON.stringify(e.app.store.auditTail(100)).includes(SECRET));
  r = await post('/onboarding/m365/test', {}, ADM); assert.equal(r.status, 200); assert.equal(r.json.ok, true);
  assert.deepEqual(r.json.list.map((s) => s.part + ':' + s.free).sort(), ['SPE_E3:1', 'STANDARDPACK:0']);
  assert.equal(auditOf(e, 'onboarding.m365.settings').length, 1); assert.equal(auditOf(e, 'onboarding.m365.test').length, 1);
});

test('assigned after the account syncs to Entra ID: usage location set, seats checked, read back; the request completes only then', async (t) => {
  const { e, G, post, get, joiner, configure } = await setup(t);
  await configure();
  const bad = await post('/onboarding', Object.assign({}, JOINER, { employee_id: 'E-1' }), HR); await post('/onboarding/' + bad.json.id + '/approve', { decision: 'approve' }, MGR);
  const x = await post('/onboarding/' + bad.json.id + '/account', { username: 'x.y', licences: ['Office 365 E5'] }, DESK); assert.equal(x.status, 400); assert.match(x.json.error, /^licences: Office 365 E5 is not in the Microsoft 365 licence catalogue/);
  const { id, r } = await joiner({ employee_id: 'E-10442', username: 'sara.ghamdi' });
  assert.equal(r.licensing.status, 'waiting'); assert.deepEqual(r.licensing.licences, ['Microsoft 365 E3'], 'the default licence for a joiner who needs Microsoft 365');
  assert.ok(r.steps.some((s) => s.key === 'licensed' && !s.done));
  await e.app.addons.onboarding.licensingTick();
  let v = (await get('/onboarding/' + id)).json; assert.equal(v.licensing.status, 'waiting'); assert.match(v.licensing.note, /waiting for Entra Connect/);
  addUser(G, 'sara.ghamdi@corp.syn');
  await e.app.addons.onboarding.licensingTick();
  v = (await get('/onboarding/' + id)).json;
  assert.equal(v.licensing.status, 'assigned', JSON.stringify(v.licensing)); assert.equal(v.licensing.verified, true); assert.equal(v.licensing.usage_location_set, 'SA');
  assert.deepEqual(G.st.users['sara.ghamdi@corp.syn'].assignedLicenses.map((l) => l.skuId), [E3]); assert.equal(G.st.users['sara.ghamdi@corp.syn'].usageLocation, 'SA');
  assert.ok(G.st.calls.indexOf('PATCH /v1.0/users/id-sara.ghamdi') < G.st.calls.indexOf('POST /v1.0/users/id-sara.ghamdi/assignLicense'), 'usage location before the licence');
  assert.equal(auditOf(e, 'onboarding.licences.assigned').length, 1);
  assert.notEqual(v.status, 'completed', 'credentials and handover still open');
  await post('/onboarding/' + id + '/credentials', { method: 'in_person', must_change: true, mfa: 'at_first_sign_in' }, DESK);
  e.app.store.collection('assets').put({ id: 'ast_l1', type: 'laptop', status: 'in_stock', serial: 'SYN-1', lifecycle: [] });
  await post('/onboarding/' + id + '/laptop', { asset_id: 'ast_l1' }, DESK);
  v = (await post('/onboarding/' + id + '/handover', { acknowledged: true }, DESK)).json; assert.equal(v.status, 'completed');
});

test('no free seat blocks (nothing assigned); a missing Graph permission is named; retry and manual record; roles', async (t) => {
  const { e, G, post, get, joiner, configure } = await setup(t);
  await configure();
  addUser(G, 'khalid.harbi@corp.syn', { usageLocation: 'SA' });
  const { id } = await joiner({ employee_id: 'E-2', username: 'khalid.harbi' }, ['Microsoft 365 E1']);
  await e.app.addons.onboarding.licensingTick();
  let v = (await get('/onboarding/' + id)).json; assert.equal(v.licensing.status, 'blocked'); assert.match(v.licensing.error, /no free seat of Microsoft 365 E1/);
  assert.equal(G.st.users['khalid.harbi@corp.syn'].assignedLicenses.length, 0, 'nothing assigned');
  G.st.skus[E1].enabled = 6;
  assert.equal((await post('/onboarding/' + id + '/licences/retry', {}, DESK)).status, 403, 'retry is admin only');
  v = (await post('/onboarding/' + id + '/licences/retry', {}, ADM)).json; assert.equal(v.licensing.status, 'assigned');
  // permission missing
  addUser(G, 'omar.new@corp.syn', { usageLocation: 'SA' });
  const j2 = await joiner({ employee_id: 'E-3', username: 'omar.new' });
  G.st.deny = true; await e.app.addons.onboarding.licensingTick();
  v = (await get('/onboarding/' + j2.id)).json; assert.equal(v.licensing.status, 'failed'); assert.match(v.licensing.error, /Authorization_RequestDenied.*lacks a Graph permission/);
  assert.equal((await post('/onboarding/' + j2.id + '/licences/manual', { reference: 'x' }, DESK)).status, 400, 'reference too short');
  v = (await post('/onboarding/' + j2.id + '/licences/manual', { reference: 'assigned in the admin center, INC-301' }, DESK)).json; assert.equal(v.licensing.status, 'assigned_manually');
  assert.ok(v.steps.find((s) => s.key === 'licensed').done);
  assert.ok(auditOf(e, 'onboarding.licences.blocked').length && auditOf(e, 'onboarding.licences.failed').length && auditOf(e, 'onboarding.licences.manual').length);
});
