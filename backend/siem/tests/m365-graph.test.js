// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Microsoft Graph sync: token, per-block permissions, portal shape, secret never exposed; settings routes.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { createGraph } = require('../engine/collect/m365-graph');

const TEN = '11111111-2222-3333-4444-555555555555', CID = '66666666-7777-8888-9999-000000000000';
function cfgWith(sec) { const c = { m365: {} }; Object.defineProperty(c, 'secrets', { value: { m365: sec }, writable: true }); return c; }
const R = (status, j) => ({ status, ok: status < 300, json: async () => j });
function fakeGraph(calls) {
  return async (url, o) => {
    calls.push([url, o && o.headers && o.headers.Authorization, o && o.body]);
    if (url.includes('/oauth2/v2.0/token')) return R(200, { access_token: 'tok-1', expires_in: 3600 });
    const u = url.replace('https://graph.microsoft.com/v1.0', '');
    if (u.startsWith('/subscribedSkus')) return R(200, { value: [{ skuId: 'sku-bp', skuPartNumber: 'O365_BUSINESS_PREMIUM', prepaidUnits: { enabled: 50 }, consumedUnits: 48, capabilityStatus: 'Enabled' }, { skuPartNumber: 'FLOW_FREE', prepaidUnits: { enabled: 10000 }, consumedUnits: 3 }] });
    if (u.startsWith('/directory/subscriptions')) return R(200, { value: [{ skuPartNumber: 'O365_BUSINESS_PREMIUM', nextLifecycleDateTime: '2026-11-10T00:00:00Z' }] });
    if (u.startsWith('/users')) return u.includes('skiptoken') ? R(200, { value: [{ displayName: 'B', userPrincipalName: 'b@x.com', accountEnabled: false }] }) : R(200, { value: [{ displayName: 'A', userPrincipalName: 'a@x.com', department: 'IT', accountEnabled: true, assignedLicenses: [{ skuId: 'sku-bp' }, { skuId: 'sku-x' }], signInActivity: { lastSignInDateTime: '2026-01-02T00:00:00Z', lastNonInteractiveSignInDateTime: '2026-03-04T00:00:00Z' } }], '@odata.nextLink': 'https://graph.microsoft.com/v1.0/users?$skiptoken=2' });
    if (u.startsWith('/auditLogs/signIns')) return R(403, { error: { code: 'Authorization_RequestDenied', message: 'Insufficient privileges' } });
    if (u.startsWith('/deviceManagement')) return R(200, { value: [{ deviceName: 'LT-1', userDisplayName: 'A', operatingSystem: 'Windows', osVersion: '10.0', serialNumber: 'S1', complianceState: 'noncompliant', lastSyncDateTime: '2026-10-10T00:00:00Z' }] });
    if (u.startsWith('/admin/serviceAnnouncement/healthOverviews')) return R(200, { value: [{ service: 'Exchange Online', status: 'serviceOperational' }] });
    if (u.startsWith('/admin/serviceAnnouncement/issues')) return R(200, { value: [{ service: 'Teams', classification: 'advisory', title: 't', startDateTime: '2026-10-10T00:00:00Z', isResolved: false }] });
    if (u.startsWith('/security/secureScores')) return R(200, { value: [{ currentScore: 40, maxScore: 80, controlScores: [{ controlName: 'MFA', controlCategory: 'Identity', score: 0 }] }] });
    if (u.startsWith('/reports/authenticationMethods')) return R(200, { value: [{ userPrincipalName: 'a@x.com', isMfaRegistered: true }, { userPrincipalName: 'b@x.com', userDisplayName: 'B', isMfaRegistered: false, isAdmin: true }, { userType: 'guest', isMfaRegistered: false }] });
    return R(403, { error: { code: 'Forbidden', message: 'no' } });
  };
}

test('graph sync: portal shape, per-block permissions, paging, secret never in the output', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mg-')), calls = [];
  const g = createGraph({ config: cfgWith({ tenant: TEN, client_id: CID, client_secret: 'very-secret' }), stateDir: dir, fetchImpl: fakeGraph(calls), now: () => Date.parse('2026-10-11T00:00:00Z') });
  assert.equal(g.enabled(), true);
  const d = await g.syncNow();
  assert.equal(d.configured, true);
  assert.deepEqual(d.licenses.map((l) => [l.sku, l.total, l.consumed, l.free, l.days]), [['O365_BUSINESS_PREMIUM', 50, 48, false, 30], ['FLOW_FREE', 10000, 3, true, undefined]]);
  assert.equal(d.users.list.length, 2); assert.deepEqual(d.users.list[0], { name: 'A', upn: 'a@x.com', dept: 'IT', lic: 2, skus: ['O365_BUSINESS_PREMIUM', 'sku-x'], enabled: true, guest: false, created: null, last: '2026-03-04T00:00:00Z' });
  assert.equal(d.users.list[1].last, undefined);
  assert.equal(d.signinsOk, false); assert.equal(d.blocks.signins.perm, 'AuditLog.Read.All'); assert.equal(d.blocks.signins.error, 'permission not granted');
  assert.equal(d.intune[0].compliance, 'noncompliant'); assert.equal(d.serviceHealth.ok, true); assert.equal(d.serviceHealth.issues[0].isResolved, false);
  assert.equal(d.security.secureScore.data.current, 40); assert.deepEqual([d.security.mfa.data.users, d.security.mfa.data.registered, d.security.mfa.data.notRegistered[0].admin], [2, 1, true]);
  assert.equal(d.security.riskyUsers.ok, false); assert.equal(d.blocks.conditionalAccess.perm, 'Policy.Read.All');
  const tokenCalls = calls.filter((c) => c[0].includes('/token')); assert.equal(tokenCalls.length, 1, 'token cached'); assert.match(tokenCalls[0][2], /scope=https%3A%2F%2Fgraph\.microsoft\.com%2F\.default/);
  assert.ok(calls.filter((c) => !c[0].includes('/token')).every((c) => c[1] === 'Bearer tok-1'));
  const all = JSON.stringify(d) + JSON.stringify(g.status()) + fs.readFileSync(path.join(dir, 'm365-graph.json'), 'utf8');
  assert.ok(!all.includes('very-secret') && !all.includes('tok-1'));
  // restart: last snapshot served from the state file
  assert.equal(createGraph({ config: cfgWith({}), stateDir: dir }).data().users.total, 2);
});

test('graph sync: missing credentials and failed sign-in are reported, nothing pretends to be live', async () => {
  const g = createGraph({ config: cfgWith({ tenant: TEN }) });
  assert.equal(g.enabled(), false); assert.equal(g.data().configured, false); assert.match(g.data().reason, /\(client\) ID missing/);
  const g2 = createGraph({ config: cfgWith({ tenant: TEN, client_id: CID, client_secret: 'x' }), fetchImpl: async () => R(401, { error: 'invalid_client', error_description: 'AADSTS7000215: Invalid client secret provided.\nTrace' }) });
  await g2.syncNow(); assert.match(g2.status().last_error, /AADSTS7000215/); assert.equal(g2.data().configured, false);
  const off = cfgWith({ tenant: TEN, client_id: CID, client_secret: 'x' }); off.m365.graph = false;
  assert.equal(createGraph({ config: off }).enabled(), false);
});

test('routes: data for signed-in users, config admin-only, secret write-only, sync needs credentials', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mgr-')), cfgFile = path.join(dir, 'config.json'), secFile = path.join(dir, 'secrets.json');
  fs.writeFileSync(cfgFile, '{}'); fs.writeFileSync(secFile, '{}');
  const config = { m365: {} }; Object.defineProperty(config, '_paths', { value: { config: cfgFile, secrets: secFile } }); Object.defineProperty(config, 'secrets', { value: {}, writable: true });
  const calls = [], m365Graph = createGraph({ config, fetchImpl: fakeGraph(calls) });
  const RT = {}; require('../engine/collect/m365-routes').register({ route: (m, p, h) => { RT[m + ' ' + p] = h; } }, { config, m365Graph, log: { info() {}, error() {} }, extras: { m365: () => ({ enabled: false }) } });
  const call = async (m, p, b, role) => { const o = {}; const ctx = { role, user: 'adm', body: b, need: (r) => { if (r === 'admin' && role !== 'admin') { o.s = 403; return false; } return true; }, audit() {}, ok(x) { o.s = 200; o.b = x; }, fail(c, msg) { o.s = c; o.e = msg; } }; const rv = await RT[m + ' /api/soc' + p](ctx); if (rv !== undefined && !o.s) { o.s = 200; o.b = rv; } return o; };
  assert.equal((await call('GET', '/m365/config', null, 'viewer')).s, 403);
  assert.equal((await call('POST', '/m365/sync', {}, 'admin')).s, 409);
  assert.equal((await call('PUT', '/m365/config', { tenant: 'nope' }, 'admin')).s, 400);
  const r = await call('PUT', '/m365/config', { tenant: TEN, client_id: CID, client_secret: 'very-secret', graph: true }, 'admin');
  assert.equal(r.s, 200, r.e); assert.equal(r.b.m365.secret_set, true); assert.ok(!JSON.stringify(r.b).includes('very-secret'));
  assert.equal(JSON.parse(fs.readFileSync(secFile, 'utf8')).m365.client_secret, 'very-secret'); assert.ok(!fs.readFileSync(cfgFile, 'utf8').includes('very-secret'));
  const s = await call('POST', '/m365/sync', {}, 'admin'); assert.equal(s.s, 200); assert.ok(s.b.graph.blocks.users.ok);
  const d = await call('GET', '/m365/graph', null, 'viewer'); assert.equal(d.s, 200); assert.equal(d.b.users.total, 2);
});

test('graph sync: users still read when signInActivity is not allowed (no Entra ID P1 / AuditLog permission)', async () => {
  const calls = [], base = fakeGraph(calls);
  const f = async (url, o) => (url.includes('/users?') && url.includes('signInActivity') ? R(403, { error: { code: 'Authorization_RequestDenied', message: 'no' } }) : base(url, o));
  const d = await createGraph({ config: cfgWith({ tenant: TEN, client_id: CID, client_secret: 's' }), fetchImpl: f }).syncNow();
  assert.ok(d.blocks.users.ok); assert.equal(d.users.total, 2); assert.equal(d.users.list[0].lic, 2);
});

test('the portal is told when the last sync failed: the last good figures stay, flagged with the error', async () => {
  const dir = require('node:fs').mkdtempSync(require('node:path').join(require('node:os').tmpdir(), 'm365s-'));
  let fail = false; const calls = [];
  const good = fakeGraph(calls);
  const g = createGraph({ config: cfgWith({ tenant: TEN, client_id: CID, client_secret: 's' }), stateDir: dir, fetchImpl: (u, o) => (fail ? R(401, { error: 'invalid_client', error_description: 'AADSTS7000222: The provided client secret keys are expired.' }) : good(u, o)) });
  await g.syncNow();
  assert.equal(g.data().sync.last_error, ''); assert.equal(g.data().sync.stale, false);
  const before = g.data().users.total;
  fail = true; await g.syncNow();
  const d = g.data();
  assert.equal(d.configured, true, 'last good copy kept'); assert.equal(d.users.total, before, 'not replaced by an empty snapshot');
  assert.match(d.sync.last_error, /Graph answered no request: .*AADSTS7000222|invalid_client|HTTP 401/);
});
