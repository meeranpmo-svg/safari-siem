// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Leaver Microsoft 365 groups and Teams (engine/offboarding.js + engine/m365-licensing.js) against an in-process fake Microsoft
// Graph: what the leaver owns is read (paged), with the groups where the leaver is the only active owner flagged; the disable
// approval carries the decision (transfer to the manager by default / add the manager / decide after / leave them); a team
// gets the new owner as member first; the leaver is removed as owner only after the new owner is in, never leaving a group
// without an active owner; each change read back; failures retried without repeating what worked; decide after with four
// eyes; settings and approval validated; audit. SYNTHETIC data only.
const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('http');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');

const HR = { user: 'hana.syn', role: 'operator' }, MGR = { user: 'faisal.syn', role: 'operator' }, DESK = { user: 'desk.syn', role: 'operator' };
const ADM = { user: 'syed', role: 'admin' }, REQ_ADMIN = { user: 'hana.syn', role: 'admin' };
const TENANT = '11111111-2222-3333-4444-555555555555', APPID = '66666666-7777-8888-9999-000000000000', SECRET = 'Synthetic-Graph-Secret-1';
const LEAVER = { name: 'Khalid Al-Harbi', employee_id: 'E-20001', username: 'khalid.harbi', department: 'Claims', last_day: '2026-10-30', manager: 'faisal.syn', reason: 'resignation' };
const id = (n) => '00000000-0000-4000-8000-' + String(n).padStart(12, '0');
const U = { khalid: id(1), faisal: id(2), omar: id(3), ghost: id(4) }, G = { claims: id(101), finance: id(102), legacy: id(103) };

function fakeGraph() {
  const st = { calls: [], deny: new Set(), users: {
    [U.khalid]: { id: U.khalid, userPrincipalName: 'khalid.harbi@corp.syn', accountEnabled: false },
    [U.faisal]: { id: U.faisal, userPrincipalName: 'faisal.syn@corp.syn', accountEnabled: true },
    [U.omar]: { id: U.omar, userPrincipalName: 'omar.syn@corp.syn', accountEnabled: true },
    [U.ghost]: { id: U.ghost, userPrincipalName: 'old.admin@corp.syn', accountEnabled: false } },
  groups: {
    [G.claims]: { id: G.claims, displayName: 'Claims Team', groupTypes: ['Unified'], resourceProvisioningOptions: ['Team'], owners: [U.khalid], members: [U.khalid] },
    [G.finance]: { id: G.finance, displayName: 'Finance Projects', groupTypes: ['Unified'], resourceProvisioningOptions: [], owners: [U.khalid, U.omar], members: [U.khalid, U.omar] },
    [G.legacy]: { id: G.legacy, displayName: 'Legacy Reports', groupTypes: ['Unified'], resourceProvisioningOptions: ['Team'], owners: [U.khalid, U.ghost], members: [U.khalid] } } };
  let base = '';
  const srv = http.createServer((req, res) => { let b = ''; req.on('data', (c) => { b += c; }); req.on('end', () => {
    const u = new URL(req.url, 'http://x'), J = (c, o) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(o === undefined ? '' : JSON.stringify(o)); };
    if (u.pathname === '/' + TENANT + '/oauth2/v2.0/token') return J(200, { access_token: 'tok' });
    st.calls.push(req.method + ' ' + u.pathname.replace('/v1.0', ''));
    const user = (k) => Object.values(st.users).find((x) => x.id === k || x.userPrincipalName === decodeURIComponent(k).toLowerCase());
    let m;
    if ((m = /^\/v1\.0\/users\/([^/]+)$/.exec(u.pathname))) { const x = user(m[1]); return x ? J(200, x) : J(404, { error: { code: 'Request_ResourceNotFound', message: 'x' } }); }
    if ((m = /^\/v1\.0\/users\/([^/]+)\/ownedObjects\/microsoft\.graph\.group$/.exec(u.pathname))) {
      const all = Object.values(st.groups).filter((g) => g.owners.includes(m[1])).map((g) => ({ id: g.id, displayName: g.displayName, groupTypes: g.groupTypes, resourceProvisioningOptions: g.resourceProvisioningOptions }));
      const skip = Number(u.searchParams.get('$skiptoken') || 0), page = all.slice(skip, skip + 2);
      return J(200, Object.assign({ value: page }, skip + 2 < all.length ? { '@odata.nextLink': base + '/v1.0/users/' + m[1] + '/ownedObjects/microsoft.graph.group?$skiptoken=' + (skip + 2) } : {}));
    }
    if ((m = /^\/v1\.0\/groups\/([^/]+)\/(owners|members)\/\$ref$/.exec(u.pathname)) && req.method === 'POST') {
      const g = st.groups[m[1]], who = String(JSON.parse(b)['@odata.id']).split('/').pop();
      if (st.deny.has(m[1])) return J(403, { error: { code: 'Authorization_RequestDenied', message: 'Insufficient privileges to complete the operation.' } });
      if (g[m[2]].includes(who)) return J(400, { error: { code: 'Request_BadRequest', message: 'One or more added object references already exist for the following modified properties: \'' + m[2] + '\'.' } });
      g[m[2]].push(who); return J(204);
    }
    if ((m = /^\/v1\.0\/groups\/([^/]+)\/owners\/([^/]+)\/\$ref$/.exec(u.pathname)) && req.method === 'DELETE') { const g = st.groups[m[1]]; g.owners = g.owners.filter((x) => x !== m[2]); return J(204); }
    if ((m = /^\/v1\.0\/groups\/([^/]+)\/owners$/.exec(u.pathname))) return J(200, { value: st.groups[m[1]].owners.map((x) => st.users[x]) });
    J(404, { error: { code: 'x', message: 'no route ' + u.pathname } });
  }); });
  return { st, srv, setBase: (x) => { base = x; } };
}

async function setup(t) {
  const clock = { t: Date.parse('2026-10-28T08:00:00Z') };
  const F = fakeGraph(); await new Promise((r) => F.srv.listen(0, '127.0.0.1', r)); t.after(() => F.srv.close());
  const gb = 'http://127.0.0.1:' + F.srv.address().port; F.setBase(gb);
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true, now: () => clock.t, python: process.env.PYTHON || 'python3', graphLogin: gb, graphBase: gb + '/v1.0' });
  const call = (m, p, b, who) => e.req(m, p, Object.assign(b !== undefined ? { body: b } : {}, who));
  const post = (p, b, who) => call('POST', p, b, who), get = (p, who = DESK) => call('GET', p, undefined, who);
  assert.equal((await post('/onboarding/ad', { upn_suffix: 'corp.syn' }, ADM)).status, 200);
  let r = await post('/onboarding/m365', { teams_enabled: true }, ADM); assert.equal(r.status, 400); assert.match(r.json.error, /teams_enabled needs tenant_id/);
  r = await post('/onboarding/m365', { tenant_id: TENANT, client_id: APPID, client_secret: SECRET, teams_enabled: true }, ADM); assert.equal(r.status, 200, JSON.stringify(r.json));
  assert.equal(r.json.teams_ready, true);
  async function leaver(extra = {}, approve = { decision: 'approve' }) {
    let x = await post('/offboarding', Object.assign({}, LEAVER, extra), HR); assert.equal(x.status, 200, JSON.stringify(x.json)); const rid = x.json.id;
    await post('/offboarding/' + rid + '/confirm', { decision: 'confirm' }, MGR);
    x = await post('/offboarding/' + rid + '/approve', approve, ADM); assert.equal(x.status, 200, JSON.stringify(x.json));
    x = await post('/offboarding/' + rid + '/disabled', { directory_ref: 'disabled in ADUC, CHG-9001' }, DESK); assert.equal(x.status, 200, JSON.stringify(x.json));
    return { id: rid, v: x.json };
  }
  return { e, F, clock, post, get, leaver };
}
const auditOf = (e, action) => e.app.store.auditTail(500).filter((x) => x.action === action);

test('default: everything the leaver owns goes to the manager - member first on a team, the leaver removed after, read back', async (t) => {
  const { e, F, get, leaver } = await setup(t);
  const { v } = await leaver();
  const tm = v.teams, g = F.st.groups;
  assert.equal(tm.status, 'transferred', JSON.stringify(tm)); assert.equal(tm.owner, 'faisal.syn@corp.syn'); assert.equal(tm.mode, 'transfer'); assert.equal(tm.decided_with, 'disable approval');
  assert.equal(tm.groups.length, 3, 'read across two pages');
  assert.deepEqual(tm.groups.filter((x) => x.sole).map((x) => x.name).sort(), ['Claims Team', 'Legacy Reports'], 'a disabled co-owner does not count');
  assert.deepEqual(g[G.claims].owners, [U.faisal]); assert.ok(g[G.claims].members.includes(U.faisal), 'a team owner is also a member');
  assert.deepEqual(g[G.finance].owners.sort(), [U.faisal, U.omar].sort()); assert.ok(!g[G.finance].members.includes(U.faisal), 'a plain group: owner only');
  assert.deepEqual(g[G.legacy].owners.sort(), [U.faisal, U.ghost].sort());
  const ix = (s) => F.st.calls.indexOf(s);
  assert.ok(ix('POST /groups/' + G.claims + '/members/$ref') < ix('POST /groups/' + G.claims + '/owners/$ref') && ix('POST /groups/' + G.claims + '/owners/$ref') < ix('DELETE /groups/' + G.claims + '/owners/' + U.khalid + '/$ref'), 'member, then owner, then the leaver out');
  assert.ok(v.steps.find((s) => s.key === 'teams').done);
  assert.equal((await get('/offboarding')).json.teams.automatic, true);
  const a = auditOf(e, 'offboarding.teams.transferred')[0]; assert.equal(a.by, 'system:microsoft-graph'); assert.equal(a.detail.approved_by, 'syed'); assert.equal(a.detail.groups.length, 3);
  assert.equal(auditOf(e, 'offboarding.disable.approve')[0].detail.teams, 'transfer');
});

test('add the manager and keep the leaver; leave them; a user not in Entra ID', async (t) => {
  const { F, leaver } = await setup(t);
  const a = await leaver({}, { decision: 'approve', teams: 'add' });
  assert.equal(a.v.teams.status, 'transferred'); assert.ok(F.st.groups[G.claims].owners.includes(U.khalid) && F.st.groups[G.claims].owners.includes(U.faisal));
  assert.ok(!F.st.calls.some((c) => c.startsWith('DELETE')), 'nothing removed');
  const n = await leaver({ username: 'none.user', employee_id: 'E-2' }, { decision: 'approve', teams: 'none' });
  assert.equal(n.v.teams.status, 'not_needed', 'none.user is not in Entra ID'); assert.ok(n.v.steps.find((s) => s.key === 'teams').done);
});

test('decide after: the only-owner groups counted, four eyes, the new owner validated, kept with a note', async (t) => {
  const { e, F, post, get, leaver } = await setup(t);
  const { id: rid, v } = await leaver({}, { decision: 'approve', teams: 'ask' });
  assert.equal(v.teams.status, 'proposed'); assert.equal(v.teams.owner, 'faisal.syn@corp.syn', 'the manager suggested');
  assert.equal((await get('/offboarding')).json.counts.teams_sole, 2);
  const D = (b, who) => post('/offboarding/' + rid + '/teams/decide', b, who);
  assert.equal((await D({ decision: 'approve' }, DESK)).status, 403);
  let r = await D({ decision: 'approve' }, REQ_ADMIN); assert.equal(r.status, 403); assert.match(r.json.error, /four eyes/);
  r = await D({ decision: 'approve' }, { user: 'khalid.harbi', role: 'admin' }); assert.equal(r.status, 403);
  r = await D({ decision: 'approve' }, { user: 'bot:helper', role: 'admin' }); assert.equal(r.status, 403);
  r = await D({ decision: 'approve', owner: 'khalid.harbi@corp.syn' }, ADM); assert.equal(r.status, 400); assert.match(r.json.error, /leaver cannot be the new owner/);
  r = await D({ decision: 'approve', owner: 'the boss' }, ADM); assert.equal(r.status, 400); assert.match(r.json.error, /^owner:/);
  r = await D({ decision: 'approve', mode: 'delete' }, ADM); assert.equal(r.status, 400); assert.match(r.json.error, /^mode must be one of/);
  r = await D({ decision: 'reject' }, ADM); assert.equal(r.status, 400); assert.match(r.json.error, /note is required/);
  r = await D({ decision: 'approve', owner: 'omar.syn@corp.syn' }, ADM); assert.equal(r.status, 200, JSON.stringify(r.json));
  assert.equal(r.json.teams.status, 'transferred'); assert.deepEqual(F.st.groups[G.claims].owners, [U.omar]);
  assert.ok(r.json.teams.results.find((x) => x.name === 'Finance Projects').already_owner, 'already an owner there');
  assert.equal(auditOf(e, 'offboarding.teams.approved')[0].detail.owner, 'omar.syn@corp.syn');
  assert.equal((await get('/offboarding')).json.counts.teams_sole, 0);
  r = await post('/offboarding/' + rid + '/approve', { decision: 'approve', teams: 'archive' }, ADM); assert.equal(r.status, 400); assert.match(r.json.error, /^teams must be one of/);
});

test('failures: a new owner not in Entra ID, a refused group - the leaver stays owner there; retried without repeating; by hand', async (t) => {
  const { e, F, clock, post, get, leaver } = await setup(t);
  const fa = F.st.users[U.faisal]; delete F.st.users[U.faisal];
  let x = await leaver();
  assert.equal(x.v.teams.status, 'approved'); assert.match(x.v.teams.error, /faisal\.syn@corp\.syn is not in Entra ID/);
  assert.equal((await get('/offboarding')).json.counts.teams_failed, 1); assert.equal(auditOf(e, 'offboarding.teams.failed').length, 1);
  F.st.users[U.faisal] = fa; F.st.deny.add(G.finance);
  clock.t += 3601000; await e.app.addons.offboarding.runDue(null);
  let tm = (await get('/offboarding/' + x.id)).json.teams;
  assert.equal(tm.status, 'approved'); assert.match(tm.error, /partly done - 2 change\(s\) left: add owner to Finance Projects/);
  assert.ok(F.st.groups[G.finance].owners.includes(U.khalid), 'never removed where the new owner could not be added');
  assert.deepEqual(F.st.groups[G.claims].owners, [U.faisal]);
  F.st.deny.clear(); const before = F.st.calls.filter((c) => c === 'POST /groups/' + G.claims + '/owners/$ref').length;
  const r = await post('/offboarding/' + x.id + '/teams/retry', {}, ADM); assert.equal(r.status, 200); assert.equal(r.json.teams.status, 'transferred');
  assert.equal(F.st.calls.filter((c) => c === 'POST /groups/' + G.claims + '/owners/$ref').length, before, 'what worked is not repeated');
  assert.deepEqual(F.st.groups[G.finance].owners.sort(), [U.faisal, U.omar].sort());
  // decide-after recorded by hand
  x = await leaver({ username: 'hand.user', employee_id: 'E-6' }, { decision: 'approve', teams: 'ask' });
  assert.equal(x.v.teams.status, 'not_needed');
  assert.equal((await post('/offboarding/' + x.id + '/teams/manual', { reference: 'done in Teams admin centre' }, DESK)).status, 409, 'nothing open');
});
