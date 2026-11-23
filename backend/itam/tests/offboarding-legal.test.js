// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Leaver legal hold (engine/offboarding.js + engine/m365-licensing.js) against an in-process fake Microsoft Purview eDiscovery
// (Graph /security/cases/ediscoveryCases): asked by one person with the matter and reason (validated; an optional PDPL legal hold
// must be active), approved by another (not the leaver, not a service identity); the case opened (or the one named, refused when
// closed), the custodian with mailbox + OneDrive, the hold placed and waited for; the licence reclaim refused while the hold is
// being put in place; the search over the date range, the estimate, the export IN Purview - only ids, counts, sizes and file names
// kept, never a download link; a failed step retried without repeating what worked; release asked by one, approved by another,
// refused while the PDPL hold is active; audit. SYNTHETIC data only.
const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('http');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');

const HR = { user: 'hana.syn', role: 'operator' }, MGR = { user: 'faisal.syn', role: 'operator' }, DESK = { user: 'desk.syn', role: 'operator' };
const ADM = { user: 'syed', role: 'admin' }, LEGAL_ADMIN = { user: 'lina.syn', role: 'admin' }, VIEW = { user: 'vera.syn', role: 'viewer' };
const TENANT = '11111111-2222-3333-4444-555555555555', APPID = '66666666-7777-8888-9999-000000000000', SECRET = 'Synthetic-Graph-Secret-1';
const LEAVER = { name: 'Khalid Al-Harbi', employee_id: 'E-20001', username: 'khalid.harbi', department: 'Claims', last_day: '2026-10-30', manager: 'faisal.syn', reason: 'resignation' };
const EXISTING = 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee', CLOSED = 'cccccccc-bbbb-4ccc-8ddd-eeeeeeeeeeee';

function fakePurview(clock) {
  const st = { calls: [], bodies: [], denyHold: 0, cases: { [EXISTING]: { id: EXISTING, displayName: 'Broker dispute 2026', status: 'active', custodians: {}, searches: {}, ops: [] }, [CLOSED]: { id: CLOSED, displayName: 'Old matter', status: 'closed', custodians: {}, searches: {}, ops: [] } } };
  let n = 0;
  const srv = http.createServer((req, res) => { let b = ''; req.on('data', (c) => { b += c; }); req.on('end', () => {
    const u = new URL(req.url, 'http://x'), J = (c, o) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(o === undefined ? '' : JSON.stringify(o)); };
    if (u.pathname === '/' + TENANT + '/oauth2/v2.0/token') return J(200, { access_token: 'tok' });
    const P = u.pathname.replace('/v1.0/security/cases/ediscoveryCases', '~'); st.calls.push(req.method + ' ' + P); if (b) st.bodies.push({ p: P, b: JSON.parse(b) });
    const parts = P.split('/').filter(Boolean); let m;
    if (P === '~' && req.method === 'POST') { const id = 'case-' + (++n); st.cases[id] = { id, displayName: JSON.parse(b).displayName, status: 'active', custodians: {}, searches: {}, ops: [] }; return J(201, st.cases[id]); }
    const c = st.cases[parts[1]]; if (!c) return J(404, { error: { code: 'NotFound', message: 'x' } });
    if (parts.length === 2) return J(200, c);
    if (parts[2] === 'custodians') {
      if (parts.length === 3) { if (req.method === 'POST') { const id = 'cu-' + (++n); c.custodians[id] = { id, email: JSON.parse(b).email, holdStatus: 'notApplied', sources: {} }; return J(201, c.custodians[id]); } return J(200, { value: Object.values(c.custodians).map((x) => ({ id: x.id, email: x.email, holdStatus: x.holdStatus })) }); }
      const cu = c.custodians[parts[3]]; if (!cu) return J(404, {});
      if (parts[4] === 'userSources') { if (req.method === 'POST') { const id = 'us-' + (++n); cu.sources[id] = { id, email: JSON.parse(b).email, includedSources: JSON.parse(b).includedSources }; return J(201, cu.sources[id]); } return J(200, { value: Object.values(cu.sources) }); }
      if (parts[4] === 'applyHold') { if (st.denyHold > 0) { st.denyHold--; return J(403, { error: { code: 'Authorization_RequestDenied', message: 'Insufficient privileges' } }); } cu.holdStatus = 'applying'; cu.polls = 0; return J(202); }
      if (parts[4] === 'removeHold') { cu.holdStatus = 'removing'; cu.polls = 0; return J(202); }
      if (parts.length === 4) { cu.polls = (cu.polls || 0) + 1; if (cu.polls >= 2 && cu.holdStatus === 'applying') cu.holdStatus = 'applied'; if (cu.polls >= 2 && cu.holdStatus === 'removing') cu.holdStatus = 'notApplied'; return J(200, { id: cu.id, holdStatus: cu.holdStatus }); }
    }
    if (parts[2] === 'searches') {
      if (parts.length === 3 && req.method === 'POST') { const id = 'se-' + (++n); c.searches[id] = { id, q: JSON.parse(b).contentQuery, est: 0 }; return J(201, c.searches[id]); }
      const se = c.searches[parts[3]];
      if (parts[4] === 'custodianSources') { se.source = JSON.parse(b)['@odata.id']; return J(204); }
      if (parts[4] === 'estimateStatistics') return J(202);
      if (parts[4] === 'lastEstimateStatisticsOperation') { se.est++; return J(200, se.est < 2 ? { status: 'running' } : { status: 'succeeded', indexedItemCount: 12873, indexedItemsSize: 4294967296, unindexedItemCount: 12, unindexedItemsSize: 1048576, mailboxCount: 1, siteCount: 1 }); }
      if (parts[4] === 'exportResult') { c.ops.push({ id: 'op-' + (++n), action: 'exportResult', status: 'running', polls: 0, createdDateTime: new Date(clock.t).toISOString() }); return J(202); }
    }
    if (parts[2] === 'operations') { for (const o of c.ops) { o.polls++; if (o.polls >= 2) { o.status = 'succeeded'; o.exportFileMetadata = [{ fileName: 'Exchange.pst', size: 4100000000, downloadUrl: 'https://download.example/SAS-SECRET-TOKEN' }, { fileName: 'SharePoint.zip', size: 190000000, downloadUrl: 'https://download.example/SAS-SECRET-2' }]; } } return J(200, { value: c.ops.map((o) => Object.assign({}, o, { polls: undefined })) }); }
    J(404, { error: { code: 'x', message: 'no route ' + P } });
  }); });
  return { st, srv };
}

async function setup(t) {
  const clock = { t: Date.parse('2026-10-28T08:00:00Z') };
  const F = fakePurview(clock); await new Promise((r) => F.srv.listen(0, '127.0.0.1', r)); t.after(() => F.srv.close());
  const gb = 'http://127.0.0.1:' + F.srv.address().port;
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true, now: () => clock.t, python: process.env.PYTHON || 'python3', graphLogin: gb, graphBase: gb + '/v1.0' });
  const call = (m, p, b, who) => e.req(m, p, Object.assign(b !== undefined ? { body: b } : {}, who));
  const post = (p, b, who) => call('POST', p, b, who), get = (p, who = DESK) => call('GET', p, undefined, who);
  assert.equal((await post('/onboarding/ad', { upn_suffix: 'corp.syn' }, ADM)).status, 200);
  async function raise(extra = {}) { const x = await post('/offboarding', Object.assign({}, LEAVER, extra), HR); assert.equal(x.status, 200, JSON.stringify(x.json)); await post('/offboarding/' + x.json.id + '/confirm', { decision: 'confirm' }, MGR); return x.json.id; }
  const tick = async (k = 1) => { for (let i = 0; i < k; i++) { clock.t += 300000; await e.app.addons.offboarding.runDue(null); } };
  return { e, F, clock, post, get, raise, tick, enable: () => post('/onboarding/m365', { tenant_id: TENANT, client_id: APPID, client_secret: SECRET, legal_enabled: true }, ADM) };
}
const auditOf = (e, action) => e.app.store.auditTail(500).filter((x) => x.action === action);

test('asked, validated, approved by another person: case, custodian, hold, search, estimate, export in Purview', async (t) => {
  const { e, F, post, get, raise, tick, enable } = await setup(t);
  const id = await raise();
  const L = (b, who) => post('/offboarding/' + id + '/legal', b, who);
  let r = await L({ matter: 'Broker dispute', reason: 'The broker claim names this employee.' }, DESK); assert.equal(r.status, 409); assert.match(r.json.error, /legal holds through Microsoft Purview are off/);
  assert.equal((await enable()).json.legal_ready, true);
  assert.equal((await L({ matter: 'Broker dispute', reason: 'The broker claim names this employee.' }, VIEW)).status, 403);
  r = await L({ matter: 'Broker dispute', reason: 'The broker claim names this employee.' }, { user: 'khalid.harbi', role: 'operator' }); assert.equal(r.status, 403); assert.match(r.json.error, /leaver cannot/);
  r = await L({ reason: 'The broker claim names this employee.' }, DESK); assert.equal(r.status, 400); assert.match(r.json.error, /^matter is required/);
  r = await L({ matter: 'Broker dispute', reason: 'short' }, DESK); assert.match(r.json.error, /^reason must be at least 10/);
  r = await L({ matter: 'Broker dispute', reason: 'The broker claim names this employee.', case_id: 'case 7' }, DESK); assert.match(r.json.error, /^case_id must be/);
  r = await L({ matter: 'Broker dispute', reason: 'The broker claim names this employee.', pdpl_hold: 'PD-LEGAL_HOLD-001' }, DESK); assert.match(r.json.error, /not an active PDPL legal hold/);
  r = await L({ matter: 'Broker dispute', reason: 'The broker claim names this employee.', from: '2026-05-01', to: '2026-01-01' }, DESK); assert.match(r.json.error, /to must be on or after from/);
  e.app.store.collection('pdpl_records').put({ id: 'PD-LEGAL_HOLD-001', kind: 'legal_hold', status: 'active', ref: 'Broker dispute' });
  r = await L({ matter: 'Broker dispute', reason: 'The broker claim names this employee.', pdpl_hold: 'PD-LEGAL_HOLD-001', from: '2025-01-01', to: '2026-10-30' }, DESK); assert.equal(r.status, 200, JSON.stringify(r.json));
  assert.equal(r.json.legal.status, 'requested'); assert.ok(r.json.steps.find((s) => s.key === 'legal' && !s.done));
  assert.equal((await L({ matter: 'Again', reason: 'A second request for the same leaver.' }, DESK)).status, 409);
  const D = (b, who) => post('/offboarding/' + id + '/legal/decide', b, who);
  assert.equal((await D({ decision: 'approve' }, DESK)).status, 403, 'administrators only');
  r = await D({ decision: 'approve' }, { user: 'desk.syn', role: 'admin' }); assert.equal(r.status, 403); assert.match(r.json.error, /four eyes/);
  r = await D({ decision: 'approve' }, { user: 'svc:legal-bot', role: 'admin' }); assert.equal(r.status, 403);
  r = await D({ decision: 'reject' }, LEGAL_ADMIN); assert.equal(r.status, 400); assert.match(r.json.error, /note is required/);
  r = await D({ decision: 'approve' }, LEGAL_ADMIN); assert.equal(r.status, 200, JSON.stringify(r.json));
  let l = r.json.legal;
  assert.equal(l.status, 'holding'); assert.ok(l.case_created); assert.match(l.case_name, /^Leaver OFF-001 - Broker dispute/); assert.equal(l.included, 'mailbox,site');
  assert.ok(F.st.bodies.some((x) => /userSources$/.test(x.p) && x.b.email === 'khalid.harbi@corp.syn' && x.b.includedSources === 'mailbox,site'), 'mailbox (Teams chats) and OneDrive');
  // the licence reclaim waits while the hold is being put in place
  r = await post('/offboarding/' + id + '/reclaim/decide', { decision: 'approve', mailbox: 'on_hold' }, ADM); assert.equal(r.status, 409); assert.match(r.json.error, /legal hold is being put in place/);
  await tick(); l = (await get('/offboarding/' + id)).json.legal; assert.equal(l.status, 'estimating', 'held (Purview applied it), then the search and the estimate started'); assert.ok(l.held_at);
  const se = Object.values(F.st.cases[l.case_id].searches)[0];
  assert.match(se.q, /\(received>=2025-01-01 AND received<=2026-10-30\) OR \(lastmodifiedtime>=2025-01-01 AND lastmodifiedtime<=2026-10-30\)/);
  assert.match(se.source, new RegExp('/custodians/' + l.custodian_id + '/userSources/' + l.source_id + '$'));
  await tick(); l = (await get('/offboarding/' + id)).json.legal; assert.equal(l.status, 'exporting'); assert.equal(l.estimate.items, 12873); assert.equal(l.estimate.unindexed, 12);
  await tick(); const v = (await get('/offboarding/' + id)).json; l = v.legal;
  assert.equal(l.status, 'exported'); assert.deepEqual(l.export_op.files.map((f) => f.name), ['Exchange.pst', 'SharePoint.zip']);
  assert.ok(v.steps.find((s) => s.key === 'legal').done);
  const everything = JSON.stringify(e.app.store.collection('offboarding').all()) + JSON.stringify(e.app.store.auditTail(500));
  assert.ok(!everything.includes('SAS-SECRET'), 'download links are never kept');
  for (const a of ['offboarding.legal.requested', 'offboarding.legal.approved', 'offboarding.legal.hold_requested', 'offboarding.legal.held', 'offboarding.legal.export_started', 'offboarding.legal.exported']) assert.equal(auditOf(e, a).length, 1, a);
  assert.equal(auditOf(e, 'offboarding.legal.approved')[0].detail.requested_by, 'desk.syn');
  assert.equal((await get('/offboarding')).json.counts.legal_active, 1);
});

test('an existing case: closed is refused, an open one is used; without export the hold is the end; release with four eyes', async (t) => {
  const { e, F, post, get, raise, tick, enable } = await setup(t);
  await enable();
  const id = await raise();
  await post('/offboarding/' + id + '/legal', { matter: 'Old matter', reason: 'Named in an old investigation file.', case_id: CLOSED, export: false }, DESK);
  let r = await post('/offboarding/' + id + '/legal/decide', { decision: 'approve' }, LEGAL_ADMIN);
  assert.equal(r.json.legal.status, 'approved'); assert.match(r.json.legal.error, /closed - reopen it in Purview/);
  // a fresh request on another leaver naming the open case
  const id2 = await raise({ username: 'nora.leaver', employee_id: 'E-2' });
  e.app.store.collection('pdpl_records').put({ id: 'PD-LEGAL_HOLD-002', kind: 'legal_hold', status: 'active', ref: 'Broker dispute 2026' });
  await post('/offboarding/' + id2 + '/legal', { matter: 'Broker dispute 2026', reason: 'Second custodian in the broker dispute.', case_id: EXISTING, export: false, pdpl_hold: 'PD-LEGAL_HOLD-002' }, DESK);
  r = await post('/offboarding/' + id2 + '/legal/decide', { decision: 'approve' }, LEGAL_ADMIN); assert.equal(r.json.legal.status, 'holding');
  assert.equal(r.json.legal.case_id, EXISTING); assert.ok(!r.json.legal.case_created); assert.ok(!F.st.calls.includes('POST ~'), 'no case created');
  await tick(2); let v = (await get('/offboarding/' + id2)).json; assert.equal(v.legal.status, 'held'); assert.ok(v.steps.find((s) => s.key === 'legal').done, 'held, nothing to export');
  const R = (b, who) => post('/offboarding/' + id2 + '/legal/release', b, who);
  assert.equal((await R({ reason: 'short' }, DESK)).status, 400);
  r = await R({ reason: 'The broker dispute was settled in court.' }, DESK); assert.equal(r.status, 409); assert.match(r.json.error, /PDPL legal hold PD-LEGAL_HOLD-002 is still active/);
  e.app.store.collection('pdpl_records').put({ id: 'PD-LEGAL_HOLD-002', kind: 'legal_hold', status: 'released', ref: 'Broker dispute 2026' });
  r = await R({ reason: 'The broker dispute was settled in court.' }, LEGAL_ADMIN); assert.equal(r.status, 200); assert.equal(r.json.legal.status, 'release_requested');
  const RD = (b, who) => post('/offboarding/' + id2 + '/legal/release/decide', b, who);
  r = await RD({ decision: 'approve' }, LEGAL_ADMIN); assert.equal(r.status, 403); assert.match(r.json.error, /asked for the release/);
  r = await RD({ decision: 'reject' }, ADM); assert.equal(r.status, 400);
  r = await RD({ decision: 'approve' }, ADM); assert.equal(r.status, 200, JSON.stringify(r.json)); assert.equal(r.json.legal.status, 'releasing');
  await tick(2); v = (await get('/offboarding/' + id2)).json; assert.equal(v.legal.status, 'released');
  assert.equal(auditOf(e, 'offboarding.legal.released')[0].detail.approved_by, 'syed');
});

test('a refused hold is retried without opening a second case', async (t) => {
  const { F, post, get, raise, tick, enable } = await setup(t);
  await enable(); F.st.denyHold = 1;
  const id = await raise();
  await post('/offboarding/' + id + '/legal', { matter: 'Audit 2026', reason: 'Internal audit asked to preserve the data.', export: false }, DESK);
  let r = await post('/offboarding/' + id + '/legal/decide', { decision: 'approve' }, LEGAL_ADMIN);
  assert.equal(r.json.legal.status, 'approved'); assert.match(r.json.legal.error, /eDiscovery\.ReadWrite\.All/);
  assert.equal((await get('/offboarding')).json.counts.legal_failed, 1);
  assert.equal((await post('/offboarding/' + id + '/legal/retry', {}, DESK)).status, 403);
  r = await post('/offboarding/' + id + '/legal/retry', {}, ADM); assert.equal(r.status, 200); assert.equal(r.json.legal.status, 'holding');
  assert.equal(F.st.calls.filter((c) => c === 'POST ~').length, 1, 'one case'); assert.equal(F.st.calls.filter((c) => /\/custodians$/.test(c) && c.startsWith('POST')).length, 1, 'one custodian');
  await tick(2); assert.equal((await get('/offboarding/' + id)).json.legal.status, 'held');
});
