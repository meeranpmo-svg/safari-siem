// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Non-Human Identities (engine/nhi.js, pyengine/nhi_rules.py) through the real routes with a stubbed SIEM: the inventory from
// the directory, Entra and this platform (connector credentials, agent keys, API keys, AI engineers) with risks judged from
// what each source reports; a SIEM that does not answer is named, never read as "none"; roles (viewer counts only, policy
// admin only), validation naming the field, owner / review / decommission with four eyes and "done" contradicted by the
// source; no secret, hash or key in any answer; audit; the duty engineer. SYNTHETIC data only.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');

const NOW = Date.parse('2026-10-28T08:00:00Z');
const ago = (d) => new Date(NOW - d * 86400000).toISOString();
const VIEW = { user: 'vera.syn', role: 'viewer' }, OP = { user: 'nora.syn', role: 'operator' }, OWN = { user: 'omar.syn', role: 'operator' };
const ADM = { user: 'syed', role: 'admin' }, BOT = { user: 'ai:nhi', role: 'operator' };
let SIEM;
const siemOk = () => ({ ad: { available: true, synced: ago(0), accounts: [
  { id: 'ad:svc-backup', name: 'svc-backup', kind: 'service_user', why: ['name pattern'], description: 'Veeam backup', privileged: true, privileged_groups: ['Domain Admins'], pwd_age_days: 900, pwd_never_expires: true, spn: [], last_logon: ago(1) },
  { id: 'ad:app-crm', name: 'app-crm', kind: 'service_user', why: ['service principal name'], spn: ['HTTP/crm'], pwd_age_days: 400, no_preauth: true, last_logon: ago(2) },
  { id: 'ad:gmsa-sql$', name: 'gmsa-sql$', kind: 'gmsa', managed: true, why: ['group managed service account'], spn: ['MSSQLSvc/sql01'], pwd_age_days: 10, last_logon: ago(1) },
  { id: 'ad:svc-old', name: 'svc-old', kind: 'service_user', why: ['name pattern'], dormant: true, pwd_age_days: 50, last_logon: ago(200) }] },
entra: { available: true, updated: ago(0), apps: [
  { id: 'o1', app_id: 'a1', name: 'CRM connector', owners: [], secrets: [{ name: 'prod', start: ago(800), end: new Date(NOW + 10 * 86400000).toISOString() }], certs: [], app_permissions: 6, delegated_permissions: 0, audience: 'AzureADMyOrg' }] } });

async function setup(t) {
  SIEM = siemOk;
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  const S = e.app.store;
  S.collection('credentials').put({ id: 'vcenter_pass', set_at: ago(500), by: 'syed', len: 20, enc: 'SEALED-SYNTHETIC' });
  S.collection('agents').put({ id: 'agt_1', key_hash: 'deadbeef', name: 'PC-OLD-01', platform: 'windows', status: 'active', enrolled_at: ago(300), last_seen: ago(60) });
  S.collection('pdpl_intake_keys').put({ id: 'DK-001', name: 'Web portal (synthetic)', sha256: 'abc123hash', created_at: ago(400), revoked_at: null, last_used: ago(1) });
  registerDuty(e.app.srv, e.app, { noTimer: true, now: () => NOW, python: process.env.PYTHON || 'python3', nhiSiem: async () => SIEM() });
  const call = (m, p, b, who) => e.req(m, p, Object.assign(b !== undefined ? { body: b } : {}, who));
  return { e, post: (p, b, who) => call('POST', p, b, who), get: (p, who = OP) => call('GET', p, undefined, who), put: (p, b, who) => call('PUT', p, b, who) };
}
const it = (v, id) => v.items.find((x) => x.id === id);
const keys = (x) => x.risks.map((r) => r.key.split(':')[0]);
const auditOf = (e, action) => e.app.store.auditTail(300).filter((x) => x.action === action);

test('inventory and risks from the directory, Entra and this platform', async (t) => {
  const { get } = await setup(t);
  const r = await get('/nhi'); assert.equal(r.status, 200, r.raw);
  const v = r.json;
  const sb = it(v, 'ad:svc-backup'); assert.equal(sb.risk, 'high'); assert.ok(keys(sb).includes('privileged') && keys(sb).includes('old_secret') && keys(sb).includes('no_owner'));
  const crm = it(v, 'ad:app-crm'); assert.ok(keys(crm).includes('no_preauth') && keys(crm).includes('kerberoast'));
  const g = it(v, 'ad:gmsa-sql$'); assert.ok(!keys(g).includes('old_secret') && !keys(g).includes('kerberoast'), 'a gMSA rotates its own password');
  assert.ok(keys(it(v, 'ad:svc-old')).includes('unused'));
  const app = it(v, 'entra:a1'); assert.ok(['expiring', 'long_secret', 'no_entra_owner', 'many_permissions'].every((k) => keys(app).includes(k)), keys(app).join());
  assert.ok(keys(it(v, 'itam:connector:vcenter_pass')).includes('old_secret'));
  assert.ok(keys(it(v, 'itam:agent:agt_1')).includes('stale_key'));
  assert.ok(keys(it(v, 'itam:key:intake:DK-001')).includes('old_secret'));
  assert.ok(v.items.some((x) => x.kind === 'ai_engineer' && keys(x).includes('no_human_approver')), 'an AI engineer with no named approver');
  assert.ok(v.findings.some((f) => f.key === 'nhi:ad:svc-backup'));
  const raw = JSON.stringify(v);
  assert.ok(!raw.includes('SEALED-SYNTHETIC') && !raw.includes('deadbeef') && !raw.includes('abc123hash'), 'no sealed value, key hash or key in the answer');
  assert.ok(v.sources.every((s) => s.connected));
});

test('a SIEM that does not answer is named; the platform identities still show', async (t) => {
  const { get } = await setup(t);
  SIEM = () => ({ _down: 'the SIEM did not answer' });
  const v = (await get('/nhi')).json;
  assert.equal(v.sources.find((s) => s.id === 'ad').connected, false); assert.match(v.sources.find((s) => s.id === 'ad').reason, /did not answer/);
  assert.ok(!v.items.some((x) => x.source === 'ad') && v.items.some((x) => x.source === 'platform'));
});

test('roles and validation', async (t) => {
  const { get, post, put } = await setup(t);
  assert.equal((await get('/nhi', VIEW)).status, 403);
  const s = await get('/nhi/summary', VIEW); assert.equal(s.status, 200); assert.ok(s.json.counts.total > 5); assert.ok(!JSON.stringify(s.json).includes('svc-backup'), 'the summary has no names');
  assert.equal((await get('/nhi/export', VIEW)).status, 403);
  assert.equal((await put('/nhi/policy', { rotation_days: 180 }, OP)).status, 403);
  assert.equal((await post('/nhi/decommission/decide', { id: 'ad:svc-old', decision: 'approve' }, OP)).status, 403, 'approval is admin only');
  let r = await post('/nhi/owner', { id: 'nope', owner: 'omar.syn' }, OP); assert.equal(r.status, 400); assert.match(r.json.error, /^id must be/);
  r = await post('/nhi/owner', { id: 'ad:svc-backup', owner: 'Omar Team!' }, OP); assert.match(r.json.error, /^owner must be/);
  r = await post('/nhi/owner', { id: 'ad:svc-backup', owner: 'svc:robot' }, OP); assert.match(r.json.error, /a person/);
  r = await post('/nhi/owner', { id: 'ad:nobody', owner: 'omar.syn' }, OP); assert.equal(r.status, 404);
  r = await post('/nhi/owner', { id: 'ad:svc-backup', owner: 'omar.syn' }, BOT); assert.equal(r.status, 403, 'an AI identity cannot record an owner');
  r = await put('/nhi/policy', { rotation_days: 0 }, ADM); assert.match(r.json.error, /^rotation_days must be at least 1/);
  r = await put('/nhi/policy', { rotation_days: 100, privileged_rotation_days: 200 }, ADM); assert.match(r.json.error, /cannot be longer/);
});

test('owner, review, decommission with four eyes; a "done" the directory contradicts; policy; export; duty', async (t) => {
  const { e, get, post, put } = await setup(t);
  let r = await post('/nhi/owner', { id: 'ad:svc-old', owner: 'omar.syn', purpose: 'old file sync (synthetic)', criticality: 'low' }, OP); assert.equal(r.status, 200, r.raw);
  assert.equal(r.json.owner, 'omar.syn'); assert.ok(!keys(r.json).includes('no_owner') && keys(r.json).includes('review_due'));
  assert.equal(auditOf(e, 'nhi.owner').length, 1);
  assert.equal((await post('/nhi/review', { id: 'ad:svc-old', decision: 'keep', note: 'still needed' }, OP)).status, 403, 'only the owner or an admin reviews');
  r = await post('/nhi/review', { id: 'ad:svc-old', decision: 'decommission', note: 'the file sync was retired' }, OWN); assert.equal(r.status, 200, r.raw);
  assert.equal(r.json.decommission.status, 'requested'); assert.ok(!keys(r.json).includes('review_due'));
  assert.equal((await post('/nhi/decommission/done', { id: 'ad:svc-old', evidence: 'CHG-1' }, OP)).status, 409, 'not before approval');
  assert.equal((await post('/nhi/decommission/decide', { id: 'ad:svc-old', decision: 'approve' }, { user: 'omar.syn', role: 'admin' })).status, 403, 'the requester cannot approve');
  r = await post('/nhi/decommission/decide', { id: 'ad:svc-old', decision: 'approve' }, ADM); assert.equal(r.status, 200, r.raw); assert.equal(r.json.decommission.status, 'approved');
  r = await post('/nhi/decommission/done', { id: 'ad:svc-old', evidence: 'CHG-2026-0412 account disabled' }, OP); assert.equal(r.status, 200, r.raw);
  assert.ok(keys(r.json).includes('decommission_not_effective'), 'the directory still reports it enabled');
  for (const a of ['nhi.review', 'nhi.decommission.approve', 'nhi.decommission.done']) assert.equal(auditOf(e, a).length, 1, a);
  // policy: a longer rotation clears the connector's old-secret risk
  r = await put('/nhi/policy', { rotation_days: 730, privileged_rotation_days: 90 }, ADM); assert.equal(r.status, 200, r.raw);
  assert.ok(!keys(it((await get('/nhi')).json, 'itam:connector:vcenter_pass')).includes('old_secret'));
  assert.equal(auditOf(e, 'nhi.policy').length, 1);
  r = await get('/nhi/export'); assert.equal(r.status, 200); assert.match(r.json.csv, /"ad:svc-backup"/); assert.equal(auditOf(e, 'nhi.export').length, 1);
  const f = await e.app.addons.nhi.adapter.findings(); assert.ok(f.some((x) => x.key === 'nhi:ad:svc-backup'));
  assert.equal((await e.app.addons.nhi.adapter.verify({ key: 'nhi:ad:svc-backup' })).present, true);
});
