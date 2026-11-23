// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Accountability Studio (engine/owner-studio.js, pyengine/owner_studio_rules.py) through the real routes and the real Asset
// Ownership on SYNTHETIC assets, with a stubbed Reconciliation: owner / service suggestions from CMDB dependencies, name +
// subnet peers and departments (with the counts), applying one writes it through Asset Ownership (audited, the evidence as the
// reason), dismissing needs a reason and is remembered; differences prioritised with a fix / accept recommendation learned from
// past decisions, clusters at one source, stale sources; reconcile fix / accept admin-only and delegated; roles; validation.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');

const VIEW = { user: 'vera.syn', role: 'viewer' }, OP = { user: 'nora.syn', role: 'operator' }, ADM = { user: 'syed', role: 'admin' }, BOT = { user: 'ai:owner-analyst', role: 'admin' };

async function setup(t) {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  const calls = [];
  const issues = [];
  for (let i = 1; i <= 6; i++) issues.push({ id: 'iss_n' + i, sig: 's' + i, kind: 'name', sev: 'warn', asset_id: 'x', field: 'name', have: 'SRV' + i, found: 'srv' + i + '.corp.syn', source: 'vcenter', fix: 'apply' });
  issues.push({ id: 'iss_r1', sig: 'r1', kind: 'retired-seen', sev: 'bad', asset_id: 'y', have: 'retired', found: 'seen yesterday', source: 'ad' });
  e.app.addons = e.app.addons || {};
  e.app.addons.reconcile = { view: () => ({ report: { issues }, freshness: [{ source: 'Nutanix', last: '2026-10-01', age_h: 700, error: null }, { source: 'AD', age_h: 2 }] }), compare: async () => ({ issues }),
    fix: async (id, who) => { calls.push(['fix', id, who.user]); return { fixed: id, kind: 'name' }; }, accept: async (b, who) => { calls.push(['accept', b.id, b.reason, who.user]); } };
  registerDuty(e.app.srv, e.app, { noTimer: true, python: process.env.PYTHON || 'python3' });
  const mk = (x) => e.app.assets.create(Object.assign({ status: 'in_use', type: 'server', site: 'HQ' }, x), ADM).asset.id;
  const id = {};
  for (let i = 1; i <= 4; i++) id['c' + i] = mk({ name: 'CLM-SYN-' + i, mgmt_ip: '10.70.2.' + i, department: 'Claims' });
  id.c5 = mk({ name: 'CLM-SYN-5', mgmt_ip: '10.70.2.5', department: 'Claims' });
  id.db = mk({ name: 'DB-SYN-CLAIMS', mgmt_ip: '10.70.9.5', department: 'Claims' });
  id.app = mk({ name: 'APPX-SYN', mgmt_ip: '10.70.8.5' });
  const O = e.app.addons.ownership || require('../engine/ownership').createOwnership(e.app); e.app.addons.ownership = O;
  O.assign({ ids: [id.c1, id.c2, id.c3, id.c4], it_owner: 'Claims IT team', business_owner: 'Head of Claims', business_service: 'Claims (synthetic)', reason: 'synthetic' }, ADM);
  O.assign({ ids: [id.db], business_service: 'Claims (synthetic)', it_owner: 'DBA team', reason: 'synthetic' }, ADM);
  e.app.assets.addRelationship({ from: id.app, to: id.db, type: 'depends_on' }, ADM, { source: 'manual', autoConfirm: true });
  // past decisions: "name" differences were accepted 4 times, fixed once
  for (let i = 0; i < 4; i++) e.app.store.collection('reconcile_accepted').put({ id: 'acc' + i, sig: 'z' + i, kind: 'name', reason: 'FQDN in vCenter (synthetic)', by: 'syed' });
  e.app.audit({ by: 'syed', role: 'admin', action: 'reconcile.fix', target: 'x', detail: { kind: 'name' } });
  const call = (m, p, b, who) => e.req(m, p, Object.assign(b !== undefined ? { body: b } : {}, who));
  return { e, id, call, calls };
}
const auditOf = (e, action) => e.app.store.auditTail(300).filter((x) => x.action === action);

test('suggestions from peers, the CMDB and departments; recommendations learned; clusters; stale sources', async (t) => {
  const { call, id } = await setup(t);
  let r = await call('GET', '/owner-studio', undefined, VIEW); assert.equal(r.status, 403);
  r = await call('GET', '/owner-studio', undefined, OP); assert.equal(r.status, 200, r.raw);
  const v = r.json;
  const peer = v.suggestions.find((x) => x.id === id.c5 && x.field === 'it_owner');
  assert.ok(peer && peer.kind === 'peers' && peer.value === 'Claims IT team', 'CLM-SYN-5 learned from its 4 peers'); assert.match(peer.why, /4 of 4 assets named CLM-\* in 10\.70\.2\.0\/24/);
  const dep = v.suggestions.find((x) => x.id === id.app && x.field === 'business_service');
  assert.ok(dep && dep.kind === 'dependency' && dep.value === 'Claims (synthetic)', 'the app depends on the Claims database');
  const dpt = v.suggestions.find((x) => x.id === id.db && x.field === 'business_owner');
  assert.ok(dpt && dpt.kind === 'department' && dpt.value === 'Head of Claims', 'learned from the Claims department');
  const nm = v.issues.find((x) => x.kind === 'name');
  assert.equal(nm.recommend, 'accept'); assert.match(nm.recommend_basis, /people accepted 4 of 5 "name" differences/);
  const rs = v.issues.find((x) => x.kind === 'retired-seen');
  assert.equal(rs.recommend, 'review'); assert.ok(rs.priority > nm.priority, 'a retired asset still seen comes first');
  assert.ok(v.clusters.some((c) => c.source === 'vcenter' && c.kind === 'name' && c.count === 6), 'one cause at the source');
  assert.ok(v.stale.some((s) => s.source === 'Nutanix'), 'stale source');
  assert.equal(v.summary.assets, 7); assert.equal(v.owners[0].owner, 'Claims IT team');
  assert.equal(v.can_reconcile, false);
});

test('apply writes through Asset Ownership with the evidence; dismiss; reconcile fix / accept admin-only; roles; audit', async (t) => {
  const { e, id, call, calls } = await setup(t);
  const key = 'it_owner|' + id.c5 + '|Claims IT team';
  let r = await call('POST', '/owner-studio/apply', { key }, VIEW); assert.equal(r.status, 403);
  r = await call('POST', '/owner-studio/apply', { key }, BOT); assert.equal(r.status, 403); assert.match(r.json.error, /a person does/);
  r = await call('POST', '/owner-studio/apply', { key: 'owner|x|y' }, OP); assert.equal(r.status, 400); assert.match(r.json.error, /key is not a suggestion key/);
  r = await call('POST', '/owner-studio/apply', { key: 'it_owner|' + id.c5 + '|Somebody Else' }, OP); assert.equal(r.status, 404);
  r = await call('POST', '/owner-studio/apply', { key, value: 'Mallory' }, OP); assert.equal(r.status, 200, r.raw);
  const row = e.app.addons.ownership.view({}).items.find((x) => x.id === id.c5);
  assert.equal(row.it_owner, 'Claims IT team', 'the learned value, never one from the request');
  const own = e.app.store.auditTail(50).find((x) => x.action === 'asset.ownership' && x.target === id.c5);
  assert.ok(own && /Accountability Studio suggestion \(peers\)/.test(JSON.stringify(own)), 'Asset Ownership audited it with the evidence as the reason');
  assert.equal(auditOf(e, 'owner.studio.apply')[0].by, 'nora.syn');
  const dk = 'business_owner|' + id.db + '|Head of Claims';
  r = await call('POST', '/owner-studio/dismiss', { key: dk }, OP); assert.equal(r.status, 400); assert.match(r.json.error, /reason is required/);
  r = await call('POST', '/owner-studio/dismiss', { key: dk, reason: 'the DBA team reports to IT (synthetic)' }, OP); assert.equal(r.status, 200);
  r = await call('GET', '/owner-studio', undefined, OP);
  assert.ok(!r.json.suggestions.some((x) => x.key === key || x.key === dk), 'applied and dismissed are not suggested again');
  r = await call('POST', '/owner-studio/reconcile/fix', { id: 'iss_n1' }, OP); assert.equal(r.status, 403, 'fixing a difference stays admin-only');
  r = await call('POST', '/owner-studio/reconcile/fix', { id: 'iss_n1' }, ADM); assert.equal(r.status, 200);
  r = await call('POST', '/owner-studio/reconcile/accept', { id: 'iss_n2' }, ADM); assert.equal(r.status, 400); assert.match(r.json.error, /reason is required/);
  r = await call('POST', '/owner-studio/reconcile/accept', { id: 'iss_n2', reason: 'vCenter uses the FQDN (synthetic)' }, ADM); assert.equal(r.status, 200);
  r = await call('POST', '/owner-studio/reconcile/accept', { id: 'iss_n3', reason: 'x'.repeat(5) }, BOT); assert.equal(r.status, 403);
  assert.deepEqual(calls, [['fix', 'iss_n1', 'syed'], ['accept', 'iss_n2', 'vCenter uses the FQDN (synthetic)', 'syed']], 'delegated to Reconciliation as the person');
  r = await call('POST', '/owner-studio/ai/ask', { question: 'who owns what?' }, VIEW); assert.equal(r.status, 403);
  r = await call('POST', '/owner-studio/ai/ask', { question: 'who owns what?' }, OP); assert.equal(r.status, 503);
});
