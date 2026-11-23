// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Cost Studio (engine/cost-studio.js, pyengine/cost_studio_rules.py) through the real routes, the real IT Budget, licence
// register and Support Contracts on SYNTHETIC records: unused licence seats priced from the recorded cost (and only then),
// a contract for more hosts than the inventory has, budget execution learned from last year's approved vs spent, an unusual
// line, showback; tracking an opportunity, done with the saving realised, dropped with a reason, dismissing, a proposal
// accepted by someone else; operators only, validation errors and the audit records.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');

const VIEW = { user: 'vera.syn', role: 'viewer' }, OP = { user: 'nora.syn', role: 'operator' }, OP2 = { user: 'omar.syn', role: 'operator' }, ADM = { user: 'syed', role: 'admin' }, BOT = { user: 'ai:cost-analyst', role: 'admin' };

async function setup(t) {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true, python: process.env.PYTHON || 'python3' });
  const mk = (x) => e.app.assets.create(Object.assign({ status: 'in_use', type: 'workstation', site: 'HQ', department: 'Claims' }, x), ADM).asset.id;
  for (let i = 1; i <= 5; i++) { const id = mk({ name: 'PC-SYN-' + i }); e.app.store.collection('assets').patch(id, (a) => { a.software = [{ name: 'Microsoft Visio Professional', version: '16' }]; a.purchase = { cost: 4000 }; }); }
  for (let i = 1; i <= 4; i++) mk({ name: 'ESX-SYN-' + i, type: 'server', os: 'VMware ESXi 8.0', site: 'DC1', department: 'IT' });
  e.app.store.collection('licences').put({ id: 'lic_visio', product: 'Visio Professional', seats: 20, cost: 20000, status: 'active', product_key_match: 'visio' });
  e.app.store.collection('licences').put({ id: 'lic_free', product: 'Free Tool (synthetic)', seats: 10, status: 'active', product_key_match: 'nothing-installed' });
  const SC = require('../engine/support-contracts').createSupportContracts(e.app); e.app.addons.supportContracts = SC;
  SC.put({ family: 'vmware', vendor: 'VMware by Broadcom', product: 'vSphere Enterprise Plus', contract_number: 'SYN-VM-1', level: 'production', start: '2026-01-01', end: '2027-03-31', quantity: 10, unit: 'hosts', cost: 50000, currency: 'SAR' }, ADM);
  const B = require('../engine/budget').createBudget(e.app); e.app.addons.budget = B;
  const fy = B.build().fy;
  e.app.store.collection('budget_previous').put({ id: 'current', fy: fy - 1, by: 'syed', at: new Date().toISOString(), rows: [1, 2, 3, 4, 5].map((i) => ({ key: String(i), title: 'Server maintenance ' + i, envelope: 'it_ops', area: 'infrastructure', kind: 'opex', approved: 100000, spent: 60000 })) });
  e.app.store.collection('budget_lines').put({ id: 'man:big', source: 'manual', fy, title: 'Data centre cooling (synthetic)', envelope: 'it_ops', area: 'infrastructure', kind: 'opex', amount: 900000, priority: 'must', status: 'proposed' });
  const call = (m, p, b, who) => e.req(m, p, Object.assign(b !== undefined ? { body: b } : {}, who));
  return { e, call };
}
const auditOf = (e, action) => e.app.store.auditTail(300).filter((x) => x.action === action);

test('savings priced only from recorded costs, contract quantity, execution learned, unusual line, showback', async (t) => {
  const { call } = await setup(t);
  let r = await call('GET', '/cost-studio', undefined, VIEW); assert.equal(r.status, 403, 'cost data is for operators and up');
  r = await call('GET', '/cost-studio', undefined, OP); assert.equal(r.status, 200, r.raw);
  const v = r.json;
  const vis = v.savings.find((x) => x.key === 'lic|lic_visio');
  assert.ok(vis, 'unused Visio seats'); assert.equal(vis.saving.value, 15000); assert.match(vis.saving.basis, /15 of 20 seats x recorded cost 20,000 \/ 20 seats/);
  assert.match(vis.evidence, /installs seen by the agents: 5/);
  const free = v.savings.find((x) => x.key === 'lic|lic_free');
  assert.ok(free && free.saving === null && free.resource === '10 seat(s)', 'no recorded cost: the seats, never a price');
  const vm = v.savings.find((x) => x.kind === 'contract-quantity');
  assert.ok(vm, 'contract for more hosts than the inventory'); assert.equal(vm.saving.value, 30000); assert.match(vm.title, /10 units paid, 4 needed/);
  assert.equal(v.summary.saving_known, 45000);
  const ex = v.execution.find((x) => x.area === 'infrastructure' && x.kind === 'opex');
  assert.equal(ex.ratio, 0.6); assert.equal(ex.lines, 5);
  const exp = v.expected.find((x) => x.envelope === 'it_ops');
  assert.ok(exp.lines_with_history >= 1 && exp.likely_unspent >= 360000, 'last year 60 % was spent: the big line will likely not be spent in full');
  assert.ok(v.unusual.some((u) => u.line === 'man:big' && /9\.0x the median/.test(u.why)), 'unusual line');
  assert.equal(v.showback.department.find((x) => x.name === 'Claims').cost, 20000);
  assert.equal(v.sources.budget && v.sources.licences && v.sources.support, true); assert.equal(v.sources.virt, false);
});

test('actions: track, done with the saving realised, dropped with a reason, dismiss, a proposal accepted by someone else; audit', async (t) => {
  const { e, call } = await setup(t);
  let r = await call('POST', '/cost-studio/actions', { key: 'lic|lic_visio' }, BOT); assert.equal(r.status, 403);
  r = await call('POST', '/cost-studio/actions', { key: 'bad key' }, OP); assert.equal(r.status, 400); assert.match(r.json.error, /key is not an opportunity key/);
  r = await call('POST', '/cost-studio/actions', { key: 'lic|lic_none' }, OP); assert.equal(r.status, 404);
  r = await call('POST', '/cost-studio/actions', { key: 'lic|lic_visio', owner: 'licensing team', expected: 999999 }, OP); assert.equal(r.status, 200, r.raw);
  const a = r.json.action; assert.equal(a.expected, 15000, 'the expected saving from the analysis, never from the request'); assert.equal(a.status, 'open');
  r = await call('GET', '/cost-studio', undefined, OP); assert.ok(!r.json.savings.some((x) => x.key === 'lic|lic_visio'), 'a tracked opportunity leaves the list'); assert.equal(r.json.summary.tracked, 15000);
  r = await call('POST', '/cost-studio/actions/' + a.id + '/status', { status: 'done' }, OP); assert.equal(r.status, 400); assert.match(r.json.error, /realised is required/);
  r = await call('POST', '/cost-studio/actions/' + a.id + '/status', { status: 'done', realised: 12000, note: 'renewed 8 seats fewer (synthetic)' }, OP); assert.equal(r.status, 200);
  r = await call('GET', '/cost-studio', undefined, OP); assert.equal(r.json.summary.realised, 12000);
  const vk = r.json.savings.find((x) => x.kind === 'contract-quantity').key;
  r = await call('POST', '/cost-studio/dismiss', { key: vk }, OP); assert.equal(r.status, 400); assert.match(r.json.error, /reason is required/);
  r = await call('POST', '/cost-studio/dismiss', { key: vk, reason: 'hosts arriving in Q1 (synthetic)' }, OP); assert.equal(r.status, 200);
  r = await call('GET', '/cost-studio', undefined, OP); assert.ok(!r.json.savings.some((x) => x.key === vk), 'dismissed: not shown again');
  // a proposal by the AI identity: accepted by a person who is not its proposer
  const p = { id: 'ca_000000000001', key: 'lic|lic_free', kind: 'unused-licence', title: 'Free Tool', status: 'proposed', by: 'ai:cost-analyst', at: new Date().toISOString(), history: [] };
  e.app.store.collection('cost_actions').put(p);
  r = await call('POST', '/cost-studio/actions/' + p.id + '/status', { status: 'open' }, BOT); assert.equal(r.status, 403);
  r = await call('POST', '/cost-studio/actions/' + p.id + '/status', { status: 'open' }, OP2); assert.equal(r.status, 200); assert.equal(r.json.action.owner, 'omar.syn');
  r = await call('POST', '/cost-studio/actions/' + p.id + '/status', { status: 'dropped' }, OP2); assert.equal(r.status, 400); assert.match(r.json.error, /note is required/);
  r = await call('POST', '/cost-studio/actions/' + p.id + '/status', { status: 'dropped', note: 'the tool is free (synthetic)' }, OP2); assert.equal(r.status, 200);
  assert.equal(auditOf(e, 'cost.studio.action.track')[0].by, 'nora.syn');
  assert.equal(auditOf(e, 'cost.studio.action.done')[0].detail.realised, 12000);
  assert.equal(auditOf(e, 'cost.studio.action.open')[0].detail.proposed_by, 'ai:cost-analyst');
  r = await call('POST', '/cost-studio/ai/ask', { question: 'where can we save?' }, VIEW); assert.equal(r.status, 403);
  r = await call('POST', '/cost-studio/ai/ask', { question: 'where can we save?' }, OP); assert.equal(r.status, 503);
});
