// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Lifecycle Studio (engine/lifecycle-studio.js, pyengine/lifecycle_studio_rules.py) through the real routes, the real End of
// Life engine and Support Contracts on SYNTHETIC assets: lifespan learned from retirements (and the stated default), the due
// date with its driver, risk with every point explained, end of life and isolation, warranty, no support contract, dependents
// from the CMDB, the cost from recorded purchases only, the 8-quarter forecast and renewals; the plan register (add, done,
// dropped with a reason, a proposal accepted by someone else), costs hidden from viewers, roles, validation and the audit.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');

const VIEW = { user: 'vera.syn', role: 'viewer' }, OP = { user: 'nora.syn', role: 'operator' }, OP2 = { user: 'omar.syn', role: 'operator' }, ADM = { user: 'syed', role: 'admin' }, BOT = { user: 'ai:lifecycle-planner', role: 'admin' };
const NOW = Date.parse('2026-10-31T09:00:00Z');
const ymd = (yearsAgo) => new Date(NOW - yearsAgo * 365.25 * 86400000).toISOString().slice(0, 10);

async function setup(t) {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true, now: () => NOW, python: process.env.PYTHON || 'python3' });
  const C = e.app.store.collection('assets'), id = {};
  const mk = (k, x, patch) => { id[k] = e.app.assets.create(Object.assign({ status: 'in_use', type: 'server', site: 'HQ' }, x), ADM).asset.id; if (patch) C.patch(id[k], patch); };
  // four laptops retired after ~3 years: the learned laptop lifespan
  [2.9, 3.0, 3.1, 3.0].forEach((y, i) => { mk('r' + i, { name: 'LT-SYN-OLD' + i, type: 'laptop' }, (a) => { a.purchase = { date: ymd(y + 1), cost: 4000 + i * 100 }; });
    e.app.assets.transition(id['r' + i], 'retire', ADM, 'synthetic'); C.patch(id['r' + i], (a) => { a.lifecycle[a.lifecycle.length - 1].at = new Date(NOW - 365.25 * 86400000).toISOString(); }); });
  mk('lt', { name: 'LT-SYN-1', type: 'laptop', model: 'Latitude 5440' }, (a) => { a.purchase = { date: ymd(3.5) }; });
  mk('w12', { name: 'SRV-SYN-2012', os: 'Windows Server 2012 R2', mgmt_ip: '10.96.0.5' }, (a) => { a.purchase = { date: ymd(9), cost: 30000 }; a.warranty = { end: ymd(4) }; });
  mk('w22', { name: 'SRV-SYN-2022', os: 'Windows Server 2022', mgmt_ip: '10.96.0.6', model: 'R750' }, (a) => { a.purchase = { date: ymd(1) }; a.warranty = { end: ymd(-2) }; });
  mk('app', { name: 'APP-SYN-1', type: 'vm', os: 'Windows Server 2022', mgmt_ip: '10.96.0.20' });
  mk('nodate', { name: 'SW-SYN-1', type: 'network' });
  e.app.assets.addRelationship({ from: id.app, to: id.w12, type: 'runs_on' }, ADM, { source: 'manual', autoConfirm: true });
  const call = (m, p, b, who) => e.req(m, p, Object.assign(b !== undefined ? { body: b } : {}, who));
  return { e, id, call };
}
const auditOf = (e, action) => e.app.store.auditTail(300).filter((x) => x.action === action);

test('learned lifespan, due and driver, risk explained, actions, cost from purchases only, forecast', async (t) => {
  const { call, id } = await setup(t);
  const r = await call('GET', '/lifecycle-studio', undefined, OP); assert.equal(r.status, 200, r.raw);
  const v = r.json;
  assert.equal(v.lifespans.laptop.source, 'learned'); assert.equal(v.lifespans.laptop.n, 4); assert.equal(v.lifespans.laptop.years, 3);
  assert.equal(v.lifespans.server.source, 'default'); assert.equal(v.lifespans.server.years, 5);
  const lt = v.assets.find((x) => x.id === id.lt);
  assert.equal(lt.action, 'replace'); assert.match(lt.due_why, /3 years of life from purchase \(learned from 4 retirements for laptop\)/);
  assert.match(lt.cost.basis, /median purchase cost of 4 laptop/); assert.equal(lt.cost.value, 4150);
  const w12 = v.assets.find((x) => x.id === id.w12);
  assert.equal(w12.eol_status, 'eol'); assert.equal(w12.action, 'isolate', 'End of Life says it must be isolated');
  assert.ok(w12.why.some((w) => w.points === 40 && /past vendor end of life/.test(w.text)) && w12.why.some((w) => /out of warranty/.test(w.text)) && w12.why.some((w) => /1 CI\(s\) run on/.test(w.text)));
  assert.equal(w12.risk, w12.why.reduce((n, w) => n + w.points, 0), 'the risk is exactly the sum of its reasons');
  assert.equal(w12.quarter, 'overdue'); assert.equal(w12.cost, null, 'one recorded server cost is not enough: not known, not guessed');
  const w22 = v.assets.find((x) => x.id === id.w22);
  assert.equal(w22.eol_status, 'supported'); assert.equal(w22.support, 'uncovered'); assert.equal(w22.action, 'renew support', 'Windows Server with no support contract on record');
  assert.match(v.assets.find((x) => x.id === id.nodate).due_why, /7 years of life from first seen - no purchase date recorded \(default for network\)/, 'no purchase date: said, not hidden');
  assert.equal(v.forecast[0].quarter, 'overdue'); assert.equal(v.forecast.length, 9); assert.equal(v.forecast[1].quarter, '2026-Q4');
  assert.ok(v.forecast[0].count >= 2 && v.forecast[0].cost === 4150 && v.forecast[0].cost_unknown >= 1, 'known cost and unknown count kept apart');
  assert.ok(v.summary.isolate >= 1);
  assert.equal(v.sources.lifecycle, true);
  const vv = (await call('GET', '/lifecycle-studio', undefined, VIEW)).json;
  assert.ok(vv.assets.every((a) => a.cost === null) && vv.forecast.every((f) => f.cost === null) && vv.costs === false, 'viewers see no cost');
});

test('the refresh plan: add, done, dropped with a reason, a proposal accepted by another person; roles; audit', async (t) => {
  const { e, id, call } = await setup(t);
  let r = await call('POST', '/lifecycle-studio/plan', { asset_id: id.lt, action: 'replace', quarter: '2027-Q1' }, VIEW); assert.equal(r.status, 403);
  r = await call('POST', '/lifecycle-studio/plan', { asset_id: id.lt, action: 'replace', quarter: '2027-Q1' }, BOT); assert.equal(r.status, 403);
  r = await call('POST', '/lifecycle-studio/plan', { asset_id: id.lt, action: 'paint', quarter: '2027-Q1' }, OP); assert.equal(r.status, 400); assert.match(r.json.error, /action must be one of/);
  r = await call('POST', '/lifecycle-studio/plan', { asset_id: id.lt, action: 'replace', quarter: 'next year' }, OP); assert.equal(r.status, 400); assert.match(r.json.error, /quarter must look like/);
  r = await call('POST', '/lifecycle-studio/plan', { asset_id: id.lt, action: 'replace', quarter: '2027-Q1', est_cost: 1 }, OP); assert.equal(r.status, 200, r.raw);
  const it = r.json.item; assert.equal(it.est_cost, 4150, 'the estimate the page showed, not one from the request'); assert.equal(it.status, 'planned');
  r = await call('POST', '/lifecycle-studio/plan', { asset_id: id.lt, action: 'replace', quarter: '2027-Q2' }, OP); assert.equal(r.status, 409);
  r = await call('POST', '/lifecycle-studio/plan/' + it.id + '/status', { status: 'dropped' }, OP); assert.equal(r.status, 400); assert.match(r.json.error, /note is required/);
  r = await call('POST', '/lifecycle-studio/plan/' + it.id + '/status', { status: 'done', note: 'PO 4711 (synthetic)' }, OP); assert.equal(r.status, 200);
  r = await call('POST', '/lifecycle-studio/plan/' + it.id + '/status', { status: 'dropped', note: 'x' }, OP); assert.equal(r.status, 409);
  // a proposal (as the AI records it) is accepted by someone other than its proposer
  const p = { id: 'lp_000000000001', asset_id: id.w22, action: 'extend warranty', quarter: '2028-Q3', status: 'proposed', by: 'ai:lifecycle-planner', at: new Date(NOW).toISOString(), history: [] };
  e.app.store.collection('lifecycle_plan').put(p);
  r = await call('POST', '/lifecycle-studio/plan/' + p.id + '/status', { status: 'planned' }, BOT); assert.equal(r.status, 403, 'the AI never accepts');
  r = await call('POST', '/lifecycle-studio/plan/' + p.id + '/status', { status: 'planned' }, OP2); assert.equal(r.status, 200);
  r = await call('POST', '/lifecycle-studio/plan/' + it.id + '/status', { status: 'planned' }, OP); assert.equal(r.status, 409, 'only a proposal is accepted');
  const v = (await call('GET', '/lifecycle-studio', undefined, OP)).json;
  assert.ok(v.plan.some((x) => x.id === p.id && x.status === 'planned' && x.asset_name === 'SRV-SYN-2022'));
  assert.ok(v.assets.find((x) => x.id === id.w22).planned.some((x) => x.id === p.id));
  assert.equal(auditOf(e, 'lifecycle.studio.plan.add')[0].by, 'nora.syn');
  assert.equal(auditOf(e, 'lifecycle.studio.plan.planned')[0].detail.proposed_by, 'ai:lifecycle-planner');
  r = await call('POST', '/lifecycle-studio/ai/ask', { question: 'what is due?' }, VIEW); assert.equal(r.status, 403);
  r = await call('POST', '/lifecycle-studio/ai/ask', { question: 'what is due?' }, OP); assert.equal(r.status, 503);
});
