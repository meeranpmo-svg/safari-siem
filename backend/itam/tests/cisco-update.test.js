// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Cisco Update Manager (engine/cisco-update.js) over a SYNTHETIC cisco-support (PSIRT advisories per version, Smart Net rows):
// Cisco version ordering; per-device status against the policy (on target / behind / below minimum / no policy / unknown) with the
// most specific rule winning; "fixed by target" only when Cisco's first-fixed names the same train; deadlines from first seen;
// priority with every point named; the policy (admin, every field validated and named, minimum above target refused); plans
// (operator, device and platform checks, a device in two open plans refused, image needs an MD5), four-eyes approval (the requester
// cannot approve, a service identity never decides, an operator without the network scope refused), reject needs a reason,
// completion verified against the running version; viewer reads, cannot write; every change audited.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');
const U = require('../engine/cisco-update');

const ADM = { user: 'syed', role: 'admin' }, ADM2 = { user: 'omar.syn', role: 'admin' }, OP = { user: 'nora.syn', role: 'operator' }, OP2 = { user: 'ali.syn', role: 'operator' }, VW = { user: 'vera.syn', role: 'viewer' };
const DAY = 86400000;
function fakeCs(state) {
  return {
    psirtView: () => ({ api: { enabled: true, secret_set: true }, last_check: '2026-11-01T00:00:00.000Z', last_error: null, devices: state.devices,
      versions: [{ key: 'iosxe|17.6.1', ostype: 'iosxe', version: '17.6.1', count: 2, worst: 'Critical', by_sir: { Critical: 1, High: 1 },
        advisories: [{ id: 'cisco-sa-syn-crit', title: 'Synthetic web UI flaw', sir: 'Critical', cvss: 10, cves: ['CVE-2026-0001'], first_fixed: ['17.9.4a'], url: '' },
          { id: 'cisco-sa-syn-high', title: 'Synthetic DoS', sir: 'High', cvss: 7.5, cves: [], first_fixed: ['16.12.10'], url: '' }] },
        { key: 'ios|15.2(7)E8', ostype: 'ios', version: '15.2(7)E8', count: 0, worst: null, advisories: [] }] }),
    report: () => ({ rows: [{ name: 'SW-CORE-1', status: 'covered', end: '2027-06-30' }, { name: 'SW-EDGE-2', status: 'expired', end: '2025-01-01' }] }),
  };
}
async function setup(t) {
  const state = { devices: [
    { id: 'sw-core-1', name: 'SW-CORE-1', vendor: 'cisco-ios', ostype: 'iosxe', version: '17.6.1', key: 'iosxe|17.6.1' },
    { id: 'sw-edge-2', name: 'SW-EDGE-2', vendor: 'cisco-ios', ostype: 'iosxe', version: '17.6.1', key: 'iosxe|17.6.1' },
    { id: 'sw-acc-3', name: 'SW-ACC-3', vendor: 'cisco-ios', ostype: 'ios', version: '15.2(7)E8', key: 'ios|15.2(7)E8' },
    { id: 'asa-4', name: 'ASA-4', vendor: 'cisco-asa', ostype: 'asa', version: null, key: null }] };
  let clock = Date.parse('2026-11-05T08:00:00Z');
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true, ciscoSupport: fakeCs(state), now: () => clock });
  return { e, state, tick: (ms) => { clock += ms; } };
}
const post = (e, p, body, who) => e.req('POST', p, Object.assign({ body }, who));
const get = (e, p, who) => e.req('GET', p, who);
const POLICY = { rules: [{ ostype: 'iosxe', target: '17.9.4a', minimum: '17.3.1' }, { ostype: 'iosxe', match: 'SW-EDGE', target: '17.12.3' }], sla: { Critical: 7 } };

test('Cisco version ordering and trains', () => {
  assert.ok(U.cmpVer('17.9.4a', '17.9.4') > 0); assert.ok(U.cmpVer('17.9', '17.9.4') < 0); assert.equal(U.cmpVer('15.2(7)E8', '15.2(7)E8'), 0);
  assert.ok(U.cmpVer('15.2(7)E8', '15.2(7)E10') < 0, 'E10 is after E8 (numbers, not text)'); assert.ok(U.cmpVer('9.18(3)56', '9.18(4)') < 0);
  assert.equal(U.train('17.9.4a'), '17.9'); assert.equal(U.train('15.2(7)E8'), '15.2');
});

test('analysis: status per policy, most specific rule wins, fixed only within the train, deadlines, points named, actions', async (t) => {
  const { e, tick } = await setup(t);
  assert.equal((await post(e, '/cisco-update/policy', POLICY, ADM)).status, 200);
  let v = (await get(e, '/cisco-update', VW)).json;
  assert.equal(v.connected, true);
  const D = Object.fromEntries(v.devices.map((d) => [d.id, d]));
  assert.equal(D['sw-core-1'].status, 'behind'); assert.equal(D['sw-core-1'].target, '17.9.4a');
  assert.equal(D['sw-edge-2'].target, '17.12.3', 'the SW-EDGE rule is more specific'); assert.equal(D['sw-acc-3'].status, 'no-policy'); assert.equal(D['asa-4'].status, 'unknown');
  const crit = D['sw-core-1'].advisories.find((a) => a.id === 'cisco-sa-syn-crit'), high = D['sw-core-1'].advisories.find((a) => a.id === 'cisco-sa-syn-high');
  assert.equal(crit.fixed_by_target, true, '17.9.4a fixes it (same 17.9 train)'); assert.equal(high.fixed_by_target, null, 'first fixed is a 16.12 release: "check", never claimed');
  assert.equal(crit.days_left, 7, 'deadline = first seen + 7 days (Critical, from the policy)'); assert.equal(D['sw-core-1'].advisories[0].sir, 'Critical', 'worst first');
  assert.ok(D['sw-core-1'].points.some((p) => /Critical advisory/.test(p.text)) && D['sw-core-1'].score === D['sw-core-1'].points.reduce((n, p) => n + p.points, 0));
  assert.equal(D['sw-edge-2'].support, 'expired'); assert.ok(D['sw-edge-2'].points.some((p) => /support contract/.test(p.text)));
  assert.equal(v.kpis.behind, 2); assert.equal(v.kpis.no_policy, 1); assert.equal(v.kpis.unknown, 1); assert.equal(v.kpis.critical, 2);
  assert.ok(v.actions.some((a) => a.filter === 'critical') && v.actions.some((a) => a.filter === 'no-support') && v.actions.some((a) => a.filter === 'unknown'));
  // eight days later the Critical advisory is past its deadline - counted from the first time it was seen, not from today
  tick(8 * DAY); v = (await get(e, '/cisco-update', VW)).json;
  assert.equal(v.devices.find((d) => d.id === 'sw-core-1').overdue, 1); assert.equal(v.actions[0].filter, 'overdue');
});

test('policy: administrator only, a person, every field validated and named, audited', async (t) => {
  const { e } = await setup(t);
  assert.equal((await post(e, '/cisco-update/policy', POLICY, OP)).status, 403);
  assert.equal((await post(e, '/cisco-update/policy', POLICY, { user: 'system:x', role: 'admin' })).status, 403, 'service identity refused');
  let r = await post(e, '/cisco-update/policy', { rules: [{ ostype: 'junos', target: '1.0' }] }, ADM); assert.equal(r.status, 400); assert.match(r.text, /ostype must be one of/);
  r = await post(e, '/cisco-update/policy', { rules: [{ ostype: 'ios', target: 'latest!' }] }, ADM); assert.equal(r.status, 400); assert.match(r.text, /target is not a version/);
  r = await post(e, '/cisco-update/policy', { rules: [{ ostype: 'ios', target: '15.2(7)E8', minimum: '15.9' }] }, ADM); assert.equal(r.status, 400); assert.match(r.text, /minimum 15.9 is above the target/);
  r = await post(e, '/cisco-update/policy', { rules: [{ ostype: 'ios', target: '15.2(7)E8' }, { ostype: 'ios', target: '15.2(7)E9' }] }, ADM); assert.equal(r.status, 400); assert.match(r.text, /two rules for ios/);
  r = await post(e, '/cisco-update/policy', { rules: [{ ostype: 'ios', target: '15.2(7)E8' }], sla: { Critical: 0 } }, ADM); assert.equal(r.status, 400); assert.match(r.text, /Critical must be at least 1/);
  r = await post(e, '/cisco-update/policy', { rules: [{ ostype: 'ios', target: '15.2(7)E8', extra: 'x' }] }, ADM); assert.equal(r.status, 200); assert.equal(r.json.policy.rules[0].extra, undefined, 'undeclared fields dropped');
  assert.ok(e.app.store.auditTail(50).some((a) => a.action === 'cisco.update.policy' && a.by === 'syed'));
});

test('plans: validated, four-eyes approval by a person with the scope, reject needs a reason, completion verified, audited', async (t) => {
  const { e, state } = await setup(t);
  await post(e, '/cisco-update/policy', POLICY, ADM);
  const plan = { name: 'Core to 17.9.4a', device_ids: ['sw-core-1'], target: '17.9.4a', reason: 'Critical PSIRT advisory', window: '2026-11-20' };
  assert.equal((await post(e, '/cisco-update/plans', plan, VW)).status, 403, 'viewer cannot raise a plan');
  let r = await post(e, '/cisco-update/plans', Object.assign({}, plan, { device_ids: ['nope'] }), OP); assert.equal(r.status, 400); assert.match(r.text, /not a Cisco device/);
  r = await post(e, '/cisco-update/plans', Object.assign({}, plan, { device_ids: ['sw-core-1', 'sw-acc-3'] }), OP); assert.equal(r.status, 400); assert.match(r.text, /one platform/);
  r = await post(e, '/cisco-update/plans', Object.assign({}, plan, { image: 'cat9k_iosxe.17.09.04a.SPA.bin' }), OP); assert.equal(r.status, 400); assert.match(r.text, /md5 is required/);
  r = await post(e, '/cisco-update/plans', Object.assign({}, plan, { md5: 'zz' }), OP); assert.equal(r.status, 400); assert.match(r.text, /md5 must be 32/);
  r = await post(e, '/cisco-update/plans', Object.assign({}, plan, { reason: 'x' }), OP); assert.equal(r.status, 400); assert.match(r.text, /reason must be at least 5/);
  r = await post(e, '/cisco-update/plans', plan, OP); assert.equal(r.status, 200); const id = r.json.plan.id; assert.equal(r.json.plan.status, 'draft'); assert.equal(r.json.plan.devices[0].from, '17.6.1');
  assert.equal((await post(e, '/cisco-update/plans', Object.assign({}, plan, { name: 'Again' }), OP2)).status, 409, 'a device in an open plan cannot go into another');
  assert.equal((await post(e, `/cisco-update/plans/${id}/approve`, {}, ADM2)).status, 409, 'not submitted yet');
  assert.equal((await post(e, `/cisco-update/plans/${id}/submit`, {}, OP2)).status, 403, 'only the requester submits');
  assert.equal((await post(e, `/cisco-update/plans/${id}/submit`, {}, OP)).status, 200);
  assert.equal((await post(e, `/cisco-update/plans/${id}/approve`, {}, OP)).status, 403, 'the requester cannot approve');
  assert.equal((await post(e, `/cisco-update/plans/${id}/approve`, {}, OP2)).status, 403, 'an operator without the network approval scope cannot approve');
  assert.equal((await post(e, `/cisco-update/plans/${id}/approve`, {}, { user: 'duty:network', role: 'admin' })).status, 403, 'an AI / service identity never approves');
  assert.equal((await post(e, `/cisco-update/plans/${id}/reject`, {}, ADM2)).status, 400, 'reject needs a reason');
  r = await post(e, `/cisco-update/plans/${id}/approve`, {}, ADM2); assert.equal(r.status, 200); assert.equal(r.json.plan.approved_by, 'omar.syn');
  // still on 17.6.1: completion is refused as not verified
  r = await post(e, `/cisco-update/plans/${id}/complete`, {}, OP); assert.equal(r.status, 200); assert.equal(r.json.completed, false); assert.equal(r.json.plan.status, 'approved'); assert.equal(r.json.pending[0].version, '17.6.1');
  // the AI Network Engineer reads the new version: now it completes
  state.devices[0].version = '17.9.4a';
  r = await post(e, `/cisco-update/plans/${id}/complete`, {}, OP); assert.equal(r.json.completed, true); assert.equal(r.json.plan.status, 'completed');
  const v = (await get(e, '/cisco-update', VW)).json; assert.equal(v.devices.find((d) => d.id === 'sw-core-1').status, 'on-target');
  const acts = e.app.store.auditTail(100).map((a) => a.action);
  for (const a of ['cisco.update.plan.create', 'cisco.update.plan.submit', 'cisco.update.plan.approve', 'cisco.update.plan.verify', 'cisco.update.plan.complete']) assert.ok(acts.includes(a), a);
  // a second plan: rejected with a reason, then the device is free again
  r = await post(e, '/cisco-update/plans', { name: 'Edge to 17.12.3', device_ids: ['sw-edge-2'], target: '17.12.3', reason: 'policy target' }, OP); const id2 = r.json.plan.id;
  await post(e, `/cisco-update/plans/${id2}/submit`, {}, OP);
  r = await post(e, `/cisco-update/plans/${id2}/reject`, { reason: 'renew Smart Net first' }, ADM2); assert.equal(r.json.plan.status, 'rejected');
  assert.equal((await post(e, '/cisco-update/plans', { name: 'Edge retry', device_ids: ['sw-edge-2'], target: '17.12.3', reason: 'contract renewed' }, OP)).status, 200, 'a rejected plan frees its devices');
  assert.equal((await post(e, '/cisco-update/plans/' + encodeURIComponent('bad id!') + '/submit', {}, OP)).status, 400, 'a bad id is refused');
});

test('not installed: says what to do, nothing invented', async (t) => {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true });
  const v = (await get(e, '/cisco-update', VW)).json;
  assert.equal(v.connected, false); assert.match(v.reason, /not installed/); assert.equal(v.devices.length, 0);
});
