// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Unified Patch Management (engine/patch-hub.js): every class of IT asset in one view - servers from Update Studio, desktops from
// Endpoint Central, Cisco switches from Cisco Update Manager, firewalls and databases against the administrator's baseline, the
// scanner's vendor-fix findings aged against the SLA (overdue), end of life on top; status = the worst source; an asset no source
// measures is "not measured", never current; the priority itemised; coverage per class; the policy admin-only and validated;
// exceptions (reason, compensating control, <= 180 days) decided by a different named person, never a service identity, ending on
// their date; roles and the audit records. SYNTHETIC assets only.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');
const { cmpVer, classOf } = require('../engine/patch-hub');

const ADM = { user: 'syed', role: 'admin' }, ADM2 = { user: 'adam.syn', role: 'admin' }, OP = { user: 'nora.syn', role: 'operator' }, VW = { user: 'vera.syn', role: 'viewer' };
const D = 86400000, T0 = Date.parse('2026-11-14T06:00:00Z');
const ASSETS = [
  { id: 'a-win1', name: 'WIN-APP01', type: 'server', os: 'Windows Server 2019', criticality: 'critical', environment: 'production', mgmt_ip: '10.9.0.11' },
  { id: 'a-sol', name: 'SOL-DB01', type: 'server', os: 'Oracle Solaris 11.4', criticality: 'high', environment: 'production' },
  { id: 'a-pc1', name: 'FIN-PC-07', type: 'laptop', os: 'Windows 11 Pro' },
  { id: 'a-pc2', name: 'HR-PC-02', type: 'desktop', os: 'Windows 11 Pro' },
  { id: 'a-pc3', name: 'OLD-PC-01', type: 'desktop', os: 'Windows 7 Professional' },
  { id: 'a-sw1', name: 'core-sw1', type: 'network', vendor: 'Cisco', os: 'IOS-XE', criticality: 'high' },
  { id: 'a-sw2', name: 'acc-sw9', type: 'switch', vendor: 'Aruba', firmware: '16.10.0011' },
  { id: 'a-fw1', name: 'FW-EDGE', type: 'firewall', vendor: 'Fortinet', model: 'FortiGate 200F', firmware: '7.2.8', criticality: 'critical', mgmt_ip: '10.9.0.1' },
  { id: 'a-fw2', name: 'FW-BR2', type: 'firewall', vendor: 'Fortinet', model: 'FortiGate 60F', firmware: '7.4.5' },
  { id: 'a-prn', name: 'PRN-01', type: 'printer' },
];
async function setup(t) {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  for (const a of ASSETS) e.app.store.collection('assets').put(Object.assign({ status: 'in_use' }, a));
  const clock = { t: T0 };
  registerDuty(e.app.srv, e.app, { noTimer: true, now: () => clock.t, usHosts: () => [],
    usEc: () => ({ computers: [{ name: 'WIN-APP01', asset_id: 'a-win1', health: 'highly vulnerable', missing: 6, critical: 2, installed: 90, last_contact: T0 - D }], patches: [] }) });
  // the other sources, as the platform holds them (synthetic)
  e.app.addons.manageengine = { computers: () => ({ computers: [
    { name: 'FIN-PC-07', asset_id: 'a-pc1', missing: 3, critical: 1, last_contact: T0 - D },
    { name: 'HR-PC-02', missing: 0, critical: 0, last_contact: T0 - 2 * D },
    { name: 'OLD-PC-01', missing: 0, critical: 0, last_contact: T0 - 30 * D }] }) };
  e.app.addons.ciscoUpdate = { view: () => ({ devices: [{ id: 'cd1', name: 'core-sw1', ostype: 'iosxe', version: '17.6.4', status: 'behind', why: '17.6.4 -> target 17.9.5', target: '17.9.5', advisories: [{ id: 'cisco-sa-syn' }], worst: 'High', overdue: 1, plan: null }] }) };
  e.app.store.collection('vulnscan_findings').put({ id: 'f1', host: '10.9.0.1', hostname: 'FW-EDGE', name: 'FortiOS synthetic flaw', severity: 'critical', score: 9.8, cves: [], status: 'open', solution_type: 'VendorFix', first_seen: new Date(T0 - 40 * D).toISOString() });
  e.app.store.collection('vulnscan_findings').put({ id: 'f2', host: '10.9.0.1', hostname: 'FW-EDGE', name: 'Weak config (synthetic)', severity: 'high', score: 7, cves: [], status: 'open', solution_type: 'Mitigation', first_seen: new Date(T0 - 90 * D).toISOString() });
  e.app.store.collection('db_inventory').put({ id: 'db1', engine: 'oracle', ip: '10.9.0.30', host: 'ora-prd', server: { version: '19.18.0.0.0', instance: 'CLAIMS' }, at: new Date(T0 - D).toISOString() });
  e.app.store.collection('db_inventory').put({ id: 'db2', engine: 'mssql', ip: '10.9.0.31', host: 'sql-prd', server: { version: '15.0.4385.2' }, at: new Date(T0 - D).toISOString() });
  return { e, clock };
}
const rq = (e, m, p, who, b) => e.req(m, p, Object.assign({ body: b }, who));
const it = (v, key) => v.items.find((i) => i.key === key);
const acts = (e) => e.app.store.auditTail(80).map((a) => a.action);

test('release compare and asset classes', () => {
  assert.equal(cmpVer('9.4.2', '9.10.1'), -1); assert.equal(cmpVer('15.0.4385.2', '15.0.4375'), 1); assert.equal(cmpVer('7.4.5', '7.4.5'), 0); assert.equal(cmpVer('19.18.0.0.0', '19.24'), -1);
  assert.equal(classOf({ type: 'laptop' }), 'desktop'); assert.equal(classOf({ type: 'network', vendor: 'Cisco', os: 'IOS-XE' }), 'network'); assert.equal(classOf({ type: 'server', vendor: 'Fortinet', os: 'FortiOS' }), 'firewall');
  assert.equal(classOf({ type: 'printer' }), null);
});

test('one view over every class: worst source wins, not measured is never current, priority itemised, coverage', async (t) => {
  const { e } = await setup(t);
  let v = (await rq(e, 'GET', '/patching', VW)).json;
  assert.equal(v.items.length, 11, '9 assets + 2 databases; the printer is not patched here');
  assert.equal(it(v, 'asset:a-win1').status, 'behind'); assert.match(it(v, 'asset:a-win1').signals.find((s) => s.source === 'Update Studio').text, /2 critical patch/);
  assert.equal(it(v, 'asset:a-sol').status, 'not_measured'); assert.match(it(v, 'asset:a-sol').reason, /Endpoint Central|agent|hypervisor/);
  assert.equal(it(v, 'asset:a-pc1').status, 'behind'); assert.equal(it(v, 'asset:a-pc2').status, 'current');
  assert.equal(it(v, 'asset:a-pc3').status, 'eol', 'Windows 7 is end of life whatever the agent says'); assert.ok(it(v, 'asset:a-pc3').signals.some((s) => s.source === 'Endpoint Central' && /stale/.test(s.text)));
  assert.equal(it(v, 'asset:a-sw1').status, 'overdue'); assert.match(it(v, 'asset:a-sw1').signals[0].text, /PSIRT advisory deadline/);
  assert.equal(it(v, 'asset:a-sw2').status, 'not_measured', 'Aruba with no baseline'); assert.equal(it(v, 'asset:a-fw2').status, 'not_measured');
  const fw = it(v, 'asset:a-fw1'); assert.equal(fw.status, 'overdue', 'a vendor-fix finding past the critical SLA');
  assert.match(fw.signals.find((s) => s.source === 'vulnerability scanner').text, /1 finding\(s\) past the critical SLA \(15 days\) - 1 open with a vendor fix/, 'the mitigation-only finding is not a patch');
  assert.equal(v.items[0].key, 'asset:a-fw1', 'critical + production + overdue ranks first');
  assert.ok(fw.points.some((p) => p.text === 'criticality critical' && p.points === 30) && fw.points.some((p) => p.text === 'production'));
  assert.equal(it(v, 'db:db1').status, 'not_measured', 'a database with no baseline is not measured');
  const net = v.classes.find((c) => c.class === 'network'); assert.deepEqual([net.total, net.measured, net.coverage, net.overdue], [2, 1, 50, 1]);
  assert.equal(v.summary.pct, Math.round(v.summary.current / v.summary.measured * 100)); assert.ok(v.summary.not_measured >= 4);
  assert.equal(v.can_act, false); assert.equal(v.can_admin, false);
  // baselines measure firewalls, switches and databases
  assert.equal((await rq(e, 'POST', '/patching/policy', OP, { baselines: [] })).status, 403, 'only an administrator sets the policy');
  let r = await rq(e, 'POST', '/patching/policy', ADM, { baselines: [{ class: 'firewall', platform: 'FortiGate', target: '7.4.5', minimum: '7.2.9' }, { class: 'database', platform: 'oracle', target: '19.24' }, { class: 'network', platform: 'aruba', target: '16.10.0011' }, { class: 'database', platform: 'mssql', target: '15.0.4375' }], sla: { critical: 14 } });
  assert.equal(r.status, 200, JSON.stringify(r.json));
  v = (await rq(e, 'GET', '/patching', VW)).json;
  assert.equal(it(v, 'asset:a-fw2').status, 'current'); assert.ok(it(v, 'asset:a-fw1').signals.some((s) => /below the minimum 7\.2\.9/.test(s.text)));
  assert.equal(it(v, 'db:db1').status, 'behind'); assert.match(it(v, 'db:db1').signals[0].text, /19\.18\.0\.0\.0 is behind the baseline 19\.24/);
  assert.equal(it(v, 'db:db2').status, 'current'); assert.equal(it(v, 'asset:a-sw2').status, 'current');
  assert.ok(acts(e).includes('patching.policy'));
  // validation names the field
  for (const [b, re] of [[{ baselines: [{ class: 'toaster', platform: 'x', target: '1' }] }, /class must be one of/], [{ baselines: [{ class: 'firewall', platform: 'fortigate', target: 'latest' }] }, /target is not a release/],
    [{ baselines: [{ class: 'firewall', platform: 'fortigate', target: '7.2', minimum: '7.4' }] }, /minimum must not be newer/], [{ sla: { critical: 60, high: 30 } }, /critical <= high/], [{ sla: { urgent: 3 } }, /not a severity/]]) {
    r = await rq(e, 'POST', '/patching/policy', ADM, b); assert.equal(r.status, 400); assert.match(r.json.error, re);
  }
});

test('exceptions: requested by an operator, decided by a different person, end on their date; audited', async (t) => {
  const { e, clock } = await setup(t);
  const until = new Date(T0 + 30 * D).toISOString().slice(0, 10);
  assert.equal((await rq(e, 'POST', '/patching/exceptions', VW, { key: 'asset:a-sol', reason: 'vendor certification pending', compensating: 'isolated VLAN', until })).status, 403);
  let r = await rq(e, 'POST', '/patching/exceptions', OP, { key: 'asset:a-sol', reason: 'short', compensating: 'isolated VLAN, no internet', until }); assert.equal(r.status, 400); assert.match(r.json.error, /reason/);
  r = await rq(e, 'POST', '/patching/exceptions', OP, { key: 'asset:a-sol', reason: 'core insurance vendor has not certified the patch', compensating: 'isolated VLAN, no internet', until: new Date(T0 + 200 * D).toISOString().slice(0, 10) }); assert.equal(r.status, 400); assert.match(r.json.error, /at most 180 days/);
  r = await rq(e, 'POST', '/patching/exceptions', OP, { key: 'asset:nope', reason: 'core insurance vendor has not certified the patch', compensating: 'isolated VLAN, no internet', until }); assert.equal(r.status, 404);
  r = await rq(e, 'POST', '/patching/exceptions', OP, { key: 'asset:a-sol', reason: 'core insurance vendor has not certified the patch', compensating: 'isolated VLAN, no internet', until, state: 'approved' });
  assert.equal(r.status, 200, JSON.stringify(r.json)); const id = r.json.id; assert.equal(r.json.state, 'pending', 'an undeclared field cannot approve it');
  assert.equal((await rq(e, 'POST', '/patching/exceptions', OP, { key: 'asset:a-sol', reason: 'core insurance vendor has not certified the patch', compensating: 'isolated VLAN, no internet', until })).status, 409);
  assert.equal((await rq(e, 'POST', '/patching/exceptions/' + id + '/decide', OP, { decision: 'approved' })).status, 403, 'an operator does not decide');
  const self = { user: 'nora.syn', role: 'admin' };
  r = await rq(e, 'POST', '/patching/exceptions/' + id + '/decide', self, { decision: 'approved' }); assert.equal(r.status, 403); assert.match(r.json.error, /requested the exception cannot decide/);
  r = await rq(e, 'POST', '/patching/exceptions/' + id + '/decide', { user: 'svc-patch', role: 'admin' }, { decision: 'approved' }); assert.equal(r.status, 403);
  r = await rq(e, 'POST', '/patching/exceptions/' + id + '/decide', ADM2, { decision: 'rejected' }); assert.equal(r.status, 400); assert.match(r.json.error, /comment is required/);
  r = await rq(e, 'POST', '/patching/exceptions/' + id + '/decide', ADM2, { decision: 'approved', comment: 'until the vendor certifies' }); assert.equal(r.status, 200); assert.equal(r.json.decided_by, 'adam.syn');
  let v = (await rq(e, 'GET', '/patching', VW)).json, s = it(v, 'asset:a-sol');
  assert.equal(s.exception.id, id); assert.equal(s.priority, 0); assert.equal(v.summary.excepted, 1);
  clock.t = T0 + 32 * D; v = (await rq(e, 'GET', '/patching', VW)).json; s = it(v, 'asset:a-sol');
  assert.equal(s.exception, null, 'an exception ends on its date - nothing renews silently'); assert.ok(v.exceptions.find((x) => x.id === id).expired);
  r = await rq(e, 'POST', '/patching/exceptions', OP, { key: 'asset:a-win1', reason: 'patch breaks the claims portal', compensating: 'WAF virtual patch in front', until: new Date(clock.t + 10 * D).toISOString().slice(0, 10) });
  assert.equal((await rq(e, 'POST', '/patching/exceptions/' + r.json.id + '/revoke', ADM, {})).status, 400);
  assert.equal((await rq(e, 'POST', '/patching/exceptions/' + r.json.id + '/revoke', ADM, { reason: 'portal fixed by the vendor' })).json.state, 'revoked');
  assert.equal((await rq(e, 'POST', '/patching/exceptions/' + encodeURIComponent('bad$id') + '/decide', ADM2, { decision: 'approved' })).status, 400);
  const a = acts(e); for (const k of ['patching.exception.request', 'patching.exception.approved', 'patching.exception.revoke']) assert.ok(a.includes(k), k);
  const rec = e.app.store.auditTail(80).find((x) => x.action === 'patching.exception.approved'); assert.equal(rec.by, 'adam.syn'); assert.equal(rec.role, 'admin');
});
