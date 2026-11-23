// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Scan-target planner / Network Assistant (engine/scan-targets.js) with SYNTHETIC data: targets built from IP Address Management
// (live addresses only, folded into ranges), fragile devices left out (asset type and host name, word-bounded), the scope proposal
// for the administrator (planned subnets not covered, unplanned networks, exclusions), priority itemised (never scanned, stale scan,
// retest, unknown devices, server network), a subnet outside the scope is not proposed, the VAPT 'within' filter, roles.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');
const { fold, FRAGILE } = require('../engine/scan-targets');
const ip4 = require('../engine/discovery/ipv4');
const VIEW = { user: 'vera.syn', role: 'viewer' }, OP = { user: 'net.syn', role: 'operator' }, ADM = { user: 'syed', role: 'admin' };
const DAY = 86400000;

test('fold and fragile patterns', () => {
  assert.deepEqual(fold([1, 2, 3, 5, 7, 8].map((n) => ip4.parseIp('10.0.0.' + n))), ['10.0.0.1-10.0.0.3', '10.0.0.5', '10.0.0.7-10.0.0.8']);
  assert.ok(FRAGILE.test('HP LaserJet printer')); assert.ok(FRAGILE.test('cctv nvr 01')); assert.ok(!FRAGILE.test('upstream-proxy'), 'word-bounded: "ups" inside a word is not a UPS');
  assert.ok(!FRAGILE.test('photoshop'), 'word-bounded: "phone" / "ot" inside a word');
});

test('Network Assistant: targets and scope from IP Address Management', async (t) => {
  let T = Date.parse('2026-11-22T08:00:00Z');
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true, now: () => T, python: process.env.PYTHON || 'python3' });
  const call = (m, p, b, who) => e.req(m, p, Object.assign(b !== undefined ? { body: b } : {}, who || ADM));
  const c = (n) => e.app.store.collection(n);
  // empty: nothing proposed, nothing invented
  let r = await call('GET', '/scan-targets', undefined, OP); assert.equal(r.status, 200, r.text); assert.equal(r.json.installed, true); assert.deepEqual(r.json.recommendations, []);
  assert.equal((await call('GET', '/scan-targets', undefined, VIEW)).status, 403, 'host names are internal');
  // the address plan
  for (const s of [{ cidr: '10.0.5.0/24', name: 'Servers DC', site: 'Riyadh HQ' }, { cidr: '10.0.6.0/24', name: 'Users floor 2', site: 'Riyadh HQ' }, { cidr: '10.0.7.0/24', name: 'Branch Jeddah', site: 'Jeddah' }]) assert.equal((await call('POST', '/ipam/subnets', s, OP)).status, 200);
  c('assets').put({ id: 'A1', name: 'srv-app-01', type: 'server', mgmt_ip: '10.0.5.10', status: 'active' });
  c('assets').put({ id: 'A2', name: 'srv-app-02', type: 'server', mgmt_ip: '10.0.5.11', status: 'active' });
  c('assets').put({ id: 'A3', name: 'Floor2 MFP', type: 'printer', mgmt_ip: '10.0.6.50', status: 'active' });
  c('assets').put({ id: 'A4', name: 'jed-fw', type: 'network', mgmt_ip: '10.0.7.1', status: 'active' });
  const seen = new Date(T - DAY).toISOString();
  c('disc_devices').put({ id: 'D1', ips: ['10.0.5.10'], macs: ['aa:00:00:00:00:10'], hostname: 'srv-app-01', last_seen: seen, status: 'approved' });
  c('disc_devices').put({ id: 'D2', ips: ['10.0.5.12'], macs: ['aa:00:00:00:00:12'], hostname: 'unknown-box', last_seen: seen, status: 'new' });
  c('disc_devices').put({ id: 'D3', ips: ['10.0.6.20'], macs: ['aa:00:00:00:00:20'], hostname: 'pc-0620', last_seen: seen, status: 'new' });
  c('disc_devices').put({ id: 'D4', ips: ['10.0.6.30'], macs: ['aa:00:00:00:00:30'], hostname: 'cisco-ip-phone-30', last_seen: seen, status: 'new' });
  c('disc_devices').put({ id: 'D5', ips: ['192.168.50.5'], macs: ['aa:00:00:00:50:05'], hostname: 'lab-1', last_seen: seen, status: 'new' });
  // no scope yet: nothing proposed to scan, the scope is proposed instead
  r = await call('GET', '/scan-targets', undefined, OP); let v = r.json;
  assert.equal(v.scope.set, false); assert.deepEqual(v.recommendations, []);
  assert.deepEqual(v.scope_proposal.add_allowed.sort(), ['10.0.5.0/24', '10.0.6.0/24', '10.0.7.0/24']);
  assert.deepEqual(v.scope_proposal.add_exclude.sort(), ['10.0.6.30', '10.0.6.50'], 'printer by asset type, IP phone by host name');
  assert.deepEqual(v.scope_proposal.add_allowed_unplanned, ['192.168.50.0/24'], 'a network in use but not in the plan');
  assert.match(v.subnets.find((s) => s.cidr === '10.0.5.0/24').blocked, /no internal scan scope/);
  // the administrator saves the scope (Jeddah left out)
  assert.equal((await call('PUT', '/vulnscan/scope', { allowed: ['10.0.5.0/24', '10.0.6.0/24'], exclude: ['10.0.6.50'] }, ADM)).status, 200);
  // a scan last month covered the servers; one open high finding there
  c('vulnscan_scans').put({ id: 'VS-0001', name: 'old', targets: ['10.0.5.10-10.0.5.11'], exclude: [], state: 'done', finished_at: new Date(T - 45 * DAY).toISOString() });
  c('vulnscan_findings').put({ id: 'F1', host: '10.0.5.11', severity: 'high', status: 'open', name: 'TLS (synthetic)' });
  r = await call('GET', '/scan-targets', undefined, OP); v = r.json;
  const srv = v.subnets.find((s) => s.cidr === '10.0.5.0/24'), usr = v.subnets.find((s) => s.cidr === '10.0.6.0/24'), jed = v.subnets.find((s) => s.cidr === '10.0.7.0/24');
  assert.deepEqual(srv.targets, ['10.0.5.10-10.0.5.12'], 'live addresses folded into a range, never the whole /24');
  assert.equal(srv.last_scan.days, 45); assert.ok(srv.why.some((w) => /45 days/.test(w))); assert.ok(srv.why.some((w) => /retest/.test(w))); assert.ok(srv.why.some((w) => /server/.test(w)));
  assert.equal(srv.priority, 25 + 15 + 2 + 10, 'stale 25 + retest 15 + one device in no asset record (10.0.5.12) 2 + server network 10');
  assert.deepEqual(usr.targets, ['10.0.6.20'], 'printer (excluded) and IP phone (fragile) left out'); assert.deepEqual(usr.exclude, ['10.0.6.30', '10.0.6.50']); assert.equal(usr.last_scan, null);
  assert.ok(usr.priority >= 40, 'never scanned');
  assert.match(jed.blocked, /outside the approved scan scope/); assert.ok(!v.recommendations.some((x) => x.subnet === jed.id), 'outside the scope is not proposed');
  assert.deepEqual(v.scope_proposal.add_allowed, ['10.0.7.0/24']); assert.deepEqual(v.scope_proposal.add_exclude, ['10.0.6.30']);
  assert.equal(v.recommendations[0].targets.length > 0, true); assert.match(v.recommendations[0].suggested_reason, /Network Assistant/);
  // the proposal is accepted by Vulnerability Scans as it stands
  const top = v.recommendations[0];
  r = await call('POST', '/vulnscan/scans', { name: top.suggested_name, targets: top.targets, exclude: top.exclude, profile: 'full', window_start: new Date(T + 15 * 60000).toISOString(), window_end: new Date(T + 4 * 3600000).toISOString(), reason: top.suggested_reason }, OP);
  assert.equal(r.status, 200, r.text);
  // VAPT scoping: only the engagement's targets
  r = await call('GET', '/scan-targets?within=10.0.6.0/24', undefined, OP); assert.deepEqual(r.json.subnets.map((s) => s.cidr), ['10.0.6.0/24']);
  assert.equal((await call('GET', '/scan-targets?within=' + 'x'.repeat(4100), undefined, OP)).status, 400);
});
