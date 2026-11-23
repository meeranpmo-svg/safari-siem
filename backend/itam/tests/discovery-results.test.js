// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Classification (rules + OUI + sysObjectID enterprise numbers), correlation of observations into one device, and the
// CMDB duplicate check (MAC and serial strong, host name weak) used by the results review.
const test = require('node:test');
const assert = require('node:assert/strict');
const { classify, ouiVendor, enterpriseVendor } = require('../engine/discovery/classify');
const merge = require('../engine/model/merge');
const { startApp } = require('./helpers');

test('OUI and enterprise-number tables', () => {
  assert.equal(ouiVendor('00:50:56:12:34:56'), 'VMware');
  assert.equal(ouiVendor('00-09-0F-AA-BB-CC'), 'Fortinet');
  assert.equal(ouiVendor('0015.5d01.0203'), 'Microsoft (Hyper-V)');
  assert.equal(ouiVendor('02:00:00:00:00:01'), null);
  assert.equal(ouiVendor('nonsense'), null);
  assert.equal(enterpriseVendor('1.3.6.1.4.1.12356.101.1.1'), 'Fortinet');
  assert.equal(enterpriseVendor('.1.3.6.1.4.1.25461.2.3.18'), 'Palo Alto Networks');
  assert.equal(enterpriseVendor('1.3.6.1.4.1.9.1.2494'), 'Cisco');
  assert.equal(enterpriseVendor('1.3.6.1.2.1.1'), null);
});

test('classification covers every device type with reasons and confidence', () => {
  const c = (d) => classify(Object.assign({ methods: {} }, d));
  const fw = c({ sys_descr: 'SYNTHETIC FortiGate-100F v7.2.8', sys_object_id: '1.3.6.1.4.1.12356.101.1.1004', mac: '00:09:0f:aa:bb:01', methods: { snmp: {} } });
  assert.deepEqual([fw.type, fw.vendor], ['firewall', 'Fortinet']);
  assert.ok(fw.confidence >= 90 && fw.reasons.length >= 2);
  assert.equal(c({ sys_descr: 'Cisco IOS XE Software, Catalyst C9300' }).type, 'switch');
  assert.equal(c({ sys_descr: 'Cisco IOS Software, ISR4331 Software' }).type, 'router');
  assert.equal(c({ sys_descr: 'ArubaOS (MODEL: 515), Aruba Instant 8.10' }).type, 'ap');
  assert.equal(c({ sys_descr: 'HP LaserJet MFP M428 JetDirect' }).type, 'printer');
  assert.equal(c({ open_ports: [9100, 80] }).type, 'printer');
  assert.equal(c({ extra: { cucm: { model: 'Cisco 8845' } } }).type, 'phone');
  assert.equal(c({ mac: '00:15:65:00:00:01' }).type, 'phone', 'Yealink OUI');
  assert.equal(c({ extra: { vcenter: { kind: 'vm' } }, mac: '00:50:56:00:00:01' }).type, 'vm');
  assert.equal(c({ extra: { hyperv: { kind: 'vm' } } }).type, 'vm');
  assert.equal(c({ extra: { cloud: { provider: 'AWS' } } }).type, 'cloud');
  assert.equal(c({ extra: { ad: { os: 'Windows Server 2019 Standard' } } }).type, 'server');
  assert.equal(c({ extra: { ad: { os: 'Windows 11 Enterprise' } } }).type, 'workstation');
  assert.equal(c({ extra: { ad: { os: 'Windows Server 2022', is_dc: true } } }).type, 'server');
  assert.equal(c({ open_ports: [135, 445, 3389] }).type, 'workstation');
  assert.equal(c({ open_ports: [22] }).type, 'server');
  assert.equal(c({ hostname: 'fw-hq-01' }).type, 'unknown', 'a host-name hint alone is too weak');
  const u = c({ methods: { arp: {} }, mac: '02:11:22:33:44:55' });
  assert.deepEqual([u.type, u.confidence], ['unknown', 0]);
  assert.ok(u.reasons.includes('seen only in the ARP table'));
});

test('merge.duplicateCandidates: MAC and serial are strong, host name is a weak hint only', () => {
  const assets = [
    { id: 'as_1', name: 'TEST-FW-01', mac: '00:09:0f:aa:bb:01', serial: 'FGTEST01', status: 'in_use', sources: [] },
    { id: 'as_2', name: ('test-app01.' + 'corp-hq.com'), status: 'in_use', sources: [{ source: 'agent', keys: ['mac:005056aa0001'] }] },
    { id: 'as_3', name: 'TEST-DISPOSED', mac: '00:00:0c:11:22:33', status: 'disposed', sources: [] },
  ];
  assert.deepEqual(merge.duplicateCandidates({ mac: '00-09-0F-AA-BB-01' }, assets).map((x) => [x.asset_id, x.by, x.strength]), [['as_1', ['mac'], 'strong']]);
  assert.deepEqual(merge.duplicateCandidates({ serial: 'fgtest01', hostname: 'test-fw-01' }, assets).map((x) => [x.asset_id, x.by, x.strength]), [['as_1', ['serial', 'hostname'], 'strong']]);
  assert.deepEqual(merge.duplicateCandidates({ macs: ['00:50:56:aa:00:01'] }, assets).map((x) => x.asset_id), ['as_2'], 'MAC carried by another source key');
  assert.deepEqual(merge.duplicateCandidates({ hostname: 'TEST-APP01' }, assets).map((x) => [x.asset_id, x.strength]), [['as_2', 'weak']], 'FQDN vs short name');
  assert.deepEqual(merge.duplicateCandidates({ mac: '00:00:0c:11:22:33' }, assets), [], 'disposed assets are not candidates');
});

test('correlation: one device per MAC / serial / source id; IP joins only inside a scope and without a MAC conflict', async (t) => {
  const h = await startApp({ noAi: true });
  t.after(() => h.close());
  const D = h.app.discovery.devices;
  const ctx = { scope_id: 'sc_a', site: 'Riyadh HQ', run_id: 'dr_1' };
  const a = D.observe({ method: 'sweep', ip: '10.20.0.5', open_ports: [22, 443] }, ctx);
  const b = D.observe({ method: 'arp', ip: '10.20.0.5', mac: '00:09:0f:aa:bb:01' }, ctx);
  assert.equal(b.id, a.id, 'ARP MAC attached to the swept host (same scope, same IP)');
  const c = D.observe({ method: 'snmp', ip: '10.20.0.5', mac: '00:09:0F:AA:BB:01', serial: 'FGTEST01', sys: { descr: 'SYNTHETIC FortiGate-100F', name: 'TEST-FW-01', object_id: '1.3.6.1.4.1.12356.101.1.1' } }, ctx);
  assert.equal(c.id, a.id);
  assert.deepEqual([c.type, c.vendor, c.hostname, c.serial, c.seen_count], ['firewall', 'Fortinet', 'test-fw-01', 'FGTEST01', 1]);
  assert.deepEqual(Object.keys(c.methods).sort(), ['arp', 'snmp', 'sweep']);
  // a later run with a different IP but the same serial is the same device; seen_count counts runs
  const d = D.observe({ method: 'snmp', ip: '10.20.9.9', serial: 'fgtest01' }, Object.assign({}, ctx, { run_id: 'dr_2' }));
  assert.equal(d.id, a.id); assert.equal(d.seen_count, 2);
  assert.deepEqual(d.ips.slice(0, 2), ['10.20.9.9', '10.20.0.5']);
  // same IP, different MAC (a reused DHCP lease) → a different device
  const e = D.observe({ method: 'arp', ip: '10.20.0.5', mac: '02:aa:bb:cc:dd:ee' }, ctx);
  assert.notEqual(e.id, a.id);
  // same IP in ANOTHER scope does not join
  const f = D.observe({ method: 'sweep', ip: '10.20.0.77' }, { scope_id: 'sc_b' });
  const g = D.observe({ method: 'sweep', ip: '10.20.0.77' }, { scope_id: 'sc_c' });
  assert.notEqual(f.id, g.id);
  // source ids (VM uuid) correlate across methods
  const v1 = D.observe({ method: 'vcenter', hostname: 'TEST-APP01', uid: 'vc:4210aaaa', extra: { vcenter: { kind: 'vm' } } }, ctx);
  const v2 = D.observe({ method: 'vcenter', ips: ['10.20.0.31'], macs: ['00:50:56:aa:00:01'], uid: 'vc:4210aaaa' }, ctx);
  assert.equal(v1.id, v2.id); assert.equal(v2.type, 'vm');
  assert.equal(D.observe({ method: 'sweep' }, ctx), null, 'nothing to identify → ignored');
});
