// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Hyper-V Virtual Network Map (engine/hyperv-netmap.js) over SYNTHETIC host reports: tolerant parsing (a lone item sent as an object,
// bad VLAN / MAC dropped); the map, the per-group baseline learned from the hosts (a host without the group's switch), uplink down,
// single uplink, mixed speed, slow link, management untagged on the VM switch, not connected, trunk, isolated, duplicate MAC / IP;
// the VLAN matrix; the VM path trace; the changes between two reports; through the real routes: the report import keeps the
// network, viewer reads, unknown VM 404, missing vm 400.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');
const N = require('../engine/hyperv-netmap');
const { normMetrics } = require('../engine/hyperv-manager');

const DAY = 86400000, VIEW = { user: 'vera.syn', role: 'viewer' }, ADM = { user: 'admin.syn', role: 'admin' };
const NIC = (name, desc, status = 'Up', mbps = 10000) => ({ name, desc, status, link_mbps: mbps, mac: '00-15-5D-00-' + name.slice(-2) + '-01' });
function net(o = {}) {
  const i = o.i || 1, m = (k) => '00155D0' + i + '02' + String(k).padStart(2, '0'), ip = (k) => '10.20.1' + i + '.' + k;
  return {
    physical: [NIC('NIC01', 'Intel X710 #1'), NIC('NIC02', 'Intel X710 #2', o.down ? 'Disconnected' : 'Up', o.slow ? 1000 : 10000), NIC('NIC03', 'Broadcom 1G #1', 'Up', 100)],
    switches: [{ name: 'vSwitch-Prod', type: 'External', set: true, mgmt_os: true, uplinks: ['Intel X710 #1', 'Intel X710 #2'] },
      ...(o.noBackup ? [] : [{ name: 'vSwitch-Backup', type: 'External', set: false, mgmt_os: false, uplinks: 'Broadcom 1G #1' }]),
      { name: 'Lab-Private', type: 'Private', uplinks: [] }],
    adapters: [
      { mgmt_os: true, name: 'Management', switch: 'vSwitch-Prod', mac: m(1), ips: ['10.20.8.1' + i], vlan_mode: o.mgmtTagged ? 'Access' : 'Untagged' , vlan: o.mgmtTagged ? 8 : null },
      { vm: 'APP-SYN-01', name: 'Network Adapter', switch: 'vSwitch-Prod', mac: m(3), ips: [ip(21)], vlan_mode: 'Access', vlan: 10, status: 'Ok' },
      { vm: 'DB-SYN-01', name: 'Network Adapter', switch: 'vSwitch-Prod', mac: o.dupMac ? '00155D010203' : m(4), ips: [o.dupIp ? ip(21) : ip(22)], vlan_mode: 'Access', vlan: 10, status: 'Ok' },
      { vm: 'FW-SYN-01', name: 'Trunk', switch: 'vSwitch-Prod', mac: m(5), vlan_mode: 'Trunk', allowed: '10,20,30', native: 1 },
      { vm: 'BKP-SYN-01', name: 'Backup', switch: 'vSwitch-Backup', mac: m(6), vlan_mode: 'Untagged' },
      { vm: 'LAB-SYN-01', name: 'Lab', switch: 'Lab-Private', mac: m(7), vlan_mode: 'Access', vlan: 99 },
      { vm: 'OLD-SYN-01', name: 'Network Adapter', switch: '', mac: m(8), vlan_mode: 'Untagged' }],
  };
}
const rep = (name, o = {}, at = '2026-11-20T06:00:00Z') => ({ collected_at: at, host: { name, logical_processors: 32, network: net(o) },
  vms: ['APP-SYN-01', 'DB-SYN-01', 'FW-SYN-01', 'BKP-SYN-01', 'LAB-SYN-01'].map((v) => ({ name: v, state: 'Running' })).concat([{ name: 'OLD-SYN-01', state: 'Running' }]) });

test('parsing is tolerant: a lone uplink as a string, bad VLAN and MAC dropped, nothing invented', () => {
  const x = N.normNetwork({ switches: { name: 'S', type: 'External', uplinks: 'NIC A' }, adapters: { vm: 'V', name: 'A', vlan_mode: 'Access', vlan: 99999, mac: 'zz', ips: ['10.0.0.1', 'fe80::1'] } });
  assert.deepEqual(x.switches[0].uplinks, ['NIC A']); assert.equal(x.adapters[0].vlan, null); assert.equal(x.adapters[0].mac, ''); assert.deepEqual(x.adapters[0].ips, ['10.0.0.1']);
  assert.equal(N.normNetwork(undefined), null); assert.equal(normMetrics({ host: { name: 'H' } }).host.network, null, 'an older script: no network, not an empty one');
  assert.equal(N.groupOf('HQPSUPERM01.safari.example'), 'hqpsuperm'); assert.equal(N.groupOf('HV-JED-02', { 'hv-jed-02': 'Jeddah' }), 'Jeddah');
});

test('analysis: baseline, uplinks, segmentation, duplicates, VLAN matrix, trace, changes', () => {
  const R = [rep('HV-SYN-01', { i: 1 }), rep('HV-SYN-02', { i: 2, down: true, dupMac: true }), rep('HV-SYN-03', { i: 3, noBackup: true, slow: true, mgmtTagged: true })].map(normMetrics);
  const v = N.analyse(R, { now: Date.parse('2026-11-20T07:00:00Z') });
  const has = (code, host) => v.findings.some((f) => f.code === code && (!host || f.host === host));
  assert.ok(has('baseline', 'HV-SYN-03') && /no switch "vSwitch-Backup" that 2 of 3 hosts of hv-syn have/.test(v.findings.find((f) => f.code === 'baseline').title), 'the learned baseline');
  assert.ok(has('uplink-down', 'HV-SYN-02')); assert.ok(has('single-uplink', 'HV-SYN-01'), 'backup switch on one NIC');
  assert.ok(has('mixed-speed', 'HV-SYN-03') && has('slow-link', 'HV-SYN-01'), '1 Gbps + 10 Gbps; a 100 Mbps link');
  assert.ok(has('mgmt-untagged', 'HV-SYN-01') && !has('mgmt-untagged', 'HV-SYN-03'), 'management untagged on the VM switch');
  assert.ok(has('not-connected') && has('trunk') && has('isolated') && has('dup-mac'), v.findings.map((f) => f.code).join(','));
  assert.ok(!has('dup-ip'), 'no IP is used twice');
  assert.equal(v.findings[0].severity, 'high'); assert.equal(v.kpis.hosts, 3); assert.equal(v.kpis.uplinks_down, 1);
  const v10 = v.vlans.find((x) => x.vlan === '10'); assert.deepEqual(v10.hosts, { 'HV-SYN-01': 2, 'HV-SYN-02': 2, 'HV-SYN-03': 2 });
  assert.ok(v.insights.some((i) => /baseline/.test(i)));
  const t = N.trace(v, 'app-syn-01'); assert.equal(t.paths.length, 3);
  const p2 = t.paths.find((p) => p.host === 'HV-SYN-02'); assert.deepEqual(p2.steps.map((x) => x.hop), ['VM', 'Adapter', 'VLAN', 'Virtual switch', 'Uplink', 'Uplink']); assert.ok(p2.steps.some((x) => x.bad), 'the down uplink on its path');
  assert.deepEqual(p2.peers, ['DB-SYN-01']);
  assert.equal(N.trace(v, 'lab-syn-01').paths[0].steps.pop().hop, 'Physical network');
  assert.throws(() => N.trace(v, 'nope'), /no reported VM adapter/);
  const d = N.diff(normMetrics(rep('X', { i: 1 })).host.network, normMetrics(rep('X', { i: 1, noBackup: true, mgmtTagged: true })).host.network); assert.ok(d.some((x) => x.what === 'switch:vSwitch-Backup' && x.change === 'removed'));
  assert.ok(d.some((x) => x.what === 'adapter:management OS/Management' && x.change === 'changed' && /VLAN 8/.test(x.now)));
  const one = N.analyse([normMetrics({ collected_at: '2026-11-20T06:00:00Z', host: { name: 'OLD' } })], {}); assert.match(one.insights[0], /not their virtual network yet/);
});

test('routes: the report import keeps the network, changes recorded, viewer reads, trace validated', async (t) => {
  let clock = Date.parse('2026-11-20T06:00:00Z');
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true, now: () => clock, python: process.env.PYTHON || 'python3' });
  const call = (m, p, b, who) => e.req(m, p, Object.assign(b !== undefined ? { body: b } : {}, who));
  const sr = await call('POST', '/discovery/scopes', { name: 'HQ Hyper-V', site: 'Riyadh HQ', targets: ['10.20.8.0/24'], methods: { hyperv: { enabled: true } } }, ADM); assert.equal(sr.status, 200, sr.text);
  let r = await call('POST', '/discovery/hyperv/import', { scope_id: sr.json.scope.id, report: rep('HV-SYN-01') }, ADM); assert.equal(r.status, 200, r.text);
  clock += 900000; r = await call('POST', '/discovery/hyperv/import', { scope_id: sr.json.scope.id, report: rep('HV-SYN-01', { mgmtTagged: true }, '2026-11-20T06:15:00Z') }, ADM); assert.equal(r.status, 200, r.text);
  const v = await call('GET', '/hyperv/network', undefined, VIEW); assert.equal(v.status, 200, v.text);
  assert.equal(v.json.kpis.hosts, 1); assert.ok(v.json.hosts[0].switches.length === 3);
  assert.equal(v.json.changes.length, 1); assert.match(v.json.changes[0].changes[0].now, /VLAN 8/);
  assert.equal((await call('GET', '/hyperv/network/trace?vm=APP-SYN-01', undefined, VIEW)).json.paths[0].steps[3].name, 'vSwitch-Prod');
  assert.equal((await call('GET', '/hyperv/network/trace?vm=NOPE', undefined, VIEW)).status, 404);
  assert.equal((await call('GET', '/hyperv/network/trace', undefined, VIEW)).status, 400);
});
