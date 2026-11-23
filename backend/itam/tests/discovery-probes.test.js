// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Network sweep (fake ping/fping + fake TCP connect — no packets leave the process), ARP table parsing, and SNMP v2c/v3
// against an in-process fake agent on 127.0.0.1 (system group, ifPhysAddress, ENTITY serial, LLDP and CDP neighbours).
const test = require('node:test');
const assert = require('node:assert/strict');
const sweep = require('../engine/discovery/methods/sweep');
const snmpM = require('../engine/discovery/methods/snmp');
const { startFakeSnmpAgent, deviceMib, fakeExec, fakeConnect } = require('./helpers/discovery-fakes');

test('ICMP: fping/ping run with strict argv arrays (no shell); results parsed; bad input refused', async () => {
  const exec = fakeExec({ alive: ['10.20.0.1', '10.20.0.5'] });
  const up = await sweep.icmp(['10.20.0.1', '10.20.0.2', '10.20.0.5'], { exec, fping_bin: '/usr/bin/fping', timeout_ms: 500 });
  assert.deepEqual([...up].sort(), ['10.20.0.1', '10.20.0.5']);
  assert.equal(exec.calls.length, 1);
  assert.equal(exec.calls[0].bin, '/usr/bin/fping');
  assert.deepEqual(exec.calls[0].args, ['-a', '-q', '-r', '1', '-t', '500', '10.20.0.1', '10.20.0.2', '10.20.0.5']);
  for (const a of exec.calls[0].args) assert.match(a, /^[-\w.]+$/, 'only plain tokens reach argv');
  // ping mode: one process per host
  const exec2 = fakeExec({ alive: ['10.20.0.2'] });
  const up2 = await sweep.icmp(['10.20.0.1', '10.20.0.2'], { exec: exec2, mode: 'ping', ping_bin: '/usr/bin/ping', timeout_ms: 800 });
  assert.deepEqual([...up2], ['10.20.0.2']);
  assert.deepEqual(exec2.calls[1].args, ['-n', '-q', '-c', '1', '-W', '1', '10.20.0.2']);
  // injection attempts never reach a process
  await assert.rejects(sweep.icmp(['10.0.0.1; rm -rf /'], { exec }), /non-IPv4 argument/);
  await assert.rejects(sweep.icmp(['$(reboot)'], { exec, mode: 'ping' }), /non-IPv4 argument/);
  await assert.rejects(sweep.icmp(['10.0.0.1'], { exec, fping_bin: 'fping' }), /absolute/);
  assert.equal(exec.calls.length, 1, 'no extra process was started');
  // fping exit 2+ (e.g. no ICMP permission) surfaces as icmp_unavailable
  await assert.rejects(sweep.icmp(['10.0.0.1'], { exec: async () => ({ code: 4, stdout: '' }) }), (e) => e.code === 'icmp_unavailable');
  // the real exec helper never uses a shell
  assert.match(sweep.realExec.toString(), /shell: false/);
});

test('TCP connect probes: open or refused proves the host is up; timeouts do not', async () => {
  const connect = fakeConnect({ open: { '10.20.0.5': [22, 443] }, closed: ['10.20.0.6'] });
  assert.deepEqual(await sweep.tcp('10.20.0.5', [22, 80, 443, 3389], { connect }), { alive: true, open: [22, 443] });
  assert.deepEqual(await sweep.tcp('10.20.0.6', [22], { connect }), { alive: true, open: [] });
  assert.deepEqual(await sweep.tcp('10.20.0.7', [22, 445], { connect }), { alive: false, open: [] });
});

test('ARP table: only complete entries with a real MAC', () => {
  const text = [
    'IP address       HW type     Flags       HW address            Mask     Device',
    '10.20.0.1        0x1         0x2         00:09:0f:aa:bb:01     *        ens160',
    '10.20.0.9        0x1         0x0         00:00:00:00:00:00     *        ens160',
    '10.20.0.12       0x1         0x2         00:50:56:12:34:56     *        ens160',
    'garbage line',
  ].join('\n');
  assert.deepEqual(sweep.parseArp(text), [{ ip: '10.20.0.1', mac: '00:09:0f:aa:bb:01', device: 'ens160' }, { ip: '10.20.0.12', mac: '00:50:56:12:34:56', device: 'ens160' }]);
  assert.equal(sweep.arp({ readFile: () => text }).length, 2);
  assert.throws(() => sweep.arp({ readFile: () => { throw Object.assign(new Error('x'), { code: 'EACCES' }); } }), (e) => e.code === 'arp_unavailable');
});

const SWITCH = () => deviceMib({
  descr: 'SYNTHETIC Cisco IOS Software, Catalyst C9300 TEST-SW-01', objectId: '1.3.6.1.4.1.9.1.2494', name: 'test-sw-01', location: 'Riyadh HQ / DC row A',
  macs: ['00:00:0c:11:22:33', '00:00:0c:11:22:34'], ifNames: { 3: 'Gi1/0/3', 7: 'Gi1/0/7' },
  entity: [{ cls: 10, serial: 'PSU-TESTSN', model: 'PWR-TEST' }, { cls: 3, serial: 'FOCTEST0001', model: 'C9300-48P' }],
  lldp: [{ localPort: 3, localPortName: 'Gi1/0/3', chassisMac: '00:09:0f:aa:bb:01', portId: 'port1', portDesc: 'internal1', sysName: 'test-fw-01', manIp: '10.20.0.1' }],
  cdp: [{ ifIndex: 7, ip: '10.20.0.40', deviceId: 'SEP0004F2ABCDEF', port: 'Port 1', platform: 'SYNTHETIC IP Phone' }],
});

test('SNMP v2c: liveness probe + full collection (system, MACs, chassis serial, LLDP + CDP neighbours)', async (t) => {
  const agent = await startFakeSnmpAgent({ rows: SWITCH(), communities: ['test-community-r0'] });
  t.after(() => agent.close());
  const cred = { kind: 'snmp_v2c', target: { port: agent.port }, secret: { community: 'test-community-r0' } };
  const p = await snmpM.probe('127.0.0.1', cred, { timeout: 500 });
  assert.equal(p.ok, true); assert.match(p.descr, /Catalyst/);
  const c = await snmpM.collect('127.0.0.1', cred, { timeout: 500 });
  assert.equal(c.ok, true);
  assert.deepEqual(c.sys, { descr: 'SYNTHETIC Cisco IOS Software, Catalyst C9300 TEST-SW-01', object_id: '1.3.6.1.4.1.9.1.2494', name: 'test-sw-01', location: 'Riyadh HQ / DC row A' });
  assert.deepEqual(c.macs, ['00:00:0c:11:22:33', '00:00:0c:11:22:34']);
  assert.equal(c.serial, 'FOCTEST0001', 'the chassis entity (class 3) serial wins over a PSU');
  assert.equal(c.model, 'C9300-48P');
  const lldp = c.neighbours.find((n) => n.via === 'lldp');
  assert.deepEqual(lldp, { via: 'lldp', local_port: 'Gi1/0/3', remote_name: 'test-fw-01', remote_port: 'internal1', remote_mac: '00:09:0f:aa:bb:01', remote_chassis: '00:09:0f:aa:bb:01', remote_ip: '10.20.0.1' });
  const cdp = c.neighbours.find((n) => n.via === 'cdp');
  assert.deepEqual(cdp, { via: 'cdp', local_port: 'Gi1/0/7', remote_name: 'SEP0004F2ABCDEF', remote_port: 'Port 1', remote_platform: 'SYNTHETIC IP Phone', remote_ip: '10.20.0.40', remote_mac: null, remote_chassis: null });
  // read-only: only GET / GETNEXT / GETBULK ever reached the agent
  assert.ok(agent.seen.every((tag) => [0xa0, 0xa1, 0xa5].includes(tag)), `PDU tags ${agent.seen}`);
  // wrong community → silently dropped → timeout class
  const bad = await snmpM.probe('127.0.0.1', { kind: 'snmp_v2c', target: { port: agent.port }, secret: { community: 'wrong-one' } }, { timeout: 200 });
  assert.deepEqual([bad.ok, bad.error_class], [false, 'timeout']);
});

test('SNMP v3 authPriv (SHA-256 + AES-128): collects; a wrong passphrase is an auth error', async (t) => {
  const agent = await startFakeSnmpAgent({ rows: SWITCH(), communities: [], users: [{ user: 'itam-disc', auth: 'sha256', authPassword: 'Synthetic-Auth-Pass-1', priv: 'aes', privPassword: 'Synthetic-Priv-Pass-1' }] });
  t.after(() => agent.close());
  const cred = { kind: 'snmp_v3', target: { port: agent.port, auth_protocol: 'sha256', priv_protocol: 'aes' }, secret: { user: 'itam-disc', auth_password: 'Synthetic-Auth-Pass-1', priv_password: 'Synthetic-Priv-Pass-1' } };
  const c = await snmpM.collect('127.0.0.1', cred, { timeout: 800 });
  assert.equal(c.ok, true);
  assert.equal(c.serial, 'FOCTEST0001');
  assert.equal(c.neighbours.length, 2);
  const wrong = await snmpM.probe('127.0.0.1', { kind: 'snmp_v3', target: { port: agent.port, auth_protocol: 'sha256', priv_protocol: 'aes' }, secret: { user: 'itam-disc', auth_password: 'Not-The-Right-Pass', priv_password: 'Synthetic-Priv-Pass-1' } }, { timeout: 800 });
  assert.deepEqual([wrong.ok, wrong.error_class], [false, 'auth']);
  // sessionOptions maps the vault record (authNoPriv when no priv passphrase)
  const o = snmpM.sessionOptions({ kind: 'snmp_v3', target: { auth_protocol: 'sha' }, secret: { user: 'u', auth_password: '12345678' } });
  assert.deepEqual([o.version, o.authProtocol, o.privProtocol], ['3', 'sha', undefined]);
});

test('LLDP / CDP parsers handle missing columns and the management-address index', () => {
  assert.deepEqual(snmpM.decodeManAddrIndex('0.12.3.1.4.10.1.2.3'), { key: '0.12.3', localPort: 12, ip: '10.1.2.3' });
  assert.equal(snmpM.decodeManAddrIndex('0.12.3.2.16.1').ip, null); // IPv6 management address ignored
  const n = snmpM.parseLldp([{ index: '0.5.1', cols: { 9: { type: 'OctetString', value: Buffer.from('peer-sw') }, 7: { type: 'OctetString', value: Buffer.from('Te1/1') } } }], [], []);
  assert.deepEqual(n, [{ via: 'lldp', local_port: '5', remote_name: 'peer-sw', remote_port: 'Te1/1', remote_mac: null, remote_chassis: null, remote_ip: null }]);
  assert.deepEqual(snmpM.parseCdp([{ index: '9.1', cols: { 6: { type: 'OctetString', value: Buffer.from('rtr-1') } } }], new Map()), [{ via: 'cdp', local_port: '9', remote_name: 'rtr-1', remote_port: null, remote_platform: null, remote_ip: null, remote_mac: null, remote_chassis: null }]);
});

test('snmp: Cisco model fallbacks from the chassis description and the sysDescr software image', () => {
  const { modelFromSysDescr, modelFromDescr } = require('../engine/discovery/methods/snmp');
  assert.equal(modelFromDescr('Cisco Catalyst 9300 Series 48-port PoE Switch'), 'Catalyst 9300 Series');
  assert.equal(modelFromDescr('C9300-48P chassis'), 'C9300-48P');
  assert.equal(modelFromDescr('C2960X-UNIVERSALK9-M'), null);
  assert.equal(modelFromSysDescr('Cisco IOS Software [Dublin], Catalyst L3 Switch Software (CAT9K_IOSXE), Version 17.12.1'), 'Catalyst 9000 series (CAT9K_IOSXE)');
  assert.equal(modelFromSysDescr('Cisco IOS Software, C2960X Software (C2960X-UNIVERSALK9-M), Version 15.2(7)E'), 'Catalyst 2960-X series (C2960X)');
  assert.equal(modelFromSysDescr('Linux edge 5.4'), null);
});

test('classify: Oracle Solaris from SNMP sysDescr (version + SPARC / x86), end of support from the lifecycle table', () => {
  const { classify } = require('../engine/discovery/classify');
  const L = require('../engine/lifecycle');
  const R = L.compile([]), now = Date.parse('2026-10-12');
  const a = classify({ sys_descr: 'SunOS ora-db01 5.11 11.4.42.111.0 sun4v', methods: { snmp: {} } });
  assert.deepEqual([a.type, a.vendor, a.os], ['server', 'Oracle', 'Oracle Solaris 11.4 (SPARC)']);
  const b = classify({ sys_descr: 'SunOS legacy 5.10 Generic_150400-59 i86pc', methods: { snmp: {} } });
  assert.equal(b.os, 'Oracle Solaris 10 (x86)');
  assert.equal(L.evaluate(a.os, R, now).status, 'supported');
  assert.equal(L.evaluate(b.os, R, now).status, 'eol');
  assert.equal(L.evaluate('Oracle Solaris 11.3 (SPARC)', R, now).status, 'eol');
  const { kindFor } = require('../engine/discovery/siem');
  assert.equal(kindFor({ type: 'server', os: 'Oracle Solaris 11.4 (SPARC)', discovery: { class: 'server' } }).kind, 'syslog');
});

test('classify: NetApp ONTAP and HPE MSA 2060 from SNMP are storage; storage protocols alone are a weaker sign', () => {
  const { classify, ITAM_TYPE } = require('../engine/discovery/classify');
  const n = classify({ sys_descr: 'NetApp Release 9.13.1P6: Tue Jan 16 2024', sys_object_id: '1.3.6.1.4.1.789.2.5', methods: { snmp: {} } });
  assert.deepEqual([n.type, n.vendor], ['storage', 'NetApp']);
  const m = classify({ sys_descr: 'HPE MSA 2060 SAN Storage', methods: { snmp: {} } });
  assert.deepEqual([m.type, m.vendor], ['storage', 'HPE']);
  assert.equal(ITAM_TYPE.storage, 'storage');
  assert.equal(classify({ extra: { storage: { protocols: ['iscsi', 'ndmp'] } }, methods: { storage: {} } }).type, 'storage');
  assert.notEqual(classify({ extra: { storage: { protocols: ['nfs'] } }, open_ports: [22, 2049], methods: { storage: {}, sweep: {} } }).type, 'storage');
});
