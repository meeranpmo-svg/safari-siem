// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Migration step 5c (docs/PYTHON-MIGRATION.md): pyengine/snmp_source.py + snmp_client.py must answer exactly like
// collect() in engine/discovery/methods/snmp.js. Both read the same fake agent (v2c, v3 authNoPriv SHA, v3 authPriv
// SHA-256 + AES-128) and must return the same device record AND ask the same questions in the same order (PDU type, OIDs,
// GETBULK size): system group, MACs, ENTITY-MIB, LLDP, CDP, a 300-row ARP table read in pages. Wrong community, wrong
// passphrase, unknown user; the Cisco model fallback; SNMPv3 privacy without the cryptography package falls back to Node.js.
const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const snmpM = require('../engine/discovery/methods/snmp');
const PM = require('../engine/discovery/py-methods');
const { createPyEngine } = require('../engine/pyengine');
const { startFakeSnmpAgent, deviceMib } = require('./helpers/discovery-fakes');

const PY = process.env.PYTHON || 'python3';
const hasPy = spawnSync(PY, ['--version']).status === 0;
const hasCrypto = hasPy && spawnSync(PY, ['-c', 'import cryptography']).status === 0;
const strip = (r) => { const o = JSON.parse(JSON.stringify(r)); delete o.latency_ms; delete o.engine; return o; };

const MIB = (o = {}) => deviceMib(Object.assign({
  descr: 'Cisco IOS Software, C2960X Software (C2960X-UNIVERSALK9-M), Version 15.2(7)E8', name: 'TEST-ACC-SW7', location: 'SYNTHETIC LAB, RUH',
  macs: ['02:00:00:aa:00:01', '02:00:00:aa:00:01', '00:00:00:00:00:00', '02:00:00:aa:00:02'], ifNames: { 1: 'Gi1/0/1', 2: 'Gi1/0/2', 49: 'Te1/1/1' },
  entity: [{ cls: 9, serial: '', model: '' }, { cls: 3, serial: 'FOC9999TEST', model: o.noModel ? '' : 'WS-C2960X-48FPD-L' }, { cls: 10, serial: 'PSU1', model: 'PWR-C1-350WAC' }],
  lldp: [{ localPort: 49, chassisMac: '02:00:00:bb:00:01', portId: 'Te1/0/1', portDesc: 'uplink', sysName: 'TEST-CORE-1', manIp: '10.0.0.1', localPortName: 'Te1/1/1' }],
  cdp: [{ ifIndex: 1, ip: '10.0.0.2', deviceId: 'TEST-AP-1', port: 'GigabitEthernet0', platform: 'cisco AIR-AP2802I' }],
  arp: Array.from({ length: 300 }, (_, i) => ({ ifIndex: 1 + (i % 3), ip: `10.20.${Math.floor(i / 250)}.${(i % 250) + 1}`, mac: `02:00:00:cc:${(i >> 8).toString(16).padStart(2, '0')}:${(i & 255).toString(16).padStart(2, '0')}` }))
    .concat([{ ip: '127.0.0.1', mac: '02:00:00:dd:00:01' }, { ip: '224.0.0.5', mac: '01:00:5e:00:00:05' }, { ip: '10.20.9.9', mac: 'ff:ff:ff:ff:ff:ff' }]),
}, o));
const USERS = [{ user: 'disc-ro', auth: 'sha', authPassword: 'Auth-pass-1!' }, { user: 'disc-priv', auth: 'sha256', authPassword: 'Auth-pass-2!', priv: true, privPassword: 'Priv-pass-2!' }];

async function both(label, cred, mibOpts = {}, opts = {}) {
  const py = createPyEngine({ python: PY });
  const a1 = await startFakeSnmpAgent({ rows: MIB(mibOpts), users: USERS, communities: ['s3cret-ro'] }), a2 = await startFakeSnmpAgent({ rows: MIB(mibOpts), users: USERS, communities: ['s3cret-ro'] });
  try {
    const o = Object.assign({ timeout: 400 }, opts);
    const n = await snmpM.collect('127.0.0.1', Object.assign({}, cred, { target: Object.assign({}, cred.target, { port: a1.port }) }), o);
    const p = await py.call('discovery.collect', { method: 'snmp', cred: Object.assign({}, cred, { target: Object.assign({}, cred.target, { port: a2.port }) }), opts: Object.assign({ host: '127.0.0.1' }, o) });
    assert.deepEqual(strip(p), strip(n), label + ': identical device records');
    assert.deepEqual(a2.reqs, a1.reqs, label + ': the same SNMP requests, in the same order');
    return n;
  } finally { await a1.close(); await a2.close(); }
}

test('Python SNMP collection answers exactly like the Node.js one', { skip: !hasPy && 'python3 not available' }, async () => {
  const v2 = { kind: 'snmp_v2c', target: {}, secret: { community: 's3cret-ro' } };
  const r = await both('v2c', v2);
  assert.equal(r.ok, true); assert.equal(r.serial, 'FOC9999TEST'); assert.equal(r.model, 'WS-C2960X-48FPD-L'); assert.deepEqual(r.macs, ['02:00:00:aa:00:01', '02:00:00:aa:00:02']);
  assert.equal(r.neighbours.length, 2); assert.equal(r.neighbours[0].remote_ip, '10.0.0.1'); assert.equal(r.neighbours[1].local_port, 'Gi1/0/1');
  assert.equal(r.arp.length, 300, '300 ARP rows read in pages; loopback, multicast and broadcast left out');
  assert.equal((await both('Cisco model from the software image', v2, { noModel: true })).model, 'Catalyst 2960-X series (C2960X)');
  assert.equal((await both('wrong community', { kind: 'snmp_v2c', target: {}, secret: { community: 'wrong' } }, {}, { timeout: 200, retries: 0 })).error_class, 'timeout');
  const v3 = await both('v3 authNoPriv SHA', { kind: 'snmp_v3', target: { auth_protocol: 'sha', priv_protocol: 'none' }, secret: { user: 'disc-ro', auth_password: 'Auth-pass-1!' } });
  assert.equal(v3.ok, true); assert.equal(v3.arp.length, 300);
  assert.equal((await both('v3 wrong passphrase', { kind: 'snmp_v3', target: { auth_protocol: 'sha' }, secret: { user: 'disc-ro', auth_password: 'Wrong-pass-1!' } })).error_class, 'auth');
  assert.equal((await both('v3 unknown user', { kind: 'snmp_v3', target: { auth_protocol: 'sha' }, secret: { user: 'nobody', auth_password: 'Auth-pass-1!' } })).error_class, 'auth');
  assert.equal((await both('v3 passphrase too short', { kind: 'snmp_v3', target: { auth_protocol: 'sha' }, secret: { user: 'disc-ro', auth_password: 'short' } })).error_class, 'config');
});

test('Python SNMPv3 authPriv (SHA-256 + AES-128) answers exactly like the Node.js one', { skip: !hasCrypto && 'python cryptography not available' }, async () => {
  const r = await both('v3 authPriv', { kind: 'snmp_v3', target: { auth_protocol: 'sha256', priv_protocol: 'aes' }, secret: { user: 'disc-priv', auth_password: 'Auth-pass-2!', priv_password: 'Priv-pass-2!' } });
  assert.equal(r.ok, true); assert.equal(r.serial, 'FOC9999TEST');
  assert.equal((await both('v3 wrong privacy passphrase', { kind: 'snmp_v3', target: { auth_protocol: 'sha256', priv_protocol: 'aes' }, secret: { user: 'disc-priv', auth_password: 'Auth-pass-2!', priv_password: 'Wrong-priv-2!' } }, {}, { timeout: 200, retries: 0 })).ok, false);
});

test('without the cryptography package, SNMPv3 privacy falls back to the Node.js reader (and says so)', { skip: !hasPy && 'python3 not available' }, async () => {
  // Python with cryptography blocked: the module answers missing_python for authPriv
  const code = "import sys,json;sys.modules['cryptography']=None;sys.path.insert(0,sys.argv[1]);import snmp_source as s;print(json.dumps(s.collect('127.0.0.1',{'kind':'snmp_v3','target':{'port':int(sys.argv[2]),'auth_protocol':'sha256','priv_protocol':'aes'},'secret':{'user':'disc-priv','auth_password':'Auth-pass-2!','priv_password':'Priv-pass-2!'}},{'timeout':400})))";
  const a = await startFakeSnmpAgent({ rows: MIB(), users: USERS });
  try {
    // asynchronous: a synchronous spawn would block the event loop the in-process agent answers on
    const out = await new Promise((ok) => require('node:child_process').execFile(PY, ['-I', '-c', code, path.join(__dirname, '..', 'pyengine'), String(a.port)], { encoding: 'utf8' }, (e, stdout) => ok(stdout)));
    const r = JSON.parse(out); assert.equal(r.error_class, 'missing_python'); assert.match(r.error, /cryptography/);
    // the bridge: a fake Python engine answering missing_python → the Node.js reader answers, marked
    PM.configure({ engine: 'python', py: { call: async () => ({ ok: false, error_class: 'missing_python', error: 'SNMPv3 privacy (AES) needs the Python "cryptography" package' }) } });
    const W = PM.wrapSnmp(snmpM);
    const n = await W.collect('127.0.0.1', { kind: 'snmp_v3', target: { port: a.port, auth_protocol: 'sha256', priv_protocol: 'aes' }, secret: { user: 'disc-priv', auth_password: 'Auth-pass-2!', priv_password: 'Priv-pass-2!' } }, { timeout: 400 });
    assert.equal(n.ok, true); assert.match(n.engine, /^node \(python unavailable: SNMPv3 privacy/);
    assert.equal(W.probe, snmpM.probe, 'the sweep probe stays in Node.js');
  } finally { PM.configure({ python: PY, engine: 'python' }); await a.close(); }
});

test('the Python SNMP client cannot encode a write (SetRequest), like the Node.js one', { skip: !hasPy && 'python3 not available' }, () => {
  const code = "import sys;sys.path.insert(0,sys.argv[1]);import snmp_client as c\nfor t in (0xa3,0xa4,0xa6,0xa7):\n  try:\n    c.encode_pdu(t,1,0,0,['1.3.6.1.2.1.1.5.0']); print('ENCODED',hex(t))\n  except c.SnmpError as e: assert e.code=='forbidden'\ntry:\n  c.encode_value({'type':'OctetString','value':'x'}); print('VALUE')\nexcept c.SnmpError: pass\nprint('ok')";
  const out = spawnSync(PY, ['-I', '-c', code, path.join(__dirname, '..', 'pyengine')], { encoding: 'utf8' });
  assert.equal(out.stdout.trim(), 'ok', out.stderr);
});
