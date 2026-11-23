// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Servers by platform (engine/servers.js + pyengine/server_rules.py): every server / VM in the asset register lands on its
// platform from facts (OS, software, tags, Exchange host name, the hypervisor a VM runs on) with the reason kept; a server
// whose OS nobody recorded is "unknown", never guessed; findings come with a fix (file system full, failed service / SMF
// maintenance, no backup, end of life, missing critical patches, OS not read and why); Solaris / Linux are read over SSH
// only with a trusted host key (the password is never sent otherwise), a fresh Database Servers reading of the same IP is
// reused; roles (viewer refused, operator reads, admin chooses the SSH login), validation errors name the field, and the
// SSH choice and a manual read are audited. Data is SYNTHETIC; SSH and the add-ons are stubs.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { registerServerRoutes } = require('../engine/servers');

const ADM = { user: 'syed', role: 'admin', ip: '' };
const NOW = Date.parse('2026-10-26T08:00:00Z');
const SOL_OK = { os: 'Oracle Solaris 11.4 SPARC', ncpu: 8, load5: 1.0, mem_total_mb: 65536, mem_avail_mb: 30000, swap_total_mb: 4096, swap_used_mb: 100,
  filesystems: [{ mount: '/', used_pct: 96, avail_kb: 400000 }, { mount: '/export', used_pct: 40, avail_kb: 9e7 }], inodes: [], failed_services: [{ name: 'svc:/network/ntp:default', state: 'maintenance' }],
  ntp_synced: null, last_patch: '2026-09-01', uptime_s: 86400 * 20, top: [] };

async function setup(t) {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  const A = e.app.assets, mk = (o) => A.create(Object.assign({ status: 'in_use' }, o), ADM).asset;
  const ids = {
    win: mk({ name: 'APP-SYN-01', type: 'vm', os: 'Windows Server 2019 Datacenter', mgmt_ip: '10.8.0.11' }).id,
    exch: mk({ name: 'EXCH01', type: 'server', os: 'Windows Server 2016', mgmt_ip: '10.8.0.12', software: [{ name: 'Microsoft Exchange Server 2016 CU23' }] }).id,
    sol: mk({ name: 'SOL-SYN-DB', type: 'server', os: 'Oracle Solaris 11.4', mgmt_ip: '10.8.0.21' }).id,
    ol: mk({ name: 'OL-SYN-APP', type: 'vm', os: 'Oracle Linux Server 8.9', mgmt_ip: '10.8.0.22' }).id,
    ol2: mk({ name: 'OL-SYN-DB2', type: 'server', os: 'Oracle Linux 7', mgmt_ip: '10.8.0.23' }).id,
    esx: mk({ name: 'ESX-SYN-01', type: 'server', os: 'VMware ESXi 7.0.3', mgmt_ip: '10.8.0.31', warranty: { end: '2025-01-31' } }).id,
    nos: mk({ name: '<b>NOOS-SYN</b>', type: 'server' }).id,
  };
  mk({ name: 'LAPTOP-SYN', type: 'laptop', os: 'Windows 11' });   // not a server: never listed
  // a Windows VM in vCenter (the hypervisor fact comes from the vCenter sync's device record)
  e.app.store.collection('disc_devices').put({ id: 'dd-win', ip: '10.8.0.11', asset_id: ids.win, status: 'approved', extra: { vcenter: { kind: 'vm' } }, last_seen: NOW });
  e.app.store.collection('disc_devices').put({ id: 'dd-sol', ip: '10.8.0.21', asset_id: ids.sol, status: 'approved', extra: { unix_login: { credential: 'SSH-RO', os: 'SunOS 5.11' } }, last_seen: NOW });
  e.app.store.collection('disc_devices').put({ id: 'dd-ol', ip: '10.8.0.22', asset_id: ids.ol, status: 'approved', extra: { unix_login: { credential: 'SSH-RO' } }, last_seen: NOW });
  const trust = e.app.store.collection('disc_trust');
  trust.put({ id: 'ssh:10.8.0.21:22', state: 'trusted', fp: 'a'.repeat(64) });
  trust.put({ id: 'ssh:10.8.0.22:22', state: 'seen', fp: 'b'.repeat(64) });   // seen, not trusted: never logged in to
  // Database Servers already read OL-SYN-DB2 a minute ago: reused, no second login
  e.app.store.collection('db_server_health').put({ id: '10.8.0.23', at: new Date(NOW - 60000).toISOString(), server: { os: 'Oracle Linux Server 7.9', filesystems: [{ mount: '/u01', used_pct: 50 }], inodes: [], failed_services: [] } });
  e.app.addons.backup = { view: () => ({ platforms: [{ id: 'veeam' }], assets: [{ asset_id: ids.win, status: 'protected' }, { asset_id: ids.sol, status: 'none' }, { asset_id: ids.exch, status: 'failed', last_attempt: '2026-10-25' }] }) };
  e.app.addons.lifecycle = { view: () => ({ items: [{ key: 'asset:' + ids.ol2, status: 'eol', product: 'Oracle Linux 7', eol: '2024-12-31' }] }) };
  e.app.addons.manageengine = { computers: () => ({ computers: [{ asset_id: ids.exch, missing: 9, critical: 3 }] }) };
  const helperCalls = [], vault = { list: () => [{ id: 'c1', kind: 'ssh', label: 'SSH-RO' }, { id: 'c2', kind: 'ssh', label: 'SSH-OTHER' }, { id: 'c3', kind: 'winrm', label: 'WIN' }],
    open: (id) => ({ secret: { username: 'zyb_ro', password: 'Syn-SSH-pw' }, release() {} }) };
  const S = registerServerRoutes(e.app.srv, e.app, { now: () => NOW, discovery: { vault, trust: { see() {} } }, invRun: async (r) => { helperCalls.push(r); return { ok: true, server: SOL_OK }; } });
  return { e, S, ids, helperCalls };
}
const get = (e, p, role = 'operator') => e.req('GET', p, { user: role === 'viewer' ? 'v.syn' : role === 'admin' ? 'syed' : 'omar.syn', role });

test('servers: every server on its platform from facts, with the reason; laptops never; OS unknown is said, not guessed', async (t) => {
  const { e, ids } = await setup(t);
  const r = await get(e, '/servers'); assert.equal(r.status, 200, r.text);
  const by = Object.fromEntries(r.json.servers.map((x) => [x.id, x]));
  assert.equal(r.json.servers.length, 7, 'servers and VMs only');
  assert.deepEqual(by[ids.win].platforms, ['windows', 'vmware'], 'a Windows VM in vCenter is on both pages');
  assert.deepEqual(by[ids.exch].platforms, ['windows', 'exchange']);
  assert.match(by[ids.exch].platform_why.join(' '), /software: Microsoft Exchange Server 2016/);
  assert.deepEqual(by[ids.sol].platforms, ['solaris']); assert.deepEqual(by[ids.ol].platforms, ['oracle_linux']); assert.deepEqual(by[ids.esx].platforms, ['vmware']);
  assert.deepEqual(by[ids.nos].platforms, ['unknown']); assert.match(by[ids.nos].platform_why.join(' '), /no operating system recorded/);
  assert.equal(r.json.platforms.windows.servers, 2); assert.equal(r.json.platforms.exchange.servers, 1); assert.equal(r.json.platforms.vmware.servers, 2);
  const ex = await get(e, '/servers?platform=exchange'); assert.deepEqual(ex.json.servers.map((x) => x.name), ['EXCH01']);
  assert.equal(ex.json.label, 'Exchange Server');
});

test('servers: findings carry the fix - backup, patches, end of life, warranty, OS not read and why', async (t) => {
  const { e, ids } = await setup(t);
  const F = (await get(e, '/servers')).json.findings, of = (id) => F.filter((f) => f.asset_id === id);
  assert.ok(of(ids.exch).some((f) => f.kind === 'backup' && f.severity === 'high' && /failed/.test(f.title)));
  assert.ok(of(ids.exch).some((f) => f.kind === 'patch' && /3 critical patches missing/.test(f.title)));
  assert.ok(of(ids.ol2).some((f) => f.kind === 'eol' && f.severity === 'high' && /Oracle Linux 7 is past end of support/.test(f.title)));
  assert.ok(of(ids.esx).some((f) => f.kind === 'warranty'));
  assert.ok(of(ids.sol).some((f) => f.kind === 'backup' && /no backup found/.test(f.title)));
  const ol = of(ids.ol).find((f) => f.kind === 'not-read'); assert.ok(ol, 'Oracle Linux not read yet');
  assert.match(ol.recommendation, /host key is seen - an administrator must trust it/);
  assert.ok(!of(ids.win).some((f) => f.kind === 'backup'), 'a protected server has no backup finding');
  assert.ok(of(ids.nos).some((f) => f.kind === 'os-unknown'));
});

test('servers: Unix read over SSH only with a trusted host key; Database Servers reading reused; findings from the reading; audited', async (t) => {
  const { e, ids, helperCalls } = await setup(t);
  const run = await e.req('POST', '/servers/run', { user: 'omar.syn', role: 'operator' }); assert.equal(run.status, 200, run.text);
  assert.equal(run.json.unix, 3); assert.equal(run.json.read, 1, 'Solaris read'); assert.equal(run.json.skipped, 1, 'Oracle Linux: host key not trusted'); assert.equal(run.json.shared, 1, 'the DB server reading reused');
  assert.equal(helperCalls.length, 1); assert.equal(helperCalls[0].host, '10.8.0.21'); assert.equal(helperCalls[0].fp, 'a'.repeat(64)); assert.equal(helperCalls[0].op, 'ssh_health');
  const one = await get(e, '/servers/' + ids.sol); assert.equal(one.status, 200);
  const F = one.json.findings;
  assert.ok(F.some((f) => f.kind === 'filesystem' && f.severity === 'critical' && /\/ 96% full/.test(f.title)));
  assert.ok(F.some((f) => f.kind === 'service' && /svc:\/network\/ntp:default is maintenance/.test(f.title) && /svcadm clear/.test(f.recommendation)));
  assert.equal(one.json.server.fs_fullest.mount, '/'); assert.equal(one.json.server.os_shown, 'Oracle Solaris 11.4 SPARC');
  const db2 = await get(e, '/servers/' + ids.ol2); assert.equal(db2.json.server.os_read.via, 'Database Servers');
  assert.ok(e.app.store.auditTail(20).some((x) => x.action === 'servers.read' && x.by === 'omar.syn' && x.detail.read === 1));
  assert.ok(!JSON.stringify(e.app.store.auditTail(20)).includes('Syn-SSH-pw'), 'the SSH password is never in the audit trail');
  assert.ok(!e.logs.some((l) => JSON.stringify(l).includes('Syn-SSH-pw')), 'nor in a log line');
});

test('servers: roles and validation - viewer refused, operator reads, only an admin chooses the SSH login; errors name the field', async (t) => {
  const { e, ids } = await setup(t);
  assert.equal((await get(e, '/servers', 'viewer')).status, 403, 'server names, IPs and owners: operators');
  assert.equal((await get(e, '/servers/' + ids.sol, 'viewer')).status, 403);
  assert.equal((await e.req('POST', '/servers/run', { user: 'v.syn', role: 'viewer' })).status, 403);
  const bp = await get(e, '/servers?platform=aix'); assert.equal(bp.status, 400); assert.match(bp.json.error, /platform must be one of/);
  assert.equal((await get(e, '/servers/no-such-asset')).status, 404);
  assert.equal((await get(e, '/servers/bad%20id')).status, 400);
  const op = await e.req('POST', '/servers/ssh', { user: 'omar.syn', role: 'operator', body: { asset_id: ids.ol, cred_id: 'c2' } }); assert.equal(op.status, 403);
  const wrong = await e.req('POST', '/servers/ssh', { user: 'syed', role: 'admin', body: { asset_id: ids.ol, cred_id: 'c3' } });
  assert.equal(wrong.status, 400); assert.match(wrong.json.error, /cred_id: choose a saved SSH login/);
  const noid = await e.req('POST', '/servers/ssh', { user: 'syed', role: 'admin', body: { cred_id: 'c2' } }); assert.equal(noid.status, 400); assert.match(noid.json.error, /asset_id is required/);
  const ok = await e.req('POST', '/servers/ssh', { user: 'syed', role: 'admin', body: { asset_id: ids.ol, cred_id: 'c2', extra: 'dropped' } }); assert.equal(ok.status, 200, ok.text);
  assert.deepEqual(ok.json, { asset_id: ids.ol, cred_id: 'c2' });
  const v = (await get(e, '/servers/' + ids.ol)).json.server; assert.equal(v.ssh.credential, 'SSH-OTHER'); assert.equal(v.ssh.via, 'chosen here');
  const a = e.app.store.auditTail(20).find((x) => x.action === 'servers.ssh'); assert.ok(a); assert.equal(a.by, 'syed'); assert.equal(a.role, 'admin'); assert.equal(a.detail.cred_id, 'c2');
});

test('servers: Exchange also recognised from the Email Route Map register and Business Services, with the reason', async (t) => {
  const { e } = await setup(t);
  const mk = (o) => e.app.assets.create(Object.assign({ status: 'in_use' }, o), ADM).asset;
  const m1 = mk({ name: 'SRV-SYN-77', type: 'server', os: 'Windows Server 2019', mgmt_ip: '10.8.0.77' }), m2 = mk({ name: 'SRV-SYN-78', type: 'vm', mgmt_ip: '10.8.0.78' });
  e.app.store.collection('mailrep').put({ id: 'route_profile', servers: [{ name: 'SRV-SYN-77', role: 'hybrid', private_ip: '10.8.0.77', public_ips: [] }] });
  e.app.addons.serviceMap = { view: () => ({ servers: [{ ip: '10.8.0.78', host: 'SRV-SYN-78', asset: { id: m2.id }, services: [{ id: 'exchange', confidence: 'confirmed', evidence: [{ detail: 'HTTPS 443: Outlook on the web 15.2' }] }] }] }) };
  const ex = await get(e, '/servers?platform=exchange'); assert.equal(ex.status, 200, ex.text);
  const by = Object.fromEntries(ex.json.servers.map((x) => [x.id, x]));
  assert.ok(by[m1.id] && /Email Route Map register: role hybrid/.test(by[m1.id].platform_why.join(' ')));
  assert.ok(by[m2.id] && /Business Services: HTTPS 443: Outlook on the web/.test(by[m2.id].platform_why.join(' ')), 'no OS recorded, still Exchange (so Windows too)');
  assert.deepEqual(by[m2.id].platforms.slice(0, 2), ['windows', 'exchange']);
  assert.equal(ex.json.platforms.exchange.servers, 3, 'EXCH01 + the two found from the register and Business Services');
});

test('servers: Exchange servers the SIEM admin already has count; an OS / IP from any discovery source counts (vCenter guest OS)', async (t) => {
  const { e } = await setup(t);
  const A = e.app.assets, mk = (o) => A.create(Object.assign({ status: 'in_use' }, o), ADM).asset;
  const ex = mk({ name: 'MBX-SYN-02', type: 'vm', os: 'Windows Server 2019', mgmt_ip: '10.8.0.92' }), ol = mk({ name: 'OLVM-SYN-9', type: 'vm' });
  e.app.store.collection('exchange_seen').put({ id: 'siem-admin', names: [], ips: ['10.8.0.92'], assets: [], at: new Date(NOW).toISOString() });
  // the newest record (a sweep) guessed nothing; the vCenter record of the same asset reported the guest OS and address
  e.app.store.collection('disc_devices').put({ id: 'dd-ol9-vc', ips: ['10.8.0.93'], asset_id: ol.id, os: 'Oracle Linux 8 (64-bit)', status: 'approved', extra: { vcenter: { kind: 'vm' } }, last_seen: NOW - 3600000 });
  e.app.store.collection('disc_devices').put({ id: 'dd-ol9-sw', asset_id: ol.id, macs: ['00:50:56:00:00:09'], status: 'approved', extra: {}, last_seen: NOW });
  const r = await get(e, '/servers'); assert.equal(r.status, 200, r.text);
  const by = Object.fromEntries(r.json.servers.map((x) => [x.id, x]));
  assert.ok(by[ex.id].platforms.includes('exchange'), 'on the Exchange page');
  assert.match(by[ex.id].platform_why.join(' '), /Windows \/ Exchange Admin \(SIEM\)/, 'with the reason');
  assert.ok(by[ol.id].platforms.includes('oracle_linux'), 'Oracle Linux from the vCenter guest OS: ' + by[ol.id].platforms);
  assert.equal(by[ol.id].ip, '10.8.0.93', 'the address another source reported');
});

// Bug fixed: a server with several addresses (second NIC, cluster / replication network) showed only one - the first source's
// first address. Every address a source reported is now returned with its source; nothing is guessed, loopback / link-local dropped.
test('servers: every address a source reported is listed with its source, not only the first one', async (t) => {
  const { e } = await setup(t);
  const a = e.app.assets.create({ status: 'in_use', name: 'HQMAIL-SYN-1', type: 'vm', os: 'Windows Server 2019', mgmt_ip: '192.0.2.141' }, ADM).asset;
  e.app.store.collection('disc_devices').put({ id: 'dd-mail-vc', ip: '192.0.2.141', ips: ['192.0.2.141', '198.51.100.20', '169.254.10.1', 'fe80::1'], method: 'vcenter', asset_id: a.id, status: 'approved', extra: { vcenter: { kind: 'vm' } }, last_seen: NOW });
  e.app.store.collection('disc_devices').put({ id: 'dd-mail-scan', ip: '203.0.113.7', method: 'nmap', asset_id: a.id, status: 'approved', extra: {}, last_seen: NOW - 3600000 });
  const r = await get(e, '/servers'); assert.equal(r.status, 200, r.text);
  const x = r.json.servers.find((s) => s.id === a.id);
  assert.equal(x.ip, '192.0.2.141', 'the managed address stays first');
  assert.deepEqual(x.ips.map((i) => i.ip), ['192.0.2.141', '198.51.100.20', '203.0.113.7'], 'every IPv4 address once, link-local and IPv6 dropped');
  assert.equal(x.ips.find((i) => i.ip === '198.51.100.20').src, 'vcenter'); assert.equal(x.ips.find((i) => i.ip === '203.0.113.7').src, 'nmap');
});
