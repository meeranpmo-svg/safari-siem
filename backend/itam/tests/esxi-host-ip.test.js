// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// ESXi host management address from vCenter / the host itself (HostSystem config.network.vnic over the read-only SOAP
// reader), so a host's IP no longer depends on the platform server resolving its name in DNS: the management VMkernel
// port is chosen (port group "Management…", else vmk0), an IPv6 address is never taken, a role that cannot read host
// networking leaves the address empty without failing the collection, and only allow-listed SOAP methods are sent.
const test = require('node:test');
const assert = require('node:assert/strict');
const X = require('../engine/discovery/xml');
const { mgmtNic, vcSoap, SOAP_OK } = require('../engine/virt-capacity');
const esxi = require('../engine/discovery/methods/esxi');
const vcM = require('../engine/discovery/methods/vcenter');
const { createVirt } = require('../engine/virt');
const { startApp } = require('./helpers');
const { fakeVc, VNIC } = require('./fixtures-vcenter-soap');

const cred = { target: { base_url: 'https://10.100.5.1' }, secret: { username: 'svc@vsphere.local', password: 'Vc-pass-1' } };
const valOf = (i) => X.find(X.findAll(X.parse(VNIC[i]), 'propSet').find((p) => X.childText(p, 'name') === 'config.network.vnic'), 'val');

test('mgmtNic: management port group first, else vmk0; IPv4 only; nothing → empty', () => {
  assert.deepEqual(mgmtNic(valOf(0)), { ip: '10.100.5.11', vmk: 'vmk0', portgroup: 'Management Network' }, 'not the vMotion vmk listed first');
  assert.deepEqual(mgmtNic(valOf(1)), { ip: '10.100.5.12', vmk: 'vmk0', portgroup: 'MGMT-VLAN100' }, 'vmk0 when no port group is called Management');
  assert.deepEqual(mgmtNic(''), { ip: null, vmk: null, portgroup: null });
  assert.deepEqual(mgmtNic(X.parse('<val><HostVirtualNic><device>vmk0</device><spec><ip><ipAddress>fe80::2</ipAddress></ip></spec></HostVirtualNic></val>')), { ip: null, vmk: null, portgroup: null }, 'IPv6 is never taken as the address');
});

test('vcSoap.hostAddresses + standalone ESXi collect: address read over allow-listed SOAP only', async () => {
  const calls = [];
  const a = await vcSoap(cred.target, cred.secret, { request: fakeVc(calls) }).hostAddresses();
  assert.deepEqual(a.map((h) => [h.id, h.ip, h.vmk]), [['host-11', '10.100.5.11', 'vmk0'], ['host-12', '10.100.5.12', 'vmk0']]);
  assert.ok(calls.every((c) => SOAP_OK.has(c.m))); assert.equal(calls[calls.length - 1].m, 'Logout', 'logged out');
  const r = await esxi.collect(cred, { request: fakeVc([]) });
  assert.equal(r.ok, true, r.error);
  assert.deepEqual(r.hosts.map((h) => h.ip).sort(), ['10.100.5.11', '10.100.5.12']);
  const n = await esxi.collect(cred, { request: fakeVc([], { noVnic: true }) });
  assert.equal(n.ok, true, 'a role without host-configuration read still collects'); assert.ok(n.hosts.every((h) => h.ip === null));
});

test('vCenter REST collect: hosts get their management IP from the SOAP reader (matched by id)', async () => {
  const soap = fakeVc([]), rest = [];
  const request = async (url, o) => {
    if (/\/sdk$/.test(url)) return soap(url, o);
    rest.push([o.method, url.replace(/^https:\/\/[^/]+/, '')]);
    const path = url.replace(/^https:\/\/[^/]+/, '');
    if (path === '/api/session') return o.method === 'DELETE' ? { status: 204, json: null } : { status: 201, json: 'sess-1' };
    if (path === '/api/vcenter/host') return { status: 200, json: [{ host: 'host-11', name: ('esx01.' + 'corp-hq.com'), connection_state: 'CONNECTED' }, { host: 'host-12', name: ('esx02.' + 'corp-hq.com'), connection_state: 'CONNECTED' }] };
    if (/^\/api\/vcenter\/vm\?hosts=/.test(path)) return { status: 200, json: [] };
    return { status: 404, json: {} };
  };
  const r = await vcM.collect(cred, { request });
  assert.equal(r.ok, true, r.error_class);
  assert.deepEqual(r.hosts.map((h) => [h.name, h.ip, h.vmk]), [[('esx01.' + 'corp-hq.com'), '10.100.5.11', 'vmk0'], [('esx02.' + 'corp-hq.com'), '10.100.5.12', 'vmk0']]);
  assert.ok(rest.every(([m, p]) => m === 'GET' || p === '/api/session'), 'REST stays read-only (GET, plus opening / closing the session)');
  // the SOAP side refused (old vCenter / no permission): hosts are still listed, without an address
  const r2 = await vcM.collect(cred, { request: async (url, o) => (/\/sdk$/.test(url) ? { status: 404, headers: {}, text: '' } : request(url, o)) });
  assert.equal(r2.ok, true); assert.ok(r2.hosts.every((h) => !h.ip));
});

test('virt sync: the reported address is used and DNS is not needed (a server that cannot resolve the names)', async (t) => {
  const s = await startApp({ noAi: true }); t.after(() => s.close());
  const looked = [];
  const resolve = async (n) => { looked.push(n); throw Object.assign(new Error('getaddrinfo EAI_AGAIN ' + n), { code: 'EAI_AGAIN' }); };
  const VC = { hosts: [{ id: 'host-11', name: ('esx01.' + 'corp-hq.com'), state: 'connected', ip: '10.100.5.11', vmk: 'vmk0' }, { id: 'host-13', name: ('esx03.' + 'corp-hq.com'), state: 'connected', ip: null }], vms: [] };
  const V = createVirt(s.app, { methods: { vcenter: { collect: async () => Object.assign({ ok: true }, VC) } }, resolve });
  const adm = { user: 'syed', role: 'admin' };
  const vc = V.save({ kind: 'vcenter', label: 'VC', base_url: 'https://vc.corp.local', username: 'u', password: 'p' }, adm).platform;
  const r = await V.sync(vc.id, adm);
  assert.equal(r.ok, true, r.error);
  assert.ok(!looked.includes(('esx01.' + 'corp-hq.com')), 'no DNS lookup when vCenter gave the address');
  assert.equal(r.hosts_without_ip, 1, 'the host without a reported address and no DNS answer is counted, not guessed');
  const A = s.app.store.collection('assets');
  assert.equal((A.all().find((a) => /^esx01/i.test(a.name)) || {}).mgmt_ip, '10.100.5.11');
  const inv = V.inventory().items.find((x) => /^esx01/i.test(x.name));
  assert.equal(inv.ip, '10.100.5.11', 'the Hosts & VMs table shows it');
});

test('standalone ESXi: the address it was added with is the host IP when no vmk is readable; VM guest IPs pass through', async () => {
  const M = require('../engine/virt-capacity'), real = M.vcSoap;
  const one = { HostSystem: [{ _id: 'ha-host', name: 'Tcs-VmHost.example.test', 'runtime.connectionState': 'connected' }],
    VirtualMachine: [{ _id: '1', name: 'APP-SYN', 'runtime.host': 'ha-host', 'runtime.powerState': 'poweredOn', ips: ['10.100.9.5'] }], ClusterComputeResource: [], Datastore: [], _health: {} };
  M.vcSoap = () => ({ collect: async () => one });
  try {
    const r = await esxi.collect({ target: { base_url: 'https://192.0.2.64' }, secret: {} });
    assert.equal(r.ok, true, r.error);
    assert.equal(r.hosts[0].ip, '192.0.2.64', 'the host is the address it was added with');
    assert.deepEqual(r.vms[0].ips, ['10.100.9.5'], 'the VM keeps its own guest address, never the host one');
    const n = await esxi.collect({ target: { base_url: 'https://esx1.example.test' }, secret: {} });
    assert.equal(n.hosts[0].ip, null, 'a host added by name with no vmk read stays empty (DNS is the fallback)');
  } finally { M.vcSoap = real; }
});

test('guestIps: primary then every NIC address; link-local dropped; IPv4 first', () => {
  const { guestIps } = require('../engine/virt-capacity');
  const net = X.parse('<val><GuestNicInfo><ipAddress>fe80::1</ipAddress><ipAddress>10.1.1.5</ipAddress></GuestNicInfo><GuestNicInfo><ipAddress>10.2.2.5</ipAddress><ipAddress>169.254.1.1</ipAddress></GuestNicInfo></val>');
  assert.deepEqual(guestIps('10.1.1.5', net), ['10.1.1.5', '10.2.2.5']);
  assert.deepEqual(guestIps('', ''), []);
});

// Bug fixed: an ESXi host showed only its management address; every VMkernel interface (vMotion, vSAN, storage ...) is kept.
test('vmkNics: every VMkernel interface with an IPv4 address, with its device and port group', () => {
  const { vmkNics } = require('../engine/virt-capacity');
  const v = X.parse('<val><HostVirtualNic><device>vmk0</device><portgroup>Management Network</portgroup><spec><ip><ipAddress>10.100.5.11</ipAddress></ip></spec></HostVirtualNic>'
    + '<HostVirtualNic><device>vmk1</device><portgroup>vMotion</portgroup><spec><ip><ipAddress>10.100.6.11</ipAddress></ip></spec></HostVirtualNic>'
    + '<HostVirtualNic><device>vmk2</device><portgroup>vSAN</portgroup><spec><ip><ipAddress>fe80::2</ipAddress></ip></spec></HostVirtualNic></val>');
  assert.deepEqual(vmkNics(v), [{ vmk: 'vmk0', portgroup: 'Management Network', ip: '10.100.5.11' }, { vmk: 'vmk1', portgroup: 'vMotion', ip: '10.100.6.11' }]);
  assert.deepEqual(vmkNics(''), []);
});
