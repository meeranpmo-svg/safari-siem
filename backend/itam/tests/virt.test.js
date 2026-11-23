// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Virtualization platforms: Nutanix Prism parsing (v3 / v2 fallback, read-only guard), several platforms feeding Asset
// Discovery, auto-approval into the inventory, VM → host links, Nutanix cores into the licence audit, sealed credentials.
const test = require('node:test');
const assert = require('node:assert/strict');
const ntnx = require('../engine/discovery/methods/nutanix');
const { createVirt } = require('../engine/virt');
const { startApp } = require('./helpers');

const V3 = {
  hosts: { metadata: { total_matches: 2 }, entities: [
    { metadata: { uuid: 'h-1' }, status: { name: 'NTNX-A', cluster_reference: { name: 'RUH-CL1' }, resources: { num_cpu_sockets: 2, num_cpu_cores: 48, cpu_model: 'Intel(R) Xeon(R) Gold 6342', serial_number: 'SN-A', block: { block_model: 'NX-3170-G8' }, hypervisor: { ip: '10.110.20.11', hypervisor_full_name: 'AHV 20230302' }, controller_vm: { ip: '10.110.20.21' } } } },
    { metadata: { uuid: 'pc' }, status: { name: 'prism-central', resources: {} } }] },
  vms: { metadata: { total_matches: 2 }, entities: [
    { metadata: { uuid: 'v-1' }, status: { name: 'ORADB-N1', cluster_reference: { name: 'RUH-CL1' }, resources: { power_state: 'ON', num_sockets: 2, num_vcpus_per_socket: 4, memory_size_mib: 32768, host_reference: { uuid: 'h-1', name: 'NTNX-A' }, nic_list: [{ mac_address: '50:6B:8D:00:00:01', ip_endpoint_list: [{ ip: '10.110.30.5' }] }] } } },
    { metadata: { uuid: 'v-2' }, status: { name: 'APP-N2', resources: { power_state: 'OFF', host_reference: { uuid: 'h-1' }, nic_list: [{ mac_address: '50:6b:8d:00:00:02' }] } } }] },
  clusters: { entities: [{ metadata: { uuid: 'c1' }, status: { name: 'RUH-CL1', resources: { config: { software_map: { NOS: { version: '6.8' } } } } } }, { metadata: { uuid: 'pcc' }, status: { name: 'PC', resources: { config: { service_list: ['PRISM_CENTRAL'] } } } }] },
};
function fakePrism(calls, { v2 = false, status = 200 } = {}) {
  return async (url, o) => {
    calls.push([o.method, url, o.headers.Authorization]);
    if (status !== 200) return { status, json: {} };
    const m = /\/api\/nutanix\/v3\/(\w+)\/list$/.exec(url);
    if (m) return v2 ? { status: 404, json: {} } : { status: 200, json: V3[m[1]] };
    if (/v2\.0\/hosts$/.test(url)) return { status: 200, json: { entities: [{ uuid: 'h2', name: 'NTNX-PE', hypervisor_address: '10.1.1.1', num_cpu_sockets: 2, num_cpu_cores: 32, serial: 'S2', block_model_name: 'NX-1065', hypervisor_full_name: 'AHV' }] } };
    if (/v2\.0\/vms\?/.test(url)) return { status: 200, json: { entities: [{ uuid: 'vv', name: 'PE-VM', host_uuid: 'h2', power_state: 'on', num_vcpus: 2, vm_nics: [{ mac_address: '50:6b:8d:aa:bb:cc', ip_address: '10.1.1.50' }] }] } };
    if (/v2\.0\/cluster$/.test(url)) return { status: 200, json: { name: 'JED-CL', uuid: 'cc' } };
    return { status: 404, json: {} };
  };
}
const CRED = { target: { base_url: 'https://pc.corp.local' }, secret: { username: 'svc-prism', password: 'Pr1sm-s3cret' } };

test('nutanix: Prism Central v3 parsing, port 9440, Basic auth, read-only guard', async () => {
  const calls = [];
  const r = await ntnx.collect(CRED, { request: fakePrism(calls) });
  assert.equal(r.ok, true); assert.equal(r.api, 'v3');
  assert.deepEqual(r.hosts.map((h) => [h.name, h.ip, h.sockets, h.cores, h.cores_per_socket, h.cluster, h.model, h.serial]), [['NTNX-A', '10.110.20.11', 2, 48, 24, 'RUH-CL1', 'NX-3170-G8', 'SN-A']]);
  assert.deepEqual(r.vms.map((v) => [v.name, v.host_name, v.power_state, v.vcpus, v.ips.join(), v.macs.join()]), [['ORADB-N1', 'NTNX-A', 'on', 8, '10.110.30.5', '50:6b:8d:00:00:01'], ['APP-N2', 'NTNX-A', 'off', 1, '', '50:6b:8d:00:00:02']]);
  assert.deepEqual(r.clusters.map((c) => c.name), ['RUH-CL1']);
  assert.ok(calls.every((c) => c[0] === 'POST' && c[1].startsWith('https://pc.corp.local:9440/api/nutanix/v3/') && c[2] === 'Basic ' + Buffer.from('svc-prism:Pr1sm-s3cret').toString('base64')));
  assert.throws(() => ntnx.guard('POST', '/api/nutanix/v3/vms'), /read-only/);
  assert.throws(() => ntnx.guard('DELETE', '/api/nutanix/v3/vms/list'), /read-only/);
  assert.throws(() => ntnx.guard('GET', '/PrismGateway/services/rest/v2.0/vms/x/set_power_state'), /read-only/);
});

test('nutanix: Prism Element v2 fallback; 401 is an auth error', async () => {
  const r = await ntnx.collect(CRED, { request: fakePrism([], { v2: true }) });
  assert.equal(r.api, 'v2'); assert.equal(r.hosts[0].cluster, 'JED-CL'); assert.equal(r.hosts[0].cores_per_socket, 16); assert.equal(r.vms[0].host_name, 'NTNX-PE');
  const f = await ntnx.collect(CRED, { request: fakePrism([], { status: 401 }) });
  assert.deepEqual([f.ok, f.error_class], [false, 'auth']);
  const t = await ntnx.test(CRED, { request: fakePrism([], { status: 401 }) });
  assert.match(t.message, /Nutanix Prism rejected the credentials/);
});

test('virt: several platforms → Asset Discovery → inventory, VM→host links, Nutanix cores into the licence audit', async (t) => {
  const s = await startApp({ noAi: true }); t.after(() => s.close());
  const VC = { hosts: [{ id: 'host-1', name: 'esx01.corp.local', state: 'connected' }], vms: [{ id: 'vm-9', name: 'WIN-APP1', host_id: 'host-1', host_name: 'esx01.corp.local', power_state: 'on', guest_os: 'Microsoft Windows Server 2022 (64-bit)', hostname: 'win-app1', ips: ['10.110.40.9'], macs: ['00:50:56:00:00:09'], uuid: '5003-aaaa' }] };
  const prismCalls = [];
  const methods = { vcenter: { collect: async (c) => { assert.equal(c.secret.password, 'Vc-pass-1'); return Object.assign({ ok: true }, VC); }, test: async () => ({ ok: true }) },
    nutanix: { collect: (c) => ntnx.collect(c, { request: fakePrism(prismCalls) }), test: async () => ({ ok: false, error_class: 'tls', tls: { presented: { fingerprint256: 'AB:CD' } } }) } };
  const V = createVirt(s.app, { methods });
  const adm = { user: 'syed', role: 'admin' };
  assert.throws(() => V.save({ kind: 'hyperv', base_url: 'https://x' }, adm), /kind must be/);
  assert.throws(() => V.save({ kind: 'nutanix', base_url: 'http://x', username: 'a', password: 'b' }, adm), /https/);
  assert.throws(() => V.save({ kind: 'nutanix', base_url: 'https://pc.corp.local' }, adm), /user name and password/);
  const vc1 = V.save({ kind: 'vcenter', label: 'VC-RUH', base_url: 'https://vc1.corp.local', username: 'svc@vsphere.local', password: 'Vc-pass-1', site: 'Riyadh HQ' }, adm).platform;
  const nx = V.save({ kind: 'nutanix', label: 'Prism Central', base_url: 'https://pc.corp.local', username: 'svc-prism', password: 'Pr1sm-s3cret', site: 'Riyadh HQ' }, adm).platform;
  V.save({ kind: 'vcenter', label: 'VC-JED', base_url: 'https://vc2.corp.local', username: 'u', password: 'p' }, adm);
  const listed = JSON.stringify(V.list());
  assert.ok(!/Vc-pass-1|Pr1sm-s3cret|svc-prism/.test(listed)); assert.equal(V.list().platforms.length, 3);
  assert.throws(() => V.save({ id: nx.id, base_url: 'https://evil.example' }, adm), /password again/);
  // TLS pin flow: only the certificate seen by the last test can be pinned
  const tr = await V.test(nx.id, adm); assert.equal(tr.result.error_class, 'tls');
  assert.throws(() => V.pin(nx.id, { fingerprint: 'FF:FF' }, adm), /last test/);
  assert.equal(V.pin(nx.id, { fingerprint: 'ab:cd' }, adm).platform.tls_fingerprint, 'abcd');

  // a successful sync refreshes the capacity collection for that platform at once (Nutanix VMs, Capacity, Power Control follow)
  const capCalls = []; s.app.addons = s.app.addons || {}; const prevCap = s.app.addons.virtCapacity; s.app.addons.virtCapacity = { collectPlatform: async (id) => { capCalls.push(id); } };
  const r1 = await V.sync(vc1.id, adm), r2 = await V.sync(nx.id, adm);
  assert.deepEqual([r1.ok, r1.hosts, r1.vms, r1.approved, r1.linked], [true, 1, 1, 2, 1]);
  await new Promise((r) => setImmediate(r));
  assert.deepEqual(capCalls, [vc1.id, nx.id], 'capacity collected for each synced platform'); assert.equal(r1.capacity, 'collecting');
  s.app.addons.virtCapacity = prevCap;
  assert.deepEqual([r2.ok, r2.hosts, r2.vms, r2.clusters, r2.approved, r2.linked, r2.cores_filled], [true, 1, 2, 1, 3, 2, 1]);
  const res = (await s.req('GET', '/discovery/results?limit=50', { role: 'admin', user: 'syed' })).json.devices;
  const byName = Object.fromEntries(res.map((d) => [d.hostname, [d.type, d.status, d.site]]));
  assert.deepEqual(byName['ntnx-a'], ['server', 'approved', 'Riyadh HQ']); assert.deepEqual(byName['oradb-n1'], ['vm', 'approved', 'Riyadh HQ']); assert.equal(byName['win-app1'][0], 'vm');
  const assets = s.app.store.collection('assets').all();
  const host = assets.find((a) => a.name === 'ntnx-a'); assert.equal(host.type, 'server'); assert.equal(host.serial, 'SN-A');
  // the licence audit now knows the Nutanix host's cores and the Oracle VM on it
  const facts = s.app.store.collection('core_lic_facts').get(host.id); assert.deepEqual([facts.sockets, facts.cores_per_socket, facts.cluster, facts.source], [2, 24, 'RUH-CL1', 'nutanix']);
  const rels = s.app.assets.allRelationships().filter((x) => x.type === 'runs_on' && x.to === host.id); assert.equal(rels.length, 2);
  // a second sync adds nothing new and keeps the links
  const r3 = await V.sync(nx.id, adm); assert.deepEqual([r3.approved, r3.linked], [0, 0]);
  // the page's inventory: hosts + VMs from this page, a Discovery scope, and hand-entered hypervisors / VMs
  s.app.assets.create({ name: 'ESX-OLD', type: 'server', status: 'in_use', os: 'VMware ESXi 7.0.3', mgmt_ip: '10.9.0.5' }, adm);
  s.app.assets.create({ name: 'HAND-VM', type: 'vm', status: 'in_use', os: 'Ubuntu 22.04' }, adm);
  s.app.discovery.devices.observe({ method: 'vcenter', hostname: 'scope-vm', ips: ['10.7.0.9'], uid: 'vc:scope-1', extra: { vcenter: { kind: 'vm', power_state: 'off', host: 'esx9', name: 'SCOPE-VM' } } }, { scope_id: 'sc1', site: 'Jeddah' });
  const inv = V.inventory(), nm = (n) => inv.items.find((i) => i.name === n);
  assert.equal(nm('WIN-APP1').source, 'vcenter'); assert.equal(nm('WIN-APP1').platform, 'VC-RUH'); assert.equal(nm('WIN-APP1').kind, 'vm');
  assert.equal(nm('ESX-OLD').kind, 'host'); assert.equal(nm('ESX-OLD').source, 'inventory'); assert.equal(nm('HAND-VM').kind, 'vm');
  assert.equal(nm('SCOPE-VM').platform, 'Discovery scope: sc1'); assert.equal(nm('SCOPE-VM').power_state, 'off');
  assert.equal(inv.items.filter((i) => i.name === 'ntnx-a' || i.name === 'NTNX-A').length, 1, 'an approved host is listed once, not again from the inventory');
  assert.ok(inv.summary.hosts >= 3 && inv.summary.vms >= 4, JSON.stringify(inv.summary)); assert.equal(inv.summary.vms_off, inv.items.filter((i) => i.kind === 'vm' && /off/i.test(i.power_state || '')).length);
  assert.equal((await s.req('GET', '/virt/inventory', { role: 'viewer' })).status, 403);
  // a failing platform reports the reason
  const bad = createVirt(s.app, { methods: { vcenter: methods.vcenter, nutanix: { collect: async () => ({ ok: false, error_class: 'auth', error: 'Prism rejected the credentials' }) } } });
  const r4 = await bad.sync(nx.id, adm); assert.equal(r4.ok, false); assert.match(r4.error, /^auth: Prism rejected/);
  assert.equal(r4.capacity, undefined, 'a failed sync does not trigger a capacity collection');
  assert.ok(!JSON.stringify(s.app.store.auditTail ? s.app.store.auditTail(500) : []).match(/Vc-pass-1|Pr1sm-s3cret/));
});

test('virt: ESXi / Nutanix hosts without an address in the API get it from DNS; hosts approved earlier without one are filled', async (t) => {
  const s = await startApp({ noAi: true }); t.after(() => s.close());
  const VC = { hosts: [{ id: 'host-1', name: 'esx01.corp.local', state: 'connected' }, { id: 'host-2', name: 'esx-unknown.corp.local', state: 'connected' }, { id: 'host-3', name: '10.110.10.23', state: 'connected' }], vms: [] };
  const NX = { hosts: [{ id: 'nh', name: 'ntnx-b.corp.local', ip: null, sockets: 2, cores: 32, cores_per_socket: 16, cluster: 'C1' }], vms: [], clusters: [] };
  const looked = [];
  const resolve = async (n) => { looked.push(n); if (n === 'esx01.corp.local') return '10.110.10.21'; if (n === 'ntnx-b.corp.local') return '10.110.20.12'; throw Object.assign(new Error('ENOTFOUND'), { code: 'ENOTFOUND' }); };
  const V = createVirt(s.app, { methods: { vcenter: { collect: async () => Object.assign({ ok: true }, VC) }, nutanix: { collect: async () => Object.assign({ ok: true }, NX) } }, resolve });
  const adm = { user: 'syed', role: 'admin' };
  const vc = V.save({ kind: 'vcenter', label: 'VC', base_url: 'https://vc.corp.local', username: 'u', password: 'p' }, adm).platform;
  const nx = V.save({ kind: 'nutanix', label: 'PC', base_url: 'https://pc.corp.local', username: 'u', password: 'p' }, adm).platform;
  const r = await V.sync(vc.id, adm), r2 = await V.sync(nx.id, adm);
  assert.equal(r.ok, true, r.error); assert.equal(r.hosts_without_ip, 1, 'the unresolvable host is counted, not guessed');
  assert.ok(!looked.includes('10.110.10.23'), 'an IP is not looked up');
  const A = s.app.store.collection('assets');
  const ip = (n) => (A.all().find((a) => String(a.name).toLowerCase().startsWith(n)) || {}).mgmt_ip;
  assert.equal(ip('esx01'), '10.110.10.21'); assert.equal(ip('ntnx-b'), '10.110.20.12'); assert.equal(r2.ok, true, r2.error);
  // a host already in the inventory without an IP (approved before this fix) gets it on the next sync; a set IP is kept
  const esx = A.all().find((a) => String(a.name).toLowerCase().startsWith('esx01'));
  A.patch(esx.id, (x) => { x.mgmt_ip = null; return x; });
  const r3 = await V.sync(vc.id, adm); assert.equal(ip('esx01'), '10.110.10.21'); assert.ok(r3.ips_filled >= 1);
  A.patch(esx.id, (x) => { x.mgmt_ip = '10.9.9.9'; return x; });
  await V.sync(vc.id, adm); assert.equal(ip('esx01'), '10.9.9.9', 'never overwritten');
});
