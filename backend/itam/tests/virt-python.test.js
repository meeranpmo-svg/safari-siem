// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Migration step 4 (docs/PYTHON-MIGRATION.md): pyengine/virt_capacity.py must answer exactly like vcSoap + fromVcenter and
// ntxClient in engine/virt-capacity.js. Both read the same simulated vCenter (SOAP: session cookie, paged
// RetrievePropertiesEx, faults for an old vCenter / a missing privilege / a wrong password) and Nutanix (Prism Element v2 +
// the v1 VM list, Prism Central v3, alerts, a 401) over real HTTP on loopback; answers and requests are compared, then a
// collection runs through the bridge.
const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const { spawnSync } = require('node:child_process');
const { vcSoap, fromVcenter, ntxClient, createVirtCapacity } = require('../engine/virt-capacity');
const { createPyEngine } = require('../engine/pyengine');
const { createSealer } = require('../engine/discovery/vault');
const { fakeVc, GiB } = require('./fixtures-vcenter-soap');
const { startApp } = require('./helpers');

const PY = process.env.PYTHON || 'python3';
const hasPy = spawnSync(PY, ['--version']).status === 0;
const plain = (v) => JSON.parse(JSON.stringify(v));

// a request-function fake (as the unit tests use) served over real HTTP
async function serve(fake, calls) {
  const srv = http.createServer((q, r) => {
    let b = ''; q.on('data', (d) => (b += d));
    q.on('end', async () => {
      calls.push([q.method, q.url, q.headers.cookie || '', q.headers.authorization || '', q.headers['content-type'] || '', b]);
      const a = await fake('http://x' + q.url, { method: q.method, headers: { Cookie: q.headers.cookie }, body: b });
      const h = Object.assign({ 'content-type': a.text != null ? 'text/xml' : 'application/json' }, a.headers || {});
      r.writeHead(a.status, h); r.end(a.text != null ? a.text : JSON.stringify(a.json == null ? {} : a.json));
    });
  });
  await new Promise((ok) => srv.listen(0, '127.0.0.1', ok));
  return { base: `http://127.0.0.1:${srv.address().port}`, close: () => new Promise((ok) => srv.close(ok)) };
}
const vcCalls = (calls) => calls.map((c) => [c[0], c[1], c[2], c[5].replace(/session\[x\]view-\w+-\d+/g, 'VIEW')]);

test('Python vCenter reader answers exactly like the Node.js one', { skip: !hasPy && 'python3 not available' }, async () => {
  const py = createPyEngine({ python: PY });
  const cases = [['normal', {}, 'Vc-pass-1'], ['old vCenter (no serial property)', { oldVc: true }, 'Vc-pass-1'], ['no health properties', { noHealth: true }, 'Vc-pass-1'],
    ['no host configuration privilege', { noVnic: true }, 'Vc-pass-1'], ['wrong password', {}, 'wrong & <x>']];
  for (const [label, o, pw] of cases) {
    const nc = [], pc = [], s1 = await serve(fakeVc([], o), nc), s2 = await serve(fakeVc([], o), pc);
    try {
      const sec = { username: 'svc@vsphere.local', password: pw };
      let n; try { n = plain(fromVcenter(await vcSoap({ base_url: s1.base + '/' }, sec).collect())); } catch (e) { n = { ok: false, error_class: e.code, error: e.message }; }
      const p = await py.call('virt.vcenter', { target: { base_url: s2.base + '/' }, secret: sec, opts: {} });
      assert.deepEqual(p, n, label + ': identical answers');
      assert.deepEqual(vcCalls(pc), vcCalls(nc), label + ': the same SOAP calls, bodies and session cookie');
      if (label === 'normal') {
        assert.equal(n.vms.length, 30); assert.equal(n.hosts[0].serial, 'SVC-TAG-01'); assert.equal(n.hosts[1].ip, '10.100.5.12');
        assert.deepEqual(n.vms.find((v) => v.id === 'vm-101').snapshots, { count: 2, oldest: '2026-06-01T10:00:00.000Z' });
      }
      if (label === 'wrong password') assert.equal(p.error_class, 'auth');
    } finally { await s1.close(); await s2.close(); }
  }
  // each host's management address (used by Asset Discovery)
  const nc = [], pc = [], s1 = await serve(fakeVc([]), nc), s2 = await serve(fakeVc([]), pc);
  try {
    const sec = { username: 'svc', password: 'Vc-pass-1' };
    const n = await vcSoap({ base_url: s1.base }, sec).hostAddresses();
    assert.deepEqual(await py.call('virt.vcenter_hosts', { target: { base_url: s2.base }, secret: sec, opts: {} }), n);
    assert.deepEqual(n.map((h) => [h.ip, h.vmk]), [['10.100.5.11', 'vmk0'], ['10.100.5.12', 'vmk0']]);
  } finally { await s1.close(); await s2.close(); }
});

function prism(mode) {
  return async (url, o) => {
    if (o.headers && 0) return null;
    const u = new URL(url), p = u.pathname + u.search;
    if (mode === 'badcreds') return { status: 401, json: {} };
    if (/v2\.0\/hosts$/.test(p)) {
      if (mode === 'central') return { status: 404, json: {} };
      return { status: 200, json: { entities: [
        { uuid: 'h1', name: 'NTNX-A', block_model_name: 'NX-3170-G8', serial: 'S1', cpu_model: 'Xeon 6342', num_cpu_sockets: 2, num_cpu_cores: 48, num_cpu_threads: 96, cpu_capacity_in_hz: 134400000000, memory_capacity_in_bytes: 1024 * GiB, hypervisor_full_name: 'AHV 20230302', state: 'NORMAL', stats: { hypervisor_cpu_usage_ppm: 300001, hypervisor_memory_usage_ppm: '600000' } },
        { uuid: 'h2', name: 'NTNX-B', block_serial: 'BLK2', hypervisor_address: '10.50.0.12', service_vmexternal_ip: '10.50.0.22', ipmi_address: '10.50.9.12; reboot', cpu_capacity_in_hz: 0, memory_capacity_in_bytes: null, state: 'ENTERING_MAINTENANCE_MODE', host_maintenance_mode_reason: 'user', stats: null },
        { uuid: 'h3' }] } };
    }
    if (/v2\.0\/cluster$/.test(p)) return { status: 200, json: { uuid: 'c1', name: 'RUH-CL1', usage_stats: { 'storage.capacity_bytes': String(100 * 1024 * GiB), 'storage.usage_bytes': 55 * 1024 * GiB }, stats: { hypervisor_cpu_usage_ppm: 412345 } } };
    if (/v2\.0\/vms\?/.test(p)) return { status: 200, json: { entities: [
      { uuid: 'v1', name: 'DB1', num_vcpus: 2, num_cores_per_vcpu: 4, memory_mb: 65536, power_state: 'on', host_uuid: 'h1', vm_disk_info: [{ size: 500 * GiB }, { size: 4 * GiB, is_cdrom: true }],
        vm_nics: [{ mac_address: '50:6B:8D:AA:00:01', ip_address: '10.20.1.15', ip_addresses: ['10.20.1.15', 'fe80::1', ' 10.20.1.16 '] }, { mac_address: 'bad', requested_ip_address: '169.254.3.3' }, null] },
      { uuid: 'v2', name: 'APP', num_vcpus: 3, memory_mb: 3333, power_state: 'off', vm_disk_info: [{ is_cdrom: true, size: 1 }] }, { uuid: 'v3', num_vcpus: 0 }] } };
    if (/storage_containers$/.test(p)) return mode === 'nocontainers' ? { status: 403, json: {} } : { status: 200, json: { entities: [{ storage_container_uuid: 'sc1', name: 'default', usage_stats: { 'storage.capacity_bytes': '0', 'storage.usage_bytes': '1024' }, max_capacity: 2048 }, { name: 'images', usage_stats: {} }] } };
    if (/alerts\?/.test(p)) return { status: 200, json: { entities: [
      { id: 'a1', severity: 'kCritical', alert_title: 'Disk {disk_id} on {host_name} failed {other}', context_types: ['disk_id', 'host_name', 'unused'], context_values: ['d7', 'NTNX-A'], affected_entities: [{ entity_name: 'NTNX-A' }], created_time_stamp_in_usecs: '1760000000123456', acknowledged: 0 },
      { alert_uid: 'a2', severity: 'kWarning', message: 'CVM memory {x}', context_types: ['x'], context_values: [], created_time_stamp_in_usecs: 1760000000000999, acknowledged: true },
      { severity: 'kInfo', message: 'no id' }] } };
    if (/v1\/vms\?count=500&page=1$/.test(p)) return mode === 'nov1' ? { status: 403, json: {} } : { status: 200, json: { entities: [{ uuid: 'v1', ipAddresses: ['2001:db8::5', '10.20.1.15', '10.20.1.17'], stats: { hypervisor_cpu_usage_ppm: '425000', 'guest.memory_usage_ppm': '-1', memory_usage_ppm: '750000', controller_num_iops: '1200', controller_avg_io_latency_usecs: '2350', controller_io_bandwidth_kBps: '9000' } }, { uuid: 'v2', ipAddresses: ['10.20.2.9'] }] } };
    if (/v3\/hosts\/list$/.test(p)) return { status: 200, json: { entities: [
      { metadata: { uuid: 'ph1' }, status: { name: 'PC-H1', cluster_reference: { uuid: 'pc1', name: 'ref-name' }, resources: { hypervisor: { hypervisor_full_name: 'AHV 9', ip: '10.60.0.11' }, controller_vm: { ip: '10.60.0.21' }, ipmi: { ip: '10.60.9.11' }, block: { block_model: 'NX-8035' }, serial_number: 'PS1', cpu_model: 'EPYC', num_cpu_sockets: 2, num_cpu_cores: 64, cpu_capacity_hz: 2.5e11, memory_capacity_mib: 524288 } } },
      { metadata: { uuid: 'pcvm' }, status: { name: 'PC-VM', resources: {} } }, { metadata: { uuid: 'ph2' }, status: { name: 'PC-H2', cluster_reference: { uuid: 'zz' }, resources: { hypervisor: {} } } }] } };
    if (/v3\/clusters\/list$/.test(p)) return { status: 200, json: { entities: [{ metadata: { uuid: 'pc1' }, status: { name: 'DMM-CL', resources: { config: { service_list: ['AOS'] } } } }, { metadata: { uuid: 'pcc' }, status: { name: 'PC', resources: { config: { service_list: ['PRISM_CENTRAL'] } } } }] } };
    if (/v3\/vms\/list$/.test(p)) {
      const off = JSON.parse(o.body).offset;
      if (off === 0) return { status: 200, json: { entities: Array.from({ length: 500 }, (_, i) => ({ metadata: { uuid: 'pv' + i }, status: { name: 'VM' + i, resources: { num_sockets: i % 3, num_vcpus_per_socket: 2, memory_size_mib: 1024, power_state: i % 2 ? 'ON' : 'OFF', host_reference: { uuid: 'ph1' }, nic_list: i % 4 ? [] : [{ mac_address: '50:6b:8d:00:00:' + String(i % 100).padStart(2, '0'), ip_endpoint_list: [{ ip: '10.30.' + (i % 250) + '.4' }, { ip: 7 }] }], disk_list: [{ disk_size_bytes: 10 * GiB }, { device_properties: { device_type: 'CDROM' }, disk_size_bytes: 1 }] } } })) } };
      return { status: 200, json: { entities: [{ metadata: { uuid: 'pvlast' }, spec: { resources: { nic_list: [{ mac_address: '50:6b:8d:ff:ff:ff', ip_endpoint_list: [{ ip: '10.40.0.2' }] }] } } }] } };
    }
    return { status: 404, json: {} };
  };
}

test('Python Nutanix reader answers exactly like the Node.js one', { skip: !hasPy && 'python3 not available' }, async () => {
  const py = createPyEngine({ python: PY });
  for (const mode of ['element', 'nov1', 'nocontainers', 'central', 'badcreds']) {
    const nc = [], pc = [], s1 = await serve(prism(mode), nc), s2 = await serve(prism(mode), pc);
    try {
      const sec = { username: 'svc-ro', password: 'Pr1sm:pass é' };
      let n; try { n = plain(await ntxClient({ base_url: s1.base + '//' }, sec).collect()); } catch (e) { n = { ok: false, error_class: e.code, error: e.message }; }
      const p = await py.call('virt.nutanix', { target: { base_url: s2.base + '//' }, secret: sec, opts: {} });
      assert.deepEqual(p, n, mode + ': identical answers');
      assert.deepEqual(pc.map((c) => c.slice(0, 1).concat(c.slice(1))), nc, mode + ': the same requests, in the same order');
      if (mode === 'element') {
        assert.equal(n.alerts.length, 2); assert.equal(n.alerts[0].title, 'Disk d7 on NTNX-A failed {other}'); assert.equal(n.alerts[1].title, 'CVM memory undefined');
        assert.equal(n.vms[0].cpu_pct, 42.5); assert.equal(n.vms[1].cpu_pct, null);
        // NIC addresses: v2 vm_nics then the v1 list, unique, IPv4 first, link-local dropped
        assert.deepEqual(n.vms[0].ips, ['10.20.1.15', '10.20.1.16', '10.20.1.17', '2001:db8::5']); assert.deepEqual(n.vms[0].macs, ['50:6b:8d:aa:00:01']);
        assert.deepEqual(n.vms[1].ips, ['10.20.2.9']); assert.deepEqual(n.vms[2].ips, []);
        // host, CVM and IPMI addresses for the power plans; a malformed one is dropped, never kept
        assert.deepEqual([n.hosts[1].ip, n.hosts[1].cvm_ip, n.hosts[1].bmc_ip], ['10.50.0.12', '10.50.0.22', undefined]);
      }
      if (mode === 'central') { assert.deepEqual([n.hosts[0].ip, n.hosts[0].cvm_ip, n.hosts[0].bmc_ip], ['10.60.0.11', '10.60.0.21', '10.60.9.11']); assert.equal(n.vms.length, 501); assert.deepEqual([n.vms[0].ips, n.vms[0].macs, n.vms[1].ips, n.vms[500].ips], [['10.30.0.4'], ['50:6b:8d:00:00:00'], [], ['10.40.0.2']]); }
      if (mode === 'badcreds') assert.equal(p.error_class, 'auth');
    } finally { await s1.close(); await s2.close(); }
  }
});

test('a capacity collection reads vCenter and Nutanix through the Python module', { skip: !hasPy && 'python3 not available' }, async (t) => {
  const e = await startApp({ noAi: true });
  const s1 = await serve(fakeVc([]), []), s2 = await serve(prism('element'), []);
  t.after(async () => { await s1.close(); await s2.close(); await e.close(); });
  e.app.config.discovery = Object.assign({}, e.app.config.discovery, { python_bin: PY });
  const dc = e.app.config.discovery, sealer = createSealer({ keyFile: dc.vault_key_file, createKey: true, purpose: 'sentra-itam-virt-platforms' });
  const P = e.app.store.collection('virt_platforms');
  P.put({ id: 'vp_v', kind: 'vcenter', label: 'VC', base_url: s1.base, enc: sealer.seal('vp_v', JSON.stringify({ username: 'svc', password: 'Vc-pass-1' })) });
  P.put({ id: 'vp_n', kind: 'nutanix', label: 'PE', base_url: s2.base, enc: sealer.seal('vp_n', JSON.stringify({ username: 'svc', password: 'x' })) });
  const C = createVirtCapacity(e.app, { sealer });
  const r = await C.run();
  assert.deepEqual(r.map((x) => [x.label, x.ok, x.engine, x.hosts, x.vms]), [['VC', true, 'python', 2, 30], ['PE', true, 'python', 3, 3]], JSON.stringify(r));
  assert.equal(C.report().clusters.find((c) => c.name === 'RUH-PROD').hosts, 2);
});
