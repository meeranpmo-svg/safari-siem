// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Virtualization capacity: vSphere SOAP flow (read-only method list, cookie, paging, serial best-effort), Nutanix v2,
// ITAM records filled only where empty / ours, cluster headroom with N+1, forecast from the daily samples.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { createVirtCapacity, vcSoap } = require('../engine/virt-capacity');
const { createSealer } = require('../engine/discovery/vault');

const { fakeVc, GiB } = require('./fixtures-vcenter-soap');

test('vCenter SOAP: only the read-only methods; refuses anything else', async () => {
  const S = vcSoap({ base_url: 'https://vc' }, { username: 'u', password: 'p' }, { request: async () => ({ status: 200, text: '' }) });
  assert.ok(S.collect);
  const { SOAP_OK } = require('../engine/virt-capacity');
  for (const bad of ['PowerOffVM_Task', 'Destroy_Task', 'ReconfigVM_Task', 'EnterMaintenanceMode_Task']) assert.ok(!SOAP_OK.has(bad), bad);
});

test('capacity: collect, fill ITAM where empty, cluster headroom with N+1, trend from samples', async (t) => {
  const e = await startApp({ noAi: true });
  t.after(() => e.close());
  const ADM = { user: 'syed', role: 'admin' };
  let clock = Date.parse('2026-08-01T08:00:00Z');
  const calls = [];
  const dc = e.app.config.discovery;
  const sealer = createSealer({ keyFile: dc.vault_key_file, createKey: true, purpose: 'sentra-itam-virt-platforms' });
  e.app.store.collection('virt_platforms').put({ id: 'vp_1', kind: 'vcenter', label: 'VC-RUH', base_url: 'https://vc1.corp.local', site: 'Riyadh HQ', enc: sealer.seal('vp_1', JSON.stringify({ username: 'svc@vsphere.local', password: 'Vc-pass-1' })) });
  // the host and one VM are in the inventory already (as virt.js approves them); the VM's memory was typed by hand
  const host = e.app.assets.create({ name: ('esx01.' + 'corp-hq.com'), type: 'server', status: 'in_use' }, ADM).asset.id;
  const vm = e.app.assets.create({ name: 'APP-3', type: 'vm', status: 'in_use' }, ADM).asset.id;
  e.app.store.collection('assets').patch(vm, (a) => { a.mem_gb = 64; a.locked = { mem_gb: true }; return a; });
  const devs = e.app.store.collection('disc_devices');
  devs.put({ id: 'dd1', asset_id: host, uids: ['vc-host:vp_1:host-11'] });
  devs.put({ id: 'dd2', asset_id: vm, uids: ['vc:5003aaaa-0000-0000-0000-000000000003'] });

  const C = createVirtCapacity(e.app, { request: fakeVc(calls), now: () => clock, sealer });
  const r = await C.run(ADM);
  assert.equal(r[0].ok, true, JSON.stringify(r)); assert.deepEqual([r[0].hosts, r[0].vms, r[0].clusters, r[0].datastores], [2, 30, 1, 1], 'template left out, VMs paged');
  assert.ok(calls.every((c) => /^(RetrieveServiceContent|Login|Logout|CreateContainerView|DestroyView|RetrievePropertiesEx|ContinueRetrievePropertiesEx)$/.test(c.m)));
  assert.ok(calls.every((c) => c.url === 'https://vc1.corp.local/sdk'));
  assert.equal(calls[calls.length - 1].m, 'Logout');

  const ha = e.app.store.collection('assets').get(host);
  assert.deepEqual([ha.vendor, ha.model, ha.serial, ha.os, ha.mem_gb, ha.cpu], ['Dell Inc.', 'PowerEdge R750', 'SVC-TAG-01', 'VMware ESXi 7.0.3 build-21930508', 768, '2 sockets, 24 cores each (48 cores) · Intel(R) Xeon(R) Gold 6342 CPU @ 2.80GHz']);
  // the cores reach the core-based licence audit: numCpuCores (48) is the host total → 2 sockets × 24
  const fc = e.app.store.collection('core_lic_facts').get(host);
  assert.deepEqual([fc.sockets, fc.cores_per_socket, fc.cluster, fc.cpu_vendor, fc.source], [2, 24, 'RUH-PROD', 'intel', 'vcenter']);
  assert.equal(r[0].cores_filled, 1);
  const LIC = require('../engine/core-licensing').createCoreLicensing(e.app).view();
  const lh = LIC.hosts.find((x) => x.id === host);
  assert.deepEqual([lh.sockets, lh.cores_per_socket, lh.cores, lh.cores_from, lh.cluster], [2, 24, 48, 'vCenter', 'RUH-PROD'], 'visible for licensing, not 2 × 48');
  const va = e.app.store.collection('assets').get(vm);
  assert.deepEqual([va.cpu, va.mem_gb, va.disk_gb], ['8 vCPU', 64, 200], 'a locked (hand-entered) value is never overwritten');

  const rep = C.report();
  const c = rep.clusters[0];
  assert.deepEqual([c.name, c.hosts, c.vms_on, c.cores, c.vcpus, c.vcpu_ratio, c.mem_gb, c.vm_mem_gb], ['RUH-PROD', 2, 28, 96, 224, 2.33, 1536, 896]);
  assert.equal(c.cpu_used_pct, 25); assert.equal(c.mem_used_pct, 54.7);
  // N+1: one host's 48 cores / 768 GB held back. CPU: 48*4 - 224 < 0 → 0 more VMs; memory: 768*0.9 - 896 < 0 → 0
  assert.equal(c.n_plus_1, true); assert.deepEqual(c.room, { cpu: 0, mem: 0, limit: 'CPU (vCPU per core)' });
  C.setSettings({ n_plus_1: false }, ADM);
  assert.deepEqual(C.report().clusters[0].room, { cpu: 20, mem: 15, limit: 'memory' }, '96*4-224=160/8 = 20; 1382.4-896=486/32 = 15');
  assert.equal(rep.datastores[0].used_pct, 65); assert.equal(rep.datastores[0].provisioned_pct, 80);
  assert.equal(rep.vms_off.length, 2); assert.equal(rep.totals.reclaim_mem_gb, 64);
  // every VM in rep.vms (per-platform pages list from it); top_vms is only the overview's largest-running cut
  assert.equal(rep.vms.length, 30); assert.equal(rep.vms.filter((v) => v.power === 'on').length, 28); assert.equal(rep.vms_capped, false);
  assert.ok(rep.vms.every((v) => v.platform && v.name && 'host' in v));
  // vSphere VM CPU %: MHz against the host's per-core speed × vCPUs; a stopped VM carries no usage
  assert.ok(rep.vms.some((v) => v.power === 'on' && typeof v.cpu_pct === 'number' && v.cpu_pct >= 0), 'running VMs get a CPU %');
  assert.ok(rep.vms.filter((v) => v.power !== 'on').every((v) => v.cpu_pct == null && v.mem_used_pct == null));
  assert.ok(C.vmHistory({ pid: 'vp_1' }).series[0].points.length === 1, 'one hourly sample after one run');
  assert.deepEqual(rep.clusters[0].forecast.memory, { days_of_history: 1 }, 'one sample is not a trend');

  // 40 days of samples with memory use growing → a forecast that says it is reliable
  const L = e.app.store.collection('virt_capacity_hist');
  for (let d = 1; d <= 40; d++) L.put({ id: 'vp_1:d' + d, pid: 'vp_1', day: 'x' + d, at: clock + d * 86400000, clusters: [{ id: 'domain-c7', mem_used_pct: 54.7 + d * 0.3, cpu_used_pct: 25 }], ds_cap: 100, ds_used: 65 + d * 0.2 });
  clock += 41 * 86400000;
  const f = C.report().clusters[0].forecast;
  assert.equal(f.memory.reliable, true); assert.equal(f.memory.per_month, 9); assert.ok(f.memory.days_to_limit === 78, JSON.stringify(f.memory));
  assert.equal(f.cpu.days_to_limit, null, 'flat CPU: no date');
  assert.ok(C.report().storage_trend['VC-RUH'].days_to_limit > 0);
  const aud = e.app.store.auditTail(50, (x) => /^virt\.capacity/.test(x.action || ''));
  assert.ok(!JSON.stringify(aud).includes('Vc-pass-1'));
});

test('capacity: wrong password and an old vCenter (no serial property) are handled', async (t) => {
  const e = await startApp({ noAi: true });
  t.after(() => e.close());
  const dc = e.app.config.discovery, sealer = createSealer({ keyFile: dc.vault_key_file, createKey: true, purpose: 'sentra-itam-virt-platforms' });
  const P = e.app.store.collection('virt_platforms');
  P.put({ id: 'vp_1', kind: 'vcenter', label: 'VC', base_url: 'https://vc1', enc: sealer.seal('vp_1', JSON.stringify({ username: 'u', password: 'wrong' })) });
  const C = createVirtCapacity(e.app, { request: fakeVc([], { oldVc: true }), sealer });
  let r = await C.run();
  assert.equal(r[0].ok, false); assert.equal(r[0].error_class, 'auth');
  P.put({ id: 'vp_1', kind: 'vcenter', label: 'VC', base_url: 'https://vc1', enc: sealer.seal('vp_1', JSON.stringify({ username: 'u', password: 'Vc-pass-1' })) });
  r = await C.run();
  assert.equal(r[0].ok, true, 'an old vCenter without the serial property still reports');
  assert.equal(C.report().hosts[0].serial, '');
});

test('capacity: Nutanix Prism Element v2 usage', async (t) => {
  const e = await startApp({ noAi: true });
  t.after(() => e.close());
  const dc = e.app.config.discovery, sealer = createSealer({ keyFile: dc.vault_key_file, createKey: true, purpose: 'sentra-itam-virt-platforms' });
  e.app.store.collection('virt_platforms').put({ id: 'vp_n', kind: 'nutanix', label: 'PE-RUH', base_url: 'https://pe.corp.local', enc: sealer.seal('vp_n', JSON.stringify({ username: 'svc', password: 'x' })) });
  const seen = [];
  const request = async (url, o) => {
    seen.push([o.method, url]);
    if (/v2\.0\/hosts$/.test(url)) return { status: 200, json: { entities: [{ uuid: 'h1', name: 'NTNX-A', block_model_name: 'NX-3170-G8', serial: 'S1', cpu_model: 'Xeon 6342', num_cpu_sockets: 2, num_cpu_cores: 48, cpu_capacity_in_hz: 134400000000, memory_capacity_in_bytes: 1024 * GiB, hypervisor_full_name: 'AHV 20230302', state: 'NORMAL', stats: { hypervisor_cpu_usage_ppm: 300000, hypervisor_memory_usage_ppm: 600000 } }] } };
    if (/v2\.0\/cluster$/.test(url)) return { status: 200, json: { uuid: 'c1', name: 'RUH-CL1', usage_stats: { 'storage.capacity_bytes': 100 * 1024 * GiB, 'storage.usage_bytes': 55 * 1024 * GiB } } };
    if (/v2\.0\/vms\?/.test(url)) return { status: 200, json: { entities: [{ uuid: 'v1', name: 'DB1', num_vcpus: 2, num_cores_per_vcpu: 4, memory_mb: 65536, power_state: 'on', host_uuid: 'h1', vm_disk_info: [{ size: 500 * GiB }, { size: 4 * GiB, is_cdrom: true }] }] } };
    if (/storage_containers$/.test(url)) return { status: 200, json: { entities: [] } };
    if (/v1\/vms\?count=500&page=1$/.test(url)) return { status: 200, json: { entities: [{ uuid: 'v1', stats: { hypervisor_cpu_usage_ppm: '425000', 'guest.memory_usage_ppm': '-1', memory_usage_ppm: '750000', controller_num_iops: '1200', controller_avg_io_latency_usecs: '2350', controller_io_bandwidth_kBps: '9000' } }] } };
    return { status: 404, json: {} };
  };
  let clock = Date.parse('2026-10-19T08:10:00Z');
  const C = createVirtCapacity(e.app, { request, sealer, now: () => clock });
  const r = await C.run();
  assert.equal(r[0].ok, true, JSON.stringify(r));
  assert.ok(seen.every((s) => s[0] === 'GET' && /^https:\/\/pe\.corp\.local:9440\/PrismGateway\/services\/rest\/(v2\.0\/|v1\/vms\?)/.test(s[1])), 'GET only, v2.0 + the v1 VM list');
  const c = C.report().clusters[0];
  assert.deepEqual([c.name, c.cores, c.vcpus, c.cpu_used_pct, c.mem_used_pct, c.storage_used_pct, c.n_plus_1], ['RUH-CL1', 48, 8, 30, 60, 55, false]);
  assert.equal(C.report().hosts[0].vm_mem_gb, 64);
  // per-VM usage from the v1 list: -1 (not reported) falls through to the next memory counter, never 0
  const v = C.report().vms[0];
  assert.deepEqual([v.id, v.pid, v.cluster, v.cpu_pct, v.mem_used_pct, v.iops, v.io_latency_ms, v.io_kbps], ['v1', 'vp_n', 'RUH-CL1', 42.5, 75, 1200, 2.4, 9000]);
  assert.equal(C.report().platforms[0].vm_usage, true);
  // hourly samples → the per-VM and per-platform graphs
  clock += 3600000; await C.run();
  const h = C.vmHistory({ pid: 'vp_n', vm: 'v1' });
  assert.equal(h.points.length, 2); assert.deepEqual([h.points[0].cpu, h.points[0].mem, h.points[0].iops, h.points[0].lat], [42.5, 75, 1200, 2.4]);
  const agg = C.vmHistory({}).series[0];
  assert.deepEqual([agg.pid, agg.points.length, agg.points[0].cpu, agg.points[0].mem, agg.points[0].iops, agg.points[0].n], ['vp_n', 2, 42.5, 75, 1200, 1]);
  assert.throws(() => C.vmHistory({ vm: 'v1' }), /pid is required/);
});

test('capacity: Nutanix without the v1 VM list keeps capacity; VM usage is not reported (null), never 0', async (t) => {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  const dc = e.app.config.discovery, sealer = createSealer({ keyFile: dc.vault_key_file, createKey: true, purpose: 'sentra-itam-virt-platforms' });
  e.app.store.collection('virt_platforms').put({ id: 'vp_n', kind: 'nutanix', label: 'PE', base_url: 'https://pe', enc: sealer.seal('vp_n', JSON.stringify({ username: 'svc', password: 'x' })) });
  const request = async (url) => {
    if (/v2\.0\/hosts$/.test(url)) return { status: 200, json: { entities: [{ uuid: 'h1', name: 'N', num_cpu_cores: 8, cpu_capacity_in_hz: 1e10, memory_capacity_in_bytes: 64 * GiB, state: 'NORMAL' }] } };
    if (/v2\.0\/cluster$/.test(url)) return { status: 200, json: { uuid: 'c1', name: 'CL' } };
    if (/v2\.0\/vms\?/.test(url)) return { status: 200, json: { entities: [{ uuid: 'v1', name: 'A', num_vcpus: 2, memory_mb: 4096, power_state: 'on', host_uuid: 'h1' }] } };
    if (/v1\/vms/.test(url)) return { status: 403, json: {} };
    return { status: 200, json: { entities: [] } };
  };
  const C = createVirtCapacity(e.app, { request, sealer });
  const r = await C.run(); assert.equal(r[0].ok, true, JSON.stringify(r));
  const v = C.report().vms[0];
  assert.deepEqual([v.cpu_pct, v.mem_used_pct, v.iops], [null, null, null]);
  assert.equal(C.report().platforms[0].vm_usage, false);
  assert.deepEqual(C.vmHistory({}).series[0].points, [], 'nothing reported → no sample');
});

test('capacity: a Nutanix VM\'s IP - Prism NICs first, else discovery (uid, asset), else a MAC seen by Network Discovery; never guessed', async (t) => {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  const dc = e.app.config.discovery, sealer = createSealer({ keyFile: dc.vault_key_file, createKey: true, purpose: 'sentra-itam-virt-platforms' });
  e.app.store.collection('virt_platforms').put({ id: 'vp_n', kind: 'nutanix', label: 'PE', base_url: 'https://pe', enc: sealer.seal('vp_n', JSON.stringify({ username: 'svc', password: 'x' })) });
  const D = e.app.store.collection('disc_devices'), A = e.app.store.collection('assets');
  D.put({ id: 'dd1', uids: ['ntnx:v2'], ips: ['10.9.0.2'], ip: '10.9.0.2', macs: [] });
  A.put({ id: 'as3', name: 'C', mgmt_ip: '10.9.0.3' }); D.put({ id: 'dd3', uids: ['ntnx:v3'], ips: [], ip: null, asset_id: 'as3', macs: [] });
  D.put({ id: 'dd4', uids: [], ips: ['10.9.0.4'], ip: '10.9.0.4', macs: ['50:6b:8d:00:00:04'] });
  const seen = [];
  const request = async (url) => {
    seen.push(url);
    if (/v2\.0\/hosts$/.test(url)) return { status: 200, json: { entities: [{ uuid: 'h1', name: 'N', num_cpu_cores: 8, cpu_capacity_in_hz: 1e10, memory_capacity_in_bytes: 64 * GiB, state: 'NORMAL' }] } };
    if (/v2\.0\/cluster$/.test(url)) return { status: 200, json: { uuid: 'c1', name: 'CL' } };
    if (/v2\.0\/vms\?/.test(url)) return { status: 200, json: { entities: [
      { uuid: 'v1', name: 'A', power_state: 'on', host_uuid: 'h1', vm_nics: [{ mac_address: '50:6b:8d:00:00:01', ip_address: '10.9.0.1' }] },
      { uuid: 'v2', name: 'B', power_state: 'on', host_uuid: 'h1', vm_nics: [{ mac_address: '50:6b:8d:00:00:02' }] },
      { uuid: 'v3', name: 'C', power_state: 'on', host_uuid: 'h1' },
      { uuid: 'v4', name: 'D', power_state: 'off', host_uuid: 'h1', vm_nics: [{ mac_address: '50:6B:8D:00:00:04' }] },
      { uuid: 'v5', name: 'E', power_state: 'on', host_uuid: 'h1', vm_nics: [{ mac_address: '50:6b:8d:00:00:05' }] }] } };
    if (/v1\/vms/.test(url)) return { status: 403, json: {} };
    return { status: 200, json: { entities: [] } };
  };
  const C = createVirtCapacity(e.app, { request, sealer });
  const r = await C.run(); assert.equal(r[0].ok, true, JSON.stringify(r));
  assert.ok(seen.some((u) => /v2\.0\/vms\?include_vm_disk_config=true&include_vm_nic_config=true$/.test(u)), 'the VM list asks Prism for the NICs');
  const by = Object.fromEntries(C.report().vms.map((v) => [v.name, [v.ips, v.ip_src]]));
  assert.deepEqual(by, { A: [['10.9.0.1'], 'prism'], B: [['10.9.0.2'], 'discovery'], C: [['10.9.0.3'], 'asset'], D: [['10.9.0.4'], 'mac'], E: [[], null] });
  assert.deepEqual(C.report().vms.find((v) => v.name === 'D').macs, ['50:6b:8d:00:00:04']);
});

test('over-provisioning: cluster ratios, Nutanix storage provisioned, right-sizing from p95 history (enough samples only, at most half per step), powered-off VMs', async (t) => {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  const dc = e.app.config.discovery, sealer = createSealer({ keyFile: dc.vault_key_file, createKey: true, purpose: 'sentra-itam-virt-platforms' });
  e.app.store.collection('virt_platforms').put({ id: 'vp_n', kind: 'nutanix', label: 'PE', base_url: 'https://pe', enc: sealer.seal('vp_n', JSON.stringify({ username: 'svc', password: 'x' })) });
  const request = async (url) => {
    if (/v2\.0\/hosts$/.test(url)) return { status: 200, json: { entities: [{ uuid: 'h1', name: 'N', num_cpu_sockets: 1, num_cpu_cores: 8, cpu_capacity_in_hz: 2e10, memory_capacity_in_bytes: 128 * GiB, state: 'NORMAL' }] } };
    if (/v2\.0\/cluster$/.test(url)) return { status: 200, json: { uuid: 'c1', name: 'CL', usage_stats: { 'storage.capacity_bytes': 1000 * GiB, 'storage.usage_bytes': 300 * GiB } } };
    if (/v2\.0\/vms\?/.test(url)) return { status: 200, json: { entities: [
      { uuid: 'big', name: 'BIG', num_vcpus: 16, memory_mb: 64 * 1024, power_state: 'on', host_uuid: 'h1', vm_disk_info: [{ size: 600 * GiB }] },
      { uuid: 'busy', name: 'BUSY', num_vcpus: 4, memory_mb: 16 * 1024, power_state: 'on', host_uuid: 'h1', vm_disk_info: [{ size: 300 * GiB }] },
      { uuid: 'new', name: 'NEW', num_vcpus: 8, memory_mb: 32 * 1024, power_state: 'on', host_uuid: 'h1', vm_disk_info: [{ size: 200 * GiB }] },
      { uuid: 'off', name: 'OFF', num_vcpus: 2, memory_mb: 8 * 1024, power_state: 'off', host_uuid: 'h1', vm_disk_info: [{ size: 100 * GiB }] }] } };
    if (/v1\/vms/.test(url)) return { status: 403, json: {} };
    return { status: 200, json: { entities: [] } };
  };
  let clock = Date.parse('2026-10-21T08:00:00Z');
  const C = createVirtCapacity(e.app, { request, sealer, now: () => clock });
  assert.equal((await C.run())[0].ok, true);
  const H = e.app.store.collection('virt_vm_hist');
  for (let i = 0; i < 100; i++) H.put({ id: 'vp_n:s' + i, pid: 'vp_n', at: clock - i * 3600000, v: { big: [i === 3 ? 90 : 5, 10, null, null], busy: [95, 92, null, null] } });
  for (let i = 0; i < 10; i++) H.put({ id: 'vp_n:n' + i, pid: 'vp_n', at: clock - i * 3600000 - 1, v: { new: [1, 1, null, null] } });
  const o = C.overprov({ days: 30 });
  const c = o.clusters[0];
  assert.deepEqual([c.vcpus, c.cores, c.vcpu_ratio, c.cpu, c.vm_mem_gb, c.mem_gb, c.mem_alloc_pct, c.mem], [28, 8, 3.5, 'near', 112, 128, 87.5, 'ok']);
  assert.deepEqual([c.storage_gb, c.disk_prov_gb, c.storage_prov_pct, c.storage], [1000, 1200, 120, 'over'], 'Nutanix: configured disks against cluster storage');
  // BIG: p95 CPU 5% of 16 → needs 2, but never more than half in one step → 8; memory p95 10% of 64 GB → 8 GB, half → 32
  const big = o.vms.find((v) => v.name === 'BIG');
  assert.deepEqual([big.cpu_p95, big.cpu_max, big.vcpus_to, big.save_vcpu, big.mem_to, big.save_mem_gb, big.samples], [5, 90, 8, 8, 32, 32, 100]);
  assert.ok(!o.vms.some((v) => v.name === 'BUSY') && o.under.some((v) => v.name === 'BUSY' && v.cpu_short && v.mem_short), 'busy VM: not cut, flagged as short of resources');
  assert.ok(!o.vms.some((v) => v.name === 'NEW') && o.short.some((v) => v.name === 'NEW' && v.samples === 10), 'too little history: never called oversized');
  assert.deepEqual([o.totals.off, o.totals.off_mem_gb, o.totals.off_disk_gb, o.totals.save_vcpu, o.totals.save_mem_gb, o.totals.storage_over], [1, 8, 100, 8, 32, 1]);
});

test('capacity: Nutanix refuses any v1 path but the paged VM list', () => {
  const { ntxClient } = require('../engine/virt-capacity');
  const NTX_OK = require('../engine/virt-capacity').NTX_OK;
  assert.ok(NTX_OK.some((re) => re.test('/PrismGateway/services/rest/v1/vms?count=500&page=3')));
  for (const p of ['/PrismGateway/services/rest/v1/vms/abc/set_power_state', '/PrismGateway/services/rest/v1/vms?count=500&page=1&x=1', '/PrismGateway/services/rest/v1/hosts']) assert.ok(!NTX_OK.some((re) => re.test(p)), p);
  assert.ok(ntxClient);
});

test('capacity: a core count typed in the licence audit is never replaced by vCenter; health read (status, HA, snapshots, Tools)', async (t) => {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  const ADM = { user: 'syed', role: 'admin' };
  const dc = e.app.config.discovery;
  const sealer = createSealer({ keyFile: dc.vault_key_file, createKey: true, purpose: 'sentra-itam-virt-platforms' });
  e.app.store.collection('virt_platforms').put({ id: 'vp_1', kind: 'vcenter', label: 'VC-RUH', base_url: 'https://vc1.corp.local', enc: sealer.seal('vp_1', JSON.stringify({ username: 'svc@vsphere.local', password: 'Vc-pass-1' })) });
  const h1 = e.app.assets.create({ name: ('esx01.' + 'corp-hq.com'), type: 'server', status: 'in_use', os: 'VMware ESXi' }, ADM).asset.id;
  e.app.store.collection('disc_devices').put({ id: 'dd1', asset_id: h1, uids: ['vc-host:vp_1:host-11'] });
  const L = require('../engine/core-licensing').createCoreLicensing(e.app);
  assert.match(L.view().hosts.find((x) => x.id === h1).cores_hint, /add-virt-capacity/, 'says what fills an unknown count');
  L.putFacts({ items: [{ id: h1, sockets: 2, cores_per_socket: 28 }] }, ADM);
  const C = createVirtCapacity(e.app, { request: fakeVc([]), sealer });
  await C.run(ADM);
  const f = e.app.store.collection('core_lic_facts').get(h1);
  assert.deepEqual([f.sockets, f.cores_per_socket, f.source], [2, 28, 'entered'], 'the person\'s count stands');
  assert.equal(L.view().hosts.find((x) => x.id === h1).cores_from, 'entered');
  const m = e.app.store.collection('virt_capacity').get('vp_1');
  assert.equal(m.hosts.find((x) => x.id === 'host-12').status, 'red');
  assert.deepEqual([m.clusters[0].ha, m.clusters[0].drs], [false, true]);
  const v1 = m.vms.find((x) => x.id === 'vm-101');
  assert.deepEqual([v1.snapshots.count, v1.snapshots.oldest, v1.consolidate, v1.tools], [2, '2026-06-01T10:00:00.000Z', true, 'not-running']);
  assert.deepEqual(m.vms.find((x) => x.id === 'vm-110').snapshots, { count: 0, oldest: null }, 'health read: no snapshot = 0, not unknown');
  // an older vCenter that refuses the health properties still gives the capacity
  const C2 = createVirtCapacity(e.app, { request: fakeVc([], { noHealth: true }), sealer });
  const r2 = await C2.run(ADM);
  assert.equal(r2[0].ok, true);
  const m2 = e.app.store.collection('virt_capacity').get('vp_1');
  assert.equal(m2.vms[0].snapshots, null, 'not read = not reported, never "no snapshots"'); assert.equal(m2.health.VirtualMachine, false);
});

test('capacity: a vCenter saved only in Asset Discovery is collected too (no second setup); same address = one source', async (t) => {
  const e = await startApp({ noAi: true });
  t.after(() => e.close());
  const ADM = { user: 'syed', role: 'admin' };
  let released = 0;
  const vault = {
    list: () => [{ id: 'cred1', kind: 'vcenter', label: 'VC-ASSET', target: { base_url: 'https://vc1.corp.local/' } }, { id: 'cred2', kind: 'ssh', label: 'x', target: {} }],
    open: (id) => { assert.equal(id, 'cred1'); return { target: { base_url: 'https://vc1.corp.local' }, secret: { username: 'svc@vsphere.local', password: 'Vc-pass-1' }, release() { released++; } }; },
  };
  // the host as Asset Discovery keys it (vc-host:<moref>, no platform id)
  const host = e.app.assets.create({ name: ('esx01.' + 'corp-hq.com'), type: 'server', status: 'in_use' }, ADM).asset.id;
  e.app.store.collection('disc_devices').put({ id: 'dd1', asset_id: host, uids: ['vc-host:host-11'] });

  const C = createVirtCapacity(e.app, { request: fakeVc([]), now: () => Date.parse('2026-08-01T08:00:00Z'), discoveryVault: vault });
  const r = await C.run(ADM);
  assert.equal(r.length, 1, 'the ssh credential is ignored'); assert.equal(r[0].ok, true, JSON.stringify(r));
  assert.equal(r[0].origin, 'asset-discovery'); assert.equal(r[0].hosts, 2);
  assert.ok(released >= 1, 'the vault secret is released after use');
  const rep = C.report();
  assert.equal(rep.platforms.length, 1); assert.equal(rep.platforms[0].origin, 'asset-discovery'); assert.equal(rep.platforms[0].collected, true);
  assert.ok(rep.clusters.length >= 1 && rep.hosts.length === 2, 'capacity planning has the clusters and hosts');
  assert.ok(e.app.store.collection('assets').get(host).cpu, 'the asset keyed by Asset Discovery is enriched');

  // the same vCenter also on the Virtualization page → one source (the page wins), not two
  const { createSealer: cs } = require('../engine/discovery/vault');
  const sealer = cs({ keyFile: e.app.config.discovery.vault_key_file, createKey: true, purpose: 'sentra-itam-virt-platforms' });
  e.app.store.collection('virt_platforms').put({ id: 'vp_1', kind: 'vcenter', label: 'VC-RUH', base_url: 'https://vc1.corp.local', enc: sealer.seal('vp_1', JSON.stringify({ username: 'u', password: 'p' })) });
  const C2 = createVirtCapacity(e.app, { request: fakeVc([]), sealer, discoveryVault: vault });
  const rep2 = C2.report();
  assert.equal(rep2.platforms.length, 1); assert.equal(rep2.platforms[0].origin, 'virtualization');
});

test('capacity live: two read-only calls refresh host / VM usage between full collections; nothing else written; settings and scheduler', async (t) => {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  const dc = e.app.config.discovery, sealer = createSealer({ keyFile: dc.vault_key_file, createKey: true, purpose: 'sentra-itam-virt-platforms' });
  e.app.store.collection('virt_platforms').put({ id: 'vp_1', kind: 'vcenter', label: 'VC-RUH', base_url: 'https://vc1.corp.local', enc: sealer.seal('vp_1', JSON.stringify({ username: 'svc@vsphere.local', password: 'Vc-pass-1' })) });
  let clock = Date.parse('2026-10-20T08:00:00Z');
  const calls = [];
  const C = createVirtCapacity(e.app, { request: fakeVc(calls), now: () => clock, sealer });
  // before any full collection there is nothing to patch: said, not guessed
  let L = await C.live({ user: 'ali', role: 'operator', ip: '' });
  assert.equal(L[0].ok, false); assert.match(L[0].error, /no full collection yet/);
  await C.run();
  const latest = e.app.store.collection('virt_capacity');
  const before = { hist: e.app.store.collection('virt_capacity_hist').all().length, assets: e.app.store.collection('assets').all().length };
  // the counters move on the platform: simulate a stale snapshot, then fetch live
  latest.patch('vp_1', (x) => { x.hosts[0].cpu_used_mhz = 1; x.vms[0].cpu_used_mhz = 1; x.vms[0].power = 'off'; return x; });
  calls.length = 0; clock += 120000;
  L = await C.live({ user: 'ali', role: 'operator', ip: '' });
  assert.equal(L[0].ok, true, JSON.stringify(L)); assert.deepEqual([L[0].hosts, L[0].vms], [2, 31]);
  const rp = calls.filter((c) => /^RetrieveProperties/.test(c.m));
  assert.equal(rp.length, 2, 'host counters + VM counters, nothing else'); assert.ok(calls.every((c) => /^(RetrieveServiceContent|Login|Logout|CreateContainerView|DestroyView|RetrievePropertiesEx|ContinueRetrievePropertiesEx)$/.test(c.m)));
  const m = latest.get('vp_1');
  assert.equal(m.hosts[0].cpu_used_mhz, 40320); assert.equal(m.vms[0].power, 'on'); assert.equal(m.live_at, new Date(clock).toISOString());
  assert.ok(m.hosts[0].serial && m.datastores.length, 'everything the live read does not carry is kept from the full read');
  assert.equal(e.app.store.collection('virt_capacity_hist').all().length, before.hist, 'no trend sample from a live read');
  assert.equal(e.app.store.collection('assets').all().length, before.assets, 'the asset register is not touched');
  const R = C.report(); assert.equal(R.platforms[0].live_at, m.live_at); assert.equal(R.last_live.results[0].ok, true);
  assert.equal(R.hosts[0].cpu_used_pct, Math.round(40320 / R.hosts[0].cpu_ghz / 1000 * 1000) / 10 || R.hosts[0].cpu_used_pct);
  // scheduler: every live_sec seconds (default 60), 0 switches it off, never faster than 30 s
  assert.equal(C.settings().live_sec, 60);
  assert.equal(await C.liveTick(), null, 'just fetched');
  clock += 61000; calls.length = 0; assert.ok(Array.isArray(await C.liveTick())); assert.ok(calls.length > 0);
  C.setSettings({ live_sec: 0 }, { user: 'syed', role: 'admin', ip: '' }); clock += 600000; assert.equal(await C.liveTick(), null, 'off');
  C.setSettings({ live_sec: 5 }, { user: 'syed', role: 'admin', ip: '' }); await C.live(); clock += 10000;
  assert.equal(await C.liveTick(), null, '5 s is raised to 30 s'); clock += 25000; assert.ok(Array.isArray(await C.liveTick()), 'due after 30 s');
  assert.throws(() => C.setSettings({ live_sec: 99999 }, { user: 'syed', role: 'admin', ip: '' }));
  // a failing live read keeps the last values and says so
  const C2 = createVirtCapacity(e.app, { request: async () => { throw Object.assign(new Error('connect ECONNREFUSED'), { code: 'unreachable' }); }, now: () => clock, sealer });
  L = await C2.live(); assert.equal(L[0].ok, false); assert.equal(latest.get('vp_1').hosts[0].cpu_used_mhz, 40320);
  assert.match(C2.report().platforms[0].live_error, /ECONNREFUSED|unreachable/);
  // route: an operator may fetch, a viewer may not
  const routes = {}; require('../engine/virt-capacity').registerVirtCapacity({ route: (m, path, fn) => { routes[m + ' ' + path] = fn; } }, e.app);
  const ctx = (role) => ({ who: { user: 'u', role, ip: '' }, body: {}, need: (r) => { const rk = { viewer: 0, operator: 2, admin: 3 }; if (rk[role] < rk[r]) throw Object.assign(new Error('forbidden'), { status: 403 }); } });
  await assert.rejects(routes['POST /virt/capacity/live'](ctx('viewer')), (x) => x.status === 403, 'a viewer may not fetch');
  const ok = await routes['POST /virt/capacity/live'](ctx('operator')); assert.ok(Array.isArray(ok.results) && ok.report && ok.report.platforms, 'an operator may fetch; the report comes back with it');
});

test('capacity live: Nutanix hosts and VMs usage refreshed from Prism', async (t) => {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  const dc = e.app.config.discovery, sealer = createSealer({ keyFile: dc.vault_key_file, createKey: true, purpose: 'sentra-itam-virt-platforms' });
  e.app.store.collection('virt_platforms').put({ id: 'vp_n', kind: 'nutanix', label: 'PE-RUH', base_url: 'https://pe.corp.local', enc: sealer.seal('vp_n', JSON.stringify({ username: 'svc', password: 'x' })) });
  let cpu = '300000', vmcpu = '425000';
  const request = async (url, o) => {
    if (/v2\.0\/hosts$/.test(url)) return { status: 200, json: { entities: [{ uuid: 'h1', name: 'NTNX-A', num_cpu_cores: 48, cpu_capacity_in_hz: 48 * 2.8e9, memory_capacity_in_bytes: 512 * GiB, stats: { hypervisor_cpu_usage_ppm: cpu, hypervisor_memory_usage_ppm: '600000' } }] } };
    if (/v2\.0\/cluster$/.test(url)) return { status: 200, json: { uuid: 'c1', name: 'RUH-CL1', usage_stats: {} } };
    if (/v2\.0\/vms\?/.test(url)) return { status: 200, json: { entities: [{ uuid: 'v1', name: 'DB1', num_vcpus: 8, memory_mb: 65536, power_state: 'on', host_uuid: 'h1' }] } };
    if (/storage_containers$/.test(url)) return { status: 200, json: { entities: [] } };
    if (/v1\/vms\?count=500&page=1$/.test(url)) return { status: 200, json: { entities: [{ uuid: 'v1', stats: { hypervisor_cpu_usage_ppm: vmcpu, memory_usage_ppm: '500000' } }] } };
    return { status: 404, json: {} };
  };
  const C = createVirtCapacity(e.app, { request, sealer });
  await C.run();
  assert.equal(C.report().hosts[0].cpu_used_pct, 30);
  cpu = '900000'; vmcpu = '125000';
  const L = await C.live();
  assert.equal(L[0].ok, true, JSON.stringify(L));
  assert.equal(C.report().hosts[0].cpu_used_pct, 90, 'host CPU refreshed');
  const v = e.app.store.collection('virt_capacity').get('vp_n').vms[0];
  assert.deepEqual([v.cpu_pct, v.mem_used_mb, v.name], [12.5, 32768, 'DB1'], 'VM usage refreshed, identity kept');
});

test('Nutanix DR: protection domains on HQ and DR - RPO, no remote copy, stuck replication, remote site down, unprotected VMs, split brain; AI Virtualization Administrator alerts', async (t) => {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  const dc = e.app.config.discovery, sealer = createSealer({ keyFile: dc.vault_key_file, createKey: true, purpose: 'sentra-itam-virt-platforms' });
  const put = (id, label, site, url) => e.app.store.collection('virt_platforms').put({ id, kind: 'nutanix', label, site, base_url: url, enc: sealer.seal(id, JSON.stringify({ username: 'svc', password: 'x' })) });
  put('vp_hq', 'PE-HQ', 'Riyadh HQ', 'https://pe-hq.corp.local'); put('vp_dr', 'PE-DR', 'Jeddah DR', 'https://pe-dr.corp.local');
  const clock = Date.parse('2026-10-20T12:00:00Z'), us = (minAgo) => (clock - minAgo * 60000) * 1000, seen = [];
  const site = {
    'pe-hq': { pds: [
      { name: 'PD-ERP', active: true, vms: [{ vm_name: 'DB1' }], remote_site_names: ['DR-SITE'], cron_schedules: [{ type: 'HOURLY', every_nth: 1 }] },
      { name: 'PD-WEB', active: true, vms: [{ vm_name: 'WEB1' }], remote_site_names: ['DR-SITE'], cron_schedules: [{ type: 'HOURLY', every_nth: 1 }] },
      { name: 'PD-MAIL', active: true, vms: [{ vm_name: 'MAIL1' }], remote_site_names: [], cron_schedules: [{ type: 'DAILY', every_nth: 1 }] },
      { name: 'PD-FILE', active: true, vms: [{ vm_name: 'FS1' }], remote_site_names: ['DR-SITE'], cron_schedules: [{ type: 'HOURLY', every_nth: 4 }] }],
      snaps: { 'PD-ERP': [{ snapshot_create_time_usecs: us(150), remote_site_names: ['DR-SITE'] }, { snapshot_create_time_usecs: us(20) }], 'PD-WEB': [{ snapshot_create_time_usecs: us(30), remote_site_names: ['DR-SITE'] }], 'PD-MAIL': [{ snapshot_create_time_usecs: us(600) }], 'PD-FILE': [{ snapshot_create_time_usecs: us(60), remote_site_names: ['DR-SITE'] }] },
      remotes: [{ name: 'DR-SITE', remote_ip_ports: { '10.20.0.10': 2020 }, status: 'unreachable' }],
      repl: [{ protection_domain_name: 'PD-ERP', remote_site_name: 'DR-SITE', replication_operation: 'SENDING', start_time_usecs: us(200), completed_percentage: 40 }],
      vms: [{ uuid: 'v1', name: 'DB1', power_state: 'on' }, { uuid: 'v2', name: 'WEB1', power_state: 'on' }, { uuid: 'v3', name: 'MAIL1', power_state: 'on' }, { uuid: 'v4', name: 'FS1', power_state: 'on' }, { uuid: 'v5', name: 'APP9', power_state: 'on' }, { uuid: 'v6', name: 'OLD', power_state: 'off' }] },
    'pe-dr': { pds: [{ name: 'PD-ERP', active: false, vms: [], remote_site_names: ['HQ-SITE'], cron_schedules: [] }, { name: 'PD-FILE', active: true, vms: [{ vm_name: 'FS1' }], remote_site_names: ['HQ-SITE'], cron_schedules: [{ type: 'HOURLY', every_nth: 4 }] }],
      snaps: { 'PD-FILE': [{ snapshot_create_time_usecs: us(30), remote_site_names: ['HQ-SITE'] }] }, remotes: [{ name: 'HQ-SITE', status: 'connected' }], repl: [], vms: [] },
  };
  const request = async (url, o) => {
    seen.push([o.method, url]);
    const s = site[/pe-hq/.test(url) ? 'pe-hq' : 'pe-dr'], p = new URL(url).pathname + new URL(url).search;
    if (/v2\.0\/hosts$/.test(p)) return { status: 200, json: { entities: [{ uuid: 'h-' + url.length, name: 'NTNX', num_cpu_cores: 32, cpu_capacity_in_hz: 32e9, memory_capacity_in_bytes: 256 * GiB, stats: {} }] } };
    if (/v2\.0\/cluster$/.test(p)) return { status: 200, json: { uuid: 'c', name: 'CL', usage_stats: {} } };
    if (/v2\.0\/vms\?/.test(p)) return { status: 200, json: { entities: s.vms } };
    if (/v2\.0\/protection_domains$/.test(p)) return { status: 200, json: { entities: s.pds } };
    const m = /v2\.0\/protection_domains\/([^/]+)\/dr_snapshots\?count=20$/.exec(p); if (m) return { status: 200, json: { entities: s.snaps[decodeURIComponent(m[1])] || [] } };
    if (/v2\.0\/remote_sites$/.test(p)) return { status: 200, json: { entities: s.remotes } };
    if (/v2\.0\/protection_domains\/replications$/.test(p)) return { status: 200, json: { entities: s.repl } };
    return { status: 404, json: {} };
  };
  const C = createVirtCapacity(e.app, { request, sealer, now: () => clock });
  await C.run();
  assert.ok(seen.every((x) => x[0] === 'GET'), 'GET only on Prism Element');
  const D = C.report().dr, hq = D.sites.find((x) => x.platform === 'PE-HQ'), dr = D.sites.find((x) => x.platform === 'PE-DR');
  const st = (S, n) => S.protection_domains.find((x) => x.name === n);
  assert.deepEqual([st(hq, 'PD-ERP').status, st(hq, 'PD-ERP').age_min, st(hq, 'PD-ERP').rpo_min, st(hq, 'PD-ERP').basis], ['late', 150, 60, 'replicated'], 'the newer local-only snapshot does not count as a DR copy');
  assert.equal(st(hq, 'PD-WEB').status, 'ok'); assert.equal(st(hq, 'PD-MAIL').status, 'no-remote'); assert.equal(st(hq, 'PD-FILE').status, 'ok');
  assert.deepEqual(st(hq, 'PD-ERP').stuck, { remote_site: 'DR-SITE', minutes: 200, pct: 40 });
  assert.equal(st(dr, 'PD-ERP').status, 'standby');
  assert.deepEqual(hq.unprotected_vms, ['APP9'], 'powered-on VM in no protection domain (powered-off ones are not counted)');
  assert.equal(hq.remote_sites[0].healthy, false);
  assert.deepEqual(D.cross.map((x) => [x.name, x.status]), [['PD-FILE', 'both-active']]);
  assert.deepEqual([D.totals.protection_domains, D.totals.late, D.totals.no_remote, D.totals.unprotected_vms, D.totals.remote_sites_down, D.totals.cross], [6, 1, 1, 1, 1, 1]);
  // alerts: the AI Virtualization Administrator opens one work item per problem
  e.app.addons = e.app.addons || {}; e.app.addons.virtCapacity = C;
  const F = require('../engine/virt-admin').createVirtAdmin(e.app, { now: () => clock }).current();
  const by = (k) => F.filter((x) => x.kind === k);
  assert.equal(by('dr-rpo').length, 1); assert.equal(by('dr-rpo')[0].severity, 'high'); assert.match(by('dr-rpo')[0].title, /PD-ERP: DR copy 150 min old - RPO 60 min missed/);
  assert.equal(by('dr-no-remote')[0].target.name, 'PD-MAIL');
  assert.equal(by('dr-replication-stuck')[0].target.name, 'PD-ERP');
  assert.equal(by('dr-remote-site')[0].severity, 'critical');
  assert.match(by('dr-unprotected')[0].title, /1 powered-on VM is in no protection domain/);
  assert.equal(by('dr-split-brain')[0].severity, 'critical'); assert.match(by('dr-split-brain')[0].title, /PD-FILE: active on PE-HQ and PE-DR/);
  assert.equal(F.filter((x) => /^dr-/.test(x.kind) && /PD-WEB/.test(x.title)).length, 0, 'a healthy protection domain raises nothing');
});

test('Nutanix DR: Prism Central (Leap) rules and plans; a Prism without DR access says unreadable, never healthy', async (t) => {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  const dc = e.app.config.discovery, sealer = createSealer({ keyFile: dc.vault_key_file, createKey: true, purpose: 'sentra-itam-virt-platforms' });
  e.app.store.collection('virt_platforms').put({ id: 'vp_pc', kind: 'nutanix', label: 'PC', base_url: 'https://pc.corp.local', enc: sealer.seal('vp_pc', JSON.stringify({ username: 'svc', password: 'x' })) });
  const request = async (url, o) => {
    const p = new URL(url).pathname;
    if (/v2\.0\/hosts$/.test(p)) return { status: 404, json: {} };
    if (/v3\/(host|vm|cluster)s\/list$/.test(p)) return { status: 200, json: { entities: [] } };
    if (/v3\/protection_rules\/list$/.test(p)) return { status: 200, json: { entities: [{ spec: { name: 'Gold-1h', resources: { availability_zone_connectivity_list: [{ destination_availability_zone_index: 1, snapshot_schedule_list: [{ recovery_point_objective_secs: 3600 }] }] } }, status: { state: 'COMPLETE' } }] } };
    if (/v3\/recovery_plans\/list$/.test(p)) return { status: 200, json: { entities: [{ spec: { name: 'RP-ERP', resources: { stage_list: [{}, {}] } }, status: { state: 'COMPLETE' } }] } };
    return { status: 404, json: {} };
  };
  const C = createVirtCapacity(e.app, { request, sealer });
  await C.run();
  const S = C.report().dr.sites[0];
  assert.deepEqual(S.leap.rules.map((r) => [r.name, r.rpo_min, r.state]), [['Gold-1h', 60, 'COMPLETE']]);
  assert.deepEqual(S.leap.plans.map((r) => [r.name, r.stages]), [['RP-ERP', 2]]);
  // Prism Element that refuses the DR views: listed as unreadable
  const C2 = createVirtCapacity(e.app, { sealer, request: async (url) => { const p = new URL(url).pathname; if (/v2\.0\/hosts$/.test(p)) return { status: 200, json: { entities: [] } }; if (/v2\.0\/(cluster)$/.test(p)) return { status: 200, json: {} }; if (/v2\.0\/vms/.test(p)) return { status: 200, json: { entities: [] } }; if (/protection_domains$|remote_sites$/.test(p)) return { status: 403, json: {} }; return { status: 404, json: {} }; } });
  await C2.run();
  const S2 = C2.report().dr.sites[0];
  assert.ok(S2.read_errors.length >= 1 && S2.read_errors.every((x) => /authori[sz]ed|403/i.test(x)), JSON.stringify(S2.read_errors));
  e.app.addons = e.app.addons || {}; e.app.addons.virtCapacity = C2;
  assert.ok(require('../engine/virt-admin').createVirtAdmin(e.app).current().some((x) => x.kind === 'dr-read'), 'unreadable DR raises a work item');
});

test('capacity: a platform added after the hourly run is collected at once; a failing one waits 10 min; one platform on demand', async (t) => {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  let clock = Date.parse('2026-10-26T12:00:00Z');
  const dc = e.app.config.discovery, calls = [];
  const sealer = createSealer({ keyFile: dc.vault_key_file, createKey: true, purpose: 'sentra-itam-virt-platforms' });
  const plats = e.app.store.collection('virt_platforms'), seal = (id) => sealer.seal(id, JSON.stringify({ username: 'svc@vsphere.local', password: 'Vc-pass-1' }));
  plats.put({ id: 'vp_1', kind: 'vcenter', label: 'VC-RUH', base_url: 'https://vc1.corp.local', enc: seal('vp_1') });
  const C = createVirtCapacity(e.app, { request: fakeVc(calls), now: () => clock, sealer });
  await C.run();
  const n0 = calls.length;
  clock += 5 * 60000; assert.equal(await C.tick(), null, 'nothing new, inside the hour: no collection');
  // a second platform (the DR site) is added: collected on the next tick, the hourly cadence is not moved
  plats.put({ id: 'vp_2', kind: 'vcenter', label: 'VC-DR', base_url: 'https://vc2.corp.local', enc: seal('vp_2') });
  const atBefore = C.report().last_run.at;
  assert.equal(await C.tick(), 'new-platforms');
  assert.ok(calls.slice(n0).every((c) => c.url === 'https://vc2.corp.local/sdk'), 'only the new platform is read');
  const lr = C.report().last_run; assert.equal(lr.at, atBefore, 'hourly cadence unchanged');
  assert.deepEqual(lr.results.map((r) => r.platform_id).sort(), ['vp_1', 'vp_2'], 'its result joins the last run');
  assert.ok(C.report().platforms.find((p) => p.id === 'vp_2').at, 'the DR platform now has a reading for every dashboard');
  // on demand (Collect now on Virtualization): that platform only
  const n1 = calls.length; await C.collectPlatform('vp_1');
  assert.ok(calls.length > n1 && calls.slice(n1).every((c) => c.url === 'https://vc1.corp.local/sdk'));
  // a new platform that fails is not retried every minute
  plats.put({ id: 'vp_3', kind: 'vcenter', label: 'VC-BAD', base_url: 'https://vc3.corp.local', enc: sealer.seal('vp_3', JSON.stringify({ username: 'x', password: 'wrong' })) });
  await C.tick(); const n2 = calls.length;
  clock += 60000; await C.tick(); assert.equal(calls.length, n2, 'failed one minute ago: waits');
  clock += 10 * 60000; await C.tick(); assert.ok(calls.length > n2, 'retried after 10 minutes');
});
