// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Core-based licensing: Oracle EE / SE2 with VMware scope, Windows Server Standard vs Datacenter, VMware per-core minimums.
const test = require('node:test');
const assert = require('node:assert/strict');
const { createCoreLicensing, parseCores, WIN_SERVER } = require('../engine/core-licensing');

function fakeStore(init) {
  const cols = {};
  return { collection: (n) => cols[n] || (cols[n] = (() => { const m = new Map((init[n] || []).map((o) => [o.id, o])); return {
    all: (f) => [...m.values()].filter((o) => !f || f(o)), get: (id) => m.get(id), put: (o) => { m.set(o.id, JSON.parse(JSON.stringify(o))); return o; }, remove: (id) => m.delete(id),
    patch: (id, fn) => { const c = JSON.parse(JSON.stringify(m.get(id))); const r = fn(c); m.set(id, r && typeof r === 'object' ? r : c); return m.get(id); } }; })()) };
}
const adm = { user: 'siva', role: 'admin' };
const esx = (id, name, cpu) => ({ id, name, type: 'server', os: 'VMware ESXi 8.0', cpu, tags: ['vcenter', 'esxi-host'], status: 'in_use' });
const vm = (id, name, os, extra) => Object.assign({ id, name, type: 'vm', os, tags: ['vcenter', 'vm'], status: 'in_use' }, extra || {});
const runs = (from, to) => ({ id: `r_${from}`, from, to, type: 'runs_on', status: 'confirmed' });

function estate() {
  return fakeStore({
    assets: [
      esx('h1', 'esx01', 'Intel Xeon Gold 6338'), esx('h2', 'esx02', 'Intel Xeon Gold 6338'), esx('h3', 'esx03', '2 x AMD EPYC 7543 32-Core'),
      { id: 'p1', name: 'ORA-PHY', type: 'server', os: 'Oracle Linux 8', cpu: '1 x Intel Xeon 8-Core', status: 'in_use', software: [{ name: 'Oracle Database 19c Standard Edition 2' }] },
      { id: 'p2', name: 'FS01', type: 'server', os: 'Microsoft Windows Server 2019 Standard', cpu: 'Intel Xeon', status: 'in_use' },
      vm('v1', 'ORADB01', 'Oracle Linux 8', { software: [{ name: 'Oracle Database 19c Enterprise Edition', publisher: 'Oracle' }] }),
      ...Array.from({ length: 14 }, (_, i) => vm('w' + i, 'WIN' + i, i % 2 ? 'WINDOWS_SERVER_2019' : 'Microsoft Windows Server 2022 (64-bit)')),
      vm('v2', 'LNX01', 'Ubuntu Linux (64-bit)'), vm('v3', 'ORPHAN', 'Oracle Linux 8'),
      { id: 'old', name: 'OLD', type: 'server', os: 'VMware ESXi 6.5', tags: ['esxi-host'], status: 'retired' },
    ],
    relationships: [runs('v1', 'h1'), runs('v2', 'h2'), ...Array.from({ length: 14 }, (_, i) => runs('w' + i, i < 12 ? 'h1' : 'h2'))],
  });
}

test('parseCores and Windows Server detection', () => {
  assert.deepEqual(parseCores('2 x AMD EPYC 7543 32-Core'), { sockets: 2, cores_per_socket: 32, from: 'cpu text' });
  assert.deepEqual(parseCores('2 sockets, 16 cores each'), { sockets: 2, cores_per_socket: 16, from: 'cpu text' });
  assert.equal(parseCores('2 CPU 24 cores').cores_per_socket, 12);
  assert.equal(parseCores('Intel Xeon Gold 6338'), null);
  for (const o of ['WINDOWS_SERVER_2019', 'windows2019srv_64Guest', 'WINDOWS_9_SERVER_64', 'Microsoft Windows Server 2022 (64-bit)']) assert.ok(WIN_SERVER.test(o), o);
  for (const o of ['Microsoft Windows 11 (64-bit)', 'WINDOWS_11_64', 'Ubuntu Linux']) assert.ok(!WIN_SERVER.test(o), o);
});

test('cores unknown are listed, never guessed; facts by name fill them in', () => {
  const st = estate(), C = createCoreLicensing({ store: st });
  let v = C.view();
  assert.equal(v.counts.physical, 5); assert.equal(v.counts.esxi, 3); assert.equal(v.counts.vms_without_host, 1);
  assert.ok(v.unknown.some((u) => u.host === 'esx01' && u.product === 'vmware'));
  assert.equal(v.deployments.find((d) => d.id === 'v3'), undefined);   // no Oracle on ORPHAN
  const r = C.putFacts({ items: [{ name: 'ESX01', sockets: 2, cores_per_socket: 28, cluster: 'Prod' }, { name: 'esx02.corp.local', sockets: 2, cores_per_socket: 12, cluster: 'Prod' }, { name: 'esx03', cluster: 'DR' }, { name: 'nope', sockets: 1 }, { name: 'FS01', sockets: 1, cores_per_socket: 4 }] }, adm);
  assert.equal(r.saved, 4); assert.deepEqual(r.not_found, ['nope']);
  assert.throws(() => C.putFacts({ items: [{ name: 'esx01', oracle: 'xe' }] }, adm), /oracle must be/);
  v = r;
  // Oracle EE on a VM in cluster Prod: every Prod host (h1 56 cores, h2 24 cores) x 0.5
  assert.deepEqual(v.products.oracle_ee.hosts.map((h) => [h.host, h.licences]), [['esx01', 28], ['esx02', 12]]);
  assert.equal(v.products.oracle_ee.required, 40); assert.equal(v.products.oracle_ee.nup_minimum, 1000);
  // SE2 on a 1-socket physical server
  assert.equal(v.products.oracle_se2.required, 1);
  // Windows: esx01 has 12 Windows VMs, 56 licensed cores; ceil(12/2)=6 > 5.8 → Datacenter 56; esx02 2 VMs → Standard 24 (2x12);
  // FS01 physical 1x4 cores → minimum 16 Standard
  const w = Object.fromEntries([...v.products.windows_std.hosts, ...v.products.windows_dc.hosts].map((h) => [h.host, [h.edition, h.edition === 'dc' ? h.datacenter_cores : h.standard_cores]]));
  assert.deepEqual(w, { esx01: ['dc', 56], esx02: ['std', 24], FS01: ['std', 16] });
  assert.equal(v.products.windows_std.required, 40); assert.equal(v.products.windows_dc.required, 56);
  // VMware: esx01 2x28=56, esx02 2x max(16,12)=32, esx03 parsed 2x32=64 → 152
  assert.equal(v.products.vmware.required, 152); assert.equal(v.products.vmware.minimum_order_applied, false);
});

test('oracle scope vcenter / host, entitlements, expiry, settings validation', () => {
  const st = estate(), C = createCoreLicensing({ store: st, now: () => Date.parse('2026-10-12T00:00:00Z') });
  C.putFacts({ items: [{ id: 'h1', sockets: 2, cores_per_socket: 28, cluster: 'Prod' }, { id: 'h2', sockets: 2, cores_per_socket: 12, cluster: 'Prod' }, { id: 'h3', cluster: 'DR' }] }, adm);
  assert.equal(C.putSettings({ oracle_scope: 'vcenter' }, adm).products.oracle_ee.required, 28 + 12 + 32);
  assert.equal(C.putSettings({ oracle_scope: 'host' }, adm).products.oracle_ee.required, 28);
  assert.throws(() => C.putSettings({ oracle_scope: 'galaxy' }, adm), /oracle_scope/);
  assert.throws(() => C.putSettings({ core_factor: 3 }, adm), /core_factor/);
  C.putSettings({ oracle_scope: 'cluster' }, adm);
  C.putEnt({ product: 'oracle_ee', quantity: 30, contract: 'CSI 1234', expiry: '2026-12-01' }, adm);
  let v = C.putEnt({ product: 'oracle_ee', quantity: 8, contract: 'old', expiry: '2026-01-01' }, adm);   // expired: not counted
  const ee = v.summary.find((x) => x.product === 'oracle_ee');
  assert.deepEqual([ee.required, ee.owned, ee.delta, ee.status], [40, 30, -10, 'shortfall']); assert.equal(ee.expiring.length, 1);
  assert.throws(() => C.putEnt({ product: 'sql', quantity: 1 }, adm), /product must be/);
  v = C.putEnt({ product: 'vmware', quantity: 200 }, adm);
  assert.equal(v.summary.find((x) => x.product === 'vmware').status, 'compliant');
  const id = v.entitlements.find((e) => e.product === 'vmware').id;
  assert.equal(C.delEnt(id, adm).summary.find((x) => x.product === 'vmware').owned, 0);
});

test('vmware 72-core order minimum and per-CPU minimum', () => {
  const st = fakeStore({ assets: [esx('h1', 'esx01', '1 x Intel Xeon 8-Core')] }), C = createCoreLicensing({ store: st });
  const v = C.view();
  assert.equal(v.products.vmware.physical_licensed, 16); assert.equal(v.products.vmware.required, 72); assert.equal(v.products.vmware.minimum_order_applied, true);
});

test('status: a product needed on hosts with unknown cores is incomplete, not "not in use"', () => {
  const st = fakeStore({ assets: [{ id: 'p', name: 'FS01', type: 'server', os: 'Windows Server 2019', cpu: 'Intel Xeon', status: 'in_use' }] });
  const s = createCoreLicensing({ store: st }).view().summary.find((x) => x.product === 'windows_std');
  assert.deepEqual([s.required, s.status, s.cores_unknown], [0, 'incomplete', 1]);
});

test('Oracle Data Integrator: processor licences like DB EE, from software or marked by hand, alongside the database', () => {
  const st = fakeStore({ assets: [
    { id: 'p1', name: 'SOL-ODI01', type: 'server', os: 'Oracle Solaris 11.4 (SPARC)', cpu: '2 x SPARC M8 32-Core', status: 'in_use', software: [{ name: 'Oracle Data Integrator 12c Standalone Agent' }, { name: 'Oracle Database 19c Enterprise Edition' }] },
    { id: 'p2', name: 'ETL02', type: 'server', os: 'Oracle Linux 8', cpu: '1 x Intel Xeon 16-Core', status: 'in_use' },
  ] });
  const C = createCoreLicensing({ store: st }), adm = { user: 'siva', role: 'admin' };
  let v = C.view();
  assert.deepEqual(v.deployments.map((d) => [d.name, d.edition]), [['SOL-ODI01', 'ee'], ['SOL-ODI01', 'odi']]);
  assert.equal(v.products.oracle_odi.required, 32);   // 64 SPARC cores x 0.5
  assert.equal(v.products.oracle_ee.required, 32);
  v = C.putFacts({ items: [{ name: 'ETL02', odi: 'yes' }] }, adm);
  assert.equal(v.products.oracle_odi.required, 32 + 8); assert.equal(v.products.oracle_odi.nup_minimum, 40 * 25);
  assert.throws(() => C.putFacts({ items: [{ name: 'ETL02', odi: 'maybe' }] }, adm), /odi must be/);
  v = C.putFacts({ items: [{ name: 'SOL-ODI01', odi: 'none' }] }, adm);
  assert.equal(v.products.oracle_odi.required, 8);
  assert.ok(v.summary.some((x) => x.product === 'oracle_odi' && x.status === 'shortfall'));
});
