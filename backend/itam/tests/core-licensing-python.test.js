// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Migration step 6e (docs/PYTHON-MIGRATION.md): pyengine/core_licensing_rules.py must answer exactly like view() in
// engine/core-licensing.js (Licence audit -> Core-based licences) - Oracle EE / SE2 / ODI with every VMware scope (host,
// cluster, vCenter), Windows Server Standard / Datacenter (suggested and chosen), VMware minimums, core counts from facts
// (entered / vCenter / Prism) and from the CPU text (every form, incl. "0 sockets" which divides by zero in Node.js),
// hosts with no count and the hint for each state of the capacity collection, VMs without a host, entitlements (expired,
// expiring, invalid date) - and through the same field projection the engine sends (inputs()).
const test = require('node:test');
const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const { startApp } = require('./helpers');
const { createCoreLicensing } = require('../engine/core-licensing');
const { createPyEngine } = require('../engine/pyengine');

const PY = process.env.PYTHON || 'python3';
const hasPy = spawnSync(PY, ['--version']).status === 0;
const NOW = Date.parse('2026-10-19T09:00:00Z');
const ADM = { user: 'syed', role: 'admin', ip: '' };
const plain = (v) => JSON.parse(JSON.stringify(v));

async function world(t) {
  const e = await startApp({ noAi: true });
  t.after(() => e.close());
  const mk = (o) => e.app.assets.create(Object.assign({ status: 'in_use' }, o), ADM).asset.id;
  const ids = {
    esx1: mk({ name: 'esx01', type: 'server', os: 'VMware ESXi 7.0.3', cpu: '2 x Intel Xeon Gold 6338 32-Core', tags: ['esxi-host'] }),
    esx2: mk({ name: 'esx02', type: 'server', os: 'VMware ESXi 7.0.3', cpu: 'Intel Xeon' }),
    esx3: mk({ name: 'esx03', type: 'server', os: 'ESXi 8.0', cpu: 'AMD EPYC 7543 2 sockets, 16 cores each' }),
    esx4: mk({ name: 'esx04', type: 'server', os: 'VMware ESX 6.5', cpu: '0 sockets 16 cores' }),
    ahv: mk({ name: 'ntnx-a', type: 'server', os: 'Nutanix AHV', cpu: '' }),
    ora: mk({ name: 'oradb01', type: 'server', os: 'Oracle Linux 8', cpu: '2 CPU 24 cores', software: [{ name: 'Oracle Database 19c Enterprise Edition', publisher: 'Oracle' }, 'Oracle Database 12c'] }),
    se2: mk({ name: 'orase2', type: 'server', os: 'Oracle Linux 7', cpu: '4 sockets 40 cores', software: [{ name: 'Oracle Database 19c Standard Edition 2', publisher: 'Oracle' }] }),
    sparc: mk({ name: 'sun-m5', type: 'server', os: 'Oracle Solaris 11.4', cpu: 'SPARC M7 32 cores', software: [{ name: 'Oracle Data Integrator 12c', publisher: 'Oracle' }] }),
    power: mk({ name: 'aix01', type: 'server', os: 'AIX 7.2', cpu: 'IBM POWER9 2x12 cores' }),
    win: mk({ name: 'DC-HQA', type: 'server', os: 'Microsoft Windows Server 2019 Datacenter', cpu: '1 x Xeon 4-core' }),
    win2: mk({ name: 'fs02', type: 'server', os: 'Windows Server 2022 Standard', cpu: '' }),
    win3: mk({ name: 'app03', type: 'server', os: 'Windows Server 2016', cpu: 'Xeon Silver' }),
    lnx: mk({ name: 'lnx01', type: 'server', os: 'Ubuntu 22.04' }),
    ret: mk({ name: 'old-srv', type: 'server', status: 'retired', os: 'Windows Server 2012', software: [{ name: 'Oracle Database 11g', publisher: 'Oracle' }] }),
    pc: mk({ name: 'PC-1', type: 'workstation', os: 'Windows 11' }),
  };
  const vm = (o) => mk(Object.assign({ type: 'vm' }, o));
  Object.assign(ids, {
    v1: vm({ name: 'ora-vm1', os: 'Oracle Linux 8', software: [{ name: 'Oracle Database 19c', publisher: 'Oracle Corporation' }] }),
    v2: vm({ name: 'sql-vm', os: 'Windows Server 2019 Standard' }),
    v3: vm({ name: 'win-vm3', os: 'Windows Server 2022 Datacenter' }),
    v4: vm({ name: 'odi-vm', os: 'Oracle Linux 8', software: [{ name: 'ODI Agent 12c' }] }),
    v5: vm({ name: 'orphan-vm', os: 'Windows Server 2019', software: [{ name: 'Oracle Database 19c Standard Edition' }] }),
    v6: vm({ name: 'se-vm', os: 'Oracle Linux 8', software: [{ name: 'Oracle 19c SE2' }] }),
    v7: vm({ name: 'ahv-vm', os: 'Windows Server 2019' }),
    v8: vm({ name: 'tagged-vm', type: 'server', tags: ['VM'], os: 'Windows Server 2016', software: [{ name: 'Oracle Database 19c' }] }),
  });
  for (let i = 0; i < 6; i++) ids['w' + i] = vm({ name: 'win-' + i, os: 'Windows Server 2019' });
  const facts = e.app.store.collection('core_lic_facts');
  facts.put({ id: ids.esx1, cluster: 'PROD', source: 'vcenter', sockets: 2, cores_per_socket: 32 });
  facts.put({ id: ids.esx2, cluster: 'PROD' });
  facts.put({ id: ids.esx3, cluster: 'DR', sockets: '2', cores_per_socket: 16, source: 'entered', windows: 'std' });
  facts.put({ id: ids.esx4, sockets: 2 });
  facts.put({ id: ids.ahv, source: 'nutanix', sockets: 2, cores_per_socket: 0 });
  facts.put({ id: ids.sparc, cpu_vendor: 'sparc', core_factor: 0.5, core_factor_src: 'table', core_factor_row: 'SPARC T4 / T5 / T7 / T8 / M5-M8 / S7' });
  facts.put({ id: ids.power, core_factor: '1', core_factor_src: 'entered', oracle_detected: 'ee' });
  facts.put({ id: ids.win3, core_factor: 7 });   // out of range: ignored, the vendor rule applies
  facts.put({ id: ids.win, windows: 'dc', notes: 'by hand' });
  facts.put({ id: ids.lnx, oracle: 'ee', odi: 'yes', sockets: 1, cores_per_socket: 6 });
  facts.put({ id: ids.v4, odi: 'none' });
  facts.put({ id: ids.v6, oracle: 'none' });
  const rels = e.app.store.collection('relationships');
  const rel = (from, to, i) => rels.put({ id: 'r' + i, type: 'runs_on', from, to });
  rel(ids.v1, ids.ret, 1); rel(ids.v1, ids.esx1, 2); rel(ids.v2, ids.esx1, 3); rel(ids.v3, ids.esx3, 4); rel(ids.v4, ids.esx2, 5); rel(ids.v6, ids.esx3, 6);
  rel(ids.v7, ids.ahv, 7); rel(ids.v8, ids.v2, 8); rels.put({ id: 'r9', type: 'connects', from: ids.v5, to: ids.esx1 });
  for (let i = 0; i < 6; i++) rel(ids['w' + i], ids.esx1, 10 + i);
  const ents = e.app.store.collection('core_lic_entitlements');
  ents.put({ id: 'e1', product: 'oracle_ee', quantity: 40, expiry: '2027-01-15', contract: 'CSI-1' });
  ents.put({ id: 'e2', product: 'oracle_ee', quantity: '8', expiry: '2026-01-01' });
  ents.put({ id: 'e3', product: 'windows_dc', quantity: 400, expiry: null });
  ents.put({ id: 'e4', product: 'vmware', quantity: 'many', expiry: 'not a date' });
  ents.put({ id: 'e5', product: 'windows_std', quantity: 16, expiry: '2026-11-30' });
  ents.put({ id: 'e6', product: 'oracle_se2', quantity: 2 });
  return { e, ids };
}

test('Python core-based licence audit answers exactly like the Node.js one', { skip: !hasPy && 'python3 not available' }, async (t) => {
  const py = createPyEngine({ python: PY });
  const { e } = await world(t);
  const C = createCoreLicensing(e.app, { now: () => NOW });
  const same = async (what) => {
    const n = plain(C.view());
    assert.deepEqual(await py.call('rules.core_licensing', plain(C.inputs())), n, what);
    return n;
  };
  const caps = [null, { platforms: [] }, { platforms: [{ label: 'VC', error: 'login failed' }, { label: 'Prism' }] }, { platforms: [{ label: 'VC' }] }];
  for (const cap of caps) {
    e.app.addons = cap ? { virtCapacity: { report: () => cap } } : {};
    const n = await same('capacity ' + JSON.stringify(cap));
    assert.ok(n.hosts.some((h) => h.cores_hint), 'a host with no count carries the hint');
  }
  e.app.addons = { virtCapacity: { report: () => { throw new Error('boom'); } } };
  await same('capacity report throws');
  const n = plain(C.view());
  assert.ok(n.deployments.some((d) => d.problem), 'a VM with no host');
  assert.ok(n.products.oracle_se2.hosts.some((r) => r.problem), 'SE2 on more than 2 sockets');
  assert.ok(n.summary.some((s) => s.status === 'shortfall') && n.summary.some((s) => s.expiring.length), JSON.stringify(n.summary.map((s) => s.status)));
  assert.ok(n.products.windows_dc.hosts.length && n.products.windows_std.hosts.length && n.products.vmware.hosts.length);
  for (const b of [{ oracle_scope: 'host' }, { oracle_scope: 'vcenter', core_factor: 0.25, win_dc_ratio: 1, vmware_min_per_cpu: 0, vmware_min_order: 10000 },
    { oracle_scope: 'cluster', win_dc_ratio: 50, vmware_min_per_cpu: 128, vmware_min_order: 0 }]) {
    C.putSettings(b, ADM);
    await same('settings ' + JSON.stringify(b));
  }
  // the route answers through Python
  const r = await C.viewAuto();
  assert.deepEqual(plain(r), plain(C.view()), 'viewAuto');
  e.app.store.collection('assets').all().forEach((a) => e.app.store.collection('assets').patch(a.id, (x) => { x.status = 'retired'; return x; }));
  await same('nothing live');
});
