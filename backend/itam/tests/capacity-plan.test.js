// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Capacity Planning (engine/capacity-plan.js) over SYNTHETIC figures: Hyper-V hosts grouped by name, N+1 (fits / short by how much),
// room for more VMs of the group's average size, memory to reclaim from oversized VMs, the soonest volume, one host = no N+1;
// Azure: Advisor right-size with target size and saving, stopped-but-billed, deallocated; nothing connected says what to connect;
// the route: viewer reads through the real app (a Hyper-V report imported), Azure not connected said plainly.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');
const C = require('../engine/capacity-plan');

const GB = 1024, vm = (name, gb, dem, st = 'running') => ({ name, state: st, vcpus: 4, mem_assigned_mb: gb * GB, mem_demand_mb: dem * GB });
const host = (name, total, free, vms, cap) => ({ name, cores: 32, mem_total_mb: total * GB, mem_free_mb: free * GB, vms, capacity: cap || { memory: null, volumes: [] }, volumes: [] });

test('Hyper-V: N+1, room, reclaim, soonest volume; one host', () => {
  const ok = C.hyperv({ hosts: [host('HV-SYN-01', 256, 156, [vm('A', 32, 30), vm('B', 32, 8), vm('C', 36, 30)]), host('HV-SYN-02', 256, 156, [vm('D', 64, 60), vm('E', 36, 30)], { memory: 40, volumes: [{ name: 'C:\\ClusterStorage\\V1', days: 25 }] }), host('HV-SYN-03', 256, 206, [vm('F', 50, 45), vm('G', 8, 2, 'off')])] });
  const g = ok.groups[0]; assert.equal(g.group, 'hv-syn'); assert.equal(g.hosts.length, 3);
  assert.equal(g.mem_used_gb, 250); assert.equal(g.n1_ok, true, '250 GB in use fits in 512 GB x 0.9'); assert.match(g.why, /its VMs fit on the others/);
  assert.equal(g.avg_vm_gb, 41.7); assert.equal(g.room_vms, Math.floor((512 * 0.9 - 250) / 41.66666)); assert.equal(g.mem_days, 40); assert.equal(g.volumes_soon[0].days, 25);
  assert.equal(g.oversized, 1); assert.equal(g.reclaim_gb, r(32 - 8 * 1.2)); assert.deepEqual(g.off, ['G']);
  const short = C.hyperv({ hosts: [host('HQ-SYN-01', 128, 8, [vm('X', 120, 110)]), host('HQ-SYN-02', 128, 8, [vm('Y', 120, 110)])] }).groups[0];
  assert.equal(short.n1_ok, false); assert.match(short.why, /cannot hold its VMs - 124\.8 GB short/); assert.equal(short.room_vms, 0);
  const one = C.hyperv({ hosts: [host('SITE-SYN-01', 64, 32, [vm('Z', 16, 10)])] }).groups[0]; assert.equal(one.n1_ok, null); assert.match(one.why, /one host/);
  assert.equal(C.hyperv({ hosts: [] }).available, false);
});
function r(x) { return Math.round(x * 10) / 10; }

test('Azure: Advisor right-size, stopped but billed, deallocated; not connected', () => {
  const a = C.azure({ vms: [{ name: 'az-app-syn', size: 'Standard_D8s_v5', power: 'running', advisor: [{ category: 'Cost', target_sku: 'Standard_D4s_v5', savings: 120, currency: 'USD', problem: 'Right-size or shutdown underutilized virtual machines' }] },
    { name: 'az-old-syn', size: 'Standard_B2s', power: 'stopped', advisor: [] }, { name: 'az-dr-syn', size: 'Standard_D4s_v5', power: 'deallocated', advisor: [] }], totals: { advisor_savings: 120, currency: 'USD' }, orphan_disks: [{}] });
  assert.equal(a.rightsize[0].target, 'Standard_D4s_v5'); assert.equal(a.savings, 120); assert.deepEqual(a.stopped_billed.map((x) => x.vm), ['az-old-syn']); assert.equal(a.deallocated.length, 1); assert.equal(a.orphan_disks, 1);
  assert.equal(C.azure(null).available, false);
});

test('route: viewer reads through the real app', async (t) => {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true, python: process.env.PYTHON || 'python3' });
  const ADM = { user: 'admin.syn', role: 'admin' }, VIEW = { user: 'vera.syn', role: 'viewer' };
  const sr = await e.req('POST', '/discovery/scopes', { body: { name: 'HQ', site: 'Riyadh HQ', targets: ['10.20.8.0/24'], methods: { hyperv: { enabled: true } } }, ...ADM });
  await e.req('POST', '/discovery/hyperv/import', { body: { scope_id: sr.json.scope.id, report: { collected_at: new Date().toISOString(), host: { name: 'HV-SYN-01', logical_processors: 16, mem_total_mb: 131072, mem_free_mb: 65536 }, vms: [{ name: 'APP-SYN', state: 'Running', vcpus: 4, mem_assigned_mb: 16384, mem_demand_mb: 4000 }] } }, ...ADM });
  const r2 = await e.req('GET', '/capacity-plan', VIEW); assert.equal(r2.status, 200, r2.text);
  assert.equal(r2.json.hyperv.available, true); assert.equal(r2.json.hyperv.groups[0].mem_used_gb, 64);
  assert.equal(r2.json.azure.available, false); assert.match(r2.json.azure.why, /Azure/);
});
