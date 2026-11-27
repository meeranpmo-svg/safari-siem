// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Hyper-V Optimization (engine/hyperv-optimize.js) over SYNTHETIC host reports, daily snapshots and 48 h of readings: memory given back
// from a VM that never uses it (p95 + 25 %, rounded to 512 MB), memory added to one running short, vCPUs halved on an idle VM, a VM still
// learning is not judged, an idle VM off 30+ days with its disk, old checkpoints, a VHD near its maximum, a volume filling on its trend
// and thin-provisioning overcommit, a busy NIC, the move that evens two hosts (and fits), an anomaly against the host's own 48 h, the
// score; the route answers a viewer.
const test = require('node:test');
const assert = require('node:assert/strict');
const O = require('../engine/hyperv-optimize');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');

const DAY = 864e5, NOW = Date.parse('2026-11-27T09:00:00Z'), GB = 1024;
function world() {
  const vm = (name, o) => Object.assign({ name, state: 'running', vcpus: 2, mem_assigned_mb: 8 * GB, mem_demand_mb: 4 * GB, cpu_pct: 20, vhds: [], checkpoints: [] }, o);
  const A = { at: new Date(NOW).toISOString(), host: { name: 'HV-SYN-01', cores: 32, cpu_pct: 60, mem_total_mb: 256 * GB, mem_free_mb: 40 * GB,
    volumes: [{ name: 'C:\\ClusterStorage\\Volume1', size_gb: 1000, free_gb: 150, csv: true }], nics: [{ name: 'NIC1', link_mbps: 1000, rx_bps: 800e6, tx_bps: 700e6 }], disk: { latency_ms: 4 } },
    vms: [vm('BIG-SYN', { mem_assigned_mb: 64 * GB, vcpus: 8, cpu_pct: 5, vhds: [{ path: 'C:\\ClusterStorage\\Volume1\\BIG\\d.vhdx', size_gb: 100, max_gb: 1300 }] }),
      vm('TIGHT-SYN', { mem_assigned_mb: 8 * GB }), vm('NEW-SYN', { mem_assigned_mb: 32 * GB }),
      vm('OLD-SYN', { state: 'off', off_since: new Date(NOW - 45 * DAY).toISOString(), vhds: [{ path: 'C:\\ClusterStorage\\Volume1\\OLD\\d.vhdx', size_gb: 120, max_gb: 200 }], checkpoints: [{ name: 'before patch', created: new Date(NOW - 40 * DAY).toISOString() }] }),
      vm('FULL-SYN', { vhds: [{ path: 'C:\\ClusterStorage\\Volume1\\FULL\\d.vhdx', size_gb: 95, max_gb: 100 }] }), vm('MOVE-SYN', { mem_assigned_mb: 48 * GB })] };
  const B = { at: new Date(NOW).toISOString(), host: { name: 'HV-SYN-02', cores: 32, cpu_pct: 10, mem_total_mb: 256 * GB, mem_free_mb: 200 * GB, volumes: [], nics: [] }, vms: [] };
  const daily = [];
  for (let d = 0; d < 10; d++) daily.push({ id: 'hv-syn-01|' + new Date(NOW - (10 - d) * DAY).toISOString().slice(0, 10), volumes: { 'C:\\ClusterStorage\\Volume1': 800 + d * 5 },
    vms: { 'BIG-SYN': { mem_demand_mb: 10 * GB, cpu_pct: 6 }, 'TIGHT-SYN': { mem_demand_mb: 7.8 * GB, cpu_pct: 30 }, 'MOVE-SYN': { mem_demand_mb: 40 * GB, cpu_pct: 30 }, 'FULL-SYN': { mem_demand_mb: 4 * GB, cpu_pct: 20 }, ...(d >= 7 ? { 'NEW-SYN': { mem_demand_mb: 2 * GB, cpu_pct: 3 } } : {}) } });
  const samples = Array.from({ length: 40 }, (_, i) => ({ id: 'hv-syn-01|' + i, host: 'hv-syn-01', t: NOW - (40 - i) * 900e3, cpu: i === 39 ? 97 : 30 + (i % 4), mem_pct: 84, disk_ms: 4, nics: { NIC1: { rx_bps: 400e6, tx_bps: 300e6 } } }));
  return { latest: [A, B], daily, samples, now: NOW };
}

test('rightsizing, idle, storage, network, balance, anomalies, score', () => {
  const r = O.analyse(world()), K = (kind, target) => r.recommendations.find((x) => x.kind === kind && (!target || x.target === target));
  const big = K('memory-down', 'BIG-SYN'); assert.ok(big, 'memory given back'); assert.match(big.title, /give back 51\.5 GB of memory \(64 → 12\.5 GB\)/);
  assert.ok(K('memory-up', 'TIGHT-SYN'), 'memory added'); assert.ok(K('vcpu-down', 'BIG-SYN') && /8 → 4 vCPUs/.test(K('vcpu-down', 'BIG-SYN').title), 'vCPUs halved');
  assert.ok(!r.recommendations.some((x) => x.target === 'NEW-SYN'), 'a VM with 3 days of history is still learning');
  assert.ok(K('idle', 'OLD-SYN') && K('idle', 'OLD-SYN').gain.disk_gb === 120 && K('checkpoint', 'OLD-SYN'));
  assert.ok(K('vhd-full', 'FULL-SYN'));
  const v = r.volumes[0]; assert.equal(v.used_pct, 85); assert.equal(v.days_to_95, 21, 'grows 5 GB a day from 845 GB: 95 % (950 GB) in 21 days'); assert.ok(v.overcommit > 1.5 && K('overcommit'));
  assert.ok(K('nic-busy') && /peaked at 75%/.test(K('nic-busy').title), 'peak receive + transmit against the link');
  assert.ok(r.move && r.move.from === 'HV-SYN-01' && r.move.to === 'HV-SYN-02' && r.move.to_after <= 85 && K('balance'), JSON.stringify(r.move));
  assert.equal(r.anomalies[0].metric, 'CPU %'); assert.ok(r.anomalies[0].z >= 3.5);
  assert.ok(r.score < 100 && r.score >= 0); assert.ok(r.insights.some((s) => /GB of memory can be given back/.test(s)));
  assert.equal(r.kpis.learning, 1); assert.equal(r.hosts[0].trend.length, 40);
  assert.equal(O.analyse({ latest: [] }).score, null);
});

test('route: a viewer reads it', async (t) => {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true, python: process.env.PYTHON || 'python3' });
  const r = await e.req('GET', '/hyperv/optimize', { user: 'vera.syn', role: 'viewer' }); assert.equal(r.status, 200, r.text); assert.equal(r.json.kpis.hosts, 0); assert.match(r.json.insights[0], /No Hyper-V host/);
});

test('balance stays within a host group (one site): no move between HQ and Jeddah hosts', () => {
  const H = (name, used) => ({ at: new Date(NOW).toISOString(), host: { name, cores: 16, mem_total_mb: 256 * GB, mem_free_mb: (256 - used) * GB, volumes: [], nics: [] }, vms: [{ name: name + '-VM', state: 'running', vcpus: 2, mem_assigned_mb: 48 * GB, vhds: [], checkpoints: [] }] });
  assert.equal(O.analyse({ latest: [H('HQHV01', 230), H('JEDHV01', 40)], now: NOW }).move, null, 'different sites');
  assert.ok(O.analyse({ latest: [H('HQHV01', 230), H('HQHV02', 40)], now: NOW }).move, 'same site');
});
