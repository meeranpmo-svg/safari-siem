// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// vSphere Studio (engine/vsphere-studio.js, pyengine/vsphere_studio_rules.py) through the real routes on SYNTHETIC vCenter data
// (the capacity collection and the AI Virtualization Administrator stubbed): Nutanix left out, host / cluster / VM health with
// every point named, hosts out of balance with DRS off, ESXi version drift, workload profiles from the VMs' own p95, unusual CPU,
// old snapshots / consolidation / Tools, right-sizing, datastore risk, open findings and plans, nothing invented when nothing
// is connected; VM history validation, roles, the AI analyst refused for a viewer and audited for an operator.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');

const VIEW = { user: 'vera.syn', role: 'viewer' }, OP = { user: 'nora.syn', role: 'operator' };
const NOW = Date.parse('2026-10-31T09:00:00Z'), DAY = 86400000;

function fixture() {
  const host = (name, cluster, cpu, mem, version, extra) => Object.assign({ platform: 'vCenter HQ (synthetic)', cluster, name, version, state: 'connected', maintenance: false, status: 'green', cpu_used_pct: cpu, mem_used_pct: mem, vcpu_ratio: 2, vms_on: 5, cores: 32, mem_gb: 512 }, extra || {});
  const vms = [];
  for (let i = 1; i <= 16; i++) vms.push({ id: 'vm-' + i, pid: 'vc1', platform: 'vCenter HQ (synthetic)', kind: 'vcenter', cluster: 'PROD', name: 'APP-SYN-' + i, host: 'esx01', power: 'on', vcpus: 4, mem_gb: 16, cpu_pct: 10, mem_used_pct: 30, guest_os: 'Windows Server 2022', snapshots: { count: 0, oldest: null }, consolidate: false, tools: 'running' });
  vms[0].snapshots = { count: 5, oldest: new Date(NOW - 10 * DAY).toISOString() }; vms[0].consolidate = true; vms[0].tools = 'not-running';
  vms[1].cpu_pct = 95;   // unusual against its p95 of 20
  vms.push({ id: 'vm-off', pid: 'vc1', platform: 'vCenter HQ (synthetic)', kind: 'vcenter', cluster: 'PROD', name: 'OLD-SYN', host: 'esx01', power: 'off', vcpus: 8, mem_gb: 64 });
  vms.push({ id: 'n1', pid: 'ntx1', platform: 'Prism (synthetic)', kind: 'nutanix', cluster: 'NTX', name: 'NTX-VM', power: 'on' });
  const rows = vms.filter((v) => v.kind === 'vcenter' && v.power === 'on').map((v, i) => ({ platform: v.platform, pid: 'vc1', id: v.id, samples: 300, cpu_p95: i < 8 ? 3 : i < 12 ? 20 : 75, mem_p95: i < 8 ? 15 : i < 12 ? 45 : 80 }));
  rows[2].vcpus_to = 2; rows[2].save_vcpu = 2; rows[15].cpu_short = true;
  return {
    report: () => ({ settings: { cpu_max_pct: 80, mem_max_pct: 90, storage_max_pct: 80, vcpu_ratio: 4 }, last_run: { at: new Date(NOW).toISOString() },
      platforms: [{ id: 'vc1', label: 'vCenter HQ (synthetic)', kind: 'vcenter' }, { id: 'ntx1', label: 'Prism (synthetic)', kind: 'nutanix' }],
      clusters: [{ platform: 'vCenter HQ (synthetic)', kind: 'vcenter', name: 'PROD', hosts: 3, hosts_up: 3, vms: 17, vms_on: 16, cores: 96, vcpus: 64, mem_gb: 1536, vm_mem_gb: 256, cpu_used_pct: 50, mem_used_pct: 60, vcpu_ratio: 0.67, ha: false, drs: false, n_plus_1: true, room: { cpu: 10, mem: 0, limit: 'memory' }, status: 'yellow' },
        { platform: 'Prism (synthetic)', kind: 'nutanix', name: 'NTX', hosts: 3, vms: 1 }],
      hosts: [host('esx01', 'PROD', 92, 85, 'VMware ESXi 8.0.2'), host('esx02', 'PROD', 30, 40, 'VMware ESXi 8.0.2'), host('esx03', 'PROD', 20, 35, 'VMware ESXi 7.0.3', { state: 'notResponding' }), Object.assign(host('ntx-h1', 'NTX', 99, 99, 'AHV'), { platform: 'Prism (synthetic)' })],
      datastores: [{ platform: 'vCenter HQ (synthetic)', name: 'DS-SYN-01', capacity_gb: 1000, free_gb: 30, used_pct: 97, provisioned_pct: 120, accessible: true }, { platform: 'vCenter HQ (synthetic)', name: 'DS-SYN-02', capacity_gb: 1000, free_gb: 600, used_pct: 40, provisioned_pct: 200, accessible: true }],
      vms, storage_trend: { 'vCenter HQ (synthetic)': { days_of_history: 20, per_month: 3 } } }),
    overprov: () => ({ vms: rows.filter((r) => r.vcpus_to), under: rows.filter((r) => r.cpu_short), short: [], platforms: [] }),
    vmHistory: (q) => ({ days: 7, pid: q.pid, vm: q.vm, points: [{ t: NOW - 3600000, cpu: 10, mem: 30 }, { t: NOW, cpu: 12, mem: 31 }] }),
    rowsAll: rows,
  };
}

async function setup(t, { connected = true } = {}) {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  const F = fixture();
  e.app.addons = e.app.addons || {};
  registerDuty(e.app.srv, e.app, { noTimer: true, now: () => NOW, python: process.env.PYTHON || 'python3' });
  // after duty: the stubs replace what duty registered
  e.app.addons.virtCapacity = connected ? { report: F.report, overprov: () => Object.assign(F.overprov(), { vms: F.rowsAll }), vmHistory: F.vmHistory } : { report: () => ({ settings: {}, platforms: [], clusters: [], hosts: [], datastores: [], vms: [] }), overprov: () => ({ vms: [] }), vmHistory: () => ({ points: [] }) };
  e.app.addons.virtAdmin = { current: () => (connected ? [{ key: 'ha:PROD', kind: 'ha-off', severity: 'high', title: 'PROD: vSphere HA is off', target: { type: 'cluster', name: 'PROD', cluster: 'PROD', platform: 'vCenter HQ (synthetic)', kind: 'vcenter' } },
    { key: 'ntx:x', kind: 'nutanix-alert', severity: 'high', title: 'Prism alert', target: { platform: 'Prism (synthetic)', kind: 'nutanix' } }] : []),
  plans: () => [{ id: 'VCH-0001', item_key: 'ha:PROD', state: 'proposed', title: 'Turn on vSphere HA on PROD', severity: 'high', requested_by: 'duty:virt' }, { id: 'VCH-0002', item_key: 'ntx:x', state: 'proposed', title: 'Nutanix thing' }],
  policy: () => ({ snapshot_warn_days: 3, snapshot_high_days: 7 }) };
  const call = (m, p, b, who) => e.req(m, p, Object.assign(b !== undefined ? { body: b } : {}, who));
  return { e, call };
}

test('vCenter only: explained host / cluster / VM health, imbalance, drift, profiles, unusual CPU, datastores, findings', async (t) => {
  const { call } = await setup(t);
  const r = await call('GET', '/vsphere-studio', undefined, VIEW); assert.equal(r.status, 200, r.raw);
  const v = r.json;
  assert.equal(v.platforms.length, 1, 'Nutanix is not on the vSphere page'); assert.equal(v.clusters.length, 1); assert.equal(v.hosts.length, 3); assert.equal(v.vms.length, 17);
  const esx3 = v.hosts.find((h) => h.name === 'esx03');
  assert.ok(esx3.why_score.some((w) => /not responding/.test(w.text)) && esx3.why_score.some((w) => /runs VMware ESXi 7.0.3/.test(w.text)));
  assert.equal(esx3.score, 100 - esx3.why_score.reduce((a, w) => a + w.points, 0), 'the score is 100 minus the named points');
  const esx1 = v.hosts.find((h) => h.name === 'esx01'); assert.ok(esx1.why_score.some((w) => /CPU 92 %/.test(w.text)));
  const c = v.clusters[0];
  assert.ok(c.why_score.some((w) => /HA is off/.test(w.text)) && c.why_score.some((w) => /N\+1/.test(w.text)) && c.why_score.some((w) => /out of balance/.test(w.text) && /esx01 busiest/.test(w.text)) && c.why_score.some((w) => /version drift/.test(w.text)));
  assert.equal(c.balance.metric, 'CPU'); assert.equal(c.open_findings, 1);
  assert.ok(v.profiles.length >= 2 && v.profiles.some((p) => p.name === 'idle'), 'workload profiles: ' + JSON.stringify(v.profiles));
  assert.equal(v.profiles.reduce((a, p) => a + p.vms, 0), 16, 'every running VM with history is profiled');
  assert.equal(new Set(v.profiles.map((p) => p.name)).size, v.profiles.length, 'one entry per profile name'); assert.ok(v.profiles.every((p) => p.vms > 0), 'no empty profile');
  const vm1 = v.vms.find((x) => x.id === 'vm-1');
  assert.ok(vm1.why_score.some((w) => /oldest 10 days/.test(w.text)) && vm1.why_score.some((w) => /5 snapshots/.test(w.text)) && vm1.why_score.some((w) => /consolidation/.test(w.text)) && vm1.why_score.some((w) => /Tools/.test(w.text)));
  const vm2 = v.vms.find((x) => x.id === 'vm-2'); assert.match(vm2.unusual, /CPU 95 % now, usually at most 3 %/);
  assert.equal(v.vms.find((x) => x.id === 'vm-3').rightsize.vcpus_to, 2);
  assert.ok(v.vms.find((x) => x.id === 'vm-16').why_score.some((w) => /short of CPU/.test(w.text)));
  assert.equal(v.datastores.find((d) => d.name === 'DS-SYN-01').risk, 'full'); assert.equal(v.datastores.find((d) => d.name === 'DS-SYN-02').risk, 'overcommitted');
  assert.equal(v.findings.length, 1, 'only vSphere findings'); assert.equal(v.plans.length, 1); assert.equal(v.plans[0].id, 'VCH-0001');
  assert.ok(v.look_first.length > 0 && v.look_first[0].points >= v.look_first[v.look_first.length - 1].points, 'ranked');
  assert.ok(['CRITICAL', 'ATTENTION'].includes(v.overall.state)); assert.equal(v.summary.unusual, 1); assert.equal(v.summary.hosts_down, 1);
  assert.equal(v.totals.cores, 96); assert.deepEqual(Object.keys(v.storage_trend), ['vCenter HQ (synthetic)']);
  assert.equal(v.ai.enabled, false);
});

test('nothing connected: NOT CONNECTED, empty lists, never a sample host', async (t) => {
  const { call } = await setup(t, { connected: false });
  const v = (await call('GET', '/vsphere-studio', undefined, VIEW)).json;
  assert.equal(v.overall.state, 'NOT CONNECTED'); assert.equal(v.hosts.length, 0); assert.equal(v.vms.length, 0); assert.equal(v.overall.score, null);
});

test('VM history: validated, vCenter platforms only; AI analyst: roles, validation, not configured', async (t) => {
  const { e, call } = await setup(t);
  let r = await call('GET', '/vsphere-studio/vm-history?pid=vc1&vm=vm-1', undefined, VIEW); assert.equal(r.status, 200); assert.equal(r.json.points.length, 2);
  r = await call('GET', '/vsphere-studio/vm-history?pid=vc1', undefined, VIEW); assert.equal(r.status, 400); assert.match(r.json.error, /vm is required/);
  r = await call('GET', '/vsphere-studio/vm-history?pid=vc1&vm=' + encodeURIComponent('<x>'), undefined, VIEW); assert.equal(r.status, 400); assert.match(r.json.error, /not a VM id/);
  r = await call('GET', '/vsphere-studio/vm-history?pid=ntx1&vm=n1', undefined, VIEW); assert.equal(r.status, 404, 'a Nutanix platform is not served here');
  r = await call('GET', '/vsphere-studio/ai/status', undefined, VIEW); assert.equal(r.status, 403);
  r = await call('POST', '/vsphere-studio/ai/ask', { question: 'what is at risk?' }, VIEW); assert.equal(r.status, 403);
  r = await call('POST', '/vsphere-studio/ai/ask', { question: 'x' }, OP); assert.equal(r.status, 400); assert.match(r.json.error, /question/);
  r = await call('POST', '/vsphere-studio/ai/ask', { question: 'what is at risk?' }, OP); assert.equal(r.status, 503, 'not configured: the reason is on GET /vsphere-studio (ai.reason)');
  assert.equal(e.app.store.auditTail(50).filter((x) => /^vsphere\.studio\./.test(x.action)).length, 0, 'nothing audited for a refused question');
});
