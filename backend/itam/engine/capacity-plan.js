// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * CAPACITY PLANNING for Hyper-V and Azure ({P} = /api/itam), from what the platform already reads - nothing is sampled or invented:
 *   Hyper-V   per host group (hosts named alike: HQPSUPERM01..04, or the site an administrator sets - hyperv-netmap.groupOf):
 *             memory and logical processors in total and in use, vCPU per core, room with ONE HOST IN RESERVE (N+1: if the largest
 *             host fails, do its VMs fit on the others?), how many more VMs of the group's average size fit, the date memory or a
 *             volume runs out at the daily trend (hyperv-manager: least squares over 5+ daily reports), VMs to rightsize or reclaim
 *   Azure     VM count, sizes, power, Azure Advisor's right-size / shut-down recommendations with the target size and saving,
 *             VMs stopped but still billed, deallocated VMs to delete or keep (azure-cloud.js; Azure's own CPU history decides)
 * Physical and Windows / Linux servers with the SIEM agent are measured by the SIEM (GET /api/soc/capacity/servers); the page shows all.
 *   GET /capacity-plan   viewer
 */
const { groupOf } = require('./hyperv-netmap');
const r1 = (x) => (x == null || !Number.isFinite(x) ? null : Math.round(x * 10) / 10);

function hyperv(view, o = {}) {
  const hosts = (view && view.hosts) || [];
  if (!hosts.length) return { available: false, why: 'No Hyper-V host reports yet - add the hosts on the Hyper-V Servers page.' };
  const G = new Map(); for (const h of hosts) { const g = groupOf(h.name, o.sites); (G.get(g) || G.set(g, []).get(g)).push(h); }
  const groups = [...G.entries()].map(([g, L]) => {
    const mem = (h) => h.mem_total_mb || 0, used = (h) => (h.mem_total_mb != null && h.mem_free_mb != null ? h.mem_total_mb - h.mem_free_mb : null);
    const total = L.reduce((s, h) => s + mem(h), 0), inUse = L.reduce((s, h) => s + (used(h) || 0), 0), cores = L.reduce((s, h) => s + (h.cores || 0), 0);
    const vms = L.flatMap((h) => h.vms || []), running = vms.filter((v) => v.state === 'running'), vcpus = running.reduce((s, v) => s + (v.vcpus || 0), 0);
    const largest = Math.max(0, ...L.map(mem)), n1Cap = total - largest, avgVm = running.length ? running.reduce((s, v) => s + (v.mem_assigned_mb || 0), 0) / running.length : null;
    const n1 = L.length < 2 ? null : inUse <= n1Cap * 0.9;
    const room = avgVm ? Math.max(0, Math.floor(((L.length < 2 ? total * 0.9 : n1Cap * 0.9) - inUse) / avgVm)) : null;
    const memDays = L.map((h) => h.capacity && h.capacity.memory).filter((x) => x != null), volDays = L.flatMap((h) => ((h.capacity && h.capacity.volumes) || []).map((x) => ({ host: h.name, volume: x.name, days: x.days }))).filter((x) => x.days != null);
    const over = vms.filter((v) => v.mem_demand_mb != null && v.mem_assigned_mb && v.mem_demand_mb < 0.5 * v.mem_assigned_mb && v.state === 'running');
    const off = vms.filter((v) => v.state === 'off');
    return { group: g, hosts: L.map((h) => h.name), mem_total_gb: r1(total / 1024), mem_used_gb: r1(inUse / 1024), mem_used_pct: total ? r1(100 * inUse / total) : null, cores, vcpus, vcpu_per_core: cores ? r1(vcpus / cores) : null,
      vms: vms.length, running: running.length, n1_ok: n1, n1_capacity_gb: L.length < 2 ? null : r1(n1Cap / 1024), room_vms: room, avg_vm_gb: avgVm == null ? null : r1(avgVm / 1024),
      mem_days: memDays.length ? Math.min(...memDays) : null, volumes_soon: volDays.sort((a, b) => a.days - b.days).slice(0, 5),
      reclaim_gb: r1(over.reduce((s, v) => s + (v.mem_assigned_mb - v.mem_demand_mb * 1.2), 0) / 1024), oversized: over.length, off: off.map((v) => v.name).slice(0, 20),
      why: L.length < 2 ? 'one host - no host to fail over to' : n1 ? 'if the largest host (' + r1(largest / 1024) + ' GB) fails, its VMs fit on the others' : 'if the largest host (' + r1(largest / 1024) + ' GB) fails, the others cannot hold its VMs - ' + r1((inUse - n1Cap * 0.9) / 1024) + ' GB short' };
  }).sort((a, b) => Number(a.n1_ok !== false) - Number(b.n1_ok !== false) || (a.mem_days == null ? 1e9 : a.mem_days) - (b.mem_days == null ? 1e9 : b.mem_days));
  return { available: true, groups, vm_names: hosts.flatMap((h) => (h.vms || []).map((v) => v.name)).slice(0, 5000), hosts: hosts.map((h) => ({ name: h.name, group: groupOf(h.name, o.sites), cores: h.cores, cpu_pct: h.cpu_pct, mem_total_gb: h.mem_total_mb == null ? null : r1(h.mem_total_mb / 1024),
    mem_used_pct: h.mem_total_mb && h.mem_free_mb != null ? r1(100 * (1 - h.mem_free_mb / h.mem_total_mb)) : null, vcpu_ratio: h.vcpu_ratio, mem_days: h.capacity ? h.capacity.memory : null, volumes: (h.volumes || []).map((v) => ({ name: v.name, size_gb: v.size_gb, free_gb: v.free_gb, days: ((h.capacity && h.capacity.volumes) || []).reduce((d, x) => (x.name === v.name ? x.days : d), null) })) })) };
}

function azure(v) {
  if (!v || !Array.isArray(v.vms) || (!v.vms.length && !v.totals)) return { available: false, why: (v && v.why) || 'Azure is not connected - set the read-only Azure credential on the Azure Cloud Servers page.' };
  const vms = v.vms, rs = vms.flatMap((x) => (x.advisor || []).filter((a) => /cost|performance/i.test(a.category)).map((a) => ({ vm: x.name, size: x.size, target: a.target_sku, problem: a.problem, solution: a.solution, savings: a.savings, currency: a.currency, category: a.category })));
  const bySize = {}; for (const x of vms) if (x.power === 'running') bySize[x.size || '?'] = (bySize[x.size || '?'] || 0) + 1;
  return { available: true, vm_names: vms.map((x) => x.name).slice(0, 5000), vms: vms.length, running: vms.filter((x) => x.power === 'running').length, stopped_billed: vms.filter((x) => x.power === 'stopped').map((x) => ({ vm: x.name, size: x.size })),
    deallocated: vms.filter((x) => x.power === 'deallocated').map((x) => ({ vm: x.name, size: x.size })), by_size: Object.entries(bySize).map(([size, n]) => ({ size, vms: n })).sort((a, b) => b.vms - a.vms).slice(0, 15),
    rightsize: rs.sort((a, b) => (b.savings || 0) - (a.savings || 0)).slice(0, 50), savings: v.totals ? v.totals.advisor_savings : null, currency: v.totals ? v.totals.currency : null, orphan_disks: (v.orphan_disks || []).length };
}

function createCapacityPlan(app) {
  const A = () => app.addons || {};
  function view(role) {
    let hv, az;
    try { hv = A().hypervManager ? hyperv(A().hypervManager.view(), { sites: ((app.store.collection('hv_settings').get('sites') || {}).map) || {} }) : { available: false, why: 'The Hyper-V module is not installed - run the platform update.' }; }
    catch (e) { if (app.log) app.log.warn('capacity: Hyper-V not read', { err: e.message }); hv = { available: false, why: 'Hyper-V figures could not be read: ' + String(e.message).slice(0, 160) }; }
    try { const ac = A().azureCloud; az = ac && typeof ac.view === 'function' ? azure(ac.view(role || 'viewer')) : { available: false, why: 'The Azure Cloud Servers module is not installed.' }; }
    catch (e) { if (app.log) app.log.warn('capacity: Azure not read', { err: e.message }); az = { available: false, why: 'Azure figures could not be read: ' + String(e.message).slice(0, 160) }; }
    const ins = [];
    if (hv.available) { for (const g of hv.groups) { if (g.n1_ok === false) ins.push('Hyper-V ' + g.group + ': ' + g.why + '.'); if (g.mem_days != null && g.mem_days <= 60) ins.push('Hyper-V ' + g.group + ': memory runs out in about ' + g.mem_days + ' day(s) at the current growth.'); if (g.reclaim_gb >= 8) ins.push('Hyper-V ' + g.group + ': ' + g.oversized + ' VM(s) use under half their memory - about ' + g.reclaim_gb + ' GB to give back before buying more.'); } }
    if (az.available) { if (az.rightsize.length) ins.push('Azure Advisor suggests resizing or shutting down ' + az.rightsize.length + ' VM(s)' + (az.savings ? ' - about ' + az.savings + ' ' + (az.currency || '') + ' a month' : '') + '.'); if (az.stopped_billed.length) ins.push(az.stopped_billed.length + ' Azure VM(s) are stopped but not deallocated - their compute is still billed.'); }
    return { at: new Date().toISOString(), hyperv: hv, azure: az, insights: ins };
  }
  return { view };
}

function registerCapacityPlan(srv, app, X) {
  srv.route('GET', '/capacity-plan', (ctx) => { ctx.need('viewer'); return X.view(ctx.who && ctx.who.role); });
}

module.exports = { createCapacityPlan, registerCapacityPlan, hyperv, azure };
