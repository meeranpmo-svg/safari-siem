#!/usr/bin/env node
// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * gen-hvnet.js - writes ui/vendor/zyb-poc-hvnet.js: the POC data of the Hyper-V Virtual Network Map (virtual-network-map.html), made by
 * the REAL engine (backend/itam/engine/hyperv-netmap.js over hyperv-manager.js normMetrics) from SYNTHETIC host reports: four head-office
 * hosts, two Jeddah hosts and one project-site host, with a few problems to find. Every name is invented; addresses are 10.x.
 *   node tools/poc/gen-hvnet.js
 */
const fs = require('fs'), path = require('path');
const ROOT = path.resolve(__dirname, '../..'), N = require(path.join(ROOT, 'backend/itam/engine/hyperv-netmap.js')), { normMetrics } = require(path.join(ROOT, 'backend/itam/engine/hyperv-manager.js'));
const NOW = Date.parse('2026-11-26T09:00:00Z'), AT = new Date(NOW - 6 * 60e3).toISOString();
const VLANS = { 110: ['ERP-AX-POC', 'ERP-AX-SQL-POC', 'FUSION-INT-POC'], 120: ['FILE-POC', 'PRINT-POC', 'DFS-POC'], 130: ['APP-HSE-POC', 'APP-FLEET-POC', 'APP-HR-POC'], 140: ['CCTV-VMS-POC', 'NVR-MGR-POC'], 150: ['DC-POC', 'DNS-POC'], 160: ['SIEM-COL-POC', 'BACKUP-POC'] };
let mc = 0;
function host(name, i, o = {}) {
  const site = i, nic = (k, st, mb) => ({ name: 'NIC' + k, desc: 'Mellanox ConnectX-4 #' + k, status: st || 'Up', link_mbps: mb || 25000, mac: '00-15-5D-' + String(i).padStart(2, '0') + '-00-0' + k });
  const physical = [nic(1), nic(2, o.down ? 'Disconnected' : 'Up', o.slow ? 10000 : 25000), { name: 'NIC3', desc: 'Intel I350 #1', status: 'Up', link_mbps: o.slowBackup ? 100 : 1000, mac: '00-15-5D-' + String(i).padStart(2, '0') + '-00-13' }];
  const switches = [{ name: 'vSW-Prod', type: 'External', set: true, mgmt_os: true, uplinks: ['Mellanox ConnectX-4 #1', 'Mellanox ConnectX-4 #2'] }];
  if (!o.noBackup) switches.push({ name: 'vSW-Backup', type: 'External', set: false, mgmt_os: false, uplinks: ['Intel I350 #1'] });
  if (o.lab) switches.push({ name: 'Lab-Isolated', type: 'Private', uplinks: [] });
  const adapters = [{ mgmt_os: true, name: 'Management', switch: 'vSW-Prod', mac: '00155D' + String(i).padStart(2, '0') + 'FF01', ips: ['10.' + site + '.8.' + (10 + i)], vlan_mode: o.mgmtUntagged ? 'Untagged' : 'Access', vlan: o.mgmtUntagged ? null : 8 },
    { mgmt_os: true, name: 'LiveMigration', switch: 'vSW-Prod', mac: '00155D' + String(i).padStart(2, '0') + 'FF02', ips: ['10.' + site + '.9.' + (10 + i)], vlan_mode: 'Access', vlan: 9 }];
  const vms = [];
  (o.vlans || [110, 120, 130]).forEach((v) => (VLANS[v] || []).forEach((vm, k) => { if ((k + i) % 2 && !o.all) return; const nm = vm.replace('-POC', '-' + String(i).padStart(2, '0') + '-POC'); vms.push({ name: nm, state: 'Running' });
    adapters.push({ vm: nm, name: 'Network Adapter', switch: 'vSW-Prod', mac: '00155D' + (++mc).toString(16).toUpperCase().padStart(6, '0'), ips: ['10.' + site + '.' + (v - 100) + '.' + (20 + mc % 200)], vlan_mode: 'Access', vlan: v, status: 'Ok' }); }));
  if (!o.noBackup) { vms.push({ name: 'VEEAM-PRX-' + i + '-POC', state: 'Running' }); adapters.push({ vm: 'VEEAM-PRX-' + i + '-POC', name: 'Backup', switch: 'vSW-Backup', mac: '00155D' + (++mc).toString(16).toUpperCase().padStart(6, '0'), ips: ['10.' + site + '.60.' + (20 + mc)], vlan_mode: 'Untagged' }); }
  if (o.trunk) { vms.push({ name: 'FW-VM-POC', state: 'Running' }); adapters.push({ vm: 'FW-VM-POC', name: 'Trunk', switch: 'vSW-Prod', mac: '00155D' + (++mc).toString(16).toUpperCase().padStart(6, '0'), vlan_mode: 'Trunk', allowed: '110,120,130,140', native: 1 }); }
  if (o.lab) { vms.push({ name: 'LAB-TEST-POC', state: 'Running' }); adapters.push({ vm: 'LAB-TEST-POC', name: 'Lab', switch: 'Lab-Isolated', mac: '00155D' + (++mc).toString(16).toUpperCase().padStart(6, '0'), vlan_mode: 'Untagged' }); }
  if (o.loose) { vms.push({ name: 'OLD-APP-POC', state: 'Running' }); adapters.push({ vm: 'OLD-APP-POC', name: 'Network Adapter', switch: '', mac: '00155D' + (++mc).toString(16).toUpperCase().padStart(6, '0'), vlan_mode: 'Untagged' }); }
  return normMetrics({ collected_at: AT, host: { name, logical_processors: 64, network: { physical, switches, adapters } }, vms });
}
const R = [host('HQPSUPERM01', 1, { all: true, vlans: [110, 120, 150] }), host('HQPSUPERM02', 1, { vlans: [110, 130, 160], trunk: true }), host('HQPSUPERM03', 1, { vlans: [120, 130, 140], down: true }),
  host('HQPSUPERM04', 1, { vlans: [110, 140], noBackup: true, mgmtUntagged: true }), host('JEDHV01', 2, { vlans: [110, 120], lab: true }), host('JEDHV02', 2, { vlans: [120, 130], slow: true, loose: true }),
  host('JUBSITEHV01', 5, { vlans: [130, 140], slowBackup: true })];
const v = N.analyse(R, { now: NOW });
const prev = host('HQPSUPERM04', 1, { vlans: [110, 140] }), cur = R[3];
v.changes = [{ id: 'poc-1', host: 'HQPSUPERM04', at: new Date(NOW - 26 * 36e5).toISOString(), changes: N.diff(prev.host.network, cur.host.network) },
  { id: 'poc-2', host: 'JEDHV02', at: new Date(NOW - 3 * 864e5).toISOString(), changes: [{ what: 'adapter:OLD-APP-POC/Network Adapter', change: 'changed', was: 'vSW-Prod VLAN 130', now: 'no switch VLAN untagged' }] }];
v.note = 'POC: illustrative Hyper-V hosts and VMs. ' + v.note;
const traces = {}; for (const h of v.hosts) for (const a of h.adapters) if (!a.mgmt_os && !traces[a.vm.toLowerCase()]) traces[a.vm.toLowerCase()] = N.trace(v, a.vm);
const out = '// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.\n'
  + '/* zyb-poc-hvnet.js - GENERATED by tools/poc/gen-hvnet.js (the real Hyper-V network map over SYNTHETIC host reports) - do not edit by hand. POC mode only. */\n'
  + '(function () {\n  var V = ' + JSON.stringify(v) + ', T = ' + JSON.stringify(traces) + ', AT = ' + JSON.stringify(new Date(NOW).toISOString()) + ';\n'
  + '  function shift(x) { var d = Date.now() - Date.parse(AT); return JSON.parse(JSON.stringify(x), function (k, s) { if (typeof s !== \'string\') return s; var m = /^\\d{4}-\\d{2}-\\d{2}(T[\\d:.]+Z)?$/.exec(s); if (!m) return s; var n = new Date(Date.parse(m[1] ? s : s + \'T00:00:00Z\') + d).toISOString(); return m[1] ? n : n.slice(0, 10); }); }\n'
  + '  window.ZYB_POC = (window.ZYB_POC || []).concat([{ re: /^\\/api\\/itam\\/hyperv\\/network$/, pages: [\'virtual-network-map.html\'], data: function () { return shift(V); } },\n'
  + '    { re: /^\\/api\\/itam\\/hyperv\\/network\\/trace$/, data: function (u) { var k = String(u.searchParams.get(\'vm\') || \'\').toLowerCase(); return T[k] || { vm: k, paths: [] }; } }]);\n})();\n';
fs.writeFileSync(path.join(ROOT, 'ui/vendor/zyb-poc-hvnet.js'), out);
console.log('wrote ui/vendor/zyb-poc-hvnet.js: ' + v.kpis.hosts + ' hosts, ' + v.kpis.vm_adapters + ' VM adapters, ' + v.kpis.findings + ' findings (' + v.kpis.high + ' high)');
