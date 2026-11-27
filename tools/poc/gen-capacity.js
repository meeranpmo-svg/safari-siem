#!/usr/bin/env node
// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * gen-capacity.js - writes ui/vendor/zyb-poc-capacity.js: the POC data of Capacity Planning (capacity.html), made by the REAL engines
 * (backend/itam engine/capacity-plan.js, backend/siem engine/ops/server-capacity.js) over SYNTHETIC figures: four head-office Hyper-V
 * hosts, two Jeddah hosts, a project-site host, 30 days of agent readings from physical servers and VMs, and Azure VMs with Advisor
 * advice. Every name is invented.   node tools/poc/gen-capacity.js
 */
const fs = require('fs'), path = require('path');
const ROOT = path.resolve(__dirname, '../..'), CP = require(path.join(ROOT, 'backend/itam/engine/capacity-plan.js')), SC = require(path.join(ROOT, 'backend/siem/engine/ops/server-capacity.js'));
let seed = 41; const rnd = () => ((seed = (seed * 1103515245 + 12345) % 2147483648) / 2147483648);
const NOW = Date.parse('2026-11-26T09:00:00Z'), GB = 1024;
const vm = (name, gb, dem, st = 'running', vc = 4) => ({ name, state: st, vcpus: vc, mem_assigned_mb: gb * GB, mem_demand_mb: dem * GB });
const host = (name, total, used, vms, memDays, vols) => ({ name, cores: 64, cpu_pct: 20 + Math.round(rnd() * 30), mem_total_mb: total * GB, mem_free_mb: (total - used) * GB, vms, vcpu_ratio: Math.round(10 * vms.reduce((s, v) => s + (v.state === 'running' ? v.vcpus : 0), 0) / 64) / 10,
  capacity: { memory: memDays, volumes: vols || [] }, volumes: (vols || []).map((v) => ({ name: v.name, size_gb: 4000, free_gb: 900 })) });
const HQ = ['ERP-AX-01', 'ERP-AX-SQL-01', 'FUSION-INT-01', 'FILE-01', 'PRINT-01', 'DC-01', 'APP-HSE-01', 'APP-FLEET-01', 'APP-HR-01', 'CCTV-VMS-01', 'SIEM-COL-01', 'BACKUP-01'];
const hv = { hosts: [
  host('HQPSUPERM01', 768, 520, HQ.slice(0, 4).map((n, i) => vm(n + '-POC', [96, 128, 32, 64][i], [80, 120, 10, 30][i], 'running', 8)), 38, [{ name: 'C:\\ClusterStorage\\Volume1', days: 44 }]),
  host('HQPSUPERM02', 768, 560, HQ.slice(4, 8).map((n, i) => vm(n + '-POC', [32, 16, 64, 64][i], [12, 6, 60, 22][i])), 52),
  host('HQPSUPERM03', 768, 600, HQ.slice(8, 12).map((n, i) => vm(n + '-POC', [32, 96, 64, 128][i], [28, 90, 60, 70][i], 'running', 8)).concat([vm('OLD-TEST-POC', 16, 0, 'off')]), 29, [{ name: 'C:\\ClusterStorage\\Volume2', days: 21 }]),
  host('HQPSUPERM04', 512, 410, [vm('DMS-POC', 64, 50), vm('INTRANET-POC', 32, 8), vm('MONITOR-POC', 32, 20)], 61),
  host('JEDHV01', 384, 210, [vm('JED-FILE-POC', 32, 20), vm('JED-DC-POC', 16, 8)], null), host('JEDHV02', 384, 160, [vm('JED-APP-POC', 64, 20)], null),
  host('JUBSITEHV01', 256, 120, [vm('JUB-CCTV-POC', 32, 28), vm('JUB-SITE-APP-POC', 16, 6)], 120)] };
const H = CP.hyperv(hv);
const A = CP.azure({ vms: [
  { name: 'az-fusion-gw-poc', size: 'Standard_D8s_v5', power: 'running', advisor: [{ category: 'Cost', target_sku: 'Standard_D4s_v5', savings: 140, currency: 'USD', problem: 'Right-size underutilized virtual machine (CPU p95 under 15 % for 7 days)' }] },
  { name: 'az-web-poc', size: 'Standard_D4s_v5', power: 'running', advisor: [] }, { name: 'az-bi-poc', size: 'Standard_E16s_v5', power: 'running', advisor: [{ category: 'Cost', target_sku: 'Standard_E8s_v5', savings: 310, currency: 'USD', problem: 'Right-size underutilized virtual machine' }] },
  { name: 'az-test-poc', size: 'Standard_B4ms', power: 'stopped', advisor: [] }, { name: 'az-dr-dc-poc', size: 'Standard_D2s_v5', power: 'deallocated', advisor: [] }, { name: 'az-api-poc', size: 'Standard_D4s_v5', power: 'running', advisor: [] }],
  totals: { advisor_savings: 450, currency: 'USD' }, orphan_disks: [{}, {}] });
const day = (k) => new Date(NOW - (29 - k) * 864e5 + 3 * 36e5).toISOString().slice(0, 10), rows = [];
const srv = (name, f) => { for (let k = 0; k < 30; k++) rows.push(Object.assign({ host: name, d: day(k) }, f(k))); };
srv('ERP-AX-SQL-01-POC', (k) => ({ cpu95: 55 + rnd() * 10, mem95: 72 + k * 0.5, mem_gb: 128, disks: 'C:|200|80;D:|2000|' + Math.round(520 - k * 13) }));
srv('FILE-01-POC', (k) => ({ cpu95: 15 + rnd() * 5, mem95: 45, mem_gb: 64, disks: 'C:|120|60;E:|8000|' + Math.round(2400 - k * 40) }));
srv('PRINT-01-POC', (k) => ({ cpu95: 4 + rnd() * 3, mem95: 22 + rnd() * 4, mem_gb: 16, disks: 'C:|120|90' }));
srv('APP-HSE-01-POC', (k) => ({ cpu95: 88 + rnd() * 6, mem95: 80 + rnd() * 6, mem_gb: 16, disks: 'C:|120|40' }));
srv('HQ-BACKUP-PHY-POC', (k) => ({ cpu95: 30 + rnd() * 10, mem95: 50, mem_gb: 96, disks: 'C:|240|150;R:|40000|' + Math.round(9000 - k * 120 - (k === 29 ? 900 : 0)) }));
srv('HQ-SQL-PHY-POC', (k) => ({ cpu95: 40 + rnd() * 8, mem95: 60 + rnd() * 4, mem_gb: 256, disks: 'C:|240|120;D:|4000|1800' }));
srv('JED-FILE-POC', (k) => ({ cpu95: 10 + rnd() * 4, mem95: 30, mem_gb: 32, disks: 'C:|120|70;E:|2000|900' }));
srv('az-fusion-gw-poc', (k) => ({ cpu95: 9 + rnd() * 4, mem95: 30 + rnd() * 5, mem_gb: 32, disks: 'C:|128|80' }));
srv('az-web-poc', (k) => ({ cpu95: 35 + rnd() * 10, mem95: 55 + k * 0.6, mem_gb: 16, disks: 'C:|128|60' }));
for (let k = 0; k < 4; k++) rows.push({ host: 'JUB-NEW-PHY-POC', d: day(26 + k), cpu95: 30, mem95: 40, disks: 'C:|240|200' });
const S = SC.analyse(rows, { days: 30 }); S.note = 'POC: illustrative servers. ' + S.note;
const plan = { at: new Date(NOW).toISOString(), hyperv: H, azure: A, insights: [] };
plan.insights = require(path.join(ROOT, 'backend/itam/engine/capacity-plan.js')).createCapacityPlan({ addons: { hypervManager: { view: () => hv }, azureCloud: null }, store: { collection: () => ({ get: () => null }) } }).view().insights
  .concat(A.rightsize.length ? ['Azure Advisor suggests resizing ' + A.rightsize.length + ' VM(s) - about ' + A.savings + ' ' + A.currency + ' a month.'] : [], A.stopped_billed.length ? [A.stopped_billed.length + ' Azure VM(s) are stopped but not deallocated - their compute is still billed.'] : []);
const out = '// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.\n'
  + '/* zyb-poc-capacity.js - GENERATED by tools/poc/gen-capacity.js (the real capacity engines over SYNTHETIC figures) - do not edit by hand. POC mode only. */\n'
  + '(function () {\n  var P = ' + JSON.stringify(plan) + ', S = ' + JSON.stringify(S) + ', AT = ' + JSON.stringify(new Date(NOW).toISOString()) + ';\n'
  + '  function shift(x) { var d = Date.now() - Date.parse(AT); return JSON.parse(JSON.stringify(x), function (k, s) { if (typeof s !== \'string\') return s; var m = /^\\d{4}-\\d{2}-\\d{2}(T[\\d:.]+Z)?$/.exec(s); if (!m) return s; var n = new Date(Date.parse(m[1] ? s : s + \'T00:00:00Z\') + d).toISOString(); return m[1] ? n : n.slice(0, 10); }); }\n'
  + '  window.ZYB_POC = (window.ZYB_POC || []).concat([{ re: /^\\/api\\/itam\\/capacity-plan$/, pages: [\'capacity.html\'], data: function () { return shift(P); } }, { re: /^\\/api\\/soc\\/capacity\\/servers$/, data: function () { return shift(S); } }]);\n})();\n';
fs.writeFileSync(path.join(ROOT, 'ui/vendor/zyb-poc-capacity.js'), out);
console.log('wrote ui/vendor/zyb-poc-capacity.js: ' + H.groups.length + ' Hyper-V groups, ' + S.kpis.servers + ' servers (' + S.kpis.findings + ' findings), ' + A.vms + ' Azure VMs');
