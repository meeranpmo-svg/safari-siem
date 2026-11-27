#!/usr/bin/env node
// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * gen-hvopt.js - writes ui/vendor/zyb-poc-hvopt.js: the POC data of Hyper-V Optimization (hyperv-optimize.html), made by the REAL engine
 * (backend/itam/engine/hyperv-optimize.js) over SYNTHETIC reports of four head-office hosts and two Jeddah hosts with 21 days of daily
 * snapshots and 48 h of readings - oversized and undersized VMs, idle VMs, old checkpoints, a filling volume, a busy NIC, uneven hosts.
 * Every name is invented.   node tools/poc/gen-hvopt.js
 */
const fs = require('fs'), path = require('path');
const ROOT = path.resolve(__dirname, '../..'), O = require(path.join(ROOT, 'backend/itam/engine/hyperv-optimize.js'));
let seed = 31; const rnd = () => ((seed = (seed * 1103515245 + 12345) % 2147483648) / 2147483648);
const DAY = 864e5, NOW = Date.parse('2026-11-27T09:00:00Z'), GB = 1024;
const OS = ['Windows Server 2022 Standard (10.0.20348)', 'Windows Server 2019 Standard (10.0.17763)', 'Ubuntu 22.04.4 LTS', 'Red Hat Enterprise Linux 9.3'];
const HOSTS = [['HQPSUPERM01', 768, 0.78, 32], ['HQPSUPERM02', 768, 0.61, 32], ['HQPSUPERM03', 768, 0.44, 32], ['HQPSUPERM04', 512, 0.83, 24], ['JEDHV01', 384, 0.38, 16], ['JEDHV02', 384, 0.52, 16]];
const ROLES = ['ERP-AX', 'ERP-AX-SQL', 'FUSION-INT', 'FILE', 'PRINT', 'DC', 'APP-HSE', 'APP-FLEET', 'APP-HR', 'CCTV-VMS', 'SIEM-COL', 'BACKUP', 'DMS', 'INTRANET', 'MONITOR', 'WSUS', 'RDS', 'TEST'];
const latest = [], daily = [], samples = [];
HOSTS.forEach(([name, mem, use, cores], hi) => {
  const key = name.toLowerCase(), vms = [];
  const n = name.startsWith('JED') ? 5 : 8;
  for (let i = 0; i < n; i++) {
    const role = ROLES[(hi * 5 + i) % ROLES.length], vname = role + '-' + String(hi + 1).padStart(2, '0') + '-POC', assigned = [8, 16, 32, 64, 96, 128][Math.floor(rnd() * 6)] * GB;
    const kind = i === 0 && hi < 4 ? 'big' : i === 1 && hi % 2 === 0 ? 'tight' : i === n - 1 && hi === 1 ? 'idle' : 'normal';
    vms.push({ name: vname, kind, state: kind === 'idle' ? 'off' : 'running', os: OS[(hi + i) % OS.length], vcpus: kind === 'big' ? 16 : [2, 4, 8][i % 3], mem_assigned_mb: kind === 'big' ? 128 * GB : assigned, mem_demand_mb: 0, cpu_pct: 0,
      off_since: kind === 'idle' ? new Date(NOW - 62 * DAY).toISOString() : null, net_rx_bps: Math.round(rnd() * 80e6), net_tx_bps: Math.round(rnd() * 60e6),
      vhds: [{ path: 'C:\\ClusterStorage\\Volume' + (1 + hi % 2) + '\\' + vname + '\\disk0.vhdx', size_gb: Math.round(80 + rnd() * 300), max_gb: kind === 'big' ? 2000 : 500 }].concat(i === 2 && hi === 0 ? [{ path: 'C:\\ClusterStorage\\Volume1\\' + vname + '\\data.vhdx', size_gb: 470, max_gb: 500 }] : []),
      checkpoints: i === 3 && hi < 3 ? [{ name: 'before update (POC)', created: new Date(NOW - (20 + hi * 9) * DAY).toISOString() }] : [] });
  }
  for (let d = 0; d < 21; d++) {
    const id = key + '|' + new Date(NOW - (21 - d) * DAY).toISOString().slice(0, 10), V = {};
    for (const v of vms) { if (v.state !== 'running') continue; const base = v.kind === 'big' ? 0.12 : v.kind === 'tight' ? 0.96 : 0.55 + rnd() * 0.25; V[v.name] = { mem_demand_mb: Math.round(v.mem_assigned_mb * base * (0.95 + rnd() * 0.08)), cpu_pct: Math.round(v.kind === 'big' ? 4 + rnd() * 4 : 20 + rnd() * 40) }; }
    daily.push({ id, mem_used_mb: Math.round(mem * GB * use), volumes: { ['C:\\ClusterStorage\\Volume' + (1 + hi % 2)]: hi === 0 ? 3100 + d * 22 : 1800 + d * 3 }, vms: V });
  }
  for (const v of vms) { const last = daily[daily.length - 1].vms[v.name]; if (last) { v.mem_demand_mb = last.mem_demand_mb; v.cpu_pct = last.cpu_pct; } }
  const nics = [{ name: 'NIC1', link_mbps: hi === 3 ? 10000 : 25000, rx_bps: 0, tx_bps: 0 }, { name: 'NIC2', link_mbps: hi === 3 ? 10000 : 25000, rx_bps: 0, tx_bps: 0 }];
  for (let k = 0; k < 192; k++) { const t = NOW - (192 - k) * 900e3, h = (new Date(t).getUTCHours() + 3) % 24, work = h >= 7 && h <= 17 ? 1 : 0.55;
    const busy = hi === 3 ? 0.78 : 0.25; samples.push({ id: key + '|' + t, host: key, t, cpu: Math.round((use * 55 + rnd() * 10) * work + (hi === 0 && k === 191 ? 40 : 0)), mem_pct: Math.round(use * 1000 + rnd() * 15) / 10, disk_ms: Math.round((3 + rnd() * 3) * 10) / 10,
      rx_bps: 0, tx_bps: 0, nics: { NIC1: { rx_bps: Math.round(nics[0].link_mbps * 1e6 * busy * work * (0.8 + rnd() * 0.4)), tx_bps: Math.round(nics[0].link_mbps * 1e6 * busy * work * 0.7) }, NIC2: { rx_bps: Math.round(nics[1].link_mbps * 1e6 * 0.2 * work), tx_bps: Math.round(nics[1].link_mbps * 1e6 * 0.15 * work) } } }); }
  latest.push({ id: key, at: new Date(NOW - 5 * 60e3).toISOString(), host: { name, cores, cpu_pct: Math.round(use * 55), mem_total_mb: mem * GB, mem_free_mb: Math.round(mem * GB * (1 - use)),
    volumes: [{ name: 'C:\\ClusterStorage\\Volume' + (1 + hi % 2), size_gb: hi === 0 ? 4000 : 4000, free_gb: hi === 0 ? 4000 - (3100 + 20 * 22) : 4000 - 1860, csv: true }], nics, disk: { latency_ms: 4 } }, vms });
});
const v = O.analyse({ latest, daily, samples, now: NOW }); v.note = 'POC: illustrative hosts and VMs. ' + v.note;
const out = '// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.\n'
  + '/* zyb-poc-hvopt.js - GENERATED by tools/poc/gen-hvopt.js (the real Hyper-V Optimization engine over SYNTHETIC reports) - do not edit by hand. POC mode only. */\n'
  + '(function () {\n  var V = ' + JSON.stringify(v) + ', AT = ' + JSON.stringify(new Date(NOW).toISOString()) + ';\n'
  + '  function shift(x) { var d = Date.now() - Date.parse(AT); return JSON.parse(JSON.stringify(x), function (k, s) { if (typeof s !== \'string\') return s; var m = /^\\d{4}-\\d{2}-\\d{2}(T[\\d:.]+Z)?$/.exec(s); if (!m) return s; var n = new Date(Date.parse(m[1] ? s : s + \'T00:00:00Z\') + d).toISOString(); return m[1] ? n : n.slice(0, 10); }); }\n'
  + '  window.ZYB_POC = (window.ZYB_POC || []).concat([{ re: /^\\/api\\/itam\\/hyperv\\/optimize$/, pages: [\'hyperv-optimize.html\'], data: function () { return shift(V); } }]);\n})();\n';
fs.writeFileSync(path.join(ROOT, 'ui/vendor/zyb-poc-hvopt.js'), out);
console.log('wrote ui/vendor/zyb-poc-hvopt.js: score ' + v.score + ', ' + v.kpis.recommendations + ' recommendations, give back ' + v.kpis.mem_back_gb + ' GB / ' + v.kpis.vcpu_back + ' vCPU, move ' + (v.move ? v.move.vm : '-'));
