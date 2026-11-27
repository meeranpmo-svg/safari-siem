#!/usr/bin/env node
// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * gen-itam.js - writes ui/vendor/zyb-poc-itam.js: the POC data of the IT Asset Management overview, made by the REAL IT Asset
 * Management engine (startApp + the duty modules) from SYNTHETIC assets at the organisation's head office, branches and project
 * sites - so the overview and its map by location look exactly as they will with the real register. Names, serials and addresses
 * are invented (10.x per site).   node tools/poc/gen-itam.js
 */
const fs = require('fs'), path = require('path');
const ROOT = path.resolve(__dirname, '../..'), ITAM = path.join(ROOT, 'backend/itam');
const { startApp } = require(path.join(ITAM, 'tests/helpers'));
const SITES = [['Riyadh Head Office', 10, 230, 92], ['Jeddah Branch', 20, 90, 84], ['Dammam Branch', 30, 70, 78], ['Khobar Office', 80, 35, 88], ['Jubail Project Site', 40, 60, 62], ['Yanbu Project Site', 50, 40, 58],
  ['Tabuk Project Site', 60, 25, 66], ['Jazan Project Site', 70, 18, 48], ['Madinah Office', 90, 22, 81], ['Abha Office', 95, 12, 74]];
const TYPES = [['workstation', 'PC', 40], ['laptop', 'LT', 25], ['server', 'SRV', 6], ['printer', 'PRN', 6], ['switch', 'SW', 5], ['firewall', 'FW', 1], ['access_point', 'AP', 6], ['cctv', 'CAM', 7], ['phone', 'TEL', 4], ['vm', 'VM', 9]];
const VENDORS = { workstation: ['Dell', 'HP', 'Lenovo'], laptop: ['Dell', 'HP', 'Lenovo'], server: ['Dell', 'HPE'], printer: ['HP', 'Canon'], switch: ['H3C'], firewall: ['Fortinet'], access_point: ['H3C', 'Fortinet'], cctv: ['Hikvision', 'Dahua'], phone: ['Yealink'], vm: ['Microsoft Hyper-V'] };
const DEPTS = ['Operations and Maintenance', 'Projects and Site Workforce', 'Human Resources', 'Finance', 'IT and Information Security', 'Procurement', 'HSE', 'Fleet and Transport'];
let seed = 11; const rnd = () => ((seed = (seed * 1103515245 + 12345) % 2147483648) / 2147483648);
const pick = (L) => L[Math.floor(rnd() * L.length)];

(async () => {
  const e = await startApp({ noAi: true });
  require(path.join(ITAM, 'engine/duty')).registerDuty(e.app.srv, e.app, { noTimer: true, copilotAiOff: true });
  try { require(path.join(ITAM, 'engine/infra-overview')).registerInfraOverview(e.app.srv, e.app); } catch (x) { /* already registered by this engine build */ }
  const ADM = { user: 'admin.poc', role: 'admin' }, tw = TYPES.reduce((s, t) => s + t[2], 0), type = () => { let r = rnd() * tw; for (const t of TYPES) { r -= t[2]; if (r <= 0) return t; } return TYPES[0]; };
  let n = 0;
  for (const [site, oct, count, quality] of SITES) {
    for (let i = 0; i < count; i++) {
      const [t, code, ] = type(), v = pick(VENDORS[t]), full = rnd() * 100 < quality, abbr = site.split(' ')[0].slice(0, 3).toUpperCase();
      const a = { name: abbr + '-' + code + '-' + String(++n).padStart(4, '0') + '-POC', type: t, site, status: rnd() < 0.9 ? 'in_use' : pick(['in_stock', 'in_repair', 'retired']), vendor: v,
        mgmt_ip: '10.' + oct + '.' + (1 + Math.floor(rnd() * 30)) + '.' + (10 + Math.floor(rnd() * 230)) };
      if (full) Object.assign(a, { serial: 'POC' + Math.floor(rnd() * 1e9).toString(36).toUpperCase(), model: v + ' ' + pick(['G5', 'G7', '800', 'X1', 'S5130', 'FG-100F']), owner: pick(['a.harbi.poc', 's.qahtani.poc', 'm.shehri.poc', 'k.otaibi.poc', 'site.supervisor.poc']), department: pick(DEPTS), os: /workstation|laptop/.test(t) ? 'Windows 11' : t === 'server' || t === 'vm' ? pick(['Windows Server 2022', 'Windows Server 2019', 'Ubuntu 22.04']) : undefined,
        mac: '02:00:' + [0, 0, 0, 0].map(() => Math.floor(rnd() * 256).toString(16).padStart(2, '0')).join(':'), classification: pick(['internal', 'internal', 'restricted']), cia: { c: 'medium', i: 'medium', a: t === 'server' || t === 'firewall' ? 'high' : 'medium' },
        warranty: (() => { const st = Date.now() - Math.floor(rnd() * 3 * 365) * 864e5, en = st + 3 * 365 * 864e5; return { start: new Date(st).toISOString().slice(0, 10), end: new Date(en).toISOString().slice(0, 10), provider: v }; })(), eol: new Date(Date.now() + Math.floor((rnd() * 5 - 0.3) * 365) * 864e5).toISOString().slice(0, 10) });
      else if (rnd() < 0.5) a.serial = 'POC' + Math.floor(rnd() * 1e9).toString(36).toUpperCase();
      e.app.assets.create(a, ADM);
    }
  }
  const r = await e.req('GET', '/itam/overview', { user: 'admin.poc', role: 'admin' });
  if (r.status !== 200) throw new Error('overview ' + r.status + ' ' + r.text);
  // the IT Infrastructure Manager (infra-manager.html): the IT Asset Management parts from the engine, the SIEM parts (availability,
  // application monitors, change plans) built from the same synthetic servers and devices
  const get = async (u) => { const x = await e.req('GET', u, { user: 'admin.poc', role: 'admin' }); return x.status === 200 ? x.json : null; };
  const infra = await get('/infra-overview'), attention = await get('/workflow/attention'), backup = await get('/backup');
  const all = e.app.store.collection('assets').all((a) => a.status === 'in_use'), infraA = all.filter((a) => /server|switch|firewall|access_point/.test(a.type));
  const T0 = Date.now(), avail = { summary: { total: 0, online: 0, offline: 0, unknown: 0 }, items: [] };
  infraA.forEach((a, i) => { const off = i % 37 === 5, st = off ? 'offline' : 'online'; avail.items.push({ id: a.id, name: a.name, ip: a.mgmt_ip, site: a.site, type: a.type, status: st, duration_s: off ? 1800 + (i % 5) * 3600 : 86400 * (3 + i % 40) }); avail.summary.total++; avail.summary[st]++; });
  const apps = { items: [['Oracle Fusion Cloud ERP', 'URL', 'up'], ['Microsoft Dynamics AX', 'REST', 'up'], ['HR Self-Service Portal', 'URL', 'up'], ['Careers Site', 'URL', 'down'], ['Microsoft 365 Sign-in', 'URL', 'up'], ['Site Timesheet API', 'REST', 'up'], ['Fleet Tracking', 'URL', 'up'], ['Document Management', 'URL', 'up']].map(([name, type, av]) => ({ name: name + ' (POC)', type, availability: av, managed: true })) };
  const srv = infraA.filter((a) => a.type === 'server'), net = infraA.filter((a) => a.type !== 'server');
  const netChanges = { items: [['Firmware 7.2.10 on ' + (net[0] || {}).name, 'approved', 1], ['VLAN 40 for Jubail site cameras', 'proposed', 0], ['Close RDP on the WAN interface', 'applied', 3], ['New IPsec tunnel to Tabuk site', 'executing', 0], ['Remove unused rules (firewall audit)', 'validated', 6]].map(([t, st, d], i) => ({ id: 'CP-' + (40 + i), device: (net[i] || net[0] || {}).name, title: t, status: st, decided_at: st === 'proposed' ? null : T0 - d * 86400000 - 3600000, decided_by: st === 'proposed' ? null : 'netmgr.poc', proposed_by: 'network.poc' })) };
  const sysChanges = { items: [['Install the monthly security updates', 'approved', 1], ['Extend the D: volume to 500 GB', 'proposed', 0], ['Restart the print spooler', 'applied', 2], ['Upgrade the backup agent', 'approved', 0]].map(([t, st, d], i) => ({ id: 'SCHG-' + (20 + i), device: (srv[i] || srv[0] || {}).name, title: t, status: st, decided_at: st === 'proposed' ? null : T0 - d * 86400000 - 7200000, decided_by: st === 'proposed' ? null : 'itmgr.poc', proposed_by: 'sysadmin.poc' })) };
  // no backup platform or ManageEngine in the harness: illustrative figures for POC only, in the engine's own shape
  if (infra && infra.backup && !infra.backup.available) { const n = (infra.register.servers || {}).total || 80; infra.backup = { available: true, assets: n, protected: Math.round(n * 0.86), stale: Math.round(n * 0.05), failed: Math.round(n * 0.04), none: n - Math.round(n * 0.86) - Math.round(n * 0.05) - Math.round(n * 0.04), exempt: 0, protected_pct: 86 }; }
  if (infra && infra.patch && !infra.patch.available) { const c = all.filter((a) => /workstation|laptop|server|vm/.test(a.type)).length; infra.patch = { available: true, computers: c, reported: c - 12, compliant: Math.round(c * 0.81), critical_missing: Math.round(c * 0.06), compliant_pct: 81, worst: all.filter((a) => a.type === 'server').slice(0, 5).map((a, i) => ({ name: a.name, missing: 9 - i, critical: i < 2 ? 2 : 1, health: i < 2 ? 'highly vulnerable' : 'vulnerable' })) }; }
  // the AI health index (leader-intel) comes from the recorded tests, which carry the backup / patch history and trends
  const IM = ['infra-manager.html'];
  const extra = [['/api/itam/infra-overview', infra], ['/api/itam/workflow/attention', attention], ['/api/itam/backup', backup], ['/api/soc/netops/avail', avail], ['/api/soc/db/oracle', { instances: [] }], ['/api/soc/integrations/apm/status', { configured: true, connected: true }], ['/api/soc/integrations/apm/monitors', apps], ['/api/soc/netops/changes', netChanges], ['/api/soc/sysadmin/changes', sysChanges]].filter((x) => x[1]);
  const out = '// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.\n'
    + '/* zyb-poc-itam.js - GENERATED by tools/poc/gen-itam.js (the real IT Asset Management engine over SYNTHETIC assets) - do not edit by hand. POC mode only. */\n'
    + '(function () {\n  var O = ' + JSON.stringify(r.json) + ';\n'
    + '  window.ZYB_POC = (window.ZYB_POC || []).concat([{ re: /^\\/api\\/itam\\/itam\\/overview$/, data: function () { var x = JSON.parse(JSON.stringify(O)); x.at = new Date().toISOString(); return x; }, pages: [\'itam-overview.html\'] }]);\n'
    + '  var X = ' + JSON.stringify(extra) + ', at = ' + JSON.stringify(new Date().toISOString()) + ', d = Date.now() - Date.parse(at);\n'
    + '  var mv = function (x) { if (Array.isArray(x)) return x.map(mv); if (x && typeof x === "object") { for (var k in x) { var v = x[k]; if (typeof v === "number" && v > 1.5e12 && v < 2.5e12) x[k] = v + d; else if (v && typeof v === "object") mv(v); } } return x; };\n'
    + '  window.ZYB_POC = window.ZYB_POC.concat(X.map(function (e) { var re = new RegExp("^" + e[0].replace(/[.*+?^${}()|[\\]\\\\/]/g, "\\\\$&") + "$"); return { re: re, data: function () { return mv(JSON.parse(JSON.stringify(e[1]))); }, pages: ' + JSON.stringify(IM) + ' }; }));\n})();\n';
  fs.writeFileSync(path.join(ROOT, 'ui/vendor/zyb-poc-itam.js'), out);
  console.log('wrote ui/vendor/zyb-poc-itam.js: ' + n + ' synthetic assets, ' + Math.round(out.length / 1024) + ' KB, sites ' + (r.json.breakdown.sites_all || []).length);
  await e.close(); process.exit(0);
})().catch((x) => { console.error(x); process.exit(1); });
