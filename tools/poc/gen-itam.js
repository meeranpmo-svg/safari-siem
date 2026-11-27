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
  // the site plan: each site registered with its block and the standard layout, so the devices below take addresses inside it
  const IPS = e.app.addons.ipamSites, IPM = e.app.addons.ipam, ip4 = require(path.join(ITAM, 'engine/discovery/ipv4')), PLAN = {};
  const kindOf = (s) => (/Head Office/.test(s) ? 'head_office' : /Branch/.test(s) ? 'branch' : /Project Site/.test(s) ? 'project_site' : 'office');
  for (const [site, oct] of SITES) {
    const kind = kindOf(site), block = '10.' + oct + '.0.0/' + { head_office: 16, branch: 18, office: 20, project_site: 20 }[kind];
    await e.req('PUT', '/ipam/sites/' + site.toLowerCase().replace(/[^a-z0-9]+/g, '-'), { user: 'admin.poc', role: 'admin', body: { name: site, kind, city: site.split(' ')[0], block, contact: 'site.supervisor.poc', ends: site === 'Jazan Project Site' ? new Date(Date.now() + 20 * 864e5).toISOString().slice(0, 10) : undefined } });
    PLAN[site] = IPS.layout(block, kind);
    for (const x of PLAN[site]) IPM.putSubnet({ cidr: x.cidr, name: site + ' ' + x.name, site, vlan: x.vlan, gateway: x.gateway, dhcp_start: x.dhcp_start || undefined, dhcp_end: x.dhcp_end || undefined, purpose: x.purpose, owner: 'network.poc' }, ADM);
  }
  const NET = { workstation: /users/i, laptop: /wi-fi staff|site wi-fi|wi-fi$|users/i, server: /servers|users/i, vm: /servers|users/i, printer: /printers/i, switch: /management/i, firewall: /management/i, access_point: /management/i, cctv: /cctv/i, phone: /voice|users/i };
  const ipIn = (site, t) => { const L = PLAN[site], sn = L.find((x) => NET[t] && NET[t].test(x.name)) || L[0], [b, bits] = sn.cidr.split('/'), base = ip4.parseIp(b), size = 2 ** (32 - Number(bits)); return ip4.ipStr(base + 2 + Math.floor(rnd() * Math.max(1, Math.min(size - 4, size * 0.7)))); };
  for (const [site, oct, count, quality] of SITES) {
    for (let i = 0; i < count; i++) {
      const [t, code, ] = type(), v = pick(VENDORS[t]), full = rnd() * 100 < quality, abbr = site.split(' ')[0].slice(0, 3).toUpperCase();
      const a = { name: abbr + '-' + code + '-' + String(++n).padStart(4, '0') + '-POC', type: t, site, status: rnd() < 0.9 ? 'in_use' : pick(['in_stock', 'in_repair', 'retired']), vendor: v,
        mgmt_ip: ipIn(site, t) };
      if (full) Object.assign(a, { serial: 'POC' + Math.floor(rnd() * 1e9).toString(36).toUpperCase(), model: v + ' ' + pick(['G5', 'G7', '800', 'X1', 'S5130', 'FG-100F']), owner: pick(['a.harbi.poc', 's.qahtani.poc', 'm.shehri.poc', 'k.otaibi.poc', 'site.supervisor.poc']), department: pick(DEPTS), os: /workstation|laptop/.test(t) ? 'Windows 11' : t === 'server' || t === 'vm' ? pick(['Windows Server 2022', 'Windows Server 2019', 'Ubuntu 22.04']) : undefined,
        mac: '02:00:' + [0, 0, 0, 0].map(() => Math.floor(rnd() * 256).toString(16).padStart(2, '0')).join(':'), classification: pick(['internal', 'internal', 'restricted']), cia: { c: 'medium', i: 'medium', a: t === 'server' || t === 'firewall' ? 'high' : 'medium' },
        warranty: (() => { const st = Date.now() - Math.floor(rnd() * 3 * 365) * 864e5, en = st + 3 * 365 * 864e5; return { start: new Date(st).toISOString().slice(0, 10), end: new Date(en).toISOString().slice(0, 10), provider: v }; })(), eol: new Date(Date.now() + Math.floor((rnd() * 5 - 0.3) * 365) * 864e5).toISOString().slice(0, 10) });
      else if (rnd() < 0.5) a.serial = 'POC' + Math.floor(rnd() * 1e9).toString(36).toUpperCase();
      e.app.assets.create(a, ADM);
    }
  }
  const r = await e.req('GET', '/itam/overview', { user: 'admin.poc', role: 'admin' });
  if (r.status !== 200) throw new Error('overview ' + r.status + ' ' + r.text);
  const MORE = [];
  // devices Asset Discovery sees on two crowded subnets (Wi-Fi clients at a project site, printers at head office) - so the plan shows a subnet filling up
  const DD = e.app.store.collection('disc_devices'), crowd = (site, re, k) => { const sn = PLAN[site].find((x) => re.test(x.name)), [b] = sn.cidr.split('/'), base = ip4.parseIp(b); for (let i = 0; i < k; i++) DD.put({ id: 'dd-poc-' + site.slice(0, 3) + i, ips: [ip4.ipStr(base + 10 + i)], macs: ['02:aa:' + [i >> 8, i & 255, 1, 2].map((x) => x.toString(16).padStart(2, '0')).join(':')], hostname: 'client-' + i + '.poc', last_seen: new Date().toISOString(), status: 'new' }); };
  crowd('Jubail Project Site', /site wi-fi/i, 225); crowd('Riyadh Head Office', /printers/i, 112); crowd('Jeddah Branch', /^users$/i, 0);
  // a new project site waiting for a second administrator, then the site plan and the subnet register as the pages read them
  IPS.propose({ name: 'Rabigh Project Site', kind: 'project_site', city: 'Rabigh', contact: 'site.supervisor.poc', ends: new Date(Date.now() + 200 * 864e5).toISOString().slice(0, 10) }, { user: 'network.poc', role: 'operator' });
  // PAM Center: privileged directory accounts, the safe with 12 weeks of checkouts (a spike this week, a rotation overdue, one not returned)
  const dAgo = (k) => new Date(Date.now() - k * 864e5).toISOString();
  const PRIV = [['administrator', 'Built-in Administrator', 3], ['a.harbi', 'Ali Al-Harbi', 1], ['s.qahtani-adm', 'Sara Al-Qahtani (admin)', 2], ['m.shehri-adm', 'Mohammed Al-Shehri (admin)', 1], ['k.otaibi', 'Khalid Al-Otaibi', 4], ['f.zahrani-adm', 'Fahad Al-Zahrani (admin)', 140],
    ['old.contractor-adm', 'Contractor 2024', null], ['svc_backup', 'Backup service', 0], ['n.dosari-adm', 'Noura Al-Dosari (admin)', 6], ['h.ghamdi', 'Hassan Al-Ghamdi', 2], ['it.admin', 'IT Admin (shared)', 1], ['y.mutairi-adm', 'Yousef Al-Mutairi (admin)', 220]];
  e.app.store.collection('ad_directory').put({ id: 'last', at: dAgo(0), by: 'admin.poc', users: PRIV.map(([sam, dn, k]) => ({ sam: sam + '.poc'.replace('.poc', ''), display_name: dn + ' (POC)', enabled: true, last_logon: k === null ? null : dAgo(k), admin_count: 1 }))
    .concat(Array.from({ length: 40 }, (_, i) => ({ sam: 'user' + i, display_name: 'Staff ' + i + ' (POC)', enabled: true, last_logon: dAgo(i % 9), admin_count: 0 }))) });
  const PCx = e.app.addons.pamCenter, SAFE = [['Riyadh DC-01', 'BG-DomainAdmin', 'break-glass', 30], ['Riyadh DC-02', 'Administrator', 'local-admin', 90], ['FW-RUH-HQ (FortiGate)', 'admin', 'network-admin', 90], ['SW-RIY-CORE (H3C)', 'admin', 'network-admin', 90],
    ['Hyper-V host HQPSUPERM01', 'Administrator', 'local-admin', 90], ['Oracle Fusion Cloud ERP', 'IT Security Manager', 'app-admin', 60], ['Microsoft 365', 'Global Admin (break-glass)', 'cloud-admin', 60], ['Jubail site NVR', 'admin', 'local-admin', 180]];
  const ids = SAFE.map(([sys, acc, kind, rot], i) => PCx.addEntry({ system: sys + ' (POC)', account: acc, kind, owner: ['it.admin.poc', 'network.poc', 'network.poc', 'network.poc', 'sysadmin.poc', 'erp.admin.poc', 'm365.admin.poc', 'site.supervisor.poc'][i], rotate_days: rot, max_hours: 4, secret: 'POC-not-a-real-password-' + i }, { user: 'admin.poc', role: 'admin' }).id);
  e.app.store.collection('pamc_safe').patch(ids[1], (o) => Object.assign(o, { last_rotated: dAgo(120) }));
  const COL = e.app.store.collection('pamc_checkouts'); let cn = 1;
  const addCo = (entry, k, st, o) => { const at = Date.now() - k * 864e5, rec = Object.assign({ id: 'PC-' + String(cn++).padStart(4, '0'), entry, requester: pick(['net.syn', 'sysadmin.poc', 'network.poc', 'it.admin.poc']).replace('.syn', '.poc'), hours: 2, reason: pick(['Monthly patching of the domain controllers', 'Firewall policy change CHG approved', 'Restore test on the DR site', 'Investigate a failed backup job', 'Site NVR firmware update']) + ' (POC)', ticket: 'CHG-' + (2000 + cn), state: st, at: new Date(at).toISOString(), decided_by: st === 'pending' ? undefined : 'secmgr.poc', from: new Date(at + 600000).toISOString(), until: new Date(at + 600000 + 2 * 36e5).toISOString(), reveals: st === 'approved' ? 1 : 0, revealed_at: new Date(at + 900000).toISOString(), checked_in_at: new Date(at + 6e6).toISOString() }, o || {}); COL.put(rec); };
  for (let w = 11; w >= 1; w--) { for (let i = 0; i < 1 + (w % 3 === 0 ? 1 : 0); i++) { addCo(ids[0], w * 7 + i, 'approved'); addCo(ids[2], w * 7 + 2 + i, 'approved'); } if (w % 2) addCo(ids[4], w * 7 + 3, 'approved'); }
  for (let i = 0; i < 6; i++) addCo(ids[2], i * 0.8 + 0.2, 'approved');   // this week: far above the usual for the firewall admin
  addCo(ids[7], 3, 'approved', { checked_in_at: undefined, revealed_at: new Date(Date.now() - 3 * 864e5 + 3600e3 * 21).toISOString() });   // used at night, never returned
  addCo(ids[6], 0.05, 'pending', { from: undefined, until: undefined, reveals: 0, revealed_at: undefined, checked_in_at: undefined, decided_by: undefined, requester: 'm365.admin.poc', reason: 'Recover a locked conditional access policy (POC)' });
  e.app.store.collection('pamc_safe').patch(ids[0], (o) => Object.assign(o, { rotation_due: true }));
  { const x = await e.req('GET', '/pam-center', { user: 'admin.poc', role: 'admin' }); if (x.status === 200) MORE.push(['/api/itam/pam-center', x.json, 'pam-center.html']); }
  for (const [u, pg] of [['/ipam/sites', 'ipam-sites.html'], ['/ipam', 'ipam.html']]) { const x = await e.req('GET', u, { user: 'admin.poc', role: 'admin' }); if (x.status === 200) MORE.push(['/api/itam' + u, x.json, pg]); }
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
  // the parts of other dashboards the recorded tests never asked for: answered by the engine over the same synthetic register
  for (const [u, pg] of [['/ciso/briefs', 'ciso-dashboard.html'], ['/role-workflows/settings', 'my-workflow.html'], ['/overview-intel', 'compliance-overview.html'], ['/assist/learning', 'compliance-assistant.html'],
    ['/contcomp-intel', 'continuous-compliance.html'], ['/docs-intel', 'compliance-docs.html'], ['/audit-dashboard', 'audit-dashboard.html'], ['/nca-itaudit-intel', 'nca-it-audit.html'], ['/netcfg-intel', 'network-config-audit.html'],
    ['/licence-sync', 'licence-audit.html'], ['/core-licensing', 'licence-audit.html'], ['/software', 'licence-audit.html'], ['/dns-fix', 'email-route-map.html'], ['/mail-route/troubleshoot', 'email-route-map.html']]) {
    const j = await get(u); if (j) MORE.push(['/api/itam' + u, j, pg]); else console.log('  not answered here: ' + u);
  }
  const IM = ['infra-manager.html'];
  const extra = [['/api/itam/infra-overview', infra], ['/api/itam/workflow/attention', attention], ['/api/itam/backup', backup], ['/api/soc/netops/avail', avail], ['/api/soc/db/oracle', { instances: [] }], ['/api/soc/integrations/apm/status', { configured: true, connected: true }], ['/api/soc/integrations/apm/monitors', apps], ['/api/soc/netops/changes', netChanges], ['/api/soc/sysadmin/changes', sysChanges]].filter((x) => x[1]);
  const out = '// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.\n'
    + '/* zyb-poc-itam.js - GENERATED by tools/poc/gen-itam.js (the real IT Asset Management engine over SYNTHETIC assets) - do not edit by hand. POC mode only. */\n'
    + '(function () {\n  var O = ' + JSON.stringify(r.json) + ';\n'
    + '  window.ZYB_POC = (window.ZYB_POC || []).concat([{ re: /^\\/api\\/itam\\/itam\\/overview$/, data: function () { var x = JSON.parse(JSON.stringify(O)); x.at = new Date().toISOString(); return x; }, pages: [\'itam-overview.html\'] }]);\n'
    + '  var X = ' + JSON.stringify(extra) + ', at = ' + JSON.stringify(new Date().toISOString()) + ', d = Date.now() - Date.parse(at);\n'
    + '  var mv = function (x) { if (Array.isArray(x)) return x.map(mv); if (x && typeof x === "object") { for (var k in x) { var v = x[k]; if (typeof v === "number" && v > 1.5e12 && v < 2.5e12) x[k] = v + d; else if (v && typeof v === "object") mv(v); } } return x; };\n'
    + '  var MORE = ' + JSON.stringify(MORE) + ';\n'
    + '  window.ZYB_POC = window.ZYB_POC.concat(MORE.map(function (e) { var re = new RegExp("^" + e[0].replace(/[.*+?^${}()|[\\]\\\\/]/g, "\\\\$&") + "$"); return { re: re, data: function () { return mv(JSON.parse(JSON.stringify(e[1]))); }, pages: [e[2]] }; }));\n'
    + '  window.ZYB_POC = window.ZYB_POC.concat(X.map(function (e) { var re = new RegExp("^" + e[0].replace(/[.*+?^${}()|[\\]\\\\/]/g, "\\\\$&") + "$"); return { re: re, data: function () { return mv(JSON.parse(JSON.stringify(e[1]))); }, pages: ' + JSON.stringify(IM) + ' }; }));\n})();\n';
  fs.writeFileSync(path.join(ROOT, 'ui/vendor/zyb-poc-itam.js'), out);
  console.log('wrote ui/vendor/zyb-poc-itam.js: ' + n + ' synthetic assets, ' + Math.round(out.length / 1024) + ' KB, sites ' + (r.json.breakdown.sites_all || []).length);
  await e.close(); process.exit(0);
})().catch((x) => { console.error(x); process.exit(1); });
