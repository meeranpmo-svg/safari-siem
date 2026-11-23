// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for job-role menu sections (vendor/zyb-modules.js + Roles & Functions): a role whose "All platform dashboards"
// is off sees only the sections of its functions - Desktop Support Engineer: Command Center, Workplace, IT Assets, Identity
// & M365; GRC Analyst: Command Center, Governance & Risk, Compliance, Data Privacy, Audit - plus their own My Work / My
// Workspace; a page outside the role says so instead of showing; an administrator and a role with every dashboard keep the
// full menu. Stubs in the shape of /auth/whoami, /auth/org and /api/itam/roles/me; SYNTHETIC names.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node role-sections.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const DASH = path.resolve(__dirname, '../../ui');
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const ALL = (v) => Object.fromEntries(['command', 'ai', 'soc', 'incidents', 'identity', 'vuln', 'compliance', 'audit', 'privacy', 'risk', 'network', 'servers', 'virtualization', 'windows', 'exchange', 'backup', 'assets', 'facilities', 'm365', 'admin', 'dashboards'].map((k) => [k, v]));
const DESK = { id: 'desktop-engineer', name: 'Desktop Support Engineer', base: 'operator', functions: Object.assign(ALL('none'), { command: 'view', facilities: 'manage', assets: 'view', m365: 'view' }) };
const GRC = { id: 'grc-analyst', name: 'GRC Analyst', base: 'operator', functions: Object.assign(ALL('none'), { command: 'view', compliance: 'manage', audit: 'manage', privacy: 'manage', risk: 'manage' }) };   // audit / privacy: as the built-in after the split from Compliance
const ONLY = (id, name, fn) => ({ id, name, base: 'operator', functions: Object.assign(ALL('none'), { [fn]: 'manage' }) });
const PEN = ONLY('pentest-engineer', 'Penetration Testing Engineer', 'vuln'), NET = ONLY('network-engineer', 'Network Engineer', 'network'),
  WIN = ONLY('windows-admin', 'Windows Server Admin', 'windows'), VIRT = ONLY('virtualization-admin', 'Virtualization Admin', 'virtualization'),
  EXC = ONLY('exchange-admin', 'Exchange Admin', 'exchange'), BAK = ONLY('backup-admin', 'Backup Admin', 'backup');
const SOC = { id: 'soc-analyst', name: 'SOC Analyst', base: 'operator', functions: Object.assign(ALL('none'), { soc: 'manage', dashboards: 'view' }) };
(async () => {
  let WHO = { user: 'rishil.syn', role: 'operator' }, ROLE = DESK;
  const srv = http.createServer((req, res) => { const u = req.url.split('?')[0];
    const j = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u === '/auth/whoami' || u === '/dashboards/whoami.json') return j(200, WHO);
    if (u === '/auth/org') return j(200, { modules: null, edition: 'Enterprise', updated: null });
    if (u === '/api/itam/roles/me') return j(200, { user: WHO.user, role: ROLE, functions: [] });
    if (u.startsWith('/api/') || u.startsWith('/auth/')) return j(404, { error: 'not in this test' });
    const f = path.join(DASH, u.replace(/^\/dashboards\//, '/')); if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (e, d) => { if (e) { res.writeHead(404); return res.end(); } res.writeHead(200, { 'Content-Type': f.endsWith('.js') ? 'application/javascript' : f.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); }); });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port + '/dashboards/';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  const open = async (page) => { const ctx = await browser.newContext({ viewport: { width: 1400, height: 900 } }); const p = await ctx.newPage(); p.on('pageerror', (e) => errs.push(e.message));
    await p.goto(base + page); await p.waitForFunction(() => { const s = window.ZybModules && window.ZybModules.state(); return s && 'areas' in s; }, null, { timeout: 15000 }); await p.waitForTimeout(400); return { p, ctx }; };
  const view = (p) => p.evaluate(() => ({ areas: window.ZybModules.state().areas, nav: window.ZYB_NAV.map((a) => a.id),
    side: [...document.querySelectorAll('#zyb-side .zs-area')].filter((x) => getComputedStyle(x).display !== 'none').map((x) => x.getAttribute('data-a')),
    blocked: (document.querySelector('[data-zyb-sub-blocked] [role=alert]') || {}).textContent || '' }));

  // Rishil - Desktop Support Engineer
  let { p, ctx } = await open('desktops.html'); let v = await view(p);
  ok(JSON.stringify(v.nav) === '["cmd","usr","eud","ast"]', 'desktop engineer menu: Command Center, Identity & M365, Workplace, IT Assets: ' + v.nav);
  ok(v.side.length && v.side.every((a) => ['cmd', 'usr', 'eud', 'ast'].includes(a)), 'sidebar shows only those sections: ' + v.side);
  ok(!v.blocked, 'a desktop page opens');
  ok(await p.evaluate(() => !window.ZybModules.off('my-workspace.html') && !window.ZybModules.off('my-work.html') && window.ZybModules.off('soc-alerts.html')), 'own workspace pages always open; SOC is outside the role');
  await ctx.close();
  ({ p, ctx } = await open('network-engineer.html')); v = await view(p);
  ok(/Not part of your job role/.test(v.blocked) && /Desktop Support Engineer/.test(v.blocked) && /Roles & Functions/.test(v.blocked), 'a page outside the role says so and where to change it: ' + v.blocked);
  await ctx.close();

  // Noor - GRC Analyst
  WHO = { user: 'noor.syn', role: 'operator' }; ROLE = GRC;
  ({ p, ctx } = await open('grc-dashboard.html')); v = await view(p);
  ok(JSON.stringify(v.nav) === '["cmd","grc","cmp","pdpl","aud"]', 'GRC analyst menu: Command Center, Governance & Risk, Compliance, Data Privacy, Audit: ' + v.nav);
  ok(!v.blocked, 'a GRC page opens');
  await ctx.close();

  // one engineer, one set of modules
  const pagesOf = (p) => p.evaluate(() => Object.fromEntries(window.ZYB_NAV.map((a) => [a.id, a.pages.map((x) => x.h.replace('.html', ''))])));
  WHO = { user: 'omar.syn', role: 'operator' }; ROLE = PEN;
  ({ p, ctx } = await open('vapt-center.html')); v = await view(p);
  // every role keeps its own workspace pages and Workflow Automation (requests to and from the IT teams, zyb-modules.js OWN)
  const own = async () => JSON.stringify((await pagesOf(p)).cmd) === '["my-workspace","my-work","workflow-automation"]';
  ok(JSON.stringify(v.nav) === '["cmd","pt"]' && await own() && !v.blocked, 'penetration testing engineer: Pentest & VAPT, and of Command Center only My Work / My Workspace / Workflow Automation: ' + v.nav);
  ok(await p.evaluate(() => window.ZybModules.off('network-dashboard.html') && window.ZybModules.off('executive-dashboard.html') && !window.ZybModules.off('my-work.html')), 'pentest: network and executive pages off, My Work stays');
  await ctx.close();
  ROLE = NET; ({ p, ctx } = await open('vsphere-studio.html')); v = await view(p);
  ok(JSON.stringify(v.nav) === '["cmd","net"]' && await own() && /Not part of your job role/.test(v.blocked) && /Network Engineer/.test(v.blocked), 'network engineer: only Network; a virtualization page is refused: ' + v.nav);
  await ctx.close();
  ROLE = WIN; ({ p, ctx } = await open('windows-servers.html')); v = await view(p); let pg = await pagesOf(p);
  ok(!v.blocked && JSON.stringify(v.nav) === '["cmd","usr","srv","ai"]' && JSON.stringify(pg.srv) === '["server-availability","windows-servers","remote-console","capacity"]' && JSON.stringify(pg.usr) === '["ad-exchange"]' && JSON.stringify(pg.ai) === '["windows-admin"]',
    'windows admin: only the Windows pages (their AI Windows Admin in the AI section), not the whole Servers section: ' + JSON.stringify(pg));
  ok(await p.evaluate(() => window.ZybModules.off('vmware-servers.html') && window.ZybModules.off('exchange-servers.html') && window.ZybModules.off('db-dashboard.html') && window.ZybModules.off('backup.html')), 'windows admin: VMware, Exchange, databases and backup are off');
  ok(v.side.length && v.side.every((a) => ['cmd', 'usr', 'srv', 'ai'].includes(a)), 'windows admin sidebar: only sections holding their pages: ' + v.side);
  await ctx.close();
  ({ p, ctx } = await open('vmware-servers.html')); v = await view(p); ok(/Not part of your job role/.test(v.blocked), 'windows admin opening a VMware page directly is refused'); await ctx.close();
  ROLE = VIRT; ({ p, ctx } = await open('nutanix-vms.html')); v = await view(p); pg = await pagesOf(p);
  ok(!v.blocked && pg.srv.includes('vsphere-studio') && pg.srv.includes('virt-power') && !pg.srv.includes('windows-servers') && JSON.stringify(pg.stor) === '["dr-replication"]', 'virtualization admin: VMware / Nutanix pages and DR replication only: ' + JSON.stringify(pg));
  await ctx.close();
  ROLE = EXC; ({ p, ctx } = await open('exchange-servers.html')); v = await view(p); pg = await pagesOf(p);
  ok(!v.blocked && (pg.ai || []).includes('exchange-admin') && pg.usr.includes('exchange-hybrid') && pg.eps.includes('email-route-map') && !pg.eps.includes('dlp') && !pg.srv.includes('windows-servers'), 'exchange admin: Exchange and mail pages only: ' + JSON.stringify(pg));
  await ctx.close();
  ROLE = BAK; ({ p, ctx } = await open('backup.html')); v = await view(p); pg = await pagesOf(p);
  ok(!v.blocked && JSON.stringify(pg.stor) === '["storage","backup","dr-studio","dr-replication","dr-drills"]' && JSON.stringify(pg.srv) === '["server-availability"]', 'backup admin: Storage & Backup and server availability only: ' + JSON.stringify(pg));
  await ctx.close();

  // a role with every dashboard, and an administrator, keep the full menu
  WHO = { user: 'sara.syn', role: 'operator' }; ROLE = SOC;
  ({ p, ctx } = await open('soc-alerts.html')); v = await view(p); ok(v.areas === null && v.nav.length === 19, 'All platform dashboards on: every section, Business Risk included (' + v.nav.length + ')'); await ctx.close();
  WHO = { user: 'syed.syn', role: 'admin' }; ROLE = DESK;
  ({ p, ctx } = await open('network-engineer.html')); v = await view(p); ok(v.nav.length === 19 && !v.blocked, 'an administrator always sees everything (' + v.nav.length + ')'); await ctx.close();

  ok(!errs.length, 'page errors: ' + errs.join(' | '));
  await browser.close(); srv.close();
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks'); process.exit(bad ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });
