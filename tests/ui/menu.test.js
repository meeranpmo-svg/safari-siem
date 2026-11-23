// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for the menu categories (vendor/zyb-nav.js): every dashboard in exactly one of the plain areas (19 with Business Risk), each AI
// engineer inside its own area (AI Oracle DBA under Databases, AI Network Engineer under Network...), the home page showing
// every area with its pages, the dashboard sidebar opening only the area of the page you are on, and the AI Team page
// still listing every AI engineer now that they are spread over the areas. No API is needed: every /api call answers 404.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node menu.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const DASH = path.resolve(__dirname, '../../ui');

let n = 0, bad = 0;
const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };

(async () => {
  global.window = { ZYB_ORG: Object.assign({}, require('../../brand/index'), { frameworks_all: true }) }; eval(fs.readFileSync(path.join(DASH, 'vendor/zyb-nav.js'), 'utf8'));
  const G = window.ZYB_NAV, all = [].concat(...G.map((a) => a.pages.map((p) => p.h)));
  const area = (h) => (G.find((a) => a.pages.some((p) => p.h === h)) || {}).id;
  ok(G.length === 19, 'areas: ' + G.map((a) => a.id).join(' '));
  ok(new Set(all).size === all.length, 'a page in two areas');
  ok(all.every((h) => fs.existsSync(path.join(DASH, h))), 'a menu page with no file: ' + all.filter((h) => !fs.existsSync(path.join(DASH, h))));
  ok(new Set(G.map((a) => a.id)).size === G.length && G.every((a) => a.sn && a.name && a.c && a.icon && a.pages.length), 'every area has id, names, colour, icon and pages');
  const want = { 'ai-dba.html': 'ai', 'ai-sql-dba.html': 'ai', 'ai-app-manager.html': 'ai', 'network-engineer.html': 'ai', 'ai-security-engineer.html': 'ai', 'pentest.html': 'ai', 'vuln-scans.html': 'pt',
    'ai-ksc-engineer.html': 'ai', 'ai-zscaler-engineer.html': 'ai', 'windows-admin.html': 'ai', 'ai-virt-admin.html': 'ai', 'exchange-admin.html': 'ai', 'exchange-servers.html': 'srv',
    'desk-support.html': 'ai', 'printers.html': 'eud', 'uc.html': 'eud', 'ai-grc-consultant.html': 'ai', 'storage.html': 'stor', 'backup.html': 'stor', 'licence-audit.html': 'aud', 'audit-dashboard.html': 'aud', 'internal-audit-team.html': 'aud', 'audit-team.html': 'aud', 'cyber-audit-team.html': 'aud', 'it-audit.html': 'aud', 'audit-log.html': 'aud', 'ai-auditors.html': 'ai', 'ad-audit.html': 'aud', 'db-audit.html': 'aud', 'app-audit.html': 'aud', 'budget.html': 'ast',
    'connections.html': 'adm', 'roles.html': 'adm', 'user-management.html': 'adm', 'my-work.html': 'cmd' };
  for (const [h, a] of Object.entries(want)) ok(area(h) === a, h + ' should be in ' + a + ', is in ' + area(h));
  // AI is kept apart from the main menu: one area, under its own heading, last - and every AI page is in it, nowhere else
  const AI = G[G.length - 1];
  ok(AI.id === 'ai' && AI.hd === 'ai' && G.filter((a) => a.hd === 'ai').length === 1 && (window.ZYB_HEADS || []).some((x) => x[0] === 'ai' && x[1] === 'Artificial Intelligence'), 'the AI area is last, under its own "Artificial Intelligence" heading');
  const strayAi = G.filter((a) => a.id !== 'ai').flatMap((a) => a.pages.filter((p) => /^ai-/.test(p.h) || /^AI\b/.test(p.s)).map((p) => a.id + ':' + p.h));
  ok(!strayAi.length, 'an AI page outside the AI area: ' + strayAi.join(', '));
  ok(AI.pages.every((p) => p.g), 'every AI page sits in a group of the AI area');
  const aiPages = G.flatMap((a) => a.pages.filter((p) => p.h !== 'ai-team.html' && (a.id === 'ai' || /^AI\b/.test(p.s))).map((p) => p.h));
  const lang = fs.readFileSync(path.join(DASH, 'vendor/zyb-lang.js'), 'utf8');
  ok(G.every((a) => lang.includes("'" + a.sn + "':") && lang.includes("'" + a.name + "':")), 'Arabic label missing for an area: ' + G.filter((a) => !lang.includes("'" + a.sn + "':") || !lang.includes("'" + a.name + "':")).map((a) => a.id));

  // compliance tags: every page carries fw {sama, nca, pdpl, ia} and every code is a domain of its framework (zyb-nav.js ZYB_FW)
  const FW = window.ZYB_FW, pages = G.flatMap((a) => a.pages);
  ok(FW && ['sama', 'nca', 'pdpl', 'ia'].every((k) => FW[k] && FW[k].short && FW[k].c), 'ZYB_FW has sama, nca, pdpl, ia');
  ok(pages.every((p) => p.fw && ['sama', 'nca', 'pdpl', 'ia'].every((k) => Array.isArray(p.fw[k]))), 'a page without fw: ' + pages.filter((p) => !p.fw).map((p) => p.h));
  const badCode = pages.flatMap((p) => ['sama', 'nca', 'pdpl', 'ia'].flatMap((k) => ((p.fw || {})[k] || []).filter((c) => !FW[k].domains[c]).map((c) => p.h + ' ' + k + ' ' + c)));
  ok(!badCode.length, 'unknown framework code: ' + badCode.join(', '));
  ok(pages.every((p) => p.fw.sama.length && p.fw.nca.length), 'a page with no SAMA or NCA domain: ' + pages.filter((p) => !p.fw.sama.length || !p.fw.nca.length).map((p) => p.h));
  ok(!FW.ia.pending && FW.ia.baseline === 'sama' && FW.ia.domains['IA-277'] && Object.keys(FW.sama.domains).every((c) => FW.ia.domains[c]) && pages.every((p) => JSON.stringify(p.fw.ia) === JSON.stringify(p.fw.sama)), 'IA = SAMA CSF baseline + IA-277 (circular UTC/277/202401); each page IA = its SAMA codes');
  ok(area('compliance-map.html') === 'cmp', 'Compliance Map in Compliance & Frameworks');

  const srv = http.createServer((req, res) => {
    const u = decodeURIComponent(req.url.split('?')[0]);
    if (u === '/dashboards/whoami.json') { res.writeHead(200, { 'Content-Type': 'application/json' }); res.end('{"user":"syed","role":"admin"}'); return; }
    if (u.startsWith('/api/')) { res.writeHead(404, { 'Content-Type': 'application/json' }); res.end('{"error":"not in this test"}'); return; }
    const f = path.join(DASH, u === '/' ? 'index.html' : u);
    if (!f.startsWith(DASH)) { res.writeHead(403); res.end(); return; }
    fs.readFile(f, (err, d) => { if (err) { res.writeHead(404); res.end(); return; } res.writeHead(200, { 'Content-Type': u.endsWith('.js') ? 'application/javascript' : u.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port + '/';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch();
  const page = await browser.newPage({ viewport: { width: 1400, height: 900 } }); const errs = [];
  page.on('pageerror', (e) => errs.push(e.message));

  // home page: one section and one filter chip per area, every page as a card
  await page.goto(base + 'index.html'); await page.waitForSelector('.grp');
  const home = await page.evaluate(() => ({ secs: [...document.querySelectorAll('.grp')].map((s) => s.getAttribute('data-sec')), chips: document.querySelectorAll('.chip[data-f]').length, cards: document.querySelectorAll('.dc').length, ai: [...document.querySelectorAll('[data-sec="ai"] .dc')].map((a) => a.getAttribute('href')), db: [...document.querySelectorAll('[data-sec="db"] .dc')].map((a) => a.getAttribute('href')) }));
  ok(JSON.stringify(home.secs.filter((s) => s !== 'portal')) === JSON.stringify(G.map((a) => a.id)), 'home sections in menu order: ' + home.secs);
  ok(home.chips === G.length + 1, 'home chips: ' + home.chips);
  ok(home.cards >= all.length, 'home cards: ' + home.cards);
  ok(home.db.includes('oracle-tuning.html') && !home.db.includes('ai-dba.html'), 'Databases section (the AI DBA is in the AI section): ' + home.db);
  ok(home.secs.filter((s) => s !== 'portal').pop() === 'ai' && home.ai.some((h) => /ai-dba\.html/.test(h)), 'the AI section is last on the home page and holds the AI DBA: ' + home.ai);
  // landing page: 15 workspace cards, quick actions, and live tiles that say "not installed" (every /api answers 404 here)
  await page.waitForFunction(() => [...document.querySelectorAll('.st .v')].every((v) => !/Loading/.test(v.textContent)), null, { timeout: 8000 }).catch(() => {});
  const land = await page.evaluate(() => ({ ws: document.querySelectorAll('.wk').length, qa: document.querySelectorAll('.qa').length, tiles: [...document.querySelectorAll('.st .v')].filter((v) => !v.closest('#grc')).map((v) => v.textContent), grc: [...document.querySelectorAll('#grc .st .v')].map((v) => v.textContent), greet: document.getElementById('greet').textContent }));
  ok(land.ws === G.length, 'workspace cards: ' + land.ws);
  ok(land.qa >= 3, 'quick actions: ' + land.qa);
  ok(land.tiles.length === 5 && land.tiles.every((t) => t === 'not installed'), 'live tiles honest with no source: ' + land.tiles);
  ok(land.grc.length === 5 && land.grc.every((t) => t === 'not installed'), 'Enterprise Risk & Compliance tiles honest with no source: ' + land.grc);
  ok(/^Good (morning|afternoon|evening), syed\.$/.test(land.greet), 'greeting with the signed-in name: ' + land.greet);
  await page.click('.wk[data-ws="db"] .hd');
  const vis0 = await page.evaluate(() => [...document.querySelectorAll('.grp')].filter((s) => s.offsetParent !== null).map((s) => s.getAttribute('data-sec')));
  ok(JSON.stringify(vis0) === '["db"]', 'a workspace card filters the directory to its area: ' + vis0);
  await page.click('.chip[data-f="eps"]');
  const vis = await page.evaluate(() => [...document.querySelectorAll('.grp')].filter((s) => s.offsetParent !== null).map((s) => s.getAttribute('data-sec')));
  ok(JSON.stringify(vis) === '["eps"]', 'the Endpoint & Email chip shows only that area: ' + vis);

  // dashboard sidebar: 15 areas, only the area of this page open, the page highlighted
  await page.goto(base + 'storage.html'); await page.waitForSelector('#zyb-side .zs-area');
  const side = await page.evaluate(() => ({ areas: [...document.querySelectorAll('#zyb-side .zs-area')].map((a) => a.getAttribute('data-a')).filter((a) => !/^p\d+$/.test(a)), open: [...document.querySelectorAll('#zyb-side .zs-area.open')].map((a) => a.getAttribute('data-a')), on: (document.querySelector('#zyb-side .zs-it.on') || {}).textContent, n: (document.querySelector('#zyb-side .zs-area[data-a="stor"] .zs-n') || {}).textContent }));
  ok(side.areas.length === 19, 'sidebar areas: ' + side.areas);
  // departments: Data privacy and Audit & assurance each stand on their own, after Governance & compliance
  const lbl = await page.evaluate(() => [...document.querySelectorAll('#zyb-side .zs-lbl')].map((x) => x.textContent));
  ok(lbl.join('|').includes('Governance & compliance|Data privacy|Audit & assurance|Administration'), 'separate departments: ' + lbl.join(' | '));
  const sgs = await page.evaluate(() => ['grc', 'srv', 'aud'].map((a) => [...document.querySelectorAll('#zyb-side .zs-area[data-a="' + a + '"] .zs-sg')].map((x) => x.textContent).join()));
  ok(sgs[0] === 'Overview,Identify & assess,Treat & track,Registers & reports,Policies & roles' && sgs[1] === 'Servers,Mail servers,Server administration,Virtualization,Capacity & power' && sgs[2] === 'Overview,Regulator audits,Audit teams,Technical audits,Audit evidence', 'sidebar sub-menus: ' + sgs.join(' / '));
  // sidebar sub-menu headings: a coloured icon each, open / hide their pages, remembered across pages; the filter shows all
  const sgx = async () => page.evaluate(() => { const w = document.querySelector('#zyb-side .zs-area[data-a="srv"] .zs-sgw[data-sg="srv|Virtualization"]');
    return { icon: !!w.querySelector('.zs-sgv') && !!w.style.getPropertyValue('--sc'), shut: w.classList.contains('shut'), shown: getComputedStyle(w.querySelector('.zs-sgb')).display !== 'none', n: document.querySelectorAll('#zyb-side .zs-area[data-a="srv"] .zs-sgw').length }; });
  const sg0 = await sgx();
  await page.evaluate(() => document.querySelector('#zyb-side .zs-sgw[data-sg="srv|Virtualization"] .zs-sg').click());
  const sg1 = await sgx(); await page.reload(); await page.waitForSelector('#zyb-side .zs-area'); const sg2 = await sgx();
  await page.fill('#zs-q', 'nutanix'); await page.waitForTimeout(100); const sg3 = await sgx(); await page.fill('#zs-q', '');
  await page.evaluate(() => document.querySelector('#zyb-side .zs-sgw[data-sg="srv|Virtualization"] .zs-sg').click()); const sg4 = await sgx();
  ok(sg0.n === 5 && sg0.icon && !sg0.shut && sg0.shown && sg1.shut && !sg1.shown && sg2.shut && sg3.shown && !sg4.shut, 'sidebar sub-menu heading: icon, open / hide, remembered, filter shows all: ' + JSON.stringify([sg0, sg1, sg2, sg3, sg4]));
  const dbItems = await page.evaluate(() => [...document.querySelectorAll('#zyb-side .zs-area[data-a="db"] a.zs-it')].map((x) => x.getAttribute('href') || ''));
  ok(dbItems.some((h) => /db-dashboard\.html/.test(h)) && dbItems.some((h) => /db-morning\.html/.test(h)), 'sidebar Databases area lists the Database Dashboard: ' + dbItems.join(','));
  ok(JSON.stringify(side.open) === '["stor"]', 'only Storage & Backup open on the storage page: ' + side.open);
  ok(/Storage/.test(side.on || '') && side.n === '5', 'storage page highlighted, area count 5: ' + side.on + ' / ' + side.n);

  // AI Team page: every AI engineer from every area
  await page.goto(base + 'ai-team.html'); await page.waitForFunction(() => document.querySelectorAll('#allai a').length > 0, null, { timeout: 8000 }).catch(() => {});
  const ai = await page.evaluate(() => [...document.querySelectorAll('#allai tbody tr')].map((r) => [r.querySelector('a').getAttribute('href'), r.cells[2].textContent]));
  const hrefs = ai.map((r) => r[0]);
  ok(aiPages.length >= 13 && aiPages.every((h) => hrefs.includes(h)), 'AI Team lists every AI engineer: missing ' + aiPages.filter((h) => !hrefs.includes(h)));
  ok((ai.find((r) => r[0] === 'ai-dba.html') || [])[1] === 'Infrastructure engineers', 'AI Oracle DBA shown with its group: ' + JSON.stringify(ai.find((r) => r[0] === 'ai-dba.html')));

  ok(!errs.length, 'page errors: ' + errs.join(' | '));
  await browser.close(); srv.close();
  console.log(bad ? 'FAILED ' + bad + ' of ' + n : 'OK ' + n + ' checks'); process.exit(bad ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });
