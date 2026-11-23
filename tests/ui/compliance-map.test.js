// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for the compliance tags (vendor/zyb-nav.js ZYB_FW + page fw): the home page shows each card's SAMA / NCA /
// PDPL codes, filters by framework and finds a page by its code; the dashboard breadcrumb shows the page's tags with the
// domain names on hover and links to the map; compliance-map.html lists every domain with the pages that support it, the
// domains with no page, IA through the SAMA CSF baseline (circular UTC/277/202401), every page's tags, and exports it to Excel. No API is needed: /api answers 404.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node compliance-map.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const DASH = path.resolve(__dirname, '../../ui');

let n = 0, bad = 0;
const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };

(async () => {
  global.window = { ZYB_ORG: require('../../brand/index') }; eval(fs.readFileSync(path.join(DASH, 'vendor/zyb-nav.js'), 'utf8'));
  const G = window.ZYB_NAV, FW = window.ZYB_FW, pages = G.flatMap((a) => a.pages);
  const withK = (k) => pages.filter((p) => p.fw[k].length).length;
  const cov = (k) => Object.keys(FW[k].domains).filter((c) => pages.some((p) => p.fw[k].includes(c))).length;

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
  const ctx = await browser.newContext({ viewport: { width: 1400, height: 900 }, acceptDownloads: true });
  const page = await ctx.newPage(); const errs = [];
  page.on('pageerror', (e) => errs.push(e.message));

  // home page: framework chips on the cards, framework filter, search by code
  await page.goto(base + 'index.html'); await page.waitForSelector('.dc .fwt');
  const card = await page.evaluate(() => { const c = document.querySelector('.dc[href="db-audit.html"]'); return { t: [...c.querySelectorAll('.fwt')].map((x) => x.textContent), tip: c.querySelector('.fwt').title }; });
  ok(card.t[0] === 'SAMA ' + pages.find((p) => p.h === 'db-audit.html').fw.sama.join(' · '), 'db-audit card SAMA chip: ' + card.t);
  ok(card.t.some((x) => /^PDPL 19\b/.test(x)) && card.t.some((x) => /^NCA 2-12/.test(x)), 'db-audit card NCA / PDPL chips: ' + card.t);
  ok(/Cyber Security Event Management/.test(card.tip), 'chip tooltip names the domain: ' + card.tip);
  const vis = () => page.evaluate(() => [...document.querySelectorAll('.dc[data-fw]')].filter((c) => !c.hidden).map((c) => c.getAttribute('href')));
  await page.click('.chip[data-fwf="pdpl"]');
  let v = await vis();
  ok(v.length === withK('pdpl') && v.includes('user-management.html'), 'PDPL filter: ' + v.length + ' of ' + withK('pdpl'));
  await page.click('.chip[data-fwf="ia"]');
  v = await vis(); ok(v.length === withK('ia') && v.length === withK('sama') && v.includes('db-audit.html'), 'IA filter = the SAMA pages: ' + v.length + ' of ' + withK('sama'));
  await page.click('.chip[data-fwf=""]');
  await page.fill('#q', '3.3.12');
  v = await vis();
  const p3312 = pages.filter((p) => p.fw.sama.includes('3.3.12')).map((p) => p.h);
  ok(JSON.stringify(v.sort()) === JSON.stringify(p3312.sort()), 'search by SAMA code finds exactly its pages: ' + v + ' / ' + p3312);
  await page.fill('#q', '');

  // breadcrumb on a dashboard: tags, domain names on hover, link to the map
  await page.goto(base + 'db-audit.html'); await page.waitForSelector('.zb-fw', { timeout: 8000 }).catch(() => {});
  const bc = await page.evaluate(() => { const a = document.querySelector('.zb-fw'); return a && { href: a.getAttribute('href'), t: a.textContent, tip: a.title, side: (document.querySelector('.zs-it[href="db-audit.html"]') || {}).title }; });
  ok(bc && bc.href === 'compliance-map.html#db-audit.html' && /^SAMANCAPDPLIA$/.test(bc.t) && /IA 3\.3\.14 - /.test(bc.tip) && /SAMA 3\.3\.14 - /.test(bc.tip), 'breadcrumb tags: ' + JSON.stringify(bc));
  ok(bc && /not a certification/.test(bc.tip) && /NCA 2-12 - /.test(bc.tip), 'breadcrumb tooltip: ' + (bc && bc.tip));
  ok(bc && /SAMA 3\.3\.14 - Cyber Security Event Management/.test(bc.side || ''), 'sidebar item tooltip has the domains: ' + (bc && bc.side));

  // the map: tiles, domain table with gaps, IA on the SAMA baseline, by page (from the breadcrumb link), Excel
  await page.goto(base + 'compliance-map.html'); await page.waitForSelector('#kk .t');
  const tl = await page.evaluate(() => [...document.querySelectorAll('#kk .t')].map((t) => t.querySelector('.l').textContent + '=' + t.querySelector('.v').textContent));
  const sTot = Object.keys(FW.sama.domains).length;
  ok(tl[0] === 'SAMA domains supported=' + cov('sama') + ' / ' + sTot, 'SAMA tile: ' + tl[0]);
  ok(tl.some((x) => /^IA domains supported=\d+ \/ 34$/.test(x)), 'IA tile: SAMA domains + IA-277: ' + tl);
  const rows = await page.evaluate(() => [...document.querySelectorAll('#body table tbody tr')].map((r) => [r.cells[0].textContent, r.cells[3].textContent]));
  ok(rows.length === sTot && rows.find((r) => r[0] === '3.3.14')[1] === String(pages.filter((p) => p.fw.sama.includes('3.3.14')).length), 'SAMA domain rows and page counts');
  // the tiles open what they count (they were plain boxes): a framework tile its tab, "Dashboards tagged" the pages
  const kt = await page.$$eval('#kk button.t[data-kt]', (b) => b.map((x) => x.getAttribute('data-kt')));
  ok(kt.length === tl.length && kt[kt.length - 1] === 'pages', 'every tile is a button: ' + kt.join(' '));
  const second = kt.find((k) => k !== 'sama' && k !== 'pages');
  await page.click('#kk button.t[data-kt="' + second + '"]'); ok(await page.evaluate((k) => !!document.querySelector('#tabs button.on[data-t="' + k + '"]'), second), 'a framework tile opens its tab: ' + second);
  await page.click('#kk button.t[data-kt="pages"]'); ok(await page.evaluate(() => !!document.querySelector('#tabs button.on[data-t="pages"]')), '"Dashboards tagged" opens the pages');
  await page.click('#kk button.t[data-kt="sama"]');
  const gaps = Object.keys(FW.sama.domains).filter((c) => !pages.some((p) => p.fw.sama.includes(c)));
  const gapUI = await page.evaluate(() => [...document.querySelectorAll('#body ul.plain li b')].map((b) => b.textContent));
  ok(JSON.stringify(gapUI) === JSON.stringify(gaps), 'domains with no page: ' + gapUI + ' / ' + gaps);
  await page.click('#tabs button[data-t="nca"]');
  ok(await page.evaluate(() => document.querySelectorAll('#body table tbody tr').length) === Object.keys(FW.nca.domains).length, 'NCA tab lists every sub-domain');
  await page.click('#tabs button[data-t="ia"]');
  ok(await page.evaluate(() => !/pending/i.test(document.getElementById('body').textContent) && /IA-277/.test(document.getElementById('body').textContent)), 'IA tab: SAMA domains plus IA-277, nothing pending');
  await page.goto(base + 'compliance-map.html#db-audit.html'); await page.waitForSelector('#hit');
  ok(await page.evaluate(() => document.querySelector('#tabs button.on').getAttribute('data-t') === 'pages' && document.querySelectorAll('#body tbody tr').length > 70), 'deep link opens By page with the row marked');
  await page.fill('#q', 'Art. 20');
  const art20 = pages.filter((p) => p.fw.pdpl.includes('Art. 20')).length;
  ok(await page.evaluate(() => document.querySelectorAll('#body tbody tr').length) === art20, 'By page filter by PDPL article: ' + art20);
  // search everywhere: ranked, typo-tolerant, highlighted, '/' to focus, fast
  await page.fill('#q', ''); await page.click('#tabs button[data-t="sama"]');
  ok(/Evidence depth/.test(await page.textContent('#body')) && (await page.$$('#body .dep div')).length === 4, 'evidence depth on the framework tab');
  ok(/Suggested evidence for uncovered domains/.test(await page.textContent('#body')), 'suggested evidence (text similarity) for uncovered domains');
  await page.keyboard.press('/'); ok(await page.evaluate(() => document.activeElement && document.activeElement.id === 'q'), '/ focuses the search');
  await page.keyboard.type('firewal');
  ok(await page.evaluate(() => document.querySelectorAll('#body a.ri[href]').length > 0 && /Firewall/i.test(document.querySelector('#body a.ri[href]').textContent)), 'a typo still finds the firewall dashboards, best match first');
  await page.fill('#q', 'database audit');
  ok(await page.evaluate(() => /Database Audit/.test(document.querySelector('#body a.ri[href]').textContent) && !!document.querySelector('#body mark')), 'ranked: the title match first, words highlighted');
  await page.fill('#q', '3.3.14');
  ok(/exact code/.test(await page.textContent('#qn')) && /SAMA 3\.3\.14/.test(await page.textContent('#body')), 'a code is matched exactly');
  const ms = await page.evaluate(() => { const q = document.getElementById('q'), t0 = performance.now(); for (let i = 0; i < 50; i++) { q.value = i % 2 ? 'log retention' : 'privileged access'; q.dispatchEvent(new Event('input')); } return (performance.now() - t0) / 50; });
  ok(ms < 60, 'search and redraw take ' + ms.toFixed(1) + ' ms on average');
  await page.fill('#q', ''); await page.click('#tabs button[data-t="matrix"]');
  ok(await page.evaluate(() => document.querySelectorAll('#body .hm2 tbody tr').length) === (await page.evaluate(() => window.ZYB_NAV.length)), 'matrix: one row per menu area');
  // graphics: the at-a-glance strip (one cell per domain, coloured by depth, a click goes to the row), depth bars, long lists folded
  await page.click('#tabs button[data-t="sama"]');
  const st = await page.evaluate(() => { const rows = document.querySelectorAll('#body tbody tr[id]'), cells = [...document.querySelectorAll('#body .strip a')];
    const big = [...rows].map((r) => ({ n: +r.querySelector('.dp b').textContent, a: r.querySelectorAll('.plist a').length, vis: [...r.querySelectorAll('.plist > a')].length, more: (r.querySelector('.plist summary') || {}).textContent })).sort((x, y) => y.n - x.n)[0];
    return { cells: cells.length, rows: rows.length, red: cells.filter((c) => /248, 81, 73/.test(c.style.background)).length, gaps: [...rows].filter((r) => r.querySelector('.dp b').textContent === '0').length, bars: document.querySelectorAll('#body .dp i').length, big }; });
  ok(st.cells === st.rows && st.cells >= 30 && st.red === st.gaps && st.bars === st.rows, 'at a glance: one cell per domain, the ones with no page red, a depth bar per row: ' + JSON.stringify(st).slice(0, 200));
  ok(st.big.vis === 8 && st.big.a === st.big.n && st.big.more === '+' + (st.big.n - 8) + ' more', 'a long list shows 8 pages, the rest one click away, none lost: ' + JSON.stringify(st.big));
  const tgt = await page.$eval('#body .strip a:nth-child(5)', (x) => x.getAttribute('data-jump')); await page.click('#body .strip a:nth-child(5)');
  ok(await page.evaluate((id) => document.getElementById(id).classList.contains('jump'), tgt), 'a strip cell goes to its row and marks it');
  if (process.env.SHOT) { await page.click('#tabs button[data-t="sama"]'); await page.screenshot({ path: process.env.SHOT, fullPage: true }); }
  const [dl] = await Promise.all([page.waitForEvent('download'), page.click('#xlsx')]);
  const buf = fs.readFileSync(await dl.path()), txt = buf.toString('latin1');
  ok(buf.slice(0, 2).toString() === 'PK' && /^compliance-map-\d{4}-\d\d-\d\d\.xlsx$/.test(dl.suggestedFilename()), 'xlsx: ' + dl.suggestedFilename());
  for (const sh of ['Summary', 'SAMA', 'NCA', 'PDPL', 'By page']) ok(txt.includes('name="' + sh + '"'), 'sheet ' + sh);
  ok(txt.includes('name="IA"'), 'IA sheet in the workbook');

  // the global Ctrl+K palette: one cached index, ranked, exact on a framework code, one typo tolerated
  await page.keyboard.press('Escape'); await page.locator('body').click({ position: { x: 5, y: 5 } }); await page.keyboard.press('Control+k');
  await page.waitForSelector('#zyb-pal:not([hidden])');
  const pal = async (v) => { await page.fill('#zp-q', v); return page.evaluate(() => [...document.querySelectorAll('#zp-l li')].map((li) => li.textContent)); };
  ok((await pal('compliance map')).length >= 1 && /compliance map/i.test((await pal('compliance map'))[0]), 'palette ranks the label first');
  ok((await pal('complience')).length >= 1, 'palette tolerates one typo');
  const pt = await page.evaluate(() => { const q = document.getElementById('zp-q'), t = performance.now(); for (let i = 0; i < 50; i++) { q.value = ['risk', 'audit', 'pdpl', 'firewal', 'nca ecc'][i % 5]; q.dispatchEvent(new Event('input')); } return (performance.now() - t) / 50; });
  ok(pt < 30, 'palette search takes ' + pt.toFixed(1) + ' ms on average');
  await page.keyboard.press('Escape');
  ok(!errs.length, 'page errors: ' + errs.join(' | '));
  await browser.close(); srv.close();
  console.log(bad ? 'FAILED ' + bad + ' of ' + n : 'OK ' + n + ' checks'); process.exit(bad ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });
