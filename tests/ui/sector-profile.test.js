// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for the organisation's sector profile (brand/brand.json: modules_off, pages_off, frameworks) and the brand
// itself on the home page: what the brand setting switches off is gone from the menu and the page registry for EVERY role
// (administrators included), opening such a page says why, a module comes back when an administrator adds it in Modules &
// Solutions, a page in pages_off stays off, and everything else stays. The other page tests run with nothing switched off
// (tools/run-tests.sh), so this test builds its own page copy of the REAL brand setting. Stub APIs, synthetic data only.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node sector-profile.test.js
const http = require('http'), fs = require('fs'), os = require('os'), path = require('path'), { execFileSync } = require('child_process');
const ZYB_ORG = require('../../brand/index');
const ROOT = path.resolve(__dirname, '../..'), DASH = path.join(ROOT, 'ui');
let n = 0, bad = 0;
const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };

(async () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'sector-')), ORGJS = path.join(tmp, 'zyb-org.js');
  execFileSync(process.execPath, [path.join(ROOT, 'tools/brand/apply-brand.js'), '--ui-out', ORGJS]);
  let ROLE = 'admin', ORGMODS = null;
  const srv = http.createServer((req, res) => {
    const u = decodeURIComponent(req.url.split('?')[0]), json = (c, o) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(o)); };
    if (u === '/dashboards/whoami.json' || u === '/auth/whoami') return json(200, { user: 'admin.syn', role: ROLE });
    if (u === '/auth/org') return ORGMODS ? json(200, { modules: ORGMODS, updated: new Date().toISOString() }) : json(200, {});
    if (u.startsWith('/api/') || u.startsWith('/auth/')) return json(404, { error: 'not in this test' });
    const rel = u === '/' ? '/index.html' : u.replace(/^\/dashboards\//, '/');
    const f = rel === '/vendor/zyb-org.js' ? ORGJS : path.join(DASH, rel);
    if (f !== ORGJS && !f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (e, d) => { if (e) { res.writeHead(404); return res.end(); } res.writeHead(200, { 'Content-Type': u.endsWith('.js') ? 'application/javascript' : u.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port + '/dashboards/';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  const open = async (file) => { const ctx = await browser.newContext({ viewport: { width: 1400, height: 1000 } }), page = await ctx.newPage(); page.on('pageerror', (e) => errs.push(file + ': ' + e.message)); await page.goto(base + file); await page.waitForFunction(() => window.ZybModules && window.ZYB_ORG); await page.waitForTimeout(700); return page; };
  const offOf = (page, files) => page.evaluate((fs_) => fs_.map((f) => window.ZybModules.off(f)), files);

  // ---- the brand setting has a profile to test at all
  ok(ZYB_ORG.modules_off.length > 0 && ZYB_ORG.frameworks.length > 0, 'the brand setting names the frameworks and what is switched off');

  for (const role of ['admin', 'operator', 'viewer']) {
    ROLE = role; ORGMODS = null;
    const page = await open('index.html');
    const reg = await page.evaluate(() => ({ byMod: window.ZybModules.CAT.map((m) => [m[0], window.ZybModules.pagesOf(m[0]).map((p) => p.h)]), nav: window.ZYB_NAV.map((a) => [a.id, a.pages.map((p) => p.h)]) }));
    const listed = new Set(reg.nav.flatMap((a) => a[1]));
    // every page of a switched-off module, and every page in pages_off, is out of the registry the menu, search and home page use
    const offPages = reg.byMod.filter((m) => ZYB_ORG.modules_off.includes(m[0])).flatMap((m) => m[1]).concat(ZYB_ORG.pages_off.map((k) => k + '.html'));
    ok(offPages.length >= ZYB_ORG.pages_off.length && offPages.every((h) => !listed.has(h)), role + ': no switched-off page is left in the page registry: ' + offPages.filter((h) => listed.has(h)).join(', '));
    ok((await offOf(page, offPages)).every(Boolean), role + ': every switched-off page reports off');
    // the frameworks and the estate that DO apply stay
    const keep = ['nca-ecc.html', 'iso27001.html', 'pdpl-dashboard.html', 'ndmo.html', 'virtualization.html', 'm365.html', 'network-map.html', 'soc-overview.html', 'risk-studio.html'];
    ok((await offOf(page, keep)).every((x) => !x) && keep.every((h) => listed.has(h)), role + ': the pages that apply are still there');
    // the menu drawn on the page offers none of them
    const links = await page.evaluate(() => [...document.querySelectorAll('#zyb-side a[href], [data-zyb-href]')].filter((a) => (a.closest('li') || a).style.display !== 'none').map((a) => (a.getAttribute('data-zyb-href') || a.getAttribute('href') || '').split(/[?#]/)[0].split('/').pop()));
    ok(links.length > 20 && offPages.every((h) => !links.includes(h)), role + ': the menu has no link to a switched-off page (' + links.length + ' links)');
    // tiles and links inside the page: none to a switched-off page is visible
    const shown = await page.evaluate(() => [...document.querySelectorAll('main a[href]')].filter((a) => a.offsetParent !== null).map((a) => (a.getAttribute('href') || '').split(/[?#]/)[0].split('/').pop()));
    ok(offPages.every((h) => !shown.includes(h)), role + ': the home page shows no tile or link to a switched-off page: ' + offPages.filter((h) => shown.includes(h)).join(', '));
    await page.context().close();
  }

  // ---- opening a switched-off page directly says why (administrator too)
  ROLE = 'admin'; ORGMODS = null;
  const firstOff = ZYB_ORG.pages_off[0] + '.html';
  let p = await open(firstOff);
  ok(await p.evaluate(() => !!document.querySelector('[data-zyb-sub-blocked]') && /Not used in this organisation/.test(document.body.textContent)), 'a switched-off page opened directly says it is not used in this organisation');
  await p.context().close();

  // ---- Modules & Solutions offers only what applies: a switched-off module, and one whose pages are all off, is not in the
  // catalogue or in any ready-made solution; the frameworks that apply stay
  // who each framework covers (brand setting framework_scope): the NCA ECC page says the company only
  { const q = await open('nca-ecc.html'); await q.waitForSelector('#ncascope:not([hidden])', { timeout: 8000 }).catch(() => {}); const t = await q.$eval('#ncascope', (x) => (x.hidden ? '' : x.textContent)).catch(() => '');
    ok(ZYB_ORG.framework_scope && t.includes(ZYB_ORG.framework_scope.nca), 'the NCA ECC page states its scope: ' + t); await q.context().close(); }
  // Live Compliance offers only the frameworks that apply: no SAMA / IA tab when their modules are off
  { const q = await open('live-compliance.html'); await q.waitForSelector('#fw option', { timeout: 8000 }).catch(() => {}); const opts = await q.$$eval('#fw option', (o) => o.map((x) => x.value)).catch(() => []);
    ok(opts.length && (!ZYB_ORG.modules_off.includes('fw-sama') || !opts.includes('sama')) && (!ZYB_ORG.modules_off.includes('fw-ia') || !opts.includes('ia')), 'Live Compliance frameworks: ' + opts.join(',')); await q.context().close(); }
  p = await open('index.html');
  const cat = await p.evaluate(() => window.ZybModules.CAT.map((m) => m[0])), sols = await p.evaluate(() => JSON.stringify(window.ZybModules.SOLUTIONS));
  ok(ZYB_ORG.modules_off.every((id) => !cat.includes(id)) && ZYB_ORG.modules_off.every((id) => !sols.includes('"' + id + '"')), 'switched-off modules are not offered: ' + ZYB_ORG.modules_off.filter((id) => cat.includes(id)).join(', '));
  ok(['fw-ecc', 'fw-pdpl', 'siem-core', 'net-mon'].every((id) => cat.includes(id)), 'the modules that apply are offered');
  ok((await offOf(p, ZYB_ORG.pages_off.map((k) => k + '.html'))).every(Boolean), 'pages in pages_off stay off');
  ok((await offOf(p, (await p.evaluate((ids) => ids.flatMap((id) => window.ZybModules.pagesOf(id).map((x) => x.h)), ZYB_ORG.modules_off)))).every(Boolean), 'the switched-off modules stay off');

  // ---- the brand on the home page: name, logo and frameworks come from the setting; no token is left on the page
  const home = await p.evaluate(() => ({ org: document.getElementById('orglogo') && (document.querySelector('#orglogo img') || {}).alt, foot: document.querySelector('footer').textContent, text: document.body.innerText, title: document.title, regs: document.getElementById('regs').getAttribute('aria-label') || '', look: document.documentElement.classList.contains('org-brand') }));
  ok(home.org === ZYB_ORG.name, 'the company logo carries the company name: ' + home.org);
  ok(home.foot.includes(ZYB_ORG.name), 'the footer names the company');
  ok(!/\{\{org\./.test(home.text + home.title), 'no brand token is left on the page');
  ok(/NCA/.test(home.regs) === ZYB_ORG.frameworks.includes('nca') && /SAMA/.test(home.regs) === ZYB_ORG.frameworks.includes('sama') && /Insurance/.test(home.regs) === ZYB_ORG.frameworks.includes('ia'), 'the frameworks shown are the ones in the brand setting: ' + home.regs);
  // the company look has two faces. The default is the dark one in the brand colour; the second is the light one: a light page with white
  // cards, the brand colour on the primary action, the company typeface on headlines, a light menu and top bar
  const rgb = (h) => 'rgb(' + [1, 3, 5].map((i) => parseInt(h.slice(i, i + 2), 16)).join(', ') + ')';
  const lookOf = () => p.evaluate(() => ({ cls: document.documentElement.className, dark: document.getElementById('orgBrand').media, light: document.getElementById('orgLight').media, bg: getComputedStyle(document.body).backgroundColor, btn: getComputedStyle(document.querySelector('main .btn.pri')).backgroundColor,
    font: getComputedStyle(document.querySelector('.greet')).fontFamily, foot: getComputedStyle(document.querySelector('footer.foot')).backgroundColor, side: getComputedStyle(document.getElementById('zyb-side')).backgroundColor, bar: getComputedStyle(document.getElementById('zyb-bar')).backgroundColor,
    sw: [document.getElementById('looksw').getAttribute('aria-checked'), document.querySelector('#zyb-side [data-zyb-looksw]').getAttribute('aria-checked')], pref: JSON.parse(localStorage.getItem('zyb-dash-prefs') || '{}').brandLook || '',
    tags: [...new Set([...document.querySelectorAll('main .fw *')].map((x) => (x.textContent || '').trim().split(' ')[0]).filter(Boolean))] }));
  let look = await lookOf();
  const lum = (c) => { const m = /(\d+), (\d+), (\d+)/.exec(c); return m ? (+m[1] + +m[2] + +m[3]) / 3 : 255; };
  if (ZYB_ORG.company_look !== false) {
    ok(look.dark === 'all' && look.light === 'not all' && !/org-light/.test(look.cls) && lum(look.bg) < 60 && lum(look.side) < 60 && look.btn === rgb(ZYB_ORG.colors.primary) && look.sw.join() === 'false,false', 'the default company look is the dark one in the brand colour: ' + JSON.stringify(look));
    await p.click('#looksw'); await p.waitForTimeout(400); look = await lookOf();
    ok(look.light === 'all' && look.dark === 'not all' && /org-light/.test(look.cls) && look.pref === 'light' && look.sw.join() === 'true,true', 'the Light switch turns on the website look, on the page and in the menu, and saves it: ' + JSON.stringify(look));
    ok(lum(look.bg) > 235 && look.btn === rgb(ZYB_ORG.colors.primary) && /^"?Raleway/.test(look.font) && look.side === 'rgb(255, 255, 255)' && look.bar === 'rgb(255, 255, 255)', 'the light look: a light page, white menu and top bar, the brand colour on the primary action, the company typeface on the headline: ' + JSON.stringify(look));
    await p.reload(); await p.waitForFunction(() => window.ZybModules && document.getElementById('zyb-side')); await p.waitForTimeout(500); look = await lookOf();
    ok(look.light === 'all' && /org-light/.test(look.cls), 'the light look is kept after a reload');
    await p.click('#zyb-side [data-zyb-looksw]'); await p.waitForTimeout(400); look = await lookOf();
    ok(look.dark === 'all' && look.light === 'not all' && look.pref === 'dark' && look.sw.join() === 'false,false' && lum(look.bg) < 60, 'the menu switch goes back to the dark look, and the page switch follows');
    await p.click('#brandsw'); await p.waitForTimeout(300); look = await lookOf();
    ok(look.dark === 'not all' && look.light === 'not all' && !/org-brand/.test(look.cls) && await p.evaluate(() => document.getElementById('looksw').hidden), 'company look off: the platform design, and the Light switch is not offered');
    await p.click('#brandsw'); await p.waitForTimeout(300);
  }
  ok(!look.tags.includes('SAMA') && !look.tags.includes('IA'), 'no framework tag outside the brand setting: ' + look.tags.join(', '));
  ok(home.look === (ZYB_ORG.company_look !== false), 'the company look is ' + (ZYB_ORG.company_look !== false ? 'on' : 'off') + ' by default');
  await p.context().close();

  ok(errs.length === 0, 'no page errors: ' + errs.join(' | '));
  await browser.close(); srv.close(); fs.rmSync(tmp, { recursive: true, force: true });
  console.log(bad ? 'FAILED ' + (n - bad) + '/' + n + ' checks' : 'ALL ' + n + ' checks passed');
  process.exit(bad ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });
