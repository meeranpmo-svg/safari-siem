// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// The organisation's branded menu (vendor/zyb-color.css, the logo card in vendor/zyb-dash.js): with its colours on, the menu shows
// the organisation's logo on a card, a brand-navy menu (blue over red), the current page in the brand primary colour, brand-tinted
// section labels; every page's header a brand banner and its colours (pages and charts) in the brand navy family; the light look a white menu with the same identity; with its colours off none of it (no logo card).
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node brand-menu.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const DASH = path.resolve(__dirname, '../../ui'), ZYB_ORG = require('../../brand/index');
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const rgb = (h) => 'rgb(' + [1, 3, 5].map((i) => parseInt(h.slice(i, i + 2), 16)).join(', ') + ')';
(async () => {
  let NOCSS = false;
  const srv = http.createServer((q, r) => { const u = decodeURIComponent(q.url.split('?')[0]), j = (c, o) => { r.writeHead(c, { 'Content-Type': 'application/json' }); r.end(JSON.stringify(o)); };
    if (NOCSS && /zyb-color\.css$/.test(u)) { r.writeHead(404); return r.end(); }
    if (u.endsWith('whoami.json')) return j(200, { user: 'syed', role: 'admin' }); if (u.startsWith('/api/')) return j(404, { error: 'not in this test' });
    fs.readFile(path.join(DASH, u.replace(/^\/dashboards\//, '/')), (e, d) => { if (e) { r.writeHead(404); return r.end(); } r.writeHead(200, { 'Content-Type': u.endsWith('.js') ? 'application/javascript' : u.endsWith('.css') ? 'text/css' : 'text/html' }); r.end(d); }); });
  await new Promise((res) => srv.listen(0, '127.0.0.1', res));
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright'); const browser = await chromium.launch(), errs = [];
  const look = async (prefs) => {
    const ctx = await browser.newContext({ viewport: { width: 1400, height: 900 } });
    await ctx.addInitScript((p) => { try { localStorage.setItem('zyb-dash-prefs', JSON.stringify(p)); } catch (e) { /* none */ } }, prefs);
    const p = await ctx.newPage(); p.on('pageerror', (e) => errs.push(e.message));
    await p.goto('http://127.0.0.1:' + srv.address().port + '/dashboards/ops-command.html'); await p.waitForSelector('#zyb-side .zs-it.on', { timeout: 15000 }); await p.waitForTimeout(500);
    const s = await p.evaluate(() => { const g = (sel) => document.querySelector(sel), cs = (el) => el ? getComputedStyle(el) : null, card = g('#zyb-side .zs-orgcard'), on = g('#zyb-side .zs-it.on'), lbl = g('#zyb-side .zs-lbl');
      return { card: card ? cs(card).display : 'missing', img: card && card.querySelector('img') ? card.querySelector('img').naturalWidth : 0, alt: card && card.querySelector('img') ? card.querySelector('img').alt : '',
        side: cs(g('#zyb-side')).backgroundColor, top: cs(g('main > .top')).backgroundImage, h1: cs(g('main > .top h1')).color, body: cs(document.body).backgroundColor, acc: getComputedStyle(document.documentElement).getPropertyValue('--v-acc').trim(), sideImg: cs(g('#zyb-side')).backgroundImage, onImg: cs(on).backgroundImage, onColor: cs(on).color, lbl: cs(lbl).color }; });
    await ctx.close(); return s;
  };
  const prim = rgb(ZYB_ORG.colors.primary);
  let s = await look({ brand: 'org', brandLook: 'dark' });
  const ch = (c) => (c.replace(/^color\(srgb/, '').match(/[\d.]+/g) || []).map(Number);
  ok(s.card === 'flex' && s.img > 0 && s.alt === ZYB_ORG.name, 'the organisation\'s logo on a card in the menu: ' + JSON.stringify({ card: s.card, img: s.img, alt: s.alt }));
  ok(/gradient/.test(s.sideImg) && ch(s.side)[2] > ch(s.side)[0] && ch(s.side).slice(0, 3).reduce((a, b) => a + b) < 120, 'a dark brand-navy menu: ' + s.side);
  ok(s.onImg.includes(prim) && s.onColor === 'rgb(255, 255, 255)', 'the current page in the brand primary colour: ' + s.onImg.slice(0, 80));
  ok(ch(s.lbl)[2] > ch(s.lbl)[0], 'section labels brand-tinted: ' + s.lbl);
  ok(/gradient/.test(s.top) && s.h1 === 'rgb(255, 255, 255)', 'every page header is a brand banner with a white title: ' + s.top.slice(0, 90));
  ok(s.body === 'rgb(7, 19, 32)' && s.acc === '#3d9be9', 'pages and charts in the brand navy family (tokens re-tinted): ' + JSON.stringify({ body: s.body, acc: s.acc }));
  s = await look({ brand: 'org', brandLook: 'light' });
  ok(s.card === 'flex' && s.side === 'rgb(255, 255, 255)' && s.onImg.includes(prim) && s.lbl === prim, 'the light look: white menu, the same identity: ' + JSON.stringify({ side: s.side, lbl: s.lbl }));
  s = await look({ brand: 'off' });
  ok(s.card === 'none' && !s.onImg.includes(prim) && !/gradient/.test(s.top) && s.acc === '#5794f2', 'colours off: no logo card, no banner, the platform design and colours');
  // Safari's own palette: a tile with no status takes a brand-family colour (never the generic purple / pink)
  { const ctx = await browser.newContext({ viewport: { width: 1400, height: 900 } });
    await ctx.addInitScript(() => { try { localStorage.setItem('zyb-dash-prefs', JSON.stringify({ brand: 'org', brandLook: 'dark' })); } catch (e) { /* */ } });
    const p = await ctx.newPage(); p.on('pageerror', (e) => errs.push(e.message));
    await p.goto('http://127.0.0.1:' + srv.address().port + '/dashboards/ops-command.html'); await p.waitForSelector('#kp .t', { timeout: 15000 }); await p.waitForTimeout(500);
    const kc = await p.$$eval('#kp .t:not(.ok):not(.warn):not(.bad)', (L) => L.map((t) => getComputedStyle(t).getPropertyValue('--kc').trim().toLowerCase()));
    const FAM = ['#2f8fd8', '#19a7b8', '#4f7fd6', '#3fb6e8', '#6c9bd2'];
    ok(kc.length > 0 && kc.every((c) => FAM.includes(c)), 'neutral tiles in the Safari blue family: ' + kc.join(','));
    // an AI / ML label is tagged and drawn as the Safari AI badge
    await p.goto('http://127.0.0.1:' + srv.address().port + '/dashboards/network-geomap.html'); await p.waitForTimeout(900);
    const ai = await p.evaluate(() => { const e = [...document.querySelectorAll('h2 .c')].find((x) => /ML/.test(x.textContent)); return e ? { tagged: e.classList.contains('zyb-ai'), bg: getComputedStyle(e).backgroundColor, fg: getComputedStyle(e).color } : null; });
    ok(ai && ai.tagged && ai.bg === 'rgb(1, 87, 155)' && ai.fg === 'rgb(255, 255, 255)', 'AI / ML label shown as the Safari AI badge: ' + JSON.stringify(ai));
    const plain = await p.evaluate(() => [...document.querySelectorAll('.zyb-ai')].map((x) => x.textContent.trim()).filter((t) => !/\b(AI|ML|learned|anomal|forecast|machine learning)/i.test(t)));
    ok(!plain.length, 'nothing that is not about AI / ML is tagged: ' + plain.join(' | '));
    await ctx.close(); }
  // the branded stylesheet failing to load: the logo card stays hidden (never a giant logo in the menu)
  NOCSS = true;
  { const ctx = await browser.newContext({ viewport: { width: 1400, height: 900 } });
    await ctx.addInitScript(() => { try { localStorage.setItem('zyb-dash-prefs', JSON.stringify({ brand: 'org', brandLook: 'dark' })); } catch (e) { /* */ } });
    const p = await ctx.newPage(); await p.goto('http://127.0.0.1:' + srv.address().port + '/dashboards/ops-command.html'); await p.waitForSelector('#zyb-side', { timeout: 15000 }); await p.waitForTimeout(500);
    const vis = await p.evaluate(() => { const c = document.querySelector('#zyb-side .zs-orgcard'); return c ? { disp: getComputedStyle(c).display, h: c.getBoundingClientRect().height } : null; });
    ok(vis && vis.disp === 'none', 'stylesheet missing: the logo card stays hidden: ' + JSON.stringify(vis)); await ctx.close(); }
  NOCSS = false;
  ok(!errs.length, 'page errors: ' + errs.join(' | '));
  await browser.close(); srv.close();
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks'); process.exit(bad ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });
