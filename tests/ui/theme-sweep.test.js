// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// The portal's theme switch on EVERY screen (vendor/zyb-theme.css + zyb-look.js): every dashboard page opened in ☀️ Light
// and ⬛ Midnight (localStorage noc_theme, the portal's key) must follow it - the page background is light / black, and no
// visible text is unreadable (contrast below 3:1 against what is really behind it). A theme change made while a page is
// open is followed live (storage event, the way the portal changes it around an embedded dashboard). The real portal: its
// Light option repaints the portal shell light too. Stub API (empty / not connected states), SYNTHETIC.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node theme-sweep.test.js [page.html …]
const http = require('http'), fs = require('fs'), path = require('path');
const DASH = path.resolve(__dirname, '../../ui'), LIVE = path.resolve(__dirname, '../../repos/live/portal');
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const ONLY = process.argv.slice(2);
const PAGES = (ONLY.length ? ONLY : fs.readdirSync(DASH).filter((f) => /\.html?$/.test(f) && !/^(oracle-licence-report|apm-claims-portal)\.html$/.test(f)));
// the contrast audit, run inside the page
function audit() {
  const rgb = (s) => { const m = /rgba?\(([^)]+)\)/.exec(s || ''); if (!m) return null; const p = m[1].split(/[ ,/]+/).filter(Boolean).map(Number); return { r: p[0], g: p[1], b: p[2], a: p.length > 3 ? p[3] : 1 }; };
  const lum = (c) => { const f = (v) => { v /= 255; return v <= 0.03928 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4); }; return 0.2126 * f(c.r) + 0.7152 * f(c.g) + 0.0722 * f(c.b); };
  const mix = (top, under) => ({ r: top.r * top.a + under.r * (1 - top.a), g: top.g * top.a + under.g * (1 - top.a), b: top.b * top.a + under.b * (1 - top.a), a: 1 });
  function bgOf(el) {   // composite the backgrounds from the root down to this element
    const chain = []; for (let x = el; x && x.nodeType === 1; x = x.parentElement) chain.unshift(x);
    let c = { r: 255, g: 255, b: 255, a: 1 }; const rootBg = rgb(getComputedStyle(document.documentElement).backgroundColor); if (rootBg && rootBg.a) c = mix(rootBg, c);
    for (const x of chain) { const st = getComputedStyle(x); if (st.backgroundImage && st.backgroundImage !== 'none' && /gradient|url/.test(st.backgroundImage)) return null; const b = rgb(st.backgroundColor); if (b && b.a > 0) c = mix(b, c); }
    return c;
  }
  const body = bgOf(document.body), issues = [];
  const els = document.querySelectorAll('body *');
  for (const el of els) {
    if (!el.childNodes.length || el.closest('svg,canvas,#zyb-err,.toast,.toast-zyb,[aria-hidden="true"]')) continue;
    let txt = ''; for (const n2 of el.childNodes) if (n2.nodeType === 3) txt += n2.nodeValue; txt = txt.trim(); if (!txt || txt.length < 2) continue;
    const st = getComputedStyle(el); if (st.visibility !== 'visible' || +st.opacity < 0.5) continue;
    const r = el.getBoundingClientRect(); if (r.width < 2 || r.height < 2 || r.bottom < 0 || r.top > 4000) continue;
    const fg = rgb(st.color), bg = bgOf(el); if (!fg || !bg) continue;
    const f2 = fg.a < 1 ? mix(fg, bg) : fg, L1 = lum(f2), L2 = lum(bg), ratio = (Math.max(L1, L2) + 0.05) / (Math.min(L1, L2) + 0.05);
    if (ratio < 3) issues.push((el.tagName.toLowerCase() + (el.className && typeof el.className === 'string' ? '.' + el.className.trim().split(/\s+/).slice(0, 2).join('.') : '')) + ' "' + txt.slice(0, 40) + '" ' + ratio.toFixed(2));
  }
  return { bodyLum: body ? lum(body) : null, theme: document.documentElement.getAttribute('data-zyb-theme'), bs: document.documentElement.getAttribute('data-bs-theme'), issues };
}
(async () => {
  const srv = http.createServer((req, res) => {
    const u = decodeURIComponent(req.url.split('?')[0]), json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u === '/dashboards/whoami.json' || u === '/auth/whoami') return json(200, { user: 'syed', role: 'admin' });
    if (u.startsWith('/api/soc/ui/menu')) return json(200, { order: null, favorites: [], can_edit_order: true });
    if (u.startsWith('/api/')) return json(404, { error: 'not in this test' });
    const f = u.startsWith('/dashboards/') ? path.join(DASH, u.slice(12)) : u === '/' ? path.join(LIVE, 'index.html') : path.join(LIVE, u);
    if (!f.startsWith(DASH) && !f.startsWith(LIVE)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (e, d) => { if (e) { res.writeHead(404); return res.end(); } res.writeHead(200, { 'Content-Type': f.endsWith('.js') ? 'application/javascript' : f.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port;
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright'); const browser = await chromium.launch();
  const summary = [];
  try {
    for (const theme of ['light', 'midnight']) {
      const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 } });
      await ctx.addInitScript((t) => { try { localStorage.setItem('noc_theme', t); } catch (e) { /* none */ } }, theme);
      for (const pg of PAGES) {
        const p = await ctx.newPage(); const errs = []; p.on('pageerror', (e) => errs.push(e.message));
        try { await p.goto(base + '/dashboards/' + pg + '?standalone=1', { waitUntil: 'load', timeout: 20000 }); } catch (e) { errs.push('load: ' + e.message); }
        await p.waitForTimeout(900);
        let a = null; try { a = await p.evaluate(audit); } catch (e) { errs.push('audit: ' + e.message); }
        if (a) {
          const okBg = theme === 'light' ? a.bodyLum > 0.75 : a.bodyLum < 0.02;
          ok(a.theme === theme && okBg, pg + ' [' + theme + ']: page follows the theme (data-zyb-theme ' + a.theme + ', background luminance ' + (a.bodyLum == null ? '?' : a.bodyLum.toFixed(3)) + ')');
          ok(!a.issues.length, pg + ' [' + theme + ']: ' + a.issues.length + ' unreadable text element(s): ' + (process.env.FULL ? a.issues : a.issues.slice(0, 6)).join(' | '));
          summary.push([theme, pg, a.issues.length]);
        }
        await p.close();
      }
      await ctx.close();
    }
    // a change while the page is open is followed live (the portal writes noc_theme; another document gets the storage event)
    const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 } });
    const a = await ctx.newPage(), b = await ctx.newPage();
    await a.goto(base + '/dashboards/connections.html?standalone=1'); await b.goto(base + '/dashboards/npm-summary.html?standalone=1'); await a.waitForTimeout(500);
    const t0 = await a.evaluate(() => document.documentElement.getAttribute('data-zyb-theme'));
    await b.evaluate(() => localStorage.setItem('noc_theme', 'light')); await a.waitForTimeout(400);
    const t1 = await a.evaluate(() => [document.documentElement.getAttribute('data-zyb-theme'), document.documentElement.getAttribute('data-bs-theme'), getComputedStyle(document.body).backgroundColor]);
    ok(t0 === 'dark' && t1[0] === 'light' && t1[1] === 'light' && /244, 245, 248/.test(t1[2]), 'an open page switches live when the theme changes elsewhere: ' + t0 + ' → ' + t1.join(' / '));
    await b.evaluate(() => localStorage.setItem('noc_theme', 'dark')); await a.waitForTimeout(500);
    const back = await a.evaluate(() => ({ t: document.documentElement.getAttribute('data-zyb-theme'), fix: !!document.getElementById('zyb-theme-fix'), marks: document.querySelectorAll('[data-zyb-tf]').length, bg: getComputedStyle(document.body).backgroundColor }));
    ok(back.t === 'dark' && !back.fix && back.marks === 0 && !/244, 245, 248/.test(back.bg), 'back to Dark NOC: every light fix is removed: ' + JSON.stringify(back));
    // an element inline() had already marked (white text on its own var() fill) is still made readable by the last safety net,
    // and going back restores its own inline colour exactly
    const m = await ctx.newPage(); await m.goto(base + '/dashboards/email-route-map.html?standalone=1'); await m.waitForTimeout(500);
    const doc0 = await m.$eval('#doc', (x) => x.style.cssText);
    await b.evaluate(() => localStorage.setItem('noc_theme', 'light')); await m.waitForTimeout(900);
    const docL = await m.evaluate(audit); ok(!docL.issues.some((x) => /Troubleshoot/.test(x)), 'light: the Troubleshoot button (white on its own fill) stays readable: ' + docL.issues.join(' | '));
    await b.evaluate(() => localStorage.setItem('noc_theme', 'dark')); await m.waitForTimeout(500);
    const doc1 = await m.$eval('#doc', (x) => [x.style.cssText, x.hasAttribute('data-zyb-tf')]);
    ok(doc1[0] === doc0 && !doc1[1], 'back to Dark NOC: its inline style is exactly what the page wrote: ' + doc0 + ' → ' + doc1.join(' / '));
    await ctx.close();
    // the real portal: its own switch repaints the portal shell too (the Vivid layer used to keep it dark)
    if (fs.existsSync(path.join(LIVE, 'index.html'))) {
      const c = await browser.newContext({ viewport: { width: 1440, height: 900 } }), q = await c.newPage(); const errs = []; q.on('pageerror', (e) => errs.push(e.message));
      await q.goto(base + '/'); await q.waitForSelector('#themeSel', { timeout: 20000 }); await q.waitForTimeout(1500);
      await q.selectOption('#themeSel', 'light'); await q.waitForTimeout(600);
      const pr = await q.evaluate(() => { const s = (x) => x && getComputedStyle(x).backgroundColor; return { theme: document.documentElement.getAttribute('data-zyb-theme'), body: s(document.body), side: s(document.querySelector('aside.side')), stored: localStorage.getItem('noc_theme') }; });
      const light = (v) => { const m = /(\d+), (\d+), (\d+)/.exec(v || ''); return m && +m[1] > 200 && +m[2] > 200 && +m[3] > 200; };
      ok(pr.theme === 'light' && pr.stored === 'light' && light(pr.body) && light(pr.side), 'portal: Light repaints the portal background and its menu: ' + JSON.stringify(pr));
      const pa = await q.evaluate(audit);
      ok(pa.issues.length <= 5, 'portal [light]: ' + pa.issues.length + ' unreadable text element(s): ' + pa.issues.slice(0, 8).join(' | '));
      await q.selectOption('#themeSel', 'dark'); await q.waitForTimeout(400);
      ok((await q.evaluate(() => document.documentElement.getAttribute('data-zyb-theme'))) === 'dark', 'portal: back to Dark NOC');
      ok(!errs.length, 'portal: no page errors: ' + errs.slice(0, 2).join(' | '));
      await c.close();
    }
  } finally { await browser.close(); srv.close(); }
  const worst = summary.filter((x) => x[2]).sort((x, y) => y[2] - x[2]).slice(0, 15).map((x) => x[0] + ' ' + x[1] + ' ' + x[2]);
  if (worst.length) console.log('worst pages: ' + worst.join(', '));
  console.log(bad ? 'FAILED ' + bad + '/' + n + ' checks' : 'OK ' + n + '/' + n + ' checks'); process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
