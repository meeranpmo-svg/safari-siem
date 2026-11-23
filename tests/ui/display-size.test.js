// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Display size (vendor/zyb-dash.js "Fit to screen") and the route-map drawings on wide screens: a QHD / 4K DESK monitor (2560 px
// at 100 %, or 4K with Windows at 150 %) keeps normal size - the old steps zoomed every page 1.2-1.45x there; only a wall / TV
// (very wide, not scaled by the OS) grows. The Email Route Map drawing stops at its designed width instead of stretching with a
// wide page. "Compact" (80 %) is offered and applied. No API is needed: every request fails (the page handles that).
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node display-size.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const DASH = path.resolve(__dirname, '../../ui');
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };

(async () => {
  const srv = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://x').pathname;
    if (u.startsWith('/api/') || u.endsWith('whoami.json') || u.startsWith('/auth/')) { res.writeHead(503, { 'Content-Type': 'application/json' }); return res.end('{"error":"not in this test"}'); }
    const f = path.join(DASH, u.replace(/^\/dashboards\//, '')); if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (e, d) => { if (e) { res.writeHead(404); return res.end(); } res.writeHead(200, { 'Content-Type': f.endsWith('.js') ? 'application/javascript' : f.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const url = 'http://127.0.0.1:' + srv.address().port + '/dashboards/email-route-map.html?standalone=1';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright'); const browser = await chromium.launch(), errs = [];
  const zoomAt = async (width, dpr, prefs) => {
    const ctx = await browser.newContext({ viewport: { width, height: 1000 }, deviceScaleFactor: dpr });
    if (prefs) await ctx.addInitScript((p) => { try { localStorage.setItem('zyb-dash-prefs', p); } catch (e) { /* storage off: defaults */ } }, JSON.stringify(prefs));
    const p = await ctx.newPage(); p.on('pageerror', (e) => errs.push(e.message)); await p.goto(url); await p.waitForTimeout(300);
    const z = await p.evaluate(() => getComputedStyle(document.documentElement).zoom);
    return { z: String(z), p, ctx };
  };
  try {
    let r = await zoomAt(2560, 1); ok(r.z === '1', 'QHD desk monitor (2560 px, 100 %): normal size, got zoom ' + r.z);
    // the route map drawing stops at its designed width on a wide page
    await r.p.evaluate(() => { document.getElementById('svg').innerHTML = '<div class="map"><svg viewBox="0 0 1240 400"></svg></div>'; });
    const w = await r.p.evaluate(() => document.querySelector('.map svg').getBoundingClientRect().width);
    ok(w > 0 && w <= 1241, 'route map drawing capped at 1240 px on a 2560 px page, got ' + w); await r.ctx.close();
    r = await zoomAt(2560, 1.5); ok(r.z === '1', '4K desk monitor with Windows at 150 % (2560 CSS px): normal size, got ' + r.z); await r.ctx.close();
    r = await zoomAt(3000, 1); ok(r.z === '1', '3000 px desk: normal size, got ' + r.z); await r.ctx.close();
    r = await zoomAt(3840, 1); ok(Number(r.z) > 1, '4K wall TV (3840 px, not OS-scaled): grows, got ' + r.z); await r.ctx.close();
    r = await zoomAt(1920, 1, { size: '80' }); ok(r.z === '0.8', 'Compact: 80 %, got ' + r.z); await r.ctx.close();
    ok(/'80': 'Compact'/.test(fs.readFileSync(path.join(DASH, 'vendor', 'zyb-dash.js'), 'utf8')), 'Compact is offered in Customize → Text size');
    ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  } finally { await browser.close(); srv.close(); }
  console.log((bad ? 'FAILED ' : 'ok ') + (n - bad) + '/' + n);
  process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
