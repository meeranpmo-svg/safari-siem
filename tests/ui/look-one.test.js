// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test: one look everywhere (vendor/zyb-look.js). A browser that still remembers the retired "classic" look gets the
// Modern + Grafana Vivid look on the portal page (and so its menu) exactly like the dashboards; the Modern | Classic switch
// is not drawn; the old choice is cleared. The portal shell is a small ul.nav + .topbar like the live one.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node look-one.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const DASH = path.resolve(__dirname, '../../ui');
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const PAGE = `<!doctype html><html><head><meta charset="utf-8"></head><body><div class="topbar"><b>Portal</b><span class="spacer"></span></div>
<aside><ul class="nav"><li class="nav-group" data-en="Command Center">Command Center</li><li data-en="Launchpad" data-view="home">Launchpad</li></ul></aside>
<script src="/dashboards/vendor/zyb-menu.js"></script></body></html>`;
(async () => {
  const srv = http.createServer((q, r) => { const u = decodeURIComponent(q.url.split('?')[0]), j = (c, o) => { r.writeHead(c, { 'Content-Type': 'application/json' }); r.end(JSON.stringify(o)); };
    if (u === '/') { r.writeHead(200, { 'Content-Type': 'text/html' }); return r.end(PAGE); }
    if (u === '/dashboards/whoami.json') return j(200, { user: 'syed', role: 'admin' });
    if (u.startsWith('/api/')) return j(404, {});
    const f = path.join(DASH, u.slice(12) || 'index.html'); if (!f.startsWith(DASH)) { r.writeHead(403); return r.end(); }
    fs.readFile(f, (e, d) => { if (e) { r.writeHead(404); return r.end(); } r.writeHead(200, { 'Content-Type': u.endsWith('.js') ? 'application/javascript' : u.endsWith('.css') ? 'text/css' : 'text/html' }); r.end(d); }); });
  await new Promise((res) => srv.listen(0, '127.0.0.1', res));
  const base = 'http://127.0.0.1:' + srv.address().port;
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), ctx = await browser.newContext({ viewport: { width: 1300, height: 900 } }), errs = [];
  await ctx.addInitScript(() => { try { if (!sessionStorage.getItem('seeded')) { localStorage.setItem('zyb-look', 'classic'); sessionStorage.setItem('seeded', '1'); } } catch (e) { /* */ } });
  const p = await ctx.newPage(); p.on('pageerror', (e) => errs.push(e.message));
  await p.goto(base + '/'); await p.waitForSelector('li.zyb-area', { state: 'attached', timeout: 15000 }); await p.waitForTimeout(1500);
  const s = await p.evaluate(() => ({ modern: document.documentElement.classList.contains('zyb-modern'), classic: document.documentElement.classList.contains('zyb-classic-look'),
    vivid: !!document.getElementById('zyb-vivid-css'), sw: document.querySelectorAll('.zyb-lk').length, kept: localStorage.getItem('zyb-look') }));
  ok(s.modern && !s.classic && s.vivid, 'portal page: Modern + Grafana Vivid even when "classic" was remembered: ' + JSON.stringify(s));
  ok(s.sw === 0, 'no Modern | Classic switch in the top bar');
  ok(s.kept !== 'classic', 'the old classic choice is cleared');
  await p.goto(base + '/dashboards/backup.html?standalone=1'); await p.waitForTimeout(1500);
  const d = await p.evaluate(() => ({ modern: document.documentElement.classList.contains('zyb-modern'), sw: document.querySelectorAll('.zyb-lk').length }));
  ok(d.modern && d.sw === 0, 'dashboards: the same look, no switch: ' + JSON.stringify(d));
  ok(!errs.length, 'page errors: ' + errs.join(' | '));
  await browser.close(); srv.close();
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks'); process.exit(bad ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });
