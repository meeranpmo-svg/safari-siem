// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const ZYB_ORG = require('../../brand/index');
// Browser test for "one screen" (vendor/zyb-menu.js host + vendor/zyb-dash.js): a dashboard clicked in the portal menu opens
// INSIDE the portal (its sidebar and header stay; the dashboard draws no second menu), the address reads /?zybdash=<page>,
// Back / Forward / refresh work, a portal page closes it, a dashboard opened on its own moves into the portal, a phone-width
// window and ?standalone=1 keep the full-page dashboard, and a portal that never takes the page causes no loop.
// The portal shell is a small ul.nav like the live one. Data is SYNTHETIC.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node portal-onescreen.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const DASH = path.resolve(__dirname, '../../ui');
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const PAGE = `<!doctype html><html><head><meta charset="utf-8"><title>Portal</title><style>body{margin:0}header{position:fixed;top:0;left:0;right:0;height:56px;background:#222}aside{position:fixed;top:56px;left:0;bottom:0;width:240px;overflow:auto}main{margin:56px 0 0 240px}ul.nav li{padding:4px 8px;list-style:none}</style></head>
<body><header>${ZYB_ORG.short} portal</header><aside><ul class="nav">
<li class="nav-group" data-en="Command Center">Command Center</li><li data-en="Home" data-view="home">Home</li><li data-en="Alarms" data-view="alarms">Alarms</li>
</ul></aside><main id="view">home view</main>
<script>window.setView=function(v){document.getElementById('view').textContent=v+' view';};
document.querySelector('ul.nav').addEventListener('click',function(e){var li=e.target.closest('li[data-view]');if(li&&!li.getAttribute('data-zyb-href'))window.setView(li.getAttribute('data-view'));});</script>
<script src="/dashboards/vendor/zyb-menu.js"></script></body></html>`;
let TAKE = true;   // false = a portal without the add-on (never takes a dashboard)
(async () => {
  const srv = http.createServer((req, res) => {
    const u = decodeURIComponent(req.url.split('?')[0]), json = (c, o) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(o)); };
    if (u === '/') { res.writeHead(200, { 'Content-Type': 'text/html' }); return res.end(TAKE ? PAGE : '<!doctype html><html><body>portal without the add-on</body></html>'); }
    if (u === '/dashboards/whoami.json') return json(200, { user: 'syed', role: 'admin' });
    if (u.startsWith('/api/')) return json(404, { error: 'not in this test' });
    if (u.startsWith('/dashboards/')) {
      const f = path.join(DASH, u.slice(12) || 'index.html'); if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
      return fs.readFile(f, (e, d) => { if (e) { res.writeHead(404); return res.end(); } res.writeHead(200, { 'Content-Type': u.endsWith('.js') ? 'application/javascript' : u.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
    }
    res.writeHead(404); res.end();
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port;
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), ctx = await browser.newContext({ viewport: { width: 1400, height: 900 } }), errs = [];
  const p = await ctx.newPage(); p.on('pageerror', (e) => errs.push(p.url() + ' :: ' + e.message + ' :: ' + String(e.stack).split('\n').slice(1, 3).join(' ')));
  const host = () => p.evaluate(() => { const h = document.getElementById('zyb-dash-host'), f = h && h.querySelector('iframe'); let inner = null; try { inner = f && f.contentWindow.location.pathname; } catch (e) { inner = 'x'; }
    return { open: !!h && h.style.display !== 'none', src: f ? f.getAttribute('src') : null, inner, left: h ? h.style.left : null, top: h ? h.style.top : null, url: location.pathname + location.search, side: !!document.getElementById('zyb-side'), view: document.getElementById('view') ? document.getElementById('view').textContent : null }; });
  await p.goto(base + '/'); await p.waitForSelector('ul.nav li[data-zyb-href="/dashboards/backup.html"]', { timeout: 15000, state: 'attached' });
  const start = await p.evaluate(() => { const l = document.querySelector('ul.nav li.zyb-lbl'); const items = ['my-work', 'connections', 'ai-team'].map((x) => document.querySelector('ul.nav li[data-zyb-href="/dashboards/' + x + '.html"]')); return { lbl: l && l.textContent, shown: !!l && l.offsetParent !== null, items: items.filter((x) => x && x.offsetParent !== null).length }; });
  ok(start.lbl === 'Start here' && start.shown && start.items === 3, '"Start here" with My Work, Connections & Setup, AI Engineering Team in the portal menu: ' + JSON.stringify(start));
  await p.evaluate(() => document.querySelector('ul.nav li[data-zyb-href="/dashboards/backup.html"]').click()); await p.waitForTimeout(1200);
  let h = await host();
  ok(h.open && h.src === '/dashboards/backup.html' && h.url === '/?zybdash=backup.html', 'a dashboard opens inside the portal, address /?zybdash=: ' + JSON.stringify(h));
  ok(h.left === '240px' && h.top === '56px', 'placed beside the portal sidebar, under its header: ' + h.left + ' ' + h.top);
  const frameSide = await p.frames()[1].evaluate(() => !!document.getElementById('zyb-side')).catch(() => 'n/a');
  ok(frameSide === false && !h.side, 'no second menu: the dashboard draws only its top bar inside the portal');
  ok(await p.evaluate(() => document.querySelector('ul.nav li[data-zyb-href="/dashboards/backup.html"]').classList.contains('zyb-on')), 'the open dashboard is highlighted in the portal menu');
  ok(await p.evaluate(() => document.querySelector('ul.nav li[data-view="alarms"]').getAttribute('data-zyb-area')) === 'soc', 'the portal\'s own Alarms page sits in Security Monitoring (one place per subject)');
  await p.evaluate(() => document.querySelector('ul.nav li[data-view="alarms"]').click()); await p.waitForTimeout(300); h = await host();
  ok(!h.open && h.view === 'alarms view' && h.url === '/', 'a portal page closes the dashboard and shows itself: ' + JSON.stringify(h));
  await p.goBack(); await p.waitForTimeout(600); h = await host();
  ok(h.open && h.url === '/?zybdash=backup.html', 'Back reopens the dashboard');
  await p.reload(); await p.waitForTimeout(2500); h = await host();
  ok(h.open && h.src === '/dashboards/backup.html', 'refresh on /?zybdash= reopens it: ' + JSON.stringify(h));
  // a dashboard opened on its own moves into the portal (this browser has seen the portal: zyb-portal-nav is set by zyb-menu)
  await p.evaluate(() => { try { localStorage.setItem('zyb-portal-nav', JSON.stringify({ at: Date.now(), groups: [{ g: 'x', items: [] }] })); sessionStorage.clear(); } catch (e) { /* */ } });
  await p.goto(base + '/dashboards/capacity.html'); await p.waitForTimeout(3000); h = await host();
  ok(h.open && h.url === '/?zybdash=capacity.html' && h.src === '/dashboards/capacity.html', 'a bookmark to a dashboard opens inside the portal: ' + JSON.stringify(h));
  await p.goto(base + '/dashboards/capacity.html?standalone=1'); await p.waitForTimeout(1500);
  ok(await p.evaluate(() => location.pathname === '/dashboards/capacity.html' && !!document.getElementById('zyb-side')), '?standalone=1 keeps the full-page dashboard');
  // a portal that never takes the page: one move, then the page stays standalone (no loop)
  TAKE = false; await p.evaluate(() => sessionStorage.clear());
  await p.goto(base + '/dashboards/storage.html'); await p.waitForTimeout(1200);
  ok(await p.evaluate(() => location.pathname) === '/', 'moved once to the portal');
  await p.goto(base + '/dashboards/storage.html'); await p.waitForTimeout(1200);
  ok(await p.evaluate(() => location.pathname) === '/dashboards/storage.html', 'not taken: the second open stays on the dashboard (no loop)');
  TAKE = true;
  // phone width: the full-page dashboard (built for phones), no frame
  const m = await ctx.newPage(); await m.setViewportSize({ width: 600, height: 900 }); m.on('pageerror', (e) => errs.push(e.message));
  await m.goto(base + '/'); await m.waitForSelector('ul.nav li[data-zyb-href="/dashboards/backup.html"]', { timeout: 15000, state: 'attached' });
  await m.evaluate(() => document.querySelector('ul.nav li[data-zyb-href="/dashboards/backup.html"]').click()); await m.waitForTimeout(1500);
  ok(await m.evaluate(() => location.pathname) === '/dashboards/backup.html', 'phone width: the dashboard opens full page');
  ok(!errs.length, 'page errors: ' + errs.join(' | '));
  await browser.close(); srv.close();
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks'); process.exit(bad ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });
