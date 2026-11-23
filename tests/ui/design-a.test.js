// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test: the approved design (vendor/zyb-vivid.css, design canvas Oct 2026) on the portal menu and on a dashboard.
// Menu: dark side panel, workspace icons coloured but not on a filled tile, quiet headings, the page you are on = blue row
// with a blue dot. Tiles: dark panel with a status dot, red tiles glow, no gradient fills. Tables: plain header row.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node design-a.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const DASH = path.resolve(__dirname, '../../ui');
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const PAGE = `<!doctype html><html><head><meta charset="utf-8"></head><body><div class="topbar"><b>Portal</b><span class="spacer"></span></div>
<aside class="side"><ul class="nav"><li class="nav-group" data-en="Command Center">Command Center</li><li data-en="Launchpad" data-view="home">Launchpad</li>
<li class="nav-group" data-en="Security Operations (SIEM)">Security Operations (SIEM)</li><li data-en="Alert Queue" data-view="alerts"><span class="ico">🚨</span> Alert Queue</li><li data-en="UEBA" data-view="ueba"><span class="ico">👤</span> UEBA</li><li data-en="Event Search" data-view="search"><span class="ico">🔎</span> Event Search</li></ul></aside>
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
  const browser = await chromium.launch(), ctx = await browser.newContext({ viewport: { width: 1400, height: 900 } }), errs = [];
  const p = await ctx.newPage(); p.on('pageerror', (e) => errs.push(e.message));

  // portal menu
  await p.goto(base + '/'); await p.waitForSelector('li.zyb-area', { state: 'attached', timeout: 15000 }); await p.waitForTimeout(1500);
  const m = await p.evaluate(() => { const g = (el, pr) => el ? getComputedStyle(el)[pr] : null, ps = (el, w, pr) => el ? getComputedStyle(el, w)[pr] : null;
    const area = document.querySelector('li.zyb-area'), ic = area && area.querySelector('.zyb-aic'), lbl = document.querySelector('li.zyb-lbl'), sub = document.querySelector('li.zyb-sub');
    return { side: g(document.querySelector('aside.side'), 'backgroundColor'), icBg: g(ic, 'backgroundColor'), icCol: g(ic, 'color'), lbl: g(lbl, 'color'), lblT: g(lbl, 'textTransform'),
      dot: ps(sub, '::after', 'width'), bar: g(document.querySelector('.topbar'), 'backgroundColor') }; });
  ok(m.side === 'rgb(20, 22, 27)', 'portal menu panel is the design dark: ' + m.side);
  ok(/rgba\(0, 0, 0, 0\)|transparent/.test(m.icBg) && m.icCol && m.icCol !== 'rgb(174, 178, 185)', 'workspace icon coloured, not on a filled tile: ' + m.icBg + ' ' + m.icCol);
  ok(m.lbl === 'rgb(142, 147, 156)' && m.lblT === 'uppercase', 'headings are quiet uppercase labels: ' + m.lbl);
  ok(m.dot === '6px', 'each page under a workspace has its dot: ' + m.dot);
  ok(m.bar === 'rgb(18, 20, 25)', 'top bar: ' + m.bar);
  const t = await p.evaluate(() => { const soc = document.querySelector('li.zyb-area[data-zyb-area="soc"]'), db = document.querySelector('li.zyb-area[data-zyb-area="db"]');
    db.click(); soc.click(); const vis = (q) => { const e = document.querySelector(q); return !!e && getComputedStyle(e).display !== 'none'; };
    const subs = [...document.querySelectorAll('li.zyb-sub[data-zyb-area="soc"]:not(.zyb-sg)')].filter((x) => getComputedStyle(x).display !== 'none'), lab = subs.map((x) => x.getAttribute('data-en') || '');
    const mv = lab.filter((x) => ['Alert Queue', 'Event Search'].includes(x));
    return { one: document.querySelectorAll('li.zyb-area.zyb-open').length, dbOpen: db.classList.contains('zyb-open'), emoji: vis('li[data-view="alerts"] .ico'), ueba: vis('li[data-view="ueba"]'),
      order: mv.join('|'), head: vis('li.nav-group[data-zyb-menu="group"]'), cnt: soc.querySelector('.zyb-cnt').textContent, n: subs.length }; });
  ok(t.one === 1 && !t.dbOpen, 'one workspace open at a time: ' + JSON.stringify(t));
  ok(!t.emoji, 'portal pages moved into a workspace lose their emoji (one icon language)');
  ok(!t.ueba, 'a portal page that repeats a dashboard ("UEBA" = "User Behaviour (UEBA)") is not listed twice');
  ok(t.order === 'Alert Queue|Event Search', 'moved portal pages follow the dashboards A to Z: ' + t.order);
  ok(!t.head, 'no extra "Dashboards" fold heading above Start here');
  ok(+t.cnt === t.n, 'the workspace count is the pages it really lists: ' + t.cnt + ' vs ' + t.n);

  // a dashboard: its menu, tiles and table
  await p.goto(base + '/dashboards/backup.html?standalone=1'); await p.waitForSelector('#zyb-side .zs-area', { timeout: 15000 }); await p.waitForTimeout(1200);
  await p.evaluate(() => { const h = document.createElement('div'); h.id = 'tst'; h.innerHTML = '<div class="k"><div class="t bad"><div class="l">Act now</div><div class="v">1</div></div><div class="t ok"><div class="l">Fine</div><div class="v">9</div></div><div class="t"><div class="l">Context</div><div class="v">4</div></div></div><table><thead><tr><th>Name</th></tr></thead><tbody><tr><td>x</td></tr></tbody></table><span class="pill bad">Failed</span>';
    (document.querySelector('main') || document.body).appendChild(h); });
  const d = await p.evaluate(() => { const g = (el, pr) => el ? getComputedStyle(el)[pr] : null, ps = (el, w, pr) => el ? getComputedStyle(el, w)[pr] : null;
    const t = document.querySelectorAll('#tst .t'), ic = document.querySelector('#zyb-side .zs-ic'), on = document.querySelector('#zyb-side .zs-it.on');
    return { side: g(document.getElementById('zyb-side'), 'backgroundColor'), icBg: g(ic, 'backgroundImage') + '|' + g(ic, 'backgroundColor'),
      onBg: g(on, 'backgroundColor'), onDot: ps(on, '::before', 'backgroundColor'), lblT: g(document.querySelector('#zyb-side .zs-lbl'), 'textTransform'),
      tBg: g(t[0], 'backgroundColor'), tImg: g(t[0], 'backgroundImage'), glow: g(t[0], 'boxShadow'), okGlow: g(t[1], 'boxShadow'),
      badDot: ps(t[0].querySelector('.l'), '::before', 'backgroundColor'), okDot: ps(t[1].querySelector('.l'), '::before', 'backgroundColor'), ctxDot: ps(t[2].querySelector('.l'), '::before', 'backgroundColor'),
      badV: g(t[0].querySelector('.v'), 'color'), th: g(document.querySelector('#tst th'), 'textTransform') + '|' + g(document.querySelector('#tst th'), 'backgroundColor'),
      pill: ps(document.querySelector('#tst .pill'), '::before', 'width') }; });
  ok(d.side === 'rgb(20, 22, 27)', 'dashboard menu panel matches the portal menu: ' + d.side);
  ok(/^none\|rgba\(0, 0, 0, 0\)/.test(d.icBg), 'dashboard workspace icon is not on a filled tile: ' + d.icBg);
  ok(d.lblT === 'uppercase', 'dashboard headings are uppercase labels');
  ok(d.onBg === 'rgb(29, 42, 64)' && d.onDot === 'rgb(87, 148, 242)', 'the page you are on: blue row, blue dot: ' + d.onBg + ' ' + d.onDot);
  ok(d.tBg === 'rgb(24, 27, 31)' && d.tImg === 'none', 'tiles are dark panels, no gradient fill: ' + d.tBg + ' ' + d.tImg);
  ok(/242, 73, 92/.test(d.glow) && d.okGlow === 'none', 'only the act-now tile glows: ' + d.glow + ' / ' + d.okGlow);
  ok(d.badDot === 'rgb(242, 73, 92)' && d.okDot === 'rgb(115, 191, 105)' && d.ctxDot && d.ctxDot !== d.okDot, 'status dot by meaning, context tiles get a rotation colour: ' + [d.badDot, d.okDot, d.ctxDot].join(' '));
  ok(d.badV === 'rgb(255, 138, 150)', 'act-now value in red: ' + d.badV);
  ok(/^none\|rgba\(0, 0, 0, 0\)/.test(d.th), 'plain table header: ' + d.th);
  ok(d.pill === '6px', 'status pill carries its dot');
  if (process.env.SHOT) { await p.screenshot({ path: process.env.SHOT }); }
  ok(!errs.length, 'page errors: ' + errs.join(' | '));
  await browser.close(); srv.close();
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks'); process.exit(bad ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });
