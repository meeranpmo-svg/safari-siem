// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for vendor/zyb-menu.js workspaces in the PORTAL menu when the portal's collapse tree hides collapsed items
// with an inline display:none (as the live portal does, not a class): clicking a workspace opens it and its pages show;
// clicking again closes it. Before the fix the row turned "open" and every page stayed hidden.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node menu-expand.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const DASH = path.resolve(__dirname, '../../ui');
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const PAGE = `<!doctype html><html><head><meta charset="utf-8"><style>.tree-hidden{display:none}ul.nav li{padding:4px 8px;list-style:none}</style></head><body><aside><ul class="nav">
<li class="nav-group" data-en="Command Center">Command Center</li><li data-en="Home" data-view="home"><span class="ico">🏠</span> Home</li><li data-en="Alarms" data-view="alarms"><span class="ico">🔔</span> Alarms</li>
<li class="nav-group" data-en="Infrastructure Automation">Infrastructure Automation</li><li data-en="Linux Hosts" data-view="infra-hosts"><span class="ico">•</span> Linux Hosts</li><li data-en="SQL Server Backups" data-view="infra-sqlbk"><span class="ico">•</span> SQL Server Backups</li><li data-en="Database Health" data-view="infra-db"><span class="ico">•</span> Database Health</li>
<li class="nav-group" data-en="Reports & Administration">Reports &amp; Administration</li><li data-en="Reports" data-view="reports"><span class="ico">📄</span> Reports</li>
</ul></aside>
<script>
/* the portal's collapse tree, as the portal shell has it: it records each heading's pages when it is built (onclick, idempotent) */
window.TREE = 0;
function initNavTree(){ var nav=document.querySelector('.nav'); if(!nav||nav._tree) return; nav._tree=true; TREE++;
  var groups=[]; [].forEach.call(nav.children, function(li){ if(li.classList.contains('nav-group')) groups.push({h:li,kids:[]}); else if(groups.length) groups[groups.length-1].kids.push(li); });
  var saved={}; try{ saved=JSON.parse(localStorage.getItem('nav_tree')||'{}')||{}; }catch(e){}
  groups.forEach(function(g){ var k=g.h.getAttribute('data-en')||g.h.textContent; var set=function(o){ g.h.classList.toggle('open',o); g.kids.forEach(function(x){ x.style.display=o?'':'none'; }); };
    set(saved.hasOwnProperty(k)?!!saved[k]:false); g.h.style.cursor='pointer';
    g.h.onclick=function(){ set(!g.h.classList.contains('open')); try{ saved[k]=g.h.classList.contains('open'); localStorage.setItem('nav_tree',JSON.stringify(saved)); }catch(e){} }; }); }
initNavTree();
</script><script src="/dashboards/vendor/zyb-menu.js"></script></body></html>`;
(async () => {
  const srv = http.createServer((q, r) => { const u = decodeURIComponent(q.url.split('?')[0]), j = (c, o) => { r.writeHead(c, { 'Content-Type': 'application/json' }); r.end(JSON.stringify(o)); };
    if (u === '/') { r.writeHead(200, { 'Content-Type': 'text/html' }); return r.end(PAGE); }
    if (u === '/dashboards/whoami.json') return j(200, { user: 'syed', role: 'admin' });
    if (u.startsWith('/api/')) return j(404, {});
    const f = path.join(DASH, u.slice(12)); if (!f.startsWith(DASH)) { r.writeHead(403); return r.end(); }
    fs.readFile(f, (e, d) => { if (e) { r.writeHead(404); return r.end(); } r.writeHead(200, { 'Content-Type': u.endsWith('.js') ? 'application/javascript' : 'text/css' }); r.end(d); }); });
  await new Promise((res) => srv.listen(0, '127.0.0.1', res));
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), p = await browser.newPage({ viewport: { width: 1300, height: 1400 } }), errs = [];
  p.on('pageerror', (e) => errs.push(e.message));
  await p.goto('http://127.0.0.1:' + srv.address().port + '/'); await p.waitForSelector('li.zyb-area[data-zyb-area="db"]', { state: 'attached', timeout: 15000 }); await p.waitForTimeout(1200);
  const vis = (a) => p.evaluate((a) => [...document.querySelectorAll('li.zyb-sub[data-zyb-area="' + a + '"]')].filter((x) => x.offsetParent !== null).length, a);
  const click = (a) => p.evaluate((a) => document.querySelector('li.zyb-area[data-zyb-area="' + a + '"]').click(), a);
  ok(await vis('db') === 0, 'a closed workspace shows no pages');
  await click('db'); await p.waitForTimeout(200);
  const nDb = await vis('db');
  ok(nDb >= 11, 'opened: the Databases pages show (inline-hidden by the portal tree before): ' + nDb);
  await click('db'); await p.waitForTimeout(200);
  ok(await vis('db') === 0, 'closed again: hidden');
  await click('stor'); await p.waitForTimeout(200);
  ok(await vis('stor') >= 4, 'another workspace opens too: ' + await vis('stor'));
  await p.reload(); await p.waitForSelector('li.zyb-area[data-zyb-area="stor"]', { state: 'attached', timeout: 15000 }); await p.waitForTimeout(1200);
  ok(await vis('stor') >= 4, 'the open state is remembered after a reload');
  // no bullets in the menu: no list marker, and a bullet-only portal icon ("•") is hidden while real icons stay
  const bl = await p.evaluate(() => { const lis = [...document.querySelectorAll('ul.nav li')]; const dots = [...document.querySelectorAll('ul.nav li .ico')].filter((x) => x.textContent.trim() === '\u2022');
    const real = [...document.querySelectorAll('ul.nav li .ico')].filter((x) => x.textContent.trim() !== '\u2022');
    return { markers: lis.filter((l) => getComputedStyle(l).listStyleType !== 'none').length, dots: dots.length, dotsShown: dots.filter((x) => getComputedStyle(x).display !== 'none').length, realShown: real.filter((x) => getComputedStyle(x).display !== 'none').length, real: real.length }; });
  ok(bl.markers === 0 && bl.dots > 0 && bl.dotsShown === 0, 'no bullets in the menu: ' + JSON.stringify(bl));
  ok(!errs.length, 'page errors: ' + errs.join(' | '));
  await browser.close(); srv.close();
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks'); process.exit(bad ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });
