// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// "Start here" in the main menu: My Workspace, My Work, Integration Hub, the portal's asset discovery pages (Credentials,
// Results - folded under "More set-up pages"), Add Server / Device, Network Discovery, Team Overview - in that order, once each.
// The portal's Asset Discovery and Discovery Scopes open Discovery Studio / Scope Studio, which have their own entries, so they
// are hidden as duplicates, not moved here (b9bd7e51). The emptied portal group is hidden; the Dashboards heading still closes them. Portal shell like menu-dnd.test.js.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node menu-start.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const DASH = path.resolve(__dirname, '../../ui');
let n = 0, bad = 0;
const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };

const PAGE = `<!doctype html><html><head><meta charset="utf-8"><style>.tree-hidden{display:none}ul.nav li{padding:4px 8px;list-style:none}</style></head><body><aside><ul class="nav">
<li class="nav-group" data-en="Command Center">Command Center</li><li data-en="Launchpad" data-view="home"><span class="ico">🏠</span> Launchpad</li><li data-en="Inbox" data-view="alarms"><span class="ico">🔔</span> Inbox</li>
<li class="nav-group" data-en="Infrastructure Automation">Infrastructure Automation</li><li data-en="Fleet" data-view="infra-hosts"><span class="ico">•</span> Fleet</li><li data-en="SQL Server Backups" data-view="infra-sqlbk"><span class="ico">•</span> SQL Server Backups</li><li data-en="Database Health" data-view="infra-db"><span class="ico">•</span> Database Health</li>
<li class="nav-group" data-en="Discovery & Onboarding">Discovery &amp; Onboarding</li><li data-en="Asset Discovery" data-view="discovery"><span class="ico">•</span> Asset Discovery</li><li data-en="Discovery Scopes" data-view="discovery-scopes"><span class="ico">•</span> Discovery Scopes</li><li data-en="Discovery Credentials" data-view="discovery-credentials"><span class="ico">•</span> Discovery Credentials</li><li data-en="Discovery Results" data-view="discovery-results"><span class="ico">•</span> Discovery Results</li>
<li class="nav-group" data-en="Reports & Administration">Reports &amp; Administration</li><li data-en="Papers" data-view="reports"><span class="ico">📄</span> Papers</li>
</ul></aside>
<script>
/* the portal's collapse tree, as the portal shell has it: it records each heading's pages when it is built (onclick, idempotent) */
window.TREE = 0;
function initNavTree(){ var nav=document.querySelector('.nav'); if(!nav||nav._tree) return; nav._tree=true; TREE++;
  var groups=[]; [].forEach.call(nav.children, function(li){ if(li.classList.contains('nav-group')) groups.push({h:li,kids:[]}); else if(groups.length) groups[groups.length-1].kids.push(li); });
  var saved={}; try{ saved=JSON.parse(localStorage.getItem('nav_tree')||'{}')||{}; }catch(e){}
  groups.forEach(function(g){ var k=g.h.getAttribute('data-en')||g.h.textContent; var set=function(o){ g.h.classList.toggle('open',o); g.kids.forEach(function(x){ x.classList.toggle('tree-hidden',!o); }); };
    set(saved.hasOwnProperty(k)?!!saved[k]:true); g.h.style.cursor='pointer';
    g.h.onclick=function(){ set(!g.h.classList.contains('open')); try{ saved[k]=g.h.classList.contains('open'); localStorage.setItem('nav_tree',JSON.stringify(saved)); }catch(e){} }; }); }
initNavTree();
</script><script src="/dashboards/vendor/zyb-menu.js"></script></body></html>`;

(async () => {
  let ROLE = 'admin', ORDER = null; const puts = [];
  const srv = http.createServer((req, res) => {
    const u = decodeURIComponent(req.url.split('?')[0]);
    const json = (code, o) => { res.writeHead(code, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(o)); };
    if (u === '/') { res.writeHead(200, { 'Content-Type': 'text/html' }); return res.end(PAGE); }
    if (u === '/api/soc/ui/menu' && req.method === 'GET') return json(200, { order: ORDER, favorites: [], user: 'syed', can_edit_order: ROLE === 'admin' });
    if (u === '/api/soc/ui/menu/order' && req.method === 'PUT') { let b = ''; req.on('data', (c) => { b += c; }); return req.on('end', () => { const o = JSON.parse(b); puts.push(o); ORDER = { groups: o.groups, v: o.v || 1 }; json(200, ORDER); }); }
    if (u === '/api/soc/ui/menu/order' && req.method === 'DELETE') { ORDER = null; return json(200, { order: null }); }
    if (u === '/dashboards/whoami.json') return json(200, { user: 'syed', role: ROLE });
    if (u.startsWith('/api/')) return json(404, { error: 'not in this test' });
    if (u.startsWith('/dashboards/')) {
      const f = path.join(DASH, u.slice('/dashboards/'.length)); if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
      return fs.readFile(f, (e, d) => { if (e) { res.writeHead(404); return res.end(); } res.writeHead(200, { 'Content-Type': u.endsWith('.js') ? 'application/javascript' : u.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
    }
    res.writeHead(404); res.end();
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port + '/';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch();
  const errs = [];
  const page = await browser.newPage({ viewport: { width: 1300, height: 1400 } }); page.on('pageerror', (e) => errs.push(e.message));
  await page.goto(base); await page.waitForSelector('li.zyb-area[data-zyb-area="db"]', { timeout: 15000 });
  await page.waitForFunction(() => document.querySelector('li[data-view="discovery-credentials"][data-zyb-start]'), null, { timeout: 8000 });
  const start = await page.evaluate(() => { const nav = document.querySelector('ul.nav'), out = []; let on = false;
    for (const li of nav.children) { const t = (li.getAttribute('data-en') || li.textContent).trim();
      if (li.classList.contains('zyb-lbl')) { if (on) break; on = /start here/i.test(t); continue; }
      if (on) { if (li.classList.contains('zyb-area') || li.classList.contains('nav-group')) break; out.push(t); } } return out; });
  ok(start.join('|') === ['My Workspace', 'My Work', 'Integration Hub', 'More set-up pages (2)', 'Discovery Credentials', 'Discovery Results', 'Add Server / Device', 'Network Discovery', 'Team Overview'].join('|'), 'Start here: ' + start.join(' | '));
  // the two duplicates of Discovery Studio / Scope Studio: hidden, never in Start here
  ok(await page.evaluate(() => ['discovery', 'discovery-scopes'].every((v) => { const li = document.querySelector('li[data-view="' + v + '"]'); return li && !li.offsetParent && !li.hasAttribute('data-zyb-start') && /same page as Discovery Studio/.test(li.getAttribute('data-zyb-dup') || ''); })), 'Asset Discovery and Discovery Scopes hidden as duplicates of Discovery Studio / Scope Studio');
  // laptop-friendly: credentials / results fold under one row until it is opened (remembered)
  ok(await page.$eval('li[data-view="discovery-credentials"]', (li) => !li.offsetParent) && await page.$eval('li[data-zyb-menu="startmore"]', (li) => !!li.offsetParent), 'credentials, results folded; the More row in sight');
  await page.click('li[data-zyb-menu="startmore"]');
  ok(await page.$eval('li[data-view="discovery-credentials"]', (li) => !!li.offsetParent) && await page.$eval('li[data-view="discovery-results"]', (li) => !!li.offsetParent), 'More set-up pages opens them');
  const vis = await page.evaluate(() => [...document.querySelectorAll('ul.nav li')].filter((li) => li.offsetParent).map((li) => (li.getAttribute('data-en') || '').trim()));
  ok(!vis.includes('Asset Discovery') && !vis.includes('Discovery Scopes') && ['Integration Hub', 'Discovery Credentials', 'Discovery Results', 'Network Discovery'].every((t) => vis.filter((x) => x === t).length === 1), 'each once, the duplicates not at all');
  ok(!vis.includes('Discovery & Onboarding'), 'the emptied portal group is hidden');
  // the Dashboards heading itself is hidden in the approved design, but its toggle still governs the moved pages
  await page.evaluate(() => document.querySelector('li[data-zyb-menu="group"]')._zybClick(new MouseEvent('click')));
  ok(await page.$eval('li[data-view="discovery-credentials"]', (li) => !li.offsetParent), 'Dashboards toggle closes the moved pages too');
  await page.evaluate(() => document.querySelector('li[data-zyb-menu="group"]')._zybClick(new MouseEvent('click')));
  ok(await page.$eval('li[data-view="discovery-credentials"]', (li) => !!li.offsetParent), 'and opens them');
  ok(!errs.length, 'errors: ' + errs.join(' | '));
  await browser.close(); srv.close();
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks'); process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
