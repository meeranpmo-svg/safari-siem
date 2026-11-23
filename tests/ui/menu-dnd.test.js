// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for the admin menu editor in vendor/zyb-menu.js: Database Health (infra-db) sits in the Dashboards
// "Databases" workspace by default; an admin drags pages between groups and into workspaces, the saved order carries
// (the portal pages here have neutral names, so the subject rules - which place real portal pages by their names - leave
// them where the portal put them and the editor itself is what is tested)
// "area:<id>" entries and v:2 and is applied for everyone on the next load (and wins over the default); a viewer gets no
// editor and nothing is draggable; Cancel puts the menu back. The portal shell is a small ul.nav like the live one.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node menu-dnd.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const DASH = path.resolve(__dirname, '../../ui');
let n = 0, bad = 0;
const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };

const PAGE = `<!doctype html><html><head><meta charset="utf-8"><style>.tree-hidden{display:none}ul.nav li{padding:4px 8px;list-style:none}</style></head><body><aside><ul class="nav">
<li class="nav-group" data-en="Group One">Group One</li><li data-en="Launchpad" data-view="home"><span class="ico">🏠</span> Launchpad</li><li data-en="Inbox" data-view="alarms"><span class="ico">🔔</span> Inbox</li>
<li class="nav-group" data-en="Group Two">Group Two</li><li data-en="Fleet" data-view="infra-hosts"><span class="ico">•</span> Fleet</li><li data-en="SQL Server Backups" data-view="infra-sqlbk"><span class="ico">•</span> SQL Server Backups</li><li data-en="Database Health" data-view="infra-db"><span class="ico">•</span> Database Health</li>
<li class="nav-group" data-en="Group Three">Group Three</li><li data-en="Papers" data-view="reports"><span class="ico">📄</span> Papers</li>
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
  const open = async () => {
    const page = await browser.newPage({ viewport: { width: 1300, height: 1400 } }); page.on('pageerror', (e) => errs.push(e.message));
    await page.goto(base); await page.waitForSelector('li.zyb-area[data-zyb-area="db"]', { timeout: 15000 });
    await page.waitForFunction(() => document.querySelector('li[data-view="infra-db"] .zyb-star'), null, { timeout: 8000 });
    return page;
  };
  // where a page sits: its group heading, and the workspace it is in (if any)
  const where = (page, v) => page.evaluate((v) => { const li = document.querySelector('ul.nav > li[data-view="' + v + '"]'); if (!li) return null; let h = li.previousElementSibling; while (h && !h.classList.contains('nav-group')) h = h.previousElementSibling;
    return { group: h && h.getAttribute('data-en'), area: li.getAttribute('data-zyb-moved') || '', sub: li.classList.contains('zyb-sub'), drag: li.getAttribute('draggable') }; }, v);
  const drag = async (page, from, to) => {
    await page.evaluate(([f, t]) => { const a = document.querySelector(f), b = document.querySelector(t), dt = new DataTransfer(), r = b.getBoundingClientRect(), y = r.top + r.height * 0.75;
      a.dispatchEvent(new DragEvent('dragstart', { bubbles: true, dataTransfer: dt }));
      b.dispatchEvent(new DragEvent('dragover', { bubbles: true, cancelable: true, dataTransfer: dt, clientY: y }));
      b.dispatchEvent(new DragEvent('drop', { bubbles: true, cancelable: true, dataTransfer: dt, clientY: y }));
      a.dispatchEvent(new DragEvent('dragend', { bubbles: true, dataTransfer: dt })); }, [from, to]);
  };

  // ---- default: Database Health is in the Databases workspace, nothing saved yet
  let page = await open();
  ok((await where(page, 'infra-sqlbk')).area === 'db' && !(await where(page, 'infra-hosts')).area, 'any database-named page moves under Databases; others stay');
  let w = await where(page, 'infra-db');
  ok(w && w.area === 'db' && w.sub && w.group === 'Dashboards', 'Database Health defaults into the Databases workspace: ' + JSON.stringify(w));
  ok((await where(page, 'infra-hosts')).group === 'Group Two', 'other pages stay where the portal put them');
  const toggled = await page.evaluate(() => { const row = document.querySelector('li.zyb-area[data-zyb-area="db"]'), li = document.querySelector('li[data-view="infra-db"]'), was = row.classList.contains('zyb-open');
    row.click(); const a = li.hasAttribute('data-zyb-col'); row.click(); return { was, after: a, back: li.hasAttribute('data-zyb-col') }; });
  ok(toggled.after === toggled.was && toggled.back === !toggled.was, 'the workspace toggle shows / hides the moved page with its own pages: ' + JSON.stringify(toggled));
  // the portal's collapse tree follows the moves: collapsing the group a page LEFT must not hide it; its new group does
  const hid = (v) => page.evaluate((v) => document.querySelector('ul.nav > li[data-view="' + v + '"]').classList.contains('tree-hidden'), v);
  const tog = (en) => page.evaluate((en) => { const h = [...document.querySelectorAll('ul.nav > li.nav-group')].find((x) => x.getAttribute('data-en') === en); h.onclick ? h.onclick() : h.click(); }, en);
  ok(await page.evaluate(() => window.TREE) >= 2, 'the collapse tree was rebuilt after the default move');
  await tog('Group Two');
  ok(!(await hid('infra-db')) && await hid('infra-hosts'), 'collapsing Group Two hides its own pages, not Database Health (now in Databases)');
  await tog('Group Two');
  ok(!(await hid('infra-hosts')), 'opening it again shows its pages');
  ok(await page.$('#zyb-editbar button[data-a="edit"]'), 'admin sees "Edit menu order"');
  ok((await where(page, 'home')).drag === null, 'nothing draggable outside edit mode');

  // ---- admin edits by drag and drop
  await page.click('#zyb-editbar button[data-a="edit"]');
  ok((await where(page, 'home')).drag === 'true' && (await where(page, 'infra-db')).drag === 'true', 'edit mode: portal pages (and the moved one) are draggable');
  ok(await page.evaluate(() => !document.querySelector('li.zyb-area[draggable="true"], li.nav-group[draggable="true"]')), 'workspace rows and headings are not draggable');
  await drag(page, 'li[data-view="alarms"]', 'li.nav-group[data-en="Group Three"]');
  w = await where(page, 'alarms'); ok(w.group === 'Group Three' && !w.area, 'drop on a group heading = end of that group: ' + JSON.stringify(w));
  await drag(page, 'li[data-view="infra-hosts"]', 'li.zyb-area[data-zyb-area="srv"]');
  w = await where(page, 'infra-hosts'); ok(w.area === 'srv' && w.sub, 'drop on a workspace row = into that workspace: ' + JSON.stringify(w));
  await drag(page, 'li[data-view="infra-db"]', 'li[data-view="home"]');
  w = await where(page, 'infra-db'); ok(w.group === 'Group One' && !w.area && !w.sub, 'a page dragged out of a workspace onto a page = after it, back to a plain item: ' + JSON.stringify(w));
  ok(await page.evaluate(() => [...document.querySelectorAll('ul.nav > li.nav-group')].find((h) => h.dataset.en === 'Group One').nextElementSibling.nextElementSibling.dataset.view === 'infra-db'), 'dropped on the lower half of Home = right after Home');
  await page.click('#zyb-editbar button[data-a="save"]'); await page.waitForFunction(() => document.querySelector('#zyb-editbar button[data-a="edit"]'));
  await tog('Group One');
  ok(!(await hid('alarms')) && await hid('home'), 'after the drag: collapsing Group One no longer hides Alarms (now in Reports)');
  await tog('Group One'); await tog('Group Three');
  ok(await hid('alarms') && await hid('reports'), 'collapsing Group Three hides Alarms with its other pages');
  await tog('Group Three');
  ok(!(await hid('alarms')), 'and opening it shows Alarms again');
  const sent = puts[puts.length - 1];
  ok(sent && sent.v === 2, 'saved with v:2');
  ok(sent && JSON.stringify((sent.groups.find((g) => g.name === 'area:srv') || {}).items) === '["infra-hosts"]', 'saved order has area:srv = infra-hosts: ' + JSON.stringify(sent && sent.groups));
  ok(sent && !((sent.groups.find((g) => g.name === 'area:db') || {}).items || []).includes('infra-db'), 'the drag is what is saved (the Databases rule is applied on load, not written into the order)');
  ok(sent && (sent.groups.find((g) => g.name === 'Group One') || {}).items.join(',') === 'home,infra-db', 'Group One saved as home, infra-db');
  ok(sent && (sent.groups.find((g) => g.name === 'Group Three') || {}).items.join(',') === 'reports,alarms', 'Group Three saved as reports, alarms');
  ok(sent && !sent.groups.some((g) => !/^area:/.test(g.name) && g.items.includes('infra-hosts')), 'a page in a workspace is not also listed in a group');
  ok((await where(page, 'home')).drag === null, 'after saving, nothing is draggable');
  await page.close();

  // ---- everyone gets the saved order on the next load; the default does not override the admin
  ROLE = 'viewer'; page = await open();
  ok((await where(page, 'infra-db')).area === 'db', 'a database page stays under Databases even when a saved order puts it elsewhere');
  ok((await where(page, 'infra-hosts')).area === 'srv', 'saved workspace placement applied for a viewer');
  ok((await where(page, 'alarms')).group === 'Group Three', 'saved group move applied for a viewer');
  ok(!(await page.$('#zyb-editbar button')), 'viewer: no menu editor');
  ok(await page.evaluate(() => !document.querySelector('ul.nav li[draggable="true"]')), 'viewer: nothing draggable');
  await page.close();

  // ---- an old (v1) order that lists Database Health in its group keeps it there; one that does not gets the default
  ORDER = { groups: [{ name: 'Group Two', items: ['infra-db', 'infra-hosts'] }], v: 1 };
  page = await open(); ok((await where(page, 'infra-db')).area === 'db', 'every database page is under Databases (business rule), an old saved order included');
  await page.close();
  ORDER = { groups: [{ name: 'Group One', items: ['alarms', 'home'] }], v: 1 }; ROLE = 'admin';
  page = await open(); ok((await where(page, 'infra-db')).area === 'db', 'a v1 order that does not mention it: default place');

  // ---- cancel puts it back
  await page.click('#zyb-editbar button[data-a="edit"]');
  await drag(page, 'li[data-view="reports"]', 'li.nav-group[data-en="Group One"]');
  ok((await where(page, 'reports')).group === 'Group One', 'moved before cancel');
  await page.click('#zyb-editbar button[data-a="cancel"]');
  ok((await where(page, 'reports')).group === 'Group Three', 'Cancel restores the menu');
  const nPuts = puts.length; await page.close();
  ok(puts.length === nPuts, 'cancel sends nothing');

  ok(!errs.length, 'page errors: ' + errs.join(' | '));
  await browser.close(); srv.close();
  console.log((bad ? 'FAILED ' : 'ok ') + (n - bad) + '/' + n);
  process.exit(bad ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });
