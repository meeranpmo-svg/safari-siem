// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for the organised portal menu (vendor/zyb-menu.js + vendor/zyb-nav.js): "Start here" once at the top, the eight
// headings in order (ZYB_HEADS: Overview, Security, Infrastructure, Business services, Governance & compliance, Data privacy,
// Audit & assurance, Administration - Audit and Data Privacy are their own departments since 7eb44720), a Start-here page never repeated
// inside its workspace, the portal's own pages placed in the workspace of their subject (one place per subject), a portal
// heading left empty is hidden, a page that matches nothing stays where it was, and a page an admin placed in a saved order
// keeps that place. The portal shell is a small ul.nav like the live one; page names are SYNTHETIC.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node menu-organise.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const DASH = path.resolve(__dirname, '../../ui');
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const li = (v, l) => `<li data-en="${l}" data-view="${v}">${l}</li>`;
const PAGE = `<!doctype html><html><head><meta charset="utf-8"><style>ul.nav li{padding:3px 8px;list-style:none}</style></head><body><aside><ul class="nav">
<li class="nav-group" data-en="Security Operations (SIEM)">Security Operations (SIEM)</li>${li('alerts', 'Alert Queue')}${li('search', 'Event Search')}
<li class="nav-group" data-en="Network & Servers">Network &amp; Servers</li>${li('netdev', 'Network Devices')}${li('hosts', 'Linux Hosts')}${li('vc', 'vCenter Inventory')}
<li class="nav-group" data-en="Governance & Compliance">Governance &amp; Compliance</li>${li('comp', 'Compliance Overview')}
<li class="nav-group" data-en="IT Asset Management">IT Asset Management</li>${li('lic', 'Software & Licences')}${li('mail', 'Mail Flow')}${li('mbx', 'Exchange Mailboxes')}
<li class="nav-group" data-en="Microsoft">Microsoft</li>${li('m365', 'Microsoft 365')}
<li class="nav-group" data-en="Other tools">Other tools</li>${li('odd', 'Weird Tool')}${li('odd2', 'Weird Tools')}
</ul></aside><script src="/dashboards/vendor/zyb-menu.js"></script></body></html>`;
let ORDER = null, EDIT = false;
(async () => {
  const srv = http.createServer((q, r) => { const u = decodeURIComponent(q.url.split('?')[0]), j = (c, o) => { r.writeHead(c, { 'Content-Type': 'application/json' }); r.end(JSON.stringify(o)); };
    if (u === '/') { r.writeHead(200, { 'Content-Type': 'text/html' }); return r.end(PAGE); }
    if (u === '/api/soc/ui/menu') return j(200, { order: ORDER, favorites: [], user: 'syed', can_edit_order: EDIT });
    if (u === '/dashboards/whoami.json') return j(200, { user: 'syed', role: 'admin' });
    if (u.startsWith('/api/')) return j(404, {});
    const f = path.join(DASH, u.slice(12)); if (!f.startsWith(DASH)) { r.writeHead(403); return r.end(); }
    fs.readFile(f, (e, d) => { if (e) { r.writeHead(404); return r.end(); } r.writeHead(200, { 'Content-Type': u.endsWith('.js') ? 'application/javascript' : 'text/css' }); r.end(d); }); });
  await new Promise((res) => srv.listen(0, '127.0.0.1', res));
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  const open = async () => { const p = await browser.newPage({ viewport: { width: 1300, height: 1600 } }); p.on('pageerror', (e) => errs.push(e.message));
    await p.goto('http://127.0.0.1:' + srv.address().port + '/'); await p.waitForSelector('li.zyb-area[data-zyb-area="soc"]', { state: 'attached', timeout: 15000 }); await p.waitForTimeout(1500); return p; };
  let p = await open();
  const st = await p.evaluate(() => {
    const lbl = [...document.querySelectorAll('ul.nav li.zyb-lbl')].map((x) => x.textContent);
    const area = (v) => { const e = document.querySelector('ul.nav li[data-view="' + v + '"]'); return e ? e.getAttribute('data-zyb-area') || '' : null; };
    const head = (t) => { const h = document.querySelector('ul.nav li.nav-group[data-en="' + t + '"]'); return h ? getComputedStyle(h).display !== 'none' : null; };
    const dup = ['my-work', 'connections', 'ai-team'].map((x) => document.querySelectorAll('ul.nav li[data-zyb-href="/dashboards/' + x + '.html"]').length);
    const order = [...document.querySelectorAll('ul.nav li.zyb-area')].map((x) => x.getAttribute('data-zyb-area'));
    return { lbl, dup, order, alerts: area('alerts'), search: area('search'), netdev: area('netdev'), hosts: area('hosts'), vc: area('vc'), comp: area('comp'), lic: area('lic'), mail: area('mail'), mbx: area('mbx'), odd: area('odd'),
      m365: (() => { const e = document.querySelector('ul.nav li[data-view="m365"]'); return { dup: e.getAttribute('data-zyb-dup') || '', shown: getComputedStyle(e).display !== 'none' }; })(),
      odd2: (() => { const e = document.querySelector('ul.nav li[data-view="odd2"]'); return { dup: e.getAttribute('data-zyb-dup') || '', shown: getComputedStyle(e).display !== 'none' }; })(),
      hMs: head('Microsoft'), ourM365: document.querySelectorAll('ul.nav li[data-zyb-href="/dashboards/m365.html"]').length,
      hSec: head('Security Operations (SIEM)'), hNet: head('Network & Servers'), hOther: head('Other tools'), cmdCount: (document.querySelector('li.zyb-area[data-zyb-area="cmd"] .zyb-cnt') || {}).textContent };
  });
  ok(JSON.stringify(st.lbl) === JSON.stringify(['Start here', 'Overview', 'Security', 'Infrastructure', 'Business services', 'Governance & compliance', 'Data privacy', 'Audit & assurance', 'Administration', 'Artificial Intelligence']), 'Start here + the nine headings in order (AI last, apart from the main menu): ' + st.lbl);
  ok(JSON.stringify(st.order) === JSON.stringify(['cmd', 'soc', 'pt', 'eps', 'usr', 'net', 'srv', 'stor', 'db', 'eud', 'app', 'ast', 'grc', 'brisk', 'cmp', 'pdpl', 'aud', 'adm', 'ai']), 'workspaces grouped under their heading: ' + st.order);
  ok(st.dup.every((x) => x === 1), 'My Work, Connections & Setup, AI Engineering Team appear once (Start here), not again in their workspace: ' + st.dup);
  // 20 pages in ZYB_NAV cmd (incl. Custom Dashboards, Platform Map, Update Guardrails, Workflow Automation) less My Workspace and My Work
  ok(st.cmdCount === '19', 'Command Center counts its own pages (19 since Patching - All Assets joined Live operations), not its sub-menu headings, without the two Start-here pages (My Workspace, My Work): ' + st.cmdCount);
  ok(st.alerts === 'soc' && st.search === 'soc', 'portal SIEM pages -> Security Monitoring');
  ok(st.netdev === 'net' && st.hosts === 'srv' && st.vc === 'srv', 'portal network / server pages -> Network, Servers & Virtualization: ' + [st.netdev, st.hosts, st.vc]);
  ok(st.comp === 'cmp' && st.lic === 'ast' && st.mail === 'eps' && st.mbx === 'usr', 'compliance -> Compliance & Frameworks, licences -> IT Assets, mail -> Endpoint & Email, Exchange -> Identity: ' + [st.comp, st.lic, st.mail, st.mbx]);
  ok(st.hSec === false && st.hNet === false, 'portal headings left empty are hidden (no second Security / Network group)');
  ok(!st.m365.shown && /same name as the dashboard \/dashboards\/m365\.html/.test(st.m365.dup) && st.ourM365 === 1 && st.hMs === false, 'a portal page named like one of our dashboards is hidden, ours stays, its emptied group too: ' + JSON.stringify(st.m365));
  ok(!st.odd2.shown && /another portal page/.test(st.odd2.dup), 'a second portal page with the same name (Weird Tool / Weird Tools) is hidden: ' + JSON.stringify(st.odd2));
  ok(st.odd === 'adm' && st.hOther !== true, 'a page no name rule places goes where its portal heading belongs (Other tools -> Platform Administration), so no old portal section is left: ' + [st.odd, st.hOther]);
  await p.close();
  // an admin: "Copy menu list" saves the menu as drawn, naming what was moved and what was hidden
  EDIT = true; p = await open();
  await p.waitForSelector('#zyb-editbar [data-a="list"]', { timeout: 8000 });
  const [dl] = await Promise.all([p.waitForEvent('download'), p.click('#zyb-editbar [data-a="list"]')]);
  const txt = fs.readFileSync(await dl.path(), 'utf8');
  ok(/=== SECURITY ===/.test(txt) && /Alert Queue .*portal:alerts · moved into soc/.test(txt) && /Microsoft 365 .*HIDDEN DUPLICATE: same name as the dashboard/.test(txt) && /Weird Tool .*moved into adm/.test(txt), 'menu list file: headings, moved and hidden pages: ' + txt.split('\n').slice(0, 6).join(' / '));
  await p.evaluate(() => { const r = document.querySelector('li.zyb-area[data-zyb-area="adm"]'); if (r && !r.classList.contains('zyb-open')) r.click(); }); await p.waitForTimeout(200);
  await p.click('#zyb-editbar [data-a="edit"]'); await p.waitForTimeout(300);
  ok(await p.evaluate(() => getComputedStyle(document.querySelector('ul.nav li[data-view="odd2"]')).display !== 'none' && getComputedStyle(document.querySelector('ul.nav li[data-view="odd2"]')).opacity === '0.5'), 'while an admin edits the menu, hidden duplicates are visible (dimmed)');
  await p.close(); EDIT = false;
  // an admin placed Alert Queue in Other tools: that wins over the subject rule
  ORDER = { v: 2, groups: [{ name: 'Other tools', items: ['odd', 'alerts'] }] };
  p = await open();
  ok(await p.evaluate(() => document.querySelector('ul.nav li[data-view="alerts"]').getAttribute('data-zyb-area')) === null, 'a page in an admin\'s saved order keeps its place');
  ok(!errs.length, 'page errors: ' + errs.join(' | '));
  await browser.close(); srv.close();
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks'); process.exit(bad ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });
