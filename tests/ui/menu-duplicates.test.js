// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// No page twice in the menu people actually see: the REAL portal (repos/live/portal) with our menu scripts, as an
// operator, after the menu settles. Every visible entry is resolved to where it really goes - a dashboard link, a portal view
// redirected to a dashboard (zyb-menu LIVE), or the portal's own view - and no destination may be reachable from two visible
// entries, and no two visible entries may carry the same name. Also: every redirect target exists. Stubbed API, SYNTHETIC user.
// Skips when the live copy is not in the repository. Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node menu-duplicates.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const LIVE = path.resolve(__dirname, '../../repos/live/portal'), DASH = path.resolve(__dirname, '../../ui');
if (!fs.existsSync(path.join(LIVE, 'index.html'))) { console.log('SKIP: repos/live/portal not present'); process.exit(0); }
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const menuSrc = fs.readFileSync(path.join(DASH, 'vendor/zyb-menu.js'), 'utf8');
const LIVEMAP = Function('return ' + /var LIVE = (\{[\s\S]*?\});/.exec(menuSrc)[1])();
ok(Object.values(LIVEMAP).every((h) => fs.existsSync(path.join(DASH, h.split('#')[0].split('?')[0]))), 'every portal redirect goes to a page that exists');

(async () => {
  const srv = http.createServer((req, res) => {
    const u = decodeURIComponent(req.url.split('?')[0]), json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u === '/dashboards/whoami.json' || u === '/auth/whoami') return json(200, { user: 'omar.syn', role: 'operator' });
    if (u.startsWith('/api/soc/ui/menu')) return json(200, { order: null, favorites: [], can_edit_order: false });
    if (u.startsWith('/api/') || u.startsWith('/auth/')) return json(404, { error: 'not in this test' });
    const f = u === '/' ? path.join(LIVE, 'index.html') : u.startsWith('/dashboards/') ? path.join(DASH, u.slice(12)) : path.join(LIVE, u);
    if (!f.startsWith(DASH) && !f.startsWith(LIVE)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (e, d) => { if (e) { res.writeHead(404); return res.end(); } res.writeHead(200, { 'Content-Type': f.endsWith('.js') ? 'application/javascript' : f.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright'); const browser = await chromium.launch();
  try {
    const p = await browser.newPage({ viewport: { width: 1440, height: 900 } });
    await p.goto('http://127.0.0.1:' + srv.address().port + '/'); await p.waitForTimeout(4000);   // the menu scripts move, rename and hide entries
    const items = await p.evaluate((LM) => {
            // an entry hidden only because its group is collapsed is still in the menu: count it (collapse is the person's choice)
      // collapsed groups hide their entries (display:none) - those are still in the menu; only the entries the menu scripts
      // took out (duplicate, outside the subscription / job role) or the portal hid on purpose (hidden) are not
      const shown = (li) => !li.hidden && !li.getAttribute('data-zyb-dup') && !li.getAttribute('data-zyb-sub-off');
      return [...document.querySelectorAll('ul.nav li[data-view], ul.nav li[data-zyb-href]')].filter((li) => !li.classList.contains('nav-group') && shown(li)).map((li) => {
        const v = li.getAttribute('data-view') || '', href = li.getAttribute('data-zyb-href') || '';
        const dest = href ? href.replace(/^\/dashboards\//, '') : LM[v] ? LM[v] : '#' + v;
        const name = (li.getAttribute('data-en') || li.textContent || '').replace(/\s+/g, ' ').trim();
        return { v, name, dest: dest.split('?')[0], start: li.hasAttribute('data-zyb-start') };
      });
    }, LIVEMAP);
    const byDest = {}, byName = {};
    const starts = items.filter((it) => it.start).length;
    for (const it of items.filter((x) => !x.start)) { (byDest[it.dest] = byDest[it.dest] || []).push(it.name + (it.v ? ' [' + it.v + ']' : '')); const k = it.name.toLowerCase(); if (k) (byName[k] = byName[k] || []).push(it.dest); }
    const dupDest = Object.entries(byDest).filter(([, v]) => v.length > 1), dupName = Object.entries(byName).filter(([, v]) => new Set(v).size > 1);
    ok(items.length > 150, 'menu entries seen: ' + items.length + ' (' + starts + ' Start here shortcuts)');
    ok(!dupDest.length, 'no page reachable from two menu entries (' + dupDest.length + '):\n  ' + dupDest.map(([d, v]) => d + ' <- ' + v.join(' | ')).join('\n  '));
    // a Start here shortcut may not be a second way to a page that has its own menu entry
    const startDup = items.filter((x) => x.start && byDest[x.dest]).map((x) => x.name + ' -> ' + x.dest + ' (also ' + byDest[x.dest].join(' | ') + ')');
    ok(!startDup.length, 'no Start here shortcut repeats another menu entry (' + startDup.length + '):\n  ' + startDup.join('\n  '));
    ok(!dupName.length, 'no two menu entries with the same name (' + dupName.length + '):\n  ' + dupName.map(([k, v]) => k + ' -> ' + v.join(' | ')).join('\n  '));
  } finally { await browser.close(); srv.close(); }
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks'); process.exit(bad ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });
