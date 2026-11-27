// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Add a server - Windows (add-server.html) against the REAL IT Asset Management engine, SYNTHETIC names: Windows is offered; it
// hides the SSH / SNMP scan form and shows the three ways in (register now, the asset agent, Active Directory); a bad name or IP is
// refused on the page; Add creates the asset (server / workstation, Windows OS, IP, site, tag windows, domain-controller for a
// DC) and links to it; the Linux / network choices still show their own form; a hostile name stays text.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node add-server-windows.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const DASH = path.resolve(__dirname, '../../ui'), ITAM = path.resolve(__dirname, '../../backend/itam');
const H = require(path.join(ITAM, 'tests/helpers'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
(async () => {
  const e = await H.startApp({ noAi: true }), WHO = { user: 'admin.syn', role: 'admin' };
  const srv = http.createServer((req, res) => { const u = new URL(req.url, 'http://x');
    if (u.pathname === '/dashboards/whoami.json') { res.writeHead(200, { 'Content-Type': 'application/json' }); return res.end(JSON.stringify(WHO)); }
    if (u.pathname.startsWith('/api/itam/')) { const h = Object.assign({}, req.headers, { 'x-sentra-proxy-secret': H.SECRET, 'x-auth-user': WHO.user, 'x-auth-role': WHO.role });
      const up = http.request({ host: '127.0.0.1', port: e.port, method: req.method, path: req.url, headers: h }, (r) => { res.writeHead(r.statusCode, r.headers); r.pipe(res); }); req.pipe(up); return; }
    if (u.pathname.startsWith('/api/')) { res.writeHead(404, { 'Content-Type': 'application/json' }); return res.end('{"error":"not in this test"}'); }
    fs.readFile(path.join(DASH, u.pathname.replace(/^\/dashboards\//, '/')), (err, d) => { if (err) { res.writeHead(404); return res.end(); } res.writeHead(200, { 'Content-Type': u.pathname.endsWith('.js') ? 'application/javascript' : u.pathname.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); }); });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright'); const browser = await chromium.launch(), errs = [];
  try {
    const p = await browser.newPage({ viewport: { width: 1300, height: 1000 } }); p.on('pageerror', (x) => errs.push(x.message));
    await p.goto('http://127.0.0.1:' + srv.address().port + '/dashboards/add-server.html?standalone=1'); await p.waitForSelector('#dtype');
    await p.selectOption('#dtype', 'windows');
    ok(await p.isVisible('#winp') && !(await p.isVisible('#ip')) && !(await p.isVisible('#go')), 'Windows: its own panel, no SSH / SNMP scan form');
    const t = await p.textContent('#winp'); ok(/Register it now/.test(t) && /asset agent/.test(t) && /Active Directory/.test(t) && !!(await p.$('#winp a[href="agents.html"]')), 'the three ways in');
    await p.fill('#wname', 'bad name;'); await p.click('#wgo'); ok(/Computer name/.test(await p.textContent('#wmsg')), 'a bad name is refused on the page');
    await p.fill('#wname', 'HQ-FS-SYN01'); await p.fill('#wip', '10.0.1.300x'); await p.click('#wgo'); ok(/IP address/.test(await p.textContent('#wmsg')), 'a bad IP is refused on the page');
    await p.fill('#wip', '10.0.1.25'); await p.fill('#wos', 'Windows Server 2022'); await p.fill('#wsite', 'Riyadh HQ'); await p.click('#wgo');
    await p.waitForFunction(() => /Added/.test(document.getElementById('wmsg').textContent), null, { timeout: 10000 });
    const A = e.app.store.collection('assets').all().find((a) => a.name === 'HQ-FS-SYN01');
    ok(A && A.type === 'server' && /Windows Server 2022/.test(A.os || '') && A.mgmt_ip === '10.0.1.25' && (A.tags || []).includes('windows'), 'the asset is created: ' + JSON.stringify(A && { type: A.type, os: A.os, ip: A.mgmt_ip, tags: A.tags, site: A.site }));
    ok(!!(await p.$('#wmsg a[href^="inventory.html#asset="]')), 'links to the new record');
    await p.fill('#wname', 'DC-SYN01'); await p.fill('#wip', '10.0.1.10'); await p.selectOption('#wrole', 'dc'); await p.fill('#wos', ''); await p.click('#wgo');
    await p.waitForFunction(() => /Added/.test(document.getElementById('wmsg').textContent) && document.getElementById('wmsg').textContent.length, null, { timeout: 10000 }); await p.waitForTimeout(300);
    const D = e.app.store.collection('assets').all().find((a) => a.name === 'DC-SYN01'); ok(D && (D.tags || []).includes('domain-controller') && /Windows Server/.test(D.os || ''), 'a domain controller is tagged');
    await p.selectOption('#dtype', 'server'); ok(await p.isVisible('#ip') && !(await p.isVisible('#winp')), 'Linux / Unix: the SSH form is back');
    await p.selectOption('#dtype', 'network'); ok(await p.isVisible('#drole') && !(await p.isVisible('#winp')), 'network: the SNMP form');
    ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  } finally { await browser.close(); srv.close(); await e.close(); }
  console.log((bad ? 'FAILED ' : 'ok ') + (n - bad) + '/' + n + ' add-server-windows checks'); process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
