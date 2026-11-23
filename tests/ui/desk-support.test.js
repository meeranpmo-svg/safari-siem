// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// desk-support.html (AI Desktop Support Engineer) against the REAL engine (backend/itam engine/desksupport.js) with a SYNTHETIC
// asset register: with Endpoint Central not connected the register's desktops and laptops are still listed, marked "no agent", with
// the reason and a link to the asset (never a patch button); servers and retired assets are not; search filters; a hostile asset
// name stays text.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node desk-support.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const ITAM = path.join(__dirname, '..', '..', 'backend', 'itam'), DASH = path.join(__dirname, '..', '..', 'ui');
const H = require(path.join(ITAM, 'tests', 'helpers'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const XSS = '<img src=x onerror="window.__xss=1">';
(async () => {
  const e = await H.startApp({ noAi: true });
  require(path.join(ITAM, 'engine/desksupport')).registerDeskSupport(e.app.srv, e.app);
  const A = e.app.store.collection('assets');
  A.put({ id: 'a1', type: 'laptop', name: 'LT-FIN-07', custodian: 'mona.syn', site: 'Riyadh HQ', os: 'Windows 11 Pro', status: 'in_use' });
  A.put({ id: 'a2', type: 'other', name: 'VDI-' + XSS, os: 'Windows 10 Enterprise', status: 'in_use' });
  A.put({ id: 'a3', type: 'server', name: 'SRV-APP-01', os: 'Windows Server 2022', status: 'in_use' });
  A.put({ id: 'a4', type: 'workstation', name: 'PC-OLD-99', status: 'retired' });
  const who = { user: 'nora.syn', role: 'operator' };
  const srv = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://x'), json = (code, b) => { res.writeHead(code, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u.pathname === '/dashboards/whoami.json') return json(200, who);
    if (u.pathname.startsWith('/api/itam/')) { const h = Object.assign({}, req.headers, { 'x-sentra-proxy-secret': H.SECRET, 'x-auth-user': who.user, 'x-auth-role': who.role });
      const up = http.request({ host: '127.0.0.1', port: e.port, method: req.method, path: req.url, headers: h }, (r) => { res.writeHead(r.statusCode, r.headers); r.pipe(res); }); req.pipe(up); return; }
    if (u.pathname.startsWith('/api/')) return json(404, { error: 'not in this test' });
    const f = path.join(DASH, u.pathname.replace(/^\/dashboards\//, '/')); if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (err, d) => { if (err) { res.writeHead(404); res.end(); return; } res.writeHead(200, { 'Content-Type': u.pathname.endsWith('.js') ? 'application/javascript' : u.pathname.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const url = 'http://127.0.0.1:' + srv.address().port + '/dashboards/desk-support.html';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  const wait = (p, fn, arg) => p.waitForFunction(fn, arg === undefined ? null : arg, { timeout: 30000 }).then(() => true, () => false);
  try {
    const p = await browser.newPage({ viewport: { width: 1400, height: 1000 } }); p.on('pageerror', (x) => errs.push(x.message));
    await p.goto(url + '?standalone=1');
    ok(await wait(p, () => document.querySelectorAll('#desktops tbody tr').length === 2), 'the two desktops from the asset register are listed without Endpoint Central');
    const D = await p.textContent('#desktops');
    ok(/Endpoint Central is not connected/.test(D) && /come from the asset register/.test(D), 'says where they come from');
    ok(/LT-FIN-07/.test(D) && /no agent/.test(D) && /no Endpoint Central agent/.test(D) && !/SRV-APP-01/.test(D) && !/PC-OLD-99/.test(D), 'no-agent gap named; no server, no retired asset');
    ok(/2 from the asset register with no Endpoint Central agent/.test(await p.textContent('#dhc')), 'count with the gap');
    ok(!(await p.$('#desktops [data-patchreq]')) && await p.$('#desktops a[href^="inventory.html#asset="]'), 'no patch button for an agentless desktop; a link to its asset');
    await p.click('[data-tab="desktops"]'); await p.fill('#dq', 'mona'); ok(await wait(p, () => document.querySelectorAll('#desktops tbody tr').length === 1), 'search');
    ok(!(await p.evaluate(() => window.__xss)), 'a hostile asset name stayed text');
    ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  } finally { await browser.close(); srv.close(); await e.close(); }
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n);
  process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
