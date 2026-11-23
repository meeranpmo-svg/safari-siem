// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for the Sign out button in the dashboards' top bar (vendor/zyb-dash.js): shown on the home page and on a
// dashboard; when the sign-in service ends the session (/auth/whoami then answers 401) the browser goes to /login; when
// no sign-out route ends it, the page says so and stays - it never claims a sign-out that did not happen.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node signout.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const DASH = path.resolve(__dirname, '../../ui');
let n = 0, bad = 0;
const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
let SIGNED = true, ROUTE = '/auth/logout'; const hits = [];
(async () => {
  const srv = http.createServer((req, res) => {
    const u = req.url.split('?')[0], json = (c, o) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(o)); };
    if (u === ROUTE) { hits.push(req.method + ' ' + u); SIGNED = false; return json(200, { ok: true }); }
    if (/logout|signout/.test(u)) { hits.push(req.method + ' ' + u); return json(404, {}); }
    if (u === '/auth/whoami') return SIGNED ? json(200, { user: 'syed', role: 'admin' }) : json(401, { error: 'sign in' });
    if (u === '/login') { res.writeHead(200, { 'Content-Type': 'text/html' }); return res.end('<title>Sign in</title><h1>Sign in</h1>'); }
    if (u.endsWith('whoami.json')) return json(200, { user: 'syed', role: 'admin' });
    if (u.startsWith('/api/')) return json(404, {});
    const f = path.join(DASH, u.replace(/^\/dashboards\//, '/'));
    if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (e, d) => { if (e) { res.writeHead(404); return res.end(); } res.writeHead(200, { 'Content-Type': u.endsWith('.js') ? 'application/javascript' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port + '/dashboards/';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  let page = await browser.newPage({ viewport: { width: 1400, height: 900 } }); page.on('pageerror', (e) => errs.push(e.message));
  await page.goto(base + 'index.html'); await page.waitForSelector('#zyb-out');
  ok(await page.isVisible('#zyb-out'), 'Sign out button on the home page');
  ok(/Sign out/.test(await page.getAttribute('#zyb-out', 'aria-label') || ''), 'labelled for screen readers');
  await Promise.all([page.waitForURL(/\/login$/), page.click('#zyb-out')]);
  ok(/Sign in/.test(await page.title()), 'session ended → sign-in page');
  ok(hits[0] === 'POST /auth/logout', 'POST /auth/logout first: ' + hits);

  SIGNED = true; hits.length = 0; ROUTE = '/logout';
  await page.goto(base + 'capacity.html'); await page.waitForSelector('#zyb-out');
  ok(await page.isVisible('#zyb-out'), 'Sign out button on a dashboard page');
  await Promise.all([page.waitForURL(/\/login$/), page.click('#zyb-out')]);
  ok(hits.join(',') === 'POST /auth/logout,POST /logout', 'falls through to the route the service has: ' + hits);

  SIGNED = true; hits.length = 0; ROUTE = '/none';
  await page.goto(base + 'index.html'); await page.waitForSelector('#zyb-out'); await page.click('#zyb-out');
  await page.waitForSelector('#zyb-out-msg', { timeout: 8000 });
  ok(/did not end the session/.test(await page.textContent('#zyb-out-msg')) && /index\.html$/.test(page.url()), 'no sign-out route: says so, stays on the page');
  ok(hits.length === 4 && await page.isEnabled('#zyb-out'), 'tried every route, button usable again: ' + hits);
  ok(!errs.length, 'page errors: ' + errs.join(' | '));
  await browser.close(); srv.close();
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks'); process.exit(bad ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });
