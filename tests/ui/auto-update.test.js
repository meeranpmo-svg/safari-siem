// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for vendor/zyb-update.js: after an update an open page refreshes by itself - the browser cache is cleared
// first (/dashboards/clear-cache) - but never in a loop and never under someone who is typing (a bar offers the reload).
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node auto-update.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const DASH = path.join(__dirname, '..', '..', 'ui');
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };

let SERVER_BUILD = '20261028070000';
const hits = { clear: 0, page: 0 };
const PAGE = (b) => '<!doctype html><html><head><meta charset="utf-8"><title>Synthetic</title><script>window.ZYB_BUILD = "' + b + '";</script><script src="/dashboards/vendor/zyb-update.js"></script></head><body><main><h1>Synthetic page</h1><input id="q"></main></body></html>';

(async () => {
  const srv = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://x');
    if (u.pathname === '/dashboards/page.html') { hits.page++; res.writeHead(200, { 'Content-Type': 'text/html', 'Cache-Control': 'no-cache' }); return res.end(PAGE(u.searchParams.get('b') || '20261028070000')); }
    if (u.pathname === '/dashboards/build.json') { res.writeHead(200, { 'Content-Type': 'application/json', 'Cache-Control': 'no-cache' }); return res.end(JSON.stringify({ build: SERVER_BUILD })); }
    if (u.pathname === '/dashboards/clear-cache') { hits.clear++; res.writeHead(204, { 'Clear-Site-Data': '"cache"', 'Cache-Control': 'no-store' }); return res.end(); }
    const f = path.join(DASH, u.pathname.replace(/^\/dashboards\//, '/')); if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (err, d) => { if (err) { res.writeHead(404); return res.end(); } res.writeHead(200, { 'Content-Type': 'application/javascript' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port;
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  try {
    const p = await browser.newPage(); p.on('pageerror', (e) => errs.push(e.message));
    await p.goto(base + '/dashboards/page.html'); await p.waitForTimeout(500);
    const loads0 = hits.page;
    // same build on the server: nothing happens
    await p.evaluate(() => window.zybUpdate.check()); await p.waitForTimeout(400);
    ok(hits.page === loads0 && hits.clear === 0, 'same build: no reload, no cache clear');
    // an update: the cache is cleared, then the page reloads once
    SERVER_BUILD = '20261028080000';
    await p.evaluate(() => window.zybUpdate.check()); await p.waitForTimeout(1200);
    ok(hits.clear === 1 && hits.page === loads0 + 1, 'new build: cache cleared, page reloaded once (clear ' + hits.clear + ', loads ' + (hits.page - loads0) + ')');
    // the reloaded page still says the old build (a stale proxy, say): no second reload - the bar is offered instead
    await p.evaluate(() => window.zybUpdate.check()); await p.waitForTimeout(800);
    ok(hits.page === loads0 + 1 && await p.isVisible('#zyb-update'), 'never reloads twice for one build: the bar is shown instead');
    await p.click('#zyb-update button:last-child');
    ok(!(await p.$('#zyb-update')), '"Later" hides the bar');

    // someone typing is never interrupted
    const q = await browser.newPage(); q.on('pageerror', (e) => errs.push(e.message));
    SERVER_BUILD = '20261028090000';
    await q.goto(base + '/dashboards/page.html?b=20261028090000'); await q.waitForTimeout(400);
    await q.fill('#q', 'half-typed text');
    SERVER_BUILD = '20261028100000';
    const l1 = hits.page; await q.evaluate(() => window.zybUpdate.check()); await q.waitForTimeout(800);
    ok(hits.page === l1 && await q.isVisible('#zyb-update') && (await q.inputValue('#q')) === 'half-typed text', 'typing: no reload, the bar offers it, the text stays');
    ok(/new version of the platform is installed/.test(await q.textContent('#zyb-update')), 'the bar says what happened');
    const c1 = hits.clear; await q.click('#zyb-update button'); await q.waitForTimeout(1200);
    ok(hits.clear === c1 + 1 && hits.page === l1 + 1, '"Reload now" clears the cache and reloads');

    // a page the browser kept from before an update (here: served with the old build) is caught as soon as it opens,
    // with no waiting for the one-minute round and no manual check
    await p.close(); await q.close();   // other open tabs would notice the new build too (rightly) and blur the counts
    const st = await browser.newPage(); st.on('pageerror', (e) => errs.push(e.message));
    SERVER_BUILD = '20261028110000'; const c2 = hits.clear, l3 = hits.page;
    await st.goto(base + '/dashboards/page.html?b=20261028100000'); await st.waitForTimeout(3500);
    ok(hits.clear === c2 + 1 && hits.page === l3 + 2, 'a stale page refreshes by itself within seconds of opening (clear ' + (hits.clear - c2) + ', loads ' + (hits.page - l3) + ')');
    // back / forward cache: the browser shows the old page from memory - pageshow (persisted) asks the server again
    const bf = await browser.newPage(); bf.on('pageerror', (e) => errs.push(e.message));
    await bf.goto(base + '/dashboards/page.html?b=20261028110000'); await bf.waitForTimeout(2200);
    SERVER_BUILD = '20261028120000'; const c3 = hits.clear;
    await bf.evaluate(() => window.dispatchEvent(new PageTransitionEvent('pageshow', { persisted: true }))); await bf.waitForTimeout(1500);
    ok(hits.clear === c3 + 1, 'a page restored from the back/forward cache checks at once and refreshes');
    // focus and pageshow firing together ask the server once
    let asks = 0; const fo = await browser.newPage(); fo.on('request', (r) => { if (/build\.json/.test(r.url())) asks++; });
    await fo.goto(base + '/dashboards/page.html?b=20261028120000'); await fo.waitForTimeout(2200); asks = 0;
    await fo.evaluate(() => { window.dispatchEvent(new Event('focus')); window.dispatchEvent(new Event('focus')); window.dispatchEvent(new Event('focus')); }); await fo.waitForTimeout(600);
    ok(asks === 0, 'focus right after the opening check: no extra request (' + asks + ')');
    const src = fs.readFileSync(path.join(DASH, 'vendor', 'zyb-update.js'), 'utf8');
    ok(/EVERY = 60000/.test(src), 'open pages check every minute');

    // the server not answering (signed out, offline): nothing happens, no error
    const r = await browser.newPage(); r.on('pageerror', (e) => errs.push(e.message));
    await r.route('**/dashboards/build.json*', (route) => route.fulfill({ status: 302, headers: { Location: '/login' } }));
    await r.goto(base + '/dashboards/page.html?b=20261028100000'); await r.waitForTimeout(300);
    const l2 = hits.page; await r.evaluate(() => window.zybUpdate.check()); await r.waitForTimeout(500);
    ok(hits.page === l2 && !(await r.$('#zyb-update')), 'no answer from the server: page left alone');
  } finally { await browser.close(); srv.close(); }
  ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks');
  process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
