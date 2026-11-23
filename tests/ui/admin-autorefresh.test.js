// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Auto-refresh on the administration pages (vendor/zyb-autorefresh.js on identity-signin.html, user-management.html,
// solution-admin.html) with a stubbed API and SYNTHETIC answers, the clock driven by Playwright: the page reads itself again every
// 30 s; it waits while a field has focus, after typing, while a confirmation dialog is open, and while a form field holds an
// unsaved change - and says why on the chip; Pause stops it and is remembered on the next visit; Resume and "refresh now" read at
// once; a hidden tab is not refreshed. The other two pages carry the chip and refresh too.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node admin-autorefresh.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const DASH = path.resolve(__dirname, '../../ui');
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const HITS = {};
const CFG = { users: [{ user: 'adam.syn', role: 'admin', name: 'Adam (synthetic)', totp: true }, { user: 'nora.syn', role: 'operator', name: 'Nora (synthetic)', totp: true }], sso: { enabled: false, roleMap: {} }, events: [], me: 'adam.syn' };
(async () => {
  const srv = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://x'), json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    HITS[u.pathname] = (HITS[u.pathname] || 0) + 1;
    if (u.pathname === '/dashboards/whoami.json' || u.pathname === '/auth/whoami') return json(200, { user: 'adam.syn', role: 'admin' });
    if (u.pathname === '/auth/admin/config') return json(200, CFG);
    if (u.pathname === '/auth/org') return json(200, { modules: null, edition: 'Enterprise' });
    if (u.pathname.startsWith('/api/') || u.pathname.startsWith('/auth/')) return json(404, { error: 'not in this test' });
    const f = path.join(DASH, u.pathname.replace(/^\/dashboards\//, '/')); if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (err, d) => { if (err) { res.writeHead(404); res.end(); return; } res.writeHead(200, { 'Content-Type': u.pathname.endsWith('.js') ? 'application/javascript' : u.pathname.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port + '/dashboards/';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  const wait = (p, fn, arg) => p.waitForFunction(fn, arg, { timeout: 15000 }).then(() => true, () => false);
  const cfgHits = () => HITS['/auth/admin/config'] || 0;
  const settle = (p) => p.waitForTimeout(400);
  try {
    const ctx = await browser.newContext({ viewport: { width: 1400, height: 1000 } });
    const p = await ctx.newPage(); p.on('pageerror', (x) => errs.push(x.message));
    await p.clock.install();
    await p.goto(base + 'identity-signin.html?standalone=1'); ok(await wait(p, () => document.querySelector('.zyb-ar')), 'the chip is on Identity & Sign-in');
    await settle(p); const h0 = cfgHits();
    ok(/auto every\s*30 s/.test(await p.textContent('.zyb-ar')), 'the chip says how often');
    await p.clock.runFor(31000); await settle(p); ok(cfgHits() === h0 + 1, 'read again after 30 s: ' + cfgHits() + ' vs ' + h0 + ' - ' + await p.textContent('.zyb-ar'));
    // waits while working
    await p.evaluate(() => { const i = document.createElement('input'); i.id = 'synthetic-field'; document.querySelector('main').appendChild(i); i.focus(); });
    await p.clock.runFor(31000); await settle(p); ok(cfgHits() === h0 + 1, 'not while a field has focus');
    ok(/waiting - a field is in use/.test(await p.textContent('.zyb-ar')), 'the chip says why it waits');
    await p.keyboard.type('abc'); await p.evaluate(() => document.activeElement.blur());
    await p.clock.runFor(31000); await settle(p); ok(cfgHits() === h0 + 1, 'not within a minute of typing');
    await p.clock.runFor(61000); await settle(p);   // ticks fall every 30 s from load: wait past one that is a full minute after the typing
    ok(/a change is not saved yet/.test(await p.textContent('.zyb-ar')) && cfgHits() === h0 + 1, 'not while a typed value is unsaved: ' + cfgHits() + ' ' + await p.textContent('.zyb-ar'));
    await p.evaluate(() => document.getElementById('synthetic-field').remove());
    await p.clock.runFor(31000); await settle(p); ok(cfgHits() === h0 + 2, 'resumes once the edit is gone');
    await p.evaluate(() => document.getElementById('dlgbg').classList.add('open'));
    await p.clock.runFor(31000); await settle(p); ok(cfgHits() === h0 + 2 && /a dialog is open/.test(await p.textContent('.zyb-ar')), 'not while a confirmation dialog is open');
    await p.evaluate(() => document.getElementById('dlgbg').classList.remove('open'));
    await p.clock.runFor(31000); await settle(p); ok(cfgHits() === h0 + 3, 'resumes when the dialog closes');
    // pause / resume / now, remembered
    await p.click('.zyb-ar [data-ar-p]'); ok(/auto-refresh paused/.test(await p.textContent('.zyb-ar')), 'pause');
    await p.clock.runFor(95000); await settle(p); ok(cfgHits() === h0 + 3, 'paused: no read');
    await p.click('.zyb-ar [data-ar-now]'); await settle(p); ok(cfgHits() === h0 + 4, 'refresh now reads at once, even paused');
    await p.reload(); await wait(p, () => document.querySelector('.zyb-ar')); ok(/auto-refresh paused/.test(await p.textContent('.zyb-ar')), 'the pause is remembered');
    const h1 = cfgHits(); await p.click('.zyb-ar [data-ar-p]'); await settle(p); ok(cfgHits() === h1 + 1 && /auto every/.test(await p.textContent('.zyb-ar')), 'resume reads at once');
    // the other two administration pages
    for (const [pg, path0] of [['user-management.html', '/auth/admin/config'], ['solution-admin.html', '/auth/org']]) {
      const q = await ctx.newPage(); q.on('pageerror', (x) => errs.push(pg + ': ' + x.message)); await q.clock.install();
      await q.goto(base + pg + '?standalone=1'); ok(await wait(q, () => document.querySelector('.zyb-ar')), pg + ': chip present');
      await q.waitForTimeout(600); const a = HITS[path0] || 0; await q.clock.runFor(31000); await q.waitForTimeout(600);
      ok((HITS[path0] || 0) > a, pg + ': read again after 30 s'); await q.close();
    }
    ok(fs.readFileSync(path.join(DASH, 'install-dashboards.sh'), 'utf8').includes('vendor/zyb-autorefresh.js'), 'installer ships the helper');
    ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  } finally { await browser.close(); srv.close(); }
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n);
  process.exit(bad ? 1 : 0);
})();
