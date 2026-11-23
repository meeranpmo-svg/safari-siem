// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for the licence banner (vendor/zyb-dash.js) with a stubbed /api/itam/licence (synthetic): during the grace period
// the banner shows the reason and the date; its close button hides it - for 7 days, or only until tomorrow in the last 7 days - and
// it stays hidden after a reload; once locked, the lock screen has no close button; no licence problem, no banner.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node licence-banner.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const DASH = path.join(__dirname, '..', '..', 'ui');
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
let LIC = null;
const grace = (days) => ({ enforcement: { enforced: true, ok: false, gate: 'grace', reason: 'no licence is installed', grace_until: '2027-02-09T08:00:00Z', grace_days_left: days, fingerprint: 'SYNT-HETI-CFPX-0001' } });
(async () => {
  const srv = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://x'), json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u.pathname === '/dashboards/whoami.json') return json(200, { user: 'syn.admin', role: 'admin' });
    if (u.pathname === '/api/itam/licence') return LIC ? json(200, LIC) : json(200, { enforcement: { enforced: true, ok: true, gate: 'ok' } });
    if (u.pathname.startsWith('/api/') || u.pathname === '/') return json(404, { error: 'not in this test' });
    const f = path.join(DASH, u.pathname.replace(/^\/dashboards\//, '/')); if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (e, d) => { if (e) { res.writeHead(404); return res.end(); } res.writeHead(200, { 'Content-Type': f.endsWith('.js') ? 'application/javascript' : f.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const url = 'http://127.0.0.1:' + srv.address().port + '/dashboards/business-risk.html?standalone=1';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  const banner = (p) => p.waitForSelector('#zybLicence', { timeout: 8000 }).then(() => true, () => false);
  try {
    const p = await browser.newPage(); p.on('pageerror', (e) => errs.push(e.message));
    LIC = null; await p.goto(url); await p.waitForTimeout(1500); ok(!(await p.$('#zybLicence')), 'a valid licence: no banner');
    LIC = grace(88); await p.goto(url); ok(await banner(p), 'grace: the banner shows');
    ok(/no licence is installed/.test(await p.textContent('#zybLicence')) && /2027-02-09 \(88 days\)/.test(await p.textContent('#zybLicence')), 'it says why and until when');
    ok(await p.getAttribute('#zybLicenceClose', 'title') === 'Hide for 7 days', 'the close button says what it does');
    await p.click('#zybLicenceClose'); ok(!(await p.$('#zybLicence')), 'closed');
    const until = await p.evaluate(() => Number(localStorage.getItem('zyb-licence-hidden')) - Date.now());
    ok(until > 6.9 * 86400000 && until <= 7 * 86400000 + 1000, 'hidden for 7 days: ' + Math.round(until / 3600000) + ' h');
    await p.goto(url); await p.waitForTimeout(1500); ok(!(await p.$('#zybLicence')), 'still hidden after a reload');
    // the last week before the lock: hidden only until tomorrow
    await p.evaluate(() => localStorage.removeItem('zyb-licence-hidden')); LIC = grace(5); await p.goto(url); ok(await banner(p), 'shows again once the hiding ends');
    ok(await p.getAttribute('#zybLicenceClose', 'title') === 'Hide until tomorrow', 'in the last 7 days: until tomorrow');
    await p.click('#zybLicenceClose');
    const tm = await p.evaluate(() => { const t = Number(localStorage.getItem('zyb-licence-hidden')), d = new Date(t); return { h: d.getHours(), m: d.getMinutes(), left: t - Date.now() }; });
    ok(tm.h === 0 && tm.m === 0 && tm.left > 0 && tm.left <= 86400000, 'hidden until midnight: ' + JSON.stringify(tm));
    // locked: no close button
    await p.evaluate(() => localStorage.removeItem('zyb-licence-hidden'));
    LIC = { enforcement: { enforced: true, ok: false, gate: 'locked', reason: 'no licence is installed', fingerprint: 'SYNT-HETI-CFPX-0001' } }; await p.goto(url);
    ok(await banner(p) && !(await p.$('#zybLicenceClose')) && /The platform licence is not valid/.test(await p.textContent('#zybLicence')), 'locked: the lock screen cannot be closed');
  } finally { await browser.close(); srv.close(); }
  ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks'); process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
