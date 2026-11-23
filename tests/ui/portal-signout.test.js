// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// The REAL portal (repos/live/portal) as the server has it (zyb-early.js after <head>): (1) a first sign-in on an empty cache
// never shows the old portal look - the page stays invisible while the platform style sheets load (one is delayed here) and appears
// once they are in; (2) Sign out ends the session and opens /login (it used to open /auth/login, "not found"); a sign-in service
// whose sign-out does not end the session is told to the person instead of pretending. SYNTHETIC identity. Skips without the live copy.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node portal-signout.test.js
const http = require('http'), fs = require('fs'), path = require('path'), cp = require('child_process');
const LIVE = path.resolve(__dirname, '../../repos/live/portal'), DASH = path.resolve(__dirname, '../../ui');
if (!fs.existsSync(path.join(LIVE, 'index.html'))) { console.log('SKIP: repos/live/portal not present'); process.exit(0); }
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const SH = fs.readFileSync(path.join(DASH, 'add-dashboards-menu.sh'), 'utf8'), ELINE = /ELINE='([^']+)'/.exec(SH)[1], AWK = /awk -v line="\$ELINE" '([^']+)'/.exec(SH)[1];
const INDEX = cp.execFileSync('awk', ['-v', 'line=' + ELINE, AWK, path.join(LIVE, 'index.html')], { encoding: 'utf8' });
let SESSION = true, LOGOUT_WORKS = true, LOGOUTS = [];
(async () => {
  const srv = http.createServer((req, res) => {
    const u = decodeURIComponent(req.url.split('?')[0]), json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u === '/auth/whoami' || u === '/dashboards/whoami.json') return SESSION ? json(200, { user: 'nora.syn', role: 'admin' }) : json(401, { error: 'signed out' });
    if (/^\/(auth\/)?(logout|signout)$/.test(u)) { LOGOUTS.push(req.method + ' ' + u); if (LOGOUT_WORKS && req.method === 'POST' && u === '/auth/logout') SESSION = false; res.writeHead(302, { Location: '/auth/login' }); return res.end(); }
    if (u === '/login') { res.writeHead(200, { 'Content-Type': 'text/html' }); return res.end('<!doctype html><title>Sign in</title><h1>Sign in SYN</h1>'); }
    if (u.startsWith('/api/soc/ui/menu')) return json(200, { order: null, favorites: [], can_edit_order: true });
    if (u.startsWith('/api/')) return json(404, { error: 'not in this test' });
    if (u === '/') { res.writeHead(200, { 'Content-Type': 'text/html' }); return res.end(INDEX); }
    const f = u.startsWith('/dashboards/') ? path.join(DASH, u.slice(12)) : path.join(LIVE, u);
    if (!f.startsWith(DASH) && !f.startsWith(LIVE)) { res.writeHead(403); return res.end(); }
    const send = () => fs.readFile(f, (e, d) => { if (e) { res.writeHead(404); return res.end(); } res.writeHead(200, { 'Content-Type': f.endsWith('.js') ? 'application/javascript' : f.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
    if (/zyb-vivid\.css$/.test(f)) return setTimeout(send, 1500);   // a slow first download of the platform look
    send();
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port;
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright'); const browser = await chromium.launch(); const errs = [];
  const wait = (p, fn) => p.waitForFunction(fn, null, { timeout: 20000 }).then(() => true, () => false);
  try {
    const p = await (await browser.newContext({ viewport: { width: 1366, height: 800 } })).newPage(); p.on('pageerror', (e) => errs.push(e.message));
    await p.goto(base + '/', { waitUntil: 'commit' });
    await p.waitForFunction(() => document.body, null, { timeout: 10000 });
    await p.waitForTimeout(600);
    ok(await p.evaluate(() => getComputedStyle(document.body).visibility === 'hidden' && !document.documentElement.classList.contains('zyb-look-ready')), 'while the look loads the old portal is not shown');
    ok(await wait(p, () => document.documentElement.classList.contains('zyb-look-ready') && getComputedStyle(document.body).visibility === 'visible'), 'shown once the look is in');
    ok(await p.evaluate(() => !!document.getElementById('zyb-vivid-css') && document.documentElement.classList.contains('zyb-modern')), 'in the platform look');
    // sign out
    await wait(p, () => document.getElementById('signOut'));
    p.once('dialog', (d) => d.accept());
    await p.evaluate(() => document.getElementById('signOut').click());
    ok(await wait(p, () => location.pathname === '/login'), 'sign out opens /login: ' + p.url());
    ok(/Sign in SYN/.test(await p.textContent('body')) && !SESSION && LOGOUTS[0] === 'POST /auth/logout', 'the session ended first: ' + LOGOUTS.join(', '));
    // a sign-out that does not end the session is said, not pretended
    SESSION = true; LOGOUT_WORKS = false; LOGOUTS = [];
    const q = await (await browser.newContext({ viewport: { width: 1366, height: 800 } })).newPage(); q.on('pageerror', (e) => errs.push(e.message));
    await q.goto(base + '/'); await wait(q, () => document.getElementById('signOut') && document.documentElement.classList.contains('zyb-look-ready'));
    q.once('dialog', (d) => d.accept()); await q.evaluate(() => document.getElementById('signOut').click());
    ok(await wait(q, () => /did not end the session/.test(document.body.innerText)), 'told when the session did not end');
    ok(new URL(q.url()).pathname === '/' && LOGOUTS.length >= 4, 'stayed, every route tried: ' + LOGOUTS.join(', '));
  } finally { await browser.close(); srv.close(); }
  ok(!errs.length, 'no page errors: ' + errs.slice(0, 3).join(' | '));
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks'); process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
