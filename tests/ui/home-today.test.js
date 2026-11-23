// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for the home page's "Today" band (dashboards/server/index.html) over stubbed, SYNTHETIC Executive Dashboard and
// Live Status answers: the health index with grade, ML trend and forecast; feeds live % with silent / late counts; the unusual-day
// and quiet-collector warning; "do these first" ranked across decisions, risks and feeds; the AI "what first" brief for an operator
// (posted to the Executive Dashboard brief) and refused for a viewer; both sources missing says so (never zeros); a hostile title
// stays text; the portal's Home opens this page.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node home-today.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const DASH = path.resolve(__dirname, '../../ui');
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const XSS = '<img src=x onerror="window.__xss=1">';
let ON = true, FOR_ROLE = true; const POSTS = [];
const EXEC = () => ({ index: 74, grade: 'adequate', decisions_waiting: 2, ml: { trend: { per_week: -1.5, verdict: 'worsening', days: 20 }, forecast_30d: 68, unusual: { today: 74, usual: 82, z: -3.4, direction: 'down' } },
  attention: [{ kind: 'decision', severity: 'high', score: 35, title: 'Approve firewall change ' + XSS, why: 'waiting for admin', link: 'network-engineer.html' }, { kind: 'gap', severity: 'low', score: 8, title: 'Enterprise IT risk is not measured', why: 'Risk Studio not installed', link: 'risk-studio.html' }],
  ai: { enabled: true, for_role: FOR_ROLE } });
const LIVE = { live_pct: 80, counts: { total: 6, live: 4, late: 0, silent: 1, waiting: 0, paused: 1 }, collector: { quiet: true }, findings: [{ severity: 'high', title: 'OLD-SW is silent', why: 'silent for 5 h' }, { severity: 'low', title: 'unknown senders', why: 'x' }] };

(async () => {
  const srv = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://x').pathname, json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u === '/dashboards/whoami.json') return json(200, { user: 'syed', role: 'admin' });
    if (u === '/api/itam/exec-dashboard' && req.method === 'GET') return ON ? json(200, EXEC()) : json(404, { error: 'not installed' });
    if (u === '/api/soc/collection/live') return ON ? json(200, LIVE) : json(404, { error: 'not installed' });
    if (u === '/api/itam/exec-dashboard/brief' && req.method === 'POST') { let b = ''; req.on('data', (c) => { b += c; }); req.on('end', () => { POSTS.push(JSON.parse(b)); json(200, { answer: '1. Restore OLD-SW logging (silent 5 h).', steps: [] }); }); return; }
    if (u.startsWith('/api/')) return json(404, { error: 'not in this test' });
    const f = path.join(DASH, u.replace(/^\/dashboards\//, '')); if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (e, d) => { if (e) { res.writeHead(404); return res.end(); } res.writeHead(200, { 'Content-Type': f.endsWith('.js') ? 'application/javascript' : f.endsWith('.css') ? 'text/css' : f.endsWith('.webp') ? 'image/webp' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const url = 'http://127.0.0.1:' + srv.address().port + '/dashboards/index.html?standalone=1';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright'); const browser = await chromium.launch(), errs = [];
  const wait = (p, fn, arg) => p.waitForFunction(fn, arg, { timeout: 15000 }).then(() => true, () => false);
  try {
    const ctx = await browser.newContext({ viewport: { width: 1500, height: 1000 } });
    const p = await ctx.newPage(); p.on('pageerror', (e) => errs.push(e.message));
    await p.goto(url); ok(await wait(p, () => /74/.test(document.querySelector('#t2-idx .big').textContent)), 'health index');
    if (process.env.SHOT) await p.screenshot({ path: process.env.SHOT, fullPage: false });   // optional: a picture for review
    const idx = await p.textContent('#t2-idx'); ok(/adequate/.test(idx) && /worsening -1.5\/week/.test(idx) && /≈ 68 in 30 days/.test(idx) && /2 decisions waiting/.test(idx), 'grade, ML trend, forecast, decisions');
    const lv = await p.textContent('#t2-live'); ok(/80%/.test(lv) && /4 of 5 live/.test(lv) && /1 silent/.test(lv) && /collectors quiet/.test(lv), 'feeds live with silent count');
    ok(/unusual today: 74 against a usual 82/.test(await p.textContent('#t2warn')) && /collectors may be down/.test(await p.textContent('#t2warn')), 'unusual-day and quiet-collector warning');
    const items = await p.$$eval('#t2-first li', (l) => l.map((x) => x.textContent));
    ok(items.length === 3 && /Approve firewall change/.test(items[0]) && /OLD-SW is silent/.test(items[1]) && /not measured/.test(items[2]), 'ranked across decision, feed, gap (a low finding is not listed): ' + JSON.stringify(items));
    ok((await p.getAttribute('#t2-first li:nth-child(2) a', 'href')) === 'live-status.html', 'a feed problem links to Live Status');
    await p.click('#t2ask'); ok(await wait(p, () => /Restore OLD-SW logging/.test(document.getElementById('t2-ai').textContent)), 'AI what-first answer');
    ok(POSTS.length === 1 && /What should I do first today/.test(POSTS[0].question), 'asked through the Executive Dashboard brief');
    ok(!(await p.evaluate(() => window.__xss)), 'hostile title stayed text');
    FOR_ROLE = false; const q = await ctx.newPage(); await q.goto(url); await wait(q, () => /74/.test(document.querySelector('#t2-idx .big').textContent));
    ok(!(await q.$('#t2ask')) && /for operators and administrators/.test(await q.textContent('#t2-ai')), 'viewer: no AI button');
    ON = false; const r = await ctx.newPage(); await r.goto(url);
    ok(await wait(r, () => /not installed/.test(document.getElementById('t2-idx').textContent) && /not installed/.test(document.getElementById('t2-live').textContent)), 'missing sources say so, never zeros');
    ok(/not reachable yet/.test(await r.textContent('#t2-first')), 'no ranked list without sources');
    ok(/home: 'index\.html'/.test(fs.readFileSync(path.join(DASH, 'vendor', 'zyb-menu.js'), 'utf8')) && /home: 'index\.html'/.test(fs.readFileSync(path.join(DASH, 'vendor', 'zyb-early.js'), 'utf8')), 'the portal\'s Home opens this page');
    ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  } finally { await browser.close(); srv.close(); }
  console.log((bad ? 'FAILED ' : 'ok ') + (n - bad) + '/' + n);
  process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
