// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Live Status (live-status.html) against the REAL SIEM module (sentra-siem engine/onboard/livestatus.js) over a SYNTHETIC assurance
// model and 7 days of samples: live % ring and tiles with the real counts, collector line, findings (silent, late, volume dropped),
// feed cards worst first with a sparkline and health, state chips and search filter, feed detail with rhythm and same-hour volume,
// Record sample (operator, audited; a viewer does not see it), AI off says why, Excel, a hostile feed label stays text, nothing
// enrolled says what to connect, the menu entry and the portal redirect (view "status").
// Colourful: the pulse over 7 days, feeds by type, about to go late, a 24-hour colour strip on each card, state tiles that filter.
// Run: SENTRA_SIEM_DIR=/home/user/sentra-siem PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node live-status.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const DASH = path.resolve(__dirname, '../../ui');
const SIEM = process.env.SENTRA_SIEM_DIR || path.resolve(__dirname, '../../backend/siem');
const L = require(path.join(SIEM, 'engine/onboard/livestatus'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const XSS = '<img src=x onerror="window.__xss=1">';
const MIN = 60000, DAY = 86400000, NOW = Date.now();
const src = (o) => Object.assign({ kind: 'fortigate', site: 'HQ', state: 'receiving', sla_min: 60, eps_1h: 50, events_24h: 4000, last_seen: NOW - 30000, parse_error_rate_1h: 0, lag_p95_s: 5 }, o);
let MODEL = { policy: {}, collector: { last_event: NOW - 30000, quiet: false, eps_1h: 120 }, unknown_senders: [],
  sources: [src({ src_id: 'fw-hq', label: 'FGT-HQ' }), src({ src_id: 'fw-jed', label: 'FGT-JED ' + XSS, last_seen: NOW - 40 * MIN }), src({ src_id: 'win-dc', label: 'DC01', kind: 'windows', eps_1h: 2 }),
    src({ src_id: 'old', label: 'OLD-SW', state: 'silent', last_seen: NOW - 5 * 3600000 }), src({ src_id: 'p', label: 'LAB', paused: true, state: 'paused' })] };
const store = new Map(), state = { collection: () => ({ all: () => [...store.values()], put: (x) => store.set(x.id, x), remove: (id) => store.delete(id) }) };
for (let t = NOW - 7 * DAY; t < NOW - 15 * MIN; t += 15 * MIN) { const i = Math.round(t / (15 * MIN)); store.set(String(i), { id: String(i), t, eps: { 'fw-hq': 50, 'fw-jed': 48, 'win-dc': 40 + (i % 3), old: 10 } }); }
const routes = {}, AUD = [];
L.register({ route: (m, p, fn) => { routes[m + ' ' + p] = fn; } }, { now: () => Date.now(), state, noTimers: true, config: {} }, { model: async () => MODEL }, '/api/soc/collection');
let ROLE = 'operator'; const RANK = { viewer: 1, analyst: 2, operator: 3, admin: 4 };

(async () => {
  const srv = http.createServer((req, res) => {
    const url = new URL(req.url, 'http://x'), u = url.pathname, json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u === '/dashboards/whoami.json' || u === '/auth/whoami') return json(200, { user: ROLE + '.syn', role: ROLE });
    const key = req.method + ' ' + u;
    if (routes[key]) { let b = ''; req.on('data', (c) => { b += c; }); req.on('end', async () => { let out = null;
      const ctx = { query: Object.fromEntries(url.searchParams), body: b ? JSON.parse(b) : {}, role: ROLE, user: ROLE + '.syn', path: u, ok: (x) => { out = [200, x]; return out; }, fail: (s, m) => { out = [s, { error: m }]; return out; },
        need: (r) => { if ((RANK[ROLE] || 0) < RANK[r]) { out = [403, { error: 'requires role ' + r }]; return false; } return true; }, audit: (a, t, d) => AUD.push({ a, t, d }) };
      try { await routes[key](ctx); } catch (e) { out = [e.code || e.status || 500, { error: e.message }]; } json(out[0], out[1]); }); return; }
    if (u.startsWith('/api/')) return json(404, { error: 'not in this test' });
    const f = path.join(DASH, u.replace(/^\/dashboards\//, '')); if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (e, d) => { if (e) { res.writeHead(404); return res.end(); } res.writeHead(200, { 'Content-Type': f.endsWith('.js') ? 'application/javascript' : f.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const url = 'http://127.0.0.1:' + srv.address().port + '/dashboards/live-status.html?standalone=1';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright'); const browser = await chromium.launch(), errs = [];
  const wait = (p, fn, arg) => p.waitForFunction(fn, arg, { timeout: 15000 }).then(() => true, () => false);
  try {
    const ctx = await browser.newContext({ viewport: { width: 1500, height: 1000 }, acceptDownloads: true });
    const p = await ctx.newPage(); p.on('pageerror', (e) => errs.push(e.message));
    await p.goto(url); ok(await wait(p, () => document.querySelectorAll('.fd').length === 5), 'one card per feed');
    if (process.env.SHOT) await p.screenshot({ path: process.env.SHOT, fullPage: true });   // optional: a picture for review
    const k = await p.textContent('#kk'); ok(/Feeds\s*5/.test(k) && /Live\s*2/.test(k) && /Late\s*1/.test(k) && /Silent\s*1/.test(k) && /Paused\s*1/.test(k), 'tiles with the real counts');
    ok(/50%/.test(await p.textContent('#ring')), 'live % = live / not paused');
    ok(/receiving/.test(await p.textContent('#col')), 'collector line');
    const f = await p.textContent('#findings'); ok(/OLD-SW is silent/.test(f) && /FGT-JED .* is late/.test(f) && /DC01: volume dropped/.test(f), 'findings: silent, late, dropped');
    ok((await p.getAttribute('.fd >> nth=0', 'data-feed')) === 'old', 'worst feed first');
    ok((await p.$$('.fd svg')).length >= 3, 'sparklines');
    ok(await p.$('#pulse svg path') && await p.$('#pulse linearGradient'), 'colourful 7-day pulse');
    ok(/fortigate|windows/i.test(await p.textContent('#kinds')) && (await p.$$('#kinds .b i')).length >= 2, 'feeds by type, coloured by state');
    ok(await p.$('#risk'), 'about-to-go-late card');
    ok(await p.evaluate(() => document.querySelectorAll('.fd .strip i').length >= 96), '24-hour colour strip on each card');
    ok(await p.evaluate(() => /gradient/.test(getComputedStyle(document.querySelector('#kk .st-t')).backgroundImage)), 'coloured state tiles');
    await p.click('#kk [data-f="silent"]'); ok(await wait(p, () => document.querySelectorAll('.fd').length === 1), 'a state tile filters the feeds'); await p.click('#chips [data-f=""]');
    await p.click('#chips [data-f="late"]'); ok(await wait(p, () => document.querySelectorAll('.fd').length === 1), 'state chip filters');
    await p.click('#chips [data-f=""]'); await p.fill('#q', 'DC01'); ok(await wait(p, () => document.querySelectorAll('.fd').length === 1), 'search');
    await p.click('.fd'); ok(await wait(p, () => !document.getElementById('dlg').hidden && /Volume vs this hour/.test(document.getElementById('dlg').textContent) && /dropped/.test(document.getElementById('dlg').textContent)), 'feed detail with volume vs the usual hour');
    await p.keyboard.press('Escape'); await p.fill('#q', '');
    ok(await p.isVisible('#sample')); await p.click('#sample'); ok(await wait(p, () => /Recorded 4 feeds/.test(document.body.textContent)), 'Record sample');
    ok(AUD.some((x) => x.a === 'collection.live.sample'), 'sample audited');
    ok(/AI live-status analyst is off/.test(await p.textContent('#ai')), 'AI off says why');
    const [dl] = await Promise.all([p.waitForEvent('download', { timeout: 10000 }), p.click('#xls')]);
    ok(/^live-status-\d{4}-\d{2}-\d{2}\.xlsx$/.test(dl.suggestedFilename()), 'Excel export');
    ok(!(await p.evaluate(() => window.__xss)), 'hostile feed label stayed text');
    ROLE = 'viewer'; const q = await ctx.newPage(); await q.goto(url); await wait(q, () => document.querySelectorAll('.fd').length === 5);
    ok(!(await q.isVisible('#sample')), 'viewer: no Record sample');
    MODEL = { policy: {}, collector: {}, sources: [] }; const r = await ctx.newPage(); await r.goto(url);
    ok(await wait(r, () => /No data feed is enrolled/.test(document.getElementById('nc').textContent)), 'nothing enrolled says what to connect');
    const nav = fs.readFileSync(path.join(DASH, 'vendor', 'zyb-nav.js'), 'utf8');
    ok(/"h": "live-status.html"/.test(nav) && /live-status\.html/.test(fs.readFileSync(path.join(DASH, 'install-dashboards.sh'), 'utf8')), 'menu entry and installer');
    ok(/status: 'live-status\.html'/.test(fs.readFileSync(path.join(DASH, 'vendor', 'zyb-menu.js'), 'utf8')) && /status: 'live-status\.html'/.test(fs.readFileSync(path.join(DASH, 'vendor', 'zyb-early.js'), 'utf8')), 'the portal\'s Live Status opens this page');
    ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  } finally { await browser.close(); srv.close(); }
  console.log((bad ? 'FAILED ' : 'ok ') + (n - bad) + '/' + n);
  process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
