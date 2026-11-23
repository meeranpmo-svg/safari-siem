// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browsing Traffic (browsing-monitor.html) against the REAL SIEM module (sentra-siem engine/soc/browsing.js) over a stubbed ClickHouse with
// SYNTHETIC web-filter rows: tiles, the allowed / blocked chart, policy gaps, top sites / categories, first-seen sites, click-to-filter
// (a filter chip; the filter reaches the SIEM as a parameter), operators see users and unusual volume, viewers do not (PDPL), the live
// feed refreshes by itself and pauses, AI off says why, Excel without names, a hostile site name stays text, not connected, the menu
// entry and the portal redirect.
// Run: SENTRA_SIEM_DIR=/home/user/sentra-siem PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node browsing-monitor.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const DASH = path.resolve(__dirname, '../../ui');
const SIEM = process.env.SENTRA_SIEM_DIR || path.resolve(__dirname, '../../backend/siem');
const bw = require(path.join(SIEM, 'engine/soc/browsing'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const XSS = '<img src=x onerror="window.__xss=1">';
const NOW = Date.now(), cur = Math.floor((NOW - 3600000) / 3600000) * 3600;
const spike = []; for (let h = cur - 168 * 3600; h < cur; h += 3600) spike.push({ who: 'nora.syn', h, n: 10 }); spike.push({ who: 'nora.syn', h: cur, n: 800 });
let A = {
  bw_src: [{ s: 'fortigate', n: 50000, last: '2026-11-01 09:59:00' }],
  bw_tot: [{ n: 12000, blk: 600, users: 140, devices: 160, sites: 900, last5: 85 }],
  bw_series: [{ k: 0, ok: 400, blk: 20 }, { k: 23, ok: 700, blk: 40 }],
  bw_sites: [{ site: 'outlook.office365.com', n: 3000, blk: 0, u: 120, cat: 'Information Technology' }, { site: 'free-proxy.example' + XSS, n: 40, blk: 10, u: 3, cat: 'Proxy Avoidance' }],
  bw_cats: [{ cat: 'Information Technology', n: 8000, blk: 0, u: 130 }, { cat: 'Proxy Avoidance', n: 40, blk: 10, u: 3 }],
  bw_risky: [{ cat: 'Proxy Avoidance', site: 'free-proxy.example', blk: 10, ok: 30, u: 3 }],
  bw_new: [{ site: 'new-saas.example', first: '2026-10-31 14:00:00', n: 60, u: 9, cat: 'Business' }],
  bw_tail: [{ ts: '2026-11-01 09:59:58', who: 'nora.syn', site: 'free-proxy.example', cat: 'Proxy Avoidance', blocked: 0, s: 'fortigate' }],
  bw_users: [{ who: 'nora.syn', n: 1200, blk: 30, risky: 25, sites: 80 }], bw_spike: spike,
};
const CALLS = [];
const ch = { query: async (sql, p) => { const tag = /^\/\*q:([a-z_0-9]+)\*\//.exec(sql)[1]; CALLS.push({ tag, p }); return (A[tag] || []).map((r) => Object.assign({}, r)); } };
const routes = {}; bw.register({ route: (m, pth, fn) => { routes[m + ' ' + pth] = fn; } }, { ch, now: () => Date.now(), config: {} });
let ROLE = 'operator';
const RANK = { viewer: 1, analyst: 2, operator: 3, admin: 4 };

(async () => {
  const srv = http.createServer((req, res) => {
    const url = new URL(req.url, 'http://x'), u = url.pathname, json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u === '/dashboards/whoami.json' || u === '/auth/whoami') return json(200, { user: ROLE + '.syn', role: ROLE });
    const key = req.method + ' ' + u;
    if (routes[key]) { let b = ''; req.on('data', (c) => { b += c; }); req.on('end', async () => { let out = null;
      const ctx = { query: Object.fromEntries(url.searchParams), body: b ? JSON.parse(b) : {}, role: ROLE, user: ROLE + '.syn', path: u, ok: (x) => { out = [200, x]; return out; }, fail: (s, m) => { out = [s, { error: m }]; return out; },
        need: (r) => { if ((RANK[ROLE] || 0) < RANK[r]) { out = [403, { error: 'requires role ' + r }]; return false; } return true; }, audit() {} };
      await routes[key](ctx); json(out[0], out[1]); }); return; }
    if (u.startsWith('/api/')) return json(404, { error: 'not in this test' });
    const f = path.join(DASH, u.replace(/^\/dashboards\//, '')); if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (e, d) => { if (e) { res.writeHead(404); return res.end(); } res.writeHead(200, { 'Content-Type': f.endsWith('.js') ? 'application/javascript' : f.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const url = 'http://127.0.0.1:' + srv.address().port + '/dashboards/browsing-monitor.html';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright'); const browser = await chromium.launch(), errs = [];
  const wait = (p, fn, arg, ms) => p.waitForFunction(fn, arg, { timeout: ms || 15000 }).then(() => true, () => false);
  try {
    const ctx = await browser.newContext({ viewport: { width: 1500, height: 1000 }, acceptDownloads: true });
    const p = await ctx.newPage(); p.on('pageerror', (e) => errs.push(e.message));
    await p.goto(url); ok(await wait(p, () => /12,000/.test(document.getElementById('kk').textContent)), 'tiles load');
    const k = await p.textContent('#kk'); ok(/Right now\s*85/.test(k) && /Risky allowed\s*30/.test(k) && /5 %/.test(k), 'tiles: live rate, risky allowed, blocked share');
    ok((await p.$$('#bars i')).length === 24, 'hourly chart');
    ok(/free-proxy\.example/.test(await p.textContent('#gaps')) && /Proxy Avoidance/.test(await p.textContent('#gaps')), 'policy gap listed');
    ok(/new-saas\.example/.test(await p.textContent('#newsites')), 'first-seen site');
    ok(await p.isVisible('#usercard') && /nora\.syn/.test(await p.textContent('#users')) && /800 requests in the last hour/.test(await p.textContent('#unusual')), 'operator: users and unusual volume');
    ok(/nora\.syn/.test(await p.textContent('#tail')), 'operator: names in the live feed');
    // click to filter
    await p.click('#cats tr[data-cat="Proxy Avoidance"]');
    ok(await wait(p, () => /cat: Proxy Avoidance/.test(document.getElementById('flt').textContent)), 'category filter chip');
    ok(CALLS.some((c) => c.tag === 'bw_tot' && c.p.cat.value === 'Proxy Avoidance'), 'the filter reaches the SIEM as a parameter');
    await p.click('[data-clear="cat"]'); ok(await wait(p, () => !document.getElementById('flt').textContent.trim()), 'filter cleared');
    // live refresh and pause
    const before = CALLS.filter((c) => c.tag === 'bw_tot').length;
    ok(await wait(p, (b) => true, before, 100), 'tick');
    await p.waitForTimeout(16000); const after = CALLS.filter((c) => c.tag === 'bw_tot').length;
    ok(after > before, 'refreshes by itself every 15 s');
    await p.click('#pause'); const paused = CALLS.filter((c) => c.tag === 'bw_tot').length; await p.waitForTimeout(16000);
    ok(CALLS.filter((c) => c.tag === 'bw_tot').length === paused && /Resume/.test(await p.textContent('#pause')), 'pause stops the refresh');
    ok(/AI analyst is off/.test(await p.textContent('#ai')), 'AI off says why');
    const [dl] = await Promise.all([p.waitForEvent('download', { timeout: 10000 }), p.click('#xls')]);
    ok(/^browsing-traffic-\d{4}-\d{2}-\d{2}\.xlsx$/.test(dl.suggestedFilename()), 'Excel export');
    ok(!(await p.evaluate(() => window.__xss)), 'hostile site name stayed text');
    // viewer: counts only
    ROLE = 'viewer'; const q = await ctx.newPage(); q.on('pageerror', (e) => errs.push(e.message)); await q.goto(url); await wait(q, () => /12,000/.test(document.getElementById('kk').textContent));
    ok(!(await q.isVisible('#usercard')) && !(await q.isVisible('#unucard')) && !/nora\.syn/.test(await q.textContent('#tail')), 'viewer: no names anywhere (PDPL)');
    // not connected
    A = { bw_src: [] }; ROLE = 'operator'; const r = await ctx.newPage(); await r.goto(url);
    ok(await wait(r, () => /No web-filter log has reached the SIEM/.test(document.getElementById('nc').textContent)), 'not connected says what to send');
    const nav = fs.readFileSync(path.join(DASH, 'vendor', 'zyb-nav.js'), 'utf8');
    ok(/"h": "browsing-monitor.html"/.test(nav) && /browsing-monitor\.html/.test(fs.readFileSync(path.join(DASH, 'install-dashboards.sh'), 'utf8')), 'menu entry and installer');
    ok(/browsing: 'browsing-monitor\.html'/.test(fs.readFileSync(path.join(DASH, 'vendor', 'zyb-menu.js'), 'utf8')) && /browsing: 'browsing-monitor\.html'/.test(fs.readFileSync(path.join(DASH, 'vendor', 'zyb-early.js'), 'utf8')), 'the portal\'s Browsing Traffic opens this page');
    ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  } finally { await browser.close(); srv.close(); }
  console.log((bad ? 'FAILED ' : 'ok ') + (n - bad) + '/' + n);
  process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
