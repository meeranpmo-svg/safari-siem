// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// log-monitor.html against the REAL SIEM log-monitor routes (sentra-siem engine/api/logmon.js; the ClickHouse search stubbed over
// SYNTHETIC events): KPIs (events, rate, medium-or-worse share, new / spiking / stopped patterns), the stacked volume chart with
// its legend, top bars that filter on click, the patterns table with status filters and a row that opens the latest line and a
// hunt link, the stopped patterns, the window switch, a filter with no match, a hostile log line staying text, the viewer refused
// with the reason (PDPL), and the menu entry, installer and portal redirect.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node log-monitor.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const DASH = path.resolve(__dirname, '../../ui');
const SIEM = process.env.SENTRA_SIEM || path.resolve(__dirname, '../..', 'backend', 'siem');
const LM = require(path.join(SIEM, 'engine/api/logmon'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const XSS = '<img src=x onerror="window.__xss=1">';
const H = 3600000, NOW = Date.now();
const E = [];
const ev = (ts, src_type, message, host, severity) => E.push({ ts, src_type, message, host: host || 'fw-syn', severity: severity || 0 });
for (let i = 0; i < 20; i++) ev(NOW - 30 * H + i * 60000, 'linux', 'Accepted password for svc from 10.0.0.' + i + ' port ' + (4000 + i) + ' ssh2', 'srv-a');
for (let i = 0; i < 20; i++) ev(NOW - 6 * H + i * 60000, 'linux', 'Accepted password for svc from 10.0.1.' + i + ' port ' + (5000 + i) + ' ssh2', 'srv-a');
for (let i = 0; i < 3; i++) ev(NOW - 30 * H + i * 60000, 'fortigate', 'srcip=10.0.0.' + i + ' action=deny policy="geo"');
for (let i = 0; i < 40; i++) ev(NOW - 5 * H + i * 30000, 'fortigate', 'srcip=10.2.0.' + (i % 7) + ' action=deny policy="geo"', 'fw-' + (i % 2), i === 5 ? 3 : 1);
for (let i = 0; i < 12; i++) ev(NOW - 40 * H + i * 60000, 'windows', 'The backup job ' + i + ' finished', 'bk-syn');
ev(NOW - 0.5 * H, 'windows', 'Audit log was cleared by ' + XSS, 'dc-syn', 4);
const fq = (q) => { const m = /(\w+):"([^"]*)"/g, out = []; let x; while ((x = m.exec(q || ''))) out.push([x[1], x[2]]); return (e) => out.every(([k, v]) => String(k === 'severity' ? e.severity : e[k]) === v); };
const inR = (from, to, q) => E.filter((e) => e.ts >= from && e.ts < to && fq(q)(e));
const search = {
  async histogram({ q, from, to, buckets }) { const step = Math.ceil((to - from) / buckets), out = Array.from({ length: buckets }, (_, i) => ({ t: from + i * step, n: 0 })); for (const e of inR(from, to, q)) out[Math.min(buckets - 1, Math.floor((e.ts - from) / step))].n++; return { buckets: out, step_ms: step }; },
  async top({ q, from, to, field, limit }) { const m = new Map(); for (const e of inR(from, to, q)) m.set(e[field], (m.get(e[field]) || 0) + 1); return { values: [...m].map(([v, c]) => ({ v, n: c })).sort((a, b) => b.n - a.n).slice(0, limit) }; },
  async fetchEvents({ q, from, to, limit }) { return inR(from, to, q).sort((a, b) => b.ts - a.ts).slice(0, limit); },
};

(async () => {
  const R = {}; LM.register({ route: (m, p, h) => { R[m + ' ' + p] = h; } }, { search });
  const RANK = { viewer: 0, analyst: 1, operator: 2, admin: 3 };
  let WHO = { user: 'nora.syn', role: 'analyst' };
  const srv = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://x'), json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u.pathname === '/dashboards/whoami.json') return json(200, WHO);
    const h = R[req.method + ' ' + u.pathname];
    if (h) { let b = ''; req.on('data', (c) => { b += c; }); req.on('end', async () => { const ctx = { role: WHO.role, user: WHO.user, body: b ? JSON.parse(b) : {}, need(r) { if (RANK[WHO.role] < RANK[r]) throw Object.assign(new Error('requires ' + r), { status: 403 }); } };
      try { json(200, await h(ctx)); } catch (e) { json(e.status || 500, { error: e.message }); } }); return; }
    if (u.pathname.startsWith('/api/')) return json(404, { error: 'not found' });
    const f = path.join(DASH, u.pathname.replace(/^\/dashboards\//, '/')); if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (err, d) => { if (err) { res.writeHead(404); res.end(); return; } res.writeHead(200, { 'Content-Type': u.pathname.endsWith('.js') ? 'application/javascript' : u.pathname.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const url = 'http://127.0.0.1:' + srv.address().port + '/dashboards/log-monitor.html';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  const wait = (p, fn, arg) => p.waitForFunction(fn, arg, { timeout: 15000 }).then(() => true, () => false);
  try {
    const p = await browser.newPage({ viewport: { width: 1500, height: 1000 } }); p.on('pageerror', (x) => errs.push(x.message));
    await p.goto(url); ok(await wait(p, () => !document.getElementById('main').hidden && document.querySelector('#vol rect')), 'loads with the volume chart');
    const K = await p.textContent('#kpis');
    ok(/61\s*events/.test(K), 'events in 24 h'); ok(/1\s*new patterns/.test(K) && /1\s*spiking/.test(K) && /1\s*patterns stopped/.test(K), 'new / spiking / stopped');
    ok(/fortigate/.test(await p.textContent('#leg')) && /linux/.test(await p.textContent('#leg')), 'stacked legend names the sources');
    ok(/Source types/.test(await p.textContent('#view')) && /fw-syn|srv-a/.test(await p.textContent('#view')), 'top bars');
    // a bar filters
    await p.click('.bar[data-add^="src_type:\\"fortigate"]');
    ok(await wait(p, () => /filter: src_type:"fortigate"/.test(document.getElementById('info').textContent)), 'clicking a bar filters on it');
    ok(/40\s*events/.test(await p.textContent('#kpis')), 'the filter applies to the figures');
    await p.click('#clear'); await wait(p, () => /61\s*events/.test(document.getElementById('kpis').textContent));
    // patterns
    await p.click('[data-tab="patterns"]');
    ok(/Accepted password for svc from <ip> port <n> ssh2/.test(await p.textContent('#view')), 'messages reduced to their pattern');
    await p.click('[data-fil="new"]'); const V = await p.textContent('#view');
    ok(/Audit log was cleared/.test(V) && !/Accepted password/.test(V), 'status filter: new only');
    await p.click('tr.pt'); ok(await wait(p, () => document.querySelector('.samp')), 'a pattern opens its latest line');
    const hl = await p.$eval('#view a[href^="soc-hunt.html"]', (a) => a.getAttribute('href')); ok(/soc-hunt\.html\?q=src_type%3A%22windows%22/.test(hl), 'hunt link carries the source: ' + hl);
    ok(!(await p.evaluate(() => window.__xss)), 'a hostile log line stayed text');
    await p.click('[data-fil="spike"]'); ok(/action=deny/.test(await p.textContent('#view')) && /spike/.test(await p.textContent('#view')), 'spiking pattern');
    await p.click('[data-fil="all"]'); await p.fill('#pq', 'backup'); ok(await wait(p, () => /No pattern matches/.test(document.getElementById('view').textContent)), 'find in patterns (the stopped one is not current)');
    await p.click('[data-tab="dropped"]'); ok(/The backup job <n> finished/.test(await p.textContent('#view')), 'stopped patterns');
    // window and an empty filter
    await p.selectOption('#win', '1'); ok(await wait(p, () => /1\s*events/.test(document.getElementById('kpis').textContent)), 'the window switch reloads');
    await p.fill('#q', 'host:"nothing-syn"'); await p.press('#q', 'Enter');
    ok(await wait(p, () => /No event matches this filter/.test(document.getElementById('view').textContent)), 'a filter with no match says so');
    // phone width
    const ph = await browser.newPage({ viewport: { width: 390, height: 900 } }); await ph.goto(url); await wait(ph, () => !document.getElementById('main').hidden);
    ok(await ph.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1), 'phone width: no sideways scroll'); await ph.close();
    // viewer
    WHO = { user: 'vera.syn', role: 'viewer' }; await p.goto(url);
    ok(await wait(p, () => /for analysts and above/.test(document.getElementById('err').textContent) && /PDPL/.test(document.getElementById('err').textContent)), 'viewer refused with the reason');
    // menu, installer, redirect
    const nav = fs.readFileSync(path.join(DASH, 'vendor', 'zyb-nav.js'), 'utf8');
    ok(/"h": "log-monitor.html"/.test(nav) && / log-monitor\.html /.test(fs.readFileSync(path.join(DASH, 'install-dashboards.sh'), 'utf8')), 'menu entry and installer');
    ok(/logs: 'log-monitor\.html'/.test(fs.readFileSync(path.join(DASH, 'vendor', 'zyb-menu.js'), 'utf8')), 'the portal\'s old "Log Monitor & Analysis" opens this page');
    ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  } finally { await browser.close(); srv.close(); }
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n);
  process.exit(bad ? 1 : 0);
})();
