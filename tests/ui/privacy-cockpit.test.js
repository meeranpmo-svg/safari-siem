// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for privacy-cockpit.html against the REAL engine (engine/pdpl-cockpit.js over the PDPL registers) with SYNTHETIC
// records: the KPIs, every clock as a chart and a table (the missing impact assessment first, the breach's 72 hours), a KPI tile
// filters the clocks, the requests at risk with their bars, the request volume chart, the heat map (a cell lists its activities),
// the riskiest activity with every point named, the registers read, a hostile name stays text, the AI briefing is labelled a
// draft, a viewer is told the page is for operators, phone width, the menu entry and the installer.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node privacy-cockpit.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const ITAM = path.join(__dirname, '..', '..', 'backend', 'itam'), DASH = path.join(__dirname, '..', '..', 'ui');
const H = require(path.join(ITAM, 'tests', 'helpers'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
(async () => {
  const e = await H.startApp({ noAi: true });
  require(path.join(ITAM, 'engine/duty')).registerDuty(e.app.srv, e.app, { noTimer: true, now: () => Date.parse('2026-11-16T08:00:00Z'), python: process.env.PYTHON || 'python3' });
  const OP = { user: 'nora.syn', role: 'operator' }, c = (m, p, b) => e.req(m, p, Object.assign({ body: b }, OP));
  await c('POST', '/pdpl/records', { kind: 'ropa', name: 'Claims handling (synthetic) <img src=x onerror=window.__px=1>', purpose: 'claims', legal_basis: 'contract', data_categories: ['health', 'identity'], systems: ['Core'] });
  await c('POST', '/pdpl/records', { kind: 'ropa', name: 'Newsletter (synthetic)', purpose: 'marketing', legal_basis: 'consent', data_categories: ['contact'], systems: ['CRM'] });
  await c('POST', '/pdpl/records', { kind: 'breach', ref: 'SYN-B1', aware_at: '2026-11-15T08:00Z', description: 'synthetic', subjects_count: 12 });
  await c('POST', '/pdpl/dsar', { ref: 'SYN-R1', type: 'access', channel: 'email', received: '2026-11-01', systems: ['Core'] });
  await c('POST', '/pdpl/dsar', { ref: 'SYN-R2', type: 'destruction', channel: 'email', received: '2026-10-20', systems: ['Core'] });
  let who = OP;
  const srv = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://x'), json = (code, b) => { res.writeHead(code, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u.pathname === '/dashboards/whoami.json') return json(200, who);
    if (u.pathname.startsWith('/api/itam/')) { const h = Object.assign({}, req.headers, { 'x-sentra-proxy-secret': H.SECRET, 'x-auth-user': who.user, 'x-auth-role': who.role });
      const up = http.request({ host: '127.0.0.1', port: e.port, method: req.method, path: req.url, headers: h }, (r) => { res.writeHead(r.statusCode, r.headers); r.pipe(res); }); req.pipe(up); return; }
    if (u.pathname.startsWith('/api/') || u.pathname === '/') return json(404, { error: 'not in this test' });
    const f = path.join(DASH, u.pathname.replace(/^\/dashboards\//, '/')); if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (err, d) => { if (err) { res.writeHead(404); res.end(); return; } res.writeHead(200, { 'Content-Type': u.pathname.endsWith('.js') ? 'application/javascript' : u.pathname.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port + '/privacy-cockpit.html?standalone=1';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  const wait = (p, fn, arg) => p.waitForFunction(fn, arg === undefined ? null : arg, { timeout: 20000 }).then(() => true, () => false);
  const T = (p, id) => p.evaluate((i) => document.getElementById(i).textContent, id);
  try {
    const p = await browser.newPage({ viewport: { width: 1440, height: 1000 } }); p.on('pageerror', (x) => errs.push(x.message));
    await p.goto(base);
    ok(await wait(p, () => document.querySelectorAll('#kpi button.t').length >= 8), 'KPI tiles');
    ok(/requests open/.test(await T(p, 'kpi')) && /breaches open/.test(await T(p, 'kpi')), 'KPIs named');
    ok(await p.$('#clockch svg.ch') !== null, 'the clocks as a chart');
    const cl = await T(p, 'clocks');
    ok(/Impact assessment/.test(cl) && /notify SDAIA \(72 h\)/.test(cl) && /SYN-R2|SYN-R1/.test(cl), 'every clock: DPIA, breach 72 h, requests');
    ok(await p.$eval('#clocks tbody tr', (r) => /Impact assessment/.test(r.textContent) && /late/.test(r.textContent)), 'the missing impact assessment first, late');
    // a tile filters the clocks
    await p.click('#kpi [data-k="breach"]');
    ok(await wait(p, () => document.querySelectorAll('#clocks tbody tr').length === 1 && /SDAIA/.test(document.getElementById('clocks').textContent)), 'the breach tile shows only the breach clock');
    ok(await p.$eval('#kpi [data-k="breach"]', (b) => b.getAttribute('aria-pressed') === 'true'), 'the tile says it is pressed');
    await p.click('#kpi [data-k="breach"]'); ok(await wait(p, () => document.querySelectorAll('#clocks tbody tr').length > 1), 'click again: all clocks');
    // requests at risk
    const rk = await T(p, 'risk'); ok(/SYN-R2/.test(rk) && /%/.test(rk) && /rule/.test(await T(p, 'rsub')), 'requests at risk with the stated method');
    ok(await p.$('#vol svg.ch') !== null, 'request volume chart');
    // heat map: a cell lists its activities
    ok(await p.$('[data-heat="health|high"]') !== null, 'heat map has the health / high cell');
    await p.click('[data-heat="health|high"]');
    ok(await wait(p, () => /Claims handling/.test(document.getElementById('acts').textContent) && !/Newsletter/.test(document.getElementById('acts').textContent)), 'the cell lists only its activities');
    ok(/impact assessment required/.test(await T(p, 'acts')), 'every point named');
    ok(!(await p.evaluate(() => window.__px)) && /<img src=x/.test(await T(p, 'acts')), 'a hostile name stays text');
    await p.click('[data-heat="health|high"]'); ok(await wait(p, () => /Newsletter/.test(document.getElementById('acts').textContent)), 'click again: every activity');
    ok(/Records of Processing|ropa|dsar/i.test(await T(p, 'src')), 'registers read listed');
    // the AI briefing (no AI here: it answers it is not configured, the box is labelled)
    ok(await p.$eval('#aibrief', (b) => !b.hidden), 'operator sees the AI briefing button');
    await p.click('#aibrief'); ok(await wait(p, () => /AI draft - verify before use|did not answer/.test(document.getElementById('aiout').textContent)), 'the AI briefing answers in a labelled box');
    // viewer
    who = { user: 'vera.syn', role: 'viewer' }; await p.reload();
    ok(await wait(p, () => /operators and administrators only/.test(document.getElementById('err').textContent)), 'a viewer is told the page is for operators');
    ok(await p.$eval('#aibrief', (b) => b.hidden), 'a viewer has no AI briefing button');
    who = OP;
    const ph = await browser.newPage({ viewport: { width: 390, height: 900 } }); ph.on('pageerror', (x) => errs.push(x.message)); await ph.goto(base); await wait(ph, () => !!document.querySelector('#clocks table'));
    ok(await ph.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1), 'phone width: no sideways scroll'); await ph.close();
    ok(/"h": "privacy-cockpit.html"/.test(fs.readFileSync(path.join(DASH, 'vendor', 'zyb-nav.js'), 'utf8')) && / privacy-cockpit\.html /.test(fs.readFileSync(path.join(DASH, 'install-dashboards.sh'), 'utf8')), 'menu entry and installer');
  } finally { await browser.close(); srv.close(); e.close(); }
  ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks'); process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
