// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Vulnerability & Testing Dashboard (vuln-dashboard.html) against the REAL ITAM engines (VAPT Center over Greenbone findings, the testing
// schedule, App Pen Testing, AppSec, engine/vuln-dashboard.js) with SYNTHETIC records: posture ring and KPIs; the five pillars with itemised
// deductions, the coverage pillar not available (never counted as good); attention most urgent first; the open-findings matrix and the
// pipeline; top vulnerabilities with an explained priority (a hostile finding name stays text); learning; a viewer sees scores and counts
// but no host or finding; menu entry, the portal's dash-vuln redirect and the installer.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node vuln-dashboard.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const ITAM = path.join(__dirname, '..', '..', 'backend', 'itam'), DASH = path.join(__dirname, '..', '..', 'ui');
const H = require(path.join(ITAM, 'tests', 'helpers'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };

(async () => {
  const e = await H.startApp({ noAi: true });
  require(path.join(ITAM, 'engine/duty')).registerDuty(e.app.srv, e.app, { noTimer: true, python: process.env.PYTHON || 'python3' });
  const col = (c) => e.app.store.collection(c), old = new Date(Date.now() - 60 * 86400000).toISOString();
  const F = (id, host, name, severity, score) => col('vulnscan_findings').put({ id, host, hostname: host, port: '443/tcp', name, severity, score, cves: ['CVE-2099-0001'], status: 'open', first_seen: old, last_seen: old, history: [] });
  F('VF-1', '10.20.0.5', 'Remote code execution in synthetic web server <img src=x onerror="window.__xss=1">', 'critical', 9.8);
  F('VF-2', '10.20.0.6', 'Outdated TLS configuration (synthetic)', 'high', 7.5);
  F('VF-3', '10.20.0.7', 'Weak SSH ciphers (synthetic)', 'medium', 5.3);
  const P = async (p, b) => { const r = await e.req('POST', p, { body: b, user: 'syed', role: 'admin' }); if (r.status !== 200) throw new Error(p + ' ' + r.status + ' ' + r.raw); return r.json; };
  await P('/apppt/targets', { name: 'Claims portal (synthetic)', url: 'https://claims.example.test', kind: 'web', exposure: 'external', criticality: 'critical', owner: 'omar.syn' });
  await P('/appsec/apps', { name: 'Mobile BFF (synthetic)', owner: 'omar.syn', criticality: 'high', exposure: 'internet' });
  let WHO = { user: 'nora.syn', role: 'operator' };
  const srv = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://x'), json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u.pathname === '/dashboards/whoami.json') return json(200, WHO);
    if (u.pathname.startsWith('/api/itam/')) {
      const h = Object.assign({}, req.headers, { 'x-sentra-proxy-secret': H.SECRET, 'x-auth-user': WHO.user, 'x-auth-role': WHO.role });
      const up = http.request({ host: '127.0.0.1', port: e.port, method: req.method, path: req.url, headers: h }, (r) => { res.writeHead(r.statusCode, r.headers); r.pipe(res); });
      req.pipe(up); return;
    }
    if (u.pathname.startsWith('/api/')) return json(404, { error: 'not in this test' });
    const f = path.join(DASH, u.pathname.replace(/^\/dashboards\//, '')); if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (err, d) => { if (err) { res.writeHead(404); return res.end(); } res.writeHead(200, { 'Content-Type': f.endsWith('.js') ? 'application/javascript' : f.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port + '/dashboards/';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright'); const browser = await chromium.launch(), errs = [];
  const wait = (p, fn, arg) => p.waitForFunction(fn, arg, { timeout: 30000 }).then(() => true, () => false);
  const toast = (p, re) => wait(p, (s) => [...document.querySelectorAll('.toast')].some((t) => new RegExp(s).test(t.textContent)), re);
  const page = async (ctx, f) => { const p = await ctx.newPage(); p.on('pageerror', (x) => errs.push(x.message)); p.on('dialog', (d) => { errs.push('unexpected dialog'); d.dismiss(); }); await p.goto(base + f + '?standalone=1'); await p.waitForSelector('#main:not([hidden])', { timeout: 60000 }); return p; };
  try {
    const ctx = await browser.newContext({ viewport: { width: 1500, height: 1000 } });
    let p = await page(ctx, 'vuln-dashboard.html');
    ok(/testing posture/.test(await p.textContent('#ring')), 'posture ring');
    ok(/Critical open/.test(await p.textContent('#kpis')) && /Release gates failing/.test(await p.textContent('#kpis')), 'KPIs');
    const pil = await p.textContent('#pil');
    ok(/Infrastructure exposure/.test(pil) && /1 critical vulnerability/.test(pil), 'exposure pillar with an itemised deduction');
    ok(/Testing coverage[\s\S]*no asset in the testing scope/.test(pil), 'coverage not available - not counted as good');
    ok(/application\(s\) never tested/.test(pil), 'application pillar: never tested');
    ok(/never scanned/.test(pil), 'code pillar: never scanned');
    ok(/left out/.test(await p.textContent('#iwhy')), 'the index says what was left out');
    ok(/critical/.test(await p.textContent('#att')) && (await p.$$('#att .att')).length >= 2, 'attention list');
    ok(await p.$eval('#mx', (x) => x.querySelectorAll('tbody tr').length === 3 && x.querySelector('tbody tr td.n').textContent === '1'), 'open-findings matrix (infrastructure critical = 1)');
    ok(/Scans waiting for approval/.test(await p.textContent('#pipe')), 'pipeline');
    ok(await p.$$eval('#top tbody tr', (r) => r.length === 3) && /10\.20\.0\.5/.test(await p.textContent('#top')) && /past SLA/.test(await p.textContent('#top')), 'top vulnerabilities with priority and SLA');
    ok(await p.evaluate(() => !window.__xss && /<img/.test(document.getElementById('top').textContent)), 'a hostile finding name stays text');
    ok(/Days to clear critical and high/.test(await p.textContent('#learn')) && /needs 3 daily snapshots/.test(await p.textContent('#learn')), 'learning: days to clear and the trend rule');
    ok(/Not available: external AI/.test(await p.textContent('#ai')), 'advisor off until allowed');
    if (process.env.SHOT) await p.screenshot({ path: process.env.SHOT, fullPage: true });   // optional: a picture for review
    WHO = { user: 'vera.syn', role: 'viewer' }; p = await page(ctx, 'vuln-dashboard.html');
    ok(/operators and administrators/.test(await p.textContent('#att')) && !/10\.20\.0\.5/.test(await p.content()), 'a viewer sees no host or finding');
    ok(/Infrastructure exposure/.test(await p.textContent('#pil')), 'a viewer still sees the pillars');
    const nav = fs.readFileSync(path.join(DASH, 'vendor', 'zyb-nav.js'), 'utf8');
    ok(/"h": "vuln-dashboard.html"/.test(nav) && /vuln-dashboard\.html/.test(fs.readFileSync(path.join(DASH, 'install-dashboards.sh'), 'utf8')), 'menu entry and installer');
    ok(/'dash-vuln': 'vuln-dashboard\.html'/.test(fs.readFileSync(path.join(DASH, 'vendor', 'zyb-menu.js'), 'utf8')) && /'dash-vuln': 'vuln-dashboard\.html'/.test(fs.readFileSync(path.join(DASH, 'vendor', 'zyb-early.js'), 'utf8')), 'the portal Vulnerability & Testing Dashboard opens this page');
    ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  } finally { await browser.close(); srv.close(); await e.close(); }
  console.log((bad ? 'FAILED ' : 'ok ') + (n - bad) + '/' + n);
  process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
