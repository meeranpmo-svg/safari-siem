// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for Implementation Plan & Budget (dashboards/server/impl-plan.html) against the REAL ITAM engine (engine/impl-plan.js)
// with SYNTHETIC remediation actions: KPIs, "estimate needed" filter, entering an estimate (operator) and the plan updating, a
// validation error shown, roadmap bars with late / at-risk colours and capacity, cash-flow chart with the envelope, forecast
// tab (calibration withheld), settings (admin saves; operator read-only), viewer read-only, AI off, Excel, a hostile action
// title stays text, the menu entry and the portal redirect.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node impl-plan.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const ITAM = path.join(__dirname, '..', '..', 'backend', 'itam'), DASH = path.join(__dirname, '..', '..', 'ui');
const H = require(path.join(ITAM, 'tests', 'helpers'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const XSS = '<img src=x onerror="window.__xss=1">';

(async () => {
  const e = await H.startApp({ noAi: true });
  const C = e.app.store.collection('grc_actions'), d = (days) => new Date(Date.now() + days * 86400000).toISOString().slice(0, 10);
  C.put({ id: 'ACT-0001', title: 'Deploy PAM ' + XSS, source: 'sama', ref: 'SAMA-3.3.5', framework: 'SAMA CSF', priority: 'high', due: d(20), status: 'open', owner: 'GRC team' });
  C.put({ id: 'ACT-0002', title: 'MFA for remote access', source: 'nca', ref: 'ECC-2-2-3', framework: 'NCA ECC', priority: 'high', due: d(300), status: 'open' });
  C.put({ id: 'ACT-0003', title: 'Data classification policy', source: 'pdpl', ref: 'PDPL-19', framework: 'PDPL', priority: 'medium', status: 'open' });
  e.app.store.collection('impl_estimates').put({ id: 'ACT-0001', effort_days: 150, resource: 'consultant', one_time: 300000, annual: 120000, depends_on: [], by: 'nora.syn', at: new Date().toISOString() });
  e.app.store.collection('impl_config').put({ id: 'settings', value: { capacity_days: 100, rate_internal: 1000, rate_consultant: 2500, envelope: 600000, currency: 'SAR' } });
  require(path.join(ITAM, 'engine/duty')).registerDuty(e.app.srv, e.app, { noTimer: true });
  if (e.app.addons.updateHealth) e.app.addons.updateHealth.view = () => ({ pages: [] });
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
    const f = path.join(DASH, u.pathname.replace(/^\/dashboards\//, '/')); if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (err, b) => { if (err) { res.writeHead(404); res.end(); return; } res.writeHead(200, { 'Content-Type': u.pathname.endsWith('.js') ? 'application/javascript' : u.pathname.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(b); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const url = 'http://127.0.0.1:' + srv.address().port + '/dashboards/impl-plan.html';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  const wait = (p, fn, arg) => p.waitForFunction(fn, arg, { timeout: 15000 }).then(() => true, () => false);
  const V = (p) => p.textContent('#view');
  try {
    const ctx = await browser.newContext({ viewport: { width: 1600, height: 1000 }, acceptDownloads: true });
    const p = await ctx.newPage(); p.on('pageerror', (x) => errs.push(x.message));
    await p.goto(url); await wait(p, () => !document.getElementById('main').hidden);
    const k = await p.textContent('#kpis');
    ok(/3\s*open actions/.test(k) && /2\s*estimate needed/.test(k), 'KPIs: open and estimate needed');
    ok((await p.$$('tr[data-item]')).length === 3 && /SAR 675,000/.test(await V(p)), 'plan rows; labour 150 x 2,500 + quotation 300,000');
    ok(/late/.test(await p.textContent('tr[data-item="ACT-0001"]')) && /bigger than a quarter/.test(await p.textContent('tr[data-item="ACT-0001"]')), 'late and too-big flags');
    await p.click('.kpi[data-go="plan:needed"]'); ok(await wait(p, () => document.querySelectorAll('tr[data-item]').length === 2), 'estimate-needed filter');
    // enter an estimate
    await p.click('tr[data-item="ACT-0002"]'); ok(await p.isVisible('#estf'), 'estimate form for an operator');
    await p.evaluate(() => document.getElementById('estf').setAttribute('novalidate', ''));   // the server re-validates what the page checked
    await p.fill('#estf [name="effort_days"]', '0'); await p.click('#estf button[type="submit"]');
    ok(await wait(p, () => /effort_days must be at least/.test(document.getElementById('estmsg').textContent)), 'validation error shown, naming the field');
    await p.fill('#estf [name="effort_days"]', '20'); await p.fill('#estf [name="one_time"]', '15000'); await p.fill('#estf [name="annual"]', '40000'); await p.fill('#estf [name="basis"]', 'quotation Q-22');
    await p.click('#estf button[type="submit"]');
    ok(await wait(p, () => /Estimate saved/.test(document.body.textContent)), 'estimate saved');
    ok(await wait(p, () => /1\s*estimate needed/.test(document.getElementById('kpis').textContent)), 'KPIs update');
    ok(e.app.store.auditTail(20).some((a) => a.action === 'impl-plan.estimate' && a.target === 'ACT-0002' && a.by === 'nora.syn'), 'estimate audited');
    // roadmap, budget, forecast
    await p.click('#tabs [data-tab="roadmap"]'); ok((await p.$$('[data-bar]')).length === 2 && /Capacity used/.test(await V(p)), 'roadmap bars and capacity');
    ok(await p.$eval('[data-bar="ACT-0001"] .gb', (b) => b.style.background) === 'rgb(196, 60, 65)', 'late action drawn red');
    await p.click('#tabs [data-tab="budget"]'); ok(!!(await p.$('#view svg rect')) && /envelope SAR 600,000/.test(await V(p)) && /over the envelope/.test(await V(p)), 'cash flow with the envelope');
    ok(/SAMA CSF/.test(await V(p)) && /NCA ECC/.test(await V(p)), 'by framework');
    await p.click('#tabs [data-tab="learning"]'); ok(/at least 3 closed actions/.test(await V(p)) && /at least 4 weeks/.test(await V(p)), 'forecast withheld without history');
    await p.click('#tabs [data-tab="settings"]'); ok(!(await p.$('#setf')) && /An administrator changes these/.test(await V(p)), 'operator: settings read-only');
    await p.click('#tabs [data-tab="ai"]'); ok(/AI plan analyst is off/.test(await V(p)), 'AI off says why');
    const [dl] = await Promise.all([p.waitForEvent('download', { timeout: 10000 }), p.click('#xls')]);
    ok(/^implementation-plan-\d{4}-\d{2}-\d{2}\.xlsx$/.test(dl.suggestedFilename()), 'Excel export');
    ok(!(await p.evaluate(() => window.__xss)), 'hostile action title stayed text');
    // admin settings
    WHO = { user: 'syed', role: 'admin' };
    const a = await ctx.newPage(); a.on('pageerror', (x) => errs.push(x.message)); await a.goto(url); await wait(a, () => !document.getElementById('main').hidden);
    await a.click('#tabs [data-tab="settings"]'); await a.fill('#setf [name="capacity_days"]', '200'); await a.click('#setf button[type="submit"]');
    ok(await wait(a, () => /Settings saved/.test(document.body.textContent)), 'admin saves settings');
    ok(e.app.store.auditTail(20).some((x) => x.action === 'impl-plan.settings' && x.by === 'syed'), 'settings audited');
    // viewer
    WHO = { user: 'vera.syn', role: 'viewer' };
    const q = await ctx.newPage(); q.on('pageerror', (x) => errs.push(x.message)); await q.goto(url); await wait(q, () => !document.getElementById('main').hidden);
    await q.click('tr[data-item="ACT-0003"]'); ok(!(await q.$('#estf')) && /an operator enters it/.test(await q.textContent('#view')), 'viewer: no estimate form');
    const nav = fs.readFileSync(path.join(DASH, 'vendor', 'zyb-nav.js'), 'utf8');
    ok(/"h": "impl-plan.html"/.test(nav) && /impl-plan\.html/.test(fs.readFileSync(path.join(DASH, 'install-dashboards.sh'), 'utf8')), 'menu entry and installer');
    ok(/implplan: 'impl-plan\.html'/.test(fs.readFileSync(path.join(DASH, 'vendor', 'zyb-menu.js'), 'utf8')) && /implplan: 'impl-plan\.html'/.test(fs.readFileSync(path.join(DASH, 'vendor', 'zyb-early.js'), 'utf8')), 'the portal\'s Implementation Plan & Budget opens this page');
    ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  } finally { await browser.close(); srv.close(); await e.close(); }
  console.log((bad ? 'FAILED ' : 'ok ') + (n - bad) + '/' + n);
  process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
