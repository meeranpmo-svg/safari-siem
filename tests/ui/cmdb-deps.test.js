// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for CMDB & Dependencies (dashboards/server/cmdb-deps.html) against the REAL ITAM engine (engine/cmdb-deps.js) with
// SYNTHETIC assets / relationships / applications: KPIs, applications ranked by risk, the layered map with single points of
// failure and the cluster, clicking a component simulates its failure (a cluster member takes nothing down; the database takes
// both applications down), risk reasons, findings filtered from a KPI, snapshot (operator) and changes, viewer read-only, AI off,
// Excel, a hostile asset name stays text, the menu entry and the portal redirect.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node cmdb-deps.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const ITAM = path.join(__dirname, '..', '..', 'backend', 'itam'), DASH = path.join(__dirname, '..', '..', 'ui');
const H = require(path.join(ITAM, 'tests', 'helpers'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const XSS = '<img src=x onerror="window.__xss=1">';

(async () => {
  const e = await H.startApp({ noAi: true });
  const A = e.app.store.collection('assets'), R = e.app.store.collection('relationships');
  const put = (id, name, type, criticality, extra) => A.put(Object.assign({ id, name, type, status: 'in_use', criticality }, extra || {}));
  put('app1', 'APP01', 'vm', 'critical'); put('app2', 'APP02', 'vm', 'critical'); put('web1', 'WEB01', 'vm', 'high', { owner: 'Web ' + XSS });
  put('db1', 'DB01', 'server', 'medium'); put('esx1', 'ESX01', 'server', 'critical'); put('esx2', 'ESX02', 'server', 'critical'); put('esx3', 'ESX03', 'server', 'high', { eol: '2025-12-31' }); put('cl1', 'CL-PROD', 'cluster', 'critical');
  let k = 0; const rel = (from, to, type, status) => R.put({ id: 'r' + (++k), from, to, type, status: status || 'confirmed', source: 'test' });
  rel('app1', 'cl1', 'runs_on'); rel('app2', 'cl1', 'runs_on'); rel('esx1', 'cl1', 'member_of'); rel('esx2', 'cl1', 'member_of');
  rel('app1', 'db1', 'depends_on'); rel('app2', 'db1', 'depends_on'); rel('db1', 'esx3', 'runs_on'); rel('web1', 'app1', 'depends_on', 'proposed');
  e.app.store.collection('app_route').put({ id: 'profile', apps: [{ id: 'claims', name: 'Claims', machines: ['APP01', 'APP02'], criticality: 'critical' }, { id: 'portal', name: 'Customer Portal', machines: ['WEB01', 'web-old'], criticality: 'high' }] });
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
    fs.readFile(f, (err, d) => { if (err) { res.writeHead(404); res.end(); return; } res.writeHead(200, { 'Content-Type': u.pathname.endsWith('.js') ? 'application/javascript' : u.pathname.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const url = 'http://127.0.0.1:' + srv.address().port + '/dashboards/cmdb-deps.html';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  const wait = (p, fn, arg) => p.waitForFunction(fn, arg, { timeout: 15000 }).then(() => true, () => false);
  const V = (p) => p.textContent('#view');
  try {
    const ctx = await browser.newContext({ viewport: { width: 1600, height: 1000 }, acceptDownloads: true });
    const p = await ctx.newPage(); p.on('pageerror', (x) => errs.push(x.message));
    await p.goto(url); await wait(p, () => !document.getElementById('main').hidden);
    ok(/applications/.test(await p.textContent('#kpis')) && /single points of failure/.test(await p.textContent('#kpis')), 'KPIs');
    ok((await p.$$('.ap')).length === 2 && /Claims/.test(await p.textContent('.ap[aria-pressed="true"]')), 'applications listed, highest risk first selected');
    ok((await p.$$('#view svg g.nd')).length >= 6 && /CL-PROD/.test(await p.textContent('#view svg')), 'layered map drawn with the cluster');
    ok(await p.$eval('g.nd[data-ci="db1"] rect', (r) => r.getAttribute('stroke')) === '#e5484d', 'DB01 marked as single point of failure');
    ok(await p.$eval('g.nd[data-ci="esx1"] rect', (r) => r.getAttribute('stroke-dasharray') === null && r.getAttribute('stroke') !== '#e5484d'), 'a cluster member is not a SPOF');
    // simulate failures
    await p.click('g.nd[data-ci="esx1"]'); ok(await wait(p, () => /If ESX01 fails/.test(document.getElementById('view').textContent) && /no application goes down/.test(document.getElementById('view').textContent) && /Kept standing by the cluster: CL-PROD/.test(document.getElementById('view').textContent)), 'a cluster member down: nothing goes down');
    await p.click('g.nd[data-ci="db1"]'); ok(await wait(p, () => /If DB01 fails/.test(document.getElementById('view').textContent) && /Claims down/.test(document.getElementById('view').textContent) && /Customer Portal down/.test(document.getElementById('view').textContent)), 'the database down: both applications down');
    ok(await p.$eval('g.nd[data-ci="app1"] rect', (r) => r.getAttribute('fill')) === '#3a1d1f', 'failed components shaded in the map');
    await p.click('#clrimp'); ok(!/If DB01 fails/.test(await V(p)), 'simulation cleared');
    ok(/Why the risk is/.test(await V(p)) && /single point/.test(await V(p)), 'risk reasons');
    await p.click('.ap[data-app="portal"]'); ok(await wait(p, () => /web-old/.test(document.getElementById('view').textContent)), 'unmapped machine said');
    // findings from a KPI
    await p.click('.kpi[data-go="findings:spof"]'); ok(await wait(p, () => document.querySelectorAll('tr[data-finding]').length >= 1 && [...document.querySelectorAll('tr[data-finding]')].every((r) => /Single point/.test(r.textContent))), 'the SPOF KPI filters the findings');
    await p.selectOption('#fk', ''); ok(/End of life/.test(await V(p)) && /Under-rated/.test(await V(p)) && /Unconfirmed link/.test(await V(p)), 'every finding kind listed');
    // snapshot + changes
    await p.click('#tabs [data-tab="drift"]'); ok(/second snapshot/.test(await V(p)), 'changes: needs a snapshot first');
    await p.click('#snap'); ok(await wait(p, () => /Snapshot recorded/.test(document.body.textContent)), 'snapshot recorded');
    ok(e.app.store.auditTail(20).some((a) => a.action === 'cmdb-deps.snapshot' && a.by === 'nora.syn'), 'snapshot audited');
    await p.click('#tabs [data-tab="ai"]'); ok(/AI dependency analyst is off/.test(await V(p)), 'AI off says why');
    const [dl] = await Promise.all([p.waitForEvent('download', { timeout: 10000 }), p.click('#xls')]);
    ok(/^cmdb-dependencies-\d{4}-\d{2}-\d{2}\.xlsx$/.test(dl.suggestedFilename()), 'Excel export');
    ok(!(await p.evaluate(() => window.__xss)), 'hostile asset text stayed text');
    WHO = { user: 'vera.syn', role: 'viewer' };
    const q = await ctx.newPage(); q.on('pageerror', (x) => errs.push(x.message)); await q.goto(url); await wait(q, () => !document.getElementById('main').hidden);
    ok(!(await q.isVisible('#snap')) && /Read-only/.test(await q.textContent('#me')), 'viewer: read-only');
    await q.click('g.nd[data-ci="db1"]'); ok(await wait(q, () => /If DB01 fails/.test(document.getElementById('view').textContent)), 'a viewer can still simulate');
    const nav = fs.readFileSync(path.join(DASH, 'vendor', 'zyb-nav.js'), 'utf8');
    ok(/"h": "cmdb-deps.html"/.test(nav) && /cmdb-deps\.html/.test(fs.readFileSync(path.join(DASH, 'install-dashboards.sh'), 'utf8')), 'menu entry and installer');
    ok(/'itam-cmdb': 'cmdb-deps\.html'/.test(fs.readFileSync(path.join(DASH, 'vendor', 'zyb-menu.js'), 'utf8')) && /'itam-cmdb': 'cmdb-deps\.html'/.test(fs.readFileSync(path.join(DASH, 'vendor', 'zyb-early.js'), 'utf8')), 'the portal\'s ITAM CMDB & Dependencies opens this page');
    ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  } finally { await browser.close(); srv.close(); await e.close(); }
  console.log((bad ? 'FAILED ' : 'ok ') + (n - bad) + '/' + n);
  process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
