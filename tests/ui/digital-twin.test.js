// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for the Digital Twin (dashboards/server/digital-twin.html) against the REAL ITAM engine (engine/twin-studio.js on
// engine/cmdb-deps.js) with SYNTHETIC assets / sites / relationships / applications: KPIs, readiness with its points, fix first from the
// Monte Carlo model, the site map, losing a site from the map, building a scenario (a cluster member alone = degraded; the database
// host = down with no recovery path), ML tab (outage probability, likelihood with reasons, prior vs learned), recording an outage
// (operator) teaches the model, DR copy recorded by an admin turns "down" into "fails over", settings (admin only), viewer read-only,
// AI off says why, Excel, a hostile asset name stays text, the menu entry, installer and the portal redirect of the old twin view.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node digital-twin.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const ITAM = path.join(__dirname, '..', '..', 'backend', 'itam'), DASH = path.join(__dirname, '..', '..', 'ui');
const H = require(path.join(ITAM, 'tests', 'helpers'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const XSS = '<img src=x onerror="window.__xss=1">';

(async () => {
  const e = await H.startApp({ noAi: true });
  const A = e.app.store.collection('assets'), R = e.app.store.collection('relationships');
  const put = (id, name, type, criticality, site, extra) => A.put(Object.assign({ id, name, type, status: 'in_use', criticality, site }, extra || {}));
  put('app1', 'APP01', 'vm', 'critical', 'Site-A'); put('app2', 'APP02', 'vm', 'critical', 'Site-A'); put('web1', 'WEB01 ' + XSS, 'vm', 'high', 'Site-B');
  put('db1', 'DB01', 'server', 'medium', 'Site-A'); put('esx1', 'ESX01', 'server', 'critical', 'Site-A'); put('esx2', 'ESX02', 'server', 'critical', 'Site-A');
  put('esx3', 'ESX03', 'server', 'high', 'Site-A', { eol: '2025-12-31' }); put('cl1', 'CL-PROD', 'cluster', 'critical', 'Site-A');
  let k = 0; const rel = (from, to, type) => R.put({ id: 'r' + (++k), from, to, type, status: 'confirmed', source: 'test' });
  rel('app1', 'cl1', 'runs_on'); rel('app2', 'cl1', 'runs_on'); rel('esx1', 'cl1', 'member_of'); rel('esx2', 'cl1', 'member_of');
  rel('app1', 'db1', 'depends_on'); rel('app2', 'db1', 'depends_on'); rel('db1', 'esx3', 'runs_on'); rel('web1', 'app1', 'depends_on');
  e.app.store.collection('app_route').put({ id: 'profile', apps: [{ id: 'claims', name: 'Claims', machines: ['APP01', 'APP02'], criticality: 'critical' }, { id: 'portal', name: 'Customer Portal', machines: ['WEB01 ' + XSS], criticality: 'high' }, { id: 'hr', name: 'HR', machines: ['NOPE'] }] });
  require(path.join(ITAM, 'engine/duty')).registerDuty(e.app.srv, e.app, { noTimer: true });
  if (e.app.addons.updateHealth) e.app.addons.updateHealth.view = () => ({ pages: [] });
  let WHO = { user: 'syed', role: 'admin' };
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
  const url = 'http://127.0.0.1:' + srv.address().port + '/dashboards/digital-twin.html';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  const wait = (p, fn, arg) => p.waitForFunction(fn, arg, { timeout: 20000 }).then(() => true, () => false);
  const V = (p) => p.textContent('#view');
  const tab = (p, t) => p.click('#tabs [data-tab="' + t + '"]');
  try {
    const ctx = await browser.newContext({ viewport: { width: 1600, height: 1000 }, acceptDownloads: true });
    const p = await ctx.newPage(); p.on('pageerror', (x) => errs.push(x.message));
    await p.goto(url); await wait(p, () => !document.getElementById('main').hidden);
    const K = await p.textContent('#kpis');
    ok(/resilience readiness/.test(K) && /single points of failure/.test(K) && /2 \/ 3/.test(K), 'KPIs: readiness, mapped 2 / 3, SPOFs');
    ok(/Administrator/.test(await p.textContent('#me')), 'role shown');
    ok(/What takes points off/.test(await V(p)) && /single point/.test(await V(p)) && /no DR copy/.test(await V(p)), 'readiness itemised');
    ok(await wait(p, () => /Cuts expected outages|Cut in expected outages/i.test(document.getElementById('view').textContent) && /%/.test(document.getElementById('view').textContent)), 'fix first from the Monte Carlo model on the overview');
    ok(/Backup Coverage/.test(await V(p)), 'data sources listed');
    // site map + losing a site
    await tab(p, 'map'); ok(/Site-A/.test(await V(p)) && /Site-B/.test(await V(p)) && (await p.$$('#view svg rect')).length >= 4, 'site map drawn');
    await p.click('[data-lose="Site-A"]'); ok(await wait(p, () => /Impact/.test(document.getElementById('view').textContent) && /2 down/.test(document.getElementById('view').textContent)), 'losing Site-A: both applications down');
    ok(/no recovery path/.test(await V(p)), 'servers without backup: no recovery path, never an invented time');
    // build a scenario
    await p.click('#clrpick'); await p.selectOption('#cisel', 'esx1'); await p.click('#ciadd'); await p.click('#run');
    ok(await wait(p, () => /Degraded — redundancy held/.test(document.getElementById('view').textContent) && /0 down/.test(document.getElementById('view').textContent)), 'a cluster member alone: degraded, nothing down');
    await p.click('#clrpick'); await p.selectOption('#cisel', 'esx3'); await p.click('#ciadd'); await p.click('#run');
    ok(await wait(p, () => /2 down/.test(document.getElementById('view').textContent) && /target missed/.test(document.getElementById('view').textContent)), 'the database host down: both down, recovery target missed');
    ok(/Unknown — not mapped/.test(await V(p)), 'an unmapped application is unknown, not safe');
    await tab(p, 'map'); ok(/DOWN/.test(await p.textContent('#view svg')), 'the site map shows the simulation');
    // ML
    await tab(p, 'ml'); ok(await wait(p, () => /Monte Carlo/.test(document.getElementById('view').textContent) && /Chance of an outage/.test(document.getElementById('view').textContent)), 'Monte Carlo per application');
    ok(/past end of life/.test(await V(p)) && /prior \(no outage recorded\)/.test(await V(p)), 'likelihood reasons and the prior said');
    // outages teach the model
    await tab(p, 'outages'); await wait(p, () => /Outage history/.test(document.getElementById('view').textContent));
    await p.selectOption('#oasset', 'esx1'); await p.fill('#odate', '2026-10-01'); await p.fill('#omin', '90'); await p.fill('#ocause', 'Power supply failure on the host'); await p.click('#osave');
    ok(await wait(p, () => /model has learned/.test(document.body.textContent)), 'outage recorded');
    ok(e.app.store.auditTail(20).some((a) => a.action === 'twin.outage' && a.by === 'syed'), 'outage audited');
    await tab(p, 'ml'); ok(await wait(p, () => /learned/.test(document.getElementById('view').textContent)), 'the model now says learned');
    // DR copy turns down into failover
    await tab(p, 'dr'); ok(/No DR copy/.test(await V(p)), 'no DR copy listed');
    await p.selectOption('#dapp', 'claims'); await p.selectOption('#dsite', 'Site-B'); await p.fill('#dnote', 'BCP 2026 section 4: Claims standby at Site-B'); await p.click('#dsave');
    ok(await wait(p, () => /DR copy recorded/.test(document.getElementById('view').textContent) && /BCP 2026/.test(document.getElementById('view').textContent)), 'DR copy recorded');
    ok(e.app.store.auditTail(20).some((a) => a.action === 'twin.dr-pair' && a.by === 'syed'), 'DR copy audited');
    await tab(p, 'map'); ok(await wait(p, () => /DR/.test(document.querySelector('#view svg').textContent)), 'DR link drawn');
    await p.click('[data-lose="Site-A"]'); ok(await wait(p, () => /Fails over to DR/.test(document.getElementById('view').textContent)), 'with the DR copy, losing Site-A fails Claims over');
    // settings
    await tab(p, 'settings'); await p.fill('#hz', '3'); await p.click('#ssave'); ok(await wait(p, () => /horizon_days must be at least 7/.test(document.body.textContent)), 'validation names the field');
    await p.fill('#hz', '30'); await p.click('#ssave'); ok(await wait(p, () => /Settings saved/.test(document.body.textContent)), 'settings saved');
    ok(e.app.store.auditTail(30).some((a) => a.action === 'twin.settings'), 'settings audited');
    await tab(p, 'ai'); ok(/Not available/.test(await V(p)) && /external_ai_allowed/.test(await V(p)), 'AI off says why');
    const [dl] = await Promise.all([p.waitForEvent('download', { timeout: 10000 }), p.click('#xls')]);
    ok(/^digital-twin-\d{4}-\d{2}-\d{2}\.xlsx$/.test(dl.suggestedFilename()), 'Excel export');
    ok(!(await p.evaluate(() => window.__xss)), 'hostile asset name stayed text');
    // viewer
    WHO = { user: 'vera.syn', role: 'viewer' };
    const q = await ctx.newPage(); q.on('pageerror', (x) => errs.push(x.message)); await q.goto(url); await wait(q, () => !document.getElementById('main').hidden);
    ok(/Read-only/.test(await q.textContent('#me')), 'viewer: read-only');
    await tab(q, 'dr'); ok(!(await q.$('#dsave')), 'viewer: no DR form'); await tab(q, 'outages'); ok(!(await q.$('#osave')), 'viewer: no outage form');
    await tab(q, 'settings'); ok(await q.$eval('#hz', (x) => x.disabled), 'viewer: settings read-only');
    await tab(q, 'map'); await q.click('[data-lose="Site-B"]'); ok(await wait(q, () => /Impact/.test(document.getElementById('view').textContent)), 'a viewer can still simulate');
    const nav = fs.readFileSync(path.join(DASH, 'vendor', 'zyb-nav.js'), 'utf8');
    ok(/"h": "digital-twin.html"/.test(nav) && /digital-twin\.html/.test(fs.readFileSync(path.join(DASH, 'install-dashboards.sh'), 'utf8')), 'menu entry and installer');
    ok(/twin: 'digital-twin\.html'/.test(fs.readFileSync(path.join(DASH, 'vendor', 'zyb-menu.js'), 'utf8')) && /twin: 'digital-twin\.html'/.test(fs.readFileSync(path.join(DASH, 'vendor', 'zyb-early.js'), 'utf8')), 'the portal\'s Digital Twin opens this page');
    ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  } finally { await browser.close(); srv.close(); await e.close(); }
  console.log((bad ? 'FAILED ' : 'ok ') + (n - bad) + '/' + n);
  process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
