// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for Infrastructure Inventory (dashboards/server/infra-inventory.html) against the REAL ITAM engine
// (engine/infra-inventory.js) with SYNTHETIC assets and a stubbed SIEM log coverage: ring and KPIs, class tiles, the coverage
// heat map (a cell opens the assets missing that signal), asset detail with each signal and its fix, the peer outlier, gaps,
// sites, stale and duplicate assets, the portal's hand-kept rows not in the register, the SIEM down (unknown, not covered),
// Excel, a hostile asset name stays text, the menu entry and the portal redirect.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node infra-inventory.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const ITAM = path.join(__dirname, '..', '..', 'backend', 'itam'), DASH = path.join(__dirname, '..', '..', 'ui');
const H = require(path.join(ITAM, 'tests', 'helpers'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const XSS = '<img src=x onerror="window.__xss=1">';
const D = 86400000;

(async () => {
  const e = await H.startApp({ noAi: true });
  const T0 = Date.now(), ago = (d) => new Date(T0 - d * D).toISOString(), src = (...a) => a.map((x) => ({ source: x[0], last_seen: ago(x[1]) }));
  const A = [
    { id: 'fw1', name: 'FGT-HQ-SYN', type: 'network', vendor: 'Fortinet', mgmt_ip: '10.0.0.1', owner: 'Network team', site: 'Riyadh HQ', criticality: 'critical', sources: src(['discovery', 1]) },
    { id: 'vm1', name: 'APP-VM-01 ' + XSS, type: 'vm', owner: 'Apps', criticality: 'high', site: 'Riyadh DC', sources: src(['vcenter', 1]) },
    { id: 'st1', name: 'NAS-OLD', type: 'storage', site: 'Riyadh DC', sources: src(['discovery', 60]) },
  ];
  for (let i = 1; i <= 5; i++) A.push({ id: 'srv' + i, name: 'WIN-SRV-0' + i, type: 'server', mgmt_ip: i === 5 ? '10.0.1.4' : '10.0.1.' + i, owner: 'Server team', site: 'Riyadh DC', criticality: i === 5 ? 'critical' : 'medium', sources: src(['discovery', 1], ['agent', 1]) });
  for (const a of A) e.app.store.collection('assets').put(Object.assign({ status: 'in_use' }, a));
  const W = { cov: { ok: true, siem_reachable: true, assets: ['fw1', 'srv1', 'srv2', 'srv3', 'srv4'].map((id) => ({ asset_id: id, status: 'covered' })).concat([{ asset_id: 'srv5', status: 'absent' }, { asset_id: 'vm1', status: 'silent' }, { asset_id: 'st1', status: 'absent' }]) } };
  require(path.join(ITAM, 'engine/duty')).registerDuty(e.app.srv, e.app, { noTimer: true, iiCoverage: async () => W.cov, iiEc: () => [], iiVirt: () => ({ hosts: [], vms: [] }) });
  if (e.app.addons.updateHealth) e.app.addons.updateHealth.view = () => ({ pages: [] });
  let WHO = { user: 'nora.syn', role: 'operator' };
  const srv = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://x'), json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u.pathname === '/dashboards/whoami.json') return json(200, WHO);
    if (u.pathname === '/api/netassets') return json(200, { assets: [{ id: 'h1', name: 'OLD-CORE-SW', cat: 'switch', ip: '10.9.9.9', site: 'Jeddah', source: 'manual' }, { id: 'itam-fw1', name: 'FGT-HQ-SYN', cat: 'firewall', ip: '10.0.0.1', source: 'itam' }] });
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
  const url = 'http://127.0.0.1:' + srv.address().port + '/dashboards/infra-inventory.html';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  const wait = (p, fn, arg) => p.waitForFunction(fn, arg, { timeout: 15000 }).then(() => true, () => false);
  const tab = (p, t) => p.click('#tabs [data-tab="' + t + '"]');
  const V = (p) => p.textContent('#view');
  try {
    const ctx = await browser.newContext({ viewport: { width: 1440, height: 1000 }, acceptDownloads: true });
    const p = await ctx.newPage(); p.on('pageerror', (x) => errs.push(x.message));
    await p.goto(url); await wait(p, () => !document.getElementById('main').hidden);
    ok(/average coverage/.test(await p.textContent('#ring')) && /infrastructure assets/.test(await p.textContent('#kpis')), 'ring and KPIs');
    ok((await p.$$('#classes .cl')).length === 4, 'class tiles (firewalls, servers, VMs, storage)');
    // heat map: physical servers x logs = 80%
    ok(await wait(p, () => /80%/.test(document.querySelector('td[data-hm="server|logs"]').textContent)), 'heat map: 4 of 5 servers send logs');
    await p.click('td[data-hm="server|logs"]');
    ok(await wait(p, () => document.querySelectorAll('tr[data-asset]').length === 1 && /WIN-SRV-05/.test(document.getElementById('view').textContent)), 'a heat-map cell opens the asset missing it');
    await p.click('tr[data-asset="srv5"]');
    ok(await wait(p, () => /outlier: 4 of 5 physical servers have it/.test(document.getElementById('view').textContent) && /Enable log collection/.test(document.getElementById('view').textContent)), 'asset detail: outlier and fix');
    // gaps, sites, issues, portal
    await tab(p, 'gaps'); ok(/WIN-SRV-05/.test(await V(p)) && /outlier/.test(await V(p)) && /silent/.test(await V(p)), 'gaps with outlier and silent');
    await tab(p, 'sites'); ok(/Riyadh DC/.test(await V(p)) && /Riyadh HQ/.test(await V(p)), 'sites');
    await p.click('.site[data-site="Riyadh HQ"]'); ok(await wait(p, () => document.querySelectorAll('tr[data-asset]').length === 1), 'a site opens its assets');
    await tab(p, 'issues'); ok(/NAS-OLD/.test(await V(p)) && /10\.0\.1\.4/.test(await V(p)), 'stale and duplicate IP');
    await tab(p, 'portal'); ok(await wait(p, () => /OLD-CORE-SW/.test(document.getElementById('view').textContent) && !/FGT-HQ-SYN/.test(document.getElementById('view').textContent)), 'portal row not in the register listed; synced rows not');
    // Excel
    const [dl] = await Promise.all([p.waitForEvent('download', { timeout: 10000 }), p.click('#xls')]);
    ok(/^infrastructure-inventory-\d{4}-\d{2}-\d{2}\.xlsx$/.test(dl.suggestedFilename()), 'Excel export');
    await tab(p, 'ai'); ok(/AI inventory analyst is off/.test(await V(p)), 'AI off says why');
    // SIEM down
    W.cov = { ok: false, siem_reachable: false, error: 'connection refused', assets: [] };
    await p.click('#refresh'); ok(await wait(p, () => /SIEM not answering/.test(document.getElementById('siemnote').textContent)), 'SIEM down is said');
    await tab(p, 'coverage'); ok(await wait(p, () => /\?/.test(document.querySelector('td[data-hm="server|logs"]').textContent)), 'log coverage reads unknown, not covered');
    ok(!(await p.evaluate(() => window.__xss)), 'hostile asset name stayed text');
    ok(e.app.store.auditTail(20).some((a) => a.action === 'infra-inventory.refresh'), 'refresh audited');
    const nav = fs.readFileSync(path.join(DASH, 'vendor', 'zyb-nav.js'), 'utf8');
    ok(/"h": "infra-inventory.html"/.test(nav) && /infra-inventory\.html/.test(fs.readFileSync(path.join(DASH, 'install-dashboards.sh'), 'utf8')), 'menu entry and installer');
    ok(/netinv: 'infra-inventory\.html'/.test(fs.readFileSync(path.join(DASH, 'vendor', 'zyb-menu.js'), 'utf8')), 'the portal\'s "Infrastructure Inventory" opens this page');
    ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  } finally { await browser.close(); srv.close(); await e.close(); }
  console.log((bad ? 'FAILED ' : 'ok ') + (n - bad) + '/' + n);
  process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
