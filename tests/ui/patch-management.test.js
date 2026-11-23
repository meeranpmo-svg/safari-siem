// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for Unified Patch Management (dashboards/server/patch-management.html) against the REAL ITAM engine (patch-hub.js
// via duty.js) with SYNTHETIC assets: KPIs and the class table (coverage, what to connect), the asset list with every source's
// finding and filters (KPI chip, class, search); an administrator sets a firewall baseline and the firewall becomes current; an
// operator requests an exception, the requester cannot approve it, a different administrator approves it and the asset shows as
// excepted; a viewer has no actions; a hostile asset name stays text; phone width; the menu entry and the installer.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node patch-management.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const ITAM = path.join(__dirname, '..', '..', 'backend', 'itam'), DASH = path.join(__dirname, '..', '..', 'ui');
const H = require(path.join(ITAM, 'tests', 'helpers'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const XSS = '<img src=x onerror="window.__xss=1">';
const D = 86400000, NOW = Date.now();
(async () => {
  const e = await H.startApp({ noAi: true });
  for (const a of [
    { id: 'a-win1', name: 'WIN-APP01', type: 'server', os: 'Windows Server 2019', criticality: 'critical', environment: 'production' },
    { id: 'a-sol', name: 'SOL-DB01', type: 'server', os: 'Oracle Solaris 11.4', environment: 'production' },
    { id: 'a-pc1', name: 'FIN-PC-07' + XSS, type: 'laptop', os: 'Windows 11 Pro' },
    { id: 'a-pc3', name: 'OLD-PC-01', type: 'desktop', os: 'Windows 7 Professional' },
    { id: 'a-fw2', name: 'FW-BR2', type: 'firewall', vendor: 'Fortinet', model: 'FortiGate 60F', firmware: '7.4.5' },
  ]) e.app.store.collection('assets').put(Object.assign({ status: 'in_use' }, a));
  require(path.join(ITAM, 'engine/duty')).registerDuty(e.app.srv, e.app, { noTimer: true, usHosts: () => [],
    usEc: () => ({ computers: [{ name: 'WIN-APP01', asset_id: 'a-win1', missing: 6, critical: 2, installed: 90, last_contact: NOW - D }], patches: [] }) });
  e.app.addons.manageengine = { computers: () => ({ computers: [{ name: 'FIN-PC-07', asset_id: 'a-pc1', missing: 3, critical: 1, last_contact: NOW - D }] }) };
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
  const url = 'http://127.0.0.1:' + srv.address().port + '/dashboards/patch-management.html';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  const wait = (p, fn, arg) => p.waitForFunction(fn, arg, { timeout: 15000 }).then(() => true, () => false);
  const row = (p, name) => p.evaluate((nm) => { const r = [...document.querySelectorAll('#items tbody tr')].find((tr) => tr.querySelector('td:nth-child(2) b').textContent.startsWith(nm)); return r ? r.textContent : null; }, name);
  try {
    const p = await browser.newPage({ viewport: { width: 1500, height: 1000 } }); p.on('pageerror', (x) => errs.push(x.message));
    await p.goto(url); ok(await wait(p, () => !document.getElementById('main').hidden && document.querySelectorAll('#items tbody tr').length === 5), 'opens with five assets');
    ok((await p.$$('#kpis .kpi')).length === 7, 'seven KPI tiles');
    const cls = await p.textContent('#classes'); ok(/Servers/.test(cls) && /Desktops & laptops/.test(cls) && /Firewalls/.test(cls) && /Databases/.test(cls), 'every class listed');
    ok(/To measure the rest: connect Endpoint Central/.test(cls), 'what to connect for unmeasured servers');
    ok(/behind/.test(await row(p, 'WIN-APP01')) && /2 critical patch/.test(await row(p, 'WIN-APP01')), 'server: critical patches missing from Update Studio');
    ok(/end of life/.test(await row(p, 'OLD-PC-01')), 'Windows 7: end of life');
    ok(/not measured/.test(await row(p, 'SOL-DB01')), 'Solaris with no source: not measured');
    ok(/not measured/.test(await row(p, 'FW-BR2')), 'firewall with no baseline: not measured');
    ok(!(await p.evaluate(() => window.__xss)) && /<img src=x/.test(await p.textContent('#items')), 'a hostile asset name stays text');
    await p.click('[data-kf="eol"]'); ok(await wait(p, () => document.querySelectorAll('#items tbody tr').length === 1), 'KPI chip filters to end of life');
    await p.click('[data-kf="eol"]'); await p.selectOption('#fc', 'desktop'); ok(await wait(p, () => document.querySelectorAll('#items tbody tr').length === 2), 'class filter');
    await p.selectOption('#fc', ''); await p.fill('#q', 'fw-br'); ok(await wait(p, () => document.querySelectorAll('#items tbody tr').length === 1), 'search');
    await p.fill('#q', '');
    ok(!(await p.$('#psave')) && /Administrators set the policy/.test(await p.textContent('#pol')), 'an operator does not set the policy');
    // operator: exception for the Solaris server
    await p.click('[data-exc="asset:a-sol"]');
    await p.fill('#xr', 'core insurance vendor has not certified the patch (synthetic)'); await p.fill('#xc', 'isolated VLAN, no internet access'); await p.click('#dok');
    ok(await wait(p, () => /PX-00001/.test(document.getElementById('exc').textContent) && /pending/.test(document.getElementById('exc').textContent)), 'exception requested, pending');
    // the requester as admin cannot approve
    WHO = { user: 'nora.syn', role: 'admin' }; await p.goto(url); await wait(p, () => !document.getElementById('main').hidden);
    ok(!(await p.$('[data-dec="approved"]')) && /another person decides/.test(await p.textContent('#exc')), 'the requester cannot approve');
    // a different administrator: baseline + approval
    WHO = { user: 'adam.syn', role: 'admin' }; await p.goto(url); await wait(p, () => document.getElementById('psave'));
    ok(/7\.4\.5 ×1/.test(await p.textContent('#pol')), 'the versions running are shown per platform');
    await p.fill('#bl tr[data-bl] [data-f="target"]', '7.4.5'); await p.click('#psave');
    ok(await wait(p, () => { const r = [...document.querySelectorAll('#items tbody tr')].find((tr) => /FW-BR2/.test(tr.textContent)); return r && /current/.test(r.textContent) && /meets the baseline 7\.4\.5/.test(r.textContent); }), 'the firewall meets its baseline');
    await p.click('[data-dec="approved"]'); await p.fill('#xm', 'until the vendor certifies'); await p.click('#dok');
    ok(await wait(p, () => /active until/.test(document.getElementById('exc').textContent)), 'approved by a different person');
    ok(/excepted/.test(await row(p, 'SOL-DB01')), 'the asset shows as excepted');
    const au = e.app.store.auditTail(50).map((a) => a.action); ok(['patching.policy', 'patching.exception.request', 'patching.exception.approved'].every((k) => au.includes(k)), 'audited');
    // viewer
    WHO = { user: 'vera.syn', role: 'viewer' }; await p.goto(url); await wait(p, () => !document.getElementById('main').hidden);
    ok(!(await p.$('[data-exc]')) && !(await p.$('[data-rev]')) && !(await p.$('#psave')), 'a viewer has no actions');
    const ph = await browser.newPage({ viewport: { width: 390, height: 900 } }); await ph.goto(url); await wait(ph, () => !document.getElementById('main').hidden);
    ok(await ph.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1), 'phone width: no sideways scroll'); await ph.close();
    const nav = fs.readFileSync(path.join(DASH, 'vendor', 'zyb-nav.js'), 'utf8');
    ok(/"h": "patch-management.html"/.test(nav) && / patch-management\.html /.test(fs.readFileSync(path.join(DASH, 'install-dashboards.sh'), 'utf8')), 'menu entry and installer');
    ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  } finally { await browser.close(); srv.close(); await e.close(); }
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n);
  process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
