// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for Continuous Attack Surface (dashboards/server/attack-surface.html, vendor/zyb-attacksurface.js) against the REAL
// ITAM engine, SYNTHETIC data only: the surface lists internet-facing assets with their exposed services and APIs; a shadow asset is
// flagged; the detail modal shows the exposure breakdown and the services with evidence, read-only (no scan / exploit control); an
// admin records a snapshot and the change feed then reports a newly exposed service; filters work; a viewer is refused; in the menu.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node attack-surface.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const ITAM = path.join(__dirname, '..', '..', 'backend', 'itam'), DASH = path.join(__dirname, '..', '..', 'ui');
const H = require(path.join(ITAM, 'tests', 'helpers'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };

(async () => {
  const e = await H.startApp({ noAi: true });
  require(path.join(ITAM, 'engine/duty')).registerDuty(e.app.srv, e.app, { noTimer: true, python: process.env.PYTHON || 'python3' });
  const c = (x) => e.app.store.collection(x);
  e.app.addons.vaptCenter = { gather: async () => ({ findings: [{ src: 'greenbone', id: 'f1', host: '203.0.113.10', asset: 'web-dmz-01', title: 'Apache path traversal (unauth RCE)', severity: 'high', cvss: 8.1, cves: ['CVE-2024-0001'], fix: 'Upgrade Apache to 2.4.62 or later (synthetic)', verify: 'Rescan the host', status: 'open', exposure: 'external' }], status: { greenbone: { ok: true } } }) };
  c('assets').put({ id: 'web', name: 'web-dmz-01', type: 'webapp', status: 'active', mgmt_ip: '203.0.113.10', hostname: 'web-dmz-01', exposure: 'external', software: [{ name: 'Apache 2.4' }], tags: ['api'] });
  c('assets').put({ id: 'db', name: 'core-db', type: 'database', status: 'active', mgmt_ip: '10.0.1.9', criticality: 'critical', classification: 'secret' });
  c('disc_devices').put({ id: 'D1', ips: ['203.0.113.10'], open_ports: [443, 22], hostname: 'web-dmz-01', last_seen: new Date().toISOString(), status: 'approved' });
  c('disc_devices').put({ id: 'D2', ips: ['203.0.113.50'], open_ports: [80, 3389], hostname: 'unknown-vps', last_seen: new Date().toISOString(), status: 'new' });
  c('relationships').put({ id: 'R1', from: 'web', to: 'db', type: 'depends_on', status: 'confirmed' });
  let WHO = { user: 'syed', role: 'admin' };
  const srv = http.createServer((req, res) => {
    const u2 = new URL(req.url, 'http://x'), json = (code, b2) => { res.writeHead(code, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b2)); };
    if (u2.pathname === '/dashboards/whoami.json') return json(200, WHO);
    if (u2.pathname.startsWith('/api/itam/')) {
      const h = Object.assign({}, req.headers, { 'x-sentra-proxy-secret': H.SECRET, 'x-auth-user': WHO.user, 'x-auth-role': WHO.role });
      const up = http.request({ host: '127.0.0.1', port: e.port, method: req.method, path: req.url, headers: h }, (r) => { res.writeHead(r.statusCode, r.headers); r.pipe(res); });
      req.pipe(up); return;
    }
    if (u2.pathname.startsWith('/api/')) return json(404, { error: 'not in this test' });
    const f = path.join(DASH, u2.pathname.replace(/^\/dashboards\//, '/')); if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (err, d) => { if (err) { res.writeHead(404); res.end(); return; } res.writeHead(200, { 'Content-Type': u2.pathname.endsWith('.js') ? 'application/javascript' : u2.pathname.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port + '/';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  const has = (p, sel, re) => p.waitForFunction((a) => new RegExp(a[1], 'i').test((document.querySelector(a[0]) || {}).textContent || ''), [sel, re.source], { timeout: 10000 }).then(() => true, () => false);
  try {
    const p = await browser.newPage({ viewport: { width: 1400, height: 1000 } }); p.on('pageerror', (x) => errs.push(x.message));
    await p.goto(base + 'attack-surface.html?standalone=1'); await p.waitForSelector('#surface table', { timeout: 10000 });
    ok(await has(p, '#surface', /web-dmz-01/), 'the internet-facing asset is listed');
    ok(await has(p, '#surface', /shadow/), 'a shadow asset is flagged');
    ok(await has(p, '#apis', /HTTPS/), 'the API surface is listed');
    ok(await has(p, '#kk', /Risky services/), 'KPIs');
    ok(await has(p, '#changes', /first run|first snapshot/i), 'first run: the feed starts next snapshot');
    // detail: exposure breakdown, services with evidence, chain, no scan/exploit control
    await p.click('#surface tr[data-open="web"]'); await p.waitForSelector('#dlg[open]');
    ok(await has(p, '#dlgb', /Why this exposure/) && await has(p, '#dlgb', /exploit|RCE/i), 'exposure itemised');
    ok(await has(p, '#dlgb', /Asset Discovery saw port 443/), 'service evidence shown');
    ok(await has(p, '#dlgb', /Required actions/) && await has(p, '#dlgb', /Upgrade Apache to 2\.4\.62/) && await has(p, '#dlgb', /Verify: Rescan the host/) && await has(p, '#dlgb', /From: Apache path traversal/), 'required actions listed with why, verify and the finding they come from');
    ok(await p.$eval('#dlgb ol', (o) => o.children.length >= 2), 'actions numbered, worst first');
    ok(await has(p, '#dlgb', /core-db/) && await has(p, '#dlgb', /Attack Chain/), 'links to the attack chain to the crown jewel');
    ok(!(await p.$('#dlgb button')), 'read-only: no scan / exploit button in the detail');
    await p.click('#dlgx');
    // admin snapshot, then a change
    await Promise.all([p.waitForResponse((r) => /\/attack-surface\/snapshot$/.test(r.url())), p.click('#snap')]);
    c('disc_devices').put({ id: 'D1', ips: ['203.0.113.10'], open_ports: [443, 22, 3389], hostname: 'web-dmz-01', last_seen: new Date().toISOString(), status: 'approved' });
    await p.click('#refresh'); ok(await has(p, '#changes', /new service.*RDP|RDP.*port 3389/i), 'change feed reports the newly exposed RDP');
    // filter
    await p.selectOption('#flt', 'shadow'); ok((await p.$$('#surface tbody tr')).length === 1, 'shadow filter');
    await p.selectOption('#flt', 'api'); ok(await has(p, '#surface', /web-dmz-01/), 'API filter');
    // viewer refused
    WHO = { user: 'vera.syn', role: 'viewer' }; await p.reload();
    ok(await has(p, '#err', /operators and administrators/), 'viewer refused with a reason');
    const nav = fs.readFileSync(path.join(DASH, 'vendor', 'zyb-nav.js'), 'utf8'), inst = fs.readFileSync(path.join(DASH, 'install-dashboards.sh'), 'utf8');
    ok(nav.includes('"attack-surface.html"') && inst.includes('attack-surface.html') && inst.includes('vendor/zyb-attacksurface.js'), 'in the menu and installed');
    ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  } finally { await browser.close(); srv.close(); await e.close(); }
  console.log((bad ? 'FAILED ' : 'ok ') + (n - bad) + '/' + n);
  process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
