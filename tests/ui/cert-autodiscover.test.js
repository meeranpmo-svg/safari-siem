// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for automatic certificate discovery on certificates.html (Discover tab) against the REAL ITAM engine
// (certs.js + cert-autodiscover.js) with a stubbed TLS reader and SYNTHETIC discovery devices: the coverage tiles read the
// open TLS ports Asset Discovery recorded; "Run now" adds what presents a certificate and the inventory shows it with the
// device name as SNI; the operator cannot save the settings, the administrator can; a hostile hostname stays text.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node cert-autodiscover.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const ITAM = path.join(__dirname, '..', '..', 'backend', 'itam'), DASH = path.join(__dirname, '..', '..', 'ui');
const H = require(path.join(ITAM, 'tests', 'helpers'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const XSS = '<img src=x onerror=alert(1)>';
const NOW = Date.now();
const CERT = (cn) => ({ ok: true, subject: cn, issuer: 'Corp Issuing CA', names: [cn], name_ok: true, trusted: true, self_signed: false, not_after: NOW + 40 * 86400000, not_after_iso: new Date(NOW + 40 * 86400000).toISOString().slice(0, 10), key_type: 'rsa', key_bits: 2048, serial: 'AB' + cn.length, fingerprint256: 'FP:' + cn });
const TLS = { '10.0.0.10:443': CERT('portal.corp.syn'), '10.0.0.11:636': CERT('dc01.corp.syn') };

let DELAY = 0;
(async () => {
  const e = await H.startApp({ noAi: true });
  require(path.join(ITAM, 'engine/duty')).registerDuty(e.app.srv, e.app, { noTimer: true, python: process.env.PYTHON || 'python3', readCert: async (h, p) => { if (DELAY) await new Promise((r) => setTimeout(r, DELAY)); return TLS[h + ':' + p] || { ok: false, error: 'ECONNRESET' }; } });
  const D = e.app.store.collection('disc_devices');
  D.put({ id: 'dd_1', status: 'new', ip: '10.0.0.10', ips: ['10.0.0.10'], hostname: 'web01' + XSS, fqdn: 'portal.corp.syn', open_ports: [22, 443] });
  D.put({ id: 'dd_2', status: 'new', ip: '10.0.0.11', ips: ['10.0.0.11'], hostname: 'dc01', open_ports: [389, 636] });
  D.put({ id: 'dd_3', status: 'new', ip: '10.0.0.12', ips: ['10.0.0.12'], hostname: 'app', open_ports: [8443] });
  let WHO = { user: 'nora.syn', role: 'operator' };
  const srv = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://x'), json = (c, b2) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b2)); };
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
  const base = 'http://127.0.0.1:' + srv.address().port + '/';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  const has = (p, sel, re) => p.waitForFunction((a) => new RegExp(a[1]).test((document.querySelector(a[0]) || {}).textContent || ''), [sel, re.source], { timeout: 10000 }).then(() => true, () => false);
  try {
    const p = await browser.newPage({ viewport: { width: 1400, height: 1000 } }); p.on('pageerror', (x) => errs.push(x.message));
    await p.goto(base + 'certificates.html?standalone=1#discover'); await p.waitForSelector('#autod .au-num', { timeout: 15000 });
    const tiles = await p.$$eval('#autod .au-num', (x) => x.map((el) => el.textContent.trim()));
    ok(tiles[0] === '3' && tiles[1] === '3' && tiles[2] === '0', 'coverage from discovery: ' + tiles.join(','));
    ok(await has(p, '#autod', /Add 636, 8443/), 'tells what to add to the sweep ports');
    await Promise.all([p.waitForResponse((r) => /autodiscovery\/run$/.test(r.url())), p.click('#adrun')]);
    ok(await has(p, '#adlast', /2 added/), 'two certificates added');
    ok(e.app.store.collection('cert_endpoints').all((x) => x.source === 'discovery').length === 2, 'in the inventory as discovery');
    await p.click('[data-tab="inventory"]'); ok(await has(p, '#inv', /portal\.corp\.syn/), 'the inventory shows it');
    ok(!(await p.$('#inv img')), 'a hostile hostname stays text');
    // settings
    await p.click('[data-tab="discover"]'); await p.waitForSelector('#adcf', { timeout: 8000 });
    await p.check('#adcf [name=enabled]');
    await Promise.all([p.waitForResponse((r) => /autodiscovery$/.test(r.url()) && r.request().method() === 'POST'), p.click('#adcf [type=submit]')]);
    ok(await has(p, '#admsg', /Only an administrator/), 'an operator cannot change the settings');
    WHO = { user: 'syed', role: 'admin' }; await p.reload(); await p.waitForSelector('#adcf', { timeout: 15000 });
    await p.check('#adcf [name=enabled]'); await p.fill('#adcf [name=ports]', '443, 636, 8443');
    await Promise.all([p.waitForResponse((r) => /autodiscovery$/.test(r.url()) && r.request().method() === 'POST'), p.click('#adcf [type=submit]')]);
    await p.waitForFunction(() => /on/.test((document.querySelectorAll('#autod .au-num')[5] || {}).textContent || ''), null, { timeout: 8000 }).then(() => ok(true), () => ok(false, 'switched on'));
    ok(e.app.store.auditTail(200).some((a) => a.action === 'certs.autodiscovery.settings' && a.by === 'syed'), 'audited');
    // a slow manual probe of the register: the page shows progress instead of an HTTP 504, then the result
    process.env.SENTRA_CERT_WAIT_MS = '200'; DELAY = 700;
    e.app.store.collection('assets').put({ id: 'ast_x', name: 'APP', type: 'server', status: 'in_use', mgmt_ip: '10.0.0.20', lifecycle: [] });
    TLS['10.0.0.20:8443'] = CERT('app.corp.syn');
    await Promise.all([p.waitForResponse((r) => /certs\/discover$/.test(r.url()) && r.request().method() === 'POST'), p.click('#disc')]);
    ok(await has(p, '#dres', /Probing in the background/), 'a slow probe shows progress (no 504)');
    ok(await p.waitForSelector('#dres [data-adopt]', { timeout: 15000 }).then(() => true, () => false) && await has(p, '#dres', /app\.corp\.syn/), 'the result appears when the probe finishes');
    delete process.env.SENTRA_CERT_WAIT_MS;
  } finally { await browser.close(); srv.close(); e.close(); }
  ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks');
  process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
