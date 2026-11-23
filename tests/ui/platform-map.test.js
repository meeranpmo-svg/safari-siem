// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for Platform Map (dashboards/server/platform-map.html) against the REAL IT Asset Management engine
// (engine/platform-map.js) over SYNTHETIC records: sources with their real state (connected / needs attention / not connected),
// wires drawn per source with flow only on connected ones, the hub stages and AI mode, outcomes with live counts linking to their
// pages, phone width stacks without overflow, menu entry.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node platform-map.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const ITAM = path.join(__dirname, '..', '..', 'backend', 'itam'), DASH = path.join(__dirname, '..', '..', 'ui');
const H = require(path.join(ITAM, 'tests', 'helpers'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
(async () => {
  const e = await H.startApp({ noAi: true });
  require(path.join(ITAM, 'engine/duty')).registerDuty(e.app.srv, e.app, { noTimer: true, python: process.env.PYTHON || 'python3' });
  const c = (x) => e.app.store.collection(x), now = new Date().toISOString();
  c('virt_platforms').put({ id: 'v1', label: 'vCenter SYN', last_sync: { at: now, ok: true } });
  c('storage_platforms').put({ id: 's1', label: 'NetApp SYN', last_sync: { at: now, ok: false, error: 'HTTP 401 (synthetic)' } });
  c('vulnscan_results').put({ id: 'r1', hosts: ['10.0.0.1'], at: now }); c('vulnscan_findings').put({ id: 'f1', status: 'open' });
  e.app.assets.create({ name: 'SRV-SYN-1', type: 'server', status: 'in_use' }, { user: 'syed', role: 'admin' });
  const srv = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://x'), json = (code, b) => { res.writeHead(code, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u.pathname === '/dashboards/whoami.json') return json(200, { user: 'vera.syn', role: 'viewer' });
    if (u.pathname.startsWith('/api/itam/')) { const h = Object.assign({}, req.headers, { 'x-sentra-proxy-secret': H.SECRET, 'x-auth-user': 'vera.syn', 'x-auth-role': 'viewer' });
      const up = http.request({ host: '127.0.0.1', port: e.port, method: req.method, path: req.url, headers: h }, (r) => { res.writeHead(r.statusCode, r.headers); r.pipe(res); }); req.pipe(up); return; }
    if (u.pathname.startsWith('/api/')) return json(404, { error: 'not in this test' });
    const f = path.join(DASH, u.pathname.replace(/^\/dashboards\//, '/')); if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (err, d) => { if (err) { res.writeHead(404); res.end(); return; } res.writeHead(200, { 'Content-Type': u.pathname.endsWith('.js') ? 'application/javascript' : u.pathname.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port + '/';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  const wait = (p, fn) => p.waitForFunction(fn, null, { timeout: 20000 }).then(() => true, () => false);
  try {
    const p = await browser.newPage({ viewport: { width: 1500, height: 1000 } }); p.on('pageerror', (x) => errs.push(x.message));
    await p.goto(base + 'platform-map.html?standalone=1');
    ok(await wait(p, () => !document.getElementById('main').hidden), 'the page loads');
    ok((await p.$$('#sources .src')).length === 14 && (await p.$$('#outcomes .out')).length === 7, '14 sources and 7 outcomes');
    ok(await p.$eval('[data-src="virt"]', (x) => x.classList.contains('connected')), 'virtualization connected from its last sync');
    ok(await p.$eval('[data-src="storage"]', (x) => x.classList.contains('error') && /HTTP 401/.test(x.textContent)), 'storage needs attention, with the reason');
    ok(await p.$eval('[data-src="backup"]', (x) => x.classList.contains('not_connected')), 'backup not connected');
    ok(await wait(p, () => document.querySelectorAll('#wires path[id^="w"]').length === 14 && document.querySelectorAll('#wires path[id^="o"]').length === 7), 'a wire per source and per outcome');
    ok(await p.evaluate(() => document.querySelectorAll('#wires animateMotion').length === 2 + 7), 'data flows only from the connected sources (+ to outcomes)');
    ok(/Collect/.test(await p.textContent('#stages')) && /A person approves/.test(await p.textContent('#stages')), 'the five stages');
    ok(/AI: /.test(await p.textContent('#aimode')), 'AI mode shown');
    ok(await p.$eval('[data-out="assets"] .val', (x) => x.textContent === '1') && await p.$eval('[data-out="vulns"] .val', (x) => x.textContent === '1'), 'live outcome counts');
    ok(await p.$eval('[data-out="vulns"]', (x) => x.getAttribute('href') === 'vapt-studio.html'), 'an outcome opens its page');
    ok(await p.evaluate(() => (window.ZYB_NAV || []).some((a) => (a.pages || []).some((x) => x.h === 'platform-map.html'))), 'the menu has the page');
    // machine learning layer
    const rd = (await p.textContent('#rd')).replace(/\s+/g, ' ');
    ok(/\d+ of 100/.test(rd) && /sources delivering/.test(rd) && /connected = full weight/.test(rd), 'readiness score with its method: ' + rd);
    ok(/Trend|days/.test(await p.textContent('#trend')), 'the readiness trend (or why it is withheld)');
    ok(/Connect Vulnerability|Connect SIEM|Connect Endpoint protection|Fix Storage/.test(await p.textContent('#nx')) && /^\+\d/.test((await p.textContent('#nx .g')).trim()), 'next best actions with the readiness each adds');
    ok(!/Connect Vulnerability scanners/.test(await p.textContent('#nx')), 'a delivering source is not proposed');
    ok(await p.$eval('[data-out="vulns"] .cf i', (x) => /width:\s*100%/.test(x.getAttribute('style'))) && /missing:/.test(await p.textContent('[data-out="coverage"]')), 'outcome confidence and the sources it is missing');
    ok((await p.$$('[data-src="virt"] .hs i')).length === 30, 'a 30-day history strip per source');
    await p.hover('[data-src="vuln"]');
    ok(await wait(p, () => document.getElementById('map').classList.contains('focus') && document.querySelector('[data-out="vulns"]').classList.contains('hl') && !document.querySelector('[data-out="soc"]').classList.contains('hl') && document.querySelector('#wires path[data-s="vuln"]').classList.contains('hl')), 'hovering a source lights the outcomes it feeds');
    await p.hover('[data-out="soc"]');
    ok(await wait(p, () => document.querySelector('[data-src="siem"]').classList.contains('hl') && !document.querySelector('[data-src="vuln"]').classList.contains('hl')), 'hovering an outcome lights the sources it depends on');
    await p.click('[data-src="storage"]');
    ok(await wait(p, () => !document.getElementById('drawer').hidden && /HTTP 401/.test(document.getElementById('drawer').innerText) && /readiness \+/.test(document.getElementById('drawer').innerText)), 'clicking a source opens its details with what fixing it adds');
    ok(await p.$eval('#drawer a.btn', (x) => x.getAttribute('href') === 'storage.html'), 'the drawer links to the source page');
    await p.keyboard.press('Escape'); ok(await wait(p, () => document.getElementById('drawer').hidden), 'Escape closes the details');
    await p.click('[data-flt="probs"]'); ok(await p.evaluate(() => document.getElementById('map').classList.contains('probs')), 'Only problems dims the connected sources');
    await p.setViewportSize({ width: 400, height: 900 }); await p.waitForTimeout(600);
    ok(await p.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1), 'phone width: no sideways scroll');
  } finally { await browser.close(); srv.close(); await e.close(); }
  ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks'); process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
