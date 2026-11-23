// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for the Cisco tab of support-contracts.html against the REAL IT Asset Management engine (support-contracts.js
// + cisco-support.js): Cisco switches recorded with other wording (vendor "CiscoSystems", OS "Cisco IOS", vendor only on
// the discovery link) are listed; a switch the AI Network Engineer reported that waits in Asset Discovery and a Cisco asset
// with the wrong type are shown with the reason - never silently missing. Names are shown as text. Data is SYNTHETIC.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node cisco-coverage.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const ITAM = path.resolve(__dirname, '../../backend/itam'), DASH = path.resolve(__dirname, '../../ui');
const H = require(path.join(ITAM, 'tests/helpers.js'));
let n = 0, bad = 0;
const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const ADM = { user: 'syed', role: 'admin', ip: '' };

(async () => {
  const e = await H.startApp({ noAi: true });
  const A = e.app.assets, S = e.app.store;
  A.create({ name: 'SW-SYN-1', type: 'network', status: 'in_use', vendor: 'CiscoSystems', serial: 'SYN0001' }, ADM);
  A.create({ name: 'SW-SYN-2', type: 'network', status: 'in_use', os: 'Cisco IOS Software', serial: 'SYN0002' }, ADM);
  const a4 = A.create({ name: 'SW-SYN-4', type: 'network', status: 'in_use', serial: 'SYN0004' }, ADM).asset.id;
  S.collection('assets').patch(a4, (x) => { x.discovery = { vendor: 'cisco-ios', class: 'switch' }; return x; });
  A.create({ name: '<b>SW-SYN-5</b>', type: 'workstation', status: 'in_use', vendor: 'Cisco', model: 'C9200L-24P', serial: 'SYN0005' }, ADM);
  S.collection('disc_devices').put({ id: 'dd_syn1', status: 'new', type: 'switch', hostname: 'acc-sw-syn-9', ip: '10.9.9.9', vendor: 'cisco-ios', model: 'C9200L-48P', serial: 'SYN0099', methods: { netops: {} } });
  require(path.join(ITAM, 'engine/support-contracts')).registerSupportContracts(e.app.srv, e.app, { noTimer: true });
  require(path.join(ITAM, 'engine/cisco-support')).registerCiscoSupport(e.app.srv, e.app, { noTimer: true });

  const srv = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://x'), json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u.pathname === '/dashboards/whoami.json') return json(200, { user: 'syed', role: 'admin' });
    if (u.pathname.startsWith('/api/itam/')) {
      const h = Object.assign({}, req.headers, { 'x-sentra-proxy-secret': H.SECRET, 'x-auth-user': 'syed', 'x-auth-role': 'admin' });
      const up = http.request({ host: '127.0.0.1', port: e.port, method: req.method, path: req.url, headers: h }, (r) => { res.writeHead(r.statusCode, r.headers); r.pipe(res); });
      req.pipe(up); return;
    }
    if (u.pathname === '/api/soc/netops/licenses') return json(200, { items: [] });
    if (u.pathname.startsWith('/api/')) return json(404, { error: 'not in this test' });
    const f = path.join(DASH, u.pathname); if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (err, d) => { if (err) { res.writeHead(404); res.end(); return; } res.writeHead(200, { 'Content-Type': u.pathname.endsWith('.js') ? 'application/javascript' : u.pathname.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  try {
    const page = await browser.newPage({ viewport: { width: 1400, height: 950 } });
    page.on('pageerror', (x) => errs.push(x.message));
    await page.goto('http://127.0.0.1:' + srv.address().port + '/support-contracts.html');
    await page.waitForFunction(() => /Cisco switches/.test((document.getElementById('csub') || {}).textContent || ''));
    await page.click('[data-tab="cisco"]');
    const t = await page.textContent('#tab-cisco');
    ok(/SW-SYN-1/.test(t) && /SW-SYN-2/.test(t) && /SW-SYN-4/.test(t), 'Cisco switches recorded with other wording are listed');
    ok(/3 Cisco switches/.test(await page.textContent('#csub')), 'count: 3 listed');
    ok(/Cisco devices waiting in Asset Discovery/.test(t) && /acc-sw-syn-9/.test(t) && /SYN0099/.test(t) && /netops/.test(t), 'the switch waiting in Asset Discovery is shown');
    ok(/Cisco assets not listed/.test(t) && /set the type to Network/.test(t), 'the wrong-type asset is shown with the reason');
    ok(!(await page.$('#unm b b')) && /<b>SW-SYN-5<\/b>/.test(t), 'names are shown as text');
    ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  } finally { await browser.close(); srv.close(); await e.close(); }
  console.log(bad ? 'FAILED ' + bad + '/' + n + ' checks' : 'OK ' + n + '/' + n + ' checks'); process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
