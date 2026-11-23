// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for the power filter of virtualization.html (Hosts and VMs from every source): each source writes the power
// state its own way (poweredOn / POWERED_OFF / ON / running / suspended); "Powered on" and "Powered off" match whole
// words, so a state such as "notConnected" (it contains "on") is in neither, and a blank state is in neither.
// Stubbed IT Asset Management API, SYNTHETIC data. Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node virtualization-power.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const DASH = path.resolve(__dirname, '../../ui');
let n = 0, bad = 0;
const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const items = [['VM-SYN-ON1', 'poweredOn'], ['VM-SYN-ON2', 'POWERED_ON'], ['VM-SYN-ON3', 'ON'], ['VM-SYN-RUN', 'running'],
  ['VM-SYN-OFF1', 'poweredOff'], ['VM-SYN-OFF2', 'OFF'], ['VM-SYN-SUS', 'suspended'], ['VM-SYN-NC', 'notConnected'], ['VM-SYN-BLANK', '']]
  .map(([name, power_state], i) => ({ id: 'v' + i, name, kind: 'vm', power_state, source: 'vcenter', ip: '10.7.0.' + (i + 1) }));
(async () => {
  const srv = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://x'), json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u.pathname === '/dashboards/whoami.json') return json(200, { user: 'omar.syn', role: 'operator' });
    if (u.pathname === '/api/itam/virt') return json(200, { platforms: [], kinds: {} });
    if (u.pathname === '/api/itam/virt/inventory') return json(200, { items, total: items.length, summary: { hosts: 0, vms: items.length, by_source: { vcenter: items.length } }, scopes: [] });
    if (u.pathname.startsWith('/api/')) return json(404, { error: 'not found' });
    const f = path.join(DASH, u.pathname.replace(/^\/dashboards\//, '/')); if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (err, d) => { if (err) { res.writeHead(404); res.end(); return; } res.writeHead(200, { 'Content-Type': u.pathname.endsWith('.js') ? 'application/javascript' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  try {
    const page = await browser.newPage(); page.on('pageerror', (x) => errs.push(x.message));
    await page.goto('http://127.0.0.1:' + srv.address().port + '/dashboards/virtualization.html');
    await page.waitForFunction(() => /of 9/.test(document.getElementById('ic').textContent), null, { timeout: 15000 });
    const names = () => page.evaluate(() => [].map.call(document.querySelectorAll('#inv tbody tr td:first-child b'), (b) => b.textContent).sort().join(','));
    await page.selectOption('#ip', 'on');
    ok(await names() === 'VM-SYN-ON1,VM-SYN-ON2,VM-SYN-ON3,VM-SYN-RUN', 'powered on: every spelling, not notConnected: ' + await names());
    await page.selectOption('#ip', 'off');
    ok(await names() === 'VM-SYN-OFF1,VM-SYN-OFF2,VM-SYN-SUS', 'powered off incl. suspended: ' + await names());
    await page.selectOption('#ip', '');
    ok((await names()).split(',').length === 9, 'any power state: all');
    ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  } finally { await browser.close(); srv.close(); }
  console.log(bad ? 'FAILED ' + bad + '/' + n + ' checks' : 'OK ' + n + '/' + n + ' checks'); process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
