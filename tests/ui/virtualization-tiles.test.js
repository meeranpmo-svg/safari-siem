// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// the vCenter / Nutanix view: an organisation with VMware on (Safari's brand runs Hyper-V only - virtualization-hyperv.test.js)
// Browser test: every KPI tile on virtualization.html is clickable and filters what it counts - Hosts / VMs set the Hosts & VMs
// list, VMs twice shows the powered-off ones, "In the inventory" shows the ones not in it yet, Failing shows only the failing
// platforms (and "show all" clears it). Stubbed IT Asset Management API, SYNTHETIC data.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node virtualization-tiles.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const DASH = path.resolve(__dirname, '../../ui');
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const items = [{ id: 'h1', name: 'ESX-SYN-01', kind: 'host', source: 'vcenter', asset_id: 'A1' }, { id: 'h2', name: 'AHV-SYN-01', kind: 'host', source: 'nutanix' },
  { id: 'v1', name: 'VM-SYN-ON', kind: 'vm', power_state: 'poweredOn', source: 'vcenter', asset_id: 'A2' }, { id: 'v2', name: 'VM-SYN-OFF', kind: 'vm', power_state: 'poweredOff', source: 'nutanix' }];
const platforms = [{ id: 'p1', label: 'VC-SYN', kind: 'vcenter', base_url: 'https://10.9.0.1', credentials_set: true, last_sync: { ok: true, hosts: 1, vms: 1, at: Date.now() } },
  { id: 'p2', label: 'PRISM-SYN', kind: 'nutanix', base_url: 'https://10.9.0.2', credentials_set: true, last_sync: { ok: false, error: 'HTTP 401', at: Date.now() } }];
(async () => {
  const srv = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://x'), json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u.pathname === '/dashboards/whoami.json') return json(200, { user: 'omar.syn', role: 'operator' });
    if (u.pathname === '/api/itam/virt') return json(200, { platforms, kinds: { vcenter: 'VMware vCenter', nutanix: 'Nutanix' } });
    if (u.pathname === '/api/itam/virt/inventory') return json(200, { items, total: items.length, summary: { hosts: 2, vms: 2, vms_on: 1, vms_off: 1, in_inventory: 2, by_source: { vcenter: 2, nutanix: 2 } }, scopes: [] });
    if (u.pathname.startsWith('/api/')) return json(404, { error: 'not found' });
    const f = path.join(DASH, u.pathname.replace(/^\/dashboards\//, '/')); if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (err, d) => { if (err) { res.writeHead(404); res.end(); return; } res.writeHead(200, { 'Content-Type': u.pathname.endsWith('.js') ? 'application/javascript' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  try {
    const page = await browser.newPage({ viewport: { width: 1400, height: 1000 } }); page.on('pageerror', (x) => errs.push(x.message)); await page.addInitScript(() => { Object.defineProperty(window, 'ZYB_ORG', { configurable: true, set(v) { this._o = Object.assign({}, v, { pages_off: [] }); }, get() { return this._o; } }); }); 
    await page.goto('http://127.0.0.1:' + srv.address().port + '/dashboards/virtualization.html');
    await page.waitForFunction(() => /of 4/.test(document.getElementById('ic').textContent) && document.querySelector('#kk [data-tile]'), null, { timeout: 15000 });
    const names = () => page.evaluate(() => [].map.call(document.querySelectorAll('#inv tbody tr td:first-child b'), (b) => b.textContent).sort().join(','));
    ok((await page.$$('[data-tile]')).length === 7, 'all seven tiles are buttons');
    await page.click('#ki [data-tile="hosts"]'); ok(await names() === 'AHV-SYN-01,ESX-SYN-01', 'Hosts (all sources) → the hosts: ' + await names());
    await page.click('#ki [data-tile="vms"]'); ok(await names() === 'VM-SYN-OFF,VM-SYN-ON', 'VMs → the VMs');
    await page.click('#ki [data-tile="vms"]'); ok(await names() === 'VM-SYN-OFF' && await page.inputValue('#ip') === 'off', 'VMs again → powered off only');
    await page.click('#ki [data-tile="notinv"]'); ok(await names() === 'AHV-SYN-01,VM-SYN-OFF' && await page.inputValue('#iv') === 'out', 'In the inventory → the ones not in it: ' + await names());
    ok(/2 not in it/.test(await page.textContent('#ki')), 'the tile says how many are missing');
    await page.click('#kk [data-tile="hosts"]'); ok(await page.inputValue('#ik') === 'host', 'Hosts (last syncs) → hosts filter');
    await page.click('#kk [data-tile="failing"]');
    const pl = await page.textContent('#plats'); ok(/PRISM-SYN/.test(pl) && !/VC-SYN/.test(pl) && /failing platforms only/.test(pl), 'Failing → only the failing platform');
    await page.click('#pfall'); ok(/VC-SYN/.test(await page.textContent('#plats')), 'show all clears it');
    ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  } finally { await browser.close(); srv.close(); }
  console.log(bad ? 'FAILED ' + bad + '/' + n + ' checks' : 'OK ' + n + '/' + n + ' checks'); process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
