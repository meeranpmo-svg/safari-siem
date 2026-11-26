// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// the vCenter / Nutanix view: an organisation with VMware on (Safari's brand runs Hyper-V only - virtualization-hyperv.test.js)
// virtualization.html, hosts without an address: a Discovery scope whose vCenter step did not run says why (blocked: disabled
// globally); a filled address says where it came from (asset / DNS); "Find missing host IPs" (operator) calls the engine and
// redraws the list with the addresses it found; a viewer has no button; an admin adds a Proxmox VE connection (API token). Stubbed IT Asset Management API, SYNTHETIC data.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node virtualization-ips.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const DASH = path.resolve(__dirname, '../../ui');
let n = 0, bad = 0, ROLE = 'operator', fills = 0, saved = null;
const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const host = (name, ip, ip_from) => ({ kind: 'host', name, ip, ip_from, os: 'VMware ESXi', power_state: 'connected', source: 'vcenter', platform: 'Discovery scope: 6388', asset_id: 'a-' + name });
const before = [host('hpvm1.corp-hq.test', '192.168.63.21', 'asset'), host('hpvm2.corp-hq.test', null, null), host('192.168.11.63', '192.168.11.63', 'vcenter')];
const after = [before[0], host('hpvm2.corp-hq.test', '192.168.63.22', 'dns'), before[2]];
const inv = (items) => ({ items, total: items.length, summary: { hosts: items.length, vms: 0, by_source: { vcenter: items.length } },
  scopes: [{ id: 's1', label: '6388', site: 'Riyadh HQ', methods: ['vcenter'], last_run: '2026-10-26T15:01:00Z', results: [{ method: 'vcenter', ok: null, note: 'blocked: disabled globally' }] }] });
(async () => {
  const srv = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://x'), json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u.pathname === '/dashboards/whoami.json') return json(200, { user: 'omar.syn', role: ROLE });
    if (u.pathname === '/api/itam/virt' && req.method === 'GET') return json(200, { platforms: [], kinds: {} });
    if (u.pathname === '/api/itam/virt/inventory') return json(200, inv(fills ? after : before));
    if (u.pathname === '/api/itam/virt/hosts/fill-ips' && req.method === 'POST') { fills++; return json(200, Object.assign({ fill: { checked: 1, filled: 1, from: { dns: 1 } } }, inv(after))); }
    if (u.pathname === '/api/itam/virt' && req.method === 'POST') { let b = ''; req.on('data', (c) => { b += c; }); req.on('end', () => { saved = JSON.parse(b || '{}'); json(200, { platform: { id: 'vp_new', kind: saved.kind, label: saved.label } }); }); return; }
    if (u.pathname.startsWith('/api/')) return json(404, { error: 'not found' });
    const f = path.join(DASH, u.pathname.replace(/^\/dashboards\//, '/')); if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (err, d) => { if (err) { res.writeHead(404); res.end(); return; } res.writeHead(200, { 'Content-Type': u.pathname.endsWith('.js') ? 'application/javascript' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  const url = 'http://127.0.0.1:' + srv.address().port + '/dashboards/virtualization.html';
  try {
    let page = await browser.newPage(); page.on('pageerror', (x) => errs.push(x.message)); await page.addInitScript(() => { Object.defineProperty(window, 'ZYB_ORG', { configurable: true, set(v) { this._o = Object.assign({}, v, { pages_off: [] }); }, get() { return this._o; } }); }); 
    await page.goto(url); await page.waitForFunction(() => /of 3/.test(document.getElementById('ic').textContent), null, { timeout: 15000 });
    ok(/vCenter: not run/.test(await page.textContent('#dscl')) && /blocked: disabled globally/.test(await page.textContent('#dscl')), 'the scope says why vCenter did not run');
    const t = await page.$eval('#inv', (x) => x.innerText.replace(/\s+/g, ' '));
    ok(/192\.168\.63\.21 from asset/.test(t), 'a filled address says where it came from: ' + t.slice(0, 200));
    ok(!/192\.168\.11\.63 from/.test(t), 'an address vCenter reported needs no note');
    ok(await page.isVisible('#fillips'), 'operator sees Find missing host IPs');
    await page.click('#fillips'); await page.waitForFunction(() => /192\.168\.63\.22/.test(document.getElementById('inv').innerText));
    ok(fills === 1, 'the engine was asked once'); ok(/from dns/i.test(await page.$eval('#inv', (x) => x.innerText)), 'the found address shows it came from DNS');
    ok(/1 of 1 host addresses filled/.test(await page.evaluate(() => document.body.innerText)), 'toast says how many were filled');
    ROLE = 'viewer'; fills = 0; await page.close(); page = await browser.newPage(); page.on('pageerror', (x) => errs.push(x.message)); await page.addInitScript(() => { Object.defineProperty(window, 'ZYB_ORG', { configurable: true, set(v) { this._o = Object.assign({}, v, { pages_off: [] }); }, get() { return this._o; } }); }); 
    await page.goto(url); await page.waitForFunction(() => /of 3/.test(document.getElementById('ic').textContent), null, { timeout: 15000 });
    ok(!(await page.isVisible('#fillips')), 'a viewer has no button');
    ROLE = 'admin'; await page.close(); page = await browser.newPage(); page.on('pageerror', (x) => errs.push(x.message)); await page.addInitScript(() => { Object.defineProperty(window, 'ZYB_ORG', { configurable: true, set(v) { this._o = Object.assign({}, v, { pages_off: [] }); }, get() { return this._o; } }); }); 
    await page.goto(url); await page.waitForFunction(() => /of 3/.test(document.getElementById('ic').textContent), null, { timeout: 15000 });
    await page.click('#add'); await page.waitForSelector('#f-k');
    await page.selectOption('#f-k', 'proxmox'); ok(/PVEAuditor/.test(await page.textContent('#f-hint')), 'the form says which Proxmox role the token needs');
    await page.fill('#f-l', 'PVE-SYN'); await page.fill('#f-u', 'https://pve.syn.test:8006'); await page.fill('#f-n', 'mon@pve!ro'); await page.fill('#f-p', 'synthetic-token');
    await page.click('#f-go'); for (let i = 0; i < 50 && !saved; i++) await page.waitForTimeout(100);
    ok(saved && saved.kind === 'proxmox' && saved.username === 'mon@pve!ro' && saved.base_url === 'https://pve.syn.test:8006', 'Proxmox connection sent: ' + JSON.stringify(saved && { kind: saved.kind, base_url: saved.base_url }));
    ok(!errs.length, 'page errors: ' + errs.join(' | '));
  } finally { await browser.close(); srv.close(); }
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks'); process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
