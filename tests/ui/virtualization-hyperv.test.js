// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Virtualization Platforms for an organisation that runs Hyper-V only (Safari: VMware and Nutanix pages switched off in the brand):
// the platforms card shows the Hyper-V hosts that report (status, CPU, memory, VMs, findings) with a link to manage them, the
// vCenter / Nutanix card and its Fetch button are hidden and /virt is not asked; no host yet says how to add one (nothing invented);
// hostile host names stay text. With VMware on (brand changed in the page) the vCenter card is back. Stubbed API, SYNTHETIC data.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node virtualization-hyperv.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const DASH = path.resolve(__dirname, '../../ui');
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const HV = { hosts: [
  { name: 'HV-SYN-01', at: new Date().toISOString(), stale: false, cores: 32, cpu_pct: 41, mem_total_mb: 262144, mem_free_mb: 131072, findings: [{ severity: 'high' }],
    vms: [{ name: 'vm-a', state: 'running' }, { name: 'vm-b', state: 'off' }] },
  { name: '<img src=x onerror=window.PWN=1>', at: '2026-11-20T10:00:00Z', stale: true, cores: 8, cpu_pct: null, mem_total_mb: null, mem_free_mb: null, findings: [], vms: [] }],
  kpis: { hosts: 2, vms: 2, running: 1, high: 1, stale_hosts: 1 }, note: '' };
let hv = HV; const asked = [];
(async () => {
  const srv = http.createServer((q, r) => { const u = decodeURIComponent(q.url.split('?')[0]), j = (c, o) => { r.writeHead(c, { 'Content-Type': 'application/json' }); r.end(JSON.stringify(o)); };
    if (u.endsWith('whoami.json')) return j(200, { user: 'op.syn', role: 'operator' });
    if (u.startsWith('/api/')) { asked.push(u); if (u === '/api/itam/hyperv') return j(200, hv); if (u === '/api/itam/virt/inventory') return j(200, { items: [], total: 0, summary: {} }); if (u === '/api/itam/virt') return j(200, { platforms: [] }); return j(404, {}); }
    fs.readFile(path.join(DASH, u.replace(/^\/dashboards\//, '/')), (e, d) => { if (e) { r.writeHead(404); return r.end(); } r.writeHead(200, { 'Content-Type': u.endsWith('.js') ? 'application/javascript' : u.endsWith('.css') ? 'text/css' : 'text/html' }); r.end(d); }); });
  await new Promise((res) => srv.listen(0, '127.0.0.1', res));
  const url = 'http://127.0.0.1:' + srv.address().port + '/dashboards/virtualization.html?standalone=1';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright'); const browser = await chromium.launch(), errs = [];
  try {
    const p = await browser.newPage({ viewport: { width: 1400, height: 1000 } }); p.on('pageerror', (e) => errs.push(e.message));
    await p.goto(url); await p.waitForSelector('#hvl table', { timeout: 15000 });
    ok(await p.$eval('#vccard', (e) => e.hidden) && await p.$eval('#fetch', (e) => e.hidden) && !(await p.$eval('#hvcard', (e) => e.hidden)), 'Hyper-V card shown, vCenter / Nutanix card and Fetch hidden');
    ok(!asked.includes('/api/itam/virt') && asked.includes('/api/itam/hyperv'), 'reads the Hyper-V reports, not the vCenter list: ' + asked.join(','));
    const rows = await p.$$eval('#hvl tbody tr', (x) => x.map((r) => r.textContent));
    ok(rows.length === 2 && /HV-SYN-01/.test(rows[0]) && /reporting/.test(rows[0]) && /41%/.test(rows[0]) && /128 GB \/ 256 GB/.test(rows[0]) && /1 \/ 2 running/.test(rows[0]), 'host row: ' + rows[0]);
    ok(/not reporting/.test(rows[1]) && /<img src=x/.test(rows[1]) && !(await p.evaluate(() => window.PWN)), 'stale host flagged, hostile name stays text');
    const kk = await p.textContent('#kk'); ok(/Hyper-V hosts\s*2/.test(kk) && /1 not reporting/.test(kk) && /1 running/.test(kk), 'tiles: ' + kk);
    ok(await p.$eval('#hvcard a[href="hyperv.html"]', (a) => /Manage Hyper-V/.test(a.textContent)), 'link to manage Hyper-V');
    ok(!(await p.$eval('#fillips', (e) => e.hidden)), 'an operator can fill host addresses');
    hv = { hosts: [], kpis: { hosts: 0, vms: 0, running: 0, high: 0, stale_hosts: 0 }, note: 'No Hyper-V host has reported metrics yet.' };
    const q = await browser.newPage(); q.on('pageerror', (e) => errs.push(e.message)); await q.goto(url); await q.waitForSelector('#hvl .empty', { timeout: 15000 });
    ok(/No Hyper-V host has reported/.test(await q.textContent('#hvl')) && !!(await q.$('#hvl a[href="hyperv.html"]')), 'no host yet: says how to add one');
    // VMware on (another organisation): the vCenter card is back
    const r = await browser.newPage(); r.on('pageerror', (e) => errs.push(e.message));
    await r.addInitScript(() => { Object.defineProperty(window, 'ZYB_ORG', { configurable: true, set(v) { this._o = Object.assign({}, v, { pages_off: [] }); }, get() { return this._o; } }); });
    await r.goto(url); await r.waitForTimeout(1500);
    ok(!(await r.$eval('#vccard', (e) => e.hidden)) && await r.$eval('#hvcard', (e) => e.hidden), 'with VMware on, the vCenter / Nutanix card is shown');
    ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  } finally { await browser.close(); srv.close(); }
  console.log((bad ? 'FAILED ' : 'ok ') + (n - bad) + '/' + n + ' virtualization-hyperv checks'); process.exit(bad ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });
