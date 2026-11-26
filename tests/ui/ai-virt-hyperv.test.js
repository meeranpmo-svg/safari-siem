// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// AI Virtualization Administrator for a Hyper-V-only organisation (Safari brand: VMware and Nutanix switched off): the vCenter /
// Nutanix cards are hidden and /virt/admin is not read; the Hyper-V estate shows tiles, charts (findings ring, host load, ML
// capacity forecast, 24 h CPU), the learned findings ranked with "Ask AI", hosts, VMs and the four-eyes VM actions; a suggestion
// or "Ask AI" fills the question box; hostile names stay text; no host yet says how to add one; with VMware on, the vCenter view
// is back. Stubbed API, SYNTHETIC data. Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node ai-virt-hyperv.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const DASH = path.resolve(__dirname, '../../ui');
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const now = Date.now(), tr = (base) => Array.from({ length: 8 }, (_, i) => ({ t: new Date(now - (7 - i) * 900000).toISOString(), cpu: base + i }));
const FULL = { hosts: [
  { name: 'HV-SYN-01', at: new Date().toISOString(), stale: false, cores: 32, cpu_pct: 62, mem_total_mb: 262144, mem_free_mb: 26214, vcpu_ratio: 2.5, disk: { latency_ms: 64 }, capacity: { memory: 12, volumes: { 'C:': 40 } }, trend: tr(50),
    vms: [{ name: 'VM-SYN-APP', state: 'running', vcpus: 8, cpu_pct: 70, mem_assigned_mb: 32768, mem_demand_mb: 30000, checkpoints: 4, heartbeat: 'OK' }, { name: '<img src=x onerror=window.PWN=1>', state: 'off', vcpus: 2, mem_assigned_mb: 4096, checkpoints: 0 }],
    findings: [{ severity: 'high', code: 'disk-latency', host: 'HV-SYN-01', target: 'HV-SYN-01', title: 'Disk latency 64 ms', fix: 'Move the VHDX to faster storage' }] },
  { name: 'HV-SYN-02', at: '2026-11-20T10:00:00Z', stale: true, cores: 16, cpu_pct: 20, mem_total_mb: 131072, mem_free_mb: 65536, vcpu_ratio: 1.2, disk: null, capacity: {}, trend: tr(15), vms: [], findings: [] }],
  findings: [{ severity: 'high', code: 'disk-latency', host: 'HV-SYN-01', target: 'HV-SYN-01', title: 'Disk latency 64 ms', fix: 'Move the VHDX to faster storage' },
    { severity: 'medium', code: 'checkpoint', host: 'HV-SYN-01', target: 'VM-SYN-APP', title: '4 checkpoints on VM-SYN-APP', fix: 'Remove-VMSnapshot after checking' }],
  actions: [{ id: 'HVAC-00001', host: 'HV-SYN-01', vm: 'VM-SYN-APP', action: 'checkpoint-remove', status: 'proposed', proposed_by: 'op.syn' }],
  kpis: { hosts: 2, vms: 2, running: 1, high: 1, stale_hosts: 1 }, note: '' };
let HV = FULL; const asked = [];
(async () => {
  const srv = http.createServer((q, r) => { const u = decodeURIComponent(q.url.split('?')[0]), j = (c, o) => { r.writeHead(c, { 'Content-Type': 'application/json' }); r.end(JSON.stringify(o)); };
    if (u.endsWith('whoami.json')) return j(200, { user: 'op.syn', role: 'operator' });
    if (u.startsWith('/api/')) { asked.push(u); if (u === '/api/itam/hyperv') return j(200, HV); if (u === '/api/itam/virt/ai/status') return j(200, { enabled: true, model: 'synthetic-model' });
      if (u === '/api/itam/virt/admin') return j(200, { platforms: [], totals: {}, hosts: [], clusters: [], datastores: [], changes: [], settings: {}, findings: 0, by_kind: {} }); return j(404, { error: 'not in this test' }); }
    fs.readFile(path.join(DASH, u.replace(/^\/dashboards\//, '/')), (e, d) => { if (e) { r.writeHead(404); return r.end(); } r.writeHead(200, { 'Content-Type': u.endsWith('.js') ? 'application/javascript' : u.endsWith('.css') ? 'text/css' : 'text/html' }); r.end(d); }); });
  await new Promise((res) => srv.listen(0, '127.0.0.1', res));
  const url = 'http://127.0.0.1:' + srv.address().port + '/dashboards/ai-virt-admin.html';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright'); const browser = await chromium.launch(), errs = [];
  try {
    const p = await browser.newPage({ viewport: { width: 1400, height: 1000 } }); p.on('pageerror', (e) => errs.push(e.message));
    await p.goto(url); await p.waitForSelector('#hvh table', { timeout: 15000 });
    ok(!(await p.$eval('#hvwrap', (e) => e.hidden)) && (await p.$$eval('.card.vc', (x) => x.every((c) => c.hidden))), 'Hyper-V estate shown, the vCenter / Nutanix cards hidden');
    ok(!asked.includes('/api/itam/virt/admin'), 'the vCenter collection is not read: ' + asked.join(','));
    ok(/Microsoft Hyper-V/.test(await p.textContent('#sub')) && !/vCenter|Prism/.test(await p.textContent('#ban')) && !/vCenter|Prism/.test(await p.textContent('#ainote')), 'subtitle and banner speak Hyper-V');
    const kk = await p.textContent('#kk');
    ok(/Hyper-V hosts\s*2/.test(kk) && /1 not reporting/.test(kk) && /VMs running\s*1 \/ 2/.test(kk) && /First to fill\s*12 days/.test(kk) && /Actions waiting\s*1/.test(kk), 'tiles: ' + kk.replace(/\s+/g, ' '));
    const charts = await p.$$eval('#hvring,#hvload,#hvcap,#hvtrend', (x) => x.map((c) => c.tagName + ':' + (c.getAttribute('aria-label') || '').slice(0, 40)));
    ok(charts.length === 4 && charts.every((c) => /^CANVAS:.+/.test(c)), 'four charts drawn with a readable summary: ' + charts.join(' | '));
    const fl = await p.$$eval('#hvf li', (x) => x.map((l) => l.textContent));
    ok(fl.length === 2 && /^high/.test(fl[0]) && /Disk latency 64 ms/.test(fl[0]) && /medium/.test(fl[1]), 'learned findings ranked high first: ' + fl.join(' | '));
    const rows = await p.$$eval('#hvh tbody tr', (x) => x.map((r) => r.textContent));
    ok(/HV-SYN-01/.test(rows[0]) && /reporting/.test(rows[0]) && /64 ms/.test(rows[0]) && /12 days/.test(rows[0]) && /2.5 : 1/.test(rows[0]) && /not reporting/.test(rows[1]), 'host rows: ' + rows.join(' | '));
    const vms = await p.$$eval('#hvv tbody tr', (x) => x.map((r) => r.textContent));
    ok(/VM-SYN-APP/.test(vms[0]) && /29.3 GB \/ 32 GB/.test(vms[0]) && /<img src=x/.test(vms[1]) && !(await p.evaluate(() => window.PWN)), 'VMs largest demand first; hostile name stays text');
    await p.waitForFunction(() => /administrator/.test((document.querySelector('[data-zyb-duty]') || {}).textContent || ''), null, { timeout: 8000 }).catch(() => {});
    const duty = await p.$eval('[data-zyb-duty]', (e) => e.textContent); ok(/Hyper-V reports/.test(duty) && !/vCenter and Prism/.test(duty), 'the duty desk describes the Hyper-V administrator: ' + duty.slice(0, 160));
    ok(/checkpoint-remove/.test(await p.textContent('#hva')) && /proposed/.test(await p.textContent('#hva')), 'the waiting VM action is listed');
    await p.click('[data-sugg]'); ok(/runs out of memory first/.test(await p.$eval('#aiq', (e) => e.value)), 'a suggestion fills the question');
    await p.click('[data-askf="0"]'); ok(/Investigate this Hyper-V finding on HV-SYN-01: Disk latency 64 ms/.test(await p.$eval('#aiq', (e) => e.value)), 'Ask AI on a finding fills the question');
    // no host yet
    HV = { hosts: [], findings: [], actions: [], kpis: { hosts: 0, vms: 0, running: 0, high: 0, stale_hosts: 0 }, note: 'No Hyper-V host has reported metrics yet.' };
    const q = await browser.newPage(); q.on('pageerror', (e) => errs.push(e.message)); await q.goto(url); await q.waitForSelector('#hvh .empty', { timeout: 15000 });
    ok(/No Hyper-V host has reported/.test(await q.textContent('#hvh')) && !!(await q.$('#hvh a[href="hyperv.html?add=1"]')), 'no host yet: says how to add one');
    // VMware on: the vCenter view
    asked.length = 0; const r = await browser.newPage(); r.on('pageerror', (e) => errs.push(e.message));
    await r.addInitScript(() => { Object.defineProperty(window, 'ZYB_ORG', { configurable: true, set(v) { this._o = Object.assign({}, v, { pages_off: [] }); }, get() { return this._o; } }); });
    await r.goto(url); await r.waitForTimeout(1500);
    ok(await r.$eval('#hvwrap', (e) => e.hidden) && asked.includes('/api/itam/virt/admin'), 'with VMware on, the vCenter view is used');
    ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  } finally { await browser.close(); srv.close(); }
  console.log((bad ? 'FAILED ' : 'ok ') + (n - bad) + '/' + n + ' ai-virt-hyperv checks'); process.exit(bad ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });
