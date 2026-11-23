// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test: every KPI tile on storage.html is clickable and shows what it counts - Arrays and Capacity open their tabs,
// Failed disks / Critical / High filter the problem list (click again or "show all" clears), Not in the inventory lists the
// arrays with no IT Asset Management record. Stubbed API, SYNTHETIC data; hostile text stays text.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node storage-tiles.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const DASH = path.resolve(__dirname, '../../ui');
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const plat = (id, label, kind) => ({ id, label, kind, base_url: 'https://10.8.0.' + id.slice(1), credentials_set: true, last_sync: { ok: true, at: Date.now() } });
const V = { settings: { pool_warn_pct: 80, pool_crit_pct: 90, volume_warn_pct: 85 }, kinds: { ontap: 'NetApp ONTAP', msa: 'HPE MSA' },
  summary: { arrays: 2, read: 2, used_pct: 72, used_bytes: 72e12, size_bytes: 100e12, failed_disks: 1, critical: 2, high: 1, not_in_inventory: 1, storage_assets: 1 },
  platforms: [plat('p1', 'NTAP-SYN', 'ontap'), plat('p2', 'MSA-SYN', 'msa')],
  arrays: [{ platform: plat('p1', 'NTAP-SYN', 'ontap'), at: Date.now(), worst: 'critical', system: { model: 'AFF', serial: 'SN-SYN-1', health: 'ok' }, capacity: { used_bytes: 1, size_bytes: 2, used_pct: 50 }, disks: { total: 24, spares: 2, failed: 1 }, asset: { name: 'NTAP-SYN' }, controllers: [], volumes_fullest: [{ name: 'vol_syn', size_bytes: 1e12, used_pct: 91 }] },
    { platform: plat('p2', 'MSA-SYN', 'msa'), at: Date.now(), worst: 'high', system: { model: 'MSA 2060', serial: 'SN-SYN-2<img src=x onerror=alert(1)>', health: 'ok' }, capacity: { used_bytes: 1, size_bytes: 2, used_pct: 60 }, disks: { total: 12, spares: 1, failed: 0 }, asset: null, controllers: [], volumes_fullest: [] }],
  findings: [{ severity: 'critical', kind: 'disk', title: 'NTAP-SYN: disk 1.0.3 failed', recommendation: 'Replace it', evidence: [] },
    { severity: 'critical', kind: 'capacity', title: 'NTAP-SYN: pool aggr1 93 % full', recommendation: 'Free space', evidence: [] },
    { severity: 'high', kind: 'controller', title: 'MSA-SYN: controller B degraded', recommendation: 'Check it', evidence: [] },
    { severity: 'medium', kind: 'volume', title: 'NTAP-SYN: 1 volume(s) above 85 %', recommendation: 'Grow', evidence: [] }] };
(async () => {
  const srv = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://x'), json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u.pathname === '/dashboards/whoami.json') return json(200, { user: 'omar.syn', role: 'operator' });
    if (u.pathname === '/api/itam/storage') return json(200, V);
    if (u.pathname.startsWith('/api/')) return json(404, { error: 'not found' });
    const f = path.join(DASH, u.pathname.replace(/^\/dashboards\//, '/')); if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (err, d) => { if (err) { res.writeHead(404); res.end(); return; } res.writeHead(200, { 'Content-Type': u.pathname.endsWith('.js') ? 'application/javascript' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  try {
    const page = await browser.newPage({ viewport: { width: 1400, height: 1000 } }); page.on('pageerror', (x) => errs.push(x.message)); page.on('dialog', (d) => { errs.push('dialog'); d.dismiss(); });
    await page.goto('http://127.0.0.1:' + srv.address().port + '/dashboards/storage.html'); await page.waitForSelector('#kk [data-act]');
    const probRows = () => page.evaluate(() => [...document.querySelectorAll('#prob tbody tr')].map((r) => r.innerText));
    const shown = (id) => page.evaluate((id) => !document.getElementById(id).hidden, id);
    ok((await page.$$('#kk button[data-act]')).length === 6, 'six clickable tiles');
    await page.click('#kk [data-act="tab:vol"]'); ok(await shown('tab-vol') && /vol_syn/.test(await page.textContent('#vol')), 'Capacity used → fullest volumes');
    await page.click('#kk [data-act="prob:disk"]'); let r = await probRows();
    ok(await shown('tab-prob') && r.length === 1 && /disk 1\.0\.3 failed/.test(r[0]) && /failed disks only/.test(await page.textContent('#pfl')), 'Failed disks → only the disk problem');
    await page.click('#kk [data-act="prob:critical"]'); r = await probRows(); ok(r.length === 2 && r.every((x) => /critical/i.test(x)), 'Critical → the 2 critical problems');
    ok(await page.getAttribute('#kk [data-act="prob:critical"]', 'aria-pressed') === 'true', 'the tile shows it is selected');
    await page.click('#kk [data-act="prob:critical"]'); ok((await probRows()).length === 4, 'clicking again clears the filter');
    await page.click('#kk [data-act="prob:high"]'); r = await probRows(); ok(r.length === 1 && /controller B/.test(r[0]), 'High → the high problem');
    await page.click('#pfall'); ok((await probRows()).length === 4, 'show all');
    await page.click('#kk [data-act="inv"]'); await page.waitForSelector('#zd:not([hidden])');
    const z = await page.evaluate(() => document.getElementById('zd').innerText);
    ok(/Not in the inventory \(1\)/.test(z) && /MSA-SYN/.test(z) && !/NTAP-SYN/.test(z) && !(await page.$('#zd img')), 'Not in the inventory → the MSA, as text');
    await page.keyboard.press('Escape');
    await page.click('#kk [data-act="tab:arr"]'); ok(await shown('tab-arr'), 'Arrays → the arrays');
    ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  } finally { await browser.close(); srv.close(); }
  console.log(bad ? 'FAILED ' + bad + '/' + n + ' checks' : 'OK ' + n + '/' + n + ' checks'); process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
