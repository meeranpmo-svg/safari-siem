// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Capacity Planning (capacity.html) with the REAL engines' answers (backend/itam capacity-plan.js, backend/siem ops/server-capacity.js)
// over SYNTHETIC figures: tiles, what runs out first across Hyper-V and servers, the N+1 verdict per Hyper-V group, servers labelled
// physical / Hyper-V VM / Azure VM and filtered, a server's history chart, findings, Azure Advisor right-sizing, CSV; the SIEM down ->
// the servers part says so and the rest still shows; Azure not connected says what to connect; POC mode with one ribbon; menu.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node capacity.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const DASH = path.resolve(__dirname, '../../ui'), ROOT = path.resolve(__dirname, '../..');
const CP = require(path.join(ROOT, 'backend/itam/engine/capacity-plan')), SC = require(path.join(ROOT, 'backend/siem/engine/ops/server-capacity'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const XSS = '<img src=x onerror=window.PWN=1>';
const GB = 1024, vm = (name, gb, dem) => ({ name, state: 'running', vcpus: 4, mem_assigned_mb: gb * GB, mem_demand_mb: dem * GB });
const host = (name, total, used, vms, md) => ({ name, cores: 32, mem_total_mb: total * GB, mem_free_mb: (total - used) * GB, vms, capacity: { memory: md, volumes: [] }, volumes: [] });
(async () => {
  const plan = { at: new Date().toISOString(), insights: ['Hyper-V hv-syn: synthetic insight'],
    hyperv: CP.hyperv({ hosts: [host('HV-SYN-01', 128, 100, [vm('APP-SYN-VM', 64, 60)], 12), host('HV-SYN-02', 128, 100, [vm('DB-SYN-VM', 64, 20)], null)] }),
    azure: CP.azure({ vms: [{ name: 'az-syn-01', size: 'Standard_D8s_v5', power: 'running', advisor: [{ category: 'Cost', target_sku: 'Standard_D4s_v5', savings: 99, currency: 'USD', problem: 'Right-size (synthetic)' }] }, { name: 'az-syn-02', size: 'Standard_B2s', power: 'stopped', advisor: [] }], totals: { advisor_savings: 99, currency: 'USD' } }) };
  const day = (k) => new Date(Date.now() - (19 - k) * 864e5).toISOString().slice(0, 10), rows = [];
  for (let k = 0; k < 20; k++) { rows.push({ host: 'PHY-SYN-01', d: day(k), cpu95: 30, mem95: 50, disks: 'D:|1000|' + (400 - k * 15) }); rows.push({ host: 'APP-SYN-VM', d: day(k), cpu95: 90, mem95: 90, disks: 'C:|100|50' }); rows.push({ host: 'az-syn-01', d: day(k), cpu95: 5, mem95: 20, disks: 'C:|128|100' }); rows.push({ host: XSS, d: day(k), cpu95: 10, mem95: 10, disks: 'C:|10|5' }); }
  const S = SC.analyse(rows, { days: 30 });
  let SIEM = true, AZ = true;
  const srv = http.createServer((req, res) => { const u = new URL(req.url, 'http://x'), json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u.pathname === '/dashboards/whoami.json') return json(200, { user: 'vera.syn', role: 'viewer' });
    if (u.pathname === '/api/itam/capacity-plan') return json(200, AZ ? plan : Object.assign({}, plan, { azure: CP.azure(null) }));
    if (u.pathname === '/api/soc/capacity/servers') return SIEM ? json(200, S) : json(502, { error: 'the SIEM is down (synthetic)' });
    if (u.pathname.startsWith('/api/')) return json(500, { error: 'down (synthetic)' });
    fs.readFile(path.join(DASH, u.pathname.replace(/^\/dashboards\//, '/')), (err, d) => { if (err) { res.writeHead(404); return res.end(); } res.writeHead(200, { 'Content-Type': u.pathname.endsWith('.js') ? 'application/javascript' : u.pathname.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); }); });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port + '/dashboards/capacity.html';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright'); const browser = await chromium.launch(), errs = [];
  const open = async (q) => { const ctx = await browser.newContext({ viewport: { width: 1500, height: 1100 }, acceptDownloads: true }); const p = await ctx.newPage(); p.on('pageerror', (x) => errs.push(x.message)); await p.goto(base + (q || '?standalone=1')); await p.waitForSelector('#main:not([hidden])', { timeout: 15000 }); return p; };
  try {
    let p = await open();
    const kp = (await p.$eval('#kp', (x) => x.innerText)).replace(/\s+/g, ' ');
    ok(/Hyper-V groups 1/.test(kp) && /1 without N\+1/.test(kp) && /Servers measured 4/.test(kp) && /Azure VMs 2/.test(kp), 'tiles: ' + kp);
    ok(/PHY-SYN-01/.test(await p.textContent('#first')) && /Hyper-V hv-syn/.test(await p.textContent('#first')), 'what runs out first, across sources');
    ok(/no N\+1/.test(await p.textContent('#hv')) && /GB short/.test(await p.textContent('#hv')), 'the N+1 verdict');
    await p.selectOption('#fk', 'Azure VM'); ok((await p.$$('#sv tbody tr')).length === 1 && /az-syn-01/.test(await p.textContent('#sv')), 'an Azure VM recognised');
    await p.selectOption('#fk', 'Hyper-V VM'); ok(/APP-SYN-VM/.test(await p.textContent('#sv')), 'a Hyper-V VM recognised'); await p.selectOption('#fk', '');
    await p.selectOption('#ff', 'undersized'); ok((await p.$$('#sv tbody tr')).length === 1, 'filter by fit'); await p.selectOption('#ff', '');
    ok((await p.$$('canvas')).length >= 3 && /Standard_D4s_v5/.test(await p.textContent('#az')) && /Stopped but billed/.test(await p.textContent('#az')), 'charts and Azure Advisor');
    ok(/disk-|reaches 95 %/.test(await p.textContent('#fl')), 'findings');
    const [dl] = await Promise.all([p.waitForEvent('download'), p.click('#csv')]); const csv = fs.readFileSync(await dl.path(), 'utf8'); ok(/^server,kind/.test(csv) && /PHY-SYN-01/.test(csv), 'CSV of the servers');
    ok(!(await p.evaluate(() => window.PWN)), 'hostile text stays text'); await p.close();
    SIEM = false; AZ = false; p = await open(); ok(/SIEM is down/.test(await p.textContent('#sv')) && /no N\+1/.test(await p.textContent('#hv')) && /Azure is not connected/.test(await p.textContent('#az')), 'SIEM down and Azure not connected said; the rest shows'); await p.close();
    p = await open('?poc=1'); await p.waitForTimeout(600); ok((await p.$$('.zyb-poc-r.br')).length === 1 && /hqpsuperm/.test(await p.textContent('#hv')) && /HQ-BACKUP-PHY-POC/.test(await p.textContent('#sv')), 'POC: illustrative estate, one ribbon');
    if (process.env.SHOT) { await p.waitForTimeout(800); await p.screenshot({ path: process.env.SHOT, fullPage: true }); }
    await p.close();
    ok(fs.readFileSync(path.join(DASH, 'vendor/zyb-nav.js'), 'utf8').includes('"h": "capacity.html"'), 'menu entry');
    ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  } finally { await browser.close(); srv.close(); }
  console.log((bad ? 'FAILED ' : 'ok ') + (n - bad) + '/' + n + ' capacity checks'); process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
