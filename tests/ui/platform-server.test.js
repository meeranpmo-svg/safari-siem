// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Platform Server (platform.html?tab=sto, menu "Platform Server"): the server the platform runs on. Stubbed health.json with
// SYNTHETIC figures: a disk at ~1 s per write shows a red Disk speed tile and a red latency in the table, the critical issue with
// the Hyper-V fix is listed; an older health.json without disk speed says to update instead of inventing a figure; the menu
// entry is there; a hostile disk name stays text.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node platform-server.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const DASH = path.resolve(__dirname, '../../ui');
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const base = () => ({ time: Math.floor(Date.now() / 1000), host: 'srv-synthetic', os: 'Ubuntu (synthetic)', kernel: '6.0', uptime: 3600, status: 'critical',
  issues: [{ sev: 'crit', area: 'storage', key: 'io-write-sda', text: 'Disk sda is very slow: 1000 ms per write (healthy is under 20 ms)', fix: 'On the Hyper-V host: remove old checkpoints (Get-VMSnapshot / Remove-VMSnapshot)' }],
  hardware: { virtual: true, virt: 'microsoft', disks: [], temps: [] }, system: { cpu_pct: 12, cores: 4, load: [1, 1, 1], mem: { pct: 40, total: 8e9, swap_pct: 0 }, ntp: true, failed_units: [] },
  storage: [{ dev: '/dev/sda2', mount: '/', total: 1e11, used: 5e10, avail: 5e10, pct: 50 }], services: [], network: [], tls: null, backup: null });
let H = base();
H.diskio = { window_s: 60, iowait_pct: 71, disks: [{ dev: 'sda', write_ms: 1000, read_ms: 5, write_iops: 10, read_iops: 1, write_mbs: 1, read_mbs: 0, busy_pct: 95, queued: 3, ops: 660 },
  { dev: '<img src=x onerror=window.PWN=1>', write_ms: 2, read_ms: null, write_iops: 30, read_iops: 0, write_mbs: 0.2, read_mbs: 0, busy_pct: 1, queued: 0, ops: 30 }] };
(async () => {
  const srv = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://x');
    if (u.pathname === '/dashboards/whoami.json') { res.writeHead(200, { 'Content-Type': 'application/json' }); return res.end('{"user":"viewer.syn","role":"viewer"}'); }
    if (u.pathname === '/dashboards/health.json') { res.writeHead(200, { 'Content-Type': 'application/json' }); return res.end(JSON.stringify(H)); }
    if (u.pathname.startsWith('/api/')) { res.writeHead(404, { 'Content-Type': 'application/json' }); return res.end('{"error":"not in this test"}'); }
    fs.readFile(path.join(DASH, u.pathname.replace(/^\/dashboards\//, '/')), (err, d) => { if (err) { res.writeHead(404); return res.end(); } res.writeHead(200, { 'Content-Type': u.pathname.endsWith('.js') ? 'application/javascript' : u.pathname.endsWith('.css') ? 'text/css' : u.pathname.endsWith('.json') ? 'application/json' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const url = 'http://127.0.0.1:' + srv.address().port + '/dashboards/platform.html?standalone=1&tab=sto';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright'); const browser = await chromium.launch(), errs = [];
  try {
    const p = await browser.newPage({ viewport: { width: 1400, height: 1000 } }); p.on('pageerror', (x) => errs.push(x.message));
    await p.goto(url); await p.waitForSelector('#dio table', { timeout: 15000 });
    ok(!(await p.$eval('#tab-sto', (e) => e.hidden)), '?tab=sto opens on disk speed & space');
    const tile = await p.$$eval('#kk .t', (x) => x.map((t) => ({ l: t.querySelector('.l').textContent, v: t.querySelector('.v').textContent, s: t.querySelector('.s').textContent, c: t.className })).find((t) => t.l === 'Disk speed'));
    ok(tile && tile.v === '1000 ms' && /bad/.test(tile.c) && /sda · I\/O wait 71%/.test(tile.s), 'Disk speed tile red with the slowest disk: ' + JSON.stringify(tile));
    const rows = await p.$$eval('#dio tbody tr', (x) => x.map((r) => r.textContent));
    ok(rows.length === 2 && /1000 ms/.test(rows[0]) && /5 ms/.test(rows[0]) && /95%/.test(rows[0]), 'table row for sda: ' + rows[0]);
    ok(await p.$eval('#dio tbody tr .pill.bad', (e) => e.textContent === '1000 ms'), 'the slow write latency is marked bad');
    ok(/no requests/.test(rows[1]) && /<img src=x/.test(rows[1]) && !(await p.evaluate(() => window.PWN)), 'hostile disk name stays text');
    ok(/I\/O wait 71%/.test(await p.textContent('#ioc')), 'the window and iowait are stated');
    await p.click('button[data-tab="iss"]');
    ok(/1000 ms per write/.test(await p.textContent('#iss')) && /checkpoints/.test(await p.textContent('#iss')), 'the critical issue lists the Hyper-V fix');
    // an older health check (no diskio) - say what to do, no figure invented
    H = base(); delete H.diskio;
    const q = await browser.newPage(); q.on('pageerror', (x) => errs.push(x.message)); await q.goto(url); await q.waitForSelector('#dio .empty', { timeout: 15000 });
    ok(/run the platform update/.test(await q.textContent('#dio')), 'no disk speed yet: says to update');
    const t2 = await q.$$eval('#kk .t', (x) => x.map((t) => t.textContent).find((t) => /Disk speed/.test(t)));
    ok(/–/.test(t2) && !/ms/.test(t2), 'tile shows no number: ' + t2);
    // the menu entry
    const nav = fs.readFileSync(path.join(DASH, 'vendor/zyb-nav.js'), 'utf8');
    ok(/"h": "platform\.html\?tab=sto", "s": "Platform Server"/.test(nav), 'menu entry Platform Server');
    ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  } finally { await browser.close(); srv.close(); }
  console.log((bad ? 'FAILED ' : 'ok ') + (n - bad) + '/' + n + ' platform-server checks'); process.exit(bad ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });
