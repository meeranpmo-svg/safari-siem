// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for the "Infrastructure health by device type" panel on server-availability.html (GET /api/soc/netops/health/types,
// engine/netops/synthetic-routes.js healthByType): one row per type with total / up / down / unknown / not monitored and the names of
// what is down; a type with none in the inventory shows 0, not an invented number; the engine without the route says so; the rest
// of the page still works; values escaped. API answers are SYNTHETIC.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node server-availability-health.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const DASH = path.resolve(__dirname, '../../ui');
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const AV = { summary: { total: 1, online: 1, offline: 0, unknown: 0, reboot_overdue: 0, spof: 0, no_dr: 0, degraded: 0, longest_offline_s: 0 },
  items: [{ id: 'h1', name: 'syn-app-01', ip: '10.0.0.1', site: 'Riyadh', status: 'online', duration_s: 3600, flags: [], availability: { d1: 100, d7: 99.9, d30: 99.8 }, group: null }], groups: [], settings: { reboot_max_days: 30, subnets: [] }, scanner: { interval_s: 60 } };
const TYPES = { types: [{ type: 'servers', label: 'Servers', total: 40, up: 38, down: 1, unknown: 1, unmonitored: 0, down_items: [{ name: 'syn-erp-02', ip: '10.0.0.9' }] },
  { type: 'domain_controllers', label: 'Domain controllers', total: 4, up: 4, down: 0, unknown: 0, unmonitored: 0, down_items: [] },
  { type: 'wlcs', label: 'Wireless LAN controllers', total: 0, up: 0, down: 0, unknown: 0, unmonitored: 0, down_items: [] },
  { type: 'fc_switches', label: 'FC switches', total: 2, up: 1, down: 1, unknown: 0, unmonitored: 0, down_items: [{ name: '<i>SYN-FC-B</i>', ip: '10.0.7.2', why: 'snmp: timeout' }] }], note: 'SYNTHETIC note' };
let MODE = 'ok';
(async () => {
  const srv = http.createServer((q, r) => {
    const u = q.url.split('?')[0], j = (c, o) => { r.writeHead(c, { 'Content-Type': 'application/json' }); r.end(JSON.stringify(o)); };
    if (u === '/dashboards/whoami.json') return j(200, { user: 'syn.viewer', role: 'viewer' });
    if (u === '/api/soc/netops/avail') return j(200, AV);
    if (u === '/api/soc/netops/health/types') return MODE === 'ok' ? j(200, TYPES) : MODE === 'missing' ? j(404, { error: 'not found' }) : j(503, { error: 'network operations are not running in the SIEM engine' });
    if (u.startsWith('/api/')) return j(404, { error: 'not in this test' });
    const f = path.join(DASH, u.replace(/^\/dashboards\//, '/')); if (!f.startsWith(DASH)) { r.writeHead(403); return r.end(); }
    fs.readFile(f, (e, d) => { if (e) { r.writeHead(404); return r.end(); } r.writeHead(200, { 'Content-Type': u.endsWith('.js') ? 'application/javascript' : u.endsWith('.css') ? 'text/css' : 'text/html' }); r.end(d); });
  });
  await new Promise((res) => srv.listen(0, '127.0.0.1', res));
  const base = 'http://127.0.0.1:' + srv.address().port + '/dashboards/';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  const open = async () => { const p = await browser.newPage({ viewport: { width: 1500, height: 950 } }); p.on('pageerror', (e) => errs.push(e.message)); p.on('dialog', (d) => { errs.push('dialog ' + d.message()); d.dismiss(); }); await p.goto(base + 'server-availability.html?standalone=1'); return p; };
  const txt = (p, sel) => p.evaluate((s) => (document.querySelector(s) || {}).textContent || '', sel);
  try {
    let p = await open(); await p.waitForSelector('#hbt-b tr[data-type]');
    const rows = await p.$$eval('#hbt-b tr[data-type]', (l) => l.map((r) => [...r.cells].slice(0, 6).map((c) => c.textContent.trim()).join('|')));
    ok(JSON.stringify(rows) === JSON.stringify(['Servers|40|38|1|1|0', 'Domain controllers|4|4|0|0|0', 'Wireless LAN controllers|0|0|0|0|0', 'FC switches|2|1|1|0|0']), 'one row per type: ' + JSON.stringify(rows));
    const fc = await txt(p, '#hbt-b tr[data-type="fc_switches"]');
    ok(/<i>SYN-FC-B<\/i>/.test(fc) && !(await p.$('#hbt-b i')), 'what is down, named and escaped');
    ok(/syn-erp-02/.test(await txt(p, '#hbt-b tr[data-type="servers"]')), 'down server named');
    ok(await p.$eval('#hbt-b tr[data-type="fc_switches"] td:last-child .pill.bad', (e) => /snmp: timeout/.test(e.title)), 'why it is down on hover');
    ok(/SYNTHETIC note/.test(await txt(p, '#hbt-b')), 'where the numbers come from');
    await p.waitForSelector('#srv tr[data-k]'); ok(/syn-app-01/.test(await txt(p, '#srv')), 'the server list still works');
    await p.close();
    MODE = 'missing'; p = await open(); await p.waitForFunction(() => /not installed in the SIEM engine yet/.test((document.getElementById('hbt-b') || {}).textContent || ''));
    ok(!(await p.$('#hbt-b table')), 'engine without the route: says so, no table'); await p.close();
    MODE = 'down'; p = await open(); await p.waitForFunction(() => /not available from the SIEM engine/.test((document.getElementById('hbt-b') || {}).textContent || ''));
    ok(/network operations are not running/.test(await txt(p, '#hbt-b')), 'engine error: shows its reason'); await p.close();
    ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  } finally { await browser.close(); srv.close(); }
  console.log((bad ? 'FAILED ' + bad + ' of ' : 'OK ') + n + ' checks');
  process.exit(bad ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });
