// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Network Estate & Licensing page (network-estate.html) against the REAL engine (engine/netops/estate.js) over a SYNTHETIC
// FortiManager fleet and switch poller: tiles, six charts, what the AI noticed, next steps, risk with reasons, licences with
// filter chips and the devices without support, FortiGates and switches with Manage links into the four-eyes workflows; hostile
// names stay text; nothing connected says where to connect; menu entry and installer.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node network-estate.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const DASH = path.resolve(__dirname, '../../ui'), E = require(path.resolve(__dirname, '../../backend/siem/engine/netops/estate'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const XSS = '<img src=x onerror=window.PWN=1>', T0 = Date.now(), day = (d) => new Date(T0 + d * 86400000).toISOString().slice(0, 10);
const FW = (name, o) => Object.assign({ name, serial: 'FG' + name.length, site: 'Riyadh', model: 'FortiGate-60F', firmware: '7.2.8', health: 'ok', conn: 'up', conf: 'in-sync', ha_mode: 'standalone', ha_members: [], links: [], findings: [], z: {}, res: { cpu: 20, mem: 40 },
  licences: [{ name: 'forticare', expires: day(200) }, { name: 'antivirus', expires: day(45) }] }, o || {});
let CONNECTED = true;
const deps = () => ({ now: () => T0, fmgApi: CONNECTED ? { status: () => ({ configured: true }), fleet: () => ({ status: {}, kpis: { tunnels: { up: 40, down: 2 } }, changes_open: 1, models: [{ model: 'FortiGate-60F', devices: 3, target: '7.2.8', versions: { '7.2.8': 2, '7.0.12': 1 } }],
  devices: [FW('FW-SYN-RUH', { conn: 'down', health: 'down', licences: [{ name: 'forticare', expires: day(-3) }] }), FW(XSS, { conf: 'modified' }), FW('FW-SYN-JED', { firmware: '7.0.12', findings: [{ code: 'firmware', severity: 'medium' }] })] }) } : null,
  netopsInstance: CONNECTED ? { inventory: { list: () => [{ id: 's1', name: 'SW-SYN-01', vendor: 'h3c-comware', role: 'access', site: 'Riyadh', ip: '10.0.0.9' }] }, poller: { snapshot: () => ({ ok: true, at: 'x', system: { cpu_pct: 10, mem_pct: 20 }, interfaces: [{ name: 'GE1/0/1', oper: 'up', err_per_min: 2 }] }) } } : null });
(async () => {
  const srv = http.createServer((q, r) => { const u = decodeURIComponent(q.url.split('?')[0]), j = (c, o) => { r.writeHead(c, { 'Content-Type': 'application/json' }); r.end(JSON.stringify(o)); };
    if (u.endsWith('whoami.json')) return j(200, { user: 'op.syn', role: 'operator' });
    if (u === '/api/soc/netops/estate') return j(200, E.createEstate(deps()).build());
    if (u.startsWith('/api/')) return j(404, { error: 'not in this test' });
    fs.readFile(path.join(DASH, u.replace(/^\/dashboards\//, '/')), (e, d) => { if (e) { r.writeHead(404); return r.end(); } r.writeHead(200, { 'Content-Type': u.endsWith('.js') ? 'application/javascript' : u.endsWith('.css') ? 'text/css' : 'text/html' }); r.end(d); }); });
  await new Promise((res) => srv.listen(0, '127.0.0.1', res));
  const url = 'http://127.0.0.1:' + srv.address().port + '/dashboards/network-estate.html?standalone=1';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright'); const browser = await chromium.launch(), errs = [];
  const open = async () => { const p = await browser.newPage({ viewport: { width: 1400, height: 1000 } }); p.on('pageerror', (x) => errs.push(x.message)); await p.goto(url); await p.waitForSelector('#main:not([hidden]), #none:not([hidden])', { timeout: 15000 }); return p; };
  try {
    let p = await open();
    const kp = (await p.$eval('#kp', (x) => x.innerText)).replace(/\s+/g, ' ');
    ok(/FortiGates 3 1 not connected/.test(kp) && /Out of sync 1/.test(kp) && /Switches 1 \/ 1/.test(kp) && /Expired 1/.test(kp) && /Tunnels 40 up 2 down/.test(kp) && /Changes waiting 1/.test(kp), 'tiles: ' + kp);
    const lab = await p.$$eval('canvas', (x) => x.map((c) => c.getAttribute('aria-label') || ''));
    ok(lab.length === 6 && lab.every(Boolean), 'six charts with summaries: ' + lab.map((l) => l.slice(0, 30)).join(' | '));
    const ins = (await p.$eval('#ins', (x) => x.innerText)).replace(/\s+/g, ' ');
    ok(/1 FortiGates are not connected/.test(ins) && /1 FortiCare \/ FortiGuard licences have expired/.test(ins) && /1 switch ports are logging errors/.test(ins) && /Highest risk: FW-SYN-RUH/.test(ins), 'noticed: ' + ins);
    ok(/Upgrade 1 FortiGate-60F to 7\.2\.8/.test(await p.textContent('#sug')) && /second administrator approves/.test(await p.textContent('#sug')), 'next steps are proposals');
    ok(/\+40 not connected to FortiManager/.test(await p.textContent('#risk')), 'risk with its reasons');
    const l1 = await p.$$eval('#lic tbody tr', (x) => x.length); await p.click('[data-lf="all"]'); const l2 = await p.$$eval('#lic tbody tr', (x) => x.length);
    ok(l1 === 3 && l2 === 5, 'licence chips: due ' + l1 + ', all ' + l2);
    ok(/No active FortiCare support: FW-SYN-RUH/.test(await p.textContent('#nosup')), 'devices without support named');
    ok(!!(await p.$('#fw a[href="fortigate-fleet.html"]')) && !!(await p.$('#sw a[href="network-engineer.html"]')), 'Manage links into the four-eyes workflows');
    ok(!(await p.evaluate(() => window.PWN)) && /<img src=x/.test(await p.textContent('#fw')), 'a hostile name stays text');
    await p.close();
    CONNECTED = false; p = await open(); ok(/Nothing connected yet/.test(await p.textContent('#none')) && /connect FortiManager/.test(await p.textContent('#none')), 'nothing connected: where to connect'); await p.close();
    ok(fs.readFileSync(path.join(DASH, 'vendor/zyb-nav.js'), 'utf8').includes('"h": "network-estate.html"') && / network-estate\.html /.test(fs.readFileSync(path.join(DASH, 'install-dashboards.sh'), 'utf8')), 'menu entry and installer');
    ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  } finally { await browser.close(); srv.close(); }
  console.log((bad ? 'FAILED ' : 'ok ') + (n - bad) + '/' + n + ' network-estate checks'); process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
