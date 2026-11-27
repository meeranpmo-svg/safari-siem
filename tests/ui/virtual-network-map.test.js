// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Hyper-V Virtual Network Map (virtual-network-map.html) over the REAL engine (backend/itam engine/hyperv-netmap.js) and SYNTHETIC host
// reports: tiles, insights, two charts, the host topology drawing (switches, uplinks, the down uplink in red), the findings with
// the fix, the learned baseline per group, the VLAN x host matrix, a VM trace with the down uplink marked, the adapter filter, a
// hostile VM name stays text, nothing reported says what to do, POC mode draws the illustrative hosts with one ribbon, menu entry.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node virtual-network-map.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const DASH = path.resolve(__dirname, '../../ui'), ITAM = path.resolve(__dirname, '../../backend/itam');
const N = require(path.join(ITAM, 'engine/hyperv-netmap')), { normMetrics } = require(path.join(ITAM, 'engine/hyperv-manager'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const XSS = '<img src=x onerror=window.PWN=1>';
const rep = (name, i, o = {}) => normMetrics({ collected_at: new Date().toISOString(), host: { name, network: {
  physical: [{ name: 'NIC1', desc: 'X #1', status: 'Up', link_mbps: 10000 }, { name: 'NIC2', desc: 'X #2', status: o.down ? 'Disconnected' : 'Up', link_mbps: 10000 }],
  switches: [{ name: 'vSW-Prod', type: 'External', set: true, mgmt_os: true, uplinks: ['X #1', 'X #2'] }].concat(o.noB ? [] : [{ name: 'vSW-Backup', type: 'External', uplinks: ['X #2'] }]),
  adapters: [{ mgmt_os: true, name: 'Management', switch: 'vSW-Prod', vlan_mode: 'Access', vlan: 8, mac: '00155D0' + i + '0001' },
    { vm: 'APP-SYN-0' + i, name: 'NA', switch: 'vSW-Prod', vlan_mode: 'Access', vlan: 110, mac: '00155D0' + i + '0002', ips: ['10.1.' + i + '.21'] },
    { vm: (o.x ? XSS : 'DB-SYN-0' + i), name: 'NA', switch: 'vSW-Prod', vlan_mode: 'Access', vlan: 120, mac: '00155D0' + i + '0003' }] } }, vms: [] });
(async () => {
  let V = N.analyse([rep('HV-SYN-01', 1), rep('HV-SYN-02', 2, { down: true, x: true }), rep('HV-SYN-03', 3, { noB: true })], {}); V.changes = [];
  const srv = http.createServer((req, res) => { const u = new URL(req.url, 'http://x'), json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u.pathname === '/dashboards/whoami.json') return json(200, { user: 'vera.syn', role: 'viewer' });
    if (u.pathname === '/api/itam/hyperv/network') return json(200, V);
    if (u.pathname === '/api/itam/hyperv/network/trace') { try { return json(200, N.trace(V, u.searchParams.get('vm'))); } catch (e) { return json(e.status || 500, { error: e.message }); } }
    if (u.pathname.startsWith('/api/')) return json(500, { error: 'down (synthetic)' });
    fs.readFile(path.join(DASH, u.pathname.replace(/^\/dashboards\//, '/')), (err, d) => { if (err) { res.writeHead(404); return res.end(); } res.writeHead(200, { 'Content-Type': u.pathname.endsWith('.js') ? 'application/javascript' : u.pathname.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); }); });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port + '/dashboards/virtual-network-map.html';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright'); const browser = await chromium.launch(), errs = [];
  const open = async (q) => { const p = await browser.newPage({ viewport: { width: 1500, height: 1100 } }); p.on('pageerror', (x) => errs.push(x.message)); await p.goto(base + (q || '?standalone=1')); await p.waitForSelector('#main:not([hidden])', { timeout: 15000 }); return p; };
  try {
    let p = await open();
    const kp = (await p.$eval('#kp', (x) => x.innerText)).replace(/\s+/g, ' ');
    ok(/Hosts 3/.test(kp) && /Uplinks down 2/.test(kp), 'tiles: ' + kp);
    ok((await p.$$('.g3 canvas')).length === 2 && /baseline/.test(await p.textContent('#ins')), 'charts and what the AI noticed');
    ok((await p.$$('#topo svg rect')).length >= 5 && /vSW-Prod/.test(await p.textContent('#topo')), 'the host topology');
    await p.selectOption('#host', 'HV-SYN-02'); ok((await p.$$('#topo path[stroke="#ff7b72"]')).length >= 1, 'the down uplink drawn in red');
    ok(/HV-SYN-03 has no switch "vSW-Backup"/.test(await p.textContent('#fl')) && /create the switch with the same name/.test(await p.textContent('#fl')), 'a finding with its fix');
    ok(/vSW-Backup/.test(await p.textContent('#bl')), 'the learned baseline');
    ok((await p.$$('#mx tbody tr')).length === 2, 'VLAN x host matrix');
    await p.fill('#vm', 'APP-SYN-02'); await p.click('#tr'); await p.waitForSelector('#trace .hop'); ok((await p.$$('#trace .hop.bad')).length === 1 && /vSW-Prod/.test(await p.textContent('#trace')), 'trace with the down uplink marked');
    await p.fill('#q', '10.1.3.21'); await p.dispatchEvent('#q', 'input'); ok((await p.$$('#ad tbody tr')).length === 1, 'filter the adapters');
    ok(!(await p.evaluate(() => window.PWN)), 'hostile text stays text'); await p.close();
    V = N.analyse([normMetrics({ collected_at: new Date().toISOString(), host: { name: 'OLD-SYN' } })], {}); V.changes = [];
    p = await open(); ok(/not their virtual network yet/.test(await p.textContent('#ins')) && /No Hyper-V host reports its network/.test(await p.textContent('#topo')), 'an older script: what to do'); await p.close();
    p = await open('?poc=1'); await p.waitForTimeout(600);
    ok((await p.$$('.zyb-poc-r.br')).length === 1 && /HQPSUPERM01/.test(await p.textContent('#host')), 'POC: the illustrative hosts, one ribbon');
    if (process.env.SHOT) { await p.waitForTimeout(800); await p.screenshot({ path: process.env.SHOT, fullPage: true }); }
    await p.close();
    ok(fs.readFileSync(path.join(DASH, 'vendor/zyb-nav.js'), 'utf8').includes('"h": "virtual-network-map.html"'), 'menu entry');
    ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  } finally { await browser.close(); srv.close(); }
  console.log((bad ? 'FAILED ' : 'ok ') + (n - bad) + '/' + n + ' virtual-network-map checks'); process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
