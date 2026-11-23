// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for the wireless controller feed on wireless.html (GET /api/soc/netops/wlc, engine/netops/wlc.js): tiles, controllers,
// SSIDs with client counts, channels, APs from the controllers with radios (band, channel, utilisation) and "not joined" APs, the AP
// filter; a controller in the inventory that has not reported says why; no controller says how to connect one; the engine without
// the feed says so; the asset-register part of the page still works; values escaped. API answers are SYNTHETIC.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node wireless-wlc.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const DASH = path.resolve(__dirname, '../../ui');
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const T0 = Date.UTC(2026, 10, 13, 9, 0, 0);
const ASSETS = { assets: [{ id: 'a1', name: 'AP-SYN-01', type: 'network', vendor: 'Cisco', model: 'AIR-AP1852', site: 'Riyadh HQ', status: 'in_use', networked: true }, { id: 'a2', name: 'SYN-WLC-1', type: 'network', vendor: 'Cisco', model: 'AIR-CT5520 WLC', site: 'Riyadh HQ', status: 'in_use' }] };
const SUM = { aps: 3, aps_up: 2, aps_down: 1, not_joined: 1, clients: 31, ssids: 2, radios: 4, radios_down: 0, busy_radios: 1, max_ch_util_pct: 81 };
const FEED = { configured: true, summary: Object.assign({ controllers: 2, reporting: 1 }, SUM),
  controllers: [{ id: 'wlc1', name: 'SYN-WLC-1', ip: '10.0.5.1', site: 'Riyadh HQ', state: 'ok', last_poll: T0, summary: SUM, ssids: [], errors: [],
    aps: [{ mac: '00:11:22:33:44:55', name: 'AP-SYN-01', model: 'AIR-SYN-1', location: 'Floor 3', ip: '10.50.0.11', status: 'up', clients: 19, radios: [{ slot: 0, band: '2.4 GHz', channel: 6, oper: 'up', clients: 7, ch_util_pct: 81 }, { slot: 1, band: '5 GHz', channel: 36, oper: 'up', clients: 12, ch_util_pct: 22 }] },
      { mac: '00:11:22:33:44:56', name: '<b>AP-SYN-02</b>', model: 'AIR-SYN-1', location: 'Floor 4', ip: '10.50.0.12', status: 'up', clients: 12, radios: [{ slot: 0, band: '2.4 GHz', channel: 11, oper: 'up', clients: 12, ch_util_pct: 40 }] },
      { mac: '00:11:22:33:44:57', name: 'AP-SYN-03', model: 'AIR-SYN-1', location: 'Floor 5', ip: '', status: 'not-joined', last_seen: T0 - 3600000, clients: 0, radios: [] }] },
    { id: 'wlc2', name: 'SYN-WLC-2', ip: '10.0.6.1', site: 'Jeddah DR', state: 'no-credentials', aps: [], ssids: [], summary: null, errors: [] }],
  ssids: [{ ssid: 'SYN-Corp', controllers: 1, clients: 27, enabled: true }, { ssid: 'SYN-Guest', controllers: 1, clients: 4, enabled: false }],
  channels: [{ channel: '2.4 GHz ch 6', radios: 1 }, { channel: '5 GHz ch 36', radios: 1 }, { channel: '2.4 GHz ch 11', radios: 1 }], vendors: [] };
let MODE = 'feed';
(async () => {
  const srv = http.createServer((q, r) => {
    const u = q.url.split('?')[0], j = (c, o) => { r.writeHead(c, { 'Content-Type': 'application/json' }); r.end(JSON.stringify(o)); };
    if (u === '/dashboards/whoami.json') return j(200, { user: 'syn.viewer', role: 'viewer' });
    if (u === '/api/itam/assets') return j(200, ASSETS);
    if (u === '/api/soc/netops/wlc') {
      if (MODE === 'feed') return j(200, FEED);
      if (MODE === 'waiting') return j(200, { configured: true, summary: { controllers: 1, reporting: 0 }, controllers: [{ id: 'wlc2', name: 'SYN-WLC-2', ip: '10.0.6.1', site: 'Jeddah DR', state: 'error', errors: ['wlc: timeout'], aps: [], ssids: [], summary: null }], ssids: [], channels: [] });
      if (MODE === 'none') return j(200, { configured: false, reason: 'No device with role "wlc"', summary: { controllers: 0, reporting: 0 }, controllers: [], ssids: [], channels: [] });
      return j(404, { error: 'not found' });
    }
    if (u.startsWith('/api/')) return j(404, { error: 'not in this test' });
    const f = path.join(DASH, u.replace(/^\/dashboards\//, '/')); if (!f.startsWith(DASH)) { r.writeHead(403); return r.end(); }
    fs.readFile(f, (e, d) => { if (e) { r.writeHead(404); return r.end(); } r.writeHead(200, { 'Content-Type': u.endsWith('.js') ? 'application/javascript' : u.endsWith('.css') ? 'text/css' : 'text/html' }); r.end(d); });
  });
  await new Promise((res) => srv.listen(0, '127.0.0.1', res));
  const base = 'http://127.0.0.1:' + srv.address().port + '/dashboards/';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  const open = async () => { const p = await browser.newPage({ viewport: { width: 1500, height: 950 } }); p.on('pageerror', (e) => errs.push(e.message)); p.on('dialog', (d) => { errs.push('dialog ' + d.message()); d.dismiss(); }); await p.goto(base + 'wireless.html?standalone=1'); return p; };
  const txt = (p, sel) => p.evaluate((s) => (document.querySelector(s) || {}).textContent || '', sel);
  try {
    let p = await open(); await p.waitForFunction(() => /Wireless clients/.test((document.getElementById('rf') || {}).textContent || ''));
    const rf = await txt(p, '#rf');
    ok(/Controllers reporting1 \/ 2/.test(rf) && /APs joined2/.test(rf) && /APs down \/ not joined1/.test(rf) && /Wireless clients31/.test(rf) && /Busiest channel81 %/.test(rf), 'tiles: ' + rf.slice(0, 220));
    ok(/SYN-Corp/.test(rf) && /27/.test(rf) && /disabled/.test(rf), 'SSIDs with client counts and state');
    ok(/2\.4 GHz ch 6/.test(rf) && /5 GHz ch 36/.test(rf), 'channels in use');
    ok(/no read-only SNMP credentials set/.test(rf), 'a controller that has not reported says why');
    ok(/Not joined/.test(rf) && /last seen/.test(rf), 'an AP that dropped off the controller');
    ok(/<b>AP-SYN-02<\/b>/.test(rf) && !(await p.$('#rf td b')), 'AP name escaped');
    ok(/2\.4 GHz · ch 6 · 81 %/.test(rf), 'radio: band, channel, utilisation');
    ok(/No client MAC/i.test(rf) || /no client MAC address/.test(rf), 'says no client identity is read');
    await p.fill('#wq', 'floor 5'); await p.dispatchEvent('#wq', 'input'); await p.waitForTimeout(150);
    const rows = await p.$$eval('#wapt tbody tr', (l) => l.length); ok(rows === 1 && /AP-SYN-03/.test(await txt(p, '#wapt tbody')), 'AP filter (' + rows + ')');
    ok(await p.evaluate(() => document.activeElement && document.activeElement.id === 'wq'), 'the filter keeps focus while typing');
    ok(/AP-SYN-01/.test(await txt(p, '#aps')) && /SYN-WLC-1/.test(await txt(p, '#wlc')), 'the asset-register part still works');
    await p.close();
    MODE = 'waiting'; p = await open(); await p.waitForFunction(() => /not reported yet/.test((document.getElementById('rf') || {}).textContent || ''));
    ok(/the last poll failed/.test(await txt(p, '#rf')) && /wlc: timeout/.test(await txt(p, '#rf')), 'controller in the inventory, poll failed: says so'); await p.close();
    MODE = 'none'; p = await open(); await p.waitForFunction(() => /No controller is connected yet/.test((document.getElementById('rf') || {}).textContent || ''));
    ok(/role wlc/.test(await txt(p, '#rf')) && /AIRESPACE-WIRELESS-MIB/.test(await txt(p, '#rf')) && !/Wireless clients/.test(await txt(p, '#rf')), 'no controller: how to connect one, no numbers'); await p.close();
    MODE = 'missing'; p = await open(); await p.waitForFunction(() => /not installed in the SIEM engine yet/.test((document.getElementById('rf') || {}).textContent || ''));
    ok(true, 'engine without the feed: says so'); await p.close();
    ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  } finally { await browser.close(); srv.close(); }
  console.log((bad ? 'FAILED ' + bad + ' of ' : 'OK ') + n + ' checks');
  process.exit(bad ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });
