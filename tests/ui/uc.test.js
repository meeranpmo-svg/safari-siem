// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for uc.html (Unified Communications): its own main menu, UC servers from Server Availability (service set or
// guessed from the name, down first), IP phones / video devices from the asset register (type phone or a UC model) plus
// devices Asset Discovery found and nobody approved, vendor / site bars and tiles filter the list, a phone opens its detail.
// Data is SYNTHETIC. Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node uc.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const DASH = path.resolve(__dirname, '../../ui');
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const day = 864e5, now = Date.now();
const PHONES = [{ id: 'a1', type: 'phone', name: 'SEP001122334455', vendor: 'Cisco', model: 'CP-8845', mgmt_ip: '10.50.1.10', mac: '00:11:22:33:44:55', custodian: 'ahmed', site: 'HQ', last_seen: new Date(now - day).toISOString(), status: 'in_use' },
  { id: 'a2', type: 'phone', name: 'yealink-recp', vendor: 'Yealink', model: 'T54W', mgmt_ip: '10.50.1.11', site: 'Jeddah', last_seen: new Date(now - 40 * day).toISOString(), status: 'in_use' }];
const ALL = PHONES.concat([{ id: 'a3', type: 'other', name: 'BOARDROOM', vendor: 'Cisco', model: 'Webex Room Kit Pro', mgmt_ip: '10.50.2.5', site: 'HQ', status: 'in_use' }, { id: 'a4', type: 'workstation', name: 'PC1', vendor: 'Dell', model: 'OptiPlex 7090', status: 'in_use' }]);
const AVAIL = [{ id: 's1', name: 'cucm-pub', ip: '10.10.5.10', service: '', status: 'online', availability: { d7: 99.9 } }, { id: 's2', name: 'HQ-VGW01', ip: '10.10.5.20', service: 'Voice gateway', status: 'offline', availability: { d7: 80 } }, { id: 's3', name: 'fileserver', ip: '10.10.5.30', service: 'File', status: 'online' }];
(async () => {
  const srv = http.createServer((q, r) => { const u = q.url.split('?')[0], qs = q.url.split('?')[1] || '', j = (c, o) => { r.writeHead(c, { 'Content-Type': 'application/json' }); r.end(JSON.stringify(o)); };
    if (u.endsWith('whoami.json')) return j(200, { user: 'syed', role: 'operator' });
    if (u === '/api/itam/assets') return j(200, { assets: /type=phone/.test(qs) ? PHONES : ALL });
    if (u === '/api/itam/discovery/results') return j(200, { devices: [{ id: 'd1', hostname: 'SEPAABBCCDDEEFF', ip: '10.50.1.99', mac: 'aa:bb:cc:dd:ee:ff', vendor: 'Cisco Systems', type: 'phone', status: 'new' }] });
    if (u === '/api/soc/netops/avail') return j(200, { items: AVAIL });
    if (u.startsWith('/api/')) return j(404, {});
    fs.readFile(path.join(DASH, u), (e, d) => { if (e) { r.writeHead(404); return r.end(); } r.writeHead(200, { 'Content-Type': u.endsWith('.js') ? 'application/javascript' : u.endsWith('.css') ? 'text/css' : 'text/html' }); r.end(d); }); });
  await new Promise((res) => srv.listen(0, '127.0.0.1', res));
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), p = await browser.newPage({ viewport: { width: 1500, height: 900 } }), errs = [];
  p.on('pageerror', (e) => errs.push(e.message));
  await p.goto('http://127.0.0.1:' + srv.address().port + '/uc.html'); await p.waitForSelector('#ph tr.cl');
  const txt = (id) => p.evaluate((i) => document.getElementById(i).textContent, id);
  const names = () => p.evaluate(() => [].map.call(document.querySelectorAll('#ph tr.cl td:first-child b'), (b) => b.textContent));
  ok(/UC servers2/.test(await txt('kp')) && /UC servers down1/.test(await txt('kp')) && /Phones and video3/.test(await txt('kp')) && /Found, not registered1/.test(await txt('kp')), 'tiles: ' + (await txt('kp')).slice(0, 200));
  ok(/HQ-VGW01[\s\S]*cucm-pub/.test(await txt('srv')) && /guessed from the name/.test(await txt('srv')) && !/fileserver/.test(await txt('srv')), 'UC servers: down first, name guess marked, others out');
  ok((await names()).length === 4 && /BOARDROOM/.test(await txt('ph')) && !/PC1/.test(await txt('ph')), 'phones + UC model + found device; PCs out');
  await p.click('#ven [data-v="Yealink"]'); ok(JSON.stringify(await names()) === '["yealink-recp"]', 'vendor bar filters');
  await p.click('#ven [data-v="Yealink"]'); await p.click('[data-act="tile:new"]'); ok(JSON.stringify(await names()) === '["SEPAABBCCDDEEFF"]', 'found, not registered tile');
  await p.click('[data-act="tile:stale"]'); ok(JSON.stringify(await names()) === '["yealink-recp"]', 'not seen 30 days tile');
  await p.click('[data-act="tile:reg"]'); await p.fill('#q', '00:11:22'); await p.dispatchEvent('#q', 'input'); ok(JSON.stringify(await names()) === '["SEP001122334455"]', 'search by MAC');
  await p.click('#ph tr.cl'); await p.waitForTimeout(300); ok(/CP-8845/.test(await p.evaluate(() => (document.getElementById('zd-b') || {}).textContent || '')), 'detail');
  const nav = fs.readFileSync(path.join(DASH, 'vendor/zyb-nav.js'), 'utf8'); ok(/"g": "Voice & video"/.test(nav) && /"g": "Printers"/.test(nav) && /uc\.html/.test(fs.readFileSync(path.join(DASH, 'install-dashboards.sh'), 'utf8')), 'menus + installer');
  ok(!errs.length, 'page errors: ' + errs.join(' | '));
  await browser.close(); srv.close();
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks'); process.exit(bad ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });
