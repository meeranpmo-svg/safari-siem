// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for facilities.html after the static build, with the three sources stubbed (SYNTHETIC data in the shapes the SIEM
// printer monitor, the availability scanner and ITAM locations return): tiles, sites joined from all three (a site where no device
// answers is flagged), needs-attention built only from real items, UPS from the UPS-MIB reader (on battery / fault first, an unreported
// value reads "not reported", no UPS says how to add one), CCTV cameras offline from the recorders (SYNTHETIC), door access, one
// source down degrades its own card, all down invents nothing, escaping, reachable from the menu, the portal dash-fac redirect.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node facilities.test.js
const http = require('http'), fs = require('fs'), path = require('path'), os = require('os'), cp = require('child_process');
const SRC = path.resolve(__dirname, '../../ui');
let n = 0, bad = 0;
const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const B = fs.mkdtempSync(path.join(os.tmpdir(), 'facil-')); fs.mkdirSync(path.join(B, 'vendor'));
fs.readdirSync(SRC).filter((f) => f.endsWith('.html')).forEach((f) => fs.copyFileSync(path.join(SRC, f), path.join(B, f)));
fs.readdirSync(path.join(SRC, 'vendor')).filter((f) => /\.(js|json|css)$/.test(f)).forEach((f) => fs.copyFileSync(path.join(SRC, 'vendor', f), path.join(B, 'vendor', f)));
cp.execFileSync(process.execPath, [path.join(SRC, 'build-static.js'), B, 't1'], { stdio: 'ignore' });

const XSS = '<img src=x onerror="window.__xss=1">';
const PR = { items: [
    { id: 'p1', name: 'PRN-RUH-01', ip: '10.1.0.50', site: 'Riyadh HQ', status: 'ok', issues: [] },
    { id: 'p2', name: 'PRN-MED-01 ' + XSS, ip: '10.5.0.50', site: 'Madinah', status: 'error', issues: [{ level: 'bad', text: 'Paper jam' }] },
    { id: 'p3', name: 'PRN-JED-01', ip: '10.2.0.50', site: 'Jeddah', status: 'warning', issues: [{ level: 'warn', text: 'Black toner 8% left' }] }],
  summary: { total: 3, ok: 1, warning: 1, error: 1, offline: 0, unknown: 0, toner_low: 1, pages_today: 120, pages_30d: 4100 } };
const AV = { items: [
    { id: 'h1', name: 'SRV-RUH-01', ip: '10.1.0.10', site: 'Riyadh HQ', status: 'online' }, { id: 'h2', name: 'SRV-RUH-02', ip: '10.1.0.11', site: 'Riyadh HQ', status: 'online' },
    { id: 'h3', name: 'SW-DMM-01', ip: '10.3.0.2', site: 'Dammam', status: 'offline', duration_s: 1800 }, { id: 'h4', name: 'AP-JED-01', ip: '10.2.0.9', site: 'Jeddah', status: 'online' }], summary: {} };
const LOC = { locations: [{ id: 'l1', name: 'Riyadh HQ', kind: 'main' }, { id: 'l2', name: 'Dammam', kind: 'branch' }, { id: 'l3', name: 'Jeddah', kind: 'branch' }, { id: 'l4', name: 'Abha', kind: 'branch' }] };
const UPS = { configured: true, kpis: { ups: 2, online: 1, on_battery: 1, low: 0, fault: 0, not_answering: 0, short_runtime: 0, ageing: 0, test_failed: 0, min_runtime: 18 },
  ups: [{ id: 'u1', name: 'UPS-DMM-01', ip: '10.3.0.5', site: 'Dammam', state: 'on-battery', why: 'running on battery - about 18 min left', manufacturer: 'SYN-Power', model: 'SYN-10K', battery: 'normal', charge_pct: 81, minutes_left: 18, load_pct: 40, temp_c: null, input_voltage: 0, alarms: ['on battery'], last_test: 'passed', short_runtime: false, ageing: { samples: 0 } },
    { id: 'u2', name: 'UPS-RUH-01', ip: '10.1.0.5', site: 'Riyadh HQ', state: 'online', why: 'on mains, battery normal', manufacturer: '', model: '', battery: 'normal', charge_pct: 100, minutes_left: null, load_pct: null, temp_c: null, input_voltage: null, alarms: [], last_test: null, short_runtime: false, ageing: { samples: 0 } }],
  actions: [{ priority: 100, title: '1 UPS on battery now', detail: 'UPS-DMM-01 (Dammam) - mains is lost at the site' }], note: 'Read from each UPS through the standard UPS-MIB. Nothing is sent to a UPS.' };
const DR = { configured: true, kpis: { servers: 1, controllers: 3, online: 2, offline: 1, not_reported: 0, doors: 6, forced: 1, held_open: 2, duress: 0, tamper: 0, alarm: 0, denied: 4, unread: 0 },
  actions: [{ priority: 95, title: '1 door(s) forced open in 24 h', detail: 'Server Room (Riyadh HQ) ×1 - check the CCTV for that door and time' }, { priority: 80, title: '1 door controller(s) offline', detail: 'CTRL-JED-01 (Jeddah)' }] };
let MODE = 'full';
(async () => {
  const srv = http.createServer((q, r) => {
    const u = q.url.split('?')[0], j = (c, o) => { r.writeHead(c, { 'Content-Type': 'application/json' }); r.end(JSON.stringify(o)); };
    if (u.endsWith('whoami.json')) return j(200, { user: 'syed', role: 'operator' });
    const dead = MODE === 'dead' || (MODE === 'noprinter' && u === '/api/soc/printers');
    if (u === '/api/soc/printers') return dead ? j(502, { error: 'down' }) : j(200, PR);
    if (u === '/api/soc/netops/avail') return dead ? j(502, { error: 'down' }) : j(200, AV);
    if (u === '/api/soc/netops/ups') return dead ? j(502, { error: 'down' }) : MODE === 'noups' ? j(200, { configured: false, reason: 'No UPS is monitored. Add each UPS in Network Onboarding with role "ups"', kpis: {}, ups: [], actions: [] }) : j(200, UPS);
    if (u === '/api/soc/facilities/cctv') return dead ? j(502, { error: 'down' }) : j(200, { configured: true, kpis: { cameras: 12, online: 11, offline: 1, not_reported: 0, recorders: 1, reachable: 1, disks_failed: 0, group_outages: 0, availability_7d: 99.2 }, actions: [] });
    if (u === '/api/soc/facilities/doors') return dead ? j(502, { error: 'down' }) : j(200, DR);
    if (u === '/api/itam/locations') return MODE === 'dead' ? j(502, { error: 'down' }) : j(200, LOC);
    if (u.startsWith('/api/')) return j(404, {});
    const f = path.join(B, u === '/' ? 'index.html' : u); if (!f.startsWith(B)) { r.writeHead(403); return r.end(); }
    fs.readFile(f, (e, d) => { if (e) { r.writeHead(404); return r.end(); } r.writeHead(200, { 'Content-Type': u.endsWith('.js') ? 'application/javascript' : u.endsWith('.css') ? 'text/css' : 'text/html' }); r.end(d); });
  });
  await new Promise((res) => srv.listen(0, '127.0.0.1', res));
  const base = 'http://127.0.0.1:' + srv.address().port + '/';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  const open = async (pg) => { const p = await browser.newPage({ viewport: { width: 1500, height: 950 } }); p.on('pageerror', (e) => errs.push(e.message)); await p.goto(base + (pg || 'facilities.html')); return p; };
  const txt = (p, id) => p.evaluate((i) => (document.getElementById(i) || {}).innerText || '', id);

  let p = await open('printers.html'); await p.waitForTimeout(800);
  const link = await p.evaluate(() => { const a = document.querySelector('a[href="facilities.html"]'); return a ? a.textContent.trim() : null; });
  ok(/Facilities/.test(link || ''), 'menu entry exists: ' + link);
  await p.evaluate(() => document.querySelector('a[href="facilities.html"]').click());
  await p.waitForURL(/facilities\.html/); await p.waitForFunction(() => /Needs attention/i.test(document.getElementById('body').innerText));
  const kp = await txt(p, 'kp');
  ok(/Sites\s*5/i.test(kp), 'sites: 4 saved + Madinah named by a printer: ' + kp.replace(/\s+/g, ' ').slice(0, 200));
  ok(/Devices reachable\s*75 %/i.test(kp) && /3 of 4 answering/.test(kp), 'reachability from the scanner');
  ok(/Printer faults\s*1/i.test(kp) && /1 toner low/.test(kp), 'printer faults + toner');
  ok(/CCTV cameras offline\s*1/i.test(kp) && /11 \/ 12 online/.test(kp), 'CCTV tile from the recorders');
  ok(/Door controllers offline\s*1/i.test(kp) && /2 of 3 online · 1 door alarms 24 h/.test(kp), 'door access tile from ZKBio');
  ok(/UPS on battery \/ fault\s*1/i.test(kp) && /2 UPS · 1 on mains · shortest 18 min/.test(kp), 'UPS tile from the reader');
  const body = await txt(p, 'body');
  ok(/Paper jam/.test(body) && /SW-DMM-01 offline/.test(body) && /Dammam: no monitored device answers/.test(body), 'needs attention from real items only');
  ok(/UPS-DMM-01 \(Dammam\) on battery/.test(body) && /about 18 min left/.test(body), 'a UPS on battery is in needs attention');
  ok(/UPS-RUH-01[\s\S]*not reported/i.test(body) && /1 UPS on battery now/.test(body), 'unreported runtime / load read "not reported"; the reader\'s actions shown');
  ok(/Dammam[\s\S]*1 on battery \/ fault/.test(body), 'the site row carries its UPS');
  ok(/Door access: 1 door\(s\) forced open/.test(body) && /held open 2/i.test(body), 'door alarms in needs attention and the door card');
  ok(/Abha[\s\S]*not monitored/.test(body), 'a site with no monitored device reads "not monitored", never healthy');
  ok(!/Madinah branch printer offline twice|13 SITES|98%/i.test(body + kp), 'none of the old sample figures');
  ok(await p.evaluate(() => !window.__xss) && !(await p.$('#body img')), 'printer names escaped');
  await p.close();

  MODE = 'noprinter'; p = await open(); await p.waitForFunction(() => /Needs attention/i.test(document.getElementById('body').innerText));
  ok(/printer monitor not reachable/.test(await txt(p, 'kp')) && /SW-DMM-01/.test(await txt(p, 'body')), 'printer source down: its card says so, the rest still renders');
  await p.close();

  MODE = 'noups'; p = await open(); await p.waitForFunction(() => /Needs attention/i.test(document.getElementById('body').innerText));
  ok(/no UPS added yet/.test(await txt(p, 'kp')) && /Network Onboarding with role "ups"/.test(await txt(p, 'body')), 'no UPS: says how to add one, no figure');
  await p.close();

  MODE = 'dead'; p = await open(); await p.waitForFunction(() => /No facilities source is reachable/i.test(document.getElementById('body').innerText));
  ok(!/\d+ %/.test(await txt(p, 'kp')), 'all down: no percentage invented');
  await p.close();

  ok(/'dash-fac': 'facilities\.html'/.test(fs.readFileSync(path.join(SRC, 'vendor/zyb-menu.js'), 'utf8')), 'the portal sample Facilities dashboard redirects here');
  ok(/ facilities\.html /.test(fs.readFileSync(path.join(SRC, 'install-dashboards.sh'), 'utf8')), 'in the installer');
  ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  await browser.close(); srv.close();
  console.log(`${n - bad}/${n} checks passed`); process.exit(bad ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });
