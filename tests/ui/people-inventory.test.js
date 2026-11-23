// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for people-inventory.html against the REAL engine (engine/people-inventory.js) with SYNTHETIC people and devices:
// the KPIs, the list with review pills, a leaver first, search and the flag filter, a KPI tile filters, a person's detail (devices
// with how each is linked, applications by category with remote-access / blocked / unusual pills), a hostile application name
// stays text, unassigned devices, departments, the CSV export, a viewer is told the page is for operators, phone width, the menu
// entry and the installer. Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node people-inventory.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const ITAM = path.join(__dirname, '..', '..', 'backend', 'itam'), DASH = path.join(__dirname, '..', '..', 'ui');
const H = require(path.join(ITAM, 'tests', 'helpers'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
(async () => {
  const e = await H.startApp({ noAi: true });
  const m365 = { connected: () => true, userApps: async () => ({ skus: [], users: [{ userPrincipalName: 'jdoe.syn@example.test', displayName: 'Jane Doe Syn', accountEnabled: true, assignedLicenses: [{ skuId: 's1' }] }, { userPrincipalName: 'asmith.syn@example.test', displayName: 'Ali Smith Syn', accountEnabled: true, assignedLicenses: [{ skuId: 's1' }] }],
    apps: [{ userPrincipalName: 'jdoe.syn@example.test', lastActivityDate: '2026-11-17', details: [{ reportPeriod: 30, outlook: true, teams: true, excel: true, windows: true }] }],
    act: [{ userPrincipalName: 'jdoe.syn@example.test', assignedProducts: ['MICROSOFT 365 E3'], exchangeLastActivityDate: '2026-11-17', teamsLastActivityDate: '2026-11-16' }, { userPrincipalName: 'asmith.syn@example.test', assignedProducts: ['MICROSOFT 365 E3'] }], errors: [] }) };
  require(path.join(ITAM, 'engine/duty')).registerDuty(e.app.srv, e.app, { noTimer: true, now: () => Date.parse('2026-11-18T08:00:00Z'), python: process.env.PYTHON || 'python3', peopleM365: m365 });
  const st = e.app.store, A = (o) => st.collection('assets').put(Object.assign({ status: 'in_use', software: [], last_seen: '2026-11-17T08:00:00Z' }, o));
  const office = { name: 'Microsoft Office Professional Plus 2021', publisher: 'Microsoft Corporation', version: '16.0' };
  const users = [{ sam: 'jdoe.syn', upn: 'jdoe.syn@example.test', display_name: 'Jane Doe Syn', department: 'Finance', title: 'Accountant', enabled: true, last_logon: '2026-11-16T07:00:00Z' },
    { sam: 'asmith.syn', display_name: 'Ali Smith Syn', department: 'Finance', enabled: false, last_logon: '2026-08-01T07:00:00Z' }, { sam: 'mk.syn', display_name: 'Mona K Syn', department: 'IT', enabled: true, last_logon: '2026-11-10T07:00:00Z' }];
  st.collection('ad_directory').put({ id: 'last', at: '2026-11-18T06:00:00Z', by: 'nora.syn', group: '', users });
  A({ id: 'as1', name: 'LAP-001', type: 'laptop', vendor: 'SynVendor', model: 'X1', serial: 'SYN001', os: 'Windows 11', custodian: 'CORP-HQ\\jdoe.syn', software: [office, { name: 'AnyDesk', publisher: 'AnyDesk Software GmbH', version: '8' }, { name: 'Calc<img src=x onerror=window.__px=1>', publisher: 'Syn' }] });
  A({ id: 'as2', name: 'WS-002', type: 'workstation', owner: 'Ali Smith Syn', software: [office] });
  A({ id: 'as3', name: 'WS-003', type: 'workstation' });
  A({ id: 'as4', name: 'LAP-004', type: 'laptop' });
  st.collection('me_ec_computers').put({ id: 'ec3', resource_id: 'ec3', name: 'WS-003', user: 'corp-hq\\mk.syn', asset_id: 'as3', last_contact: Date.now() });
  let who = { user: 'nora.syn', role: 'operator' };
  const srv = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://x'), json = (code, b) => { res.writeHead(code, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u.pathname === '/dashboards/whoami.json') return json(200, who);
    if (u.pathname.startsWith('/api/itam/')) { const h = Object.assign({}, req.headers, { 'x-sentra-proxy-secret': H.SECRET, 'x-auth-user': who.user, 'x-auth-role': who.role });
      const up = http.request({ host: '127.0.0.1', port: e.port, method: req.method, path: req.url, headers: h }, (r) => { res.writeHead(r.statusCode, r.headers); r.pipe(res); }); req.pipe(up); return; }
    if (u.pathname.startsWith('/api/') || u.pathname === '/') return json(404, { error: 'not in this test' });
    const f = path.join(DASH, u.pathname.replace(/^\/dashboards\//, '/')); if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (err, d) => { if (err) { res.writeHead(404); res.end(); return; } res.writeHead(200, { 'Content-Type': u.pathname.endsWith('.js') ? 'application/javascript' : u.pathname.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port + '/people-inventory.html?standalone=1';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  const wait = (p, fn, arg) => p.waitForFunction(fn, arg === undefined ? null : arg, { timeout: 20000 }).then(() => true, () => false);
  const T = (p, id) => p.evaluate((i) => document.getElementById(i).textContent, id);
  try {
    const p = await browser.newPage({ viewport: { width: 1440, height: 1000 }, acceptDownloads: true }); p.on('pageerror', (x) => errs.push(x.message));
    await p.goto(base);
    ok(await wait(p, () => document.querySelectorAll('#list tr.row').length === 3), 'three people listed');
    ok(/leavers holding devices/.test(await T(p, 'kpi')) && /devices with no person/.test(await T(p, 'kpi')), 'KPIs');
    ok(await p.$eval('#list tr.row', (r) => /Ali Smith Syn/.test(r.textContent) && /leaver/.test(r.textContent)), 'the leaver holding a device comes first');
    ok(/remote access/.test(await T(p, 'list')), 'review pill for remote-access tools');
    await p.fill('#q', 'mona'); ok(await wait(p, () => document.querySelectorAll('#list tr.row').length === 1), 'search narrows the list');
    await p.fill('#q', ''); await p.selectOption('#flag', 'leaver'); ok(await wait(p, () => document.querySelectorAll('#list tr.row').length === 1), 'flag filter');
    await p.selectOption('#flag', ''); await p.click('#kpi [data-k="risky"]'); ok(await wait(p, () => document.querySelectorAll('#list tr.row').length === 1 && /Jane/.test(document.getElementById('list').textContent)), 'a KPI tile filters');
    await p.click('#kpi [data-k="risky"]'); await wait(p, () => document.querySelectorAll('#list tr.row').length === 3);
    // detail
    await p.click('tr.row:has-text("Jane Doe Syn")');
    ok(await wait(p, () => /LAP-001/.test(document.getElementById('det').textContent) && /custodian/.test(document.getElementById('det').textContent)), 'devices with how each is linked');
    const det = await T(p, 'det');
    ok(/SYN001/.test(det) && /Windows 11/.test(det) && /AnyDesk/.test(det) && /remote access/.test(det) && /office/i.test(det), 'model, serial, OS and applications by category');
    ok(!(await p.evaluate(() => window.__px)) && /Calc<img/.test(det), 'a hostile application name stays text');
    await p.click('tr.row:has-text("Mona K Syn")'); ok(await wait(p, () => /signed in \(Endpoint Central\)/.test(document.getElementById('det').textContent)), 'linked by the Endpoint Central signed-in user');
    // Microsoft 365: read from the page, column, detail, leaver flag
    ok(await wait(p, () => !document.getElementById('m365read').hidden), 'the Read Microsoft 365 button shows when Microsoft 365 is connected');
    await p.click('#m365read'); ok(await wait(p, () => /Microsoft 365 2 accounts, 2 matched/.test(document.getElementById('src').textContent)), 'Microsoft 365 read from the page');
    ok(await wait(p, () => /1 licence/.test(document.getElementById('list').textContent) && /M365 licence on leaver/.test(document.getElementById('list').textContent)), 'licence column and the leaver flag');
    await p.click('tr.row:has-text("Jane Doe Syn")');
    ok(await wait(p, () => /MICROSOFT 365 E3/.test(document.getElementById('det').textContent) && /Outlook/.test(document.getElementById('det').textContent) && /✓ used/.test(document.getElementById('det').textContent) && /Used on: Windows/.test(document.getElementById('det').textContent)), 'licences, apps used and platforms in the detail');
    ok(e.app.store.auditTail(80).some((a) => a.action === 'people.m365.read' && a.by === 'nora.syn'), 'the read is audited');
    ok(/LAP-004/.test(await T(p, 'unas')) && /Finance/.test(await T(p, 'depts')), 'unassigned devices and departments');
    const [dl] = await Promise.all([p.waitForEvent('download'), p.click('#csv')]);
    const csv = fs.readFileSync(await dl.path(), 'utf8'); ok(/"Rows","3 of 3"/.test(csv) && /Jane Doe Syn/.test(csv) && /M365 apps used/.test(csv) && /Outlook Excel Teams/.test(csv), 'CSV export with the filter written in and the Microsoft 365 columns');
    ok(e.app.store.auditTail(50).some((a) => a.action === 'people.view' && a.by === 'nora.syn'), 'detail reads audited');
    who = { user: 'vera.syn', role: 'viewer' }; await p.reload(); ok(await wait(p, () => /operators and administrators only/.test(document.getElementById('err').textContent)), 'a viewer is told the page is for operators');
    who = { user: 'nora.syn', role: 'operator' };
    const ph = await browser.newPage({ viewport: { width: 390, height: 900 } }); ph.on('pageerror', (x) => errs.push(x.message)); await ph.goto(base); await wait(ph, () => !!document.querySelector('#list tr.row'));
    ok(await ph.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1), 'phone width: no sideways scroll'); await ph.close();
    ok(/"h": "people-inventory.html"/.test(fs.readFileSync(path.join(DASH, 'vendor', 'zyb-nav.js'), 'utf8')) && / people-inventory\.html /.test(fs.readFileSync(path.join(DASH, 'install-dashboards.sh'), 'utf8')), 'menu entry and installer');
  } finally { await browser.close(); srv.close(); e.close(); }
  ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks'); process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
