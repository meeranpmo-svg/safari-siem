// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for the ✦ AI / ML sections (vendor/zyb-leader.js) on the CIO Dashboard and the IT Infrastructure Manager page,
// against the REAL ITAM engine (engine/leader-intel.js) with SYNTHETIC servers, backup / storage / Endpoint Central add-ons,
// licences, support contracts and 12 days of snapshots: CIO - decide this week (an imminent renewal first), the renewal wave
// with its peak, budget forecast (or what to connect), posture and infrastructure gauges; Infra - the health index with an
// itemised bar per area, the ranked fix-first list, the storage forecast date, area trends, an unusual drop; the advisor box;
// escaped names; a viewer told the section is for operators; phone width; no page error.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node leader-ai.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const ITAM = path.join(__dirname, '..', '..', 'backend', 'itam'), DASH = path.join(__dirname, '..', '..', 'ui');
const H = require(path.join(ITAM, 'tests', 'helpers'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const XSS = '<img src=x onerror="window.__xss=1">';
(async () => {
  const e = await H.startApp({ noAi: true }); const ADM = { user: 'syed', role: 'admin', ip: '' }, DAY = 864e5, T = Date.now();
  for (let i = 0; i < 8; i++) e.app.assets.create({ name: 'SRV-SYN-' + i, type: 'server', status: 'in_use' }, ADM);
  let prot = 3;
  e.app.addons.backup = { view: () => ({ platforms: [{ id: 'veeam' }], summary: { assets: 8, protected: prot, stale: 0, failed: 8 - prot, none: 0, exempt: 0 } }) };
  e.app.addons.storage = { view: () => ({ arrays: [], summary: { arrays: 1, read: 1, used_pct: 72, failed_disks: 0 } }) };
  e.app.addons.manageengine = { computers: () => ({ computers: [{ name: 'SRV-SYN-1', missing: 0 }, { name: 'SRV-SYN-2 ' + XSS, missing: 3, critical: 1 }] }) };
  const iso = (d) => new Date(T + d * DAY).toISOString().slice(0, 10);
  e.app.store.collection('licences').put({ id: 'lic-1', product: 'M365 E3 SYN ' + XSS, expiry: iso(9), cost: 450000, status: 'active' });
  e.app.store.collection('licences').put({ id: 'lic-2', product: 'Adobe SYN', expiry: iso(70), cost: 40000, status: 'active' });
  e.app.store.collection('support_contracts').put({ id: 'sc-1', vendor: 'Cisco', product: 'SmartNet SYN', end: iso(120), cost: 120000 });
  const snaps = e.app.store.collection('leader_intel_snaps');
  for (let d = 12; d >= 1; d--) { const id = new Date(T - d * DAY).toISOString().slice(0, 10); snaps.put({ id, at: id, overall: 72, backup: 75, patch: 50, storage: 92, storage_used: 66 + (12 - d) * 0.5 }); }
  require(path.join(ITAM, 'engine/duty')).registerDuty(e.app.srv, e.app, { noTimer: true });
  let WHO = { user: 'nora.syn', role: 'operator' };
  const web = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://x'), json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u.pathname === '/dashboards/whoami.json') return json(200, WHO);
    if (u.pathname.startsWith('/api/itam/')) {
      const h = Object.assign({}, req.headers, { 'x-sentra-proxy-secret': H.SECRET, 'x-auth-user': WHO.user, 'x-auth-role': WHO.role });
      const up = http.request({ host: '127.0.0.1', port: e.port, method: req.method, path: req.url, headers: h }, (r) => { res.writeHead(r.statusCode, r.headers); r.pipe(res); });
      req.pipe(up); return;
    }
    if (u.pathname.startsWith('/api/')) return json(404, { error: 'not in this test' });
    const f = path.join(DASH, u.pathname.replace(/^\/dashboards\//, '/')); if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (err, d) => { if (err) { res.writeHead(404); res.end(); return; } res.writeHead(200, { 'Content-Type': u.pathname.endsWith('.js') ? 'application/javascript' : u.pathname.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => web.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + web.address().port + '/dashboards/';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  const wait = (p, fn, arg) => p.waitForFunction(fn, arg, { timeout: 15000 }).then(() => true, () => false);
  const txt = (p, id) => p.evaluate((i) => document.getElementById(i).innerText, id);
  try {
    const p = await browser.newPage({ viewport: { width: 1500, height: 1100 } }); p.on('pageerror', (x) => errs.push(x.message));
    await p.goto(base + 'cio-dashboard.html');
    ok(await wait(p, () => /Decide this week/.test(document.getElementById('zl-ai').innerText)), 'CIO: AI section drawn');
    const c = await txt(p, 'zl-ai');
    ok(/Renewal in 9 days: M365 E3 SYN/.test(c), 'the imminent renewal is on the week list: ' + c.slice(0, 300));
    ok(/Renewal wave/.test(c) && await p.$('#zl-ai svg rect') && /peak/.test(c), 'renewal wave with its peak');
    ok(/Budget forecast/.test(c), 'budget forecast card'); ok(/Security posture/.test(c) && /Infrastructure health/.test(c), 'two gauges');
    ok(await p.evaluate(() => !window.__xss), 'names escaped');
    const q = await browser.newPage({ viewport: { width: 1500, height: 1100 } }); q.on('pageerror', (x) => errs.push(x.message));
    await q.goto(base + 'infra-manager.html');
    ok(await wait(q, () => /Infrastructure health index/.test(document.getElementById('zl-ai').innerText)), 'Infra: AI section drawn');
    const i = await txt(q, 'zl-ai');
    ok(/Backup protection[\s\S]*38/.test(i), 'backup area scored 38 (3 of 8)');
    ok(/5 server backup\(s\) failing/.test(i), 'fix-first list ranked');
    ok(/Storage forecast/.test(i) && /85 % around/.test(i) && /\d{4}-\d{2}-\d{2}/.test(i), 'storage forecast date');
    ok(/Backup protection[\s\S]*dropped unusually|Backup protection\s*fell/.test(i) || /fell 37 points/.test(i), 'unusual drop named');
    ok(await q.$('#zli-f') && await p.$('#zlc-f'), 'advisor boxes');
    ok(await q.evaluate(() => !window.__xss), 'names escaped (infra)');
    WHO = { user: 'vera.syn', role: 'viewer' };
    const v = await browser.newPage({ viewport: { width: 390, height: 900 } }); v.on('pageerror', (x) => errs.push(x.message));
    await v.goto(base + 'cio-dashboard.html');
    ok(await wait(v, () => /for operators and administrators/.test(document.getElementById('zl-ai').innerText)), 'viewer told who the section is for');
    WHO = { user: 'nora.syn', role: 'operator' };
    const ph = await browser.newPage({ viewport: { width: 390, height: 900 } }); ph.on('pageerror', (x) => errs.push(x.message));
    await ph.goto(base + 'infra-manager.html'); await wait(ph, () => /Infrastructure health index/.test(document.getElementById('zl-ai').innerText));
    ok(await ph.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1), 'phone width: no sideways scroll');
    if (process.env.SHOT) { await p.screenshot({ path: process.env.SHOT + '-cio.png', fullPage: true }); await q.screenshot({ path: process.env.SHOT + '-infra.png', fullPage: true }); }
  } finally { await browser.close(); web.close(); try { e.app.addons.leaderIntel.stop(); } catch (x) { /* not started */ } await e.close(); }
  ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks'); process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
