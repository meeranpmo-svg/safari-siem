// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for capacity.html: after "Fetch now" the "updated ... ago" header and the platform pill move to the live
// read time (the full collection stays visible as "inventory ..."); a failed live fetch is shown, never hidden.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node capacity-fetch.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const DASH = path.resolve(__dirname, '../../ui');
let n = 0, bad = 0;
const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const old = new Date(Date.now() - 14 * 60000).toISOString();
let live = null, liveErr = null;
const report = () => ({ settings: { live_sec: 60, cpu_max_pct: 80, mem_max_pct: 85, storage_max_pct: 85, vcpu_ratio: 4, interval_min: 60 }, last_run: { at: old }, last_live: live ? { at: live } : null,
  platforms: [{ id: 'p1', label: '1161', kind: 'nutanix', site: 'HO', at: old, live_at: live, live_error: liveErr, collected: true, credentials_set: true, usage: true }], clusters: [], hosts: [], datastores: [], vms_off: [], top_vms: [], vms: [], totals: {} });
(async () => {
  const srv = http.createServer((req, res) => {
    const u = req.url.split('?')[0], json = (c, o) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(o)); };
    if (u === '/api/itam/virt/capacity' && req.method === 'GET') return json(200, report());
    if (u === '/api/itam/virt/capacity/live') { live = new Date().toISOString(); return json(200, { results: [{ label: '1161', ok: true, hosts: 3, vms: 40 }], report: report() }); }
    if (u.startsWith('/api/') || u.endsWith('whoami.json')) return json(404, {});
    const f = path.join(DASH, u === '/' ? 'capacity.html' : u); if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (e, d) => { if (e) { res.writeHead(404); return res.end(); } res.writeHead(200, { 'Content-Type': u.endsWith('.js') ? 'application/javascript' : u.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), page = await browser.newPage(), errs = [];
  page.on('pageerror', (e) => errs.push(e.message));
  await page.goto('http://127.0.0.1:' + srv.address().port + '/capacity.html');
  await page.waitForFunction(() => /updated|not collected/.test(document.getElementById('when').textContent));
  const before = await page.evaluate(() => ({ when: document.getElementById('when').textContent, pill: document.querySelector('#plats .pill').textContent }));
  ok(before.when === 'updated 14 min ago' && before.pill === 'updated 14 min ago', 'before fetch: ' + JSON.stringify(before));
  await page.click('#fetch');
  await page.waitForFunction(() => /just now/.test(document.getElementById('when').textContent), null, { timeout: 5000 }).catch(() => {});
  const after = await page.evaluate(() => ({ when: document.getElementById('when').textContent, title: document.getElementById('when').title, plat: document.querySelector('#plats').textContent, live: document.getElementById('live').textContent }));
  ok(after.when === 'updated just now', 'header moves after Fetch now: ' + after.when);
  ok(/updated just now/.test(after.plat) && /inventory 14 min ago/.test(after.plat), 'platform pill moves, inventory time still shown: ' + after.plat);
  ok(/Full collection/.test(after.title) && /Live counters/.test(after.title), 'tooltip names both times: ' + after.title);
  ok(/Live counters \d/.test(after.live), 'live line: ' + after.live);
  liveErr = 'HTTP 401'; await page.reload(); await page.waitForSelector('#plats .pill');
  ok(/live fetch failed/.test(await page.textContent('#plats')), 'a failed live fetch is shown');
  ok(!errs.length, 'page errors: ' + errs.join(' | '));
  await browser.close(); srv.close();
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks'); process.exit(bad ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });
