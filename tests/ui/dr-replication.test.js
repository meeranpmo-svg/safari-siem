// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for dr-replication.html with the REAL ITAM capacity module (backend/itam engine/virt-capacity.js) over two
// fake Prism Elements (HQ, DR): tiles, cross-site split brain, sites with remote-site state and replication in progress,
// protection domains with RPO status and why, filter, drawer, unprotected VMs, Fetch now, Excel, and "nothing connected".
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node dr-replication.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const DASH = path.resolve(__dirname, '../../ui');
const ITAM = process.env.SENTRA_ITAM_DIR || path.resolve(__dirname, '../../backend/itam');
const { startApp } = require(path.join(ITAM, 'tests/helpers')), { createVirtCapacity } = require(path.join(ITAM, 'engine/virt-capacity'));
const { createSealer } = require(path.join(ITAM, 'engine/discovery/vault'));

let n = 0, bad = 0;
const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };

(async () => {
  const itam = await startApp({ noAi: true });
  const dc = itam.app.config.discovery, sealer = createSealer({ keyFile: dc.vault_key_file, createKey: true, purpose: 'sentra-itam-virt-platforms' });
  const put = (id, label, site, url) => itam.app.store.collection('virt_platforms').put({ id, kind: 'nutanix', label, site, base_url: url, enc: sealer.seal(id, JSON.stringify({ username: 'svc', password: 'x' })) });
  const us = (minAgo) => (Date.now() - minAgo * 60000) * 1000;
  let erpAge = 150;
  const site = () => ({
    'pe-hq': { pds: [{ name: 'PD-ERP', active: true, vms: [{ vm_name: 'DB1' }], remote_site_names: ['DR-SITE'], cron_schedules: [{ type: 'HOURLY', every_nth: 1 }] },
      { name: 'PD-WEB', active: true, vms: [{ vm_name: 'WEB1' }], remote_site_names: ['DR-SITE'], cron_schedules: [{ type: 'HOURLY', every_nth: 1 }] },
      { name: 'PD-FILE', active: true, vms: [{ vm_name: 'FS1' }], remote_site_names: ['DR-SITE'], cron_schedules: [{ type: 'HOURLY', every_nth: 4 }] }],
      snaps: { 'PD-ERP': [{ snapshot_create_time_usecs: us(erpAge), remote_site_names: ['DR-SITE'] }], 'PD-WEB': [{ snapshot_create_time_usecs: us(30), remote_site_names: ['DR-SITE'] }], 'PD-FILE': [{ snapshot_create_time_usecs: us(60), remote_site_names: ['DR-SITE'] }] },
      remotes: [{ name: 'DR-SITE', remote_ip_ports: { '10.20.0.10': 2020 }, status: 'connected' }],
      repl: [{ protection_domain_name: 'PD-ERP', remote_site_name: 'DR-SITE', replication_operation: 'SENDING', start_time_usecs: us(20), completed_percentage: 65 }],
      vms: [{ uuid: 'v1', name: 'DB1', power_state: 'on' }, { uuid: 'v2', name: 'WEB1', power_state: 'on' }, { uuid: 'v4', name: 'FS1', power_state: 'on' }, { uuid: 'v5', name: 'APP9', power_state: 'on' }] },
    'pe-dr': { pds: [{ name: 'PD-ERP', active: false, vms: [], remote_site_names: ['HQ-SITE'] }, { name: 'PD-FILE', active: true, vms: [{ vm_name: 'FS1' }], remote_site_names: ['HQ-SITE'], cron_schedules: [{ type: 'HOURLY', every_nth: 4 }] }],
      snaps: { 'PD-FILE': [{ snapshot_create_time_usecs: us(30), remote_site_names: ['HQ-SITE'] }] }, remotes: [{ name: 'HQ-SITE', status: 'connected' }], repl: [], vms: [] } });
  const request = async (url) => {
    const s = site()[/pe-hq/.test(url) ? 'pe-hq' : 'pe-dr'], u = new URL(url), p = u.pathname + u.search;
    if (/v2\.0\/hosts$/.test(p)) return { status: 200, json: { entities: [{ uuid: 'h' + url.length, name: 'NTNX', num_cpu_cores: 32, cpu_capacity_in_hz: 32e9, memory_capacity_in_bytes: 256 * 1024 ** 3, stats: {} }] } };
    if (/v2\.0\/cluster$/.test(p)) return { status: 200, json: { uuid: 'c', name: 'CL', usage_stats: {} } };
    if (/v2\.0\/vms\?/.test(p)) return { status: 200, json: { entities: s.vms } };
    if (/v2\.0\/protection_domains$/.test(p)) return { status: 200, json: { entities: s.pds } };
    const m = /protection_domains\/([^/]+)\/dr_snapshots\?count=20$/.exec(p); if (m) return { status: 200, json: { entities: s.snaps[decodeURIComponent(m[1])] || [] } };
    if (/v2\.0\/remote_sites$/.test(p)) return { status: 200, json: { entities: s.remotes } };
    if (/v2\.0\/protection_domains\/replications$/.test(p)) return { status: 200, json: { entities: s.repl } };
    return { status: 404, json: {} };
  };
  const C = createVirtCapacity(itam.app, { request, sealer });
  let EMPTY = true;
  const srv = http.createServer((req, res) => {
    const chunks = []; req.on('data', (c) => chunks.push(c)); req.on('end', async () => {
      const u = decodeURIComponent(req.url.split('?')[0]), J = (st, x) => { res.writeHead(st, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(x)); };
      if (u === '/dashboards/whoami.json') return J(200, { user: 'ali', role: 'operator' });
      if (u === '/api/itam/virt/capacity') return J(200, C.report());
      if (u === '/api/itam/virt/capacity/live' && req.method === 'POST') return J(200, { results: await C.live({ user: 'ali', role: 'operator', ip: '' }), report: C.report() });
      if (u.startsWith('/api/')) return J(404, { error: 'not in this test' });
      const f = path.join(DASH, u === '/' ? 'index.html' : u);
      if (!f.startsWith(DASH)) { res.writeHead(403); res.end(); return; }
      fs.readFile(f, (err, d) => { if (err) { res.writeHead(404); res.end(); return; } res.writeHead(200, { 'Content-Type': u.endsWith('.js') ? 'application/javascript' : u.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
    });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port + '/';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch();
  const ctx = await browser.newContext({ viewport: { width: 1400, height: 900 }, acceptDownloads: true });
  const page = await ctx.newPage(); const errs = [];
  page.on('pageerror', (e) => errs.push(e.message));
  const tiles = () => page.evaluate(() => Object.fromEntries([...document.querySelectorAll('#kk .t')].map((t) => [t.querySelector('.l').textContent, t.querySelector('.v').textContent])));

  // nothing connected yet
  await page.goto(base + 'dr-replication.html'); await page.waitForFunction(() => /No Nutanix cluster is connected yet/.test(document.getElementById('pds').textContent));
  ok(true, 'no Nutanix: says so and links to Virtualization');

  put('vp_hq', 'PE-HQ', 'Riyadh HQ', 'https://pe-hq.corp.local'); put('vp_dr', 'PE-DR', 'Jeddah DR', 'https://pe-dr.corp.local');
  await C.run();
  await page.goto('about:blank'); await page.goto(base + 'dr-replication.html'); await page.waitForSelector('#kk .t');
  let t = await tiles();
  ok(t['Protection domains'] === '5' && t['Within RPO'] === '3' && t['RPO missed'] === '1' && t['Unprotected VMs'] === '1' && t['Cross-site issues'] === '1', 'tiles: ' + JSON.stringify(t));
  ok(await page.evaluate(() => /PD-FILE.*active on PE-HQ and PE-DR.*split brain/s.test(document.getElementById('cross').innerText)), 'split brain banner');
  const sites = await page.evaluate(() => document.getElementById('sites').innerText);
  ok(/PE-HQ/.test(sites) && /Riyadh HQ/.test(sites) && /DR-SITE/.test(sites) && /connected/.test(sites) && /PD-ERP → DR-SITE/.test(sites) && /65%/.test(sites), 'site cards: remote site + replication in progress');
  const first = await page.evaluate(() => document.querySelector('#pds tbody tr').innerText);
  ok(/RPO missed/.test(first) && /PD-ERP/.test(first) && /150 min ago, RPO 60 min/.test(first) && /every 1 h/.test(first), 'worst first, with why: ' + first);
  await page.selectOption('#fs', 'standby');
  ok(await page.evaluate(() => document.querySelectorAll('#pds tbody tr').length === 1 && /Standby/.test(document.querySelector('#pds tbody tr').innerText)), 'filter: standby (DR side)');
  await page.selectOption('#fs', '');
  await page.click('#pds tbody tr'); await page.waitForSelector('#zd:not([hidden])');
  ok(/DR-SITE/.test(await page.evaluate(() => document.getElementById('zd-b').innerText)) && /AI Virtualization Administrator/.test(await page.evaluate(() => document.getElementById('zd-b').innerText)), 'drawer');
  await page.keyboard.press('Escape');
  ok(/APP9/.test(await page.evaluate(() => document.getElementById('unprot').innerText)), 'unprotected VM listed');
  // every tile is clickable: it filters the protection-domain table or opens / scrolls to what it counts
  ok((await page.$$('#kk button.t[data-tile]')).length === 7, 'all seven tiles are buttons');
  const rowsTxt = () => page.evaluate(() => [...document.querySelectorAll('#pds tbody tr')].map((r) => r.innerText));
  await page.click('#kk [data-tile="missed"]'); let rs = await rowsTxt();
  ok(rs.length === 1 && /PD-ERP/.test(rs[0]) && await page.inputValue('#fs') === 'missed' && await page.getAttribute('#kk [data-tile="missed"]', 'aria-pressed') === 'true', 'RPO missed → only those: ' + rs.length);
  await page.click('#kk [data-tile="missed"]'); ok((await rowsTxt()).length === 5 && await page.inputValue('#fs') === '', 'clicking again clears it');
  await page.click('#kk [data-tile="ok"]'); rs = await rowsTxt(); ok(rs.length === 3 && rs.every((r) => /Within RPO/.test(r)), 'Within RPO → those 3');
  await page.click('#kk [data-tile="all"]'); ok((await rowsTxt()).length === 5, 'Protection domains → all');
  await page.click('#kk [data-tile="rsdown"]'); await page.waitForSelector('#zd:not([hidden])');
  ok(/Remote sites down/.test(await page.evaluate(() => document.getElementById('zd').innerText)), 'Remote sites down opens the list'); await page.keyboard.press('Escape');
  await page.click('#kk [data-tile="cross"]'); await page.waitForTimeout(300);
  ok(await page.evaluate(() => { const r = document.getElementById('cross').getBoundingClientRect(); return r.top < window.innerHeight && r.bottom > 0; }), 'Cross-site issues scrolls to the banner');

  // replication catches up: Fetch now shows it within RPO
  erpAge = 10;
  await page.click('#fetch'); await page.waitForFunction(() => !document.getElementById('fetch').disabled);
  t = await tiles(); ok(t['RPO missed'] === '0' && t['Within RPO'] === '4', 'after Fetch now: ' + JSON.stringify(t));
  ok(/Live counters \d\d:\d\d:\d\d/.test(await page.evaluate(() => document.getElementById('live').textContent)), 'live line');

  const [dl] = await Promise.all([page.waitForEvent('download'), page.click('#xlsx')]);
  const txt = fs.readFileSync(await dl.path()).toString('latin1');
  for (const sh of ['Protection domains', 'Remote sites', 'Unprotected VMs', 'Cross-site']) ok(txt.includes('name="' + sh + '"'), 'sheet ' + sh);

  ok(!errs.length, 'page errors: ' + errs.join(' | '));
  await browser.close(); srv.close(); itam.close();
  console.log(bad ? 'FAILED ' + bad + ' of ' + n : 'OK ' + n + ' checks'); process.exit(bad ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });
