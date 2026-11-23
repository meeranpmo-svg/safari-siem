// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for "Fetch now" and the live line on the Nutanix VMs, Capacity and Virtualization pages, with the REAL ITAM
// capacity module (backend/itam engine/virt-capacity.js) over a fake Prism whose CPU figure changes; and Fetch now on
// Server Availability (SIEM POST /netops/avail/scan) and Node Details (POST /netops/devices/:id/poll) over stubs.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node live-fetch.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const DASH = path.resolve(__dirname, '../../ui');
const ITAM = process.env.SENTRA_ITAM_DIR || path.resolve(__dirname, '../../backend/itam');
const { startApp } = require(path.join(ITAM, 'tests/helpers')), { createVirtCapacity } = require(path.join(ITAM, 'engine/virt-capacity'));
const { createSealer } = require(path.join(ITAM, 'engine/discovery/vault'));

let n = 0, bad = 0;
const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const GiB = 1024 ** 3;

(async () => {
  const itam = await startApp({ noAi: true });
  const dc = itam.app.config.discovery, sealer = createSealer({ keyFile: dc.vault_key_file, createKey: true, purpose: 'sentra-itam-virt-platforms' });
  itam.app.store.collection('virt_platforms').put({ id: 'vp_n', kind: 'nutanix', label: 'PE-RUH', base_url: 'https://pe.corp.local', enc: sealer.seal('vp_n', JSON.stringify({ username: 'svc', password: 'x' })) });
  let cpu = '300000';
  const request = async (url) => {
    if (/v2\.0\/hosts$/.test(url)) return { status: 200, json: { entities: [{ uuid: 'h1', name: 'NTNX-A', num_cpu_cores: 48, num_cpu_sockets: 2, cpu_capacity_in_hz: 48 * 2.8e9, memory_capacity_in_bytes: 512 * GiB, stats: { hypervisor_cpu_usage_ppm: cpu, hypervisor_memory_usage_ppm: '600000' } }] } };
    if (/v2\.0\/cluster$/.test(url)) return { status: 200, json: { uuid: 'c1', name: 'RUH-CL1', usage_stats: { 'storage.capacity_bytes': 100 * 1024 * GiB, 'storage.usage_bytes': 40 * 1024 * GiB } } };
    if (/v2\.0\/vms\?/.test(url)) return { status: 200, json: { entities: [{ uuid: 'v1', name: 'DB1', num_vcpus: 8, memory_mb: 65536, power_state: 'on', host_uuid: 'h1' }] } };
    if (/storage_containers$/.test(url)) return { status: 200, json: { entities: [] } };
    if (/v1\/vms\?count=500&page=1$/.test(url)) return { status: 200, json: { entities: [{ uuid: 'v1', stats: { hypervisor_cpu_usage_ppm: '250000', memory_usage_ppm: '500000' } }] } };
    return { status: 404, json: {} };
  };
  const C = createVirtCapacity(itam.app, { request, sealer });
  await C.run();
  let ROLE = 'operator'; const posted = [];
  const srv = http.createServer((req, res) => {
    const chunks = []; req.on('data', (c) => chunks.push(c)); req.on('end', async () => {
      const u = decodeURIComponent(req.url.split('?')[0]), J = (st, x) => { res.writeHead(st, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(x)); };
      if (u === '/dashboards/whoami.json') return J(200, { user: 'ali', role: ROLE });
      if (u === '/api/itam/virt/capacity' && req.method === 'GET') return J(200, C.report());
      if (u === '/api/itam/virt/capacity/live' && req.method === 'POST') { posted.push(u); if (ROLE === 'viewer') return J(403, { error: 'forbidden' }); return J(200, { results: await C.live({ user: 'ali', role: ROLE, ip: '' }), report: C.report() }); }
      if (u === '/api/itam/virt' && req.method === 'GET') return J(200, { platforms: [], kinds: {} });
      if (u === '/api/itam/virt/inventory') return J(200, { hosts: [], vms: [], summary: {} });
      if (u === '/api/soc/netops/avail/scan' && req.method === 'POST') { posted.push(u); return J(200, { summary: { total: 1 }, items: [] }); }
      if (/^\/api\/soc\/netops\/devices\/[^/]+\/poll$/.test(u) && req.method === 'POST') { posted.push(u); return J(200, { ok: true }); }
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
  const page = await browser.newPage({ viewport: { width: 1400, height: 900 } }); const errs = [];
  page.on('pageerror', (e) => errs.push(e.message));
  const body = () => page.evaluate(() => document.body.innerText);

  // Nutanix VMs: live line, Fetch now picks up the new CPU figure
  await page.goto(base + 'nutanix-vms.html'); await page.waitForFunction(() => document.getElementById('live').textContent.length > 0);
  ok(/Live counters not read yet · every 60 s/.test(await page.evaluate(() => document.getElementById('live').textContent)), 'live line before any live read');
  ok(/30(\.0)?\s*%/.test(await body()), 'host CPU 30 % from the full collection');
  cpu = '850000';
  await page.click('#fetch'); await page.waitForFunction(() => /Live counters \d\d:\d\d:\d\d \(\d+ s ago\)/.test(document.getElementById('live').textContent), null, { timeout: 15000 });
  ok(/85(\.0)?\s*%/.test(await body()), 'host CPU 85 % after Fetch now');
  ok(posted.includes('/api/itam/virt/capacity/live'), 'Fetch now asked ITAM for the live counters');
  ok(await page.evaluate(() => /PE-RUH: 1 hosts, 1 VMs updated/.test(document.body.innerText)), 'toast names what was updated');

  // Capacity: Fetch now + live line + live interval setting for an admin
  ROLE = 'admin'; await page.goto(base + 'capacity.html'); await page.waitForFunction(() => /Live counters/.test(document.getElementById('live').textContent));
  ok(await page.evaluate(() => document.getElementById('s_l') && document.getElementById('s_l').value === '60'), 'live interval setting shown (60 s)');
  cpu = '450000'; await page.click('#fetch'); await page.waitForFunction(() => !document.getElementById('fetch').disabled);
  ok(/45(\.0)?\s*%/.test(await body()), 'capacity page shows the new figure after Fetch now');

  // Virtualization page has the button too; a viewer is told it needs an operator
  ROLE = 'viewer'; await page.goto(base + 'virtualization.html'); await page.waitForSelector('#fetch');
  await page.click('#fetch'); await page.waitForFunction(() => /needs an operator or administrator/.test(document.body.innerText), null, { timeout: 8000 }).catch(() => {});
  ok(/needs an operator or administrator/.test(await body()), 'viewer: told Fetch now needs an operator');

  // Server Availability and Node Details: Fetch now reaches the SIEM
  ROLE = 'operator'; await page.goto(base + 'server-availability.html'); await page.waitForSelector('#fetch');
  await page.click('#fetch'); await page.waitForFunction(() => /Fetched \d\d:\d\d/.test(document.body.innerText), null, { timeout: 8000 }).catch(() => {});
  ok(posted.includes('/api/soc/netops/avail/scan'), 'Server Availability: every server checked now');
  await page.goto(base + 'node-details.html?id=core-sw1'); await page.waitForSelector('#fetch');
  await page.click('#fetch'); await page.waitForTimeout(800);
  ok(posted.some((p) => /\/netops\/devices\/core-sw1\/poll$/.test(p)), 'Node Details: this node polled now');

  ok(!errs.length, 'page errors: ' + errs.join(' | '));
  await browser.close(); srv.close(); itam.close();
  console.log(bad ? 'FAILED ' + bad + ' of ' + n : 'OK ' + n + ' checks'); process.exit(bad ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });
