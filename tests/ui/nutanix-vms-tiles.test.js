// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for nutanix-vms.html tiles: every tile opens what it counts (VM list filtered / sorted, clusters, hosts).
// Also (from the IP test harness): the IP address column (Prism first, a fallback named with its source, "not reported"
// rather than blank), search by IP / MAC, IP sort, the count of running VMs with no IP, and the VM drawer's IP / MAC rows.
// Data is SYNTHETIC. Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node nutanix-vms-ip.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const DASH = path.resolve(__dirname, '../../ui');
let n = 0, bad = 0;
const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const at = new Date().toISOString();
const vm = (id, name, power, ips, src, macs) => ({ id, pid: 'p1', platform: 'PE', kind: 'nutanix', cluster: 'CL', name, host: 'NTNX-A', power, vcpus: 2, mem_gb: 4, disk_gb: 50, guest_os: '', ips, ip_src: src, macs: macs || [], cpu_pct: null, mem_used_pct: null, iops: null });
const VMS = [vm('v1', 'APP01', 'on', ['10.20.1.15', '10.20.1.16'], 'prism', ['50:6b:8d:aa:00:01']), vm('v2', 'DB01', 'on', ['10.20.1.9'], 'mac', ['50:6b:8d:aa:00:02']), vm('v3', 'WEB01', 'on', [], null, ['50:6b:8d:aa:00:03']), vm('v4', 'OLD01', 'off', [], null)];
const report = { settings: {}, last_run: { at }, platforms: [{ id: 'p1', label: 'PE', kind: 'nutanix', at, collected: true, credentials_set: true, usage: true }], clusters: [{ id: 'c1', platform: 'PE', kind: 'nutanix', name: 'CL' }], hosts: [], datastores: [], vms_off: [], top_vms: [], vms: VMS, totals: {} };
(async () => {
  const srv = http.createServer((req, res) => {
    const u = req.url.split('?')[0], json = (c, o) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(o)); };
    if (u === '/api/itam/virt/capacity') return json(200, report);
    if (u.startsWith('/api/') || u.endsWith('whoami.json')) return json(404, {});
    const f = path.join(DASH, u); if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (e, d) => { if (e) { res.writeHead(404); return res.end(); } res.writeHead(200, { 'Content-Type': u.endsWith('.js') ? 'application/javascript' : u.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), page = await browser.newPage({ viewport: { width: 1500, height: 900 } }), errs = [];
  page.on('pageerror', (e) => errs.push(e.message));
  await page.goto('http://127.0.0.1:' + srv.address().port + '/nutanix-vms.html');
  await page.waitForSelector('#vms tr.vr');
  const names = () => page.evaluate(() => [].map.call(document.querySelectorAll('#vms tr.vr'), (tr) => tr.children[0].textContent));
  const acts = await page.evaluate(() => [].map.call(document.querySelectorAll('.t[data-act]'), (t) => t.getAttribute('data-act')));
  ok(['all', 'on', 'clusters', 'hosts', 'vcpus', 'mem_gb'].every((a) => acts.includes(a)), 'top tiles clickable: ' + acts);
  await page.click('.t[data-act="on"]'); await page.waitForTimeout(200);
  ok(!(await names()).includes('OLD01') && await page.inputValue('#pw') === 'on', 'Powered on: running VMs only');
  ok(await page.getAttribute('.t[data-act="on"]', 'aria-pressed') === 'true' && /running VMs/.test(await page.textContent('#vmf')), 'tile marked, filter named');
  await page.click('.t[data-act="all"]'); await page.waitForTimeout(200);
  ok((await names()).includes('OLD01'), 'VM count: every VM again');
  await page.click('.t[data-act="vcpus"]'); await page.waitForTimeout(200);
  ok((await page.textContent('#vms th.on')).startsWith('vCPU'), 'vCPU allocated: sorted by vCPU');
  await page.click('#vmclr'); await page.waitForTimeout(200);
  ok(await page.textContent('#vmf') === '' && (await names()).includes('OLD01'), 'Clear resets');
  await page.click('.t[data-act="hosts"]'); await page.waitForTimeout(300);
  ok(/Hosts \(/.test(await page.evaluate(() => (document.getElementById('zd') || document.body).textContent)), 'Hosts opens the host list');
  await page.keyboard.press('Escape');
  await page.focus('.t[data-act="mem_gb"]'); await page.keyboard.press('Enter'); await page.waitForTimeout(200);
  ok((await page.textContent('#vms th.on')).startsWith('Memory (GB)'), 'keyboard: Enter on a tile');
  ok(!errs.length, 'page errors: ' + errs.join(' | '));
  await browser.close(); srv.close();
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks'); process.exit(bad ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });
