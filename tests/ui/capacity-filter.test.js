// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for capacity.html's consolidated filter: All / VMware / Nutanix, connection, site and cluster. Tiles, tables,
// recommendations and the platform cards follow the filter; a platform card click filters to it; the choice survives a reload.
// Data is SYNTHETIC. Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node capacity-filter.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const DASH = path.resolve(__dirname, '../../ui');
let n = 0, bad = 0;
const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const at = new Date().toISOString();
const cl = (platform, kind, name, o) => Object.assign({ id: name, platform, kind, name, hosts: 2, hosts_up: 2, vms: 10, vms_on: 8, cores: 64, vcpus: 100, mem_gb: 1024, vm_mem_gb: 512, mem_alloc_pct: 50, cpu_used_pct: 30, mem_used_pct: 40, vcpu_ratio: 1.56, usage_reported: true, room: { cpu: 20, mem: 20, limit: 'memory' } }, o || {});
const vm = (pid, platform, cluster, name, power, mem) => ({ id: name, pid, platform, cluster, name, host: 'h', power, vcpus: 2, mem_gb: mem, disk_gb: 40 });
const report = { settings: { vcpu_ratio: 4, cpu_max_pct: 80, mem_max_pct: 85, storage_max_pct: 85, interval_min: 60, n_plus_1: false }, last_run: { at },
  platforms: [{ id: 'vc1', label: 'VC-HQ', kind: 'vcenter', site: 'HQ', at, collected: true }, { id: 'nx1', label: 'PE-HQ', kind: 'nutanix', site: 'HQ', at, collected: true }, { id: 'nx2', label: 'PE-DR', kind: 'nutanix', site: 'DR', at, collected: true }],
  clusters: [cl('VC-HQ', 'vcenter', 'VMW-CL1'), cl('PE-HQ', 'nutanix', 'NTX-HQ', { storage_gb: 20000, storage_used_pct: 50 }), cl('PE-DR', 'nutanix', 'NTX-DR', { storage_gb: 10000, storage_used_pct: 95, vcpu_ratio: 5 })],
  hosts: [{ platform: 'VC-HQ', cluster: 'VMW-CL1', name: 'esx1', state: 'connected' }, { platform: 'PE-HQ', cluster: 'NTX-HQ', name: 'ntx1', state: 'connected' }, { platform: 'PE-DR', cluster: 'NTX-DR', name: 'ntx9', state: 'connected' }],
  datastores: [{ platform: 'VC-HQ', name: 'ds-vmw', capacity_gb: 4000, free_gb: 1000, used_pct: 75, accessible: true }],
  vms: [vm('vc1', 'VC-HQ', 'VMW-CL1', 'vmw-app', 'on', 16), vm('vc1', 'VC-HQ', 'VMW-CL1', 'vmw-old', 'off', 8), vm('nx1', 'PE-HQ', 'NTX-HQ', 'ntx-db', 'on', 64), vm('nx2', 'PE-DR', 'NTX-DR', 'ntx-dr-old', 'off', 32)],
  top_vms: [], vms_off: [], storage_trend: {}, totals: { clusters: 3, hosts: 3, vms: 30, vms_on: 24, cores: 192, vcpus: 300, mem_gb: 3072, vm_mem_gb: 1536, storage_gb: 34000, storage_free_gb: 1000, reclaim_mem_gb: 40, reclaim_disk_gb: 80 } };
const OPR = { at, days: 30, basis: { cpu_target_pct: 70, mem_target_pct: 80, min_samples: 72, under_pct: 90, vcpu_ratio: 4, mem_max_pct: 85 }, platforms: report.platforms,
  clusters: [{ platform: 'VC-HQ', kind: 'vcenter', cluster: 'VMW-CL1', vcpus: 100, cores: 64, vcpu_ratio: 1.56, vcpu_target: 4, cpu: 'ok', vm_mem_gb: 512, mem_gb: 1024, mem_alloc_pct: 50, mem: 'ok' },
    { platform: 'PE-DR', kind: 'nutanix', cluster: 'NTX-DR', vcpus: 320, cores: 64, vcpu_ratio: 5, vcpu_target: 4, cpu: 'over', vm_mem_gb: 1100, mem_gb: 1024, mem_alloc_pct: 107.4, mem: 'over', storage_gb: 10000, disk_prov_gb: 12500, storage_prov_pct: 125, storage: 'over' }],
  hosts: [], datastores: [{ platform: 'VC-HQ', name: 'ds-vmw', capacity_gb: 4000, provisioned_gb: 4400, provisioned_pct: 110, used_pct: 75, storage: 'over' }],
  vms: [{ platform: 'PE-DR', pid: 'nx2', kind: 'nutanix', cluster: 'NTX-DR', id: 'ntx-big', name: 'ntx-big', vcpus: 16, vcpus_to: 8, save_vcpu: 8, cpu_p95: 5, cpu_max: 40, mem_gb: 64, mem_to: 32, save_mem_gb: 32, mem_p95: 10, samples: 400, history_days: 17 },
    { platform: 'VC-HQ', pid: 'vc1', kind: 'vcenter', cluster: 'VMW-CL1', id: 'vmw-big', name: 'vmw-big', vcpus: 8, vcpus_to: 4, save_vcpu: 4, cpu_p95: 3, cpu_max: 20, mem_gb: 16, mem_p95: 70, samples: 300, history_days: 12 }],
  under: [{ platform: 'VC-HQ', pid: 'vc1', cluster: 'VMW-CL1', id: 'vmw-app', name: 'vmw-app', vcpus: 2, cpu_p95: 97, mem_gb: 16, mem_p95: 50, cpu_short: true }], short: [{ platform: 'PE-HQ', cluster: 'NTX-HQ', name: 'ntx-db', samples: 4 }], off: [{ platform: 'PE-DR', cluster: 'NTX-DR', name: 'ntx-dr-old', mem_gb: 32 }] };
report.top_vms = report.vms.filter((v) => v.power === 'on'); report.vms_off = report.vms.filter((v) => v.power !== 'on');
(async () => {
  const srv = http.createServer((req, res) => {
    const u = req.url.split('?')[0], json = (c, o) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(o)); };
    if (u === '/api/itam/virt/capacity') return json(200, report);
    if (u === '/api/itam/virt/capacity/overprovisioning') return json(200, OPR);
    if (u.startsWith('/api/') || u.endsWith('whoami.json')) return json(404, {});
    const f = path.join(DASH, u); if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (e, d) => { if (e) { res.writeHead(404); return res.end(); } res.writeHead(200, { 'Content-Type': u.endsWith('.js') ? 'application/javascript' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), page = await browser.newPage({ viewport: { width: 1400, height: 900 } }), errs = [];
  page.on('pageerror', (e) => errs.push(e.message));
  const base = 'http://127.0.0.1:' + srv.address().port + '/capacity.html';
  await page.goto(base); await page.waitForSelector('#fbar .chip');
  const tile = (i) => page.evaluate((k) => document.querySelectorAll('#tiles .t')[k].querySelector('.v').textContent, i);
  const rows = (id) => page.evaluate((k) => [].map.call(document.querySelectorAll('#' + k + ' tbody tr td:first-child b'), (b) => b.textContent), id);
  ok(/All platforms 3/.test(await page.textContent('#fbar')) && /VMware 1/.test(await page.textContent('#fbar')) && /Nutanix 2/.test(await page.textContent('#fbar')), 'chips with counts');
  ok((await tile(0)) === '3' && (await rows('clusters')).length === 3, 'all: server totals');
  await page.click('[data-fk="nutanix"]');
  ok(JSON.stringify(await rows('clusters')) === '["NTX-HQ","NTX-DR"]' && (await tile(0)) === '2', 'Nutanix only: clusters and hosts tile');
  ok((await tile(1)) === '16', 'VMs running recomputed: ' + await tile(1));
  const sub4 = await page.evaluate(() => document.querySelectorAll('#tiles .t')[4].querySelector('.s').textContent);
  ok(/of 29\.3 TB/.test(sub4), 'storage = the Nutanix clusters\' storage, VMware datastores out: ' + sub4);
  ok(JSON.stringify(await rows('off')) === '["ntx-dr-old"]', 'powered-off VMs filtered');
  ok(!/ds-vmw/.test(await page.textContent('#ds')) && !/VC-HQ/.test(await page.textContent('#plats')), 'VMware datastores and connection hidden');
  ok(/NTX-DR/.test(await page.textContent('#recs')) && !/VMW-CL1/.test(await page.textContent('#recs')), 'recommendations follow the filter');
  await page.selectOption('#f-cl', 'NTX-HQ'); ok(JSON.stringify(await rows('clusters')) === '["NTX-HQ"]' && JSON.stringify(await rows('top')) === '["ntx-db"]', 'cluster filter');
  ok(/Nutanix · cluster NTX-HQ/.test(await page.textContent('#fdesc')), 'filter described');
  await page.click('#f-clr'); ok((await rows('clusters')).length === 3, 'clear');
  await page.click('[data-fk="vmware"]'); ok(JSON.stringify(await rows('clusters')) === '["VMW-CL1"]' && /ds-vmw/.test(await page.textContent('#ds')), 'VMware only');
  await page.click('[data-fk=""]'); await page.click('#plats [data-plat="nx2"]');
  ok(JSON.stringify(await rows('clusters')) === '["NTX-DR"]' && (await page.inputValue('#f-pid')) === 'nx2', 'platform card click filters to that connection');
  await page.reload(); await page.waitForSelector('#fbar .chip');
  ok(JSON.stringify(await rows('clusters')) === '["NTX-DR"]' && /pid=nx2/.test(page.url()), 'survives reload / deep link');
  await page.selectOption('#f-site', 'HQ'); ok((await page.inputValue('#f-pid')) === '' && (await rows('clusters')).length === 2, 'site filter: HQ clusters');
  // over-provisioning report follows the same filter
  await page.click('#f-clr'); await page.waitForSelector('#opvm tbody tr');
  const opr = (id) => page.evaluate((k) => [].map.call(document.querySelectorAll('#' + k + ' tbody tr td:first-child b'), (b) => b.textContent), id);
  ok(JSON.stringify(await opr('opvm')) === '["ntx-big","vmw-big"]' && /12 vCPU/.test(await page.textContent('#opvc')), 'right-size list, all platforms: ' + await page.textContent('#opvc'));
  ok(/Clusters over the vCPU target1/.test(await page.textContent('#opk')) && /Storage over-provisioned2/.test(await page.textContent('#opk')), 'report tiles: ' + await page.textContent('#opk'));
  ok(/125%/.test(await page.textContent('#opcl')) && /110%/.test(await page.textContent('#opds')) && /95th percentile/.test(await page.textContent('#opbasis')), 'cluster + datastore provisioning, basis stated');
  await page.click('[data-fk="nutanix"]');
  ok(JSON.stringify(await opr('opvm')) === '["ntx-big"]' && JSON.stringify(await opr('opcl')) === '["NTX-DR"]' && /cluster table above/.test(await page.textContent('#opds')), 'Nutanix filter applies to the report');
  ok(/1 running VM\(s\) have fewer than 72/.test(await page.textContent('#opshort')), 'short history stated, not oversized');
  await page.click('[data-fk="vmware"]'); ok(/vmw-app/.test(await page.textContent('#opun')), 'short-of-resources list');
  await page.click('#opun tbody tr'); await page.waitForTimeout(400);
  ok(/vmw-app/.test(await page.evaluate(() => (document.getElementById('zd-b') ? document.getElementById('zd') && document.getElementById('zd').textContent : ''))), 'a VM row opens its detail');
  // the over-provisioning tiles are clickable: the cluster ones filter the tables, the others go to their list
  await page.keyboard.press('Escape'); await page.waitForTimeout(300); await page.click('#f-clr', { timeout: 3000 }).catch(() => {}); await page.waitForTimeout(200);
  const opRows = (id) => page.evaluate((id) => [...document.querySelectorAll('#' + id + ' tbody tr td:first-child b')].map((b) => b.textContent), id);
  ok((await page.$$('#opk [data-op]')).length === 6, 'six over-provisioning tiles clickable');
  await page.click('#opk [data-op="cpu"]'); await page.waitForTimeout(200);
  ok(JSON.stringify(await opRows('opcl')) === '["NTX-DR"]' && /clusters over the vCPU target/.test(await page.textContent('#opfl')), 'vCPU tile → only the cluster over target: ' + JSON.stringify(await opRows('opcl')));
  await page.click('#opk [data-op="cpu"]'); await page.waitForTimeout(200);
  ok((await opRows('opcl')).length > 1 && (await page.textContent('#opfl')) === '', 'clicking again clears it');
  await page.click('#opk [data-op="sto"]'); await page.waitForTimeout(200);
  ok(JSON.stringify(await opRows('opds')) === '["ds-vmw"]', 'storage tile → the over-provisioned datastore');
  await page.click('#opall'); await page.waitForTimeout(200); ok((await page.textContent('#opfl')) === '', 'show all');
  await page.click('#opk [data-op="off"]'); await page.waitForTimeout(600);
  ok(await page.evaluate(() => { const r = document.getElementById('off').getBoundingClientRect(); return r.top < window.innerHeight && r.bottom > 0; }), 'Powered off → scrolls to the powered-off VMs');
  ok(!errs.length, 'page errors: ' + errs.join(' | '));
  await browser.close(); srv.close();
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks'); process.exit(bad ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });
