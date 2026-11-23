// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test: DR replication status on nutanix-vms.html. Each VM shows its protection domain's state (within RPO, behind RPO,
// no DR copy, not protected, not reported - with the reason as the tooltip); the five DR tiles count them and filter the list;
// the DR column sorts the worst first; hostile names stay text. Data is SYNTHETIC.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node nutanix-vms-dr.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const DASH = path.resolve(__dirname, '../../ui');
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const at = new Date().toISOString();
const vm = (id, name, platform) => ({ id, pid: platform === 'PE' ? 'p1' : 'p2', platform, kind: 'nutanix', cluster: 'CL', name, host: 'NTNX-A', power: 'on', vcpus: 2, mem_gb: 4, ips: [], macs: [] });
const VMS = [vm('v1', 'APP01', 'PE'), vm('v2', 'DB01', 'PE'), vm('v3', 'FILE01', 'PE'), vm('v4', 'TEST<img src=x onerror=alert(1)>', 'PE'), vm('v5', 'BRANCH01', 'PE2')];
const dr = { sites: [{ platform: 'PE', read: true, read_errors: [], unprotected_vms: ['TEST<img src=x onerror=alert(1)>'], leap: null, protection_domains: [
  { name: 'PD-APP', status: 'ok', why: 'last replicated copy 20 min ago, within RPO 60 min', rpo_min: 60, age_min: 20, vms: ['app01'], remote_sites: ['DR-SITE'] },
  { name: 'PD-DB', status: 'critical', why: 'last replicated copy 400 min ago, RPO 60 min (more than 4x)', rpo_min: 60, age_min: 400, vms: ['DB01'], remote_sites: ['DR-SITE'] },
  { name: 'PD-FILE', status: 'no-remote', why: 'snapshots stay on this cluster only - no remote site, so there is no DR copy', rpo_min: 60, age_min: 30, vms: ['FILE01'], remote_sites: [] }] },
  { platform: 'PE2', read: false, read_errors: ['protection domains: HTTP 403'], protection_domains: [], unprotected_vms: null, leap: null }] };
const report = { settings: {}, last_run: { at }, platforms: [{ id: 'p1', label: 'PE', kind: 'nutanix', at, collected: true, credentials_set: true, usage: true }, { id: 'p2', label: 'PE2', kind: 'nutanix', at, collected: true, credentials_set: true, usage: true }],
  clusters: [{ id: 'c1', platform: 'PE', kind: 'nutanix', name: 'CL' }], hosts: [], datastores: [], vms: VMS, dr };
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
  const browser = await chromium.launch(), page = await browser.newPage({ viewport: { width: 1600, height: 1000 } }), errs = [];
  page.on('pageerror', (e) => errs.push(e.message)); page.on('dialog', (d) => { errs.push('dialog'); d.dismiss(); });
  try {
    await page.goto('http://127.0.0.1:' + srv.address().port + '/nutanix-vms.html'); await page.waitForSelector('#vms tr.vr');
    const names = () => page.evaluate(() => [].map.call(document.querySelectorAll('#vms tr.vr'), (tr) => tr.children[0].textContent));
    const drOfRow = (nm) => page.evaluate((nm) => { const tr = [].find.call(document.querySelectorAll('#vms tr.vr'), (r) => r.children[0].textContent === nm); return tr ? tr.lastElementChild.textContent : null; }, nm);
    const kt = (await page.textContent('#drk')).replace(/\s+/g, ' ');
    ok(/Replicating within RPO\s*1/.test(kt) && /Behind RPO\s*1/.test(kt) && /No DR copy\s*1/.test(kt) && /Not protected\s*1/.test(kt) && /DR not reported\s*1/.test(kt), 'DR tiles count each state: ' + kt);
    ok(/Replicating within RPO/.test(await drOfRow('APP01')) && /PD-APP · 20 min ago/.test(await drOfRow('APP01')), 'APP01: within RPO, case-insensitive name match');
    ok(/Behind RPO/.test(await drOfRow('DB01')) && /No DR copy/.test(await drOfRow('FILE01')) && /DR not reported/.test(await drOfRow('BRANCH01')), 'DB01 behind, FILE01 no copy, BRANCH01 not reported');
    const tip = await page.evaluate(() => { const tr = [].find.call(document.querySelectorAll('#vms tr.vr'), (r) => r.children[0].textContent === 'BRANCH01'); return tr.lastElementChild.querySelector('.pill').title; });
    ok(/not read from PE2 \(protection domains: HTTP 403\)/.test(tip), 'the reason is the tooltip: ' + tip);
    ok(!(await page.$('#vms img')) && /Not protected/.test(await drOfRow('TEST<img src=x onerror=alert(1)>')), 'hostile name is text, and it is the unprotected VM');
    await page.click('.t[data-act="dr:late"]'); await page.waitForTimeout(200);
    ok(JSON.stringify(await names()) === '["DB01"]' && /DR: behind RPO/.test(await page.textContent('#vmf')), 'Behind RPO tile filters the list');
    await page.click('.t[data-act="dr:late"]'); await page.waitForTimeout(200);
    ok((await names()).length === 5, 'clicking again clears it');
    await page.click('#vms th[data-so="dr"]'); await page.waitForTimeout(200);
    ok((await names())[0] === 'DB01', 'DR column sorts the worst first: ' + (await names()).join(','));
    ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  } finally { await browser.close(); srv.close(); }
  console.log(bad ? 'FAILED ' + bad + '/' + n + ' checks' : 'OK ' + n + '/' + n + ' checks'); process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
