// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for backup.html: Edit on an existing backup system offers the Type select with its current type chosen, so a
// NetBackup primary saved as Cohesity can be corrected; the save sends the new type with the new secret.
// Data is SYNTHETIC. Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node backup-edit.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const DASH = path.resolve(__dirname, '../../ui');
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const PLAT = { id: 'bp1', kind: 'cohesity', label: 'NBU Primary', base_url: 'https://asbackup.example/webui', credentials_set: true, last_sync: { at: new Date().toISOString(), ok: false, error: 'GET /irisservices/api/v1/public/protectionRuns answered HTTP 404' } };
let posted = null;
(async () => {
  const srv = http.createServer((q, r) => { const u = q.url.split('?')[0], j = (c, o) => { r.writeHead(c, { 'Content-Type': 'application/json' }); r.end(JSON.stringify(o)); };
    if (u.endsWith('whoami.json')) return j(200, { user: 'syed', role: 'admin' });
    if (u === '/api/itam/backup' && q.method === 'GET') return j(200, { settings: { target_hours: 26, window_days: 7 }, kinds: { netbackup: 'Veritas NetBackup', veeam: 'Veeam Backup & Replication', cohesity: 'Cohesity' }, platforms: [PLAT], assets: [], items: [], unmatched: [{ name: '0579b919-6ecb-48ad-98f3-aab30b8a8132_NTX-ASI-CLS-HO-01', vm_uuid: '0579b919-6ecb-48ad-98f3-aab30b8a8132', vm_name: 'EXCH-HQ01', vm_cluster: 'NTX-ASI-CLS-HO-01', platform: 'NBU Primary', job: 'Nutanix_Exchange', last_success: new Date().toISOString(), last_status: 'success' }], vm_names: { by_uuid: 150, resolved: 140 }, failed_jobs: [], summary: { coverage_pct: null, failed: 0, none: 0, stale: 0, protected: 0, assets: 0, failed_jobs_24h: 0 } });
    if (u === '/api/itam/backup/platforms' && q.method === 'POST') { let b = ''; q.on('data', (d) => { b += d; }); q.on('end', () => { posted = JSON.parse(b); j(200, { platforms: [Object.assign({}, PLAT, { kind: posted.kind })], items: [] }); }); return; }
    if (u.startsWith('/api/')) return j(404, {});
    fs.readFile(path.join(DASH, u), (e, d) => { if (e) { r.writeHead(404); return r.end(); } r.writeHead(200, { 'Content-Type': u.endsWith('.js') ? 'application/javascript' : u.endsWith('.css') ? 'text/css' : 'text/html' }); r.end(d); }); });
  await new Promise((res) => srv.listen(0, '127.0.0.1', res));
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), p = await browser.newPage({ viewport: { width: 1500, height: 900 } }), errs = [];
  p.on('pageerror', (e) => errs.push(e.message));
  await p.goto('http://127.0.0.1:' + srv.address().port + '/backup.html'); await p.waitForSelector('[data-tab="plat"]'); await p.click('[data-tab="plat"]');
  const un = await p.evaluate(() => document.getElementById('un').textContent + ' | ' + document.getElementById('unnote').textContent);
  ok(/EXCH-HQ01/.test(un) && /0579b919/.test(un) && /NTX-ASI-CLS-HO-01/.test(un) && /140 were named/.test(un), 'a VM backed up under its UUID shows its name: ' + un.slice(0, 200));
  await p.click('[data-pa="edit"]'); await p.waitForSelector('#f-k');
  ok(await p.evaluate(() => document.getElementById('f-k').value) === 'cohesity', 'Edit shows the Type select with the current type');
  await p.selectOption('#f-k', 'netbackup'); await p.fill('#f-key', 'nb-key');
  await p.click('#f-go'); await p.waitForTimeout(500);
  ok(posted && posted.id === 'bp1' && posted.kind === 'netbackup' && posted.api_key === 'nb-key', 'save sends the new type with its secret: ' + JSON.stringify(posted && { id: posted.id, kind: posted.kind }));
  ok(!errs.length, 'page errors: ' + errs.join(' | '));
  await browser.close(); srv.close();
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks'); process.exit(bad ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });
