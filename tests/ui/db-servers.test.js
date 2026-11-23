// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for db-servers.html against the REAL IT Asset Management engine (db-servers.js) with a stub SSH helper:
// servers with their asset (or "not in asset register" + the same-name suggestion), OS readings, fullest file system,
// Oracle instances, findings; the detail panel (file systems, oratab vs running); an administrator links a server to its
// asset through the real route (audited) and the row updates; Read now goes through the real pass; viewer refused.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node db-servers.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const ITAM = path.resolve(__dirname, '../../backend/itam'), DASH = path.resolve(__dirname, '../../ui');
const H = require(path.join(ITAM, 'tests/helpers.js'));
let WHO = { user: 'syed', role: 'admin' };
let n = 0, bad = 0;
const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };

(async () => {
  const e = await H.startApp({ noAi: true });
  const st = e.app.store;
  st.collection('assets').put({ id: 'as_ess', type: 'server', name: 'ESKAUAT', asset_tag: 'SENTRA-SRV-0042', status: 'in_use', owner: 'DBA team', mgmt_ip: '192.168.9.30' });
  st.collection('assets').put({ id: 'as_hr', type: 'server', name: 'hrdb01', asset_tag: 'SENTRA-SRV-0077', status: 'in_use', serial: 'CZJ1234' });
  st.collection('disc_devices').put({ id: 'dev1', ip: '192.168.9.30', hostname: 'eskauat', extra: { unix_login: { credential: 'linux-ro' } } });
  st.collection('disc_trust').put({ id: 'ssh:192.168.9.30:22', kind: 'ssh', ip: '192.168.9.30', port: 22, fp: 'b'.repeat(64), state: 'trusted' });
  const creds = [{ id: 'ssh1', kind: 'ssh', label: 'linux-ro', target: { port: 22 }, _s: { username: 'zybread', password: 'Synthetic-1' } }];
  const vault = { list: () => creds, get: (id) => creds.find((c) => c.id === id), open: (id) => { const c = creds.find((x) => x.id === id); return { target: c.target, secret: Object.assign({}, c._s), release() {} }; } };
  const server = { os: 'Oracle Linux Server 8.8', kernel: 'Linux 5.4', uptime_s: 864000, load1: 3, load5: 2.5, load15: 2, ncpu: 8, mem_total_mb: 65536, mem_avail_mb: 20000, swap_total_mb: 8192, swap_used_mb: 100,
    hugepages_total: 10240, hugepages_free: 200, thp: 'never', filesystems: [{ fs: '/dev/sdb1', mount: '/u02', size_kb: 1048576000, used_kb: 1006632960, avail_kb: 41943040, used_pct: 96 }, { fs: '/dev/root', mount: '/', size_kb: 52428800, used_kb: 10485760, avail_kb: 41943040, used_pct: 20 }],
    inodes: [], oracle: { pmon: ['ESS'], asm: [], listeners: ['LISTENER'], mrp: false, clusterware: false }, oratab: [{ sid: 'ESS', home: '/u01/app/oracle/19c', autostart: true }], ntp_synced: true, ntp_offset_ms: 0.2, last_patch: '2026-09-01', top: [] };
  const helperCalls = [];
  const dbHealth = { targets: () => ({ list: [{ ip: '192.168.9.30', host: 'eskauat', instance: 'ESS', device_id: 'dev1' }, { ip: '10.0.0.9', host: 'hrdb01', instance: 'HRP', reg_id: 'odb_1' }] }), push: async (r) => r.length };
  require(path.join(ITAM, 'engine/db-servers')).registerDbServers(e.app.srv, e.app, { discovery: { vault }, dbHealth, invRun: async (r) => { helperCalls.push(r); return { ok: true, server }; }, noTimer: true });

  const srv = http.createServer((req, res) => {
    const u = req.url.split('?')[0];
    const json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u === '/dashboards/whoami.json') return json(200, WHO);
    if (u.startsWith('/api/itam/')) {
      const h = Object.assign({}, req.headers, { 'x-sentra-proxy-secret': H.SECRET, 'x-auth-user': WHO.user, 'x-auth-role': WHO.role });
      const up = http.request({ host: '127.0.0.1', port: e.port, method: req.method, path: req.url, headers: h }, (r) => { res.writeHead(r.statusCode, r.headers); r.pipe(res); });
      req.pipe(up); return;
    }
    if (u.startsWith('/api/')) return json(404, { error: 'not in this test' });
    fs.readFile(path.join(DASH, u), (err, d) => { if (err) { res.writeHead(404); res.end(); return; } res.writeHead(200, { 'Content-Type': u.endsWith('.js') ? 'application/javascript' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port + '/';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch();
  const page = await browser.newPage({ viewport: { width: 1400, height: 900 } }); const errs = [];
  page.on('pageerror', (x) => errs.push(x.message));
  page.on('console', (m) => { if (m.type() === 'error' && !/40[34]/.test(m.text())) errs.push(m.text()); });

  await page.goto(base + 'db-servers.html'); await page.waitForSelector('#srv table');
  let rows = await page.$$eval('#srv tbody tr', (T) => T.map((r) => r.innerText.replace(/\s+/g, ' ')));
  ok(rows.length === 2, 'two servers: ' + rows.length);
  ok(/SENTRA-SRV-0042/.test(rows[0]) && /not read/.test(rows[0]), 'eskauat: asset by management IP, not read yet: ' + rows[0]);
  ok(/not in asset register/.test(rows[1]) && /same name: hrdb01/.test(rows[1]), 'hrdb01: not registered, suggestion shown: ' + rows[1]);
  const kk = await page.$eval('#kk', (x) => x.innerText.replace(/\s+/g, ' '));
  ok(/In the asset register 1 \/ 2/i.test(kk), 'tile: 1 of 2 aligned: ' + kk);

  // read now (real pass): only the host with a trusted key + login is read
  await page.click('#run');
  await page.waitForFunction(() => /Oracle Linux/.test(document.querySelector('#srv').innerText));
  ok(helperCalls.length === 1 && helperCalls[0].op === 'ssh_health' && helperCalls[0].host === '192.168.9.30' && helperCalls[0].fp === 'b'.repeat(64), 'only the trusted host was read: ' + JSON.stringify(helperCalls.map((c) => c.host)));
  rows = await page.$$eval('#srv tbody tr', (T) => T.map((r) => r.innerText.replace(/\s+/g, ' ')));
  ok(/2\.5 \/ 8 CPU/.test(rows[0]) && /\/u02/.test(rows[0]) && /96%/.test(rows[0]) && /ESS/.test(rows[0]) && /LISTENER/.test(rows[0]) && /synced/.test(rows[0]), 'readings in the row: ' + rows[0]);
  const find = await page.$eval('#find', (x) => x.innerText);
  ok(/\/u02 96% full \(Oracle file system\)/.test(find), 'Oracle file system finding');
  ok(/hrdb01: operating system not read/.test(find) && /hrdb01: not in the IT asset register/.test(find), 'not read + not registered findings for hrdb01');

  // detail panel + link hrdb01 to its asset
  await page.click('#srv tbody tr:nth-child(2)');
  await page.waitForSelector('#zd-b [data-link]');
  await page.click('#zd-b [data-link="as_hr"]');
  await page.waitForFunction(() => /SENTRA-SRV-0077/.test(document.querySelector('#srv').innerText));
  ok(st.collection('db_server_links').get('10.0.0.9').asset_id === 'as_hr', 'link stored');
  ok(st.auditTail(20, (x) => x.action === 'db.servers.link').length === 1, 'link audited');
  const dt = await page.$eval('#zd-b', (x) => x.innerText);
  ok(/linked by syed/.test(dt), 'panel shows who linked it: ' + dt.slice(0, 200));
  // eskauat detail: file systems + oratab vs running
  await page.click('#zd .zd-back').catch(() => {});
  await page.click('#srv tbody tr:nth-child(1)'); await page.waitForFunction(() => /oratab entry/i.test((document.querySelector('#zd-b') || {}).innerText || ''));
  const d1 = await page.$eval('#zd-b', (x) => x.innerText);
  ok(/\/u02/.test(d1) && /running/i.test(d1) && /Oracle Linux Server 8\.8/.test(d1), 'detail: file systems, oratab, OS');

  // viewer: refused
  WHO = { user: 'v', role: 'viewer' };
  await page.goto(base + 'db-servers.html'); await page.waitForSelector('#srv .err');
  ok(/Operators and administrators only/.test(await page.$eval('#srv', (x) => x.innerText)), 'viewer refused');

  ok(!errs.length, 'page errors: ' + errs.join(' | '));
  await browser.close(); srv.close(); await e.close();
  console.log(bad ? 'FAILED ' + bad + ' of ' + n : 'OK ' + n + ' checks'); process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
