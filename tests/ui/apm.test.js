// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for apm.html (ManageEngine Applications Manager) after the static build: reachable from the menu, tiles,
// every monitor type with filters (search, type, health, down, unmanaged, databases), tiles filter the list, monitor drawer
// with attributes, Poll now / Maintenance requests, approvals, the not-connected state, the admin connection form, escaping.
// API answers are SYNTHETIC, in the shape engine/integrations/apm-routes.js returns.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node apm.test.js
const http = require('http'), fs = require('fs'), path = require('path'), os = require('os'), cp = require('child_process');
const SRC = path.resolve(__dirname, '../../ui');
let n = 0, bad = 0;
const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const B = fs.mkdtempSync(path.join(os.tmpdir(), 'apmpage-')); fs.mkdirSync(path.join(B, 'vendor'));
fs.readdirSync(SRC).filter((f) => f.endsWith('.html')).forEach((f) => fs.copyFileSync(path.join(SRC, f), path.join(B, f)));
fs.readdirSync(path.join(SRC, 'vendor')).filter((f) => /\.(js|json|css)$/.test(f)).forEach((f) => fs.copyFileSync(path.join(SRC, 'vendor', f), path.join(B, 'vendor', f)));
['zyb-menu.js', 'zyb-dash.js'].forEach((t) => fs.writeFileSync(path.join(B, 'vendor', t), fs.readFileSync(path.join(B, 'vendor/zyb-nav.js'), 'utf8') + '\n' + fs.readFileSync(path.join(B, 'vendor', t), 'utf8')));
cp.execFileSync(process.execPath, [path.join(SRC, 'build-static.js'), B, 't1'], { stdio: 'ignore' });
const now = new Date().toISOString();
const MONS = [
  { id: '10001', name: 'ORCLPRD', type: 'Oracle-DB-server', host: 'db1', health: 'critical', availability: 'up', managed: true, db: true },
  { id: '10002', name: 'Claims portal', type: 'UrlMonitor', host: 'portal', health: 'clear', availability: 'up', managed: true, db: false },
  { id: '10003', name: 'FINDB', type: 'MSSQL-DB-server', host: 'sql1', health: 'warning', availability: 'down', managed: false, db: true },
  { id: '10004', name: '<img src=x onerror=alert(1)>', type: 'Windows', host: 'app7', health: 'clear', availability: 'up', managed: true, db: false }];
const ALS = [{ resource_id: '10001', name: 'ORCLPRD', severity: 'critical', attribute: 'Tablespace USERS', message: 'Tablespace USERS 96% used', time: '2026-10-21 10:00', db: true }];
let CONF = true, ROLE = 'admin'; const POSTS = [];
const status = () => CONF ? { configured: true, ok: true, last_sync: now, monitors: 4, db_monitors: 2, down: 1, unmanaged: 1, alarms: { critical: 1, warning: 0, db: 1 }, pending_actions: 1 } : { configured: false, monitors: 0, db_monitors: 0, down: 0, unmanaged: 0, alarms: { critical: 0, warning: 0, db: 0 }, pending_actions: 0 };
(async () => {
  const srv = http.createServer((q, r) => {
    const u = q.url.split('?')[0], j = (c, o) => { r.writeHead(c, { 'Content-Type': 'application/json' }); r.end(JSON.stringify(o)); };
    if (u.endsWith('whoami.json')) return j(200, { user: 'syed', role: ROLE });
    if (u.startsWith('/api/')) {
      if (q.method === 'POST') { let b = ''; q.on('data', (c) => { b += c; }); q.on('end', () => { POSTS.push({ u, b: JSON.parse(b || '{}') }); j(200, { ok: true, status: 'pending', monitors: 4 }); }); return; }
      const P = '/api/soc/integrations/apm/';
      if (u === P + 'status') return j(200, status());
      if (u === P + 'monitors') return j(200, { items: MONS });
      if (u === P + 'monitors/10001') return j(200, { resource_id: '10001', attributes: [{ name: 'Tablespace USERS used', value: '96', unit: '%', status: 'critical' }] });
      if (u === P + 'alarms') return j(200, { items: ALS });
      if (u === P + 'coverage') return j(200, { both: [{ name: 'ORCLPRD' }], apm_only: [{ name: 'FINDB', type: 'MSSQL-DB-server' }], siem_only: [{ instance: 'HRDB' }] });
      if (u === P + 'actions') return j(200, { items: [{ id: 'APMA-00001', action: 'unmanage', hours: 4, suppress: 'alerts', monitor: 'ORCLPRD', reason: 'patching', requested_by: 'ali', requested_at: now, status: 'pending' }] });
      if (u === P + 'settings') return j(200, { settings: { base_url: 'https://apm:8443', poll_min: 5, enabled: true, fingerprint256: '' }, key: { api_key_set: true, key_fingerprint: 'ab12' } });
      return j(404, { error: 'not in this test' });
    }
    const f = path.join(B, u === '/' ? 'index.html' : u); if (!f.startsWith(B)) { r.writeHead(403); return r.end(); }
    fs.readFile(f, (e, d) => { if (e) { r.writeHead(404); return r.end(); } r.writeHead(200, { 'Content-Type': u.endsWith('.js') ? 'application/javascript' : u.endsWith('.css') ? 'text/css' : 'text/html' }); r.end(d); });
  });
  await new Promise((res) => srv.listen(0, '127.0.0.1', res));
  const base = 'http://127.0.0.1:' + srv.address().port + '/';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  const open = async (pg) => { const p = await browser.newPage({ viewport: { width: 1500, height: 950 } }); p.on('pageerror', (e) => errs.push(e.message)); p.on('dialog', (d) => { errs.push('dialog ' + d.message()); d.dismiss(); }); await p.goto(base + (pg || 'apm.html')); return p; };
  const txt = (p, id) => p.evaluate((i) => (document.getElementById(i) || {}).textContent || '', id);
  const names = (p) => p.evaluate(() => [].map.call(document.querySelectorAll('#mon tr.mr td:first-child b'), (b) => b.textContent));

  // reachable by clicking the menu from another page
  let p = await open('applications.html');
  await p.waitForTimeout(800);
  const link = await p.evaluate(() => { const a = document.querySelector('a[href="apm.html"]'); return a ? a.textContent.trim() : null; });
  ok(/Applications Manager/.test(link || ''), 'menu entry exists: ' + link);
  await p.evaluate(() => document.querySelector('a[href="apm.html"]').click());
  await p.waitForURL(/apm\.html/); await p.click('[data-tab="mo"]'); await p.waitForSelector('#mon tr.mr');
  ok(true, 'menu entry opens the page');

  ok(/Monitors4/.test(await txt(p, 'kp')) && /Down1/.test(await txt(p, 'kp')), 'tiles: ' + (await txt(p, 'kp')).slice(0, 120));
  ok(JSON.stringify(await names(p)) === JSON.stringify(['FINDB', 'ORCLPRD', '<img src=x onerror=alert(1)>', 'Claims portal']), 'every type, down/critical first, escaped: ' + JSON.stringify(await names(p)));
  ok(/UrlMonitor \(1\)/.test(await txt(p, 'ty')), 'type filter lists the types');
  await p.selectOption('#ty', 'UrlMonitor'); ok(JSON.stringify(await names(p)) === '["Claims portal"]', 'filter by type');
  await p.selectOption('#ty', ''); await p.fill('#q', 'sql1'); await p.dispatchEvent('#q', 'input'); ok(JSON.stringify(await names(p)) === '["FINDB"]', 'search by host');
  await p.fill('#q', ''); await p.dispatchEvent('#q', 'input');
  await p.check('#db'); ok((await names(p)).length === 2, 'databases only'); await p.uncheck('#db');
  await p.click('#kp [data-act="tile:crit"]'); ok(JSON.stringify(await names(p)) === '["ORCLPRD"]' && (await p.inputValue('#hl')) === 'critical', 'Critical tile filters');
  await p.click('#kp [data-act="tile:um"]'); ok(JSON.stringify(await names(p)) === '["FINDB"]', 'Unmanaged tile filters');
  await p.click('#kp [data-act="tile:um"]'); ok((await names(p)).length === 4, 'clicking again clears');

  await p.click('#mon tr.mr:has-text("ORCLPRD") td:first-child'); await p.waitForFunction(() => /Tablespace USERS used/.test((document.getElementById('zd-b') || {}).textContent || ''));
  const d = await p.evaluate(() => document.getElementById('zd-b').textContent);
  ok(/Oracle-DB-server/.test(d) && /Tablespace USERS 96% used/.test(d) && /96 %/.test(d), 'drawer: type, alarm, attributes');
  await p.evaluate(() => document.querySelector('#zd-b [data-app="m"]').click()); await p.waitForTimeout(300);
  ok(POSTS.some((x) => /apm\/actions$/.test(x.u) && x.b.action === 'poll' && x.b.resource_id === '10001'), 'Poll now from the drawer');
  await p.keyboard.press('Escape'); await p.waitForTimeout(300);
  await p.click('#mon tr.mr:has-text("Claims portal") [data-apu]'); await p.waitForSelector('#ap-r');
  await p.fill('#ap-r', 'portal release'); await p.click('#ask-ok'); await p.waitForTimeout(300);
  ok(POSTS.some((x) => x.b.action === 'unmanage' && x.b.resource_id === '10002' && x.b.reason === 'portal release' && x.b.hours === 4), 'Maintenance is a request with a reason');

  await p.click('[data-tab="al"]'); ok(/Tablespace USERS 96% used/.test(await txt(p, 'alm')), 'alarms tab');
  await p.click('[data-tab="rq"]'); ok(/APMA-00001/.test(await txt(p, 'act')) && /1 waiting/.test(await txt(p, 'rqc')), 'approvals tab');
  await p.click('[data-tab="cv"]'); ok(/Only on the Database Dashboard: HRDB/.test(await txt(p, 'cov')), 'coverage tab');
  await p.click('[data-tab="st"]'); ok((await p.inputValue('#as-url')) === 'https://apm:8443' && /stored · ab12/.test(await txt(p, 'set')), 'admin connection form, key never shown');
  await p.close();

  CONF = false; ROLE = 'operator'; p = await open(); await p.waitForFunction(() => /not connected/.test(document.getElementById('kp').textContent));
  ok((await names(p)).length === 0 && /Administrators set the connection/.test(await txt(p, 'set')), 'not connected: nothing invented; operator sees no settings');
  ok(await p.evaluate(() => document.getElementById('sync').hidden), 'Read now hidden when not connected');
  await p.close();

  ok(/apm\.html/.test(fs.readFileSync(path.join(SRC, 'install-dashboards.sh'), 'utf8')), 'in the installer');
  ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  await browser.close(); srv.close();
  console.log(`${n - bad}/${n} checks passed`); process.exit(bad ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });
