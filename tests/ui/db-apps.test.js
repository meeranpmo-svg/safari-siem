// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for the Databases and Applications menu areas: databases.html against the real IT Asset Management engine
// (db-health with a stub Oracle helper; the SIEM link is absent, so "not reaching the SIEM" is shown honestly), and
// applications.html against a stub in the exact shape of the SIEM's /netops/avail. Checks the menu has both categories,
// the 3-step Add database (script for the DBA, TLS choice, saved sealed), monitored vs found rows, admin-only actions,
// applications with status / redundancy / DR / owners, and grouping servers into an application through the real API calls.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node db-apps.test.js
const http = require('http'), fs = require('fs'), path = require('path'), assert = require('assert/strict');
const ITAM = path.resolve(__dirname, '../../backend/itam'), DASH = path.resolve(__dirname, '../../ui');
const H = require(path.join(ITAM, 'tests/helpers.js'));
let WHO = { user: 'syed', role: 'admin' };

(async () => {
  const e = await H.startApp({ noAi: true });
  const helperCalls = [];
  require(path.join(ITAM, 'engine/db-health')).registerDbHealth(e.app.srv, e.app, { invRun: async (r) => { helperCalls.push(r); return { ok: true, records: [{ kind: 'instance', instance: 'ESS', host: 'eskauat', db_name: 'ESS', status: 'OPEN' }], errors: [] }; } });
  require(path.join(ITAM, 'engine/ownership')).registerOwnership && require(path.join(ITAM, 'engine/ownership')).registerOwnership(e.app.srv, e.app);
  // SIEM availability stub (shape of engine/netops/availability.js view())
  const hosts = [
    { id: 'erp-app1', name: 'ERP-APP1', ip: '10.1.1.11', service: 'ERP', role: 'primary', status: 'online', dr_site: false, availability: { d1: 100, d7: 99.9, d30: 99.8 } },
    { id: 'erp-app2', name: 'ERP-APP2', ip: '10.1.1.12', service: 'ERP', role: 'secondary', status: 'offline', dr_site: false, availability: null },
    { id: 'hr-web01', name: 'HR-WEB01', ip: '10.1.2.5', service: '', role: '', status: 'online', dr_site: false, availability: null },
  ];
  const posts = [];
  const avail = () => ({ summary: { total: 3, online: 2, offline: 1, unknown: 0 }, items: hosts, groups: [
    { key: 'svc:erp', name: 'ERP', inferred: false, critical: true, required: true, members: ['erp-app1', 'erp-app2'], production: 2, production_online: 1, dr: 0, dr_online: 0, ha: true, issues: ['no-redundancy-now', 'no-dr'], status: 'degraded' },
    { key: 'auto:hr-web', name: 'HR-WEB', inferred: true, critical: false, required: true, members: ['hr-web01'], production: 1, production_online: 1, dr: 0, dr_online: 0, ha: false, issues: ['single-server', 'no-dr'], status: 'spof' }] });

  const srv = http.createServer((req, res) => {
    const u = req.url.split('?')[0];
    const json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u === '/dashboards/whoami.json') return json(200, WHO);
    if (u.startsWith('/api/itam/')) {
      const h = Object.assign({}, req.headers, { 'x-sentra-proxy-secret': H.SECRET, 'x-auth-user': WHO.user, 'x-auth-role': WHO.role });
      const up = http.request({ host: '127.0.0.1', port: e.port, method: req.method, path: req.url, headers: h }, (r) => { res.writeHead(r.statusCode, r.headers); r.pipe(res); });
      req.pipe(up); return;
    }
    if (u === '/api/soc/netops/avail') return json(200, avail());
    if (u === '/api/soc/netops/avail/hosts' && req.method === 'POST') { let b = ''; req.on('data', (d) => { b += d; }); req.on('end', () => { const x = JSON.parse(b); posts.push(x); const h = hosts.find((y) => y.id === x.id); if (h && x.service !== undefined) h.service = x.service; json(200, h || {}); }); return; }
    if (u.startsWith('/api/soc/')) return json(404, { error: 'not in this test' });
    if (u === '/') { res.writeHead(200); res.end('home'); return; }
    fs.readFile(path.join(DASH, u), (err, d) => { if (err) { res.writeHead(404); res.end(); return; } res.writeHead(200, { 'Content-Type': u.endsWith('.js') ? 'application/javascript' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port + '/';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch();
  const page = await browser.newPage({ viewport: { width: 1400, height: 900 } }); const errs = [];
  page.on('pageerror', (x) => errs.push(x.message)); page.on('console', (m) => { if (m.type() === 'error' && !/40[34]/.test(m.text())) errs.push(m.text()); });
  let n = 0; const ok = (c, m) => { assert.ok(c, m); n++; };

  // the menu: two main categories with their pages
  const navSrc = fs.readFileSync(path.join(DASH, 'vendor/zyb-nav.js'), 'utf8'), G = JSON.parse(navSrc.match(/(\[\s*\{\s*"id"[\s\S]*?\n\s*\])\s*;/)[1]);
  const pg = (id) => G.find((g) => g.id === id).pages.map((p) => p.h);
  ok(JSON.stringify(pg('db')) === JSON.stringify(['db-morning.html', 'db-dashboard.html', 'databases.html', 'db-servers.html', 'db-health-statement.html', 'db-performance.html', 'db-sessions.html', 'oracle-tuning.html', 'db-connections.html', 'app-route-map.html', 'db-replication.html', 'oracle-licences.html', 'ai-dba.html', 'ai-sql-dba.html']), 'Databases menu, grouped (Database Audit lives in the Audit menu): ' + pg('db'));
  ok(pg('aud').includes('db-audit.html'), 'Database Audit in the Audit menu');
  ok(pg('app')[0] === 'applications.html' && pg('app').includes('ai-app-manager.html'), 'Applications menu: ' + pg('app'));
  ok(!pg('srv').includes('db-performance.html') && !pg('ai').includes('ai-dba.html'), 'moved, not duplicated');

  // Databases: empty → add in three steps
  await page.goto(base + 'databases.html'); await page.waitForSelector('#kk .t');
  ok(/No database yet/.test(await page.innerText('#tbl')), 'empty state explains');
  await page.click('#add'); await page.waitForSelector('#w-sql');
  ok(/CREATE USER zyb_monitor/.test(await page.innerText('#w-sql')), 'Oracle read-only script shown');
  await page.selectOption('#w-eng', 'mssql'); ok((await page.inputValue('#w-port')) === '1433' && /VIEW SERVER STATE/.test(await page.innerText('#w-sql')), 'engine switch: port and script follow');
  await page.selectOption('#w-eng', 'oracle');
  await page.fill('#w-host', '192.168.9.30'); await page.fill('#w-svc', 'ESS'); await page.fill('#w-label', 'Eskauat'); await page.fill('#w-pass', 'Synthetic-Ora-Pass-1'); await page.selectOption('#w-tls', 'require');
  await page.click('#w-save');
  await page.waitForFunction(() => /Eskauat/.test(document.getElementById('tbl').innerText), null, { timeout: 10000 });
  ok(helperCalls.some((c) => c.host === '192.168.9.30' && c.service === 'ESS' && c.tls === 'require'), 'tested over TLS: ' + JSON.stringify(helperCalls.map((c) => [c.host, c.tls])));
  const cred = (await e.req('GET', '/discovery/credentials', { user: 'syed', role: 'admin' })).json.credentials.find((c) => c.kind === 'db_login');
  ok(cred && cred.target.tls === 'require' && !JSON.stringify(cred).includes('Synthetic-Ora-Pass-1'), 'login saved sealed with its TLS mode');
  ok(/TLS/.test(await page.innerText('#tbl')), 'encryption shown in the table');
  await page.click('#run'); await page.waitForTimeout(800);
  ok(/not reaching the SIEM|waiting|healthy/.test(await page.innerText('#tbl')), 'status after a read: ' + (await page.innerText('#tbl')).slice(0, 200));
  // a found database nobody wants: Remove (reason asked) → Removed list → Restore
  e.app.store.collection('disc_devices').put({ id: 'dd_old', ip: '10.9.9.9', hostname: 'oldtestdb', status: 'approved', methods: { db: { at: Date.now() } }, macs: [], ips: ['10.9.9.9'], uids: [], extra: { db_login: { mysql: { credential: 'MY-RO', version: '5.7' } } } });
  await page.click('#refresh'); await page.waitForSelector('[data-rmf="dd_old"]');
  page.once('dialog', (d) => d.accept('old test copy, not used'));
  await page.click('[data-rmf="dd_old"]'); await page.waitForSelector('#rml [data-rst="dd_old"]');
  ok(!/oldtestdb/.test(await page.innerText('#tbl')) && /old test copy, not used/.test(await page.innerText('#rml')), 'found database removed from the inventory with its reason');
  await page.click('[data-rst="dd_old"]'); await page.waitForSelector('[data-rmf="dd_old"]');
  ok(/oldtestdb/.test(await page.innerText('#tbl')) && await page.isHidden('#rmw'), 'restored');
  // operator: no admin buttons
  WHO = { user: 'siva', role: 'operator' }; await page.goto('about:blank'); await page.goto(base + 'databases.html'); await page.waitForSelector('#kk .t');
  ok(!(await page.isVisible('#add')) && !(await page.$('[data-del]')) && !(await page.$('[data-rmf]')), 'operator: view only');

  // Applications
  WHO = { user: 'syed', role: 'admin' }; await page.goto(base + 'applications.html'); await page.waitForSelector('#kk .t');
  const tb = await page.innerText('#tbl');
  ok(/ERP/.test(tb) && /degraded/i.test(tb) && /HR-WEB/.test(tb) && /guessed/i.test(tb) && /single server/i.test(tb), 'applications listed: ' + tb.slice(0, 300));
  await page.click('[data-f="spof"]'); ok((await page.$$('#tbl tbody tr')).length === 1, 'tile filters');
  await page.click('[data-f=""]');
  await page.click('tr[data-app="auto:hr-web"]'); await page.waitForSelector('[data-confirm]');
  await page.click('[data-confirm]'); await page.waitForTimeout(500);
  ok(posts.some((p) => p.id === 'hr-web01' && p.service === 'HR-WEB'), 'confirm writes the application name to its servers');
  await page.click('#new'); await page.waitForSelector('#p-name');
  await page.fill('#p-name', 'Payroll'); await page.check('#p-list input[value="hr-web01"]'); await page.click('#p-ok'); await page.waitForTimeout(500);
  ok(posts.some((p) => p.id === 'hr-web01' && p.service === 'Payroll'), 'new application = servers grouped under its name');
  ok(errs.length === 0, 'errors: ' + errs.join(' | '));
  console.log('OK', n, 'checks');
  await browser.close(); srv.close(); await e.close(); process.exit(0);
})().catch((x) => { console.error('FAIL', x.message, (x.stack || '').split('\n').find((l) => /db-apps\.test/.test(l))); process.exit(1); });
