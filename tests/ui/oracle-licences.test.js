// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for oracle-licences.html against the real IT Asset Management engine (core-licensing + oracle-licences):
// in the Databases menu, licence position, deployments with the hosts they are licensed on (VMware cluster), the core factor
// matched from the Oracle table per CPU, "assumed" when no row matches, a person sets a factor with a reason, the table shown
// with its source, admin rows. Data is SYNTHETIC. Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node oracle-licences.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const ITAM = path.resolve(__dirname, '../../backend/itam'), DASH = path.resolve(__dirname, '../../ui');
const H = require(path.join(ITAM, 'tests/helpers.js'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
let WHO = { user: 'syed', role: 'admin' };
(async () => {
  const e = await H.startApp({ noAi: true });
  const ADM = { user: 'syed', role: 'admin', ip: '' };
  const mk = (o) => e.app.assets.create(Object.assign({ status: 'in_use' }, o), ADM).asset.id;
  const esx1 = mk({ name: 'esx01', type: 'server', os: 'VMware ESXi 8.0', cpu: '2 x Intel Xeon Gold 6338 32-Core', tags: ['esxi-host'] });
  mk({ name: 'esx02', type: 'server', os: 'VMware ESXi 8.0', cpu: '2 x Intel Xeon Gold 6338 32-Core', tags: ['esxi-host'] });
  const vm = mk({ name: 'oravm01', type: 'vm', os: 'Oracle Linux 8', software: [{ name: 'Oracle Database 19c Enterprise Edition', publisher: 'Oracle' }] });
  mk({ name: 'sun-t5', type: 'server', os: 'Solaris 11', cpu: 'SPARC T5 2 sockets, 16 cores each', software: [{ name: 'Oracle Database 19c Enterprise Edition', publisher: 'Oracle' }] });
  mk({ name: 'odd01', type: 'server', os: 'Linux', cpu: 'Hygon C86 7285 2 x 32 cores', software: [{ name: 'Oracle Database 19c', publisher: 'Oracle' }] });
  e.app.store.collection('relationships').put({ id: 'r1', type: 'runs_on', from: vm, to: esx1 });
  const F = e.app.store.collection('core_lic_facts');
  for (const x of e.app.store.collection('assets').all((a) => /^esx/.test(a.name))) F.put({ id: x.id, cluster: 'PROD' });
  require(path.join(ITAM, 'engine/core-licensing')).registerCoreLicensing(e.app.srv, e.app, { noTimer: true });
  const srv = http.createServer((req, res) => {
    const u = req.url.split('?')[0], json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u === '/dashboards/whoami.json') return json(200, WHO);
    if (u.startsWith('/api/itam/')) { const h = Object.assign({}, req.headers, { 'x-sentra-proxy-secret': H.SECRET, 'x-auth-user': WHO.user, 'x-auth-role': WHO.role });
      const up = http.request({ host: '127.0.0.1', port: e.port, method: req.method, path: req.url, headers: h }, (r) => { res.writeHead(r.statusCode, r.headers); r.pipe(res); }); req.pipe(up); return; }
    if (u.startsWith('/api/')) return json(404, {});
    fs.readFile(path.join(DASH, u), (err, d) => { if (err) { res.writeHead(404); return res.end(); } res.writeHead(200, { 'Content-Type': u.endsWith('.js') ? 'application/javascript' : u.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port + '/';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), page = await browser.newPage({ viewport: { width: 1400, height: 950 } }), errs = [];
  page.on('pageerror', (x) => errs.push(x.message));
  const txt = (id) => page.evaluate((i) => document.getElementById(i).textContent, id);
  await page.goto(base + 'databases.html'); await page.waitForTimeout(800);
  ok(await page.evaluate(() => !!document.querySelector('a[href="oracle-licences.html"]')), 'in the Databases menu');
  await page.goto(base + 'oracle-licences.html'); await page.waitForSelector('#hosts tr.cl');
  ok(/Deployments3/.test(await txt('kp')) && /112 needed/.test(await txt('kp')), 'tiles: ' + (await txt('kp')).slice(0, 160));
  ok(/esx01 \(64 cores × 0\.5\)/.test(await txt('dep')) && /esx02 \(64 cores × 0\.5\)/.test(await txt('dep')), 'VM licensed on every host of its cluster');
  ok(/SPARC T3 \/ T4 \/ T5/.test(await txt('hosts')) && /Intel Xeon/.test(await txt('hosts')), 'matched table rows shown');
  ok(/assumed/.test(await page.textContent('#hosts tr.cl:has-text("odd01")')) && /no row matched/.test(await txt('hosts')), 'no match = assumed');
  ok(/shortfall/.test(await txt('pos')) && /2800/.test(await txt('pos')), 'position: shortfall and NUP minimum (112 x 25)');
  // compliance matrix + alerts + the one-page report
  await page.waitForFunction(() => /OVER-UTILISED/.test(document.getElementById('verdict').innerText));
  ok(/none owned/.test(await txt('matrix')) && /none recorded/.test(await txt('matrix')), 'matrix: nothing owned is shown as such: ' + (await txt('matrix')).slice(0, 200));
  ok(!(await page.isHidden('#alc')) && /over-utilised by 112/.test(await txt('alerts')) && /Infrastructure manager/.test(await txt('alerts')), 'alerts: ' + (await txt('alerts')).slice(0, 200));
  // wait for the toast itself: the notes text always contains "e-mailed", so matching that raced the answer
  await page.click('#send'); await page.waitForFunction(() => /Not sent: |Report e-mailed to /.test(document.body.innerText)).catch(() => { /* the check below names what was shown */ });
  { const bt = await page.evaluate(() => document.body.innerText); ok(/Not sent: .+/.test(bt), 'send without a mail relay says why: ' + (bt.match(/Not sent[^\n]*/) || [''])[0]); }
  const rp = await browser.newPage(); rp.on('pageerror', (x) => errs.push(x.message));
  await rp.goto(base + 'oracle-licence-report.html'); await rp.waitForFunction(() => /Compliance matrix/.test(document.getElementById('pg').innerText));
  const rt = await rp.$eval('#pg', (x) => x.innerText);
  ok(/Oracle Licence Compliance/.test(rt) && /OVER-UTILISED/.test(rt) && /Alerts and actions/.test(rt) && /Servers that drive the count/.test(rt) && /No entitlement recorded/.test(rt), 'one-page report: ' + rt.slice(0, 200));
  const hgt = await rp.evaluate(() => { const p = document.getElementById('pg'); return p.scrollHeight; });
  ok(hgt <= 1160, 'fits one A4 page at 96 dpi (' + hgt + ' px)');
  await rp.close();
  await page.click('#hosts tr.cl:has-text("odd01")'); await page.waitForSelector('#cf-ok');
  await page.selectOption('#cf-f', '1'); await page.click('#cf-ok'); await page.waitForTimeout(300);
  ok(await page.isVisible('#cf-ok'), 'no reason: refused (dialog stays)');
  await page.fill('#cf-r', 'Hygon not in the Oracle table - LMS confirmed 1.0'); await page.click('#cf-ok'); await page.waitForTimeout(500);
  ok(/entered/.test(await page.textContent('#hosts tr.cl:has-text("odd01")')) && /144 needed/.test(await txt('kp')), 'a person\'s factor applies: ' + (await txt('kp')).slice(0, 120));
  ok(/processor-core-factor-table/.test(await page.getAttribute('#tsrc', 'href')) && /IBM POWER/.test(await txt('tbl')), 'the table with its source');
  await page.click('#tadd'); await page.waitForSelector('#tt'); await page.fill('#tt', 'hygon | Hygon Dhyana | \\bhygon\\b | 0.5'); await page.click('#tt-ok'); await page.waitForTimeout(500);
  ok(/added by the administrator/.test(await txt('tbl')), 'admin row added');
  await page.fill('#q', 'sparc'); await page.dispatchEvent('#q', 'input'); ok((await page.$$('#dep tbody tr')).length === 1, 'search');
  WHO = { user: 'v', role: 'viewer' }; await page.goto('about:blank'); await page.goto(base + 'oracle-licences.html'); await page.waitForTimeout(800);
  ok(/Operators and administrators/.test(await txt('kp')), 'viewer refused');
  ok(/oracle-licences\.html/.test(fs.readFileSync(path.join(DASH, 'install-dashboards.sh'), 'utf8')), 'installer');
  ok(!errs.length, 'page errors: ' + errs.join(' | '));
  await browser.close(); srv.close(); await e.close();
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks'); process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
