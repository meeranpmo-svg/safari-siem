// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for business-services.html against the REAL IT Asset Management engine (service-map.js) with stub SSH
// helper and network probes: every server with what runs on it (confirmed chips; port-only hidden until asked), the tiles
// filter, the kind chips filter, search, the detail panel (evidence per service, who could look and why not), an
// administrator confirms business-critical through the real route (asset tagged, audited), "not critical" needs a reason,
// the menu entry, and Look again now runs the real pass. All names and addresses are SYNTHETIC.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node business-services.test.js
const http = require('http'), fs = require('fs'), path = require('path'), vm = require('vm');
const ITAM = path.resolve(__dirname, '../../backend/itam'), DASH = path.resolve(__dirname, '../../ui');
const H = require(path.join(ITAM, 'tests/helpers.js'));
const scopes = require(path.join(ITAM, 'engine/discovery/scopes'));
let WHO = { user: 'syed', role: 'admin' };
let n = 0, bad = 0;
const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };

(async () => {
  // the menu lists the page once, under Applications & Business Services
  const w = { ZYB_ORG: require('../../brand/index') }; vm.runInNewContext(fs.readFileSync(path.join(DASH, 'vendor/zyb-nav.js'), 'utf8'), { window: w });
  const hits = w.ZYB_NAV.filter((a) => a.pages.some((p) => p.h === 'business-services.html'));
  ok(hits.length === 1 && hits[0].id === 'app', 'menu: once, in Applications & Business Services');

  const e = await H.startApp({ noAi: true });
  const st = e.app.store;
  st.collection('assets').put({ id: 'as_erp', type: 'server', name: 'ERPDB01', asset_tag: 'SENTRA-SRV-0101', status: 'in_use', mgmt_ip: '10.20.0.11' });
  st.collection('assets').put({ id: 'as_web', type: 'vm', name: 'WEBAPP01', asset_tag: 'SENTRA-VM-0201', status: 'in_use', mgmt_ip: '10.20.0.21', software: [{ name: 'Microsoft SQL Server 2019 (64-bit)', version: '15.0.2000.5' }] });
  st.collection('disc_devices').put({ id: 'd1', ip: '10.20.0.11', type: 'server', hostname: 'erpdb01', asset_id: 'as_erp', open_ports: [22, 1521], extra: { db: [{ engine: 'oracle', port: 1521 }], unix_login: { credential: 'linux-ro' } } });
  st.collection('disc_devices').put({ id: 'd3', ip: '10.20.0.41', type: 'server', hostname: 'quiet41', extra: {} });
  st.collection('disc_trust').put({ id: 'ssh:10.20.0.11:22', kind: 'ssh', ip: '10.20.0.11', port: 22, fp: 'b'.repeat(64), state: 'trusted' });
  const sc = { id: 'sc1', name: 'Servers VLAN', targets: ['10.20.0.0/24'], exclusions: [], allow_public: false };
  sc.checklist = { completed_at: '2026-10-01T00:00:00Z', targets_fp: scopes.targetsFingerprint(sc) };
  st.collection('disc_scopes').put(sc);
  const creds = [{ id: 'ssh1', kind: 'ssh', label: 'linux-ro', target: { port: 22 }, _s: { username: 'zybread', password: 'Synthetic-1' } }];
  const vault = { list: () => creds, open: (id) => { const c = creds.find((x) => x.id === id); return { target: c.target, secret: Object.assign({}, c._s), release() {} }; } };
  const calls = [];
  const facts = { hostname: 'erpdb01', os: 'Linux 5.4 x86_64\nPRETTY_NAME="Oracle Linux Server 8.8"', ps: 'oracle ora_pmon_ERPPRD ora_pmon_ERPPRD\noracle tnslsnr /u01/bin/tnslsnr LISTENER\ntomcat java /usr/bin/java org.apache.catalina.startup.Bootstrap start', listen: 'LISTEN 0 128 0.0.0.0:1521 0.0.0.0:*\nLISTEN 0 100 0.0.0.0:8080 0.0.0.0:*', units: '', oratab: 'ERPPRD:/u01/19c:Y' };
  const probe = {
    tcp: async (ip, p) => (ip === '10.20.0.21' ? [80, 443, 1433, 445, 3389].includes(p) : false),
    http: async (ip, p, t) => (ip === '10.20.0.21' ? { status: 200, server: 'Microsoft-IIS/10.0', powered: 'ASP.NET', port: p, tls: t } : null),
    sql: async (ip) => (ip === '10.20.0.21' ? [{ instance: 'APPS', version: '15.0.4000.1', tcp: 1433 }] : []),
  };
  require(path.join(ITAM, 'engine/service-map')).registerServiceMap(e.app.srv, e.app, { discovery: { vault, trust: { see() {} } }, dbHealth: { targets: () => ({ list: [] }) },
    invRun: async (r) => { calls.push(r); return { ok: true, facts }; }, probe, noTimer: true });

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
    fs.readFile(path.join(DASH, u.replace(/^\/dashboards\//, '/')), (err, d) => { if (err) { res.writeHead(404); res.end(); return; } res.writeHead(200, { 'Content-Type': u.endsWith('.js') ? 'application/javascript' : u.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port + '/';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch();
  const page = await browser.newPage({ viewport: { width: 1400, height: 900 } }); const errs = [];
  page.on('pageerror', (x) => errs.push(x.message));
  page.on('console', (m) => { if (m.type() === 'error' && !/40[034]/.test(m.text())) errs.push(m.text()); });
  const txt = (s) => page.$eval(s, (x) => x.innerText.replace(/\s+/g, ' '));
  const rows = () => page.$$eval('#srv tbody tr', (T) => T.map((r) => r.innerText.replace(/\s+/g, ' ')));

  await page.goto(base + 'business-services.html?standalone=1'); await page.waitForSelector('#srv table');
  let R = await rows();
  ok(R.length === 1 && /WEBAPP01|SENTRA-VM-0201/.test(R[0]) && /Microsoft SQL Server/.test(R[0]), 'before a look: the installed SQL Server is confirmed; a port-only Oracle listener and quiet41 are hidden: ' + JSON.stringify(R));
  await page.check('#pos'); R = await rows();
  ok(R.length === 2 && /erpdb01/i.test(R[0]) && /Oracle Database/.test(R[0]), 'the Oracle listener shows as possible on request: ' + JSON.stringify(R));
  await page.uncheck('#pos');

  // look again now (real pass)
  await page.click('#run');
  await page.waitForFunction(() => /Microsoft IIS/.test(document.querySelector('#srv').innerText));
  ok(calls.length === 1 && calls[0].op === 'ssh_services' && calls[0].fp === 'b'.repeat(64), 'SSH only to the trusted host: ' + calls.length);
  R = await rows();
  ok(/Oracle Database ERPPRD/.test(R[0]) && /Apache Tomcat/.test(R[0]) && /proposed/.test(R[0]), 'erpdb01: Oracle with its instance, Tomcat, proposed: ' + R[0]);
  ok(/Microsoft IIS 10\.0/.test(R[1]) && /Microsoft SQL Server APPS/.test(R[1]) && !/Remote Desktop/.test(R[1]), 'webapp01: IIS + SQL instance, remote access hidden: ' + R[1]);
  const kk = await txt('#kk');
  ok(/Oracle Database 1/.test(kk) && /SQL Server 1/.test(kk) && /IIS 1/.test(kk) && /Awaiting decision 2/.test(kk), 'tiles: ' + kk);
  await page.check('#pos'); R = await rows();
  ok(/Remote Desktop/.test(R[1]), 'possible / remote access on request');
  await page.uncheck('#pos');

  // tile filter, kind chip, search
  await page.click('#kk [data-tile="oracle"]'); R = await rows();
  ok(R.length === 1 && /erpdb01/i.test(R[0]), 'Oracle tile filters: ' + R.length);
  await page.click('#kk [data-tile="oracle"]');
  await page.click('#chips [data-kind="web"]'); R = await rows();
  ok(R.length === 1 && /IIS/.test(R[0]), 'Web server chip filters: ' + R.length);
  await page.click('#chips [data-kind=""]');
  await page.fill('#q', 'APPS'); R = await rows();
  ok(R.length === 1 && /WEBAPP01|SENTRA-VM-0201/.test(R[0]), 'search finds an instance name');
  await page.fill('#q', '');
  const find = await txt('#find');
  ok(/Microsoft SQL Server on .* is not monitored/.test(find) && /business-critical not confirmed/.test(find), 'findings: ' + find.slice(0, 300));

  // insights (vendor/zyb-bizsvc.js): ranked decision queue with points, single copies, stack mix, a link fills the search
  await page.waitForFunction(() => /decisions taken \(0 of 2\)/.test((document.getElementById('bizi') || {}).textContent || ''), null, { timeout: 15000 }).catch(() => {});
  const bi = await txt('#bizi');
  ok(/decisions taken \(0 of 2\)/.test(bi), 'insights: decisions ring 0 of 2: ' + bi.slice(0, 200));
  const dq = await page.$$eval('#bizi ol li', (L) => L.map((l) => l.innerText));
  ok(dq.length === 2 && /erpdb01/i.test(dq[0]) && /Oracle Database\) \+30/.test(dq[0]) && /\+10/.test(dq[0]), 'insights: queue ranked with its points: ' + JSON.stringify(dq));
  ok(/Only one copy[\s\S]*Oracle Database/.test(bi) && /Stack mix/.test(bi), 'insights: single copies and stack mix');
  await page.click('#bizi [data-bq="Oracle Database"]'); R = await rows();
  ok((await page.$eval('#q', (x) => x.value)) === 'Oracle Database' && R.length === 1 && /erpdb01/i.test(R[0]), 'insights: a link fills the search and filters');
  await page.fill('#q', '');
  // detail + not critical needs a reason + confirm
  await page.click('#srv tbody tr:nth-child(1)');
  await page.waitForSelector('#zd-b #dcrit');
  const dt = await page.$eval('#zd-b', (x) => x.innerText);
  ok(/ora_pmon|oratab: ERPPRD|process/.test(dt) && /Who could look/i.test(dt) && /read with linux-ro/.test(dt), 'detail: evidence + coverage: ' + dt.slice(0, 400));
  await page.click('#zd-b #dnot');
  await page.waitForFunction(() => /reason/i.test(document.body.innerText.slice(-400)));
  ok(!st.collection('svc_decisions').get('10.20.0.11'), 'not critical without a reason is refused');
  await page.click('#zd-b #dcrit');
  await page.waitForFunction(() => /business-critical/.test((document.querySelector('#srv tbody tr') || {}).innerText || '') && !/proposed/.test(document.querySelector('#srv tbody tr').innerText));
  const a = st.collection('assets').get('as_erp');
  ok(a.tags.includes('business-critical') && a.tags.includes('svc:oracle') && a.tags.includes('svc:tomcat'), 'asset tagged: ' + JSON.stringify(a.tags));
  ok(st.auditTail(30, (x) => x.action === 'service_map.decide').length === 1, 'decision audited');

  // a viewer sees it but cannot decide or run
  WHO = { user: 'viewer.one', role: 'viewer' };
  await page.goto(base + 'business-services.html?standalone=1'); await page.waitForSelector('#srv table');
  ok(await page.$eval('#run', (b) => b.hidden), 'viewer: no Look again');
  await page.click('#srv tbody tr:nth-child(2)'); await page.waitForSelector('#zd-b');
  ok(!(await page.$('#zd-b #dcrit')), 'viewer: no decision buttons');
  await page.keyboard.press('Escape');
  ok(await page.waitForFunction(() => /decisions taken \(1 of 2\)/.test(document.getElementById('bizi').textContent)).then(() => true, () => false), 'insights: the decision counts');

  ok(!errs.length, 'page errors: ' + errs.join(' | '));
  await browser.close(); srv.close(); await e.close();
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks'); process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
