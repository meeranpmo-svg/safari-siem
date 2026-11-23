// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for Scan Coverage Assurance (dashboards/server/scan-assurance.html, vendor/zyb-scanassure.js) - setup shared with the test for the VAPT Workflow (dashboards/server/vapt-workflow.html, vendor/zyb-vaptwf.js) and the Network Assistant on
// Vulnerability Scans (vendor/zyb-vulnscan.js) against the REAL ITAM engine, SYNTHETIC data only: the scope form arrives filled from
// IP Address Management (planned subnets, fragile devices under "never scanned"); the scan request form arrives filled with the best
// proposal and another proposal can be picked; a new engagement takes its targets from the ticked subnets; the engagement is clicked
// through authorise -> approve by another person -> finding -> testing complete -> validate -> assign -> claim fixed -> independent
// retest -> final report -> issue -> sign-off by a person who did not write it; a hostile finding title stays text; a viewer sees counts
// only; the page is in the menu and the install list.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node scan-assurance.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const ITAM = path.join(__dirname, '..', '..', 'backend', 'itam'), DASH = path.join(__dirname, '..', '..', 'ui');
const H = require(path.join(ITAM, 'tests', 'helpers'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const XSS = '<img src=x onerror=alert(1)>';

(async () => {
  const e = await H.startApp({ noAi: true });
  require(path.join(ITAM, 'engine/duty')).registerDuty(e.app.srv, e.app, { noTimer: true, python: process.env.PYTHON || 'python3' });
  const c = (x) => e.app.store.collection(x), ADM = { user: 'syed', role: 'admin' };
  for (const s of [{ cidr: '10.0.5.0/24', name: 'Servers DC', site: 'Riyadh HQ' }, { cidr: '10.0.6.0/24', name: 'Users floor 2', site: 'Riyadh HQ' }]) await e.req('POST', '/ipam/subnets', Object.assign({ body: s }, ADM));
  c('assets').put({ id: 'A1', name: 'srv-app-01', type: 'server', mgmt_ip: '10.0.5.10', status: 'active' });
  c('assets').put({ id: 'A3', name: 'Floor2 MFP', type: 'printer', mgmt_ip: '10.0.6.50', status: 'active' });
  const seen = new Date().toISOString();
  c('disc_devices').put({ id: 'D1', ips: ['10.0.5.10'], macs: ['aa:00:00:00:00:10'], hostname: 'srv-app-01', last_seen: seen, status: 'approved' });
  c('disc_devices').put({ id: 'D2', ips: ['10.0.5.12'], macs: ['aa:00:00:00:00:12'], hostname: 'srv-app-12', last_seen: seen, status: 'new' });
  c('disc_devices').put({ id: 'D3', ips: ['10.0.6.20'], macs: ['aa:00:00:00:00:20'], hostname: 'pc-0620', last_seen: seen, status: 'new' });
  c('vulnscan').put({ id: 'cfg', socket: '/run/syn.sock', username: 'syn' });
  await e.req('PUT', '/vulnscan/scope', Object.assign({ body: { allowed: ['10.0.5.0/24', '10.0.6.0/24'], exclude: [] } }, ADM));
  c('assets').put({ id: 'A8', name: 'srv-new', type: 'server', mgmt_ip: '10.0.5.11', status: 'active' });
  c('assets').put({ id: 'A9', name: 'srv-out', type: 'server', mgmt_ip: '10.9.0.5', status: 'active' });
  c('vulnscan_scans').put({ id: 'VS-1', name: 'old', targets: ['10.0.5.10'], exclude: [], state: 'done', requested_at: seen, finished_at: seen }); c('vulnscan_results').put({ id: 'VS-1', hosts: ['10.0.5.10'], at: seen });
  let WHO = ADM;
  const srv = http.createServer((req, res) => {
    const u2 = new URL(req.url, 'http://x'), json = (code, b2) => { res.writeHead(code, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b2)); };
    if (u2.pathname === '/dashboards/whoami.json') return json(200, WHO);
    if (u2.pathname.startsWith('/api/itam/')) {
      const h = Object.assign({}, req.headers, { 'x-sentra-proxy-secret': H.SECRET, 'x-auth-user': WHO.user, 'x-auth-role': WHO.role });
      const up = http.request({ host: '127.0.0.1', port: e.port, method: req.method, path: req.url, headers: h }, (r) => { res.writeHead(r.statusCode, r.headers); r.pipe(res); });
      req.pipe(up); return;
    }
    if (u2.pathname.startsWith('/api/')) return json(404, { error: 'not in this test' });
    const f = path.join(DASH, u2.pathname.replace(/^\/dashboards\//, '/')); if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (err, d) => { if (err) { res.writeHead(404); res.end(); return; } res.writeHead(200, { 'Content-Type': u2.pathname.endsWith('.js') ? 'application/javascript' : u2.pathname.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port + '/';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  const has = (p, sel, re) => p.waitForFunction((a) => new RegExp(a[1], 'i').test((document.querySelector(a[0]) || {}).textContent || ''), [sel, re.source], { timeout: 10000 }).then(() => true, () => false);
  const as = async (p, who) => { WHO = who; await p.reload(); };
  try {
    const p = await browser.newPage({ viewport: { width: 1400, height: 1000 } }); p.on('pageerror', (x) => errs.push(x.message));
    await p.goto(base + 'scan-assurance.html?standalone=1'); await p.waitForSelector('#assets table', { timeout: 10000 });
    ok(await has(p, '#kk', /Coverage/), 'KPIs');
    ok(await has(p, '#reasons', /Outside the internal scan scope/), 'the reason for srv-out');
    ok(await has(p, '#reasons', /10\.9\.0\.0\/24/), 'the subnet to add to the scope');
    ok(await has(p, '#assets', /srv-out/) && !(await has(p, '#assets', /srv-app-01/)), 'default filter: not scanned only (srv-app-01 was scanned)');
    await p.click('[data-reason="out_of_scope"]'); ok((await p.$$('#assets tbody tr')).length === 1, 'click a reason to filter');
    await p.click('[data-reason="out_of_scope"]'); await p.selectOption('#flt', 'scanned'); ok(await has(p, '#assets', /srv-app-01/), 'scanned list');
    ok(await has(p, '#rescan', /address\(es\) whose fix is a rescan/), 'rescan prepared');
    await p.click('#filebtn'); await Promise.all([p.waitForResponse((r) => /\/scan-assurance\/rescan$/.test(r.url())), p.click('#dlgok')]);
    ok(await has(p, 'body', /scan request\(s\) filed: VS-/), 'rescan filed in Vulnerability Scans');
    await p.selectOption('#flt', 'pending'); ok((await p.$$('#assets tbody tr')).length >= 1, 'assets now in a scan');
    const filed = e.app.store.collection('vulnscan_scans').all((x) => x.state === 'requested'); ok(filed.length === 1 && filed[0].requested_by === 'syed', 'request waits for a different approver');
    // viewer refused
    WHO = { user: 'vera.syn', role: 'viewer' }; await p.reload(); ok(await has(p, '#err', /operators and administrators/), 'viewer refused with a reason');
    const nav = fs.readFileSync(path.join(DASH, 'vendor', 'zyb-nav.js'), 'utf8'), inst = fs.readFileSync(path.join(DASH, 'install-dashboards.sh'), 'utf8');
    ok(nav.includes('"scan-assurance.html"') && inst.includes('scan-assurance.html') && inst.includes('vendor/zyb-scanassure.js'), 'in the menu and installed');
    ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  } finally { await browser.close(); srv.close(); await e.close(); }
  console.log((bad ? 'FAILED ' : 'ok ') + (n - bad) + '/' + n);
  process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
