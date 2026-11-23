// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for Scanned Assets (scanned-assets.html) against the REAL IT Asset Management engine (engine/scanned-assets.js over
// VAPT Center's gather) on SYNTHETIC hosts / findings (.syn / SYN): KPI tiles, the severity-stacked chart of the riskiest assets,
// filters, sortable table, the drawer with deduplicated findings linking to Vulnerabilities, the Coverage tab (never / stale in
// the approved scope, unknown hosts linking to the register), the admin stale-days setting, Excel export, a hostile host name stays
// text, a viewer is refused gracefully, phone width, no page errors.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node scanned-assets.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const ITAM = path.join(__dirname, '..', '..', 'backend', 'itam'), DASH = path.join(__dirname, '..', '..', 'ui');
const H = require(path.join(ITAM, 'tests', 'helpers'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const HOSTILE = '<img src=x onerror="window.__pwned=1">.syn';
(async () => {
  const e = await H.startApp({ noAi: true });
  const T0 = Date.now(), DAY = 86400000, D = (k) => new Date(T0 - k * DAY).toISOString();
  require(path.join(ITAM, 'engine/duty')).registerDuty(e.app.srv, e.app, { noTimer: true, python: process.env.PYTHON || 'python3', acovLogCoverage: async () => ({ ok: true, assets: [] }), acovAvail: async () => ({ ok: true, hosts: {} }) });
  if (!e.app.addons.scannedAssets) { const SA = require(path.join(ITAM, 'engine/scanned-assets')); SA.registerScannedAssets(e.app.srv, e.app, SA.createScannedAssets(e.app, {})); }
  const ADM = { user: 'syed', role: 'admin' }, col = e.app.store.collection('assets');
  const mk = (x, extra) => { const id = e.app.assets.create(Object.assign({ status: 'in_use' }, x), ADM).asset.id; col.put(Object.assign({}, col.get(id), extra || {})); return id; };
  mk({ name: 'SRV-SYN-1', type: 'server', mgmt_ip: '10.20.0.1', site: 'HQ-SYN', owner: 'owner.syn', department: 'Finance SYN' }, { tags: ['business-critical'] });
  mk({ name: 'SRV-SYN-2', type: 'server', mgmt_ip: '10.20.0.2', site: 'DR-SYN', owner: 'other.syn' }, { criticality: 'low' });
  mk({ name: 'PC-SYN-3', type: 'workstation', mgmt_ip: '10.20.0.3', site: 'HQ-SYN' });
  mk({ name: 'PC-SYN-4', type: 'workstation', mgmt_ip: '10.20.0.4', site: 'HQ-SYN' });
  e.app.store.collection('vulnscan').put({ id: 'scope', allowed: ['10.20.0.0/24'], exclude: [] });
  const res = e.app.store.collection('vulnscan_results');
  res.put({ id: 'scan-syn-1', hosts: ['10.20.0.1', '10.20.0.2', '10.20.0.99'], findings: [], at: D(2) });
  res.put({ id: 'scan-syn-0', hosts: ['10.20.0.4'], findings: [], at: D(60) });
  const gb = e.app.store.collection('vulnscan_findings');
  gb.put({ id: 'g1', status: 'open', name: 'Example Server Overflow (synthetic)', severity: 'critical', host: '10.20.0.1', cves: ['CVE-2099-0001'], score: 9.8, first_seen: D(40), last_seen: D(2) });
  gb.put({ id: 'g2', status: 'open', name: 'Example Daemon remote code execution (synthetic)', severity: 'high', host: '10.20.0.1', cves: [], score: 7.5, first_seen: D(5), last_seen: D(2) });
  gb.put({ id: 'g3', status: 'fixed', name: 'Old Library Flaw (synthetic)', severity: 'medium', host: '10.20.0.2', cves: ['CVE-2099-0002'], score: 5, first_seen: D(50), fixed_at: D(3) });
  gb.put({ id: 'g4', status: 'open', name: 'TLS 1.0 enabled (synthetic)', severity: 'low', host: '10.20.0.2', cves: [], score: 2.6, first_seen: D(10), last_seen: D(2) });
  gb.put({ id: 'g5', status: 'open', name: 'Unknown Host Weakness (synthetic)', severity: 'high', host: '10.20.0.99', hostname: HOSTILE, cves: ['CVE-2099-0005'], score: 8, first_seen: D(3), last_seen: D(2) });
  e.app.store.collection('fc_findings').put({ id: 'tn:0123456789abcdef0001', vendor: 'tenable', asset: '10.20.0.1', host: '10.20.0.1', title: 'Example Server Overflow (synthetic)', severity: 'critical', cvss: 9.8, cves: ['CVE-2099-0001'], status_src: 'open', first_seen: D(30).slice(0, 10) });
  let who = ADM;
  const srv = http.createServer((req, res2) => {
    const u = new URL(req.url, 'http://x'), json = (code, b) => { res2.writeHead(code, { 'Content-Type': 'application/json' }); res2.end(JSON.stringify(b)); };
    if (u.pathname === '/dashboards/whoami.json') return json(200, who);
    if (u.pathname.startsWith('/api/itam/')) { const h = Object.assign({}, req.headers, { 'x-sentra-proxy-secret': H.SECRET, 'x-auth-user': who.user, 'x-auth-role': who.role });
      const up = http.request({ host: '127.0.0.1', port: e.port, method: req.method, path: req.url, headers: h }, (r) => { res2.writeHead(r.statusCode, r.headers); r.pipe(res2); }); req.pipe(up); return; }
    if (u.pathname.startsWith('/api/')) return json(404, { error: 'not in this test' });
    const f = path.join(DASH, u.pathname.replace(/^\/dashboards\//, '/')); if (!f.startsWith(DASH)) { res2.writeHead(403); return res2.end(); }
    fs.readFile(f, (err, d) => { if (err) { res2.writeHead(404); res2.end(); return; } res2.writeHead(200, { 'Content-Type': u.pathname.endsWith('.js') ? 'application/javascript' : u.pathname.endsWith('.css') ? 'text/css' : 'text/html' }); res2.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port + '/';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  const wait = (p, fn) => p.waitForFunction(fn, null, { timeout: 30000 }).then(() => true, () => false);
  try {
    const p = await browser.newPage({ viewport: { width: 1500, height: 1000 }, acceptDownloads: true }); p.on('pageerror', (x) => errs.push(x.message));
    await p.goto(base + 'scanned-assets.html?standalone=1');
    ok(await wait(p, () => document.querySelectorAll('#tbl tbody tr').length >= 3), 'table rows');
    ok(await p.evaluate(() => document.querySelectorAll('#kpis .k').length === 6), 'six KPI tiles');
    ok(/SRV-SYN-1/.test(await p.textContent('#chart .stk .r')) && (await p.$$('#chart .stk .r:first-child .b i')).length >= 2, 'riskiest first, stacked by severity (critical + high, + the pentest engineer\'s own)');
    ok(/greenbone/i.test(await p.textContent('#srcs')), 'sources shown');
    ok(/Risk rule/.test(await p.textContent('#rule')) && /15 days/.test(await p.textContent('#rule')), 'risk rule and SLA stated');
    // the hostile host name is text, never markup
    ok(await p.evaluate((h) => document.getElementById('tbl').textContent.includes(h) && !document.querySelector('#tbl img') && !window.__pwned, HOSTILE), 'hostile host name stays text');
    ok(/not in register/.test(await p.textContent('#tbl')), 'unknown host flagged');
    // sort
    await p.click('th[data-sort="host"]'); ok(await wait(p, () => /ascending/.test(document.querySelector('th[data-sort="host"]').getAttribute('aria-sort'))), 'sort by asset');
    ok(await p.evaluate(() => { const h = [...document.querySelectorAll('#tbl tbody tr td:first-child b')].map((x) => x.textContent); return h.join('|') === h.slice().sort((a, b) => a.localeCompare(b)).join('|'); }), 'rows sorted by asset name');
    // filters
    await p.selectOption('#site', 'DR-SYN'); ok(await wait(p, () => document.querySelectorAll('#tbl tbody tr').length === 1 && /SRV-SYN-2/.test(document.getElementById('tbl').textContent)), 'site filter');
    await p.selectOption('#site', ''); await p.selectOption('#sev', 'critical'); ok(await wait(p, () => document.querySelectorAll('#tbl tbody tr').length === 1 && /SRV-SYN-1/.test(document.getElementById('tbl').textContent)), 'severity filter');
    await p.selectOption('#sev', ''); await p.selectOption('#crit', 'low'); ok(await wait(p, () => document.querySelectorAll('#tbl tbody tr').length === 1 && /SRV-SYN-2/.test(document.getElementById('tbl').textContent)), 'criticality filter');
    await p.selectOption('#crit', ''); await p.selectOption('#owner', 'owner.syn'); ok(await wait(p, () => document.querySelectorAll('#tbl tbody tr').length === 1), 'owner filter');
    await p.selectOption('#owner', ''); await p.selectOption('#scanner', 'tenable'); ok(await wait(p, () => document.querySelectorAll('#tbl tbody tr').length === 1), 'scanner filter');
    await p.selectOption('#scanner', ''); await p.fill('#q', 'CVE-2099-0005'); ok(await wait(p, () => document.querySelectorAll('#tbl tbody tr').length === 1 && /10\.20\.0\.99/.test(document.getElementById('tbl').textContent)), 'search by CVE');
    await p.fill('#q', ''); await wait(p, () => document.querySelectorAll('#tbl tbody tr').length >= 3);
    // drawer
    await p.click('#tbl tbody tr:has-text("SRV-SYN-1")');
    ok(await wait(p, () => !document.getElementById('dr').hidden && /owner\.syn/.test(document.getElementById('dr').textContent)), 'drawer: owner from the register');
    ok(await p.evaluate(() => { const d = document.getElementById('dr'); return /IP/.test(d.textContent) && d.querySelectorAll('a[href^="vuln-inventory.html#key=CVE-2099-0001"]').length === 1 && /Greenbone, Tenable|Tenable, Greenbone/.test(d.textContent); }), 'drawer: one deduplicated finding from both scanners, linking to Vulnerabilities');
    ok(/overdue/.test(await p.textContent('#dr')) && /exploit named/.test(await p.textContent('#dr')), 'drawer: overdue and known-exploited shown');
    await p.click('#drx');
    // export
    const [dl] = await Promise.all([p.waitForEvent('download', { timeout: 15000 }), p.click('#exp')]);
    ok(/^scanned-assets-\d{4}-\d{2}-\d{2}\.xlsx$/.test(dl.suggestedFilename()), 'Excel export');
    ok(e.app.store.auditTail(40).some((a) => a.action === 'scanned.assets.export' && a.by === 'syed'), 'export audited');
    // coverage
    await p.click('#tab-cov');
    ok(await wait(p, () => !document.getElementById('p-cov').hidden && /PC-SYN-3/.test(document.getElementById('never').textContent)), 'coverage: never scanned in scope');
    ok(/PC-SYN-4/.test(await p.textContent('#stalel')) && /60 days/.test(await p.textContent('#stalel')), 'coverage: not scanned recently');
    ok(await p.evaluate((h) => document.getElementById('unknown').textContent.includes(h) && !!document.querySelector('#unknown a[href="asset-studio.html"]'), HOSTILE), 'coverage: unknown host with a register link');
    ok(await p.isVisible('#setcard'), 'admin sees the freshness setting');
    await p.fill('#stale', '90'); await p.click('#savestale');
    ok(await wait(p, () => !/PC-SYN-4/.test(document.getElementById('stalel').textContent)), 'stale days saved: 60 days is no longer stale');
    ok(e.app.store.auditTail(40).some((a) => a.action === 'scanned.assets.settings' && a.by === 'syed'), 'setting audited');
    // operator: no setting
    who = { user: 'nora.syn', role: 'operator' };
    const o = await browser.newPage({ viewport: { width: 400, height: 900 } }); o.on('pageerror', (x) => errs.push(x.message));
    await o.goto(base + 'scanned-assets.html?standalone=1');
    ok(await wait(o, () => document.querySelectorAll('#tbl tbody tr').length >= 3), 'operator sees rows');
    ok(await o.evaluate(() => document.getElementById('setcard').hidden), 'operator: no setting');
    ok(await o.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1), 'phone width: no sideways scroll');
    // viewer: refused gracefully
    who = { user: 'vera.syn', role: 'viewer' };
    const v = await browser.newPage({ viewport: { width: 1200, height: 900 } }); v.on('pageerror', (x) => errs.push(x.message));
    await v.goto(base + 'scanned-assets.html?standalone=1');
    ok(await wait(v, () => /operators and administrators/.test(document.getElementById('err').textContent)), 'viewer: told why, no crash');
    ok(await v.evaluate(() => document.getElementById('body').hidden && document.getElementById('exp').hidden && !document.getElementById('zyb-err')), 'viewer: nothing shown, no generic error banner');
  } finally { await browser.close(); srv.close(); await e.close(); }
  ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks'); process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
