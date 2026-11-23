// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for Vulnerabilities (vuln-inventory.html) and Risk Prioritization (risk-prioritization.html) against the REAL IT Asset
// Management engine (engine/vuln-intel.js) over SYNTHETIC records: severity / software / OS charts, the deduplicated inventory with
// adapters, primary and max score, filters, the device drawer; risk cards (profile pie, overall bands, factors), profiles toggled and
// added by an admin, the fix-first list with its reasons; a viewer sees charts only; phone width; menu entries.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node vuln-risk.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const ITAM = path.join(__dirname, '..', '..', 'backend', 'itam'), DASH = path.join(__dirname, '..', '..', 'ui');
const H = require(path.join(ITAM, 'tests', 'helpers'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
(async () => {
  const e = await H.startApp({ noAi: true });
  require(path.join(ITAM, 'engine/duty')).registerDuty(e.app.srv, e.app, { noTimer: true, python: process.env.PYTHON || 'python3', acovLogCoverage: async () => ({ ok: true, assets: [] }), acovAvail: async () => ({ ok: true, hosts: {} }) });
  const ADM = { user: 'syed', role: 'admin' }, col = e.app.store.collection('assets');
  const mk = (x, extra, sw) => { const id = e.app.assets.create(Object.assign({ status: 'in_use', site: 'HQ' }, x), ADM).asset.id; col.put(Object.assign({}, col.get(id), extra, { software: sw })); };
  mk({ name: 'SRV-SYN-1', type: 'server', os: 'Windows Server 2019', mgmt_ip: '10.1.0.1' }, { internet_facing: true, eol: '2026-01-01', classification: 'secret' }, [{ name: 'Mozilla Firefox 115.0' }]);
  mk({ name: 'SRV-SYN-2', type: 'server', os: 'Red Hat Enterprise Linux 9', mgmt_ip: '10.1.0.2' }, {}, []);
  mk({ name: 'PC-SYN-3', type: 'workstation', os: 'Windows 11 Enterprise', mgmt_ip: '10.1.0.3' }, {}, [{ name: 'Mozilla Firefox 115.0' }]);
  const gb = e.app.store.collection('vulnscan_findings');
  gb.put({ id: 'g1', status: 'open', name: 'OpenSSH < 9.6 (synthetic)', severity: 'high', host: '10.1.0.2', cves: ['CVE-2024-6387'], score: 8.1 });
  gb.put({ id: 'g2', status: 'open', name: 'Mozilla Firefox < 130 Multiple Vulnerabilities (synthetic)', severity: 'medium', host: '10.1.0.3', cves: ['CVE-2024-9392'], score: 6.1 });
  e.app.store.collection('fc_findings').put({ id: 'tn:0123456789abcdef0123', vendor: 'tenable', asset: '10.1.0.2', host: '10.1.0.2', title: 'OpenSSH regreSSHion (synthetic)', severity: 'critical', cvss: 9.8, cves: ['CVE-2024-6387'], status_src: 'open' });
  let who = ADM;
  const srv = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://x'), json = (code, b) => { res.writeHead(code, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u.pathname === '/dashboards/whoami.json') return json(200, who);
    if (u.pathname.startsWith('/api/itam/')) { const h = Object.assign({}, req.headers, { 'x-sentra-proxy-secret': H.SECRET, 'x-auth-user': who.user, 'x-auth-role': who.role });
      const up = http.request({ host: '127.0.0.1', port: e.port, method: req.method, path: req.url, headers: h }, (r) => { res.writeHead(r.statusCode, r.headers); r.pipe(res); }); req.pipe(up); return; }
    if (u.pathname.startsWith('/api/')) return json(404, { error: 'not in this test' });
    const f = path.join(DASH, u.pathname.replace(/^\/dashboards\//, '/')); if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (err, d) => { if (err) { res.writeHead(404); res.end(); return; } res.writeHead(200, { 'Content-Type': u.pathname.endsWith('.js') ? 'application/javascript' : u.pathname.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port + '/';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  const wait = (p, fn) => p.waitForFunction(fn, null, { timeout: 30000 }).then(() => true, () => false);
  try {
    // ---- Vulnerabilities
    const p = await browser.newPage({ viewport: { width: 1500, height: 1000 } }); p.on('pageerror', (x) => errs.push(x.message));
    await p.goto(base + 'vuln-inventory.html?standalone=1');
    ok(await wait(p, () => document.querySelectorAll('#inv tbody tr').length >= 2), 'inventory rows');
    ok(/Critical/.test(await p.textContent('#bysev')) && !!(await p.$('#bysev svg')), 'by severity donut');
    ok(/Mozilla Firefox/.test(await p.textContent('#bysw')) && /OpenSSH/.test(await p.textContent('#bysw')), 'by software bars');
    ok(/Windows/.test(await p.textContent('#byos')) && /Linux/.test(await p.textContent('#byos')), 'by OS donut');
    const row = await p.$eval('tr[data-key="CVE-2024-6387"]', (r) => r.textContent);
    ok(/9\.8/.test(row) && /Tenable/.test(row) && /critical/i.test(row), 'one row for the CVE: primary score from Tenable 9.8, critical');
    ok(await p.$$eval('tr[data-key="CVE-2024-6387"] .ad', (x) => x.length) === 2, 'two adapter badges');
    await p.selectOption('#sev', 'medium'); ok(await wait(p, () => document.querySelectorAll('#inv tbody tr').length >= 1 && ![...document.querySelectorAll('#inv tbody tr')].some((r) => /CRITICAL/.test(r.textContent))), 'severity filter');
    await p.selectOption('#sev', ''); await wait(p, () => !!document.querySelector('tr[data-key="CVE-2024-6387"]'));
    await p.click('tr[data-key="CVE-2024-6387"]'); ok(await wait(p, () => !document.getElementById('dr').hidden && /SRV-SYN-2/.test(document.getElementById('dr').textContent)), 'drawer lists the device');
    await p.click('#drx');
    ok(await p.isVisible('#exp') && /Primary score from/.test(await p.textContent('#ordtxt')), 'export + primary order shown to the admin');
    ok(await p.evaluate(() => ['vuln-inventory.html', 'risk-prioritization.html'].every((h) => (window.ZYB_NAV || []).some((a) => (a.pages || []).some((x) => x.h === h)))), 'both pages are in the menu');
    // ---- Risk prioritization (admin)
    const r = await browser.newPage({ viewport: { width: 1500, height: 1100 } }); r.on('pageerror', (x) => errs.push(x.message));
    await r.goto(base + 'risk-prioritization.html?standalone=1');
    ok(await wait(r, () => document.querySelectorAll('#profiles tbody tr').length === 6), 'six built-in profiles');
    ok(await r.evaluate(() => document.querySelectorAll('#overall .big').length === 3), 'overall: critical / medium / low shares');
    ok(/Internet-facing/.test(await r.textContent('#factors')) && /33\.3%/.test(await r.textContent('#factors')), 'risk factors with shares');
    ok(/withheld|two daily snapshots/.test(await r.textContent('#trend')), 'trend says how much history it has');
    ok(await wait(r, () => /SRV-SYN-1/.test(document.getElementById('ff').textContent) && /internet-facing/.test(document.getElementById('ff').textContent)), 'fix-first with reasons');
    await r.click('[data-tg="p-linsrv"]'); ok(await wait(r, () => document.querySelector('[data-tg="p-linsrv"]').getAttribute('aria-checked') === 'false' && /inactive profiles/.test(document.getElementById('meta').textContent)), 'deactivating a profile takes its devices out of the score');
    await r.click('#addp'); await r.fill('#pn', 'DMZ servers (synthetic)'); await r.check('#pt input[value="server"]'); await r.selectOption('#ps', 'high'); await r.click('#psave');
    ok(await wait(r, () => /DMZ servers/.test(document.getElementById('profiles').textContent)), 'admin adds a profile');
    // ---- viewer
    who = { user: 'vera.syn', role: 'viewer' };
    const v = await browser.newPage({ viewport: { width: 400, height: 900 } }); v.on('pageerror', (x) => errs.push(x.message));
    await v.goto(base + 'risk-prioritization.html?standalone=1');
    ok(await wait(v, () => document.querySelectorAll('#profiles tbody tr').length >= 6), 'viewer sees profiles');
    ok(await v.evaluate(() => document.getElementById('ffp').hidden && document.getElementById('addp').hidden && document.querySelector('[data-tg]').disabled), 'viewer: no devices, no edits');
    ok(await v.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1), 'phone width: no sideways scroll (risk)');
    await v.goto(base + 'vuln-inventory.html?standalone=1');
    ok(await wait(v, () => /operators and administrators/.test(document.getElementById('inv').textContent)), 'viewer: charts only, rows withheld');
    ok(await v.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1), 'phone width: no sideways scroll (vulnerabilities)');
  } finally { await browser.close(); srv.close(); await e.close(); }
  ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks'); process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
