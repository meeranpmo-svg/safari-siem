// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for Vulnerability Scans (vuln-scans.html) against the REAL ITAM engine and a mock gvmd, SYNTHETIC data only:
// with nothing set the page says Greenbone is not connected and no range may be scanned; the admin saves the connection and the
// test runs step by step; the scope accepts only private ranges; an operator requests a scan; the requester's own approval is
// refused and a different admin approves; the scan runs and its findings show (a hostile NVT name stays text); a finding opens
// with its fix; the CSV export downloads; no page error.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node vuln-scans.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const ITAM = path.join(__dirname, '..', '..', 'backend', 'itam'), DASH = path.join(__dirname, '..', '..', 'ui');
const H = require(path.join(ITAM, 'tests', 'helpers'));
const { startGmpMock } = require(path.join(ITAM, 'tests', 'gmp-mock'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const XSS = '<img src=x onerror=alert(1)>';

(async () => {
  const gm = await startGmpMock({ hosts: ['10.20.1.5', '10.20.1.6'], findings: [
    { host: '10.20.1.6', hostname: 'db01.syn', port: '1521/tcp', oid: '1.3.6.1.4.1.25623.1.0.900002', name: XSS + ' Synthetic listener exposure', score: 9.8, cves: ['CVE-2099-0002'], solution: 'Restrict the listener (synthetic).' },
    { host: '10.20.1.5', hostname: 'app01.syn', port: '443/tcp', oid: '1.3.6.1.4.1.25623.1.0.900001', name: 'Synthetic TLS weakness', score: 7.5, cves: ['CVE-2099-0001'] }] });
  const e = await H.startApp({ noAi: true });
  let clock = Date.now();
  const sealer = { seal: (id, t) => 'SEALED:' + Buffer.from(t).toString('base64'), unseal: (id, x) => Buffer.from(String(x).slice(7), 'base64').toString() };
  require(path.join(ITAM, 'engine/duty')).registerDuty(e.app.srv, e.app, { noTimer: true, now: () => clock, python: process.env.PYTHON || 'python3', eccFacts: async () => ({}), ndmoCatalogFiles: false, vulnSealer: sealer, gvmFilePassword: () => '' });
  const V = e.app.addons.vulnscan;
  const ADM = { user: 'syed', role: 'admin' }, ADM2 = { user: 'sami.syn', role: 'admin' }, OP = { user: 'omar.syn', role: 'operator' };
  let WHO = ADM;
  const srv = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://x'), json = (c, b2) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b2)); };
    if (u.pathname === '/dashboards/whoami.json') return json(200, WHO);
    if (u.pathname.startsWith('/api/itam/')) {
      const h = Object.assign({}, req.headers, { 'x-sentra-proxy-secret': H.SECRET, 'x-auth-user': WHO.user, 'x-auth-role': WHO.role });
      const up = http.request({ host: '127.0.0.1', port: e.port, method: req.method, path: req.url, headers: h }, (r) => { res.writeHead(r.statusCode, r.headers); r.pipe(res); });
      req.pipe(up); return;
    }
    if (u.pathname.startsWith('/api/')) return json(404, { error: 'not in this test' });
    const fl = path.join(DASH, u.pathname.replace(/^\/dashboards\//, '/')); if (!fl.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(fl, (err, d) => { if (err) { res.writeHead(404); res.end(); return; } res.writeHead(200, { 'Content-Type': u.pathname.endsWith('.js') ? 'application/javascript' : u.pathname.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port + '/';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  const toast = (p) => p.waitForSelector('.toast-zyb', { timeout: 8000 }).then(() => p.$$eval('.toast-zyb', (x) => x.map((t) => t.textContent).join(' | ')));
  const closeDrawer = async (p) => { await p.keyboard.press('Escape'); await p.waitForFunction(() => { const z = document.getElementById('zd'); return !z || !z.offsetParent || getComputedStyle(z).display === 'none'; }, null, { timeout: 5000 }).catch(() => {}); };
  try {
    const p = await browser.newPage({ viewport: { width: 1400, height: 1100 }, acceptDownloads: true }); p.on('pageerror', (x) => errs.push(x.message));
    p.on('dialog', (d) => d.accept('change freeze (synthetic)'));
    await p.goto(base + 'vuln-scans.html?standalone=1'); await p.waitForFunction(() => /not connected/.test(document.getElementById('setup').textContent), null, { timeout: 20000 });
    ok(/no range may be scanned yet/.test(await p.textContent('#setup')), 'empty state names what to set');
    ok(/No scan has finished yet/.test(await p.textContent('#hosts')), 'no invented hosts');
    // connection + test
    await p.click('#conn'); await p.waitForSelector('#connf');
    ok(await p.$eval('#connf input[name=password]', (x) => x.type) === 'password', 'password field masked');
    await p.fill('#connf input[name=socket]', gm.socket); await p.fill('#connf input[name=username]', 'zyberon'); await p.fill('#connf input[name=password]', 'synthetic-pw');
    await p.click('#connf button[type=submit]');
    await p.waitForFunction(() => /Connection test/.test((document.getElementById('zd') || {}).textContent || ''), null, { timeout: 10000 });
    const steps = await p.textContent('#zd'); ok(/✓ Log in/.test(steps) && /! Internal scan scope/.test(steps) && /Fix: Set the internal scan scope/.test(steps), 'test steps with the scope warning: ' + steps.slice(0, 300));
    ok(!(await p.content()).includes('synthetic-pw'), 'password never on the page');
    await closeDrawer(p);
    // scope
    await p.click('#scopeb'); await p.waitForSelector('#scopef');
    await p.fill('#scopef input[name=allowed]', '8.8.8.0/24'); await p.click('#scopef button[type=submit]');
    await p.waitForFunction(() => /RFC 1918/.test(document.querySelector('#scopef [data-msg]').textContent), null, { timeout: 8000 }).then(() => ok(true, 'public range refused'), () => ok(false, 'public range refused'));
    await p.fill('#scopef input[name=allowed]', '10.20.0.0/16'); await p.click('#scopef button[type=submit]');
    ok(/Scope saved/.test(await toast(p)), 'scope saved'); await closeDrawer(p);
    // operator requests
    WHO = OP; await p.reload(); await p.waitForFunction(() => /10\.20\.0\.0\/16/.test(document.getElementById('setup').textContent), null, { timeout: 10000 });
    await p.click('#newscan'); await p.waitForSelector('#scanf');
    const iso = (ms) => new Date(ms).toISOString().slice(0, 16);
    await p.fill('#scanf input[name=name]', 'Server VLAN (synthetic)'); await p.fill('#scanf input[name=targets]', '10.20.1.0/24');
    await p.fill('#scanf input[name=window_start]', iso(clock - 60000)); await p.fill('#scanf input[name=window_end]', iso(clock + 3 * 3600000));
    await p.fill('#scanf textarea[name=reason]', 'quarterly VAPT (synthetic)'); await p.click('#scanf button[type=submit]');
    ok(/requested - a different person approves it/.test(await toast(p)), 'scan requested');
    await p.waitForSelector('[data-sact="approve"]'); ok(/waiting for approval/.test(await p.textContent('#scans')), 'state: waiting for approval');
    await p.click('[data-sact="approve"]');
    await p.waitForFunction(() => /needs an administrator|approving|four-eyes/i.test([].map.call(document.querySelectorAll('.toast-zyb'), (t) => t.textContent).join(' ')), null, { timeout: 8000 }).then(() => ok(true, 'the operator cannot approve'), () => ok(false, 'the operator cannot approve'));
    WHO = ADM2; await p.reload(); await p.waitForSelector('[data-sact="approve"]'); await p.click('[data-sact="approve"]');
    ok(/approved/.test(await toast(p)), 'approved by a different admin');
    // the background job runs it
    await V.tick(); gm.st.status = 'Done'; await V.tick();
    await p.click('#refresh'); await p.waitForFunction(() => /done/.test(document.getElementById('scans').textContent), null, { timeout: 10000 });
    const kp = (await p.textContent('#kpis')).replace(/\s+/g, ''); ok(/1Criticalopen/.test(kp) && /1Highopen/.test(kp), 'KPIs from the scan: ' + kp.slice(0, 120));
    ok(/10\.20\.1\.6/.test(await p.textContent('#hosts')), 'affected host listed');
    ok(!(await p.$('img[src="x"]')) && /Synthetic listener exposure/.test(await p.textContent('#finds')), 'hostile NVT name is text');
    await p.click('#finds tr[data-fid]'); await p.waitForSelector('#ownf');
    const z = await p.textContent('#zd'); ok(/Restrict the listener/.test(z) && /CVE-2099-0002/.test(z), 'finding drawer with fix and CVE');
    await closeDrawer(p);
    const [dl] = await Promise.all([p.waitForEvent('download', { timeout: 10000 }), p.click('#csv')]);
    ok(/^vulnerability-findings-\d{4}-\d{2}-\d{2}\.csv$/.test(dl.suggestedFilename()), 'CSV downloaded');
    ok(e.app.store.auditTail(80).some((x) => x.action === 'vulnscan.scan.approve' && x.by === ADM2.user), 'approval recorded');
    ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  } catch (x) { ok(false, 'exception: ' + (x && x.stack || x)); }
  await browser.close(); srv.close(); await e.close(); await gm.close();
  console.log(bad ? `${bad}/${n} FAILED` : `all ${n} checks passed`);
  process.exit(bad ? 1 : 0);
})();
