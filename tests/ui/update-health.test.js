// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for Update Health (dashboards/server/update-health.html) against the REAL ITAM engine (engine/update-health.js,
// install/update-doctor.js) with a SYNTHETIC update report: the state and ring, the cause + fix read from a synthetic log line,
// a module not on the server, the pages table and its filter, the installers table, a hostile log line stays text, an operator is
// told it is admin-only, and a server without the module says how to install it. Nothing is invented with no report.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node update-health.test.js
const http = require('http'), fs = require('fs'), os = require('os'), path = require('path');
const ITAM = path.join(__dirname, '..', '..', 'backend', 'itam'), DASH = path.join(__dirname, '..', '..', 'ui');
const H = require(path.join(ITAM, 'tests', 'helpers')), D = require(path.join(ITAM, 'install', 'update-doctor'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const ADM = { user: 'syed', role: 'admin' }, OP = { user: 'nora.syn', role: 'operator' };
const XSS = '<img src=x onerror="window.__xss=1">';

(async () => {
  const e = await H.startApp({ noAi: true });
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'zyb-uhp-')), rep = path.join(tmp, 'update-report.json');
  D.report(rep, 'duty', 'partial', JSON.stringify({ missing: '/vapt-studio', findings: D.diagnose("Error: Cannot find module './firecompass-syn' " + XSS) }));
  D.report(rep, 'remote-console', 'rolled-back', JSON.stringify({ reason: 'the remote console API does not answer (HTTP 404)', findings: D.diagnose('listen EADDRINUSE: address already in use 127.0.0.1:9150') }));
  D.report(rep, 'final-check', 'ok', '{}');
  for (const r0 of ['/ciso/insights', '/ciso/overview']) e.app.srv.route('GET', r0, () => ({}));   // main.js registers AI CISO on a server
  require(path.join(ITAM, 'engine/duty')).registerDuty(e.app.srv, e.app, { noTimer: true, python: process.env.PYTHON || 'python3', updateReportFile: rep });
  e.app.dutyMissing = (e.app.dutyMissing || []).concat(['vsphere-studio']);
  let WHO = ADM, NOMOD = false;
  const srv = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://x'), json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u.pathname === '/dashboards/whoami.json') return json(200, WHO);
    if (NOMOD && u.pathname === '/api/itam/platform/update-health') return json(404, { error: 'not found' });
    if (u.pathname.startsWith('/api/itam/')) {
      const h = Object.assign({}, req.headers, { 'x-sentra-proxy-secret': H.SECRET, 'x-auth-user': WHO.user, 'x-auth-role': WHO.role });
      const up = http.request({ host: '127.0.0.1', port: e.port, method: req.method, path: req.url, headers: h }, (r) => { res.writeHead(r.statusCode, r.headers); r.pipe(res); });
      req.pipe(up); return;
    }
    if (u.pathname.startsWith('/api/')) return json(404, { error: 'not in this test' });
    const f = path.join(DASH, u.pathname.replace(/^\/dashboards\//, '/')); if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (err, d) => { if (err) { res.writeHead(404); res.end(); return; } res.writeHead(200, { 'Content-Type': u.pathname.endsWith('.js') ? 'application/javascript' : u.pathname.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port + '/';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  const wait = (p, fn, arg) => p.waitForFunction(fn, arg, { timeout: 20000 }).then(() => true, () => false);
  try {
    const p = await browser.newPage({ viewport: { width: 1440, height: 1000 } }); p.on('pageerror', (x) => errs.push(x.message));
    p.on('dialog', (d) => { errs.push('dialog: ' + d.message()); d.dismiss(); });
    await p.goto(base + 'dashboards/update-health.html');
    ok(await wait(p, () => !document.getElementById('body').hidden && document.querySelectorAll('#pages tr').length > 10), 'the pages table is drawn');
    ok(/ATTENTION/.test(await p.textContent('#state')), 'state ATTENTION (a module is missing)');
    ok(/^\d+\/\d+$/.test((await p.textContent('#ring b')).trim()), 'ring shows working / checked');
    const fx = await p.textContent('#findings');
    ok(/vsphere-studio\.js is not on the server/.test(fx), 'the missing module is named with its fix');
    ok(/firecompass-syn\.js was not installed/.test(fx), 'the missing-file cause and fix from the log');
    ok(/port 9150 is already used/.test(fx) && /ss -ltnp \| grep :9150/.test(fx), 'the port-in-use cause with the command to find it');
    ok(!(await p.evaluate(() => window.__xss)) && fx.includes('<img') && !(await p.$('#findings img')), 'a hostile log line stays text');
    const rows = await p.$$eval('#pages tr', (t) => t.map((r) => r.textContent));
    ok(rows.some((r) => /vSphere Studio/.test(r) && /not working/.test(r) && /vsphere-studio\.js is not on the server/.test(r)), 'vSphere Studio not working, with why');
    ok(rows.some((r) => /Email Route Map/.test(r) && /working/.test(r) && !/not working/.test(r)), 'Email Route Map working');
    await p.click('#flt [data-f="bad"]');
    const badRows = await p.$$eval('#pages tr', (t) => t.map((r) => r.textContent));
    ok(badRows.length >= 1 && badRows.every((r) => /not working/.test(r)), 'filter: only pages not working');
    await p.click('#flt [data-f="all"]');
    const inst = await p.textContent('#inst');
    ok(/duty/.test(inst) && /partial/.test(inst) && /\/vapt-studio/.test(inst), 'installer duty: partial, names the page');
    ok(/remote-console/.test(inst) && /rolled-back/.test(inst) && /HTTP 404/.test(inst), 'installer remote-console: rolled back, with the reason');
    ok(/final-check/.test(inst), 'the final check is recorded');
    ok(await p.evaluate(() => { const a = (window.ZYB_NAV || []).find((x) => x.id === 'adm'); return !!(a && a.pages.some((x) => x.h === 'update-health.html')); }), 'the menu has the page');
    // operator: admin only
    WHO = OP; await p.reload();
    ok(await wait(p, () => /Administrators only/.test(document.getElementById('err').textContent)) && await p.isHidden('#body'), 'an operator is told it is admin-only');
    // not installed on the server
    WHO = ADM; NOMOD = true; await p.reload();
    ok(await wait(p, () => /not installed on the server yet/.test(document.getElementById('err').textContent)), 'not installed: says how to install');
    // no report yet: nothing invented
    NOMOD = false; fs.unlinkSync(rep); e.app.dutyMissing = []; await p.reload();
    ok(await wait(p, () => /NO REPORT YET|HEALTHY|ATTENTION/.test(document.getElementById('state').textContent)), 'drawn without a report');
    ok(/No installer has reported yet/.test(await p.textContent('#inst')), 'no installer rows invented');
  } finally { await browser.close(); srv.close(); await e.close(); }
  ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks');
  process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
