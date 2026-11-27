// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Error handling on every page (vendor/zyb-errors.js): an uncaught error, an unhandled promise, a 5xx and a timed-out /
// unanswered request each show one message with a reference and are reported to Platform Health; the same failure is shown
// once; a 401 says the session ended (Sign in again); Arabic when the page is Arabic; Platform Health lists jobs and errors.
// Then EVERY dashboard page is opened with every server failing (HTTP 503): no page may crash (uncaught error) or stay
// blank. Stub API, SYNTHETIC data. Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node page-errors.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const DASH = path.resolve(__dirname, '../../ui');
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
let MODE = 'fail500'; const reports = [];
const JOBS = { at: '2026-10-22T10:00:00Z', failing: 1, jobs: [{ name: 'db-health.pass', runs: 12, failures: 4, consecutive: 3, state: 'failing', last_error: 'ORA-01017: invalid username/password', last_error_at: '2026-10-22T09:58:00Z', last_ok: '2026-10-22T08:00:00Z' }, { name: 'virt.tick', runs: 40, failures: 0, consecutive: 0, state: 'ok', last_ok: '2026-10-22T09:59:00Z' }],
  server: [{ at: '2026-10-22T09:50:00Z', method: 'GET', path: '/api/itam/reconcile', status: 500, error: 'hyperv: socket hang up' }], client: [{ at: '2026-10-22T09:40:00Z', user: 'ali', kind: 'http', status: 502, page: '/dashboards/storage.html', message: 'HTTP 502', ref: 'E-SYNTH1' }], process: { unhandled: 1, uncaught: 0 } };
(async () => {
  const srv = http.createServer((req, res) => { const u = req.url.split('?')[0]; const json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u === '/dashboards/whoami.json' || u === '/auth/whoami') return json(200, { user: 'syed', role: 'admin' });
    if (u === '/api/itam/platform/client-errors') { let b = ''; req.on('data', (c) => { b += c; }); req.on('end', () => { try { reports.push(JSON.parse(b)); } catch (e) { reports.push({ bad: b }); } json(200, { ok: true }); }); return; }
    if (MODE === 'platform' && u === '/api/itam/platform/errors') return json(200, JOBS);
    if (MODE === 'platform' && u === '/api/soc/platform/errors') return json(200, Object.assign({}, JOBS, { jobs: [{ name: 'collect.m365-graph.sync', runs: 3, failures: 0, consecutive: 0, state: 'ok', last_ok: '2026-10-22T09:00:00Z' }], failing: 0, client: [] }));
    if (u === '/api/test/401') return json(401, { error: 'missing or invalid identity' });
    if (u === '/api/test/500') return json(500, { error: 'internal error' });
    if (u.startsWith('/api/') || u.startsWith('/zyb-')) return json(MODE === 'down' ? 503 : MODE === 'platform' ? 404 : 500, { error: 'synthetic outage' });
    fs.readFile(path.join(DASH, u.replace(/^\/dashboards\//, '/')), (e, d) => { if (e) { res.writeHead(404); return res.end(); } res.writeHead(200, { 'Content-Type': u.endsWith('.js') ? 'application/javascript' : u.endsWith('.css') ? 'text/css' : u.endsWith('.json') ? 'application/json' : 'text/html' }); res.end(d); }); });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r)); const base = 'http://127.0.0.1:' + srv.address().port + '/dashboards/';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright'); const browser = await chromium.launch();
  const toasts = (p) => p.$$eval('#zyb-err .ze', (l) => l.map((x) => x.innerText));

  // 1. one page, every kind of failure
  let p = await browser.newPage({ viewport: { width: 1366, height: 900 } });
  await p.goto(base + 'domains.html?standalone=1'); await p.waitForTimeout(1500);
  let t = await toasts(p);
  ok(t.length >= 1 && /could not complete this request \(HTTP 500\)/.test(t.join('\n')), 'a 5xx shows a message: ' + t.join(' | ').slice(0, 200));
  ok(/Reference: E-/.test(t.join('\n')) && /rest of the page still works/.test(t.join('\n')), 'with a reference and "the rest of the page still works"');
  ok(reports.some((r) => r.kind === 'http' && r.status === 500 && r.page === '/dashboards/domains.html' && /^E-/.test(r.ref)), 'reported to Platform Health with page, status and reference');
  ok(reports.every((r) => !/[?]/.test(r.url || '') && !/[?]/.test(r.page || '')), 'no query string reported');
  const before = (await toasts(p)).length;
  await p.evaluate(() => new Promise((r) => { const x = new XMLHttpRequest(); x.open('GET', '/api/test/500'); x.onloadend = r; x.send(); }));
  await p.evaluate(() => new Promise((r) => { const x = new XMLHttpRequest(); x.open('GET', '/api/test/500'); x.onloadend = r; x.send(); }));
  await p.waitForTimeout(200);
  ok((await toasts(p)).length <= Math.min(3, before + 1), 'the same failure is shown once');
  await p.evaluate(() => { document.querySelectorAll('#zyb-err .ze').forEach((x) => x.remove()); setTimeout(() => { throw new Error('synthetic-boom'); }, 0); }); await p.waitForTimeout(200);
  t = await toasts(p); ok(/unexpected error/.test(t.join('\n')), 'an uncaught error shows a message: ' + t.join(' | ').slice(0, 160));
  ok(reports.some((r) => r.kind === 'error' && /synthetic-boom/.test(r.message)), 'and is reported');
  await p.evaluate(() => { Promise.reject(new Error('synthetic-lost-promise')); }); await p.waitForTimeout(200);
  ok(reports.some((r) => r.kind === 'rejection' && /synthetic-lost-promise/.test(r.message)), 'an unhandled promise is caught and reported');
  await p.evaluate(() => fetch('/api/test/401')); await p.waitForTimeout(200);
  t = await toasts(p); ok(/session has ended/.test(t.join('\n')) && await p.$('#zyb-err a[href="/"]'), 'a 401 says the session ended, with Sign in again');
  await p.evaluate(() => { const x = new XMLHttpRequest(); x.zybQuiet = true; x.open('GET', '/api/test/500?quiet'); x.send(); }); await p.waitForTimeout(200);
  ok(!reports.some((r) => /quiet/.test(r.message || '')), 'a request the page handles itself (zybQuiet) is left alone');
  await p.evaluate(() => { document.querySelectorAll('#zyb-err .ze').forEach((x) => x.remove()); for (let i = 0; i < 6; i++) setTimeout(() => { throw new Error('flood ' + i); }, 0); }); await p.waitForTimeout(200);
  ok((await toasts(p)).length <= 3, 'at most three messages at a time');
  await p.addInitScript(() => { window.ZYB_ARABIC = false; });   // the switch off (it ships on): Arabic saved still shows English
  await p.evaluate(() => localStorage.setItem('zyb-dash-prefs', JSON.stringify({ lang: 'ar' }))); await p.reload(); await p.waitForTimeout(1500);
  t = await toasts(p); ok(/Something went wrong/.test(t.join('\n')) && !/حدث خطأ/.test(t.join('\n')), 'English while Arabic is switched off, even with Arabic saved');
  await p.addInitScript(() => { window.ZYB_ARABIC = true; }); await p.reload(); await p.waitForTimeout(1500);   // Arabic switched on (vendor/zyb-dash.js ARABIC_ON)
  t = await toasts(p); ok(/حدث خطأ/.test(t.join('\n')), 'Arabic when the page is Arabic');
  await p.evaluate(() => localStorage.removeItem('zyb-dash-prefs')); await p.close();

  // 2. Platform Health: the errors tab
  MODE = 'platform'; p = await browser.newPage({ viewport: { width: 1366, height: 900 } });
  await p.goto(base + 'platform.html?standalone=1'); await p.waitForTimeout(800);
  await p.click('[data-tab="err"]'); await p.waitForSelector('[data-ej]', { timeout: 5000 }).catch(() => {});
  const txt = await p.$eval('#err', (x) => x.innerText);
  ok(/db-health\.pass/.test(txt) && /failing/.test(txt) && /ORA-01017/.test(txt), 'Platform Health lists the failing job with its last error');
  ok(/collect\.m365-graph\.sync/.test(txt), 'and the SIEM jobs');
  ok(/hyperv: socket hang up/.test(txt) && /E-SYNTH1/.test(txt), 'server errors and page errors with their reference');
  await p.click('[data-ej="itam:0"]'); await p.waitForTimeout(300);
  ok(/runs again on its schedule/.test(await p.evaluate(() => document.body.innerText)), 'a job row opens its detail');
  await p.close();

  // 3. every page with every server failing: nothing may crash or stay blank
  MODE = 'down';
  const pages = fs.readdirSync(DASH).filter((f) => f.endsWith('.html'));
  const crashed = [], blank = [];
  for (const f of pages) {
    const q = await browser.newPage({ viewport: { width: 1366, height: 900 } }); const errs = []; q.on('pageerror', (e) => errs.push(e.message)); const r0 = reports.length;
    try { await q.goto(base + f + '?standalone=1', { waitUntil: 'load', timeout: 15000 }); await q.waitForTimeout(1200); } catch (e) { errs.push('load: ' + e.message); }
    const len = await q.evaluate(() => (document.body ? document.body.innerText.trim().length : 0)).catch(() => 0);
    // a promise the page left unhandled is a gap too (Playwright does not report it as a page error; zyb-errors.js does)
    reports.slice(r0).filter((r) => r.kind === 'rejection' || r.kind === 'error').forEach((r) => errs.push(r.kind + ': ' + r.message));
    if (errs.length) crashed.push(f + ': ' + errs[0].slice(0, 120));
    if (len < 20) blank.push(f);
    await q.close();
  }
  ok(!crashed.length, 'no page crashes when the servers fail (' + pages.length + ' pages):\n  ' + crashed.join('\n  '));
  ok(!blank.length, 'no page stays blank: ' + blank.join(', '));
  await browser.close(); srv.close();
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks'); process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
