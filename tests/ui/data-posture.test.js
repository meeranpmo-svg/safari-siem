// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for Data Security Posture (data-posture.html) against the REAL IT Asset Management engine (engine/data-posture.js)
// with a stubbed SIEM link and SYNTHETIC records (backend/itam/tests/data-posture-fixtures.js): the score with its why list and
// "based on N of M sources", the seven risk cards, a risk drill-down (measures, items from the operator route), the store summary
// (Microsoft 365 and Azure first, the Teams note), scan status, classes by sensitivity, a hostile file name stays text, a viewer
// sees counts and no names, the empty state when nothing is connected says what to connect, phone width, no page errors.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node data-posture.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const ITAM = path.join(__dirname, '..', '..', 'backend', 'itam'), DASH = path.join(__dirname, '..', '..', 'ui');
const H = require(path.join(ITAM, 'tests', 'helpers')), F = require(path.join(ITAM, 'tests', 'data-posture-fixtures'));
const DP = require(path.join(ITAM, 'engine', 'data-posture'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
(async () => {
  const T0 = Date.parse('2026-11-08T08:00:00Z');
  const e = await H.startApp({ noAi: true }), e2 = await H.startApp({ noAi: true });
  e.app.addons.pdpl = require(path.join(ITAM, 'engine', 'pdpl')).createPdpl(e.app, { now: () => T0 });
  F.seedLocal(e.app, T0);
  DP.registerDataPosture(e.app.srv, e.app, DP.createDataPosture(e.app, { now: () => T0, siem: F.fakeSiem(T0), noTimer: true }));
  DP.registerDataPosture(e2.app.srv, e2.app, DP.createDataPosture(e2.app, { now: () => T0, noTimer: true }));   // nothing connected
  let who = { user: 'nora.syn', role: 'operator' }, eng = e;
  const srv = http.createServer((req, res2) => {
    const u = new URL(req.url, 'http://x'), json = (code, b) => { res2.writeHead(code, { 'Content-Type': 'application/json' }); res2.end(JSON.stringify(b)); };
    if (u.pathname === '/dashboards/whoami.json') return json(200, who);
    if (u.pathname.startsWith('/api/itam/')) { const h = Object.assign({}, req.headers, { 'x-sentra-proxy-secret': H.SECRET, 'x-auth-user': who.user, 'x-auth-role': who.role });
      const up = http.request({ host: '127.0.0.1', port: eng.port, method: req.method, path: req.url, headers: h }, (r) => { res2.writeHead(r.statusCode, r.headers); r.pipe(res2); }); req.pipe(up); return; }
    if (u.pathname.startsWith('/api/')) return json(404, { error: 'not in this test' });
    const f = path.join(DASH, u.pathname.replace(/^\/dashboards\//, '/')); if (!f.startsWith(DASH)) { res2.writeHead(403); return res2.end(); }
    fs.readFile(f, (err, d) => { if (err) { res2.writeHead(404); res2.end(); return; } res2.writeHead(200, { 'Content-Type': u.pathname.endsWith('.js') ? 'application/javascript' : u.pathname.endsWith('.css') ? 'text/css' : 'text/html' }); res2.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port + '/';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  const wait = (p, fn, arg) => p.waitForFunction(fn, arg, { timeout: 30000 }).then(() => true, () => false);
  try {
    const p = await browser.newPage({ viewport: { width: 1500, height: 1000 } }); p.on('pageerror', (x) => errs.push(x.message));
    await p.goto(base + 'data-posture.html?standalone=1');
    ok(await wait(p, () => document.querySelectorAll('#risks .rk').length === 7), 'seven risk cards');
    ok((await p.textContent('#scorev')).startsWith('1.5') && (await p.textContent('#scorel')) === 'Poor', 'score 1.5 / 10, Poor');
    ok(/based on 12 of 12 sources/.test(await p.textContent('#basedon')), 'based on N of M sources');
    const why = await p.$$eval('#why li', (l) => l.map((x) => x.textContent));
    ok(why.length >= 10 && why.some((w) => /anonymous link × 0\.5 = 0\.5 \(SharePoint \/ OneDrive discovery \(SIEM\)\)/.test(w)) && why.some((w) => /capped at 2/.test(w)), 'why lists every deduction with its source, and the cap');
    ok(/Microsoft 365|SharePoint/.test(await p.textContent('#srcs')), 'source chips');
    // store summary, scan status, classes
    const st = await p.textContent('#stores');
    ok(/SharePoint sites/.test(st) && /OneDrive/.test(st) && /Azure storage accounts/.test(st) && /SQL Server databases/.test(st), 'store summary by type');
    ok(/Teams files are counted in their SharePoint site/.test(st), 'Teams note');
    ok(await p.evaluate(() => document.querySelector('#storet tbody tr td').textContent === 'SharePoint sites'), 'Microsoft 365 first');
    ok(/not connected/.test(await p.textContent('#scans')) && /scanned/.test(await p.textContent('#scans')), 'scan status per source');
    ok(await p.evaluate(() => document.querySelectorAll('#classes .bars .r').length >= 5 && /Health/.test(document.querySelector('#classes .bars .r').textContent)), 'classes ordered by sensitivity');
    ok(await p.evaluate(() => document.getElementById('nmcard').hidden), 'nothing unmeasured: the card is hidden');
    // drill-down: exposed data
    await p.click('[data-risk="exposed"]');
    ok(await wait(p, () => !document.getElementById('dr').hidden && document.querySelectorAll('#items tbody tr').length === 3), 'exposed drill-down: three items from the operator route');
    const dr = await p.textContent('#dr');
    ok(/anonymous link/.test(dr) && /public cloud store/.test(dr) && /payroll-syn\.xlsx/.test(dr) && /claimsdocssyn/.test(dr) && /exposure 95/.test(dr), 'measures and named items');
    ok(/unknown, not safe/.test(dr), 'the unknown-public store is said, not safe');
    ok(await p.evaluate((h) => document.getElementById('dr').textContent.includes(h) && !document.querySelector('#dr img') && !window.__pwned, F.HOSTILE), 'a hostile file name stays text');
    ok(e.app.store.auditTail(40).some((a) => a.action === 'data.posture.risk.read' && a.by === 'nora.syn' && a.target === 'exposed'), 'drill-down audited');
    await p.click('#drx'); ok(await p.evaluate(() => document.getElementById('dr').hidden), 'drawer closes');
    await p.click('[data-risk="excessive"]');
    ok(await wait(p, () => /admin\.syn@example\.invalid/.test(document.getElementById('dr').textContent) && /guest account/.test(document.getElementById('dr').textContent)), 'excessive access: administrators without MFA, guests');
    await p.keyboard.press('Escape');
    // viewer: counts only
    who = { user: 'vera.syn', role: 'viewer' };
    const v = await browser.newPage({ viewport: { width: 400, height: 900 } }); v.on('pageerror', (x) => errs.push(x.message));
    await v.goto(base + 'data-posture.html?standalone=1');
    ok(await wait(v, () => document.querySelectorAll('#risks .rk').length === 7), 'viewer sees the risks');
    await v.click('[data-risk="exposed"]');
    ok(await wait(v, () => !!document.getElementById('noitems')), 'viewer: names are for operators');
    ok(await v.evaluate(() => !['payroll-syn', 'HR-Site-SYN', 'claimsdocssyn', 'admin.syn', 'FS-SYN-01', 'HRDB-SYN'].some((x) => document.body.textContent.includes(x))), 'viewer: no file, site, bucket, server or person name on the page');
    ok(await v.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1), 'phone width: no sideways scroll');
    // nothing connected: the empty state says what to connect
    eng = e2; who = { user: 'nora.syn', role: 'operator' };
    const z = await browser.newPage({ viewport: { width: 1300, height: 900 } }); z.on('pageerror', (x) => errs.push(x.message));
    await z.goto(base + 'data-posture.html?standalone=1');
    ok(await wait(z, () => /Nothing is connected yet/.test(document.getElementById('empty').textContent)), 'empty state says what to connect');
    ok((await z.textContent('#scorel')) === 'Not measured' && (await z.textContent('#scorev')).startsWith('-'), 'no score, never a 10');
    ok(await z.evaluate(() => !document.getElementById('nmcard').hidden && document.querySelectorAll('#nm li').length === 12), 'all twelve sources listed as not measured');
    ok(await z.evaluate(() => [...document.querySelectorAll('#risks .rk')].every((x) => /not measured/.test(x.textContent))), 'every risk says not measured');
    ok(!(await z.$('#zyb-err .ze')), 'no generic error banner');
  } finally { await browser.close(); srv.close(); await e.close(); await e2.close(); }
  ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks'); process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
