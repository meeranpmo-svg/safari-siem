// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for RBC Assessment (dashboards/server/rbc-assessment.html, vendor/zyb-rbc.js) against the REAL ITAM engine with a
// SYNTHETIC workbook in the IA template layout: Finance uploads it, the page shows the ratio, MCR cover, insights, every schedule, the
// checks, the projection and the board answers; the uploader cannot approve (four eyes), Risk approves; the report opens; settings
// change the verdict; a viewer is refused; in the menu.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node rbc-assessment.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const ITAM = path.join(__dirname, '..', '..', 'backend', 'itam'), DASH = path.join(__dirname, '..', '..', 'ui');
const H = require(path.join(ITAM, 'tests', 'helpers')), F = require(path.join(ITAM, 'tests', 'rbc-fixture'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };

(async () => {
  const e = await H.startApp({ noAi: true });
  require(path.join(ITAM, 'engine/duty')).registerDuty(e.app.srv, e.app, { noTimer: true, python: process.env.PYTHON || 'python3' });
  let WHO = { user: 'fin.syn', role: 'operator' };
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
  try {
    const p = await browser.newPage({ viewport: { width: 1400, height: 1000 } }); p.on('pageerror', (x) => errs.push(x.message));
    await p.goto(base + 'rbc-assessment.html?standalone=1'); await p.waitForSelector('#upl:not([hidden])');
    ok(await has(p, '#periods', /No RBC assessment uploaded/), 'empty state says what to upload');
    // Finance uploads the synthetic Q1 2026 workbook
    const tmp = path.join(require('os').tmpdir(), 'rbc-syn-' + process.pid + '.xlsx'); fs.writeFileSync(tmp, F.build());
    await p.setInputFiles('#file', tmp); fs.unlinkSync(tmp);
    ok(await has(p, '#det', /Solvency ratio/) && await has(p, '#det', /260%/), 'solvency ratio 260% shown');
    ok(await has(p, '#det', /MCR cover/) && await has(p, '#det', /764\.7%/), 'MCR cover');
    ok(await has(p, '#det', /Headroom 800,000/), 'headroom insight');
    ok(await has(p, '#det', /own funds \+50,000 contributed/), 'change split into own funds and RBC effects');
    ok(await has(p, '#det', /Capital quality/), 'capital quality insight');
    ok(await has(p, '#det', /above 100% in Q4/), 'combined ratio above 100% in Q4');
    ok(await has(p, '#det', /Tier components/) && await has(p, '#det', /Share capital \(synthetic\)/), 'tier components listed');
    ok(await has(p, '#det', /Template checks/) && await has(p, '#det', /PASS/), 'checks listed');
    ok(await has(p, '#det', /Financial projection/) && await has(p, '#det', /Net Combined Ratio/), 'projection table');
    ok(await has(p, '#det', /Presented to the Board/), 'board answers');
    ok(await has(p, '#periods', /2026-Q1/) && await has(p, '#periods', /draft/), 'period listed as draft');
    ok(!(await p.$('[data-act="approve"]')), 'an operator has no approve button');
    // the uploader, even as admin, cannot approve (four eyes)
    WHO = { user: 'fin.syn', role: 'admin' }; await p.reload(); await p.waitForSelector('#det .card');
    ok(!(await p.$('[data-act="approve"]')) && await has(p, '#det', /different person approves/), 'the uploader sees the four-eyes note, no approve button');
    // Risk approves
    WHO = { user: 'risk.syn', role: 'admin' }; await p.reload(); await p.waitForSelector('[data-act="approve"]');
    await p.click('[data-act="approve"]'); ok(await has(p, '#periods', /approved/) && await has(p, '#periods', /risk\.syn/), 'approved by Risk');
    ok(!!(await p.$('[data-act="reopen"]')), 'reopen offered after approval');
    // the report opens in a new tab: white, with insights
    const [pop] = await Promise.all([p.waitForEvent('popup'), p.click('[data-act="html"]')]); await pop.waitForLoadState();
    ok(/RBC Own Funds/.test(await pop.frameLocator('iframe[sandbox]').locator('h1').textContent()) && /Insights/.test(await pop.frameLocator('iframe[sandbox]').locator('html').innerHTML()), 'report opens'); await pop.close();
    // settings (admin): raise the target to 300% and the ratio verdict changes
    await p.click('#setb'); await p.fill('#f-tgt', '300'); await p.click('#dlgok');
    ok(await has(p, '#up', /Target 300%/) && await has(p, '#det', /below the 300% target/), 'settings change the verdict');
    // a viewer is refused
    const v = await browser.newPage(); WHO = { user: 'vera.syn', role: 'viewer' }; await v.goto(base + 'rbc-assessment.html?standalone=1');
    ok(await has(v, '#err', /internal/), 'viewer refused'); await v.close();
    const nav = fs.readFileSync(path.join(DASH, 'vendor', 'zyb-nav.js'), 'utf8'), inst = fs.readFileSync(path.join(DASH, 'install-dashboards.sh'), 'utf8');
    ok(/"h": "rbc-assessment.html"/.test(nav) && inst.includes('rbc-assessment.html') && inst.includes('vendor/zyb-rbc.js'), 'in the menu and the install list');
    ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  } finally { await browser.close(); srv.close(); await e.close(); }
  console.log((bad ? 'FAILED ' : 'ok ') + (n - bad) + '/' + n);
  process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
