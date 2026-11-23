// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for Pricing Adequacy (dashboards/server/pricing-adequacy.html, vendor/zyb-pricing.js) against the REAL ITAM engine,
// SYNTHETIC figures: Actuarial records a Motor review, the page shows the combined ratio and required rate change; a different person
// (Risk) approves (four eyes - the recorder cannot); the report opens; a viewer is refused; in the menu.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node pricing-adequacy.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const ITAM = path.join(__dirname, '..', '..', 'backend', 'itam'), DASH = path.join(__dirname, '..', '..', 'ui');
const H = require(path.join(ITAM, 'tests', 'helpers'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };

(async () => {
  const e = await H.startApp({ noAi: true });
  require(path.join(ITAM, 'engine/duty')).registerDuty(e.app.srv, e.app, { noTimer: true, python: process.env.PYTHON || 'python3' });
  let WHO = { user: 'act.syn', role: 'operator' };
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
    await p.goto(base + 'pricing-adequacy.html?standalone=1'); await p.waitForSelector('#newb:not([hidden])');
    ok(await has(p, '#lines', /Motor/) && await has(p, '#lines', /Medical/), 'both lines shown');
    ok(await has(p, '#lines', /no review yet|Record a review/), 'empty line state');
    // record an inadequate Motor review
    await p.click('#newb'); await p.waitForSelector('#f-period');
    await p.fill('#f-period', '2026-Q1'); await p.fill('#f-nep', '250000'); await p.fill('#f-ulr', '88'); await p.fill('#f-expense_ratio', '18'); await p.fill('#f-commission_ratio', '4'); await p.fill('#f-target_loss_ratio', '75'); await p.fill('#f-rate_change', '5');
    await Promise.all([p.waitForResponse((r) => /\/pricing-adequacy$/.test(r.url()) && r.request().method() === 'POST'), p.click('#dlgok')]);
    ok(await has(p, '#lines', /110/), 'combined ratio 110% shown'); ok(await has(p, '#lines', /inadequate/), 'inadequate verdict');
    ok(await has(p, '#reviews', /2026-Q1/), 'review listed');
    // the recorder cannot approve; Risk can
    ok(!(await p.$('[data-appr]')), 'an operator (recorder) has no approve button');
    WHO = { user: 'risk.syn', role: 'admin' }; await p.reload(); await p.waitForSelector('#reviews table');
    await Promise.all([p.waitForResponse((r) => /\/approve$/.test(r.url())), p.click('[data-appr]')]);
    ok(await has(p, '#reviews', /approved/), 'approved by Risk (four eyes)');
    ok(!!(await p.$('[data-reopen]')), 'an approved review can be reopened');
    // report opens (new tab intercepted)
    let opened = null; await p.context().route('**/*', (route) => route.continue()); p.on('popup', (pg) => { opened = pg; });
    await p.evaluate(() => { window.open = function () { window.__op = 1; return { closed: false }; }; });
    await p.click('#rhtml'); ok(await p.waitForFunction(() => window.__op === 1, null, { timeout: 8000 }).then(() => true, () => false), 'report opened');
    // viewer refused
    // read figures from a synthetic actuarial report PDF: proposals with pages, the form pre-filled, a value chosen, the draft names its source
    WHO = { user: 'act.syn', role: 'operator' }; await p.reload(); await p.waitForSelector('#pdfc:not([hidden])');
    await p.setInputFiles('#pdff', { name: 'pricing-2026Q1.pdf', mimeType: 'application/pdf', buffer: require(path.join(ITAM, 'tests', 'pdf-fixture')).pricingReport() });
    await p.click('#pdfgo'); ok(await has(p, '#pdfr', /figure\(s\) found/) && await has(p, '#pdfr', /Comprehensive/), 'the report is read: figures per line');
    ok(await has(p, '#pdfr', /choose/), 'a figure printed twice with different values asks to choose');
    const rows = await p.$$eval('#pdfr tbody tr', (x) => x.map((r) => r.textContent)); const ix = rows.findIndex((t) => /2026-Q1/.test(t) && /Comprehensive/.test(t));
    await p.click('[data-pxg="' + ix + '"]'); await p.waitForSelector('dialog[open] #f-ulr');
    ok((await p.inputValue('#f-ulr')) === '71.4' && (await p.inputValue('#f-period')) === '2026-Q1' && (await p.inputValue('#f-sub_line')) === 'Comprehensive', 'the form opens pre-filled from the report');
    ok(await has(p, '#dlgb', /p\.1/) && await has(p, '#dlgb', /Table 1/), 'each value shows the page and table it came from');
    await p.click('[data-pxv="ulr"][data-v="70.9"]'); ok((await p.inputValue('#f-ulr')) === '70.9', 'the other printed value is one click');
    await p.click('#dlgok'); ok(await has(p, '#reviews', /Comprehensive/), 'recorded as a draft');
    const rec = (await e.req('GET', '/pricing-adequacy', { user: 'act.syn', role: 'operator' })).json.reviews.find((x) => x.sub_line === 'Comprehensive');
    const det = (await e.req('GET', '/pricing-adequacy/' + rec.id, { user: 'act.syn', role: 'operator' })).json; ok(det.ulr === 70.9 && det.source && det.source.filename === 'pricing-2026Q1.pdf', 'the draft keeps the chosen value and names its source');
    WHO = { user: 'vera.syn', role: 'viewer' }; await p.reload();
    ok(await has(p, '#err', /internal/i), 'viewer refused');
    const nav = fs.readFileSync(path.join(DASH, 'vendor', 'zyb-nav.js'), 'utf8'), inst = fs.readFileSync(path.join(DASH, 'install-dashboards.sh'), 'utf8');
    ok(nav.includes('"pricing-adequacy.html"') && inst.includes('pricing-adequacy.html') && inst.includes('vendor/zyb-pricing.js'), 'in the menu and installed');
    ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  } finally { await browser.close(); srv.close(); await e.close(); }
  console.log((bad ? 'FAILED ' : 'ok ') + (n - bad) + '/' + n);
  process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
