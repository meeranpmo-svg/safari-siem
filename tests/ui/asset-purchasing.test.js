// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for dashboards/server/asset-purchasing.html against the REAL ITAM engine (engine/asset-autofill.js through duty.js) with
// SYNTHETIC data: empty state; a request with product lines (the page and the server check it); four eyes - the requester cannot approve,
// a second person does; ordered with a PO number; items received with serials become assets with purchase + warranty; budget
// utilisation; vendor scorecard; viewers see no costs; escaped; menu + installer.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node asset-autofill.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const ITAM = path.join(__dirname, '..', '..', 'backend', 'itam'), DASH = path.join(__dirname, '..', '..', 'ui');
const H = require(path.join(ITAM, 'tests', 'helpers'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const ADM = { user: 'syed', role: 'admin' }, OP = { user: 'nora.syn', role: 'operator' }, OP2 = { user: 'head.syn', role: 'operator' }, VW = { user: 'vera.syn', role: 'viewer' };
const XSS = '<img src=x onerror="window.__xss=1">';

(async () => {
  const e = await H.startApp({ noAi: true });
  require(path.join(ITAM, 'engine/duty')).registerDuty(e.app.srv, e.app, { noTimer: true });
  const B = e.app.addons.budget || (e.app.addons.budget = require(path.join(ITAM, 'engine/budget')).createBudget(e.app));
  B.saveLine({ envelope: 'it_ops', area: 'infrastructure', kind: 'capex', title: 'Laptop refresh SYN', amount: 50000 }, ADM);
  const lineId = B.build().lines.find((l) => l.title === 'Laptop refresh SYN').id; B.decide(lineId, { status: 'approved' }, ADM);
  let WHO = OP;
  const web = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://x'), json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u.pathname === '/dashboards/whoami.json') return json(200, WHO);
    if (u.pathname.startsWith('/api/itam/')) {
      const h = Object.assign({}, req.headers, { 'x-sentra-proxy-secret': H.SECRET, 'x-auth-user': WHO.user, 'x-auth-role': WHO.role });
      const up = http.request({ host: '127.0.0.1', port: e.port, method: req.method, path: req.url, headers: h }, (r) => { res.writeHead(r.statusCode, r.headers); r.pipe(res); });
      req.pipe(up); return;
    }
    if (u.pathname.startsWith('/api/')) return json(404, { error: 'not in this test' });
    const f = path.join(DASH, u.pathname.replace(/^\/dashboards\//, '/')); if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (err, d) => { if (err) { res.writeHead(404); res.end(); return; } res.writeHead(200, { 'Content-Type': u.pathname.endsWith('.js') ? 'application/javascript' : u.pathname.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => web.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + web.address().port + '/dashboards/';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  const wait = (p, fn, arg) => p.waitForFunction(fn, arg, { timeout: 15000 }).then(() => true, () => false);
  const txt = (p, id) => p.evaluate((i) => document.getElementById(i).innerText, id);
  try {
    const p = await browser.newPage({ viewport: { width: 1500, height: 1000 } }); p.on('pageerror', (x) => errs.push(x.message)); p.on('dialog', (d) => { errs.push('dialog ' + d.message()); d.dismiss(); });
    await p.goto(base + 'asset-purchasing.html');
    ok(await wait(p, () => /No purchase recorded yet/.test(document.body.innerText)), 'empty state says what to do');
    await p.click('#b-new'); await p.click('#n-save'); ok(/Title is required/.test(await txt(p, 'n-err')), 'the page checks the title');
    await p.fill('#n-title', 'Laptops for Finance ' + XSS); await p.fill('#v-name', 'SynSupplier'); await p.fill('#v-email', 'bad-mail');
    await p.selectOption('#n-bl', lineId);
    await p.fill('#n-lines [data-k=product]', 'SynBook 14'); await p.selectOption('#n-lines [data-k=type]', 'laptop'); await p.fill('#n-lines [data-k=qty]', '2'); await p.fill('#n-lines [data-k=unit_cost]', '5000'); await p.fill('#n-lines [data-k=warranty_months]', '36');
    ok(/10,000/.test(await txt(p, 'n-total')), 'running total');
    await p.click('#n-save'); ok(await wait(p, () => /vendor.email/.test(document.getElementById('n-err').innerText)), 'the server re-checks the vendor e-mail');
    await p.fill('#v-email', 'sales@supplier.syn'); await p.click('#n-save');
    ok(await wait(p, () => /submitted for approval/.test(document.body.innerText)), 'request submitted');
    ok(await p.evaluate(() => !window.__xss) && !(await p.$('#list img')), 'titles escaped');
    await p.click('#list [data-id]'); await wait(p, () => !document.getElementById('drw').hidden);
    await p.click('#d-appr'); ok(await wait(p, () => /four eyes/.test(document.getElementById('d-err').innerText)), 'the requester cannot approve');
    WHO = OP2; await p.reload(); await wait(p, () => document.querySelector('#list [data-id]'));
    await p.click('#list [data-id]'); await p.click('#d-appr'); ok(await wait(p, () => /✓ approved/.test(document.getElementById('drw').innerText)), 'a second person approves');
    await p.fill('#d-po', 'PO-SYN-77'); await p.click('#d-go'); ok(await wait(p, () => /✓ ordered/.test(document.getElementById('drw').innerText)), 'ordered with a PO number');
    await wait(p, () => document.querySelector('[data-rs="1"]'));
    await p.fill('[data-rs="1"]', 'SYN-S1\nSYN-S2'); await p.click('#d-rcv');
    ok(await wait(p, () => /2 asset\(s\) created/.test(document.getElementById('drw').innerText)), 'received into the asset register');
    const made = e.app.store.collection('assets').all((a) => a.serial === 'SYN-S1')[0];
    ok(made && made.purchase.po === 'PO-SYN-77' && made.warranty && made.warranty.end, 'asset carries purchase and warranty');
    await p.click('#d-x'); await p.click('[data-tab="bu"]');
    const bu = await txt(p, 'bu'); ok(/Laptop refresh SYN[\s\S]*50,000[\s\S]*10,000/.test(bu) && /20 %/.test(bu), 'budget line: 10 000 committed of 50 000 = 20 %: ' + bu.replace(/\s+/g, ' ').slice(0, 300));
    await p.click('[data-tab="ve"]'); ok(/SynSupplier/.test(await txt(p, 'vend')), 'vendor scorecard');
    WHO = VW; await p.reload(); ok(await wait(p, () => /operators and administrators/.test(document.body.innerText)), 'viewers do not see costs');
    await p.close();
    const q = await browser.newPage(); await q.goto(base + 'lifecycle-studio.html'); await q.waitForTimeout(800);
    ok(await q.evaluate(() => !!document.querySelector('a[href="asset-purchasing.html"]')), 'menu entry'); await q.close();
    ok(/ asset-purchasing\.html /.test(fs.readFileSync(path.join(DASH, 'install-dashboards.sh'), 'utf8')), 'in the installer');
    ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  } finally { await browser.close(); web.close(); e.close(); }
  console.log(`${n - bad}/${n} checks passed`); process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
