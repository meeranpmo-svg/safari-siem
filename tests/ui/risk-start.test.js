// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Start a Risk Assessment (risk-start.html) against the REAL Business Risk register and assessment cycle (engine/business-risk.js,
// engine/risk-programme.js) with a SYNTHETIC register (tests/brisk-fixture.js) and synthetic people: the method and position are shown;
// a new risk is added with machine-learning suggestions (a hostile title stays text); an administrator opens the cycle for one
// department; an operator re-assesses one risk up to Class IV with a live class preview and confirms the rest unchanged; the Class IV
// risk is accepted by the operator and the acceptance waits for, and is approved by, an administrator; the assessor cannot sign the
// department off, another operator does; the administrator who opened the cycle cannot approve it, a second administrator does - the
// cycle is approved and frozen; the committee report is built; no undefined / NaN on any step, no page error, no browser dialog.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node risk-start.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const ITAM = path.join(__dirname, '..', '..', 'backend', 'itam'), DASH = path.join(__dirname, '..', '..', 'ui');
const H = require(path.join(ITAM, 'tests', 'helpers'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
(async () => {
  const e = await H.startApp({ noAi: true });
  require(path.join(ITAM, 'engine/duty')).registerDuty(e.app.srv, e.app, { noTimer: true, python: process.env.PYTHON || 'python3' });
  const F = require(path.join(ITAM, 'tests', 'brisk-fixture'));
  const imp = (kind, b64) => e.req('POST', '/brisk/import/' + kind, { body: { filename: kind + '.xlsx', xlsx_b64: b64, apply: true }, user: 'adam.syn', role: 'admin' });
  await imp('register', await F.registerB64());
  const XSS = '<img src=x onerror="window.__x=1">';
  let WHO = { user: 'syed', role: 'admin' };
  const srv = http.createServer((req, res) => {
    const u2 = new URL(req.url, 'http://x'), json = (c, b2) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b2)); };
    if (u2.pathname === '/dashboards/whoami.json' || u2.pathname === '/auth/whoami') return json(200, WHO);
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
  const base = 'http://127.0.0.1:' + srv.address().port + '/risk-start.html';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  const p = await browser.newPage({ viewport: { width: 1440, height: 950 } });
  p.on('pageerror', (x) => errs.push(x.message)); p.on('dialog', (d) => { errs.push('dialog: ' + d.message()); d.dismiss(); });
  const wait = (fn, a) => p.waitForFunction(fn, a, { timeout: 10000 }).then(() => true, () => false);
  const toastHas = (re) => p.waitForFunction((s) => new RegExp(s).test([...document.querySelectorAll('.toast')].map((t) => t.textContent).join(' ')), re.source, { timeout: 10000 }).then(() => true, () => false);
  const as = async (who) => { WHO = who; await p.goto('about:blank'); await p.goto(base); await p.waitForSelector('#steps li'); await p.waitForTimeout(250); };
  const step = async (n) => { await p.click('#steps [data-step="' + n + '"]'); await p.waitForTimeout(150); };
  const form = async (vals) => { await p.waitForSelector('#dlgbg.open'); for (const [k, v] of Object.entries(vals)) await p.fill('#' + k, String(v)); await p.click('#dlgok'); };
  const panel = () => p.evaluate(() => document.getElementById('panel').innerText);
  const done = (n) => p.waitForFunction((k) => document.querySelector('#steps li:nth-child(' + k + ')').classList.contains('done'), n, { timeout: 8000 }).then(() => true, () => false);
  const ADM = { user: 'adam.syn', role: 'admin' }, ADM2 = { user: 'aisha.syn', role: 'admin' }, OP = { user: 'nora.syn', role: 'operator' }, OP2 = { user: 'omar.syn', role: 'operator' };
  const d = (n) => new Date(Date.now() + n * 86400000).toISOString().slice(0, 10), y = new Date().getUTCFullYear(), q = 'Q' + (Math.floor(new Date().getUTCMonth() / 3) + 1);
  try {
    await as(ADM); ok(/3 · Open the assessment cycle/.test(await panel()), 'opens on the first step still to do (the cycle)'); await step(1); ok(/1 · Scope and method/.test(await panel()) && /Class IV/.test(await panel()) && /Synthetic IT/.test(await panel()), 'step 1: the method, the matrix and the departments');
    // 2 a new risk with machine-learning suggestions
    await step(2); await p.fill('#n-title', 'Claim fraud not detected ' + XSS); await p.fill('#n-desc', 'Weak fraud checks lead to fraudulent claims paid');
    await p.click('#n-sugg'); ok(await p.waitForFunction(() => /Suggested/.test((document.getElementById('n-out') || {}).innerText || ''), null, { timeout: 8000 }).then(() => true, () => false), 'suggestion shown');
    ok(/possible duplicate|similar/.test(await p.$eval('#n-out', (x) => x.innerText)), 'similar risks named');
    await p.fill('#n-dept', 'Synthetic IT'); await p.fill('#n-owner', 'Synthetic IT Head'); await p.selectOption('#n-e', '2'); await p.click('#n-add');
    ok(await toastHas(/Risk added/), 'risk added'); ok(!(await p.evaluate(() => window.__x)), 'a hostile title stays text');
    // 3 open the cycle (one department)
    await step(3); await p.fill('#c-period', y + '-' + q); await p.fill('#c-due', d(30)); await p.check('[data-cdept="Synthetic IT"]'); await p.click('#c-open');
    ok(await toastHas(/Cycle opened/) && await done(3), 'cycle opened by an administrator');
    // 4 assess: one risk up to Class IV, the rest unchanged
    await as(OP); ok(/4 · Assess every risk/.test(await panel()), 'opens on the assessment step');
    const ks = await p.$$eval('[data-sub]', (b) => b.map((x) => x.getAttribute('data-k'))); ok(ks.length >= 2, 'risks to assess: ' + ks.length);
    const k0 = ks[0]; await p.selectOption('#' + k0 + '-l', '5'); await p.selectOption('#' + k0 + '-i', '4'); await p.selectOption('#' + k0 + '-e', '5');
    ok(/Preview: inherent High \(20\) → Class IV/.test(await p.$eval('[data-prev="' + k0 + '"]', (x) => x.textContent)), 'live class preview');
    await p.click('[data-sub][data-k="' + k0 + '"]'); ok(await toastHas(/Not done|Note/), 'a note is required');
    await p.fill('#' + k0 + '-n', 'Two incidents this quarter (synthetic)'); await p.click('[data-sub][data-k="' + k0 + '"]'); ok(await toastHas(/Assessed/), 'assessed');
    for (const k of ks.slice(1)) { await p.waitForSelector('[data-unch][data-k="' + k + '"]'); await p.fill('#' + k + '-n', 'No change (synthetic)'); await p.click('[data-unch][data-k="' + k + '"]'); await p.waitForTimeout(350); }
    ok(await done(4), 'every risk assessed');
    // 5 treat: accept the Class IV risk - waits for a second administrator
    await step(5); ok(/Class IV/.test(await panel()), 'the Class IV risk is listed');
    const tk = await p.$eval('[data-treat]', (b) => b.getAttribute('data-k')); await p.selectOption('#' + tk + '-r', 'accept'); await p.click('[data-treat]');
    ok(await toastHas(/acceptance waits for a second administrator/), 'acceptance requested');
    await as(ADM); await step(5); await p.click('[data-accd="approve"]'); ok(await toastHas(/Acceptance approved/) && await done(5), 'acceptance approved by an administrator');
    // 6 sign-off: not by the assessor
    await as(OP); await step(6); await p.click('[data-sign]'); await form({}); ok(await toastHas(/Not done/), 'the assessor cannot sign the department off');
    await as(OP2); await step(6); await p.click('[data-sign]'); await form({ 'd-note': 'Reviewed (synthetic)' }); ok(await toastHas(/signed off/) && await done(6), 'signed off by another person');
    // 7 committee: not the opener
    await as(ADM); await step(7); await p.click('[data-dec="approve"]'); await form({}); ok(await toastHas(/Not done/), 'the administrator who opened the cycle cannot approve it');
    await as(ADM2); await step(7); await p.click('[data-dec="approve"]'); await form({ 'd-note': 'Committee approved (synthetic)' }); ok(await toastHas(/Cycle approved/) && await done(7), 'approved by the committee');
    ok(e.app.store.auditTail(500).some((x) => /cycle/.test(x.action) && /approve/.test(x.action)), 'the approval is in the audit trail');
    // 8 report
    await step(8); await p.click('[data-rep="committee"]'); ok(await toastHas(/Report built/), 'committee report built');
    let clean = true; for (let k = 1; k <= 8; k++) { await step(k); if (/undefined|NaN|\[object Object\]/.test(await panel())) { clean = false; console.log('step', k, 'shows undefined/NaN'); } }
    ok(clean, 'every step renders without undefined / NaN / [object Object]');
    ok(!errs.length, 'no page errors or browser dialogs: ' + errs.join(' | '));
  } finally { await browser.close(); srv.close(); await e.close(); }
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks'); process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
