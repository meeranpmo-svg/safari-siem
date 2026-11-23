// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for Process Risk Assessments (dashboards/server/risk-assessments.html, vendor/zyb-procassess.js) against the REAL
// ITAM engine, SYNTHETIC data: a risk officer creates a procurement assessment and records a finding (rating shown); submits; a
// different person (Risk) approves (four eyes - the author cannot); the report opens; a viewer is refused; in the menu.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node risk-assessments.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const ITAM = path.join(__dirname, '..', '..', 'backend', 'itam'), DASH = path.join(__dirname, '..', '..', 'ui');
const H = require(path.join(ITAM, 'tests', 'helpers'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };

(async () => {
  const e = await H.startApp({ noAi: true });
  require(path.join(ITAM, 'engine/duty')).registerDuty(e.app.srv, e.app, { noTimer: true, python: process.env.PYTHON || 'python3' });
  let WHO = { user: 'ro.syn', role: 'operator' };
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
    await p.goto(base + 'risk-assessments.html?standalone=1'); await p.waitForSelector('#newb:not([hidden])');
    ok(await has(p, '#list', /No assessment yet/), 'empty state');
    await p.click('#newb'); await p.waitForSelector('#f-title');
    await p.fill('#f-title', 'Procurement deep-dive Q1'); await p.selectOption('#f-process', 'procurement'); await p.fill('#f-owner', 'proc.head'); await p.fill('#f-objective', 'Assess procurement controls (synthetic)');
    await Promise.all([p.waitForResponse((r) => /\/process-assessment$/.test(r.url()) && r.request().method() === 'POST'), p.click('#dlgok')]);
    ok(await has(p, '#dt', /Procurement deep-dive/), 'opened the new assessment');
    ok(await has(p, '#obj', /Suggested focus areas/), 'procurement focus areas shown');
    await p.click('#addf'); await p.waitForSelector('#f-area');
    await p.fill('#f-area', 'Single-source buys'); await p.fill('#f-observation', 'Emergency single-source purchases above the limit (synthetic).'); await p.fill('#f-likelihood', '4'); await p.fill('#f-impact', '4'); await p.fill('#f-recommendation', 'Require committee approval above SAR 100k');
    await Promise.all([p.waitForResponse((r) => /\/findings$/.test(r.url())), p.click('#dlgok')]);
    ok(await has(p, '#finds', /critical \(16\)/), 'finding rated critical (16)');
    ok(await has(p, '#dkk', /critical/), 'overall rating critical');
    // raise a GRC action
    await Promise.all([p.waitForResponse((r) => /\/action$/.test(r.url())), p.click('[data-af]')]);
    ok(await has(p, '#finds', /ACT-/), 'GRC action raised');
    // submit, then four-eyes approve by Risk
    await Promise.all([p.waitForResponse((r) => /\/submit$/.test(r.url())), p.click('[data-a="submit"]')]);
    ok(await has(p, '#dkk', /in_review/), 'submitted for review');
    ok(!(await p.$('[data-a="approve"]')), 'the author (operator) has no approve button');
    WHO = { user: 'risk.syn', role: 'admin' }; await p.reload(); await p.waitForSelector('#list table'); await p.click('#list tr[data-open]');
    await Promise.all([p.waitForResponse((r) => /\/approve$/.test(r.url())), p.click('[data-a="approve"]')]);
    ok(await has(p, '#dkk', /approved/), 'approved by Risk (four eyes)');
    // report opens
    await p.evaluate(() => { window.open = function () { window.__op = 1; return { closed: false }; }; });
    await p.click('#rep'); ok(await p.waitForFunction(() => window.__op === 1, null, { timeout: 8000 }).then(() => true, () => false), 'report opened');
    // viewer refused
    WHO = { user: 'vera.syn', role: 'viewer' }; await p.reload(); ok(await has(p, '#err', /internal/i), 'viewer refused');
    const nav = fs.readFileSync(path.join(DASH, 'vendor', 'zyb-nav.js'), 'utf8'), inst = fs.readFileSync(path.join(DASH, 'install-dashboards.sh'), 'utf8');
    ok(nav.includes('"risk-assessments.html"') && inst.includes('risk-assessments.html') && inst.includes('vendor/zyb-procassess.js'), 'in the menu and installed');
    ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  } finally { await browser.close(); srv.close(); await e.close(); }
  console.log((bad ? 'FAILED ' : 'ok ') + (n - bad) + '/' + n);
  process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
