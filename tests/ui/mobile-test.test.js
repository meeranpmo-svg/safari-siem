// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const ZYB_ORG = require('../../brand/index');
// Mobile Application Testing (mobile-test.html) against the REAL ITAM engine (engine/mobile-test.js) with a SYNTHETIC MobSF report: an
// operator registers an app (empty state first), opens it, imports the report from a file; the MASVS matrix (FAIL / PARTIAL), the release
// gate naming its failed rules, the findings with their MASVS group (secrets masked, a hostile title stays text); a manual MASTG check
// recorded; a risk acceptance requested and approved by a different administrator; a viewer sees the matrix but no findings; menu entry,
// installer, the portal's mobile redirect.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node mobile-test.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const ITAM = path.join(__dirname, '..', '..', 'backend', 'itam'), DASH = path.join(__dirname, '..', '..', 'ui');
const H = require(path.join(ITAM, 'tests', 'helpers'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const REPORT = JSON.stringify({ app_name: (ZYB_ORG.short + ' (synthetic)'), version_name: '4.2.0', package_name: 'sa.corp.synthetic', file_name: 'app.apk', security_score: 48,
  code_analysis: { findings: { world_readable: { files: {}, metadata: { description: 'World-readable file (synthetic)', severity: 'high', masvs: 'MSTG-STORAGE-2', cwe: 'CWE-276' } }, weak_hash: { files: {}, metadata: { description: 'MD5 used (synthetic)', severity: 'warning', masvs: 'MSTG-CRYPTO-4' } } } },
  manifest_analysis: { manifest_findings: [{ rule: 'debuggable', title: 'Debug enabled <img src=x onerror="window.__xss=1">', severity: 'high', description: 'android:debuggable=true' }] },
  network_security: { network_findings: [{ scope: ['*'], description: 'Cleartext traffic allowed (synthetic)', severity: 'high' }] },
  secrets: ['"google_api_key" : "AIzaSyNOTAREALKEY000000000000000000"'] });

(async () => {
  const e = await H.startApp({ noAi: true });
  require(path.join(ITAM, 'engine/duty')).registerDuty(e.app.srv, e.app, { noTimer: true, python: process.env.PYTHON || 'python3' });
  let WHO = { user: 'nora.syn', role: 'operator' };
  const srv = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://x'), json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u.pathname === '/dashboards/whoami.json') return json(200, WHO);
    if (u.pathname.startsWith('/api/itam/')) {
      const h = Object.assign({}, req.headers, { 'x-sentra-proxy-secret': H.SECRET, 'x-auth-user': WHO.user, 'x-auth-role': WHO.role });
      const up = http.request({ host: '127.0.0.1', port: e.port, method: req.method, path: req.url, headers: h }, (r) => { res.writeHead(r.statusCode, r.headers); r.pipe(res); });
      req.pipe(up); return;
    }
    if (u.pathname.startsWith('/api/')) return json(404, { error: 'not in this test' });
    const f = path.join(DASH, u.pathname.replace(/^\/dashboards\//, '')); if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (err, d) => { if (err) { res.writeHead(404); return res.end(); } res.writeHead(200, { 'Content-Type': f.endsWith('.js') ? 'application/javascript' : f.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port + '/dashboards/';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright'); const browser = await chromium.launch(), errs = [];
  const wait = (p, fn, arg) => p.waitForFunction(fn, arg, { timeout: 30000 }).then(() => true, () => false);
  const toast = (p, re) => wait(p, (s) => [...document.querySelectorAll('.toast')].some((t) => new RegExp(s).test(t.textContent)), re);
  let ANS = [];
  const page = async (ctx, f) => { const p = await ctx.newPage(); p.on('pageerror', (x) => errs.push(x.message)); p.on('dialog', (d) => { const a = ANS.shift(); if (a === undefined) { errs.push('unexpected dialog: ' + d.message()); d.dismiss(); } else d.accept(a); }); await p.goto(base + f + '?standalone=1'); await p.waitForSelector('#main:not([hidden])', { timeout: 60000 }); return p; };
  try {
    const ctx = await browser.newContext({ viewport: { width: 1500, height: 1000 } });
    let p = await page(ctx, 'mobile-test.html');
    ok(/No mobile app registered yet/.test(await p.textContent('#mx')), 'empty state says what to do');
    await p.fill('#aform [name=name]', (ZYB_ORG.short + ' Android (synthetic)')); await p.fill('#aform [name=package]', 'sa.corp.synthetic'); await p.selectOption('#aform [name=criticality]', 'critical'); await p.check('#aform [name=resilience]');
    await p.click('#aform button[type=submit]'); ok(await toast(p, 'App registered'), 'app registered');
    ok(await wait(p, () => /not tested/.test(document.getElementById('mx').textContent)), 'never tested: not tested, never pass');
    await p.click('#mx tr[data-app]'); await p.waitForSelector('#iform');
    await p.setInputFiles('#iform input[type=file]', { name: 'mobsf.json', mimeType: 'application/json', buffer: Buffer.from(REPORT) });
    await p.click('#iform button[type=submit]'); ok(await toast(p, 'Report imported'), 'report imported');
    ok(await wait(p, () => /World-readable/.test(document.getElementById('dlgb').textContent)), 'findings listed');
    const dl = await p.textContent('#dlgb');
    ok(/STORAGE/.test(dl) && /from the report/.test(dl), 'MASVS group from the report tag');
    ok(/Hard-coded secret/.test(dl) && !/AIzaSyNOTAREALKEY/.test(dl), 'the secret is masked');
    ok(await p.evaluate(() => !window.__xss && /<img src=x/.test(document.getElementById('dlgb').textContent)), 'a hostile title stays text');
    await p.selectOption('#vform [name=group]', 'AUTH'); await p.fill('#vform [name=note]', 'biometric binding and step-up verified on a device (synthetic)'); await p.click('#vform button[type=submit]');
    ok(await toast(p, 'Manual check recorded'), 'manual check recorded');
    ok(await wait(p, () => /AUTH<\/b> pass by nora\.syn/.test(document.getElementById('dlgb').innerHTML)), 'the check shows who recorded it');
    const until = new Date(Date.now() + 30 * 86400000).toISOString().slice(0, 10);
    ANS = ['compensating control at the gateway for now (synthetic)', until];
    await p.click('#dlgb tr:has-text("Cleartext") [data-ra]'); ok(await toast(p, 'Risk acceptance requested'), 'risk acceptance requested');
    await p.keyboard.press('Escape');
    const mx = await p.textContent('#mx'); ok(/FAIL/.test(mx) && /partial/.test(mx), 'MASVS matrix: FAIL and partial');
    const g = await p.textContent('#gates'); ok(/no go/.test(g) && /hard-coded secret/.test(g) && /high finding\(s\) in STORAGE/.test(g), 'release gate names its failed rules');
    ok(!(await p.$('[data-acc]')), 'the requester (an operator) cannot decide');
    if (process.env.SHOT) await p.screenshot({ path: process.env.SHOT, fullPage: true });   // optional: a picture for review
    WHO = { user: 'syed', role: 'admin' }; p = await page(ctx, 'mobile-test.html');
    await p.click('[data-acc="approve"]'); ok(await toast(p, 'Acceptance approved'), 'a different administrator approves');
    WHO = { user: 'vera.syn', role: 'viewer' }; p = await page(ctx, 'mobile-test.html');
    ok(/FAIL/.test(await p.textContent('#mx')) && /operators and administrators/.test(await p.textContent('#accs')), 'a viewer sees the matrix, not the acceptances');
    ok(await p.$eval('#regc', (x) => x.hidden), 'a viewer cannot register an app');
    const nav = fs.readFileSync(path.join(DASH, 'vendor', 'zyb-nav.js'), 'utf8');
    ok(/"h": "mobile-test.html"/.test(nav) && /mobile-test\.html/.test(fs.readFileSync(path.join(DASH, 'install-dashboards.sh'), 'utf8')), 'menu entry and installer');
    ok(/mobile: 'mobile-test\.html'/.test(fs.readFileSync(path.join(DASH, 'vendor', 'zyb-menu.js'), 'utf8')) && /mobile: 'mobile-test\.html'/.test(fs.readFileSync(path.join(DASH, 'vendor', 'zyb-early.js'), 'utf8')), 'the portal Mobile Application Testing opens this page');
    ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  } finally { await browser.close(); srv.close(); await e.close(); }
  console.log((bad ? 'FAILED ' : 'ok ') + (n - bad) + '/' + n);
  process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
