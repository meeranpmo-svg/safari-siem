// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Application Pen Testing (dashboards/server/apppt.html) against the REAL ITAM engine (engine/apppt.js) with SYNTHETIC data: the
// empty state says what to add; an operator adds an application (risk card, never tested) and plans an engagement; the scope is
// requested, the requester cannot approve, an administrator approves; testing starts inside the window; a finding is recorded and
// an OWASP ZAP report imported (informational skipped, a token in the evidence never shown); every WSTG area decided, then reported;
// the fix is claimed, the claimer's own retest is refused, another person's retest verifies it; the Verified chip; OWASP chart and
// coverage heat map; Excel; a hostile title stays text; a viewer sees no endpoint, no steps, no Excel and no forms; menu + installer.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node apppt.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const ITAM = path.join(__dirname, '..', '..', 'backend', 'itam'), DASH = path.join(__dirname, '..', '..', 'ui');
const H = require(path.join(ITAM, 'tests', 'helpers'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const XSS = '<img src=x onerror="window.__xss=1">', TOKEN = 'ghp_' + 'SYNTHETICSYNTHETICSYNTHETIC1234567';
const day = (d) => new Date(Date.now() + d * 86400000).toISOString().slice(0, 10);
const ZAP = JSON.stringify({ site: [{ '@name': 'https://portal.synthetic.test', alerts: [
  { alert: 'SQL Injection', riskcode: '3', cweid: '89', desc: 'synthetic', solution: 'parameterise', instances: [{ uri: 'https://portal.synthetic.test/search', method: 'GET', param: 'q', evidence: 'Authorization: Bearer ' + TOKEN }] },
  { alert: 'Server Leaks Version', riskcode: '0', cweid: '200', instances: [{ uri: 'https://portal.synthetic.test/' }] }] }] });

(async () => {
  const e = await H.startApp({ noAi: true });
  require(path.join(ITAM, 'engine/duty')).registerDuty(e.app.srv, e.app, { noTimer: true });
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
  const url = 'http://127.0.0.1:' + srv.address().port + '/dashboards/apppt.html?standalone=1';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright'); const browser = await chromium.launch(), errs = [];
  const wait = (p, fn, arg) => p.waitForFunction(fn, arg, { timeout: 20000 }).then(() => true, () => false);
  const toast = (p, re) => wait(p, (s) => [...document.querySelectorAll('.toast')].some((t) => new RegExp(s).test(t.textContent)), re);
  let ANSWERS = [];
  const page = async (ctx) => { const p = await ctx.newPage(); p.on('pageerror', (x) => errs.push(x.message)); p.on('dialog', (d) => { const a = ANSWERS.shift(); if (a === undefined) { errs.push('unexpected dialog: ' + d.message()); d.dismiss(); } else d.accept(a); }); await p.goto(url); await p.waitForSelector('#main:not([hidden])'); return p; };
  try {
    const ctx = await browser.newContext({ viewport: { width: 1500, height: 1000 }, acceptDownloads: true });
    const p = await page(ctx);
    ok(/No application is in the programme yet/.test(await p.textContent('#apps')), 'empty state says what to add');
    // an application
    await p.click('#newapp summary'); await p.fill('#appf [name=name]', 'Customer portal ' + XSS); await p.fill('#appf [name=url]', 'https://portal.synthetic.test'); await p.selectOption('#appf [name=criticality]', 'critical'); await p.fill('#appf [name=owner]', 'digital.syn');
    await p.click('#appf button[type=submit]'); ok(await wait(p, () => document.querySelectorAll('#apps .app').length === 1), 'application added');
    ok(/never tested/.test(await p.textContent('#apps')) && /every 90 days/.test(await p.textContent('#apps')), 'card: never tested, 90-day cadence for critical external');
    ok(!(await p.evaluate(() => window.__xss)), 'a hostile name stayed text');
    // an engagement
    await p.click('#neweng summary'); await p.fill('#engf [name=title]', 'Q4 portal test (synthetic)'); await p.selectOption('#engf [name=target_ids]', { index: 0 }); await p.fill('#engf [name=tester]', 'Internal red team (synthetic)');
    await p.fill('#engf [name=window_start]', day(0)); await p.fill('#engf [name=window_end]', day(10)); await p.fill('#engf [name=rules]', 'Test accounts tester1 / tester2 only; no denial of service');
    await p.click('#engf button[type=submit]'); ok(await wait(p, () => document.querySelectorAll('#flow .eng').length === 1), 'engagement planned (Draft column)');
    await p.click('#flow .eng'); await p.waitForSelector('#dlg:not([hidden]) [data-eact="scope"]');
    await p.click('[data-eact="scope"]'); ok(await wait(p, () => document.querySelector('[data-sdec="approve"]')), 'scope requested');
    await p.click('[data-sdec="approve"]'); ok(await toast(p, 'four eyes|CISO'), 'the requester (an operator) cannot approve the scope');
    // the administrator approves
    WHO = { user: 'sara.syn', role: 'admin' }; const a = await page(ctx);
    ok(/scope waits for the CISO/.test(await a.textContent('#attn')), 'attention: scope waiting');
    await a.click('#attn .att[data-att]'); await a.waitForSelector('[data-sdec="approve"]'); await a.click('[data-sdec="approve"]');
    ok(await wait(a, () => document.querySelector('[data-state="testing"]')), 'scope approved by someone else');
    await a.click('[data-state="testing"]'); ok(await wait(a, () => /Testing/.test(document.querySelector('#dlg h2').textContent) && document.querySelector('#ff')), 'testing started inside the window');
    // a finding, then the tester's ZAP report
    await a.click('#ff >> xpath=..//summary'); await a.fill('#ff [name=title]', 'Stored XSS in claim notes ' + XSS); await a.selectOption('#ff [name=severity]', 'high'); await a.fill('#ff [name=cwe]', 'CWE-79'); await a.fill('#ff [name=endpoint]', '/claims/notes'); await a.fill('#ff [name=steps]', 'POST a note with a script tag');
    await a.click('#ff button[type=submit]'); ok(await wait(a, () => /Stored XSS/.test(document.getElementById('dlgb').textContent)), 'finding recorded');
    await a.click('#impt >> xpath=../..//summary'); await a.setInputFiles('#impf', { name: 'zap.json', mimeType: 'application/json', buffer: Buffer.from(ZAP) }); await a.click('#impgo');
    ok(await toast(a, '1 added.*1 informational skipped'), 'ZAP import: 1 added, informational skipped');
    ok(await wait(a, () => /SQL Injection/.test(document.getElementById('dlgb').textContent)), 'imported finding listed');
    ok(!(await a.content()).includes(TOKEN), 'the token in the ZAP evidence is never shown');
    // coverage, then the report
    for (const k of ['INFO', 'CONF', 'IDNT', 'ATHN', 'ATHZ', 'SESS', 'INPV', 'ERRH', 'CRYP', 'BUSL', 'CLNT', 'APIT']) { await a.selectOption('select[data-cov="' + k + '"]', k === 'CLNT' ? 'na' : 'tested'); await wait(a, (kk) => { const s = document.querySelector('select[data-cov="' + kk + '"]'); return s && s.value; }, k); }
    ok(await wait(a, () => /12 of 12 decided/.test(document.getElementById('dlgb').textContent)), 'every WSTG area decided');
    await a.click('[data-state="reported"]'); ok(await wait(a, () => /Reported/.test(document.querySelector('#dlg h2').textContent)), 'reported');
    // the fix: claimed by the administrator, refused as their own retest, verified by the operator
    await a.click('#dlgb tr[data-f]:has-text("Stored XSS")'); await a.waitForSelector('[data-fact="claim_fix"]');
    ANSWERS = ['CHG-SYN-1 output encoding']; await a.click('[data-fact="claim_fix"]'); ok(await wait(a, () => document.querySelector('[data-fact="retest_pass"]')), 'fix claimed');
    ANSWERS = ['payload encoded']; await a.click('[data-fact="retest_pass"]'); ok(await toast(a, 'four eyes'), 'the claimer cannot verify their own fix');
    await a.click('[data-close]');
    WHO = { user: 'nora.syn', role: 'operator' }; await p.reload(); await p.waitForSelector('#main:not([hidden])');
    ok(/fix claimed, waits for a retest/.test(await p.textContent('#attn')), 'attention: waiting for retest');
    await p.click('#attn .att[data-fid]'); await p.waitForSelector('[data-fact="retest_pass"]');
    ANSWERS = ['payload encoded in page and PDF']; await p.click('[data-fact="retest_pass"]');
    ok(await wait(p, () => /verified fixed/.test(document.getElementById('dlgb').textContent)), 'verified by another person\'s retest');
    await p.click('[data-close]'); await p.click('[data-ff="verified"]'); ok(await wait(p, () => document.querySelectorAll('#fl tr[data-f]').length === 1), 'Verified chip');
    ok(/A03 Injection/.test(await p.textContent('#cats')), 'OWASP chart (SQL injection → A03)');
    ok((await p.$$('#heat td.hb-t')).length === 11 && (await p.$$('#heat td.hb-n')).length === 1, 'coverage heat map: 11 tested, 1 not applicable');
    const [dl] = await Promise.all([p.waitForEvent('download', { timeout: 15000 }), p.click('#xls')]);
    ok(/^app-pentest-findings-\d{4}-\d{2}-\d{2}\.xlsx$/.test(dl.suggestedFilename()), 'Excel');
    { const x = fs.readFileSync(await dl.path(), 'latin1'); ok(x.includes('Stored XSS') && x.includes('Verified by') && x.includes('nora.syn'), 'the Excel file holds the findings and who verified them'); }
    if (process.env.SHOT) await p.screenshot({ path: process.env.SHOT, fullPage: true });   // optional: a picture for review
    ok(!(await p.evaluate(() => window.__xss)) && !(await a.evaluate(() => window.__xss)), 'no hostile text ran');
    // viewer
    WHO = { user: 'vera.syn', role: 'viewer' }; const v = await page(ctx);
    ok(!(await v.isVisible('#xls')) && !(await v.$('#newapp summary')) && !(await v.$('#neweng summary')), 'viewer: no Excel, no forms');
    await v.click('[data-ff="all"]'); await v.click('#fl tr[data-f]'); ok(await wait(v, () => /shown to operators and administrators/.test(document.getElementById('dlgb').textContent)), 'viewer: no endpoint or steps');
    ok(!/\/claims\/notes/.test(await v.textContent('#dlgb')), 'viewer: the endpoint is not in the page');
    ok(/shown to operators and administrators/.test(await v.textContent('#ai')), 'viewer: no AI analyst');
    const nav = fs.readFileSync(path.join(DASH, 'vendor', 'zyb-nav.js'), 'utf8');
    ok(/"h": "apppt.html"/.test(nav) && /apppt\.html/.test(fs.readFileSync(path.join(DASH, 'install-dashboards.sh'), 'utf8')), 'menu entry and installer');
    ok(/apppt: 'apppt\.html'/.test(fs.readFileSync(path.join(DASH, 'vendor', 'zyb-menu.js'), 'utf8')) && /apppt: 'apppt\.html'/.test(fs.readFileSync(path.join(DASH, 'vendor', 'zyb-early.js'), 'utf8')), 'the portal\'s App Pen Testing opens this page');
    ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  } finally { await browser.close(); srv.close(); await e.close(); }
  console.log((bad ? 'FAILED ' : 'ok ') + (n - bad) + '/' + n);
  process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
