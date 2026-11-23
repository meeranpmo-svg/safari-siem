// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for solvency-capital.html against the REAL engine (engine/solvency.js) with a SYNTHETIC workbook in the layout of
// the Insurance Authority's Solvency and Capital template (backend/itam/tests/sca-fixture.js): upload from the page, the KPIs and
// results, the failed check explained, every area signed off, the uploader cannot review, review by another operator, approval by
// the Risk Head (job role), the download (sign-offs written into the workbook, formulas kept), the submission record, a hostile
// text stays text, a viewer reads but cannot upload or download, phone width, the menu entry and the installer.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node solvency-capital.test.js
const http = require('http'), fs = require('fs'), os = require('os'), path = require('path');
const ITAM = path.join(__dirname, '..', '..', 'backend', 'itam'), DASH = path.join(__dirname, '..', '..', 'ui');
const H = require(path.join(ITAM, 'tests', 'helpers'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
(async () => {
  const e = await H.startApp({ noAi: true });
  require(path.join(ITAM, 'engine/duty')).registerDuty(e.app.srv, e.app, { noTimer: true, now: () => Date.parse('2026-02-20T08:00:00Z'), python: process.env.PYTHON || 'python3' });
  const F = require(path.join(ITAM, 'tests', 'sca-fixture')), { readBook } = require(path.join(ITAM, 'engine', 'xlsx-book'));
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'sca-')), wb = path.join(tmp, '20260226_Solvency_and_Capital_Template_2026_vSCA.04_SYN.xlsx');
  fs.writeFileSync(wb, F.build());
  let who = { user: 'nora.syn', role: 'operator' };
  const srv = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://x'), json = (code, b) => { res.writeHead(code, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u.pathname === '/dashboards/whoami.json') return json(200, who);
    if (u.pathname.startsWith('/api/itam/')) { const h = Object.assign({}, req.headers, { 'x-sentra-proxy-secret': H.SECRET, 'x-auth-user': who.user, 'x-auth-role': who.role });
      const up = http.request({ host: '127.0.0.1', port: e.port, method: req.method, path: req.url, headers: h }, (r) => { res.writeHead(r.statusCode, r.headers); r.pipe(res); }); req.pipe(up); return; }
    if (u.pathname.startsWith('/api/') || u.pathname === '/') return json(404, { error: 'not in this test' });
    const f = path.join(DASH, u.pathname.replace(/^\/dashboards\//, '/')); if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (err, d) => { if (err) { res.writeHead(404); res.end(); return; } res.writeHead(200, { 'Content-Type': u.pathname.endsWith('.js') ? 'application/javascript' : u.pathname.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port + '/solvency-capital.html?standalone=1';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  const wait = (p, fn, arg) => p.waitForFunction(fn, arg === undefined ? null : arg, { timeout: 20000 }).then(() => true, () => false);
  const toast = (p, re) => wait(p, (s) => [...document.querySelectorAll('.toast')].some((t) => new RegExp(s).test(t.textContent)), re);
  const dlgOk = (p) => p.click('#dlgok');
  try {
    // the Risk Head is a job role (approval scope 'risk')
    await e.req('POST', '/roles/assign', { body: { user: 'rita.syn', role_id: 'risk-head' }, user: 'adam.syn', role: 'admin' });
    const p = await browser.newPage({ viewport: { width: 1440, height: 1000 }, acceptDownloads: true }); p.on('pageerror', (x) => errs.push(x.message));
    await p.goto(base);
    ok(await wait(p, () => /No return yet/.test(document.getElementById('list').textContent)), 'empty: says what to upload');
    await p.setInputFiles('#file', wb);
    ok(await toast(p, 'Read: 2025-12-31 revision 1'), 'upload from the page');
    ok(await wait(p, () => /225%/.test(document.getElementById('kpi').textContent) && /273\.8%/.test(document.getElementById('kpi').textContent)), 'KPIs: regulatory 225 %, RBC 273.8 %');
    const det = await p.textContent('#det');
    ok(/Regulatory solvency/.test(det) && /Non life Underwriting - Premium risk/.test(det) && /Composition of the capital charge/.test(det), 'results, stress tests ranked, composition');
    ok(/1 area\(s\)|4 area\(s\) not signed off/.test(det) && /1 failed check\(s\) without an explanation/.test(det), 'what blocks the approval is said');
    ok(await p.$eval('#rv', (b) => b.disabled), 'the uploader cannot review (button disabled)');
    // explain the failed check (hostile text stays text)
    await p.click('[data-ex="C25"]'); await p.fill('#f-note', 'Synthetic: sukuk reconciled in note 7 <img src=x onerror=window.__sx=1>'); await dlgOk(p);
    ok(await toast(p, 'Explanation recorded') && /sukuk reconciled/.test(await p.textContent('#det')) && !(await p.evaluate(() => window.__sx)), 'explanation recorded, shown as text');
    // sign off every area
    for (const row of [4, 6, 7, 8]) { await p.click('[data-so="' + row + '"]'); await p.fill('#f-name', 'Synthetic Signer ' + row); await p.fill('#f-title', 'Head ' + row); await dlgOk(p); await toast(p, 'Signed off'); await wait(p, (r) => !document.querySelector('[data-so="' + r + '"]') || /Sign again/.test(document.querySelector('[data-so="' + r + '"]').textContent), row); }
    ok(await wait(p, () => !/not signed off/.test(document.getElementById('det').textContent)), 'every area signed off');
    // another operator reviews
    who = { user: 'omar.syn', role: 'operator' }; await p.reload(); await wait(p, () => !!document.getElementById('rv'));
    await p.click('#rv'); await dlgOk(p); ok(await toast(p, 'Marked reviewed') && await wait(p, () => !!document.getElementById('ap')), 'reviewed by a second person');
    await p.click('#ap'); await dlgOk(p); ok(await toast(p, 'Not allowed'), 'a plain operator cannot approve');
    // the Risk Head approves
    who = { user: 'rita.syn', role: 'operator' }; await p.reload(); await wait(p, () => !!document.getElementById('ap'));
    await p.click('#ap'); await dlgOk(p); ok(await toast(p, 'Approved') && await wait(p, () => /approved by rita\.syn/.test(document.getElementById('det').textContent)), 'approved by the Risk Head');
    // insights: the charts, the reverse stress, the AI commentary (no AI configured here: it says so, escaped)
    ok(await wait(p, () => document.querySelectorAll('#ins svg.ch').length >= 2 && /Loss that takes the ratio to 100 %/.test(document.getElementById('ins').textContent)), 'insights: ratio chart and stress chart');
    ok(/Ratio after each stress test/.test(await p.textContent('#ins')) && /trend needs 3 or more approved returns/.test(await p.textContent('#ins')), 'stress chart; the trend says how little history there is');
    await p.click('#aicom'); ok(await wait(p, () => /AI draft - verify before use/.test(document.getElementById('aiout').textContent)), 'the AI commentary box is labelled a draft');
    // download: the same workbook with the sign-offs written in
    const [dl] = await Promise.all([p.waitForEvent('download'), p.click('#dl')]);
    const got = fs.readFileSync(await dl.path()), B = readBook(got);
    ok(dl.suggestedFilename() === path.basename(wb), 'the original file name: ' + dl.suggestedFilename());
    ok(B.sheet('Sign-off Record').cells.get('C7').v === 'Synthetic Signer 7' && /sukuk reconciled/.test(B.sheet('Validations').cells.get('D25').v), 'sign-offs and the explanation are in the workbook');
    ok(B.sheet('Regulatory Solvency').cells.get('E43').f === 'IF(E38=0,"",E28/E38)', 'formulas kept');
    // record the submission
    await p.click('#sb'); await p.fill('#f-date', '2026-02-19'); await p.fill('#f-ref', 'IA-SYN-2026-01'); await dlgOk(p);
    ok(await toast(p, 'Submission recorded') && /IA-SYN-2026-01/.test(await p.textContent('#list')), 'submission recorded and listed');
    ok(e.app.store.auditTail(300).some((a) => a.action === 'brisk.solvency.approve' && a.by === 'rita.syn'), 'approval audited');
    // viewer: reads, no upload / download
    who = { user: 'vera.syn', role: 'viewer' }; await p.reload(); await wait(p, () => /IA-SYN-2026-01/.test(document.getElementById('list').textContent));
    ok(await p.$eval('#up', (b) => b.hidden) && !(await p.$('#dl')), 'a viewer reads, cannot upload or download');
    const ph = await browser.newPage({ viewport: { width: 390, height: 900 } }); ph.on('pageerror', (x) => errs.push(x.message)); await ph.goto(base); await wait(ph, () => !!document.querySelector('#det .card'));
    ok(await ph.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1), 'phone width: no sideways scroll'); await ph.close();
    ok(/"h": "solvency-capital.html"/.test(fs.readFileSync(path.join(DASH, 'vendor', 'zyb-nav.js'), 'utf8')) && / solvency-capital\.html /.test(fs.readFileSync(path.join(DASH, 'install-dashboards.sh'), 'utf8')), 'menu entry and installer');
  } finally { await browser.close(); srv.close(); e.close(); fs.rmSync(tmp, { recursive: true, force: true }); }
  ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks'); process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
