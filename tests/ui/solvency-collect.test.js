// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for the collection round on solvency-capital.html against the REAL engine (engine/solvency-collect.js) with a SYNTHETIC
// workbook in the layout of the Insurance Authority's template (backend/itam/tests/sca-fixture.js): the Risk Head opens a round
// from last year's approved return with a Finance owner; Finance downloads its pack, uploads it with an amount typed in riyals (the
// units check flags it), explains it; the uploader cannot accept; another Risk Head accepts; Actuarial's pack is uploaded and accepted;
// the workbook is assembled with the values and the new date; a hostile explanation stays text; a viewer sees no action; phone width.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node solvency-collect.test.js
const http = require('http'), fs = require('fs'), os = require('os'), path = require('path');
const ITAM = path.join(__dirname, '..', '..', 'backend', 'itam'), DASH = path.join(__dirname, '..', '..', 'ui');
const H = require(path.join(ITAM, 'tests', 'helpers'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
(async () => {
  const e = await H.startApp({ noAi: true });
  require(path.join(ITAM, 'engine/duty')).registerDuty(e.app.srv, e.app, { noTimer: true, now: () => Date.parse('2026-12-20T08:00:00Z'), python: process.env.PYTHON || 'python3' });
  const F = require(path.join(ITAM, 'tests', 'sca-fixture')), { readBook, patchBook } = require(path.join(ITAM, 'engine', 'xlsx-book'));
  const api = (m, p, b, w) => e.req(m, p, Object.assign(b !== undefined ? { body: b } : {}, w));
  const ADM = { user: 'adam.syn', role: 'admin' }, OP = { user: 'nora.syn', role: 'operator' }, OP2 = { user: 'omar.syn', role: 'operator' };
  for (const u of ['rita.syn', 'raed.syn']) await api('POST', '/roles/assign', { user: u, role_id: 'risk-head' }, ADM);
  { const id = (await api('POST', '/brisk/solvency/import', { filename: 'sca-2025.xlsx', xlsx_b64: F.b64() }, OP)).json.id;
    for (const row of [4, 6, 7, 8]) await api('POST', '/brisk/solvency/' + id + '/signoff', { row, name: 'S', title: 'T' }, OP2);
    await api('POST', '/brisk/solvency/' + id + '/explain', { ref: 'C25', note: 'synthetic' }, OP2); await api('POST', '/brisk/solvency/' + id + '/review', {}, OP2);
    await api('POST', '/brisk/solvency/' + id + '/approve', {}, { user: 'rita.syn', role: 'operator' }); }
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'scc-'));
  let who = { user: 'rita.syn', role: 'operator' };
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
  const as = async (p, w) => { who = w; await p.reload(); await wait(p, () => !!document.querySelector('#colbody table, #colbody .empty')); };
  try {
    const p = await browser.newPage({ viewport: { width: 1440, height: 1000 }, acceptDownloads: true }); p.on('pageerror', (x) => errs.push(x.message));
    await p.goto(base); ok(await wait(p, () => /No collection round is open/.test(document.getElementById('colbody').textContent)), 'empty: says what a round is');
    // the Risk Head opens a round
    await p.click('#cyopen'); await p.fill('#c-asat', '2026-12-31'); await p.fill('#c-due', '2027-01-20'); await p.fill('#c-own1', 'fin.syn'); await p.click('#dlgok');
    ok(await toast(p, 'Round opened: 2 department pack'), 'round opened from the page');
    ok(await wait(p, () => /Finance Function/.test(document.getElementById('colbody').textContent) && /approved return 2025-12-31/.test(document.getElementById('colbody').textContent)), 'packs listed, base = last approved return');
    // Finance: download its pack, upload it with an amount in riyals
    await as(p, { user: 'fin.syn', role: 'operator' });
    const [d1] = await Promise.all([p.waitForEvent('download'), p.click('[data-pdl="finance-function"]')]);
    ok(/Finance Function\.xlsx$/.test(d1.suggestedFilename()), 'the pack: ' + d1.suggestedFilename());
    const filled = path.join(tmp, 'finance.xlsx'); fs.writeFileSync(filled, patchBook(fs.readFileSync(await d1.path()), { Market: { C5: 125000000 } }));
    await p.click('[data-pup="finance-function"]'); await p.setInputFiles('#pfile', filled);
    ok(await toast(p, 'Uploaded: \\d+ values, 1 flagged'), 'uploaded; one value flagged');
    ok(await wait(p, () => /Market!C5/.test(document.getElementById('colbody').textContent) && /units/.test(document.getElementById('colbody').textContent) && /SR '000/.test(document.getElementById('colbody').textContent)), 'the units check explains itself');
    await p.click('[data-pex="finance-function"][data-cell="Market!C5"]'); await p.fill('#f-note', 'Synthetic: confirmed by treasury <img src=x onerror=window.__cx=1>'); await p.click('#dlgok');
    ok(await toast(p, 'Explanation recorded') && !(await p.evaluate(() => window.__cx)) && /confirmed by treasury <img/.test(await p.textContent('#colbody')), 'explanation recorded, shown as text');
    // acceptance: four eyes, Risk function
    await as(p, { user: 'raed.syn', role: 'operator' });
    await p.click('[data-pac="finance-function"]'); await p.click('#dlgok'); ok(await toast(p, '^Accepted'), 'another Risk Head accepts');
    // Actuarial: uploaded by the administrator, accepted by the other Risk Head
    await as(p, ADM);
    const [d2] = await Promise.all([p.waitForEvent('download'), p.click('[data-pdl="actuarial-function"]')]);
    const filled2 = path.join(tmp, 'actuarial.xlsx'); fs.writeFileSync(filled2, patchBook(fs.readFileSync(await d2.path()), { 'Projected RBC': { F8: 455000 } }));
    await p.click('[data-pup="actuarial-function"]'); await p.setInputFiles('#pfile', filled2); ok(await toast(p, 'Uploaded:'), 'actuarial uploaded');
    ok(await p.$eval('[data-pac="actuarial-function"]', (b) => b.disabled), 'the uploader cannot accept (button disabled)');
    await as(p, { user: 'rita.syn', role: 'operator' });
    await p.click('[data-pac="actuarial-function"]'); await p.click('#dlgok'); ok(await toast(p, '^Accepted'), 'accepted');
    ok(await wait(p, () => /2 of 2 departments accepted/.test(document.getElementById('colbody').textContent)), 'progress 2 of 2');
    const [d3] = await Promise.all([p.waitForEvent('download'), p.click('#cyasm')]);
    const out = readBook(fs.readFileSync(await d3.path()));
    ok(out.sheet('Market').cells.get('C5').v === 125000000 && out.sheet('Projected RBC').cells.get('F8').v === 455000, 'assembled with every department\'s values');
    ok(out.sheet('Regulatory Solvency').cells.get('E43').f === 'IF(E38=0,"",E28/E38)', 'formulas kept');
    // viewer
    await as(p, { user: 'vera.syn', role: 'viewer' });
    ok(!(await p.$('[data-pup]')) && !(await p.$('[data-pac]')) && !(await p.$('#cyasm')), 'a viewer follows the round, no actions');
    const ph = await browser.newPage({ viewport: { width: 390, height: 900 } }); ph.on('pageerror', (x) => errs.push(x.message)); await ph.goto(base); await wait(ph, () => !!document.querySelector('#colbody table'));
    ok(await ph.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1), 'phone width: no sideways scroll'); await ph.close();
  } finally { await browser.close(); srv.close(); e.close(); fs.rmSync(tmp, { recursive: true, force: true }); }
  ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks'); process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
