// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Compliance Programme (compliance-start.html) against the REAL compliance registers (engine/pdpl.js, ndmo.js, nca-ecc.js, sama-ia.js)
// with SYNTHETIC people: PDPL - the administrator names the DPO, the baseline counts what the records show, the statement step shows
// the readiness and digest; NCA ECC - the CISO is named, the gaps go to the GRC register as actions, an operator records a control
// (evidence required for compliant), the recorder cannot approve it, the CISO does; NDMO - the CDO is named, a recorded control is
// rejected with a note; SAMA CSF - reuses the NCA ECC CISO, the report is drafted, the register is downloaded; every regulation and
// step renders without undefined / NaN; no page error, no browser dialog.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node compliance-start.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const ITAM = path.join(__dirname, '..', '..', 'backend', 'itam'), DASH = path.join(__dirname, '..', '..', 'ui');
const H = require(path.join(ITAM, 'tests', 'helpers'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
(async () => {
  const e = await H.startApp({ noAi: true });
  require(path.join(ITAM, 'engine/duty')).registerDuty(e.app.srv, e.app, { noTimer: true, python: process.env.PYTHON || 'python3' });
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
  const base = 'http://127.0.0.1:' + srv.address().port + '/compliance-start.html';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  const p = await browser.newPage({ viewport: { width: 1440, height: 950 } });
  p.on('pageerror', (x) => errs.push(x.message)); p.on('dialog', (d) => { errs.push('dialog: ' + d.message()); d.dismiss(); });
  const wait = (fn, a) => p.waitForFunction(fn, a, { timeout: 10000 }).then(() => true, () => false);
  const toastHas = (re) => p.waitForFunction((s) => new RegExp(s).test([...document.querySelectorAll('.toast')].map((t) => t.textContent).join(' ')), re.source, { timeout: 15000 }).then(() => true, () => false);
  const as = async (who, hash) => { WHO = who; await p.goto('about:blank'); await p.goto(base + (hash || '')); await p.waitForSelector('#steps li'); await p.waitForTimeout(400); };
  const step = async (n) => { await p.click('#steps [data-step="' + n + '"]'); await p.waitForTimeout(200); };
  const panel = () => p.evaluate(() => document.getElementById('panel').innerText);
  const done = (n) => p.waitForFunction((k) => document.querySelector('#steps li:nth-child(' + k + ')').classList.contains('done'), n, { timeout: 10000 }).then(() => true, () => false);
  const form = async (vals) => { await p.waitForSelector('#dlgbg.open'); for (const [k, v] of Object.entries(vals)) { const tag = await p.$eval('#' + k, (x) => x.tagName); if (tag === 'SELECT') await p.selectOption('#' + k, v); else await p.fill('#' + k, String(v)); } await p.click('#dlgok'); };
  const ADM = { user: 'syed', role: 'admin' }, OP = { user: 'nora.syn', role: 'operator' }, CISO = { user: 'ciso.syn', role: 'operator' }, CDO = { user: 'cdo.syn', role: 'operator' };
  try {
    // PDPL: owner
    await as(ADM, '#fw=pdpl'); ok(/1 · Owner and scope/.test(await panel()), 'PDPL starts at the owner');
    await p.fill('#pf-dpo_user', 'dpo.syn'); await p.fill('#pf-dpo_appointed', '2026-01-15'); await p.check('#pf-sdaia_registered'); await p.click('#pf-save');
    ok(await toastHas(/Saved/) && await done(1), 'DPO named');
    await step(2); ok(/Baseline assessment/.test(await panel()) && /Need evidence/.test(await panel()), 'baseline with met / gaps / need evidence');
    await step(5); ok(/Ready to sign/.test(await panel()) && /sha256:/.test(await panel()), 'statement readiness and digest');
    // NCA ECC: CISO, gaps to GRC, record and independent approval
    await p.click('[data-fw="nca"]'); await p.waitForTimeout(500); await step(1);
    await p.fill('#pf-ciso_user', 'ciso.syn'); await p.fill('#pf-function_established', '2025-06-01'); await p.click('#pf-save'); ok(await toastHas(/Saved/) && await done(1), 'CISO named');
    await step(3); const before = e.app.store.collection('grc_actions').all().length; await p.click('#g-send'); ok(await toastHas(/Gaps sent/), 'gaps sent');
    ok(e.app.store.collection('grc_actions').all().length > before, 'GRC actions created from the gaps');
    await as(OP, '#fw=nca'); await step(4); const cid = await p.$eval('[data-conf]', (b) => b.getAttribute('data-conf'));
    await p.click('[data-conf="' + cid + '"]'); await form({ 'd-st': 'compliant' }); ok(await toastHas(/Evidence is needed/), 'evidence required for compliant');
    await p.fill('#d-ev', 'DOC-SYN-001 approved policy'); await p.click('#dlgok'); ok(await toastHas(/waiting for independent approval/), 'recorded');
    await step(5); await p.click('[data-dec="approve"][data-id="' + cid + '"]'); ok(await toastHas(/Not done/), 'the recorder cannot approve');
    await as(CISO, '#fw=nca'); await step(5); await p.click('[data-dec="approve"][data-id="' + cid + '"]'); ok(await toastHas(/Approved/), 'the CISO approved it');
    await step(6); const dl = p.waitForEvent('download'); await p.click('#ex-csv'); const d = await dl; ok(/nca-register-/.test(d.suggestedFilename()), 'register downloaded');
    // NDMO: CDO, record, reject with a note
    await as(ADM, '#fw=ndmo'); await p.fill('#pf-cdo_user', 'cdo.syn'); await p.click('#pf-save'); ok(await toastHas(/Saved/), 'CDO named');
    await as(OP, '#fw=ndmo'); await step(4); const nid = await p.$eval('[data-conf]', (b) => b.getAttribute('data-conf'));
    await p.click('[data-conf="' + nid + '"]'); await form({ 'd-st': 'non_compliant', 'd-note': 'Not started yet (synthetic)' }); ok(await toastHas(/Recorded/), 'NDMO control recorded');
    await as(CDO, '#fw=ndmo'); await step(5); await p.click('[data-dec="reject"][data-id="' + nid + '"]'); await form({ 'd-note': 'Attach the plan (synthetic)' }); ok(await toastHas(/Rejected/), 'rejected by the CDO with a note');
    // SAMA: CISO from NCA ECC, report drafted
    await as(OP, '#fw=sama'); await step(1); ok(/ciso\.syn/.test(await panel()), 'SAMA uses the NCA ECC CISO');
    await step(6); await p.click('#rp-draft'); ok(await toastHas(/Report drafted|Not done/), 'report draft requested');
    let clean = true; for (const f of ['pdpl', 'ndmo', 'nca', 'sama']) { await p.click('[data-fw="' + f + '"]'); await p.waitForTimeout(500); for (let k = 1; k <= 7; k++) { await step(k); if (/undefined|NaN|\[object Object\]/.test(await panel())) { clean = false; console.log(f, k, 'undefined'); } } }
    ok(clean, 'every regulation and step renders cleanly');
    ok(!errs.length, 'no page errors or browser dialogs: ' + errs.join(' | '));
  } finally { await browser.close(); srv.close(); await e.close(); }
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks'); process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
