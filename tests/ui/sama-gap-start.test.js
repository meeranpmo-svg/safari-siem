// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for Start a SAMA CSF Gap Assessment (dashboards/server/sama-gap-start.html, vendor/zyb-gapwiz.js) against the REAL ITAM
// engine, SYNTHETIC data: open the engagement, send the kick-off, record and accept evidence, take the baseline, link the
// SAMA register (recorded and approved by the CISO through the API), rate the gaps, publish the plan, sign as the lead, approve
// as the CISO; the report opens; a viewer is refused; in the menu.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node sama-gap-start.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const ITAM = path.join(__dirname, '..', '..', 'backend', 'itam'), DASH = path.join(__dirname, '..', '..', 'ui');
const H = require(path.join(ITAM, 'tests', 'helpers'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };

(async () => {
  const e = await H.startApp({ noAi: true });
  require(path.join(ITAM, 'engine/duty')).registerDuty(e.app.srv, e.app, { noTimer: true, python: process.env.PYTHON || 'python3' });
  let WHO = { user: 'lina.syn', role: 'operator' };
  const api = (m, p, body, who) => e.req(m, p, Object.assign(body !== undefined ? { body } : {}, who));
  await api('POST', '/nca-ecc/profile', { ciso_user: 'karim.syn' }, { user: 'syed', role: 'admin' });
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
    await p.goto(base + 'sama-gap-start.html?standalone=1'); await p.waitForSelector('#g-save');
    ok(await has(p, '#steps', /Team & scope/) && await has(p, '#steps', /Report & sign-off/), 'seven steps listed');
    ok(await has(p, '#panel', /karim\.syn/), 'the CISO from the profile is named');
    // 1 open it
    await p.fill('#g-name', 'SAMA CSF gap 2026 (synthetic)'); await p.fill('#g-ass', 'amir.syn'); await p.fill('#g-dept', 'IT, Cybersecurity'); await p.fill('#g-target', '2027-01-31');
    await p.click('#g-save'); await p.waitForSelector('#k-send');
    ok(await has(p, '#panel', /36 requests/), 'kick-off counts 2 departments x 18 items');
    // 2 kick-off and evidence
    await p.fill('#k-due', '2027-01-10'); await p.click('#k-send'); await p.waitForSelector('[data-ev="received"]');
    ok(await has(p, '#panel', /requested 36/) && await has(p, '#panel', /SAMA CSF 3\.1\.1/), 'evidence requests sent with SAMA references');
    await p.click('[data-ev="received"]'); await p.fill('#d-x', 'DPO appointment letter (synthetic)'); await p.click('#dlgok');
    ok(await has(p, '#panel', /received 1/), 'evidence recorded as received');
    await p.click('[data-ev="accepted"]'); ok(await has(p, '#panel', /accepted 1/), 'evidence accepted');
    await p.selectOption('#k-dept', 'Cybersecurity'); ok(!(await p.textContent('#panel')).includes('IT</td>'), 'department filter');
    // 3 baseline
    await p.click('[data-step="3"]'); await p.click('#b-take'); ok(await has(p, '#panel', /Requirements: Gap/) && await has(p, '#panel', /target level/), 'baseline shows the SAMA register and the maturity target');
    // 4 clause & control review
    await p.click('[data-step="4"]'); await p.click('#a-start'); ok(await has(p, '#panel', /SAMA-REGISTER/) && await has(p, '#panel', /Open the SAMA CSF register/), 'register linked with the way to finish it');
    ok(await has(p, '#panel', /to be recorded by a person/), 'what blocks the review is named');
    const ASR = { user: 'amir.syn', role: 'operator' }, v0 = (await api('GET', '/sama-ia', undefined, ASR)).json, openC = v0.requirements.concat(v0.ia.requirements).filter((c) => ['pending', 'not_measured', 'no_evidence'].includes(c.result));
    for (const c of openC) await api('POST', '/sama-ia/confirm', { id: c.id, status: 'compliant', evidence: 'synthetic ' + c.id }, ASR);
    for (const c of openC) await api('POST', '/sama-ia/confirm/' + c.id + '/decide', { decision: 'approve' }, { user: 'karim.syn', role: 'operator' });
    // 5 rate every gap
    await p.click('#refresh'); await p.waitForTimeout(500); await p.click('[data-step="5"]'); await p.waitForSelector('[data-rate]');
    // previous year: import a synthetic 2025 report (two of today's gaps by id, one gap that is no longer one), see the comparison
    const g0 = (await api('GET', '/sama-ia/gap', undefined, { user: 'lina.syn', role: 'operator' })).json.current.gaps;
    const prevCsv = 'Gap,Requirement,Result,Risk,Owner\r\n' + g0[0].id + ',' + g0[0].text.replace(/[,"]/g, ' ') + ',gap,high (16),amir.syn\r\n' + g0[1].id + ',x,partial,medium (8),\r\nSA-3.4.9-99,A synthetic requirement no longer a gap,gap,low (2),\r\n';
    ok(await has(p, '#panel', /No earlier report imported/), 'no previous report yet');
    await p.click('#h-imp'); await p.setInputFiles('#h-file', { name: 'sama-2025.csv', mimeType: 'text/csv', buffer: Buffer.from(prevCsv) }); await p.fill('#h-year', '2025');
    await Promise.all([p.waitForResponse((x) => /history\/import/.test(x.url())), p.click('#dlgok')]);
    ok(await has(p, '#panel', /recurring 2/) && await has(p, '#panel', /closed since 1/) && await has(p, '#panel', /SA-3\.4\.9-99/), 'year-on-year comparison: recurring, new, closed');
    await p.click('#h-list'); ok(await has(p, '#dlgb', /sama-2025\.csv/), 'imported reports listed'); await p.click('#dlgok');
    let k = 0; while (await p.$('[data-rate]:text("Rate")') && k++ < 40) {
      await p.click('[data-rate]:text("Rate")');
      if (k === 1) { ok(await p.$('#d-su') && await has(p, '#d-su', /Suggested: likelihood/), 'a suggested rating with its reasons'); await p.selectOption('#d-l', '1'); await p.click('#d-use'); ok((await p.inputValue('#d-l')) !== '1', 'use the suggestion fills the rating'); } await p.selectOption('#d-l', '4'); await p.selectOption('#d-i', '5'); await p.fill('#d-rc', 'no owner (synthetic)'); await p.fill('#d-rec', 'assign an owner and implement the control'); await p.fill('#d-o', 'amir.syn'); await p.fill('#d-t', '2027-02-28');
      await Promise.all([p.waitForResponse((x) => /\/gaps\//.test(x.url()) && x.request().method() === 'POST'), p.click('#dlgok')]); await p.waitForResponse((x) => /\/sama-ia\/gap$/.test(x.url())); await p.waitForTimeout(100); }
    const gs = (await api('GET', '/sama-ia/gap', undefined, { user: 'lina.syn', role: 'operator' })).json.current.gaps;
    ok(gs.length > 1 && gs.every((g) => g.rating) && await has(p, '#panel', /critical/), 'every gap rated (' + gs.filter((g) => g.rating).length + '/' + gs.length + ')');
    // 6 plan
    await p.click('[data-step="6"]'); ok(await has(p, '#panel', /Score forecast/), 'forecast from the plan dates'); await p.click('#pl-pub'); ok(await has(p, '#panel', /GRC action\(s\) ACT-/), 'plan published to GRC actions');
    // 7 report
    await p.click('[data-step="7"]'); ok(await has(p, '#panel', /AI draft of the summary/) && await has(p, '#panel', /written by hand/), 'AI draft panel says why it is not available');
    const [dl] = await Promise.all([p.waitForEvent('download'), p.click('#r-xlsx')]); ok(/\.xlsx$/.test(dl.suggestedFilename()), 'Excel export of the current assessment (' + dl.suggestedFilename() + ')');
    const xb = fs.readFileSync(await dl.path()), XB = require(path.join(ITAM, 'engine/xlsx-book')).readBook(xb); ok(XB.sheets.some((sh) => sh.name === 'Gaps') && XB.sheets.some((sh) => sh.name === 'Year on year'), 'the workbook has the gaps and the year-on-year sheet');
    await p.fill('#r-sum', 'Governance gaps found; the plan has owners and dates (synthetic).'); await p.click('#r-sign');
    ok(await has(p, '#panel', /Signed by lina\.syn/), 'lead signs');
    ok(await has(p, '#panel', /a different person approves/), 'four-eyes note for the signer');
    const [pop] = await Promise.all([p.waitForEvent('popup'), p.click('#r-html')]); await pop.waitForLoadState();
    ok(/Gap Assessment/.test(await pop.textContent('h1')) && /not a SAMA or Insurance Authority assessment/.test(await pop.content()), 'report opens'); await pop.close();
    WHO = { user: 'karim.syn', role: 'operator' }; await p.reload(); await p.waitForSelector('#steps'); await p.click('[data-step="7"]'); await p.click('#r-appr');
    ok(await has(p, '#panel', /Approved by karim\.syn/), 'CISO approves the report');
    ok((await p.$$eval('#steps li.done', (x) => x.length)) === 7, 'every step done');
    const v = await browser.newPage(); WHO = { user: 'vera.syn', role: 'viewer' }; await v.goto(base + 'sama-gap-start.html?standalone=1');
    ok(await has(v, '#err', /cybersecurity team/), 'viewer refused'); await v.close();
    const nav = fs.readFileSync(path.join(DASH, 'vendor', 'zyb-nav.js'), 'utf8'), inst = fs.readFileSync(path.join(DASH, 'install-dashboards.sh'), 'utf8');
    ok(/"h": "sama-gap-start.html"/.test(nav) && inst.includes('sama-gap-start.html') && inst.includes('vendor/zyb-gapwiz.js'), 'in the menu and the install list');
    ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  } finally { await browser.close(); srv.close(); await e.close(); }
  console.log((bad ? 'FAILED ' : 'ok ') + (n - bad) + '/' + n);
  process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
