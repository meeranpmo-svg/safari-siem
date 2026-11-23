// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Start an Audit (audit-start.html) - the guided audit - against the REAL audit engine (engine/audit-engage.js) with SYNTHETIC people
// and records: the administrator names the Head of Audit and auditors; the lead proposes and submits the plan, the Head of Audit
// approves it; the lead opens an engagement (a hostile title stays text), starts fieldwork, draws a sample of leavers and concludes
// each item (one exception with a note); writes a workpaper, concludes it; the Head of Audit reviews it (never the preparer); a
// finding is raised from the exception and issued; the report is drafted, the summary written, signed by the lead and approved by
// the Head of Audit - final; a viewer is told why the records do not open; the Cyber team is a separate set of records; no page
// error, no browser dialog. Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node audit-start.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const ITAM = path.join(__dirname, '..', '..', 'backend', 'itam'), DASH = path.join(__dirname, '..', '..', 'ui');
const H = require(path.join(ITAM, 'tests', 'helpers'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
(async () => {
  const e = await H.startApp({ noAi: true });
  require(path.join(ITAM, 'engine/duty')).registerDuty(e.app.srv, e.app, { noTimer: true, python: process.env.PYTHON || 'python3' });
  const XSS = '<img src=x onerror="window.__x=1">';
  const off = e.app.store.collection('offboarding');
  for (let n = 1; n <= 8; n++) off.put({ id: 'OFF-' + n, username: 'leaver' + n + '.syn', last_day: '2026-0' + n + '-10', requested_by: 'hr.syn', status: 'completed', disable: { approved_by: n === 2 ? 'hr.syn' : 'mgr.syn' }, disabled: { at: '2026-0' + n + '-10T20:00:00Z' } });
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
  const base = 'http://127.0.0.1:' + srv.address().port + '/audit-start.html';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  const p = await browser.newPage({ viewport: { width: 1440, height: 950 } });
  p.on('pageerror', (x) => errs.push(x.message)); p.on('dialog', (d) => { errs.push('dialog: ' + d.message()); d.dismiss(); });
  const wait = (fn, a) => p.waitForFunction(fn, a, { timeout: 10000 }).then(() => true, () => false);
  const toastHas = (re) => p.waitForFunction((s) => new RegExp(s).test([...document.querySelectorAll('.toast')].map((t) => t.textContent).join(' ')), re.source, { timeout: 10000 }).then(() => true, () => false);
  const as = async (who, hash) => { WHO = who; await p.goto('about:blank'); await p.goto(base + (hash || '')); await p.waitForSelector('#steps li'); await p.waitForTimeout(200); };
  const step = async (n) => { await p.click('#steps [data-step="' + n + '"]'); await p.waitForTimeout(150); };
  const form = async (vals) => { await p.waitForSelector('#dlgbg.open'); for (const [k, v] of Object.entries(vals)) { const tag = await p.$eval('#' + k, (x) => x.tagName); if (tag === 'SELECT') await p.selectOption('#' + k, v); else await p.fill('#' + k, String(v)); } await p.click('#dlgok'); };
  const panel = () => p.evaluate(() => document.getElementById('panel').innerText);
  const done = (n) => p.waitForFunction((k) => document.querySelector('#steps li:nth-child(' + k + ')').classList.contains('done'), n, { timeout: 8000 }).then(() => true, () => false);
  const ADM = { user: 'syed', role: 'admin' }, LEAD = { user: 'laila.syn', role: 'operator' }, HEAD = { user: 'hana.syn', role: 'operator' }, VIEW = { user: 'vera.syn', role: 'viewer' };
  const Y = new Date().getUTCFullYear(), d = (n) => new Date(Date.now() + n * 86400000).toISOString().slice(0, 10);
  try {
    // 1 team
    await as(ADM); ok(/1 · Audit team/.test(await panel()), 'starts at step 1 when the team is not set');
    await p.fill('#p-head', 'hana.syn'); await p.fill('#p-aud', 'laila.syn, adel.syn'); await p.click('#p-save');
    ok(await toastHas(/Audit team saved/) && await done(1), 'team saved; step 1 done');
    // 2 plan: the lead proposes and submits, the Head of Audit approves
    await as(LEAD); await step(2); await p.click('[data-pa="propose"]'); ok(await toastHas(/Plan proposed/), 'plan proposed');
    ok(await p.waitForFunction(() => /\+\d+ /.test(document.getElementById('panel').innerText), null, { timeout: 8000 }).then(() => true, () => false), 'each score shows its reasons');
    await p.click('[data-pa="submit"]'); ok(await toastHas(/Submitted/), 'submitted');
    ok(!(await p.$('[data-pa="approve"]')) || (await p.click('[data-pa="approve"]'), await toastHas(/Not done/)), 'the preparer cannot approve');
    await as(HEAD); await step(2); await p.click('[data-pa="approve"]'); ok(await toastHas(/Plan approved/) && await done(2), 'Head of Audit approved the plan');
    // 3 engagement
    await as(LEAD); await step(3);
    await p.fill('#e-title', 'Leavers access removal ' + XSS); await p.selectOption('#e-area', 'joiners'); await p.fill('#e-dept', 'Human Resources'); await p.fill('#e-owner', 'omar.syn');
    await p.selectOption('#e-lead', 'laila.syn'); await p.check('[data-team-m="adel.syn"]'); await p.fill('#e-obj', 'Leavers lose access on their last day'); await p.fill('#e-scope', 'All leavers this year');
    await p.fill('#e-crit', 'NCA ECC 1-9'); await p.fill('#e-start', d(0)); await p.fill('#e-fw', d(20)); await p.fill('#e-due', d(35));
    await p.click('#e-create'); ok(await toastHas(/ENG-\d{4}-\d{3} opened/), 'engagement opened');
    ok(await p.waitForFunction(() => /4 · Start fieldwork/.test(document.getElementById('panel').innerText), null, { timeout: 8000 }).then(() => true, () => false), 'moves on to step 4');
    ok(!(await p.evaluate(() => window.__x)) && /<img src=x/.test(await panel()), 'a hostile title stays text');
    // 4 previous audit report: fieldwork waits for it; upload the report (PDF) with its findings list (Excel), open findings carried in
    ok(await p.$eval('#adv-fw', (b) => b.disabled) && /Upload the previous audit report/.test(await panel()), 'fieldwork waits for the previous audit report');
    const XB = require(path.join(ITAM, 'tests', 'sca-fixture')).bookOf([['Findings', { A1: 'Ref', B1: 'Observation', C1: 'Rating', D1: 'Status', E1: 'Recommendation',
      A2: 'F-01', B2: 'Leavers kept access after their last day (synthetic) <img src=x onerror=window.__x=1>', C2: 'High', D2: 'Open', E2: 'Disable on the last day', A3: 'F-02', B3: 'Joiner forms unsigned (synthetic)', C3: 'Low', D3: 'Closed' }]]);
    await p.fill('#pr-title', 'Joiners and leavers audit (synthetic)'); await p.fill('#pr-date', d(-200)); await p.selectOption('#pr-src', 'external'); await p.fill('#pr-aud', 'Synthetic Audit Firm');
    await p.setInputFiles('#pr-file', { name: 'jml-previous.pdf', mimeType: 'application/pdf', buffer: Buffer.from('%PDF-1.4\n% synthetic\n') });
    await p.setInputFiles('#pr-ff', { name: 'findings.xlsx', mimeType: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', buffer: XB });
    await p.click('#pr-up'); ok(await toastHas(/Previous report uploaded/), 'previous report uploaded');
    ok(await p.waitForFunction(() => /Synthetic Audit Firm/.test(document.getElementById('panel').innerText) && /1 open/.test(document.getElementById('panel').innerText), null, { timeout: 8000 }).then(() => true, () => false), 'listed with its open findings');
    ok(!(await p.evaluate(() => window.__x)), 'a finding\'s text from the file stays text');
    const [dl] = await Promise.all([p.waitForEvent('download'), p.click('[data-pdl]')]); ok(dl.suggestedFilename() === 'jml-previous.pdf', 'the report downloads');
    // 4 fieldwork
    await p.click('#adv-fw'); ok(await toastHas(/Fieldwork started/) && await p.waitForFunction(() => document.querySelector('#steps li:nth-child(4)').classList.contains('done'), null, { timeout: 8000 }).then(() => true, () => false), 'fieldwork started');
    // 5 sample: draw and conclude
    await p.waitForFunction(() => /5 · Test samples/.test(document.getElementById('panel').innerText), null, { timeout: 8000 });
    await p.selectOption('#s-pop', 'leavers'); await p.fill('#s-size', '3'); await p.click('#s-draw'); ok(await toastHas(/Sample drawn/), 'sample drawn');
    await p.waitForSelector('[data-res]'); ok(/✓|✗/.test(await panel()), 'the platform\'s suggested tests are shown');
    const refs = await p.$$eval('[data-res="pass"]', (b) => b.map((x) => x.getAttribute('data-ref')));
    await p.click('[data-res="exception"][data-ref="' + refs[0] + '"]'); await form({ 'd-note': 'Account disabled two days late (synthetic)' }); await toastHas(/exception/);
    for (const r of refs.slice(1)) { await p.waitForSelector('[data-res="pass"][data-ref="' + r + '"]'); await p.click('[data-res="pass"][data-ref="' + r + '"]'); await p.waitForTimeout(300); }
    ok(await p.waitForFunction(() => document.querySelector('#steps li:nth-child(5)').classList.contains('done'), null, { timeout: 8000 }).then(() => true, () => false), 'every item concluded; step 5 done');
    // follow-up of the previous finding: the draft report waits for it
    await step(4); ok(/Follow-up of the previous findings/.test(await panel()) && /1 to do/.test(await panel()), 'the open previous finding is carried into the audit');
    await p.click('[data-fur="repeat"]'); await form({ 'd-note': 'Two leavers still active after their last day (synthetic)' }); ok(await toastHas(/Follow-up recorded/) && await p.waitForFunction(() => /all followed up/.test(document.getElementById('panel').innerText) && /repeat finding/.test(document.getElementById('panel').innerText), null, { timeout: 8000 }).then(() => true, () => false), 'followed up as a repeat finding');
    // 6 workpaper: prepared by the lead, reviewed by the Head of Audit
    await step(6); await p.fill('#w-title', 'Leaver accounts disabled on the last day'); await p.fill('#w-obj', 'Access removed in time'); await p.fill('#w-proc', 'Compared the disable time with the last day');
    const sid = await p.$eval('#w-smp option:nth-child(2)', (o) => o.value); await p.selectOption('#w-smp', sid); await p.click('#w-add'); ok(await toastHas(/Workpaper added/), 'workpaper added');
    await p.waitForSelector('[data-wc]'); await p.click('[data-wc]'); await form({ 'd-c': 'partially_effective', 'd-s': 'One of three leavers kept access two days' }); ok(await toastHas(/Concluded/), 'concluded');
    await p.waitForSelector('[data-wr="accept"]'); await p.click('[data-wr="accept"]'); ok(await toastHas(/Not done/), 'the preparer cannot review their own workpaper');
    await as(HEAD, '#team=ia'); await step(6); await p.click('[data-wr="accept"]'); ok(await toastHas(/Review accepted/) && await done(6), 'the Head of Audit reviewed it');
    // 7 finding from the exception, issued
    await as(LEAD); await step(7);
    await p.fill('#f-title', 'Leaver access removed late'); await p.fill('#f-cond', 'One sampled leaver kept access two days after the last day'); await p.fill('#f-cause', 'Manual disable step'); await p.fill('#f-eff', 'Former staff could reach systems'); await p.fill('#f-rec', 'Automate disable at end of day');
    await p.check('[data-fx]'); await p.click('#f-add'); ok(await toastHas(/Finding raised/), 'finding raised, linked to the exception');
    await p.waitForSelector('[data-fi="issue"]'); await p.click('[data-fi="issue"]'); ok(await toastHas(/issued to the owner/) && await done(7), 'finding issued');
    // 8 report
    await step(8); await p.click('#adv-rep'); ok(await toastHas(/Report drafting started/), 'report drafting started');
    await p.waitForSelector('#r-sum'); await p.fill('#r-sum', 'Leavers mostly lose access on time; one late removal found. Automating the disable step is recommended.'); await p.click('#r-save'); ok(await toastHas(/Summary saved/), 'summary saved');
    await p.waitForSelector('#r-sign'); await p.click('#r-sign'); ok(await toastHas(/Report signed/), 'signed by the lead');
    await p.waitForSelector('#r-appr'); await p.click('#r-appr'); ok(await toastHas(/Not done/), 'the lead cannot approve their own report');
    await as(HEAD); await step(8); await p.click('#r-appr'); ok(await toastHas(/Report approved/), 'approved by the Head of Audit');
    ok(await p.waitForFunction(() => /Final - approved/.test(document.getElementById('panel').innerText) && document.querySelector('#steps li:nth-child(8)').classList.contains('done'), null, { timeout: 8000 }).then(() => true, () => false), 'final, every step done');
    ok(e.app.store.auditTail(500).some((x) => x.action === 'ia.report.approve'), 'audit trail records the approval');
    let clean = true; for (let k = 1; k <= 8; k++) { await step(k); if (/undefined|NaN|\[object Object\]/.test(await panel())) { clean = false; console.log('step', k, 'shows undefined/NaN'); } }
    ok(clean, 'every step renders without undefined / NaN / [object Object]');
    // another team is its own record set; a viewer is told why
    await as(LEAD, '#team=csa'); ok(/1 · Audit team/.test(await panel()), 'Cyber Security Audit starts from its own team set-up');
    await as(VIEW); ok(/operators and administrators only \(PDPL\)/.test(await panel()), 'a viewer is told why the records do not open');
    ok(!/undefined|NaN|\[object Object\]/.test(await panel()), 'no undefined / NaN / [object Object] on the page');
    ok(!errs.length, 'no page errors or browser dialogs: ' + errs.join(' | '));
  } finally { await browser.close(); srv.close(); await e.close(); }
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks'); process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
