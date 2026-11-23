// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Audit Command Center (audit-command.html) - automatic re-testing, against the REAL ITAM engines with SYNTHETIC leavers: the
// Re-testing card lists implemented findings with their use case; "Re-test now" gives a clean result (closure proposal with the
// evidence) or exceptions (reopened, the new exceptions listed); the finding owner sees no Confirm button; an auditor of the team
// confirms (the finding closes in the team engine) or rejects with a reason; a finding with no use case is a manual re-test until
// an auditor links one; the history drawer; the admin rule auto_retest; hostile labels stay text; no page errors.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node audit-command-retest.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const ITAM = path.join(__dirname, '..', '..', 'backend', 'itam'), DASH = path.join(__dirname, '..', '..', 'ui');
const H = require(path.join(ITAM, 'tests', 'helpers'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };

(async () => {
  const e = await H.startApp({ noAi: true });
  require(path.join(ITAM, 'engine/duty')).registerDuty(e.app.srv, e.app, { noTimer: true, python: process.env.PYTHON || 'python3' });
  const col = (c) => e.app.store.collection(c), today = new Date().toISOString().slice(0, 10), dayOff = (d) => new Date(Date.now() + d * 86400000).toISOString().slice(0, 10);
  const leaver = (id, last, o = {}) => col('offboarding').put(Object.assign({ id, username: id.toLowerCase() + '.syn', last_day: last, requested_by: 'hr.syn', status: 'completed', disable: { approved_by: 'mgr.syn' }, disabled: { at: last + 'T10:00:00Z' } }, o));
  for (let i = 1; i <= 8; i++) { const last = dayOff(-10 - i); leaver('OFF-' + i, last, { disable: { approved_by: i === 4 ? 'hr.syn' : 'mgr.syn' }, disabled: i === 2 ? null : { at: last + 'T10:00:00Z' } }); }
  const A = { user: 'laila.syn', role: 'operator' }, OWN = { user: 'omar.syn', role: 'operator' }, ADM = { user: 'syed', role: 'admin' };
  const P = async (p, b, who = A) => { const r = await e.req('POST', p, { body: b, user: who.user, role: who.role }); if (r.status !== 200) throw new Error(p + ' ' + r.status + ' ' + r.raw); return r.json; };
  await P('/csa/profile', { head_of_audit: 'hana.syn', auditors: ['laila.syn', 'adel.syn'], engagements_per_year: 4 }, ADM);
  const E = (await P('/csa/engagements', { title: 'Identity lifecycle (synthetic)', area: 'iam', auditee_dept: 'IT', auditee_owner: 'omar.syn', lead: 'laila.syn', team: ['adel.syn'], objectives: ['Leavers lose access'], scope: 'All leavers', criteria: 'NCA ECC 2-2', start: today, fieldwork_end: dayOff(20), report_due: dayOff(30) })).id;
  await (await P('/csa/engagements/' + E + '/prior-none', { note: 'first audit of this area (synthetic)' }), P('/csa/engagements/' + E + '/advance', { to: 'fieldwork' }));
  await P('/audit-auto/run', {});
  const props = (await e.req('GET', '/audit-auto', A)).json.proposals, F = {};
  const flow = async (id) => { await P('/csa/findings/' + id + '/issue', {}); await P('/csa/findings/' + id + '/respond', { response: 'agreed', action_plan: 'fix it', due: dayOff(20) }, OWN); await P('/csa/findings/' + id + '/implemented', { evidence: 'done (synthetic)' }, OWN); };
  for (const uc of ['UC-01', 'UC-02']) { const p = props.find((x) => x.uc === uc && x.state === 'proposed'); F[uc] = (await P('/audit-auto/proposals/' + p.id + '/accept', { engagement: E, owner: OWN.user })).finding.id; await flow(F[uc]); }
  const M = (await P('/csa/engagements/' + E + '/findings', { title: 'Service accounts without an owner <img src=x onerror="window.__xss=1"> (synthetic)', condition: 'c', criteria: 'k', cause: 'x', effect: 'y', recommendation: 'z', rating: 'high', owner: OWN.user })).id; await flow(M);
  // after the fix: two clean leavers, one whose disable the requester approved again (UC-02 fails)
  leaver('OFF-21', dayOff(1)); leaver('OFF-22', dayOff(2), { username: '<b>hostile</b>', disable: { approved_by: 'hr.syn' } });
  let WHO = A;
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
  const card = (p, id) => p.$eval('#retest [data-rt="' + id + '"]', (x) => x.textContent).catch(() => '');
  let ANS = [];
  const page = async (ctx, f) => { const p = await ctx.newPage(); p.on('pageerror', (x) => errs.push(x.message)); p.on('dialog', (d) => { const a = ANS.shift(); if (a === undefined) { errs.push('unexpected dialog: ' + d.message()); d.dismiss(); } else d.accept(a); }); await p.goto(base + f + '?standalone=1'); await p.waitForSelector('#main:not([hidden])', { timeout: 60000 }); return p; };
  const finding = async (id) => (await e.req('GET', '/csa/findings', A)).json.find((x) => x.id === id);
  try {
    const ctx = await browser.newContext({ viewport: { width: 1500, height: 1000 } });
    let p = await page(ctx, 'audit-command.html');
    ok((await p.$$('#retest [data-rt]')).length === 3, 'three implemented findings in the Re-testing card');
    ok(/waiting for the run/.test(await card(p, F['UC-01'])) && /UC-01/.test(await card(p, F['UC-01'])), 'a use-case finding waits for the run, with its use case');
    ok(/manual re-test/.test(await card(p, M)) && /corrected records/.test(await card(p, M)), 'no use case: manual re-test with the evidence to attach');
    ok(/Closures to confirm/.test(await p.textContent('#kpis')) && /Failed re-tests/.test(await p.textContent('#kpis')), 'KPIs for the re-tests');
    // clean
    await p.click('[data-rtrun="' + F['UC-01'] + '"]'); ok(await toast(p, 'Re-test clean'), 'Re-test now: clean');
    ok(await wait(p, (id) => /clean - confirm closure/.test((document.querySelector('[data-rt="' + id + '"]') || {}).textContent || ''), F['UC-01']), 'closure proposed');
    ok(/Evidence: re-test RT-\d{5}.*2 Leavers.*record\(s\) dated from.*0 exceptions/.test(await card(p, F['UC-01'])), 'the evidence: re-test id, population, 0 exceptions: ' + await card(p, F['UC-01']));
    ok(!!(await p.$('[data-rtok="' + F['UC-01'] + '"]')), 'the lead auditor may confirm');
    // exceptions
    await p.click('[data-rtrun="' + F['UC-02'] + '"]'); ok(await toast(p, 'reopened'), 'Re-test now: exceptions');
    ok(await wait(p, (id) => /failed - reopened/.test((document.querySelector('[data-rt="' + id + '"]') || {}).textContent || ''), F['UC-02']), 'reopened shown');
    ok(/New exceptions: OFF-22/.test(await card(p, F['UC-02'])) && await p.evaluate(() => !document.querySelector('#retest b') || ![...document.querySelectorAll('#retest b')].some((b) => b.textContent === 'hostile')), 'the new exceptions listed, the hostile label stays text');
    ok((await finding(F['UC-02'])).state === 'responded', 'the team engine has it back with the owner');
    await p.click('[data-rth="' + F['UC-02'] + '"]'); ok(await wait(p, () => /Re-tests of/.test(document.getElementById('dlgb').textContent) && /exceptions/.test(document.querySelector('#dlgb tbody').textContent)), 'history drawer');
    await p.click('[data-close]');
    // link the manual finding
    await p.click('[data-rtlink="' + M + '"]'); await p.waitForSelector('#lform'); await p.selectOption('#lform select[name=uc]', 'UC-13'); await p.click('#lform button[type=submit]');
    ok(await toast(p, 'Use case linked'), 'linked');
    ok(await wait(p, (id) => /UC-13/.test((document.querySelector('[data-rt="' + id + '"]') || {}).textContent || '') && !!document.querySelector('[data-rtrun="' + id + '"]'), M), 'now re-tested automatically');
    ok(await p.evaluate(() => !window.__xss), 'a hostile finding title stays text');
    // the owner: no buttons to confirm
    WHO = OWN; p = await page(ctx, 'audit-command.html');
    ok(!(await p.$('[data-rtok]')) && /clean - confirm closure/.test(await card(p, F['UC-01'])), 'the finding owner sees the proposal but cannot confirm it');
    // the auditor confirms
    WHO = A; p = await page(ctx, 'audit-command.html');
    ANS = ['checked the job log (synthetic)']; await p.click('[data-rtok="' + F['UC-01'] + '"]'); ok(await toast(p, 'Closure confirmed'), 'closure confirmed');
    const f1 = await finding(F['UC-01']); ok(f1.state === 'closed' && f1.retested_by === 'laila.syn' && /RT-\d{5}/.test(f1.retest_note), 'closed through the team engine with the evidence');
    // UC-02 again: the owner fixes the record and implements again; clean; the auditor rejects the closure
    col('offboarding').put(Object.assign(col('offboarding').get('OFF-22'), { disable: { approved_by: 'mgr.syn' } }));
    await P('/csa/findings/' + F['UC-02'] + '/implemented', { evidence: 'second approver enforced (synthetic)' }, OWN);
    await p.click('#refresh'); await p.waitForSelector('[data-rtrun="' + F['UC-02'] + '"]');
    await p.click('[data-rtrun="' + F['UC-02'] + '"]'); ok(await toast(p, 'Re-test clean'), 'the second implementation is clean');
    await p.waitForSelector('[data-rtno="' + F['UC-02'] + '"]');
    ANS = ['too few leavers since the fix to conclude (synthetic)']; await p.click('[data-rtno="' + F['UC-02'] + '"]'); ok(await toast(p, 'Closure rejected'), 'closure rejected');
    ok(await wait(p, (id) => /closure rejected - manual re-test/.test((document.querySelector('[data-rt="' + id + '"]') || {}).textContent || ''), F['UC-02']), 'rejected shown');
    // the administrator: the auto_retest rule
    WHO = ADM; p = await page(ctx, 'audit-command.html');
    ok(!!(await p.$('#sform [name=auto_retest]')) && /Re-test implemented findings automatically/.test(await p.textContent('#set')), 'the auto_retest rule is listed');
    await p.uncheck('#sform [name=auto_retest]'); await p.click('#sform button[type=submit]'); ok(await toast(p, 'Automation rules saved'), 'rule switched off');
    ok((await e.req('GET', '/audit-auto', A)).json.settings.rules.auto_retest === false, 'saved on the server');
    if (process.env.SHOT) await p.screenshot({ path: process.env.SHOT, fullPage: true });
    ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  } finally { await browser.close(); srv.close(); await e.close(); }
  console.log((bad ? 'FAILED ' : 'ok ') + (n - bad) + '/' + n);
  process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
