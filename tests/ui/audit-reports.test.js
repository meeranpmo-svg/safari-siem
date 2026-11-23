// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for Audit Reports (audit-reports.html) against the REAL ITAM engine (engine/audit-report.js over the IT Audit
// Team's engine) with the AI stubbed (the helpers' fake model server), SYNTHETIC engagement data only: the lead drafts the report
// from the engagement's records (a hostile finding title stays text), asks the AI for a draft (a link and a script in the AI text
// are shown as text), puts it in the editor, edits and saves a version, signs; an administrator outside the team approves it
// for issue - frozen with its fingerprint, verified; print and Excel export work; a viewer is refused with the reason; no page errors.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node audit-reports.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const ITAM = path.join(__dirname, '..', '..', 'backend', 'itam'), DASH = path.join(__dirname, '..', '..', 'ui');
const H = require(path.join(ITAM, 'tests', 'helpers'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const XSS = '<img src=x onerror=alert(1)>';

(async () => {
  const e = await H.startApp({});
  require(path.join(ITAM, 'engine/duty')).registerDuty(e.app.srv, e.app, { noTimer: true, python: process.env.PYTHON || 'python3' });
  if (!e.app.addons.auditReport) { const M = require(path.join(ITAM, 'engine/audit-report')); const X = M.createAuditReport(e.app); e.app.addons.auditReport = X; M.registerAuditReport(e.app.srv, e.app, X); }
  const ADM = { user: 'syed', role: 'admin' }, HEAD = { user: 'hana.syn', role: 'operator' }, LEAD = { user: 'laila.syn', role: 'operator' }, OWNER = { user: 'omar.syn', role: 'operator' }, VIEW = { user: 'vera.syn', role: 'viewer' };
  // a synthetic engagement taken to draft report through the IT Audit Team's own engine
  const A = e.app.addons.auditEngage, off = e.app.store.collection('offboarding');
  for (let i = 1; i <= 4; i++) off.put({ id: 'OFF-000' + i, username: 'leaver' + i + '.syn', last_day: '2026-0' + i + '-15', requested_by: 'hr.syn', status: 'completed', disable: { approved_by: i === 2 ? 'hr.syn' : 'mgr.syn' }, disabled: { at: '2026-0' + i + '-15T20:00:00Z' } });
  A.putProfile({ head_of_audit: HEAD.user, auditors: [LEAD.user] }, ADM);
  const today = new Date().toISOString().slice(0, 10), later = new Date(Date.now() + 30 * 86400000).toISOString().slice(0, 10);
  const eng = A.createEngagement({ title: 'Leavers access removal (synthetic)', area: 'joiners', auditee_dept: 'Human Resources', auditee_owner: OWNER.user, lead: LEAD.user, objectives: ['Leavers lose access on their last day'],
    scope: 'All 2026 leavers (synthetic)', criteria: 'NCA ECC 1-9', start: today, fieldwork_end: later, report_due: later }, LEAD);
  A.priorNone(eng.id, { note: 'first audit of this area (synthetic)' }, LEAD); A.advance(eng.id, { to: 'fieldwork' }, LEAD);
  const smp = A.sample(eng.id, { population: 'leavers', size: 2, method: 'judgemental', refs: ['OFF-0002', 'OFF-0004'] }, LEAD);
  A.concludeItem(smp.id, 'OFF-0002', { result: 'exception', note: 'approved by the requester (synthetic)' }, LEAD); A.concludeItem(smp.id, 'OFF-0004', { result: 'pass' }, LEAD);
  const wp = A.addWorkpaper(eng.id, { title: 'Leaver approvals', objective: 'Approved by a second person', procedure: 'Inspect each sampled leaver', sample: smp.id }, LEAD);
  A.concludeWp(wp.id, { conclusion: 'partially_effective', summary: 'One of two leavers self-approved (synthetic)' }, LEAD); A.reviewWp(wp.id, { decision: 'accept' }, HEAD);
  const f = A.addFinding(eng.id, { title: XSS + ' Self-approved leaver', condition: '1 of 2 sampled leavers <script>window.__pwn=1</script>', criteria: 'Four eyes', cause: 'No check', effect: 'Abuse possible', recommendation: 'Block self-approval', rating: 'medium', owner: OWNER.user }, LEAD);
  A.findingAct(f.id, 'issue', {}, LEAD); A.findingAct(f.id, 'respond', { response: 'Agreed (synthetic)', action_plan: 'Second-approver rule', due: later }, OWNER);
  A.advance(eng.id, { to: 'draft_report' }, LEAD);
  e.fake.override = () => ({ ok: true, model: 'synthetic-model-1', usage: { input: 5, output: 5 }, text: JSON.stringify({ executive_summary: 'Needs improvement: one medium finding (synthetic AI). See https://evil.example/x <script>window.__pwn=2</script>',
    conclusion: 'Management agreed (synthetic AI).', finding_narratives: [{ id: f.id, text: 'Narrative <img src=x onerror=alert(2)> (synthetic AI)' }] }) });

  let WHO = LEAD;
  const srv = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://x'), json = (c, b2) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b2)); };
    if (u.pathname === '/dashboards/whoami.json') return json(200, WHO);
    if (u.pathname.startsWith('/api/itam/')) {
      const h = Object.assign({}, req.headers, { 'x-sentra-proxy-secret': H.SECRET, 'x-auth-user': WHO.user, 'x-auth-role': WHO.role });
      const up = http.request({ host: '127.0.0.1', port: e.port, method: req.method, path: req.url, headers: h }, (r) => { res.writeHead(r.statusCode, r.headers); r.pipe(res); });
      req.pipe(up); return;
    }
    if (u.pathname.startsWith('/api/')) return json(404, { error: 'not in this test' });
    const fl = path.join(DASH, u.pathname.replace(/^\/dashboards\//, '/')); if (!fl.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(fl, (err, d) => { if (err) { res.writeHead(404); res.end(); return; } res.writeHead(200, { 'Content-Type': u.pathname.endsWith('.js') ? 'application/javascript' : u.pathname.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port + '/';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  const posted = (p, re) => p.waitForResponse((r) => re.test(r.url()) && r.request().method() === 'POST', { timeout: 10000 });
  const txt = (p, sel, re) => p.waitForFunction((a) => new RegExp(a[1]).test((document.querySelector(a[0]) || {}).textContent || ''), [sel, re.source], { timeout: 10000 }).then(() => true, () => false);
  const pwned = (p) => p.evaluate(() => !!window.__pwn || !!document.querySelector('#rep img[src="x"], #rep a[href], #rep script'));
  try {
    const ctx = await browser.newContext({ viewport: { width: 1400, height: 1100 }, acceptDownloads: true });
    await ctx.addInitScript(() => { window.__printed = 0; window.print = () => { window.__printed++; }; });
    const p = await ctx.newPage(); p.on('pageerror', (x) => errs.push(x.message)); p.on('dialog', (d) => d.accept('Synthetic reason'));
    await p.goto(base + 'audit-reports.html?standalone=1'); await p.waitForSelector('#kpis .card', { timeout: 15000 });
    ok(await txt(p, '#engs', new RegExp(eng.id)), 'the engagement in draft report is offered');
    ok(/No report drafted yet/.test(await p.textContent('#reps')), 'an empty report list says so, with no invented rows');
    // draft from the records
    await Promise.all([posted(p, /audit-reports$/), p.click('[data-draft="' + eng.id + '"]')]);
    await p.waitForSelector('#rep:not([hidden]) #doc h1', { timeout: 10000 });
    const doc = await p.textContent('#doc');
    ok(/Overall rating: Needs improvement/.test(doc) && /1 medium/.test(doc), 'the overall rating follows the stated rule');
    ok(/Leaver approvals/.test(doc) && new RegExp(smp.id).test(doc) && /1 pass · 1 exception/.test(doc) && /Agreed \(synthetic\)/.test(doc), 'procedures, samples and management response come from the records');
    ok(doc.includes(XSS) && !(await pwned(p)), 'a hostile finding title stays text');
    ok(/not drafted by the AI/.test(await p.textContent('#aibox')), 'before the AI the page says the summary is not drafted');
    // the AI proposal, shown as text
    await Promise.all([posted(p, /ai-draft$/), p.click('#aiask')]);
    ok(await txt(p, '#ai-sum', /synthetic AI/), 'the AI draft is shown, labelled');
    const ai = await p.textContent('#aibox');
    ok(/AI draft/.test(ai) && ai.includes('https://evil.example/x') && ai.includes('<script>') && !(await pwned(p)), 'a link and a script in the AI text are shown as text, never as a link or code');
    ok(/link or markup/.test(ai), 'the page says the AI text contained a link or markup');
    ok(!/synthetic AI/.test(await p.textContent('#doc')), 'the AI text is not in the report until a person saves it');
    await p.click('#aiuse');
    ok((await p.inputValue('#f-executive_summary')).includes('synthetic AI'), 'the AI text is put in the editor');
    await p.fill('#f-executive_summary', 'Leaver access removal needs improvement: one medium finding, an action plan is agreed (synthetic, edited by the lead).');
    await Promise.all([posted(p, /\/edit$/), p.click('#editf [type=submit]')]);
    ok(await txt(p, '#editmsg', /Saved as version 2/), 'the edit is saved as a new version');
    ok(await txt(p, '#vers', /laila\.syn/) && (await p.$$('#vers tbody tr')).length === 2, 'both versions are listed');
    ok(await txt(p, '#doc', /edited by the lead/), 'the report shows the person\'s text');
    // sign as the lead
    await Promise.all([posted(p, /\/sign$/), p.click('#sign')]);
    ok(await txt(p, '#rstate', /signed by laila\.syn/), 'signed by the lead');
    ok(await p.isHidden('#approve'), 'the lead cannot approve for issue');
    // an administrator outside the team approves for issue
    WHO = ADM; await p.goto('about:blank'); await p.goto(base + 'audit-reports.html?standalone=1#report=AR-' + eng.id); await p.waitForSelector('#rep:not([hidden]) #doc h1', { timeout: 15000 });
    await Promise.all([posted(p, /\/approve$/), p.click('#approve')]);
    ok(await txt(p, '#rstate', /approved for issue by syed/) && await txt(p, '#rstate', /SHA-256 fingerprint [0-9a-f]{64}/), 'issued, approved and fingerprinted');
    ok(await p.isHidden('#editf') && await p.isHidden('#aiask'), 'an issued report cannot be edited');
    await Promise.all([p.waitForResponse((r) => /\/verify$/.test(r.url()), { timeout: 10000 }), p.click('#verify')]);
    ok(await txt(p, '.toast-zyb', /Fingerprint verified/), 'the fingerprint verifies');
    await p.click('#print'); ok(await p.evaluate(() => window.__printed) === 1, 'print opens the print dialog');
    const [dl] = await Promise.all([p.waitForEvent('download', { timeout: 10000 }), p.click('#xlsx')]);
    const fp = await dl.path(), buf = fs.readFileSync(fp);
    ok(dl.suggestedFilename() === 'AR-' + eng.id + '.xlsx' && buf.slice(0, 2).toString() === 'PK' && buf.includes(Buffer.from('xl/worksheets/sheet2.xml')), 'the Excel export is a real workbook');
    ok(await txt(p, '#reps', /issued/), 'the list shows it issued');
    // a viewer is refused, with the reason, and nothing breaks
    WHO = VIEW; await p.goto(base + 'audit-reports.html?standalone=1');
    ok(await txt(p, '#engs', /operator role/), 'viewer refused with the reason');
    ok(!errs.length, 'no page errors: ' + errs.join(' | '));
    await ctx.close();
  } catch (x) { ok(false, 'exception: ' + (x && x.stack || x)); }
  await browser.close(); srv.close(); await e.close();
  console.log(bad ? `${bad}/${n} FAILED` : `all ${n} checks passed`);
  process.exit(bad ? 1 : 0);
})();
