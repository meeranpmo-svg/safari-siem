// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Privacy Office (pdpl-office.html) - the re-check of tasks marked done, stubbed ITAM, SYNTHETIC data: the verification state on
// each task (being re-checked with the number of re-checks, verified by re-test, not confirmed - reopened), the KPIs and filters
// for it, the task drawer's Verification section (which check, when, the evidence, the reopen date), the re-check period in
// Settings (posted as verify_days), escaping, no page errors.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node pdpl-office-retest.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const DASH = path.resolve(__dirname, '../../ui');
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const POSTS = [];
const XSS = '<img src=x onerror=alert(1)>';
const ROADMAP = { progress: 10, note: 'synthetic', phases: [1, 2, 3, 4, 5, 6, 7, 8].map((i) => ({ phase: i, name: 'Phase ' + i, goal: 'g', state: 'todo', done: 0, steps: 1, progress: 0, resources: ['DPO'], when: 'estimate', open_tasks: 0, overdue_tasks: 0 })), steps: [], maintain: [{ cadence: 'Daily', what: 'w', who: 'DPO' }] };
const H = [{ at: '2026-10-20T08:00:00Z', by: 'system:privacy-office', what: 'raised' }];
const CHECK = 'PDPL register check P-04:ropa:PD-ROPA-001:incomplete (P-04) on pdpl "Medical claims (synthetic) ' + XSS + '"';
const TASKS = [
  { id: 'PO-00001', key: 'f:P-04:ropa:PD-ROPA-001:incomplete', source: 'finding', title: 'Activity incomplete (synthetic)', severity: 'medium', requirement: 'P-04', assignee: 'faisal.syn', why: 'data steward of Claims', due: '2026-11-20T08:00:00Z', status: 'claimed', overdue: false, escalation: 0, history: H, claimed_by: 'faisal.syn', claimed_at: '2026-10-21T08:00:00Z',
    verification: { state: 'checking', claim_at: '2026-10-21T08:00:00Z', claimed_by: 'faisal.syn', runs: 4, check: CHECK, days: 3, deadline: '2026-10-24T08:00:00Z', last_check_at: '2026-10-22T08:00:00Z', last_result: 'the registers still show it' } },
  { id: 'PO-00002', key: 'f:P-07:dpia:PD-ROPA-001', source: 'finding', title: 'DPIA missing (synthetic)', severity: 'high', requirement: 'P-07', assignee: 'faisal.syn', why: 'data steward of Claims', due: '2026-10-27T08:00:00Z', status: 'open', overdue: false, escalation: 1, escalated_to: 'huda.syn', history: H.concat([{ at: '2026-10-24T08:00:00Z', by: 'system:privacy-office', what: 'verification failed: the registers still show it 3 day(s) after faisal.syn marked it done (6 re-check(s)) - reopened' }]),
    verification: { state: 'failed', claim_at: '2026-10-21T08:00:00Z', claimed_by: 'faisal.syn', runs: 6, check: 'PDPL register check P-07:dpia:PD-ROPA-001 (P-07)', days: 3, failed_at: '2026-10-24T08:00:00Z', last_check_at: '2026-10-24T08:00:00Z', last_result: 'the registers still show it' } },
  { id: 'PO-00003', key: 'f:P-12:retention', source: 'finding', title: 'No retention rule (synthetic)', severity: 'medium', requirement: 'P-12', assignee: 'huda.syn', why: 'the DPO', due: '2026-11-20T08:00:00Z', status: 'closed', closed_reason: 'verified by re-test', overdue: false, escalation: 0, history: H,
    verification: { state: 'verified', claim_at: '2026-10-21T08:00:00Z', claimed_by: 'huda.syn', runs: 2, check: 'PDPL register check P-12:retention (P-12)', verified_at: '2026-10-21T08:30:00Z', last_check_at: '2026-10-21T08:30:00Z', evidence: 'verified by re-test: PDPL register check P-12:retention (P-12) is no longer raised by the PDPL registers at 2026-10-21T08:30:00Z (2 re-check(s) since the claim of 2026-10-21T08:00)' } }];
const ORG = { dpo: 'huda.syn', dpo_deputy: null, functions: [], departments: [{ department: 'Claims', data_steward: 'faisal.syn', deputy: null, champion: null }], committee: { chair: null, members: [] }, owners: [] };
const VIEW = () => ({ org: ORG, gaps: [], calendar: [], roadmap: ROADMAP, sla_days: { critical: 2, high: 7, medium: 30, low: 60 }, escalate_days: 7, verify_days: 3, tasks: TASKS, me: 'huda.syn', is_dpo: true, can_configure: true,
  totals: { open: 2, overdue: 0, escalated: 1, claimed: 1, verified: 1, verify_failed: 1, accepted: 0, unassigned: 0 } });
(async () => {
  const srv = http.createServer((req, res) => {
    const u = decodeURIComponent(req.url.split('?')[0]), json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    const body = (fn) => { let b = ''; req.on('data', (c) => { b += c; }); req.on('end', () => { const j = JSON.parse(b || '{}'); POSTS.push([u, j]); fn(j); }); };
    if (u === '/dashboards/whoami.json' || u === '/auth/whoami') return json(200, { user: 'huda.syn', role: 'operator' });
    if (u === '/api/itam/pdpl/office/mine') return json(200, { tasks: [TASKS[0], TASKS[1]], roadmap: ROADMAP, me: 'huda.syn', roles: ['DPO'], maintain: ROADMAP.maintain });
    if (u === '/api/itam/pdpl/office') return json(200, VIEW());
    if (u === '/api/itam/pdpl/office/notify') return json(200, { email_enabled: false, teams_enabled: false, smtp: {}, contacts: [], outbox: [], vault: 'available' });
    if (u === '/api/itam/pdpl/office/config') return body((b) => json(200, b));
    if (u.startsWith('/api/')) return json(404, { error: 'not in this test' });
    const f = path.join(DASH, u.replace(/^\/dashboards\//, '')); if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (e, d) => { if (e) { res.writeHead(404); return res.end(); } res.writeHead(200, { 'Content-Type': f.endsWith('.js') ? 'application/javascript' : f.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port;
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright'); const browser = await chromium.launch();
  const last = (end) => [...POSTS].reverse().find((x) => x[0].endsWith(end));
  try {
    const p = await browser.newPage(); const errs = []; await p.addInitScript(() => { window.ZYB_ARABIC = false; }); let dialogs = 0; p.on('pageerror', (e) => errs.push(e.message)); p.on('dialog', (d) => { dialogs++; d.dismiss(); });
    await p.goto(base + '/dashboards/pdpl-office.html?standalone=1'); await p.waitForSelector('#route svg [data-phase="8"]');
    await p.waitForFunction(() => !document.querySelector('[data-tab="all"]').hidden);
    ok(/re-checked against the registers every 30 minutes/.test(await p.$eval('[data-t="intro"]', (e) => e.textContent)), 'the introduction says how a "done" is checked');
    // my tasks: the badges
    await p.click('[data-tab="mine"]'); await p.waitForSelector('#mylist [data-open="PO-00001"]');
    const ml = await p.$eval('#mylist', (e) => e.innerText);
    ok(/being re-checked · 4/.test(ml), 'a claimed task: being re-checked, with the re-checks so far');
    ok(/not confirmed - reopened/.test(ml) && /at the DPO/.test(ml), 'a failed re-check: reopened and at the DPO');
    // the drawer: Verification section
    await p.click('#mylist [data-open="PO-00001"]'); await p.waitForSelector('#zd-b');
    let dr = await p.$eval('#zd-b', (e) => e.innerText);
    ok(/Verification/.test(dr) && /PDPL register check P-04:ropa:PD-ROPA-001:incomplete/.test(dr) && /Reopened if still shown on/.test(dr) && /3 day\(s\)/.test(dr) && /the registers still show it/.test(dr), 'drawer: which check, the re-checks and when it reopens');
    ok(await p.$$eval('#zd-b img', (a) => a.length) === 0, 'the check text is escaped');
    await p.keyboard.press('Escape');
    await p.click('#mylist [data-open="PO-00002"]'); await p.waitForSelector('#zd-b');
    dr = await p.$eval('#zd-b', (e) => e.innerText); ok(/not confirmed - reopened/.test(dr) && /Reopened/.test(dr) && /verification failed: the registers still show it 3 day/.test(dr), 'drawer: a failed re-check and its history');
    await p.keyboard.press('Escape');
    // all tasks: KPIs and filters
    await p.click('[data-tab="all"]'); await p.waitForSelector('#alllist [data-open]');
    const k = await p.$eval('#kpis', (e) => e.innerText); ok(/Verified by re-test/i.test(k) && /Not confirmed by the re-check/i.test(k), 'KPIs: verified and not confirmed');
    await p.selectOption('#fstat', 'verify_failed'); ok(await p.$$eval('#alllist [data-open]', (a) => a.map((x) => x.getAttribute('data-open')).join()) === 'PO-00002', 'filter: not confirmed by the re-check');
    await p.selectOption('#fstat', 'verified'); ok(await p.$$eval('#alllist [data-open]', (a) => a.map((x) => x.getAttribute('data-open')).join()) === 'PO-00003', 'filter: verified by re-test');
    ok(/verified by re-test/.test(await p.$eval('#alllist', (e) => e.innerText)), 'a closed task shows it was verified');
    await p.click('#alllist [data-open="PO-00003"]'); await p.waitForSelector('#zd-b');
    ok(/verified by re-test: PDPL register check P-12:retention .*no longer raised by the PDPL registers at 2026-10-21T08:30/.test(await p.$eval('#zd-b', (e) => e.innerText)), 'drawer: the verification evidence');
    await p.keyboard.press('Escape');
    // settings: the re-check period
    await p.click('[data-tab="cfg"]'); await p.waitForSelector('#cfgform');
    ok(await p.$eval('#cfgform-verify_days', (e) => e.value) === '3', 'the re-check period is shown');
    await p.fill('#cfgform-verify_days', '5'); await p.click('#cfgform button[type=submit]'); await p.waitForTimeout(300);
    const x = last('/office/config'); ok(x && x[1].verify_days === 5, 'verify_days posted: ' + JSON.stringify(x && x[1]));
    ok(!errs.length, 'no page errors: ' + errs.join(' | ')); ok(!dialogs, 'no browser dialogs');
  } finally { await browser.close(); srv.close(); }
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks'); process.exit(bad ? 1 : 0);
})();
