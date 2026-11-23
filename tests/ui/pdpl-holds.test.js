// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Legal holds (ai-pdpl.html → Retention) and the breach regulator track (pdpl-breach.html), stubbed ITAM, SYNTHETIC data:
// holds table (active / released, review overdue, blocked runs), place a hold posting the right body, review and release
// with notes, a four-eyes refusal shown, "on hold" badge on the rule, the plan form offering the hold exclusion and posting
// it; the regulators column and drawer (to decide / due / overdue / notified / not required), recording a decision and a
// notification, a refusal shown, escaping, operator-only message.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node pdpl-holds.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const DASH = path.resolve(__dirname, '../../ui');
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const POSTS = []; let RELEASE403 = false, HOLDS403 = false, REG409 = false;
const XSS = '<img src=x onerror=alert(1)>';
const VIEW = { engine: 'python', connected: true, compliance_pct: 10, counts: { compliant: 0, partial: 0, non_compliant: 0, not_applicable: 0, auto_pass: 0, not_assessed: 1 }, requirements: [], findings: [], readiness: { ready: false, blockers: [], digest: 'sha256:' + 'a'.repeat(64) }, statement: { status: 'none' }, note: 'n' };
const RET = { overdue: 0, pending_approval: 1, active_holds: 1, note: 'The platform never deletes data.', rules: [{ id: 'PD-RETENTION-001', name: 'Closed motor claims', systems: ['CLAIMS-SYN', 'DMS-SYN'], data_categories: ['identity'], period_months: 60, trigger: 'claim_closed', action: 'destroy',
  due: { next_due: '2027-01-01T00:00:00.000Z', overdue: false }, holds: [{ id: 'PD-LEGAL_HOLD-001', ref: 'CL-SYN-0042', systems: ['CLAIMS-SYN'] }],
  runs: [{ id: 'PD-DESTRUCTION-001', status: 'approved', system: 'CLAIMS-SYN', cutoff: '2020-12-31', approved_by: 'huda.syn', holds_excluded: [{ id: 'PD-LEGAL_HOLD-001', ref: 'CL-SYN-0042' }], exclusion: 'claim filter' }] }] };
const HOLDS = { active: 1, review_overdue: 1, note: 'A legal hold keeps records past their retention period. A hold is released by the DPO or an administrator who did not place it.',
  reasons: [['claim', 'open or disputed claim'], ['litigation', 'court case or arbitration'], ['complaint', 'complaint (customer, SDAIA, Insurance Authority)']],
  holds: [{ id: 'PD-LEGAL_HOLD-001', ref: 'CL-SYN-0042', reason: 'litigation', reason_label: 'court case or arbitration', scope: XSS + ' records of claim CL-SYN-0042', systems: ['CLAIMS-SYN'], all_systems: false, data_categories: [], status: 'active',
    placed_by: 'nora.syn', placed_at: '2026-06-01T08:00:00.000Z', review: { next_review: '2026-09-01T00:00:00.000Z', overdue: true }, rules: ['PD-RETENTION-001'], runs: [{ id: 'PD-DESTRUCTION-001', status: 'approved', system: 'CLAIMS-SYN', excluded: true }, { id: 'PD-DESTRUCTION-002', status: 'planned', system: 'CLAIMS-SYN', excluded: false }] },
  { id: 'PD-LEGAL_HOLD-002', ref: 'AUD-SYN-1', reason: 'audit', reason_label: 'audit', scope: 'external audit (synthetic)', systems: [], all_systems: true, data_categories: ['financial'], status: 'released', placed_by: 'fahad.syn', placed_at: '2026-05-01T08:00:00.000Z', released_by: 'huda.syn', released_at: '2026-10-01T08:00:00.000Z', review: { next_review: '2026-11-01T00:00:00.000Z', overdue: false }, rules: [], runs: [] }] };
const reg = (key, label, o) => Object.assign({ key, label, hours: null, decided: false, required: null, deadline: null, hours_left: null, late: false, notified_at: null, ref: null, reason: null, by: null, at: null, status: 'to decide' }, o || {});
const BRE = { open: 1, playbook: [], regulator_note: 'Deadlines are the hours an administrator sets in the PDPL profile - the platform assumes none.', regulators: [],
  breaches: [{ id: 'PD-BREACH-001', ref: 'BR-SYN-9', aware_at: '2026-10-19T08:00Z', deadline: '2026-10-22T08:00:00Z', hours_left: 20, late: false, closed: false, next: 'Contain', subjects_count: null, categories: [], description: 'synthetic', regulators_open: 3,
    steps: [{ step: 'contain', label: 'Contain', done: false }, { step: 'assess', label: 'Assess', done: true, at: '2026-10-19T09:00Z', by: 'nora.syn' }],
    regulators: [reg('ia', 'Insurance Authority', { hours: 24, decided: true, required: true, status: 'notified', notified_at: '2026-10-19T20:00Z', ref: 'IA-SYN-' + XSS, by: 'nora.syn', at: '2026-10-19T20:00Z' }),
      reg('sama', 'Saudi Central Bank (SAMA)', { hours: 4, decided: true, required: true, status: 'overdue', late: true, hours_left: -20, deadline: '2026-10-19T12:00:00Z', by: 'nora.syn', at: '2026-10-19T10:00Z' }),
      reg('nca', 'National Cybersecurity Authority (NCA)', { decided: true, required: false, status: 'not required', reason: 'no CNI system involved', by: 'nora.syn', at: '2026-10-19T10:00Z' }),
      reg('chi', 'Council of Health Insurance (CHI)')] }] };
(async () => {
  const srv = http.createServer((req, res) => {
    const u = decodeURIComponent(req.url.split('?')[0]), json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    const body = (fn) => { let b = ''; req.on('data', (c) => { b += c; }); req.on('end', () => { const j = JSON.parse(b || '{}'); POSTS.push([u, j]); fn(j); }); };
    if (u === '/dashboards/whoami.json' || u === '/auth/whoami') return json(200, { user: 'syed', role: 'admin' });
    if (u === '/api/itam/pdpl') return json(200, VIEW);
    if (u === '/api/itam/pdpl/retention') return json(200, RET);
    if (u === '/api/itam/pdpl/holds' && req.method === 'GET') return HOLDS403 ? json(403, { error: 'requires operator' }) : json(200, HOLDS);
    if (u === '/api/itam/pdpl/holds') return body(() => json(200, { id: 'PD-LEGAL_HOLD-003', status: 'active' }));
    if (/^\/api\/itam\/pdpl\/holds\/PD-LEGAL_HOLD-001\/(review|release)$/.test(u)) return body(() => (RELEASE403 && /release$/.test(u) ? json(403, { error: 'four-eyes: the person who placed the hold cannot release it' }) : json(200, { id: 'PD-LEGAL_HOLD-001', status: /release$/.test(u) ? 'released' : 'active' })));
    if (u === '/api/itam/pdpl/destruction') return body(() => json(200, { id: 'PD-DESTRUCTION-003', status: 'planned' }));
    if (u === '/api/itam/pdpl/breaches') return json(200, BRE);
    if (u === '/api/itam/pdpl/breach/PD-BREACH-001/regulator') return body(() => (REG409 ? json(409, { error: 'sama was recorded as notified - that record is evidence and is not changed' }) : json(200, BRE.breaches[0])));
    if (u.startsWith('/api/')) return json(404, { error: 'not in this test' });
    const f = path.join(DASH, u.replace(/^\/dashboards\//, '')); if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (e, d) => { if (e) { res.writeHead(404); return res.end(); } res.writeHead(200, { 'Content-Type': f.endsWith('.js') ? 'application/javascript' : f.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port;
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright'); const browser = await chromium.launch();
  const last = (end) => [...POSTS].reverse().find((x) => x[0].endsWith(end));
  try {
    const p = await browser.newPage(); const errs = []; let dialogs = 0; p.on('pageerror', (e) => errs.push(e.message)); p.on('dialog', (d) => { dialogs++; d.dismiss(); });
    await p.goto(base + '/dashboards/ai-pdpl.html?standalone=1#retention'); await p.waitForSelector('#hbody table'); await p.waitForSelector('#rbody table');
    const ht = await p.$eval('#v-retention', (e) => e.innerText);
    ok(/1 active · 1 review overdue/.test(ht) && /CL-SYN-0042/.test(ht) && /court case or arbitration/.test(ht) && /\(overdue\)/.test(ht), 'holds summary and review overdue');
    ok(/PD-DESTRUCTION-001 \(excluded\)/.test(ht) && /PD-DESTRUCTION-002 blocked/.test(ht), 'runs a hold stops / excludes');
    ok(/released 2026-10-01 by huda\.syn/.test(ht) && /all systems/.test(ht) && /financial only/.test(ht), 'released hold and narrowed categories');
    ok(/on hold: CL-SYN-0042/.test(ht) && /1 legal hold\(s\)/.test(ht) && /excludes CL-SYN-0042/.test(ht), 'rule badge and run exclusion');
    ok(await p.$$eval('#v-retention img', (a) => a.length) === 0, 'scope escaped');
    ok(await p.$$eval('tr[data-hold="PD-LEGAL_HOLD-002"] [data-hact]', (a) => a.length) === 0, 'no actions on a released hold');
    // place a hold
    await p.click('#hnew'); await p.waitForSelector('#hform');
    await p.fill('#hform input[name=ref]', 'CMP-SYN-7'); await p.selectOption('#hform select[name=reason]', 'complaint'); await p.fill('#hform input[name=systems]', 'DMS-SYN, CRM-SYN');
    await p.check('#hform input[name=cat][value=contact]'); await p.fill('#hform textarea[name=scope]', 'documents of complaint CMP-SYN-7'); await p.fill('#hform input[name=review_months]', '3');
    await p.click('#hform button[type=submit]'); await p.waitForTimeout(400);
    let x = last('/pdpl/holds'); ok(x && x[1].ref === 'CMP-SYN-7' && x[1].reason === 'complaint' && x[1].systems.join() === 'DMS-SYN,CRM-SYN' && x[1].data_categories.join() === 'contact' && x[1].review_months === 3 && x[1].all_systems === false, 'hold posted: ' + JSON.stringify(x && x[1]));
    // review, release (refused, then accepted)
    await p.click('[data-hact="review"][data-id="PD-LEGAL_HOLD-001"]'); await p.waitForSelector('#hform'); await p.fill('#hform input[name=note]', 'court case still open'); await p.click('#hform button[type=submit]'); await p.waitForTimeout(400);
    x = last('/review'); ok(x && x[1].note === 'court case still open', 'review posted');
    RELEASE403 = true; await p.click('[data-hact="release"][data-id="PD-LEGAL_HOLD-001"]'); await p.waitForSelector('#hform'); await p.fill('#hform input[name=note]', 'claim settled and appeal period over'); await p.click('#hform button[type=submit]'); await p.waitForTimeout(400);
    ok(/four-eyes/.test(await p.$eval('#hmsg', (e) => e.textContent)), 'four-eyes refusal shown');
    RELEASE403 = false; await p.click('#hform button[type=submit]'); await p.waitForTimeout(400);
    ok(POSTS.filter((y) => /001\/release$/.test(y[0])).length === 2, 'release posted');
    // plan: the form offers the exclusion and posts it
    await p.click('[data-dplan="PD-RETENTION-001"]'); await p.waitForSelector('#dform');
    ok(/Under legal hold: CL-SYN-0042 \(CLAIMS-SYN\)/.test(await p.$eval('#dform', (e) => e.innerText)), 'plan form warns of the hold');
    await p.fill('#dform input[name=cutoff]', '2020-12-31'); await p.check('#dform input[name=exh][value="PD-LEGAL_HOLD-001"]'); await p.fill('#dform input[name=exclusion]', 'purge script filters claim CL-SYN-0042');
    await p.click('#dform button[type=submit]'); await p.waitForTimeout(400);
    x = last('/destruction'); ok(x && x[1].exclude_holds.join() === 'PD-LEGAL_HOLD-001' && x[1].exclusion === 'purge script filters claim CL-SYN-0042' && x[1].system === 'CLAIMS-SYN', 'plan with exclusion posted: ' + JSON.stringify(x && x[1]));
    // profile: regulator deadlines are fields an admin fills
    ok(/notify_hours_sama/.test(await p.content()), 'profile carries the regulator deadline fields');
    HOLDS403 = true; const p2 = await browser.newPage(); p2.on('pageerror', (e) => errs.push(e.message));
    await p2.goto(base + '/dashboards/ai-pdpl.html?standalone=1#retention'); await p2.waitForFunction(() => /for operators/.test(document.getElementById('hbody').innerText)); ok(true, 'operator-only message');

    // breach regulators
    await p.goto(base + '/dashboards/pdpl-breach.html?standalone=1'); await p.waitForSelector('#kpis .card');
    const lt = await p.$eval('#list', (e) => e.innerText); ok(/IA/.test(lt) && /SAMA/.test(lt) && /CHI/.test(lt), 'regulators column');
    await p.click('#list tr[data-id="PD-BREACH-001"]'); await p.waitForSelector('#rform');
    const dt = await p.$eval('#zd-b', (e) => e.innerText);
    ok(/assumes none/.test(dt) && /overdue 20 h/.test(dt) && /not required/.test(dt) && /no CNI system involved/.test(dt) && /to decide/.test(dt) && /notified/.test(dt), 'drawer statuses: ' + dt.slice(0, 300));
    ok(await p.$$eval('#zd-b img', (a) => a.length) === 0, 'reference escaped');
    const opts = await p.$$eval('#rform-regulator option', (a) => a.map((o) => o.value)); ok(!opts.includes('ia') && opts.includes('sama') && opts.includes('other'), 'a notified regulator is not offered again: ' + opts);
    await p.selectOption('#rform-regulator', 'sama'); await p.selectOption('#rform-required', 'yes'); await p.fill('#rform-notified_at', '2026-10-19T20:00'); await p.fill('#rform-ref', 'SAMA-SYN-1');
    await p.click('#rform button[type=submit]'); await p.waitForTimeout(400);
    x = last('/regulator'); ok(x && x[1].regulator === 'sama' && x[1].required === true && x[1].notified_at === '2026-10-19T20:00Z' && x[1].ref === 'SAMA-SYN-1', 'notification posted: ' + JSON.stringify(x && x[1]));
    await p.waitForSelector('#rform');
    await p.selectOption('#rform-regulator', 'chi'); await p.selectOption('#rform-required', 'no'); await p.fill('#rform-reason', 'no health data involved');
    await p.click('#rform button[type=submit]'); await p.waitForTimeout(400);
    x = last('/regulator'); ok(x && x[1].regulator === 'chi' && x[1].required === false && x[1].reason === 'no health data involved', 'not-required decision posted');
    await p.waitForSelector('#rform');
    REG409 = true; await p.selectOption('#rform-regulator', 'sama'); await p.selectOption('#rform-required', 'no'); await p.fill('#rform-reason', 'changed'); await p.click('#rform button[type=submit]'); await p.waitForTimeout(400);
    ok(/evidence/.test(await p.$eval('#rform [data-msg]', (e) => e.textContent)), 'refusal shown');
    ok(!errs.length, 'no page errors: ' + errs.join(' | ')); ok(!dialogs, 'no browser dialogs');
  } finally { await browser.close(); srv.close(); }
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks'); process.exit(bad ? 1 : 0);
})();
