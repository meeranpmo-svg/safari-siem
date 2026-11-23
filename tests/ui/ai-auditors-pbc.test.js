// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// AI Auditors → Audit checklist → Evidence requests (PBC list), stubbed ITAM, SYNTHETIC data: the list loads with the
// checklist, overdue / provided / issued states, Issue posts {fw, due}, Respond posts {id, reference, note}, Accept and
// Reject post the decision, a server refusal (four-eyes) is shown, escaping, formula-safe CSV, viewer refusal message.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node ai-auditors-pbc.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const DASH = path.resolve(__dirname, '../../ui');
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const POSTS = []; let REFUSE_DECIDE = false, VIEWER = false;
const VIEW = { fw: 'sama', name: 'SAMA Cyber Security Framework', generated_at: new Date().toISOString(), note: 'n', compliance_pct: 0, assessed_pct: 0, counts: { compliant: 0, partial: 0, non_compliant: 0, not_applicable: 0, auto_pass: 0, not_assessed: 1 },
  domains: [{ code: '3.3.5', name: 'IAM SYN', checks: ['AC-24'], result: 'not_assessed' }], checks: [{ id: 'AC-24', title: 'Privileged access', procedure: 'p', evidence_expected: 'e', owner: 'cyber', owner_name: 'Cyber Security', sama: ['3.3.5'], nca: ['2-2'], ia: ['3.3.5'], auto: null, assessment: null, result: 'not_assessed', why: 'w', conflict: false }] };
const RQ = (id, o) => Object.assign({ ref: 'PBC-' + id, id, title: 'Check ' + id, owner: 'infra', owner_name: 'IT Infrastructure', evidence_expected: 'Synthetic evidence for ' + id, procedure: 'Inspect.', result: 'not_assessed', why: 'w', failing_tests: [], state: 'not_issued', overdue: false, days_overdue: 0, due: null }, o);
const LIST = () => ({ fw: 'sama', name: 'SAMA Cyber Security Framework', note: 'Accepting the evidence does not by itself make the check compliant.', by_state: { not_issued: 1, issued: 1, provided: 1, accepted: 0, overdue: 1 }, by_owner: {},
  items: [RQ('AC-24', { title: '<img src=x onerror=alert(1)> privileged', failing_tests: ['CY-16'] }), RQ('AC-29', { state: 'issued', due: '2026-10-01', overdue: true, days_overdue: 12 }),
    RQ('AC-52', { state: 'provided', due: '2026-11-03', response: { reference: '=HYPERLINK("x")', by: 'infra.syn', at: new Date().toISOString(), late: false } })] });
(async () => {
  const srv = http.createServer((req, res) => {
    const u = decodeURIComponent(req.url.split('?')[0]), json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    const post = (fn) => { let b = ''; req.on('data', (c) => { b += c; }); req.on('end', () => { const j = JSON.parse(b || '{}'); POSTS.push([u, j]); fn(j); }); };
    if (u === '/dashboards/whoami.json' || u === '/auth/whoami') return json(200, { user: 'syed', role: 'admin' });
    if (u === '/api/itam/audit-programme') return json(200, { departments: {}, note: 'n', auditors: [{ id: 'itaudit', name: 'AI IT Auditor', about: 'a', counts: { pass: 0, fail: 0, not_tested: 0, not_run: 1 }, tests: [] }, { id: 'cyberaudit', name: 'AI Cyber Security Auditor', about: 'b', counts: { pass: 0, fail: 0, not_tested: 0, not_run: 1 }, tests: [] }] });
    if (u === '/api/itam/audit-checklist') return json(200, VIEW);
    if (u === '/api/itam/audit-checklist/requests') return VIEWER ? json(403, { error: 'requires operator' }) : json(200, LIST());
    if (u === '/api/itam/audit-checklist/requests/issue') return post((j) => json(200, { issued: 1, due: j.due }));
    if (u === '/api/itam/audit-checklist/requests/respond') return post((j) => json(200, { id: j.id, state: 'provided' }));
    if (u === '/api/itam/audit-checklist/requests/decide') return post((j) => (REFUSE_DECIDE ? json(403, { error: 'four-eyes: the person who provided the evidence cannot accept or reject it' }) : json(200, { id: j.id, state: j.decision === 'accept' ? 'accepted' : 'issued' })));
    if (u.startsWith('/api/')) return json(404, { error: 'not in this test' });
    const f = path.join(DASH, u.replace(/^\/dashboards\//, '')); if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (e, d) => { if (e) { res.writeHead(404); return res.end(); } res.writeHead(200, { 'Content-Type': f.endsWith('.js') ? 'application/javascript' : f.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port;
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright'); const browser = await chromium.launch();
  try {
    const ctx = await browser.newContext({ acceptDownloads: true }); const p = await ctx.newPage(); const errs = []; let dialogs = 0; p.on('pageerror', (e) => errs.push(e.message)); p.on('dialog', (d) => { dialogs++; d.dismiss(); });
    await p.goto(base + '/dashboards/ai-auditors.html?standalone=1#checklist'); await p.waitForSelector('#pbcbody table');
    const sum = await p.$eval('#pbcsum', (e) => e.textContent);
    ok(/3 request\(s\)/.test(sum) && /1 overdue/.test(sum) && /does not by itself make the check compliant/.test(sum), 'summary: ' + sum);
    const rows = await p.$$eval('#pbcbody tbody tr', (a) => a.map((r) => r.innerText.replace(/\s+/g, ' ')));
    ok(rows.length === 3 && /Overdue 12 d/.test(rows[1]) && /Provided - to review/.test(rows[2]) && /AI test failing: CY-16/.test(rows[0]), 'states shown: ' + JSON.stringify(rows));
    ok(await p.$$eval('#pbcbody img', (a) => a.length) === 0, 'titles escaped');
    // issue
    await p.fill('#pbcdue', '2026-11-10'); await p.click('#pbcissue'); await p.waitForTimeout(400);
    let last = POSTS[POSTS.length - 1]; ok(last[0].endsWith('/issue') && last[1].fw === 'sama' && last[1].due === '2026-11-10', 'issue posted: ' + JSON.stringify(last));
    // respond
    await p.click('[data-pbc="respond"][data-id="AC-29"]'); await p.waitForSelector('#pbcform');
    await p.fill('#pbcform input[name=reference]', 'DMS/IT/PATCH-REPORT-OCT.pdf'); await p.fill('#pbcform textarea[name=note]', 'October report'); await p.click('#pbcform button[type=submit]'); await p.waitForTimeout(400);
    last = POSTS[POSTS.length - 1]; ok(last[0].endsWith('/respond') && last[1].id === 'AC-29' && last[1].reference === 'DMS/IT/PATCH-REPORT-OCT.pdf', 'response posted: ' + JSON.stringify(last));
    // four-eyes refusal shown, then accept
    REFUSE_DECIDE = true; await p.click('[data-pbc="accept"][data-id="AC-52"]'); await p.waitForSelector('#pbcform'); await p.click('#pbcform button[type=submit]'); await p.waitForTimeout(400);
    ok(/four-eyes/.test(await p.$eval('#pbcmsg', (e) => e.textContent)), 'four-eyes refusal shown in the form');
    REFUSE_DECIDE = false; await p.click('#pbcform button[type=submit]'); await p.waitForTimeout(400);
    last = POSTS[POSTS.length - 1]; ok(last[0].endsWith('/decide') && last[1].id === 'AC-52' && last[1].decision === 'accept', 'accept posted: ' + JSON.stringify(last));
    await p.click('[data-pbc="reject"][data-id="AC-52"]'); await p.waitForSelector('#pbcform'); await p.fill('#pbcform textarea[name=note]', 'not signed'); await p.click('#pbcform button[type=submit]'); await p.waitForTimeout(400);
    last = POSTS[POSTS.length - 1]; ok(last[1].decision === 'reject' && last[1].note === 'not signed', 'reject posted with a note');
    // CSV
    const [dl] = await Promise.all([p.waitForEvent('download'), p.click('#pbccsv')]);
    const csv = fs.readFileSync(await dl.path(), 'utf8');
    ok(/PBC-AC-29/.test(csv) && /"'=HYPERLINK/.test(csv) && /overdue/.test(csv) && /^pbc-list-sama-/.test(dl.suggestedFilename()), 'CSV with every request, formula-safe');
    // viewer
    VIEWER = true; const p2 = await ctx.newPage(); p2.on('pageerror', (e) => errs.push(e.message));
    await p2.goto(base + '/dashboards/ai-auditors.html?standalone=1#checklist'); await p2.waitForFunction(() => /operators and administrators only/.test(document.getElementById('pbcbody').innerText));
    ok(true, 'viewer told the list is for operators');
    ok(!errs.length, 'no page errors: ' + errs.join(' | ')); ok(!dialogs, 'no browser dialogs');
  } finally { await browser.close(); srv.close(); }
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks'); process.exit(bad ? 1 : 0);
})();
