// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// AI Auditors → Audit checklist (SAMA · IA · NCA), stubbed ITAM, SYNTHETIC data: the framework switch loads each checklist,
// domains with their worst result, KPIs (confirmed compliance, non-compliant, automated pass to confirm, not assessed),
// the filter, the check drawer (procedure, AI tests, conflict) with the assessment form posting {id, status, evidence,
// note}, the server's refusal shown, escaping, CSV (formula-safe) and the printable checklist with sign-off.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node ai-auditors-checklist.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const DASH = path.resolve(__dirname, '../../ui');
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const POSTS = []; let REFUSE = false;
const ck = (id, title, res, o) => Object.assign({ id, title, procedure: 'Inspect the SYN records.', evidence_expected: 'SYN evidence', owner: 'grc', owner_name: 'Governance, Risk & Compliance', sama: ['3.1.1'], nca: ['1-2'], ia: ['3.1.1'], auto: null, assessment: null, result: res, why: 'w', conflict: false }, o);
const VIEW = (fw) => ({ fw, name: { sama: 'SAMA Cyber Security Framework', nca: 'NCA Essential Cybersecurity Controls (ECC-2:2024)', ia: 'Insurance Authority (IA) - SAMA CSF baseline' }[fw], basis: fw === 'ia' ? 'Circular UTC/277/202401 basis.' : null, generated_at: new Date().toISOString(), note: 'domain-level mapping.',
  compliance_pct: 25, assessed_pct: 50, counts: { compliant: 1, partial: 0, non_compliant: 1, not_applicable: 0, auto_pass: 1, not_assessed: 1 },
  domains: [{ code: fw === 'nca' ? '1-2' : '3.1.1', name: 'Governance SYN', checks: ['AC-01', 'AC-02'], result: 'not_assessed' }, { code: fw === 'nca' ? '2-3' : '3.3.7', name: 'Change SYN', checks: ['AC-28', 'AC-29'], result: 'non_compliant' }].concat(fw === 'ia' ? [{ code: 'IA-277', name: 'Mailbox', checks: ['AC-56'], result: 'not_assessed' }] : []),
  checks: [ck('AC-01', '<img src=x onerror=alert(1)> committee', 'compliant', { assessment: { status: 'compliant', evidence: '=HYPERLINK("x")', note: '', by: 'aud.syn', role: 'operator', at: new Date().toISOString(), expired: false } }), ck('AC-02', 'Independent function', 'not_assessed'),
    ck('AC-28', 'Four-eyes changes', 'non_compliant', { conflict: true, auto: { state: 'fail', tests: [{ id: 'IT-02', title: 'Approvals by a different person', state: 'fail', detail: '1 finding' }] }, assessment: { status: 'compliant', evidence: 'CAB', by: 'aud.syn', role: 'operator', at: new Date().toISOString() } }),
    ck('AC-29', 'Patches', 'auto_pass', { auto: { state: 'pass', tests: [{ id: 'IT-06', state: 'pass', detail: 'ok' }] } }), ck('AC-56', 'Contact mailbox', 'not_assessed', { ia: ['IA-277'] })] });
(async () => {
  const srv = http.createServer((req, res) => {
    const u = decodeURIComponent(req.url.split('?')[0]), q = new URLSearchParams(req.url.split('?')[1] || ''), json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u === '/dashboards/whoami.json' || u === '/auth/whoami') return json(200, { user: 'syed', role: 'admin' });
    if (u === '/api/itam/audit-programme') return json(200, { departments: {}, note: 'n', auditors: [{ id: 'itaudit', name: 'AI IT Auditor', about: 'a', counts: { pass: 0, fail: 0, not_tested: 0, not_run: 1 }, tests: [] }, { id: 'cyberaudit', name: 'AI Cyber Security Auditor', about: 'b', counts: { pass: 0, fail: 0, not_tested: 0, not_run: 1 }, tests: [] }] });
    if (u === '/api/itam/audit-checklist') return json(200, VIEW(q.get('fw') || 'sama'));
    if (u === '/api/itam/audit-checklist/assess') { let b = ''; req.on('data', (c) => { b += c; }); req.on('end', () => { POSTS.push(JSON.parse(b)); REFUSE ? json(400, { error: 'evidence is required for a compliant or partially compliant result' }) : json(200, Object.assign(ck('AC-02', 'x', 'partial'), { id: 'AC-02' })); }); return; }
    if (u.startsWith('/api/')) return json(404, { error: 'not in this test' });
    const f = path.join(DASH, u.replace(/^\/dashboards\//, '')); if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (e, d) => { if (e) { res.writeHead(404); return res.end(); } res.writeHead(200, { 'Content-Type': f.endsWith('.js') ? 'application/javascript' : f.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port;
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright'); const browser = await chromium.launch();
  try {
    const ctx = await browser.newContext({ acceptDownloads: true }); const p = await ctx.newPage(); const errs = []; let dialogs = 0; p.on('pageerror', (e) => errs.push(e.message)); p.on('dialog', (d) => { dialogs++; d.dismiss(); });
    await p.goto(base + '/dashboards/ai-auditors.html?standalone=1'); await p.waitForTimeout(600);
    await p.click('#tabs [data-tab="checklist"]'); await p.waitForSelector('.cl-dom');
    ok(await p.$eval('#auview', (e) => e.hidden) && !(await p.$eval('#clview', (e) => e.hidden)), 'checklist tab shows the checklist and hides the programme');
    const k = await p.$eval('#clkpis', (e) => e.textContent.replace(/\s+/g, ' '));
    ok(/25%/.test(k) && /non-compliant/.test(k) && /automated pass/.test(k) && /not assessed/.test(k), 'KPIs: ' + k);
    const d = await p.$$eval('.cl-dom', (a) => a.map((x) => ({ t: x.querySelector('summary').innerText.replace(/\s+/g, ' '), open: x.open })));
    ok(d.length === 2 && /3.1.1/.test(d[0].t) && /Not assessed/.test(d[0].t) && /Non-compliant/.test(d[1].t) && d[1].open && !d[0].open, 'domains with worst result, non-compliant opened: ' + JSON.stringify(d));
    ok(await p.$$eval('#cldoms img', (a) => a.length) === 0 && /<img src=x/.test(await p.$eval('#cldoms', (e) => e.textContent)), 'check titles escaped');
    ok(/conflicts with the AI test/.test(await p.$eval('#cldoms', (e) => e.textContent)), 'conflict shown in the row');
    await p.selectOption('#clfilter', 'auto_pass'); const fl = await p.$$eval('[data-check]', (a) => a.map((x) => x.getAttribute('data-check')));
    ok(fl.length === 1 && fl[0] === 'AC-29', 'filter: automated pass only: ' + fl); await p.selectOption('#clfilter', '');
    await p.click('#clkpis [data-clf="auto_pass"]'); const tf = await p.$$eval('[data-check]', (a) => a.map((x) => x.getAttribute('data-check')));
    ok(tf.length === 1 && tf[0] === 'AC-29' && (await p.inputValue('#clfilter')) === 'auto_pass' && (await p.getAttribute('#clkpis [data-clf="auto_pass"]', 'aria-pressed')) === 'true', 'clicking a tile filters to it: ' + tf);
    await p.click('#clkpis [data-clf="auto_pass"]'); ok((await p.inputValue('#clfilter')) === '' && (await p.$$('[data-check]')).length > 1, 'clicking it again shows all');
    await p.click('#clkpis [data-clf="non_compliant"]'); ok((await p.inputValue('#clfilter')) === 'non_compliant', 'the non-compliant tile filters too'); await p.selectOption('#clfilter', '');
    await p.click('#clfw [data-fw="ia"]'); await p.waitForFunction(() => /IA-277/.test(document.getElementById('cldoms').innerText));
    ok(/UTC\/277/.test(await p.$eval('#clbasis', (e) => e.innerText)), 'IA checklist with its basis and IA-277');
    await p.click('#clfw [data-fw="nca"]'); await p.waitForFunction(() => /1-2/.test(document.getElementById('cldoms').innerText));
    ok(/NCA Essential/.test(await p.$eval('#clbasis', (e) => e.innerText)), 'NCA checklist loads');
    // drawer + assessment
    await p.$$eval('.cl-dom', (a) => a.forEach((x) => { x.open = true; })); await p.click('[data-check="AC-02"]'); await p.waitForSelector('#clform');
    const dr = await p.evaluate(() => document.getElementById('clform').closest('section,aside,div').parentElement.innerText);
    ok(/Inspect the SYN records/.test(dr) && /SYN evidence/.test(dr) && /No automated test/.test(dr), 'drawer: procedure, evidence expected, manual check');
    REFUSE = true; await p.selectOption('#clform select[name=status]', 'compliant'); await p.click('#clform button[type=submit]'); await p.waitForTimeout(400);
    ok(/evidence is required/.test(await p.$eval('#clmsg', (e) => e.textContent)), 'server refusal shown in the form');
    REFUSE = false; await p.selectOption('#clform select[name=status]', 'partial'); await p.fill('#clform input[name=evidence]', 'charter v2'); await p.fill('#clform textarea[name=note]', '3 of 4 meetings'); await p.click('#clform button[type=submit]'); await p.waitForTimeout(500);
    const last = POSTS[POSTS.length - 1];
    ok(last.id === 'AC-02' && last.status === 'partial' && last.evidence === 'charter v2' && last.note === '3 of 4 meetings', 'assessment posted: ' + JSON.stringify(last));
    await p.keyboard.press('Escape');
    await p.$$eval('.cl-dom', (a) => a.forEach((x) => { x.open = true; })); await p.click('[data-check="AC-28"]'); await p.waitForTimeout(300);
    ok(/stays non-compliant until the test passes/.test(await p.evaluate(() => document.body.innerText)), 'conflict explained in the drawer'); await p.keyboard.press('Escape');
    // CSV + print
    const [dl] = await Promise.all([p.waitForEvent('download'), p.click('#clcsv')]); const csv = fs.readFileSync(await dl.path(), 'utf8');
    ok(/audit-checklist-nca-/.test(dl.suggestedFilename()) && /AC-28/.test(csv) && /"'=HYPERLINK/.test(csv), 'CSV with every check, formula-safe');
    await p.click('#clprint'); const rp = await p.$eval('#rep', (e) => e.innerText);
    ok(/Audit checklist — NCA/.test(rp) && /Sign-off/.test(rp) && /Reviewed by/.test(rp) && await p.$eval('#repwhich', (e) => e.hidden), 'printable checklist with sign-off');
    ok(!errs.length && !dialogs, 'no page errors, no injected script: ' + errs.join(' | '));
  } finally { await browser.close(); srv.close(); }
  console.log(bad ? 'FAILED ' + bad + '/' + n + ' checks' : 'OK ' + n + '/' + n + ' checks'); process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
