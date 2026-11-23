// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// RoPA by Department (pdpl-ropa-collect.html), stubbed ITAM, SYNTHETIC data: KPIs and department cards (late, waiting,
// approved), department workspace with issues, DPO comments, suggestions from templates / Data Catalog systems / the register,
// questionnaire posts the right fields (template, system, linked record), submit, DPO review, open a campaign, register CSV,
// AI help (proposals escaped, applied only when ticked, saved only by Save), a steward's view (no manage controls), escaping,
// empty state that says what to do.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node pdpl-ropa-collect.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const DASH = path.resolve(__dirname, '../../ui');
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const POSTS = []; let STEWARD = false, NONE = false, SUBMITTED = false, AI_OFF = false;
const XSS = '<img src=x onerror=alert(1)>';
const TPL = { key: 'cl_motor', name: 'Motor claims handling', purpose: 'Register, assess and settle motor claims', legal_basis: 'contract', data_categories: ['identity', 'contact', 'financial', 'location'], subjects: 'Claimants', recipients: 'Surveyors, Najm', flags: [], hint: '' };
const VIEW = () => ({ campaign: { id: 'RC-001', name: 'RoPA 2026 (synthetic)', due: '2026-11-30', status: 'open' }, can_manage: !STEWARD, me: STEWARD ? 'faisal.syn' : 'huda.syn',
  totals: { departments: 2, approved: 0, submitted: SUBMITTED ? 1 : 0, late: 1, activities: 1, gaps: 2, progress: 40 },
  departments: [{ department: 'Claims', steward: 'faisal.syn', status: SUBMITTED ? 'submitted' : 'returned', late: false, progress: 80, gaps: 2, can_submit: false, submitted_by: SUBMITTED ? 'faisal.syn' : null,
      comments: [{ at: '2026-10-20T08:00:00Z', by: 'huda.syn', decision: 'return', text: 'Add identity ' + XSS }],
      drafts: [{ id: 'RD-0001', name: 'Medical claims processing', complete: 80, gaps: 2, template: 'cl_medical', ropa_id: null, issues: [{ level: 'gap', field: 'retention_months', text: 'Retention period missing (Implementing Regulation Art. 33)' }, { level: 'warn', field: 'dpia', text: 'Needs an impact assessment (health)' }],
        fields: { name: 'Medical claims processing', purpose: 'Pay claims', legal_basis: 'contract', data_categories: ['health'], systems: ['CLAIMS-SQL'] } }],
      suggest_templates: [TPL], suggest_systems: [{ system: 'CLAIMS-ORA', categories: ['health', 'identity'] }], existing_records: [{ id: 'PD-ROPA-007', name: 'Recoveries', version: 2, purpose: 'Recover costs', legal_basis: 'legitimate_interest', data_categories: ['identity'] }] },
    { department: 'Human Resources', steward: null, status: 'not_started', late: true, progress: 0, gaps: 0, drafts: [], comments: [], suggest_templates: [], suggest_systems: [], existing_records: [], can_submit: false }] });
(async () => {
  const srv = http.createServer((req, res) => {
    const u = decodeURIComponent(req.url.split('?')[0]), json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    const body = (fn) => { let b = ''; req.on('data', (c) => { b += c; }); req.on('end', () => { const j = JSON.parse(b || '{}'); POSTS.push([u, j]); fn(j); }); };
    if (u === '/dashboards/whoami.json' || u === '/auth/whoami') return json(200, { user: 'huda.syn', role: STEWARD ? 'viewer' : 'operator' });
    if (u === '/api/itam/pdpl/ropa/campaigns' && req.method === 'GET') return json(200, NONE ? { campaigns: [], can_manage: !STEWARD } : { campaigns: [{ id: 'RC-001', name: 'RoPA 2026 (synthetic)', status: 'open', due: '2026-11-30' }], can_manage: !STEWARD });
    if (u === '/api/itam/pdpl/ropa/campaigns') return body((b) => json(200, { id: 'RC-002', name: b.name }));
    if (u === '/api/itam/pdpl/ropa/campaigns/RC-001') return json(200, VIEW());
    if (u === '/api/itam/pdpl/ropa-flow/RC-001') return json(200, { ml: { ok: true, totals: { at_risk: 1, dpia_required: 1, duplicates: 1, retention: 1, proposed_drafts: 1 },
      forecast: { Claims: { verdict: 'at risk', text: 'at 4.0% a day it finishes 3 day(s) after the due date' }, 'Human Resources': { verdict: 'late', text: 'no activity yet and the due date has passed' } },
      risk: { 'RD-0001': { score: 45, level: 'medium', why: ['sensitive data (health)'], dpia_required: true } },
      duplicates: [{ a: { department: 'Claims', name: 'Medical claims processing' }, b: { department: 'Finance', name: 'Claims payments ' + XSS }, score: 0.8 }],
      retention: [{ department: 'Claims', name: 'Medical claims processing', text: '240 months against a usual 60 for the same data' }],
      autodraft: { Claims: [{ system: 'CLAIMS-DW', categories: ['health', 'identity'], template: 'cl_medical', text: 'closest template: Medical claims (62%)' }] } },
      settings: STEWARD ? undefined : { reminders: true, before_days: [7, 3, 1], late_every_days: 2, dpo_email: '' }, reminders: [{ at: Date.now(), department: 'Claims', why: '3 day(s) to the due date', status: 'sent' }] });
    if (u === '/api/itam/pdpl/ropa-flow/RC-001/accept') return body((b) => json(200, { created: b.items.length, drafts: [] }));
    if (u === '/api/itam/pdpl/ropa-flow/RC-001/settings') return body((b) => json(200, b));
    if (u === '/api/itam/pdpl/ropa-flow/RC-001/remind-now') return body(() => json(200, { sent: 2 }));
    if (u === '/api/itam/pdpl/ropa/templates') return json(200, { departments: [{ key: 'claims', name: 'Claims', activities: [TPL] }, { key: 'hr', name: 'Human Resources', activities: [] }] });
    if (u === '/api/itam/pdpl/ropa/drafts') return body(() => json(200, { id: 'RD-0002' }));
    if (u === '/api/itam/pdpl/ropa/campaigns/RC-001/submit') return body(() => json(200, { status: 'submitted' }));
    if (u === '/api/itam/pdpl/ropa/campaigns/RC-001/review') return body((b) => json(200, { status: b.decision === 'approve' ? 'approved' : 'returned', register: [{ ropa_id: 'PD-ROPA-008' }] }));
    if (u === '/api/itam/pdpl/ropa/assist') return body(() => json(200, AI_OFF ? { available: false, message: 'No Anthropic API key is stored on the server (synthetic).' } : { available: true, ok: true, note: 'AI suggestion - verify every value. Nothing is saved until you save the questionnaire.',
      summary: 'Medical claims hold health data ' + XSS, questions: ['How long are closed files kept? ' + XSS], dropped: [{ field: 'lia_done', why: 'a person attests the balancing test' }],
      suggestions: [{ field: 'purpose', value: 'Assess and pay medical claims (synthetic)', why: 'from the template' }, { field: 'data_categories', value: ['identity', 'health'], why: 'found in CLAIMS-SQL' },
        { field: 'retention_months', value: 120, why: XSS }, { field: 'fraud_scoring', value: true, why: 'claims are scored' }, { field: 'subjects', value: 'Should not be applied', why: 'unticked by the steward' }] }));
    if (u === '/api/itam/pdpl/ropa/register') return json(200, { columns: ['Id', 'Activity'], rows: [['PD-ROPA-008', '=cmd']] });
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
    await p.goto(base + '/dashboards/pdpl-ropa-collect.html?standalone=1'); await p.waitForSelector('[data-dept="Claims"]');
    const all = await p.$eval('main', (e) => e.innerText);
    ok(/40%/.test(all) && /Late \(due 2026-11-30\)/i.test(all) && /steward: none named/.test(all) && /1 system\(s\) with personal data not yet described/.test(all), 'KPIs and department cards');
    ok(!(await p.$eval('#newc', (e) => e.hidden)) && !(await p.$eval('#reg', (e) => e.hidden)), 'manage controls for an operator');
    // workflow automation (ML): panel, forecast chips, risk + DPIA, proposed drafts accepted, reminder settings
    await p.waitForFunction(() => /departments at risk or late/i.test((document.getElementById('flowb') || {}).innerText || ''));   // tile labels are upper-cased by CSS
    const fl = await p.$eval('#flowb', (e) => e.innerText);
    ok(/Medical claims processing/.test(fl) && /80% alike/.test(fl) && /240 months against a usual 60/.test(fl), 'duplicates and retention outliers');
    ok(fl.includes('<img src=x') && !(await p.$('#flowb img')), 'a hostile activity name stays text');
    ok(/at risk/.test(await p.$eval('[data-dept="Claims"]', (e) => e.innerText)) && /1 proposed draft/.test(await p.$eval('[data-dept="Claims"]', (e) => e.innerText)), 'forecast and proposals on the department card');
    await p.fill('#rfset [name="before_days"]', '5, 2'); await p.click('#rfset button[type="submit"]');
    await p.waitForFunction(() => /Reminder settings saved/.test(document.body.innerText));
    let fx = last('/ropa-flow/RC-001/settings'); ok(fx && fx[1].before_days.join() === '5,2' && fx[1].reminders === true, 'reminder settings posted');
    await p.click('#rfnow'); await p.waitForFunction(() => /2 reminder\(s\) sent/.test(document.body.innerText)); ok(true, 'send reminders now');
    await p.click('[data-dept="Claims"]'); await p.waitForSelector('#acceptp');
    ok(/DPIA required/.test(await p.$eval('#zd-b', (e) => e.innerText)) && /sensitive data \(health\)/.test(await p.$eval('#zd-b', (e) => e.innerText)), 'risk and DPIA on the activity');
    await p.click('#acceptp'); await p.waitForFunction(() => /1 draft\(s\) created/.test(document.body.innerText));
    fx = last('/ropa-flow/RC-001/accept'); ok(fx && fx[1].department === 'Claims' && fx[1].items[0].system === 'CLAIMS-DW' && fx[1].items[0].template === 'cl_medical', 'proposed draft accepted');
    await p.reload(); await p.waitForSelector('[data-dept="Claims"]');
    await p.click('[data-dept="Claims"]'); await p.waitForSelector('[data-fromtpl]');
    const ws = await p.$eval('#zd-b', (e) => e.innerText);
    ok(/Retention period missing/.test(ws) && /Needs an impact assessment/.test(ws) && /CLAIMS-ORA/.test(ws) && /PD-ROPA-007 v2/.test(ws) && /Motor claims handling/.test(ws), 'workspace: issues and the three kinds of suggestion');
    ok(await p.$$eval('#zd-b img', (a) => a.length) === 0, 'DPO comment escaped');
    // from a template
    await p.click('[data-fromtpl="0"]'); await p.waitForSelector('#dform');
    ok(await p.$eval('#dform-name', (e) => e.value) === 'Motor claims handling' && await p.$eval('#dform input[name=data_categories][value=location]', (e) => e.checked), 'template prefills the questionnaire');
    await p.fill('#dform-retention_months', '84'); await p.fill('#dform-security_measures', 'Tiered access'); await p.click('#dform button[type=submit]'); await p.waitForTimeout(400);
    let x = last('/ropa/drafts'); ok(x && x[1].template === 'cl_motor' && x[1].department === 'Claims' && x[1].campaign === 'RC-001' && x[1].retention_months === 84 && x[1].recipients.join() === 'Surveyors,Najm' && x[1].security_measures === 'Tiered access', 'template draft posted: ' + JSON.stringify(x && x[1]));
    // from a Data Catalog system and from the register
    await p.waitForSelector('[data-fromsys]'); await p.click('[data-fromsys="0"]'); await p.waitForSelector('#dform');
    await p.click('#dform button[type=submit]'); await p.waitForTimeout(300);
    x = last('/ropa/drafts'); ok(x && x[1].systems.join() === 'CLAIMS-ORA' && x[1].data_categories.slice().sort().join() === 'health,identity', 'system draft posted');
    await p.waitForSelector('[data-fromrec]'); await p.click('[data-fromrec="0"]'); await p.waitForSelector('#dform'); await p.click('#dform button[type=submit]'); await p.waitForTimeout(300);
    x = last('/ropa/drafts'); ok(x && x[1].ropa_id === 'PD-ROPA-007' && x[1].name === 'Recoveries' && !x[1].id, 'review of a register record posted');
    // edit an existing draft keeps its id
    await p.waitForSelector('[data-edit]'); await p.click('[data-edit="RD-0001"]'); await p.waitForSelector('#dform'); await p.click('#dform button[type=submit]'); await p.waitForTimeout(300);
    x = last('/ropa/drafts'); ok(x && x[1].id === 'RD-0001' && x[1].template === 'cl_medical', 'edit keeps the draft id');
    // AI help: asks with the form's fields + question, shows proposals escaped, applies only the ticked ones, nothing saved until Save
    await p.waitForSelector('[data-edit]'); await p.click('[data-edit="RD-0001"]'); await p.waitForSelector('#aiask');
    const nPosts = POSTS.filter((y) => y[0].endsWith('/ropa/drafts')).length;
    await p.fill('#aiq', 'Which legal basis fits?'); await p.click('#aiask'); await p.waitForSelector('#aiapply');
    x = last('/ropa/assist'); ok(x && x[1].question === 'Which legal basis fits?' && x[1].department === 'Claims' && x[1].template === 'cl_medical' && x[1].name === 'Medical claims processing' && x[1].systems.join() === 'CLAIMS-SQL', 'assist posted the form: ' + JSON.stringify(x && x[1]));
    const aio = await p.$eval('#aiout', (e) => e.innerText);
    ok(/AI suggestion - verify/i.test(aio) && /Questions only your department can answer/i.test(aio) && /1 proposal\(s\) removed/.test(aio) && /Kept for \(months\): 120/.test(aio), 'AI panel: badge, proposals, questions, removed count');
    ok(await p.$$eval('#zd-b img', (a) => a.length) === 0, 'AI text escaped');
    ok(POSTS.filter((y) => y[0].endsWith('/ropa/drafts')).length === nPosts, 'asking saves nothing');
    await p.uncheck('[data-aisel="4"]'); await p.click('#aiapply');
    ok(await p.$eval('#dform-purpose', (e) => e.value) === 'Assess and pay medical claims (synthetic)' && await p.$eval('#dform-retention_months', (e) => e.value) === '120' && await p.$eval('#dform input[name=data_categories][value=identity]', (e) => e.checked)
      && await p.$eval('#dform input[name=fraud_scoring]', (e) => e.checked) && await p.$eval('#dform-subjects', (e) => e.value) !== 'Should not be applied', 'ticked proposals applied, the unticked one not');
    await p.click('#dform button[type=submit]'); await p.waitForTimeout(300);
    x = last('/ropa/drafts'); ok(x && x[1].id === 'RD-0001' && x[1].retention_months === 120 && x[1].fraud_scoring === true && x[1].data_categories.slice().sort().join() === 'health,identity', 'the steward saves what was applied');
    AI_OFF = true; await p.waitForSelector('[data-edit]'); await p.click('[data-edit="RD-0001"]'); await p.waitForSelector('#aiask'); await p.click('#aiask');
    await p.waitForFunction(() => /No Anthropic API key/.test(document.getElementById('aiout').innerText)); ok(true, 'AI not configured: says so'); AI_OFF = false;
    // submitted: the DPO reviews
    SUBMITTED = true; await p.reload(); await p.waitForSelector('[data-dept="Claims"]');
    await p.click('[data-dept="Claims"]'); await p.waitForSelector('#rvform');
    ok(await p.$$eval('[data-fromtpl]', (a) => a.length) === 0, 'a submitted department is locked');
    await p.selectOption('#rvform-decision', 'approve'); await p.click('#rvform button[type=submit]'); await p.waitForTimeout(300);
    x = last('/review'); ok(x && x[1].decision === 'approve' && x[1].department === 'Claims', 'review posted');
    // open a campaign
    await p.reload(); await p.waitForSelector('[data-dept="Claims"]'); await p.click('#newc'); await p.waitForSelector('#cform'); await p.fill('#cform-due', '2027-01-31'); await p.fill('#cform-more', 'Corporate Strategy'); await p.click('#cform button[type=submit]'); await p.waitForTimeout(400);
    x = last('/ropa/campaigns'); ok(x && x[1].departments.includes('Claims') && x[1].departments.includes('Corporate Strategy') && x[1].due === '2027-01-31', 'campaign opened: ' + JSON.stringify(x && x[1]));
    // register CSV (formula-safe)
    await p.reload(); await p.waitForSelector('[data-dept="Claims"]');
    const [dl] = await Promise.all([p.waitForEvent('download'), p.click('#reg')]);
    const csv = fs.readFileSync(await dl.path(), 'utf8'); ok(/"'=cmd"/.test(csv) && /PD-ROPA-008/.test(csv), 'register CSV, formula-safe');
    // a steward
    STEWARD = true; SUBMITTED = false; const p2 = await browser.newPage(); p2.on('pageerror', (e) => errs.push(e.message));
    await p2.goto(base + '/dashboards/pdpl-ropa-collect.html?standalone=1'); await p2.waitForSelector('[data-dept="Claims"]');
    ok(await p2.$eval('#newc', (e) => e.hidden) && await p2.$eval('#reg', (e) => e.hidden), 'a steward sees no manage controls');
    await p2.waitForFunction(() => /departments at risk or late/i.test(document.body.innerText)); ok(!(await p2.$('#rfset')), 'a steward does not see the reminder settings');
    NONE = true; const p3 = await browser.newPage(); p3.on('pageerror', (e) => errs.push(e.message));
    await p3.goto(base + '/dashboards/pdpl-ropa-collect.html?standalone=1'); await p3.waitForFunction(() => /data steward on the Programme page/.test(document.body.innerText));
    ok(true, 'empty state tells a steward what to do');
    ok(!errs.length, 'no page errors: ' + errs.join(' | ')); ok(!dialogs, 'no browser dialogs');
  } finally { await browser.close(); srv.close(); }
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks'); process.exit(bad ? 1 : 0);
})();
