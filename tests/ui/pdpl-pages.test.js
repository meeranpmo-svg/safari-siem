// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// The PDPL menu pages (pdpl-*.html, vendor/zyb-pdpl.js), stubbed ITAM, SYNTHETIC data: the strip linking the pages, the menu
// area, Records of Processing (filter, edit, CSV export with formula guard), Sensitive Data Controls (checklist saved),
// Data Subject Requests (record, verify, task, extend, answer, letter in Arabic / English), DPIA (assess, sign), Transfers
// (impact assessment scored, DPO sign, refusal shown), Breach (playbook step), Processors (due diligence, sub-processor
// proposed and approved), Programme (obligations, penalties, steward, maturity). Escaping and the operator-only message.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node pdpl-pages.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const DASH = path.resolve(__dirname, '../../ui');
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const POSTS = []; let DENY = false;
const XSS = '<img src=x onerror=alert(1)>';
const ROPA = { total: 2, complete: 1, note: 'Implementing Regulation Art. 33', export_columns: ['Id', 'Activity'], export_rows: [['PD-ROPA-001', '=HYPERLINK("x")'], ['PD-ROPA-002', 'Marketing']],
  activities: [{ id: 'PD-ROPA-002', name: XSS + ' Marketing list', owner: null, legal_basis: null, data_categories: [], systems: [], completeness: 11, missing: ['Purpose', 'Legal basis'], reviewed: null, review_due: true, dpia: 'not needed', dpia_needed_for: [], transfers: [], retention_rule: [], consent_purposes: [], sensitive: [], sensitive_controls: null, steward: null },
    { id: 'PD-ROPA-001', name: 'Medical claims', owner: 'Claims', legal_basis: 'contract', data_categories: ['identity', 'health'], systems: ['CLAIMS-DB', 'CRM'], completeness: 100, missing: [], reviewed: '2026-06-01', review_due: false, dpia: 'missing', dpia_needed_for: ['sensitive data (health)'], transfers: [], retention_rule: ['PD-RETENTION-001'], consent_purposes: [], sensitive: ['health'], sensitive_controls: false, steward: 'omar.syn' }] };
const SENS = { note: 'n', findings: [{ key: 'sens:PD-ROPA-001', severity: 'high', title: '"Medical claims" (health): 6 control(s) missing', requirement: 'P-14' }],
  activities: [{ id: 'PD-ROPA-001', name: 'Medical claims', owner: 'Claims', sensitive: ['health'], recorded: false, gaps: 2, access_tiers: [], evidence: '', controls: [{ control: 'lawful_basis', label: 'Explicit consent', ok: true }, { control: 'health_chi', label: 'CHI controls', ok: false }, { control: 'dpia', label: 'Impact assessment', ok: false }] }] };
const DSAR = { open: 1, overdue: 0, due_7d: 0, note: 'Only a reference is kept here', refusal_grounds: { legal: 'another law requires the data to be kept or not disclosed', repetitive: 'repeats' }, types: {},
  requests: [{ id: 'PD-DSR-001', ref: 'REQ-1', type: 'access', channel: 'branch', received: '2026-10-01', stage: 'received', assigned_to: 'nora.syn', due: '2026-10-31', days_left: 10, overdue: false, extended: false, identity_verified: false, identity_method: null, tasks: [{ system: 'CRM', status: 'open', note: '' }], blockers: ['identity not verified', 'open in: CRM'], can_respond: false, outcome: null }] };
const DPIA = { missing: 1, outdated: 0, note: 'Art. 22', activities: [{ id: 'PD-ROPA-001', name: 'Medical claims', needed_for: ['sensitive data (health)'], state: 'draft', outdated: false, latest: 'PD-DPIA-001', residual: 'medium', outcome: 'mitigations' }] };
const Q = { questions: [{ id: 'sensitive', question: 'Sensitive data?', options: ['no', 'yes'] }], measures: [{ id: 'encryption', measure: 'Encryption', reduces: 2 }] };
const TRANS = { note: 'Art. 29', purposes: [], questions: [{ id: 'purpose', question: 'Permitted purpose', options: ['central_operations', 'none of these'] }, { id: 'sensitive', question: 'Sensitive?', options: ['no', 'yes'] }],
  transfers: [{ id: 'PD-TRANSFER-001', name: 'Reinsurer', country: 'Germany', basis: 'scc', sensitive: true, large_scale: false, tia: { level: 'medium', outcome: 'proceed_with_measures', prepared_by: 'nora.syn', signed_by: null }, gaps: ['impact assessment not signed'] }] };
const BRE = { open: 1, playbook: [], breaches: [{ id: 'PD-BREACH-001', ref: 'BR-1', aware_at: '2026-10-19T08:00Z', deadline: '2026-10-22T08:00:00Z', hours_left: 20, late: false, closed: false, next: 'Contain: stop the leak', subjects_count: null, categories: [], description: XSS,
  steps: [{ step: 'contain', label: 'Contain: stop the leak', done: false }, { step: 'assess', label: 'Assess', done: false }, { step: 'notify_sdaia', label: 'Notify SDAIA within 72 hours', done: false }] }] };
const PROC = { note: 'Art. 8', findings: [], checks: [{ key: 'iso27001', label: 'ISO 27001', weight: 2 }, { key: 'breach_24h', label: 'Breach in 24 h', weight: 2 }],
  processors: [{ id: 'PD-PROCESSOR-001', name: 'TPA', service: 'claims admin', outside_ksa: false, agreement: '2026-01-01', clauses: ['purpose'], score: 17, checks: [{ key: 'iso27001', label: 'ISO 27001', ok: true }, { key: 'breach_24h', label: 'Breach in 24 h', ok: false }], assessed: '2026-10-20', review_due: false,
    subprocessors: [{ n: 1, name: 'Cloud host', country: 'KSA', status: 'pending', proposed_by: 'huda.syn' }], pending_subprocessors: 1 }] };
let POLDRAFT = false;
const POL = () => ({ total: 2, counts: { approved: 0, in_review: 0, draft: POLDRAFT ? 1 : 0, missing: POLDRAFT ? 1 : 2 }, note: 'an outline, not policy text',
  policies: [{ id: 'PP-05', title: 'Data Subject Rights Procedure', ref: 'PDPL Art. 4', page: 'pdpl-dsar.html', state: POLDRAFT ? 'draft' : 'missing', doc: POLDRAFT ? 'DRAFT-0001' : null, in_practice: '1 requests recorded', covers: ['Answer within 30 days', XSS], can_draft: !POLDRAFT, review_overdue: false },
    { id: 'PP-07', title: 'Data Breach Notification Policy', ref: 'PDPL Art. 20', page: 'pdpl-breach.html', state: 'missing', doc: null, in_practice: '0 breaches recorded', covers: ['SDAIA within 72 hours'], can_draft: true, review_overdue: false }] });
const GOV = { note: 'n', dpo: { user: 'huda.syn', reports_to: null, can_stop: false, appointed: '2026-01-01', ok: false },
  functions: [{ function: 'requests', label: 'Data subject requests', user: null }, { function: 'sdaia', label: 'SDAIA liaison and documentation', user: 'huda.syn', deputy: null }], functions_gap: ['Data subject requests'],
  committee: { meetings: [], last: null, overdue: true, missing_departments: ['legal', 'it', 'hr', 'operations'], required: [] },
  pbd: [{ id: 'PD-PBD_REVIEW-001', name: XSS + ' Claims app', type: 'new_system', go_live: '2026-12-01', state: 'submitted', requested_by: 'nora.syn', dpia_required: true, required: ['an impact assessment signed before go-live'], late: false }],
  pbd_questions: [{ id: 'personal', question: 'Personal data?', options: ['no', 'yes'] }, { id: 'sensitive', question: 'Sensitive?', options: ['no', 'yes'] }],
  reviews: [], review_checks: [{ id: 'followed', label: 'Processes followed' }, { id: 'changes', label: 'Changes' }], review_overdue: true,
  actions: [{ review: 'PD-PROGRAMME_REVIEW-001', n: 1, action: 'add portal to RoPA', owner: 'omar.syn', due: '2026-10-01', status: 'open', overdue: true }], open_actions: 1, overdue_actions: 1, untrained_departments: [] };
const PROG = { note: 'fully enforceable since 14 September 2024', penalties: { fine: 'warning, or a fine up to SAR 5,000,000', criminal: 'up to 2 years in prison', note: 'for the DPO to verify' },
  obligations: [{ id: 'register', obligation: 'Registered on SDAIA\'s national register of controllers', state: 'gap', evidence: 'profile', penalty: 'warning, or a fine up to SAR 5,000,000', criminal: false },
    { id: 'sensitive', obligation: 'Sensitive data never disclosed except as the law allows', state: 'confirm', evidence: 'Sensitive Data Controls', penalty: 'up to 2 years in prison', criminal: true }],
  departments: [{ department: 'claims', activities: ['PD-ROPA-001'], stewards: [], playbooks: [], gap: true }], maturity: null, history: [],
  questions: { mapping: { name: 'Data mapping & ownership', questions: [{ id: 'mapping.map', question: 'Every system is mapped' }] }, audit: { name: 'Documentation & audit readiness', questions: [{ id: 'audit.retrieve', question: 'Retrieve and delete within 72 hours' }] } },
  measured: { ropa_complete_pct: 50, activities_with_steward_pct: 0, consent_purposes_live: 0, dsr_on_time_pct: null, requirements_confirmed_pct: 4 }, training: [], roles: { legal: 'Interprets PDPL' } };
(async () => {
  const srv = http.createServer((req, res) => {
    const u = decodeURIComponent(req.url.split('?')[0]), q = new URLSearchParams(req.url.split('?')[1] || ''), json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    const body = (fn) => { let b = ''; req.on('data', (c) => { b += c; }); req.on('end', () => { const j = JSON.parse(b || '{}'); POSTS.push([u, j]); fn(j); }); };
    if (u === '/dashboards/whoami.json' || u === '/auth/whoami') return json(200, { user: 'syed', role: 'admin' });
    if (u.startsWith('/api/itam/pdpl') && DENY) return json(403, { error: 'requires operator' });
    const G = { '/api/itam/pdpl/ropa': ROPA, '/api/itam/pdpl/ropa/export': { columns: ROPA.export_columns, rows: ROPA.export_rows, generated_at: '2026-10-20T08:00:00Z' }, '/api/itam/pdpl/sensitive': SENS, '/api/itam/pdpl/dsar': DSAR, '/api/itam/pdpl/dpia/view': DPIA, '/api/itam/pdpl/dpia/questions': Q,
      '/api/itam/pdpl/transfers': TRANS, '/api/itam/pdpl/breaches': BRE, '/api/itam/pdpl/processors': PROC, '/api/itam/pdpl/programme': PROG,
      '/api/itam/pdpl/dsar/PD-DSR-001/letter': { en: 'Reference: REQ-1 ' + XSS, ar: 'عزيزنا العميل', note: 'A draft' } };
    if (req.method === 'GET' && u === '/api/itam/pdpl/governance') return json(200, GOV);
    if (req.method === 'GET' && u === '/api/itam/pdpl/policies') return json(200, POL());
    if (req.method === 'GET' && G[u]) return json(200, G[u]);
    if (u === '/api/itam/pdpl/records' && req.method === 'GET') return json(200, { records: q.get('kind') === 'ropa' ? [{ id: 'PD-ROPA-001', kind: 'ropa', name: 'Medical claims', owner: 'Claims' }] : q.get('kind') === 'dpia' ? [{ id: 'PD-DPIA-001', kind: 'dpia', answers: { sensitive: 'yes' }, measures: ['encryption'] }] : [] });
    if (req.method === 'POST') return body((b) => {
      if (u === '/api/itam/pdpl/transfers/PD-TRANSFER-001/tia/sign') return json(403, { error: 'four-eyes: the DPO cannot sign an assessment they prepared' });
      if (u === '/api/itam/pdpl/transfers/PD-TRANSFER-001/tia') return json(200, { id: 'PD-TRANSFER-001', level: 'high', likelihood: 4, severity: 5, outcome: 'not_permitted', required: ['the transfer has no permitted purpose under Art. 29 - it must not happen'], why: ['purpose: none of these'], conditions: [{ id: 'purpose', ref: 'Art. 29(1)', label: 'A permitted purpose', state: 'not_met', why: 'no purpose listed' }, { id: 'security', ref: 'Art. 29(2)', label: 'No prejudice to national security', state: 'met', why: 'assessed' }, { id: 'adequacy', ref: 'Art. 29(2)', label: 'Adequate protection outside the Kingdom (SDAIA assessment)', state: 'safeguards', why: 'replaced by the appropriate safeguards (scc) ' + XSS }] });
      if (u === '/api/itam/pdpl/dpia/assess') return json(200, { id: 'PD-DPIA-001', outcome: 'mitigations', score: { level: 'medium', residual: 3, inherent: 5, why: ['sensitive: yes'] } });
      if (u === '/api/itam/pdpl/dpia/PD-DPIA-001/sign') return json(200, { id: 'PD-DPIA-001', approved_by: 'huda.syn' });
      if (/\/dsar\/PD-DSR-001\//.test(u) || u === '/api/itam/pdpl/dsar') return json(200, Object.assign({}, DSAR.requests[0], { stage: 'in_progress' }));
      if (u === '/api/itam/pdpl/processors/PD-PROCESSOR-001/assessment') return json(200, Object.assign({}, PROC.processors[0], { score: 50 }));
      if (u === '/api/itam/pdpl/policies/PP-05/draft') { POLDRAFT = true; return json(200, Object.assign(POL().policies[0], { state: 'draft', doc: 'DRAFT-0001' })); }
      if (u === '/api/itam/pdpl/pbd/PD-PBD_REVIEW-001/decide') return json(409, { error: 'an impact assessment is required: link the processing activity and have its DPIA signed first' });
      if (u === '/api/itam/pdpl/maturity') return json(200, { id: 'PD-MATURITY-001', score: { overall: 50, level: 'Defined' } });
      return json(200, Object.assign({ id: 'PD-X-001' }, PROC.processors[0], b, { id: 'PD-X-001' }));
    });
    if (u.startsWith('/api/')) return json(404, { error: 'not in this test' });
    const f = path.join(DASH, u.replace(/^\/dashboards\//, '')); if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (e, d) => { if (e) { res.writeHead(404); return res.end(); } res.writeHead(200, { 'Content-Type': f.endsWith('.js') ? 'application/javascript' : f.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port;
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright'); const browser = await chromium.launch();
  const last = (suffix) => POSTS.filter((x) => x[0].endsWith(suffix)).pop();
  try {
    const ctx = await browser.newContext({ acceptDownloads: true });
    const p = await ctx.newPage(); const errs = []; let dialogs = 0; p.on('pageerror', (e) => errs.push(e.message)); p.on('dialog', (d) => { dialogs++; d.accept('synthetic reason'); });
    const go = async (f) => { await p.goto(base + '/dashboards/' + f + '?standalone=1'); await p.waitForSelector('#kpis .card'); };
    const submit = async (sel) => { await p.click(sel + ' button[type=submit]'); await p.waitForTimeout(300); };

    // menu: one area holds the eight pages
    const nav = fs.readFileSync(path.join(DASH, 'vendor/zyb-nav.js'), 'utf8');
    { const w = { ZYB_ORG: Object.assign({}, require('../../brand/index'), { frameworks_all: true }) }; new Function('window', nav)(w); const area = (id) => w.ZYB_NAV.find((a) => a.id === id).pages.map((x) => x.h);
      ok(area('ai').includes('ai-pdpl.html') && !area('pdpl').includes('ai-pdpl.html'), 'AI PDPL Consultant sits in the AI section, apart from the PDPL menu'); }
    ok(['pdpl-programme', 'pdpl-governance', 'pdpl-policies', 'pdpl-ropa', 'pdpl-sensitive', 'pdpl-dsar', 'pdpl-dpia', 'pdpl-transfers', 'pdpl-breach', 'pdpl-processors'].every((x) => nav.includes('"h": "' + x + '.html"')), 'every page has a menu entry');

    // Records of processing
    await go('pdpl-ropa.html');
    ok(await p.$$eval('#pdplnav a.btn', (a) => a.length) === 17 && await p.$eval('#pdplnav a.btn-primary', (a) => a.getAttribute('href')) === 'pdpl-ropa.html', 'strip links the PDPL pages, this one highlighted');
    const src = await p.$$eval('[data-pdpl-source] a', (a) => a.map((x) => x.getAttribute('href') + '|' + x.getAttribute('rel')));
    ok(src.length === 2 && /PersonalDataProtectionLaw\.pdf\|noopener/.test(src[0]) && /ImplementingRegulation\.pdf\|noopener/.test(src[1]), 'the official SDAIA texts are named as the source: ' + src);
    ok(await p.$$eval('#list img', (a) => a.length) === 0, 'activity name escaped');
    let t = await p.$eval('#list', (e) => e.innerText);
    ok(/Medical claims/.test(t) && /missing/.test(t) && /omar\.syn/.test(t) && /no controls/.test(t), 'completeness, DPIA, steward, sensitive controls shown');
    await p.selectOption('#filter', 'dpia'); ok(await p.$$eval('#list tbody tr', (r) => r.length) === 1, 'filter: DPIA missing');
    await p.selectOption('#filter', '');
    await p.click('#list tr[data-id="PD-ROPA-001"]'); await p.waitForSelector('#rform');
    await p.fill('#rform-purpose', 'settle health claims'); await submit('#rform');
    let x = last('/pdpl/records'); ok(x && x[1].kind === 'ropa' && x[1].id === 'PD-ROPA-001' && x[1].purpose === 'settle health claims', 'edit saves the activity');
    const [dl] = await Promise.all([p.waitForEvent('download'), p.click('#export')]);
    const csv = fs.readFileSync(await dl.path(), 'utf8');
    ok(/"'=HYPERLINK/.test(csv) && /records-of-processing-2026-10-20\.csv/.test(dl.suggestedFilename()), 'CSV export, formula cells neutralised');

    // Sensitive data controls
    await go('pdpl-sensitive.html');
    t = await p.$eval('#finds', (e) => e.innerText); ok(/P-14/.test(t), 'gaps listed with the requirement');
    await p.click('#list tr[data-id="PD-ROPA-001"]'); await p.waitForSelector('#sform');
    ok(await p.$$eval('#sform input[name="credit_notice"]', (a) => a.length) === 0 && await p.$$eval('#sform input[name="health_chi"]', (a) => a.length) === 1, 'only the controls that apply (health, not credit)');
    await p.check('#sform input[name="health_chi"]'); await p.fill('#sform-access_tiers', 'claims-adjuster, medical-reviewer'); await submit('#sform');
    x = last('/pdpl/sensitive/PD-ROPA-001'); ok(x && x[1].health_chi === true && x[1].access_tiers.length === 2, 'controls saved');

    // Data subject requests
    await go('pdpl-dsar.html');
    t = await p.$eval('#list', (e) => e.innerText); ok(/REQ-1/.test(t) && /identity not verified/.test(t) && /10 days/.test(t), 'request, blockers, days left');
    await p.click('#add'); await p.waitForSelector('#nform');
    await p.fill('#nform-ref', 'REQ-2'); await p.selectOption('#nform-type', 'copy'); await p.selectOption('#nform-channel', 'call_centre'); await p.fill('#nform-received', '2026-10-20T09:30'); await p.fill('#nform-systems', 'CRM, CLAIMS-DB'); await submit('#nform');
    x = last('/pdpl/dsar'); ok(x && x[1].ref === 'REQ-2' && x[1].received === '2026-10-20T09:30Z' && x[1].systems.length === 2, 'request recorded with systems');
    await p.click('#list tr[data-id="PD-DSR-001"]'); await p.waitForSelector('#a-verify', { state: 'attached' });
    await p.click('summary:has-text("Verify identity")'); await p.selectOption('#a-verify-method', 'absher_otp'); await submit('#a-verify');
    x = last('/dsar/PD-DSR-001/verify'); ok(x && x[1].method === 'absher_otp', 'identity verification posted');
    await p.waitForSelector('#a-task', { state: 'attached' }); await p.click('summary:has-text("Record a system")'); await p.fill('#a-task-system', 'CRM'); await p.selectOption('#a-task-status', 'done'); await submit('#a-task');
    x = last('/dsar/PD-DSR-001/task'); ok(x && x[1].system === 'CRM' && x[1].status === 'done', 'system task posted');
    await p.waitForSelector('#a-extend', { state: 'attached' }); await p.click('summary:has-text("Extend")'); await p.fill('#a-extend-reason', 'archive restore from tape'); await submit('#a-extend');
    ok(last('/dsar/PD-DSR-001/extend'), 'extension posted');
    await p.waitForSelector('#letter'); await p.click('#letter'); await p.waitForSelector('#letterout pre');
    ok(await p.$eval('#letterout pre[dir="rtl"]', (e) => e.getAttribute('lang')) === 'ar' && await p.$$eval('#letterout img', (a) => a.length) === 0, 'letter in Arabic (RTL) and English, escaped');

    // DPIA
    await go('pdpl-dpia.html');
    await p.click('[data-assess="PD-ROPA-001"]'); await p.waitForSelector('#dform');
    ok(await p.$eval('#q-sensitive', (e) => e.value) === 'yes', 'draft answers pre-filled');
    await submit('#dform'); await p.waitForSelector('#dres .alert');
    x = last('/pdpl/dpia/assess'); ok(x && x[1].id === 'PD-DPIA-001' && x[1].measures[0] === 'encryption', 'assessment re-scored on the same draft');
    await p.keyboard.press('Escape'); await p.click('[data-sign="PD-DPIA-001"]'); await p.waitForTimeout(300); ok(last('/dpia/PD-DPIA-001/sign'), 'DPO sign posted');

    // Transfers
    await go('pdpl-transfers.html');
    await p.click('#list tr[data-id="PD-TRANSFER-001"]'); await p.waitForSelector('#tform');
    await p.selectOption('#t-purpose', 'none of these'); await p.selectOption('#t-sensitive', 'yes'); await submit('#tform'); await p.waitForSelector('#tres .alert');
    t = await p.$eval('#tres', (e) => e.innerText); ok(/not_permitted/.test(t) && /must not happen/.test(t), 'assessment result and what is required');
    ok(/A permitted purpose/.test(t) && /not met/.test(t) && /replaced by safeguards/.test(t) && !(await p.$('#tres img')), 'the Art. 29 conditions with their state (hostile text stays text)');
    await p.click('#tsign'); await p.waitForTimeout(300);
    ok(/four-eyes/.test(await p.$eval('#tform [data-msg]', (e) => e.textContent)), 'four-eyes refusal shown');

    // Breach
    await go('pdpl-breach.html');
    ok(/20 h left/.test(await p.$eval('#list', (e) => e.innerText)), 'the 72-hour clock');
    await p.click('#list tr[data-id="PD-BREACH-001"]'); await p.waitForSelector('#pform');
    ok(await p.$$eval('#zd-b img', (a) => a.length) === 0, 'description escaped');
    await p.selectOption('#pform-step', 'contain'); await p.fill('#pform-note', 'link disabled'); await submit('#pform');
    x = last('/breach/PD-BREACH-001/step'); ok(x && x[1].step === 'contain', 'playbook step posted');

    // Processors
    await go('pdpl-processors.html');
    await p.click('#list tr[data-id="PD-PROCESSOR-001"]'); await p.waitForSelector('#qform');
    await p.check('#qform input[name="breach_24h"]'); await submit('#qform');
    x = last('/processors/PD-PROCESSOR-001/assessment'); ok(x && x[1].breach_24h === true && x[1].iso27001 === true, 'due diligence posted');
    await p.waitForSelector('[data-dec="approve"]'); await p.click('[data-dec="approve"]'); await p.waitForTimeout(300);
    x = last('/subprocessor/1'); ok(x && x[1].decision === 'approve', 'sub-processor approval posted');

    // Programme
    await go('pdpl-programme.html');
    t = await p.$eval('#obl', (e) => e.innerText); ok(/national register of controllers/.test(t) && /SAR 5,000,000/.test(t) && /2 years in prison/.test(t), 'obligations with penalties');
    ok(/—/.test(await p.$eval('#meas', (e) => e.innerText)), 'nothing recorded shows a dash, not zero');
    await p.click('#addst'); await p.waitForSelector('#stform'); await p.fill('#stform-department', 'Claims'); await p.fill('#stform-user', 'omar.syn'); await p.selectOption('#stform-role', 'data_steward'); await submit('#stform');
    x = last('/pdpl/stewards'); ok(x && x[1].user === 'omar.syn', 'steward posted');
    await p.click('#assess'); await p.waitForSelector('#mform'); await p.click('label[for="m-mapping-map-yes"]'); await p.click('label[for="m-audit-retrieve-partly"]'); await submit('#mform');
    x = last('/pdpl/maturity'); ok(x && x[1].answers['mapping.map'] === 'yes' && x[1].answers['audit.retrieve'] === 'partly', 'maturity answers posted');

    // Policies
    await go('pdpl-policies.html');
    t = await p.$eval('#list', (e) => e.innerText); ok(/Data Subject Rights Procedure/.test(t) && /missing/.test(t) && /1 requests recorded/.test(t), 'policy set with state and what the registers show');
    await p.click('#list tr[data-id="PP-05"] td'); await p.waitForSelector('#zd-b ul');
    ok(/Answer within 30 days/.test(await p.$eval('#zd-b', (e) => e.innerText)) && await p.$$eval('#zd-b img', (a) => a.length) === 0, 'outline shown, escaped');
    await p.click('#zd-b [data-draft="PP-05"]'); await p.waitForTimeout(400);
    ok(last('/pdpl/policies/PP-05/draft'), 'Start a draft posted');
    ok(await p.$$eval('#list [data-draft="PP-05"], #list [data-act="draft"][data-pid="PP-05"]', (a) => a.length) === 0 && /DRAFT-0001/.test(await p.$eval('#list', (e) => e.innerText)), 'row now shows the draft, no second Start button');
    ok(!!(await p.$('#list tr[data-id="PP-05"] [data-act="submit"]')) && !!(await p.$('#list tr[data-id="PP-05"] [data-act="upload"]')), 'a draft offers Upload document and Submit for approval');

    // Governance
    await go('pdpl-governance.html');
    t = await p.$eval('#kpis', (e) => e.innerText); ok(/incomplete/i.test(t) && /5 \/ 6/.test(t) && /never/i.test(t) && /1 \(1 late\)/.test(t), 'governance KPIs: DPO line, named owners, committee, actions');
    ok(/not recorded/.test(await p.$eval('#dpo', (e) => e.innerText)), 'DPO reporting line shown as not recorded');
    ok(await p.$$eval('#pbd img', (a) => a.length) === 0, 'review name escaped');
    await p.click('[data-fn="requests"]'); await p.waitForSelector('#fform'); await p.fill('#fform-user', 'nora.syn'); await submit('#fform');
    x = last('/pdpl/accountability'); ok(x && x[1].function === 'requests' && x[1].user === 'nora.syn', 'named owner posted');
    await p.click('#addmeet'); await p.waitForSelector('#mform'); await p.fill('#mform-date', '2026-10-20'); await p.check('#mform input[name="departments"][value="legal"]'); await p.check('#mform input[name="departments"][value="it"]');
    await p.fill('#mform textarea[name="macts"]', 'map HR data | omar.syn | 2026-12-01'); await submit('#mform');
    x = last('/pdpl/committee'); ok(x && x[1].departments.join() === 'legal,it' && x[1].actions[0].owner === 'omar.syn' && x[1].actions[0].due === '2026-12-01', 'committee meeting with parsed actions');
    await p.click('#addpbd'); await p.waitForSelector('#pform'); await p.fill('#pform-name', 'New portal'); await p.selectOption('#pform-type', 'new_system'); await p.selectOption('#pq-personal', 'yes'); await p.selectOption('#pq-sensitive', 'no'); await submit('#pform');
    x = last('/pdpl/pbd'); ok(x && x[1].answers.personal === 'yes' && x[1].name === 'New portal', 'privacy review requested with answers');
    await p.click('[data-pbd="approve"]'); await p.waitForTimeout(400);
    ok(last('/pbd/PD-PBD_REVIEW-001/decide'), 'approve posted (refusal shown as a toast)');
    await p.click('#addrev'); await p.waitForSelector('#rform'); await p.fill('#rform-date', '2026-10-20'); await p.selectOption('[data-ck="followed"]', 'ok'); await p.selectOption('[data-ck="changes"]', 'issues'); await p.fill('[data-ckn="changes"]', 'new portal');
    await p.fill('#rform textarea[name="racts"]', 'add portal | omar.syn | 2026-11-01'); await submit('#rform');
    x = last('/pdpl/reviews'); ok(x && x[1].checks.changes.result === 'issues' && x[1].checks.changes.note === 'new portal' && x[1].actions.length === 1, 'programme review with checks and actions');

    // operator-only message
    DENY = true; await p.goto(base + '/dashboards/pdpl-dsar.html?standalone=1'); await p.waitForSelector('#list .alert');
    ok(/operator role/.test(await p.$eval('#list', (e) => e.innerText)), 'operator-only message');
    ok(errs.length === 0, 'no page errors: ' + errs.join(' | '));
    ok(dialogs === 0, 'no dialogs');
  } finally { await browser.close(); srv.close(); }
  console.log((bad ? 'FAILED ' : 'ok ') + (n - bad) + '/' + n);
  process.exit(bad ? 1 : 0);
})();
