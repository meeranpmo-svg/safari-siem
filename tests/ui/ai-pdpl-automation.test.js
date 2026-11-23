// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const ZYB_ORG = require('../../brand/index');
// AI PDPL Consultant automation tabs (ai-pdpl.html), stubbed ITAM, SYNTHETIC data: Data discovery (findings, categories,
// Scan now, Adopt), Breach (open from a SIEM incident, the 72-hour clock, SDAIA draft and Arabic / English notice), DPIA
// wizard (questions, measures, score with reasons, Sign as DPO, a refusal shown), escaping, operator-only messages.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node ai-pdpl-automation.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const DASH = path.resolve(__dirname, '../../ui');
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const POSTS = []; let SIGN403 = false, DISC403 = false;
const VIEW = { engine: 'python', connected: true, compliance_pct: 10, counts: { compliant: 0, partial: 0, non_compliant: 0, not_applicable: 0, auto_pass: 0, not_assessed: 1 }, requirements: [], findings: [], readiness: { ready: false, blockers: [], digest: 'sha256:' + 'a'.repeat(64) }, statement: { status: 'none' }, note: 'n' };
const DISC = { last: { at: new Date().toISOString(), by: 'syed' }, note: 'n', findings: [{ key: 'disc:reg:core:unmapped', severity: 'high', title: '<img src=x onerror=alert(1)> CORE-DB holds personal data', recommendation: 'Record the processing activity' }],
  databases: [{ db: 'reg:core', label: 'CORE-DB', ok: true, columns: 5, scanned_columns: 400, probe_denied: 1, activities: [], categories: [{ category: 'health', columns: 1, confirmed: 0, tables: 1, max_rows: 900000, kinds: ['health'], declared: false, sensitive: true }, { category: 'identity', columns: 1, confirmed: 1, tables: 1, max_rows: 120000, kinds: ['national_id'], declared: false, sensitive: false }] },
    { db: 'reg:hr', label: 'HR-DB', ok: false, error: 'auth: login refused', columns: 0, activities: [], categories: [] }] };
const DRAFT = { breach: 'PD-BREACH-001', deadline: new Date(Date.now() + 70 * 3600000).toISOString(), hours_left: 70, notified: false, late: false, missing: ['categories of personal data'], subjects_required: true,
  sdaia: [['Controller', ZYB_ORG.name], ['How it happened (circumstances)', '<b>synthetic</b>']], subject_notice: { en: 'Dear customer, synthetic', ar: 'عزيزنا العميل' }, note: 'the platform does not send it' };
const Q = { questions: [{ id: 'sensitive', question: 'Sensitive data?', options: ['no', 'yes'] }, { id: 'scale', question: 'How many?', options: ['under 1,000', 'over 100,000'] }], measures: [{ id: 'encryption', measure: 'Encryption', reduces: 2 }, { id: 'access', measure: 'Access control', reduces: 2 }] };
let DPIAS = [];
(async () => {
  const srv = http.createServer((req, res) => {
    const u = decodeURIComponent(req.url.split('?')[0]), q = new URLSearchParams(req.url.split('?')[1] || ''), json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    const body = (fn) => { let b = ''; req.on('data', (c) => { b += c; }); req.on('end', () => { const j = JSON.parse(b || '{}'); POSTS.push([u, j]); fn(j); }); };
    if (u === '/dashboards/whoami.json' || u === '/auth/whoami') return json(200, { user: 'syed', role: 'admin' });
    if (u === '/api/itam/pdpl') return json(200, VIEW);
    if (u === '/api/itam/pdpl/discovery') return DISC403 ? json(403, { error: 'requires operator' }) : json(200, DISC);
    if (u === '/api/itam/pdpl/discovery/run') return body(() => json(200, { at: new Date().toISOString(), databases: [{ db: 'reg:core' }, { db: 'reg:hr' }] }));
    if (u === '/api/itam/pdpl/discovery/adopt') return body((b) => json(200, { id: 'PD-ROPA-007', systems: ['CORE-DB'] }));
    if (u === '/api/itam/pdpl/records' && q.get('kind') === 'breach') return json(200, { records: POSTS.some((p) => p[0].endsWith('/from-incident')) ? [{ id: 'PD-BREACH-001', kind: 'breach', source_case: 'CASE-000042', aware_at: '2026-10-20T06:00Z', description: 'Mass export' }] : [] });
    if (u === '/api/itam/pdpl/records' && q.get('kind') === 'ropa') return json(200, { records: [{ id: 'PD-ROPA-001', kind: 'ropa', name: 'Medical claims' }] });
    if (u === '/api/itam/pdpl/records' && q.get('kind') === 'dpia') return json(200, { records: DPIAS });
    if (u === '/api/itam/pdpl/breach/from-incident') return body((b) => json(200, { id: 'PD-BREACH-001', source_case: b.case_id }));
    if (u === '/api/itam/pdpl/breach/PD-BREACH-001/draft') return json(200, DRAFT);
    if (u === '/api/itam/pdpl/dpia/questions') return json(200, Q);
    if (u === '/api/itam/pdpl/dpia/assess') return body((b) => { const r = { id: 'PD-DPIA-001', kind: 'dpia', ropa_id: b.ropa_id, wizard: true, prepared_by: 'nora.syn', outcome: 'mitigations', score: { likelihood: 2, severity: 5, inherent: 7, reduced_by: 2, residual: 5, level: 'medium', why: ['sensitive: yes (+1 likelihood, +3 severity)'], required: ['explicit consent'], note: '' } }; DPIAS = [r]; json(200, r); });
    if (u === '/api/itam/pdpl/dpia/PD-DPIA-001/sign') return body(() => (SIGN403 ? json(403, { error: 'four-eyes: the DPO cannot sign an assessment they prepared' }) : json(200, { id: 'PD-DPIA-001', completed: '2026-10-20' })));
    if (u.startsWith('/api/')) return json(404, { error: 'not in this test' });
    const f = path.join(DASH, u.replace(/^\/dashboards\//, '')); if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (e, d) => { if (e) { res.writeHead(404); return res.end(); } res.writeHead(200, { 'Content-Type': f.endsWith('.js') ? 'application/javascript' : f.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port;
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright'); const browser = await chromium.launch();
  try {
    const p = await browser.newPage(); const errs = []; let dialogs = 0; p.on('pageerror', (e) => errs.push(e.message)); p.on('dialog', (d) => { dialogs++; d.dismiss(); });
    // discovery
    await p.goto(base + '/dashboards/ai-pdpl.html?standalone=1#discovery'); await p.waitForSelector('#dbody table');
    const dt = await p.$eval('#v-discovery', (e) => e.innerText);
    ok(/CORE-DB holds personal data/.test(dt) && /health · 1 col/.test(dt) && /1 confirmed/.test(dt) && /login refused/.test(dt) && /1 not readable/.test(dt), 'discovery table and finding');
    ok(await p.$$eval('#v-discovery img', (a) => a.length) === 0, 'finding title escaped');
    await p.click('#drun'); await p.waitForTimeout(400); ok(POSTS.some((x) => x[0].endsWith('/discovery/run')), 'Scan now posts');
    await p.click('[data-adopt="reg:core"]'); await p.waitForTimeout(400);
    const ad = POSTS.find((x) => x[0].endsWith('/adopt')); ok(ad && ad[1].db === 'reg:core', 'adopt posts the database key');
    // breach
    await p.click('#tabs [data-tab="breach"]'); await p.waitForSelector('#bbody');
    await p.fill('#bcase', 'CASE-000042'); await p.click('#bopen'); await p.waitForSelector('#bdraft h4');
    const fi = POSTS.find((x) => x[0].endsWith('/from-incident')); ok(fi && fi[1].case_id === 'CASE-000042', 'open from incident posts the case id');
    const bd = await p.$eval('#bdraft', (e) => e.innerText);
    ok(/70 h left/.test(bd) && /Still missing: categories of personal data/.test(bd) && new RegExp(ZYB_ORG.name).test(bd) && /عزيزنا العميل/.test(bd) && /does not send/.test(bd), 'clock, missing fields, drafts in both languages');
    ok(await p.$$eval('#bdraft b', (a) => a.filter((x) => x.textContent === 'synthetic').length) === 0, 'draft values escaped');
    ok(await p.$eval('#bdraft pre[dir="rtl"]', (e) => e.getAttribute('lang')) === 'ar', 'Arabic notice right-to-left');
    // DPIA
    await p.click('#tabs [data-tab="dpia"]'); await p.waitForSelector('#dpq select');
    await p.selectOption('select[name=q_sensitive]', 'yes'); await p.selectOption('select[name=q_scale]', 'over 100,000'); await p.check('input[name=m_encryption]');
    await p.click('#dpform button[type=submit]'); await p.waitForSelector('#dpres .alert');
    const as = POSTS.find((x) => x[0].endsWith('/dpia/assess'));
    ok(as && as[1].ropa_id === 'PD-ROPA-001' && as[1].answers.sensitive === 'yes' && as[1].answers.scale === 'over 100,000' && as[1].measures.join() === 'encryption', 'assessment posted: ' + JSON.stringify(as && as[1]));
    const rs = await p.$eval('#dpres', (e) => e.innerText);
    ok(/residual risk 5 \(medium\)/.test(rs) && /sensitive: yes/.test(rs) && /Required: explicit consent/.test(rs) && /until the DPO signs/.test(rs), 'score with reasons');
    await p.waitForSelector('[data-dpsign]');
    SIGN403 = true; await p.click('[data-dpsign]'); await p.waitForTimeout(400);
    ok(/four-eyes/.test(await p.evaluate(() => [].map.call(document.querySelectorAll('.toast-zyb'), (t) => t.textContent).join(' '))), 'sign refusal shown');
    SIGN403 = false; await p.click('[data-dpsign]'); await p.waitForTimeout(400);
    ok(POSTS.filter((x) => x[0].endsWith('/sign')).length === 2, 'sign posted');
    // operator-only
    DISC403 = true; const p2 = await browser.newPage(); p2.on('pageerror', (e) => errs.push(e.message));
    await p2.goto(base + '/dashboards/ai-pdpl.html?standalone=1#discovery'); await p2.waitForFunction(() => /for operators/.test(document.getElementById('dbody').innerText));
    ok(true, 'viewer message');
    ok(!errs.length, 'no page errors: ' + errs.join(' | ')); ok(!dialogs, 'no browser dialogs');
  } finally { await browser.close(); srv.close(); }
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks'); process.exit(bad ? 1 : 0);
})();
