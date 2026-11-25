// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Aramco CCC page: the empty state says to import the organisation's own SACS-002 control list (no control text ships); the eight
// stages with the current one marked; import from a CSV file; assess a control; "not applicable" asks for a justification; the
// person who proposed N/A is not offered Accept and another person is; add evidence and an action; hostile text stays text;
// a viewer sees no controls to change. Stub ITAM; contracts, controls and people are SYNTHETIC.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node aramco-ccc.test.js
const http = require('http'), fs = require('fs'), path = require('path'), os = require('os');
const DASH = path.resolve(__dirname, '../../ui');
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
let USER = 'omar.syn', ROLE = 'operator', CONTROLS = [], SUBS = [], LINKED = [];
const SVC = { general: 'General (every third party)', 'network-connectivity': 'Network connectivity to Aramco', 'outsourced-infrastructure': 'Outsourced infrastructure / hosting', 'critical-data': 'Critical data processing', 'custom-software': 'Customized software development', cloud: 'Cloud computing service' };
const stage = (id, name, done, why, next) => ({ id, name, done, why, next });
const VIEW = () => ({ org: 'Synthetic Co', profile: { ccc_owner: 'omar.syn', vendor_no: 'V-SYN', planned_audit: '2027-02-01' }, can_manage: USER === 'omar.syn' || ROLE === 'admin', services: SVC,
  contracts: [{ id: 'CON-0001', contract_no: 'C-SYN-1', title: 'Synthetic O&M', services: ['general', 'network-connectivity'], ccc_needed_by: '2027-03-01', active: true }],
  controls: CONTROLS, controls_total: CONTROLS.length, score: CONTROLS.length ? 50 : null, assessed: CONTROLS.filter((c) => c.status !== 'not-assessed').length, applicable: CONTROLS.length, gaps: 1, actions: [], overdue: 0,
  evidence_missing: [], na_pending: [], audit: null, findings: [], certificate: null, days_left: null, uncovered: ['C-SYN-1'],
  stages: [stage('scope', 'Scope', true, '1 active Aramco contract(s)', ''), stage('controls', 'Controls', !!CONTROLS.length, CONTROLS.length ? 'imported' : 'no control list imported', 'Import the control list'), stage('assessment', 'Self-assessment', false, '0 of 2 assessed', 'Assess'), stage('remediation', 'Remediation', false, '', 'x'), stage('evidence', 'Evidence', false, '', 'x'), stage('audit', 'Audit', false, '', 'x'), stage('certificate', 'Certificate', false, '', 'x'), stage('renewal', 'Renewal', false, '', 'x')],
  current: CONTROLS.length ? 'assessment' : 'controls', projection: null, snapshots: 0 });
const posts = [];
(async () => {
  const srv = http.createServer((req, res) => {
    const u = req.url.split('?')[0]; const json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    const body = (fn) => { let b = ''; req.on('data', (d) => { b += d; }); req.on('end', () => { const j = b ? JSON.parse(b) : null; posts.push([req.method, u, j]); fn(j); }); };
    if (u === '/dashboards/whoami.json') return json(200, { user: USER, role: ROLE });
    if (u === '/api/itam/aramco-ccc') return json(200, VIEW());
    if (u === '/api/itam/aramco-ccc/evidence') return json(200, { catalogue: [{ id: 'assets', name: 'Asset inventory' }, { id: 'backup', name: 'Backup and recovery' }], covered: LINKED.length, gaps: 2 - LINKED.length,
      sources: [{ id: 'assets', name: 'Asset inventory', stale: false, snapshot: { at: '2026-11-25T08:00:00Z', available: true, sha256: 'ab'.repeat(32), collections: { assets: { count: 240 } } } }, { id: 'backup', name: 'Backup and recovery', snapshot: { at: '2026-11-25T08:00:00Z', available: false, why: 'nothing recorded yet <img src=x onerror=alert(1)>', collections: {}, sha256: 'cd'.repeat(32) } }],
      controls: [{ id: 'SYN-1', title: 'Policy', status: 'implemented', linked: LINKED, references: 0, suggested: LINKED.length ? [] : [{ source: 'assets', score: 0.42 }], gap: LINKED.length ? '' : 'no evidence' }], submissions: SUBS });
    if (u === '/api/itam/aramco-ccc/evidence/collect') return body(() => json(200, [{ source: 'assets', available: true }, { source: 'backup', available: false }]));
    if (u === '/api/itam/aramco-ccc/evidence/link') return body((b) => { if (b.linked) LINKED = [b.source]; json(200, b); });
    if (u === '/api/itam/aramco-ccc/submissions') return body(() => { const x = { id: 'SUB-0001', status: 'prepared', prepared_by: USER, controls: 2, gaps: 1, unassessed: 0, readiness: 50, manifest_sha256: 'ef'.repeat(32) }; SUBS = [x]; json(200, x); });
    if (/\/submissions\/SUB-0001\/approve$/.test(u)) return body(() => { SUBS[0].status = 'approved'; SUBS[0].approved_by = USER; json(200, SUBS[0]); });
    if (/\/submissions\/SUB-0001\/submitted$/.test(u)) return body((b) => { Object.assign(SUBS[0], { status: 'submitted' }, b); json(200, SUBS[0]); });
    if (/\/submissions\/SUB-0001\/export$/.test(u)) return json(200, { filename: 'aramco-ccc-SUB-0001.csv', csv: '"control"\n"SYN-1"', manifest_sha256: 'ef'.repeat(32) });
    if (u === '/api/itam/aramco-ccc/controls/import') return body((b) => { CONTROLS = [{ id: 'SYN-1', domain: 'Governance', title: 'Policy <img src=x onerror=alert(1)>', requirement: 'Synthetic requirement', applies: ['all'], status: 'not-assessed', evidence: [] }, { id: 'SYN-2', domain: 'Access', title: 'MFA', requirement: 'Synthetic', applies: ['network-connectivity'], status: 'not-implemented', evidence: [] }]; json(200, { added: 2, updated: 0, total: 2 }); });
    const m = u.match(/^\/api\/itam\/aramco-ccc\/controls\/([^/]+)\/(assess|na|evidence)$/);
    if (m) return body((b) => { const c = CONTROLS.find((x) => x.id === m[1]); if (m[2] === 'assess') { c.status = b.status; c.na = b.status === 'not-applicable' ? { state: 'proposed', by: USER, justification: b.justification } : null; } if (m[2] === 'na') c.na.state = b.decision; if (m[2] === 'evidence') c.evidence.push(b); json(200, c); });
    if (u === '/api/itam/aramco-ccc/actions') return body((b) => json(200, Object.assign({ id: 'ACT-0001', status: 'open' }, b)));
    if (u.startsWith('/api/')) return json(404, { error: 'not in this test' });
    fs.readFile(path.join(DASH, u.replace(/^\/dashboards\//, '/')), (err, d) => { if (err) { res.writeHead(404); res.end(); return; } res.writeHead(200, { 'Content-Type': u.endsWith('.js') ? 'application/javascript' : u.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const URL0 = 'http://127.0.0.1:' + srv.address().port + '/aramco-ccc.html?standalone=1';
  const csv = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'accc-')), 'controls.csv'); fs.writeFileSync(csv, 'id,domain,title,requirement,applies_to\nSYN-1,Governance,Policy,Synthetic,all\n');
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(); const errs = []; let answers = [];
  const open = async () => { const p = await browser.newPage({ viewport: { width: 1400, height: 900 } }); p.on('pageerror', (x) => errs.push(x.message)); p.on('dialog', (d) => d.accept(answers.length ? answers.shift() : '')); await p.goto(URL0); return p; };
  const toast = async (p) => { await p.waitForSelector('.toast', { timeout: 8000 }); const t = await p.$$eval('.toast', (x) => x.map((e) => e.textContent).join(' | ')); await p.$$eval('.toast', (x) => x.forEach((e) => e.remove())); return t; };
  let p = await open(); await p.waitForSelector('#stg .st');
  ok(/ships no control text/.test(await p.textContent('#x-ctl')), 'empty state: import your own SACS-002 list');
  ok((await p.$$('#stg .st')).length === 8 && /Controls/.test(await p.textContent('#stg .st.cur')), 'eight stages, the current marked');
  ok(/C-SYN-1/.test(await p.textContent('#x-scope')) && /Not covered: C-SYN-1/.test(await p.textContent('#x-cert')) === false, 'scope lists the contract');
  await p.setInputFiles('#i-f', csv); await p.click('#i-go'); ok(/2 added/.test(await toast(p)), 'imported');
  const imp = posts.find((x) => x[1].endsWith('/controls/import')); ok(imp && /SYN-1,Governance/.test(imp[2].csv), 'the file is sent as CSV text');
  await p.waitForSelector('[data-as="SYN-1"]');
  ok(!(await p.$('img[src="x"]')), 'hostile text stays text');
  await p.selectOption('[data-as="SYN-2"]', 'partial'); await toast(p);
  ok(posts.some((x) => /SYN-2\/assess$/.test(x[1]) && x[2].status === 'partial'), 'assessed');
  answers = ['no remote access to Aramco from this site (synthetic)']; await p.waitForSelector('[data-as="SYN-1"]'); await p.selectOption('[data-as="SYN-1"]', 'not-applicable'); await toast(p);
  const na = posts.find((x) => /SYN-1\/assess$/.test(x[1])); ok(na && na[2].status === 'not-applicable' && /no remote access/.test(na[2].justification), 'N/A with its justification');
  await p.waitForFunction(() => /waiting for a second person/.test(document.querySelector('#x-ctl').innerText));
  ok(!(await p.$('[data-na="accepted"]')), 'the proposer is not offered Accept');
  answers = ['Access review minutes', 'DMS/CCC/SYN-2', '2026-11-20']; await p.click('[data-ev="SYN-2"]'); await toast(p);
  ok(posts.some((x) => /SYN-2\/evidence$/.test(x[1]) && x[2].location === 'DMS/CCC/SYN-2'), 'evidence reference');
  answers = ['Enforce MFA on the VPN', 'it.syn', '2026-12-15']; await p.waitForSelector('[data-ac="SYN-2"]'); await p.click('[data-ac="SYN-2"]'); await toast(p);
  ok(posts.some((x) => x[1] === '/api/itam/aramco-ccc/actions' && x[2].control === 'SYN-2' && x[2].due === '2026-12-15'), 'action');
  // platform evidence and the submission pack
  ok(/Asset inventory/.test(await p.textContent('#x-ev')) && /assets: 240/.test(await p.textContent('#x-ev')), 'snapshots shown');
  ok(!(await p.$('img[src="x"]')), 'hostile text in evidence stays text');
  await p.click('#ev-go'); ok(/1 of 2 sources collected/.test(await toast(p)), 'collect now');
  await p.waitForSelector('[data-link="SYN-1"]'); await p.click('[data-link="SYN-1"]'); await toast(p);
  ok(posts.some((x) => x[1].endsWith('/evidence/link') && x[2].source === 'assets' && x[2].linked === true), 'suggestion linked by a person');
  await p.waitForSelector('#sub-go'); await p.click('#sub-go'); ok(/SUB-0001 prepared - waiting for approval/.test(await toast(p)), 'pack prepared');
  await p.waitForFunction(() => /SUB-0001/.test(document.querySelector('#x-sub').innerText));
  ok(!(await p.$('[data-sapp]')), 'the preparer is not offered Approve');
  await p.close();
  USER = 'admin.syn'; ROLE = 'admin'; p = await open(); await p.waitForSelector('[data-na="accepted"]'); await p.click('[data-na="accepted"]'); await toast(p);
  ok(posts.some((x) => /SYN-1\/na$/.test(x[1]) && x[2].decision === 'accepted'), 'another person accepts');
  await p.waitForSelector('[data-sapp]'); answers = ['yes']; await p.click('[data-sapp]'); await toast(p); ok(SUBS[0].status === 'approved', 'another person approves the pack');
  answers = ['2026-11-25', 'SYN-AUDIT-REF']; await p.waitForSelector('[data-ssub]'); await p.click('[data-ssub]'); await toast(p); ok(SUBS[0].status === 'submitted' && SUBS[0].reference === 'SYN-AUDIT-REF', 'recorded as submitted');
  const [dl] = await Promise.all([p.waitForEvent('download', { timeout: 8000 }).catch(() => null), p.click('[data-sdl][data-fmt="csv"]')]); ok(dl && dl.suggestedFilename() === 'aramco-ccc-SUB-0001.csv', 'pack downloaded');
  await p.close();
  USER = 'vera.syn'; ROLE = 'viewer'; p = await open(); await p.waitForSelector('#x-ctl table');
  ok(!(await p.$('[data-as]')) && !(await p.$('#i-go')) && !(await p.$('#c-add')), 'viewer: read only');
  await p.close();
  ok(!errs.length, 'errors: ' + errs.join(' | '));
  await browser.close(); srv.close();
  console.log(bad ? `${bad}/${n} FAILED` : `OK ${n}/${n} checks`); process.exit(bad ? 1 : 0);
})();
