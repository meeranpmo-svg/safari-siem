// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const ZYB_ORG = require('../../brand/index');
// Organisation & Automation (automation-org.html) and AI Auditors (ai-auditors.html), stubbed engines, SYNTHETIC people:
// the automation flow is drawn; five departments hold their people (from Roles & Functions), their AI engineers with live
// status and the named approvers (or "administrators only"); the auditors sit in the audit department and every other
// department shows its open audit findings; clicking an engineer opens its card; a viewer sees no names. The auditors
// page shows each programme (pass / fail / not tested), the findings drawer, the CSV report (formula-safe), Run audit now
// (operator; viewer told the role) and the tab switch. Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node automation-org.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const DASH = path.resolve(__dirname, '../../ui');
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
let WHO = { user: 'syed', role: 'admin' }, RUNS = 0, PROG404 = false; const POSTS = [];
const T = Date.now();
const eng = (id, name, o) => Object.assign({ id, name, on_duty: true, last_patrol: T - 120000, open: 2, critical: 0, by_status: {}, resolved_24h: 1 }, o || {});
const SIEM_E = [eng('network', 'AI Network Engineer', { by_status: { 'awaiting-approval': 2 } }), eng('security', 'AI Security Engineer'), eng('dba', 'AI Oracle DBA'), eng('apps', 'AI Application Manager', { on_duty: false })];
const ITAM_E = [eng('virt', 'AI Virtualization Administrator'), eng('desktop', 'AI Desktop Support Engineer', { not_connected: true }), eng('grc', 'AI GRC Consultant'), eng('itaudit', 'AI IT Auditor'), eng('cyberaudit', 'AI Cyber Security Auditor')];
const APPR = { engineers: [{ scope: 'eng:network', group: 'infra', engineer: 'AI Network Engineer', approves: 'x', people: ['khalid.syn'], direct: ['khalid.syn'], via_group: [] }, { scope: 'eng:virt', group: 'infra', engineer: 'AI Virtualization Administrator', approves: 'x', people: [], direct: [], via_group: [] }, { scope: 'eng:security', group: 'security', engineer: 'AI Security Engineer', approves: 'x', people: ['nora.syn'], direct: [], via_group: ['nora.syn'] }] };
const ROLES = { roles: [{ id: 'system-admin', name: 'System Admin', builtin: true, users: ['syed'] }, { id: 'infra-manager', name: 'Infrastructure Manager', base: 'operator', approves: ['infra'], builtin: true, users: ['khalid.syn'] }, { id: 'network-admin', name: 'Network Admin', base: 'operator', approves: [], builtin: true, users: ['fahad.syn'] },
  { id: 'ciso', name: 'CISO', builtin: true, users: ['nora.syn'] }, { id: 'grc-officer', name: 'Compliance / GRC Officer', builtin: true, users: ['huda.syn'] }, { id: 'auditor', name: 'Auditor (read-only)', base: 'viewer', builtin: true, users: ['aud.syn'] }, { id: 'r9', name: 'Oracle DBA Lead', builtin: false, users: ['dba.syn'] }] };
const test = (id, title, owner, owner_name, state, findings, items) => ({ id, area: 'Area', title, refs: ['ISO/IEC 27001:2022 A.5.3 Segregation of duties'], owner, owner_name, state, detail: state === 'not_tested' ? 'Backup Status is not installed' : 'checked', findings, items });
const PROG = (op) => ({ departments: {}, note: 'A test passes only on evidence.', auditors: [
  { id: 'itaudit', name: 'AI IT Auditor', about: 'IT general controls', last_run: T - 60000, counts: { pass: 1, fail: 1, not_tested: 1, not_run: 0 }, tested: 2, pass_pct: 50, tests: [
    test('IT-01', 'The audit trail is complete', 'platform', 'Platform administration', 'pass', 0, op ? [] : undefined),
    test('IT-02', 'Approvals by a different, named person', 'audit', 'IT & Cyber Security Audit', 'fail', 1, op ? [{ key: 'IT-02:patch:PR-1', severity: 'high', title: 'Patch install PR-1 approved by the person who requested it', evidence: ['=cmd|calc requested and approved by omar.syn'], recommendation: 'Record a retrospective approval.' }] : undefined),
    test('IT-05', 'Servers are backed up', 'infra', 'IT Infrastructure', 'not_tested', 0, op ? [] : undefined)] },
  { id: 'cyberaudit', name: 'AI Cyber Security Auditor', about: 'Cyber security controls', last_run: null, counts: { pass: 0, fail: 0, not_tested: 0, not_run: 1 }, tested: 0, pass_pct: null, tests: [
    test('CY-01', 'End-of-life systems isolated', 'cyber', 'Cyber Security', 'not_run', 0, op ? [] : undefined)] }] });
(async () => {
  const srv = http.createServer((req, res) => {
    const u = decodeURIComponent(req.url.split('?')[0]), json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    const op = WHO.role === 'operator' || WHO.role === 'admin';
    if (u === '/dashboards/whoami.json' || u === '/auth/whoami') return json(200, WHO);
    if (u === '/api/soc/duty/engineers') return json(200, { engineers: SIEM_E, policy: {} });
    if (u === '/api/itam/duty/engineers') return json(200, { engineers: ITAM_E, policy: {} });
    if (u === '/api/itam/roles/approvers') return op ? json(200, APPR) : json(403, { error: 'requires operator' });
    if ((u === '/api/itam/roles' || u === '/api/itam/roles/assign') && req.method === 'POST') { let b = ''; req.on('data', (c) => { b += c; }); req.on('end', () => { POSTS.push([u, JSON.parse(b || '{}')]); json(WHO.role === 'admin' ? 200 : 403, WHO.role === 'admin' ? ROLES : { error: 'requires admin' }); }); return; }
    if (u === '/api/itam/roles') return op ? json(200, ROLES) : json(403, { error: 'requires operator' });
    if (u === '/api/itam/audit-programme') return PROG404 ? json(404, { error: 'not found' }) : json(200, PROG(op));
    if (u === '/api/itam/audit-programme/report') { if (!op) return json(403, { error: 'requires operator' }); return json(200, { title: 'IT and Cyber Security Audit Report', organisation: ZYB_ORG.name, generated_at: new Date(T).toISOString(), basis: 'Automated testing.', digest: 'sha256:' + 'a'.repeat(64),
      signoff: { prepared_by: 'AI auditors (automated, read-only)', reviewed_by: null, review_note: 'To be reviewed and signed by the Head of IT & Cyber Security Audit before it is issued.' },
      sections: [{ auditor: 'itaudit', name: 'AI IT Auditor', run_at: new Date(T).toISOString(), opinion: { rating: 'Needs improvement', tone: 'orange', why: '1 high finding(s) need management action.' }, counts: { pass: 1, fail: 1, not_tested: 1, not_run: 0 }, pass_pct: 50, by_severity: { critical: 0, high: 1, medium: 0, low: 0 }, scope: 'IT general controls',
        programme: [{ id: 'IT-02', area: 'Change management', title: 'Approvals by a different person', owner: 'IT & Cyber Security Audit', result: 'fail', detail: '1 finding(s)', findings: 1 }], criteria: ['ISO/IEC 27001:2022 A.5.3 Segregation of duties'],
        findings: [{ ref: 'ITA-01', test: 'IT-02', area: 'Change management', severity: 'high', title: 'Patch install PR-1 approved by the person who requested it', condition: ['<img src=x> requested and approved by omar.syn'], criteria: ['ISO/IEC 27001:2022 A.5.3 Segregation of duties'], effect: 'A key control is not operating.', recommendation: 'Record a retrospective approval.', owner: 'IT & Cyber Security Audit', status: 'diagnosed', since: new Date(T).toISOString(), work_item: 'DW-000001' },
          { ref: 'ITA-02', test: 'IT-05', key: 'IT-05:none', area: 'Backup', severity: 'high', title: '2 server(s) with no backup at all', condition: ['3 servers in scope, 0 exempt'], criteria: ['ISO/IEC 27001:2022 A.8.13 Information backup'], effect: 'A key control is not operating.', recommendation: 'Add the servers to a backup job.', owner: 'IT Infrastructure', status: 'diagnosed',
            basis: ['Source: Backup Status, 1 platform(s) read - Veeam SYN (veeam; last sync 2026-10-20T07:00:00Z, ok, 4 objects)', 'Method: matched by name, host name, IP, VM UUID'],
            evidence: { columns: ['Server', 'Management IP', 'Status'], rows: [['SRV-SYN-NB1', '10.9.0.5', 'none'], ['<b>SRV-SYN-NB2</b>', '10.9.0.6', 'none']], count: 2, digest: 'sha256:' + 'b'.repeat(64), taken_at: new Date(T).toISOString() },
            counter: { columns: ['Backup object', 'VM name', 'Platform', 'Job', 'VM cluster'], rows: [['srv-syn-nb1-old', 'SRVSYNNB1', 'Veeam SYN', 'Weekly', '']], count: 1 } }],
        limitations: [{ id: 'IT-05', title: 'Servers are backed up', why: 'Backup Status is not installed' }] }] }); }
    if (u === '/api/itam/audit-programme/evidence') { if (!op) return json(403, { error: 'requires operator' }); return json(200, { key: 'IT-05:none', title: '2 server(s) with no backup at all', basis: ['Source: Veeam SYN'], columns: ['Server', 'Management IP', 'Status'], rows: [['=SRV-SYN-NB1', '10.9.0.5', 'none'], ['SRV-SYN-NB2', '10.9.0.6', 'none']], digest: 'sha256:' + 'b'.repeat(64), taken_at: new Date(T).toISOString(), counter: { title: 'Backup objects that matched no server in the register', columns: ['Backup object'], rows: [['srv-syn-nb1-old']] } }); }
    if (u === '/api/itam/audit-programme/run' && req.method === 'POST') { if (!op) return json(403, { error: 'requires operator' }); RUNS++; return json(200, { auditors: [PROG(true).auditors[0]] }); }
    if (u.startsWith('/api/itam/duty/')) return json(200, { items: [], engineers: ITAM_E, reports: [], policy: {} });
    if (u.startsWith('/api/')) return json(404, { error: 'not in this test' });
    const f = path.join(DASH, u.replace(/^\/dashboards\//, '/'));
    if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (e, d) => { if (e) { res.writeHead(404); return res.end(); } res.writeHead(200, { 'Content-Type': f.endsWith('.js') ? 'application/javascript' : f.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port + '/dashboards/';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright'); const browser = await chromium.launch(); const errs = [];
  const page = async (f) => { const ctx = await browser.newContext({ viewport: { width: 1500, height: 1000 }, acceptDownloads: true }); const p = await ctx.newPage(); p.on('pageerror', (e) => errs.push(f + ': ' + e.message)); await p.goto(base + f); return p; };
  const toasts = (p) => p.evaluate(() => [...document.querySelectorAll('.toast-zyb')].map((t) => t.textContent).join(' | '));
  try {
    // ---- organisation chart
    let p = await page('automation-org.html?standalone=1');
    await p.waitForSelector('.dept', { timeout: 15000 });
    ok((await p.$$('#flow .fs')).length === 8 && /Approve/.test(await p.textContent('#flow')) && /never the requester/.test(await p.textContent('#flow')), 'the automation flow: 8 steps, human approval spelled out');
    const depts = await p.$$eval('.dept .dh span', (a) => a.map((x) => x.textContent));
    ok(depts.join('|') === 'IT Infrastructure|IT Applications|Cyber Security|Governance, Risk & Compliance|IT & Cyber Security Audit', 'five departments: ' + depts.join('|'));
    const dtext = async (id) => p.textContent('.dept[data-dept="' + id + '"]');
    ok(/khalid\.syn/.test(await dtext('infra')) && /fahad\.syn/.test(await dtext('infra')) && /AI Network Engineer/.test(await dtext('infra')), 'infrastructure: its people and AI engineers');
    ok(/dba\.syn/.test(await dtext('apps')) && /AI Oracle DBA/.test(await dtext('apps')), 'a custom role named DBA lands in IT Applications');
    ok(/nora\.syn/.test(await dtext('cyber')) && /aud\.syn/.test(await dtext('audit')) && /AI IT Auditor/.test(await dtext('audit')) && /AI Cyber Security Auditor/.test(await dtext('audit')), 'cyber and audit departments');
    ok(/syed/.test(await p.textContent('#topppl')), 'platform administrators at the top');
    ok(/khalid\.syn · approver/.test(await dtext('infra')) && !/fahad\.syn · approver/.test(await dtext('infra')), 'the people who approve are marked');
    ok(/Nobody here approves/.test(await dtext('apps')) && /Oracle DBA Lead/.test(await dtext('apps')) && !/Nobody here approves/.test(await dtext('infra')), 'a department whose people approve nothing says how to fix it');
    const net = await p.textContent('[data-eng="network"]');
    ok(/Approved by khalid\.syn/.test(net) && /2 waiting for approval/.test(net), 'AI Network Engineer: its named approver and what waits for approval: ' + net);
    ok(/Administrators only/.test(await p.textContent('[data-eng="virt"]')), 'an AI engineer without a named approver says so');
    ok(/Independent/.test(await p.textContent('[data-eng="itaudit"]')), 'the auditors approve nothing');
    ok(/off duty/.test(await p.textContent('[data-eng="apps"]')) && /not connected/.test(await p.textContent('[data-eng="desktop"]')), 'live status per engineer');
    ok(/1<\/b> open finding/.test(await p.innerHTML('.dept[data-dept="audit"]')) || /Tests every department/.test(await dtext('audit')), 'audit lane');
    ok(/1 control test\(s\)/.test(await dtext('infra')), 'each department shows its audit tests: ' + (await dtext('infra')).slice(-80));
    await p.click('[data-eng="network"]'); await p.waitForTimeout(300);
    const dr = await p.evaluate(() => document.body.innerText);
    ok(/Approved by\s*khalid\.syn/.test(dr) && /Audited by/.test(dr) && /Job description|Mission/i.test(dr), 'clicking an engineer: approvers, auditors, job description');
    ok(await p.$eval('[data-eng="network"]', (b) => b.classList.contains('hl')), 'the engineer is highlighted');
    // ---- set up the approval workflow (admin)
    await p.keyboard.press('Escape'); await p.waitForTimeout(300);
    ok(/2 of 3 AI engineers have a named approver/.test(await p.textContent('#st3')) && /Infrastructure Manager/.test(await p.textContent('#st2')), 'set-up status: ' + (await p.textContent('#setup')).replace(/\s+/g, ' ').slice(0, 200));
    await p.click('[data-setappr="virt"]'); await p.waitForTimeout(300);
    ok(await p.$eval('[data-aprole="infra-manager"]', (c) => c.checked && c.disabled), 'a role approving the whole group is shown ticked, changed only in Roles & Functions');
    ok(!(await p.$('[data-aprole="auditor"]')), 'read-only roles are not offered');
    await p.check('[data-aprole="network-admin"]'); await p.click('[data-apprsave="virt"]'); await p.waitForTimeout(500);
    ok(POSTS.length === 1 && POSTS[0][0] === '/api/itam/roles' && JSON.stringify(POSTS[0][1]) === JSON.stringify({ id: 'network-admin', approves: ['eng:virt'] }), 'Save sends only the changed role: ' + JSON.stringify(POSTS));
    await p.fill('#asUser', 'new.syn'); await p.selectOption('#asRole', 'network-admin'); await p.click('#asSave'); await p.waitForTimeout(400);
    ok(POSTS.length === 2 && JSON.stringify(POSTS[1]) === JSON.stringify(['/api/itam/roles/assign', { user: 'new.syn', role_id: 'network-admin' }]), 'assign a person to a role: ' + JSON.stringify(POSTS[1]));
    ok(/Requested by/.test(await p.textContent('#matrix')) && /audit finding/i.test(await p.textContent('#matrix')), 'the approval matrix, with audit findings');
    await p.context().close();
    PROG404 = true; p = await page('automation-org.html?standalone=1'); await p.waitForSelector('.dept', { timeout: 15000 });
    ok(/not installed yet - run the update/.test(await dtext('infra')), 'audit programme missing: the reason, not "not readable"');
    await p.context().close(); PROG404 = false;
    WHO = { user: 'v.syn', role: 'viewer' }; p = await page('automation-org.html?standalone=1'); await p.waitForSelector('.dept', { timeout: 15000 });
    const vt = await p.textContent('#depts');
    ok(!/khalid\.syn|nora\.syn/.test(vt) && /operators and administrators see the names/.test(vt), 'viewer: no names');
    ok(!(await p.$('[data-setappr]')) && await p.isHidden('#assignbox'), 'viewer: no set-up controls');
    await p.context().close();

    // ---- auditors page
    WHO = { user: 'omar.syn', role: 'operator' };
    p = await page('ai-auditors.html?standalone=1'); await p.waitForSelector('#prog table', { timeout: 15000 });
    const k = await p.textContent('#kpis');
    ok(/50%/.test(k) && /tests failed/.test(k) && /not tested/.test(k), 'IT programme KPIs: ' + k.replace(/\s+/g, ' '));
    ok((await p.$$('#prog tr.rowc')).length === 3 && /Not tested/.test(await p.textContent('#prog')) && /A\.5\.3/.test(await p.textContent('#prog')), 'programme rows with state and criteria');
    await p.click('tr[data-test="IT-02"]'); await p.waitForTimeout(300);
    ok(/approved by the person who requested it/.test(await p.evaluate(() => document.body.innerText)) && /Recommendation/.test(await p.evaluate(() => document.body.innerText)), 'findings drawer with evidence and recommendation');
    await p.keyboard.press('Escape');
    const [dl] = await Promise.all([p.waitForEvent('download'), p.click('#csv')]);
    const csv = fs.readFileSync(await dl.path(), 'utf8');
    ok(/IT-02/.test(csv) && /"'=cmd\|calc/.test(csv) && /Tests passed/.test(csv), 'CSV report, formula-safe');
    await p.click('#run'); await p.waitForFunction(() => /passed/.test([...document.querySelectorAll('.toast-zyb')].map((t) => t.textContent).join(' ')), null, { timeout: 10000 }).catch(() => {});
    ok(RUNS === 1 && /1 passed, 1 failed, 1 not tested/.test(await toasts(p)), 'Run audit now: ' + await toasts(p));
    await p.click('#report'); await p.waitForSelector('#rep h1', { timeout: 10000 });
    const rp = await p.textContent('#rep');
    ok(/Needs improvement/.test(rp) && /ITA-01/.test(rp) && /Condition \(evidence\)/.test(rp) && /Criteria/.test(rp) && /Effect/.test(rp) && /Management response/.test(rp) && /Limitations/.test(rp) && /Backup Status is not installed/.test(rp) && /Reviewed by/.test(rp), 'the audit report: opinion, finding with condition / criteria / effect, management response, limitations, sign-off');
    ok(!(await p.$('#rep img')) && !(await p.$('#rep table b')), 'evidence is escaped in the report');
    ok(/Basis of the test/.test(rp) && /Veeam SYN \(veeam; last sync/.test(rp) && /SRV-SYN-NB1/.test(rp) && /Counter-evidence/.test(rp) && /srv-syn-nb1-old/.test(rp) && /Annex A - evidence/.test(rp) && /sha256:b{64}/.test(rp), 'evidence: basis, rows, counter-evidence, annex, digest');
    const [evd] = await Promise.all([p.waitForEvent('download'), p.click('#rep [data-evkey="IT-05:none"]')]);
    const evcsv = fs.readFileSync(await evd.path(), 'utf8');
    ok(/evidence-ITA-02-/.test(evd.suggestedFilename()) && /Digest \(SHA-256\)/.test(evcsv) && /"'=SRV-SYN-NB1"/.test(evcsv) && /srv-syn-nb1-old/.test(evcsv) && /Basis/.test(evcsv), 'evidence CSV: header, basis, rows (formula-safe), counter-evidence');
    ok(await p.isVisible('#repprint'), 'print / save as PDF');
    await p.click('#repclose');
    await p.click('[data-tab="cyberaudit"]'); await p.waitForTimeout(200);
    ok(/CY-01/.test(await p.textContent('#prog')) && /not run yet/.test(await p.textContent('#lastrun')) && /—/.test(await p.textContent('#kpis')), 'cyber tab: nothing tested = no percentage');
    ok(await p.isHidden('#duty-itaudit') && !(await p.isHidden('#duty-cyberaudit')), 'the duty desk follows the tab');
    await p.context().close();
    WHO = { user: 'v.syn', role: 'viewer' }; p = await page('ai-auditors.html?standalone=1#cyberaudit'); await p.waitForSelector('#prog table', { timeout: 15000 });
    ok(/CY-01/.test(await p.textContent('#prog')), 'the address opens the cyber tab');
    await p.click('#run'); await p.waitForTimeout(500);
    ok(/needs the operator role/.test(await toasts(p)) && RUNS === 1, 'viewer: told the role');
    await p.click('#report'); await p.waitForTimeout(600);
    ok(/for operators and administrators/.test(await p.textContent('#rep')), 'viewer: the report is refused with the reason');
    await p.context().close();
    ok(!errs.length, 'no page errors: ' + errs.slice(0, 3).join(' | '));
  } finally { await browser.close(); srv.close(); }
  console.log(bad ? 'FAILED ' + bad + '/' + n + ' checks' : 'OK ' + n + '/' + n + ' checks'); process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
