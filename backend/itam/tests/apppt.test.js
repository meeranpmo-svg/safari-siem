// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Application Penetration Testing (engine/apppt.js) through the real routes with SYNTHETIC applications and reports: the
// application register (validation naming the field, roles, duplicates), the cadence (critical external = 90 days, never tested =
// due now); an engagement from draft to closed - scope approved by the CISO / an administrator who did not request it, testing
// only inside the approved window, every WSTG area decided before the report, a note when closing with open findings; findings
// (manual with CWE → OWASP category, out-of-scope refused, duplicates refused), OWASP ZAP JSON and Burp XML imports (informational
// skipped, secrets in evidence masked, a DOCTYPE refused); a fix verified only by another person's retest, a failed retest counted;
// regression across engagements; four-eyes risk acceptance; ML (systemic weakness on two apps, SLA miss chance needs 5 fixes,
// retest failure rate from 3 claims, risk itemised); a viewer sees no endpoint or steps; export and the audit records.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');
const { parseZap, parseBurp } = require('../engine/apppt');

const VIEW = { user: 'vera.syn', role: 'viewer' }, OP = { user: 'nora.syn', role: 'operator' }, OP2 = { user: 'omar.syn', role: 'operator' }, ADM = { user: 'syed', role: 'admin' }, BOT = { user: 'ai:apppt', role: 'operator' };
const DAY = 86400000, TOKEN = 'ghp_' + 'SYNTHETICSYNTHETICSYNTHETIC1234567';
const zap = (alerts, site = 'https://portal.synthetic.test') => JSON.stringify({ '@version': '2.15.0', site: [{ '@name': site, alerts }] });
const za = (name, risk, cwe, uri, extra) => Object.assign({ alert: name, riskcode: String(risk), confidence: '2', cweid: String(cwe), desc: '<p>synthetic ' + name + '</p>', solution: '<p>fix it</p>', instances: [{ uri, method: 'GET', param: 'q', evidence: 'x' }] }, extra || {});

async function setup(t) {
  let clock = Date.parse('2026-10-28T08:00:00Z');
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true, now: () => clock });
  const call = (m, p, body, who) => e.req(m, p, Object.assign(body !== undefined ? { body } : {}, who));
  const post = (p, b, who = OP) => call('POST', p, b, who), get = (p, who = OP) => call('GET', p, undefined, who);
  const mkApp = async (name, x = {}) => (await post('/apppt/targets', Object.assign({ name, url: 'https://' + name.toLowerCase().replace(/[^a-z]+/g, '') + '.synthetic.test', kind: 'web', exposure: 'external', criticality: 'critical', owner: 'digital.syn' }, x))).json;
  const mkEng = async (ids, x = {}) => (await post('/apppt/engagements', Object.assign({ title: 'Q4 portal test (synthetic)', target_ids: ids, approach: 'grey_box', tester: 'Internal red team (synthetic)', window_start: '2026-10-29', window_end: '2026-11-10', rules: 'Test accounts tester1/tester2 only; no denial of service; contact soc.syn' }, x))).json;
  // draft → approved → testing (the clock moves into the window)
  const startTesting = async (id) => { await post('/apppt/engagements/' + id + '/scope', {}); await post('/apppt/engagements/' + id + '/scope/decide', { decision: 'approve' }, ADM); if (clock < Date.parse('2026-10-29T08:00:00Z')) clock = Date.parse('2026-10-29T08:00:00Z'); return post('/apppt/engagements/' + id + '/state', { state: 'testing' }); };
  const coverAll = async (id) => { for (const a of ['INFO', 'CONF', 'IDNT', 'ATHN', 'ATHZ', 'SESS', 'INPV', 'ERRH', 'CRYP', 'BUSL', 'CLNT', 'APIT']) await post('/apppt/engagements/' + id + '/coverage', { area: a, status: a === 'CLNT' ? 'na' : 'tested' }); };
  const find = async (eid, tid, x = {}) => post('/apppt/engagements/' + eid + '/findings', Object.assign({ target_id: tid, title: 'Stored XSS in claim notes', severity: 'high', cwe: 'CWE-79', endpoint: '/claims/notes?id=1', steps: 'POST a note with <script>', recommendation: 'Encode output' }, x));
  return { e, tick: (ms) => { clock += ms; }, setClock: (iso) => { clock = Date.parse(iso); }, post, get, mkApp, mkEng, startTesting, coverAll, find, audits: (a) => e.app.store.auditTail(800).filter((x) => x.action === a) };
}

test('applications: validation names the field, roles, duplicates, cadence; never tested = due now', async (t) => {
  const S = await setup(t);
  let r = await S.post('/apppt/targets', { name: 'X', url: 'ftp://x', kind: 'web', exposure: 'external', criticality: 'high' }); assert.equal(r.status, 400); assert.match(r.json.error, /url/);
  r = await S.post('/apppt/targets', { name: 'X', url: 'https://x.test', kind: 'desktop', exposure: 'external', criticality: 'high' }); assert.equal(r.status, 400); assert.match(r.json.error, /kind must be one of/);
  assert.equal((await S.post('/apppt/targets', { name: 'X', url: 'https://x.test', kind: 'web', exposure: 'external', criticality: 'high' }, VIEW)).status, 403);
  assert.equal((await S.post('/apppt/targets', { name: 'X', url: 'https://x.test', kind: 'web', exposure: 'external', criticality: 'high' }, BOT)).status, 403, 'an AI identity does not add applications');
  const a = await S.mkApp('Customer portal synthetic'), b = await S.mkApp('Claims intranet synthetic', { exposure: 'internal', criticality: 'medium' });
  assert.equal((await S.post('/apppt/targets', { name: 'customer portal SYNTHETIC', url: 'https://y.test', kind: 'web', exposure: 'external', criticality: 'high' })).status, 409);
  const v = (await S.get('/apppt', VIEW)).json;
  const pa = v.apps.find((x) => x.id === a.id), pb = v.apps.find((x) => x.id === b.id);
  assert.equal(pa.cadence_days, 90); assert.equal(pb.cadence_days, 180); assert.ok(pa.never_tested && pa.test_overdue && pa.next_due === '2026-10-28');
  assert.equal(pa.risk_why.overdue_points, 10, 'an overdue test adds itemised points');
  assert.equal(v.kpis.never_tested, 2); assert.ok(v.attention.some((x) => /never been pen tested/.test(x.text)));
  assert.equal(S.audits('apppt.target.create').length, 2);
});

test('engagement lifecycle: four-eyes scope, window enforced, coverage before the report, note to close with open findings', async (t) => {
  const S = await setup(t); const a = await S.mkApp('Customer portal synthetic');
  let r = await S.post('/apppt/engagements', { title: 'x', target_ids: [a.id], approach: 'grey_box', tester: 't', window_start: '2026-11-10', window_end: '2026-11-01', rules: 'rules of engagement' }); assert.equal(r.status, 400); assert.match(r.json.error, /before window_start/);
  r = await S.post('/apppt/engagements', { title: 'x', target_ids: [a.id], approach: 'grey_box', tester: 't', window_start: '2026-11-01', window_end: '2027-02-01', rules: 'rules of engagement' }); assert.match(r.json.error, /at most 60 days/);
  r = await S.post('/apppt/engagements', { title: 'x', target_ids: ['PTA-9999'], approach: 'grey_box', tester: 't', window_start: '2026-11-01', window_end: '2026-11-02', rules: 'rules of engagement' }); assert.equal(r.status, 404);
  const g = await S.mkEng([a.id]);
  assert.equal((await S.post('/apppt/engagements/' + g.id + '/state', { state: 'testing' })).status, 409, 'no testing before the scope is approved');
  await S.post('/apppt/engagements/' + g.id + '/scope', {});
  assert.equal((await S.post('/apppt/engagements/' + g.id, { title: 'changed' })).status, 409, 'the scope is frozen once requested');
  r = await S.post('/apppt/engagements/' + g.id + '/scope/decide', { decision: 'approve' }, OP2); assert.equal(r.status, 403); assert.match(r.json.error, /CISO/);
  S.e.app.store.collection('ecc_profile').put({ id: 'profile', ciso_user: 'nora.syn' });
  r = await S.post('/apppt/engagements/' + g.id + '/scope/decide', { decision: 'approve' }, OP); assert.equal(r.status, 403); assert.match(r.json.error, /four eyes/);
  assert.equal((await S.post('/apppt/engagements/' + g.id + '/scope/decide', { decision: 'reject' }, ADM)).status, 400, 'a rejection needs a note');
  assert.equal((await S.post('/apppt/engagements/' + g.id + '/scope/decide', { decision: 'approve' }, ADM)).json.state, 'approved');
  r = await S.post('/apppt/engagements/' + g.id + '/state', { state: 'testing' }); assert.equal(r.status, 409); assert.match(r.json.error, /only between 2026-10-29 and 2026-11-10/);
  S.tick(DAY); assert.equal((await S.post('/apppt/engagements/' + g.id + '/state', { state: 'testing' })).json.state, 'testing');
  await S.find(g.id, a.id);
  r = await S.post('/apppt/engagements/' + g.id + '/state', { state: 'reported' }); assert.equal(r.status, 409); assert.match(r.json.error, /decide every testing area/);
  await S.coverAll(g.id);
  assert.equal((await S.post('/apppt/engagements/' + g.id + '/state', { state: 'reported' })).json.state, 'reported');
  assert.equal((await S.post('/apppt/engagements/' + g.id + '/state', { state: 'closed' })).status, 400, 'open findings: a note is required');
  assert.equal((await S.post('/apppt/engagements/' + g.id + '/state', { state: 'closed', note: 'carried to the Q1 remediation plan' })).json.state, 'closed');
  const v = (await S.get('/apppt', VIEW)).json, pa = v.apps.find((x) => x.id === a.id);
  assert.equal(pa.last_report.slice(0, 10), '2026-10-29'); assert.equal(pa.next_due, '2027-01-27'); assert.equal(pa.test_overdue, false);
  assert.deepEqual(pa.coverage_gaps, [], 'every area tested or n/a in the last 12 months');
  for (const a2 of ['apppt.engagement.create', 'apppt.engagement.scope_request', 'apppt.engagement.scope_approve', 'apppt.engagement.testing', 'apppt.engagement.reported', 'apppt.engagement.closed', 'apppt.engagement.coverage']) assert.ok(S.audits(a2).length, a2 + ' audited');
});

test('findings: CWE → OWASP, scope, duplicates; a fix verified only by another person\'s retest; failed retest counted; regression; risk acceptance', async (t) => {
  const S = await setup(t); const a = await S.mkApp('Customer portal synthetic'), b = await S.mkApp('Broker portal synthetic'), c = await S.mkApp('Quote API synthetic', { kind: 'api' });
  const g = await S.mkEng([a.id, b.id]); await S.startTesting(g.id);
  let r = await S.find(g.id, c.id); assert.equal(r.status, 400); assert.match(r.json.error, /not in the scope/);
  r = await S.find(g.id, a.id); assert.equal(r.status, 200); const f = r.json; assert.equal(f.category, 'A03', 'CWE-79 maps to A03 Injection');
  assert.equal((await S.find(g.id, a.id)).status, 409, 'same finding twice');
  r = await S.find(g.id, a.id, { title: 'x', severity: 'urgent' }); assert.equal(r.status, 400); assert.match(r.json.error, /severity/);
  assert.equal((await S.post('/apppt/findings/' + f.id + '/action', { action: 'claim_fix' })).status, 400, 'a fix claim needs a note');
  assert.equal((await S.post('/apppt/findings/' + f.id + '/action', { action: 'claim_fix', note: 'CHG-SYN-1 output encoding' })).json.status, 'fix_claimed');
  r = await S.post('/apppt/findings/' + f.id + '/action', { action: 'retest_pass', note: 'payload is encoded' }); assert.equal(r.status, 403); assert.match(r.json.error, /four eyes/);
  r = await S.post('/apppt/findings/' + f.id + '/action', { action: 'retest_fail', note: 'still executes in the PDF export' }, OP2); assert.equal(r.json.status, 'open'); assert.equal(r.json.retest_failures, 1);
  await S.post('/apppt/findings/' + f.id + '/action', { action: 'claim_fix', note: 'CHG-SYN-2 PDF export encoded' });
  r = await S.post('/apppt/findings/' + f.id + '/action', { action: 'retest_pass', note: 'payload encoded in page and PDF' }, OP2); assert.equal(r.json.status, 'verified'); assert.equal(r.json.verified_by, 'omar.syn');
  // the same weakness in a later engagement is a regression
  S.tick(5 * DAY); const g2 = await S.mkEng([a.id], { title: 'Retest round (synthetic)', window_start: '2026-11-02', window_end: '2026-11-20' }); await S.startTesting(g2.id);
  r = await S.find(g2.id, a.id, { endpoint: '/claims/notes/v2' }); assert.equal(r.json.regression_of, f.id);
  // risk acceptance: four eyes, ≤ 180 days
  const h = (await S.find(g.id, b.id, { title: 'Missing HSTS header', severity: 'low', cwe: 'CWE-319' })).json;
  assert.equal((await S.post('/apppt/findings/' + h.id + '/accept', { reason: 'legacy load balancer, replaced in Q1', until: '2027-09-01' })).status, 400);
  await S.post('/apppt/findings/' + h.id + '/accept', { reason: 'legacy load balancer, replaced in Q1', until: '2027-01-31' });
  assert.equal((await S.post('/apppt/findings/' + h.id + '/accept/decide', { decision: 'approve' }, OP2)).status, 403);
  assert.equal((await S.post('/apppt/findings/' + h.id + '/accept/decide', { decision: 'approve' }, ADM)).json.status, 'accepted');
  for (const a2 of ['apppt.finding.create', 'apppt.finding.claim_fix', 'apppt.finding.retest_fail', 'apppt.finding.retest_pass', 'apppt.finding.accept_request', 'apppt.finding.accept_approve']) assert.ok(S.audits(a2).length, a2 + ' audited');
  // a viewer sees what and how bad, not where or how
  const vf = (await S.get('/apppt/engagements/' + g.id, VIEW)).json;
  assert.ok(vf.findings.length && vf.findings.every((x) => x.endpoint === undefined && x.steps === undefined)); assert.match(vf.rules, /operators and administrators/);
  const of = (await S.get('/apppt/engagements/' + g.id, OP)).json; assert.ok(of.findings.some((x) => x.endpoint)); assert.match(of.rules, /tester1/);
});

test('imports: OWASP ZAP JSON and Burp XML - informational skipped, CWE mapped, evidence secrets masked, DOCTYPE refused, wrong format named', async (t) => {
  const S = await setup(t); const a = await S.mkApp('Customer portal synthetic'); const g = await S.mkEng([a.id]); await S.startTesting(g.id);
  const Z = zap([za('SQL Injection', 3, 89, 'https://portal.synthetic.test/search?q=1', { instances: [{ uri: 'https://portal.synthetic.test/search', method: 'GET', param: 'q', evidence: 'Authorization: Bearer ' + TOKEN }] }), za('Cookie No HttpOnly Flag', 1, 1004, 'https://portal.synthetic.test/'), za('Server Leaks Version', 0, 200, 'https://portal.synthetic.test/')]);
  let r = await S.post('/apppt/engagements/' + g.id + '/import', { target_id: a.id, filename: 'zap.json', content: Z });
  assert.equal(r.status, 200); assert.equal(r.json.added, 2); assert.equal(r.json.informational_skipped, 1);
  const v = (await S.get('/apppt/engagements/' + g.id, OP)).json, sq = v.findings.find((x) => /SQL/.test(x.title));
  assert.equal(sq.severity, 'high'); assert.equal(sq.category, 'A03'); assert.equal(v.findings.find((x) => /HttpOnly/.test(x.title)).category, 'A05');
  assert.ok(!JSON.stringify(v).includes(TOKEN), 'a token in the evidence is never kept');
  assert.equal((await S.post('/apppt/engagements/' + g.id + '/import', { target_id: a.id, filename: 'zap.json', content: Z })).json.duplicates, 2, 'importing again adds nothing');
  const burp = '<?xml version="1.0"?><issues burpVersion="2024.1"><issue><name>Cross-site scripting (reflected)</name><host ip="10.0.0.1">https://portal.synthetic.test</host><path><![CDATA[/search]]></path><location>/search [q parameter]</location><severity>High</severity><confidence>Certain</confidence><issueBackground><![CDATA[<p>synthetic</p>]]></issueBackground><vulnerabilityClassifications><![CDATA[<a href="https://cwe.mitre.org/data/definitions/79.html">CWE-79</a>]]></vulnerabilityClassifications></issue><issue><name>TLS cookie</name><host>https://portal.synthetic.test</host><path>/</path><severity>Information</severity></issue></issues>';
  r = await S.post('/apppt/engagements/' + g.id + '/import', { target_id: a.id, filename: 'burp.xml', content: burp }); assert.equal(r.json.added, 1); assert.equal(r.json.informational_skipped, 1);
  r = await S.post('/apppt/engagements/' + g.id + '/import', { target_id: a.id, filename: 'b.xml', content: '<!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><issues><issue><name>&e;</name></issue></issues>' }); assert.equal(r.status, 400); assert.match(r.json.error, /DOCTYPE/);
  r = await S.post('/apppt/engagements/' + g.id + '/import', { target_id: a.id, filename: 'x.json', content: '{"runs":[]}' }); assert.equal(r.status, 400); assert.match(r.json.error, /OWASP ZAP/);
  r = await S.post('/apppt/engagements/' + g.id + '/import', { target_id: a.id, filename: 'x.csv', content: 'a' }); assert.equal(r.status, 400); assert.match(r.json.error, /filename/);
  assert.equal((await S.post('/apppt/engagements/' + g.id + '/import', { target_id: a.id, filename: 'zap.json', content: Z }, VIEW)).status, 403);
  assert.ok(S.audits('apppt.import').length >= 2);
  // the parsers on their own
  assert.equal(parseZap(JSON.parse(Z)).findings[0].cwe, 'CWE-89'); assert.equal(parseBurp(burp).findings[0].cwe, 'CWE-79');
});

test('learning: systemic weakness on two applications, SLA miss chance after 5 fixes, retest failure rate from 3 claims; export audited', async (t) => {
  const S = await setup(t); const a = await S.mkApp('Customer portal synthetic'), b = await S.mkApp('Broker portal synthetic');
  const g = await S.mkEng([a.id, b.id]); await S.startTesting(g.id);
  await S.find(g.id, a.id, { title: 'IDOR on claim documents', severity: 'critical', cwe: 'CWE-639', endpoint: '/docs/1' });
  await S.find(g.id, b.id, { title: 'IDOR on policy documents', severity: 'high', cwe: 'CWE-639', endpoint: '/policy/docs/2' });
  let v = (await S.get('/apppt')).json;
  const sy = v.systemic.find((x) => x.category === 'A01'); assert.ok(sy && sy.apps.length === 2, 'the same weakness on two applications is systemic');
  const open0 = v.findings.find((x) => x.open); assert.equal(open0.miss.p, null); assert.match(open0.miss.why, /needs 5 verified fixes/);
  // five verified fixes (two failed retests among the claims), then the model speaks
  for (let i = 0; i < 5; i++) {
    const f = (await S.find(g.id, a.id, { title: 'Header issue ' + i, severity: 'medium', cwe: 'CWE-693', endpoint: '/h' + i })).json;
    await S.post('/apppt/findings/' + f.id + '/action', { action: 'claim_fix', note: 'CHG-SYN-' + i });
    if (i < 2) { await S.post('/apppt/findings/' + f.id + '/action', { action: 'retest_fail', note: 'still missing' }, OP2); await S.post('/apppt/findings/' + f.id + '/action', { action: 'claim_fix', note: 'again' }); }
    S.tick((10 + i) * DAY); await S.post('/apppt/findings/' + f.id + '/action', { action: 'retest_pass', note: 'header present' }, OP2);
  }
  v = (await S.get('/apppt')).json;
  assert.ok(v.findings.filter((x) => x.open).every((x) => typeof x.miss.p === 'number'), 'SLA miss chance once 5 fixes are verified');
  const rf = v.learning.retest_failure.find((x) => x.owner === 'digital.syn'); assert.equal(rf.claims, 7); assert.equal(rf.failed, 2); assert.equal(rf.p_fail, Math.round((3 / 9) * 100) / 100);
  assert.equal(v.learning.median_days_to_verified_fix.medium != null, true);
  const pa = v.apps.find((x) => x.id === a.id); assert.ok(pa.risk_why.top.length && pa.risk_why.multiplier === 2.1, 'risk itemised: critical x external');
  assert.equal((await S.get('/apppt/export', VIEW)).status, 403);
  const x = (await S.get('/apppt/export')).json; assert.ok(x.rows.length >= 7 && x.columns.includes('Regression of')); assert.ok(S.audits('apppt.export').length);
  assert.equal((await S.post('/apppt/settings', { sla_high: 20 }, OP)).status, 403);
  assert.equal((await S.post('/apppt/settings', { cadence_high: 10 }, ADM)).status, 400);
  assert.equal((await S.post('/apppt/settings', { sla_high: 20 }, ADM)).json.sla_high, 20); assert.ok(S.audits('apppt.settings').length);
  assert.equal((await S.post('/apppt/ask', { question: 'what first?' }, OP)).status, 424, 'AI off until it is allowed and has a key');
  assert.equal((await S.post('/apppt/ask', { question: 'what first?' }, VIEW)).status, 403);
});
