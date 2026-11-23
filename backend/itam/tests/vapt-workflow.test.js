// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// VAPT & Penetration Testing Workflow (engine/vapt-workflow.js) with SYNTHETIC data: one engagement from scoping to the signed
// report - validation errors (scope, window, third-party tester, checklist, out-of-scope host, credential in evidence), roles
// (viewer sees counts only, operator works, admin authorises / issues, a service identity never acts), four eyes (the requester or
// the authoriser never approves, a false positive / risk acceptance is decided by a second person, the owner never retests, the
// author never signs off), scanner findings imported for the hosts in scope and verified fixed only by a later scan, the stage
// machine and next step, the risk rating, SLA, recurrence across engagements, the report (escaped, SHA-256, versions) and the audit.
const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('crypto');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');
const VIEW = { user: 'vera.syn', role: 'viewer' }, OP = { user: 'tester.syn', role: 'operator' }, OP2 = { user: 'owner.syn', role: 'operator' }, OP3 = { user: 'qa.syn', role: 'operator' };
const ADM = { user: 'syed', role: 'admin' }, ADM2 = { user: 'amal.syn', role: 'admin' }, BOT = { user: 'ai:pentest', role: 'admin' };
const DAY = 86400000, XSS = '<img src=x onerror=alert(1)>';

test('VAPT workflow: scoping to signed report, roles, four eyes, scanner verification, report, audit', async (t) => {
  let T = Date.parse('2026-11-22T08:00:00Z');
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true, now: () => T, python: process.env.PYTHON || 'python3' });
  const call = (m, p, b, who) => e.req(m, p, Object.assign(b !== undefined ? { body: b } : {}, who || ADM));
  const d0 = new Date(T).toISOString().slice(0, 10), d14 = new Date(T + 14 * DAY).toISOString().slice(0, 10);
  // scanner findings, read through the VAPT Center (stubbed: the real one needs live scanners)
  let G = [{ src: 'greenbone', id: 'gb-1', host: '10.0.6.7', title: 'OpenSSH remote code execution', severity: 'critical', cvss: 9.8, cves: ['CVE-2024-6387'], status: 'open' },
    { src: 'greenbone', id: 'gb-2', host: '10.9.9.9', title: 'Out of scope host', severity: 'high', status: 'open' },
    { src: 'tenable', id: 'tn-1', host: '10.0.5.10', title: 'TLS 1.0 enabled', severity: 'medium', status: 'open' }];
  e.app.addons.vaptCenter = Object.assign({}, e.app.addons.vaptCenter || {}, { gather: async () => ({ findings: G.map((x) => Object.assign({}, x)), status: { greenbone: { ok: true } } }), slaDays: () => ({ critical: 7, high: 30, medium: 90, low: 180 }) });

  const scope = { name: 'Q4 internal VAPT (synthetic)', kind: 'internal_vapt', targets: ['10.0.5.10', '10.0.6.0/24', 'portal.syn.local'], out_of_scope: ['10.0.6.99'], window_start: d0, window_end: d14, objectives: 'Core network', emergency_contact: 'NOC +966-000 (synthetic)' };
  // validation
  assert.equal((await call('POST', '/vapt-workflow', Object.assign({}, scope, { targets: undefined }), OP)).status, 400);
  let r = await call('POST', '/vapt-workflow', Object.assign({}, scope, { tester_type: 'third_party' }), OP); assert.equal(r.status, 400); assert.match(r.json.error, /tester_org/);
  r = await call('POST', '/vapt-workflow', Object.assign({}, scope, { window_end: '2027-06-01' }), OP); assert.equal(r.status, 400); assert.match(r.json.error, /90 days/);
  assert.equal((await call('POST', '/vapt-workflow', scope, VIEW)).status, 403, 'a viewer cannot request');
  assert.equal((await call('POST', '/vapt-workflow', scope, BOT)).status, 403, 'a service identity cannot request');
  r = await call('POST', '/vapt-workflow', Object.assign({}, scope, { role_hack: 'admin' }), OP); assert.equal(r.status, 200, r.text);
  const id = r.json.engagement.id; assert.match(id, /^VA-2026-\d{3}$/); assert.equal(r.json.engagement.role_hack, undefined, 'undeclared field dropped');
  assert.equal(r.json.stage, 'authorisation'); assert.equal(r.json.engagement.lead, 'tester.syn');
  // viewer: counts only
  r = await call('GET', '/vapt-workflow', undefined, VIEW); assert.equal(r.status, 200); assert.equal(r.json.kpi.engagements, 1); assert.equal(r.json.engagements, undefined);
  assert.equal((await call('GET', '/vapt-workflow/' + id, undefined, VIEW)).status, 403);
  // nothing tested before approval
  r = await call('POST', '/vapt-workflow/' + id + '/findings', { title: 'x finding', severity: 'low', host: '10.0.5.10', evidence: 'seen' }, OP); assert.equal(r.status, 409);
  // authorise
  assert.equal((await call('POST', '/vapt-workflow/' + id + '/authorise', { checklist: {} }, OP)).status, 403);
  r = await call('POST', '/vapt-workflow/' + id + '/authorise', { checklist: { roe_signed: true, soc_notified: true } }, ADM); assert.equal(r.status, 400); assert.match(r.json.error, /Backups/);
  r = await call('POST', '/vapt-workflow/' + id + '/authorise', { checklist: { roe_signed: true, soc_notified: true, backups_confirmed: true, emergency_contact: true, change_ref: 'CHG-1001' } }, ADM); assert.equal(r.status, 200, r.text);
  assert.equal(r.json.stage, 'approval');
  // four eyes
  assert.equal((await call('POST', '/vapt-workflow/' + id + '/approve', {}, ADM)).status, 403, 'the authoriser cannot approve');
  assert.equal((await call('POST', '/vapt-workflow/' + id + '/approve', {}, Object.assign({}, OP, { role: 'admin' }))).status, 403, 'the requester cannot approve');
  assert.equal((await call('POST', '/vapt-workflow/' + id + '/approve', {}, BOT)).status, 403);
  r = await call('POST', '/vapt-workflow/' + id + '/approve', {}, ADM2); assert.equal(r.status, 200, r.text); assert.equal(r.json.stage, 'testing');
  assert.equal((await call('POST', '/vapt-workflow/' + id + '/scope', { name: 'changed name here' }, OP)).status, 409, 'approved scope is frozen');
  // testing: manual findings, tool run, import
  r = await call('POST', '/vapt-workflow/' + id + '/findings', { title: 'Admin panel ' + XSS, severity: 'high', host: '10.0.9.1', evidence: 'screenshot ref S-1' }, OP); assert.equal(r.status, 400); assert.match(r.json.error, /not in the engagement scope/);
  r = await call('POST', '/vapt-workflow/' + id + '/findings', { title: 'Admin panel ' + XSS, severity: 'high', host: '10.0.6.99', evidence: 'screenshot' }, OP); assert.equal(r.status, 400, 'out of scope wins over a range');
  r = await call('POST', '/vapt-workflow/' + id + '/findings', { title: 'Default creds', severity: 'high', host: 'portal.syn.local', evidence: 'password=Synthetic123' }, OP); assert.equal(r.status, 400); assert.match(r.json.error, /credential/);
  r = await call('POST', '/vapt-workflow/' + id + '/findings', { title: 'Weak', severity: 'low', host: 'portal.syn.local', evidence: 'ref', cves: ['nope'] }, OP); assert.equal(r.status, 400);
  r = await call('POST', '/vapt-workflow/' + id + '/findings', { title: 'Admin panel ' + XSS, severity: 'high', cvss: 8.1, host: 'portal.syn.local', evidence: 'screenshot ref S-1 (synthetic)', fix: 'Restrict to VPN', technique: 'T1190', exposure: 'internet' }, OP); assert.equal(r.status, 200, r.text);
  r = await call('POST', '/vapt-workflow/' + id + '/findings', { title: 'Directory listing', severity: 'low', host: '10.0.6.20', evidence: 'listing at /backup (synthetic)' }, OP); assert.equal(r.status, 200);
  r = await call('POST', '/vapt-workflow/' + id + '/tool-run', { tool: 'Burp Suite (synthetic)', ran_on: d0 }, OP); assert.equal(r.status, 200);
  r = await call('POST', '/vapt-workflow/' + id + '/import', {}, OP); assert.equal(r.status, 200, r.text); assert.equal(r.json.imported, 2, 'only the hosts in scope');
  r = await call('POST', '/vapt-workflow/' + id + '/import', {}, OP); assert.equal(r.json.imported, 0); assert.equal(r.json.already, 2, 'imported once');
  assert.equal((await call('POST', '/vapt-workflow/' + id + '/report', { kind: 'final' }, OP)).status, 409, 'no final report before testing is complete');
  r = await call('POST', '/vapt-workflow/' + id + '/report', { kind: 'interim' }, OP); assert.equal(r.status, 200); assert.equal(r.json.reports[0].kind, 'interim');
  assert.equal((await call('POST', '/vapt-workflow/' + id + '/testing-done', {}, OP2)).status, 403, 'only the lead or an admin');
  r = await call('POST', '/vapt-workflow/' + id + '/testing-done', {}, OP); assert.equal(r.status, 200); assert.equal(r.json.stage, 'validation');
  const F = (v, re) => v.findings.find((f) => re.test(f.title));
  // validation
  let v = r.json; const crit = F(v, /OpenSSH/), tls = F(v, /TLS/), adm = F(v, /Admin panel/), dir = F(v, /Directory/);
  assert.equal(v.findings[0].severity, 'critical', 'sorted by severity');
  const vp = (f) => '/vapt-workflow/' + id + '/findings/' + f.id;
  assert.equal((await call('POST', vp(dir) + '/validate', { result: 'false_positive', note: 'short' }, OP)).status, 400);
  r = await call('POST', vp(dir) + '/validate', { result: 'false_positive', note: '/backup is an empty placeholder by design' }, OP); assert.equal(r.status, 200);
  assert.equal((await call('POST', vp(dir) + '/decide', { decision: 'approve' }, Object.assign({}, OP, { role: 'admin' }))).status, 403, 'the requester never decides');
  r = await call('POST', vp(dir) + '/decide', { decision: 'approve' }, ADM); assert.equal(r.status, 200);
  for (const f of [crit, tls, adm]) { r = await call('POST', vp(f) + '/validate', { result: 'confirmed' }, OP); assert.equal(r.status, 200); }
  assert.equal(r.json.stage, 'remediation'); assert.equal(r.json.analysis.false_positive, 1);
  assert.ok(r.json.analysis.risk >= 40, 'critical RCE + internet-facing high: ' + r.json.analysis.risk); assert.ok(r.json.analysis.risk_why.some((w) => /exploit named/.test(w)));
  // remediation: owner + SLA due + GRC action when the register is installed
  r = await call('POST', vp(crit) + '/remediate', { owner: 'owner.syn' }, OP); assert.equal(r.status, 200, r.text);
  let cf = F(r.json, /OpenSSH/); assert.equal(cf.due, new Date(Date.parse(cf.created_at) + 7 * DAY).toISOString().slice(0, 10), 'critical: 7-day SLA');
  if (e.app.addons.grcRegisters) assert.match(cf.grc_action, /^ACT-/);
  for (const f of [tls, adm]) assert.equal((await call('POST', vp(f) + '/remediate', { owner: 'owner.syn', due: d14 }, OP)).status, 200);
  assert.equal((await call('POST', vp(tls) + '/remediate', { owner: 'bad name!' }, OP)).status, 400);
  // retest: manual finding needs an independent person; scanner finding needs a later scan
  r = await call('POST', vp(adm) + '/fixed', { note: 'restricted to VPN' }, OP2); assert.equal(r.status, 200); assert.equal(r.json.stage, 'retest');
  assert.equal((await call('POST', vp(adm) + '/retest', { result: 'pass', evidence: 'checked' }, OP2)).status, 403, 'the owner never retests');
  r = await call('POST', vp(adm) + '/retest', { result: 'fail', evidence: 'still reachable from the internet' }, OP3); assert.equal(F(r.json, /Admin panel/).state, 'open'); assert.equal(F(r.json, /Admin panel/).reopened, 1);
  await call('POST', vp(adm) + '/fixed', { note: 'firewall rule added' }, OP2);
  r = await call('POST', vp(adm) + '/retest', { result: 'pass', evidence: 'not reachable from outside (synthetic)' }, OP3); assert.equal(F(r.json, /Admin panel/).state, 'verified');
  await call('POST', vp(crit) + '/fixed', { note: 'patched OpenSSH' }, OP2);
  r = await call('GET', '/vapt-workflow/' + id, undefined, OP); assert.equal(F(r.json, /OpenSSH/).state, 'fix_claimed', 'a claim is not a fix');
  T += DAY; G = G.map((x) => (x.id === 'gb-1' ? Object.assign({}, x, { status: 'fixed', fixed_at: new Date(T).toISOString() }) : x));
  r = await call('GET', '/vapt-workflow/' + id, undefined, OP); assert.equal(F(r.json, /OpenSSH/).state, 'verified'); assert.equal(F(r.json, /OpenSSH/).verified_how, 'rescan');
  // risk acceptance: four eyes
  assert.equal((await call('POST', vp(tls) + '/accept', { reason: 'legacy printer', until: '2028-01-01' }, OP)).status, 400, 'at most a year');
  r = await call('POST', vp(tls) + '/accept', { reason: 'legacy device, replacement ordered', until: '2027-03-31' }, OP2); assert.equal(r.status, 200);
  assert.equal((await call('POST', vp(tls) + '/decide', { decision: 'approve' }, Object.assign({}, OP2, { role: 'admin' }))).status, 403);
  r = await call('POST', vp(tls) + '/decide', { decision: 'approve', note: 'until replacement' }, ADM2); assert.equal(r.status, 200); assert.equal(r.json.stage, 'report');
  // final report, issue, sign-off
  r = await call('POST', '/vapt-workflow/' + id + '/report', { kind: 'final' }, OP); assert.equal(r.status, 200, r.text);
  const rep = r.json.reports.find((x) => x.kind === 'final'); assert.equal(rep.version, 2); assert.equal(rep.status, 'draft');
  r = await call('GET', '/vapt-workflow/' + id + '/report/2?format=html', undefined, OP); assert.equal(r.status, 200);
  assert.ok(!r.json.html.includes(XSS) && r.json.html.includes('&lt;img'), 'finding text escaped in the report');
  assert.equal(crypto.createHash('sha256').update(r.json.html).digest('hex'), rep.sha256);
  for (const re of [/Executive summary/, /CHG-1001/, /amal\.syn/, /3\.3\.11/, /2-11/, /A\.8\.8/, /verified by rescan/, /Risk accepted until 2027-03-31/, /Burp Suite/]) assert.match(r.json.html, re);
  r = await call('GET', '/vapt-workflow/' + id + '/report/2?format=csv', undefined, OP); assert.match(r.json.csv, /OpenSSH/); assert.ok(!/\n=/.test(r.json.csv));
  assert.equal((await call('POST', '/vapt-workflow/' + id + '/report/2/issue', {}, OP)).status, 403);
  assert.equal((await call('POST', '/vapt-workflow/' + id + '/signoff', { statement: 'accepted for the board' }, ADM2)).status, 409, 'not issued yet');
  r = await call('POST', '/vapt-workflow/' + id + '/report/2/issue', {}, ADM); assert.equal(r.status, 200); assert.equal(r.json.stage, 'signoff');
  assert.equal((await call('POST', '/vapt-workflow/' + id + '/signoff', { statement: 'I sign off this report' }, Object.assign({}, OP, { role: 'admin' }))).status, 403, 'the author never signs off');
  r = await call('POST', '/vapt-workflow/' + id + '/signoff', { statement: 'Reviewed and accepted for the risk committee' }, ADM2); assert.equal(r.status, 200, r.text);
  assert.equal(r.json.stage, 'closed'); assert.equal(r.json.engagement.signed_sha256, rep.sha256);
  // recurrence: the same finding in a later engagement
  T += 10 * DAY; const d1 = new Date(T).toISOString().slice(0, 10);
  r = await call('POST', '/vapt-workflow', Object.assign({}, scope, { name: 'Q1 retest (synthetic)', window_start: d1, window_end: d1 }), OP); const id2 = r.json.engagement.id;
  await call('POST', '/vapt-workflow/' + id2 + '/authorise', { checklist: { roe_signed: true, soc_notified: true, backups_confirmed: true, emergency_contact: true, change_ref: 'CHG-1002' } }, ADM);
  await call('POST', '/vapt-workflow/' + id2 + '/approve', {}, ADM2);
  r = await call('POST', '/vapt-workflow/' + id2 + '/findings', { title: 'Admin panel ' + XSS, severity: 'high', host: 'portal.syn.local', evidence: 'again (synthetic)' }, OP);
  const f2 = r.json.findings[0]; r = await call('POST', '/vapt-workflow/' + id2 + '/findings/' + f2.id + '/validate', { result: 'confirmed' }, OP);
  assert.deepEqual(r.json.analysis.recurring, [f2.id], 'recurring across engagements'); assert.equal(r.json.analysis.cycle.withheld, true);
  r = await call('GET', '/vapt-workflow', undefined, OP); assert.equal(r.json.engagements.length, 2); assert.equal(r.json.kpi.closed, 1);
  // audit
  const au = e.app.store.auditTail(400).filter((a) => /^vaptwf\./.test(a.action));
  for (const a of ['create', 'authorise', 'approve', 'finding', 'import', 'validate', 'decide', 'remediate', 'retest', 'report', 'report.issue', 'signoff']) assert.ok(au.some((x) => x.action === 'vaptwf.' + a), 'audited: ' + a);
  assert.ok(au.some((x) => x.action === 'vaptwf.approve' && x.by === 'amal.syn' && x.target === id));
  assert.ok(!JSON.stringify(au).includes('Synthetic123'), 'no credential reaches the audit trail');
});
