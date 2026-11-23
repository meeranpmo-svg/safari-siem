// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const ZYB_ORG = require('../engine/brand');
// Mobile Application Testing (engine/mobile-test.js) through the real ITAM routes with SYNTHETIC MobSF reports: the parser maps findings to
// MASVS groups (the report's own tag first, else the section), masks secrets, drops info; an app registered (validation names the field,
// duplicate package refused); a report for another package or platform refused; the MASVS matrix (fail / partial / pass / not tested,
// L2 needs a manual check, resilience only with R); the release gate names each failed rule; build over build NEW / FIXED / REGRESSED;
// the group failure rate (Beta(1,1)) from 3 builds; risk itemised; risk acceptance four-eyes by the CISO / an admin, lifts the gate;
// roles (viewer sees counts, operator works, AI off until allowed); the audit records.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');
const { parseMobsf, groupOfTag } = require('../engine/mobile-test');

const ADM = { user: 'syed', role: 'admin' }, OP = { user: 'laila.syn', role: 'operator' }, OP2 = { user: 'adel.syn', role: 'operator' }, VIEW = { user: 'vera.syn', role: 'viewer' }, BOT = { user: 'ai:pentest', role: 'operator' };
const PKG = 'sa.corp.synthetic';
function report({ secret = true, storageHigh = true, network = true, version = '4.2.0', pkg = PKG, extra = [] } = {}) {
  const code = { 'android_logging': { files: {}, metadata: { description: 'App logs sensitive data (synthetic)', severity: 'info', masvs: 'MSTG-STORAGE-3', cwe: 'CWE-532' } } };
  if (storageHigh) code.android_world_readable = { files: {}, metadata: { description: 'World-readable file (synthetic)', severity: 'high', masvs: 'MSTG-STORAGE-2', cwe: 'CWE-276' } };
  code.weak_hash = { files: {}, metadata: { description: 'MD5 used (synthetic)', severity: 'warning', masvs: 'MSTG-CRYPTO-4', cwe: 'CWE-327' } };
  for (const e of extra) code[e] = { files: {}, metadata: { description: e + ' (synthetic)', severity: 'high', masvs: 'MSTG-CODE-8' } };
  return JSON.stringify({ app_name: (ZYB_ORG.short + ' (synthetic)'), version_name: version, package_name: pkg, file_name: 'app.apk', security_score: 48, code_analysis: { findings: code },
    manifest_analysis: { manifest_findings: [{ rule: 'debuggable', title: 'Debug enabled <img src=x onerror=alert(1)>', severity: 'high', description: 'android:debuggable=true' }] },
    network_security: { network_findings: network ? [{ scope: ['*'], description: 'Cleartext traffic allowed (synthetic)', severity: 'high' }] : [] },
    secrets: secret ? ['"google_api_key" : "AIzaSyNOTAREALKEY000000000000000000"'] : [],
    permissions: { 'android.permission.READ_CONTACTS': { status: 'dangerous', description: 'read contacts' }, 'android.permission.INTERNET': { status: 'normal' } },
    trackers: { trackers: [{ name: 'Synthetic Analytics', categories: 'Analytics' }] } });
}
async function setup(t) {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true, python: process.env.PYTHON || 'python3' });
  const call = (m, p, b, who) => e.req(m, p, Object.assign(b !== undefined ? { body: b } : {}, who));
  return { e, post: (p, b, who = OP) => call('POST', p, b, who), get: (p, who = OP) => call('GET', p, undefined, who), audit: (a) => e.app.store.auditTail(500).filter((x) => x.action === a) };
}

test('parser: MASVS group from the report tag or the section, secrets masked, info dropped', () => {
  assert.equal(groupOfTag('MSTG-STORAGE-14'), 'STORAGE'); assert.equal(groupOfTag('MASVS-NETWORK-1'), 'NETWORK'); assert.equal(groupOfTag('arch-1'), 'CODE'); assert.equal(groupOfTag('nothing'), null);
  const r = parseMobsf(JSON.parse(report()));
  assert.equal(r.package, PKG); assert.equal(r.platform, 'android'); assert.equal(r.version, '4.2.0');
  assert.ok(!r.findings.some((f) => /logs sensitive/.test(f.title)), 'info dropped');
  const sec = r.findings.find((f) => f.secret); assert.ok(sec && !JSON.stringify(sec).includes('AIzaSyNOTAREALKEY'), 'the secret value is masked'); assert.equal(sec.group, 'STORAGE');
  assert.equal(r.findings.find((f) => /World-readable/.test(f.title)).mapped, 'report');
  assert.equal(r.findings.find((f) => f.section === 'network').group, 'NETWORK'); assert.equal(r.findings.find((f) => f.section === 'permissions').group, 'PRIVACY');
  assert.throws(() => parseMobsf([]), /not a MobSF JSON report/);
});

test('apps, import, matrix, gate, diff, learning, four-eyes acceptance, roles, audit', async (t) => {
  const s = await setup(t);
  let r = await s.post('/mobile-test/apps', { name: (ZYB_ORG.short + ' Android'), platform: 'android', package: 'bad pkg!', criticality: 'critical', profile: 'L2' }); assert.equal(r.status, 400); assert.match(r.json.error, /package/);
  r = await s.post('/mobile-test/apps', { name: (ZYB_ORG.short + ' Android'), platform: 'android', package: PKG, criticality: 'critical', profile: 'L2' }, BOT); assert.equal(r.status, 403);
  r = await s.post('/mobile-test/apps', { name: (ZYB_ORG.short + ' Android'), platform: 'android', package: PKG, criticality: 'critical', profile: 'L2', resilience: true }); assert.equal(r.status, 200, r.raw); const A = r.json.id;
  assert.equal((await s.post('/mobile-test/apps', { name: 'dup', platform: 'android', package: PKG, criticality: 'low', profile: 'L1' })).status, 409);
  let v = (await s.get('/mobile-test')).json; assert.equal(v.kpis.never_tested, 1); assert.equal(v.apps[0].matrix.find((m) => m.group === 'STORAGE').status, 'not_tested'); assert.equal(v.apps[0].gate.go, false);
  r = await s.post('/mobile-test/apps/' + A + '/import', { filename: 'other.json', content: report({ pkg: 'com.other.app' }) }); assert.equal(r.status, 400); assert.match(r.json.error, /not sa\.corp/);
  r = await s.post('/mobile-test/apps/' + A + '/import', { filename: 'x.json', content: 'not json' }); assert.equal(r.status, 400); assert.match(r.json.error, /content/);
  r = await s.post('/mobile-test/apps/' + A + '/import', { filename: 'b1.json', content: report() }); assert.equal(r.status, 200, r.raw);
  v = (await s.get('/mobile-test')).json; let a = v.apps[0];
  const st = (g) => a.matrix.find((m) => m.group === g).status;
  assert.equal(st('STORAGE'), 'fail'); assert.equal(st('NETWORK'), 'fail'); assert.equal(st('CRYPTO'), 'partial'); assert.equal(st('AUTH'), 'partial', 'L2: scanned clean but no manual check'); assert.equal(st('RESILIENCE'), 'partial');
  assert.ok(a.gate.failed.some((x) => /hard-coded secret/.test(x)) && a.gate.failed.some((x) => /high finding\(s\) in STORAGE/.test(x)));
  assert.ok(a.risk > 0 && a.risk_items.some((i) => /open high/.test(i.what)));
  r = await s.post('/mobile-test/apps/' + A + '/verify', { group: 'AUTH', result: 'pass', note: 'short' }); assert.equal(r.status, 400); assert.match(r.json.error, /note/);
  r = await s.post('/mobile-test/apps/' + A + '/verify', { group: 'AUTH', result: 'pass', note: 'biometric binding and step-up verified on a device (synthetic)' }); assert.equal(r.status, 200);
  // build 2: secret and network fixed; build 3: network comes back = regression
  await s.post('/mobile-test/apps/' + A + '/import', { filename: 'b2.json', content: report({ secret: false, network: false, version: '4.2.1', extra: ['new_issue'] }) });
  a = (await s.get('/mobile-test')).json.apps[0]; assert.equal(a.matrix.find((m) => m.group === 'AUTH').status, 'pass'); assert.ok(a.diff.fixed >= 2 && a.diff.new >= 1);
  await s.post('/mobile-test/apps/' + A + '/import', { filename: 'b3.json', content: report({ secret: false, network: true, version: '4.2.2' }) });
  const d = (await s.get('/mobile-test/apps/' + A)).json;
  assert.equal(d.diff.regressed, 1); assert.ok(d.findings.find((f) => f.section === 'network').regressed); assert.ok(d.gate.failed.some((x) => /regression/.test(x)));
  assert.equal(d.matrix.find((m) => m.group === 'STORAGE').fail_rate, 80, '3 of 3 builds failed STORAGE: (3+1)/(3+2)');
  assert.ok(d.findings.some((f) => f.section === 'manifest' && /<img src=x/.test(f.title)), 'report text is kept as data - the page escapes it');
  // risk acceptance: four eyes
  const key = d.findings.find((f) => f.section === 'network').key;
  r = await s.post('/mobile-test/apps/' + A + '/accept', { key, reason: 'compensating control at the gateway (synthetic)', until: '2099-01-01' }); assert.equal(r.status, 400); assert.match(r.json.error, /until/);
  const until = new Date(Date.now() + 30 * 86400000).toISOString().slice(0, 10);
  r = await s.post('/mobile-test/apps/' + A + '/accept', { key, reason: 'compensating control at the gateway (synthetic)', until }); assert.equal(r.status, 200, r.raw); const X = r.json.id;
  assert.equal((await s.post('/mobile-test/accepts/' + X + '/decide', { decision: 'approve' }, OP2)).status, 403, 'an operator who is not the CISO cannot decide');
  assert.equal((await s.post('/mobile-test/accepts/' + X + '/decide', { decision: 'approve' }, { user: 'laila.syn', role: 'admin' })).status, 403, 'four-eyes: not the requester');
  r = await s.post('/mobile-test/accepts/' + X + '/decide', { decision: 'approve' }, ADM); assert.equal(r.status, 200);
  a = (await s.get('/mobile-test')).json.apps[0]; assert.ok(!a.gate.failed.some((x) => /regression/.test(x)), 'the accepted regression no longer blocks');
  for (const act of ['mobile-test.app.create', 'mobile-test.import', 'mobile-test.verify', 'mobile-test.accept.request', 'mobile-test.accept.approve']) assert.ok(s.audit(act).length, act);
  // roles
  const vv = (await s.get('/mobile-test', VIEW)); assert.equal(vv.status, 200); assert.equal(vv.json.can_details, false); assert.equal(vv.json.accepts.length, 0);
  assert.equal((await s.get('/mobile-test/apps/' + A, VIEW)).status, 403);
  assert.equal((await s.post('/mobile-test/ask', { question: 'what blocks the release?' })).status, 424, 'AI off until allowed');
  assert.equal((await s.post('/mobile-test/ask', { question: 'x' })).status, 400);
});
