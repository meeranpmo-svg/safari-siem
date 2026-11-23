// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Audit checklist by framework (engine/audit-checklist.js): every SAMA CSF domain, NCA ECC sub-domain and the IA view
// (SAMA baseline + IA-277) has at least one check; nothing is compliant without evidence (not assessed / automated pass
// awaiting confirmation); a failed AI auditor test makes the check non-compliant even over a person's "compliant" (shown
// as a conflict); assessments: validation names the field, evidence / note rules, viewer refused, a service identity
// refused, the audit record, viewer reads without evidence or names, 12-month expiry. Data is SYNTHETIC.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');
const { CHECKS, FW } = require('../engine/audit-checklist');

let clock = Date.parse('2026-10-20T08:00:00Z');
const now = () => clock;
async function setup(t) {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true, now });
  return e;
}

test('catalogue: every domain of SAMA CSF, NCA ECC and IA has a check; IDs unique; IA = SAMA + IA-277', () => {
  for (const f of ['sama', 'nca', 'ia']) for (const d of Object.keys(FW[f].domains)) assert.ok(CHECKS.some((c) => c[f].includes(d)), f + ' ' + d + ' has no check');
  assert.equal(new Set(CHECKS.map((c) => c.id)).size, CHECKS.length);
  for (const c of CHECKS) { assert.ok(c.procedure && c.evidence && c.title, c.id); for (const d of c.sama) assert.ok(FW.sama.domains[d], c.id + ' ' + d); for (const d of c.nca) assert.ok(FW.nca.domains[d], c.id + ' ' + d); }
  assert.ok(CHECKS.find((c) => c.id === 'AC-56').ia.includes('IA-277'));
});

test('nothing is compliant without evidence; a failed AI test is non-compliant over a person; conflict shown', async (t) => {
  const e = await setup(t);
  let v = (await e.req('GET', '/audit-checklist?fw=nca', { role: 'operator' })).json;
  assert.equal(v.counts.compliant, 0); assert.equal(v.counts.not_assessed, v.checks.length, 'fresh: every check not assessed');
  assert.ok(v.domains.every((d) => d.result === 'not_assessed'));
  // a four-eyes breach → IT-02 fails → AC-28 non-compliant
  e.app.store.collection('desk_patch').put({ id: 'PR-1', resource_id: 'r1', name: 'PC-SYN-1', state: 'deploying', requested_by: 'omar.syn', approved_by: 'omar.syn', approved_at: new Date(clock - 3600000).toISOString() });
  await e.app.addons.auditors.run('itaudit');
  const ok = await e.req('POST', '/audit-checklist/assess', { user: 'aud.syn', role: 'operator', body: { id: 'AC-28', status: 'compliant', evidence: 'CAB minutes Oct' } });
  assert.equal(ok.status, 200); assert.equal(ok.json.result, 'non_compliant'); assert.equal(ok.json.conflict, true); assert.match(ok.json.why, /IT-02/);
  // a manual assessment with no failing test stands
  const r2 = await e.req('POST', '/audit-checklist/assess', { user: 'aud.syn', role: 'operator', body: { id: 'AC-01', status: 'partial', evidence: 'charter v2; 3 of 4 meetings' } });
  assert.equal(r2.json.result, 'partial'); assert.equal(r2.json.conflict, false);
  v = (await e.req('GET', '/audit-checklist?fw=sama', { role: 'operator' })).json;
  assert.equal(v.domains.find((d) => d.code === '3.3.7').result, 'non_compliant');
  assert.equal(v.domains.find((d) => d.code === '3.1.1').result, 'not_assessed', 'AC-02 in the same domain is still not assessed: worst wins');
  assert.ok(v.compliance_pct > 0 && v.compliance_pct < 5);
  const ia = (await e.req('GET', '/audit-checklist?fw=ia', { role: 'viewer' })).json;
  assert.ok(ia.domains.find((d) => d.code === 'IA-277')); assert.match(ia.basis, /UTC\/277\/202401/);
  // 12 months later the assessment is due again
  clock += 366 * 86400000;
  const late = (await e.req('GET', '/audit-checklist?fw=sama', { role: 'operator' })).json.checks.find((c) => c.id === 'AC-01');
  assert.equal(late.result, 'not_assessed'); assert.match(late.why, /12 months/); assert.equal(late.assessment.expired, true);
});

test('assess: roles, validation, service identity refused, audit record, viewer sees no evidence or names', async (t) => {
  const e = await setup(t);
  assert.equal((await e.req('POST', '/audit-checklist/assess', { role: 'viewer', body: { id: 'AC-01', status: 'compliant', evidence: 'x' } })).status, 403);
  const b1 = await e.req('POST', '/audit-checklist/assess', { role: 'operator', body: { id: 'AC-01', status: 'compliant' } });
  assert.equal(b1.status, 400); assert.match(b1.json.error, /evidence/);
  const b2 = await e.req('POST', '/audit-checklist/assess', { role: 'operator', body: { id: 'AC-01', status: 'not_applicable' } });
  assert.equal(b2.status, 400); assert.match(b2.json.error, /note/);
  const b3 = await e.req('POST', '/audit-checklist/assess', { role: 'operator', body: { id: 'X-1', status: 'compliant', evidence: 'e' } });
  assert.equal(b3.status, 400); assert.match(b3.json.error, /id/);
  const b4 = await e.req('POST', '/audit-checklist/assess', { role: 'operator', body: { id: 'AC-01', status: 'great', evidence: 'e' } });
  assert.equal(b4.status, 400); assert.match(b4.json.error, /status/);
  assert.equal((await e.req('POST', '/audit-checklist/assess', { role: 'operator', body: { id: 'AC-99', status: 'compliant', evidence: 'e' } })).status, 404);
  assert.equal((await e.req('GET', '/audit-checklist?fw=iso', { role: 'viewer' })).status, 400);
  assert.equal((await e.req('POST', '/audit-checklist/assess', { user: 'ai:grc', role: 'operator', body: { id: 'AC-01', status: 'compliant', evidence: 'e' } })).status, 403);
  const ok = await e.req('POST', '/audit-checklist/assess', { user: 'aud.syn', role: 'admin', body: { id: 'AC-39', status: 'not_applicable', note: 'no card data is stored, processed or transmitted', extra: 'dropped' } });
  assert.equal(ok.status, 200); assert.equal(ok.json.result, 'not_applicable');
  const a = e.app.store.auditTail(10).find((x) => x.action === 'audit.checklist.assess');
  assert.ok(a && a.by === 'aud.syn' && a.role === 'admin' && a.target === 'AC-39' && a.detail.status === 'not_applicable');
  const v = (await e.req('GET', '/audit-checklist?fw=sama', { role: 'viewer' })).json.checks.find((c) => c.id === 'AC-39');
  assert.equal(v.assessment.status, 'not_applicable'); assert.equal(v.assessment.by, undefined); assert.equal(v.assessment.note, undefined);
});
