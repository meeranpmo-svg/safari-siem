// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// The AI PDPL Consultant (engine/pdpl.js; the rules in Python - pyengine/pdpl_rules.py, run for real here): nothing is
// compliant on an empty register; the registers prove gaps (DSR past 30 days, breach not notified in 72 h, legitimate
// interest on health data, missing impact assessment, processor without agreement, transfer without basis); a gap
// overrides a person's "compliant" (conflict); confirmations need evidence / a note; the statement can be signed only when
// every requirement is confirmed and no serious finding is open, by the named DPO first, then a DIFFERENT person; a
// stale digest is refused; service identities refused; viewer refused the registers and sees no evidence; profile is
// admin-only; mass assignment dropped; every write audited; the duty desk raises the gaps. Data is SYNTHETIC.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');

const PY = process.env.PYTHON || 'python3';
let clock = Date.parse('2026-10-20T08:00:00Z');
const now = () => clock;
const day = (d) => new Date(clock - d * 86400000).toISOString().slice(0, 10);
async function setup(t) {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  const D = registerDuty(e.app.srv, e.app, { noTimer: true, now, python: PY });
  return { e, D };
}
const OP = { user: 'nora.syn', role: 'operator' }, ADM = { user: 'syed', role: 'admin' };
const post = (e, p, body, who = OP) => e.req('POST', p, Object.assign({ body }, who));
const reqOf = (v, id) => v.requirements.find((r) => r.id === id);

test('empty register: nothing compliant, everything not assessed or not tested; viewer refused the registers', async (t) => {
  const { e } = await setup(t);
  const v = (await e.req('GET', '/pdpl', { role: 'viewer' })).json;
  assert.equal(v.engine, 'python'); assert.equal(v.counts.compliant, 0); assert.equal(v.readiness.ready, false);
  assert.equal(reqOf(v, 'P-01').auto.state, 'not_tested'); assert.equal(typeof v.findings, 'number', 'viewer gets a count, not the findings');
  assert.match(v.note, /not an SDAIA certificate/);
  assert.equal((await e.req('GET', '/pdpl/records', { role: 'viewer' })).status, 403);
  assert.equal((await e.req('GET', '/pdpl/statement', { role: 'viewer' })).status, 403);
});

test('registers prove the gaps; a gap overrides a person; validation; profile admin-only; audit; duty desk', async (t) => {
  const { e, D } = await setup(t);
  // validation names the field; undeclared fields dropped
  let r = await post(e, '/pdpl/records', { kind: 'ropa' }); assert.equal(r.status, 400); assert.match(r.json.error, /name/);
  r = await post(e, '/pdpl/records', { kind: 'ropa', name: 'x', legal_basis: 'because' }); assert.equal(r.status, 400); assert.match(r.json.error, /legal_basis/);
  r = await post(e, '/pdpl/records', { kind: 'breach', ref: 'B1', aware_at: 'yesterday' }); assert.equal(r.status, 400); assert.match(r.json.error, /aware_at/);
  r = await post(e, '/pdpl/records', { kind: 'payroll' }); assert.equal(r.status, 400); assert.match(r.json.error, /kind/);
  assert.equal((await post(e, '/pdpl/records', { kind: 'profile', dpo_user: 'huda.syn' })).status, 403, 'operator cannot name the DPO');
  assert.equal((await post(e, '/pdpl/records', { kind: 'ropa', name: 'x' }, { user: 'v', role: 'viewer' })).status, 403);
  // claims processing: health data on legitimate interest, no LIA, no DPIA, no retention
  const ropa = (await post(e, '/pdpl/records', { kind: 'ropa', name: 'Motor & medical claims', purpose: 'Handle claims', legal_basis: 'legitimate_interest', data_categories: ['identity', 'health'], owner: 'Claims', sources: 2, reviewed: day(10), injected: 'x' })).json;
  assert.match(ropa.id, /^PD-ROPA-\d{3}$/); assert.equal(ropa.injected, undefined, 'mass assignment dropped');
  await post(e, '/pdpl/records', { kind: 'dsr', ref: 'DSR-SYN-1', type: 'access', received: day(45) });
  await post(e, '/pdpl/records', { kind: 'breach', ref: 'BR-SYN-1', aware_at: new Date(clock - 100 * 3600000).toISOString(), harm_likely: true, subjects_count: 12 });
  await post(e, '/pdpl/records', { kind: 'processor', name: 'SYN Cloud Backup', outside_ksa: true });
  await post(e, '/pdpl/records', { kind: 'profile', dpo_user: 'huda.syn', dpo_appointed: day(200), privacy_policy_url: 'https://example.invalid/privacy', privacy_policy_published: true, sdaia_registered: true, sdaia_ref: 'SYN-REG-1' }, ADM);
  const a = e.app.store.auditTail(20).filter((x) => x.action === 'pdpl.record.put');
  assert.ok(a.length >= 5 && a.some((x) => x.by === 'syed' && x.target === 'profile'));
  const v = (await e.req('GET', '/pdpl', OP)).json;
  const keys = v.findings.map((f) => f.key).join(' ');
  for (const k of ['P-06:lia:' + ropa.id + ':sensitive', 'P-06:lia:' + ropa.id + ':assessment', 'P-07:dpia:' + ropa.id, 'P-08:dsr:', 'P-09:breach:', 'P-10:proc:', 'P-11:transfer:unrecorded', 'P-12:retention:']) assert.ok(keys.includes(k), 'finding ' + k + ' in ' + keys);
  assert.equal(v.findings[0].severity, 'critical', 'worst first');
  assert.equal(reqOf(v, 'P-01').result, 'auto_pass'); assert.equal(reqOf(v, 'P-09').result, 'non_compliant');
  // a gap overrides a person
  const c = await post(e, '/pdpl/confirm', { id: 'P-09', status: 'compliant', evidence: 'breach procedure v3' });
  assert.equal(c.status, 200); assert.equal(c.json.result, 'non_compliant'); assert.equal(c.json.conflict, true);
  assert.ok(e.app.store.auditTail(5).some((x) => x.action === 'pdpl.confirm' && x.by === 'nora.syn' && x.target === 'P-09'));
  // confirmation validation and identities
  assert.match((await post(e, '/pdpl/confirm', { id: 'P-14', status: 'compliant' })).json.error, /evidence/);
  assert.match((await post(e, '/pdpl/confirm', { id: 'P-15', status: 'not_applicable' })).json.error, /note/);
  assert.equal((await post(e, '/pdpl/confirm', { id: 'P-99', status: 'compliant', evidence: 'x' })).status, 404);
  assert.equal((await post(e, '/pdpl/confirm', { id: 'P-14', status: 'compliant', evidence: 'x' }, { user: 'ai:grc', role: 'operator' })).status, 403);
  // the duty desk raises the gaps as work items for the consultant
  await D.patrol('pdpl');
  const items = D.list({ engineer: 'pdpl', status: 'open', limit: 100 }).items;
  assert.ok(items.some((x) => /legitimate interest for sensitive data/.test(x.title)) && items.length >= 8, items.length + ' work items');
  // fixing the register clears the finding at the next patrol
  const up = await post(e, '/pdpl/records', { kind: 'dsr', id: 'PD-DSR-001', responded: day(20) });
  assert.equal(up.status, 200, 'an update sends only what changes: ' + JSON.stringify(up.json)); assert.equal(up.json.received, day(45), 'the rest is kept');
  let v2 = (await e.req('GET', '/pdpl', OP)).json;
  assert.ok(!v2.findings.some((f) => /PD-DSR-001:late/.test(f.key)), 'answered on day 25: within 30 days, finding gone');
  await post(e, '/pdpl/records', { kind: 'dsr', id: 'PD-DSR-001', responded: day(5) });
  v2 = (await e.req('GET', '/pdpl', OP)).json;
  assert.ok(v2.findings.some((f) => /PD-DSR-001:late/.test(f.key)), 'answered on day 40: late');
  assert.equal((await post(e, '/pdpl/records', { kind: 'breach', id: 'PD-DSR-001', ref: 'x', aware_at: day(1) })).status, 400, 'kind must match the record');
});

test('statement: only when ready; DPO signs first, a different person countersigns; stale digest refused; lapses', async (t) => {
  const { e } = await setup(t);
  await post(e, '/pdpl/records', { kind: 'profile', dpo_user: 'huda.syn', dpo_appointed: day(200), privacy_policy_url: 'https://example.invalid/privacy', privacy_policy_published: true, sdaia_registered: true, sdaia_ref: 'SYN-REG-1' }, ADM);
  await post(e, '/pdpl/records', { kind: 'ropa', name: 'Policy administration', purpose: 'Issue policies', legal_basis: 'contract', data_categories: ['identity', 'contact'], owner: 'Operations', retention_months: 120, reviewed: day(30) });
  await post(e, '/pdpl/records', { kind: 'retention', name: 'Policy files', ropa_id: 'PD-ROPA-001', period_months: 120, trigger: 'policy_expiry', action: 'destroy' });
  let s = (await e.req('GET', '/pdpl/statement', OP)).json;
  assert.equal(s.ready, false); assert.ok(s.blockers.length > 10);
  assert.ok(e.app.store.auditTail(5).some((x) => x.action === 'pdpl.statement.view'));
  let r = await post(e, '/pdpl/statement/sign', { as: 'dpo', digest: s.digest }, { user: 'huda.syn', role: 'operator' });
  assert.equal(r.status, 409); assert.match(r.json.error, /not ready/);
  // confirm every requirement (synthetic evidence)
  const v = (await e.req('GET', '/pdpl', OP)).json;
  for (const q of v.requirements) {
    const res = await post(e, '/pdpl/confirm', ['P-15', 'P-22'].includes(q.id) ? { id: q.id, status: 'not_applicable', note: 'no credit data / no research use (synthetic)' } : { id: q.id, status: 'compliant', evidence: 'SYN-EV-' + q.id });
    assert.equal(res.status, 200, q.id + ' ' + JSON.stringify(res.json));
  }
  s = (await e.req('GET', '/pdpl/statement', OP)).json;
  assert.equal(s.ready, true, JSON.stringify(s.blockers)); assert.equal(s.compliance_pct, 100); assert.match(s.not_certificate, /not a certificate issued by SDAIA/);
  assert.equal((await post(e, '/pdpl/statement/sign', { as: 'dpo', digest: s.digest }, OP)).status, 403, 'only the named DPO signs as DPO');
  assert.equal((await post(e, '/pdpl/statement/sign', { as: 'management', digest: s.digest }, { user: 'cio.syn', role: 'admin' })).status, 409, 'DPO first');
  assert.equal((await post(e, '/pdpl/statement/sign', { as: 'dpo', digest: 'sha256:' + '0'.repeat(64) }, { user: 'huda.syn', role: 'operator' })).status, 409, 'stale digest');
  assert.equal((await post(e, '/pdpl/statement/sign', { as: 'dpo', digest: 'abc' }, { user: 'huda.syn', role: 'operator' })).status, 400);
  r = await post(e, '/pdpl/statement/sign', { as: 'dpo', digest: s.digest }, { user: 'huda.syn', role: 'operator' });
  assert.equal(r.status, 200); assert.equal(r.json.status, 'awaiting_management');
  assert.equal((await post(e, '/pdpl/statement/sign', { as: 'management', digest: s.digest }, { user: 'huda.syn', role: 'admin' })).status, 403, 'four-eyes: not the DPO again');
  assert.equal((await post(e, '/pdpl/statement/sign', { as: 'management', digest: s.digest }, { user: 'svc:board', role: 'admin' })).status, 403, 'no service identity');
  r = await post(e, '/pdpl/statement/sign', { as: 'management', digest: s.digest }, { user: 'cio.syn', role: 'admin' });
  assert.equal(r.status, 200); assert.equal(r.json.status, 'attested'); assert.ok(r.json.valid_until);
  const au = e.app.store.auditTail(10).map((x) => x.action);
  assert.ok(au.includes('pdpl.statement.sign_dpo') && au.includes('pdpl.statement.countersign'));
  // a new gap makes the signed statement lapse
  await post(e, '/pdpl/records', { kind: 'dsr', ref: 'DSR-SYN-9', type: 'copy', received: day(40) });
  assert.equal((await e.req('GET', '/pdpl', { role: 'viewer' })).json.statement.status, 'lapsed');
});
