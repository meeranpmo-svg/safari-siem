// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const ZYB_ORG = require('../engine/brand');
// Risk & Control Hub (engine/risk-control.js) through the real routes on SYNTHETIC records: business hierarchy (cycle refused,
// delete refused while used), the control library (citations validated, policy checked, signal bound), independent control tests
// (owner refused, a failed test raises a GRC action), risk <-> control links and the CALCULATED residual (untested reduces
// nothing, effective reduces, the cap, the "claimed below" flag), KRIs (thresholds validated, breach audited, signal KRIs not
// typed), loss events (challenged controls), roll-ups per unit and framework, the acceptances register (expired), roles.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');

const VIEW = { user: 'vera.syn', role: 'viewer' }, OP = { user: 'nora.syn', role: 'operator' }, OP2 = { user: 'omar.syn', role: 'operator' }, ADM = { user: 'adam.syn', role: 'admin' };
const T0 = Date.parse('2026-11-09T08:00:00Z');

async function setup(t) {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true, now: () => T0, python: process.env.PYTHON || 'python3', acovLogCoverage: async () => ({ ok: true, assets: [] }), acovAvail: async () => ({ ok: true, hosts: {} }) });
  // Asset Coverage stub: EDR on 19 of 20 assets (95 % = effective), SIEM logs on 10 of 20 (ineffective)
  const rows = Array.from({ length: 20 }, (_, i) => ({ id: 'A' + i, controls: { edr: { state: i < 19 ? 'present' : 'missing' }, patch: { state: 'not_checked' }, backup: { state: 'na' }, vuln_scan: { state: 'present' }, siem_logs: { state: i < 10 ? 'present' : 'missing' } } }));
  e.app.addons.assetCoverage = { view: async () => ({ rows, sources: { edr: { ok: true }, patch: { ok: false, error: 'Endpoint Central not connected' }, backup: { ok: true }, vuln_scan: { ok: true }, siem_logs: { ok: true } } }) };
  const call = (m, p, b, who) => e.req(m, p, Object.assign(b !== undefined ? { body: b } : {}, who || OP));
  const risk = async (title, L, I, extra) => (await call('POST', '/grc/risks', Object.assign({ title, likelihood: L, impact: I, owner: 'risk.owner.syn' }, extra || {}))).json;
  return { e, call, risk };
}

test('hierarchy, control library, links and the calculated residual', async (t) => {
  const { e, call, risk } = await setup(t);
  // hierarchy (admin)
  assert.equal((await call('POST', '/rc/units', { name: (ZYB_ORG.short + ' (synthetic)'), kind: 'company' }, OP)).status, 403);
  const co = (await call('POST', '/rc/units', { name: (ZYB_ORG.short + ' (synthetic)'), kind: 'company' }, ADM)).json;
  let r = await call('POST', '/rc/units', { name: 'Claims', kind: 'division' }, ADM); assert.equal(r.status, 400, 'a division sits under a unit'); assert.match(r.text, /parent/);
  const claims = (await call('POST', '/rc/units', { name: 'Claims', kind: 'division', parent: co.id }, ADM)).json;
  const med = (await call('POST', '/rc/units', { name: 'Medical claims', kind: 'unit', parent: claims.id }, ADM)).json;
  r = await call('POST', '/rc/units', { id: claims.id, name: 'Claims', kind: 'division', parent: med.id }, ADM); assert.equal(r.status, 400, 'no cycles');
  // controls
  r = await call('POST', '/rc/controls', { title: 'EDR on every endpoint', type: 'preventive', nature: 'automated', frequency: 'continuous', citations: ['SAMA 3.3.6'] }); assert.equal(r.status, 400); assert.match(r.text, /citations/);
  r = await call('POST', '/rc/controls', { title: 'EDR on every endpoint', type: 'preventive', nature: 'automated', frequency: 'continuous', signal: 'cov:nonsense' }); assert.equal(r.status, 400); assert.match(r.text, /signal/);
  r = await call('POST', '/rc/controls', { title: 'X', type: 'preventive', nature: 'automated', frequency: 'continuous', policy: 'NOPE-1' }); assert.equal(r.status, 400); assert.match(r.text, /policy/);
  assert.equal((await call('POST', '/rc/controls', { title: 'EDR', type: 'preventive', nature: 'automated', frequency: 'continuous' }, VIEW)).status, 403);
  assert.equal((await call('POST', '/rc/controls', { title: 'EDR', type: 'preventive', nature: 'automated', frequency: 'continuous' }, { user: 'ai:grc', role: 'operator' })).status, 403, 'not an AI identity');
  const edr = (await call('POST', '/rc/controls', { title: 'Endpoint protection on every asset', type: 'preventive', nature: 'automated', frequency: 'continuous', unit: med.id, owner: 'ciso.syn', citations: ['SAMA:3.3.6', 'NCA:2-3-1'], signal: 'cov:edr', design: 'effective' })).json;
  const siem = (await call('POST', '/rc/controls', { title: 'Security logs reach the SIEM', type: 'detective', nature: 'automated', frequency: 'continuous', citations: ['NCA:2-12-1'], signal: 'cov:siem_logs' })).json;
  const review = (await call('POST', '/rc/controls', { title: 'Quarterly access review of the claims system', type: 'detective', nature: 'manual', frequency: 'quarterly', owner: 'nora.syn', unit: med.id, citations: ['PDPL:Art. 19', 'SAMA:3.3.5'], policy: 'IT-GOV-001' })).json;
  const patchC = (await call('POST', '/rc/controls', { title: 'Patching', type: 'preventive', nature: 'automated', frequency: 'monthly', signal: 'cov:patch', citations: ['NCA:2-3-3'] })).json;
  // risk and links
  const rk = await risk('Ransomware on claims servers (synthetic)', 4, 5, { residual_likelihood: 1, residual_impact: 3 });
  assert.equal((await call('POST', '/rc/links', { risk: 'bad', control: edr.id })).status, 400);
  assert.equal((await call('POST', '/rc/links', { risk: 'RSK-9999', control: edr.id })).status, 400);
  for (const [c, st] of [[edr.id, 'primary'], [siem.id, 'supporting'], [review.id, 'supporting'], [patchC.id, 'supporting']]) assert.equal((await call('POST', '/rc/links', { risk: rk.id, control: c, strength: st })).status, 200);
  assert.equal((await call('POST', '/rc/risks/' + rk.id + '/unit', { unit: med.id })).status, 200);
  let v = (await call('GET', '/rc')).json; let R = v.risks.find((x) => x.id === rk.id);
  const eff = Object.fromEntries(v.controls.map((c) => [c.id, c.eff.overall]));
  assert.equal(eff[edr.id], 'effective', '19 of 20 = 95 %'); assert.equal(eff[siem.id], 'ineffective', '10 of 20');
  assert.equal(eff[review.id], 'untested', 'no signal, no test'); assert.equal(eff[patchC.id], 'unknown', 'a source not connected is unknown, never a pass');
  assert.equal(R.inherent, 20); assert.equal(R.residual.mitigation_pct, 60, 'only the effective primary control reduces'); assert.equal(R.residual.calculated, 8);
  assert.ok(R.flags.some((f) => /claimed \(3\) below/.test(f)), 'owner residual 3 is below the 8 the controls support');
  // an independent operating test: the owner may not test their own control; a pass makes it effective
  r = await call('POST', '/rc/tests', { control: review.id, kind: 'operating', result: 'pass', evidence: 'sample of 25 reviews (synthetic)' }, OP); assert.equal(r.status, 403, 'the control owner cannot test it');
  assert.equal((await call('POST', '/rc/tests', { control: review.id, kind: 'operating', result: 'maybe', evidence: 'x' }, OP2)).status, 400);
  assert.equal((await call('POST', '/rc/tests', { control: review.id, kind: 'operating', result: 'pass', evidence: 'sample of 25 reviews (synthetic)' }, OP2)).status, 200);
  v = (await call('GET', '/rc')).json; R = v.risks.find((x) => x.id === rk.id);
  assert.equal(R.residual.mitigation_pct, 72, '1 - 0.4 x 0.7 = 72 %'); assert.equal(R.residual.calculated, 6);
  // a failed test raises a GRC action (and so an Issues Management item)
  r = await call('POST', '/rc/tests', { control: siem.id, kind: 'design', result: 'fail', evidence: 'firewalls not onboarded (synthetic)' }, OP2); assert.equal(r.status, 200); assert.match(r.json.action, /^ACT-/);
  const iss = (await call('GET', '/issues')).json; assert.ok(iss.issues.some((i) => i.key === 'grc:' + r.json.action), 'the finding is in Issues Management');
  // roll-ups
  const u = v.by_unit.find((x) => x.id === claims.id); assert.equal(u.risks, 1, 'a division rolls up its units'); assert.equal(u.controls, 2);
  assert.ok(v.by_framework.find((f) => f.framework === 'NCA').controls >= 3);
  assert.ok(v.gaps.controls_signal_unknown.some((c) => c.id === patchC.id));
  // viewer sees roll-ups only
  const vv = (await call('GET', '/rc', undefined, VIEW)).json; assert.equal(vv.risks, undefined); assert.equal(vv.kpis.risks, 1);
  // delete refused while used
  assert.equal((await call('POST', '/rc/units/' + med.id + '/delete', {}, ADM)).status, 409);
  const a = e.app.store.auditTail(80).map((x) => x.action);
  for (const n of ['rc.unit.create', 'rc.control.create', 'rc.link', 'rc.risk.unit', 'rc.control.test']) assert.ok(a.includes(n), n);
});

test('KRIs, loss events, challenged controls, the cap, policy import, acceptances register', async (t) => {
  const { e, call, risk } = await setup(t);
  const rk = await risk('Claims fraud (synthetic)', 5, 5);
  const c = []; for (let i = 0; i < 3; i++) c.push((await call('POST', '/rc/controls', { title: 'Control ' + i, type: 'preventive', nature: 'automated', frequency: 'continuous', signal: 'cov:edr', citations: ['INTERNAL:F' + i] })).json);
  for (const x of c) await call('POST', '/rc/links', { risk: rk.id, control: x.id, strength: 'primary' });
  let R = (await call('GET', '/rc')).json.risks.find((x) => x.id === rk.id);
  assert.equal(R.residual.mitigation_pct, 80); assert.equal(R.residual.capped, true, '1 - 0.4^3 = 93.6 %, capped at 80 %'); assert.equal(R.residual.calculated, 5);
  // KRI
  let r = await call('POST', '/rc/kris', { risk: rk.id, name: 'Suspicious claims per month', measure: 'count', direction: 'higher_worse', amber: 20, red: 10 }); assert.equal(r.status, 400); assert.match(r.text, /red/);
  const k = (await call('POST', '/rc/kris', { risk: rk.id, name: 'Suspicious claims per month', measure: 'count', direction: 'higher_worse', amber: 10, red: 20 })).json;
  assert.equal((await call('POST', '/rc/kris/' + k.id + '/value', { value: 'many' })).status, 400);
  r = await call('POST', '/rc/kris/' + k.id + '/value', { value: 25, note: 'October (synthetic)' }); assert.equal(r.json.status, 'red');
  const ks = (await call('POST', '/rc/kris', { risk: rk.id, name: 'EDR coverage', measure: '%', direction: 'lower_worse', amber: 95, red: 80, signal: 'cov:edr' })).json;
  assert.equal((await call('POST', '/rc/kris/' + ks.id + '/value', { value: 50 })).status, 409, 'a signal KRI is not typed');
  // loss event
  assert.equal((await call('POST', '/rc/losses', { date: '2026-10-01', category: 'external fraud', gross: 100, recovered: 200, description: 'x' })).status, 400);
  assert.equal((await call('POST', '/rc/losses', { date: '2027-10-01', category: 'external fraud', gross: 100, description: 'x' })).status, 400, 'not in the future');
  assert.equal((await call('POST', '/rc/losses', { date: '2026-10-01', category: 'theft', gross: 100, description: 'x' })).status, 400);
  r = await call('POST', '/rc/losses', { date: '2026-10-01', risk: rk.id, controls: [c[0].id], category: 'external fraud', gross: 250000, recovered: 50000, description: 'Staged accident ring (synthetic)' }); assert.equal(r.status, 200, r.text);
  let v = (await call('GET', '/rc')).json; R = v.risks.find((x) => x.id === rk.id);
  assert.equal(R.losses_12m.net_sar, 200000); assert.ok(R.flags.some((f) => /KRI|indicator is red/.test(f))); assert.ok(R.flags.some((f) => /controls challenged/.test(f)));
  assert.equal(v.controls.find((x) => x.id === c[0].id).challenged, true);
  assert.equal(v.kpis.kris_red, 1); assert.equal(v.kpis.losses_net_sar_12m, 200000);
  // policy import (admin): one control per approved register policy, once
  assert.equal((await call('POST', '/rc/controls/import-policies', {}, OP)).status, 403);
  r = await call('POST', '/rc/controls/import-policies', {}, ADM); assert.ok(r.json.created.length > 10);
  assert.equal((await call('POST', '/rc/controls/import-policies', {}, ADM)).json.created.length, 0, 'idempotent');
  // acceptances register: a policy exception approved and expired
  e.app.store.collection('grc_exceptions').put({ id: 'EXC-0001', policy_id: 'IT-GOV-001', title: 'Legacy app (synthetic)', status: 'approved', expires: '2026-10-01', decided_by: 'adam.syn' });
  e.app.store.collection('insp_actions').put({ id: 'act-1', item_text: 'Cabinet lock (synthetic)', exception: { decision: 'approve', decided_by: 'adam.syn', until: '2026-11-20' } });
  v = (await call('GET', '/rc')).json;
  assert.equal(v.acceptances.find((x) => x.ref === 'EXC-0001').state, 'expired'); assert.equal(v.acceptances.find((x) => x.ref === 'act-1').state, 'expiring');
  assert.equal(v.kpis.acceptances_expired, 1);
  const a = e.app.store.auditTail(80).map((x) => x.action);
  for (const n of ['rc.kri.create', 'rc.kri.value', 'rc.kri.breach', 'rc.loss', 'rc.control.import']) assert.ok(a.includes(n), n);
});
