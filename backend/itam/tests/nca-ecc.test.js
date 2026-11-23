// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// NCA ECC verification register (engine/nca-ecc.js, pyengine/nca_ecc_rules.py) through the real routes: 5 domains / 29
// subdomains, automated evidence (verified / gap / not measured with what to connect), roles (viewer / operator / admin
// and the refused cases), validation errors naming the field, four-eyes approval by a person, automated gaps winning over
// a confirmation, the official list import and its subdomain-bound mapping, gaps to GRC once, audit and the duty engineer.
// SYNTHETIC facts only.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');

const PY = process.env.PYTHON || 'python3';
const VIEW = { user: 'vera.syn', role: 'viewer' }, OP = { user: 'nora.syn', role: 'operator' }, OP2 = { user: 'omar.syn', role: 'operator' };
const ADM = { user: 'syed', role: 'admin' }, CISO = { user: 'khalid.syn', role: 'operator' }, BOT = { user: 'ai:grc', role: 'operator' };

// a synthetic estate: some sources connected and clean, some showing gaps, the rest not connected
const FACTS = () => ({
  grc: { available: true, total: 20, reviews_overdue: 3, attested: 15, policies: [{ title: 'Data Classification Policy (synthetic)', status: 'Approved', next_review: '2027-06-01' }],
    control_status: { assets: { state: 'pass', metric: '40 registered', detail: 'all discovered devices registered' }, patch: { state: 'fail', metric: '30/40 healthy', detail: '10 host(s) missing critical patches' },
      backup: { state: 'pass', metric: '12/12 protected', detail: 'ok' }, roles: { state: 'unknown' } } },
  risk: { available: false },
  ownership: { available: true, assets: 40, missing_it: 0, missing_business: 0 },
  pentest: { available: true, assets: 12, findings: 4, by_severity: { critical: 1, high: 0 }, internet_facing: 3, exposed_assets: 0 },
  siem: { available: true, sama: { '3.3.14': 'covered', '3.3.15': 'partial', '3.3.16': 'n/a' }, retention_days: 400, logflow: { required: 10, silent: 0, not_onboarded: 0, no_connector: 0 } },
  training_12m: 2,
});

async function setup(t, facts = FACTS) {
  const clock = Date.parse('2026-10-28T08:00:00Z');
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  const D = registerDuty(e.app.srv, e.app, { noTimer: true, now: () => clock, python: PY, eccFacts: async () => facts() });
  const call = async (m, p, body, who) => e.req(m, p, Object.assign(body !== undefined ? { body } : {}, who));
  return { e, D, call, post: (p, b, who = ADM) => call('POST', p, b, who), get: (p, who = OP) => call('GET', p, undefined, who) };
}
const ctl = (v, id) => v.controls.find((c) => c.id === id);
const auditOf = (e, action) => e.app.store.auditTail(300).filter((x) => x.action === action);

test('the register: 29 subdomains, automated evidence verified / gap / not measured', async (t) => {
  const { e, get } = await setup(t);
  const r = await get('/nca-ecc', VIEW); assert.equal(r.status, 200, r.raw);
  const v = r.json;
  assert.equal(v.domains.length, 5); assert.equal(v.subdomains.length, 29);
  assert.deepEqual(v.subdomains.filter((s) => s.decide).map((s) => s.code), ['4-2', '5-1']);
  assert.ok(v.controls.every((c) => /^ZS-[1-5]-\d{1,2}-\d{2}$/.test(c.id)) && v.subdomains.every((s) => s.controls > 0), 'every subdomain has register controls');
  assert.match(v.note, /not NCA's own assessment/);
  assert.equal(ctl(v, 'ZS-2-1-01').result, 'verified'); assert.equal(ctl(v, 'ZS-2-1-02').result, 'verified');
  assert.equal(ctl(v, 'ZS-2-3-02').result, 'gap'); assert.match(ctl(v, 'ZS-2-3-02').why, /10 host\(s\) missing critical patches/);
  assert.equal(ctl(v, 'ZS-1-3-01').result, 'gap', 'policies past review = a gap');
  assert.equal(ctl(v, 'ZS-2-10-01').result, 'gap', 'a critical open finding = a gap');
  assert.equal(ctl(v, 'ZS-2-12-01').result, 'verified'); assert.equal(ctl(v, 'ZS-2-12-02').result, 'verified'); assert.equal(ctl(v, 'ZS-2-12-03').result, 'verified');
  assert.equal(ctl(v, 'ZS-2-13-01').result, 'gap', 'SIEM SAMA 3.3.15 partial = gap');
  assert.equal(ctl(v, 'ZS-2-13-02').result, 'not_measured', 'a SAMA control the SIEM does not evidence is not measured');
  assert.equal(ctl(v, 'ZS-2-7-01').result, 'verified', 'an approved classification policy');
  const nm = ctl(v, 'ZS-1-5-01'); assert.equal(nm.result, 'not_measured'); assert.match(nm.why, /not measured: the GRC risk register was not read/);
  assert.equal(ctl(v, 'ZS-2-14-01').result, 'no_evidence', 'physical security has no automated source');
  assert.equal(ctl(v, 'ZS-1-2-01').result, 'gap', 'no CISO in the profile');
  assert.equal(v.sources.find((s) => s.id === 'risk').connected, false);
  assert.ok(v.findings.some((f) => f.key === 'ecc:ZS-2-3-02') && v.findings.some((f) => f.key === 'ecc:decide:5-1'));
  assert.ok(v.subdomains.find((s) => s.code === '2-12').status === 'compliant');
  // NCA's assessment language: every subdomain, domain and the overall carry fully / partially / not compliant / not assessed %
  const s13 = v.subdomains.find((s) => s.code === '1-3'), s23 = v.subdomains.find((s) => s.code === '2-3'), s212 = v.subdomains.find((s) => s.code === '2-12');
  assert.equal(s212.nca.status, 'fully_compliant'); assert.equal(s212.nca.pct.fully, 100);
  assert.equal(s13.nca.status, 'partially_compliant', 'one control fully compliant, one not: partially compliant, not "gap"'); assert.deepEqual(s13.nca.pct, { fully: 50, partially: 0, not: 50, not_assessed: 0 }); assert.equal(s23.nca.status, 'not_compliant', 'nothing compliant and a verified gap');
  for (const x of v.subdomains.concat(v.domains, [{ nca: v.nca }])) if (x.nca.applicable) assert.equal(Object.values(x.nca.pct).reduce((a, b) => a + b, 0), 100, 'the four parts add up to 100');
  assert.equal(s23.nca.counts.fully + s23.nca.counts.partially + s23.nca.counts.not + s23.nca.counts.not_assessed, s23.nca.applicable);
  assert.equal(ctl(v, 'ZS-2-3-02').nca_level, 'not'); assert.equal(ctl(v, 'ZS-2-12-01').nca_level, 'fully'); assert.equal(ctl(v, 'ZS-1-5-01').nca_level, 'not_assessed', 'not measured is not assessed, never compliant');
  assert.ok(e.app.addons.ncaEcc);
});

test('nothing connected: nothing reads as a pass', async (t) => {
  const { get } = await setup(t, () => ({}));
  const v = (await get('/nca-ecc', VIEW)).json;
  assert.ok(!v.controls.some((c) => c.result === 'verified' || c.result === 'met'));
  assert.equal(v.score, 0);
  assert.ok(v.controls.filter((c) => c.automated && c.subdomain !== '1-1' && c.subdomain !== '1-2').every((c) => c.result === 'not_measured'), 'every automated control says what to connect');
});

test('roles and validation', async (t) => {
  const { post, get } = await setup(t);
  assert.equal((await post('/nca-ecc/confirm', { id: 'ZS-2-14-01', status: 'compliant', evidence: 'x' }, VIEW)).status, 403);
  assert.equal((await post('/nca-ecc/profile', { ciso_user: 'khalid.syn' }, OP)).status, 403);
  assert.equal((await post('/nca-ecc/official', { rows: [{ code: '2-10-3-1', title: 't' }] }, OP)).status, 403);
  assert.equal((await post('/nca-ecc/mapping', { code: '2-10-3-1', control: 'ZS-2-10-01' }, OP)).status, 403);
  assert.equal((await get('/nca-ecc/suggest', VIEW)).status, 403); assert.equal((await get('/nca-ecc/export', VIEW)).status, 403);
  let r = await post('/nca-ecc/confirm', { id: 'ZS-2-14-01', status: 'compliant' }, OP); assert.equal(r.status, 400); assert.match(r.json.error, /evidence is required/);
  r = await post('/nca-ecc/confirm', { id: 'ZS-2-14-01', status: 'non_compliant' }, OP); assert.match(r.json.error, /note is required/);
  r = await post('/nca-ecc/confirm', { id: '2-14-1', status: 'compliant', evidence: 'x' }, OP); assert.equal(r.status, 400); assert.match(r.json.error, /^id must be a register control/);
  r = await post('/nca-ecc/confirm', { id: 'ZS-2-14-99', status: 'compliant', evidence: 'x' }, OP); assert.equal(r.status, 404);
  r = await post('/nca-ecc/confirm', { id: 'ZS-2-14-01', status: 'compliant', evidence: 'x' }, BOT); assert.equal(r.status, 403, 'an AI identity cannot record');
  r = await post('/nca-ecc/profile', { strategy_approved: '2026-13-01' }); assert.equal(r.status, 400); assert.match(r.json.error, /strategy_approved/);
  r = await post('/nca-ecc/profile', { applicability: { '2-1': 'not_applicable' } }); assert.equal(r.status, 400); assert.match(r.json.error, /applicability: 2-1/);
  r = await post('/nca-ecc/profile', { applicability: { '5-1': 'not_applicable' } }); assert.equal(r.status, 400); assert.match(r.json.error, /applicability_note.5-1 is required/);
});

test('four eyes, automated gaps win, ICS not applicable, profile audited', async (t) => {
  const { e, post, get } = await setup(t);
  let r = await post('/nca-ecc/profile', { ciso_user: 'khalid.syn', function_established: '2025-01-01', reports_to: 'CEO', strategy_approved: '2025-06-01', committee_last_met: '2026-09-15', applicability: { '5-1': 'not_applicable' }, applicability_note: { '5-1': 'no industrial control systems (synthetic)' } });
  assert.equal(r.status, 200, r.raw);
  assert.equal(auditOf(e, 'ecc.profile').length, 1);
  let v = (await get('/nca-ecc', VIEW)).json;
  assert.equal(ctl(v, 'ZS-1-2-01').result, 'verified'); assert.equal(ctl(v, 'ZS-5-1-01').result, 'not_applicable');
  // a manual control: recorded, then approved by the CISO, not the recorder
  r = await post('/nca-ecc/confirm', { id: 'ZS-2-14-01', status: 'compliant', evidence: 'badge access review Q3 (synthetic)' }, OP); assert.equal(r.status, 200, r.raw); assert.equal(r.json.result, 'pending');
  assert.equal((await post('/nca-ecc/confirm/ZS-2-14-01/decide', { decision: 'approve' }, OP)).status, 403, 'the recorder cannot approve');
  assert.equal((await post('/nca-ecc/confirm/ZS-2-14-01/decide', { decision: 'approve' }, OP2)).status, 403, 'another operator who is not the CISO cannot approve');
  r = await post('/nca-ecc/confirm/ZS-2-14-01/decide', { decision: 'approve' }, CISO); assert.equal(r.status, 200, r.raw); assert.equal(r.json.result, 'met');
  assert.equal((await post('/nca-ecc/confirm/ZS-2-14-01/decide', { decision: 'approve' }, ADM)).status, 409);
  assert.equal(auditOf(e, 'ecc.confirm.approve')[0].by, 'khalid.syn');
  // a person says compliant, the patch feed says gap: the gap stays
  await post('/nca-ecc/confirm', { id: 'ZS-2-3-02', status: 'compliant', evidence: 'monthly patch report (synthetic)' }, OP);
  await post('/nca-ecc/confirm/ZS-2-3-02/decide', { decision: 'approve' }, ADM);
  v = (await get('/nca-ecc', VIEW)).json;
  assert.equal(ctl(v, 'ZS-2-3-02').result, 'gap'); assert.equal(ctl(v, 'ZS-2-3-02').conflict, true);
  // reject needs a note and removes the record
  await post('/nca-ecc/confirm', { id: 'ZS-2-15-01', status: 'partial', evidence: 'WAF on portal only (synthetic)' }, OP);
  assert.match((await post('/nca-ecc/confirm/ZS-2-15-01/decide', { decision: 'reject' }, CISO)).json.error, /note is required/);
  assert.equal((await post('/nca-ecc/confirm/ZS-2-15-01/decide', { decision: 'reject', note: 'no test report' }, CISO)).json.result, 'no_evidence');
});

test('official list: import checked, suggestions bound to the subdomain, mapping, export, gaps to GRC once, duty', async (t) => {
  const { e, D, post, get } = await setup(t);
  let r = await post('/nca-ecc/official', { rows: [{ code: '2-10-3-1', title: 'Periodic vulnerability assessments (synthetic text)' }, { code: '2-12-3-5', title: 'Retention of cybersecurity event logs (synthetic text)' }, { code: '9-9-9', title: 'bad' }, { code: '2-10-3-1', title: 'dup' }] });
  assert.equal(r.status, 200, r.raw); assert.equal(r.json.imported, 2); assert.equal(r.json.error_count, 2);
  assert.match(r.json.errors.join(' '), /9-9-9" is not an ECC control code/);
  const s = (await get('/nca-ecc/suggest')).json.suggestions;
  assert.equal(s.find((x) => x.code === '2-10-3-1').control.startsWith('ZS-2-10-'), true);
  assert.equal(s.find((x) => x.code === '2-12-3-5').control, 'ZS-2-12-03', 'the retention control is picked by its words');
  r = await post('/nca-ecc/mapping', { accept: ['2-10-3-1', '2-12-3-5'] }); assert.equal(r.json.accepted, 2);
  r = await post('/nca-ecc/mapping', { code: '2-10-3-1', control: 'ZS-9-9-99' }); assert.equal(r.status, 400);
  let v = (await get('/nca-ecc', VIEW)).json;
  assert.equal(v.coverage.mapped, 2); assert.deepEqual(ctl(v, 'ZS-2-12-03').official, ['2-12-3-5']);
  r = await get('/nca-ecc/export'); assert.equal(r.status, 200); assert.match(r.json.csv, /"ZS-2-12-03","2-12"/); assert.match(r.json.csv, /"Overall","ECC-1:2018","NCA Essential Cybersecurity Controls","(Fully|Partially|Not) compliant/); assert.match(r.json.csv, /"Subdomain","2-12","[^"]+","Fully compliant","100"/); assert.equal(auditOf(e, 'ecc.export').length, 1);
  // gaps to GRC: the CISO or an admin, once
  assert.equal((await post('/nca-ecc/gaps-to-grc', {}, OP)).status, 403);
  assert.equal((await post('/nca-ecc/gaps-to-grc', {}, { user: 'ai:x', role: 'admin' })).status, 403);
  r = await post('/nca-ecc/gaps-to-grc', {}); assert.equal(r.status, 200, r.raw);
  const gaps = v.controls.filter((c) => c.result === 'gap').length;
  assert.equal(r.json.created.length, gaps);
  r = await post('/nca-ecc/gaps-to-grc', {}); assert.equal(r.json.created.length, 0, 'an open action is not raised twice'); assert.equal(r.json.skipped.length, gaps);
  const act = e.app.store.collection('grc_actions').all((a) => a.source === 'nca');
  assert.ok(act.length === gaps && act.every((a) => a.framework === 'NCA ECC' && /^ecc:ZS-/.test(a.ref)));
  // the duty engineer
  const f = await e.app.addons.ncaEcc.adapter.findings();
  assert.ok(f.some((x) => x.key === 'ecc:ZS-2-3-02'));
  assert.equal((await e.app.addons.ncaEcc.adapter.verify({ key: 'ecc:ZS-2-3-02' })).present, true);
  assert.ok(D);
});
