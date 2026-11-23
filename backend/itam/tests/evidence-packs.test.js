// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Regulator Evidence Packs (engine/evidence-packs.js) through the real routes over the real registers (engine/duty.js: SAMA CSF,
// IA, NCA ECC, PDPL, NDMO with pyengine) and SYNTHETIC facts / evidence: one frozen, SHA-256-fingerprinted pack per framework;
// results as the registers hold them; evidence named and hashed, never its content; a module not installed says so; roles
// (viewer refused, operator builds, admin signs) and validation errors that name the field; four-eyes sign-off by a person who
// did not build it, never a service / AI identity, once, and a tampered pack refused; month-on-month comparison (worse / better,
// evidence expired); the monthly job (guarded, retried, no timer in tests) and its signals; retention of 24 per framework with
// signed packs kept; the audit record for every change.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');
const { createEvidencePacks, registerEvidencePacks, fingerprint } = require('../engine/evidence-packs');

const PY = process.env.PYTHON || 'python3';
const VIEW = { user: 'vera.syn', role: 'viewer' }, OP = { user: 'nora.syn', role: 'operator' }, ADM = { user: 'syed', role: 'admin' }, ADM2 = { user: 'reem.syn', role: 'admin' };
const BOT = { user: 'ai:grc', role: 'admin' }, SVC = { user: 'svc:packs', role: 'operator' };
const DAY = 86400000;
const FILE = Buffer.from('SYNTHETIC hardening report - not real data\nhost-a: pass\n');

function facts(o = {}) {
  return {
    grc: { available: true, total: 20, reviews_overdue: 0, attested: 15, policies: [{ title: 'Cryptography Standard (synthetic)', status: 'Approved', next_review: '2027-06-01' }], control_status: {} },
    hardening: { available: true, assets: 40, scanned: 38, coverage_pct: 95, score: 82, fail: 30, critical_fail: o.critical || 0 },
    pentest: { available: true, assets: 12, findings: 4, by_severity: { critical: 0, high: 0 }, internet_facing: 3, exposed_assets: 0 },
    cadence: { available: true, assets: 12, out_of_policy: 3 },
    siem: { available: true, sama: { '3.3.14': 'covered', '3.3.15': 'partial', '3.3.16': 'covered' }, retention_days: 400, logflow: { required: 10, silent: 0, not_onboarded: 0, no_connector: 0 } },
  };
}

async function setup(t, o = {}) {
  const S = { clock: o.clock || Date.parse('2026-10-05T08:00:00Z'), critical: 0 };
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  const now = () => S.clock;
  registerDuty(e.app.srv, e.app, { noTimer: true, now, python: PY, samaFacts: async () => facts(S), eccFacts: async () => facts(S) });
  if (o.without) for (const k of o.without) delete e.app.addons[k];
  const X = createEvidencePacks(e.app, { now, noTimer: true }); e.app.addons.evidencePacks = X;
  registerEvidencePacks(e.app.srv, e.app, X);
  const call = (m, p, b, who) => e.req(m, p, Object.assign(b !== undefined ? { body: b } : {}, who));
  return { e, X, S, call, post: (p, b, who = OP) => call('POST', p, b, who), get: (p, who = OP) => call('GET', p, undefined, who) };
}
const auditOf = (e, action) => e.app.store.auditTail(2000).filter((x) => x.action === 'evidence-packs.' + action);
const ctl = (p, ref) => p.controls.find((c) => c.ref === ref);

test('Build now: one frozen, fingerprinted pack per framework, results as the registers hold them, evidence named and hashed', async (t) => {
  const { e, post, get } = await setup(t);
  // SYNTHETIC evidence filed against a SAMA requirement; the file content must never appear in a pack
  const ev = await post('/grc/evidence', { framework: 'SAMA CSF', control: 'SA-3.3.8-01', title: 'Hardening baseline report (synthetic)', owner: 'faisal.syn', filename: 'hardening-synthetic.txt', content_b64: FILE.toString('base64'), collected: '2026-09-20', valid_days: 365 });
  assert.equal(ev.status, 200, ev.text);
  const r = await post('/evidence-packs/build', { framework: 'all', built_by: 'mallory', sha256: 'f'.repeat(64) });
  assert.equal(r.status, 200, r.text);
  assert.equal(r.json.built.length, 5, JSON.stringify(r.json.failed)); assert.deepEqual(r.json.failed, []);
  assert.deepEqual(r.json.built.map((p) => p.code).sort(), ['ECC', 'IA', 'NDMO', 'PDPL', 'SAMA']);
  for (const row of r.json.built) {
    assert.match(row.id, /^EP-[A-Z]+-2026-10-01$/); assert.equal(row.built_by, OP.user, 'undeclared built_by is dropped'); assert.notEqual(row.sha256, 'f'.repeat(64));
    const p = (await get('/evidence-packs/' + row.id)).json;
    assert.equal(p.integrity.ok, true); assert.equal(fingerprint(p), p.sha256, 'the fingerprint is the SHA-256 of the canonical content');
    assert.ok(p.controls.length > 10, row.code + ' has its controls'); assert.ok(p.controls.every((c) => ['implemented', 'partial', 'not_implemented', 'not_applicable', 'not_tested'].includes(c.status)));
    const sm = p.summary; assert.equal(Object.values(sm.counts).reduce((a, b) => a + b, 0), sm.controls);
  }
  const sama = (await get('/evidence-packs/EP-SAMA-2026-10-01')).json;
  const c = ctl(sama, 'SA-3.3.8-01');
  assert.equal(c.status, 'implemented', 'no critical hardening failure: verified by the register');
  assert.equal(c.evidence.length, 1); assert.equal(c.evidence[0].file, 'hardening-synthetic.txt');
  assert.equal(c.evidence[0].sha256, require('node:crypto').createHash('sha256').update(FILE).digest('hex')); assert.equal(c.evidence[0].integrity, 'verified');
  assert.equal(c.owner, 'faisal.syn'); assert.equal(c.owner_source, 'evidence register');
  assert.equal(ctl(sama, 'SA-3.3.15-01').status, 'not_implemented', 'SIEM incident management partial in SAMA = a gap');
  assert.equal(ctl(sama, 'SA-3.1.5-01').status, 'not_tested', 'a manual requirement with nothing recorded is not tested, never a pass');
  assert.ok(ctl(sama, 'SA-3.1.5-01').missing.some((m) => /no evidence file/.test(m)));
  assert.ok(ctl(sama, 'SA-3.1.1-01').policies.length >= 1, 'the supporting policies from the GRC policy register');
  const raw = JSON.stringify(sama);
  assert.ok(!raw.includes(FILE.toString('base64')) && !raw.includes('content_b64') && !raw.includes('host-a: pass'), 'the evidence content never enters a pack');
  const ia = (await get('/evidence-packs/EP-IA-2026-10-01')).json;
  assert.ok(ctl(ia, 'IA-277-01') && ctl(ia, 'SA-3.3.8-01'), 'the IA register = IA items + the SAMA CSF baseline');
  assert.ok(ia.live.resilience && Array.isArray(ia.live.resilience.areas), 'the IA operational resilience areas');
  const pd = (await get('/evidence-packs/EP-PDPL-2026-10-01')).json;
  assert.equal(typeof pd.live.record_counts, 'object', 'PDPL registers as counts only');
  assert.equal(ctl(pd, 'P-01').status, 'not_tested');
  const b = auditOf(e, 'build'); assert.equal(b.length, 5);
  assert.equal(b[0].by, OP.user); assert.equal(b[0].role, 'operator'); assert.ok(b[0].detail.sha256 && b[0].detail.period === '2026-10');
  const l = (await get('/evidence-packs')).json;
  assert.equal(l.packs.length, 5); assert.ok(l.frameworks.every((f) => f.installed && f.this_month)); assert.equal(l.me.user, OP.user);
  assert.equal(l.can.sign, false, 'an operator cannot sign');
});

test('a framework module not installed: its pack says so, holds no passes, and cannot be signed', async (t) => {
  const { post, get } = await setup(t, { without: ['ndmo'] });
  const r = await post('/evidence-packs/build', { framework: 'ndmo' }); assert.equal(r.status, 200, r.text);
  const p = (await get('/evidence-packs/' + r.json.built[0].id)).json;
  assert.equal(p.installed, false); assert.match(p.reason, /not installed/); assert.deepEqual(p.controls, []); assert.equal(p.summary, null);
  assert.equal((await get('/evidence-packs')).json.frameworks.find((f) => f.key === 'ndmo').installed, false);
  const s = await post('/evidence-packs/' + p.id + '/sign', { confirm: true }, ADM); assert.equal(s.status, 409); assert.match(s.json.error, /not installed/);
});

test('roles and validation: viewer refused, operator builds, admin signs; errors name the field', async (t) => {
  const { post, get } = await setup(t);
  assert.equal((await get('/evidence-packs', VIEW)).status, 403, 'packs name owners: a viewer is refused');
  assert.equal((await post('/evidence-packs/build', { framework: 'ecc' }, VIEW)).status, 403);
  let r = await post('/evidence-packs/build', { framework: 'iso' }); assert.equal(r.status, 400); assert.match(r.json.error, /^framework must be one of/);
  r = await post('/evidence-packs/build', { framework: 'ecc' }, SVC); assert.equal(r.status, 403, 'a service identity does not press Build now'); assert.match(r.json.error, /service or AI/);
  r = await post('/evidence-packs/build', { framework: 'ecc' }); assert.equal(r.status, 200, r.text);
  const id = r.json.built[0].id;
  assert.equal((await get('/evidence-packs/' + id, VIEW)).status, 403);
  assert.equal((await get('/evidence-packs/not%20a%20pack')).status, 400);
  r = await get('/evidence-packs/ACT-0001'); assert.equal(r.status, 400); assert.match(r.json.error, /^id must be an evidence pack id/);
  assert.equal((await get('/evidence-packs/EP-ECC-2020-01-01')).status, 404);
  r = await get('/evidence-packs/' + id + '/compare?with=bad%20id'); assert.equal(r.status, 400); assert.match(r.json.error, /^with is not a valid id/);
  assert.equal((await post('/evidence-packs/' + id + '/sign', { confirm: true }, OP)).status, 403, 'an operator does not sign');
  r = await post('/evidence-packs/' + id + '/sign', {}, ADM2); assert.equal(r.status, 400); assert.match(r.json.error, /^confirm is required/);
  r = await post('/evidence-packs/' + id + '/sign', { confirm: 'yes' }, ADM2); assert.equal(r.status, 400); assert.match(r.json.error, /^confirm must be true or false/);
  r = await post('/evidence-packs/' + id + '/sign', { confirm: false }, ADM2); assert.equal(r.status, 400); assert.match(r.json.error, /^confirm must be true/);
  r = await post('/evidence-packs/' + id + '/sign', { confirm: true, note: 'x'.repeat(1001) }, ADM2); assert.equal(r.status, 400); assert.match(r.json.error, /^note is longer/);
});

test('sign-off: a person who did not build it, never an AI identity, once; signed packs are immutable; tampering is caught', async (t) => {
  const { e, X, post, get } = await setup(t);
  const id = (await post('/evidence-packs/build', { framework: 'pdpl' }, ADM)).json.built[0].id;
  let r = await post('/evidence-packs/' + id + '/sign', { confirm: true }, ADM); assert.equal(r.status, 403); assert.match(r.json.error, /four eyes/);
  assert.equal((await get('/evidence-packs/' + id, ADM)).json.can_sign, false);
  r = await post('/evidence-packs/' + id + '/sign', { confirm: true }, BOT); assert.equal(r.status, 403); assert.match(r.json.error, /service or AI/);
  assert.equal((await get('/evidence-packs/' + id, ADM2)).json.can_sign, true);
  r = await post('/evidence-packs/' + id + '/sign', { confirm: true, note: 'Reviewed for the SDAIA request (synthetic)', by: 'mallory' }, ADM2);
  assert.equal(r.status, 200, r.text); assert.equal(r.json.signoff.by, ADM2.user); assert.equal(r.json.signoff.sha256, r.json.sha256); assert.equal(r.json.integrity.ok, true);
  r = await post('/evidence-packs/' + id + '/sign', { confirm: true }, { user: 'third.syn', role: 'admin' }); assert.equal(r.status, 409); assert.match(r.json.error, /already signed/);
  const a = auditOf(e, 'sign'); assert.equal(a.length, 1); assert.equal(a[0].by, ADM2.user); assert.equal(a[0].role, 'admin'); assert.equal(a[0].detail.built_by, ADM.user);
  // the monthly job's pack (built by the system) can be signed by any administrator who is a person
  await X.tick();
  const sys = (await get('/evidence-packs')).json.packs.find((p) => p.code === 'SAMA' && p.kind === 'monthly');
  assert.equal(sys.built_by, 'system:evidence-packs');
  // tampering with a stored pack: integrity fails and the pack cannot be signed
  const st = e.app.store.collection('evidence_packs'), raw = st.get(sys.id);
  st.put(Object.assign({}, raw, { controls: raw.controls.map((c, i) => (i ? c : Object.assign({}, c, { status: 'implemented' }))) }));
  const g = (await get('/evidence-packs/' + sys.id, ADM)).json; assert.equal(g.integrity.ok, false); assert.equal(g.can_sign, false);
  r = await post('/evidence-packs/' + sys.id + '/sign', { confirm: true }, ADM); assert.equal(r.status, 409); assert.match(r.json.error, /no longer matches/);
});

test('month on month: controls that got worse or better, evidence that expired; the export; signals for Notification & Escalation', async (t) => {
  const { e, X, S, post, get } = await setup(t);
  await post('/grc/evidence', { framework: 'NCA ECC', control: 'ZS-1-3-01', title: 'Policy review minutes (synthetic)', filename: 'minutes-synthetic.txt', content_b64: FILE.toString('base64'), collected: '2026-09-10', valid_days: 30 });
  const m1 = await X.tick(); assert.deepEqual(m1.failed, []);
  assert.equal((await get('/evidence-packs')).json.packs.length, 5);
  assert.equal((await X.tick()).failed.length, 0); assert.equal((await get('/evidence-packs')).json.packs.length, 5, 'one monthly pack per framework per month');
  assert.deepEqual(X.signals(), [], 'every pack built, nothing compared yet');
  // next month: hardening has critical failures, the ECC evidence is past its validity
  S.clock = Date.parse('2026-11-01T06:00:00Z'); S.critical = 3;
  const miss = X.signals().filter((x) => /missing/.test(x.fp)); assert.equal(miss.length, 0, 'day 1: the job still has time');
  S.clock = Date.parse('2026-11-03T06:00:00Z');
  const missing = X.signals().filter((x) => /^evidence-packs:missing:/.test(x.fp));
  assert.equal(missing.length, 5); const m = missing.find((x) => x.fp === 'evidence-packs:missing:sama:2026-11');
  assert.deepEqual(Object.keys(m).sort(), ['condition', 'fp', 'ref', 'severity', 'source', 'text', 'title']); assert.equal(m.source, 'platform'); assert.equal(m.condition, true);
  await X.tick();
  const sama = (await get('/evidence-packs')).json.packs.find((p) => p.code === 'SAMA' && p.period === '2026-11');
  const c = (await get('/evidence-packs/' + sama.id + '/compare')).json;
  assert.equal(c.previous.id, 'EP-SAMA-2026-10-01');
  const w = c.worse.find((x) => x.ref === 'SA-3.3.8-01'); assert.ok(w, JSON.stringify(c.worse)); assert.equal(w.from, 'implemented'); assert.equal(w.to, 'not_implemented');
  assert.ok(c.delta.implemented < 0);
  const ecc = (await get('/evidence-packs')).json.packs.find((p) => p.code === 'ECC' && p.period === '2026-11');
  const ce = (await get('/evidence-packs/' + ecc.id + '/compare?with=EP-ECC-2026-10-01')).json;
  assert.equal(ce.evidence_expired.length, 1); assert.equal(ce.evidence_expired[0].control, 'ZS-1-3-01'); assert.equal(ce.evidence_expired[0].now, 'stale');
  assert.ok(ctl((await get('/evidence-packs/' + ecc.id)).json, 'ZS-1-3-01').missing.some((x) => /evidence expired/.test(x)));
  assert.equal((await get('/evidence-packs/' + ecc.id + '/compare?with=' + sama.id)).status, 400, 'not across frameworks');
  const sig = X.signals();
  assert.ok(!sig.some((x) => /missing/.test(x.fp)), 'built: no missing signal');
  const ws = sig.find((x) => x.fp === 'evidence-packs:worse:' + sama.id);
  assert.ok(ws, JSON.stringify(sig)); assert.equal(ws.source, 'platform'); assert.equal(ws.condition, true); assert.equal(ws.ref, sama.id); assert.match(ws.text, /SA-3\.3\.8-01 implemented -> not implemented/);
  // a month later with nothing changed: improvements counted the other way
  S.clock = Date.parse('2026-12-02T06:00:00Z'); S.critical = 0; await X.tick();
  const dec = (await get('/evidence-packs')).json.packs.find((p) => p.code === 'SAMA' && p.period === '2026-12');
  assert.ok((await get('/evidence-packs/' + dec.id + '/compare')).json.better.some((x) => x.ref === 'SA-3.3.8-01'));
  // the workbook rows, audited
  const x = await get('/evidence-packs/' + sama.id + '/export');
  assert.equal(x.status, 200); assert.equal(x.json.filename, 'evidence-pack-' + sama.id + '.xlsx');
  assert.deepEqual(x.json.sheets.map((s2) => s2.name), ['Summary', 'Controls', 'Evidence', 'Missing']);
  assert.ok(x.json.sheets[1].rows.length > 50);
  assert.equal((await get('/evidence-packs/' + sama.id + '/export', VIEW)).status, 403);
  const ea = auditOf(e, 'export'); assert.equal(ea.length, 1); assert.equal(ea[0].by, OP.user); assert.equal(ea[0].target, sama.id);
});

test('the monthly job: guarded, a register that cannot be read gets no pack (said, retried), no timer in tests', async (t) => {
  const { e, X, get } = await setup(t);
  assert.equal(X.start(), false, 'opts.noTimer: the job does not start');
  const orig = e.app.addons.ncaEcc.view;
  e.app.addons.ncaEcc.view = async () => { throw new Error('synthetic: Python did not answer'); };
  await assert.rejects(X.tick(), /not built for 2026-10: ecc/);
  const l = (await get('/evidence-packs')).json;
  assert.equal(l.packs.length, 4, 'the others are built'); assert.ok(!l.packs.some((p) => p.code === 'ECC'), 'no ECC pack from a register that did not answer');
  assert.match(l.job.last_error, /NCA ECC: .*could not be read/);
  e.app.addons.ncaEcc.view = orig;
  await X.tick(); assert.ok((await get('/evidence-packs')).json.packs.some((p) => p.code === 'ECC'), 'retried on the next run');
  assert.equal((await get('/evidence-packs')).json.job.last_error, null);
  // a guarded job never rejects: the failure is recorded in the errors register instead
  const { guardOf } = require('../engine/errors');
  e.app.addons.ndmo.view = async () => { throw new Error('synthetic failure'); };
  const S2 = createEvidencePacks(e.app, { now: () => Date.parse('2027-01-02T08:00:00Z'), noTimer: true });
  await guardOf(e.app, 'evidence-packs.monthly', S2.tick)();
});

test('retention: the last 24 packs per framework are kept, a signed pack is never removed, each removal audited', async (t) => {
  const { e, post, get } = await setup(t);
  const first = (await post('/evidence-packs/build', { framework: 'pdpl' }, ADM)).json.built[0].id;
  assert.equal((await post('/evidence-packs/' + first + '/sign', { confirm: true }, ADM2)).status, 200);
  const second = (await post('/evidence-packs/build', { framework: 'pdpl' }, ADM)).json.built[0].id;
  for (let i = 0; i < 24; i++) assert.equal((await post('/evidence-packs/build', { framework: 'pdpl' })).status, 200);
  const l = (await get('/evidence-packs')).json.packs.filter((p) => p.code === 'PDPL');
  assert.equal(l.length, 25, '24 kept + the signed one');
  assert.ok(l.some((p) => p.id === first), 'the signed pack stays'); assert.ok(!l.some((p) => p.id === second), 'the oldest unsigned pack went');
  assert.equal((await get('/evidence-packs/' + second)).status, 404);
  const pr = auditOf(e, 'prune'); assert.equal(pr.length, 1); assert.equal(pr[0].target, second); assert.ok(pr[0].detail.sha256);
});

test('a new install with no pack yet pages nobody; a failed attempt or a gap after pack history does', async (t) => {
  const { X, S } = await setup(t);
  S.clock = Date.parse('2026-11-05T06:00:00Z');
  assert.deepEqual(X.signals().filter((x) => /^evidence-packs:missing:/.test(x.fp)), [], 'no pack history and no failed attempt: the monthly job builds the first packs');
});
