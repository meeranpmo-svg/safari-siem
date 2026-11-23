// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// GRC module (engine/grc.js): the the organisation approved IT policy register becomes live data — control-automation
// mapping, review lifecycle, framework crosswalk, server-side live checks for ITAM-held signals, and owner attestations.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { createGrc, registerGrc, frameworksOf, parseReviewDate, REGISTER } = require('../engine/grc');

const ADM = { user: 'syed', role: 'admin', ip: '' }, OP = { user: 'ali', role: 'operator', ip: '' };

test('grc: register loads the 42 approved policies and enriches each with control, frameworks and review', async (t) => {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  const G = createGrc(e.app);
  const r = G.register();
  assert.equal(r.total, 42);
  const patch = r.items.find((p) => p.doc_id === 'IT-DEV-009');
  assert.equal(patch.control.cls, 'automated'); assert.equal(patch.control.check, 'patch');
  assert.ok(patch.frameworks_list.includes('SAMA') && patch.frameworks_list.includes('ISO 27001'));
  assert.ok(patch.review.next_review); assert.equal(typeof patch.review.overdue, 'boolean');
  // every policy carries a control classification
  for (const p of r.items) assert.ok(['automated', 'monitored', 'manual'].includes(p.control.cls), p.doc_id);
});

test('grc: framework parsing and review-date parsing', () => {
  assert.deepEqual(frameworksOf('SAMA ITGF 3.4.9, SAMA CSF, ISO/IEC 27001:2022, BCM Framework'), ['SAMA', 'ISO 27001', 'BCM']);
  assert.deepEqual(frameworksOf('NCA ECC, PDPL'), ['NCA', 'PDPL']);
  assert.ok(frameworksOf('Insurance Authority cyber regulation, NDMO data standards').includes('Insurance Authority'));
  assert.ok(frameworksOf('Insurance Authority cyber regulation, NDMO data standards').includes('NDMO'));
  assert.equal(parseReviewDate('November 2026'), Date.UTC(2026, 11, 0)); // end of November 2026
  assert.equal(parseReviewDate(''), null);
});

test('grc: Insurance Authority framework crosswalk — coverage, gaps and policy mappings', async (t) => {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  const ia = createGrc(e.app).frameworkIA();
  assert.equal(ia.framework, 'Insurance Authority'); assert.equal(ia.indicative, true);
  assert.equal(ia.domains.length, 12);
  const by = Object.fromEntries(ia.domains.map((d) => [d.key, d]));
  assert.equal(by.itops.status, 'covered'); assert.ok(by.itops.policies.length >= 8);
  assert.equal(by.bcm.status, 'partial'); assert.equal(by.cyber.status, 'partial');
  assert.equal(by.outsourcing.status, 'gap'); assert.equal(by.data.status, 'gap');
  assert.equal(by.aml.status, 'na'); // business function, not IT GRC
  // coverage counts only required domains; AML/consumer are n/a
  assert.equal(ia.summary.required, 10); assert.equal(ia.summary.gap, 2); assert.equal(ia.summary.partial, 2);
  assert.ok(ia.summary.coverage_pct > 0 && ia.summary.coverage_pct <= 100);
  // mapped policies resolve to real register entries
  assert.ok(by.itops.policies.some((p) => p.doc_id && p.title));
});

test('grc: summary counts by class, domain, framework coverage and review status', async (t) => {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  const s = createGrc(e.app).summary();
  assert.equal(s.total, 42);
  assert.ok(s.by_cls.automated >= 8 && s.by_cls.monitored >= 1 && s.by_cls.manual >= 1);
  assert.equal(s.by_cls.automated + s.by_cls.monitored + s.by_cls.manual, 42);
  assert.equal(s.by_domain.length, 4); // 3.1 .. 3.4
  assert.ok(s.frameworks.find((f) => f.framework === 'SAMA').policies >= 10);
  assert.ok(s.control_status.register && s.control_status.register.state); // the register's own control
});

test('grc: server-side live checks read ITAM-held signals honestly', async (t) => {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  const st = e.app.store;
  st.collection('assets').put({ id: 'a1', type: 'server', name: 'SRV1', status: 'in_use' });
  st.collection('assets').put({ id: 'a2', type: 'network', name: 'SW1', status: 'in_use' });
  st.collection('disc_devices').put({ id: 'd1', fields: {}, source: 'snmp' }); // discovered, not adopted
  st.collection('me_ec_computers').put({ id: 'r1', resource_id: 'r1', critical: 4, missing: 10 });
  st.collection('me_ec_computers').put({ id: 'r2', resource_id: 'r2', critical: 0, missing: 1 });
  st.collection('me_ec_computers').put({ id: 'r3', resource_id: 'r3', critical: 0, missing: 0 });
  st.collection('backup_platforms').put({ id: 'bp1', kind: 'proxmox' });
  st.collection('backup_objects').put({ id: 'o1', ok: true });
  st.collection('backup_objects').put({ id: 'o2', ok: false });
  st.collection('virt_platforms').put({ id: 'v1', kind: 'nutanix' });
  const cs = createGrc(e.app).controlStatus();
  assert.equal(cs.assets.state, 'partial'); assert.match(cs.assets.detail, /discovered/);
  assert.equal(cs.patch.state, 'fail'); assert.equal(cs.patch.metric, '2/3 healthy');
  assert.equal(cs.backup.state, 'partial'); assert.equal(cs.backup.metric, '1/2 protected');
  assert.equal(cs.virt.state, 'pass');
  // nothing connected → unknown, never a false pass
  const e2 = await startApp({ noAi: true }); t.after(() => e2.close());
  assert.equal(createGrc(e2.app).controlStatus().patch.state, 'unknown');
});

test('grc: attestation requires a note and is recorded; review acknowledgement recorded', async (t) => {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  const G = createGrc(e.app);
  assert.throws(() => G.attest('IT-DEV-009', { note: '' }, OP), /note is required/);
  assert.throws(() => G.attest('NOPE', { note: 'x' }, OP), /not found/);
  const a = G.attest('IT-DEV-009', { note: 'Patch SLA reviewed; all criticals within 14 days', period: '2026-Q4' }, OP);
  assert.match(a.id, /^ATT-IT-DEV-009-/); assert.equal(a.by, 'ali'); assert.equal(a.decision, 'compliant');
  assert.equal(G.policy('IT-DEV-009').attestation.id, a.id);
  const rv = G.reviewAck('IT-DEV-009', { note: 'Annual review complete, no change' }, ADM);
  assert.equal(G.policy('IT-DEV-009').review.acknowledged, true); assert.equal(G.reviewAck && rv.by, 'syed');
});

test('grc: routes — reads open, attest needs operator, review needs admin', async (t) => {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerGrc(e.app.srv, e.app);
  assert.equal((await e.req('GET', '/grc/register', { role: 'viewer' })).status, 200);
  assert.equal((await e.req('GET', '/grc/summary', { role: 'viewer' })).status, 200);
  assert.equal((await e.req('GET', '/grc/policy/IT-DEV-009', { role: 'viewer' })).status, 200);
  assert.equal((await e.req('GET', '/grc/policy/NOPE', { role: 'viewer' })).status, 404);
  assert.equal((await e.req('POST', '/grc/policy/IT-DEV-009/attest', { role: 'viewer', body: { note: 'x' } })).status, 403);
  assert.equal((await e.req('POST', '/grc/policy/IT-DEV-009/attest', { role: 'operator', body: { note: 'checked' } })).status, 200);
  assert.equal((await e.req('POST', '/grc/policy/IT-DEV-009/review', { role: 'operator', body: {} })).status, 403);
  assert.equal((await e.req('POST', '/grc/policy/IT-DEV-009/review', { role: 'admin', body: { note: 'ok' } })).status, 200);
});

test('grc: policy drafting — create, edit (version bump), upload document, status workflow, seed gaps', async (t) => {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  const G = createGrc(e.app); const OP = { user: 'ali' }, ADM = { user: 'syed' };
  assert.throws(() => G.draftPut({ title: '' }, OP), /title is required/);
  let d = G.draftPut({ title: 'Information & Cyber Security Policy', frameworks: 'SAMA, ISO 27001', purpose: 'ISMS umbrella' }, OP);
  assert.match(d.id, /^DRAFT-\d{4}$/); assert.equal(d.version, '0.1'); assert.equal(d.status, 'draft');
  d = G.draftPut({ id: d.id, requirements: 'A\nB\nC' }, OP);
  assert.equal(d.version, '0.2'); assert.equal(d.requirements.length, 3);
  d = G.draftUpload(d.id, { filename: 'infosec.docx', size: 1200, sha256: 'ABCDEF', content_b64: 'UEsDBBQ=' }, OP);
  assert.equal(d.document.filename, 'infosec.docx'); assert.equal(d.document.stored, 'inline'); assert.equal(d.document.content_b64, undefined, 'inline bytes never leak in the record');
  assert.equal(G.draftDocument(d.id).filename, 'infosec.docx'); // download returns the bytes
  d = G.draftStatus(d.id, 'approved', ADM); assert.equal(d.status, 'approved'); assert.equal(d.version, '1.0'); assert.equal(d.approved_by, 'syed');
  const seed = G.draftSeedGaps(ADM); assert.equal(seed.created, 15); assert.equal(G.draftSeedGaps(ADM).created, 0, 'idempotent');
  assert.equal(G.draftList().items.length, 16);
  G.draftDelete(d.id); assert.equal(G.draftList().items.length, 15);
});

test('grc: DR drill — plan, validate, record result, four-eyes sign-off (SAMA recoverability testing)', async (t) => {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  const G = createGrc(e.app); const OP = { user: 'ali' }, OP2 = { user: 'omar' }, ADM = { user: 'syed' };
  assert.throws(() => G.drillPut({ title: '' }, OP), /title is required/);
  assert.throws(() => G.drillPut({ title: 'x' }, OP), /system .* is required/);
  assert.throws(() => G.drillPut({ title: 'x', system: 'Core', type: 'nope' }, OP), /type must be one of/);
  let d = G.drillPut({ title: 'Core banking failover', system: 'Core Banking', type: 'failover', rto_target_min: 60, rpo_target_min: 15, scheduled: '2026-11-01', frequency_months: 6, owner: 'IT Ops' }, OP);
  assert.match(d.id, /^DR-\d{4}$/); assert.equal(d.status, 'planned'); assert.equal(d.result, null); assert.equal(d.frequency_months, 6);
  // record the outcome (operator)
  assert.throws(() => G.drillResult(d.id, { result: 'maybe' }, OP), /result must be/);
  d = G.drillResult(d.id, { result: 'partial', executed: '2026-11-02', rto_actual_min: 45, rpo_actual_min: 30, findings: 'DNS cutover slow\nRunbook step 4 stale', actions: 'Automate DNS TTL drop', summary: 'Recovered within RTO; RPO target missed on the DB replica.' }, OP);
  assert.equal(d.status, 'completed'); assert.equal(d.result, 'partial'); assert.equal(d.executed_by, 'ali');
  assert.equal(d.met.rto, true);  // 45 <= 60
  assert.equal(d.met.rpo, false); // 30 > 15
  assert.equal(d.findings.length, 2); assert.equal(d.actions.length, 1); assert.equal(d.signoff, null);
  // sign-off needs admin and is marked independent when a different person approves
  d = G.drillSignoff(d.id, { note: 'Reviewed evidence; accept with the DNS action tracked' }, ADM);
  assert.equal(d.signoff.by, 'syed'); assert.equal(d.signoff.independent, true);
  // the person who ran the drill may not sign it off (SAMA independent review)
  let d2 = G.drillPut({ title: 'SIEM restore', system: 'SIEM', type: 'backup-restore' }, OP2);
  d2 = G.drillResult(d2.id, { result: 'pass' }, OP2);
  assert.throws(() => G.drillSignoff(d2.id, {}, OP2), /another administrator must sign it off/);
  d2 = G.drillSignoff(d2.id, {}, ADM); assert.equal(d2.signoff.independent, true);
  assert.throws(() => G.drillSignoff(G.drillPut({ title: 'x', system: 'y' }, OP).id, {}, ADM), /only a completed drill/);
});

test('grc: DR drill — per-system coverage, overdue cadence and RTO/RPO honesty', async (t) => {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  const G = createGrc(e.app); const OP = { user: 'ali' };
  const today = new Date().toISOString().slice(0, 10);
  // a system tested recently within cadence → not overdue
  let a = G.drillPut({ title: 'VMware failover', system: 'VMware Cluster', type: 'failover', frequency_months: 12, rto_target_min: 120 }, OP);
  G.drillResult(a.id, { result: 'pass', executed: today, rto_actual_min: 90 }, OP);
  // a system last tested years ago → overdue
  let b = G.drillPut({ title: 'DB restore', system: 'Oracle DB', type: 'restore', frequency_months: 12 }, OP);
  G.drillResult(b.id, { result: 'pass', executed: '2020-01-01' }, OP);
  // a system only planned, never executed → untested → overdue
  G.drillPut({ title: 'M365 tabletop', system: 'Microsoft 365', type: 'tabletop' }, OP);
  const sys = G.drillSystems();
  const by = Object.fromEntries(sys.map((s) => [s.system, s]));
  assert.equal(by['VMware Cluster'].overdue, false); assert.equal(by['VMware Cluster'].tested, true); assert.equal(by['VMware Cluster'].rto_met, true);
  assert.equal(by['Oracle DB'].overdue, true);
  assert.equal(by['Microsoft 365'].tested, false); assert.equal(by['Microsoft 365'].overdue, true); assert.equal(by['Microsoft 365'].last, null);
  // RTO/RPO never recorded stays null — never counted as met
  assert.equal(by['Oracle DB'].rto_met, null);
});

test('grc: DR drill — summary and report shape', async (t) => {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  const G = createGrc(e.app); const OP = { user: 'ali' }, ADM = { user: 'syed' };
  let p = G.drillPut({ title: 'Pass drill', system: 'A', rto_target_min: 60, rpo_target_min: 30 }, OP);
  G.drillResult(p.id, { result: 'pass', rto_actual_min: 30, rpo_actual_min: 10 }, OP);
  let f = G.drillPut({ title: 'Fail drill', system: 'B' }, OP);
  f = G.drillResult(f.id, { result: 'fail' }, OP); G.drillSignoff(f.id, {}, ADM);
  G.drillPut({ title: 'Future', system: 'C', scheduled: '2099-01-01' }, OP);
  const s = G.drillSummary();
  assert.equal(s.total, 3);
  assert.equal(s.by_status.completed, 2); assert.equal(s.by_status.planned, 1);
  assert.equal(s.by_result.pass, 1); assert.equal(s.by_result.fail, 1);
  assert.equal(s.rto.measured, 1); assert.equal(s.rto.met, 1); assert.equal(s.rto.pct, 100);
  assert.equal(s.awaiting_signoff, 1); assert.equal(s.signed_off, 1);
  assert.equal(s.systems.total, 3); assert.ok(s.upcoming.find((u) => u.system === 'C'));
  const r = G.drillReport();
  assert.match(r.framework, /SAMA/); assert.equal(r.indicative, true);
  assert.equal(r.drills.length, 3); assert.equal(r.systems.length, 3); assert.ok(r.summary.total === 3);
});

test('grc: DR drill routes — reads open, plan/result need operator, sign-off/delete need admin, specific routes resolve before :id', async (t) => {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerGrc(e.app.srv, e.app);
  assert.equal((await e.req('GET', '/grc/drills', { role: 'viewer' })).status, 200);
  // specific GET routes must not be swallowed by /grc/drills/:id
  const sumR = await e.req('GET', '/grc/drills/summary', { role: 'viewer' });
  assert.equal(sumR.status, 200); assert.ok(sumR.json.by_status, 'summary resolved, not treated as :id');
  const sysR = await e.req('GET', '/grc/drills/systems', { role: 'viewer' });
  assert.equal(sysR.status, 200); assert.ok(Array.isArray(sysR.json.systems));
  assert.equal((await e.req('GET', '/grc/drills/report', { role: 'viewer' })).status, 200);
  // viewer cannot plan
  assert.equal((await e.req('POST', '/grc/drills', { role: 'viewer', body: { title: 'x', system: 'y' } })).status, 403);
  const created = await e.req('POST', '/grc/drills', { role: 'operator', body: { title: 'Failover test', system: 'Payments', type: 'failover' } });
  assert.equal(created.status, 200); const id = created.json.id; assert.match(id, /^DR-/);
  assert.equal((await e.req('GET', '/grc/drills/' + id, { role: 'viewer' })).status, 200);
  assert.equal((await e.req('POST', '/grc/drills/' + id + '/result', { role: 'viewer', body: { result: 'pass' } })).status, 403);
  assert.equal((await e.req('POST', '/grc/drills/' + id + '/result', { role: 'operator', body: { result: 'pass' } })).status, 200);
  assert.equal((await e.req('POST', '/grc/drills/' + id + '/signoff', { role: 'operator', body: {} })).status, 403);
  assert.equal((await e.req('POST', '/grc/drills/' + id + '/signoff', { role: 'admin', user: 'op.one', body: { note: 'ok' } })).status, 403, 'who ran it may not sign it off');
  assert.equal((await e.req('POST', '/grc/drills/' + id + '/signoff', { role: 'admin', user: 'adm.two', body: { note: 'ok' } })).status, 200);
  assert.equal((await e.req('POST', '/grc/drills/' + id + '/delete', { role: 'operator', body: {} })).status, 403);
  assert.equal((await e.req('POST', '/grc/drills/' + id + '/delete', { role: 'admin', body: {} })).status, 200);
  assert.equal((await e.req('GET', '/grc/drills/' + id, { role: 'viewer' })).status, 404);
});

test('grc: SAMA CSF view - every policy mapped, each cross-checked on four points with a remark, ITAM signals attached', async (t) => {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  const G = createGrc(e.app);
  const { POLICY_CSF } = require('../engine/grc');
  for (const p of REGISTER) assert.ok(Array.isArray(POLICY_CSF[p.doc_id]), 'policy not mapped to the CSF: ' + p.doc_id);
  let r = G.csfCoverage();
  assert.equal(r.policies_total, 42);
  assert.ok(r.unmapped.some((u) => u.doc_id === 'IT-OPS-007' && /no SAMA CSF control/.test(u.reason)), 'batch processing has no CSF control');
  const c = r.controls['3.3.17'];
  const patch = c.policies.find((p) => p.doc_id === 'IT-DEV-009');
  assert.deepEqual(patch.items.map((i) => i.k), ['approved', 'review', 'attested', 'text']);
  for (const i of patch.items) assert.ok(i.remark && i.max === 25 && i.pts >= 0 && i.pts <= 25, i.k);
  assert.equal(patch.items[0].pts, 25); assert.equal(patch.items[2].pts, 0); assert.match(patch.items[2].remark, /No attestation recorded/);
  assert.ok(patch.lines.length > 0 && patch.lines.every((l) => /\b(vulnerab|patch|scan|penetration)/i.test(l)), 'patch policy lines address vulnerability management');
  assert.equal(patch.items[3].pts, 25);
  assert.equal(patch.score, patch.items.reduce((a, i) => a + i.pts, 0));
  // a policy whose text was not extracted cannot be cross-checked - scored 0 on that point, says so
  const inc = r.controls['3.3.15'].policies.find((p) => p.doc_id === 'IT-OPS-008');
  assert.equal(inc.items[3].pts, 0); assert.match(inc.items[3].remark, /not extracted/);
  // a procedure flow is not an approved policy record
  const flow = r.controls['3.3.14'].policies.find((p) => p.doc_id === 'IT-OPS-006-F4');
  assert.equal(flow.items[0].pts, 0); assert.match(flow.items[0].remark, /procedure flow/);
  // control with no policy: a gap, said in words
  assert.equal(r.controls['3.3.9'], undefined, 'no policy maps to cryptography');
  // ITAM signals: patch evidence on 3.3.17 (no Endpoint Central here: unknown, never pass)
  assert.ok(c.signals.some((s) => s.key === 'patch' && s.pillar === 'devices' && s.state === 'unknown'));
  // an attestation raises the score; an exception less than compliant
  G.attest('IT-DEV-009', { note: 'patch SLA met for Q3, report PM-2026-09' }, OP);
  r = G.csfCoverage();
  const p2 = r.controls['3.3.17'].policies.find((p) => p.doc_id === 'IT-DEV-009');
  assert.equal(p2.items[2].pts, 25); assert.match(p2.items[2].remark, /Confirmed followed by ali/);
  assert.equal(p2.score, patch.score + 25);
  assert.equal(r.controls['3.3.17'].policy_pct, Math.round(r.controls['3.3.17'].policies.reduce((a, x) => a + x.score, 0) / r.controls['3.3.17'].policies.length));
  // over HTTP, any signed-in role may read it
  const res = await e.req('GET', '/grc/csf-coverage', { role: 'viewer' });
  assert.equal(res.status, 200); assert.ok(res.json.controls['3.3.17']);
});
