// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// The shared gap-assessment engagement (engine/gap-engagement.js) through its NCA ECC adapter (engine/nca-gap.js), SYNTHETIC data:
// team & scope validated; kick-off with the 17 ECC evidence items per department; the register baseline (sources not connected
// are shown as such); the review is complete only when no control is pending, not measured or without evidence - every control
// is recorded by a person and approved by the CISO on the register (four eyes); gaps = gap / partial controls; rating; the plan
// written onto the "ecc:<control>" GRC actions (owner, due) and frozen; summary, the lead's signature, the CISO's approval (never
// the signer, never a service identity); viewer and non-team refused; every step audited; report and CSV.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');

const now = () => Date.parse('2026-11-01T08:00:00Z');
const LEAD = { user: 'lina.syn', role: 'operator' }, ASR = { user: 'amir.syn', role: 'operator' }, OUT = { user: 'omar.syn', role: 'operator' }, CISO = { user: 'karim.syn', role: 'operator' }, ADM = { user: 'syed', role: 'admin' }, VW = { user: 'v.syn', role: 'viewer' }, BOT = { user: 'ai:nca', role: 'admin' };
const B = '/nca-ecc/gap';

test('NCA ECC gap assessment: team to approved report, on the shared engagement', async (t) => {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true, now, python: process.env.PYTHON || 'python3' });
  const audits = []; const orig = e.app.audit; e.app.audit = (a) => { audits.push(a); return orig ? orig.call(e.app, a) : undefined; };
  const post = (p, body, who) => e.req('POST', p, Object.assign({ body }, who || LEAD)), get = (p, who) => e.req('GET', p, who || LEAD);
  assert.equal((await post('/nca-ecc/profile', { ciso_user: 'karim.syn' }, ADM)).status, 200);
  let r = await get(B); assert.equal(r.status, 200, r.text); assert.equal(r.json.framework, 'nca'); assert.equal(r.json.approver, 'karim.syn'); assert.equal(r.json.approver_name, 'CISO');
  assert.equal(r.json.evidence_catalogue.length, 17); assert.ok(r.json.evidence_catalogue.every((x) => /ECC \d-\d/.test(x.ref)));
  assert.equal((await get(B, VW)).status, 403, 'viewer refused');
  const S = { name: 'ECC gap 2026', lead: 'lina.syn', assessors: ['amir.syn'], departments: ['IT', 'Cybersecurity'], start: '2026-11-01', target: '2026-12-31' };
  assert.equal((await post(B, Object.assign({}, S, { assessors: ['bad name'] }))).status, 400);
  assert.equal((await post(B, S, BOT)).status, 403, 'a service identity never opens one');
  r = await post(B, S); assert.equal(r.status, 200, r.text); const id = r.json.id; assert.equal(id, 'NGA-2026-001');
  assert.equal((await post(B + '/' + id + '/kickoff', { due: '2026-11-20' }, OUT)).status, 403, 'not on the team');
  r = await post(B + '/' + id + '/kickoff', { due: '2026-11-20' }, ASR); assert.equal(r.json.evidence.length, 34);
  // baseline: the register as it stands
  r = await post(B + '/' + id + '/baseline', {}); assert.equal(r.status, 200, r.text);
  assert.ok(r.json.baseline.table.some((x) => /^Controls: Gap/.test(x.label))); assert.equal(r.json.baseline.controls, 53); assert.ok(r.json.baseline.counts.no_evidence > 0);
  r = await post(B + '/' + id + '/review', {}); assert.equal(r.status, 200, r.text); assert.equal(r.json.review.done, false); assert.match(r.json.steps[3].block, /to be recorded by a person/);
  assert.equal((await post(B + '/' + id + '/gaps/ZS-1-1-01', { likelihood: 3, impact: 3, root_cause: 'not yet', recommendation: 'nothing to rate yet', owner: 'amir.syn', target: '2026-12-31' })).status, 409, 'rate after the review');
  // every open control is recorded by an assessor and approved by the CISO on the register
  let v = (await get('/nca-ecc', ASR)).json; const open = v.controls.filter((c) => ['pending', 'not_measured', 'no_evidence'].includes(c.result)); assert.ok(open.length > 5);
  const PART = open[0].id;
  for (const c of open) { const rec = c.id === PART ? { id: c.id, status: 'partial', evidence: 'draft document (synthetic)' } : { id: c.id, status: 'compliant', evidence: 'synthetic evidence ' + c.id };
    const x = await post('/nca-ecc/confirm', rec, ASR); assert.equal(x.status, 200, c.id + ' ' + x.text); }
  assert.equal((await post('/nca-ecc/confirm/' + open[1].id + '/decide', { decision: 'approve' }, ASR)).status, 403, 'the recorder never approves');
  for (const c of open) { const x = await post('/nca-ecc/confirm/' + c.id + '/decide', { decision: 'approve' }, CISO); assert.equal(x.status, 200, x.text); }
  r = await get(B + '/' + id); assert.equal(r.json.review.done, true, JSON.stringify(r.json.steps[3])); assert.equal(r.json.steps[3].done, true);
  const gaps = r.json.gaps; assert.ok(gaps.length >= 2); assert.ok(gaps.some((g) => g.id === PART && g.answer === 'partial')); assert.ok(gaps.every((g) => ['gap', 'partial'].includes(g.answer)));
  // rate every gap, then publish
  for (const g of gaps) { const x = await post(B + '/' + id + '/gaps/' + g.id, { likelihood: g.id === PART ? 2 : 4, impact: 4, root_cause: 'no owner assigned (synthetic)', recommendation: 'assign an owner and implement the control', owner: 'amir.syn', target: '2027-02-28' }, ASR); assert.equal(x.status, 200, x.text); }
  assert.equal((await post(B + '/' + id + '/gaps/ZS-9-9-99', {})).status, 400, 'not a control id');
  r = await post(B + '/' + id + '/plan', {}); assert.equal(r.status, 200, r.text); assert.equal(r.json.plan.actions.length, gaps.length); assert.equal(r.json.plan.snapshot, undefined, 'the frozen list is not sent');
  const act = (await get('/grc/actions?source=nca', ADM)).json.items.find((a) => a.ref === 'ecc:' + gaps[0].id); assert.equal(act.owner, 'amir.syn'); assert.equal(act.due, '2027-02-28'); assert.equal(act.framework, 'NCA ECC');
  // the published gap list is frozen: a later change on the register does not change the report
  r = await get(B + '/' + id); assert.equal(r.json.gaps.length, gaps.length);
  // report
  assert.equal((await post(B + '/' + id + '/report/summary', { summary: 'Gaps found in governance; plan published with owners.' }, ASR)).status, 403, 'the lead writes it');
  assert.equal((await post(B + '/' + id + '/report/summary', { summary: 'Gaps found in governance; plan published with owners.' })).status, 200);
  assert.equal((await post(B + '/' + id + '/report/sign', {})).status, 200);
  assert.equal((await post(B + '/' + id + '/report/approve', {}, ASR)).status, 403, 'not the CISO');
  assert.equal((await post(B + '/' + id + '/report/approve', {}, { user: 'lina.syn', role: 'admin' })).status, 403, 'never the signer');
  assert.equal((await post(B + '/' + id + '/report/approve', {}, BOT)).status, 403, 'never a service identity');
  r = await post(B + '/' + id + '/report/approve', {}, CISO); assert.equal(r.status, 200, r.text); assert.equal(r.json.status, 'closed'); assert.ok(r.json.steps.every((s) => s.done));
  for (const a of ['create', 'kickoff', 'baseline', 'review', 'rate', 'plan', 'summary', 'sign', 'approve']) assert.ok(audits.some((x) => x.action === 'nca.gap.' + a && x.target === id), 'audited: ' + a);
  r = await get(B + '/' + id + '/report?format=html'); assert.match(r.json.html, /NCA ECC Gap Assessment/); assert.match(r.json.html, /not an NCA certificate/); assert.match(r.json.html, /approved by karim\.syn/); assert.match(r.json.html, /Compliance score/);
  r = await get(B + '/' + id + '/report?format=csv'); assert.match(r.json.csv, /^# NCA ECC gap assessment/); assert.ok(audits.some((x) => x.action === 'nca.gap.report'));
  // the PDPL engagement is a separate collection: an open NCA one does not block it
  assert.equal((await post('/pdpl/gap', Object.assign({}, S, { name: 'PDPL gap 2026' }))).status, 200);
});

test('ISO 27001 gap assessment: team to approved report, on the shared engagement', async (t) => {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true, now, python: process.env.PYTHON || 'python3' });
  const audits = []; const orig = e.app.audit; e.app.audit = (a) => { audits.push(a); return orig ? orig.call(e.app, a) : undefined; };
  const post = (p, body, who) => e.req('POST', p, Object.assign({ body }, who || LEAD)), get = (p, who) => e.req('GET', p, who || LEAD);
  assert.equal((await post('/iso27001/profile', { isms_manager: 'karim.syn' }, ADM)).status, 200, 'ISMS manager named');
  const B = '/iso27001/gap'; let r = await get(B); assert.equal(r.status, 200, r.text); assert.equal(r.json.framework, 'iso'); assert.equal(r.json.approver, 'karim.syn'); assert.equal(r.json.approver_name, 'ISMS manager');
  assert.equal(r.json.evidence_catalogue.length, 20); assert.ok(r.json.evidence_catalogue.every((x) => /Clause \d|A\.\d/.test(x.ref)));
  assert.equal((await get(B, VW)).status, 403, 'viewer refused');
  const S = { name: 'ISO gap 2026', lead: 'lina.syn', assessors: ['amir.syn'], departments: ['IT', 'Cybersecurity'], start: '2026-11-01', target: '2026-12-31' };
  assert.equal((await post(B, Object.assign({}, S, { assessors: ['bad name'] }))).status, 400);
  assert.equal((await post(B, S, BOT)).status, 403, 'a service identity never opens one');
  r = await post(B, S); assert.equal(r.status, 200, r.text); const id = r.json.id; assert.equal(id, 'IGA-2026-001');
  assert.equal((await post(B + '/' + id + '/kickoff', { due: '2026-11-20' }, OUT)).status, 403, 'not on the team');
  r = await post(B + '/' + id + '/kickoff', { due: '2026-11-20' }, ASR); assert.equal(r.json.evidence.length, 40);
  // baseline: the register as it stands
  r = await post(B + '/' + id + '/baseline', {}); assert.equal(r.status, 200, r.text);
  assert.ok(r.json.baseline.table.some((x) => /^Clauses & controls: Gap/.test(x.label))); assert.ok(r.json.baseline.table.some((x) => x.key === 'soa')); assert.equal(r.json.baseline.controls, 118); assert.ok(r.json.baseline.counts.no_evidence > 0);
  r = await post(B + '/' + id + '/review', {}); assert.equal(r.status, 200, r.text); assert.equal(r.json.review.done, false); assert.match(r.json.steps[3].block, /to be recorded by a person/);
  assert.equal((await post(B + '/' + id + '/gaps/A.5.9', { likelihood: 3, impact: 3, root_cause: 'not yet', recommendation: 'nothing to rate yet', owner: 'amir.syn', target: '2026-12-31' })).status, 409, 'rate after the review');
  // every open control is recorded by an assessor and approved by the CISO on the register
  let v = (await get('/iso27001', ASR)).json; const open = v.clauses.concat(v.annex).filter((c) => ['pending', 'not_measured', 'no_evidence'].includes(c.result)); assert.ok(open.length > 5);
  const PART = open[0].id;
  for (const c of open) { const rec = c.id === PART ? { id: c.id, status: 'partial', evidence: 'draft document (synthetic)' } : { id: c.id, status: 'compliant', evidence: 'synthetic evidence ' + c.id };
    const x = await post('/iso27001/confirm', rec, ASR); assert.equal(x.status, 200, c.id + ' ' + x.text); }
  assert.equal((await post('/iso27001/confirm/' + open[1].id + '/decide', { decision: 'approve' }, ASR)).status, 403, 'the recorder never approves');
  for (const c of open) { const x = await post('/iso27001/confirm/' + c.id + '/decide', { decision: 'approve' }, CISO); assert.equal(x.status, 200, x.text); }
  r = await get(B + '/' + id); assert.equal(r.json.review.done, true, JSON.stringify(r.json.steps[3])); assert.equal(r.json.steps[3].done, true);
  const gaps = r.json.gaps; assert.ok(gaps.length >= 2); assert.ok(gaps.some((g) => g.id === PART && g.answer === 'partial')); assert.ok(gaps.every((g) => ['gap', 'partial'].includes(g.answer)));
  // rate every gap, then publish
  for (const g of gaps) { const x = await post(B + '/' + id + '/gaps/' + g.id, { likelihood: g.id === PART ? 2 : 4, impact: 4, root_cause: 'no owner assigned (synthetic)', recommendation: 'assign an owner and implement the control', owner: 'amir.syn', target: '2027-02-28' }, ASR); assert.equal(x.status, 200, x.text); }
  assert.equal((await post(B + '/' + id + '/gaps/A.9.99', {})).status, 400, 'not a control id');
  r = await post(B + '/' + id + '/plan', {}); assert.equal(r.status, 200, r.text); assert.equal(r.json.plan.actions.length, gaps.length); assert.equal(r.json.plan.snapshot, undefined, 'the frozen list is not sent');
  const act = (await get('/grc/actions?source=iso', ADM)).json.items.find((a) => a.ref === 'iso:' + gaps[0].id); assert.equal(act.owner, 'amir.syn'); assert.equal(act.due, '2027-02-28'); assert.equal(act.framework, 'ISO 27001');
  // the published gap list is frozen: a later change on the register does not change the report
  r = await get(B + '/' + id); assert.equal(r.json.gaps.length, gaps.length);
  // report
  assert.equal((await post(B + '/' + id + '/report/summary', { summary: 'Gaps found in governance; plan published with owners.' }, ASR)).status, 403, 'the lead writes it');
  assert.equal((await post(B + '/' + id + '/report/summary', { summary: 'Gaps found in governance; plan published with owners.' })).status, 200);
  assert.equal((await post(B + '/' + id + '/report/sign', {})).status, 200);
  assert.equal((await post(B + '/' + id + '/report/approve', {}, ASR)).status, 403, 'not the CISO');
  assert.equal((await post(B + '/' + id + '/report/approve', {}, { user: 'lina.syn', role: 'admin' })).status, 403, 'never the signer');
  assert.equal((await post(B + '/' + id + '/report/approve', {}, BOT)).status, 403, 'never a service identity');
  r = await post(B + '/' + id + '/report/approve', {}, CISO); assert.equal(r.status, 200, r.text); assert.equal(r.json.status, 'closed'); assert.ok(r.json.steps.every((s) => s.done));
  for (const a of ['create', 'kickoff', 'baseline', 'review', 'rate', 'plan', 'summary', 'sign', 'approve']) assert.ok(audits.some((x) => x.action === 'iso.gap.' + a && x.target === id), 'audited: ' + a);
  r = await get(B + '/' + id + '/report?format=html'); assert.match(r.json.html, /ISO\/IEC 27001:2022 Gap Assessment/); assert.match(r.json.html, /not a certification audit/); assert.match(r.json.html, /approved by karim\.syn/); assert.match(r.json.html, /Compliance score/);
  r = await get(B + '/' + id + '/report?format=csv'); assert.match(r.json.csv, /^# ISO 27001 gap assessment/); assert.ok(audits.some((x) => x.action === 'iso.gap.report'));
  // the NCA engagement is a separate collection: an open ISO one does not block it
  assert.equal((await post('/nca-ecc/gap', Object.assign({}, S, { name: 'NCA gap 2026' }))).status, 200);
});

test('SAMA CSF gap assessment: team to approved report, on the shared engagement', async (t) => {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true, now, python: process.env.PYTHON || 'python3' });
  const audits = []; const orig = e.app.audit; e.app.audit = (a) => { audits.push(a); return orig ? orig.call(e.app, a) : undefined; };
  const post = (p, body, who) => e.req('POST', p, Object.assign({ body }, who || LEAD)), get = (p, who) => e.req('GET', p, who || LEAD);
  assert.equal((await post('/nca-ecc/profile', { ciso_user: 'karim.syn' }, ADM)).status, 200, 'CISO named (shared by the SAMA register)');
  const B = '/sama-ia/gap'; let r = await get(B); assert.equal(r.status, 200, r.text); assert.equal(r.json.framework, 'sama'); assert.equal(r.json.approver, 'karim.syn'); assert.equal(r.json.approver_name, 'CISO');
  assert.equal(r.json.evidence_catalogue.length, 18); assert.ok(r.json.evidence_catalogue.every((x) => /SAMA CSF 3\.\d/.test(x.ref)));
  assert.equal((await get(B, VW)).status, 403, 'viewer refused');
  const S = { name: 'SAMA gap 2026', lead: 'lina.syn', assessors: ['amir.syn'], departments: ['IT', 'Cybersecurity'], start: '2026-11-01', target: '2026-12-31' };
  assert.equal((await post(B, Object.assign({}, S, { assessors: ['bad name'] }))).status, 400);
  assert.equal((await post(B, S, BOT)).status, 403, 'a service identity never opens one');
  r = await post(B, S); assert.equal(r.status, 200, r.text); const id = r.json.id; assert.equal(id, 'SGA-2026-001');
  assert.equal((await post(B + '/' + id + '/kickoff', { due: '2026-11-20' }, OUT)).status, 403, 'not on the team');
  r = await post(B + '/' + id + '/kickoff', { due: '2026-11-20' }, ASR); assert.equal(r.json.evidence.length, 36);
  // baseline: the register as it stands
  r = await post(B + '/' + id + '/baseline', {}); assert.equal(r.status, 200, r.text);
  assert.ok(r.json.baseline.table.some((x) => /^Requirements: Gap/.test(x.label))); assert.ok(r.json.baseline.table.some((x) => x.key === 'ciso' && x.text === 'karim.syn')); assert.equal(r.json.baseline.controls, 57); assert.ok(r.json.baseline.counts.no_evidence > 0);
  r = await post(B + '/' + id + '/review', {}); assert.equal(r.status, 200, r.text); assert.equal(r.json.review.done, false); assert.match(r.json.steps[3].block, /to be recorded by a person/);
  assert.equal((await post(B + '/' + id + '/gaps/SA-3.1.1-01', { likelihood: 3, impact: 3, root_cause: 'not yet', recommendation: 'nothing to rate yet', owner: 'amir.syn', target: '2026-12-31' })).status, 409, 'rate after the review');
  // every open control is recorded by an assessor and approved by the CISO on the register
  let v = (await get('/sama-ia', ASR)).json; const open = v.requirements.concat(v.ia.requirements).filter((c) => ['pending', 'not_measured', 'no_evidence'].includes(c.result)); assert.ok(open.length > 5);
  const PART = open[0].id;
  for (const c of open) { const rec = c.id === PART ? { id: c.id, status: 'partial', evidence: 'draft document (synthetic)' } : { id: c.id, status: 'compliant', evidence: 'synthetic evidence ' + c.id };
    const x = await post('/sama-ia/confirm', rec, ASR); assert.equal(x.status, 200, c.id + ' ' + x.text); }
  assert.equal((await post('/sama-ia/confirm/' + open[1].id + '/decide', { decision: 'approve' }, ASR)).status, 403, 'the recorder never approves');
  for (const c of open) { const x = await post('/sama-ia/confirm/' + c.id + '/decide', { decision: 'approve' }, CISO); assert.equal(x.status, 200, x.text); }
  r = await get(B + '/' + id); assert.equal(r.json.review.done, true, JSON.stringify(r.json.steps[3])); assert.equal(r.json.steps[3].done, true);
  const gaps = r.json.gaps; assert.ok(gaps.length >= 2); assert.ok(gaps.some((g) => g.id === PART && g.answer === 'partial')); assert.ok(gaps.every((g) => ['gap', 'partial'].includes(g.answer)));
  // rate every gap, then publish
  for (const g of gaps) { const x = await post(B + '/' + id + '/gaps/' + g.id, { likelihood: g.id === PART ? 2 : 4, impact: 4, root_cause: 'no owner assigned (synthetic)', recommendation: 'assign an owner and implement the control', owner: 'amir.syn', target: '2027-02-28' }, ASR); assert.equal(x.status, 200, x.text); }
  assert.equal((await post(B + '/' + id + '/gaps/SA-9.9.9-99', {})).status, 400, 'not a control id');
  r = await post(B + '/' + id + '/plan', {}); assert.equal(r.status, 200, r.text); assert.equal(r.json.plan.actions.length, gaps.length); assert.equal(r.json.plan.snapshot, undefined, 'the frozen list is not sent');
  const act = (await get('/grc/actions?source=sama', ADM)).json.items.find((a) => a.ref === 'sama:' + gaps[0].id); assert.equal(act.owner, 'amir.syn'); assert.equal(act.due, '2027-02-28'); assert.equal(act.framework, 'SAMA CSF');
  // the published gap list is frozen: a later change on the register does not change the report
  r = await get(B + '/' + id); assert.equal(r.json.gaps.length, gaps.length);
  // report
  assert.equal((await post(B + '/' + id + '/report/summary', { summary: 'Gaps found in governance; plan published with owners.' }, ASR)).status, 403, 'the lead writes it');
  assert.equal((await post(B + '/' + id + '/report/summary', { summary: 'Gaps found in governance; plan published with owners.' })).status, 200);
  assert.equal((await post(B + '/' + id + '/report/sign', {})).status, 200);
  assert.equal((await post(B + '/' + id + '/report/approve', {}, ASR)).status, 403, 'not the CISO');
  assert.equal((await post(B + '/' + id + '/report/approve', {}, { user: 'lina.syn', role: 'admin' })).status, 403, 'never the signer');
  assert.equal((await post(B + '/' + id + '/report/approve', {}, BOT)).status, 403, 'never a service identity');
  r = await post(B + '/' + id + '/report/approve', {}, CISO); assert.equal(r.status, 200, r.text); assert.equal(r.json.status, 'closed'); assert.ok(r.json.steps.every((s) => s.done));
  for (const a of ['create', 'kickoff', 'baseline', 'review', 'rate', 'plan', 'summary', 'sign', 'approve']) assert.ok(audits.some((x) => x.action === 'sama.gap.' + a && x.target === id), 'audited: ' + a);
  r = await get(B + '/' + id + '/report?format=html'); assert.match(r.json.html, /SAMA Cyber Security Framework Gap Assessment/); assert.match(r.json.html, /not a SAMA or Insurance Authority assessment/); assert.match(r.json.html, /approved by karim\.syn/); assert.match(r.json.html, /Compliance score/);
  r = await get(B + '/' + id + '/report?format=csv'); assert.match(r.json.csv, /^# SAMA CSF gap assessment/); assert.ok(audits.some((x) => x.action === 'sama.gap.report'));
  // the ISO engagement is a separate collection: an open SAMA one does not block it
  assert.equal((await post('/iso27001/gap', Object.assign({}, S, { name: 'ISO gap 2026' }))).status, 200);
});

test('NDMO gap assessment: team to approved report, on the shared engagement', async (t) => {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true, now, python: process.env.PYTHON || 'python3' });
  const audits = []; const orig = e.app.audit; e.app.audit = (a) => { audits.push(a); return orig ? orig.call(e.app, a) : undefined; };
  const post = (p, body, who) => e.req('POST', p, Object.assign({ body }, who || LEAD)), get = (p, who) => e.req('GET', p, who || LEAD);
  assert.equal((await post('/ndmo/profile', { cdo_user: 'karim.syn' }, ADM)).status, 200, 'CDO named');
  const B = '/ndmo/gap'; let r = await get(B); assert.equal(r.status, 200, r.text); assert.equal(r.json.framework, 'ndmo'); assert.equal(r.json.approver, 'karim.syn'); assert.equal(r.json.approver_name, 'Chief Data Officer');
  assert.equal(r.json.evidence_catalogue.length, 16); assert.ok(r.json.evidence_catalogue.every((x) => /^[A-Z]{2,3} - /.test(x.ref)));
  assert.equal((await get(B, VW)).status, 403, 'viewer refused');
  const S = { name: 'NDMO gap 2026', lead: 'lina.syn', assessors: ['amir.syn'], departments: ['IT', 'Cybersecurity'], start: '2026-11-01', target: '2026-12-31' };
  assert.equal((await post(B, Object.assign({}, S, { assessors: ['bad name'] }))).status, 400);
  assert.equal((await post(B, S, BOT)).status, 403, 'a service identity never opens one');
  r = await post(B, S); assert.equal(r.status, 200, r.text); const id = r.json.id; assert.equal(id, 'DGA-2026-001');
  assert.equal((await post(B + '/' + id + '/kickoff', { due: '2026-11-20' }, OUT)).status, 403, 'not on the team');
  r = await post(B + '/' + id + '/kickoff', { due: '2026-11-20' }, ASR); assert.equal(r.json.evidence.length, 32);
  // baseline: the register as it stands
  r = await post(B + '/' + id + '/baseline', {}); assert.equal(r.status, 200, r.text);
  assert.ok(r.json.baseline.table.some((x) => /^Controls: Gap/.test(x.label))); assert.ok(r.json.baseline.table.some((x) => /^Maturity: Data Governance/.test(x.label))); assert.equal(r.json.baseline.controls, 57); assert.ok(r.json.baseline.counts.no_evidence > 0);
  r = await post(B + '/' + id + '/review', {}); assert.equal(r.status, 200, r.text); assert.equal(r.json.review.done, false); assert.match(r.json.steps[3].block, /to be recorded by a person/);
  assert.equal((await post(B + '/' + id + '/gaps/ZS-DG-01', { likelihood: 3, impact: 3, root_cause: 'not yet', recommendation: 'nothing to rate yet', owner: 'amir.syn', target: '2026-12-31' })).status, 409, 'rate after the review');
  // every open control is recorded by an assessor and approved by the CISO on the register
  let v = (await get('/ndmo', ASR)).json; const open = v.controls.filter((c) => ['pending', 'not_measured', 'no_evidence'].includes(c.result)); assert.ok(open.length > 5);
  const PART = open[0].id;
  for (const c of open) { const rec = c.id === PART ? { id: c.id, status: 'partial', evidence: 'draft document (synthetic)' } : { id: c.id, status: 'compliant', evidence: 'synthetic evidence ' + c.id };
    const x = await post('/ndmo/confirm', rec, ASR); assert.equal(x.status, 200, c.id + ' ' + x.text); }
  assert.equal((await post('/ndmo/confirm/' + open[1].id + '/decide', { decision: 'approve' }, ASR)).status, 403, 'the recorder never approves');
  for (const c of open) { const x = await post('/ndmo/confirm/' + c.id + '/decide', { decision: 'approve' }, CISO); assert.equal(x.status, 200, x.text); }
  r = await get(B + '/' + id); assert.equal(r.json.review.done, true, JSON.stringify(r.json.steps[3])); assert.equal(r.json.steps[3].done, true);
  const gaps = r.json.gaps; assert.ok(gaps.length >= 2); assert.ok(gaps.some((g) => g.id === PART && g.answer === 'partial')); assert.ok(gaps.every((g) => ['gap', 'partial'].includes(g.answer)));
  // rate every gap, then publish
  for (const g of gaps) { const x = await post(B + '/' + id + '/gaps/' + g.id, { likelihood: g.id === PART ? 2 : 4, impact: 4, root_cause: 'no owner assigned (synthetic)', recommendation: 'assign an owner and implement the control', owner: 'amir.syn', target: '2027-02-28' }, ASR); assert.equal(x.status, 200, x.text); }
  assert.equal((await post(B + '/' + id + '/gaps/ZS-9-99', {})).status, 400, 'not a control id');
  r = await post(B + '/' + id + '/plan', {}); assert.equal(r.status, 200, r.text); assert.equal(r.json.plan.actions.length, gaps.length); assert.equal(r.json.plan.snapshot, undefined, 'the frozen list is not sent');
  const act = (await get('/grc/actions?source=ndmo', ADM)).json.items.find((a) => a.ref === 'ndmo:' + gaps[0].id); assert.equal(act.owner, 'amir.syn'); assert.equal(act.due, '2027-02-28'); assert.equal(act.framework, 'NDMO');
  // the published gap list is frozen: a later change on the register does not change the report
  r = await get(B + '/' + id); assert.equal(r.json.gaps.length, gaps.length);
  // report
  assert.equal((await post(B + '/' + id + '/report/summary', { summary: 'Gaps found in governance; plan published with owners.' }, ASR)).status, 403, 'the lead writes it');
  assert.equal((await post(B + '/' + id + '/report/summary', { summary: 'Gaps found in governance; plan published with owners.' })).status, 200);
  assert.equal((await post(B + '/' + id + '/report/sign', {})).status, 200);
  assert.equal((await post(B + '/' + id + '/report/approve', {}, ASR)).status, 403, 'not the CISO');
  assert.equal((await post(B + '/' + id + '/report/approve', {}, { user: 'lina.syn', role: 'admin' })).status, 403, 'never the signer');
  assert.equal((await post(B + '/' + id + '/report/approve', {}, BOT)).status, 403, 'never a service identity');
  r = await post(B + '/' + id + '/report/approve', {}, CISO); assert.equal(r.status, 200, r.text); assert.equal(r.json.status, 'closed'); assert.ok(r.json.steps.every((s) => s.done));
  for (const a of ['create', 'kickoff', 'baseline', 'review', 'rate', 'plan', 'summary', 'sign', 'approve']) assert.ok(audits.some((x) => x.action === 'ndmo.gap.' + a && x.target === id), 'audited: ' + a);
  r = await get(B + '/' + id + '/report?format=html'); assert.match(r.json.html, /NDMO Data Management Gap Assessment/); assert.match(r.json.html, /not an NDMO \/ SDAIA assessment/); assert.match(r.json.html, /approved by karim\.syn/); assert.match(r.json.html, /Compliance score/);
  r = await get(B + '/' + id + '/report?format=csv'); assert.match(r.json.csv, /^# NDMO gap assessment/); assert.ok(audits.some((x) => x.action === 'ndmo.gap.report'));
  // the PDPL engagement is a separate collection: an open NDMO one does not block it
  assert.equal((await post('/pdpl/gap', Object.assign({}, S, { name: 'PDPL gap 2026' }))).status, 200);
});


// AI / ML on the shared engine, with a SYNTHETIC framework adapter and a stubbed AI client: the suggested rating from the chance-of-gap
// model (regression +1, partial -1), fix-once clusters, the forecast from the plan's dates, evidence analytics per department, and the
// AI draft of the summary (budget, redaction, untrusted facts, the lead only, kept as a draft, refused with AI off).
test('gap intelligence: suggested ratings, clusters, forecast, evidence analytics, AI draft', async (t) => {
  const { createGapEngagement, registerGapRoutes } = require('../engine/gap-engagement');
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  const GAPS = [{ id: 'X-1', req: '1 Governance', area: 'Governance', ref: 'X 1', text: 'A security officer is appointed', answer: 'gap', weight: 3 },
    { id: 'X-2', req: '1 Governance', area: 'Governance', ref: 'X 1', text: 'The officer reports to the board', answer: 'gap', weight: 2 },
    { id: 'X-3', req: '2 Operations', area: 'Operations', ref: 'X 2', text: 'Backups are tested', answer: 'partial', weight: 1 }];
  const FEAT = { 'X-1': { severity: 'high', p_gap: 0.9, runs: 10, regression: true, cause: 'no officer recorded in the profile' }, 'X-2': { severity: 'medium', p_gap: 0.5, runs: 10, cause: 'no officer recorded in the profile' }, 'X-3': { severity: 'low', cause: 'backup tests not recorded' } };
  const AD = { fw: 'syn', name: 'Synthetic FW', collection: 'syn_gap', prefix: 'YGA', audit: 'syn.gap.', evidence: [['policy', 'Policy', 'X 1'], ['logs', 'Logs', 'X 2']], steps: ['a', 'b', 'c', 'd', 'e', 'f', 'g'],
    approverName: 'Officer', reviewName: 'synthetic review', gid: /^X-\d$/, gidName: 'X-n', reqLabel: 'Req', textLabel: 'Text', reportTitle: 'Synthetic Gap Assessment', disclaimer: 'Synthetic.', note: 'Synthetic.',
    approver: () => 'karim.syn', baseline: async () => ({ counts: {}, empty: [], table: [] }), startReview: async () => 'SYN', review: async () => ({ id: 'SYN', label: 'syn', status: 'approved', done: true, score: 40, chapters: [], what: 'done' }),
    gaps: async () => GAPS, features: async () => FEAT, action: (x, g) => ({ source: 'manual', ref: 'syn:' + g.id, framework: '', title: g.text }) };
  let CALLS = []; const sdk = function () { return { messages: { create: async (req) => { CALLS.push(req); return { model: 'stub-model', stop_reason: 'end_turn', usage: { input_tokens: 10, output_tokens: 20 }, content: [{ type: 'text', text: 'Synthetic draft: two governance gaps; the plan reaches 100% by March.' }] }; } } }; };
  const G = createGapEngagement(e.app, AD, { now: () => Date.parse('2026-11-01T08:00:00Z'), sdk, getKey: () => 'k' }); registerGapRoutes(e.app.srv, e.app, G, '/syn/gap');
  const post = (p, b, who) => e.req('POST', p, Object.assign({ body: b }, who || LEAD)), get = (p, who) => e.req('GET', p, who || LEAD);
  let r = await post('/syn/gap', { name: 'Synthetic gap', lead: 'lina.syn', assessors: ['amir.syn'], departments: ['IT', 'HR'], target: '2027-03-31' }); const id = r.json.id;
  r = await post('/syn/gap/' + id + '/kickoff', { due: '2026-11-10' }); const ev = r.json.evidence;
  await post('/syn/gap/' + id + '/evidence/' + ev[0].id, { status: 'accepted', reference: 'policy v2 (synthetic)' });
  await post('/syn/gap/' + id + '/baseline', {}); r = await post('/syn/gap/' + id + '/review', {});
  const I = r.json.intel, s1 = I.suggestions['X-1'], s3 = I.suggestions['X-3'];
  assert.equal(s1.likelihood, 5, 'p_gap 0.9 -> 5 (capped with the regression)'); assert.equal(s1.impact, 4); assert.ok(s1.why.some((w) => /regressed/.test(w)) && s1.why.some((w) => /90% chance/.test(w)));
  assert.equal(I.suggestions['X-2'].likelihood, 3); assert.equal(s3.likelihood, 2, 'no history 3, partial -1'); assert.equal(s3.impact, 1, 'low 2, partial -1'); assert.ok(s3.why.some((w) => /no run history/.test(w)));
  assert.equal(I.clusters.length, 1); assert.deepEqual(I.clusters[0].gaps.sort(), ['X-1', 'X-2']); assert.match(I.clusters[0].cause, /no officer/);
  assert.equal(I.forecast, null, 'no plan dates yet: no forecast');
  // evidence analytics: the request nobody answered after its due date
  const T2 = Date.parse('2026-11-20T08:00:00Z'); const G2 = createGapEngagement(e.app, AD, { now: () => T2, sdk, getKey: () => 'k' });
  const v2 = await G2.view(id); assert.equal(v2.intel.evidence.departments.length, 2); assert.ok(v2.intel.evidence.departments[0].overdue >= 1); assert.match(v2.intel.evidence.slowest, /overdue/);
  // rate (one with the suggestion), then the forecast follows the dates
  for (const [gid, tg] of [['X-1', '2026-12-31'], ['X-2', '2027-01-31'], ['X-3', '2027-03-31']]) { const sg = I.suggestions[gid]; assert.equal((await post('/syn/gap/' + id + '/gaps/' + gid, { likelihood: sg.likelihood, impact: sg.impact, root_cause: 'no officer named (synthetic)', recommendation: 'name the officer and record it in the profile', owner: 'amir.syn', target: tg })).status, 200); }
  r = await get('/syn/gap/' + id); const F = r.json.intel.forecast;
  assert.equal(F.from, 40); assert.deepEqual(F.points.map((p) => p.date), ['2026-12-31', '2027-01-31', '2027-03-31']); assert.equal(F.points[2].score, 100); assert.ok(F.points[0].score > 40 && F.points[0].score < F.points[1].score);
  // AI draft: only after the plan, only the lead, through the guard, kept as a draft
  assert.equal((await post('/syn/gap/' + id + '/report/ai-draft', {})).status, 409, 'plan first');
  await post('/syn/gap/' + id + '/plan', {});
  assert.equal((await post('/syn/gap/' + id + '/report/ai-draft', {}, ASR)).status, 403, 'the lead asks for it');
  r = await post('/syn/gap/' + id + '/report/ai-draft', {}); assert.equal(r.status, 200, r.text);
  assert.match(r.json.ai_draft.text, /Synthetic draft/); assert.equal(r.json.ai_draft.requested_by, 'lina.syn'); assert.equal(r.json.summary, undefined, 'a draft is not adopted by itself');
  const sent = JSON.stringify(CALLS[0]); assert.match(sent, /untrusted|UNTRUSTED/i); assert.match(CALLS[0].system, /untrusted/i); assert.ok(/no officer named/.test(sent), 'the facts are the engagement\'s own');
  // AI off: refused with the reason
  const G3 = createGapEngagement(e.app, Object.assign({}, AD, { collection: 'syn_gap' }), { now: () => T2, getKey: () => '' });
  await assert.rejects(() => G3.aiDraft(id, { user: 'lina.syn', role: 'operator' }), (er) => er.status === 503);
});

test('previous years: import a past report (CSV / Excel), compare recurring / new / closed, export as JSON for Excel', async (t) => {
  const { createGapEngagement, registerGapRoutes } = require('../engine/gap-engagement');
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  const audits = []; const orig = e.app.audit; e.app.audit = (a) => { audits.push(a); return orig ? orig.call(e.app, a) : undefined; };
  const GAPS = [{ id: 'X-1', req: '1 Gov', area: 'Gov', ref: 'X 1', text: 'A security officer is appointed', answer: 'gap', weight: 3 },
    { id: 'X-5', req: '2 Ops', area: 'Ops', ref: 'X 2', text: 'Backups are tested every quarter', answer: 'partial', weight: 1 }, { id: 'X-7', req: '3 New', area: 'New', ref: 'X 3', text: 'Cloud use is approved', answer: 'gap', weight: 2 }];
  const AD = { fw: 'syh', name: 'Synthetic FW', collection: 'syh_gap', prefix: 'HGA', audit: 'syh.gap.', evidence: [['policy', 'Policy', 'X 1']], steps: ['a', 'b', 'c', 'd', 'e', 'f', 'g'],
    approverName: 'Officer', reviewName: 'r', gid: /^X-\d$/, gidName: 'X-n', reqLabel: 'Req', textLabel: 'Text', reportTitle: 'Synthetic Gap Assessment', disclaimer: 'Synthetic.', note: 'Synthetic.',
    approver: () => 'karim.syn', baseline: async () => ({ counts: {}, empty: [], table: [] }), startReview: async () => 'SYN', review: async () => ({ id: 'SYN', label: 'syn', status: 'approved', done: true, score: 40, chapters: [], what: 'done' }),
    gaps: async () => GAPS, action: (x, g) => ({ source: 'manual', ref: 'syh:' + g.id, framework: '', title: g.text }) };
  const G = createGapEngagement(e.app, AD, { now: () => Date.parse('2026-11-01T08:00:00Z') }); registerGapRoutes(e.app.srv, e.app, G, '/syh/gap');
  const post = (p, b, who) => e.req('POST', p, Object.assign({ body: b }, who || LEAD)), get = (p, who) => e.req('GET', p, who || LEAD);
  let r = await post('/syh/gap', { name: 'Synthetic 2026', lead: 'lina.syn', assessors: ['amir.syn'], departments: ['IT'], target: '2027-03-31' }); const id = r.json.id;
  // a 2025 report as this platform's own CSV export: X-1 recurring (by id), X-5 recurring (by text, renumbered), X-2 closed; X-9 was compliant
  const csv = '# Synthetic gap assessment HGA-2025-001 (closed)\r\nGap,Req,Area,Reference,Text,Result,Likelihood,Impact,Risk,Root cause,Recommendation,Owner,Target\r\n'
    + 'X-1,1 Gov,Gov,X 1,A security officer is appointed,gap,4,4,high (16),none,appoint,amir.syn,2025-12-31\r\n'
    + 'X-4,2 Ops,Ops,X 2,"Backups are tested every quarter",partial,3,2,medium (6),,,,\r\n'
    + 'X-2,1 Gov,Gov,X 1,"The officer reports to the board, quarterly",gap,3,3,medium (9),,,,\r\nX-9,4 Other,Other,X 4,Logs are kept,compliant,,,,,,,\r\n';
  const b64 = (s) => Buffer.from(s).toString('base64');
  // refused: viewer, no year, a bad file, a sheet without headings, a non-team person
  assert.equal((await post('/syh/gap/history/import', { filename: 'g.csv', data_b64: b64(csv), year: 2025 }, VW)).status, 403);
  assert.equal((await post('/syh/gap/history/import', { filename: 'g.csv', data_b64: b64(csv) })).status, 400);
  r = await post('/syh/gap/history/import', { filename: 'g.csv', data_b64: b64('just,some\r\nwords,here\r\n'), year: 2025 }); assert.equal(r.status, 400); assert.match(r.text, /heading row/);
  assert.equal((await post('/syh/gap/history/import', { filename: 'g.exe', data_b64: b64(csv), year: 2025 })).status, 400);
  assert.equal((await post('/syh/gap/history/import', { filename: 'g.csv', data_b64: b64(csv), year: 2025 }, OUT)).status, 403, 'not on any gap team');
  r = await post('/syh/gap/history/import', { filename: 'g.csv', data_b64: b64(csv), year: 2025, label: 'FY2025 gap report (synthetic)' }); assert.equal(r.status, 200, r.text);
  assert.equal(r.json.reports.length, 1); assert.equal(r.json.reports[0].rows, 4); assert.ok(r.json.reports[0].columns.includes('result'));
  assert.ok(audits.some((a) => a.action === 'syh.gap.history.import' && a.by === 'lina.syn' && a.detail.rows === 4));
  assert.ok(!JSON.stringify(e.app.store.collection('syh_gap_history').all()).includes(b64(csv)), 'the file itself is not kept');
  // the comparison (gaps exist once the review is linked)
  await post('/syh/gap/' + id + '/kickoff', { due: '2026-11-10' }); await post('/syh/gap/' + id + '/baseline', {}); await post('/syh/gap/' + id + '/review', {});
  r = await get('/syh/gap/' + id); const C = r.json.compare; assert.equal(C.with.year, 2025);
  assert.deepEqual(C.recurring.map((x) => x.id).sort(), ['X-1', 'X-5']); assert.equal(C.recurring.find((x) => x.id === 'X-1').before.risk, 'high (16)');
  assert.deepEqual(C.new.map((x) => x.id), ['X-7']); assert.deepEqual(C.closed.map((x) => x.id), ['X-2'], 'X-9 was compliant: not a closed gap');
  // the list carries the history; an Excel workbook (2024) is read too
  const xl = require('./sca-fixture').bookOf([['Cover', { A1: 'Synthetic FY2024 report' }], ['Gaps', { A3: 'Control ID', B3: 'Control title', C3: 'Compliance status', D3: 'Risk rating', A4: 'X-1', B4: 'A security officer is appointed', C4: 'Not compliant', D4: 'High', A5: 'X-3', B5: 'Something old', C5: 'Partial' }]]);
  r = await post('/syh/gap/history/import', { filename: 'fy2024.xlsx', data_b64: xl.toString('base64'), year: 2024 }); assert.equal(r.status, 200, r.text); assert.equal(r.json.reports.find((x) => x.year === 2024).rows, 2);
  r = await get('/syh/gap'); assert.equal(r.json.history.length, 2); assert.equal(r.json.current.compare.with.year, 2025, 'compared with the latest earlier report');
  // exports: JSON (the page writes the Excel), HTML carries the comparison, the CSV unchanged
  r = await get('/syh/gap/' + id + '/report?format=json'); assert.equal(r.status, 200); assert.equal(r.json.gaps.length, 3); assert.match(r.json.filename, /\.xlsx$/); assert.equal(r.json.compare.closed.length, 1);
  r = await get('/syh/gap/' + id + '/report'); assert.match(r.text, /Compared with FY2025 gap report/);
  assert.equal((await get('/syh/gap/' + id + '/report?format=pdf')).status, 400);
  // remove: admin only, audited
  const hid = (await get('/syh/gap/history')).json.reports.find((x) => x.year === 2024).id;
  assert.equal((await post('/syh/gap/history/' + hid + '/remove', {})).status, 403);
  r = await post('/syh/gap/history/' + hid + '/remove', {}, ADM); assert.equal(r.status, 200); assert.equal(r.json.reports.length, 1);
  assert.ok(audits.some((a) => a.action === 'syh.gap.history.remove' && a.by === 'syed'));
});
