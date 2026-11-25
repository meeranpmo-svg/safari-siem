// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// The department framework checklist (engine/dept-checklist.js) through the real routes: an admin names each department's
// head; the head attests each periodic obligation with evidence; an auditor reviews (four-eyes, never the department's own head,
// never a service identity); fully compliant only when done AND verified; a period that ends without an attestation becomes
// overdue after the grace days; percentages per department and framework add up to 100; roles, validation, audit and CSV.
// SYNTHETIC names only.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');
const { periodOf, OBLIGATIONS } = require('../engine/dept-checklist');

const ADM = { user: 'syed', role: 'admin' }, VIEW = { user: 'vera.syn', role: 'viewer' };
const HEAD = { user: 'huda.syn', role: 'operator' }, DEP = { user: 'dana.syn', role: 'operator' }, AUD = { user: 'adel.syn', role: 'operator' }, OTHER = { user: 'omar.syn', role: 'operator' };

async function setup(t, start = '2027-01-10T08:00:00Z') {
  let clock = Date.parse(start);
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true, now: () => clock, python: process.env.PYTHON || 'python3', eccFacts: async () => ({}), ndmoCatalogFiles: false });
  const call = (m, p, body, who) => e.req(m, p, Object.assign(body !== undefined ? { body } : {}, who));
  return { e, post: (p, b, who) => call('POST', p, b, who), get: (p, who = AUD) => call('GET', p, undefined, who), tick: (d) => { clock += d * 86400000; } };
}
const item = (v, id) => v.items.find((x) => x.id === id);
const sum = (p) => p.fully + p.partially + p.not + p.not_assessed;

test('periods are Riyadh calendar periods', () => {
  assert.equal(periodOf('M', Date.parse('2027-01-31T22:00:00Z')).key, '2027-02', '01:00 on 1 Feb in Riyadh is February');
  assert.equal(periodOf('Q', Date.parse('2027-05-10T00:00:00Z')).key, '2027-Q2');
  assert.equal(periodOf('H', Date.parse('2027-07-01T00:00:00Z')).key, '2027-H2');
  assert.equal(periodOf('Y', Date.parse('2027-07-01T00:00:00Z')).key, '2027');
  assert.ok(OBLIGATIONS.every((o) => /^DO-\d{2}$/.test(o.id)) && new Set(OBLIGATIONS.map((o) => o.id)).size === OBLIGATIONS.length, 'unique ids');
});

test('nothing named is never compliant; roles on owners; validation names the field', async (t) => {
  const s = await setup(t);
  const v = (await s.get('/dept-checklist', VIEW)).json;
  assert.equal(v.overall.status, 'not_assessed'); assert.equal(sum(v.overall.pct), 100); assert.equal(v.overall.pct.not_assessed, 100);
  assert.equal(item(v, 'DO-01').result, 'no_owner'); assert.equal(v.counts.no_owner, v.departments.length);
  assert.equal((await s.post('/dept-checklist/owners', { dept: 'hr', head: HEAD.user }, AUD)).status, 403, 'operators cannot name heads');
  let r = await s.post('/dept-checklist/owners', { dept: 'hr', head: 'svc:hr' }, ADM); assert.equal(r.status, 400); assert.match(r.json.error, /head/);
  r = await s.post('/dept-checklist/owners', { dept: 'hr', head: HEAD.user, deputy: 'HUDA.syn' }, ADM); assert.equal(r.status, 400); assert.match(r.json.error, /deputy/);
  r = await s.post('/dept-checklist/owners', { dept: 'nope', head: HEAD.user }, ADM); assert.equal(r.status, 400); assert.match(r.json.error, /dept/);
  r = await s.post('/dept-checklist/owners', { dept: 'hr', head: HEAD.user, deputy: DEP.user, role: 'admin' }, ADM); assert.equal(r.status, 200, r.raw);
  const au = s.e.app.store.auditTail(20).find((x) => x.action === 'dept-checklist.owner'); assert.equal(au.by, ADM.user); assert.equal(au.detail.head, HEAD.user);
  const ow = (await s.get('/dept-checklist/owners', VIEW)).json.find((x) => x.dept === 'hr'); assert.equal(ow.named, true); assert.equal(ow.head, undefined, 'viewers do not see names (PDPL)');
  assert.equal((await s.get('/dept-checklist/owners')).json.find((x) => x.dept === 'hr').head, HEAD.user);
  assert.equal((await s.get('/dept-checklist?fw=bad')).status, 400);
  assert.equal((await s.get('/dept-checklist/export', VIEW)).status, 403);
});

test('attest, then an independent auditor verifies: only then fully compliant; four-eyes and independence enforced', async (t) => {
  const s = await setup(t);
  assert.equal((await s.post('/dept-checklist/attest', { id: 'DO-01', status: 'done', evidence: 'DMS/HR/2027-Q1' }, HEAD)).status, 409, 'no head named yet');
  await s.post('/dept-checklist/owners', { dept: 'hr', head: HEAD.user, deputy: DEP.user }, ADM);
  assert.equal((await s.post('/dept-checklist/attest', { id: 'DO-01', status: 'done', evidence: 'x' }, OTHER)).status, 403, 'not the head or deputy');
  assert.equal((await s.post('/dept-checklist/attest', { id: 'DO-01', status: 'done', evidence: 'x' }, VIEW)).status, 403, 'viewer');
  let r = await s.post('/dept-checklist/attest', { id: 'DO-01', status: 'done' }, HEAD); assert.equal(r.status, 400); assert.match(r.json.error, /evidence/);
  r = await s.post('/dept-checklist/attest', { id: 'DO-01', status: 'not_done' }, HEAD); assert.equal(r.status, 400); assert.match(r.json.error, /note/);
  r = await s.post('/dept-checklist/attest', { id: 'DO-01', status: 'done', evidence: 'x', period: '2026-Q2' }, HEAD); assert.equal(r.status, 400); assert.match(r.json.error, /period/);
  r = await s.post('/dept-checklist/attest', { id: 'DO-99', status: 'done', evidence: 'x' }, HEAD); assert.equal(r.status, 404);
  r = await s.post('/dept-checklist/attest', { id: 'DO-01', status: 'done', evidence: 'DMS/HR/screening-2027-Q1' }, HEAD); assert.equal(r.status, 200, r.raw);
  assert.equal(r.json.result, 'awaiting_review'); assert.equal(r.json.level, 'not_assessed', 'an unverified attestation is not compliance');
  const au = s.e.app.store.auditTail(20).find((x) => x.action === 'dept-checklist.attest'); assert.equal(au.by, HEAD.user); assert.equal(au.detail.period, '2027-Q1');
  assert.equal((await s.post('/dept-checklist/review', { id: 'DO-01', period: '2027-Q1', decision: 'verified' }, HEAD)).status, 403, 'four-eyes');
  r = await s.post('/dept-checklist/review', { id: 'DO-01', period: '2027-Q1', decision: 'verified' }, DEP); assert.equal(r.status, 403); assert.match(r.json.error, /independence/);
  r = await s.post('/dept-checklist/review', { id: 'DO-01', period: '2027-Q1', decision: 'exception' }, AUD); assert.equal(r.status, 400); assert.match(r.json.error, /note/);
  r = await s.post('/dept-checklist/review', { id: 'DO-01', period: '2027-Q1', decision: 'verified' }, AUD); assert.equal(r.status, 200, r.raw);
  assert.equal(r.json.result, 'verified'); assert.equal(r.json.level, 'fully');
  assert.equal(s.e.app.store.auditTail(20).find((x) => x.action === 'dept-checklist.review').detail.attested_by, HEAD.user);
  assert.equal((await s.post('/dept-checklist/review', { id: 'DO-01', period: '2027-Q1', decision: 'verified' }, OTHER)).status, 409, 'reviewed once');
  assert.equal((await s.post('/dept-checklist/attest', { id: 'DO-01', status: 'not_done', note: 'n' }, HEAD)).status, 409, 'a verified attestation is locked');
  // an exception: not compliant until the department attests again and it is verified
  await s.post('/dept-checklist/attest', { id: 'DO-02', status: 'done', evidence: 'DMS/HR/leavers' }, DEP);
  r = await s.post('/dept-checklist/review', { id: 'DO-02', period: '2027-Q1', decision: 'exception', note: 'two leavers have no IT request (synthetic)' }, AUD);
  assert.equal(r.json.result, 'exception'); assert.equal(r.json.level, 'not');
  r = await s.post('/dept-checklist/attest', { id: 'DO-02', status: 'done', evidence: 'DMS/HR/leavers-v2' }, DEP); assert.equal(r.json.result, 'awaiting_review');
  const v = (await s.get('/dept-checklist?dept=hr')).json, hr = v.departments.find((d) => d.key === 'hr');
  assert.equal(v.items.length, OBLIGATIONS.filter((o) => o.dept === 'hr').length);
  assert.equal(hr.status, 'partially_compliant'); assert.equal(sum(hr.pct), 100); assert.equal(hr.counts.fully, 1); assert.equal(hr.head, HEAD.user);
  assert.equal(item(v, 'DO-01').current.evidence, 'DMS/HR/screening-2027-Q1');
  const vv = (await s.get('/dept-checklist?dept=hr', VIEW)).json; assert.equal(item(vv, 'DO-01').current.evidence, undefined, 'viewers do not see evidence or names');
  assert.equal(item(vv, 'DO-01').result, 'verified');
  const sama = v.frameworks.find((f) => f.key === 'sama'); assert.equal(sum(sama.pct), 100); assert.ok(sama.counts.fully >= 1);
});

test('a period that ends unattested becomes overdue after the grace days and reaches the audit dashboard', async (t) => {
  const s = await setup(t);
  await s.post('/dept-checklist/owners', { dept: 'infra', head: HEAD.user }, ADM);
  let v = (await s.get('/dept-checklist?dept=infra')).json; assert.equal(item(v, 'DO-06').result, 'open', 'first month still open');
  s.tick(25);   // 2027-02-04: January ended, still within 15 days
  v = (await s.get('/dept-checklist?dept=infra')).json; assert.equal(item(v, 'DO-06').result, 'open');
  s.tick(12);   // 2027-02-16: January's grace passed
  v = (await s.get('/dept-checklist?dept=infra')).json; const d = item(v, 'DO-06');
  assert.equal(d.result, 'overdue'); assert.equal(d.level, 'not'); assert.equal(d.previous_period, '2027-01');
  assert.equal(item(v, 'DO-07').result, 'open', 'a quarterly obligation is not due yet');
  const dash = (await s.get('/audit-dashboard')).json;
  assert.ok(dash.departments.available); assert.ok(dash.attention.some((a) => a.ref === 'DO-06' && a.page === 'dept-checklist.html'));
  // a late attestation for the previous period is accepted and marked late
  const r = await s.post('/dept-checklist/attest', { id: 'DO-06', period: '2027-01', status: 'partly', evidence: 'DMS/IT/patch-2027-01', note: 'three servers waiting for a window (synthetic)' }, HEAD);
  assert.equal(r.status, 200, r.raw); assert.equal(r.json.result, 'partly'); assert.equal(r.json.level, 'partially'); assert.equal(r.json.previous.late, true);
});

test('CSV export: audited, summary first, and a cell that starts like a formula cannot run in Excel', async (t) => {
  const s = await setup(t);
  await s.post('/dept-checklist/owners', { dept: 'hr', head: HEAD.user }, ADM);
  await s.post('/dept-checklist/attest', { id: 'DO-03', status: 'done', evidence: '=HYPERLINK("http://x") synthetic' }, HEAD);
  const r = await s.get('/dept-checklist/export'); assert.equal(r.status, 200, r.raw);
  const lines = r.json.csv.split('\r\n');
  assert.match(lines[0], /^"Section","Item"/); assert.match(lines[1], /^"Overall"/);
  assert.ok(!/(^|,)"=/.test(r.json.csv), 'no cell starts with =');
  const au = s.e.app.store.auditTail(20).find((x) => x.action === 'dept-checklist.export'); assert.equal(au.by, AUD.user); assert.ok(au.detail.rows > OBLIGATIONS.length);
});

test('departments by sector (brand setting): an operations & maintenance group gets its own departments and obligations', () => {
  const B = require('../engine/brand'), { DEPTS, OBLIGATIONS } = require('../engine/dept-checklist');
  const ids = DEPTS.map((d) => d[0]), insurer = /^(insurer|insurance)$/i.test(String(B.sector || ''));
  if (insurer) { assert.ok(ids.includes('underwriting')); return; }
  for (const d of ['operations', 'projects', 'hse', 'fleet', 'site_security', 'group_services', 'hr', 'infra']) assert.ok(ids.includes(d), d);
  assert.ok(!ids.includes('underwriting') && !ids.includes('claims'), 'no insurer departments');
  assert.ok(OBLIGATIONS.every((o) => ids.includes(o.dept)), 'every obligation belongs to a department that exists');
  for (const d of ['operations', 'projects', 'hse', 'fleet', 'site_security', 'group_services']) assert.ok(OBLIGATIONS.some((o) => o.dept === d), 'obligations for ' + d);
  assert.ok(OBLIGATIONS.filter((o) => o.dept === 'group_services').some((o) => o.pdpl.includes('Art. 8')), 'processor agreements with the group companies');
});
