// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Audit Analytics (engine/audit-analytics.js + audit-analytics-lib.js) through the real routes over a SYNTHETIC payments file: import
// (hashed, the same file refused twice, a broken CSV refused naming the problem); profile and suggested tests; duplicates, fuzzy
// duplicates, gaps, Benford (conforming vs manipulated, under 100 values "not reliable"), stratify, ageing, summarize, outliers, join
// against a platform dataset, filter; attribute sample sizes equal the AICPA table (59 / 93 / 77), seeded draws re-perform, MUS keeps
// every item above the interval; the run log carries input and result hashes; four-eyes review; dispositions; a run becomes an IT Audit
// finding only through an engagement the auditor is on; scripts need a second person's approval before they run on schedule, an edit
// withdraws it; viewer, service identity and the wrong role are refused; the CSV export is formula-safe; every step audited.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');
const L = require('../engine/audit-analytics-lib');

const NOW = Date.parse('2027-01-14T09:00:00Z');
const ADM = { user: 'syed.syn', role: 'admin' }, OP = { user: 'auditor.syn', role: 'operator' }, REV = { user: 'reviewer.syn', role: 'operator' }, VIEW = { user: 'vera.syn', role: 'viewer' }, BOT = { user: 'ai:audit', role: 'operator' };
const HEAD = { user: 'hana.syn', role: 'operator' }, LEAD = { user: 'laila.syn', role: 'operator' }, OWNER = { user: 'omar.syn', role: 'operator' };

// a deterministic synthetic payments file: Benford-like amounts, two duplicate payments, a near-duplicate vendor, two missing voucher numbers
function payments() {
  let a = 7; const r = () => { a = (a * 1103515245 + 12345) % 2147483648; return a / 2147483648; };
  const V = ['Synthetic Trading Co', 'Example Supplies LLC', 'Test Services Est', 'Demo Logistics'], rows = ['voucher,vendor,amount,paid_on,dept'];
  let v = 1000;
  for (let i = 0; i < 300; i++) { v++; if (v === 1050 || v === 1051) v = 1052; const amt = Math.round(Math.pow(10, 1 + r() * 4) * 100) / 100; rows.push([v, V[i % 4], amt, '2026-' + String(1 + (i % 12)).padStart(2, '0') + '-15', i % 3 ? 'Claims' : 'Finance'].join(',')); }
  rows.push([++v, 'Synthetic Trading Co', '4999.00', '2026-12-01', 'Claims'].join(','), [++v, 'Synthetic Trading Co', '4999.00', '2026-12-01', 'Claims'].join(','), [++v, 'Synthetic Tradng Co.', '880000', '2026-12-02', 'Claims'].join(','));
  return rows.join('\n') + '\n';
}

async function setup(t) {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  const audit0 = e.app.audit; e.app.audit = (x) => audit0(Object.assign({ at: new Date(NOW).toISOString() }, x));
  e.app.store.collection('support_contracts').put({ id: 'SC1', vendor: 'Synthetic Trading Co', value: 1000, api_key: 'never-read' });
  registerDuty(e.app.srv, e.app, { noTimer: true, now: () => NOW, python: process.env.PYTHON || 'python3' });
  const call = (m, p, b, who) => e.req(m, p, Object.assign(b !== undefined ? { body: b } : {}, who));
  return { e, post: (p, b, who = OP) => call('POST', p, b, who), get: (p, who = OP) => call('GET', p, undefined, who), audit: (a) => e.app.store.auditTail(500).filter((x) => x.action === 'audit-analytics.' + a) };
}
const run = (s, ds, test, params, other, who) => s.post('/audit-analytics/run', Object.assign({ dataset: ds, test, params }, other ? { other } : {}), who);

test('import, profile, suggestions and every analytic test', async (t) => {
  const s = await setup(t);
  let r = await s.post('/audit-analytics/datasets', { name: 'Synthetic payments 2026', purpose: 'duplicate payment review (synthetic)', csv: payments() }); assert.equal(r.status, 200, r.text);
  const D = r.json; assert.equal(D.rows, 303); assert.match(D.hash, /^sha256:[0-9a-f]{64}$/);
  assert.equal((await s.post('/audit-analytics/datasets', { name: 'again', purpose: 'x', csv: payments() })).status, 409, 'the same file twice');
  r = await s.post('/audit-analytics/datasets', { name: 'bad', purpose: 'x', csv: 'a,b\n"open,2\n' }); assert.equal(r.status, 400); assert.match(r.text, /quoted value is not closed/);
  r = await s.post('/audit-analytics/datasets', { name: 'bad', csv: 'a\n1\n' }); assert.equal(r.status, 400); assert.match(r.text, /purpose is required/);
  assert.equal(s.audit('dataset.import').length, 1);

  const v = (await s.get('/audit-analytics/datasets/' + D.id)).json;
  assert.equal(v.types.amount, 'number'); assert.equal(v.types.paid_on, 'date'); assert.equal(v.types.vendor, 'text');
  const am = v.profile.find((p) => p.field === 'amount'); assert.ok(am.max === 880000 && am.count === 303);
  for (const k of ['benford', 'gaps', 'fuzzy', 'duplicates', 'age']) assert.ok(v.suggestions.some((x) => x.test === k), 'suggests ' + k);
  assert.equal(s.audit('dataset.view').length, 1, 'viewing personal data is recorded');

  r = await run(s, D.id, 'duplicates', { keys: ['vendor', 'amount', 'paid_on'] }); assert.equal(r.status, 200, r.text); assert.equal(r.json.result.groups, 1); assert.equal(r.json.exceptions_total, 2);
  r = await run(s, D.id, 'fuzzy', { field: 'vendor' }); assert.ok(r.json.result.exceptions.some((x) => /Tradng/.test(JSON.stringify(x.values))), 'near-duplicate vendor');
  r = await run(s, D.id, 'gaps', { field: 'voucher' }); assert.equal(r.json.result.missing, 2); assert.match(r.json.summary, /2 missing/);
  r = await run(s, D.id, 'benford', { field: 'amount' }); assert.ok(r.json.result.reliable); assert.notEqual(r.json.result.conformity, 'nonconformity', 'Benford-like amounts conform: ' + r.json.summary);
  r = await run(s, D.id, 'stratify', { field: 'amount', bands: [100, 1000, 10000] }); assert.equal(r.json.result.bands.length, 4); assert.equal(r.json.result.bands.reduce((t, b) => t + b.count, 0), 303);
  r = await run(s, D.id, 'age', { field: 'paid_on', amount: 'amount', as_of: '2027-01-14' }); assert.ok(r.json.result.bands.some((b) => b.count > 0));
  r = await run(s, D.id, 'summarize', { by: 'dept', amount: 'amount' }); assert.equal(r.json.result.groups_total, 2);
  r = await run(s, D.id, 'outliers', { field: 'amount', by: 'dept' }); assert.ok(r.json.result.exceptions.some((x) => x.values.amount === '880000'), 'the 880,000 payment');
  r = await run(s, D.id, 'filter', { conditions: [{ field: 'amount', op: 'ge', value: '4999' }, { field: 'dept', op: 'eq', value: 'claims' }] }); assert.ok(r.json.exceptions_total >= 3);
  r = await run(s, D.id, 'join', { key: 'vendor', other_key: 'vendor', mode: 'unmatched_this' }, 'src:contracts'); assert.equal(r.status, 200, r.text);
  assert.ok(r.json.result.exceptions.every((x) => !/Synthetic Trading Co$/.test(x.values.vendor)), 'a vendor with a contract matches');

  // validation names the field
  assert.match((await run(s, D.id, 'nope', {})).text, /test must be one of/);
  assert.match((await run(s, D.id, 'gaps', {})).text, /field is required/);
  assert.match((await run(s, D.id, 'gaps', { field: 'nosuch' })).text, /field: nosuch is not a column/);
  assert.match((await run(s, D.id, 'filter', { conditions: [{ field: 'amount', op: 'gt' }] })).text, /conditions\[0\]\.value is required/);
  assert.match((await run(s, D.id, 'filter', { conditions: [{ field: 'amount', op: 'eval' }] })).text, /op must be one of/);
  assert.match((await run(s, D.id, 'join', { key: 'vendor', other_key: 'vendor' })).text, /other: the second dataset/);

  // platform datasets: read-only, a secret-shaped field never read
  const pc = (await s.get('/audit-analytics/datasets/src:contracts')).json; assert.ok(pc.fields.includes('vendor') && !pc.fields.includes('api_key'));
});

test('sampling: AICPA sizes, re-performable draws, monetary-unit sampling', async (t) => {
  assert.equal(L.sampleSize({ confidence: 95, tolerable: 5, expected: 0 }).size, 59);
  assert.equal(L.sampleSize({ confidence: 95, tolerable: 5, expected: 1 }).size, 93);
  assert.equal(L.sampleSize({ confidence: 90, tolerable: 5, expected: 1 }).size, 77);
  assert.throws(() => L.sampleSize({ confidence: 95, tolerable: 5, expected: 5 }), /expected deviation rate must be below/);
  assert.deepEqual(L.draw(100, 10, 42), L.draw(100, 10, 42)); assert.notDeepEqual(L.draw(100, 10, 42), L.draw(100, 10, 43));
  const s = await setup(t);
  const D = (await s.post('/audit-analytics/datasets', { name: 'p', purpose: 'sampling (synthetic)', csv: payments() })).json;
  let r = await s.post('/audit-analytics/sample', { dataset: D.id, method: 'attribute', seed: 99 }); assert.equal(r.status, 200, r.text); assert.equal(r.json.result.size, 59); assert.equal(r.json.result.seed, 99);
  const again = (await s.post('/audit-analytics/sample', { dataset: D.id, method: 'random', size: 59, seed: 99 })).json;
  assert.deepEqual(again.result.exceptions.map((x) => x['#']), r.json.result.exceptions.map((x) => x['#']), 're-performed from the seed');
  r = await s.post('/audit-analytics/sample', { dataset: D.id, method: 'mus', size: 20, amount: 'amount', seed: 5 }); assert.equal(r.status, 200, r.text);
  assert.ok(r.json.result.exceptions.some((x) => x.values.amount === '880000'), 'an item above the interval is always selected');
  r = await s.post('/audit-analytics/sample', { dataset: D.id, method: 'mus', size: 20 }); assert.equal(r.status, 400); assert.match(r.text, /amount: the monetary field is required/);
});

test('log, four-eyes review, dispositions, finding through the engagement, export, roles', async (t) => {
  const s = await setup(t);
  assert.equal((await s.get('/audit-analytics', VIEW)).status, 403, 'datasets can hold personal data: no viewers');
  const D = (await s.post('/audit-analytics/datasets', { name: 'p', purpose: 'review (synthetic)', csv: payments() })).json;
  assert.equal((await run(s, D.id, 'gaps', { field: 'voucher' }, null, BOT)).status, 403, 'a service or AI identity does not run tests');
  const R = (await run(s, D.id, 'duplicates', { keys: ['vendor', 'amount', 'paid_on'] })).json;
  assert.match(R.input_hash, /^sha256:/); assert.match(R.result_hash, /^sha256:/);
  const ov = (await s.get('/audit-analytics')).json; assert.ok(ov.runs.some((x) => x.id === R.id)); assert.equal(ov.kpis.awaiting_review, 1);
  assert.equal((await s.post('/audit-analytics/runs/' + R.id + '/review', { note: 'self' })).status, 403, 'not the person who ran it');
  assert.equal((await s.post('/audit-analytics/runs/' + R.id + '/review', { note: 'checked the parameters and re-performed' }, REV)).status, 200);
  assert.equal((await s.post('/audit-analytics/runs/' + R.id + '/review', { note: 'twice' }, ADM)).status, 409);
  assert.equal((await s.post('/audit-analytics/runs/' + R.id + '/exceptions/0', { decision: 'finding', note: 'paid twice (synthetic)' })).status, 200);
  assert.match((await s.post('/audit-analytics/runs/' + R.id + '/exceptions/9', { decision: 'finding', note: 'x' })).text, /no exception 9/);
  assert.match((await s.post('/audit-analytics/runs/' + R.id + '/exceptions/1', { decision: 'maybe', note: 'x' })).text, /decision must be one of/);

  await s.post('/ia/profile', { head_of_audit: HEAD.user, auditors: [LEAD.user] }, ADM);
  const eng = (await s.post('/ia/engagements', { title: 'Payments (synthetic)', area: 'change', auditee_dept: 'Finance', auditee_owner: OWNER.user, lead: LEAD.user, objectives: ['no duplicate payments'], scope: 's', start: '2027-01-14', fieldwork_end: '2027-01-31', report_due: '2027-02-15' }, LEAD)).json;
  await (await s.post('/ia/engagements/' + eng.id + '/prior-none', { note: 'first audit of this area (synthetic)' }, LEAD), s.post('/ia/engagements/' + eng.id + '/advance', { to: 'fieldwork' }, LEAD));
  const F = { team: 'it', engagement: eng.id, owner: OWNER.user, title: 'Duplicate payment (synthetic)', criteria: 'each invoice is paid once', cause: 'no duplicate check', effect: 'overpayment', recommendation: 'add a duplicate check', rating: 'high' };
  assert.equal((await s.post('/audit-analytics/runs/' + R.id + '/to-finding', F)).status, 403, 'only an auditor on that engagement raises its findings');
  let r = await s.post('/audit-analytics/runs/' + R.id + '/to-finding', F, LEAD); assert.equal(r.status, 200, r.text); assert.match(r.json.finding.condition, /re-performable from the analytics log/);
  assert.equal((await s.post('/audit-analytics/runs/' + R.id + '/to-finding', F, LEAD)).status, 409, 'once');

  const x = await s.get('/audit-analytics/runs/' + R.id + '/export'); assert.equal(x.status, 200); assert.match(x.json.csv, /^# AAR-\d{4} duplicates/); assert.match(x.json.csv, /paid twice/);
  const inj = (await s.post('/audit-analytics/datasets', { name: 'inj', purpose: 'formula (synthetic)', csv: 'ref,amt\n=HYPERLINK("x"),5\n=HYPERLINK("x"),5\n' })).json;
  const ir = (await run(s, inj.id, 'duplicates', { keys: ['ref'] })).json; assert.match((await s.get('/audit-analytics/runs/' + ir.id + '/export')).json.csv, /"'=HYPERLINK/, 'formula-safe export');

  assert.equal((await s.post('/audit-analytics/datasets/' + inj.id + '/archive', { note: 'test' })).status, 403, 'administrators archive');
  assert.equal((await s.post('/audit-analytics/datasets/' + inj.id + '/archive', { note: 'superseded (synthetic)' }, ADM)).status, 200);
  assert.equal((await run(s, inj.id, 'gaps', { field: 'amt' })).status, 409, 'an archived dataset is not analysed');
  for (const a of ['run', 'review', 'exception.disposition', 'finding', 'export', 'dataset.archive']) assert.ok(s.audit(a).length >= 1, 'audited: ' + a);
  assert.equal(s.audit('run')[0].by !== undefined, true);
});

test('scripts: approval by a second person, an edit withdraws it, scheduled runs only when approved', async (t) => {
  const s = await setup(t);
  const D = (await s.post('/audit-analytics/datasets', { name: 'p', purpose: 'scripts (synthetic)', csv: payments() })).json;
  const steps = [{ test: 'duplicates', params: { keys: ['vendor', 'amount', 'paid_on'] } }, { test: 'gaps', params: { field: 'voucher' } }];
  assert.match((await s.post('/audit-analytics/scripts', { name: 'x', dataset: D.id, steps: [{ test: 'gaps', params: {} }] })).text, /steps\[0\]\.field is required/);
  let sc = (await s.post('/audit-analytics/scripts', { name: 'Payments weekly', dataset: D.id, steps, schedule: 'daily' })).json; assert.equal(sc.version, 1);
  const X = s.e.app.addons.auditAnalytics;
  X.daily(); assert.equal(s.audit('script.run').length, 0, 'not approved: not run on schedule');
  assert.equal((await s.post('/audit-analytics/scripts/' + sc.id + '/approve', {})).status, 403, 'not the author');
  assert.equal((await s.post('/audit-analytics/scripts/' + sc.id + '/approve', {}, BOT)).status, 403, 'not an AI identity');
  assert.equal((await s.post('/audit-analytics/scripts/' + sc.id + '/approve', {}, REV)).status, 200);
  X.daily(); const runs = s.audit('script.run'); assert.equal(runs.length, 1); assert.equal(runs[0].by, 'system:audit-analytics'); assert.equal(runs[0].detail.runs, 2);
  X.daily(); assert.equal(s.audit('script.run').length, 1, 'once a day');
  sc = (await s.post('/audit-analytics/scripts', { id: sc.id, name: 'Payments weekly', dataset: D.id, steps: steps.slice(0, 1), schedule: 'daily' }, REV)).json;
  assert.equal(sc.version, 2); assert.equal(sc.approved_by, null, 'an edit withdraws the approval');
  assert.equal((await s.post('/audit-analytics/scripts/' + sc.id + '/approve', {}, REV)).status, 403, 'not the person who edited it');
  const r = await s.post('/audit-analytics/scripts/' + sc.id + '/run', {}); assert.equal(r.status, 200); assert.equal(r.json.results.length, 1);
  assert.equal((await s.post('/audit-analytics/ask', { question: 'what should I test?' }, VIEW)).status, 403);
  assert.equal((await s.post('/audit-analytics/ask', { question: 'what should I test?' })).status, 424, 'the advisor is off until an administrator allows external AI');
});

test('Benford: manipulated figures read nonconformity; under 100 values not reliable', () => {
  const rows = Array.from({ length: 300 }, (_, i) => ({ a: String(4000 + (i * 37) % 2000) }));
  const b = L.benford(rows, { field: 'a' }); assert.equal(b.conformity, 'nonconformity'); assert.ok(b.exceptions_total > 0);
  assert.match(L.benford(rows.slice(0, 50), { field: 'a' }).summary, /needs at least 100/);
});
