// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Insurer-specific PDPL controls:
//  - the sensitive-access log (engine/pdpl-access.js, pyengine/pdpl_access.py): keys (admin, once, hash only, revocable),
//    the agent API validated event by event, exceptions (no purpose, other without reason, investigation without case,
//    sensitive export, delete), volume / export indicators against the person's own pattern, review by a person who is
//    not the user concerned, settings (admin), hash-chained journal, duty findings, viewer refused, audit records
//  - fraud scoring / profiling / automated underwriting / telematics need an impact assessment (P-07)
//  - reinsurance outside the Kingdom must be a recorded transfer; identified sensitive data to a reinsurer needs a reason
// Data is SYNTHETIC.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs'), path = require('node:path');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');

const PY = process.env.PYTHON || 'python3';
let clock = Date.parse('2026-10-20T08:00:00Z');
const now = () => clock;
const OP = { user: 'nora.syn', role: 'operator' }, ADM = { user: 'syed', role: 'admin' }, VW = { user: 'v.syn', role: 'viewer' };
async function setup(t) {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true, now, python: PY });
  const post = (p, body, who = OP) => e.req('POST', p, Object.assign({ body }, who));
  const get = (p, who = OP) => e.req('GET', p, who);
  const agent = (bearer, body) => e.req('POST', '/agent/access/events', { body, bearer, user: '', role: '' });
  return { e, post, get, agent };
}
const iso = (ms) => new Date(ms).toISOString();
const acts = (e, n = 80) => e.app.store.auditTail(n).map((x) => x.action);

test('access log: keys, validated events, exceptions, review four-eyes, chain, audit, viewer refused', async (t) => {
  const { e, post, get, agent } = await setup(t);
  assert.equal((await post('/pdpl/access/keys', { name: 'Claims system' })).status, 403, 'keys are issued by an administrator');
  assert.equal((await post('/pdpl/access/keys', { name: '<b>x</b>' }, ADM)).status, 400);
  const k = (await post('/pdpl/access/keys', { name: 'Medical claims (synthetic)' }, ADM)).json;
  assert.match(k.key, /^ak_[0-9a-f]{48}$/); assert.match(k.note, /once/);
  assert.ok(!JSON.stringify(e.app.store.collection('pdpl_access_keys').all()).includes(k.key), 'only the hash is stored');
  // agent API: auth, validation per event
  assert.equal((await agent('ak_' + '0'.repeat(48), { events: [] })).status, 401);
  assert.equal((await agent(k.key, { events: [] })).status, 400);
  let r = await agent(k.key, { events: [{ at: iso(clock), user: 'ali.syn', record_ref: 'CL-1', action: 'peek' }] }); assert.equal(r.status, 400); assert.match(r.json.error, /events\[0\]: action/);
  r = await agent(k.key, { events: [{ at: iso(clock + 86400000), user: 'ali.syn', record_ref: 'CL-1', action: 'view' }] }); assert.equal(r.status, 400); assert.match(r.json.error, /future/);
  r = await agent(k.key, { events: [{ at: iso(clock), user: 'ali syn', record_ref: 'CL-1', action: 'view' }] }); assert.equal(r.status, 400); assert.match(r.json.error, /user/);
  assert.equal((await agent(k.key, { events: new Array(501).fill({ at: iso(clock), user: 'a', record_ref: 'CL-1', action: 'view' }) })).status, 400);
  const T = iso(clock - 3600000);
  r = await agent(k.key, { events: [
    { at: T, user: 'ali.syn', record_ref: 'CL-SYN-1', action: 'view', purpose: 'claim_handling', sensitive: true, categories: ['health'] },
    { at: T, user: 'ali.syn', record_ref: 'CL-SYN-2', action: 'view', sensitive: true },
    { at: T, user: 'ali.syn', record_ref: 'CL-SYN-3', action: 'view', purpose: 'other' },
    { at: T, user: 'sara.syn', record_ref: 'CL-SYN-4', action: 'view', purpose: 'fraud_investigation', sensitive: true },
    { at: T, user: 'sara.syn', record_ref: 'CL-SYN-5', action: 'export', purpose: 'medical_review', sensitive: true, reason: 'TPA review', unknown: 'dropped' },
    { at: T, user: 'nora.syn', record_ref: 'CL-SYN-6', action: 'delete', purpose: 'claim_handling' },
  ] });
  assert.equal(r.status, 200, r.raw); assert.equal(r.json.accepted, 6); assert.equal(r.json.exceptions, 5);
  // viewer refused, operator view audited
  assert.equal((await get('/pdpl/access', VW)).status, 403);
  let v = (await get('/pdpl/access')).json;
  assert.equal(v.totals.events, 6); assert.equal(v.totals.sensitive, 4); assert.equal(v.totals.exceptions_open, 5); assert.equal(v.chain.ok, true); assert.equal(v.chain.length, 6);
  const types = Object.fromEntries(v.exceptions.map((x) => [x.record_ref, x.types]));
  assert.deepEqual(types['CL-SYN-2'], ['no_purpose']); assert.deepEqual(types['CL-SYN-3'], ['other_no_reason']); assert.deepEqual(types['CL-SYN-4'], ['investigation_no_case']);
  assert.deepEqual(types['CL-SYN-5'], ['sensitive_export']); assert.deepEqual(types['CL-SYN-6'], ['delete']); assert.equal(types['CL-SYN-1'], undefined);
  assert.equal(v.exceptions.find((x) => x.record_ref === 'CL-SYN-5').unknown, undefined);
  assert.match(v.note, /not proof/); assert.equal(v.keys[0].events, 6);
  assert.ok(acts(e).includes('pdpl.access.view'));
  // review: a person, not the user concerned, decision + note
  const x6 = v.exceptions.find((x) => x.record_ref === 'CL-SYN-6').id, x2 = v.exceptions.find((x) => x.record_ref === 'CL-SYN-2').id;
  r = await post('/pdpl/access/exceptions/' + x6 + '/review', { decision: 'justified', note: 'duplicate claim removed (synthetic)' }); assert.equal(r.status, 403); assert.match(r.json.error, /own access/);
  r = await post('/pdpl/access/exceptions/' + x2 + '/review', { decision: 'justified', note: 'duplicate claim removed (synthetic)' }, { user: 'ai:pdpl', role: 'operator' }); assert.equal(r.status, 403);
  r = await post('/pdpl/access/exceptions/' + x2 + '/review', { decision: 'ok', note: 'duplicate claim removed (synthetic)' }); assert.equal(r.status, 400);
  r = await post('/pdpl/access/exceptions/' + x2 + '/review', { decision: 'justified', note: 'short' }); assert.equal(r.status, 400);
  r = await post('/pdpl/access/exceptions/' + x2 + '/review', { decision: 'escalated', note: 'no open claim for this person (synthetic)' }, VW); assert.equal(r.status, 403);
  r = await post('/pdpl/access/exceptions/' + x2 + '/review', { decision: 'escalated', note: 'no open claim for this person (synthetic)' }); assert.equal(r.status, 200); assert.equal(r.json.status, 'escalated'); assert.equal(r.json.review.by, 'nora.syn');
  assert.equal((await post('/pdpl/access/exceptions/' + x2 + '/review', { decision: 'justified', note: 'second thoughts here' })).status, 409);
  assert.equal((await post('/pdpl/access/exceptions/AX-999/review', { decision: 'justified', note: 'nothing to see here' })).status, 404);
  // findings: exceptions open for over 7 days
  clock += 8 * 86400000;
  let f = await e.app.addons.pdpl.adapter.findings();
  assert.ok(f.some((x) => x.key === 'access:exc:delete' && x.severity === 'high'));
  assert.ok(!f.some((x) => x.key === 'access:exc:no_purpose'), 'the reviewed one is not a gap');
  assert.ok(f.some((x) => x.key === 'access:silent:' + k.id), 'a sending system silent for 7 days');
  clock -= 8 * 86400000;
  // revoke
  assert.equal((await post('/pdpl/access/keys/' + k.id + '/revoke', {}, OP)).status, 403);
  assert.equal((await post('/pdpl/access/keys/' + k.id + '/revoke', {}, ADM)).status, 200);
  assert.equal((await agent(k.key, { events: [{ at: T, user: 'ali.syn', record_ref: 'CL-1', action: 'view' }] })).status, 401);
  // an edited journal line breaks the chain and becomes a critical finding
  const jf = fs.readdirSync(e.app.store.dir).find((n) => /^access-\d{6}\.jsonl$/.test(n));
  const p = path.join(e.app.store.dir, jf); fs.writeFileSync(p, fs.readFileSync(p, 'utf8').replace('CL-SYN-2', 'CL-SYN-9'));
  f = await e.app.addons.pdpl.adapter.findings(); assert.ok(f.some((x) => x.key === 'access:chain' && x.severity === 'critical'));
  for (const a of ['pdpl.access.key.issue', 'pdpl.access.key.revoke', 'pdpl.access.exception.review']) assert.ok(acts(e).includes(a), a);
});

test('access log: volume indicator against the person\'s own pattern; settings (admin); indicator review', async (t) => {
  const { e, post, get, agent } = await setup(t);
  const k = (await post('/pdpl/access/keys', { name: 'Claims (synthetic)' }, ADM)).json;
  // 11 ordinary days of ~10 records, then 80 in one day
  for (let d = 12; d >= 2; d--) {
    const at = iso(clock - d * 86400000);
    assert.equal((await agent(k.key, { events: Array.from({ length: 10 }, (_, i) => ({ at, user: 'Ali.Syn', record_ref: 'CL-' + d + '-' + i, action: 'view', purpose: 'claim_handling' })) })).status, 200);
  }
  const at = iso(clock - 3600000);
  assert.equal((await agent(k.key, { events: Array.from({ length: 80 }, (_, i) => ({ at, user: 'ali.syn', record_ref: 'CL-X-' + i, action: 'view', purpose: 'claim_handling' })) })).status, 200);
  let v = (await get('/pdpl/access')).json;
  const ind = v.indicators.find((x) => x.type === 'volume');
  assert.ok(ind, 'volume indicator raised'); assert.equal(ind.n, 80); assert.match(ind.why, /median of 11 days/); assert.equal(ind.status, 'open');
  assert.equal(v.indicators.length, 1, 'ordinary days raise nothing');
  // settings: admin only, validated; a higher floor removes it
  assert.equal((await post('/pdpl/access/settings', { min_volume: 100 })).status, 403);
  assert.equal((await post('/pdpl/access/settings', { min_volume: 1 }, ADM)).status, 400);
  assert.equal((await post('/pdpl/access/settings', { min_volume: 100, multiplier: 3, export_limit: 20 }, ADM)).status, 200);
  v = (await get('/pdpl/access')).json; assert.equal(v.indicators.length, 0); assert.equal(v.settings.min_volume, 100);
  assert.equal((await post('/pdpl/access/settings', { min_volume: 50 }, ADM)).status, 200);
  // review: not by the user, needs a note, once
  let r = await post('/pdpl/access/indicators/review', { id: ind.id, decision: 'justified', note: 'month-end claim backlog (synthetic)' }, { user: 'ALI.SYN', role: 'operator' }); assert.equal(r.status, 403);
  r = await post('/pdpl/access/indicators/review', { id: 'bad', decision: 'justified', note: 'month-end claim backlog (synthetic)' }); assert.equal(r.status, 400);
  r = await post('/pdpl/access/indicators/review', { id: '2026-01-01|nobody|volume', decision: 'justified', note: 'month-end claim backlog (synthetic)' }); assert.equal(r.status, 404);
  let f = await e.app.addons.pdpl.adapter.findings(); assert.ok(f.some((x) => x.key === 'access:ind:ali.syn'));
  r = await post('/pdpl/access/indicators/review', { id: ind.id, decision: 'justified', note: 'month-end claim backlog (synthetic)' }); assert.equal(r.status, 200);
  assert.equal((await post('/pdpl/access/indicators/review', { id: ind.id, decision: 'escalated', note: 'month-end claim backlog (synthetic)' })).status, 409);
  v = (await get('/pdpl/access')).json; assert.equal(v.indicators[0].status, 'justified'); assert.equal(v.indicators[0].review.by, 'nora.syn');
  f = (await e.app.addons.pdpl.adapter.findings()) || []; assert.ok(!f.some((x) => x.key === 'access:ind:ali.syn'));
  for (const a of ['pdpl.access.settings', 'pdpl.access.indicator.review']) assert.ok(acts(e).includes(a), a);
});

test('insurer DPIA triggers and reinsurance flows', async (t) => {
  const { post, get } = await setup(t);
  const ro = (await post('/pdpl/records', { kind: 'ropa', name: 'Motor fraud analytics (synthetic)', purpose: 'detect fraud', legal_basis: 'legitimate_interest', data_categories: ['identity'], owner: 'Fraud', retention_months: 60, lia_done: true,
    fraud_scoring: true, telematics: true, reinsurance_outside: true, reinsurers: ['Reinsurer A (synthetic)'] })).json;
  assert.equal(ro.fraud_scoring, true);
  assert.equal((await post('/pdpl/records', { kind: 'ropa', name: 'x', profiling: 'yes' })).status, 400, 'flags are booleans');
  let pd = (await get('/pdpl')).json;
  const dp = pd.findings.find((f) => f.key === 'P-07:dpia:' + ro.id);
  assert.ok(dp, 'fraud scoring needs an impact assessment'); assert.ok(dp.evidence.join(' ').includes('fraud scoring') && dp.evidence.join(' ').includes('telematics'));
  const rv = (await get('/pdpl/ropa')).json.activities.find((x) => x.id === ro.id); assert.ok(rv.dpia_needed_for.some((w) => /fraud scoring/.test(w)));
  assert.ok(pd.findings.some((f) => f.key === 'P-11:transfer:' + ro.id + ':reinsurance'), 'reinsurance abroad with no transfer');
  // the transfer: flow and data form validated
  assert.equal((await post('/pdpl/records', { kind: 'transfer', name: 'Treaty', country: 'Germany', flow_type: 'smuggling' })).status, 400);
  assert.equal((await post('/pdpl/records', { kind: 'transfer', name: 'Treaty', country: 'Germany', data_form: 'partly' })).status, 400);
  const tr = (await post('/pdpl/records', { kind: 'transfer', name: 'Motor treaty bordereaux (synthetic)', country: 'Germany', ropa_id: ro.id, basis: 'scc', flow_type: 'reinsurance', counterparty: 'Reinsurer A (synthetic)', data_form: 'identified', sensitive: true })).json;
  pd = (await get('/pdpl')).json;
  assert.ok(!pd.findings.some((f) => f.key === 'P-11:transfer:' + ro.id + ':reinsurance'));
  assert.ok(pd.findings.some((f) => f.key === 'P-11:transfer:' + tr.id + ':minimise'));
  let tv = (await get('/pdpl/transfers')).json.transfers.find((x) => x.id === tr.id);
  assert.equal(tv.flow_type, 'reinsurance'); assert.ok(tv.gaps.some((g) => /reinsurer without a recorded reason/.test(g)));
  await post('/pdpl/records', { kind: 'transfer', id: tr.id, identified_why: 'large-claim file the reinsurer must assess (synthetic)' });
  pd = (await get('/pdpl')).json; assert.ok(!pd.findings.some((f) => f.key === 'P-11:transfer:' + tr.id + ':minimise'));
  tv = (await get('/pdpl/transfers')).json.transfers.find((x) => x.id === tr.id); assert.ok(!tv.gaps.some((g) => /reinsurer/.test(g)));
});

test('a PDPL part the update did not install leaves only its own page out - every other PDPL page still answers', async (t) => {
  const Module = require('node:module'), orig = Module.prototype.require;   // as if the file were not on the server
  Module.prototype.require = function (id) {
    if (id === './pdpl-access') { const e = new Error("Cannot find module './pdpl-access'"); e.code = 'MODULE_NOT_FOUND'; throw e; }
    return orig.apply(this, arguments);
  };
  t.after(() => { Module.prototype.require = orig; });
  const { e, get } = await setup(t);
  assert.ok(e.app.addons.pdpl, 'the PDPL consultant is still loaded');
  assert.equal((await get('/pdpl/breaches')).status, 200);
  assert.equal((await get('/pdpl/holds')).status, 200);
  assert.equal((await get('/pdpl/catalog')).status, 200);
  assert.equal((await get('/pdpl/access')).status, 404, 'only the missing part is absent');
  const rd = (await get('/duty/readiness', ADM)).json;
  const chk = JSON.stringify(rd); assert.match(chk, /missing: engine\/pdpl-access\.js/, 'readiness names the missing file');
});
