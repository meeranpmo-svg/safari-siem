// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Data subject request intake (engine/pdpl-intake.js + pyengine/pdpl_intake.py): requests sent in by the customer portal /
// app / call centre with an intake key. Keys shown once and stored as a hash; validation names the field; routing to the
// handler per type; the channel's identity check counts only when an administrator listed the method as strong; a second
// identical request while one is open is the same request; a repeat of one answered recently is flagged (never refused
// automatically); the acknowledgement in Arabic and English; automatic identity search only when switched on and only for a
// verified requester; the identifier stored nowhere; settings admin-only; findings; every step audited. SYNTHETIC data.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs'), path = require('node:path');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');

const PY = process.env.PYTHON || 'python3';
let clock = Date.parse('2026-10-20T08:00:00Z');
const now = () => clock;
const OP = { user: 'nora.syn', role: 'operator' }, ADM = { user: 'syed', role: 'admin' }, VW = { user: 'v.syn', role: 'viewer' };
const NID = '1012345678';

async function setup(t) {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  e.app.store.collection('disc_devices').put({ id: 'd-pg', ip: '10.8.0.53', hostname: 'CRM-PG', status: 'matched', extra: { db_login: { postgres: { credential: 'pg-ro', host_name: 'CRM-PG' } } } });
  const vault = { list: () => [{ id: 'c3', kind: 'db_login', label: 'pg-ro', target: { engine: 'postgres', database: 'crm' } }], open: () => ({ target: { database: 'crm' }, secret: { username: 'ro_syn', password: 'Synthetic-Pass-1' }, release() {} }) };
  e.app.discovery = Object.assign({}, e.app.discovery, { vault });
  const calls = [];
  const invRun = async (input) => {
    calls.push(input);
    if (input.op === 'db_pii_scan') return { ok: true, engine: 'postgres', scanned_columns: 20, columns: [{ owner: 'crm', table: 'customers', column: 'national_id', type: 'character varying', rows: 5200, kind: 'national_id', category: 'identity', by: 'name', confirmed: true }] };
    if (input.op === 'db_find') return { ok: true, results: input.columns.map((c) => Object.assign({}, c, { count: 3 })) };
    return { ok: false, error: 'unexpected op' };
  };
  registerDuty(e.app.srv, e.app, { noTimer: true, now, python: PY, pdplInvRun: invRun });
  const post = (p, body, who = OP) => e.req('POST', p, Object.assign({ body }, who));
  const get = (p, who = OP) => e.req('GET', p, who);
  const agent = (bearer, body) => e.req('POST', '/agent/dsar/intake', { body, bearer, user: '', role: '' });
  return { e, post, get, agent, calls };
}

test('keys: admin issues one, shown once and stored as a hash; a wrong or revoked key is refused; validation names the field', async (t) => {
  const { e, post, get, agent } = await setup(t);
  assert.equal((await post('/pdpl/intake/keys', { name: 'Customer portal' })).status, 403);
  const k = (await post('/pdpl/intake/keys', { name: 'Customer portal' }, ADM)).json; assert.match(k.key, /^dk_[0-9a-f]{48}$/); assert.equal(k.id, 'DK-001');
  assert.ok(!JSON.stringify(e.app.store.collection('pdpl_intake_keys').all()).includes(k.key), 'only the hash is stored');
  assert.ok(!JSON.stringify((await get('/pdpl/intake')).json).includes(k.key));
  assert.equal((await get('/pdpl/intake', VW)).status, 403);
  assert.equal((await agent('dk_' + '0'.repeat(48), { ref: 'WEB-1', type: 'access', channel: 'web' })).status, 401);
  for (const [b, re] of [[{ type: 'access', channel: 'web' }, /ref is required/], [{ ref: 'WEB-1', type: 'gossip', channel: 'web' }, /type/], [{ ref: 'WEB 1;', type: 'access', channel: 'web' }, /ref must be/],
    [{ ref: 'WEB-1', type: 'access', channel: 'web', id_type: 'national_id' }, /go together/], [{ ref: 'WEB-1', type: 'access', channel: 'web', received: '2030-01-01' }, /future/], [{ ref: 'WEB-1', type: 'access', channel: 'web', identity_method: 'gut_feeling' }, /identity_method/]]) {
    const r = await agent(k.key, b); assert.equal(r.status, 400, JSON.stringify(b) + ' ' + r.raw); assert.match(r.json.error, re);
  }
  assert.equal((await post('/pdpl/intake/keys/DK-001/revoke', {}, ADM)).status, 200);
  assert.equal((await agent(k.key, { ref: 'WEB-1', type: 'access', channel: 'web' })).status, 401);
  const acts = e.app.store.auditTail(40).map((x) => x.action); for (const a of ['pdpl.intake.key.issue', 'pdpl.intake.key.revoke']) assert.ok(acts.includes(a), a);
});

test('a request arrives: routed, clock started, weak channel check not accepted, acknowledgement in Arabic and English, audited', async (t) => {
  const { e, post, agent, get } = await setup(t);
  const k = (await post('/pdpl/intake/keys', { name: 'Call centre' }, ADM)).json;
  let r = await agent(k.key, { ref: 'CC-SYN-1', type: 'correction', channel: 'call_centre', identity_method: 'registered_email', systems: ['Core insurance'] });
  assert.equal(r.status, 200, r.raw);
  assert.equal(r.json.stage, 'verifying'); assert.equal(r.json.identity_verified, false); assert.equal(r.json.due, '2026-11-19');
  assert.deepEqual(r.json.flags.sort(), ['unassigned', 'verify_identity']);
  assert.match(r.json.acknowledgement.en, /CC-SYN-1[\s\S]*correction of your personal data[\s\S]*2026-11-19/); assert.match(r.json.acknowledgement.ar, /تصحيح بياناتك الشخصية/);
  const rq = (await get('/pdpl/dsar')).json.requests.find((x) => x.ref === 'CC-SYN-1');
  assert.equal(rq.intake.source_name, 'Call centre'); assert.ok(rq.blockers.includes('identity not verified')); assert.equal(rq.tasks[0].system, 'Core insurance');
  const au = e.app.store.auditTail(30).find((x) => x.action === 'pdpl.dsar.intake'); assert.equal(au.by, 'system:dsar-intake:DK-001'); assert.equal(au.detail.auto_verified, false);
  // the same reference again (a retry) is the same request
  r = await agent(k.key, { ref: 'CC-SYN-1', type: 'correction', channel: 'call_centre' }); assert.equal(r.status, 200); assert.equal(r.json.request, rq.id); assert.equal(r.json.repeat_of_call, true);
  assert.equal((await get('/pdpl/dsar')).json.requests.filter((x) => x.ref === 'CC-SYN-1').length, 1);
  // settings: admin only, validated
  assert.equal((await post('/pdpl/intake/settings', { default_assignee: 'huda.syn' })).status, 403);
  assert.equal((await post('/pdpl/intake/settings', { assignees: { gossip: 'x' } }, ADM)).status, 400);
  assert.equal((await post('/pdpl/intake/settings', { assignees: { access: 'bad user!' } }, ADM)).status, 400);
  assert.equal((await post('/pdpl/intake/settings', { strong_methods: ['none'] }, ADM)).status, 400);
  const s = await post('/pdpl/intake/settings', { default_assignee: 'huda.syn', assignees: { destruction: 'omar.syn' }, strong_methods: ['nafath', 'absher_otp'] }, ADM); assert.equal(s.status, 200, s.raw);
  assert.deepEqual(s.json.settings.strong_methods, ['nafath', 'absher_otp']);
  r = await agent(k.key, { ref: 'CC-SYN-2', type: 'destruction', channel: 'call_centre', identity_method: 'absher_otp' });
  assert.equal(r.json.stage, 'in_progress'); assert.equal(r.json.identity_verified, true); assert.deepEqual(r.json.flags, []);
  const rq2 = (await get('/pdpl/dsar')).json.requests.find((x) => x.ref === 'CC-SYN-2'); assert.equal(rq2.assigned_to, 'omar.syn'); assert.equal(rq2.identity_method, 'absher_otp');
  assert.ok(e.app.store.auditTail(40).some((x) => x.action === 'pdpl.intake.settings' && x.by === 'syed'));
  // a language asked for
  r = await agent(k.key, { ref: 'CC-SYN-3', type: 'access', channel: 'call_centre', language: 'ar' }); assert.ok(r.json.acknowledgement.ar && !r.json.acknowledgement.en);
});

test('same person: an open request is not duplicated, a recently answered one is flagged as possibly repetitive; the identifier is stored nowhere', async (t) => {
  const { e, post, agent, get } = await setup(t);
  const k = (await post('/pdpl/intake/keys', { name: 'Customer portal' }, ADM)).json;
  await post('/pdpl/intake/settings', { default_assignee: 'huda.syn', strong_methods: ['nafath'] }, ADM);
  const first = await agent(k.key, { ref: 'WEB-SYN-1', type: 'access', channel: 'web', identity_method: 'nafath', id_type: 'national_id', id_value: NID });
  assert.equal(first.status, 200, first.raw);
  const dup = await agent(k.key, { ref: 'WEB-SYN-2', type: 'access', channel: 'web', identity_method: 'nafath', id_type: 'national_id', id_value: ' ' + NID + ' ' });
  assert.equal(dup.json.request, first.json.request, 'the same open request'); assert.equal(dup.json.duplicate_of, first.json.request); assert.match(dup.json.acknowledgement.en, /already open/);
  assert.equal((await get('/pdpl/dsar')).json.requests.length, 1);
  // a different kind of request from the same person is its own request
  const other = await agent(k.key, { ref: 'WEB-SYN-3', type: 'correction', channel: 'web', identity_method: 'nafath', id_type: 'national_id', id_value: NID });
  assert.notEqual(other.json.request, first.json.request);
  // answer the first, then the same request again two months later: flagged, not refused
  const id = first.json.request;
  assert.equal((await post('/pdpl/dsar/' + id + '/task', { system: 'Core', status: 'done' })).status, 200);
  assert.equal((await post('/pdpl/dsar/' + id + '/respond', { outcome: 'fulfilled' })).status, 200);
  clock += 60 * 86400000;
  const again = await agent(k.key, { ref: 'WEB-SYN-4', type: 'access', channel: 'web', identity_method: 'nafath', id_type: 'national_id', id_value: NID });
  assert.notEqual(again.json.request, id); assert.ok(again.json.flags.includes('possibly_repetitive')); assert.equal(again.json.stage, 'in_progress');
  const rq = (await get('/pdpl/dsar')).json.requests.find((x) => x.ref === 'WEB-SYN-4'); assert.deepEqual(rq.intake.repetitive_of, ['WEB-SYN-1']);
  assert.ok(rq.flags.some((f) => f.flag === 'possibly_repetitive' && /only the DPO may refuse/.test(f.detail)));
  // the identifier: in no record, no audit entry, no store file
  assert.ok(!JSON.stringify(e.app.store.collection('pdpl_records').all()).includes(NID));
  assert.ok(!JSON.stringify(e.app.store.auditTail(300)).includes(NID));
  const dir = e.app.store.dir; for (const f of fs.readdirSync(dir)) { const p = path.join(dir, f); if (fs.statSync(p).isFile()) assert.ok(!fs.readFileSync(p, 'utf8').includes(NID), 'identifier found in ' + f); }
});

test('automatic identity search: off by default; on, it runs only for a verified requester, adds the systems as tasks, audited as automated', async (t) => {
  const { e, post, agent, get, calls } = await setup(t);
  await post('/pdpl/discovery/run', {}, ADM);
  assert.equal((await post('/pdpl/catalog/identifiers', { column_id: 'postgres|10.8.0.53|5432|crm|customers|national_id', id_type: 'national_id' }, ADM)).status, 200);
  const k = (await post('/pdpl/intake/keys', { name: 'Customer portal' }, ADM)).json;
  await post('/pdpl/intake/settings', { default_assignee: 'huda.syn', strong_methods: ['nafath'] }, ADM);
  let r = await agent(k.key, { ref: 'WEB-A1', type: 'access', channel: 'web', identity_method: 'nafath', id_type: 'national_id', id_value: NID });
  assert.equal(r.json.search, null, 'off by default'); assert.equal(calls.filter((c) => c.op === 'db_find').length, 0);
  await post('/pdpl/intake/settings', { auto_search: true }, ADM);
  r = await agent(k.key, { ref: 'WEB-A2', type: 'copy', channel: 'web', identity_method: 'registered_email', id_type: 'national_id', id_value: NID });
  assert.equal(r.json.search, null, 'not verified: no search'); assert.equal(calls.filter((c) => c.op === 'db_find').length, 0);
  r = await agent(k.key, { ref: 'WEB-A3', type: 'destruction', channel: 'web', identity_method: 'nafath', id_type: 'national_id', id_value: NID });
  assert.equal(r.status, 200, r.raw); assert.equal(r.json.search.found_in, 1); assert.deepEqual(r.json.search.tasks_added, ['CRM-PG']);
  assert.equal(calls.filter((c) => c.op === 'db_find').length, 1);
  const rq = (await get('/pdpl/dsar')).json.requests.find((x) => x.ref === 'WEB-A3');
  assert.ok(rq.tasks.some((x) => x.system === 'CRM-PG')); assert.equal(rq.intake.searched, true); assert.equal(rq.intake.found_in, 1);
  const au = e.app.store.auditTail(40).find((x) => x.action === 'pdpl.dsar.correlate'); assert.equal(au.detail.automated, true); assert.match(au.by, /^system:dsar-intake/);
  // a person still answers: the service identity cannot respond
  assert.equal((await post('/pdpl/dsar/' + rq.id + '/respond', { outcome: 'fulfilled' }, { user: 'system:dsar-intake:DK-001', role: 'operator' })).status, 403);
  // and other services still cannot search
  assert.equal((await post('/pdpl/dsar/' + rq.id + '/correlate', { id_type: 'national_id', value: NID }, { user: 'ai:pdpl', role: 'operator' })).status, 403);
  // the view and its findings
  const v = (await get('/pdpl/intake')).json; assert.equal(v.summary.auto_searched, 1); assert.equal(v.summary.keys_active, 1); assert.ok(v.log.some((x) => x.ref === 'WEB-A3' && x.auto_searched));
  assert.ok(!JSON.stringify(e.app.store.auditTail(300)).includes(NID));
});

test('findings: keys active with no handler, requests waiting for verification more than 5 days', async (t) => {
  const { post, agent, e } = await setup(t);
  const k = (await post('/pdpl/intake/keys', { name: 'App' }, ADM)).json;
  await agent(k.key, { ref: 'APP-1', type: 'access', channel: 'app' });
  clock += 6 * 86400000;
  const v = (await e.req('GET', '/pdpl/intake', OP)).json;
  const keys = v.findings.map((f) => f.key); assert.ok(keys.includes('intake:assignee') && keys.includes('intake:verify'), keys.join());
});
