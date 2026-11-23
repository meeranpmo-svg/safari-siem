// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// GRC Register (engine/grc-register.js) through the real routes, the real policy register and the real GRC registers with SYNTHETIC
// records: one record per policy / risk / action / exception / evidence and a control node where they meet; links (risk → control,
// action → risk, exception → policy, evidence → control, policy → control); health and itemised quality issues (no owner, mitigate
// with no action, no compensating control, stale evidence); orphans; possible duplicates; owner load; a record with everything two
// steps out; roles (viewer reads, export for operators, analyst off until allowed, invalid kind 400) and the export audit.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');

const OP = { user: 'nora.syn', role: 'operator' }, VIEW = { user: 'vera.syn', role: 'viewer' };
test('GRC register: records, links, quality, learning, roles', async (t) => {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true });
  const post = (p, b, who = OP) => e.req('POST', p, Object.assign({ body: b }, who)), get = (p, who = OP) => e.req('GET', p, who);
  const pol = (await get('/grc/register')).json.items[0];
  const r1 = (await post('/grc/risks', { title: 'Ransomware on claims servers (synthetic)', likelihood: 4, impact: 5, treatment: 'mitigate', owner: 'omar.syn', controls: [pol.sub_code], review_due: '2027-01-15' })).json;
  const r2 = (await post('/grc/risks', { title: 'Ransomware on claims servers synthetic copy', likelihood: 3, impact: 4, treatment: 'mitigate' })).json;
  const a1 = (await post('/grc/actions', { title: 'Immutable backups for claims (synthetic)', source: 'risk', ref: r1.id, owner: 'omar.syn', due: '2027-02-01' })).json;
  await post('/grc/actions', { title: 'Tidy the file share (synthetic)', source: 'manual' });
  const x1 = (await post('/grc/exceptions', { policy_id: pol.doc_id, title: 'Legacy system without MFA (synthetic)', reason: 'vendor end of life in Q2', expires: '2027-03-01' })).json;
  const ev = (await post('/grc/evidence', { framework: 'SAMA ITGF', control: pol.sub_code, title: 'Steering committee minutes (synthetic)', url: 'https://intranet.synthetic.test/minutes', owner: 'khalid.syn' })).json;
  assert.ok(r1.id && a1.id && x1.id && ev.id, 'records created through their own registers');
  const v = (await get('/grc-register', VIEW)).json;
  const rec = (k, id) => v.records.find((r) => r.kind === k && r.id === id);
  assert.ok(rec('policy', pol.doc_id) && rec('control', pol.sub_code), 'policy and its control');
  assert.ok(rec('risk', r2.id).issues.includes('no owner') && rec('risk', r2.id).issues.includes('mitigate, but no open action') && rec('risk', r2.id).orphan, 'an unowned risk with no action and no control is an orphan');
  assert.ok(!rec('risk', r1.id).issues.includes('mitigate, but no open action') && rec('risk', r1.id).links >= 2, 'the risk with an action and a control is linked');
  assert.ok(rec('action', a1.id).links >= 1 && v.records.some((r) => r.kind === 'action' && r.issues.includes('not linked to a risk, control or finding') && r.orphan), 'a manual action pointing at nothing');
  assert.ok(rec('exception', x1.id).issues.includes('no compensating control'));
  assert.ok(v.learning.duplicates.some((d) => d.kind === 'risk' && [d.a, d.b].includes(r1.id) && [d.a, d.b].includes(r2.id)), 'the two ransomware risks are possible duplicates');
  assert.ok(v.learning.owners.some((o) => o.owner === 'omar.syn' && o.open === 2));
  assert.equal(typeof v.kpis.hygiene, 'number'); assert.ok(v.learning.issues.length > 0); assert.match(v.learning.p_late.why, /needs 5 closed actions/);
  const one = (await get('/grc-register/record/risk/' + r1.id, VIEW)).json;
  assert.ok(one.nodes.some((n) => n.key === 'action:' + a1.id) && one.nodes.some((n) => n.key === 'control:' + pol.sub_code) && one.nodes.some((n) => n.kind === 'policy' && n.depth === 2), 'two steps out: action, control, then the policy');
  assert.equal((await get('/grc-register/record/vendor/x', VIEW)).status, 400);
  assert.equal((await get('/grc-register/record/risk/RSK-9999', VIEW)).status, 404);
  assert.equal((await get('/grc-register/export', VIEW)).status, 403);
  const x = (await get('/grc-register/export')).json; assert.ok(x.rows.length === v.records.length && x.columns.includes('Quality issues'));
  assert.ok(e.app.store.auditTail(200).some((a) => a.action === 'grc-register.export' && a.by === 'nora.syn'));
  assert.equal((await post('/grc-register/ask', { question: 'what do we clean up first?' }, VIEW)).status, 403);
  assert.equal((await post('/grc-register/ask', { question: 'what do we clean up first?' })).status, 424);
});
