// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Aramco CCC evidence and submission (engine/aramco-ccc-evidence.js) with SYNTHETIC records: snapshots are counts and dates only
// with a hash (no names leak), a source with nothing recorded says what to connect; the TF-IDF matching suggests the right
// source for a control; a person links (an AI identity is refused); gaps; the pack is prepared, approved by a DIFFERENT person
// who is the CCC owner / admin (refused while controls are unassessed), recorded as submitted, exported as JSON and CSV; audit.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');

const OP = { user: 'nora.syn', role: 'operator' }, ADM = { user: 'admin.syn', role: 'admin' }, OWNER = { user: 'omar.syn', role: 'operator' }, BOT = { user: 'ai:grc', role: 'operator' }, VIEW = { user: 'vera.syn', role: 'viewer' };
const CSV = 'id,domain,title,requirement,applies_to\nSYN-1,Assets,Maintain an asset inventory,Keep an inventory of hardware and software assets,all\nSYN-2,Resilience,Backups,Back up critical data and test restores,all\n';
test('evidence: snapshots, matching, links, gaps, four-eyes submission, export, audit', async (t) => {
  const clock = Date.parse('2026-11-25T08:00:00Z');
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true, now: () => clock, python: process.env.PYTHON || 'python3' });
  const call = (m, p, b, who) => e.req(m, p, Object.assign(b !== undefined ? { body: b } : {}, who));
  const post = (p, b, who = OWNER) => call('POST', p, b, who), get = (p, who = VIEW) => call('GET', p, undefined, who);
  const audit = (a) => e.app.store.auditTail(1000).filter((x) => x.action === a);
  e.app.store.collection('assets').put({ id: 'a1', name: 'SECRET-HOSTNAME-SYN', type: 'server', status: 'active' });
  e.app.store.collection('assets').put({ id: 'a2', name: 'PC-SYN', type: 'desktop', status: 'active' });
  assert.equal((await e.req('PUT', '/aramco-ccc/profile', Object.assign({ body: { ccc_owner: 'omar.syn' } }, ADM))).status, 200);
  assert.equal((await post('/aramco-ccc/contracts', { contract_no: 'C-SYN', title: 'Synthetic', services: ['general'] })).status, 200);
  assert.equal((await post('/aramco-ccc/controls/import', { csv: CSV })).status, 200);
  // snapshots
  assert.equal((await post('/aramco-ccc/evidence/collect', {}, BOT)).status, 403);
  assert.equal((await post('/aramco-ccc/evidence/collect', {}, VIEW)).status, 403);
  const c = await post('/aramco-ccc/evidence/collect', {}, OP); assert.equal(c.status, 200, c.text);
  const as = c.json.find((x) => x.source === 'assets'); assert.equal(as.available, true); assert.equal(as.collections.assets.count, 2); assert.deepEqual(as.collections.assets.by_type, { server: 1, desktop: 1 }); assert.match(as.sha256, /^[0-9a-f]{64}$/);
  assert.ok(!JSON.stringify(c.json).includes('SECRET-HOSTNAME-SYN'), 'counts only, no names');
  assert.match(c.json.find((x) => x.source === 'backup').why, /nothing recorded yet/);
  // matching suggests the right source
  let v = (await get('/aramco-ccc/evidence')).json;
  const s1 = v.controls.find((x) => x.id === 'SYN-1'), s2 = v.controls.find((x) => x.id === 'SYN-2');
  assert.equal(s1.suggested[0].source, 'assets', JSON.stringify(s1.suggested)); assert.equal(s2.suggested[0].source, 'backup', JSON.stringify(s2.suggested));
  assert.equal(v.gaps, 2); assert.equal(s1.gap, 'no evidence');
  // link: a person; validation names the field
  assert.equal((await post('/aramco-ccc/evidence/link', { control: 'SYN-1', source: 'assets' }, BOT)).status, 403);
  let r = await post('/aramco-ccc/evidence/link', { control: 'SYN-1', source: 'magic' }, OP); assert.equal(r.status, 400); assert.match(r.json.error, /source/);
  assert.equal((await post('/aramco-ccc/evidence/link', { control: 'NOPE', source: 'assets' }, OP)).status, 404);
  assert.equal((await post('/aramco-ccc/evidence/link', { control: 'SYN-1', source: 'assets' }, OP)).status, 200);
  v = (await get('/aramco-ccc/evidence')).json; assert.equal(v.controls.find((x) => x.id === 'SYN-1').gap, ''); assert.equal(v.gaps, 1);
  // submission: refused while unassessed; four-eyes
  r = await post('/aramco-ccc/submissions', {}, OP); assert.equal(r.status, 200, r.text); let sid = r.json.id; assert.equal(r.json.unassessed, 2); assert.ok(!('pack' in r.json));
  r = await post('/aramco-ccc/submissions/' + sid + '/approve', {}, OWNER); assert.equal(r.status, 409); assert.match(r.json.error, /not assessed/);
  for (const id of ['SYN-1', 'SYN-2']) assert.equal((await post('/aramco-ccc/controls/' + id + '/assess', { status: 'implemented' }, OP)).status, 200);
  r = await post('/aramco-ccc/submissions', {}, OP); sid = r.json.id; assert.equal(r.json.unassessed, 0); assert.match(r.json.manifest_sha256, /^[0-9a-f]{64}$/);
  assert.equal((await post('/aramco-ccc/submissions/' + sid + '/approve', {}, OP)).status, 403, 'an operator who is not the CCC owner');
  assert.equal((await post('/aramco-ccc/submissions/' + sid + '/submitted', { submitted_on: '2026-11-25', reference: 'X' })).status, 409, 'not before approval');
  r = await post('/aramco-ccc/submissions', {}, OWNER); const own = r.json.id;
  r = await post('/aramco-ccc/submissions/' + own + '/approve', {}, OWNER); assert.equal(r.status, 403); assert.match(r.json.error, /four-eyes/);
  assert.equal((await post('/aramco-ccc/submissions/' + sid + '/approve', {}, OWNER)).status, 200);
  assert.equal((await post('/aramco-ccc/submissions/' + sid + '/submitted', { submitted_on: '2099-01-01', reference: 'R' })).status, 400);
  r = await post('/aramco-ccc/submissions/' + sid + '/submitted', { submitted_on: '2026-11-25', reference: 'SYN-AUDIT-REF-1' }); assert.equal(r.status, 200); assert.equal(r.json.status, 'submitted');
  // export
  assert.equal((await get('/aramco-ccc/submissions/' + sid + '/export?format=csv', VIEW)).status, 403);
  const x = (await get('/aramco-ccc/submissions/' + sid + '/export?format=csv', OP)).json; assert.match(x.csv, /^"control","domain"/); assert.match(x.csv, /assets @ 2026-11-25 [0-9a-f]{16}/);
  const j = (await get('/aramco-ccc/submissions/' + sid + '/export', OP)).json; assert.equal(j.pack.controls.length, 2); assert.equal(j.approved_by, 'omar.syn');
  for (const a of ['aramco-ccc.evidence.collect', 'aramco-ccc.evidence.link', 'aramco-ccc.submission.prepare', 'aramco-ccc.submission.approve', 'aramco-ccc.submission.submitted', 'aramco-ccc.submission.export'])
    assert.ok(audit(a).length && audit(a).every((y) => y.by && y.role), 'audited: ' + a);
});
