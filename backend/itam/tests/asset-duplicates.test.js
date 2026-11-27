// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Duplicate assets through the real app, SYNTHETIC records: a second record with the same name or IP is refused (409 duplicate_asset)
// unless confirmed; the Asset Register Officer raises one work item per duplicate pair; an administrator merges the duplicate into
// the fuller record (empty fields filled, tags joined, links moved, the other removed, audited) - an operator is refused, from and
// reason are required; bulk delete is administrator-only and needs a reason.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');
const { adapters } = require('../engine/ai-team-adapters');

const ADM = { user: 'admin.syn', role: 'admin' }, OP = { user: 'nora.syn', role: 'operator' };

test('duplicates: refused on create, raised as work items, merged by an administrator', async (t) => {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true, python: process.env.PYTHON || 'python3' });
  const call = (m, p, b, who) => e.req(m, p, Object.assign(b !== undefined ? { body: b } : {}, who));
  let r = await call('POST', '/assets', { name: 'hqpadcmsfp1', type: 'server', status: 'in_use', mgmt_ip: '10.0.1.12', tags: ['windows'] }, OP); assert.equal(r.status, 200, r.text);
  const keepId = (r.json.asset || r.json).id;
  r = await call('POST', '/assets', { name: 'HQPADCMSFP1.safari-syn.example', type: 'server', status: 'in_use' }, OP); assert.equal(r.status, 409); assert.equal(r.json.code, 'duplicate_asset'); assert.match(r.json.error, /already exists/);
  r = await call('POST', '/assets', { name: 'OTHER-SYN', type: 'server', mgmt_ip: '10.0.1.12' }, OP); assert.equal(r.status, 409); assert.match(r.json.error, /10\.0\.1\.12 already belongs to hqpadcmsfp1/);
  r = await call('POST', '/assets', { name: 'hqpadcmsfp1', type: 'server', status: 'in_use', serial: 'SYN-SER-9', allow_duplicate: true }, OP); assert.equal(r.status, 200, r.text);
  const dupId = (r.json.asset || r.json).id; assert.ok(!('allow_duplicate' in e.app.store.collection('assets').get(dupId)), 'the confirmation is not stored on the record');
  // the duty desk raises it
  const reg = adapters(e.app).find((a) => a.id === 'register'); const f = await reg.findings();
  assert.equal(f.length, 1); assert.match(f[0].title, /Duplicate asset: hqpadcmsfp1 and hqpadcmsfp1/); assert.match(f[0].recommendation, /Merge 2 selected/);
  // merge
  r = await call('POST', `/assets/${keepId}/merge`, { from: dupId, reason: 'same server registered twice' }, OP); assert.equal(r.status, 403);
  r = await call('POST', `/assets/${keepId}/merge`, { reason: 'same server registered twice' }, ADM); assert.equal(r.status, 400); assert.match(r.json.error, /from/);
  r = await call('POST', `/assets/${keepId}/merge`, { from: dupId, reason: 'x' }, ADM); assert.equal(r.status, 400); assert.match(r.json.error, /reason/);
  r = await call('POST', `/assets/${keepId}/merge`, { from: keepId, reason: 'same server registered twice' }, ADM); assert.equal(r.status, 400); assert.match(r.json.error, /itself/);
  r = await call('POST', `/assets/${keepId}/merge`, { from: dupId, reason: 'same server registered twice' }, ADM); assert.equal(r.status, 200, r.text);
  assert.ok(r.json.filled.includes('serial'), 'the serial came over'); const K = e.app.store.collection('assets').get(keepId);
  assert.equal(K.serial, 'SYN-SER-9'); assert.equal(K.mgmt_ip, '10.0.1.12', 'what the kept record said stays'); assert.equal(K.merged_from[0].id, dupId);
  assert.equal(e.app.store.collection('assets').get(dupId), null, 'the duplicate is gone');
  assert.ok(e.app.store.auditTail(200).some((a) => a.action === 'asset.merge' && a.target === keepId && a.by === 'admin.syn'));
  assert.equal((await reg.findings()).length, 0, 'the work item clears once merged');
  // bulk delete: administrators, with a reason
  r = await call('POST', '/assets', { name: 'TEMP-SYN', type: 'server' }, OP); const tmp = (r.json.asset || r.json).id;
  assert.equal((await call('POST', '/bulk/assets/delete', { ids: [tmp], reason: 'test record' }, OP)).status, 403);
  assert.equal((await call('POST', '/bulk/assets/delete', { ids: [tmp] }, ADM)).status, 400);
  r = await call('POST', '/bulk/assets/delete', { ids: [tmp], reason: 'test record' }, ADM); assert.equal(r.status, 200); assert.equal(r.json.ok, 1);
});
