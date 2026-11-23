// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Asset information classification (engine/model/asset.js + pyengine/assets_write.py fields, engine/asset-studio.js classify):
// NDMO levels and the CIA rating on the asset record; validation naming the field; operator only, a person only; one audited
// edit per asset; a human classification is locked - a discovery / agent sighting never overwrites it; coverage, peer-learned
// suggestions with their counts, and the inconsistency rule. SYNTHETIC assets only.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');
const { normaliseFields } = require('../engine/model/asset');

const OP = { user: 'nora.syn', role: 'operator' }, VIEW = { user: 'vera.syn', role: 'viewer' }, ADM = { user: 'syed', role: 'admin' }, BOT = { user: 'ai:assets', role: 'operator' };

test('the model accepts the four NDMO levels and a CIA rating, and warns on anything else', () => {
  assert.deepEqual(normaliseFields({ classification: ' Top Secret ', cia: { c: 'HIGH', i: 'x', a: 'low', z: 'high' } }).fields, { classification: 'top_secret', cia: { c: 'high', i: null, a: 'low' } });
  const r = normaliseFields({ classification: 'confidential' }); assert.equal(r.fields.classification, undefined); assert.match(r.warnings[0], /top_secret, secret, restricted or public/);
  assert.equal(normaliseFields({ classification: '', cia: {} }).fields.classification, null);
  assert.equal(normaliseFields({ cia: {} }).fields.cia, null);
});

test('classify: validation, roles, audit, locked against discovery, coverage, suggestions, inconsistency', async (t) => {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true, python: process.env.PYTHON || 'python3' });
  const call = (m, p, b, who) => e.req(m, p, Object.assign(b !== undefined ? { body: b } : {}, who));
  const ids = [];
  for (let i = 1; i <= 6; i++) ids.push(e.app.assets.create({ name: 'DB-SYN-' + i, type: 'server', department: 'Finance', status: 'in_use', serial: 'SNC' + i }, ADM).asset.id);
  let r = await call('POST', '/asset-studio/classify', { ids: [ids[0]], classification: 'secret' }, VIEW); assert.equal(r.status, 403);
  r = await call('POST', '/asset-studio/classify', { ids: [ids[0]], classification: 'secret' }, BOT); assert.equal(r.status, 403, 'a service / AI identity never classifies');
  r = await call('POST', '/asset-studio/classify', { ids: [ids[0]], classification: 'confidential' }, OP); assert.equal(r.status, 400); assert.match(r.json.error, /classification must be one of/);
  r = await call('POST', '/asset-studio/classify', { ids: [ids[0]], cia: { c: 'extreme' } }, OP); assert.equal(r.status, 400); assert.match(r.json.error, /c must be one of/);
  r = await call('POST', '/asset-studio/classify', { ids: [ids[0]] }, OP); assert.equal(r.status, 400); assert.match(r.json.error, /classification and \/ or cia/);
  r = await call('POST', '/asset-studio/classify', { ids: ['as_nope00000000'], classification: 'public' }, OP); assert.equal(r.status, 404);
  r = await call('POST', '/asset-studio/classify', { ids: ids.slice(0, 4), classification: 'secret', cia: { c: 'high' } }, OP); assert.equal(r.status, 200, r.raw); assert.equal(r.json.classified, 4);
  const a = e.app.store.collection('assets').get(ids[0]);
  assert.equal(a.classification, 'secret'); assert.deepEqual(a.cia, { c: 'high', i: null, a: null }); assert.equal(a.locked.classification, true); assert.equal(a.prov.classification, 'manual');
  const au = e.app.store.auditTail(100).filter((x) => x.action === 'assets.studio.classify'); assert.equal(au.length, 4); assert.equal(au[0].by, OP.user); assert.equal(au[0].detail.to, 'secret');
  // a discovery sighting sending a classification never overwrites the human one
  e.app.assets.upsert({ serial: 'SNC1', name: 'DB-SYN-1', classification: 'public' }, 'discovery', { at: new Date().toISOString() });
  assert.equal(e.app.store.collection('assets').get(ids[0]).classification, 'secret', 'locked against discovery');
  const v = (await call('GET', '/asset-studio', undefined, VIEW)).json.classification;
  assert.equal(v.by_level.secret, 4); assert.equal(v.by_level.unclassified, 2); assert.equal(v.coverage_pct, 67);
  const sg = v.suggestions.find((x) => x.id === ids[4]); assert.ok(sg && sg.value === 'secret', JSON.stringify(v.suggestions));
  assert.match(sg.why, /4 of 4 classified server assets in Finance are Secret/);
  await call('POST', '/asset-studio/classify', { ids: [ids[5]], classification: 'top_secret', cia: { c: 'low' } }, OP);
  const v2 = (await call('GET', '/asset-studio', undefined, VIEW)).json;
  assert.ok(v2.classification.inconsistent.some((x) => x.id === ids[5] && /Top secret but confidentiality rated low/.test(x.why)));
  assert.equal(v2.assets.find((x) => x.id === ids[5]).classification, 'top_secret', 'the register rows carry the level');
});
