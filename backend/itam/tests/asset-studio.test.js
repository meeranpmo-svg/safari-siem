// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Asset Studio (engine/asset-studio.js, pyengine/asset_studio_rules.py) through the real routes on SYNTHETIC assets: health
// with every point explained, stale and ghost anomalies, warranty, field suggestions learned from peers; applying a
// suggestion edits that one field through engine/assets.js, dismissing needs a reason and is remembered, service identities
// never apply; roles, validation errors and the audit records.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');

const VIEW = { user: 'vera.syn', role: 'viewer' }, OP = { user: 'nora.syn', role: 'operator' }, BOT = { user: 'ai:asset-analyst', role: 'admin' }, ADM = { user: 'syed', role: 'admin' };
const NOW = Date.parse('2026-10-30T09:00:00Z'), iso = (d) => new Date(NOW - d * 86400000).toISOString();

async function setup(t) {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true, now: () => NOW, python: process.env.PYTHON || 'python3' });
  const C = e.app.store.collection('assets'), id = {};
  const mk = (k, x) => { id[k] = e.app.assets.create(Object.assign({ status: 'in_use', type: 'server', site: 'HQ' }, x), ADM).asset.id; if (x.last_seen || x.warranty_end || x.eol) C.patch(id[k], (a) => { if (x.last_seen) a.last_seen = x.last_seen; if (x.warranty_end) a.warranty = { end: x.warranty_end }; if (x.eol) a.eol = x.eol; }); };
  for (let i = 1; i <= 5; i++) mk('e' + i, { name: 'ESX-SYN-' + i, mgmt_ip: '10.90.1.' + i, vendor: 'Dell', model: 'R750', os: 'ESXi 8', owner: 'infra', serial: 'SYN' + i, last_seen: iso(1) });
  mk('bare', { name: 'ESX-SYN-9', mgmt_ip: '10.90.1.9', site: '', last_seen: iso(45) });
  mk('old', { name: 'ESX-SYN-OLD', mgmt_ip: '10.90.1.20', vendor: 'Dell', model: 'R720', os: 'ESXi 6', owner: 'infra', serial: 'SYNOLD', last_seen: iso(1), warranty_end: '2025-01-01', eol: '2026-01-01' });
  mk('ghost', { name: 'SRV-SYN-GONE', mgmt_ip: '10.91.0.5' });
  e.app.assets.transition ? e.app.assets.transition(id.ghost, 'retire', ADM, 'synthetic') : null;
  C.patch(id.ghost, (a) => { a.last_seen = iso(2); });
  const call = (m, p, b, who) => e.req(m, p, Object.assign(b !== undefined ? { body: b } : {}, who));
  return { e, id, call };
}
const auditOf = (e, action) => e.app.store.auditTail(200).filter((x) => x.action === action);

test('health explained, anomalies, warranty / end of life, learned suggestions, one asset in 360', async (t) => {
  const { call, id } = await setup(t);
  let r = await call('GET', '/asset-studio', undefined, VIEW);
  assert.equal(r.status, 200, r.raw);
  const v = r.json;
  assert.equal(v.summary.active, 7); assert.equal(v.summary.stale, 1); assert.equal(v.summary.ghosts, 1); assert.equal(v.summary.eol, 1); assert.equal(v.summary.out_of_warranty, 1);
  const bare = v.assets.find((x) => x.id === id.bare);
  assert.ok(bare.health < 60 && bare.why.some((w) => /no source has seen it for 45 days/.test(w.text)) && bare.why.some((w) => /missing/.test(w.text)), 'every point explained');
  assert.ok(v.anomalies.some((x) => x.kind === 'ghost' && x.id === id.ghost), 'retired, yet seen');
  for (const f of ['vendor', 'model', 'os', 'site']) assert.ok(v.suggestions.some((x) => x.id === id.bare && x.field === f && x.kind === 'learned' && x.confidence >= 0.7), f + ' learned');
  assert.match(v.suggestions.find((x) => x.id === id.bare && x.field === 'os').why, /of \d+ assets with name prefix ESX-\* have operating system "ESXi 8"|subnet/);
  assert.ok(!v.suggestions.some((x) => x.field === 'owner'), 'an owner is never guessed');
  r = await call('GET', '/asset-studio/asset/' + id.old, undefined, VIEW);
  assert.equal(r.status, 200); assert.ok(r.json.health.why.some((w) => w.code === 'eol') && r.json.health.why.some((w) => w.code === 'warranty'));
  r = await call('GET', '/asset-studio/asset/bad$id', undefined, VIEW); assert.equal(r.status, 400);
  r = await call('GET', '/asset-studio/asset/as_none', undefined, VIEW); assert.equal(r.status, 404);
  assert.equal(v.ai.enabled, false);
});

test('apply edits one field and is audited; dismiss needs a reason and is remembered; roles; AI refused without consent', async (t) => {
  const { e, id, call } = await setup(t);
  let v = (await call('GET', '/asset-studio', undefined, OP)).json;
  const os = v.suggestions.find((x) => x.id === id.bare && x.field === 'os'), site = v.suggestions.find((x) => x.id === id.bare && x.field === 'site');
  let r = await call('POST', '/asset-studio/apply', { key: os.key }, VIEW); assert.equal(r.status, 403);
  r = await call('POST', '/asset-studio/apply', { key: os.key }, BOT); assert.equal(r.status, 403); assert.match(r.json.error, /a person does/);
  r = await call('POST', '/asset-studio/apply', { key: 'owner|x|y' }, OP); assert.equal(r.status, 400); assert.match(r.json.error, /key is not a suggestion key/);
  r = await call('POST', '/asset-studio/apply', { key: 'os|' + id.e1 + '|Windows' }, OP); assert.equal(r.status, 404);
  r = await call('POST', '/asset-studio/apply', { key: os.key, value: 'evil' }, OP); assert.equal(r.status, 200, r.raw);
  assert.equal(e.app.store.collection('assets').get(id.bare).os, 'ESXi 8', 'the learned value, not one from the body');
  const a = auditOf(e, 'assets.studio.apply')[0]; assert.equal(a.by, 'nora.syn'); assert.equal(a.detail.field, 'os');
  r = await call('POST', '/asset-studio/dismiss', { key: site.key }, OP); assert.equal(r.status, 400); assert.match(r.json.error, /reason is required/);
  r = await call('POST', '/asset-studio/dismiss', { key: site.key, reason: 'it is in the DR site (synthetic)' }, OP); assert.equal(r.status, 200);
  v = (await call('GET', '/asset-studio', undefined, OP)).json;
  assert.ok(!v.suggestions.some((x) => x.key === site.key || x.key === os.key), 'applied and dismissed are not suggested again');
  assert.equal(auditOf(e, 'assets.studio.dismiss')[0].detail.reason, 'it is in the DR site (synthetic)');
  r = await call('POST', '/asset-studio/ai/ask', { question: 'what is stale?' }, VIEW); assert.equal(r.status, 403);
  r = await call('POST', '/asset-studio/ai/ask', { question: 'what is stale?' }, OP); assert.equal(r.status, 503);
});
