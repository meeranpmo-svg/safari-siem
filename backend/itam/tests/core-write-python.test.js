// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Migration step 9e (docs/PYTHON-MIGRATION.md): the other human writes of the core engine - licences (save, retire),
// stocktake (open, scan, close), AI finding accept / dismiss and the CMDB links a person adds - decided by
// pyengine/core_write.py and committed by engine/py-writer.js must do exactly what Node.js does, over HTTP: same answers,
// same records, same audit entries, with odd values (seats '12.5' / -3 / 'abc', ids given or not, a closed stocktake,
// codes by tag / serial / unknown, a symmetric link given both ways, a body that tries to set the link's source).
// Python decides every write, and a decision made on a record that changed meanwhile is never written.
const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { spawnSync } = require('node:child_process');
const { startApp } = require('./helpers');

const PY = process.env.PYTHON || 'python3';
const hasPy = spawnSync(PY, ['--version']).status === 0;
const NOW = Date.parse('2026-10-19T09:00:00Z');

test('Python-decided licence, stocktake, finding and CMDB writes do exactly what Node.js does', { skip: !hasPy && 'python3 not available' }, async (t) => {
  // one clock, and per request one id for both engines, so the two stores compare record for record
  const RealDate = Date, realRB = crypto.randomBytes;
  global.Date = class extends RealDate { constructor(...a) { if (a.length) super(...a); else super(NOW); } static now() { return NOW; } };
  let seq = 0;
  crypto.randomBytes = function (n, cb) { if ((n !== 5 && n !== 6) || cb) return realRB.apply(this, arguments); return Buffer.from(String(seq).padStart(2 * n, '0'), 'hex'); };
  t.after(() => { global.Date = RealDate; crypto.randomBytes = realRB; });
  const N = await startApp({ noAi: true, config: { writes: { engine: 'node' }, assets: { engine: 'node' } } }), P = await startApp({ noAi: true, config: { discovery: { python_bin: PY } } });
  t.after(async () => { await N.close(); await P.close(); });
  for (const e of [N, P]) e.app.now = () => NOW;
  const strip = (j) => JSON.parse(JSON.stringify(j));
  let i = 0;
  const both = async (path, body, role = 'operator') => {
    i++;
    seq = i; const a = await N.req('POST', path, { body, user: 'siva', role });
    seq = i; const b = await P.req('POST', path, { body, user: 'siva', role });
    assert.equal(b.status, a.status, path + ' status ' + a.text);
    assert.deepEqual(strip(b.json), strip(a.json), path);
    return a.json;
  };
  // assets to count, scan and link (their writes are 9d's)
  const A = {};
  for (const [k, body] of [['srv', { name: 'srv1', asset_tag: 'TAG-1', serial: 'SN-AAA1', site: 'Riyadh', software: [{ name: 'Microsoft Office', publisher: 'Microsoft' }] }], ['vm', { name: 'vm1', asset_tag: 'TAG-2', site: 'Riyadh', type: 'vm' }], ['pc', { name: 'pc1', asset_tag: 'TAG-3', site: 'Jeddah' }], ['old', { name: 'old', asset_tag: 'TAG-4', site: 'Riyadh' }]]) A[k] = (await both('/assets', body)).asset.id;
  await both('/assets/' + A.old + '/retire', { reason: 'gone' });
  const before = P.app.coreWriteStats().python;
  const n0 = i;
  const steps = [
    ['/licences', { product: 'Microsoft Office', seats: '12.5', expiry: '2027-03-31', cost: '1200', product_key_match: 'office' }],
    ['/licences', { id: 'LIC-ADOBE', product: 'Adobe Acrobat', seats: -3, type: 'perpetual', publisher: 'Adobe' }],
    ['/licences', { id: 'LIC-ADOBE', product: 'Adobe Acrobat Pro', seats: 'abc', notes: ' renewed ' }],
    ['/licences', { id: 'LIC-X', seats: 5 }],
    ['/licences', { product: 'Visio', seats: 2.5, expiry: '2027-02-30' }],           // a date only Date.parse reads: Node.js decides
    ['/licences/LIC-ADOBE/retire', { reason: 'replaced' }],
    ['/licences/LIC-ADOBE/retire', {}],
    ['/licences/nope/retire', { reason: 'x' }],
    ['/stocktake', { site: ' Riyadh ', name: 'Q4 count' }, 'admin'],
    ['/stocktake', {}, 'admin'],
    [() => '/stocktake/' + stk + '/scan', { code: ' tag-1 ' }],
    [() => '/stocktake/' + stk + '/scan', { tag: 'TAG-1' }],
    [() => '/stocktake/' + stk + '/scan', { serial: 'sn-aaa1' }],
    [() => '/stocktake/' + stk + '/scan', { code: 'TAG-3' }],
    [() => '/stocktake/' + stk + '/scan', { code: 'NOT-OURS' }],
    [() => '/stocktake/' + stk + '/scan', { code: 'NOT-OURS' }],
    [() => '/stocktake/' + stk + '/scan', { code: '  ' }],
    [() => '/stocktake/' + stk + '/close', {}, 'admin'],
    [() => '/stocktake/' + stk + '/close', {}, 'admin'],
    [() => '/stocktake/' + stk + '/scan', { code: 'TAG-2' }],
    ['/stocktake/nope/scan', { code: 'TAG-1' }],
    ['/stocktake/nope/close', {}, 'admin'],
    ['/cmdb', { from: () => A.vm, to: () => A.srv, type: 'Runs_On', confidence: '0.7', rationale: ' vCenter says so ' }],
    ['/cmdb', { from: () => A.vm, to: () => A.srv, type: 'runs_on', confirm: false }],
    ['/cmdb', { from: () => A.srv, to: () => A.pc, type: 'connected_to', confirm: false, source: 'AI', confidence: 7 }],
    ['/cmdb', { from: () => A.pc, to: () => A.srv, type: 'connected_to', status: 'confirmed', id: 'mine' }],
    ['/cmdb', { from: () => A.pc, to: () => A.pc, type: 'depends_on' }],
    ['/cmdb', { from: () => A.pc, to: 'as_missing', type: 'depends_on' }],
    ['/cmdb', { from: () => A.pc, to: () => A.srv, type: 'likes' }],
  ];
  let stk = null;
  const val = (b) => { const o = {}; for (const [k, v] of Object.entries(b)) o[k] = typeof v === 'function' ? v() : v; return o; };
  for (const [p, body, role] of steps) {
    const r = await both(typeof p === 'function' ? p() : p, val(body), role);
    if (!stk && r && r.status === 'open' && r.site === 'Riyadh') stk = r.id;
  }
  assert.ok(stk, 'the Riyadh stocktake was opened');
  // findings: the same set in both (the engine computes them), then accept / dismiss
  await N.req('POST', '/ai/findings/regenerate', { user: 'siva', role: 'operator' }); await P.req('POST', '/ai/findings/regenerate', { user: 'siva', role: 'operator' });
  const fs = P.app.store.collection('findings').all().map((f) => f.id);
  assert.deepEqual(fs, N.app.store.collection('findings').all().map((f) => f.id));
  assert.ok(fs.length >= 1, 'a finding to decide on');
  await both('/ai/findings/' + fs[0] + '/accept', { reason: ' checked ' });
  await both('/ai/findings/' + fs[0] + '/accept', {});   // the earlier reason is kept
  await both('/ai/findings/' + fs[0] + '/dismiss', { reason: 0 });
  await both('/ai/findings/nope/accept', {});
  const writes = i - n0;
  for (const c of ['licences', 'stocktakes', 'relationships', 'findings', 'assets']) assert.deepEqual(P.app.store.collection(c).all(), N.app.store.collection(c).all(), c + ': the same records');
  const audits = (e) => strip(e.app.store.auditTail(2000, (x) => /^(licence|stocktake|cmdb|ai\.findings)\./.test(x.action)).map(({ at, prev, hash, seq: _s, ...rest }) => rest));
  assert.deepEqual(audits(P), audits(N), 'the same audit entries');
  let st = P.app.coreWriteStats();
  assert.deepEqual({ python: st.python - before, node: st.node, changed: st.changed_meanwhile }, { python: writes - 1, node: 1, changed: 0 }, 'Python decided every write but the date it hands back: ' + JSON.stringify(st));
  assert.equal(N.app.coreWriteStats().python, 0, 'writes.engine = "node": Node.js only');
  const lic = P.app.store.collection('licences').get('LIC-ADOBE');
  assert.equal(lic.status, 'inactive'); assert.equal(lic.seats, null); assert.equal(lic.product, 'Adobe Acrobat Pro');
  const stkRec = P.app.store.collection('stocktakes').get(stk);
  assert.equal(stkRec.status, 'closed'); assert.equal(stkRec.missing.length, 1, 'vm1 was not scanned (old is retired, pc1 is in Jeddah)');
  assert.equal(P.app.store.collection('relationships').all().length, 2, 'a symmetric link given both ways is one link');

  // decided on a record that changed meanwhile → never written; Node.js decides on what it holds
  const L = P.app.store.collection('licences'), lic2 = L.get('LIC-X') ? 'LIC-X' : L.all()[0].id;
  for (const e of [N, P]) e.app.store.collection('licences').get(lic2).notes = 'held in memory only';
  await both('/licences/' + lic2 + '/retire', { reason: 'stale copy' });
  st = P.app.coreWriteStats();
  assert.equal(st.node, 2); assert.equal(st.changed_meanwhile, 1);
  assert.deepEqual(P.app.store.collection('licences').all(), N.app.store.collection('licences').all());

  const t0 = process.hrtime.bigint();
  for (let k = 0; k < 20; k++) await P.req('POST', '/stocktake/' + stk + '/close', { body: {}, user: 'siva', role: 'admin' });
  t.diagnostic('Python-decided write: ' + (Number(process.hrtime.bigint() - t0) / 20e6).toFixed(1) + ' ms each (HTTP included)');
});
