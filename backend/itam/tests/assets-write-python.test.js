// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Migration step 9d (docs/PYTHON-MIGRATION.md): the human asset WRITES - add, edit, the lifecycle transitions, move,
// assign - decided by pyengine/assets_write.py and committed by engine/assets-write.js must do exactly what
// engine/assets.js does, over HTTP: the same answers, the same asset records (locks, provenance, sightings, lifecycle
// events) and the same audit entries, with the odd values people and imports send (padded text, numbers as text, hex,
// arrays, '1e400', aliases, MAC / IP spellings, dates with offsets, repeated tags, a software list). Python decides every
// write except the two it hands back on purpose (a date only Date.parse reads, a type named like an Object property),
// and a decision made on a record that is not the one this process holds is never written.
const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { spawnSync } = require('node:child_process');
const { startApp } = require('./helpers');

const PY = process.env.PYTHON || 'python3';
const hasPy = spawnSync(PY, ['--version']).status === 0;
const NOW = Date.parse('2026-10-19T09:00:00Z');

test('Python-decided asset writes do exactly what Node.js does', { skip: !hasPy && 'python3 not available' }, async (t) => {
  // one clock and one id sequence for both engines, so the two stores can be compared record for record
  const RealDate = Date, realRB = crypto.randomBytes;
  global.Date = class extends RealDate { constructor(...a) { if (a.length) super(...a); else super(NOW); } static now() { return NOW; } };
  let seq = 0;
  crypto.randomBytes = function (n, cb) { if (n !== 6 || cb) return realRB.apply(this, arguments); seq++; return Buffer.from(String(seq).padStart(12, '0'), 'hex'); };
  t.after(() => { global.Date = RealDate; crypto.randomBytes = realRB; });
  const N = await startApp({ noAi: true, config: { assets: { engine: 'node' } } }), P = await startApp({ noAi: true, config: { discovery: { python_bin: PY } } });
  t.after(async () => { await N.close(); await P.close(); });
  for (const e of [N, P]) e.app.now = () => NOW;
  const ids = {};
  const id = (k) => ids[k] || 'nope';
  const steps = [
    ['srv', '/assets', { asset_tag: ' TAG-1 ', name: 'Srv 1', type: 'Server', status: 'in_stock', site: 'Riyadh', location: { building: 'HQ', room: ' 3 ', rack: 7 }, owner: 'Siva', vendor: 'Dell', model: 'R750', serial: 'SN12345', mgmt_ip: '10.0.0.5', mac: 'AA-BB-CC-DD-EE-FF', os: 'Windows Server 2022', cpu: 'Xeon', mem_gb: '64', disk_gb: '0x10', warranty: { start: '2024-01-01', end: '2027-01-01T10:00:00.5+03:00', provider: 'Dell' }, purchase: { date: '2024-01-01', cost: '12,000', po: 12345, supplier: true }, eol: '2030-12-31', tags: ['a', ' b ', 'a', '', 5, null, [1, 2]], software: [{ name: 'Office', publisher: 'Microsoft', install_date: '2025-05-05T08:30Z' }, 'Chrome', { name: '' }, 7, ['x']], notes: 'line1\nline2', source_id: 'barcode-1' }],
    ['blank', '/assets', {}],
    ['nocost', '/assets', { name: 'no cost', purchase: { date: '2025-01-01', po: 'PO-9' } }],   // Number(undefined): null, not 0
    ['laptop', '/assets', { name: 'laptop', type: 'notebook', no_network_source: false, mem_gb: [8], disk_gb: '1e400', tags: 'single', status: 'broken', purchase: { cost: '  .5e1 ' }, warranty: { provider: '' } }],
    ['odd', '/assets', { type: 'spaceship', mac: 'zz-not-a-mac', mgmt_ip: '999.1.1.1', name: '  Pad ﻿', asset_tag: 12.5e-7, serial: 'ab', mem_gb: '-0', disk_gb: 'Infinity', networked: 'yes', location: ['x'], eol: '' }],
    ['ph', '/assets', { name: 'IP phone 7', type: 'IP Phone', mgmt_ip: '10.0.0.9', mem_gb: null, disk_gb: true, tags: [], warranty: 'none', purchase: { date: '2025-02-28T23:59:59Z', cost: 0 } }],
    ['nodedate', '/assets', { name: 'legacy', eol: 'Dec 5 2026' }],            // Date.parse's own format: Node.js decides
    ['proto', '/assets', { name: 'weird', type: 'constructor' }],              // TYPE_ALIASES['constructor'] in JS: Node.js decides
    [null, () => '/assets/' + id('srv'), { name: 'Srv 1 renamed', owner: 'Siva', tags: ['x', 'x', 'y'], mem_gb: 64, warranty: {}, status: 'retired', location: 'nope', unknown: 1 }],
    [null, () => '/assets/' + id('srv'), { name: 'Srv 1 renamed', mem_gb: 64 }],
    [null, () => '/assets/' + id('blank'), { mgmt_ip: '', mac: null, serial: ' SN-777 ', eol: '2031-01-01', networked: 0 }],
    [null, () => '/assets/' + id('blank'), { classification: ' Top-Secret ', cia: { c: 'HIGH', i: 'medium', a: 'nope', x: 'high' } }],   // information classification + CIA
    [null, () => '/assets/' + id('blank'), { classification: 'confidential', cia: {} }],                                          // not an NDMO level: a warning, kept as it was
    [null, () => '/assets/' + id('ph'), { classification: '', cia: { c: 'low', i: 'low', a: 'high' } }],
    [null, () => '/assets/nope', { name: 'x' }],
    [null, () => '/assets/' + id('srv') + '/retire', { reason: ' end of support ' }],
    [null, () => '/assets/' + id('srv') + '/dispose', {}],
    [null, () => '/assets/' + id('laptop') + '/lost', { reason: { why: 1 } }],
    [null, () => '/assets/' + id('laptop') + '/found', { reason: 42 }],
    [null, () => '/assets/' + id('odd') + '/repair', { reason: 'x'.repeat(2500) }],
    [null, () => '/assets/nope/restock', {}],
    [null, () => '/assets/' + id('ph') + '/move', { site: ' Jeddah ', location: { building: 'B2', rack: 4 } }],
    [null, () => '/assets/' + id('ph') + '/move', {}],
    [null, () => '/assets/' + id('ph') + '/move', { site: '', location: [] }],
    [null, () => '/assets/nope/move', { site: 'x' }],
    [null, () => '/assets/' + id('ph') + '/assign', { owner: ' Rasheed ', custodian: null, department: 5 }],
    [null, () => '/assets/' + id('blank') + '/assign', {}],
    [null, () => '/assets/nope/assign', { owner: 'x' }],
  ];
  const strip = (j) => JSON.parse(JSON.stringify(j));
  let i = 0;
  for (const [label, p, body] of steps) {
    const path = typeof p === 'function' ? p() : p;
    i++;
    seq = i * 10; const a = await N.req('POST', path, { body, user: 'siva', role: 'operator' });
    seq = i * 10 - (/^(nodedate|proto)$/.test(label) ? 1 : 0);   // handed back: the id given to Python goes unused, Node.js draws the next
    const b = await P.req('POST', path, { body, user: 'siva', role: 'operator' });
    assert.equal(b.status, a.status, path + ' status ' + a.text);
    assert.deepEqual(strip(b.json), strip(a.json), path);
    if (label && a.json && a.json.asset) ids[label] = a.json.asset.id;
  }
  assert.equal(Object.keys(ids).length, 8, 'every add answered a record');
  assert.deepEqual(P.app.store.collection('assets').all(), N.app.store.collection('assets').all(), 'the same asset records');
  const audits = (e) => e.app.store.auditTail(2000, (x) => /^asset\./.test(x.action)).map(({ at, prev, hash, ...rest }) => rest);
  assert.deepEqual(audits(P), audits(N), 'the same audit entries');
  assert.ok(audits(P).length >= steps.length - 5, 'the writes were audited');
  let st = P.app.assetsWriteStats();
  assert.deepEqual(st, { python: steps.length - 2, node: 2, changed_meanwhile: 0 }, 'Python decided every write but the two handed back: ' + JSON.stringify(st));
  assert.equal(N.app.assetsWriteStats().python, 0, 'assets.engine = "node": Node.js only');
  const srv = P.app.store.collection('assets').get(ids.srv);
  assert.equal(srv.status, 'disposed'); assert.equal(srv.locked.name, true); assert.equal(srv.prov.owner, 'manual');
  assert.equal(srv.mac, 'aa:bb:cc:dd:ee:ff'); assert.equal(srv.disk_gb, 16); assert.equal(srv.warranty, null, 'an empty warranty clears it');
  assert.equal(srv.purchase.cost, null, '"12,000" is not a number'); assert.equal(srv.eol, '2030-12-31T00:00:00.000Z');

  // a decision made on another copy of the record is never written: here this process holds a change it has not
  // written to the store files (Python reads those) - Node.js decides, on what it holds
  for (const e of [N, P]) e.app.store.collection('assets').get(ids.ph).notes = 'held in memory only';
  i++; seq = i * 10; const a = await N.req('POST', '/assets/' + ids.ph, { body: { name: 'phone 8' }, user: 'siva', role: 'operator' });
  seq = i * 10; const b = await P.req('POST', '/assets/' + ids.ph, { body: { name: 'phone 8' }, user: 'siva', role: 'operator' });
  assert.deepEqual(strip(b.json), strip(a.json));
  assert.equal(b.json.asset.notes, 'held in memory only', 'the record this process holds');
  st = P.app.assetsWriteStats();
  assert.equal(st.node, 3); assert.equal(st.changed_meanwhile, 1, 'counted as decided on another copy');
  assert.deepEqual(P.app.store.collection('assets').all(), N.app.store.collection('assets').all());

  // the cost of a write once the resident service runs
  const t0 = process.hrtime.bigint();
  for (let k = 0; k < 20; k++) await P.req('POST', '/assets/' + ids.blank + '/assign', { body: { owner: 'o' + k }, user: 'siva', role: 'operator' });
  t.diagnostic('Python-decided write: ' + (Number(process.hrtime.bigint() - t0) / 20e6).toFixed(1) + ' ms each (HTTP included)');
  assert.equal(P.app.assetsWriteStats().python, steps.length - 2 + 20);
});
