// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Migration step 9f (docs/PYTHON-MIGRATION.md): the Locations and Asset Ownership writes decided by
// pyengine/addons_write.py and committed by engine/py-writer.js must do exactly what Node.js does, over HTTP: create /
// rename (on every inventory asset at that site) / delete a location, an inventory site saved on first edit (and kept
// when its new name is then refused), names that clash only by case or spacing; ownership for many assets at once
// (repeated and unknown ids), service owners set and cleared, a CSV import that never guesses between two assets.
// Same answers, records and audit entries; Python decides every write.
const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { spawnSync } = require('node:child_process');
const { startApp } = require('./helpers');
const { registerOwnership } = require('../engine/ownership');

const PY = process.env.PYTHON || 'python3';
const hasPy = spawnSync(PY, ['--version']).status === 0;
const NOW = Date.parse('2026-10-19T09:00:00Z');

test('Python-decided Locations and Ownership writes do exactly what Node.js does', { skip: !hasPy && 'python3 not available' }, async (t) => {
  const RealDate = Date, realRB = crypto.randomBytes;
  global.Date = class extends RealDate { constructor(...a) { if (a.length) super(...a); else super(NOW); } static now() { return NOW; } };
  let seq = 0;
  crypto.randomBytes = function (n, cb) { if ((n !== 5 && n !== 6) || cb) return realRB.apply(this, arguments); return Buffer.from(String(seq).padStart(2 * n, '0'), 'hex'); };
  t.after(() => { global.Date = RealDate; crypto.randomBytes = realRB; });
  const off = { locations: { engine: 'node' }, ownership: { engine: 'node' }, assets: { engine: 'node' } };
  const N = await startApp({ noAi: true, config: off }), P = await startApp({ noAi: true, config: { discovery: { python_bin: PY } } });
  t.after(async () => { await N.close(); await P.close(); });
  for (const e of [N, P]) registerOwnership(e.app.srv, e.app);
  const strip = (j) => JSON.parse(JSON.stringify(j));
  let i = 0;
  const both = async (path, body, role = 'admin') => {
    i++;
    seq = i; const a = await N.req('POST', path, { body, user: 'syed', role });
    seq = i; const b = await P.req('POST', path, { body, user: 'syed', role });
    assert.equal(b.status, a.status, path + ' status ' + a.text);
    assert.deepEqual(strip(b.json), strip(a.json), path);
    return a.json;
  };
  const A = {};
  for (const [k, body] of [['db', { name: 'CORE-DB01', asset_tag: 'ZS-1001', serial: 'SN1', mgmt_ip: '10.1.1.10', site: 'Riyadh HQ' }], ['app', { name: 'CORE-APP01', asset_tag: 'ZS-1002', site: ' riyadh  hq ' }],
    ['pc', { name: 'PC-7', asset_tag: 'ZS-2001', site: 'Jeddah' }], ['twin1', { name: 'TWIN', asset_tag: 'ZS-3001' }], ['twin2', { name: 'twin', asset_tag: 'ZS-3002', allow_duplicate: true }], ['gone', { name: 'OLD-1', asset_tag: 'ZS-9', site: 'Dammam' }]]) A[k] = (await both('/assets', body, 'operator')).asset.id;
  await both('/assets/' + A.gone + '/dispose', { reason: 'scrapped' }, 'operator');
  const w0 = i;
  let loc = null;
  const steps = [
    ['/locations', { name: '  Riyadh   DR ', city: 'Riyadh', kind: 'DR', address: 'Exit 5\nKing Fahd Rd' }],
    ['/locations', { name: 'riyadh dr' }],
    ['/locations', { name: '' }],
    ['/locations', { name: 'Cloud', kind: 'space' }],
    ['/locations', { name: 'Azure UAE', kind: 'cloud', notes: 'x'.repeat(600) }],
    [() => '/locations/' + loc, { city: 'Riyadh 2', kind: '' }],
    [() => '/locations/' + loc, { name: 'Azure UAE' }],
    ['/locations/' + encodeURIComponent('site:Riyadh HQ'), { name: 'Riyadh Head Office', kind: 'main' }],
    ['/locations/' + encodeURIComponent('site:Jeddah'), { name: 'azure uae' }],          // saved first, then the name refused
    ['/locations/nope', { name: 'x' }],
    [() => '/locations/' + loc + '/delete', {}],
    ['/locations/nope/delete', {}],
    ['/ownership/assign', { ids: [() => A.db, () => A.app, () => A.db, 'as_missing', '', null], it_owner: ' Infra Team ', business_owner: 'CFO', business_service: 'Core Banking', reason: 'Q4 review' }, 'operator'],
    ['/ownership/assign', { ids: () => A.pc, business_service: '' }, 'operator'],
    ['/ownership/assign', { ids: [], it_owner: 'x' }, 'operator'],
    ['/ownership/assign', { ids: [() => A.pc] }, 'operator'],
    ['/ownership/services', { service: ' Core Banking ', business_owner: 'CFO', it_owner: 'Infra Team' }, 'operator'],
    ['/ownership/services', { service: 'core banking', it_owner: '' }, 'operator'],
    ['/ownership/services', { service: '  ' }, 'operator'],
    ['/ownership/import', { rows: [{ asset: 'zs-1002', it_owner: 'App Team' }, { serial: 'SN1', business_owner: '  ', business_service: 'Treasury' }, { name: 'twin', it_owner: 'x' }, { ip: '10.9.9.9', it_owner: 'y' }, { asset: 'ZS-9', it_owner: 'z' }, { asset_tag: 'ZS-2001' }, { asset: 'ZS-2001', business_owner: 0 }], reason: '' }, 'operator'],
    ['/ownership/import', { rows: [] }, 'operator'],
  ];
  const val = (v) => (typeof v === 'function' ? v() : Array.isArray(v) ? v.map(val) : v && typeof v === 'object' ? Object.fromEntries(Object.entries(v).map(([k, x]) => [k, val(x)])) : v);
  for (const [p, body, role] of steps) {
    const r = await both(typeof p === 'function' ? p() : p, val(body), role);
    if (!loc && r && r.location && r.location.name === 'Riyadh DR') loc = r.location.id;
  }
  const writes = i - w0;
  for (const c of ['locations', 'assets', 'asset_ownership', 'ownership_services']) assert.deepEqual(P.app.store.collection(c).all(), N.app.store.collection(c).all(), c + ': the same records');
  const audits = (e) => strip(e.app.store.auditTail(2000, (x) => /^(location|ownership|asset\.ownership)/.test(x.action)).map(({ at, prev, hash, seq: _s, ...rest }) => rest));
  assert.deepEqual(audits(P), audits(N), 'the same audit entries');
  const st = { l: P.app.locationsWriteStats(), o: P.app.ownershipWriteStats() };
  assert.equal(st.l.python + st.o.python, writes, 'Python decided every write: ' + JSON.stringify(st));
  assert.equal(st.l.node + st.o.node, 0);
  assert.equal(N.app.locationsWriteStats().python + N.app.ownershipWriteStats().python, 0, 'engine = "node": Node.js only');
  const assets = P.app.store.collection('assets');
  assert.equal(assets.get(A.db).site, 'Riyadh Head Office'); assert.equal(assets.get(A.app).site, 'Riyadh Head Office', 'renamed on every asset at the site, spacing and case aside');
  assert.ok(P.app.store.collection('locations').all().some((l) => l.name === 'Jeddah'), 'the inventory site saved before its new name was refused');
  assert.equal(P.app.store.collection('asset_ownership').get(A.app).it_owner, 'App Team');
  assert.equal(P.app.store.collection('asset_ownership').get(A.twin1), null, 'two assets called twin: never guessed');
});
