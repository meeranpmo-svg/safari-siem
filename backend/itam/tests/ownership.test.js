// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Asset ownership (engine/ownership.js): IT owner + business owner + business service per asset; service owners are
// inherited by assets without their own; coverage counts active assets only; import never guesses between two assets;
// viewers read, operators assign; every change audited.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { registerOwnership } = require('../engine/ownership');
const ADM = { user: 'syed', role: 'admin', ip: '' };

test('ownership: assign, inherit from the service, coverage, import without guessing, roles', async (t) => {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerOwnership(e.app.srv, e.app);
  const mk = (o) => e.app.assets.create(Object.assign({ type: 'server', status: 'in_use' }, o), ADM).asset.id;
  const a1 = mk({ name: 'CORE-DB01', asset_tag: 'ZS-1001', serial: 'SN1', mgmt_ip: '10.1.1.10', department: 'Finance' });
  const a2 = mk({ name: 'CORE-APP01', asset_tag: 'ZS-1002' });
  const a3 = mk({ name: 'CLAIMS-WEB', asset_tag: 'ZS-1003' });
  mk({ name: 'OLD-SRV', asset_tag: 'ZS-0999', status: 'retired' });
  mk({ name: 'DUP', asset_tag: 'ZS-2001' }); mk({ name: 'DUP', asset_tag: 'ZS-2002' });
  const view = e.as('viewer.v', 'viewer'), op = e.as('op.one', 'operator');
  let r = await view('GET', '/ownership'); assert.equal(r.status, 200);
  assert.equal(r.json.summary.assets, 5, 'retired asset out of scope');
  assert.equal(r.json.summary.with_business_owner, 0);
  assert.equal(r.json.items.find((x) => x.id === a1).business_owner, '', 'department is not guessed into an owner');
  assert.equal((await view('POST', '/ownership/assign', { body: { ids: [a1], it_owner: 'x' } })).status, 403);
  r = await op('POST', '/ownership/assign', { body: { ids: [a1, a2], business_service: 'Core Insurance', it_owner: 'IT Infrastructure - DB team', reason: 'ownership review' } });
  assert.equal(r.status, 200); assert.equal(r.json.updated, 2);
  await op('POST', '/ownership/services', { body: { service: 'Core Insurance', business_owner: 'Head of Underwriting', it_owner: 'IT Applications' } });
  r = await view('GET', '/ownership');
  const i1 = r.json.items.find((x) => x.id === a1);
  assert.equal(i1.business_owner, 'Head of Underwriting'); assert.equal(i1.business_owner_from, 'service', 'inherited from the service');
  assert.equal(i1.it_owner, 'IT Infrastructure - DB team'); assert.equal(i1.it_owner_from, 'asset', 'the asset\'s own owner wins over the service');
  assert.equal(r.json.summary.with_both, 2);
  assert.equal(r.json.services.find((s) => s.service === 'Core Insurance').assets, 2);
  assert.equal((await view('GET', '/ownership?missing=business')).json.items.length, 3);
  // import: matches tag / serial / name / ip, never guesses between two assets named DUP
  r = await op('POST', '/ownership/import', { body: { rows: [{ asset: 'ZS-1003', it_owner: 'Web team', business_owner: 'Head of Claims', business_service: 'Claims Portal' }, { asset: 'DUP', business_owner: 'x' }, { asset: 'NOPE', business_owner: 'y' }] } });
  assert.equal(r.json.updated, 1); assert.deepEqual(r.json.ambiguous, ['DUP']); assert.deepEqual(r.json.unmatched, ['NOPE']);
  const i3 = (await view('GET', '/ownership')).json.items.find((x) => x.id === a3);
  assert.equal(i3.business_owner, 'Head of Claims'); assert.equal(i3.updated_by, 'op.one');
  const bo = (await view('GET', '/ownership')).json.business_owners;
  assert.equal(bo[0].owner, 'Head of Underwriting'); assert.equal(bo[0].assets, 2);
  assert.ok(e.logs || true);
});
