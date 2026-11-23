// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const asset = require('../engine/model/asset');
const sw = require('../engine/model/software');
const rel = require('../engine/model/relationship');

test('asset.normaliseFields: type aliases, mac/ip normalisation, enum validation, dates', () => {
  const { fields, warnings } = asset.normaliseFields({ type: 'Switch', mac: 'AA-BB-CC-DD-EE-FF', mgmt_ip: '10.0.0.5', status: 'in_use', eol: '2027-01-01', warranty: { end: '2026-12-31', provider: 'Dell' }, tags: ['x', 'x', 'y'] });
  assert.equal(fields.type, 'network');
  assert.equal(fields.mac, 'aa:bb:cc:dd:ee:ff');
  assert.equal(fields.mgmt_ip, '10.0.0.5');
  assert.equal(fields.status, 'in_use');
  assert.match(fields.eol, /^2027-01-01/);
  assert.equal(fields.warranty.provider, 'Dell');
  assert.deepEqual(fields.tags, ['x', 'y']);
  assert.equal(warnings.length, 0);
});

test('asset.normaliseFields: unknown type → other + warning; invalid status ignored', () => {
  const { fields, warnings } = asset.normaliseFields({ type: 'frobnicator', status: 'exploded' });
  assert.equal(fields.type, 'other');
  assert.ok('status' in fields === false);
  assert.ok(warnings.some((w) => /type/.test(w)) && warnings.some((w) => /status/.test(w)));
});

test('software rollup + licence compliance (over/under/ok)', () => {
  const assets = [
    { id: 'a1', status: 'in_use', software: [{ name: 'Acme CAD', publisher: 'Acme', version: '1.0' }] },
    { id: 'a2', status: 'in_use', software: [{ name: 'Acme CAD', publisher: 'Acme', version: '1.1' }] },
    { id: 'a3', status: 'in_use', software: [{ name: 'Acme CAD', publisher: 'Acme', version: '1.1' }] },
  ];
  const rolled = sw.rollup(assets);
  const cad = rolled.find((p) => /cad/i.test(p.name));
  assert.equal(cad.installs, 3);
  assert.deepEqual(cad.versions, ['1.0', '1.1']);
  const over = sw.licenceCompliance(sw.normLicence({ id: 'L1', product: 'Acme CAD', seats: 2 }), rolled);
  assert.equal(over.compliance, 'over'); assert.equal(over.used, 3); assert.equal(over.delta, 1);
  const okL = sw.licenceCompliance(sw.normLicence({ id: 'L2', product: 'Acme CAD', seats: 3 }), rolled);
  assert.equal(okL.compliance, 'ok');
  const under = sw.licenceCompliance(sw.normLicence({ id: 'L3', product: 'Acme CAD', seats: 5 }), rolled);
  assert.equal(under.compliance, 'under'); assert.equal(under.delta, -2);
});

test('relationship normalisation, symmetric dedupe key, high-impact flag', () => {
  const r = rel.normRelationship({ from: 'a', to: 'b', type: 'CONNECTED_TO' });
  assert.equal(r.type, 'connected_to'); assert.equal(r.status, 'proposed');
  const r2 = rel.normRelationship({ from: 'b', to: 'a', type: 'connected_to' });
  assert.equal(r.key, r2.key, 'symmetric relationship keys match regardless of direction');
  assert.equal(rel.normRelationship({ from: 'a', to: 'a', type: 'runs_on' }), null);
  assert.ok(rel.isHighImpact(rel.normRelationship({ from: 'vm', to: 'h', type: 'runs_on' })));
  assert.ok(!rel.isHighImpact(rel.normRelationship({ from: 'a', to: 'b', type: 'connected_to' })));
});
