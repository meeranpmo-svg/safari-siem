// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const merge = require('../engine/model/merge');

function mkAsset(f) { return Object.assign({ id: 'x', sources: [], tags: [], prov: {}, locked: {} }, f); }

test('identityKeys: serial strongest, mac medium, name weak', () => {
  const k = merge.identityKeys({ serial: 'SN1', mac: 'aa:bb:cc:dd:ee:ff', name: 'host' });
  assert.ok(k.find((x) => x.k === 'serial:sn1' && x.w === 100));
  assert.ok(k.find((x) => x.k.startsWith('mac:') && x.w === 70));
  assert.ok(k.find((x) => x.k === 'name:host' && x.w === 30));
});

test('decideMatch: single strong key → confident match; two strong → ambiguous; name-only weak', () => {
  const a = mkAsset({ id: 'a', serial: 'SN1' });
  const b = mkAsset({ id: 'b', serial: 'SN2' });
  const one = merge.decideMatch(merge.identityKeys({ serial: 'SN1' }), [a, b]);
  assert.equal(one.match.id, 'a'); assert.equal(one.ambiguous, false);
  // two assets both carry the same mac (conflict) → ambiguous
  const c = mkAsset({ id: 'c', mac: 'aa:bb:cc:dd:ee:ff' });
  const d = mkAsset({ id: 'd', mac: 'aa:bb:cc:dd:ee:ff' });
  const amb = merge.decideMatch(merge.identityKeys({ mac: 'aa:bb:cc:dd:ee:ff' }), [c, d]);
  assert.equal(amb.match, null); assert.equal(amb.ambiguous, true);
  const none = merge.decideMatch(merge.identityKeys({ serial: 'ZZZ' }), [a, b]);
  assert.equal(none.match, null);
});

test('mergeInto: field precedence — sensor wins mac, agent wins os; blanks always filled', () => {
  let a = mkAsset({ id: 'a' });
  // sensor sees network identity
  ({ asset: a } = merge.mergeInto(a, { mac: 'aa:bb:cc:dd:ee:ff', mgmt_ip: '10.0.0.5', os: 'IOS 15' }, 'sensor', { source_id: 'nd1' }));
  assert.equal(a.mac, 'aa:bb:cc:dd:ee:ff'); assert.equal(a.networked, true);
  // agent reports a better OS → agent wins os (higher precedence for os)
  ({ asset: a } = merge.mergeInto(a, { os: 'Windows 11 23H2', mac: 'ff:ff:ff:ff:ff:ff' }, 'agent', { source_id: 'agt1' }));
  assert.equal(a.os, 'Windows 11 23H2', 'agent wins os');
  assert.equal(a.mac, 'aa:bb:cc:dd:ee:ff', 'sensor keeps mac over agent');
  assert.equal(a.sources.length, 2);
});

test('mergeInto: human-locked field is never overwritten by a discovery source', () => {
  let a = mkAsset({ id: 'a', owner: 'Ali', locked: { owner: true }, prov: { owner: 'manual' } });
  ({ asset: a } = merge.mergeInto(a, { owner: 'Discovered User', name: 'srv1' }, 'agent', { source_id: 'agt1' }));
  assert.equal(a.owner, 'Ali', 'locked owner survives agent merge');
  assert.equal(a.name, 'srv1');
});

test('mergeInto: tags union + first_seen/last_seen tracking across sources', () => {
  let a = mkAsset({ id: 'a', tags: ['keep'] });
  ({ asset: a } = merge.mergeInto(a, { tags: ['netops'] }, 'sensor', { source_id: 'nd1', at: '2026-01-01T00:00:00Z' }));
  ({ asset: a } = merge.mergeInto(a, { tags: ['agent-reported'] }, 'agent', { source_id: 'agt1', at: '2026-02-01T00:00:00Z' }));
  assert.deepEqual(a.tags.sort(), ['agent-reported', 'keep', 'netops']);
  assert.equal(a.first_seen, '2026-01-01T00:00:00Z');
  assert.equal(a.last_seen, '2026-02-01T00:00:00Z');
});
