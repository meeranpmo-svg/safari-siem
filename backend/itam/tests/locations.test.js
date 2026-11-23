// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Shared locations: add, edit (renames inventory assets), unsaved sites, delete only when unused.
const test = require('node:test');
const assert = require('node:assert/strict');
const { createLocations } = require('../engine/locations');

function fakeStore(init) {
  const cols = {};
  return { collection: (n) => cols[n] || (cols[n] = (() => { const m = new Map((init[n] || []).map((o) => [o.id, o])); return {
    all: (f) => [...m.values()].filter((o) => !f || f(o)), get: (id) => m.get(id), put: (o) => { m.set(o.id, JSON.parse(JSON.stringify(o))); return o; }, remove: (id) => m.delete(id),
    patch: (id, fn) => { const c = JSON.parse(JSON.stringify(m.get(id))); const r = fn(c); m.set(id, r && typeof r === 'object' ? r : c); return m.get(id); } }; })()) };
}
const adm = { user: 'siva', role: 'admin' };

test('locations: add, list with inventory sites, rename everywhere, delete rules', () => {
  const st = fakeStore({ assets: [{ id: 'a1', site: 'Riyadh HQ' }, { id: 'a2', site: 'riyadh hq' }, { id: 'a3', site: 'Jeddah' }] });
  const audits = []; const L = createLocations({ store: st, audit: (e) => audits.push(e) });
  let v = L.list(); assert.deepEqual(v.locations.map((l) => [l.name, l.assets, l.saved]), [['Jeddah', 1, false], ['Riyadh HQ', 2, false]]);
  assert.throws(() => L.create({ name: '' }, adm), /name is required/);
  assert.throws(() => L.create({ name: 'Dammam', kind: 'moon' }, adm), /kind must be/);
  const c = L.create({ name: 'Dammam Branch', city: 'Dammam', kind: 'branch' }, adm);
  assert.equal(c.location.kind, 'branch'); assert.throws(() => L.create({ name: 'dammam branch' }, adm), /already exists/);
  const e = L.edit('site:Jeddah', { name: 'Jeddah DR', city: 'Jeddah', kind: 'dr' }, adm);
  assert.equal(e.renamed, 1); assert.equal(st.collection('assets').get('a3').site, 'Jeddah DR');
  v = L.list(); assert.equal(v.locations.find((l) => l.name === 'Jeddah DR').assets, 1); assert.ok(!v.locations.some((l) => l.name === 'Jeddah'));
  const jid = v.locations.find((l) => l.name === 'Jeddah DR').id;
  assert.throws(() => L.remove(jid, adm), /move them first/);
  assert.equal(L.remove(c.location.id, adm).locations.some((l) => l.name === 'Dammam Branch'), false);
  assert.deepEqual(audits.map((a) => a.action), ['location.create', 'location.edit', 'location.delete']);
});
