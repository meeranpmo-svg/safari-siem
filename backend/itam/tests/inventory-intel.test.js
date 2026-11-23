// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// ITAM Inventory intelligence (engine/inventory-intel.js) over a SYNTHETIC register: quality per asset with the missing fields (what
// matters depends on the type), duplicates by serial / MAC (strong) and host name (weak), spec outliers against the median of the
// same model, stale and ghost assets, facets and coverage by field and site; retired assets only with all=1; viewers read; nothing written.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');

const VW = { user: 'vera.syn', role: 'viewer' };
const ago = (d) => new Date(Date.now() - d * 86400000).toISOString();
test('quality, duplicates, outliers, stale, ghosts, facets', async (t) => {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true, python: process.env.PYTHON || 'python3' });
  const A = e.app.store.collection('assets');
  const full = { serial: 'S', mac: '00:11:22:33:44:00', owner: 'o', site: 'Riyadh', department: 'IT', vendor: 'SynV', model: 'SYN-100', warranty: { end: '2028-01-01' }, eol: '2030-01-01', classification: 'restricted', cia: { c: 'high' } };
  for (let i = 0; i < 4; i++) A.put(Object.assign({}, full, { id: 'w' + i, name: 'WS-' + i, type: 'workstation', status: 'in_use', networked: true, serial: 'SER' + i, mac: '00:11:22:33:44:0' + i, mem_gb: i === 3 ? 64 : 16, last_seen: ago(1) }));
  A.put({ id: 'bare', name: 'BARE-1', type: 'server', status: 'in_use', networked: true, last_seen: ago(90), site: 'Jeddah' });
  A.put(Object.assign({}, full, { id: 'dup', name: 'WS-0-copy', type: 'workstation', status: 'in_use', serial: 'SER0', mac: '00:11:22:33:44:99', last_seen: ago(1) }));
  A.put({ id: 'old', name: 'OLD-1', type: 'laptop', status: 'retired', last_seen: ago(2) });
  const v = (await e.req('GET', '/inventory', VW)).json;
  const R = (id) => v.rows.find((r) => r.id === id);
  assert.equal(R('w0').quality, 100); assert.ok(R('bare').quality < 30); assert.ok(R('bare').missing.includes('serial') && R('bare').missing.includes('owner'));
  assert.ok(R('bare').issues.includes('stale') && R('bare').issues.includes('incomplete'));
  assert.ok(v.duplicates.some((d) => [d.a, d.b].sort().join() === 'dup,w0' && d.strength === 'strong' && d.by.includes('serial')), JSON.stringify(v.duplicates));
  assert.ok(R('w3').issues.includes('outlier') && /memory 64 GB vs 16 GB typical for SYN-100/.test(R('w3').outlier[0]));
  assert.equal(R('old'), undefined, 'retired hidden by default');
  const va = (await e.req('GET', '/inventory?all=1', VW)).json; assert.ok(va.rows.find((r) => r.id === 'old').issues.includes('ghost'), 'retired yet seen 2 days ago');
  assert.equal(v.facets.type.find((f) => f.value === 'workstation').count, 5);
  assert.ok(v.quality.by_site[0].site === 'Jeddah', 'worst site first');
  assert.equal(v.quality.by_field.find((f) => f.field === 'serial').have, 5);
});
