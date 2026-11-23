// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Asset alignment in the reconciliation (engine/reconcile.js alignmentIssues): every configured device is aligned with an
// asset - a database server with no asset and a host added to Server Availability by hand that no active asset has are
// issues; a host an asset (or a linked discovery device) has, and a database server linked to an asset, are not.
const test = require('node:test');
const assert = require('node:assert/strict');
const { alignmentIssues } = require('../engine/reconcile');

test('configured devices without an asset are listed; aligned ones are not', () => {
  const inp = {
    assets: [{ id: 'a1', name: 'ESKAUAT', status: 'in_use', mgmt_ip: '192.168.9.30' }, { id: 'a2', name: 'OLD', status: 'retired', mgmt_ip: '10.0.0.77' }],
    devices: [{ id: 'd1', asset_id: 'a3', ip: '10.0.0.5' }],
    dbservers: { servers: [{ ip: '192.168.9.30', host: 'eskauat', asset: { id: 'a1' }, databases: [{ instance: 'ESS' }] }, { ip: '10.0.0.9', host: 'hrdb01', asset: null, asset_suggestion: { name: 'hrdb01' }, databases: [{ instance: 'HRP' }] }] },
    avail: { ok: true, data: { hosts: { '192.168.9.30': { s: 'online' }, '10.0.0.5': { s: 'online' }, '10.0.0.77': { s: 'online' }, '10.9.9.9': { s: 'offline' } } } },
  };
  const out = alignmentIssues(inp);
  assert.deepEqual(out.map((i) => i.id).sort(), ['dbsrv:10.0.0.9', 'monorphan:10.0.0.77', 'monorphan:10.9.9.9']);
  const db = out.find((i) => i.kind === 'db_server_not_in_inventory');
  assert.match(db.found, /HRP/); assert.match(db.found, /same name as asset hrdb01/);
  assert.equal(out.find((i) => i.id === 'monorphan:10.0.0.77').source, 'availability', 'a RETIRED asset does not align a monitored host');
  assert.deepEqual(alignmentIssues({ assets: [], devices: [], avail: { ok: false } }), [], 'a source that cannot be read adds nothing (reported as not checked elsewhere)');
});
