// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// IP / MAC for PCs and servers from the SIEM: fills only empty fields, devices + assets, errors reported.
const test = require('node:test');
const assert = require('node:assert/strict');
const { createSiemIp } = require('../engine/siem-ip');

function fakeStore(init) {
  const cols = {};
  const col = (n) => cols[n] || (cols[n] = (() => { const m = new Map((init[n] || []).map((o) => [o.id, o])); return {
    all: (f) => [...m.values()].filter((o) => !f || f(o)), get: (id) => m.get(id),
    patch: (id, fn) => { const c = JSON.parse(JSON.stringify(m.get(id))); const r = fn(c); m.set(id, r && typeof r === 'object' ? r : c); return m.get(id); } }; })());
  return { collection: col };
}

test('fills missing IP / MAC from the SIEM, never overwrites', async () => {
  const store = fakeStore({
    disc_devices: [{ id: 'd1', hostname: 'jb-sa2051-lt', status: 'new', ips: [], macs: [] }, { id: 'd2', hostname: 'ho-sa1914-lt', status: 'new', ip: '10.0.0.9', ips: ['10.0.0.9'], macs: [] }, { id: 'd3', hostname: 'x', status: 'ignored', ips: [], macs: [] }],
    assets: [{ id: 'a1', type: 'laptop', name: 'JB-SA2051-LT', status: 'in_use' }, { id: 'a2', type: 'server', name: 'srv1', mgmt_ip: '10.1.1.1', mac: 'aa:bb:cc:dd:ee:ff', status: 'in_use' }, { id: 'a3', type: 'printer', name: 'prn', status: 'in_use' }],
  });
  const asked = []; const audits = [];
  const x = createSiemIp({ store, config: { discovery: { siem: {} } }, audit: (e) => audits.push(e) }, { request: async (p, b) => { asked.push(...b.names); return { hosts: { 'jb-sa2051-lt': { ip: '192.168.40.21', mac: '00:1a:2b:3c:4d:5e', via: 'kerberos', seen: 't' }, 'ho-sa1914-lt': { ip: '10.9.9.9', mac: '00-11-22-33-44-55', via: 'firewall' } } }; } });
  const r = await x.run({ user: 'adm', role: 'admin' });
  assert.deepEqual(asked.sort(), ['ho-sa1914-lt', 'jb-sa2051-lt']);
  const D = store.collection('disc_devices'), A = store.collection('assets');
  assert.equal(D.get('d1').ip, '192.168.40.21'); assert.deepEqual(D.get('d1').macs, ['00:1a:2b:3c:4d:5e']); assert.equal(D.get('d1').extra.siem.via, 'kerberos'); assert.equal(D.get('d1').methods.siem.count, 1);
  assert.equal(D.get('d2').ip, '10.0.0.9', 'existing IP kept'); assert.deepEqual(D.get('d2').macs, ['00:11:22:33:44:55']);
  assert.equal(A.get('a1').mgmt_ip, '192.168.40.21'); assert.equal(A.get('a1').mac, '00:1a:2b:3c:4d:5e'); assert.equal(A.get('a1').prov.mgmt_ip, 'siem');
  assert.equal(A.get('a2').mgmt_ip, '10.1.1.1');
  assert.deepEqual([r.found, r.devices_ip, r.devices_mac, r.assets_ip, r.assets_mac], [2, 1, 2, 1, 1]); assert.equal(audits.length, 1);
});

test('SIEM failure is reported, nothing changed; not configured is explained', async () => {
  const store = fakeStore({ disc_devices: [{ id: 'd1', hostname: 'pc1', status: 'new', ips: [], macs: [] }], assets: [] });
  const x = createSiemIp({ store, config: {} }, { request: async () => { throw new Error('SIEM HTTP 404'); } });
  const r = await x.safeRun(); assert.equal(r.ok, false); assert.match(r.error, /404/); assert.equal(store.collection('disc_devices').get('d1').ip, undefined);
  const y = createSiemIp({ store, config: {} }); const r2 = await y.safeRun(); assert.match(r2.error, /not configured/);
});
