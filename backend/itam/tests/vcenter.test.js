// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const vc = require('../engine/connectors/vcenter');
const { VC_HOSTS, VC_VMS, vcenterFetch } = require('./helpers');

test('parseHosts: vSphere {value:[...]} envelope → server asset fields', () => {
  const hosts = vc.parseHosts(VC_HOSTS);
  assert.equal(hosts.length, 1);
  assert.equal(hosts[0].source_id, 'host-1');
  assert.equal(hosts[0].fields.type, 'server');
  assert.equal(hosts[0].fields.mem_gb, 256);
  assert.equal(hosts[0].fields.uuid, 'HOSTUUID-1');
  assert.ok(hosts[0].fields.os.includes('ESXi'));
});

test('parseVms: VM fields + host linkage; runs_on relationship hints', () => {
  const vms = vc.parseVms(VC_VMS);
  assert.equal(vms[0].fields.type, 'vm');
  assert.equal(vms[0].fields.mem_gb, 8);
  assert.equal(vms[0].host_source_id, 'host-1');
  const rels = vc.vmHostRelationships(vms);
  assert.deepEqual(rels[0], { vm_source_id: 'vm-101', host_source_id: 'host-1', type: 'runs_on' });
});

test('connector.pull via injected fetch (no network): hosts + vms + relationships', async () => {
  const conn = vc.createVcenterConnector({ config: { vcenter: {} }, fetchImpl: vcenterFetch() });
  const r = await conn.pull();
  assert.equal(r.ok, true);
  assert.equal(r.hosts.length, 1); assert.equal(r.vms.length, 1); assert.equal(r.relationships.length, 1);
});

// ---- ZS-25: legacy vCenter connector transport policy -----------------------------------------------------------------
test('ZS-25 legacy vCenter connector refuses http:// and insecure_tls unless lab_mode', async () => {
  const http = require('node:http');
  let hits = 0;
  const srv = http.createServer((req, res) => { hits++; res.writeHead(401); res.end('{}'); });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const url = `http://127.0.0.1:${srv.address().port}`;
  try {
    const creds = () => ({ user: 'u', pass: 'synthetic-pass' });
    const plain = await vc.createVcenterConnector({ config: { vcenter: { base_url: url } }, getCreds: creds }).pull();
    assert.equal(plain.ok, false); assert.match(plain.error, /must be https/);
    const insecure = await vc.createVcenterConnector({ config: { vcenter: { base_url: 'https://127.0.0.1:1', insecure_tls: true } }, getCreds: creds }).pull();
    assert.equal(insecure.ok, false); assert.match(insecure.error, /insecure_tls is refused/);
    assert.equal(hits, 0, 'no request (and no Basic-auth password) sent');
    const lab = await vc.createVcenterConnector({ config: { vcenter: { base_url: url, lab_mode: true } }, getCreds: creds }).pull();
    assert.equal(lab.ok, false); assert.match(lab.error, /session failed/);
    assert.equal(hits, 1, 'lab_mode allows http');
  } finally { srv.close(); }
});
