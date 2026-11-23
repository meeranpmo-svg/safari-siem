// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Migration step 8c (docs/PYTHON-MIGRATION.md): the asset read routes answered by Python reading the store
// (pyengine/assets_read.py via engine/assets-py.js) must answer exactly like the Node.js routes. One inventory is built
// through the real engine (assets of every status with provenance / locks, sources, software, relationships confirmed
// and proposed, licences active / retired / Microsoft 365), then a Python-backed engine and a Node.js-only engine
// (off by default until step 9; assets.engine = "python" here) are started on identical copies of the data and every route is asked the same questions over
// HTTP - filters, text search, limits that are not numbers, an unknown asset, lookup by tag and serial, the software
// roll-up, licence compliance (with the Microsoft 365 seats of the licence sync add-on) and the CMDB graph.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { startApp, tmpDir } = require('./helpers');
const { createLicenceSync } = require('../engine/licence-sync');

const PY = process.env.PYTHON || 'python3';
const hasPy = spawnSync(PY, ['--version']).status === 0;
const ADM = { user: 'syed', role: 'admin', ip: '' };

async function build(dir) {
  const e = await startApp({ noAi: true, dir });
  const A = e.app.assets, mk = (o) => A.create(Object.assign({ status: 'in_use' }, o), ADM).asset.id;
  const ids = {
    srv: mk({ name: 'DC-HQA', type: 'server', asset_tag: 'AT-0001', serial: 'SN-ABC', site: 'RUH', owner: 'it', vendor: 'Dell', model: 'R740', networked: true, software: [{ name: 'Microsoft SQL Server 2019', publisher: 'Microsoft Corporation', version: '15.0' }, { name: 'Oracle Database 19c', publisher: 'Oracle' }] }),
    vm: mk({ name: 'app-vm', type: 'vm', site: 'JED', networked: true, software: ['Microsoft SQL Server 2019 15.0.2000'] }),
    pc: mk({ name: 'PC-77 Ahmed', type: 'workstation', asset_tag: 'at-0077', owner: 'ahmed', software: [{ name: 'Microsoft Office Professional Plus 2019', publisher: 'Microsoft' }, { name: 'AutoCAD 2024', publisher: 'Autodesk' }] }),
    ret: mk({ name: 'old-srv', type: 'server', status: 'retired', serial: 'sn-old', software: [{ name: 'Microsoft Office Professional Plus 2019', publisher: 'Microsoft' }] }),
    disp: mk({ name: 'gone-pc', type: 'workstation', status: 'disposed', software: [{ name: 'Adobe Photoshop', publisher: 'Adobe' }] }),
    sw: mk({ name: 'core-sw1', type: 'network', vendor: 'Cisco', model: 'C9500', site: 'RUH', networked: true }),
    ar: mk({ name: 'خادم-المالية', type: 'server', site: 'DMM', vendor: 'HPE' }),
  };
  e.app.store.collection('assets').patch(ids.srv, (a) => { a.prov = { os: 'agent' }; a.locked = { owner: true }; a.sources = [{ source: 'sensor', source_id: 's1', first_seen: '2026-01-01', last_seen: '2026-10-01', extra: 1 }, { source: 'vcenter', source_id: 'vm-1' }]; });
  e.app.store.collection('assets').patch(ids.vm, (a) => { a.sources = [{ source: 'vcenter', source_id: 'vm-9' }]; });
  A.addRelationship({ from: ids.vm, to: ids.srv, type: 'runs_on' }, ADM, { source: 'manual', autoConfirm: true });
  A.addRelationship({ from: ids.pc, to: ids.sw, type: 'connected_to' }, ADM, { source: 'sensor', autoConfirm: false });
  A.addRelationship({ from: ids.srv, to: ids.sw, type: 'connected_to' }, ADM, { source: 'manual', autoConfirm: true });
  const L = e.app.licences;
  L.upsert({ id: 'lic_sql', product: 'SQL Server', seats: 1, product_key_match: 'sql server' }, ADM);
  L.upsert({ id: 'lic_office', product: 'Microsoft Office', seats: 10, expiry: '2026-12-31' }, ADM);
  L.upsert({ id: 'lic_x', product: 'Nothing installed' }, ADM);
  L.upsert({ id: 'lic_old', product: 'AutoCAD', seats: 2 }, ADM); L.retire('lic_old', ADM, 'replaced');
  e.app.store.collection('licences').put({ id: 'lic_m365', product: 'Microsoft 365 E3', seats: 50, status: 'active', source: 'm365', m365: { consumed: '47', sku: 'ENTERPRISEPACK' } });
  e.app.store.collection('licences').put({ id: 'lic_m365b', product: 'Visio Plan 2', status: 'active', source: 'm365', m365: { consumed: 'x' } });
  await e.close();
  return ids;
}

function copyDir(a, b) { fs.mkdirSync(b, { recursive: true }); for (const f of fs.readdirSync(a)) { const s = path.join(a, f); if (fs.statSync(s).isDirectory()) copyDir(s, path.join(b, f)); else fs.copyFileSync(s, path.join(b, f)); } }

test('Python asset read routes answer exactly like the Node.js ones', { skip: !hasPy && 'python3 not available' }, async (t) => {
  const d0 = tmpDir(); const ids = await build(d0);
  const dn = tmpDir(), dp = tmpDir(); copyDir(d0, dn); copyDir(d0, dp);
  const N = await startApp({ noAi: true, dir: dn, config: { assets: { engine: 'node' } } });
  const P = await startApp({ noAi: true, dir: dp, config: { assets: { engine: 'python' }, discovery: { python_bin: PY } } });
  t.after(async () => { await N.close(); await P.close(); });
  for (const e of [N, P]) createLicenceSync(e.app, { siemCall: async () => ({ status: 404 }) });   // the Microsoft 365 seats wrapper
  const paths = ['/assets', '/assets?type=server', '/assets?status=retired', '/assets?site=RUH&type=network', '/assets?owner=ahmed', '/assets?source=vcenter', '/assets?networked=1', '/assets?networked=0',
    '/assets?q=ahmed', '/assets?q=SN-ABC', '/assets?q=%D8%AE%D8%A7%D8%AF%D9%85', '/assets?q=nothing', '/assets?limit=2', '/assets?limit=0', '/assets?limit=abc', '/assets?limit=1e1', '/assets?limit=2.5', '/assets?limit=99999',
    '/assets/' + ids.srv, '/assets/' + ids.vm, '/assets/' + ids.disp, '/assets/nope', '/lookup?tag=AT-0077', '/lookup?q=sn-abc', '/lookup?tag=SN-OLD', '/lookup?tag=none', '/lookup',
    '/software', '/licences', '/cmdb', '/cmdb?asset=' + ids.sw, '/cmdb?asset=' + ids.sw + '&confirmed=1', '/cmdb?asset=nope'];
  for (const p of paths) for (const role of ['viewer', 'operator']) {
    const [a, b] = await Promise.all([N.req('GET', p, { role }), P.req('GET', p, { role })]);
    assert.equal(b.status, a.status, p + ' status');
    assert.deepEqual(b.json, a.json, p + ' as ' + role);
  }
  // it really was Python: the answer must survive the Node.js module being unable to answer
  P.app.assets.list = () => { throw new Error('Node.js asked'); }; P.app.licences.complianceView = Object.assign(() => { throw new Error('Node.js asked'); }, { m365: true });   // the wrapper's mark stays
  assert.equal((await P.req('GET', '/assets')).status, 200, 'Python answered /assets');
  assert.equal((await P.req('GET', '/licences')).json.licences.find((l) => l.id === 'lic_m365').used, 47, 'Microsoft 365 assigned seats');
  const sec = await P.req('GET', '/assets/' + ids.srv);
  assert.ok(!('prov' in sec.json.asset) && !('locked' in sec.json.asset), 'provenance and locks never leave the engine');
  // writes still go through Node.js and Python sees them at once
  const id = P.app.assets.create({ name: 'new-one', type: 'server', status: 'in_use' }, ADM).asset.id;
  assert.ok((await P.req('GET', '/assets?q=new-one')).json.assets.some((a) => a.id === id), 'a new asset is listed straight away');
});
