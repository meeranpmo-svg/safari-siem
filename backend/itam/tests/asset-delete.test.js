// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Admin delete of inventory assets (engine/asset-delete.js): admin only; a reason is required; relationships go with the
// asset; discovery results go back to review or are ignored by MAC; the SIEM source is stopped first and a SIEM failure
// refuses the delete unless forced; the audit entry keeps who / why / a snapshot; bulk is capped and reports per asset.
// Names are SYNTHETIC.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { registerAssetDelete } = require('../engine/asset-delete');

const ADM = { user: 'syed', role: 'admin', ip: '10.0.0.5' };

test('asset delete: roles, reason, relationships, discovery, SIEM, audit, bulk', async (t) => {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  const A = e.app.assets, S = e.app.store;
  const a1 = A.create({ name: 'OLD-SRV-01', type: 'server', status: 'in_use', mgmt_ip: '10.9.0.11', serial: 'SN-SYN-1' }, ADM).asset.id;
  const a2 = A.create({ name: 'OLD-SRV-02', type: 'server', status: 'in_use', mgmt_ip: '10.9.0.12' }, ADM).asset.id;
  const a3 = A.create({ name: 'OLD-SRV-03', type: 'server', status: 'in_use' }, ADM).asset.id;
  S.collection('relationships').put({ id: 'rel_s1', from: a1, to: a2, type: 'depends_on' });
  S.collection('disc_devices').put({ id: 'dev_s1', asset_id: a1, ip: '10.9.0.11', macs: ['00:11:22:33:44:55'], status: 'approved' });
  registerAssetDelete(e.app.srv, e.app);

  // authorization
  assert.equal((await e.req('POST', `/assets/${a1}/delete`, { role: 'operator', body: { reason: 'decommissioned' } })).status, 403, 'operators cannot delete');
  assert.ok(A.get ? A.get(a1) : S.collection('assets').get(a1), 'nothing deleted by a refused call');
  // validation
  const nr = await e.req('POST', `/assets/${a1}/delete`, { role: 'admin', user: 'syed', body: {} });
  assert.equal(nr.status, 400); assert.match(nr.json.error, /reason is required/);
  assert.equal((await e.req('POST', '/assets/ast_missing/delete', { role: 'admin', user: 'syed', body: { reason: 'decommissioned' } })).status, 404);

  // the SIEM source cannot be stopped: refused unless forced
  S.collection('assets').patch(a1, (x) => { x.siem = { source_id: 'src_s1' }; return x; });
  e.app.membership = { stop: async () => { throw new Error('SIEM unreachable'); }, invalidate() {} };
  const r409 = await e.req('POST', `/assets/${a1}/delete`, { role: 'admin', user: 'syed', body: { reason: 'decommissioned' } });
  assert.equal(r409.status, 409); assert.equal(r409.json.code, 'siem_stop_failed');
  assert.ok(S.collection('assets').get(a1), 'refused delete leaves the asset');
  const ok = await e.req('POST', `/assets/${a1}/delete`, { role: 'admin', user: 'syed', body: { reason: 'decommissioned in Q3', discovery: 'ignore', force: true } });
  assert.equal(ok.status, 200); assert.equal(ok.json.siem.stopped, false);
  assert.equal(S.collection('assets').get(a1), null, 'deleted');
  assert.equal(S.collection('relationships').get('rel_s1'), null, 'its relationships go with it');
  assert.equal(S.collection('disc_devices').get('dev_s1').status, 'ignored', 'discovery keeps the device out');
  assert.ok(S.collection('disc_ignores').get('mac:001122334455'), 'ignored by MAC');

  // audit: who, why, what
  const au = S.auditTail(50, (x) => x.action === 'asset.delete')[0];
  assert.equal(au.by, 'syed'); assert.equal(au.detail.reason, 'decommissioned in Q3'); assert.equal(au.detail.deleted.name, 'OLD-SRV-01');

  // bulk: per-asset results, cap, reason
  e.app.membership = null;
  assert.equal((await e.req('POST', '/bulk/assets/delete', { role: 'admin', user: 'syed', body: { ids: [a2], reason: '' } })).status, 400);
  assert.equal((await e.req('POST', '/bulk/assets/delete', { role: 'admin', user: 'syed', body: { ids: Array.from({ length: 501 }, (_, i) => 'x' + i), reason: 'too many' } })).status, 400);
  const b = await e.req('POST', '/bulk/assets/delete', { role: 'admin', user: 'syed', body: { ids: [a2, a3, 'ast_missing'], reason: 'room cleared' } });
  assert.equal(b.json.ok, 2); assert.equal(b.json.failed, 1); assert.equal(b.json.results.find((x) => x.asset_id === 'ast_missing').ok, false);
  assert.ok(S.auditTail(50, (x) => x.action === 'asset.bulk-delete').length === 1);
});
