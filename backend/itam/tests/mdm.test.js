// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// The MDM for the leaver device step (engine/mdm.js): settings admin-only and validated (https only, a fingerprint pin, the
// token sealed and never returned), ManageEngine read against a fake MDM Plus API (owner and platform mapped, matched by e-mail
// only), only numeric device ids and only the two actions, Intune refused until its Graph switch is on, the test audited.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');
const { fakeMdm, TOKEN } = require('./helpers/fake-mdm');

const ADM = { user: 'syed', role: 'admin' }, OP = { user: 'desk.syn', role: 'operator' }, VIEW = { user: 'vera.syn', role: 'viewer' };

test('settings, the ManageEngine adapter and its limits', async (t) => {
  const F = fakeMdm(); await new Promise((r) => F.srv.listen(0, '127.0.0.1', r)); t.after(() => F.srv.close());
  const base = 'http://127.0.0.1:' + F.srv.address().port;
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true, python: process.env.PYTHON || 'python3' });
  const post = (p, b, who) => e.req('POST', p, Object.assign({ body: b }, who)), get = (p, who) => e.req('GET', p, who);
  assert.equal((await get('/offboarding/mdm', VIEW)).status, 403);
  assert.equal((await get('/offboarding/mdm', OP)).json.provider, 'none');
  assert.equal((await post('/offboarding/mdm', { provider: 'manageengine' }, OP)).status, 403, 'admin only');
  let r = await post('/offboarding/mdm', { provider: 'manageengine' }, ADM); assert.equal(r.status, 400); assert.match(r.json.error, /needs base_url and api_token/);
  r = await post('/offboarding/mdm', { base_url: 'http://mdm.corp.syn' }, ADM); assert.match(r.json.error, /^base_url must be/);
  r = await post('/offboarding/mdm', { cert_pin: 'abc' }, ADM); assert.match(r.json.error, /^cert_pin must be/);
  r = await post('/offboarding/mdm', { provider: 'intune' }, ADM); assert.equal(r.status, 400); assert.match(r.json.error, /leavers' devices/);
  r = await post('/offboarding/mdm', { provider: 'manageengine', base_url: 'https://mdm.corp.syn:9383', api_token: TOKEN, cert_pin: 'AB:'.repeat(31) + 'AB' }, ADM); assert.equal(r.status, 200, JSON.stringify(r.json));
  assert.equal(r.json.api_token_set, true); assert.ok(!JSON.stringify(r.json).includes(TOKEN)); assert.ok(!JSON.stringify(e.app.store.collection('mdm_cfg').all()).includes(TOKEN), 'sealed');
  // point it at the fake (loopback http is allowed by httpc only for test fakes)
  e.app.store.collection('mdm_cfg').put(Object.assign({}, e.app.store.collection('mdm_cfg').get('cfg'), { base_url: base, cert_pin: '' }));
  r = await post('/offboarding/mdm/test', {}, ADM); assert.equal(r.status, 200); assert.equal(r.json.ok, true); assert.equal(r.json.devices, 4);
  assert.ok(F.st.auth.every((a) => a === TOKEN), 'the token as the Authorization header');
  const A = e.app.addons.offboarding.mdm.adapter();
  assert.equal(A.name, 'manageengine');
  const u = await A.userDevices('Khalid.Harbi@corp.syn');
  assert.deepEqual(u.devices.map((d) => [d.name, d.owner_type, d.os]), [['LAP-CLAIMS-07', 'company', 'windows'], ['Khalid Pixel', 'personal', 'android'], ['MBP-CLAIMS-02', 'company', 'macos']], 'matched by e-mail, mapped');
  await assert.rejects(A.deviceAction('../../admin', 'wipe'), /ManageEngine device id/);
  await assert.rejects(A.deviceAction('1001', 'lock'), /only wipe or retire/);
  await assert.rejects(A.deviceGet('x'), /ManageEngine device id/);
  const audits = e.app.store.auditTail(50).map((x) => x.action);
  assert.ok(audits.includes('offboarding.mdm.settings') && audits.includes('offboarding.mdm.test'));
  assert.ok(!JSON.stringify(e.app.store.auditTail(100)).includes(TOKEN));
});
