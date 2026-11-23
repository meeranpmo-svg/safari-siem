// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Endpoint & Mobile Management (engine/mdm.js inventory) against the in-process fake ManageEngine MDM Plus (SYNTHETIC devices):
// the whole estate read (not only one leaver), counted by platform and ownership; stale when a device has not checked in for 14
// days or never; no compliance verdict is invented; cached between reads and refreshed on request by a person (audited); a
// failing MDM keeps the last good read and names the error; operators only (device names and e-mail addresses are personal data);
// no MDM connected says what to do.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');
const { fakeMdm, TOKEN } = require('./helpers/fake-mdm');

const ADM = { user: 'syed', role: 'admin' }, OP = { user: 'desk.syn', role: 'operator' }, VW = { user: 'vera.syn', role: 'viewer' };
async function setup(t, connect = true) {
  const clock = { t: Date.parse('2026-11-05T08:00:00Z') };
  const F = fakeMdm(); await new Promise((r) => F.srv.listen(0, '127.0.0.1', r)); t.after(() => F.srv.close());
  const day = (n) => String(clock.t - n * 86400000);
  F.st.devices['1001'].last_contact_time = day(1); F.st.devices['1002'].last_contact_time = day(2); F.st.devices['1003'].last_contact_time = day(30);   // 1004 never
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true, now: () => clock.t, python: process.env.PYTHON || 'python3' });
  const call = (m, p, b, who) => e.req(m, p, Object.assign(b !== undefined ? { body: b } : {}, who));
  if (connect) {
    assert.equal((await call('POST', '/offboarding/mdm', { provider: 'manageengine', base_url: 'https://mdm.corp.syn', api_token: TOKEN }, ADM)).status, 200);
    e.app.store.collection('mdm_cfg').put(Object.assign({}, e.app.store.collection('mdm_cfg').get('cfg'), { base_url: 'http://127.0.0.1:' + F.srv.address().port }));
  }
  return { e, F, clock, call };
}

test('the whole estate, by platform and ownership, stale devices, no compliance invented, operators only', async (t) => {
  const { call } = await setup(t);
  assert.equal((await call('GET', '/mdm/devices', undefined, VW)).status, 403, 'viewers do not see device owners (PDPL)');
  const r = await call('GET', '/mdm/devices', undefined, OP); assert.equal(r.status, 200);
  const v = r.json;
  assert.equal(v.configured, true); assert.equal(v.kpis.devices, 4, 'every device, not only one leaver');
  assert.equal(v.kpis.company, 3); assert.equal(v.kpis.personal, 1);
  assert.equal(v.kpis.stale, 2, '30 days and never'); assert.equal(v.kpis.never, 1);
  assert.equal(v.by_os.windows, 2); assert.equal(v.by_os.android, 1);
  assert.equal(v.devices[0].stale, true, 'stale first');
  assert.ok(v.devices.every((d) => d.compliance === null), 'no compliance verdict invented');
  assert.match(v.note, /not inferred/);
});

test('cached between reads, refreshed by a person (audited), the last good read kept when the MDM fails', async (t) => {
  const { e, F, clock, call } = await setup(t);
  await call('GET', '/mdm/devices', undefined, OP);
  const n0 = F.st.calls.filter((c) => c === 'GET /api/v1/mdm/devices').length;
  await call('GET', '/mdm/devices', undefined, OP); assert.equal(F.st.calls.filter((c) => c === 'GET /api/v1/mdm/devices').length, n0, 'cached: no second call within 15 minutes');
  assert.equal((await call('POST', '/mdm/devices/refresh', {}, { user: 'system:x', role: 'admin' })).status, 403, 'a service identity does not refresh');
  let r = await call('POST', '/mdm/devices/refresh', {}, OP); assert.equal(r.status, 200);
  assert.ok(F.st.calls.filter((c) => c === 'GET /api/v1/mdm/devices').length > n0, 'refresh reads the MDM');
  assert.ok(e.app.store.auditTail(50).some((a) => a.action === 'mdm.inventory.refresh' && a.by === 'desk.syn'));
  // the token stops working: the error is named, the last read stays
  e.app.store.collection('mdm_cfg').put(Object.assign({}, e.app.store.collection('mdm_cfg').get('cfg'), { base_url: 'http://127.0.0.1:1' }));
  clock.t += 16 * 60000;
  r = await call('GET', '/mdm/devices', undefined, OP); assert.equal(r.status, 200);
  assert.ok(r.json.error, 'error named: ' + r.json.error); assert.equal(r.json.kpis.devices, 4, 'the last good read is kept');
  assert.equal((await call('POST', '/mdm/devices/refresh', { x: 1 }, OP)).status, 200, 'undeclared fields dropped, not an error');
});

test('no MDM connected: says what to do, nothing invented', async (t) => {
  const { call } = await setup(t, false);
  const v = (await call('GET', '/mdm/devices', undefined, OP)).json;
  assert.equal(v.configured, false); assert.match(v.reason, /HR Offboarding/); assert.equal(v.kpis.devices, 0);
});
