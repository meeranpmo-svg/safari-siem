// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Leaver devices (engine/offboarding.js + engine/mdm.js) against a fake ManageEngine MDM Plus and a fake Intune (Graph): after
// the disable each device the MDM reports for the leaver is proposed (company -> full wipe, personal / Mac -> retire), matched
// to the asset register by serial; an administrator who did not raise the request decides per device - a full wipe needs the
// serial typed, keep needs a reason, a personal device or a Mac can never be fully wiped, nothing at all while a legal hold is
// in place; the device is re-checked just before sending (reassigned = nothing sent), the action sent once and followed until
// the MDM reports it; a failed send is never resent automatically, only by an administrator; the same step works on Intune;
// audit. SYNTHETIC data only.
const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('http');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');
const { fakeMdm, TOKEN } = require('./helpers/fake-mdm');

const HR = { user: 'hana.syn', role: 'operator' }, MGR = { user: 'faisal.syn', role: 'operator' }, DESK = { user: 'desk.syn', role: 'operator' };
const ADM = { user: 'syed', role: 'admin' }, REQ_ADMIN = { user: 'hana.syn', role: 'admin' };
const LEAVER = { name: 'Khalid Al-Harbi', employee_id: 'E-20001', username: 'khalid.harbi', department: 'Claims', last_day: '2026-10-30', manager: 'faisal.syn', reason: 'resignation' };

async function setup(t, provider = 'manageengine') {
  const clock = { t: Date.parse('2026-10-28T08:00:00Z') };
  const F = fakeMdm(); await new Promise((r) => F.srv.listen(0, '127.0.0.1', r)); t.after(() => F.srv.close());
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  const G = fakeIntune(); await new Promise((r) => G.srv.listen(0, '127.0.0.1', r)); t.after(() => G.srv.close());
  const gb = 'http://127.0.0.1:' + G.srv.address().port;
  registerDuty(e.app.srv, e.app, { noTimer: true, now: () => clock.t, python: process.env.PYTHON || 'python3', graphLogin: gb, graphBase: gb + '/v1.0' });
  const call = (m, p, b, who) => e.req(m, p, Object.assign(b !== undefined ? { body: b } : {}, who));
  const post = (p, b, who) => call('POST', p, b, who), get = (p, who = DESK) => call('GET', p, undefined, who);
  assert.equal((await post('/onboarding/ad', { upn_suffix: 'corp.syn' }, ADM)).status, 200);
  if (provider === 'manageengine') {
    assert.equal((await post('/offboarding/mdm', { provider: 'manageengine', base_url: 'https://mdm.corp.syn', api_token: TOKEN }, ADM)).status, 200);
    e.app.store.collection('mdm_cfg').put(Object.assign({}, e.app.store.collection('mdm_cfg').get('cfg'), { base_url: 'http://127.0.0.1:' + F.srv.address().port }));
  } else {
    assert.equal((await post('/onboarding/m365', { tenant_id: '11111111-2222-3333-4444-555555555555', client_id: '66666666-7777-8888-9999-000000000000', client_secret: 'Synthetic-Graph-Secret-1', devices_enabled: true }, ADM)).status, 200);
    assert.equal((await post('/offboarding/mdm', { provider: 'intune' }, ADM)).status, 200);
  }
  e.app.store.collection('assets').put({ id: 'ast_1', asset_tag: 'AST-0107', name: 'Claims laptop 7', serial: 'SN-LAP-1', status: 'in_use', type: 'laptop', lifecycle: [] });
  async function leaver(extra = {}) {
    let x = await post('/offboarding', Object.assign({}, LEAVER, extra), HR); assert.equal(x.status, 200, JSON.stringify(x.json)); const rid = x.json.id;
    await post('/offboarding/' + rid + '/confirm', { decision: 'confirm' }, MGR);
    x = await post('/offboarding/' + rid + '/approve', { decision: 'approve' }, ADM); assert.equal(x.status, 200, JSON.stringify(x.json));
    x = await post('/offboarding/' + rid + '/disabled', { directory_ref: 'disabled in ADUC, CHG-9001' }, DESK); assert.equal(x.status, 200, JSON.stringify(x.json));
    return { id: rid, v: x.json };
  }
  const tick = async (k = 1) => { for (let i = 0; i < k; i++) { clock.t += 300000; await e.app.addons.offboarding.runDue(null); } };
  return { e, F, G, clock, post, get, leaver, tick };
}
function fakeIntune() {
  const id = '00000000-0000-4000-8000-0000000000aa';
  const st = { calls: [], bodies: [], dev: { id, deviceName: 'LAP-INTUNE-1', operatingSystem: 'Windows', serialNumber: 'SN-INT-1', managedDeviceOwnerType: 'company', userPrincipalName: 'khalid.harbi@corp.syn', deviceActionResults: [] } };
  const srv = http.createServer((req, res) => { let b = ''; req.on('data', (c) => { b += c; }); req.on('end', () => {
    const u = new URL(req.url, 'http://x'), J = (c, o) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(o === undefined ? '' : JSON.stringify(o)); };
    if (/oauth2\/v2\.0\/token$/.test(u.pathname)) return J(200, { access_token: 'tok' });
    const P = u.pathname.replace('/v1.0', ''); st.calls.push(req.method + ' ' + P); if (b) st.bodies.push(JSON.parse(b));
    if (/^\/users\/[^/]+$/.test(P)) return J(200, { id: 'uid-k' });
    if (P === '/users/uid-k/managedDevices') return J(200, { value: [st.dev] });
    if (P === '/deviceManagement/managedDevices/' + id) return J(200, st.dev);
    if (P === '/deviceManagement/managedDevices/' + id + '/wipe') { st.dev.deviceActionResults = [{ actionName: 'wipe', actionState: 'done' }]; return J(204); }
    J(404, { error: { code: 'x', message: P } });
  }); });
  return { st, srv, id };
}
const auditOf = (e, action) => e.app.store.auditTail(500).filter((x) => x.action === action);

test('ManageEngine: proposed per device, decided per device by a second person, sent once, followed to the end', async (t) => {
  const { e, F, post, get, leaver, tick } = await setup(t);
  const { id, v } = await leaver();
  const D = v.devices;
  assert.equal(D.status, 'proposed'); assert.equal(D.provider, 'manageengine');
  assert.deepEqual(D.devices.map((d) => [d.name, d.proposed, d.allowed.join('|')]), [['LAP-CLAIMS-07', 'wipe', 'wipe|retire|keep'], ['Khalid Pixel', 'retire', 'retire|keep'], ['MBP-CLAIMS-02', 'retire', 'retire|keep']], 'another person\'s device is not listed');
  assert.equal(D.devices[0].asset.tag, 'AST-0107', 'matched to the register by serial');
  assert.match(D.devices[2].note, /Mac: full wipe is done in Intune|unlock code/);
  assert.equal((await get('/offboarding')).json.devices.provider, 'manageengine');
  const ids = Object.fromEntries(D.devices.map((d) => [d.name, d.id]));
  const DEC = (decisions, who) => post('/offboarding/' + id + '/devices/decide', { decisions }, who);
  assert.equal((await DEC([{ device_id: ids['LAP-CLAIMS-07'], action: 'wipe', confirm: 'SN-LAP-1' }], DESK)).status, 403, 'administrators only');
  let r = await DEC([{ device_id: ids['LAP-CLAIMS-07'], action: 'wipe', confirm: 'SN-LAP-1' }], REQ_ADMIN); assert.equal(r.status, 403); assert.match(r.json.error, /four eyes/);
  r = await DEC([{ device_id: ids['LAP-CLAIMS-07'], action: 'wipe', confirm: 'SN-LAP-1' }], { user: 'khalid.harbi', role: 'admin' }); assert.equal(r.status, 403);
  r = await DEC([{ device_id: ids['Khalid Pixel'], action: 'wipe', confirm: 'PX-77' }], ADM); assert.equal(r.status, 400); assert.match(r.json.error, /cannot be wiped here - not a company device/);
  r = await DEC([{ device_id: ids['MBP-CLAIMS-02'], action: 'wipe', confirm: 'C02-MAC' }], ADM); assert.equal(r.status, 400, 'never a full wipe of a Mac');
  r = await DEC([{ device_id: ids['LAP-CLAIMS-07'], action: 'wipe' }], ADM); assert.match(r.json.error, /type the serial of LAP-CLAIMS-07/);
  r = await DEC([{ device_id: ids['LAP-CLAIMS-07'], action: 'wipe', confirm: 'SN-LAP-2' }], ADM); assert.equal(r.status, 400);
  r = await DEC([{ device_id: ids['MBP-CLAIMS-02'], action: 'keep' }], ADM); assert.match(r.json.error, /say why MBP-CLAIMS-02 is kept/);
  r = await DEC([{ device_id: '9999', action: 'retire' }], ADM); assert.match(r.json.error, /not one of this leaver's devices/);
  r = await DEC([{ device_id: ids['LAP-CLAIMS-07'], action: 'format' }], ADM); assert.match(r.json.error, /action must be one of/);
  // nothing while a legal hold is in place
  const rec = e.app.store.collection('offboarding').get(id); rec.legal = { status: 'held' }; e.app.store.collection('offboarding').put(rec);
  r = await DEC([{ device_id: ids['Khalid Pixel'], action: 'retire' }], ADM); assert.equal(r.status, 409); assert.match(r.json.error, /legal hold is held/);
  rec.legal = null; e.app.store.collection('offboarding').put(rec);
  assert.ok(!F.st.calls.some((c) => /actions\/(complete|corporate)_wipe/.test(c)), 'nothing sent so far');
  r = await DEC([{ device_id: ids['LAP-CLAIMS-07'], action: 'wipe', confirm: 'sn-lap-1 ' }, { device_id: ids['Khalid Pixel'], action: 'retire' }, { device_id: ids['MBP-CLAIMS-02'], action: 'keep', reason: 'returned to IT, re-imaged on the bench' }], ADM);
  assert.equal(r.status, 200, JSON.stringify(r.json));
  const st = Object.fromEntries(r.json.devices.devices.map((d) => [d.name, d.state]));
  assert.deepEqual(st, { 'LAP-CLAIMS-07': 'sent', 'Khalid Pixel': 'sent', 'MBP-CLAIMS-02': 'kept' });
  assert.deepEqual(F.st.calls.filter((c) => c.startsWith('POST')), ['POST /api/v1/mdm/devices/1001/actions/complete_wipe', 'POST /api/v1/mdm/devices/1002/actions/corporate_wipe']);
  assert.equal((await get('/offboarding')).json.counts.devices_pending, 2);
  await tick(2);
  const v2 = (await get('/offboarding/' + id)).json;
  assert.deepEqual(v2.devices.devices.map((d) => d.state), ['wiped', 'retired', 'kept']); assert.equal(v2.devices.status, 'done');
  assert.ok(v2.steps.find((s) => s.key === 'devices').done);
  assert.equal(F.st.calls.filter((c) => c.startsWith('POST')).length, 2, 'each action sent once');
  assert.equal(auditOf(e, 'offboarding.device.wipe_approved')[0].detail.serial, 'SN-LAP-1');
  assert.equal(auditOf(e, 'offboarding.device.wipe_sent')[0].detail.approved_by, 'syed');
  assert.equal(auditOf(e, 'offboarding.device.wiped').length, 1); assert.equal(auditOf(e, 'offboarding.devices.done').length, 1);
});

test('re-checked before sending; a failed send waits for an administrator; by hand', async (t) => {
  const { e, F, post, get, leaver, tick } = await setup(t);
  const { id, v } = await leaver();
  const ids = Object.fromEntries(v.devices.devices.map((d) => [d.name, d.id]));
  F.st.devices['1002'].user = { user_email: 'new.owner@corp.syn' };   // handed to someone else since the read
  F.st.fail = 1;                                                     // the MDM fails the first action
  let r = await post('/offboarding/' + id + '/devices/decide', { decisions: [{ device_id: ids['LAP-CLAIMS-07'], action: 'wipe', confirm: 'SN-LAP-1' }, { device_id: ids['Khalid Pixel'], action: 'retire' }] }, ADM);
  const st = Object.fromEntries(r.json.devices.devices.map((d) => [d.name, d]));
  assert.equal(st['LAP-CLAIMS-07'].state, 'error'); assert.match(st['LAP-CLAIMS-07'].error, /Internal error/);
  assert.equal(st['Khalid Pixel'].state, 'error'); assert.match(st['Khalid Pixel'].error, /now assigned to new\.owner@corp\.syn - nothing sent/);
  assert.equal(F.st.calls.filter((c) => c.endsWith('corporate_wipe')).length, 0, 'nothing sent to the reassigned device');
  assert.equal((await get('/offboarding')).json.counts.devices_failed, 2);
  await tick(3); assert.equal(F.st.calls.filter((c) => c.startsWith('POST')).length, 1, 'never resent automatically');
  F.st.devices['1002'].user = { user_email: 'khalid.harbi@corp.syn' };
  assert.equal((await post('/offboarding/' + id + '/devices/retry', {}, DESK)).status, 403);
  r = await post('/offboarding/' + id + '/devices/retry', {}, ADM); assert.equal(r.status, 200);
  assert.deepEqual(r.json.devices.devices.filter((d) => d.decision).map((d) => d.state), ['sent', 'sent']);
  r = await post('/offboarding/' + id + '/devices/manual', { device_id: ids['MBP-CLAIMS-02'], reference: 'x' }, DESK); assert.equal(r.status, 400);
  r = await post('/offboarding/' + id + '/devices/manual', { device_id: ids['MBP-CLAIMS-02'], reference: 'Erased in Intune with an unlock code, CHG-9600' }, DESK); assert.equal(r.json.devices.devices[2].state, 'manual');
  await tick(2); assert.equal((await get('/offboarding/' + id)).json.devices.status, 'done');
  assert.equal(auditOf(e, 'offboarding.device.manual').length, 1);
});

test('the same step on Intune (the later move is one setting)', async (t) => {
  const { G, post, get, leaver, tick } = await setup(t, 'intune');
  const { id, v } = await leaver();
  assert.equal(v.devices.provider, 'intune'); assert.deepEqual(v.devices.devices.map((d) => [d.name, d.proposed]), [['LAP-INTUNE-1', 'wipe']]);
  const r = await post('/offboarding/' + id + '/devices/decide', { decisions: [{ device_id: G.id, action: 'wipe', confirm: 'SN-INT-1' }] }, ADM); assert.equal(r.status, 200, JSON.stringify(r.json));
  assert.deepEqual(G.st.bodies.find((b) => 'keepUserData' in b), { keepEnrollmentData: false, keepUserData: false });
  await tick(); assert.equal((await get('/offboarding/' + id)).json.devices.status, 'done');
});
