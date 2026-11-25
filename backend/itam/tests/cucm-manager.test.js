// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Cisco Unified CM manager (engine/cucm-manager.js) against a SYNTHETIC CUCM (injected SOAP answers): phones with registration,
// SIP trunks / gateways, PerfMon call counters; the learned findings (learning first, then a device pool dropping against its
// own baseline, flapping, a trunk down, failed calls above their baseline); settings (admin, the AXL credential kind checked,
// a separate write login); restart / reset as four-eyes changes that run only with the write login; roles, audit; the phone list
// (it names people) for operators only.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');
const { parsePerf, assess } = require('../engine/cucm-manager');

const VIEW = { user: 'vera.syn', role: 'viewer' }, OP = { user: 'nora.syn', role: 'operator' }, ADM = { user: 'admin.syn', role: 'admin' }, ADM2 = { user: 'sec.syn', role: 'admin' }, BOT = { user: 'ai:voice', role: 'admin' };
const phone = (n, pool, st) => `<phone><name>${n}</name><description>Ext ${n.slice(-4)}</description><model>Cisco 8845</model><devicePoolName>${pool}</devicePoolName><protocol>SIP</protocol></phone>`;
function fakeCucm(state) {
  const calls = [];
  const req = async (url, o) => {
    const a = o.headers.SOAPAction, b = String(o.body || ''); calls.push({ url, a, auth: o.headers.Authorization });
    const user = Buffer.from(o.headers.Authorization.split(' ')[1], 'base64').toString().split(':')[0];
    if (/listPhone/.test(a)) return { status: 200, text: '<Envelope><Body><listPhoneResponse><return>' + state.phones.map((p) => phone(p.name, p.pool)).join('') + '</return></listPhoneResponse></Body></Envelope>' };
    if (/selectCmDevice/.test(a)) {
      const cls = (/<soap:DeviceClass>(\w+)</.exec(b) || [])[1];
      const list = cls === 'Phone' ? state.phones.map((p) => [p.name, p.reg ? 'Registered' : 'UnRegistered']) : cls === 'SIPTrunk' ? [['SIP-CARRIER-SYN', state.trunk]] : [['GW-SITE-SYN', 'Registered']];
      return { status: 200, text: '<Envelope><Body><selectCmDeviceResponse><selectCmDeviceReturn><SelectCmDeviceResult><CmNodes><item><CmDevices>' + list.map(([n, st]) => `<item><Name>${n}</Name><Status>${st}</Status><IPAddress><item><IP>10.30.0.9</IP></item></IPAddress></item>`).join('') + '</CmDevices></item></CmNodes></SelectCmDeviceResult></selectCmDeviceReturn></selectCmDeviceResponse></Body></Envelope>' };
    }
    if (/perfmonCollectCounterData/.test(a)) return { status: 200, text: `<Envelope><Body><perfmonCollectCounterDataResponse><ArrayOfCounterInfo><item><Name>\\\\cucm\\Cisco CallManager\\CallsActive</Name><Value>${state.active}</Value></item><item><Name>\\\\cucm\\Cisco CallManager\\CallsAttempted</Name><Value>${state.att}</Value></item><item><Name>\\\\cucm\\Cisco CallManager\\CallsCompleted</Name><Value>${state.comp}</Value></item></ArrayOfCounterInfo></perfmonCollectCounterDataResponse></Body></Envelope>` };
    if (/doDeviceReset/.test(a)) { if (user !== 'axl-rw') return { status: 403, text: '' }; state.resets.push((/<deviceName>([^<]+)</.exec(b) || [])[1]); return { status: 200, text: '<Envelope><Body><doDeviceResetResponse><return>ok</return></doDeviceResetResponse></Body></Envelope>' }; }
    return { status: 404, text: '' };
  };
  return { req, calls };
}

test('PerfMon parsing and the model on its own', () => {
  assert.deepEqual(parsePerf('<x><Name>\\\\h\\Cisco CallManager\\CallsActive</Name><Value>7</Value></x>'), { CallsActive: 7 });
  const r = assess({ phones: [{ name: 'SEP1', device_pool: 'P', status: 'Registered' }], trunks: [], calls: {} }, [], {}, Date.now());
  assert.equal(r.learning, true); assert.equal(r.findings.length, 0);
});

test('poll, learn, findings, settings, four-eyes changes, roles, audit', async (t) => {
  let clock = Date.parse('2026-11-25T08:00:00Z');
  const state = { phones: Array.from({ length: 20 }, (_, i) => ({ name: 'SEP0000000000' + String(10 + i), pool: i < 10 ? 'DP_HQ' : 'DP_SITE7', reg: true })), trunk: 'Registered', active: 4, att: 1000, comp: 990, resets: [] };
  const fk = fakeCucm(state);
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true, now: () => clock, python: process.env.PYTHON || 'python3', cucmRequest: fk.req });
  const call = (m, p, b, who) => e.req(m, p, Object.assign(b !== undefined ? { body: b } : {}, who));
  const audit = (a) => e.app.store.auditTail(1000).filter((x) => x.action === a);
  const mk = async (label, user) => (await call('POST', '/discovery/credentials', { kind: 'cucm_axl', label, target: { host: 'cucm.corp.example', port: 8443, axl_version: '12.5' }, secret: { username: user, password: 'Synthetic-Axl-1' } }, ADM)).json.credential.id;
  const ro = await mk('CUCM read-only', 'axl-ro'), rw = await mk('CUCM changes', 'axl-rw');
  assert.equal((await call('POST', '/cucm/poll', {}, OP)).status, 409, 'no login chosen yet');
  // settings: admin only; the credential kind is checked; a separate write login
  assert.equal((await call('PUT', '/cucm/settings', { credential_id: ro }, OP)).status, 403);
  const snmp = (await call('POST', '/discovery/credentials', { kind: 'snmp_v2c', label: 'x', secret: { community: 'synthetic-community' } }, ADM)).json.credential.id;
  let r = await call('PUT', '/cucm/settings', { credential_id: snmp }, ADM); assert.equal(r.status, 400); assert.match(r.json.error, /credential_id/);
  r = await call('PUT', '/cucm/settings', { credential_id: ro, write_credential_id: ro, write_enabled: true }, ADM); assert.equal(r.status, 400); assert.match(r.json.error, /separate/);
  assert.equal((await call('PUT', '/cucm/settings', { credential_id: ro, write_credential_id: rw, write_enabled: false }, ADM)).status, 200);
  // learning: 7 polls of a healthy estate
  for (let i = 0; i < 7; i++) { state.att += 100; state.comp += 99; assert.equal((await call('POST', '/cucm/poll', {}, OP)).status, 200); clock += 15 * 60000; }
  let v = (await call('GET', '/cucm', undefined, VIEW)).json;
  assert.equal(v.kpis.phones, 20); assert.equal(v.kpis.registered, 20); assert.equal(v.kpis.trunks, 2); assert.equal(v.learning, false); assert.equal(v.findings.length, 0, JSON.stringify(v.findings));
  assert.ok(!('phones' in v), 'viewers get the summary, not the phone list');
  assert.equal((await call('GET', '/cucm/phones', undefined, VIEW)).status, 403);
  assert.ok(fk.calls.every((c) => c.auth === 'Basic ' + Buffer.from('axl-ro:Synthetic-Axl-1').toString('base64')), 'reads use the read-only login');
  // trouble at site 7: 8 of 10 phones drop, the carrier trunk is down, failed calls jump; one phone flaps
  for (let i = 10; i < 18; i++) state.phones[i].reg = false;
  state.trunk = 'UnRegistered'; state.att += 100; state.comp += 40;
  await call('POST', '/cucm/poll', {}, OP); clock += 5 * 60000;
  for (let k = 0; k < 3; k++) { state.phones[0].reg = !state.phones[0].reg; state.att += 30; state.comp += 12; await call('POST', '/cucm/poll', {}, OP); clock += 5 * 60000; }
  v = (await call('GET', '/cucm', undefined, VIEW)).json;
  const codes = v.findings.map((f) => f.code);
  assert.ok(codes.includes('pool-drop') && codes.includes('trunk-down') && codes.includes('failed-calls') && codes.includes('flapping'), codes.join(','));
  assert.match(v.findings.find((f) => f.code === 'pool-drop').title, /DP_SITE7: 2 of 10 phones registered .* usually 100 %/);
  // changes: four-eyes, only known phones, run only with the write login switched on
  assert.equal((await call('POST', '/cucm/changes', { type: 'reset', phones: ['SEP000000000010'], reason: 'synthetic reason' }, VIEW)).status, 403);
  r = await call('POST', '/cucm/changes', { type: 'wipe', phones: ['SEP000000000010'], reason: 'synthetic reason' }, OP); assert.equal(r.status, 400);
  r = await call('POST', '/cucm/changes', { type: 'restart', phones: ['SEPDEADBEEF0000'], reason: 'synthetic reason' }, OP); assert.equal(r.status, 400); assert.match(r.json.error, /not in the last CUCM read/);
  r = await call('POST', '/cucm/changes', { type: 'restart', phones: ['SEP000000000020', 'SEP000000000021'], reason: 'phones stuck after the outage (synthetic)' }, ADM); assert.equal(r.status, 200, r.text); const id = r.json.id;
  assert.equal((await call('POST', `/cucm/changes/${id}/decide`, { decision: 'approved' }, ADM)).status, 403, 'the proposer does not approve');
  assert.equal((await call('POST', `/cucm/changes/${id}/decide`, { decision: 'approved' }, OP)).status, 403, 'an operator does not approve');
  r = await call('POST', `/cucm/changes/${id}/decide`, { decision: 'approved' }, BOT); assert.equal(r.status, 403); assert.match(r.json.error, /person/);
  assert.equal((await call('POST', `/cucm/changes/${id}/decide`, { decision: 'approved' }, ADM2)).status, 200);
  r = await call('POST', `/cucm/changes/${id}/run`, {}, OP); assert.equal(r.status, 409); assert.match(r.json.error, /switched off/);
  await call('PUT', '/cucm/settings', { write_enabled: true }, ADM);
  r = await call('POST', `/cucm/changes/${id}/run`, {}, OP); assert.equal(r.status, 200, r.text); assert.equal(r.json.status, 'done');
  assert.deepEqual(state.resets, ['SEP000000000020', 'SEP000000000021']);
  assert.ok(fk.calls.filter((c) => /doDeviceReset/.test(c.a)).every((c) => c.auth === 'Basic ' + Buffer.from('axl-rw:Synthetic-Axl-1').toString('base64')), 'changes use the write login only');
  for (const a of ['cucm.settings', 'cucm.change.propose', 'cucm.change.approve', 'cucm.change.run']) assert.ok(audit(a).length && audit(a).every((x) => x.by && x.role), 'audited: ' + a);
});
