// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// AI Security Engineer — Zscaler (ZIA+ZPA) and AI Endpoint Protection Engineer (Kaspersky KSC): the posture models,
// the KSC host normalisation, the module's rule-based findings (null = not connected), the duty adapters, and the
// four-eyes change plan. Pure/offline: no network, no filesystem (credentials are not set in these tests).
const test = require('node:test');
const assert = require('node:assert/strict');
const zia = require('../engine/zscaler/zia');
const zpa = require('../engine/zscaler/zpa');
const ksc = require('../engine/ksc/ksc');
const { createZscaler } = require('../engine/zscaler');
const { createKsc } = require('../engine/ksc');
const { zscalerAdapter, kscAdapter } = require('../engine/duty/sec-adapters');

function memStore() {
  const cols = {};
  return { collection(name) {
    if (!cols[name]) { const m = new Map(); cols[name] = {
      all: (f) => { const a = [...m.values()]; return f ? a.filter(f) : a; },
      get: (id) => m.get(id) || null, put: (o) => { m.set(o.id, o); return o; }, remove: (id) => { m.delete(id); },
      patch: (id, fn) => { const o = m.get(id); if (!o) return null; const n = fn(o); m.set(id, n); return n; } }; }
    return cols[name];
  } };
}

test('ZIA posture model flags only well-defined conditions', () => {
  const m = zia.model({
    status: { ok: true, data: { status: 'ACTIVE' } },
    locations: { ok: true, data: [{ id: 1, name: 'HQ', ofwEnabled: true, ipsControl: true }, { id: 2, name: 'Branch', ofwEnabled: false, ipsControl: true }] },
    fwRules: { ok: true, data: [{ id: 10, name: 'AllowWeb', action: 'ALLOW', enableLogging: false, state: 'ENABLED' }, { id: 11, name: 'Logged', action: 'ALLOW', enableLogging: true, state: 'ENABLED' }] },
    urlRules: { ok: true, data: [{ id: 20, name: 'OldRule', state: 'DISABLED' }] },
    admins: { ok: true, data: [{ id: 1 }] },
    advanced: { available: false },
  });
  assert.equal(m.counts.locations, 2); assert.equal(m.counts.fwRules, 2);
  assert.equal(m.fwNoLog.length, 1); assert.equal(m.fwNoLog[0].id, 10);
  assert.equal(m.locUnprotected.length, 1); assert.equal(m.locUnprotected[0].id, 2);
  assert.equal(m.urlDisabled.length, 1);
  assert.equal(m.availability.advanced, 'not-available');
  assert.equal(m.activation, 'ACTIVE');
});

test('ZIA key obfuscation is deterministic and uses the timestamp tail', () => {
  const k = zia.obfuscate('0123456789abcdef', 1700000000123);
  assert.equal(typeof k, 'string'); assert.ok(k.length > 0);
  assert.equal(k, zia.obfuscate('0123456789abcdef', 1700000000123));
});

test('ZPA posture model flags down connectors and disabled segments/rules', () => {
  const m = zpa.model({
    segments: { ok: true, data: [{ id: 1, name: 'App1', enabled: true }, { id: 2, name: 'App2', enabled: false }] },
    connectors: { ok: true, data: [{ id: 5, name: 'C1', controlChannelStatus: 'ZPN_STATUS_CONNECTED' }, { id: 6, name: 'C2', controlChannelStatus: 'ZPN_STATUS_DISCONNECTED' }] },
    access: { ok: true, data: [{ id: 9, name: 'R1', ruleState: 'ENABLED' }, { id: 10, name: 'R2', ruleState: 'DISABLED' }] },
  });
  assert.equal(m.connectorsDown.length, 1); assert.equal(m.connectorsDown[0].id, 6);
  assert.equal(m.disabledSegments.length, 1); assert.equal(m.disabledSegments[0].id, 2);
  assert.equal(m.disabledRules.length, 1); assert.equal(m.disabledRules[0].id, 10);
});

test('KSC normalises RTP state, status and IP; only a running RTP counts as protected', () => {
  const stopped = ksc.normHost({ KLHST_WKS_DN: 'PC1', KLHST_WKS_IP_LONG: { type: 'long', value: 3232235786 }, KLHST_WKS_RTP_STATE: 1, KLHST_WKS_STATUS_ID: 1, KLHST_WKS_VIRUS_COUNT: 0 });
  assert.equal(stopped.protection, false); assert.equal(stopped.rtpState, 'stopped'); assert.equal(stopped.status, 'critical'); assert.equal(stopped.ip, '192.168.1.10');
  const running = ksc.normHost({ KLHST_WKS_DN: 'PC2', KLHST_WKS_RTP_STATE: 4, KLHST_WKS_STATUS_ID: 0 });
  assert.equal(running.protection, true); assert.equal(running.rtpState, 'running'); assert.equal(running.status, 'ok');
  const unknown = ksc.normHost({ KLHST_WKS_DN: 'PC3' });
  assert.equal(unknown.protection, false); assert.equal(unknown.rtpState, 'not reported');
});

test('Zscaler module: not connected until a tenant exists; a configured tenant with no API read raises connectivity', () => {
  const Z = createZscaler({ state: memStore(), config: { _paths: {}, secrets: {} }, log: { info() {}, warn() {} } });
  assert.equal(Z.findings(), null, 'no tenant → not connected (never healthy)');
  Z.put({ id: 't1', label: 'TENANT1', zia: { enabled: true, cloud: 'zsapi.zscalertwo.net', username: 'admin' } }, 'tester');
  const f = Z.findings();
  assert.ok(Array.isArray(f)); assert.ok(f.some((x) => x.kind === 'zia-unreachable'), 'configured but unread → unreachable finding');
  // the duty adapter passes findings straight through; absent module = no engineer
  assert.deepEqual(zscalerAdapter(undefined), []);
  const ad = zscalerAdapter(Z)[0];
  assert.equal(ad.id, 'zscaler'); assert.equal(ad.findings().length, f.length);
});

test('Zscaler module: four-eyes change plan (propose → approve by another admin → applied)', () => {
  const Z = createZscaler({ state: memStore(), config: { _paths: {}, secrets: {} }, log: { info() {}, warn() {} } });
  Z.put({ id: 't1', label: 'TENANT1', zia: { enabled: true, cloud: 'zsapi.zscalertwo.net', username: 'admin' } }, 'tester');
  const it = Z.findings()[0]; const got = [];
  Z.propose(it, { onChange: (p) => got.push(p.id) });
  assert.equal(got.length, 1);
  const proposed = Z.changes.list({ status: 'proposed' }); assert.equal(proposed.length, 1);
  // the author (duty:zscaler) cannot approve its own request
  assert.throws(() => Z.changes.decide(got[0], 'approved', 'duty:zscaler'), /another administrator/i);
  const approved = Z.changes.decide(got[0], 'approved', 'syed'); assert.equal(approved.status, 'approved');
  const applied = Z.changes.markApplied(got[0], 'ali', 'done in the ZIA console'); assert.equal(applied.status, 'applied');
  assert.equal(Z.changeStatus(got[0]).status, 'applied');
});

test('KSC module: not connected until a server exists; configured-but-unread raises unreachable; adapter id', () => {
  const K = createKsc({ state: memStore(), config: { _paths: {}, secrets: {} }, log: { info() {}, warn() {} } });
  assert.equal(K.findings(), null);
  K.put({ id: 'k1', label: 'KSC-RUH', host: 'ksc.corp.local', user: 'reader' }, 'tester');
  const f = K.findings();
  assert.ok(f.some((x) => x.kind === 'ksc-unreachable'));
  assert.deepEqual(kscAdapter(undefined), []);
  assert.equal(kscAdapter(K)[0].id, 'ksc');
});
