// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// SIEM cutover, NewEvol vs ours (engine/soc/cutover.js): export rows checked (fields named, unknown columns dropped); sources matched
// by IP / name / short name, a missing source, a silent day, a low feed, a drift day found by the robust z against the source's own
// ratio; detections matched one-to-one on a shared entity within the window, recall on medium+, ours-only; rules mapped by technique
// or name; the five gates and the blockers; routes: analyst read (viewer refused), admin import (operator refused), validation, the
// four-eyes switch (proposer cannot decide, a service identity cannot, an open gate needs a written risk), audit records. SYNTHETIC.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs'), os = require('node:os'), path = require('node:path');
const C = require('../engine/soc/cutover');
const { createState } = require('../engine/soc/state');
const { fakeApi } = require('./soc-fakes');

const DAY = 864e5, NOW = Date.parse('2026-11-26T09:00:00Z');
const day = (k) => new Date(NOW - k * DAY + 3 * 36e5).toISOString().slice(0, 10);

function world(o = {}) {
  const neSrc = [], vol = [];
  for (let k = 0; k < 15; k++) {
    neSrc.push({ source: 'FW-RUH-01', ip: '10.1.0.1', type: 'FortiGate', day: day(k), events: 100000 }); vol.push({ d: day(k), host: 'fw-ruh-01.safari.example', ip: '10.1.0.1', src_type: 'fortigate', n: k === 3 && o.drift ? 60000 : 98000 + (k % 3) * 1000 });
    neSrc.push({ source: 'DC01', ip: '', type: 'Windows', day: day(k), events: 50000 }); vol.push({ d: day(k), host: 'dc01.safari.example', ip: '10.1.0.10', src_type: 'windows', n: k === 2 ? 0 : 50500 });
    neSrc.push({ source: 'SW-JED-CORE', ip: '10.2.0.2', type: 'H3C', day: day(k), events: 2000 }); vol.push({ d: day(k), host: 'sw-jed-core', ip: '10.2.0.2', src_type: 'h3c', n: 900 });
    if (!o.noMissing) neSrc.push({ source: 'OLD-PROXY', ip: '10.9.9.9', type: 'Squid', day: day(k), events: 3000 });
    vol.push({ d: day(k), host: 'm365', ip: '', src_type: 'm365', n: 7000 });
  }
  const t = (h) => new Date(NOW - h * 36e5).toISOString();
  const neAlerts = C.cleanRows('alerts', [
    { id: 'n1', time: t(5), rule: 'Brute force on domain controller', severity: 'high', host: 'DC01', user: 'syn.lina', technique: 'T1110' },
    { id: 'n2', time: t(30), rule: 'Port scan from internet', severity: 'medium', ip: '203.0.113.9' },
    { id: 'n3', time: t(40), rule: 'Proxy policy bypass', severity: 'high', host: 'OLD-PROXY' },
    { id: 'n4', time: t(50), rule: 'Info heartbeat', severity: 'low', host: 'x' },
  ]).rows;
  const ourAlerts = [{ id: 'ALR-1', ts: NOW - 5 * 36e5 + 6e5, rule: 'Password spraying / brute force', host: 'dc01.safari.example', user: 'syn.lina' },
    { id: 'ALR-2', ts: NOW - 30 * 36e5 - 3e5, rule: 'Inbound scan', ip: '203.0.113.9' }, { id: 'ALR-3', ts: NOW - 10 * 36e5, rule: 'UEBA unusual logon', user: 'syn.omar' }];
  const neRules = C.cleanRows('rules', [{ name: 'Brute force on domain controller', technique: 'T1110', severity: 'high' }, { name: 'Port scan detection', severity: 'medium' }, { name: 'Proxy policy bypass', severity: 'high', technique: 'T1090' }, { name: 'Old disabled', enabled: 'false' }]).rows;
  const ourRules = [{ id: 'r1', name: 'Password spraying / brute force', mitre: ['T1110.003'] }, { id: 'r2', name: 'Inbound port scan detection', mitre: ['T1046'] }];
  return { ne: { sources: C.cleanRows('sources', neSrc).rows, alerts: neAlerts, rules: neRules }, ours: { volumes: vol, alerts: ourAlerts, rules: ourRules } };
}

test('rows: fields checked and named, unknown columns dropped, a bad file refused', () => {
  const r = C.cleanRows('sources', [{ 'Log Source': 'FW', Date: '2026-11-01', 'Event Count': '12', secret: 'x' }]);
  assert.deepEqual(r.rows[0], { source: 'FW', ip: '', type: '', day: '2026-11-01', events: 12 });
  assert.throws(() => C.cleanRows('alarms', [{}]), /kind must be one of/);
  assert.throws(() => C.cleanRows('sources', Array.from({ length: 20 }, () => ({ source: 'x', day: 'yesterday', events: 1 }))), /day must be YYYY-MM-DD/);
  assert.equal(C.cleanRows('rules', [{ name: 'a', enabled: 'no' }]).rows[0].enabled, false);
});

test('compare: sources, parity, silent day, drift by robust z, detections, rules, gates and blockers', () => {
  const w = world({ drift: true }), r = C.compare(Object.assign(w, { now: NOW, days: 14 }));
  const S = Object.fromEntries(r.sources.map((s) => [s.source, s]));
  assert.equal(S['OLD-PROXY'].status, 'missing'); assert.equal(S['DC01'].status, 'gaps', 'matched by short name, one silent day'); assert.equal(S['SW-JED-CORE'].status, 'low');
  assert.equal(S['FW-RUH-01'].status, 'drift', 'matched by IP; the 60% day stands out against its own ~99%'); assert.equal(S['FW-RUH-01'].drift[0].day, day(3));
  assert.equal(r.extra[0].source, 'm365');
  const D = Object.fromEntries(r.detections.map((d) => [d.id, d]));
  assert.equal(D.n1.ours.id, 'ALR-1'); assert.equal(D.n2.ours.id, 'ALR-2'); assert.equal(D.n3.matched, false);
  assert.equal(r.kpis.ours_only_alerts, 1); assert.equal(r.gates.find((g) => g.id === 'recall').value, 66.7);
  const R = Object.fromEntries(r.rules.map((x) => [x.name, x]));
  assert.equal(R['Brute force on domain controller'].ours.by, 'ATT&CK technique'); assert.equal(R['Port scan detection'].ours.id, 'r2'); assert.equal(R['Proxy policy bypass'].mapped, false); assert.ok(!R['Old disabled']);
  assert.equal(r.ready, false); assert.ok(r.blockers.some((b) => /Source not in our SIEM: OLD-PROXY/.test(b.what)) && r.blockers.some((b) => /Proxy policy bypass/.test(b.what)));
  assert.ok(r.score > 0 && r.score < 100); assert.ok(r.insights[0].startsWith('Readiness'));
  assert.equal(r.series.length, 15);
});

test('compare: everything matched is ready', () => {
  const w = world({ noMissing: true }); w.ours.volumes = w.ours.volumes.map((v) => Object.assign({}, v, { n: v.host === 'm365' ? 7000 : v.host.startsWith('fw') ? 100000 : v.host.startsWith('dc') ? 50000 : 2000 }));
  w.ne.alerts = w.ne.alerts.filter((a) => a.id !== 'n3'); w.ne.rules = w.ne.rules.filter((x) => x.name !== 'Proxy policy bypass');
  const r = C.compare(Object.assign(w, { now: NOW, days: 14 }));
  assert.equal(r.ready, true, JSON.stringify(r.gates)); assert.equal(r.score, 100); assert.match(r.insights[0], /Every gate passes/);
});

test('routes: roles, validation, import, four-eyes switch, audit', async () => {
  const state = createState({ dir: fs.mkdtempSync(path.join(os.tmpdir(), 'cut-')) }), w = world();
  const cut = C.createCutover({ state, alerts: { all: () => w.ours.alerts.map((a) => ({ id: a.id, ts_first: a.ts, rule_name: a.rule, host: a.host, group: { user: a.user, src_ip: a.ip } })) }, rules: () => w.ours.rules, volumes: async () => w.ours.volumes, now: () => NOW });
  const api = fakeApi({ realRanks: true }); C.register(api, { state, cutover: cut, now: () => NOW });
  let r = await api.call('GET', '/api/soc/cutover', { role: 'viewer' }); assert.equal(r.status, 403);
  r = await api.call('GET', '/api/soc/cutover?days=90', { role: 'analyst' }); assert.equal(r.status, 400); assert.match(r.body.error, /days must be/);
  r = await api.call('POST', '/api/soc/cutover/import', { role: 'operator', body: { kind: 'sources', rows: [] } }); assert.equal(r.status, 403);
  r = await api.call('POST', '/api/soc/cutover/import', { role: 'admin', body: { kind: 'logs', rows: [{}] } }); assert.equal(r.status, 400); assert.match(r.body.error, /kind/);
  r = await api.call('POST', '/api/soc/cutover/import', { role: 'admin', body: { kind: 'sources' } }); assert.equal(r.status, 400); assert.match(r.body.error, /rows is required/);
  for (const k of C.KINDS) { r = await api.call('POST', '/api/soc/cutover/import', { role: 'admin', user: 'syn.admin', body: { kind: k, rows: w.ne[k].map((x) => k === 'alerts' ? Object.assign({}, x, { time: new Date(x.ts).toISOString(), technique: x.technique }) : x), file: k + '.csv' } }); assert.equal(r.status, 200, JSON.stringify(r.body)); }
  assert.ok(api.audits.some((a) => a.action === 'cutover.import' && a.user === 'syn.admin'));
  r = await api.call('GET', '/api/soc/cutover?days=14', { role: 'analyst', user: 'syn.soc' }); assert.equal(r.status, 200); assert.equal(r.body.kpis.missing, 1); assert.equal(r.body.imported.sources.file, 'sources.csv');
  assert.ok(api.audits.some((a) => a.action === 'cutover.read' && a.user === 'syn.soc'));
  r = await api.call('POST', '/api/soc/cutover/signoff', { role: 'admin', user: 'syn.admin', body: { note: 'switch over on Thursday night' } }); assert.equal(r.status, 400); assert.match(r.body.error, /accept_risk/);
  r = await api.call('POST', '/api/soc/cutover/signoff', { role: 'admin', user: 'syn.admin', body: { note: 'switch over on Thursday night', accept_risk: 'OLD-PROXY is retired on the same night; proxy rule rebuilt in week 1' } }); assert.equal(r.status, 200); const id = r.body.id;
  r = await api.call('POST', '/api/soc/cutover/signoff', { role: 'admin', user: 'syn.admin', body: { note: 'second proposal here' } }); assert.equal(r.status, 409);
  r = await api.call('POST', '/api/soc/cutover/signoff/' + id + '/decide', { role: 'admin', user: 'syn.admin', body: { decision: 'approve', note: 'ok by me' } }); assert.equal(r.status, 403); assert.match(r.body.error, /four-eyes/);
  r = await api.call('POST', '/api/soc/cutover/signoff/' + id + '/decide', { role: 'admin', user: 'svc-siem', body: { decision: 'approve', note: 'auto ok' } }); assert.equal(r.status, 403); assert.match(r.body.error, /named person/);
  r = await api.call('POST', '/api/soc/cutover/signoff/' + id + '/decide', { role: 'operator', user: 'syn.ops', body: { decision: 'approve', note: 'ok' } }); assert.equal(r.status, 403);
  r = await api.call('POST', '/api/soc/cutover/signoff/' + id + '/decide', { role: 'admin', user: 'syn.ciso', body: { decision: 'maybe', note: 'hmm hmm' } }); assert.equal(r.status, 400);
  r = await api.call('POST', '/api/soc/cutover/signoff/' + id + '/decide', { role: 'admin', user: 'syn.ciso', body: { decision: 'approve', note: 'approved with the risk noted' } }); assert.equal(r.status, 200); assert.equal(r.body.status, 'approved'); assert.equal(r.body.decided_by, 'syn.ciso');
  assert.ok(api.audits.some((a) => a.action === 'cutover.approve' && a.user === 'syn.ciso'));
  r = await api.call('GET', '/api/soc/cutover/signoff', { role: 'viewer' }); assert.equal(r.status, 200); assert.equal(r.body.items[0].status, 'approved');
  r = await api.call('DELETE', '/api/soc/cutover/import/rules', { role: 'admin', user: 'syn.admin' }); assert.equal(r.status, 200); assert.equal(r.body.removed, true);
  r = await api.call('DELETE', '/api/soc/cutover/import/bogus', { role: 'admin' }); assert.equal(r.status, 400);
});
