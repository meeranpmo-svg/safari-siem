// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// XDR: cross-domain correlation into incidents, explainable score, hubs, promotion to a case (playbook approvals),
// auto-case policy, hunts over the event search, beacon statistics, routes and roles.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const { createState } = require('../engine/soc/state');
const { createAlerts } = require('../engine/soc/alerts');
const { createCases } = require('../engine/soc/cases');
const xdrRoutes = require('../engine/xdr/routes');
const { correlate, domainOf, entitiesOf, isOperational } = require('../engine/xdr/xdr');
const { fakeApi, tmpDir, quietLog } = require('./soc-fakes');

const H = 3600e3, T0 = Date.now() - 6 * H;
let n = 0;
const A = (o) => Object.assign({ id: 'ALR-' + String(++n).padStart(7, '0'), rule_id: 'SENTRA-AUTH-001', rule_name: 'Brute force', severity: 3, mitre: [], group: {}, fields: {}, status: 'new', ts_first: T0, ts_last: T0 + 1000 }, o);

test('domains, operational exclusion and entity normalisation', () => {
  assert.equal(domainOf({ rule_id: 'SENTRA-EDR-001' }), 'endpoint');
  assert.equal(domainOf({ rule_id: 'SENTRA-M365-002' }), 'identity');
  assert.equal(domainOf({ rule_id: 'SENTRA-EXO-004' }), 'email');
  assert.equal(domainOf({ rule_id: 'SENTRA-FGT-003' }), 'network');
  assert.equal(domainOf({ rule_id: 'MANUAL', src_type: 'kaspersky' }), 'endpoint');
  assert.equal(domainOf({ rule_id: 'X', src_type: 'unknown-thing' }), 'other');
  assert.ok(isOperational({ rule_id: 'SENTRA-ORAP-003' }));
  assert.ok(isOperational({ rule_id: 'SENTRA-SCH-002', rule_name: 'Security-relevant log source went silent' }));
  assert.ok(!isOperational({ rule_id: 'SENTRA-SCH-001', rule_name: 'Organisation-wide spike in failed logons' }));
  const e = entitiesOf({ host: 'PC-17.corp.local', group: { user: 'CORP\\Alice' }, fields: { src_ip: '10.1.2.3', dst_ip: '203.0.113.5', target_user: 'bob@corp.local' } }, new Set(['corp.local']));
  assert.deepEqual(e.sort(), ['host:pc-17', 'ip:10.1.2.3', 'user:alice', 'user:bob', 'xip:203.0.113.5']);
  assert.ok(!entitiesOf({ group: { user: 'PC17$' } }, new Set()).length, 'machine accounts are not users');
  assert.deepEqual(entitiesOf({ rule_id: 'UEBA-IMPOSSIBLE_TRAVEL', group: { entity: 'user:alice', entity_type: 'user' }, fields: { entity_id: 'user:alice' } }, new Set()), ['user:alice'], 'UEBA alerts join on their entity');
  assert.ok(entitiesOf({ group: { user: 'bob@partner.com' } }, new Set(['corp.local'])).includes('user:bob@partner.com'), 'a UPN outside the internal domains stays whole - never reduced to a name');
});

test('correlate: same user across identity, endpoint and email in the window = one incident; scoring is itemised', () => {
  const list = [
    A({ rule_id: 'SENTRA-M365-001', rule_name: 'Risky sign-in', severity: 3, group: { user: 'alice@corp.local' }, fields: { src_ip: '198.51.100.7' }, ts_first: T0 }),
    A({ rule_id: 'SENTRA-EXO-001', rule_name: 'Forwarding rule', severity: 2, group: { user: 'CORP\\alice' }, ts_first: T0 + 2 * H }),
    A({ rule_id: 'SENTRA-EDR-001', rule_name: 'EDR detection', severity: 4, host: 'pc-17', group: { user: 'alice' }, ts_first: T0 + 3 * H }),
    A({ rule_id: 'SENTRA-FGT-003', rule_name: 'IPS', severity: 2, fields: { src_ip: '10.9.9.9' }, ts_first: T0 + H }),                 // unrelated
    A({ rule_id: 'SENTRA-AUTH-001', group: { user: 'alice' }, ts_first: T0 - 5 * 24 * H, ts_last: T0 - 5 * 24 * H }),             // too old
    A({ rule_id: 'SENTRA-ORAP-001', rule_name: 'Oracle CPU', group: { user: 'alice' } }),                                          // operational
    A({ rule_id: 'LR-1', source: 'logrhythm', group: { user: 'alice' } }),
  ];
  const cat = require('../engine/bas/attack-catalog.json');
  const { makeTactics } = require('../engine/xdr/xdr');
  const tac = makeTactics(cat, (id) => ({ 'SENTRA-M365-001': 'initial-access', 'SENTRA-EXO-001': 'collection', 'SENTRA-EDR-001': 'execution' })[id] || '');
  const r = correlate(list, { internalDomains: ['corp.local'], tactics: tac, riskOf: (k, v) => (v === 'alice' ? 'high' : '') });
  assert.deepEqual(r.excluded, { operational: 1, lr: 1, old: 1 });
  const big = r.incidents[0];
  assert.equal(big.alerts, 3);
  assert.deepEqual(Object.keys(big.domains).sort(), ['email', 'endpoint', 'identity']);
  assert.deepEqual(big.tactics, ['initial-access', 'execution', 'collection'], 'kill-chain order');
  assert.equal(big.score, Math.min(100, 4 * 15 + 20 + 10 + 10));
  assert.ok(big.why.some((w) => /crosses 3 domains/.test(w.reason)) && big.why.some((w) => /UEBA rates alice high/.test(w.reason)));
  assert.equal(big.why.reduce((s, w) => s + w.points, 0) >= big.score, true);
  assert.ok(big.linked_by.includes('user:alice'));
  assert.equal(r.incidents.length, 2);
  const again = correlate(list.slice().reverse(), { internalDomains: ['corp.local'], tactics: tac });
  assert.equal(again.incidents.find((i) => i.alerts === 3).id, big.id, 'incident id is stable whatever the order');
});

test('link window splits activity days apart; hubs do not merge everything', () => {
  const far = correlate([A({ group: { user: 'x' }, ts_first: T0 - 50 * H, ts_last: T0 - 50 * H }), A({ group: { user: 'x' }, ts_first: T0, ts_last: T0 })], { linkWindowH: 24 });
  assert.equal(far.incidents.length, 2);
  const hubList = [];
  for (let i = 0; i < 6; i++) hubList.push(A({ fields: { dst_ip: '10.0.0.10' }, group: { user: 'u' + i }, ts_first: T0 + i * 60000 }));
  const h = correlate(hubList, { hubMax: 5 });
  assert.equal(h.incidents.length, 6, 'the domain controller IP in every alert links nothing');
  assert.deepEqual(h.hubs, [{ entity: 'ip:10.0.0.10', alerts: 6 }]);
});

function setup(config) {
  const dir = tmpDir('sentra-xdr-');
  const state = createState({ dir, log: quietLog });
  const alerts = createAlerts({ state, log: quietLog });
  const cases = createCases({ state, alerts, log: quietLog });
  const api = fakeApi();
  const searched = [];
  const search = async (q) => { searched.push(q); return { rows: [{ ts: Date.now(), host: 'pc-17', cmdline: 'powershell -enc AAAA' }], total_estimate: 1, took_ms: 3 }; };
  const deps = { state, alerts, cases, config: config || {}, log: quietLog, search };
  xdrRoutes.register(api, deps);
  return { api, alerts, cases, deps, searched, done: () => { alerts.stop(); state.close(); fs.rmSync(dir, { recursive: true, force: true }); } };
}
const raise = (alerts, o) => alerts.raise(Object.assign({ rule_id: 'SENTRA-AUTH-001', rule_name: 'Brute force', severity: 3, mitre: ['T1110.001'], group: { user: 'alice' }, group_key: `k${Math.random()}`, count: 1, ts_first: T0, ts_last: T0 + 1000, sample_event_ids: [], summary: 'x' }, o)).alert;

test('routes: incidents list + detail with playbook recommendations, promote to case (approvals), roles, hunts', async () => {
  const s = setup();
  try {
    raise(s.alerts, { rule_id: 'SENTRA-AUTH-003', rule_name: 'Logon after failures', group: { user: 'alice', src_ip: '203.0.113.9' }, ts_first: T0 });
    raise(s.alerts, { rule_id: 'SENTRA-EDR-001', rule_name: 'EDR detection not remediated', severity: 4, mitre: ['T1059'], group: { host: 'pc-17', user: 'alice' }, ts_first: T0 + H });
    raise(s.alerts, { rule_id: 'SENTRA-FGT-001', rule_name: 'IPS', severity: 1, group: { src_ip: '10.5.5.5' }, ts_first: T0 });
    let r = await s.api.call('GET', '/api/soc/xdr/incidents');
    assert.equal(r.status, 200);
    assert.equal(r.body.total, 1, 'the lone low-severity IPS alert is not an incident in the default scope');
    assert.equal(r.body.summary.cross_domain, 1);
    const inc = r.body.items[0];
    assert.equal(inc.alerts, 2); assert.ok(inc.domains.identity && inc.domains.endpoint);
    r = await s.api.call('GET', '/api/soc/xdr/incidents?scope=all');
    assert.equal(r.body.total, 2);
    r = await s.api.call('GET', `/api/soc/xdr/incidents/${inc.id}`);
    assert.equal(r.body.timeline.length, 2);
    assert.ok(r.body.playbook && r.body.playbook.id, 'a playbook is suggested');
    assert.ok(Array.isArray(r.body.recommended));
    r = await s.api.call('POST', `/api/soc/xdr/incidents/${inc.id}/case`, { role: 'viewer' });
    assert.equal(r.status, 403);
    r = await s.api.call('POST', `/api/soc/xdr/incidents/${inc.id}/case`, { role: 'operator', user: 'ana' });
    assert.equal(r.status, 200); assert.equal(r.body.created, true); assert.equal(r.body.added, 2);
    const c = s.cases.get(r.body.case_id);
    assert.equal(c.alerts.length, 2); assert.match(c.title, /^\[XDR-/); assert.match(c.description, /score \d+/);
    raise(s.alerts, { rule_id: 'SENTRA-EXO-001', rule_name: 'Forwarding rule', severity: 2, group: { user: 'alice' }, ts_first: T0 + 2 * H });
    s.deps.xdr.invalidate();
    r = await s.api.call('POST', `/api/soc/xdr/incidents/${inc.id}/case`, { role: 'operator' });
    assert.deepEqual([r.body.created, r.body.added, r.body.case_id], [false, 1, c.id], 'a new alert joins the incident\'s existing case');
    assert.ok(s.api.audits.some((x) => x.action === 'xdr.case'));
    r = await s.api.call('GET', '/api/soc/xdr/hunts');
    assert.ok(r.body.items.length >= 8);
    r = await s.api.call('POST', '/api/soc/xdr/hunts/H-PS-ENC/run', { role: 'viewer' });
    assert.equal(r.status, 403);
    r = await s.api.call('POST', '/api/soc/xdr/hunts/H-PS-ENC/run', { role: 'operator', body: {} });
    assert.equal(r.body.total, 1); assert.match(s.searched[0].q, /-enc/);
    r = await s.api.call('POST', '/api/soc/xdr/hunts/H-NOPE/run', { role: 'operator', body: {} });
    assert.equal(r.status, 404);
    r = await s.api.call('GET', '/api/soc/xdr/coverage');
    assert.ok(r.body.domains.find((d) => d.domain === 'endpoint').alerts_72h >= 1);
    r = await s.api.call('GET', '/api/soc/xdr/beacons');
    assert.equal(r.body.available, false, 'no event store in this test - says so instead of "no beacons"');
  } finally { s.done(); }
});

test('hunt search queries parse in the engine search language', () => {
  const { parse } = require('../engine/api/query');
  for (const h of require('../engine/xdr/xdr').HUNTS) assert.doesNotThrow(() => parse(h.q), h.id);
});

test('auto-case policy: off by default; at the threshold opens a case once', () => {
  const off = setup();
  try {
    raise(off.alerts, { group: { user: 'bob' }, severity: 4 }); raise(off.alerts, { rule_id: 'SENTRA-EDR-001', group: { user: 'bob' }, severity: 4 });
    assert.equal(off.deps.xdr.autoTick().enabled, false);
  } finally { off.done(); }
  const s = setup({ xdr: { auto_case_score: 60 } });
  try {
    raise(s.alerts, { group: { user: 'bob' }, severity: 4 }); raise(s.alerts, { rule_id: 'SENTRA-EDR-001', group: { user: 'bob' }, severity: 4 });
    raise(s.alerts, { group: { user: 'carol' }, severity: 1 }); raise(s.alerts, { rule_id: 'SENTRA-AD-001', group: { user: 'carol' }, severity: 1 });
    const r = s.deps.xdr.autoTick();
    assert.equal(r.opened.length, 1, 'carol scores below 60');
    assert.equal(s.deps.xdr.autoTick().opened.length, 0, 'never twice');
    assert.equal(s.cases.list({ status: 'all' }).items[0].timeline[0].by, 'xdr:auto-case');
  } finally { s.done(); }
});

test('beacons: regular outbound intervals are flagged, jittery traffic and internal destinations are not', async () => {
  const { createXdr } = require('../engine/xdr/xdr');
  const t0 = 1700000000, reg = [], noisy = [];
  for (let i = 0; i < 40; i++) { reg.push(t0 + i * 60 + (i % 2)); noisy.push(t0 + Math.round(i * 60 + Math.sin(i) * 50)); }
  const ch = { database: 'siem', query: async (sql, params) => {
    assert.match(sql, /siem\.events/); assert.equal(params.h.value, 24);
    return [{ src_ip: '10.1.1.5', dst_ip: '185.1.2.3', dst_port: 443, n: 40, t: reg }, { src_ip: '10.1.1.6', dst_ip: '185.1.2.4', dst_port: 443, n: 40, t: noisy }, { src_ip: '10.1.1.7', dst_ip: '10.2.2.2', dst_port: 445, n: 40, t: reg }];
  } };
  const x = createXdr({ alerts: { all: () => [], get: () => null }, cases: {}, ch });
  const r = await x.beacons({});
  assert.equal(r.available, true);
  assert.deepEqual(r.items.map((i) => i.src_ip), ['10.1.1.5']);
  assert.equal(r.items[0].interval_s, 60);
});

test('operational: settings saved by an admin override config, validated and audited; status says what is missing', async () => {
  const s = setup({ xdr: { lookback_h: 48 } });
  try {
    let r = await s.api.call('GET', '/api/soc/xdr/status');
    assert.equal(r.status, 200);
    assert.equal(r.body.ready, false); assert.equal(r.body.operational, 'not-ready');
    const ck = Object.fromEntries(r.body.checks.map((c) => [c.id, c]));
    assert.equal(ck.alerts.ok, false); assert.match(ck.alerts.fix, /log sources/i);
    assert.equal(ck.domains.ok, false); assert.match(ck.domains.fix, /EDR/);
    assert.equal(ck.auto_case.ok, false);
    // one domain only: alerts present, still not ready
    raise(s.alerts, { group: { user: 'alice' }, severity: 3 });
    s.deps.xdr.invalidate();
    r = await s.api.call('GET', '/api/soc/xdr/status');
    assert.deepEqual([r.body.checks[0].ok, r.body.checks[1].ok, r.body.ready], [true, false, false]);
    raise(s.alerts, { rule_id: 'SENTRA-EDR-001', group: { user: 'alice', host: 'pc-1' }, severity: 4 });
    s.deps.xdr.invalidate();
    r = await s.api.call('GET', '/api/soc/xdr/status');
    assert.equal(r.body.ready, true); assert.equal(r.body.operational, 'partial', 'network and email still silent');

    // settings: viewer / operator refused, bad values refused, admin saves; config value kept where not overridden
    assert.equal((await s.api.call('PUT', '/api/soc/xdr/settings', { role: 'operator', body: { auto_case_score: 70 } })).status, 403);
    for (const b of [{ auto_case_score: 20 }, { auto_case_score: 101 }, { internal_domains: ['not a domain'] }, { link_window_h: 100, lookback_h: 24 }]) {
      assert.equal((await s.api.call('PUT', '/api/soc/xdr/settings', { role: 'admin', body: b })).status, 400, JSON.stringify(b));
    }
    r = await s.api.call('PUT', '/api/soc/xdr/settings', { role: 'admin', user: 'siva', body: { auto_case_score: 70, internal_domains: ('Corp.Local, corp.local; ' + 'corp-hq.com') } });
    assert.equal(r.status, 200);
    assert.deepEqual([r.body.settings.auto_case_score, r.body.settings.lookback_h, r.body.settings.internal_domains], [70, 48, ['corp.local', 'corp-hq.com']]);
    assert.ok(s.api.audits.some((a) => a.action === 'xdr.settings'));
    assert.equal(s.deps.xdr.settings().auto_case_score, 70);
    // the policy now runs: the alice incident (score >= 70) gets a case, and status reports it
    const t = s.deps.xdr.autoTick();
    assert.equal(t.enabled, true); assert.equal(t.opened.length, 1);
    r = await s.api.call('GET', '/api/soc/xdr/status');
    assert.deepEqual([r.body.auto_case.enabled, r.body.auto_case.last_tick.opened, r.body.auto_case.opened_since_start], [true, 1, 1]);
    // switching off with 0
    r = await s.api.call('PUT', '/api/soc/xdr/settings', { role: 'admin', body: { auto_case_score: 0 } });
    assert.equal(r.body.settings.auto_case_score, 0);
  } finally { s.done(); }
});
