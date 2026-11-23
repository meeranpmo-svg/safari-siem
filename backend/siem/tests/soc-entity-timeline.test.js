// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Threat Hunting - entity timeline (engine/soc/entity-timeline.js via investigate-routes.js): one user / host / IP across events,
// alerts (exact, host with its domain dropped, never a similar name), the cases those alerts belong to, the UEBA profile and its
// findings, threat-intel lists, the network device and the changes carried out on it - newest first; a missing or failing source is
// named and the rest still answer; the query is built for the kind of entity; analyst and above, validated, audited. SYNTHETIC data.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const { createState } = require('../engine/soc/state');
const { createAlerts } = require('../engine/soc/alerts');
const { createCases } = require('../engine/soc/cases');
const routes = require('../engine/soc/investigate-routes');
const ET = require('../engine/soc/entity-timeline');
const { fakeApi, tmpDir, quietLog } = require('./soc-fakes');

const H = 3600e3, NOW = Date.now();
function world(extra = {}) {
  const dir = tmpDir(), state = createState({ dir, log: quietLog });
  const alerts = createAlerts({ state, log: quietLog }), cases = createCases({ state, alerts, log: quietLog });
  const queries = [];
  const search = {
    parse() {},
    search: async (o) => { queries.push(o.q); return { rows: [{ id: 'ev-1', ts: new Date(NOW - H).toISOString(), user: 'dave.syn', host: 'pc-9', src_type: 'windows', action: 'logon-failed', outcome: 'failure', severity: 2, message: 'synthetic failed logon' }, { id: 'ev-2', ts: new Date(NOW - 3 * H).toISOString(), user: 'dave.syn', host: 'pc-9', src_type: 'windows', action: 'logon', outcome: 'success', severity: 0, message: 'synthetic logon' }] }; },
    histogram: async () => ({ buckets: [{ t: NOW - 2 * H, n: 5 }, { t: NOW - H, n: 7 }], step_ms: H }),
    top: async () => ({ values: [{ v: 'windows', n: 12 }] }),
  };
  const ueba = { entities: (q) => ({ items: [{ id: 'u:dave.syn', name: 'dave.syn', type: 'user', peer_group: 'finance' }, { id: 'u:dave.synx', name: 'dave.synx', type: 'user' }].filter((e) => e.name.includes(q.q)) }),
    entity: (id) => (id === 'u:dave.syn' ? { risk: { score: 72, tier: 'high' }, findings: [{ id: 'F-1', detector: 'impossible_travel', severity: 3, explanation: 'synthetic sign-ins from two countries', ts_last: NOW - 2 * H, status: 'open' }] } : null) };
  const intel = { lookup: (v) => (v === '198.51.100.9' ? [{ list: 'synthetic-c2', type: 'ip', description: 'synthetic C2' }] : []) };
  const inv = [{ id: 'core-syn', name: 'CORE-SYN', ip: '10.0.0.2', role: 'core', site: 'Riyadh HQ' }];
  const netopsInstance = { inventory: { list: () => inv }, poller: { snapshot: () => ({ ok: true, sources: ['ping'], reach: { sent: 3, received: 3 } }) },
    changelog: { view: () => ({ changes: [{ id: 'NCHG-000001', at: NOW - 4 * H, target: 'CORE-SYN', ip: '10.0.0.2', what: 'Raise OSPF cost', risk: 'high', source: 'network', by: 'nora.syn', soc: { alerts: 1 } }] }) } };
  const deps = Object.assign({ state, alerts, cases, search, ueba, intel, netopsInstance, config: { soc_analyst: {} }, log: quietLog }, extra);
  const api = fakeApi({ realRanks: true }); routes.register(api, deps);
  const raise = (o) => alerts.raise(Object.assign({ rule_id: 'R-' + Math.random(), rule_name: 'Synthetic rule', severity: 2, group: {}, fields: {}, summary: 'synthetic', ts_first: NOW - 2 * H, ts_last: NOW - H, source: 'engine', count: 1 }, o)).alert;
  return { api, alerts, cases, raise, queries, deps, cleanup: () => fs.rmSync(dir, { recursive: true, force: true }) };
}

test('a user: events, alerts and their case, UEBA risk and findings, newest first; similar names never joined', async () => {
  const w = world(); try {
    const a1 = w.raise({ rule_name: 'Brute force then success', severity: 3, group: { user: 'dave.syn' }, ts_first: NOW - 0.5 * H, ts_last: NOW - 0.5 * H });
    w.raise({ rule_name: 'Other person', group: { user: 'dave.synx' } });
    const c = w.cases.create({ title: 'Synthetic account compromise', alert_ids: [a1.id] }, 'nora.syn');
    const r = await w.api.call('POST', '/api/soc/soc/hunt/entity', { role: 'analyst', body: { entity: 'dave.syn', hours: 24 } }); assert.equal(r.status, 200, JSON.stringify(r.body));
    const T = r.body;
    assert.equal(T.kind, 'name'); assert.match(T.query, /user:"dave\.syn" OR target_user:"dave\.syn" OR host:"dave\.syn"/);
    assert.deepEqual(T.counts, { event: 2, alert: 1, case: 1, ueba: 1 });
    assert.equal(T.items[0].source, 'case', 'newest first: the case was opened after the alert'); const al = T.items.find((x) => x.source === 'alert'); assert.equal(al.ref, a1.id); assert.equal(al.case_id, c.id);
    assert.ok(T.items.every((x, i, A) => !i || A[i - 1].t >= x.t));
    assert.ok(!T.items.some((x) => x.title === 'Other person'), 'dave.synx is someone else');
    assert.deepEqual([T.ueba.risk, T.ueba.tier, T.ueba.peer_group], [72, 'high', 'finance']);
    assert.equal(T.events.total, 12); assert.equal(T.events.top_sources[0].v, 'windows');
    assert.equal(T.sources.intel, 'not on any list', 'a name is checked against the lists too');
    assert.equal(T.worst, 'high');
  } finally { w.cleanup(); }
});

test('an IP: ip: query, intel lists, alerts by grouping value; a network device: state and changes', async () => {
  const w = world(); try {
    w.raise({ rule_name: 'Beacon to C2', severity: 4, group: { src_ip: '198.51.100.9' } });
    let T = (await w.api.call('POST', '/api/soc/soc/hunt/entity', { role: 'analyst', body: { entity: '198.51.100.9' } })).body;
    assert.equal(T.kind, 'ip'); assert.equal(T.query, 'ip:198.51.100.9'); assert.equal(T.intel[0].list, 'synthetic-c2'); assert.equal(T.sources.intel, 'on 1 list(s)');
    assert.equal(T.counts.alert, 1); assert.equal(T.worst, 'critical'); assert.equal(T.sources.network, 'not a network device');
    w.raise({ rule_name: 'Interface flaps', host: 'core-syn.as.local', group: {} });
    T = (await w.api.call('POST', '/api/soc/soc/hunt/entity', { role: 'analyst', body: { entity: 'CORE-SYN' } })).body;
    assert.deepEqual(T.device, { id: 'core-syn', name: 'CORE-SYN', ip: '10.0.0.2', role: 'core', site: 'Riyadh HQ', state: 'up' });
    assert.ok(T.items.some((x) => x.source === 'change' && x.ref === 'NCHG-000001' && /1 alert\(s\) after/.test(x.detail)));
    assert.ok(T.items.some((x) => x.source === 'alert' && x.title === 'Interface flaps'), 'host with its domain dropped');
    assert.match(T.query, /OR host:CORE-SYN\.\*/, 'a bare host name also matches its FQDN');
  } finally { w.cleanup(); }
});

test('a failing or missing source is named; the others still answer', async () => {
  const w = world({ ueba: null, intel: null, search: { parse() {}, search: async () => { throw new Error('ClickHouse unreachable (synthetic)'); }, histogram: async () => ({ buckets: [] }), top: async () => ({ values: [] }) } }); try {
    w.raise({ rule_name: 'Still here', group: { user: 'dave.syn' } });
    const T = (await w.api.call('POST', '/api/soc/soc/hunt/entity', { role: 'analyst', body: { entity: 'dave.syn' } })).body;
    assert.match(T.sources.events, /failed: ClickHouse unreachable/); assert.equal(T.sources.ueba, 'not available'); assert.equal(T.sources.intel, 'not available');
    assert.equal(T.counts.alert, 1, 'alerts still answer');
  } finally { w.cleanup(); }
});

test('roles, validation and audit', async () => {
  const w = world(); try {
    assert.equal((await w.api.call('POST', '/api/soc/soc/hunt/entity', { role: 'viewer', body: { entity: 'dave.syn' } })).status, 403);
    let r = await w.api.call('POST', '/api/soc/soc/hunt/entity', { role: 'analyst', body: {} }); assert.equal(r.status, 400); assert.match(JSON.stringify(r.body), /entity is required/);
    r = await w.api.call('POST', '/api/soc/soc/hunt/entity', { role: 'analyst', body: { entity: 'x" OR 1=1' } }); assert.equal(r.status, 400); assert.match(JSON.stringify(r.body), /no quotes/);
    r = await w.api.call('POST', '/api/soc/soc/hunt/entity', { role: 'analyst', body: { entity: 'dave.syn', hours: 5000 } }); assert.equal(r.status, 400); assert.match(JSON.stringify(r.body), /hours/);
    r = await w.api.call('POST', '/api/soc/soc/hunt/entity', { role: 'analyst', user: 'ali.syn', body: { entity: 'dave.syn', hours: 12 } }); assert.equal(r.status, 200);
    assert.ok(w.api.audits.some((a) => a.action === 'soc.hunt.entity' && a.target === 'dave.syn' && a.detail.hours === 12));
    assert.equal(ET.kindOf('10.0.0.1'), 'ip'); assert.equal(ET.kindOf('AS\\dave'), 'user'); assert.equal(ET.kindOf('pc-9'), 'name');
  } finally { w.cleanup(); }
});
