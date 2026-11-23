// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// SOC Performance & Operations (engine/soc/watchlist.js via analyst-routes.js): the watchlist (validated per kind, duplicates and
// the 200 cap refused, expiry, open alerts naming the entity as hits, exact matching with the host's domain dropped, the 5-minute
// check raising ONE grouped alert per entry and merging later appearances), asset criticality (crown jewel / high, replacing a
// rating) and both feeding the alert priority as itemised points; response times (detect / acknowledge / resolve, median and p90,
// withheld below 3 alerts, per severity and week); roles (viewer reads only the times, analyst the lists, operator the watchlist,
// admin the criticality), validation errors naming the field, and the audit records. SYNTHETIC data only.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const { createState } = require('../engine/soc/state');
const { createAlerts } = require('../engine/soc/alerts');
const { createCases } = require('../engine/soc/cases');
const { parse } = require('../engine/api/query');
const { fakeApi, tmpDir, quietLog } = require('./soc-fakes');

const MIN = 60000, H = 60 * MIN, DAY = 24 * H;
function world() {
  let t = Date.parse('2026-11-14T08:00:00Z');
  const dir = tmpDir(), state = createState({ dir, log: quietLog });
  const alerts = createAlerts({ state, log: quietLog, now: () => t }), cases = createCases({ state, alerts, log: quietLog });
  const counts = {};
  const search = { parse, search: async () => ({ rows: [] }), top: async () => ({ values: [] }), histogram: async (o) => ({ buckets: [{ t: o.from, n: counts[o.q] || 0 }] }) };
  const deps = { state, alerts, cases, search, config: { soc_analyst: {} }, log: quietLog, noTimers: true, now: () => t };
  const api = fakeApi({ realRanks: true }); require('../engine/soc/analyst-routes').register(api, deps);
  const raise = (o) => alerts.raise(Object.assign({ rule_id: 'R-' + Math.random(), rule_name: 'Synthetic', severity: 2, group: {}, fields: {}, summary: 'synthetic', ts_first: t - 10 * MIN, ts_last: t, source: 'engine', count: 1 }, o)).alert;
  return { api, alerts, deps, raise, counts, at: (x) => { t = x; }, now: () => t, cleanup: () => fs.rmSync(dir, { recursive: true, force: true }) };
}

test('watchlist: add (validated, audited), hits from open alerts, the check raises one grouped alert, expiry, remove', async () => {
  const w = world(); try {
    const call = (m, p, o) => w.api.call(m, '/api/soc' + p, o);
    assert.equal((await call('POST', '/soc/watchlist', { role: 'analyst', body: { kind: 'host', value: 'pc-9', reason: 'synthetic: suspected infection' } })).status, 403);
    let r = await call('POST', '/soc/watchlist', { role: 'operator', body: { kind: 'planet', value: 'x', reason: 'abc' } }); assert.equal(r.status, 400); assert.match(JSON.stringify(r.body), /kind must be one of/);
    r = await call('POST', '/soc/watchlist', { role: 'operator', body: { kind: 'cve', value: 'not-a-cve', reason: 'abc' } }); assert.equal(r.status, 400); assert.match(JSON.stringify(r.body), /value is not a valid cve/);
    r = await call('POST', '/soc/watchlist', { role: 'operator', body: { kind: 'host', value: 'pc-9' } }); assert.equal(r.status, 400); assert.match(JSON.stringify(r.body), /reason is required/);
    r = await call('POST', '/soc/watchlist', { role: 'operator', user: 'omar.syn', body: { kind: 'host', value: 'pc-9', reason: 'synthetic: suspected infection', days: 7, by: 'someone' } });
    assert.equal(r.status, 200, JSON.stringify(r.body)); const id = r.body.id; assert.equal(r.body.by, 'omar.syn'); assert.ok(r.body.until > w.now());
    assert.ok(w.api.audits.some((a) => a.action === 'soc.watchlist.add' && a.target === id && a.detail.value === 'pc-9'));
    r = await call('POST', '/soc/watchlist', { role: 'operator', body: { kind: 'host', value: 'PC-9', reason: 'again' } }); assert.equal(r.status, 409);
    // hits: an open alert on pc-9.as.local; not on pc-90
    const a1 = w.raise({ host: 'pc-9.as.local', severity: 3 }); w.raise({ host: 'pc-90' });
    let L = (await call('GET', '/soc/watchlist', { role: 'analyst' })).body.items;
    assert.equal(L[0].open_alerts, 1); assert.equal(L[0].hits[0].id, a1.id); assert.equal(L[0].worst, 3);
    // the check: no event - nothing; events - one alert, then merged
    let c = await w.deps.watchlist.check(); assert.deepEqual(c, { checked: 1, raised: 0 });
    w.counts['host:"pc-9"'] = 4; w.at(w.now() + 5 * MIN); c = await w.deps.watchlist.check(); assert.equal(c.raised, 1);
    const hit = () => w.alerts.all((a) => a.rule_id === 'soc-watchlist-hit');
    assert.equal(hit().length, 1); assert.match(hit()[0].summary, /4 event\(s\) naming watched host pc-9.*suspected infection/); assert.equal(hit()[0].severity, 3);
    w.at(w.now() + 5 * MIN); await w.deps.watchlist.check(); assert.equal(hit().length, 1, 'a later appearance merges into the same alert');
    L = (await call('GET', '/soc/watchlist', { role: 'analyst' })).body.items; assert.ok(L[0].last_appearance);
    // expiry
    w.at(w.now() + 8 * DAY); L = (await call('GET', '/soc/watchlist', { role: 'analyst' })).body.items; assert.equal(L[0].active, false);
    c = await w.deps.watchlist.check(); assert.equal(c.checked, 0, 'an expired entry is not checked');
    // remove
    r = await call('POST', '/soc/watchlist/' + id + '/remove', { role: 'operator', body: {} }); assert.equal(r.status, 400); assert.match(JSON.stringify(r.body), /reason is required/);
    r = await call('POST', '/soc/watchlist/AC-00001/remove', { role: 'operator', body: { reason: 'wrong list' } }); assert.equal(r.status, 400);
    r = await call('POST', '/soc/watchlist/' + id + '/remove', { role: 'operator', body: { reason: 'cleaned and verified' } }); assert.equal(r.status, 200);
    assert.ok(w.api.audits.some((a) => a.action === 'soc.watchlist.remove' && a.detail.reason === 'cleaned and verified'));
    assert.equal((await call('GET', '/soc/watchlist', { role: 'viewer' })).status, 403, 'a viewer does not see named systems and people');
  } finally { w.cleanup(); }
});

test('asset criticality and the watchlist raise an alert\'s priority, itemised; admin only, validated, audited', async () => {
  const w = world(); try {
    const call = (m, p, o) => w.api.call(m, '/api/soc' + p, o);
    const a = w.raise({ group: { host: 'srv-db-01' }, severity: 2 }), b = w.raise({ group: { host: 'pc-77' }, severity: 2 });
    const prio = async (id) => (await call('GET', '/soc/queue', { role: 'analyst' })).body.items.find((x) => x.id === id);
    const p0 = (await prio(a.id)).priority;
    assert.equal((await call('POST', '/soc/criticality', { role: 'operator', body: { value: 'srv-db-01', level: 'crown_jewel', reason: 'claims database' } })).status, 403);
    let r = await call('POST', '/soc/criticality', { role: 'admin', body: { value: 'srv-db-01', level: 'gold', reason: 'x1x' } }); assert.equal(r.status, 400); assert.match(JSON.stringify(r.body), /level must be one of/);
    r = await call('POST', '/soc/criticality', { role: 'admin', user: 'adam.syn', body: { value: 'srv-db-01', level: 'high', reason: 'claims database (synthetic)' } }); assert.equal(r.status, 200);
    r = await call('POST', '/soc/criticality', { role: 'admin', user: 'adam.syn', body: { value: 'SRV-DB-01', level: 'crown_jewel', reason: 'claims database (synthetic)' } }); assert.equal(r.body.replaced, 'high', 'a re-rating replaces, not duplicates');
    assert.ok(w.api.audits.some((x) => x.action === 'soc.criticality.rate' && x.detail.level === 'crown_jewel'));
    const pa = await prio(a.id); assert.equal(pa.priority, p0 + 20);
    assert.ok(pa.why.some((x) => x.factor === 'asset criticality' && x.points === 20 && /crown jewel/.test(x.reason)));
    const pb0 = (await prio(b.id)).priority;
    await call('POST', '/soc/watchlist', { role: 'operator', body: { kind: 'host', value: 'pc-77', reason: 'synthetic' } });
    const pb = await prio(b.id); assert.equal(pb.priority, pb0 + 15); assert.ok(pb.why.some((x) => x.factor === 'watchlist'));
    const id = (await call('GET', '/soc/watchlist', { role: 'analyst' })).body.criticality[0].id;
    r = await call('POST', '/soc/criticality/' + id + '/remove', { role: 'admin', body: {} }); assert.equal(r.status, 200);
    assert.equal((await prio(a.id)).priority, p0, 'removing the rating removes the points');
  } finally { w.cleanup(); }
});

test('response times: detect / acknowledge / resolve, median and p90, withheld below 3, per severity and week; any role', async () => {
  const w = world(); try {
    const T = w.now();
    for (let i = 0; i < 5; i++) { const x = w.raise({ severity: 4, ts_first: T - (i + 1) * 10 * MIN }); const rec = w.alerts.get(x.id); w.deps.state.collection('alerts').put(Object.assign({}, rec, { created: T, ack_at: T + (i + 1) * MIN, closed_at: T + (i + 1) * 30 * MIN, status: 'closed-true-positive' })); }
    w.raise({ severity: 1, ts_first: T - MIN });
    const r = await w.api.call('GET', '/api/soc/soc/performance', { role: 'viewer' }); assert.equal(r.status, 200);
    const P = r.body, crit = P.by_severity.find((s) => s.severity === 4);
    assert.deepEqual([crit.raised, crit.detect.median_min, crit.detect.n, crit.acknowledge.median_min, crit.acknowledge.p90_min, crit.resolve.median_min], [5, 30, 5, 3, 5, 90]);
    assert.equal(P.by_severity.find((s) => s.severity === 1).acknowledge.withheld, 'fewer than 3 alerts');
    assert.equal(P.weeks.length, 4); assert.equal(P.weeks[3].raised, 6);
    assert.equal(P.unacknowledged, 1); assert.ok(P.oldest_unacked_min >= 0);
  } finally { w.cleanup(); }
});
