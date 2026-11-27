// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Sentra Next-Gen SIEM (engine/soc/nextgen.js) over SYNTHETIC counters: unify (sources live / quiet, cloud feeds, pipeline eps and
// stage errors, collectors), hunt & detect (search, indicators, rules firing, duplicates suppressed), respond (cases, AI engineers'
// investigations, SOAR runs); the headline figures are measured (noise removed, median time to resolve, false-positive share, eps)
// and a figure resting on too few cases is withheld with the reason; an empty installation says what to connect; a part that throws
// is left out, not an error; the route answers a viewer with counts only (no event, user or host names).
const test = require('node:test');
const assert = require('node:assert/strict');
const N = require('../engine/soc/nextgen');
const { fakeApi } = require('./soc-fakes');

const NOW = Date.parse('2026-11-27T09:00:00Z'), MIN = 60000, H = 36e5;
function world() {
  const alerts = [];
  for (let i = 0; i < 10; i++) alerts.push({ id: 'A' + i, created: NOW - (i + 1) * H, ack_at: NOW - (i + 1) * H + 5 * MIN, closed_at: NOW - (i + 1) * H + (20 + i) * MIN, status: i < 2 ? 'closed-false-positive' : 'closed-true-positive', host: 'dc-syn-01' });
  alerts.push({ id: 'A10', created: NOW - H, status: 'new', host: 'dc-syn-01' });
  return {
    sources: [{ src_id: 'fw', src_type: 'fortigate', collector: 'syslog', last_seen: NOW - MIN, events_since_start: 9000, parse_errors_since_start: 90 },
      { src_id: 'm365', src_type: 'm365', collector: 'graph', last_seen: NOW - 2 * MIN, events_since_start: 1000 }, { src_id: 'old', src_type: 'h3c', collector: 'syslog', last_seen: NOW - 3 * H }],
    pipeline: { events: 10000, eps_1m: 42.5, stages: [{ name: 'parse', calls: 10000, errors: 0 }, { name: 'detect', calls: 10000, errors: 2 }] },
    detector: { rules_loaded: 3, load_errors: 0, rules: [{ id: 'r1', matches: 400, suppressed: 360, alerts: 8 }, { id: 'r2', matches: 50, suppressed: 30, alerts: 3 }, { id: 'r3', matches: 0, suppressed: 0, alerts: 0 }] },
    intel: { ip: 1200, domain: 300, hash: 0, lists: 2, hits: { 'feodo': 4 } }, search: true,
    alerts, alertStats: { merged: 50 },
    cases: [{ id: 'C1', status: 'open', created: NOW - 5 * H }, { id: 'C2', status: 'closed', created: NOW - 30 * H, closed_at: NOW - 20 * H }],
    soarRuns: [{ id: 'S1', at: NOW - H, auto: true }, { id: 'S2', at: NOW - 2 * H, auto: false }],
    dutyItems: [{ id: 'D1', status: 'investigating' }, { id: 'D2', status: 'resolved', resolved_at: NOW - H }], aiLedger: [{ id: 'x', day: '2026-11-26', calls: 17 }],
  };
}

test('unify, hunt & detect, respond: segments, states, headline figures from the counters', () => {
  const r = N.analyse(world(), NOW), S = Object.fromEntries(r.segments.map((s) => [s.id, s]));
  assert.equal(r.segments.length, 9);
  assert.equal(S.data.figure, '2 / 3'); assert.equal(S.data.state, 'ready'); assert.match(S.data.sub, /1 cloud/); assert.match(S.data.next, /1 source\(s\) quiet/);
  assert.equal(S.pipeline.state, 'partial', 'stage errors make it partial'); assert.equal(S.pipeline.figure, '42.5');
  assert.equal(S.collect.figure, '2');
  assert.equal(S.intel.figure, '1,500'); assert.match(S.intel.sub, /4 hit/);
  assert.equal(S.detections.state, 'ready'); assert.match(S.detections.sub, /2 firing · 390 duplicate/);
  assert.equal(S.cases.figure, '1'); assert.equal(S.soar.figure, '2'); assert.match(S.soar.sub, /1 automatic/); assert.equal(S.investigate.figure, '1'); assert.match(S.investigate.sub, /17 AI call/);
  const HL = Object.fromEntries(r.headline.map((h) => [h.id, h]));
  assert.equal(HL.noise.value, 88, '(390 suppressed + 50 merged) of (450 matches + 50 merged)');
  assert.equal(HL.mttr.value, 25, 'median of 20..29 minutes = 24.5, rounded'); assert.match(HL.mttr.basis, /median 5 min to acknowledge/);
  assert.equal(HL.fp.value, 20, '2 of 10 closed were false positives'); assert.equal(HL.eps.value, 42.5);
  assert.deepEqual(r.pillars, { unify: 83, detect: 100, respond: 100 });
  assert.ok(!JSON.stringify(r).includes('dc-syn-01'), 'no host names leave');
});

test('too few cases: the figure is withheld with the reason; an empty installation says what to connect', () => {
  const w = world(); w.alerts = w.alerts.slice(0, 2); w.detector.rules = [{ id: 'r', matches: 5, suppressed: 1, alerts: 1 }]; w.alertStats = {};
  const HL = Object.fromEntries(N.analyse(w, NOW).headline.map((h) => [h.id, h]));
  assert.equal(HL.mttr.value, null); assert.match(HL.mttr.why, /after 3 closed alerts/); assert.equal(HL.fp.value, null); assert.equal(HL.noise.value, null); assert.match(HL.noise.why, /20 rule matches/);
  const e = N.analyse({}, NOW), S = Object.fromEntries(e.segments.map((s) => [s.id, s]));
  assert.equal(S.data.state, 'none'); assert.match(S.data.next, /Connect the first log source/); assert.equal(S.search.state, 'none'); assert.equal(S.detections.state, 'none');
  assert.equal(e.headline.find((h) => h.id === 'eps').value, null); assert.deepEqual(e.pillars, { unify: 0, detect: 0, respond: 50 }, 'case management, investigations and SOAR are there, not yet used');
});

test('gather: a part that throws is left out (logged once), not an error', () => {
  const warned = [];
  const g = N.gather({ tracker: { summary() { throw new Error('tracker down (synthetic)'); } }, pipeline: { stats: () => ({ eps_1m: 1, events: 5, stages: [] }) }, log: { every: (k, ms, lvl, msg) => warned.push(msg) } });
  assert.deepEqual(g.sources, []); assert.equal(g.pipeline.eps_1m, 1); assert.equal(warned.length, 1);
  assert.equal(N.analyse(g, NOW).segments.find((s) => s.id === 'pipeline').figure, '1');
});

test('route: GET /api/soc/soc/nextgen answers a viewer from the live parts', async () => {
  const api = fakeApi({ realRanks: true }), w = world();
  N.register(api, { now: () => NOW, tracker: { summary: () => w.sources }, pipeline: { stats: () => w.pipeline }, detector: { stats: () => w.detector }, intel: { stats: () => w.intel }, search: {},
    alerts: { all: () => w.alerts, stats: () => w.alertStats }, cases: { all: () => w.cases } });
  const path = api.routes[0].pattern; assert.match(path, /\/soc\/nextgen$/);
  const r = await api.call('GET', path, { role: 'viewer', user: 'vera.syn' });
  assert.equal(r.status, 200, JSON.stringify(r.body)); assert.equal(r.body.segments.length, 9); assert.equal(r.body.totals.live_sources, 2);
});
