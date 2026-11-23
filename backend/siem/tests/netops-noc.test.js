// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// NOC Summary intelligence (engine/netops/noc-intel.js + GET /netops/noc, POST /netops/noc/brief): itemised health scores,
// one cause one incident (a down gateway covers the nodes behind it; a whole site down = its link; nearly everything down =
// the engine's own path), anomalies only after 30 samples of the node's own history (robust z), flapping, capacity forecast
// from ClickHouse history (withheld below 5 days or when flat), the routes' roles (viewer reads; brief = operator, a person;
// AI off = 503) and the audit record. SYNTHETIC devices.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs'), os = require('node:os'), path = require('node:path');
const { createNocIntel, robustZ, linfit } = require('../engine/netops/noc-intel');

const quiet = { info() {}, warn() {}, error() {}, debug() {} };
function estate(devs) {
  const snaps = {};
  return { snaps, inventory: { list: () => devs }, poller: { snapshot: (id) => snaps[id] || null, snapshots: () => snaps, stats: () => ({ running: false }) } };
}
const dev = (id, site, role, extra) => Object.assign({ id, name: id.toUpperCase() + '-SYN', vendor: 'cisco-ios', ip: '10.0.0.' + (id.length + 10), site, role, poll: { ping: true, snmp: true } }, extra || {});
const up = (at, o) => Object.assign({ at, ok: true, errors: [], reach: { rtt_avg_ms: 5, loss_pct: 0 }, system: { cpu_pct: 20, mem_pct: 40 }, interfaces: [] }, o || {});
const down = (at) => ({ at, ok: false, errors: ['ping: no reply'], reach: { sent: 3, received: 0, loss_pct: 100 } });

test('statistics: robust z needs 30 samples; least squares', () => {
  assert.equal(robustZ([5, 5, 5], 50), null, 'fewer than 30 samples: no verdict');
  const s = Array.from({ length: 40 }, (_, i) => 5 + (i % 3));
  assert.ok(robustZ(s, 60) >= 4); assert.ok(Math.abs(robustZ(s, 6)) < 2);
  const f = linfit([[0, 10], [1, 12], [2, 14]]); assert.equal(Math.round(f.slope), 2); assert.equal(Math.round(f.intercept), 10);
});

test('health is itemised; anomalies only after learning; flapping counted', () => {
  let t = 1e12; const E = estate([dev('sw1', 'Riyadh', 'access')]);
  const N = createNocIntel(Object.assign({ log: quiet, now: () => t, config: {} }, E));
  // learning: 10 samples -> no anomaly verdict even with a huge value
  for (let i = 0; i < 10; i++) { t += 60000; E.snaps.sw1 = up(t); N.sample(); }
  t += 60000; E.snaps.sw1 = up(t, { reach: { rtt_avg_ms: 400, loss_pct: 0 } }); N.sample();
  let v = N.view(), n = v.nodes[0];
  assert.equal(n.learning, true); assert.deepEqual(n.anomalies, [], 'still learning: no anomaly claimed');
  for (let i = 0; i < 30; i++) { t += 60000; E.snaps.sw1 = up(t); N.sample(); }
  t += 60000; E.snaps.sw1 = up(t, { reach: { rtt_avg_ms: 400, loss_pct: 2 }, system: { cpu_pct: 95, mem_pct: 40 }, interfaces: [{ name: 'Gi0/1', oper: 'up', util_in: 96, util_out: 10, err_per_min: 0 }] }); N.sample();
  v = N.view(); n = v.nodes[0];
  assert.equal(n.learning, false); assert.ok(n.anomalies.some((a) => a.metric === 'rtt' && a.z >= 4 && a.baseline === 5), JSON.stringify(n.anomalies));
  assert.ok(n.score < 100 && n.why.some((w) => /packet loss/.test(w.why)) && n.why.some((w) => /CPU 95/.test(w.why)) && n.why.some((w) => /90 %/.test(w.why)), 'every point lost says why: ' + JSON.stringify(n.why));
  assert.equal(n.score, 100 + n.why.reduce((a, w) => a + w.pts, 0), 'the score is the sum of its reasons');
  // flapping: interface going up and down
  for (const op of ['down', 'up', 'down', 'up']) { t += 60000; E.snaps.sw1 = up(t, { interfaces: [{ name: 'Gi0/2', oper: op }] }); N.sample(); }
  v = N.view(); assert.ok(v.flapping.length === 1 && v.flapping[0].flaps >= 3, JSON.stringify(v.flapping));
  assert.ok(v.nodes[0].why.some((w) => /flapping/.test(w.why)));
});

test('one cause, one incident: a down gateway covers the nodes behind it; a site with every node down is its link; everything down is the engine path', () => {
  const t = 1e12;
  let E = estate([dev('gw1', 'Jeddah', 'gateway'), dev('sw2', 'Jeddah', 'access'), dev('sw3', 'Jeddah', 'access'), dev('sw4', 'Riyadh', 'access'), dev('sw5', 'Riyadh', 'access')]);
  Object.assign(E.snaps, { gw1: down(t), sw2: down(t), sw3: down(t), sw4: up(t), sw5: up(t) });
  let v = createNocIntel(Object.assign({ log: quiet, now: () => t, config: {} }, E)).view();
  assert.equal(v.causes.length, 1); assert.equal(v.causes[0].kind, 'device'); assert.equal(v.causes[0].root, 'gw1');
  assert.deepEqual(v.nodes.filter((n) => n.covered_by === 'gw1').map((n) => n.id).sort(), ['sw2', 'sw3']);
  assert.ok(!v.attention.some((a) => a.id === 'sw2'), 'a covered node is not listed again as its own problem');
  // a site with no gateway in the inventory, every node down: the link
  E = estate([dev('a1', 'Dammam', 'access'), dev('a2', 'Dammam', 'access'), dev('b1', 'Riyadh', 'access'), dev('b2', 'Riyadh', 'access')]);
  Object.assign(E.snaps, { a1: down(t), a2: down(t), b1: up(t), b2: up(t) });
  v = createNocIntel(Object.assign({ log: quiet, now: () => t, config: {} }, E)).view();
  assert.equal(v.causes[0].kind, 'site-link'); assert.match(v.causes[0].title, /Dammam/);
  // >= 80 % down: the engine's own path, never N outages
  E = estate(['c1', 'c2', 'c3', 'c4', 'c5'].map((id, i) => dev(id, 'Site' + i, 'access')));
  for (const id of ['c1', 'c2', 'c3', 'c4']) E.snaps[id] = down(t); E.snaps.c5 = up(t);
  v = createNocIntel(Object.assign({ log: quiet, now: () => t, config: {} }, E)).view();
  assert.equal(v.causes.length, 1); assert.equal(v.causes[0].kind, 'engine-path');
  // not polled stays not polled, never a score
  E = estate([dev('x1', 'Riyadh', 'access', { poll: {} })]);
  v = createNocIntel(Object.assign({ log: quiet, now: () => t, config: {} }, E)).view();
  assert.equal(v.nodes[0].state, 'unpolled'); assert.equal(v.nodes[0].score, null); assert.equal(v.estate_score, null, 'nothing measured: no estate score');
});

test('capacity forecast from history: a growing interface gets a date; flat, falling or short history get none', async () => {
  const DAY = 864e5, t = Date.parse('2026-11-01T00:00:00Z'); const E = estate([dev('core1', 'Riyadh', 'core')]);
  const rows = [];
  for (let i = 13; i >= 0; i--) { const d = new Date(t - i * DAY).toISOString().slice(0, 10);
    rows.push({ device: 'core1', key: 'Te1/1', d, peak: 50 + (13 - i) * 2 }); rows.push({ device: 'core1', key: 'Gi0/9', d, peak: 40 });
    if (i < 3) rows.push({ device: 'core1', key: 'Gi0/5', d, peak: 70 + (3 - i) * 5 }); }
  const sql = []; const ch = { query: async (q) => { sql.push(q); return rows; } };
  const N = createNocIntel(Object.assign({ log: quiet, now: () => t, ch, config: { clickhouse: { database: 'siem' } } }, E));
  const F = await N.refreshForecast(true);
  assert.equal(F.items.length, 1, 'only the growing interface with enough history: ' + JSON.stringify(F.items));
  assert.equal(F.items[0].interface, 'Te1/1'); assert.equal(F.items[0].growth_per_week, 14); assert.ok(F.items[0].days_to_90 >= 6 && F.items[0].days_to_90 <= 8, String(F.items[0].days_to_90));
  assert.match(sql[0], /FROM siem\.net_metrics/); assert.ok(!/\$\{/.test(sql[0]));
  const N2 = createNocIntel(Object.assign({ log: quiet, now: () => t, config: {} }, E));
  assert.match((await N2.refreshForecast(true)).note, /needs ClickHouse/, 'no history store: says so');
  const bad = createNocIntel(Object.assign({ log: quiet, now: () => t, ch: { query: async () => { throw new Error('connection refused'); } }, config: {} }, E));
  assert.match((await bad.refreshForecast(true)).note, /could not be read/, 'a failing history query is reported, not swallowed');
});

test('routes: viewer reads the NOC view; the brief is operator-only, a person, refused when AI is off; audited', async () => {
  const routes = require('../engine/netops/routes'), { createState } = require('../engine/soc/state');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'noc-')), secrets = path.join(dir, 'secrets.json'); fs.writeFileSync(secrets, '{}', { mode: 0o600 });
  try {
    const state = await createState({ dir: path.join(dir, 'state') });
    const config = { netops: { enabled: false }, soc_analyst: { enabled: false } };
    Object.defineProperty(config, 'secrets', { value: {}, enumerable: false, writable: true });
    Object.defineProperty(config, '_paths', { value: { secrets }, enumerable: false });
    const E = estate([dev('sw1', 'Riyadh', 'access')]); E.snaps.sw1 = up(1);
    const N = routes.createNetops({ state, config, log: quiet, poller: Object.assign({ forget() {}, start() {}, pollDevice: async () => ({}) }, E.poller) });
    N.inventory.put({ id: 'sw1', name: 'SW1-SYN', vendor: 'cisco-ios', ip: '10.0.0.1', site: 'Riyadh', poll: { ping: true } }, 'syed');
    const R = {}; routes.register({ route: (m, p, h) => { R[m + ' ' + p] = h; } }, { state, config, log: quiet, netops: N, noTimer: true });
    const RANK = { viewer: 0, analyst: 1, operator: 2, admin: 3 }, audits = [];
    const call = async (m, p, role, user) => { const o = {}; const ctx = { role, user: user || 'op1', body: {}, params: {}, query: {},
      need(r) { if (RANK[role] < RANK[r]) { o.s = 403; return false; } return true; }, ok(b) { o.s = 200; o.b = b; return b; }, fail(c, msg) { o.s = c; o.b = { error: msg }; }, audit(a, t, d) { audits.push({ a, t, d }); } };
      await R[m + ' /api/soc/netops' + p](ctx); return o; };
    const v = await call('GET', '/noc', 'viewer');
    assert.equal(v.s, 200); assert.equal(v.b.total, 1); assert.equal(v.b.nodes[0].state, 'up'); assert.ok(v.b.model && v.b.ai && v.b.note);
    assert.equal((await call('POST', '/noc/brief', 'viewer')).s, 403, 'a viewer cannot ask for the AI brief');
    const off = await call('POST', '/noc/brief', 'operator'); assert.equal(off.s, 503, 'AI switched off: said so'); assert.match(off.b.error, /switched off|API key|SDK/);
    assert.ok(!audits.some((x) => x.a === 'netops.noc.brief'), 'nothing audited when nothing was asked of the model');
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('brief: a service identity is refused; the model call is checked and audited through the guard', async () => {
  const t = 1e12; const E = estate([dev('gw1', 'Jeddah', 'gateway'), dev('sw2', 'Jeddah', 'access')]); Object.assign(E.snaps, { gw1: down(t), sw2: down(t) });
  const script = [{ content: [{ type: 'tool_use', id: 'a', name: 'summary', input: {} }], stop_reason: 'tool_use', usage: { input_tokens: 10, output_tokens: 5 } },
    { content: [{ type: 'tool_use', id: 'b', name: 'submit_brief', input: { summary: 'Jeddah gateway down', priorities: [{ device: 'gw1', why: 'gateway down', check: 'power and uplink', team: 'network' }, { device: 'not-a-node', why: 'x', check: 'y' }] } }], stop_reason: 'tool_use', usage: { input_tokens: 10, output_tokens: 5 } }];
  class Fake { constructor() { this.messages = { create: async () => script.shift() }; } }
  const N = createNocIntel(Object.assign({ log: quiet, now: () => t, sdk: Fake, config: { soc_analyst: {}, secrets: { netops: { anthropic_api_key: 'sk-ant-synthetic-for-tests' } }, ai_limits: { per_user_hour: 100, per_user_day: 1000 } } }, E));
  await assert.rejects(N.brief({ user: 'system:noc', role: 'operator' }), /service or AI identity/);
  const r = await N.brief({ user: 'nora.syn', role: 'operator' });
  assert.equal(r.ok, true); assert.equal(r.label, 'AI draft - verify');
  assert.equal(r.priorities[0].verified, true, 'a node the AI looked at'); assert.equal(r.priorities[1].verified, false, 'an invented node is marked unverified'); assert.equal(r.unverified, 1);
});
