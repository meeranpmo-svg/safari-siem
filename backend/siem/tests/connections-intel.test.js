// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Application Connections intelligence (engine/db-audit/connections-intel.js) over SYNTHETIC current applications and 14 days of
// hourly session history: the normal band per hour; MISSING (usually connected at this hour, absent now), LEAK (rising for 12 h with
// idle sessions piling up), SPIKE (3x the usual p90), NEW (never seen before today); shared database accounts; refusal rates; the
// dependency map; itemised health; nothing learned yet says so; the route: operator reads, a viewer is refused, validation.
const test = require('node:test');
const assert = require('node:assert/strict');
const CI = require('../engine/db-audit/connections-intel');
const { fakeApi } = require('./soc-fakes');

const H = 3600000, DAY = 86400000, NOW = Date.parse('2026-11-19T07:30:00Z');   // 10:30 Riyadh
const app = (o) => Object.assign({ service: 'CLAIMS', program: 'JDBC Thin Client', state: 'connected', sessions: 20, max_idle_s: 60 }, o);
function world() {
  const apps = [
    app({ machine: 'app01', db_user: 'CLAIMS_APP', sessions: 22 }),                                       // usual
    app({ machine: 'hr01', service: 'HR', db_user: 'HR_APP', state: 'dropped', sessions: 0 }),            // missing
    app({ machine: 'pool9', db_user: 'POOL_APP', sessions: 90, max_idle_s: 3600 }),                        // leak
    app({ machine: 'rep01', service: 'REP', db_user: 'REP_APP', sessions: 200 }),                          // spike
    app({ machine: 'odd01', program: 'sqlplus.exe', db_user: 'CLAIMS_APP', sessions: 1 }),                 // new
    app({ machine: 'app02', db_user: 'CLAIMS_APP', program: 'python.exe', sessions: 3 })];
  const history = [];
  for (let d = 14; d >= 1; d--) for (let h = 0; h < 24; h++) {
    const t = Date.parse('2026-11-19T00:00:00+03:00') - d * DAY + h * H;
    history.push({ k: CI.keyOf(apps[0]), h: t, s: 20 + (h % 3) }, { k: CI.keyOf(apps[1]), h: t, s: h >= 8 && h <= 17 ? 12 : 0 }, { k: CI.keyOf(apps[2]), h: t, s: 20 }, { k: CI.keyOf(apps[3]), h: t, s: 15 + (h % 2) }, { k: CI.keyOf(apps[5]), h: t, s: 3 });
  }
  for (let i = 12; i >= 1; i--) history.push({ k: CI.keyOf(apps[2]), h: NOW - i * H, s: 90 - i * 6, idle: 3600 });
  const view = { instance: 'ORCLPRD', applications: apps, listener: [{ client_host: '10.0.0.9', service: 'CLAIMS', ok: 60, refused: 40, reasons: [{ code: '12519', n: 40, meaning: 'no appropriate service handler found' }] }, { client_host: '10.0.0.8', service: 'HR', ok: 3, refused: 1, reasons: [] }],
    links: [{ link: 'TO_FIN', remote_db: 'FINPRD', verdict: 'read_only' }] };
  return { view, history, now: NOW };
}

test('baseline, missing, leak, spike, new, shared accounts, refusals, map and health', () => {
  const v = CI.analyse(world()), by = (m) => v.apps.find((a) => a.machine === m), has = (m, x) => by(m).verdicts.some((y) => y.verdict === x);
  assert.equal(by('app01').verdicts.length, 0, 'a usual application raises nothing'); assert.ok(by('app01').baseline.median >= 20 && by('app01').band.length === 24);
  assert.ok(has('hr01', 'missing')); assert.match(by('hr01').verdicts[0].why, /usually connected at 10:00 \(14 days, about 12 sessions\)/);
  assert.ok(has('pool9', 'leak')); assert.match(by('pool9').verdicts.find((x) => x.verdict === 'leak').why, /rising for 1[23] hours .* idle sessions up to 60 min/);
  assert.ok(has('rep01', 'spike')); assert.ok(has('odd01', 'new')); assert.ok(!has('app02', 'new'));
  assert.deepEqual(v.counts, { missing: 1, leak: 1, spike: 1, new: 1, shared: 1, refusing: 1 });
  assert.equal(v.flagged[0].verdicts[0].severity, 'high');
  const sh = v.shared[0]; assert.equal(sh.db_user, 'CLAIMS_APP'); assert.equal(sh.machines, 3); assert.match(sh.why, /shared account/);
  assert.equal(v.refusals.length, 1, 'fewer than 10 attempts is not judged'); assert.equal(v.refusals[0].rate_pct, 40);
  assert.equal(v.map.services[0].service, 'REP'); assert.ok(v.map.machines.some((m) => m.machine === 'pool9')); assert.equal(v.map.links[0].remote_db, 'FINPRD');
  assert.ok(v.health.score < 100 && v.health.items.some((i) => /missing/.test(i.label)));
  assert.equal(v.learning.days, 14);
  const fresh = CI.analyse({ view: { instance: 'X', applications: [app({ machine: 'a', db_user: 'U' })] }, history: [], now: NOW });
  assert.equal(fresh.apps[0].baseline, null); assert.ok(fresh.apps[0].verdicts.some((x) => x.verdict === 'new')); assert.equal(fresh.learning.days, 0);
  assert.equal(CI.analyse({ view: { instance: 'X', applications: [] }, now: NOW }).health.score, null);
});

test('route: operator reads (history queried for 14 days), a viewer is refused, validation', async () => {
  const api = fakeApi({ realRanks: true }), w = world(), sql = [];
  const deps = { now: () => NOW, ch: { query: async (q) => { sql.push(q); return w.history; } }, dbConnections: { view: async () => w.view } };
  CI.register(api, deps, '/api/soc');
  let r = await api.call('GET', '/api/soc/db/oracle/connections/intel?instance=ORCLPRD', { role: 'operator' }); assert.equal(r.status, 200, JSON.stringify(r.body));
  assert.equal(r.body.counts.leak, 1); assert.match(sql[0], /INTERVAL 14 DAY/); assert.match(sql[0], /app-session/);
  r = await api.call('GET', '/api/soc/db/oracle/connections/intel?instance=ORCLPRD', { role: 'viewer' }); assert.equal(r.status, 403);
  r = await api.call('GET', "/api/soc/db/oracle/connections/intel?instance=x' or 1=1", { role: 'operator' }); assert.equal(r.status, 400); assert.match(r.body.error, /instance/);
});
