// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// SOC Console intel (engine/soc/console.js intel(), GET {P}/soc/console/intel): log sources quiet / loud / new against the same hour
// on 7 days (judged from 4), watched-file changes scored with every point named (technique, first seen - and not first on the
// next read, off hours, process, high-impact path), flapping agents from heartbeat gaps, hosts needing attention fusing offenses,
// file changes and the agent (several kinds of signal first), the analyst role (viewer refused). SYNTHETIC events only.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const { createState } = require('../engine/soc/state');
const K = require('../engine/soc/console');
const { fakeApi, tmpDir, quietLog } = require('./soc-fakes');

const MIN = 60e3, H = 60 * MIN, DAY = 24 * H, T = Date.parse('2026-11-15T20:00:00Z');   // 23:00 in Riyadh: off hours
const iso = (t) => new Date(t).toISOString().replace('T', ' ').replace('Z', '');
function world() {
  // per hour-window source counts: d = 0 is the last hour
  const counts = (d) => d === 0 ? [['windows', 2], ['fortigate', 900], ['newapp', 40]] : [['windows', 500], ['fortigate', 100]];
  const hb = [];
  for (let m = 0; m < 24 * 60; m += 5) { hb.push({ ts: T - m * MIN, host: 'pc-syn-1', action: 'agent-heartbeat' }); if (!(m % 120 < 30)) hb.push({ ts: T - m * MIN, host: 'pc-syn-flap', action: 'agent-heartbeat' }); }
  const fileEv = [
    { ts: T - 10 * MIN, host: 'pc-syn-1', category: 'file', action: 'file-created', process: 'C:\\Users\\x\\AppData\\upd.exe', fields: { target_filename: 'C:\\Users\\x\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\upd.lnk' }, tags: ['T1547.001'] },
    { ts: T - 9 * MIN, host: 'srv-syn-2', category: 'file', action: 'file-created', process: 'C:\\Windows\\System32\\msiexec.exe', fields: { target_filename: 'C:\\Windows\\System32\\drivers\\x.sys' }, tags: [] },
  ];
  const search = {
    top: async (q) => { if (q.field === 'host') return { values: [{ v: 'pc-syn-1', n: 50 }] }; const d = Math.round((T - q.to) / DAY); return { values: counts(d).map(([v, n]) => ({ v, n })) }; },
    rare: async () => ({ values: [{ v: 'pc-syn-1', n: 288, first: iso(T - 7 * DAY), last: iso(T) }, { v: 'pc-syn-gone', n: 50, first: iso(T - 7 * DAY), last: iso(T - 10 * H) }, { v: 'pc-syn-flap', n: 200, first: iso(T - 7 * DAY), last: iso(T - 40 * MIN) }] }),
    fetchEvents: async (q) => (/^action:agent-heartbeat/.test(q.q) ? hb.filter((e) => e.ts >= q.from).sort((a, b) => (q.order === 'desc' ? b.ts - a.ts : a.ts - b.ts)) : fileEv.slice()),
    histogram: async (q) => ({ buckets: Array.from({ length: 60 }, (_, i) => ({ t: q.from + i * MIN, n: 100 })), step_ms: MIN }),
    search: async () => ({ rows: [] }),
  };
  const dir = tmpDir(), state = createState({ dir, log: quietLog });
  const deps = { state, search, config: {}, log: quietLog, now: () => T,
    analyst: { queue: () => ({ items: [{ id: 'ALR-1', rule_name: 'Synthetic LSASS read', priority: 80, entities: ['host:pc-syn-1'], host: 'pc-syn-1' }, { id: 'ALR-2', rule_name: 'Synthetic scan', priority: 30, entities: ['host:srv-syn-9'] }] }) } };
  const api = fakeApi({ realRanks: true }); K.register(api, deps);
  return { call: (m, p, x) => api.call(m, '/api/soc' + p, x), cleanup: () => fs.rmSync(dir, { recursive: true, force: true }) };
}

test('console intel: sources, FIM risk, flapping agents, hosts needing attention; viewer refused', async () => {
  const w = world(); try {
    let r = await w.call('GET', '/soc/console/intel', { role: 'viewer' }); assert.equal(r.status, 403);
    r = await w.call('GET', '/soc/console/intel', { role: 'analyst' }); assert.equal(r.status, 200, JSON.stringify(r.body));
    const S = Object.fromEntries(r.body.sources.map((x) => [x.source, x]));
    assert.equal(S.windows.state, 'quiet'); assert.match(S.windows.why, /2 events in the last hour against a usual 500 - check that collection is running/);
    assert.equal(S.fortigate.state, 'loud'); assert.match(S.fortigate.why, /9x the usual 100/);
    assert.equal(S.newapp.state, 'new'); assert.equal(r.body.sources[0].state, 'quiet', 'a quiet source first: a blind spot');
    const f = r.body.fim, top = f[0];
    assert.match(top.path, /Startup\\upd\.lnk/); assert.equal(top.risk, 100);
    assert.deepEqual(top.risk_why.map((x) => x.factor), ['technique', 'first seen', 'off hours', 'process', 'path']);
    const sys = f.find((x) => /x\.sys/.test(x.path)); assert.ok(!sys.risk_why.some((x) => x.factor === 'process'), 'msiexec is an installer: no process points');
    assert.ok(r.body.stability.some((x) => x.host === 'pc-syn-flap' && x.gaps >= 3) && !r.body.stability.some((x) => x.host === 'pc-syn-1'), 'flapping agent found, steady one not');
    const h0 = r.body.hosts[0]; assert.equal(h0.host, 'pc-syn-1'); assert.deepEqual(h0.why.map((x) => x.factor), ['offense', 'file change']); assert.equal(h0.score, 40 + 30);
    assert.ok(r.body.hosts.some((x) => x.host === 'pc-syn-gone' && /disconnected/.test(x.why[0].reason)) && r.body.hosts.some((x) => x.host === 'pc-syn-flap' && /flapping/.test(x.why[0].reason)));
    r = await w.call('GET', '/soc/console/intel', { role: 'analyst' });
    assert.ok(!r.body.fim[0].risk_why.some((x) => x.factor === 'first seen'), 'not first seen on the next read');
  } finally { w.cleanup(); }
});
