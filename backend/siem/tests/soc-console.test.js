// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// SOC Console (engine/soc/console.js): agents from their heartbeats - active / delayed / disconnected against the interval, the
// version against the newest running one (outdated), degraded queue, retire with a reason (stops counting as disconnected, comes
// back by itself on a new heartbeat), restore; file-integrity changes on the watched paths grouped per host + path, with coverage
// and the honest note, the watch list admin-only and validated; ingest per minute against the hour's median (a silent minute
// after a normal hour is flagged); the latest events for analysts only; viewers get counts; validation errors name the field;
// audit records (the heartbeat parser's agent version is checked in api.test.js). SYNTHETIC events only.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const { createState } = require('../engine/soc/state');
const K = require('../engine/soc/console');
const { fakeApi, tmpDir, quietLog } = require('./soc-fakes');

const MIN = 60e3, H = 60 * MIN, T = Date.parse('2026-11-15T08:00:00Z');
const iso = (t) => new Date(t).toISOString().replace('T', ' ').replace('Z', '');
function world(o = {}) {
  let t = T;
  const hb = [   // [host, minutes ago, version, degraded]
    ['pc-syn-1', 2, '1.3.0'], ['pc-syn-2', 4, '1.2.9'], ['srv-syn-3', 40, '1.3.0'], ['srv-syn-4', 600, '1.1.0'], ['pc-syn-5', 3, '1.3.0', true],
  ];
  const fileEv = [
    { ts: T - 30 * MIN, host: 'pc-syn-1', category: 'file', action: 'file-created', process: 'C:\\Users\\x\\AppData\\evil.exe', user: 'dana.syn', fields: { target_filename: 'C:\\Users\\dana.syn\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\upd.lnk' }, tags: ['T1547.001'], severity: 2 },
    { ts: T - 20 * MIN, host: 'pc-syn-1', category: 'file', action: 'file-created', process: 'x.exe', fields: { target_filename: 'C:\\Users\\dana.syn\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\upd.lnk' }, tags: [] },
    { ts: T - 10 * MIN, host: 'web-syn-1', category: 'registry', action: 'registry-set', process: 'reg.exe', fields: { target_object: 'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater' }, tags: ['T1547.001'] },
    { ts: T - 5 * MIN, host: 'pc-syn-2', category: 'file', action: 'file-created', process: 'word.exe', fields: { target_filename: 'C:\\Users\\x\\Documents\\report.docx' }, tags: [] },
  ];
  const perMin = o.perMin || ((i) => 100 + (i % 3));
  const search = {
    rare: async (q) => ({ values: hb.map(([h, m]) => ({ v: h, n: 100, first: iso(T - 7 * 24 * H), last: iso(t - m * MIN + (t - T)) })) }),
    fetchEvents: async (q) => (/^action:agent-heartbeat/.test(q.q) ? hb.filter(([, m]) => m <= 30).map(([h, m, v, d]) => ({ ts: T - m * MIN, host: h, action: 'agent-heartbeat', message: 'Agent heartbeat v' + v + ' (queue 0 files)', fields: h === 'pc-syn-2' ? { queue_files: '0' } : { agent_version: v, queue_files: d ? '400' : '0' }, tags: d ? ['heartbeat', 'agent-degraded'] : ['heartbeat'] }))
      : fileEv.slice()),
    top: async (q) => (q.field === 'host' ? { values: [{ v: 'pc-syn-1', n: 50 }, { v: 'pc-syn-2', n: 9 }, { v: 'web-syn-1', n: 4 }] } : { values: [{ v: 'windows', n: 5000 }, { v: 'fortigate', n: 900 }] }),
    histogram: async (q) => ({ buckets: Array.from({ length: 60 }, (_, i) => ({ t: q.from + i * MIN, n: perMin(i) })), step_ms: MIN }),
    search: async (q) => ({ rows: [{ ts: iso(T - MIN), host: 'pc-syn-1', src_type: 'windows', action: 'logon', message: 'synthetic' }] }),
  };
  const dir = tmpDir(), state = createState({ dir, log: quietLog });
  const deps = { state, search, config: {}, log: quietLog, now: () => t };
  const api = fakeApi({ realRanks: true }); K.register(api, deps);
  return { api, call: (m, p, x) => api.call(m, '/api/soc' + p, x), at: (x) => { t = x; }, hb, cleanup: () => fs.rmSync(dir, { recursive: true, force: true }) };
}

test('agents: active / delayed / disconnected, outdated against the newest, degraded, retire and restore', async () => {
  const w = world(); try {
    assert.equal((await w.call('GET', '/soc/console/agents', { role: 'viewer' })).status, 403, 'host names are for analysts');
    let r = (await w.call('GET', '/soc/console/agents', { role: 'analyst' })).body;
    const a = (h) => r.agents.find((x) => x.host === h);
    assert.deepEqual(['pc-syn-1', 'srv-syn-3', 'srv-syn-4'].map((h) => a(h).status), ['active', 'delayed', 'disconnected']);
    assert.equal(r.newest_version, '1.3.0'); assert.equal(a('pc-syn-2').version, '1.2.9', 'read from the message when the field is absent'); assert.equal(a('pc-syn-2').outdated, true); assert.equal(a('pc-syn-1').outdated, false);
    assert.equal(a('pc-syn-5').degraded, true); assert.equal(a('pc-syn-5').queue_files, 400);
    assert.deepEqual(r.summary, { total: 5, active: 3, delayed: 1, disconnected: 1, retired: 0, degraded: 1, outdated: 1 });
    assert.equal(r.agents[0].host, 'srv-syn-4', 'disconnected first');
    // retire
    assert.equal((await w.call('POST', '/soc/console/agents/retire', { role: 'analyst', body: { host: 'srv-syn-4', reason: 'decommissioned' } })).status, 403);
    let x = await w.call('POST', '/soc/console/agents/retire', { role: 'operator', body: { host: 'srv-syn-4' } }); assert.equal(x.status, 400); assert.match(x.body.error, /reason is required/);
    x = await w.call('POST', '/soc/console/agents/retire', { role: 'operator', user: 'nora.syn', body: { host: 'srv-syn-4', reason: 'server decommissioned (synthetic CHG-1)' } }); assert.equal(x.status, 200);
    assert.equal((await w.call('POST', '/soc/console/agents/retire', { role: 'operator', body: { host: 'SRV-SYN-4', reason: 'again please' } })).status, 409);
    assert.ok(w.api.audits.some((e) => e.action === 'soc.console.agent.retire' && e.target === 'srv-syn-4' && e.user === 'nora.syn'));
    r = (await w.call('GET', '/soc/console/agents', { role: 'analyst' })).body;
    assert.equal(r.summary.disconnected, 0); assert.equal(r.summary.retired, 1); assert.equal(a('srv-syn-4').retired.by, 'nora.syn');
    // a heartbeat after the retirement brings it back by itself
    w.hb[3][1] = -5; w.at(T + 10 * MIN); r = (await w.call('GET', '/soc/console/agents', { role: 'analyst' })).body;
    assert.notEqual(a('srv-syn-4').status, 'retired', 'a new heartbeat un-retires it');
    x = await w.call('POST', '/soc/console/agents/restore', { role: 'operator', body: { host: 'srv-syn-4', reason: 'back in service' } }); assert.equal(x.status, 200);
    assert.equal((await w.call('POST', '/soc/console/agents/restore', { role: 'operator', body: { host: 'srv-syn-4', reason: 'back in service' } })).status, 404);
  } finally { w.cleanup(); }
});

test('FIM: watched-path changes grouped per host + path, coverage stated, watch list admin-only and validated', async () => {
  const w = world(); try {
    let r = await w.call('GET', '/soc/console/fim?hours=24', { role: 'analyst', user: 'ana.syn' }); assert.equal(r.status, 200);
    const f = r.body;
    assert.equal(f.changes.length, 2, 'the startup link (twice = one row) and the Run key; the document is not watched');
    const st = f.changes.find((c) => /Startup/.test(c.path)); assert.equal(st.count, 2); assert.equal(st.host, 'pc-syn-1'); assert.deepEqual(st.techniques, ['T1547.001']);
    assert.ok(f.changes.some((c) => c.host === 'web-syn-1' && /CurrentVersion\\Run/.test(c.path)));
    assert.equal(f.hosts_changed, 2); assert.equal(f.coverage.hosts, 3); assert.match(f.note, /not proof it is unchanged/);
    assert.ok(w.api.audits.some((e) => e.action === 'soc.console.fim' && e.user === 'ana.syn'));
    assert.equal((await w.call('GET', '/soc/console/fim?hours=999', { role: 'analyst' })).status, 400);
    assert.equal((await w.call('GET', '/soc/console/fim', { role: 'viewer' })).status, 403);
    assert.equal((await w.call('POST', '/soc/console/fim/watch', { role: 'operator', body: { paths: ['\\documents\\'] } })).status, 403);
    r = await w.call('POST', '/soc/console/fim/watch', { role: 'admin', body: { paths: ['ab'] } }); assert.equal(r.status, 400); assert.match(r.body.error, /paths\[0\] must be 4-200/);
    r = await w.call('POST', '/soc/console/fim/watch', { role: 'admin', body: { paths: [] } }); assert.equal(r.status, 400);
    r = await w.call('POST', '/soc/console/fim/watch', { role: 'admin', user: 'syed', body: { paths: ['\\Documents\\', '\\documents\\'] } }); assert.deepEqual(r.body.paths, ['\\Documents\\'], 'de-duplicated, case-insensitive');
    assert.ok(w.api.audits.some((e) => e.action === 'soc.console.fim.watch' && e.user === 'syed'));
    const f2 = (await w.call('GET', '/soc/console/fim', { role: 'analyst' })).body; assert.equal(f2.changes.length, 1); assert.match(f2.changes[0].path, /report\.docx/);
  } finally { w.cleanup(); }
});

test('ingest against the hour; overview counts for viewers; live events for analysts only', async () => {
  let w = world(); try {
    let o = (await w.call('GET', '/soc/console', { role: 'viewer' })).body;
    assert.equal(o.named, false); assert.ok(o.agents.summary && !o.agents.agents, 'viewer: counts only'); assert.equal(o.fim.changes, 2); assert.ok(!Array.isArray(o.fim.changes));
    assert.ok(o.ingest.per_minute >= 100 && Math.abs(o.ingest.z) < 3); assert.equal(o.ingest.quiet, false);
    assert.equal((await w.call('GET', '/soc/console/live', { role: 'viewer' })).status, 403, 'raw events are personal data');
    assert.equal((await w.call('GET', '/soc/console/live', { role: 'analyst' })).body.events.length, 1);
  } finally { w.cleanup(); }
  w = world({ perMin: (i) => (i >= 57 ? 0 : 100) }); try {
    const g = (await w.call('GET', '/soc/console', { role: 'viewer' })).body.ingest;
    assert.equal(g.per_minute, 0); assert.equal(g.quiet, true); assert.ok(g.z <= -3); assert.match(g.note, /check that collection is running/);
  } finally { w.cleanup(); }
  assert.equal(K.cmpVer('1.10.0', '1.9.9'), 1); assert.equal(K.cmpVer('1.2', '1.2.0'), 0);
});
