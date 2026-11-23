// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Database Health Statement (engine/db-audit/statement.js): verdicts from the SIEM readings for a complaint window - healthy
// (with the evidence), database (blocking, plan regression, waits above normal, errors), server (CPU / memory), network
// (timeouts from the client in the alert log, firewall blocks), not measurable (too few readings) - validation, roles,
// audit, routing to a team as a case. Stub ClickHouse answering by query tag; synthetic data.
const test = require('node:test');
const assert = require('node:assert/strict');
const st = require('../engine/db-audit/statement');

const NOW = Date.UTC(2026, 9, 26, 10, 0);
function memState() {
  const cols = {};
  return { collection(n) { const m = cols[n] || (cols[n] = new Map()); return { get: (id) => m.get(id), put: (d) => m.set(d.id, d), remove: (id) => m.delete(id), all: (f) => [...m.values()].filter(f || (() => true)) }; } };
}
const HEALTHY = {
  st_cov: [{ buckets: 12, n: 400, h: 'db1' }], st_updown: [{ action: 'health-sample', n: 12, last: NOW - 60000 }],
  st_load: [{ aas: 2.1, aas_max: 3.4, cpu: 1.2, n: 60 }], st_load_b: [{ aas: 2.0, n: 2000 }],
  st_wc: [{ c: 'User I/O', ms: 4, ts_s: 0.6, n: 60 }, { c: 'Commit', ms: 2, ts_s: 0.1, n: 60 }], st_wc_b: [{ c: 'User I/O', ms: 3.8, ts_s: 0.5 }, { c: 'Commit', ms: 1.9, ts_s: 0.1 }],
  st_waits: [{ e: 'db file sequential read', c: 'User I/O', ms: 4, tm: 30 }], st_sess: [{ total: 220, lim: 600, active: 9 }], st_block: [{ n: 0 }], st_long: [{ n: 0 }],
  st_sql: [{ s: 'a1b2c3d4e5f6g', md: 'claims-api', el: 40, ex: 900 }], st_plans: [], st_alert: [{ tail: '' }], st_host: [{ cpu: 41, memfree: 9000, memtot: 65536, n: 60 }],
  st_srv: [{ loadpc: 0.4, memav: 0.3, ip: '10.10.5.20', n: 12 }], st_fw: [{ action: 'allowed', n: 5200, ports: ['1521'] }],
};
function harness(answers) {
  const calls = [], routes = {}, audits = [], made = [];
  const ch = { query: async (sql, p) => { const tag = /^\/\*q:([a-z_]+)\*\//.exec(sql)[1]; calls.push({ tag, sql, p }); return (answers[tag] || []).map((r) => Object.assign({}, r)); } };
  const cases = { create: (i, by) => { const c = Object.assign({ id: 'CASE-000' + (made.length + 1), by }, i); made.push(c); return c; } };
  st.register({ route: (m, p, fn) => { routes[m + ' ' + p] = fn; } }, { ch, state: memState(), cases, now: () => NOW, config: {}, log: { warn() {} } });
  const RANK = { viewer: 1, analyst: 2, operator: 3, admin: 4 };
  const call = async (m, path, b, role = 'operator', params = {}) => {
    let out = null;
    const ctx = { body: b, params, query: {}, role, user: 'dba.syn', ok: (x) => { out = { status: 200, body: x }; return out; }, fail: (s, msg) => { out = { status: s, error: msg }; return out; },
      need: (r) => { if ((RANK[role] || 0) < RANK[r]) { out = { status: 403, error: 'requires ' + r }; return false; } return true; }, audit: (a, t, d) => audits.push({ a, t, d }) };
    await routes[m + ' /api/soc' + path](ctx); return out;
  };
  return { call, calls, audits, made };
}
const W = { instance: 'orclprd', from: '2026-10-26T08:00:00Z', to: '2026-10-26T09:00:00Z', client_ip: '10.20.1.15', app: 'Claims portal', complaint: 'slow saving claims', ticket: 'INC-4411' };

test('healthy: up, load and waits within normal, no locks / plan / errors, firewall allowed - with the evidence', async () => {
  const h = harness(HEALTHY);
  const r = await h.call('POST', '/db/statements', W);
  assert.equal(r.status, 200); const s = r.body;
  assert.equal(s.conclusion, 'healthy'); assert.match(s.conclusion_text, /ORCLPRD was healthy in this window/);
  assert.equal(s.coverage, 100); assert.match(s.id, /^DHS-20261026-\d{3}$/); assert.match(s.digest, /^sha256:[0-9a-f]{64}$/); assert.equal(s.prepared_by, 'dba.syn');
  const t = s.checks.map((c) => c.title).join(' | ');
  assert.match(t, /Average active sessions 2\.1 - within its normal \(2 at these hours/); assert.match(t, /Wait times were within their normal range/);
  assert.match(t, /No session was blocked/); assert.match(t, /firewall allowed every connection between 10\.20\.1\.15 and 10\.10\.5\.20/);
  assert.match(t, /No dropped connection from 10\.20\.1\.15/); assert.match(t, /server had capacity to spare/);
  assert.ok(s.checks.every((c) => c.reading), 'each check names its reading');
  const fw = h.calls.find((c) => c.tag === 'st_fw'); assert.ok(!fw.sql.includes('10.20.1.15'), 'IPs are parameters'); assert.equal(fw.p.c.value, '10.20.1.15'); assert.equal(fw.p.d.value, '10.10.5.20', 'database IP from the server read');
  const lb = h.calls.find((c) => c.tag === 'st_load_b'); assert.deepEqual(lb.p.hours.value, [8], 'baseline: the same hours of the previous 7 days'); assert.equal(lb.p.bf.value, Date.parse(W.from) - 7 * 86400000);
  assert.deepEqual(h.audits.at(-1), { a: 'db.statement.create', t: s.id, d: { instance: 'ORCLPRD', from: '2026-10-26T08:00:00.000Z', to: '2026-10-26T09:00:00.000Z', client_ip: '10.20.1.15', conclusion: 'healthy', digest: s.digest } });
});

test('network: the database recorded timeouts from this client and the firewall blocked some connections', async () => {
  const h = harness(Object.assign({}, HEALTHY, {
    st_alert: [{ tail: 'Fatal NI connect error 12170.\n  TNS-12535: TNS:operation timed out\n  Client address: (ADDRESS=(PROTOCOL=tcp)(HOST=10.20.1.15)(PORT=51234))\nFatal NI connect error 12170.\n  TNS-12535: TNS:operation timed out\n  Client address: (ADDRESS=(PROTOCOL=tcp)(HOST=10.20.1.15)(PORT=51290))' }],
    st_fw: [{ action: 'allowed', n: 5000 }, { action: 'blocked', n: 37 }] }));
  const s = (await h.call('POST', '/db/statements', W)).body;
  assert.equal(s.conclusion, 'network');
  assert.ok(s.checks.some((c) => c.area === 'network' && c.status === 'issue' && /recorded 2 dropped \/ timed-out connection\(s\) from 10\.20\.1\.15/.test(c.title)));
  assert.ok(s.checks.some((c) => /firewall blocked 37 connection/.test(c.title)));
  assert.ok(!s.checks.some((c) => c.area === 'database' && c.status === 'issue'), 'the database itself is clean');
});

test('database: blocking, plan regression, Concurrency waits above normal, serious errors; server short of CPU', async () => {
  const h = harness(Object.assign({}, HEALTHY, {
    st_block: [{ n: 14, w: 420, md: 'claims-api', sq: 'f00f00f00f00f' }], st_plans: [{ s: 'p1p1p1p1p1p1p', o: '12', nw: '480', md: 'claims-api' }],
    st_wc: [{ c: 'Concurrency', ms: 40, ts_s: 2.5 }], st_wc_b: [{ c: 'Concurrency', ms: 3, ts_s: 0.1 }],
    st_alert: [{ tail: '2026-10-26T08:12:00Z ORA-00060: Deadlock detected.\n2026-10-26T08:30:00Z ORA-04031: unable to allocate 4096 bytes of shared memory' }],
    st_host: [{ cpu: 97, memfree: 2000, memtot: 65536 }] }));
  const s = (await h.call('POST', '/db/statements', W)).body;
  assert.equal(s.conclusion, 'mixed'); assert.deepEqual(s.areas.sort(), ['database', 'server']);
  const t = s.checks.filter((c) => c.status === 'issue').map((c) => c.title).join(' | ');
  assert.match(t, /blocked by locks \(14 reading\(s\), longest 420 s\)/); assert.match(t, /changed execution plan and became slower/); assert.match(t, /Concurrency waits 40 ms .*13\.3× normal/);
  assert.match(t, /Serious database errors/); assert.match(t, /short of capacity/);
  assert.ok(s.checks.find((c) => /changed execution plan/.test(c.title)).evidence[0].includes('12 → 480 ms per execution (claims-api)'));
});

test('not measurable: too few readings - never "healthy"; checks without readings say not measured', async () => {
  const h = harness({ st_cov: [{ buckets: 1, n: 3 }] });
  const s = (await h.call('POST', '/db/statements', Object.assign({}, W, { client_ip: undefined }))).body;
  assert.equal(s.conclusion, 'not_measurable'); assert.match(s.conclusion_text, /readings for only 8% of the window/);
  assert.ok(s.checks.some((c) => c.status === 'not_measured' && /load not measured/.test(c.title)));
  assert.ok(s.checks.some((c) => c.status === 'not_measured' && /CPU and memory not measured/.test(c.title)));
});

test('validation, roles, list / get, routing to a team opens a case', async () => {
  const h = harness(HEALTHY);
  const bad = async (b, rx) => { const r = await h.call('POST', '/db/statements', Object.assign({}, W, b)); assert.equal(r.status, 400, JSON.stringify(b)); assert.match(r.error, rx); };
  await bad({ to: '2026-10-26T07:00:00Z' }, /after from/);
  await bad({ from: '2026-10-24T08:00:00Z' }, /at most 24 hours/);
  await bad({ to: '2026-10-27T09:00:00Z', from: '2026-10-27T08:00:00Z' }, /future/);
  await bad({ client_ip: 'app01' }, /client_ip must be an IP/);
  await bad({ instance: "x'; drop" }, /instance must be/);
  await bad({ from: 'yesterday' }, /from must be a date-time/);
  assert.equal((await h.call('POST', '/db/statements', W, 'viewer')).status, 403, 'viewer refused');
  const s = (await h.call('POST', '/db/statements', W)).body;
  assert.equal((await h.call('GET', '/db/statements', null, 'operator')).body.items[0].id, s.id);
  assert.equal((await h.call('GET', '/db/statements/:id', null, 'viewer', { id: s.id })).status, 403);
  assert.equal((await h.call('GET', '/db/statements/:id', null, 'operator', { id: 'nope' })).status, 400);
  assert.equal((await h.call('POST', '/db/statements/:id/route', { team: 'hr', note: 'x' }, 'operator', { id: s.id })).status, 400);
  assert.equal((await h.call('POST', '/db/statements/:id/route', { team: 'network', note: '' }, 'operator', { id: s.id })).status, 400, 'a note is required');
  const r = await h.call('POST', '/db/statements/:id/route', { team: 'application', note: 'database healthy in the window - please check the claims-api connection pool' }, 'operator', { id: s.id });
  assert.equal(r.status, 200); assert.equal(r.body.routing[0].team, 'application'); assert.equal(r.body.routing[0].case_id, 'CASE-0001');
  assert.match(h.made[0].title, /^\[Application\] ORCLPRD 2026-10-26T08:00-09:00: Claims portal/); assert.match(h.made[0].description, /was healthy in this window[\s\S]*connection pool[\s\S]*DHS-/);
  assert.equal(h.made[0].severity, 1);
  assert.deepEqual(h.audits.at(-1), { a: 'db.statement.route', t: s.id, d: { team: 'application', case_id: 'CASE-0001' } });
});
