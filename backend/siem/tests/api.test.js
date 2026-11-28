// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// API server, HTTP ingest, core routes (with a fake ClickHouse), live tail SSE, and a full engine integration run.
// All data is synthetic.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const http = require('node:http');
const net = require('node:net');
const zlib = require('node:zlib');
const { createApi } = require('../engine/api/server');
const { createHttpIngest } = require('../engine/collect/http-ingest');
const { createParser } = require('../engine/parse');
const { createPipeline } = require('../engine/pipeline');
const { createSearch } = require('../engine/api/search');
const { createTail } = require('../engine/api/tail');
const { createCH } = require('../engine/store/clickhouse');
const { createSourceTracker } = require('../engine/collect/tracker');
const coreRoutes = require('../engine/api/routes');
const { startFakeCH } = require('./helpers/fake-ch');

const SECRET = 'synthetic-proxy-secret-0123456789';
const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'sentra-siem-api-'));
const waitFor = async (fn, ms = 5000) => { const t = Date.now(); while (!fn()) { if (Date.now() - t > ms) throw new Error('timeout'); await new Promise((r) => setTimeout(r, 20)); } };

// Requests through the proxy carry a portal identity (as nginx would set) and a JSON content type unless a test
// overrides them; `identity: false` sends the proxy secret with no identity at all.
function req(port, method, p, { body, headers = {}, secret = SECRET, identity = true } = {}) {
  return new Promise((resolve, reject) => {
    const data = body === undefined ? null : Buffer.isBuffer(body) ? body : Buffer.from(typeof body === 'string' ? body : JSON.stringify(body));
    const who = secret && identity ? { 'X-Auth-User': 'test-user', 'X-Auth-Role': 'analyst' } : {};   // raw-event search / tail need analyst (PDPL)
    const ct = data && !p.startsWith('/ingest/') ? { 'Content-Type': 'application/json' } : {};
    const r = http.request({ host: '127.0.0.1', port, method, path: p, headers: { ...(data ? { 'Content-Length': data.length } : {}), ...ct, ...(secret ? { 'X-Sentra-Proxy-Secret': secret } : {}), ...who, ...headers } }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => {
        const text = Buffer.concat(chunks).toString();
        let json = null;
        try { json = JSON.parse(text); } catch { /* not json */ }
        resolve({ status: res.statusCode, headers: res.headers, text, json });
      });
    });
    r.on('error', reject);
    if (data) r.write(data);
    r.end();
  });
}

test('api server: routing, params, body parsing, 404/405/413/400, roles, audit, handler return values', async () => {
  const audits = [];
  const api = createApi({ port: 0, audit: (e) => audits.push(e), proxySecret: SECRET });
  api.route('GET', '/api/soc/things/:id', (ctx) => ({ id: ctx.params.id, q: ctx.query.x, user: ctx.user, role: ctx.role, ip: ctx.ip }));
  api.route('POST', '/api/soc/things', (ctx) => { ctx.need('operator'); ctx.audit('thing.create', 'T1', { n: ctx.body.n }); ctx.ok({ ok: true, n: ctx.body.n }); }, { maxBody: 100 });
  api.route('POST', '/api/soc/admin', (ctx) => { ctx.need('admin'); return { ok: 1 }; });
  api.route('GET', '/api/soc/boom', () => { throw new Error('secret internals'); });
  api.route('GET', '/api/soc/empty', () => undefined);
  api.route('GET', '/api/soc/rest/*', (ctx) => ({ rest: ctx.params['*'] }));
  const { port } = await api.start();
  try {
    let r = await req(port, 'GET', '/api/soc/things/a%20b?x=1', { headers: { 'X-Auth-User': 'analyst1', 'X-Auth-Role': 'Operator', 'X-Real-IP': '198.51.100.7' } });
    assert.equal(r.status, 200);
    assert.deepEqual(r.json, { id: 'a b', q: '1', user: 'analyst1', role: 'operator', ip: '198.51.100.7' });
    assert.equal(r.headers['cache-control'], 'no-store');
    r = await req(port, 'GET', '/api/soc/nope');
    assert.equal(r.status, 404);
    r = await req(port, 'DELETE', '/api/soc/things/1');
    assert.equal(r.status, 405);
    r = await req(port, 'POST', '/api/soc/things', { body: '{bad', headers: { 'X-Auth-Role': 'operator' } });
    assert.equal(r.status, 400);
    assert.deepEqual(r.json, { error: 'invalid JSON body', errors: ['invalid JSON body'] });
    r = await req(port, 'POST', '/api/soc/things', { body: { n: 'x'.repeat(200) }, headers: { 'X-Auth-Role': 'operator' } });
    assert.equal(r.status, 413);
    r = await req(port, 'POST', '/api/soc/things', { body: { n: 5 }, headers: { 'X-Auth-Role': 'viewer', 'X-Auth-User': 'v' } });
    assert.equal(r.status, 403);
    r = await req(port, 'POST', '/api/soc/things', { body: { n: 5 }, headers: { 'X-Auth-Role': 'admin', 'X-Auth-User': 'boss' } });
    assert.deepEqual(r.json, { ok: true, n: 5 });
    const writes = audits.filter((e) => e.action !== 'access.denied');
    assert.equal(writes.length, 1);
    assert.equal(writes[0].by, 'boss');
    assert.equal(writes[0].action, 'thing.create');
    assert.deepEqual(writes[0].detail, { n: 5 });
    // the viewer's refused write is itself audited
    assert.ok(audits.some((e) => e.action === 'access.denied' && e.by === 'v' && e.detail.status === 403));
    r = await req(port, 'POST', '/api/soc/admin', { headers: { 'X-Auth-Role': 'operator' } });
    assert.equal(r.status, 403);
    r = await req(port, 'GET', '/api/soc/boom');
    assert.equal(r.status, 500);
    assert.equal(r.json.error, 'internal error');
    r = await req(port, 'GET', '/api/soc/empty');
    assert.equal(r.status, 204);
    r = await req(port, 'GET', '/api/soc/rest/a/b/c');
    assert.deepEqual(r.json, { rest: 'a/b/c' });

    // fail closed: a valid proxy secret with no identity, or an unknown role, reads nothing (and is audited)
    const before = audits.length;
    r = await req(port, 'GET', '/api/soc/things/1', { identity: false });
    assert.equal(r.status, 401);
    r = await req(port, 'GET', '/api/soc/things/1', { headers: { 'X-Auth-User': 'u', 'X-Auth-Role': 'guest' } });
    assert.equal(r.status, 401);
    r = await req(port, 'GET', '/api/soc/things/1', { headers: { 'X-Auth-User': '', 'X-Auth-Role': 'admin' } });
    assert.equal(r.status, 401);
    assert.equal(audits.slice(before).filter((e) => e.action === 'access.denied' && e.detail.status === 401).length, 3);

    // CSRF: cross-site / same-site browser requests and non-JSON bodies are refused on writes
    const boss = { 'X-Auth-User': 'boss', 'X-Auth-Role': 'admin' };
    r = await req(port, 'POST', '/api/soc/things', { body: { n: 1 }, headers: { ...boss, 'Sec-Fetch-Site': 'cross-site' } });
    assert.equal(r.status, 403);
    r = await req(port, 'POST', '/api/soc/things', { body: { n: 1 }, headers: { ...boss, 'Sec-Fetch-Site': 'same-site' } });
    assert.equal(r.status, 403);
    r = await req(port, 'POST', '/api/soc/things', { body: '{"a":"=b"}', headers: { ...boss, 'Content-Type': 'text/plain' } });
    assert.equal(r.status, 403);
    assert.match(r.json.error, /application\/json/);
    // an empty HTML form (no fields, Content-Length 0) still declares a form type - refused too (security review)
    r = await req(port, 'POST', '/api/soc/things', { headers: { ...boss, 'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': 0 } });
    assert.equal(r.status, 403); assert.match(r.json.error, /application\/json/);
    r = await req(port, 'POST', '/api/soc/things', { headers: { ...boss, 'Content-Type': 'text/plain', 'Content-Length': 0 } });
    assert.equal(r.status, 403);
    r = await req(port, 'POST', '/api/soc/things', { headers: { ...boss, 'Content-Length': 0 } });
    assert.notEqual(r.status, 403, 'a body-less call with no form type (the engines calling each other) is not a form');
    r = await req(port, 'POST', '/api/soc/things', { body: { n: 2 }, headers: { ...boss, 'Sec-Fetch-Site': 'same-origin', 'Content-Type': 'application/json; charset=utf-8' } });
    assert.deepEqual(r.json, { ok: true, n: 2 });
  } finally { await api.stop(); }
});

test('api server: audit detail is bounded', async () => {
  const audits = [];
  const api = createApi({ port: 0, audit: (e) => audits.push(e), proxySecret: SECRET });
  api.route('POST', '/api/soc/big', (ctx) => { ctx.need('operator'); ctx.audit('big', 'x', ctx.body); return { ok: true }; });
  const { port } = await api.start();
  try {
    await req(port, 'POST', '/api/soc/big', { body: { blob: 'y'.repeat(100000) }, headers: { 'X-Auth-User': 'o', 'X-Auth-Role': 'operator' } });
    const e = audits.find((x) => x.action === 'big');
    assert.equal(e.detail.truncated, true);
    assert.ok(e.detail.preview.length <= 4096);
    assert.ok(JSON.stringify(e).length < 6000);
  } finally { await api.stop(); }
});

test('api server: default audit appends JSON lines to <data>/state/audit.jsonl', async () => {
  const dir = tmp();
  const api = createApi({ port: 0, dataDir: dir, proxySecret: SECRET });
  api.route('POST', '/api/soc/x', (ctx) => { ctx.audit('x.do', 'id1', { a: 1 }); return { ok: true }; });
  const { port } = await api.start();
  try {
    await req(port, 'POST', '/api/soc/x', { body: {}, headers: { 'X-Auth-User': 'u1', 'X-Auth-Role': 'admin' } });
    const lines = fs.readFileSync(path.join(dir, 'state', 'audit.jsonl'), 'utf8').trim().split('\n').map((l) => JSON.parse(l));
    assert.equal(lines.length, 1);
    assert.equal(lines[0].by, 'u1');
    assert.equal(lines[0].action, 'x.do');
  } finally { await api.stop(); }
});

function ingestSetup() {
  const config = { sources: [{ id: 'test-win', type: 'windows' }], syslog: { tz_offset_min: 0 }, ingest: { max_mb: 5 } };
  Object.defineProperty(config, 'secrets', { value: { ingest_tokens: { 'test-win': 'synthetic-token-1', 'test-json': 'synthetic-token-2' } } });
  const events = [];
  const pipeline = createPipeline();
  pipeline.use((ev) => events.push(ev));
  const ingest = createHttpIngest({ config, parser: createParser(), pipeline });
  const api = createApi({ port: 0, audit: () => {}, proxySecret: SECRET });
  ingest.register(api);
  return { api, events, ingest };
}

test('http ingest: token check, NDJSON, JSON array, gzip, raw text lines, errors', async () => {
  const { api, events, ingest } = ingestSetup();
  const { port } = await api.start();
  const W = (u) => ({ Channel: 'Security', EventID: 4625, TimeCreated: '2024-05-01T10:00:00Z', Computer: 'TEST-WS-01', EventData: { TargetUserName: u, IpAddress: '203.0.113.5', Status: '0xc000006d' } });
  try {
    let r = await req(port, 'POST', '/ingest/test-win', { body: JSON.stringify(W('a')) + '\n' });
    assert.equal(r.status, 401);
    r = await req(port, 'POST', '/ingest/test-win', { body: '{}', headers: { 'X-Sentra-Token': 'synthetic-token-2' } });
    assert.equal(r.status, 401);
    r = await req(port, 'POST', '/ingest/unknown-src', { body: '{}', headers: { 'X-Sentra-Token': 'x' } });
    assert.equal(r.status, 401);
    r = await req(port, 'POST', '/ingest/bad%20id', { body: '{}', headers: { 'X-Sentra-Token': 'x' } });
    assert.equal(r.status, 400);
    r = await req(port, 'POST', '/ingest/test-win', { body: [W('a'), W('b')].map((o) => JSON.stringify(o)).join('\n') + '\n\n', headers: { 'X-Sentra-Token': 'synthetic-token-1' } });
    assert.deepEqual(r.json, { ok: true, accepted: 2, rejected: 0, errors: [] });
    assert.equal(events.length, 2);
    assert.equal(events[0].collector, 'agent');
    assert.equal(events[0].action, 'logon-failed');
    assert.equal(events[0].src_id, 'test-win');
    r = await req(port, 'POST', '/ingest/test-json', { body: JSON.stringify([{ message: 'synthetic', user: 'X' }, 'plain synthetic text line', 42]), headers: { 'X-Sentra-Token': 'synthetic-token-2' } });
    assert.deepEqual(r.json, { ok: true, accepted: 2, rejected: 1, errors: ['item 2: expected object or string'] });
    assert.equal(events[2].user, 'x');
    assert.equal(events[3].action, 'unparsed');
    assert.equal(events[3].collector, 'http');
    const gz = zlib.gzipSync(Buffer.from(JSON.stringify(W('c')) + '\n'));
    r = await req(port, 'POST', '/ingest/test-win', { body: gz, headers: { 'X-Sentra-Token': 'synthetic-token-1', 'Content-Encoding': 'gzip' } });
    assert.equal(r.json.accepted, 1);
    assert.equal(events[4].user, 'c');
    r = await req(port, 'POST', '/ingest/test-win', { body: '[{"a":', headers: { 'X-Sentra-Token': 'synthetic-token-1' } });
    assert.equal(r.status, 400);
    r = await req(port, 'POST', '/ingest/test-win', { body: Buffer.alloc(6 * 1024 * 1024, 97), headers: { 'X-Sentra-Token': 'synthetic-token-1' } });
    assert.equal(r.status, 413);
    assert.equal(ingest.stats().auth_failures, 3);
  } finally { await api.stop(); }
});

function coreSetup(fake, extra = {}) {
  const config = { clickhouse: { database: 'siem' }, timezone: 'Asia/Riyadh', sources: [{ id: 'test-fw', type: 'fortigate' }], syslog: { host: '127.0.0.1', udp: { port: 5514 }, tcp: { port: 5514 }, tls: { enabled: false, port: 6514 } }, node_name: 'test-node' };
  const ch = createCH({ url: fake.url, database: 'siem', timeout_ms: 2000 });
  const pipeline = createPipeline();
  const tracker = createSourceTracker();
  const tail = createTail({ maxClients: 2, maxEps: 1000 });
  pipeline.use(tracker.stage, 'sources');
  pipeline.use(tail.stage, 'tail');
  const search = createSearch({ ch, config });
  const api = createApi({ port: 0, audit: () => {}, proxySecret: SECRET });
  coreRoutes.register(api, { ch, config, search, tail, pipeline, tracker, parser: createParser(), writer: null, spool: null, syslog: null, ingest: null, ...extra });
  return { api, pipeline, ch, search };
}

test('core routes: search / histogram / top compile to parameterised SQL; errors are 400 with errors[]', async () => {
  const fake = await startFakeCH({
    respond: (q) => {
      if (/intDiv/.test(q)) return { data: [{ b: 0, n: 5 }, { b: 2, n: 7 }] };
      if (/GROUP BY v/.test(q)) return { data: [{ v: 'alice', n: 9 }, { v: 'bob', n: 3 }] };
      if (/FROM siem.events/.test(q)) return { data: [{ ts: '2024-05-01T10:00:00.000Z', id: 'x', user: 'alice' }], rows_before_limit_at_least: 1234 };
      return null;
    },
  });
  const { api } = coreSetup(fake);
  const { port } = await api.start();
  try {
    let r = await req(port, 'POST', '/api/soc/search', { body: { q: 'user:Alice ip:10.0.0.0/8', from: '2024-05-01T00:00:00.000Z', to: '2024-05-02T00:00:00.000Z', limit: 50, order: 'asc' } });
    assert.equal(r.status, 200);
    assert.equal(r.json.total_estimate, 1234);
    assert.equal(r.json.rows[0].user, 'alice');
    assert.equal(typeof r.json.took_ms, 'number');
    assert.match(r.json.sql_hint, /ORDER BY ts ASC LIMIT \{lim:UInt32\}/);
    let sent = fake.requests.at(-1);
    assert.equal(sent.params.param_q1, 'alice');
    assert.equal(sent.params.param_q2, '10.0.0.0/8');
    assert.equal(sent.params.param_t_from, String(Date.UTC(2024, 4, 1)));
    assert.equal(sent.params.param_lim, '50');
    assert.equal(sent.params.readonly, '2');
    assert.doesNotMatch(sent.body, /alice|10\.0\.0\.0/);
    // viewers may not search raw events (sign-ins / mailbox / logons of named people - PDPL)
    r = await req(port, 'POST', '/api/soc/search', { body: { q: 'user:Alice' }, headers: { 'X-Auth-Role': 'viewer' } });
    assert.equal(r.status, 403, 'viewers cannot search raw events');
    r = await req(port, 'POST', '/api/soc/search', { body: { q: 'nosuchfield:1' } });
    assert.equal(r.status, 400);
    assert.match(r.json.errors[0], /unknown field/);
    r = await req(port, 'POST', '/api/soc/search', { body: { q: '', limit: 5000 } });
    assert.equal(r.status, 400);
    r = await req(port, 'POST', '/api/soc/search', { body: { fields: ['user', 'raw) FROM x --'] } });
    assert.equal(r.status, 400);
    const T0 = Date.UTC(2024, 4, 1);
    r = await req(port, 'POST', '/api/soc/histogram', { body: { q: '', from: new Date(T0).toISOString(), to: T0 + 60000, buckets: 6 } });
    assert.equal(r.status, 200);
    assert.deepEqual(r.json.buckets, [{ t: T0, n: 5 }, { t: T0 + 10000, n: 0 }, { t: T0 + 20000, n: 7 }, { t: T0 + 30000, n: 0 }, { t: T0 + 40000, n: 0 }, { t: T0 + 50000, n: 0 }]);
    assert.equal(fake.requests.at(-1).params.param_step, '10000');
    r = await req(port, 'POST', '/api/soc/top', { body: { q: 'action:logon-failed', field: 'user', limit: 5, from: 'now-1h' } });
    assert.deepEqual(r.json.values, [{ v: 'alice', n: 9 }, { v: 'bob', n: 3 }]);
    r = await req(port, 'POST', '/api/soc/top', { body: { field: 'fields.logon_type' } });
    sent = fake.requests.at(-1);
    assert.match(sent.body, /fields\[\{fkey:String\}\] AS v/);
    assert.equal(sent.params.param_fkey, 'logon_type');
    r = await req(port, 'POST', '/api/soc/top', { body: { field: 'raw' } });
    assert.equal(r.status, 400);
    // positional form used by detect/scheduled
    const { search } = coreSetup(fake);
    const res = await search('user:alice', Date.UTC(2024, 4, 1), Date.UTC(2024, 4, 2), { limit: 1000, offset: 2000, order: 'asc' });
    assert.equal(res.total_estimate, 1234);
    assert.equal(fake.requests.at(-1).params.param_off, '2000');
  } finally { await api.stop(); await fake.close(); }
});

test('core routes: sources and health shapes; ClickHouse errors surface as 502', async () => {
  const fake = await startFakeCH({
    respond: (q) => {
      if (/stats_minute/.test(q)) return { data: [{ src_id: 'test-fw', src_type: 'fortigate', events: 1000, parse_errors: 10, last_minute: new Date(Date.now() - 60000).toISOString() }] };
      if (/version\(\)/.test(q)) return { data: [{ version: '25.3.1' }] };
      if (/FROM batches/.test(q)) return { data: [{ seq: 1, sha256: 'a', prev_sha256: '0'.repeat(64), ts: '2024-05-01T10:00:00Z' }, { seq: 2, sha256: 'b', prev_sha256: 'a', ts: '2024-05-01T10:00:01Z' }] };
      if (/siem.events/.test(q)) return { status: 500, body: 'Code: 241. DB::Exception: Memory limit (synthetic)' };
      return null;
    },
  });
  const writer = { stats: () => ({ seq: 2, chain_head: 'b', spool_failures: 0 }), node: 'test-node' };
  const spool = { stats: () => ({ files: 0, bytes: 0, mb: 0, dropped_batches: 0 }) };
  const { api, pipeline } = coreSetup(fake, { writer, spool });
  const { port } = await api.start();
  try {
    pipeline.emit({ src_id: 'test-new', src_type: 'linux', collector: 'syslog-udp', host: 'test-host-01', action: 'log', tags: [], fields: {} });
    let r = await req(port, 'GET', '/api/soc/sources');
    const byId = Object.fromEntries(r.json.sources.map((s) => [s.src_id, s]));
    assert.equal(byId['test-fw'].events_today, 1000);
    assert.equal(byId['test-fw'].parse_error_rate, 0.01);
    assert.equal(byId['test-fw'].status, 'ok');
    assert.equal(byId['test-fw'].src_type, 'fortigate');
    assert.equal(byId['test-new'].status, 'ok');
    assert.equal(byId['test-new'].collector, 'syslog-udp');
    r = await req(port, 'GET', '/api/soc/health');
    const h = r.json;
    assert.equal(h.clickhouse.ok, true);
    assert.equal(h.clickhouse.version, '25.3.1');
    assert.equal(h.integrity.ok, true);
    assert.equal(h.integrity.status, 'verified');
    assert.equal(h.integrity.chain_len, 2);
    assert.equal(h.spool.files, 0);
    assert.ok(Array.isArray(h.collectors) && h.collectors.some((c) => c.name === 'http-ingest'));
    assert.equal(typeof h.eps.now, 'number');
    assert.equal(h.engine.status, 'ok');
    assert.equal(h.detector.running, false);
    r = await req(port, 'POST', '/api/soc/search', { body: { q: '' } });
    assert.equal(r.status, 502);
    assert.match(r.json.error, /Memory limit/);
  } finally { await api.stop(); await fake.close(); }
});

function sse(port, p) {
  return new Promise((resolve, reject) => {
    const events = [];
    const r = http.get({ host: '127.0.0.1', port, path: p, headers: { 'X-Sentra-Proxy-Secret': SECRET, 'X-Auth-User': 'test-user', 'X-Auth-Role': 'analyst' } }, (res) => {
      let buf = '';
      res.on('data', (c) => {
        buf += c;
        let i;
        while ((i = buf.indexOf('\n\n')) >= 0) {
          const block = buf.slice(0, i);
          buf = buf.slice(i + 2);
          const ev = /^event: (.*)$/m.exec(block);
          const data = /^data: (.*)$/m.exec(block);
          if (ev && data) events.push({ event: ev[1], data: JSON.parse(data[1]) });
        }
      });
      resolve({ res, events, close: () => r.destroy() });
    });
    r.on('error', reject);
  });
}

test('tail: SSE stream with per-client JS filter from the same query language', async () => {
  const fake = await startFakeCH();
  const { api, pipeline } = coreSetup(fake);
  const { port } = await api.start();
  try {
    const bad = await req(port, 'GET', '/api/soc/tail?q=' + encodeURIComponent('user:('));
    assert.equal(bad.status, 400);
    const a = await sse(port, '/api/soc/tail?q=' + encodeURIComponent('action:logon-failed ip:203.0.113.0/24'));
    const b = await sse(port, '/api/soc/tail');
    assert.equal(a.res.headers['content-type'], 'text/event-stream; charset=utf-8');
    assert.equal(a.res.headers['x-accel-buffering'], 'no');
    await waitFor(() => a.events.length === 1 && b.events.length === 1); // hello
    const full = await req(port, 'GET', '/api/soc/tail');
    assert.equal(full.status, 503); // max 2 clients
    const base = { tags: [], fields: {}, raw: 'synthetic', message: '' };
    pipeline.emit({ ...base, action: 'logon-failed', src_ip: '203.0.113.9', user: 'x' });
    pipeline.emit({ ...base, action: 'logon', src_ip: '203.0.113.9', user: 'y' });
    pipeline.emit({ ...base, action: 'logon-failed', src_ip: '198.51.100.1', user: 'z' });
    await waitFor(() => b.events.length === 4);
    await waitFor(() => a.events.length === 2);
    await new Promise((r) => setTimeout(r, 100));
    assert.deepEqual(a.events.filter((e) => e.event === 'event').map((e) => e.data.user), ['x']);
    a.close(); b.close();
  } finally { await api.stop(); await fake.close(); }
});

test('proxy secret: /api/soc requires X-Sentra-Proxy-Secret; identity headers stripped otherwise; /health and /ingest exempt', async () => {
  const api = createApi({ port: 0, audit: () => {}, proxySecret: SECRET });
  api.route('GET', '/api/soc/health', (ctx) => ({ user: ctx.user, role: ctx.role }));
  api.route('GET', '/api/soc/who', (ctx) => ({ user: ctx.user, role: ctx.role }));
  api.route('POST', '/ingest/:src_id', (ctx) => { let denied = false; try { ctx.need('viewer'); } catch { denied = true; } return { user: ctx.user, denied }; }, { raw: true });
  const { port } = await api.start();
  const H = { 'X-Auth-User': 'mallory', 'X-Auth-Role': 'admin' };
  try {
    let r = await req(port, 'GET', '/api/soc/who', { headers: H });
    assert.deepEqual(r.json, { user: 'mallory', role: 'admin' });
    r = await req(port, 'GET', '/api/soc/who', { headers: H, secret: null });
    assert.equal(r.status, 401);
    assert.deepEqual(r.json.errors, ['missing or invalid proxy credentials']);
    r = await req(port, 'GET', '/api/soc/who', { headers: H, secret: SECRET + 'x' });
    assert.equal(r.status, 401);
    r = await req(port, 'GET', '/api/soc/nonexistent', { secret: null });
    assert.equal(r.status, 401);
    r = await req(port, 'GET', '/api/soc/health', { headers: H, secret: null });
    assert.deepEqual(r.json, { user: '', role: '' });
    r = await req(port, 'POST', '/ingest/x', { body: '{}', headers: H, secret: null });
    assert.deepEqual(r.json, { user: '', denied: true });
  } finally { await api.stop(); }
  // no secret configured → everything but /health refused, even with a header
  const api2 = createApi({ port: 0, audit: () => {} });
  api2.route('GET', '/api/soc/who', () => ({ ok: 1 }));
  api2.route('GET', '/api/soc/health', () => ({ ok: 1 }));
  const p2 = (await api2.start()).port;
  try {
    assert.equal((await req(p2, 'GET', '/api/soc/who', { secret: '' })).status, 401);
    assert.equal((await req(p2, 'GET', '/api/soc/who')).status, 401);
    assert.equal((await req(p2, 'GET', '/api/soc/health')).status, 200);
  } finally { await api2.stop(); }
});

test('http ingest: X-Sentra-Batch-Id de-duplication per source; agent heartbeat parsed', async () => {
  const { api, events, ingest } = ingestSetup();
  const { port } = await api.start();
  const line = JSON.stringify({ Channel: 'SentraAgent', EventID: 0, TimeCreated: '2024-05-01T10:00:00.000Z', Computer: 'test-ws-09.test.local', RecordId: 0, Level: 4, ProviderName: 'SentraAgent', EventData: { type: 'heartbeat', agent_version: '1.0.0', queue_files: '0' } }) + '\n';
  const H = { 'X-Sentra-Token': 'synthetic-token-1', 'X-Sentra-Batch-Id': 'batch-0001' };
  try {
    let r = await req(port, 'POST', '/ingest/test-win', { body: line, headers: H });
    assert.deepEqual(r.json, { ok: true, accepted: 1, rejected: 0, errors: [] });
    r = await req(port, 'POST', '/ingest/test-win', { body: line, headers: H });
    assert.deepEqual(r.json, { ok: true, duplicate: true, accepted: 0, rejected: 0, errors: [] });
    assert.equal(events.length, 1);
    assert.equal(events[0].action, 'agent-heartbeat');
    assert.equal(events[0].category, 'system');
    assert.ok(events[0].tags.includes('heartbeat'));
    assert.equal(events[0].fields.agent_version, '1.0.0', 'the SOC Console reads the agent version from the heartbeat'); assert.equal(events[0].fields.queue_files, '0');
    r = await req(port, 'POST', '/ingest/test-json', { body: '{"message":"synthetic"}', headers: { 'X-Sentra-Token': 'synthetic-token-2', 'X-Sentra-Batch-Id': 'batch-0001' } });
    assert.equal(r.json.accepted, 1); // same id, other source → not a duplicate
    r = await req(port, 'POST', '/ingest/test-win', { body: line, headers: { ...H, 'X-Sentra-Batch-Id': 'bad id with spaces' } });
    assert.equal(r.status, 400);
    assert.equal(ingest.stats().duplicates, 1);
  } finally { await api.stop(); }
});

test('LogRhythm manual import: simple + native shapes, NDJSON, dedupe, role and audit', async () => {
  const raised = [];
  const store = [];
  const alerts = { raise: (p) => { raised.push(p); store.push({ ...p, id: 'ALR-' + store.length }); }, all: (fn) => store.filter(fn) };
  const audits = [];
  const api = createApi({ port: 0, audit: (e) => audits.push(e), proxySecret: SECRET });
  require('../engine/api/lr-import').register(api, { alerts });
  const { port } = await api.start();
  const H = { 'X-Auth-Role': 'operator', 'X-Auth-User': 'op1' };
  try {
    const simple = [{ ts: '2024-05-01T10:00:00Z', alarm_name: 'Synthetic LR brute force', rule_id: 1001, host: 'test-dc-01', user: 'bob', src_ip: '203.0.113.5', severity: 3 }, { alarm_name: 'missing ts' }];
    let r = await req(port, 'POST', '/api/soc/lr/alarms', { body: simple, headers: H });
    assert.equal(r.status, 200);
    assert.equal(r.json.imported, 1);
    assert.equal(r.json.errors.length, 1);
    assert.equal(raised[0].source, 'logrhythm');
    assert.equal(raised[0].severity, 3);
    assert.equal(raised[0].rule_name, 'Synthetic LR brute force');
    r = await req(port, 'POST', '/api/soc/lr/alarms', { body: JSON.stringify(simple[0]) + '\n' + JSON.stringify({ alarm_id: 77, alarm_rule_name: 'Synthetic native', alarm_date: '2024-05-01T11:00:00Z', priority: 95 }) + '\n', headers: H });
    assert.equal(r.json.imported, 1);
    assert.equal(r.json.skipped, 1);
    assert.equal(raised[1].lr_alarm_id, '77');
    assert.equal(audits.at(-1).action, 'lr.import');
    r = await req(port, 'POST', '/api/soc/lr/alarms', { body: simple, headers: { 'X-Auth-Role': 'viewer' } });
    assert.equal(r.status, 403);
    r = await req(port, 'POST', '/api/soc/lr/alarms', { body: '[{', headers: H });
    assert.equal(r.status, 400);
  } finally { await api.stop(); }
});

test('integration: main() with fake ClickHouse — replayed syslog lines are parsed, detected, stored; graceful shutdown flushes', async () => {
  const fake = await startFakeCH({ respond: () => null });
  const dir = tmp();
  const ports = await Promise.all([0, 0].map(() => new Promise((r) => { const s = net.createServer().listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => r(p)); }); })));
  const cfgPath = path.join(dir, 'config.json');
  fs.writeFileSync(cfgPath, JSON.stringify({
    data_dir: path.join(dir, 'data'), log_level: 'error', api: { port: ports[0] },
    syslog: { udp: { enabled: false }, tcp: { port: ports[1] }, tz_offset_min: 0 },
    clickhouse: { url: fake.url, timeout_ms: 2000 }, writer: { batch_size: 50, flush_ms: 200 }, spool_max_mb: 10,
    sources: [{ id: 'test-lo', type: 'syslog', match: { ip: '127.0.0.1' } }],
  }));
  fs.writeFileSync(path.join(dir, 'secrets.json'), JSON.stringify({ clickhouse: { user: 'u', password: 'p' }, ingest_tokens: {}, proxy_secret: SECRET }));
  const { main } = require('../engine/main');
  const eng = await main({ configPath: cfgPath, installSignals: false });
  try {
    const { spawn } = require('node:child_process');
    const fixture = path.join(__dirname, 'fixtures', 'synthetic-mixed.log');
    const lines = fs.readFileSync(fixture, 'utf8').split('\n').filter((l) => l && !l.startsWith('#'));
    const child = spawn(process.execPath, [path.join(__dirname, 'replay.js'), '--file', fixture, '--port', String(ports[1]), '--rate', '5000'], { stdio: 'pipe' });
    const code = await new Promise((r) => child.on('exit', r));
    assert.equal(code, 0);
    await waitFor(() => eng.pipeline.stats().events >= lines.length, 8000);
    const h = await req(ports[0], 'GET', '/api/soc/health');
    assert.equal(h.status, 200);
    await eng.shutdown('test');
    const rows = fake.rows('siem.events');
    assert.equal(rows.length, lines.length);
    const types = new Set(rows.map((r) => r.src_type));
    for (const t of ['linux', 'fortigate', 'cisco', 'cef', 'nginx']) assert.ok(types.has(t), 'missing src_type ' + t);
    assert.ok(rows.every((r) => r.src_id === 'test-lo'));
    assert.ok(fake.rows('siem.batches').length >= 1);
    assert.ok(fake.rows('siem.stats_minute').length >= 1);
    assert.ok(fs.existsSync(path.join(dir, 'data', 'state', 'chain.json')));
    if (eng.detector) assert.ok(eng.detector.stats().events >= lines.length);
  } finally {
    await eng.shutdown('test');
    await fake.close();
  }
});

test('collector-health alerting mode is admin only (operator refused, admin audited)', async () => {
  const docs = new Map();
  const state = { collection: () => ({ get: (id) => docs.get(id), put: (d) => { docs.set(d.id, d); return d; }, all: () => [...docs.values()], delete: (id) => docs.delete(id) }) };
  const audits = [];
  const api = createApi({ port: 0, audit: (e) => audits.push(e), proxySecret: SECRET });
  require('../engine/api/lr-import').register(api, { alerts: { raise() {}, all: () => [] }, state });
  const { port } = await api.start();
  try {
    let r = await req(port, 'POST', '/api/soc/lr/collector-health/mode', { body: JSON.stringify({ mode: 'suppress' }), headers: { 'X-Auth-Role': 'operator', 'X-Auth-User': 'op1' } });
    assert.equal(r.status, 403);
    assert.equal(docs.size, 0, 'nothing stored');
    r = await req(port, 'POST', '/api/soc/lr/collector-health/mode', { body: JSON.stringify({ mode: 'suppress' }), headers: { 'X-Auth-Role': 'admin', 'X-Auth-User': 'adm1' } });
    assert.equal(r.status, 200, JSON.stringify(r.json));
    assert.ok(audits.some((a) => a.action === 'lr.collector_health.mode'));
  } finally { await api.stop(); }
});

test('health: a detector whose stats() throws is reported as not running and degraded, with a fixed message', async () => {
  const fake = await startFakeCH({ respond: (q) => (/version\(\)/.test(q) ? { data: [{ version: '25.3.1' }] } : /FROM batches/.test(q) ? { data: [] } : null) });
  const writer = { stats: () => ({ seq: 0 }), node: 'test-node' }, spool = { stats: () => ({ files: 0, bytes: 0, mb: 0, dropped_batches: 0 }) };
  const detector = { stats: () => { throw new Error('boom at /srv/synthetic/rules.json'); } };
  const { api } = coreSetup(fake, { writer, spool, detector });
  const { port } = await api.start();
  try {
    const r = await req(port, 'GET', '/api/soc/health');
    assert.equal(r.status, 200);
    assert.equal(r.json.detector.running, false);
    assert.equal(r.json.detector.error, 'the detector did not answer');
    assert.ok(!JSON.stringify(r.json).includes('synthetic/rules.json'), 'the exception text is not exposed');
    assert.equal(r.json.status, 'degraded'); assert.ok(r.json.degraded_by.includes('detector'));
  } finally { await api.stop(); await fake.close(); }
});
