// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// ClickHouse client, writer (batching + integrity chain + spool fallback), spool, migrate. Synthetic data only.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { startFakeCH } = require('./helpers/fake-ch');
const { createCH, formatParam } = require('../engine/store/clickhouse');
const { createWriter, verifyChain, GENESIS } = require('../engine/store/writer');
const { createSpool } = require('../engine/store/spool');
const { renderSchema, schemaColumns, migrate } = require('../engine/store/migrate');
const { createParser } = require('../engine/parse');
const { FIELD_NAMES } = require('../engine/schema');

const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'sentra-siem-test-'));
const parser = createParser();
const mkEv = (i) => parser.parse(`<38>May  1 10:00:00 test-host-01 sshd[1]: Failed password for user${i} from 192.0.2.${i % 250} port ${1000 + i} ssh2`, { collector: 'syslog-tcp', src_id: 'test-src', peer_ip: '10.0.0.1', rts: Date.UTC(2024, 4, 1, 10, 0, 0) });
const waitFor = async (fn, ms = 5000) => { const t = Date.now(); while (!fn()) { if (Date.now() - t > ms) throw new Error('timeout'); await new Promise((r) => setTimeout(r, 20)); } };

test('param formatting uses ClickHouse escaped text format', () => {
  assert.equal(formatParam({ value: 'C:\\Windows\\x' }), 'C:\\\\Windows\\\\x');
  assert.equal(formatParam({ value: 'a\tb\nc' }), 'a\\tb\\nc');
  assert.equal(formatParam({ value: 42 }), '42');
  assert.equal(formatParam({ value: "it's" }), "it's");
  assert.equal(formatParam({ value: null }), '\\N');
});

test('clickhouse client: query with params, basic auth, FORMAT JSON, readonly, errors, retry once', async () => {
  const fake = await startFakeCH({ respond: (q) => (/version/.test(q) ? { data: [{ v: '25.3' }], rows_before_limit_at_least: 7, statistics: { elapsed: 0.001 } } : null) });
  try {
    const ch = createCH({ url: fake.url, user: 'sentra_siem', password: 'synthetic-pw', database: 'siem', timeout_ms: 1000 });
    const r = await ch.queryFull('SELECT version() AS v WHERE x = {p1:String}', { p1: { type: 'String', value: "a'b\\c" } }, { readonly: true });
    assert.deepEqual(r.rows, [{ v: '25.3' }]);
    assert.equal(r.rows_before_limit_at_least, 7);
    const req = fake.requests.at(-1);
    assert.equal(req.params.param_p1, "a'b\\\\c");
    assert.equal(req.params.database, 'siem');
    assert.equal(req.params.readonly, '2');
    assert.match(req.body, /FORMAT JSON$/);
    assert.equal(req.headers.authorization, 'Basic ' + Buffer.from('sentra_siem:synthetic-pw').toString('base64'));
    // retry once on 503
    fake.fail = 1;
    const rows = await ch.query('SELECT version() AS v', {});
    assert.equal(rows[0].v, '25.3');
    assert.equal(ch.stats().retries, 1);
    // persistent failure → CHError with API status 502
    fake.fail = 2;
    await assert.rejects(ch.query('SELECT version() AS v'), (e) => e.name === 'CHError' && e.status === 502 && e.httpStatus === 503);
    // non-retriable 500 is not retried
    fake.fail = 1; fake.failStatus = 500;
    const before = fake.requests.length;
    await assert.rejects(ch.exec('SELECT 1'));
    assert.equal(fake.requests.length, before + 1);
    fake.failStatus = 503;
    assert.equal(await ch.ping(), true);
    await assert.rejects(ch.query('SELECT 1', { 'bad name': { type: 'String', value: 1 } }), /invalid parameter name/);
  } finally { await fake.close(); }
});

test('clickhouse client: timeout and unreachable', async () => {
  const fake = await startFakeCH();
  fake.hang = true;
  const ch = createCH({ url: fake.url, database: 'siem', timeout_ms: 150 });
  await assert.rejects(ch.query('SELECT 1'), /timeout/);
  await fake.close();
  const dead = createCH({ url: 'http://127.0.0.1:1', timeout_ms: 300 });
  await assert.rejects(dead.query('SELECT 1'), /unreachable/);
  assert.equal(await dead.ping(200), false);
});

test('clickhouse client: gzip JSONEachRow insert with dedup token', async () => {
  const fake = await startFakeCH();
  try {
    const ch = createCH({ url: fake.url, database: 'siem' });
    await ch.insertRows('events', [{ a: 1 }, { a: 'x"y' }], { dedupToken: 'tok-1' });
    const ins = fake.inserts['siem.events'][0];
    assert.deepEqual(ins.rows, [{ a: 1 }, { a: 'x"y' }]);
    assert.equal(ins.params.insert_deduplication_token, 'tok-1');
    assert.equal(fake.requests.at(-1).headers['content-encoding'], 'gzip');
    await assert.rejects(ch.insertRows('events; DROP', [{ a: 1 }]), /invalid table/);
  } finally { await fake.close(); }
});

test('writer: batches by size, sha256 chain, batches table, stats_minute, chain persisted', async () => {
  const fake = await startFakeCH();
  const dir = tmp();
  try {
    const ch = createCH({ url: fake.url, database: 'siem' });
    const w = createWriter({ ch, stateDir: dir, node: 'test-node', batchSize: 100, flushMs: 60000, statsFlushMs: 60000 });
    for (let i = 0; i < 250; i++) w.push(mkEv(i));
    await w.flush();
    const events = fake.inserts['siem.events'];
    assert.equal(events.length, 3);
    assert.deepEqual(events.map((b) => b.rows.length), [100, 100, 50]);
    const row = events[0].rows[0];
    assert.deepEqual(Object.keys(row).sort(), [...FIELD_NAMES, 'batch_id'].sort()); // batch_id ties each row to its chained batch
    assert.equal(row.ts, '2024-05-01 10:00:00.000');
    const batches = fake.rows('siem.batches');
    assert.equal(batches.length, 3);
    assert.equal(batches[0].prev_sha256, GENESIS);
    assert.equal(batches[1].prev_sha256, batches[0].sha256);
    assert.equal(batches[2].prev_sha256, batches[1].sha256);
    assert.deepEqual(batches.map((b) => b.seq), [1, 2, 3]);
    // hash = sha256 of the exact NDJSON body that was inserted
    const nd = events[1].rows.map((r) => JSON.stringify(r)).join('\n') + '\n';
    assert.equal(crypto.createHash('sha256').update(nd).digest('hex'), batches[1].sha256);
    assert.equal(events[0].params.insert_deduplication_token, batches[0].batch_id);
    const stats = fake.rows('siem.stats_minute');
    assert.equal(stats.length, 1);
    assert.equal(stats[0].events, 250);
    assert.equal(stats[0].src_id, 'test-src');
    const chain = JSON.parse(fs.readFileSync(path.join(dir, 'chain.json'), 'utf8'));
    assert.equal(chain.sha256, batches[2].sha256);
    assert.equal(chain.seq, 3);
    await w.close();
    // a new writer continues the chain
    const w2 = createWriter({ ch, stateDir: dir, node: 'test-node', batchSize: 100, flushMs: 60000, statsFlushMs: 60000 });
    w2.push(mkEv(1));
    await w2.close();
    const b4 = fake.rows('siem.batches')[3];
    assert.equal(b4.seq, 4);
    assert.equal(b4.prev_sha256, batches[2].sha256);
  } finally { await fake.close(); }
});

test('writer: time-based flush', async () => {
  const fake = await startFakeCH();
  try {
    const ch = createCH({ url: fake.url, database: 'siem' });
    const w = createWriter({ ch, node: 'test-node', batchSize: 5000, flushMs: 100, statsFlushMs: 60000 });
    w.push(mkEv(1));
    await waitFor(() => fake.inserts['siem.events']);
    await w.close();
  } finally { await fake.close(); }
});

test('writer + spool: ClickHouse down → spooled, replayed oldest-first when back, chain intact', async () => {
  const fake = await startFakeCH();
  const dir = tmp();
  try {
    const ch = createCH({ url: fake.url, database: 'siem', timeout_ms: 500 });
    const spool = createSpool({ dir: path.join(dir, 'spool'), maxMb: 10, rotateMs: 50, minBackoffMs: 50, maxBackoffMs: 200 });
    fake.fail = 1000; fake.failStatus = 500;
    const w = createWriter({ ch, spool, stateDir: dir, node: 'test-node', batchSize: 10, flushMs: 60000, statsFlushMs: 60000, breakerMs: 100000 });
    for (let i = 0; i < 35; i++) w.push(mkEv(i));
    await w.flush();
    const st = w.stats();
    assert.equal(st.rows_spooled, 35);
    assert.equal(st.rows_written, 0);
    assert.ok(spool.stats().bytes > 0);
    assert.equal(fake.inserts['siem.events'], undefined);
    // back online → replay
    fake.fail = 0;
    await waitFor(() => spool.stats().files === 0 && (fake.inserts['siem.events'] || []).length === 4, 8000);
    const batches = fake.rows('siem.batches').sort((a, b) => a.seq - b.seq);
    assert.deepEqual(batches.map((b) => b.seq), [1, 2, 3, 4]);
    for (let i = 1; i < batches.length; i++) assert.equal(batches[i].prev_sha256, batches[i - 1].sha256);
    assert.equal(fake.rows('siem.events').length, 35);
    assert.equal(spool.stats().replayed_batches, 4);
    await w.close();
  } finally { await fake.close(); }
});

test('spool: bounded size drops oldest closed segments; parse tolerates truncated batch', async () => {
  const dir = tmp();
  const spool = createSpool({ dir, maxMb: 1, segmentMb: 0.2 });
  const big = 'x'.repeat(100 * 1024);
  for (let i = 0; i < 30; i++) await spool.write({ batch_id: 'b' + i, rows: 1 }, JSON.stringify({ raw: big }) + '\n');
  const st = spool.stats();
  assert.ok(st.bytes <= 1024 * 1024, 'spool exceeds cap: ' + st.bytes);
  assert.ok(st.dropped_segments > 0);
  const parsed = spool._parseSegment('{"_b":{"batch_id":"a"}}\n{"x":1}\n{"_e":"a"}\n{"_b":{"batch_id":"b"}}\n{"x":2}\n');
  assert.equal(parsed.length, 2);
  assert.equal(parsed[0].complete, true);
  assert.equal(parsed[1].complete, false);
  await spool.stop();
});

test('spool: pending segments survive a restart and are replayed', async () => {
  const dir = tmp();
  const s1 = createSpool({ dir });
  await s1.write({ batch_id: 'r1', rows: 2 }, '{"a":1}\n{"a":2}\n');
  await s1.stop();
  const got = [];
  const s2 = createSpool({ dir, minBackoffMs: 10 });
  assert.equal(s2.stats().files, 1);
  s2.start(async (meta, nd) => { got.push([meta.batch_id, nd]); });
  await waitFor(() => got.length === 1 && s2.stats().files === 0);
  assert.deepEqual(got[0], ['r1', '{"a":1}\n{"a":2}\n']);
  await s2.stop();
});

test('verifyChain detects breaks and tolerates gaps', async () => {
  const rows = [{ seq: 1, sha256: 'a', prev_sha256: GENESIS }, { seq: 2, sha256: 'b', prev_sha256: 'a' }, { seq: 4, sha256: 'd', prev_sha256: 'c' }, { seq: 5, sha256: 'e', prev_sha256: 'X' }];
  const r = await verifyChain({ query: async () => rows }, { node: 'n' });
  assert.equal(r.breaks, 1);
  assert.equal(r.gaps, 1);
  assert.equal(r.broken_at, 5);
  assert.equal(r.ok, false);
  const ok = await verifyChain({ query: async () => rows.slice(0, 2) }, { node: 'n' });
  assert.equal(ok.ok, true);
  assert.equal(ok.status, 'verified');
});

test('migrate: schema renders with retention, all ARCH tables/columns present, idempotent statements', async () => {
  const { statements, days } = renderSchema({ retentionDays: 400 });
  assert.equal(days, 400);
  assert.ok(statements.every((s) => /IF NOT EXISTS/.test(s)));
  const all = statements.join('\n');
  assert.match(all, /TTL toDateTime\(ts\) \+ INTERVAL 400 DAY/);
  assert.doesNotMatch(all, /\{retention_days\}/);
  assert.match(all, /PARTITION BY toYYYYMMDD\(ts\)/);
  assert.match(all, /ORDER BY \(src_type, host, ts\)/);
  assert.match(all, /ReplacingMergeTree\(updated\)/);
  assert.match(all, /SummingMergeTree/);
  for (const idx of ['raw', 'message']) assert.match(all, new RegExp(`${idx}\\s+TYPE tokenbf_v1`));
  for (const idx of ['user', 'src_ip', 'dst_ip', 'hash', 'event_code']) assert.match(all, new RegExp(`${idx}\\s+TYPE bloom_filter`));
  const cols = schemaColumns(statements);
  assert.deepEqual(cols.events.cols.map((c) => c.name), [...FIELD_NAMES, 'batch_id']);
  assert.deepEqual(cols.alerts.cols.map((c) => c.name), ['id', 'rule_id', 'rule_name', 'severity', 'ts_first', 'ts_last', 'status', 'assignee', 'summary', 'group_json', 'mitre', 'updated']);
  assert.deepEqual(cols.stats_minute.cols.map((c) => c.name), ['minute', 'src_id', 'src_type', 'events', 'bytes', 'parse_errors']);
  const other = renderSchema({ retentionDays: 30, database: 'siem_test' }).statements.join('\n');
  assert.match(other, /siem_test\.events/);
  assert.doesNotMatch(other, /\bsiem\.events/);
  assert.throws(() => renderSchema({ retentionDays: 0 }));
  assert.throws(() => renderSchema({ database: 'x;y' }));
});

test('migrate: adds missing columns and changes TTL only when retention differs', async () => {
  const fake = await startFakeCH({
    respond: (q) => {
      if (/system\.columns/.test(q)) return { data: [{ name: 'ts' }, { name: 'rts' }] };
      if (/system\.tables/.test(q)) return { data: [{ engine_full: 'MergeTree PARTITION BY toYYYYMMDD(ts) ORDER BY (src_type, host, ts) TTL toDateTime(ts) + toIntervalDay(365) SETTINGS index_granularity = 8192' }] };
      return null;
    },
  });
  try {
    const ch = createCH({ url: fake.url, database: '' });
    const r = await migrate({ ch, retentionDays: 365 });
    assert.ok(r.applied.some((s) => /ADD COLUMN IF NOT EXISTS src_type LowCardinality\(String\)/.test(s)));
    assert.ok(!r.applied.some((s) => /MODIFY TTL/.test(s)));
    const r2 = await migrate({ ch, retentionDays: 180 });
    assert.ok(r2.applied.some((s) => /ALTER TABLE siem\.events MODIFY TTL toDateTime\(ts\) \+ INTERVAL 180 DAY/.test(s)));
    assert.ok(fake.requests.every((q) => q.path === '/ping' || q.params.database === undefined));
  } finally { await fake.close(); }
});

test('verifyChain: deleted or added event rows in a tagged batch are reported as tampered', async () => {
  const now = new Date().toISOString().replace('T', ' ').replace('Z', '');
  const batches = [
    { seq: 1, sha256: 'a', prev_sha256: GENESIS, batch_id: 'b1', rows: 3, tagged: 1, first_ts: now },
    { seq: 2, sha256: 'b', prev_sha256: 'a', batch_id: 'b2', rows: 2, tagged: 1, first_ts: now },
    { seq: 3, sha256: 'c', prev_sha256: 'b', batch_id: 'b3', rows: 5, tagged: 0, first_ts: now }, // pre-upgrade batch: not counted
  ];
  const fake = (counts) => ({
    query: async (sql, params) => (sql.includes('FROM batches') ? batches
      : params.ids.value.filter((id) => counts[id] !== undefined).map((id) => ({ batch_id: id, n: counts[id] }))),
  });
  let r = await verifyChain(fake({ b1: 3, b2: 2 }), { node: 'n', retentionDays: 365 });
  assert.equal(r.ok, true);
  assert.equal(r.status, 'verified');
  assert.equal(r.rows_checked_batches, 2);
  r = await verifyChain(fake({ b1: 2, b2: 2 }), { node: 'n', retentionDays: 365 }); // one row deleted from b1
  assert.equal(r.ok, false);
  assert.equal(r.status, 'tampered');
  assert.equal(r.tampered_at, 1);
  r = await verifyChain(fake({ b1: 3 }), { node: 'n', retentionDays: 365 }); // every row of b2 deleted
  assert.equal(r.tampered_batches, 1);
  assert.equal(r.tampered_at, 2);
});
