// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const { guard: guardJob } = require('../util/errors');
// Batch writer: events → ClickHouse siem.events in batches (5000 rows or 1 s), with
//  * integrity chain: sha256 of each batch's exact NDJSON, chained to the previous batch's hash → siem.batches
//    (chain head persisted in <state>/chain.json so it continues across restarts, including spooled batches),
//  * spool fallback when ClickHouse fails (circuit breaker: while ClickHouse is down batches go straight to the spool;
//    the spool's replay loop is the probe that closes the breaker again),
//  * per-minute source statistics → siem.stats_minute (SummingMergeTree, flushed every 10 s).
//   createWriter({ch, spool, log, stateDir, node, batchSize, flushMs, maxInflight, maxQueue, statsFlushMs})
//     → { push(ev), flush() → Promise, close() → Promise, stats(), insertBatch(meta, ndjson) }
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { FIELD_NAMES } = require('../schema');

const GENESIS = '0'.repeat(64);

function fmtTs(ms) {
  const d = new Date(Number.isFinite(ms) ? ms : Date.now());
  return d.toISOString().slice(0, 23).replace('T', ' ');
}

// Internal event → ClickHouse JSONEachRow row (only schema fields, DateTime64 as 'YYYY-MM-DD hh:mm:ss.mmm' UTC)
function toRow(ev) {
  const r = {};
  for (const f of FIELD_NAMES) r[f] = ev[f];
  r.ts = fmtTs(ev.ts);
  r.rts = fmtTs(ev.rts);
  return r;
}

function createWriter({ ch, spool, log, stateDir, node = require('node:os').hostname(), batchSize = 5000, flushMs = 1000, maxInflight = 2, maxQueue = 10, statsFlushMs = 10000, table = 'events', breakerMs = 5000 } = {}) {
  let buf = [];
  let bufFirst = 0;
  const queue = []; // cut batches waiting for an insert slot
  let inflight = 0;
  let seq = 0;
  let prevHash = GENESIS;
  let chDownUntil = 0;
  let closed = false;
  const waiters = [];
  const st = { pushed: 0, batches: 0, rows_written: 0, batches_spooled: 0, rows_spooled: 0, spool_failures: 0, insert_errors: 0, last_error: '', last_write_at: 0, replayed_batches: 0 };
  const minute = new Map(); // "minuteMs|src_id|src_type" → {events, bytes, parse_errors}
  const chainFile = stateDir ? path.join(stateDir, 'chain.json') : null;
  let chainDirty = false;

  if (chainFile) {
    try {
      const c = JSON.parse(fs.readFileSync(chainFile, 'utf8'));
      if (/^[0-9a-f]{64}$/.test(c.sha256)) { prevHash = c.sha256; seq = Number(c.seq) || 0; }
    } catch { /* first run */ }
  }

  function persistChain() {
    if (!chainFile || !chainDirty) return;
    chainDirty = false;
    try {
      fs.mkdirSync(path.dirname(chainFile), { recursive: true });
      fs.writeFileSync(chainFile + '.tmp', JSON.stringify({ sha256: prevHash, seq, at: new Date().toISOString() }));
      fs.renameSync(chainFile + '.tmp', chainFile);
    } catch (e) { if (log) log.every('chain-persist', 60000, 'error', 'writer: cannot persist chain head', { err: e.message }); }
  }

  function push(ev) {
    if (closed) return;
    st.pushed++;
    if (!buf.length) bufFirst = Date.now();
    buf.push(ev);
    // stats_minute aggregation
    const m = Math.floor((ev.rts || Date.now()) / 60000) * 60000;
    const key = m + '|' + ev.src_id + '|' + ev.src_type;
    let a = minute.get(key);
    if (!a) { a = { events: 0, bytes: 0, parse_errors: 0 }; minute.set(key, a); }
    a.events++;
    a.bytes += ev.raw ? ev.raw.length : 0;
    if (ev._perr || ev.action === 'unparsed') a.parse_errors++;
    if (buf.length >= batchSize) cut();
  }

  // Seal the current buffer into a batch: serialise, hash, chain. Order of cut() == chain order.
  function cut() {
    if (!buf.length) return;
    const events = buf;
    buf = [];
    let ndjson = '';
    let first = Infinity;
    let last = 0;
    // every event row carries its batch_id, so verifyChain can count a batch's events and notice deleted rows
    const batchId = crypto.randomUUID();
    for (const ev of events) {
      const row = toRow(ev);
      row.batch_id = batchId;
      ndjson += JSON.stringify(row) + '\n';
      if (ev.ts < first) first = ev.ts;
      if (ev.ts > last) last = ev.ts;
    }
    const sha = crypto.createHash('sha256').update(ndjson).digest('hex');
    seq++;
    const meta = {
      batch_id: batchId, seq, ts: fmtTs(Date.now()), rows: events.length, bytes: Buffer.byteLength(ndjson),
      sha256: sha, prev_sha256: prevHash, first_ts: fmtTs(first), last_ts: fmtTs(last), node, tagged: 1,
    };
    prevHash = sha;
    chainDirty = true;
    st.batches++;
    queue.push({ meta, ndjson });
    pump();
  }

  async function insertBatch(meta, ndjson) {
    await ch.insertNDJSON(table, ndjson, { dedupToken: meta.batch_id });
    const { truncated, ...row } = meta;
    await ch.insertRows('batches', [row], { dedupToken: 'b-' + meta.batch_id });
  }

  async function toSpool(b, reason) {
    if (!spool) { st.spool_failures++; if (log) log.error('writer: no spool configured, batch lost', { batch_id: b.meta.batch_id, rows: b.meta.rows }); return; }
    try {
      await spool.write(b.meta, b.ndjson);
      st.batches_spooled++;
      st.rows_spooled += b.meta.rows;
      if (log) log.every('writer-spooled', 30000, 'warn', 'writer: batch spooled', { reason, rows: b.meta.rows });
    } catch (e) {
      st.spool_failures++;
      if (log) log.error('writer: spool write failed, batch lost', { batch_id: b.meta.batch_id, rows: b.meta.rows, err: e.message });
    }
  }

  function pump() {
    // overflow → spool the oldest queued batches (bounded memory)
    while (queue.length > maxQueue) { const b = queue.shift(); inflight++; toSpool(b, 'queue-full').finally(done); }
    while (inflight < maxInflight && queue.length) {
      const b = queue.shift();
      inflight++;
      if (Date.now() < chDownUntil) { toSpool(b, 'clickhouse-down').finally(done); continue; }
      insertBatch(b.meta, b.ndjson).then(() => {
        st.rows_written += b.meta.rows;
        st.last_write_at = Date.now();
      }, (e) => {
        st.insert_errors++;
        st.last_error = e.message;
        chDownUntil = Date.now() + breakerMs;
        if (log) log.every('writer-insert', 30000, 'error', 'writer: ClickHouse insert failed, spooling', { err: e.message });
        return toSpool(b, 'insert-failed');
      }).finally(done);
    }
  }

  function done() {
    inflight--;
    pump();
    if (!inflight && !queue.length) while (waiters.length) waiters.shift()();
  }

  function idle() {
    if (!inflight && !queue.length) return Promise.resolve();
    return new Promise((r) => waiters.push(r));
  }

  async function flushStats(all = false) {
    if (!minute.size) return;
    const rows = [];
    const keys = [];
    for (const [key, a] of minute) {
      const [m, src_id, src_type] = key.split('|');
      rows.push({ minute: fmtTs(Number(m)).slice(0, 19), src_id, src_type, events: a.events, bytes: a.bytes, parse_errors: a.parse_errors });
      keys.push(key);
    }
    void all;
    minute.clear();
    try {
      if (Date.now() < chDownUntil) throw new Error('clickhouse down');
      await ch.insertRows('stats_minute', rows);
    } catch (e) {
      // merge back (SummingMergeTree: partial rows are summed later, so retrying is safe) — bounded
      for (let i = 0; i < rows.length && minute.size < 20000; i++) {
        const r = rows[i];
        const a = minute.get(keys[i]) || { events: 0, bytes: 0, parse_errors: 0 };
        a.events += r.events; a.bytes += r.bytes; a.parse_errors += r.parse_errors;
        minute.set(keys[i], a);
      }
      if (log) log.every('writer-stats', 60000, 'warn', 'writer: stats_minute flush failed, will retry', { err: e.message });
    }
  }

  const tFlush = setInterval(guardJob('store.writer.flush', () => { if (buf.length && Date.now() - bufFirst >= flushMs * 0.9) cut(); persistChain(); }), Math.max(50, Math.floor(flushMs / 2)));   // a disk error here must not end the process
  const tStats = setInterval(guardJob('store.writer.flushStats', () => flushStats()), statsFlushMs);
  tFlush.unref();
  tStats.unref();

  // spool replay uses the same insert path; success closes the breaker
  if (spool) spool.start(async (meta, ndjson) => {
    await insertBatch(meta, ndjson);
    chDownUntil = 0;
    st.replayed_batches++;
  });

  async function flush() {
    cut();
    await idle();
    await flushStats(true);
    persistChain();
  }

  async function close() {
    if (closed) return;
    cut();
    closed = true;
    clearInterval(tFlush);
    clearInterval(tStats);
    await idle();
    await flushStats(true);
    persistChain();
    if (spool) await spool.stop();
  }

  function stats() {
    return { ...st, buffered: buf.length, queued: queue.length, inflight, seq, chain_head: prevHash, clickhouse_down: Date.now() < chDownUntil };
  }

  // First start without chain.json (e.g. reinstall): continue the chain from the last batch this node wrote.
  async function resumeFromStore() {
    if (seq > 0 || prevHash !== GENESIS) return false;
    try {
      const r = await ch.query('SELECT seq, sha256 FROM batches WHERE node = {node:String} ORDER BY seq DESC LIMIT 1', { node: { type: 'String', value: node } }, { timeout_ms: 5000 });
      if (r.length && /^[0-9a-f]{64}$/.test(r[0].sha256)) {
        seq = Number(r[0].seq) || 0;
        prevHash = r[0].sha256;
        chainDirty = true;
        persistChain();
        if (log) log.info('writer: integrity chain resumed from ClickHouse', { seq });
        return true;
      }
    } catch (e) { if (log) log.warn('writer: could not read chain head from ClickHouse', { err: e.message }); }
    return false;
  }

  return { push, flush, close, stats, insertBatch, toRow, resumeFromStore, get node() { return node; } };
}

// Verify the integrity chain stored in siem.batches for one node: consecutive seq must link prev_sha256 → sha256, and
// every tagged batch (events carry batch_id) must still have exactly `rows` events in siem.events — a deleted or
// added row is reported as `tampered`. Gaps in seq (batches still in the spool, or dropped) are counted in `gaps`;
// the caller decides whether a gap is explained (spool not empty). Checks the newest `limit` batches; batches older
// than the retention window (TTL removes their events) are not counted.
async function verifyChain(ch, { node, limit = 5000, retentionDays = 0 } = {}) {
  const rows = await ch.query(
    'SELECT seq, sha256, prev_sha256, ts, batch_id, rows, tagged, first_ts FROM (SELECT seq, any(sha256) AS sha256, any(prev_sha256) AS prev_sha256, max(ts) AS ts, any(batch_id) AS batch_id, any(rows) AS rows, max(tagged) AS tagged, min(first_ts) AS first_ts FROM batches WHERE node = {node:String} GROUP BY seq ORDER BY seq DESC LIMIT {lim:UInt32}) ORDER BY seq',
    { node: { type: 'String', value: node }, lim: { type: 'UInt32', value: limit } }, { readonly: true, timeout_ms: 10000 });
  let breaks = 0;
  let gaps = 0;
  let brokenAt = null;
  for (let i = 1; i < rows.length; i++) {
    const a = rows[i - 1];
    const b = rows[i];
    if (Number(b.seq) !== Number(a.seq) + 1) { gaps++; continue; }
    if (b.prev_sha256 !== a.sha256) { breaks++; if (brokenAt === null) brokenAt = Number(b.seq); }
  }
  // row counts per tagged batch (inside the retention window, leaving a day's margin before TTL removal)
  const cutoff = retentionDays > 1 ? Date.now() - (retentionDays - 1) * 86400000 : 0;
  const tagged = rows.filter((r) => Number(r.tagged) === 1 && (!cutoff || Date.parse(String(r.first_ts).replace(' ', 'T') + 'Z') > cutoff));
  let tampered = 0;
  let tamperedAt = null;
  if (tagged.length) {
    const counts = new Map();
    for (let i = 0; i < tagged.length; i += 500) {
      const ids = tagged.slice(i, i + 500).map((r) => r.batch_id);
      const got = await ch.query('SELECT batch_id, count() AS n FROM events WHERE batch_id IN {ids:Array(String)} GROUP BY batch_id',
        { ids: { type: 'Array(String)', value: ids } }, { readonly: true, timeout_ms: 30000 });
      for (const g of got) counts.set(g.batch_id, Number(g.n));
    }
    for (const r of tagged) {
      if ((counts.get(r.batch_id) || 0) !== Number(r.rows)) { tampered++; if (tamperedAt === null) tamperedAt = Number(r.seq); }
    }
  }
  const last = rows[rows.length - 1];
  return {
    ok: breaks === 0 && tampered === 0, status: breaks ? 'broken' : tampered ? 'tampered' : 'verified', checked: rows.length,
    breaks, gaps, broken_at: brokenAt, rows_checked_batches: tagged.length, tampered_batches: tampered, tampered_at: tamperedAt,
    last_seq: last ? Number(last.seq) : 0, last_hash: last ? last.sha256 : null, last_batch: last ? last.ts : null, verified_at: new Date().toISOString(),
  };
}

module.exports = { createWriter, verifyChain, toRow, fmtTs, GENESIS };
