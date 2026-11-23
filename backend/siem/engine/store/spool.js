// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const { guard: guardJob } = require('../util/errors');
// Disk spool for batches that could not be written to ClickHouse.
//   createSpool({dir, maxMb, log}) → { write(meta, ndjson), start(replayFn), stop(), stats(), pendingBytes() }
// Segment files `seg-<epochms>-<seq>.ndjson` hold one or more batches:
//   {"_b": {batch meta}}\n <event rows…>\n {"_e": "<batch_id>"}\n
// Replay is oldest-first; replayFn(meta, ndjson) must throw on failure → exponential back-off (1 s … 60 s).
// Bounded by maxMb: when full, the OLDEST closed segments are deleted (counted in stats.dropped_*).
const fs = require('node:fs');
const fsp = require('node:fs/promises');
const path = require('node:path');

const SEG_RE = /^seg-(\d{13})-(\d{6})\.ndjson$/;

function createSpool({ dir, maxMb = 2048, log, segmentMb = 16, rotateMs = 5000, minBackoffMs = 1000, maxBackoffMs = 60000 } = {}) {
  if (!dir) throw new Error('spool: dir required');
  fs.mkdirSync(dir, { recursive: true });
  const maxBytes = Math.max(1, maxMb) * 1024 * 1024;
  const segBytes = Math.max(1, Math.min(segmentMb * 1024 * 1024, maxBytes / 4));
  let segs = []; // [{name, bytes, batches, closed}]
  let seq = 0;
  let active = null;
  let chain = Promise.resolve(); // serialises writes/replay file operations
  let timer = null;
  let replayFn = null;
  let backoff = 0;
  let nextAttempt = 0;
  let replaying = false;
  let stopped = false;
  let writing = 0;
  const st = { written_batches: 0, written_bytes: 0, replayed_batches: 0, replayed_rows: 0, dropped_segments: 0, dropped_bytes: 0, dropped_batches: 0, replay_errors: 0, last_error: '', write_errors: 0 };

  // load existing segments (after a restart everything on disk is closed and replayable)
  for (const f of fs.readdirSync(dir).sort()) {
    if (!SEG_RE.test(f)) continue;
    try { segs.push({ name: f, bytes: fs.statSync(path.join(dir, f)).size, batches: -1, closed: true, created: Number(SEG_RE.exec(f)[1]) }); } catch { /* raced */ }
  }
  if (segs.length && log) log.warn('spool: found pending segments from a previous run', { segments: segs.length, bytes: total() });

  function total() { return segs.reduce((a, s) => a + s.bytes, 0); }

  function newSegment() {
    const now = Date.now();
    seq = (seq + 1) % 1000000;
    const s = { name: `seg-${String(now).padStart(13, '0')}-${String(seq).padStart(6, '0')}.ndjson`, bytes: 0, batches: 0, closed: false, created: now };
    segs.push(s);
    return s;
  }

  function enforceCap(incoming) {
    while (total() + incoming > maxBytes) {
      const victim = segs.find((s) => s.closed) || (segs.length > 1 ? segs[0] : null);
      if (!victim) break;
      segs = segs.filter((s) => s !== victim);
      if (victim === active) active = null;
      try { fs.unlinkSync(path.join(dir, victim.name)); } catch { /* gone */ }
      st.dropped_segments++;
      st.dropped_bytes += victim.bytes;
      if (victim.batches > 0) st.dropped_batches += victim.batches;
      if (log) log.error('spool: size cap reached, dropped oldest segment (data loss)', { segment: victim.name, bytes: victim.bytes, cap_mb: maxMb });
    }
  }

  function write(meta, ndjson) {
    const body = (ndjson.endsWith('\n') ? ndjson : ndjson + '\n');
    const rec = JSON.stringify({ _b: meta }) + '\n' + body + JSON.stringify({ _e: meta.batch_id }) + '\n';
    const bytes = Buffer.byteLength(rec);
    const p = chain.then(async () => {
      writing++;
      if (!active || active.closed || active.bytes + bytes > segBytes) { if (active) active.closed = true; active = newSegment(); }
      enforceCap(bytes);
      if (!segs.includes(active)) active = newSegment();
      try {
        await fsp.appendFile(path.join(dir, active.name), rec);
        active.bytes += bytes;
        active.batches++;
        st.written_batches++;
        st.written_bytes += bytes;
      } catch (e) {
        st.write_errors++;
        st.last_error = e.message;
        if (log) log.error('spool: write failed (batch lost)', { err: e.message, batch_id: meta.batch_id });
        throw e;
      } finally {
        writing--;
      }
    });
    chain = p.catch(() => { /* the caller of p sees the error; the chain only keeps writes in order */ });
    return p;
  }

  function parseSegment(text) {
    const batches = [];
    let cur = null;
    for (const line of text.split('\n')) {
      if (!line) continue;
      if (line.startsWith('{"_b":')) { if (cur) batches.push(cur); try { cur = { meta: JSON.parse(line)._b, lines: [], complete: false }; } catch { cur = null; } continue; }
      if (line.startsWith('{"_e":')) { if (cur) { cur.complete = true; batches.push(cur); cur = null; } continue; }
      if (cur) cur.lines.push(line);
    }
    if (cur) batches.push(cur);
    return batches;
  }

  async function replayOne() {
    // rotate an idle active segment so it becomes replayable
    if (active && !active.closed && !writing && Date.now() - active.created > rotateMs) { active.closed = true; active = null; }
    const seg = segs.find((s) => s.closed);
    if (!seg) return false;
    const file = path.join(dir, seg.name);
    let text;
    try { text = await fsp.readFile(file, 'utf8'); } catch (e) {
      if (e.code === 'ENOENT') { segs = segs.filter((s) => s !== seg); return true; }
      throw e;
    }
    const batches = parseSegment(text);
    let doneCount = 0;
    try {
      for (const b of batches) {
        if (!b.lines.length) { doneCount++; continue; }
        if (!b.complete && log) log.warn('spool: replaying truncated batch', { batch_id: b.meta && b.meta.batch_id, rows: b.lines.length });
        await replayFn({ ...b.meta, rows: b.lines.length, truncated: !b.complete || undefined }, b.lines.join('\n') + '\n');
        doneCount++;
        st.replayed_batches++;
        st.replayed_rows += b.lines.length;
      }
    } finally {
      if (doneCount === batches.length) {
        await fsp.unlink(file).catch(() => { /* already gone */ });
        segs = segs.filter((s) => s !== seg);
      } else if (doneCount > 0) {
        // keep only the batches not yet replayed
        const rest = batches.slice(doneCount).map((b) => JSON.stringify({ _b: b.meta }) + '\n' + b.lines.join('\n') + '\n' + (b.complete ? JSON.stringify({ _e: b.meta.batch_id }) + '\n' : '')).join('');
        await fsp.writeFile(file + '.tmp', rest);
        await fsp.rename(file + '.tmp', file);
        seg.bytes = Buffer.byteLength(rest);
      }
    }
    return true;
  }

  async function tick() {
    if (stopped || replaying || !replayFn || Date.now() < nextAttempt || !segs.length) return;
    replaying = true;
    try {
      // replay as many segments as possible while ClickHouse accepts them
      // (closed segments are never appended to, so replay does not need the write chain)
      for (let i = 0; i < 50 && !stopped; i++) {
        const more = await replayOne();
        backoff = 0;
        if (!more) break;
      }
    } catch (e) {
      st.replay_errors++;
      st.last_error = e.message;
      backoff = Math.min(maxBackoffMs, backoff ? backoff * 2 : minBackoffMs);
      nextAttempt = Date.now() + backoff;
      if (log) log.every('spool-replay', 30000, 'warn', 'spool: replay failed, backing off', { err: e.message, backoff_ms: backoff, pending_bytes: total() });
    } finally {
      replaying = false;
    }
  }

  function start(fn) {
    replayFn = fn;
    if (!timer) { timer = setInterval(guardJob('store.spool.tick', () => tick()), 1000); timer.unref(); }
  }

  async function stop() {
    stopped = true;
    if (timer) clearInterval(timer);
    timer = null;
    await chain.catch(() => { /* reported to the writer that queued it */ });
    if (active) active.closed = true;
  }

  function stats() {
    const bytes = total();
    return { files: segs.length, segments: segs.length, bytes, mb: Math.round((bytes / 1048576) * 10) / 10, pending_bytes: bytes, oldest: segs.length ? segs[0].created : null, max_bytes: maxBytes, backoff_ms: backoff, replaying, ...st };
  }

  return { write, start, stop, stats, pendingBytes: total, tick, _parseSegment: parseSegment };
}

module.exports = { createSpool };
