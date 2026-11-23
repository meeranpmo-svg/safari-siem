// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const { guard: guardJob } = require('../util/errors');
/*
 * Data Optimizer — archive (cold) tier (DATAOPT.md "Archive tier"). Nothing is truly lost:
 *   - route:archive sends full events to a compressed long-TTL ClickHouse table (siem.events_archive, ZSTD) and/or
 *     an S3-compatible / file object store as NDJSON.gz.
 *   - drop keeps an optional minimal STUB (ts, source, type, hash) in the archive so the drop is provable/reversible.
 *   - search({from,to,q,...}) queries the cold tier on demand.
 *
 *   createArchive({ ch, dir, config, log, now, batchSize, flushMs }) →
 *     { write(ev, meta), writeStub(ev, meta), flush(), stop(), search(opts), stats() }
 */
const fs = require('node:fs');
const path = require('node:path');
const zlib = require('node:zlib');
const { toRow, fmtTs } = require('../store/writer');

const ARCH_TABLE = 'events_archive';

function createArchive({ ch, dir, config = {}, log, now = Date.now, batchSize = 2000, flushMs = 2000 } = {}) {
  const ac = (config.dataopt && config.dataopt.archive) || {};
  const useCH = ac.clickhouse !== false; // ClickHouse archive on by default
  const fileEnabled = !!(ac.file && ac.file.enabled);
  const fileDir = ac.file && ac.file.dir ? ac.file.dir : (dir ? path.join(dir, 'archive') : null);
  if (fileEnabled && fileDir) fs.mkdirSync(fileDir, { recursive: true });
  let buf = [];
  let fileBuf = [];
  let fileHour = '';
  const st = { written: 0, stubs: 0, batches: 0, insert_errors: 0, file_bytes: 0, last_error: '' };

  function archRow(ev, meta, stub) {
    const base = stub
      ? { ts: fmtTs(ev.ts), rts: fmtTs(ev.rts || ev.ts), id: ev.id || '', src_id: ev.src_id || '', src_type: ev.src_type || '', action: ev.action || '', event_code: ev.event_code || '', hash: ev.hash || '' }
      : toRow(ev);
    base.arch_at = fmtTs(now());
    base.arch_rule = (meta && meta.rule_id) || '';
    base.arch_reason = (meta && meta.reason) || '';
    base.arch_stub = stub ? 1 : 0;
    return base;
  }

  function push(row) {
    if (useCH) { buf.push(row); if (buf.length >= batchSize) flush().catch(() => { /* flush counts and logs its own insert errors (st.insert_errors) */ }); }
    if (fileEnabled && fileDir) {
      const h = row.ts.slice(0, 13).replace(/[: ]/g, '').replace(/-/g, ''); // YYYYMMDDHH
      if (h !== fileHour && fileBuf.length) flushFile();
      fileHour = h;
      fileBuf.push(row);
      if (fileBuf.length >= batchSize) flushFile();
    }
  }

  function write(ev, meta) { st.written++; push(archRow(ev, meta, false)); }
  function writeStub(ev, meta) { st.stubs++; push(archRow(ev, meta, true)); }

  function flushFile() {
    if (!fileEnabled || !fileDir || !fileBuf.length) return;
    const rows = fileBuf; fileBuf = [];
    try {
      const ndjson = rows.map((r) => JSON.stringify(r)).join('\n') + '\n';
      const gz = zlib.gzipSync(Buffer.from(ndjson, 'utf8'), { level: 6 });
      const file = path.join(fileDir, `events-${fileHour || fmtTs(now()).slice(0, 13).replace(/[: ]/g, '').replace(/-/g, '')}-${now()}.ndjson.gz`);
      fs.writeFileSync(file, gz);
      st.file_bytes += gz.length;
    } catch (e) { st.last_error = e.message; if (log) log.every('dataopt-arch-file', 30000, 'error', 'dataopt: archive file write failed', { err: e.message }); }
  }

  async function flush() {
    if (fileBuf.length) flushFile();
    if (!useCH || !buf.length) return;
    const rows = buf; buf = [];
    if (!ch) return;
    try { await ch.insertRows(ARCH_TABLE, rows); st.batches++; }
    catch (e) { st.insert_errors++; st.last_error = e.message; if (log) log.every('dataopt-arch', 30000, 'error', 'dataopt: archive insert failed', { err: e.message, rows: rows.length }); }
  }

  const timer = flushMs ? setInterval(guardJob('dataopt.archive.flush', () => flush()), flushMs) : null;
  if (timer && timer.unref) timer.unref();

  // On-demand cold search over ClickHouse (file archive search is scan-based; CH is the primary path).
  async function search({ from, to, q, src_id, src_type, limit = 200, stub } = {}) {
    if (!ch) return { rows: [], total_estimate: 0, backend: 'none' };
    const lim = Math.min(5000, Math.max(1, Number(limit) || 200));
    const where = ['ts >= {from:DateTime64(3)}', 'ts <= {to:DateTime64(3)}'];
    const params = { from: { type: 'String', value: fmtTs(from) }, to: { type: 'String', value: fmtTs(to) }, lim: { type: 'UInt32', value: lim } };
    if (src_id) { where.push('src_id = {src_id:String}'); params.src_id = { type: 'String', value: String(src_id) }; }
    if (src_type) { where.push('src_type = {src_type:String}'); params.src_type = { type: 'String', value: String(src_type) }; }
    if (stub === true || stub === 'true') where.push('arch_stub = 1');
    else if (stub === false || stub === 'false') where.push('arch_stub = 0');
    if (q) { where.push('(position(raw, {q:String}) > 0 OR position(message, {q:String}) > 0)'); params.q = { type: 'String', value: String(q) }; }
    const sql = `SELECT ts, rts, id, src_id, src_type, host, action, event_code, outcome, severity, user, src_ip, dst_ip, message, hash, arch_stub, arch_rule, arch_reason, arch_at FROM ${ARCH_TABLE} WHERE ${where.join(' AND ')} ORDER BY ts DESC LIMIT {lim:UInt32}`;
    const rows = await ch.query(sql, params, { readonly: true, timeout_ms: 20000 });
    return { rows, total_estimate: (rows.info && rows.info.rows_before_limit_at_least) || rows.length, backend: 'clickhouse' };
  }

  return {
    write, writeStub, flush, search,
    stats: () => ({ ...st, buffered: buf.length, file_buffered: fileBuf.length, backend: { clickhouse: useCH, file: fileEnabled } }),
    async stop() { if (timer) clearInterval(timer); if (fileBuf.length) flushFile(); await flush(); },
    ARCH_TABLE,
  };
}

module.exports = { createArchive, ARCH_TABLE };
