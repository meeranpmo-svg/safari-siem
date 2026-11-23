// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// ClickHouse HTTP client (fetch, no dependencies).
//   createCH({url, user, password, database, timeout_ms, log}) →
//     { query(sql, params) → rows[], queryFull(sql, params) → {rows, meta, statistics, rows_before_limit_at_least},
//       exec(sql, params) → text, insertRows(table, rows[]), insertNDJSON(table, ndjson, {dedupToken}), ping() → bool }
//   params: { name: { type: 'String'|'UInt16'|'Int64'|…, value } } → sent as `param_<name>` (use {name:Type} in SQL).
// Inserts are JSONEachRow with a gzip request body. Idempotent requests are retried once (network error, timeout, 502/503/504).
const zlib = require('node:zlib');
const { promisify } = require('node:util');
const gzip = promisify(zlib.gzip);

class CHError extends Error {
  // .status is the HTTP status the API should answer with (502: upstream store failed); .httpStatus is ClickHouse's own.
  constructor(message, { status, code, retriable } = {}) { super(message); this.name = 'CHError'; this.httpStatus = status; this.status = 502; this.expose = true; this.chCode = code; this.retriable = !!retriable; }
}

const NAME_RE = /^[A-Za-z_][A-Za-z0-9_]{0,63}$/;
const TABLE_RE = /^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)?$/;

// Query parameter values use ClickHouse's "escaped" text format: backslash, tab, newline… must be escaped.
function escapeText(s) {
  return s.replace(/[\\\t\n\r\0\b\f]/g, (c) => ({ '\\': '\\\\', '\t': '\\t', '\n': '\\n', '\r': '\\r', '\0': '\\0', '\b': '\\b', '\f': '\\f' })[c]);
}
function quoteLiteral(v) {
  if (typeof v === 'number' || typeof v === 'bigint') return String(v);
  if (v === null || v === undefined) return 'NULL';
  return "'" + String(v).replace(/\\/g, '\\\\').replace(/'/g, "\\'") + "'";
}
function formatParam(p) {
  const v = p && typeof p === 'object' && 'value' in p ? p.value : p;
  if (v === null || v === undefined) return '\\N';
  if (Array.isArray(v)) return escapeText('[' + v.map(quoteLiteral).join(',') + ']');
  if (v instanceof Date) return v.toISOString().replace('T', ' ').replace('Z', '');
  if (typeof v === 'boolean') return v ? 'true' : 'false';
  if (typeof v === 'number' || typeof v === 'bigint') return String(v);
  return escapeText(String(v));
}

function parseCHError(status, text) {
  const m = /Code: (\d+)/.exec(text || '');
  const msg = String(text || '').trim().split('\n')[0].slice(0, 500) || `HTTP ${status}`;
  return new CHError(`ClickHouse: ${msg}`, { status, code: m ? Number(m[1]) : undefined, retriable: status === 502 || status === 503 || status === 504 });
}

function createCH({ url = 'http://127.0.0.1:8123', user = 'default', password = '', database = 'siem', timeout_ms = 30000, log, settings = {} } = {}) {
  const base = String(url).replace(/\/+$/, '');
  const auth = 'Basic ' + Buffer.from(`${user}:${password}`).toString('base64');
  const stats = { queries: 0, inserts: 0, rows_inserted: 0, bytes_sent: 0, errors: 0, retries: 0, last_error: '', last_error_at: 0 };

  function buildUrl(q, params, extra) {
    const u = new URLSearchParams();
    if (database) u.set('database', database);
    u.set('output_format_json_quote_64bit_integers', '0');
    u.set('date_time_output_format', 'iso');
    for (const [k, v] of Object.entries(settings)) u.set(k, String(v));
    for (const [k, v] of Object.entries(extra || {})) if (v !== undefined) u.set(k, String(v));
    if (q) u.set('query', q);
    for (const [name, p] of Object.entries(params || {})) {
      if (!NAME_RE.test(name)) throw new CHError(`invalid parameter name "${name}"`);
      u.set('param_' + name, formatParam(p));
    }
    return base + '/?' + u.toString();
  }

  async function request({ sql, params, body, headers = {}, extra, idempotent = true, timeout = timeout_ms }) {
    const fullUrl = buildUrl(body !== undefined ? sql : null, params, extra);
    const init = {
      method: 'POST',
      headers: { Authorization: auth, ...headers },
      body: body !== undefined ? body : sql,
    };
    for (let attempt = 0; ; attempt++) {
      let res;
      try {
        res = await fetch(fullUrl, { ...init, signal: AbortSignal.timeout(timeout) });
      } catch (e) {
        const timedOut = e && (e.name === 'TimeoutError' || e.name === 'AbortError');
        const err = new CHError(`ClickHouse ${timedOut ? 'timeout after ' + timeout + ' ms' : 'unreachable: ' + ((e.cause && e.cause.code) || e.message)}`, { retriable: true });
        if (attempt === 0 && idempotent) { stats.retries++; await new Promise((r) => setTimeout(r, 200)); continue; }
        note(err);
        throw err;
      }
      const text = await res.text();
      if (res.ok) return text;
      const err = parseCHError(res.status, text);
      if (attempt === 0 && idempotent && err.retriable) { stats.retries++; await new Promise((r) => setTimeout(r, 200)); continue; }
      note(err);
      throw err;
    }
  }

  function note(err) {
    stats.errors++;
    stats.last_error = err.message.slice(0, 300);
    stats.last_error_at = Date.now();
  }

  const hasFormat = (sql) => /\bFORMAT\s+\w+\s*;?\s*$/i.test(sql);

  async function queryFull(sql, params, opts = {}) {
    stats.queries++;
    const q = hasFormat(sql) ? sql : sql.replace(/;\s*$/, '') + '\nFORMAT JSON';
    const extra = { ...(opts.settings || {}) };
    if (opts.readonly) extra.readonly = 2;
    const text = await request({ sql: q, params, extra, timeout: opts.timeout_ms || timeout_ms });
    let j;
    try { j = JSON.parse(text); } catch { throw new CHError('ClickHouse returned non-JSON output'); }
    return { rows: j.data || [], meta: j.meta || [], statistics: j.statistics || {}, rows_before_limit_at_least: j.rows_before_limit_at_least };
  }

  async function query(sql, params, opts) {
    const r = await queryFull(sql, params, opts);
    Object.defineProperty(r.rows, 'info', { value: { statistics: r.statistics, rows_before_limit_at_least: r.rows_before_limit_at_least, meta: r.meta }, enumerable: false });
    return r.rows;
  }

  async function exec(sql, params, opts = {}) {
    stats.queries++;
    return request({ sql, params, extra: opts.settings, timeout: opts.timeout_ms || timeout_ms, idempotent: opts.idempotent !== false });
  }

  function tableName(t) {
    if (!TABLE_RE.test(t)) throw new CHError(`invalid table name "${t}"`);
    return t.includes('.') || !database ? t : `${database}.${t}`;
  }

  async function insertNDJSON(table, ndjson, { dedupToken, settings: s } = {}) {
    const buf = Buffer.isBuffer(ndjson) ? ndjson : Buffer.from(ndjson, 'utf8');
    if (!buf.length) return;
    const body = await gzip(buf, { level: 3 });
    stats.inserts++;
    stats.bytes_sent += body.length;
    const extra = { input_format_skip_unknown_fields: 1, max_partitions_per_insert_block: 1000, ...(s || {}) };
    if (dedupToken) extra.insert_deduplication_token = dedupToken;
    await request({
      sql: `INSERT INTO ${tableName(table)} FORMAT JSONEachRow`, body, extra,
      headers: { 'Content-Encoding': 'gzip', 'Content-Type': 'application/x-ndjson' },
      idempotent: !!dedupToken,
    });
  }

  async function insertRows(table, rows, opts) {
    if (!rows || !rows.length) return;
    let s = '';
    for (const r of rows) s += JSON.stringify(r) + '\n';
    await insertNDJSON(table, s, opts);
    stats.rows_inserted += rows.length;
  }

  async function ping(timeout = 3000) {
    try {
      const res = await fetch(base + '/ping', { signal: AbortSignal.timeout(timeout) });
      return res.ok;
    } catch { return false; }
  }

  return { query, queryFull, exec, insertRows, insertNDJSON, ping, stats: () => ({ ...stats }), database, url: base };
}

module.exports = { createCH, CHError, formatParam, escapeText };
