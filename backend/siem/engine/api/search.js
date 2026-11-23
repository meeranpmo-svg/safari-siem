// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Search service over siem.events (used by the core routes and handed to detect/soc as deps.search).
//   const search = createSearch({ch, config, log});
//   await search({q, from, to, limit, offset, fields, order}) → {rows, total_estimate, took_ms, sql_hint}
//   await search(q, fromMs, toMs, {limit, offset, order})  → same (positional form used by detect/routes.js + scheduled.js)
//   await search.histogram({q, from, to, buckets})        → {buckets:[{t, n}], step_ms}
//   await search.top({q, from, to, field, limit})         → {values:[{v, n}]}
//   await search.rare({q, from, to, field, limit})        → least frequent values first (long tail) {values:[{v, n, first, last, hosts}]}
//   await search.newValues({q, from, to, field, baselineDays}) → values never seen in the baseline days before "from"
//   await search.fetchEvents({q, from, to, limit})        → events in internal form (ts/rts epoch ms) — e.g. for rule tests
//   search.compile(q) / search.compileJS(q) / search.parse(q) — the query language (api/query.js)
const { compile, compileJS, parse, parseTimeValue, QueryError } = require('./query');
const { FIELDS, FIELD_NAMES } = require('../schema');

const MAX_LIMIT = 1000;
const ORDERABLE = FIELD_NAMES.filter((f) => !['tags', 'fields', 'raw'].includes(f));

function bad(msg) { return new QueryError(msg); }

function timeRange(from, to, now = Date.now(), defaultSpanMs = 24 * 3600 * 1000) {
  const t = to === undefined || to === null || to === '' ? now : parseTimeValue(to, now);
  const f = from === undefined || from === null || from === '' ? t - defaultSpanMs : parseTimeValue(from, now);
  if (!(f <= t)) throw bad('"from" must be before "to"');
  if (t - f > 5 * 366 * 86400000) throw bad('time range too large (max 5 years)');
  return { from: f, to: t };
}

function createSearch({ ch, config = {}, log, table } = {}) {
  const db = (config.clickhouse && config.clickhouse.database) || 'siem';
  const tbl = table || `${db}.events`;
  const qopts = { readonly: true, settings: { max_execution_time: 30 } };

  function base(q, from, to) {
    const c = compile(q || '');
    const r = timeRange(from, to);
    c.params.t_from = { type: 'Int64', value: r.from };
    c.params.t_to = { type: 'Int64', value: r.to };
    const where = `ts >= fromUnixTimestamp64Milli({t_from:Int64}) AND ts <= fromUnixTimestamp64Milli({t_to:Int64}) AND ${c.where}`;
    return { where, params: c.params, range: r };
  }

  function columns(fields) {
    if (fields === undefined || fields === null) return FIELD_NAMES;
    if (!Array.isArray(fields) || !fields.length) throw bad('"fields" must be a non-empty array of field names');
    for (const f of fields) if (!FIELDS[f]) throw bad(`unknown field "${f}" in fields`);
    return [...new Set(['ts', 'id', ...fields])];
  }

  function orderBy(order) {
    if (order === undefined || order === null || order === '' || order === 'desc') return 'ts DESC';
    if (order === 'asc') return 'ts ASC';
    const m = /^([a-z_]+)(?:\s+(asc|desc))?$/i.exec(String(order).trim());
    if (!m || !ORDERABLE.includes(m[1])) throw bad(`invalid order "${order}" (use asc|desc or "<field> asc|desc")`);
    return `\`${m[1]}\` ${(m[2] || 'desc').toUpperCase()}${m[1] === 'ts' ? '' : ', ts DESC'}`;
  }

  async function search({ q = '', from, to, limit = 100, offset = 0, fields, order } = {}) {
    const t0 = Date.now();
    const lim = Math.trunc(Number(limit));
    if (!(lim >= 1 && lim <= MAX_LIMIT)) throw bad(`limit must be 1..${MAX_LIMIT}`);
    const off = Math.trunc(Number(offset || 0));
    if (!(off >= 0 && off <= 10000000)) throw bad('offset must be 0..10000000');
    const b = base(q, from, to);
    const cols = columns(fields).map((c) => '`' + c + '`').join(', ');
    b.params.lim = { type: 'UInt32', value: lim };
    b.params.off = { type: 'UInt32', value: off };
    const sql = `SELECT ${cols} FROM ${tbl} WHERE ${b.where} ORDER BY ${orderBy(order)} LIMIT {lim:UInt32} OFFSET {off:UInt32}`;
    const r = await ch.queryFull(sql, b.params, qopts);
    return {
      rows: r.rows,
      total_estimate: r.rows_before_limit_at_least !== undefined ? r.rows_before_limit_at_least : r.rows.length,
      took_ms: Date.now() - t0,
      sql_hint: sql,
      range: b.range,
    };
  }

  async function histogram({ q = '', from, to, buckets = 60 } = {}) {
    const nb = Math.trunc(Number(buckets));
    if (!(nb >= 1 && nb <= 1000)) throw bad('buckets must be 1..1000');
    const b = base(q, from, to);
    const span = Math.max(1, b.range.to - b.range.from);
    const step = Math.max(1000, Math.ceil(span / nb));
    b.params.step = { type: 'Int64', value: step };
    const sql = `SELECT intDiv(toUnixTimestamp64Milli(ts) - {t_from:Int64}, {step:Int64}) AS b, count() AS n FROM ${tbl} WHERE ${b.where} GROUP BY b ORDER BY b`;
    const rows = await ch.query(sql, b.params, qopts);
    const count = Math.ceil(span / step);
    const out = [];
    const byB = new Map(rows.map((r) => [Number(r.b), Number(r.n)]));
    for (let i = 0; i < count; i++) out.push({ t: b.range.from + i * step, n: byB.get(i) || 0 });
    return { buckets: out, step_ms: step, sql_hint: sql };
  }

  // the expression to aggregate a field on, and the condition that it is present (shared by top / rare / newValues)
  function fieldExpr(field, params) {
    if (typeof field !== 'string' || !field) throw bad('"field" is required');
    if (field.startsWith('fields.')) {
      const key = field.slice(7);
      if (!/^[A-Za-z0-9_.:@$-]{1,128}$/.test(key)) throw bad(`invalid fields key "${key}"`);
      params.fkey = { type: 'String', value: key };
      return { expr: 'fields[{fkey:String}]', nonEmpty: "fields[{fkey:String}] != ''" };
    }
    if (field === 'tags') return { expr: 'arrayJoin(tags)', nonEmpty: 'notEmpty(tags)' };
    const d = FIELDS[field];
    if (!d || d.kind === 'map' || field === 'raw' || field === 'id') throw bad(`cannot aggregate on field "${field}"`);
    const e = '`' + field + '`';
    return { expr: d.kind === 'time' ? `toStartOfMinute(${e})` : e, nonEmpty: d.kind === 'num' || d.kind === 'time' ? '1' : `${e} != ''` };
  }
  const limitOf = (limit, max) => { const lim = Math.trunc(Number(limit)); if (!(lim >= 1 && lim <= max)) throw bad(`limit must be 1..${max}`); return lim; };

  async function top({ q = '', from, to, field, limit = 10 } = {}) {
    const lim = limitOf(limit, 100);
    const b = base(q, from, to);
    const { expr, nonEmpty } = fieldExpr(field, b.params);
    b.params.lim = { type: 'UInt32', value: lim };
    const sql = `SELECT ${expr} AS v, count() AS n FROM ${tbl} WHERE ${b.where} AND ${nonEmpty} GROUP BY v ORDER BY n DESC LIMIT {lim:UInt32}`;
    const rows = await ch.query(sql, b.params, qopts);
    return { values: rows.map((r) => ({ v: r.v, n: Number(r.n) })), sql_hint: sql };
  }

  // Hunting: the LEAST frequent values of a field in the window (long-tail analysis - a process run on one host, a domain
  // one user resolved), with when each was first and last seen
  async function rare({ q = '', from, to, field, limit = 25 } = {}) {
    const lim = limitOf(limit, 200);
    const b = base(q, from, to);
    const { expr, nonEmpty } = fieldExpr(field, b.params);
    b.params.lim = { type: 'UInt32', value: lim };
    const sql = `SELECT ${expr} AS v, count() AS n, min(ts) AS first, max(ts) AS last, uniqExact(host) AS hosts FROM ${tbl} WHERE ${b.where} AND ${nonEmpty} GROUP BY v ORDER BY n ASC, last DESC LIMIT {lim:UInt32}`;
    const rows = await ch.query(sql, b.params, qopts);
    return { values: rows.map((r) => ({ v: r.v, n: Number(r.n), first: r.first, last: r.last, hosts: Number(r.hosts) })), sql_hint: sql };
  }

  // Hunting: values seen in the window that never appeared in the baseline days BEFORE it (first-seen: a new process, a new
  // admin, a new outbound domain). The same query applies to both periods.
  async function newValues({ q = '', from, to, field, baselineDays = 14, limit = 50 } = {}) {
    const lim = limitOf(limit, 200);
    const bd = Math.trunc(Number(baselineDays));
    if (!(bd >= 1 && bd <= 90)) throw bad('baselineDays must be 1..90');
    const b = base(q, from, to);
    const { expr, nonEmpty } = fieldExpr(field, b.params);
    const c = compile(q || '');   // the same query, compiled again: identical parameter names and values
    b.params.b_from = { type: 'Int64', value: b.range.from - bd * 86400000 };
    b.params.lim = { type: 'UInt32', value: lim };
    const baseline = `ts >= fromUnixTimestamp64Milli({b_from:Int64}) AND ts < fromUnixTimestamp64Milli({t_from:Int64}) AND ${c.where} AND ${nonEmpty}`;
    const sql = `SELECT ${expr} AS v, count() AS n, min(ts) AS first, max(ts) AS last, uniqExact(host) AS hosts FROM ${tbl} WHERE ${b.where} AND ${nonEmpty} GROUP BY v `
      + `HAVING v NOT IN (SELECT DISTINCT ${expr} FROM ${tbl} WHERE ${baseline}) ORDER BY first DESC LIMIT {lim:UInt32}`;
    const rows = await ch.query(sql, b.params, { ...qopts, settings: { max_execution_time: 60 } });
    return { values: rows.map((r) => ({ v: r.v, n: Number(r.n), first: r.first, last: r.last, hosts: Number(r.hosts) })), baseline_days: bd, sql_hint: sql };
  }

  // Internal-form events (for rule testing / scheduled searches): ts/rts back to epoch ms, fields as object.
  async function fetchEvents({ q = '', from, to, limit = 10000, order = 'asc' } = {}) {
    const lim = Math.trunc(Number(limit));
    if (!(lim >= 1 && lim <= 100000)) throw bad('limit must be 1..100000');
    const b = base(q, from, to);
    b.params.lim = { type: 'UInt32', value: lim };
    const sql = `SELECT * FROM ${tbl} WHERE ${b.where} ORDER BY ts ${order === 'desc' ? 'DESC' : 'ASC'} LIMIT {lim:UInt32}`;
    const rows = await ch.query(sql, b.params, { ...qopts, settings: { max_execution_time: 120 }, timeout_ms: 130000 });
    for (const r of rows) {
      r.ts = Date.parse(r.ts);
      r.rts = Date.parse(r.rts);
      if (!r.fields || typeof r.fields !== 'object') r.fields = {};
    }
    return rows;
  }

  const fn = (a, from, to, opts) => (typeof a === 'string' || a === undefined || a === null
    ? search({ ...(opts || {}), q: a || '', from, to })
    : search(a));
  fn.search = search;
  fn.histogram = histogram;
  fn.top = top;
  fn.rare = rare;
  fn.newValues = newValues;
  fn.fetchEvents = fetchEvents;
  fn.compile = compile;
  fn.compileJS = compileJS;
  fn.parse = parse;
  fn.timeRange = timeRange;
  void log;
  return fn;
}

module.exports = { createSearch, timeRange };
