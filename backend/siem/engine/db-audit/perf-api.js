// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Oracle performance API backend (docs/ORACLE.md section 4.6; routes in routes.js; portal module ui/as-dbperf-module.js).
 *
 *   createOraclePerf({ ch, alerts, log, now, table = 'siem.events', staleS = 300 })
 *     → { stage(ev), perf(q), topsql(q), sessions(q), capacity(q), stats() }
 *
 * Source of truth: ClickHouse siem.events (src_type 'oracle-health', tag 'db-perf'); metric values are read from the
 * fields map with toFloat64OrZero(fields['x']). Every query is parameterised ({name:Type}); aggregate aliases end in
 * "_v" and never reuse a column name (ClickHouse 26.8 rejects an alias that shadows a column used inside another
 * aggregate — e.g. max(ts) AS ts). stage() keeps a bounded in-memory copy of recent perf events so the API stays live
 * while ClickHouse is down / not configured, and fills the minutes not yet flushed to ClickHouse.
 */
const P = require('./oracle-perf');

const LOAD_METRICS = ['aas', 'db_time_s', 'db_cpu_s', 'executions_s', 'user_calls_s', 'transactions_s', 'logical_reads_s', 'physical_reads_s', 'physical_writes_s',
  'physical_read_mb_s', 'physical_write_mb_s', 'redo_mb_s', 'hard_parses_s', 'soft_parses_s', 'logons_s', 'network_mb_s', 'host_cpu_pct', 'cpu_count'];
const EFF_METRICS = ['buffer_cache_hit_pct', 'library_cache_hit_pct', 'soft_parse_pct', 'execute_to_parse_pct'];
const CLASS_FIELDS = Object.keys(P.CLASS_KEYS);
const PERIODS = { '1h': 3600, '6h': 21600, '24h': 86400, '7d': 604800 };
const SQL_BY = { elapsed: 'elapsed_s', cpu: 'cpu_s', gets: 'buffer_gets', reads: 'disk_reads', execs: 'executions' };
const CAP_ACTIONS = ['temp-undo', 'memory', 'resource-limit', 'redo-rate', 'archive-dest', 'asm-diskgroup', 'tablespace-growth', 'host-stats'];
const SESS_ACTIONS = ['load-profile', 'active-sessions', 'blocking-chain', 'long-query', 'active-session', 'active-sql'];
const MAX_RANGE_MS = 31 * 86400000;
const MAX_POINTS = 720;
const MEM_CAP = { 'load-profile': 6000, 'wait-event': 24000, 'wait-class-rate': 20000, 'active-sessions': 3000, 'efficiency': 3000, 'latch-hotspot': 8000, 'active-sql': 15000,
  'active-session': 15000, 'top-sql-delta': 20000, 'plan-change': 2000, 'blocking-chain': 5000, 'long-query': 5000, 'host-stats': 3000, 'tablespace-usage': 0 };
const DAY = 86400000;

class PerfError extends Error { constructor(code, msg) { super(msg); this.code = code; this.errors = [msg]; } }
const num = P.num;
function s(v) { return v === undefined || v === null ? '' : String(v); }
function r(n, d = 3) { if (n === null || n === undefined || !Number.isFinite(n)) return null; const p = 10 ** d; return Math.round(n * p) / p; }
function chTs(v) { if (typeof v === 'number') return v; const t = Date.parse(String(v).replace(' ', 'T') + (/[Zz]|[+-]\d\d:?\d\d$/.test(String(v)) ? '' : 'Z')); return Number.isFinite(t) ? t : 0; }
function fv(row, k) { return num(row && row[k]); }
function tparam(v, dflt) {
  if (v === undefined || v === null || v === '') return dflt;
  const n = Number(v);
  if (Number.isFinite(n)) return n < 1e11 ? n * 1000 : n;
  const t = Date.parse(v);
  if (!Number.isFinite(t)) throw new PerfError(400, `invalid time "${v}"`);
  return t;
}

// ---------------------------------------------------------------------------------------------------------- SQL ---
// (exported for the static alias / parameter test). T = table name (configuration, never user input).
const avgs = (list, fn) => list.map((m) => `${fn}(toFloat64OrZero(fields['${m}'])) AS ${m}_v`).join(', ');
const WHERE_INST = `src_type = 'oracle-health' AND host = {host:String} AND fields['instance'] = {inst:String}`;
const WHERE_RANGE = `ts >= fromUnixTimestamp64Milli({t_from:Int64}) AND ts < fromUnixTimestamp64Milli({t_to:Int64})`;
const BUCKET = `intDiv(toUnixTimestamp64Milli(ts), {step:Int64}) * {step:Int64} AS bucket_v`;
const SQL = {
  instances: (T) => `/* perf:instances */ SELECT host, fields['instance'] AS inst_v, fields['db_name'] AS db_v, fields['scope'] AS scope_v, fields['key'] AS con_v,
      max(ts) AS last_v, argMax(fields['cpu_count'], ts) AS cpu_v, argMax(fields['version'], ts) AS ver_v
    FROM ${T} WHERE src_type = 'oracle-health' AND action = 'load-profile' AND ts >= now() - INTERVAL {h:UInt32} HOUR
    GROUP BY host, inst_v, db_v, scope_v, con_v ORDER BY host, inst_v LIMIT 2000`,
  load: (T) => `/* perf:load */ SELECT ${BUCKET}, ${avgs(LOAD_METRICS, 'avg')}, max(toFloat64OrZero(fields['aas'])) AS aas_max_v, count() AS n_v
    FROM ${T} WHERE ${WHERE_INST} AND action = 'load-profile' AND fields['key'] = {con:String} AND ${WHERE_RANGE}
    GROUP BY bucket_v ORDER BY bucket_v`,
  classes: (T) => `/* perf:classes */ SELECT ${BUCKET}, ${avgs(CLASS_FIELDS.map((c) => 'aas_' + c), 'avg')}, avg(toFloat64OrZero(fields['aas'])) AS total_v
    FROM ${T} WHERE ${WHERE_INST} AND action = 'active-sessions' AND ${WHERE_RANGE}
    GROUP BY bucket_v ORDER BY bucket_v`,
  efficiency: (T) => `/* perf:efficiency */ SELECT ${BUCKET}, ${avgs(EFF_METRICS, 'avg')}
    FROM ${T} WHERE ${WHERE_INST} AND action = 'efficiency' AND ${WHERE_RANGE}
    GROUP BY bucket_v ORDER BY bucket_v`,
  waitClasses: (T) => `/* perf:waitclasses */ SELECT fields['key'] AS cls_v, avg(toFloat64OrZero(fields['time_s'])) AS time_v, avg(toFloat64OrZero(fields['waits_s'])) AS waits_v,
      avg(toFloat64OrZero(fields['dbtime_pct'])) AS dbt_v
    FROM ${T} WHERE ${WHERE_INST} AND action = 'wait-class-rate' AND ${WHERE_RANGE}
    GROUP BY cls_v ORDER BY time_v DESC LIMIT 20`,
  waitEvents: (T) => `/* perf:waitevents */ SELECT fields['key'] AS ev_v, any(fields['class']) AS cls_v, sum(toFloat64OrZero(fields['d_time_us'])) AS time_us_v,
      sum(toFloat64OrZero(fields['d_waits'])) AS waits_v, sum(toFloat64OrZero(fields['elapsed_s'])) AS el_v, sum(toFloat64OrZero(fields['fg_time_s']) * toFloat64OrZero(fields['elapsed_s'])) AS fg_v
    FROM ${T} WHERE ${WHERE_INST} AND action = 'wait-event' AND ${WHERE_RANGE}
    GROUP BY ev_v ORDER BY time_us_v DESC LIMIT 25`,
  latches: (T) => `/* perf:latches */ SELECT fields['key'] AS name_v, any(fields['type']) AS type_v, avg(toFloat64OrZero(fields['sleeps_s'])) AS sleeps_v,
      avg(toFloat64OrZero(fields['miss_pct'])) AS miss_v
    FROM ${T} WHERE ${WHERE_INST} AND action = 'latch-hotspot' AND ${WHERE_RANGE}
    GROUP BY name_v ORDER BY sleeps_v DESC LIMIT 10`,
  topsql: (T) => `/* perf:topsql */ SELECT fields['sql_id'] AS sql_v, fields['plan_hash'] AS plan_v,
      sum(toFloat64OrZero(fields['executions'])) AS execs_v, sum(toFloat64OrZero(fields['d_ela_us'])) AS ela_v, sum(toFloat64OrZero(fields['d_cpu_us'])) AS cpu_v,
      sum(toFloat64OrZero(fields['buffer_gets'])) AS gets_v, sum(toFloat64OrZero(fields['disk_reads'])) AS reads_v, sum(toFloat64OrZero(fields['rows_processed'])) AS rows_v,
      anyLast(fields['module']) AS module_v, anyLast(user) AS user_v, anyLast(fields['sql_text']) AS text_v, min(ts) AS first_v, max(ts) AS last_v
    FROM ${T} WHERE ${WHERE_INST} AND action = 'top-sql-delta' AND ${WHERE_RANGE}
    GROUP BY sql_v, plan_v ORDER BY ela_v DESC LIMIT 500`,
  planChanges: (T) => `/* perf:planchanges */ SELECT fields['key'] AS sql_v, argMax(fields, ts) AS f_v, max(ts) AS last_v
    FROM ${T} WHERE ${WHERE_INST} AND action = 'plan-change' AND ${WHERE_RANGE}
    GROUP BY sql_v ORDER BY last_v DESC LIMIT 200`,
  activity: (T) => `/* perf:activity */ SELECT fields['key'] AS sql_v, sum(toFloat64OrZero(fields['aas'])) AS aas_sum_v, sum(toFloat64OrZero(fields['count'])) AS cnt_v,
      anyLast(fields['top_event']) AS ev_v, anyLast(fields['module']) AS module_v
    FROM ${T} WHERE ${WHERE_INST} AND action = 'active-sql' AND ${WHERE_RANGE}
    GROUP BY sql_v ORDER BY aas_sum_v DESC LIMIT 20`,
  activityMinutes: (T) => `/* perf:activityminutes */ SELECT count() AS n_v FROM ${T} WHERE ${WHERE_INST} AND action = 'active-sessions' AND ${WHERE_RANGE}`,
  sqlHistory: (T) => `/* perf:sqlhistory */ SELECT fields['plan_hash'] AS plan_v, ${BUCKET}, sum(toFloat64OrZero(fields['executions'])) AS execs_v,
      sum(toFloat64OrZero(fields['d_ela_us'])) AS ela_v, sum(toFloat64OrZero(fields['d_cpu_us'])) AS cpu_v, sum(toFloat64OrZero(fields['buffer_gets'])) AS gets_v
    FROM ${T} WHERE ${WHERE_INST} AND action = 'top-sql-delta' AND fields['sql_id'] = {sql:String} AND ${WHERE_RANGE}
    GROUP BY plan_v, bucket_v ORDER BY bucket_v`,
  sessions: (T) => `/* perf:sessions */ SELECT action, fields['key'] AS k_v, ts AS t_v, user AS u_v, fields AS f_v
    FROM ${T} WHERE ${WHERE_INST} AND action IN ('load-profile', 'active-sessions', 'blocking-chain', 'long-query', 'active-session', 'active-sql')
      AND ts >= now() - INTERVAL 15 MINUTE ORDER BY t_v DESC LIMIT 3000`,
  capacity: (T) => `/* perf:capacity */ SELECT host, fields['instance'] AS inst_v, fields['db_name'] AS db_v, action, fields['key'] AS k_v, max(ts) AS last_v,
      argMax(fields, ts) AS f_v, argMax(severity, ts) AS sev_v
    FROM ${T} WHERE src_type = 'oracle-health' AND action IN ('temp-undo', 'memory', 'resource-limit', 'redo-rate', 'archive-dest', 'asm-diskgroup', 'tablespace-growth', 'host-stats')
      AND ts >= now() - INTERVAL 8 DAY
    GROUP BY host, inst_v, db_v, action, k_v LIMIT 20000`,
  growth: (T) => `/* perf:growth */ SELECT host, fields['instance'] AS inst_v, fields['key'] AS tbs_v, toDate(ts) AS day_v,
      max(toFloat64OrZero(fields['used_mb'])) AS used_v, max(toFloat64OrZero(fields['max_mb'])) AS max_v
    FROM ${T} WHERE src_type = 'oracle-health' AND action IN ('tablespace-usage', 'tablespace-growth') AND ts >= now() - INTERVAL 60 DAY
    GROUP BY host, inst_v, tbs_v, day_v ORDER BY day_v LIMIT 100000`,
};

function createOraclePerf({ ch, alerts, log, now = Date.now, table = 'siem.events', staleS = 300 } = {}) {
  const mem = new Map(); // "host|INST" → { key, host, instance, db_name, last_seen, cpu_count, version, pdbs:Set, a:{action → [{ts,key,user,f,sev}]}, days:Map }
  const st = { staged: 0, ch_queries: 0, ch_errors: 0, last_ch_error: '' };
  const keyOf = (host, inst) => `${String(host || '').toLowerCase()}|${String(inst || '').toUpperCase()}`;

  // ------------------------------------------------------------------------------------------------ memory stage ---
  function slot(ev) {
    const f = ev.fields || {};
    const k = keyOf(ev.host, f.instance);
    let m = mem.get(k);
    if (!m) { m = { key: k, host: String(ev.host || ''), instance: String(f.instance || '').toUpperCase(), db_name: String(f.db_name || f.instance || '').toUpperCase(), last_seen: 0, cpu_count: null, version: '', pdbs: new Set(), a: Object.create(null), days: new Map() }; mem.set(k, m); if (mem.size > 500) mem.delete(mem.keys().next().value); }
    return m;
  }
  function stage(ev) {
    if (!ev || ev.src_type !== 'oracle-health' || !Array.isArray(ev.tags) || ev.tags.indexOf('oracle') < 0) return;
    const f = ev.fields || {};
    if (ev.action === 'tablespace-usage' || ev.action === 'tablespace-growth') { // daily points for the growth forecast
      const m = slot(ev); const tb = String(f.key || f.name || '').toUpperCase(); const used = num(f.used_mb);
      if (tb && used !== null) {
        const d = Math.floor((ev.ts || now()) / DAY);
        let t = m.days.get(tb); if (!t) { t = new Map(); m.days.set(tb, t); if (m.days.size > 2000) m.days.delete(m.days.keys().next().value); }
        const prev = t.get(d); t.set(d, { used_mb: Math.max(used, prev ? prev.used_mb : 0), max_mb: num(f.max_mb) });
        if (t.size > 62) t.delete(Math.min(...t.keys()));
      }
      if (ev.action === 'tablespace-usage') return;
    }
    if (ev.tags.indexOf('db-perf') < 0) return;
    st.staged++;
    const m = slot(ev);
    const ts = ev.ts || now();
    if (ts > m.last_seen) m.last_seen = ts;
    if (ev.action === 'load-profile') {
      if (f.scope === 'pdb') { if (f.key) m.pdbs.add(f.key); } else { if (num(f.cpu_count) !== null) m.cpu_count = num(f.cpu_count); if (f.version) m.version = f.version; if (f.db_name) m.db_name = String(f.db_name).toUpperCase(); }
    }
    const arr = m.a[ev.action] || (m.a[ev.action] = []);
    arr.push({ ts, key: f.key || '', user: ev.user || '', sev: ev.severity || 0, f: Object.assign({}, f) });
    const cap = MEM_CAP[ev.action] !== undefined ? MEM_CAP[ev.action] : 2000;
    if (arr.length > cap) arr.splice(0, arr.length - cap);
  }
  const memRows = (m, action, from, to, pred) => ((m && m.a[action]) || []).filter((x) => x.ts >= from && x.ts < to && (!pred || pred(x)));

  // --------------------------------------------------------------------------------------------------- ClickHouse ---
  let chState = { ok: !!(ch && typeof ch.query === 'function'), error: ch && typeof ch.query === 'function' ? '' : 'clickhouse not configured' };
  async function q(name, params) {
    if (!ch || typeof ch.query !== 'function') return null;
    try {
      st.ch_queries++;
      const rows = await ch.query(SQL[name](table), params || {});
      return Array.isArray(rows) ? rows : [];
    } catch (e) {
      st.ch_errors++; st.last_ch_error = e.message; chState = { ok: false, error: e.message };
      if (log && log.warn) log.warn('oracle perf: ClickHouse query failed — serving in-memory data', { query: name, err: e.message });
      return null;
    }
  }
  // The fleet-wide aggregations (instances over 8 days, capacity over 8 days, tablespace growth over 60 days) scan weeks of
  // oracle-health events and ran on every page load, for every user - the Database Dashboard sat on "Loading" while they ran.
  // They are cached for CACHE_MS; callers arriving together share one query; once the cache is old, the last good answer is
  // served (up to STALE_MS) while one refresh runs. A failed query is never cached. Recent events still come from memory (mem).
  const CACHE_MS = 5 * 60000, STALE_MS = 60 * 60000, QC = new Map();
  function qc(name, params) {
    const k = name + '|' + JSON.stringify(params || {}), c = QC.get(k) || (QC.set(k, { rows: null, at: 0, busy: null }), QC.get(k)), t = now();
    if (c.rows && t - c.at < CACHE_MS) { st.ch_cache_hits = (st.ch_cache_hits || 0) + 1; return Promise.resolve(c.rows); }
    if (!c.busy) c.busy = q(name, params).then((rows) => { if (rows) { c.rows = rows; c.at = now(); } return rows; }).finally(() => { c.busy = null; });
    if (c.rows && t - c.at < STALE_MS) { st.ch_cache_stale = (st.ch_cache_stale || 0) + 1; return Promise.resolve(c.rows); }
    return c.busy;
  }
  function resetCh() { chState = { ok: !!(ch && typeof ch.query === 'function'), error: ch && typeof ch.query === 'function' ? '' : 'clickhouse not configured' }; }
  const P_INST = (i) => ({ host: { type: 'String', value: i.host }, inst: { type: 'String', value: i.instance } });
  const P_RANGE = (from, to) => ({ t_from: { type: 'Int64', value: Math.floor(from) }, t_to: { type: 'Int64', value: Math.floor(to) } });

  async function instances(hours = 24 * 8) {
    const out = new Map();
    const rows = await qc('instances', { h: { type: 'UInt32', value: hours } });
    for (const x of rows || []) {
      const k = keyOf(x.host, x.inst_v);
      const i = out.get(k) || (out.set(k, { key: k, host: s(x.host), instance: s(x.inst_v).toUpperCase(), db_name: s(x.db_v || x.inst_v).toUpperCase(), pdbs: new Set(), cpu_count: null, version: '', last_seen: 0 }), out.get(k));
      if (s(x.scope_v) === 'pdb' && x.con_v) i.pdbs.add(s(x.con_v).toUpperCase());
      else { if (num(x.cpu_v) !== null) i.cpu_count = num(x.cpu_v); if (x.ver_v) i.version = s(x.ver_v); }
      i.last_seen = Math.max(i.last_seen, chTs(x.last_v));
    }
    for (const m of mem.values()) {
      if (!m.a['load-profile'] && !CAP_ACTIONS.some((a) => m.a[a])) continue;
      const i = out.get(m.key) || (out.set(m.key, { key: m.key, host: m.host, instance: m.instance, db_name: m.db_name, pdbs: new Set(), cpu_count: null, version: '', last_seen: 0 }), out.get(m.key));
      for (const p of m.pdbs) i.pdbs.add(p);
      if (m.cpu_count !== null) i.cpu_count = m.cpu_count;
      if (m.version) i.version = m.version;
      i.last_seen = Math.max(i.last_seen, m.last_seen);
    }
    const t = now();
    return [...out.values()].map((i) => Object.assign(i, { pdbs: [...i.pdbs].sort(), stale: !i.last_seen || t - i.last_seen > staleS * 1000 })).sort((a, b) => a.key.localeCompare(b.key));
  }
  function resolve(list, want) {
    const w = s(want).trim();
    if (!w) return list[0] || null;
    if (w.includes('|')) { const [h, i] = w.split('|'); return list.find((x) => x.key === keyOf(h, i)) || null; }
    return list.find((x) => x.instance === w.toUpperCase()) || null;
  }
  async function target(qq, list) {
    const inst = resolve(list, qq.instance);
    if (s(qq.instance) && !inst) throw new PerfError(404, `oracle instance ${s(qq.instance).slice(0, 80)} not found`);
    return inst;
  }
  function openAlerts(inst) {
    if (!alerts || typeof alerts.all !== 'function') return [];
    return alerts.all((a) => (/^SENTRA-ORAP-/.test(a.rule_id || '') || a.rule_id === 'SENTRA-ORA-009' || a.rule_id === 'SENTRA-ORA-010') && !/^closed-/.test(a.status || ''))
      .map((a) => ({ id: a.id, rule_id: a.rule_id, rule_name: a.rule_name, severity: a.severity, status: a.status, count: a.count, ts_first: a.ts_first, ts_last: a.ts_last, summary: a.summary,
        host: a.host || (a.group && a.group.host) || '', instance: (a.group && a.group['fields.instance']) || (a.fields && a.fields.instance) || '' }))
      .filter((a) => !inst || (a.instance ? a.instance.toUpperCase() === inst.instance : a.host.toLowerCase() === inst.host.toLowerCase()))
      .sort((a, b) => (b.severity - a.severity) || ((b.ts_last || 0) - (a.ts_last || 0))).slice(0, 200);
  }
  const pub = (i) => (i ? { key: i.key, host: i.host, instance: i.instance, db_name: i.db_name, pdbs: i.pdbs, cpu_count: i.cpu_count, version: i.version, last_seen: i.last_seen, stale: i.stale } : null);

  // -------------------------------------------------------------------------------------------------------- perf ---
  function bucketsMem(rows, step, metrics, maxKey) {
    const b = new Map();
    for (const x of rows) {
      const k = Math.floor(x.ts / step) * step;
      const o = b.get(k) || (b.set(k, { bucket_v: k, n: 0, sums: {}, cnt: {}, mx: null }), b.get(k));
      o.n++;
      for (const m of metrics) { const v = num(x.f[m]); if (v !== null) { o.sums[m] = (o.sums[m] || 0) + v; } o.cnt[m] = (o.cnt[m] || 0) + 1; }
      if (maxKey) { const v = num(x.f[maxKey]); if (v !== null && (o.mx === null || v > o.mx)) o.mx = v; }
    }
    return [...b.values()].map((o) => { const row = { bucket_v: o.bucket_v, n_v: o.n }; for (const m of metrics) row[m + '_v'] = (o.sums[m] || 0) / (o.cnt[m] || 1); if (maxKey) row[maxKey + '_max_v'] = o.mx === null ? 0 : o.mx; return row; });
  }
  function mergeBuckets(chRows, memRowsB) {
    const m = new Map();
    for (const x of chRows || []) m.set(Number(x.bucket_v), x);
    for (const x of memRowsB) if (!m.has(Number(x.bucket_v))) m.set(Number(x.bucket_v), x);
    return [...m.values()].sort((a, b) => Number(a.bucket_v) - Number(b.bucket_v));
  }
  function stepFor(from, to, want) {
    let step = 0;
    if (want !== undefined && want !== null && want !== '') { const n = Number(want); if (!Number.isFinite(n) || n <= 0) throw new PerfError(400, `invalid step "${want}"`); step = n < 1e5 ? n * 1000 : n; }
    if (!step) step = Math.ceil((to - from) / 360 / 60000) * 60000;
    step = Math.max(60000, Math.min(DAY, step));
    while ((to - from) / step > MAX_POINTS) step *= 2;
    return step;
  }

  async function perf(qq = {}) {
    resetCh();
    const t = now();
    const to = tparam(qq.to, t); const from = tparam(qq.from, to - 3600000);
    if (!(to > from)) throw new PerfError(400, 'from must be before to');
    if (to - from > MAX_RANGE_MS) throw new PerfError(400, 'range too large (max 31 days)');
    const step = stepFor(from, to, qq.step);
    const list = await instances();
    const inst = await target(qq, list);
    const con = s(qq.con).toUpperCase();
    if (con && inst && inst.pdbs.indexOf(con) < 0) throw new PerfError(404, `PDB ${con.slice(0, 80)} not reported by ${inst.instance}`);
    const base = { generated_at: new Date(t).toISOString(), from, to, step_s: step / 1000, instances: list.map(pub), instance: pub(inst), con, thresholds: { aas_per_cpu: P.DEFAULTS.aas_per_cpu, log_file_sync_ms: P.DEFAULTS.log_file_sync_ms, seq_read_ms: P.DEFAULTS.seq_read_ms } };
    if (!inst) return Object.assign(base, { clickhouse: chState, series: { ts: [] }, aas_by_class: { ts: [], classes: [] }, efficiency: { ts: [], latest: null }, wait_classes: [], wait_events: [], latches: [], summary: null, alerts: openAlerts(null) });
    const m = mem.get(inst.key);
    const pr = Object.assign(P_INST(inst), P_RANGE(from, to), { step: { type: 'Int64', value: step } });
    const [loadCH, clsCH, effCH, wcCH, weCH, laCH] = await Promise.all([
      q('load', Object.assign({ con: { type: 'String', value: con } }, pr)), q('classes', pr), q('efficiency', pr),
      q('waitClasses', Object.assign(P_INST(inst), P_RANGE(from, to))), q('waitEvents', Object.assign(P_INST(inst), P_RANGE(from, to))), q('latches', Object.assign(P_INST(inst), P_RANGE(from, to)))]);
    // load profile series
    const load = mergeBuckets(loadCH, bucketsMem(memRows(m, 'load-profile', from, to, (x) => (x.key || '') === con), step, LOAD_METRICS, 'aas'));
    const series = { ts: load.map((x) => Number(x.bucket_v)) };
    for (const k of LOAD_METRICS) series[k] = load.map((x) => r(fv(x, k + '_v')));
    series.aas_max = load.map((x) => r(fv(x, 'aas_max_v')));
    // AAS by wait class (licence-free capture)
    const cls = mergeBuckets(clsCH, bucketsMem(memRows(m, 'active-sessions', from, to), step, CLASS_FIELDS.map((c) => 'aas_' + c).concat(['aas']), null).map((x) => Object.assign(x, { total_v: x.aas_v })));
    const classes = CLASS_FIELDS.map((c) => ({ key: c, name: P.CLASS_KEYS[c], values: cls.map((x) => r(fv(x, `aas_${c}_v`)) || 0) })).filter((c) => c.values.some((v) => v > 0));
    // efficiency
    const eff = mergeBuckets(effCH, bucketsMem(memRows(m, 'efficiency', from, to), step, EFF_METRICS, null));
    const efficiency = { ts: eff.map((x) => Number(x.bucket_v)) };
    for (const k of EFF_METRICS) efficiency[k] = eff.map((x) => r(fv(x, k + '_v'), 2));
    efficiency.latest = eff.length ? EFF_METRICS.reduce((o, k) => Object.assign(o, { [k]: r(fv(eff[eff.length - 1], k + '_v'), 2) }), {}) : null;
    // wait classes / events / latches over the range
    let wc = wcCH && wcCH.length ? wcCH : null;
    if (!wc) { const g = new Map(); for (const x of memRows(m, 'wait-class-rate', from, to)) { const o = g.get(x.key) || (g.set(x.key, { cls_v: x.key, t: 0, w: 0, d: 0, n: 0 }), g.get(x.key)); o.t += num(x.f.time_s) || 0; o.w += num(x.f.waits_s) || 0; o.d += num(x.f.dbtime_pct) || 0; o.n++; } wc = [...g.values()].map((o) => ({ cls_v: o.cls_v, time_v: o.t / o.n, waits_v: o.w / o.n, dbt_v: o.d / o.n })); }
    const wcTotal = wc.reduce((tt, x) => tt + (fv(x, 'time_v') || 0), 0);
    const wait_classes = wc.map((x) => ({ class: s(x.cls_v), time_s: r(fv(x, 'time_v')), waits_s: r(fv(x, 'waits_v'), 2), dbtime_pct: r(fv(x, 'dbt_v'), 1), pct: wcTotal > 0 ? r((fv(x, 'time_v') || 0) / wcTotal * 100, 1) : null })).sort((a, b) => (b.time_s || 0) - (a.time_s || 0));
    let we = weCH && weCH.length ? weCH : null;
    if (!we) { const g = new Map(); for (const x of memRows(m, 'wait-event', from, to)) { const o = g.get(x.key) || (g.set(x.key, { ev_v: x.key, cls_v: x.f.class || '', time_us_v: 0, waits_v: 0, el_v: 0, fg_v: 0 }), g.get(x.key)); o.time_us_v += num(x.f.d_time_us) || 0; o.waits_v += num(x.f.d_waits) || 0; o.el_v += num(x.f.elapsed_s) || 0; o.fg_v += (num(x.f.fg_time_s) || 0) * (num(x.f.elapsed_s) || 0); } we = [...g.values()].sort((a, b) => b.time_us_v - a.time_us_v).slice(0, 25); }
    const covered = Math.max(1, ...we.map((x) => fv(x, 'el_v') || 0));
    const weTotal = we.reduce((tt, x) => tt + (fv(x, 'fg_v') || 0), 0);
    const wait_events = we.map((x) => { const tu = fv(x, 'time_us_v') || 0; const w = fv(x, 'waits_v') || 0; return { event: s(x.ev_v), class: s(x.cls_v), avg_ms: w > 0 ? r(tu / w / 1000) : null, waits_s: r(w / covered, 2), time_s: r(tu / 1e6 / covered), pct: weTotal > 0 ? r((fv(x, 'fg_v') || 0) / weTotal * 100, 1) : null, waits: w, time_waited_s: r(tu / 1e6, 1) }; })
      .map((e) => Object.assign(e, { over: (e.event === 'log file sync' && e.avg_ms > P.DEFAULTS.log_file_sync_ms) || (e.event === 'db file sequential read' && e.avg_ms > P.DEFAULTS.seq_read_ms) }))
      .slice(0, 15);
    let la = laCH && laCH.length ? laCH : null;
    if (!la) { const g = new Map(); for (const x of memRows(m, 'latch-hotspot', from, to)) { const o = g.get(x.key) || (g.set(x.key, { name_v: x.key, type_v: x.f.type || '', s: 0, mi: 0, n: 0 }), g.get(x.key)); o.s += num(x.f.sleeps_s) || 0; o.mi += num(x.f.miss_pct) || 0; o.n++; } la = [...g.values()].map((o) => ({ name_v: o.name_v, type_v: o.type_v, sleeps_v: o.s / o.n, miss_v: o.mi / o.n })).sort((a, b) => b.sleeps_v - a.sleeps_v).slice(0, 10); }
    const latches = la.map((x) => ({ name: s(x.name_v), type: s(x.type_v), sleeps_s: r(fv(x, 'sleeps_v')), miss_pct: r(fv(x, 'miss_v'), 3) }));
    const vals = (a) => a.filter((v) => v !== null);
    const avg = (a) => { const v = vals(a); return v.length ? r(v.reduce((x, y) => x + y, 0) / v.length) : null; };
    const summary = series.ts.length ? {
      points: series.ts.length, cpu_count: inst.cpu_count, aas_avg: avg(series.aas), aas_max: vals(series.aas_max).length ? Math.max(...vals(series.aas_max)) : null, aas_latest: series.aas[series.aas.length - 1],
      db_time_s_avg: avg(series.db_time_s), db_cpu_s_avg: avg(series.db_cpu_s), executions_s_avg: avg(series.executions_s), transactions_s_avg: avg(series.transactions_s),
      logical_reads_s_avg: avg(series.logical_reads_s), physical_reads_s_avg: avg(series.physical_reads_s), redo_mb_s_avg: avg(series.redo_mb_s), host_cpu_pct_avg: avg(series.host_cpu_pct),
    } : null;
    return Object.assign(base, { clickhouse: chState, series, aas_by_class: { ts: cls.map((x) => Number(x.bucket_v)), classes }, efficiency, wait_classes, wait_events, latches, summary, alerts: openAlerts(inst) });
  }

  // ------------------------------------------------------------------------------------------------------ topsql ---
  async function topsql(qq = {}) {
    resetCh();
    const t = now();
    const period = PERIODS[s(qq.period)] ? s(qq.period) : (s(qq.period) ? null : '1h');
    if (!period) throw new PerfError(400, `period must be one of ${Object.keys(PERIODS).join(', ')}`);
    const by = SQL_BY[s(qq.by)] ? s(qq.by) : (s(qq.by) ? null : 'elapsed');
    if (!by) throw new PerfError(400, `by must be one of ${Object.keys(SQL_BY).join(', ')}`);
    const sqlId = s(qq.sql_id).trim();
    if (sqlId && !/^[0-9a-z]{1,20}$/i.test(sqlId)) throw new PerfError(400, 'invalid sql_id');
    const showText = !!qq._sql_text;
    const to = t; const from = to - PERIODS[period] * 1000;
    const list = await instances();
    const inst = await target(qq, list);
    const base = { generated_at: new Date(t).toISOString(), period, period_s: PERIODS[period], by, sql_text_visible: showText, instances: list.map(pub), instance: pub(inst), plan_ratio: P.DEFAULTS.plan_ratio };
    if (!inst) return Object.assign(base, { clickhouse: chState, sql: [], plan_changes: [], activity: [], activity_minutes: 0, detail: null });
    const m = mem.get(inst.key);
    const pr = Object.assign(P_INST(inst), P_RANGE(from, to));
    const [aggCH, pcCH, actCH, minCH] = await Promise.all([q('topsql', pr), q('planChanges', pr), q('activity', pr), q('activityMinutes', pr)]);
    let agg = aggCH && aggCH.length ? aggCH : null;
    if (!agg) {
      const g = new Map();
      for (const x of memRows(m, 'top-sql-delta', from, to)) {
        const k = `${x.f.sql_id}:${x.f.plan_hash}`;
        const o = g.get(k) || (g.set(k, { sql_v: x.f.sql_id || '', plan_v: x.f.plan_hash || '', execs_v: 0, ela_v: 0, cpu_v: 0, gets_v: 0, reads_v: 0, rows_v: 0, module_v: '', user_v: '', text_v: '', first_v: x.ts, last_v: x.ts }), g.get(k));
        o.execs_v += num(x.f.executions) || 0; o.ela_v += num(x.f.d_ela_us) || 0; o.cpu_v += num(x.f.d_cpu_us) || 0; o.gets_v += num(x.f.buffer_gets) || 0; o.reads_v += num(x.f.disk_reads) || 0; o.rows_v += num(x.f.rows_processed) || 0;
        if (x.f.module) o.module_v = x.f.module; if (x.user) o.user_v = x.user; if (x.f.sql_text) o.text_v = x.f.sql_text; o.first_v = Math.min(o.first_v, x.ts); o.last_v = Math.max(o.last_v, x.ts);
      }
      agg = [...g.values()];
    }
    const plansRows = agg.map((x) => ({ sql_id: s(x.sql_v), plan_hash: s(x.plan_v), executions: fv(x, 'execs_v') || 0, elapsed_us: fv(x, 'ela_v') || 0, cpu_us: fv(x, 'cpu_v') || 0, gets: fv(x, 'gets_v') || 0, reads: fv(x, 'reads_v') || 0, rows: fv(x, 'rows_v') || 0, module: s(x.module_v), user: s(x.user_v), sql_text: s(x.text_v), first_ts: chTs(x.first_v), last_ts: chTs(x.last_v) }));
    // plan changes: collector-detected (V$SQLSTATS, both plans still cached) ∪ detected here from the stored history
    const changes = new Map();
    let pc = pcCH && pcCH.length ? pcCH.map((x) => ({ f: x.f_v && typeof x.f_v === 'object' ? x.f_v : {}, ts: chTs(x.last_v) })) : memRows(m, 'plan-change', from, to).map((x) => ({ f: x.f, ts: x.ts }));
    for (const x of pc) { const id = s(x.f.sql_id || x.f.key); const ratio = num(x.f.ratio); if (!id) continue; const prev = changes.get(id); if (!prev || x.ts > prev.ts) changes.set(id, { sql_id: id, old_plan: s(x.f.old_plan), new_plan: s(x.f.new_plan), old_ms_exec: num(x.f.old_ms_exec), new_ms_exec: num(x.f.new_ms_exec), ratio, worse: ratio !== null && ratio >= P.DEFAULTS.plan_ratio, ts: x.ts, source: 'collector' }); }
    for (const c of P.planChanges(plansRows)) if (!changes.has(c.sql_id)) changes.set(c.sql_id, Object.assign({}, c, { ts: Math.max(...plansRows.filter((p) => p.sql_id === c.sql_id).map((p) => p.last_ts)), source: 'history' }));
    // per statement
    const stmts = new Map();
    for (const p of plansRows) {
      const o = stmts.get(p.sql_id) || (stmts.set(p.sql_id, { sql_id: p.sql_id, plans: [], executions: 0, elapsed_us: 0, cpu_us: 0, gets: 0, reads: 0, rows: 0, module: '', user: '', sql_text: '', last_ts: 0 }), stmts.get(p.sql_id));
      o.plans.push({ plan_hash: p.plan_hash, executions: p.executions, ela_ms_exec: p.executions > 0 ? r(p.elapsed_us / p.executions / 1000) : null, last_ts: p.last_ts });
      o.executions += p.executions; o.elapsed_us += p.elapsed_us; o.cpu_us += p.cpu_us; o.gets += p.gets; o.reads += p.reads; o.rows += p.rows;
      if (p.last_ts >= o.last_ts) { o.last_ts = p.last_ts; o.plan_hash = p.plan_hash; }
      o.module = o.module || p.module; o.user = o.user || p.user; o.sql_text = o.sql_text || p.sql_text;
    }
    const e = (o) => o.executions;
    const sql = [...stmts.values()].map((o) => {
      const c = changes.get(o.sql_id) || null;
      const row = { sql_id: o.sql_id, plan_hash: o.plan_hash, plan_count: o.plans.length, plans: o.plans.sort((a, b) => b.last_ts - a.last_ts), executions: o.executions,
        elapsed_s: r(o.elapsed_us / 1e6), cpu_s: r(o.cpu_us / 1e6), buffer_gets: o.gets, disk_reads: o.reads, rows_processed: o.rows,
        ela_ms_exec: e(o) > 0 ? r(o.elapsed_us / e(o) / 1000) : null, cpu_ms_exec: e(o) > 0 ? r(o.cpu_us / e(o) / 1000) : null, gets_exec: e(o) > 0 ? r(o.gets / e(o), 2) : null,
        reads_exec: e(o) > 0 ? r(o.reads / e(o), 2) : null, rows_exec: e(o) > 0 ? r(o.rows / e(o), 2) : null, module: o.module, user: o.user,
        plan_change: c ? { old_plan: c.old_plan, new_plan: c.new_plan, ratio: c.ratio, worse: c.worse } : null };
      if (showText) row.sql_text = o.sql_text;
      return row;
    }).sort((a, b) => (b[SQL_BY[by]] || 0) - (a[SQL_BY[by]] || 0)).slice(0, 50);
    // activity from the licence-free capture
    let act = actCH && actCH.length ? actCH : null; let minutes = minCH && minCH.length ? Number(minCH[0].n_v) || 0 : 0;
    if (!act) { const g = new Map(); for (const x of memRows(m, 'active-sql', from, to)) { const o = g.get(x.key) || (g.set(x.key, { sql_v: x.key, aas_sum_v: 0, cnt_v: 0, ev_v: '', module_v: '' }), g.get(x.key)); o.aas_sum_v += num(x.f.aas) || 0; o.cnt_v += num(x.f.count) || 0; o.ev_v = x.f.top_event || o.ev_v; o.module_v = x.f.module || o.module_v; } act = [...g.values()].sort((a, b) => b.aas_sum_v - a.aas_sum_v).slice(0, 20); }
    if (!minutes) minutes = memRows(m, 'active-sessions', from, to).length;
    const activity = act.map((x) => ({ sql_id: s(x.sql_v), aas: minutes ? r((fv(x, 'aas_sum_v') || 0) / minutes) : null, captured: fv(x, 'cnt_v') || 0, top_event: s(x.ev_v), module: s(x.module_v) }));
    // drawer: history per plan for one statement
    let detail = null;
    if (sqlId) {
      const step = stepFor(from, to);
      const hCH = await q('sqlHistory', Object.assign({}, pr, { sql: { type: 'String', value: sqlId }, step: { type: 'Int64', value: step } }));
      let hist = hCH && hCH.length ? hCH : null;
      if (!hist) { const g = new Map(); for (const x of memRows(m, 'top-sql-delta', from, to, (y) => y.f.sql_id === sqlId)) { const b = Math.floor(x.ts / step) * step; const k = `${x.f.plan_hash}|${b}`; const o = g.get(k) || (g.set(k, { plan_v: x.f.plan_hash, bucket_v: b, execs_v: 0, ela_v: 0, cpu_v: 0, gets_v: 0 }), g.get(k)); o.execs_v += num(x.f.executions) || 0; o.ela_v += num(x.f.d_ela_us) || 0; o.cpu_v += num(x.f.d_cpu_us) || 0; o.gets_v += num(x.f.buffer_gets) || 0; } hist = [...g.values()].sort((a, b) => a.bucket_v - b.bucket_v); }
      const plans = new Map();
      for (const x of hist) {
        const ph = s(x.plan_v); const ex = fv(x, 'execs_v') || 0;
        const o = plans.get(ph) || (plans.set(ph, { plan_hash: ph, executions: 0, ela_us: 0, cpu_us: 0, gets: 0, points: [] }), plans.get(ph));
        o.executions += ex; o.ela_us += fv(x, 'ela_v') || 0; o.cpu_us += fv(x, 'cpu_v') || 0; o.gets += fv(x, 'gets_v') || 0;
        o.points.push({ ts: Number(x.bucket_v), executions: ex, ela_ms_exec: ex > 0 ? r((fv(x, 'ela_v') || 0) / ex / 1000) : null, cpu_ms_exec: ex > 0 ? r((fv(x, 'cpu_v') || 0) / ex / 1000) : null, gets_exec: ex > 0 ? r((fv(x, 'gets_v') || 0) / ex, 2) : null });
      }
      const st0 = stmts.get(sqlId);
      detail = { sql_id: sqlId, module: st0 ? st0.module : '', user: st0 ? st0.user : '', step_s: step / 1000, plan_change: changes.get(sqlId) || null,
        plans: [...plans.values()].map((o) => ({ plan_hash: o.plan_hash, executions: o.executions, ela_ms_exec: o.executions > 0 ? r(o.ela_us / o.executions / 1000) : null, cpu_ms_exec: o.executions > 0 ? r(o.cpu_us / o.executions / 1000) : null, gets_exec: o.executions > 0 ? r(o.gets / o.executions, 2) : null, points: o.points })) };
      if (showText) detail.sql_text = st0 ? st0.sql_text : '';
    }
    return Object.assign(base, { clickhouse: chState, sql, plan_changes: [...changes.values()].sort((a, b) => (b.ratio || 0) - (a.ratio || 0)), activity, activity_minutes: minutes, detail });
  }

  // ---------------------------------------------------------------------------------------------------- sessions ---
  async function sessions(qq = {}) {
    resetCh();
    const t = now();
    const showText = !!qq._sql_text;
    const list = await instances();
    const inst = await target(qq, list);
    const base = { generated_at: new Date(t).toISOString(), sql_text_visible: showText, instances: list.map(pub), instance: pub(inst) };
    const empty = { snapshot_ts: 0, stale: true, blocking: { trees: [], waiters: 0, max_wait_s: null }, long_running: [], top_sessions: [], top_sql: [], active: null };
    if (!inst) return Object.assign(base, { clickhouse: chState }, empty);
    const m = mem.get(inst.key);
    const chRows = await q('sessions', P_INST(inst));
    let rows = (chRows || []).map((x) => ({ action: s(x.action), key: s(x.k_v), ts: chTs(x.t_v), user: s(x.u_v), f: x.f_v && typeof x.f_v === 'object' ? x.f_v : {} }));
    const memAll = SESS_ACTIONS.flatMap((a) => memRows(m, a, t - 15 * 60000, t + 60000).map((x) => ({ action: a, key: x.key, ts: x.ts, user: x.user, f: x.f })));
    rows = rows.concat(memAll);
    const lp = rows.filter((x) => x.action === 'load-profile' && (x.f.scope || 'instance') !== 'pdb');
    const snap = lp.length ? Math.max(...lp.map((x) => x.ts)) : (rows.length ? Math.max(...rows.map((x) => x.ts)) : 0);
    if (!snap) return Object.assign(base, { clickhouse: chState }, empty);
    const cur = new Map(); // dedupe CH + memory copies of the same record
    for (const x of rows) if (Math.abs(x.ts - snap) <= 2000) cur.set(`${x.action}|${x.key}`, x);
    const of = (a) => [...cur.values()].filter((x) => x.action === a);
    const blk = of('blocking-chain').map((x) => Object.assign({}, x.f, { user: x.user ? x.user.toUpperCase() : (x.f.user || '') }));
    const trees = P.blockingTree(blk);
    const long_running = of('long-query').map((x) => { const o = { sid: x.f.sid || '', serial: x.f.serial || '', user: (x.user || '').toUpperCase(), sql_id: x.f.sql_id || '', elapsed_s: num(x.f.elapsed_s), sql_exec_start: x.f.sql_exec_start || '', state: x.f.state || '', event: x.f.event || '', wait_class: x.f.wait_class || '', module: x.f.module || '', program: x.f.program || '', machine: x.f.machine || '' }; if (showText) o.sql_text = x.f.sql_text || ''; return o; })
      .sort((a, b) => (b.elapsed_s || 0) - (a.elapsed_s || 0));
    const top_sessions = of('active-session').map((x) => ({ sid: x.f.sid || '', serial: x.f.serial || '', user: (x.user || '').toUpperCase(), program: x.f.program || '', module: x.f.module || '', machine: x.f.machine || '', count: num(x.f.count), aas: num(x.f.aas), top_event: x.f.top_event || '', sql_id: x.f.sql_id || '', state: x.f.state || '', rank: num(x.f.rank) }))
      .sort((a, b) => (a.rank || 99) - (b.rank || 99));
    const top_sql = of('active-sql').map((x) => ({ sql_id: x.f.sql_id || x.key, aas: num(x.f.aas), pct: num(x.f.pct), count: num(x.f.count), top_event: x.f.top_event || '', module: x.f.module || '', user: (x.user || '').toUpperCase(), rank: num(x.f.rank) }))
      .sort((a, b) => (a.rank || 99) - (b.rank || 99));
    const as = of('active-sessions')[0];
    const active = as ? { captures: num(as.f.captures), aas: num(as.f.aas), top_event: as.f.top_event || '', by_class: CLASS_FIELDS.map((c) => ({ key: c, name: P.CLASS_KEYS[c], aas: num(as.f['aas_' + c]) })).filter((c) => c.aas) } : null;
    return Object.assign(base, { clickhouse: chState, snapshot_ts: snap, stale: t - snap > staleS * 1000,
      blocking: { trees, waiters: blk.length, max_wait_s: blk.length ? Math.max(...blk.map((x) => num(x.wait_s) || 0)) : null }, long_running, top_sessions, top_sql, active });
  }

  // ---------------------------------------------------------------------------------------------------- capacity ---
  async function capacity(qq = {}) {
    resetCh();
    const t = now();
    const [capCH, grCH, list] = await Promise.all([qc('capacity', {}), qc('growth', {}), instances()]);
    const byInst = new Map();
    const get = (host, instName, db) => { const k = keyOf(host, instName); return byInst.get(k) || (byInst.set(k, { key: k, host: s(host), instance: s(instName).toUpperCase(), db_name: s(db || instName).toUpperCase(), last_seen: 0, latest: {}, hist: new Map() }), byInst.get(k)); };
    for (const x of capCH || []) { const i = get(x.host, x.inst_v, x.db_v); const ts = chTs(x.last_v); i.last_seen = Math.max(i.last_seen, ts); const k = `${x.action}|${s(x.k_v)}`; i.latest[k] = { action: s(x.action), key: s(x.k_v), ts, sev: Number(x.sev_v) || 0, f: x.f_v && typeof x.f_v === 'object' ? x.f_v : {} }; }
    for (const x of grCH || []) { const i = get(x.host, x.inst_v); const tb = s(x.tbs_v).toUpperCase(); const d = Math.floor(chTs(String(x.day_v).length <= 10 ? `${x.day_v}T00:00:00Z` : x.day_v) / DAY); const h = i.hist.get(tb) || (i.hist.set(tb, new Map()), i.hist.get(tb)); h.set(d, { used_mb: fv(x, 'used_v'), max_mb: fv(x, 'max_v') }); }
    for (const m of mem.values()) {
      const has = CAP_ACTIONS.some((a) => m.a[a] && m.a[a].length) || m.days.size;
      if (!has) continue;
      const i = get(m.host, m.instance, m.db_name);
      for (const a of CAP_ACTIONS) for (const x of m.a[a] || []) { const k = `${a}|${x.key}`; if (!i.latest[k] || x.ts >= i.latest[k].ts) i.latest[k] = { action: a, key: x.key, ts: x.ts, sev: x.sev, f: x.f }; i.last_seen = Math.max(i.last_seen, x.ts); }
      for (const [tb, days] of m.days) { const h = i.hist.get(tb) || (i.hist.set(tb, new Map()), i.hist.get(tb)); for (const [d, v] of days) { const p = h.get(d); if (!p || (v.used_mb || 0) > (p.used_mb || 0)) h.set(d, v); } }
    }
    let insts = [...byInst.values()];
    if (s(qq.instance)) {
      const one = resolve(insts.map((i) => ({ key: i.key, instance: i.instance })), qq.instance) || resolve(list, qq.instance);
      if (!one) throw new PerfError(404, `oracle instance ${s(qq.instance).slice(0, 80)} not found`);
      insts = insts.filter((i) => i.key === one.key);
    }
    const out = insts.map((i) => {
      const L = (a) => Object.values(i.latest).filter((x) => x.action === a);
      const one = (a) => L(a).sort((x, y) => y.ts - x.ts)[0] || null;
      const tbsNames = new Set([...i.hist.keys(), ...L('tablespace-growth').map((x) => x.key.toUpperCase())]);
      const tablespaces = [...tbsNames].map((name) => {
        const h = i.hist.get(name) || new Map();
        const pts = [...h.entries()].map(([d, v]) => ({ day: d, used_mb: v.used_mb }));
        const lastMax = [...h.entries()].sort((a, b) => b[0] - a[0]).map(([, v]) => v.max_mb).find((v) => v > 0) || null;
        const col = L('tablespace-growth').find((x) => x.key.toUpperCase() === name);
        const maxMb = lastMax || (col ? num(col.f.max_mb) : null);
        const fc = P.forecast(pts, maxMb);
        const useEngine = fc.history_days >= 3;
        const used = useEngine ? fc.used_mb : (col ? num(col.f.used_mb) : fc.used_mb);
        const growth = useEngine ? fc.growth_mb_day : (col ? num(col.f.growth_mb_day) : fc.growth_mb_day);
        const dtf = useEngine ? fc.days_to_full : (col ? num(col.f.days_to_full) : fc.days_to_full);
        const severity = dtf !== null && dtf < P.DEFAULTS.days_to_full ? (dtf < P.DEFAULTS.days_to_full_crit ? 4 : 3) : 0;
        return { name, used_mb: used, max_mb: maxMb, used_pct: used !== null && maxMb > 0 ? r(used / maxMb * 100, 1) : null, growth_mb_day: growth, days_to_full: dtf, history_days: useEngine ? fc.history_days : (col ? num(col.f.history_days) : fc.history_days), source: useEngine ? 'engine' : (col ? 'collector' : 'engine'), severity };
      }).sort((a, b) => ((a.days_to_full === null ? 1e9 : a.days_to_full) - (b.days_to_full === null ? 1e9 : b.days_to_full)) || ((b.used_pct || 0) - (a.used_pct || 0)));
      const pick = (x, keys) => (x ? keys.reduce((o, k) => Object.assign(o, { [k]: /^[a-z0-9_]+_(mb|pct|s|1h|24h|min)$|^(load|num_cpus|num_cpu_cores|switches_max_hour_24h|log_groups|pga_over_alloc|ratio)$/.test(k) ? num(x.f[k]) : (x.f[k] || '') }), { ts: x.ts, severity: x.sev }) : null);
      return {
        key: i.key, host: i.host, instance: i.instance, db_name: i.db_name, last_seen: i.last_seen, stale: !i.last_seen || t - i.last_seen > 2 * DAY,
        tablespaces,
        asm: L('asm-diskgroup').map((x) => Object.assign({ name: x.key }, pick(x, ['state', 'type', 'total_mb', 'free_mb', 'usable_file_mb', 'free_pct']), { offline_disks: num(x.f.offline_disks) })).sort((a, b) => (a.free_pct === null ? 1e9 : a.free_pct) - (b.free_pct === null ? 1e9 : b.free_pct)),
        limits: L('resource-limit').map((x) => ({ resource: x.key, current: num(x.f.current), max_util: num(x.f.max_util), limit: x.f.limit || '', pct: num(x.f.pct), severity: x.sev, ts: x.ts })).sort((a, b) => (b.pct || 0) - (a.pct || 0)),
        temp_undo: pick(one('temp-undo'), ['temp_used_mb', 'temp_max_mb', 'temp_used_pct', 'temp_top_sql_id', 'temp_top_user', 'undo_tablespace', 'undo_used_pct', 'undo_retention_s', 'tuned_undoretention_s', 'maxquerylen_s', 'maxquery_sql_id', 'ora1555_1h', 'nospace_1h', 'unexpired_steals_1h', 'undo_risk', 'undo_risk_reason']),
        memory: pick(one('memory'), ['sga_max_mb', 'sga_free_mb', 'sga_used_pct', 'buffer_cache_mb', 'shared_pool_mb', 'sga_target_mb', 'memory_target_mb', 'pga_alloc_mb', 'pga_inuse_mb', 'pga_max_alloc_mb', 'pga_target_mb', 'pga_limit_mb', 'pga_pct_target', 'pga_pct_limit', 'pga_over_alloc', 'pga_cache_hit_pct']),
        redo: pick(one('redo-rate'), ['switches_1h', 'switches_24h', 'switches_max_hour_24h', 'log_groups', 'log_size_mb', 'avg_switch_min']),
        archive_dests: L('archive-dest').map((x) => ({ dest: x.key, dest_id: x.f.dest_id || '', status: x.f.status || '', target: x.f.target || '', destination: x.f.destination || '', error: x.f.dest_error || '', severity: x.sev, ts: x.ts })),
        host: pick(one('host-stats'), ['num_cpus', 'num_cpu_cores', 'load', 'mem_total_mb', 'mem_free_mb', 'mem_used_pct', 'host_cpu_pct']),
      };
    }).sort((a, b) => a.key.localeCompare(b.key));
    return { generated_at: new Date(t).toISOString(), clickhouse: chState, thresholds: { days_to_full: P.DEFAULTS.days_to_full, temp_pct: P.DEFAULTS.temp_pct, limit_pct: P.DEFAULTS.limit_pct, asm_free_pct: P.DEFAULTS.asm_free_pct }, instances: out };
  }

  return { stage, perf, topsql, sessions, capacity, stats: () => Object.assign({}, st, { memory_instances: mem.size }) };
}

module.exports = { createOraclePerf, SQL, PerfError, PERIODS, SQL_BY, LOAD_METRICS, EFF_METRICS };
