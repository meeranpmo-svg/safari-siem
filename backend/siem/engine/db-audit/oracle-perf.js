// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Oracle PERFORMANCE record kinds (collector agents/oracle/queries-perf*.sql, docs/ORACLE.md section 4) → normalised
 * events, plus the pure math shared by the API (engine/db-audit/perf-api.js) and the tests.
 * Called by oracle-health.js parse() for every kind in KINDS. Every perf event: category "database", tags
 * ["oracle","db-health","db-perf"], fields.instance / db_name / key / kind, numbers as strings.
 *
 *   collector kind     action             fields.key            severity (defaults — the alert thresholds live in the rules)
 *   load_profile       load-profile       '' | PDB name         aas_per_cpu > 1 (instance scope) → 2
 *   efficiency         efficiency         ''                    0
 *   latch              latch-hotspot      latch / mutex name    0
 *   wait_classes       wait-class-rate    wait class            0
 *   wait_events        wait-event         event name            log file sync avg > 10 ms / db file sequential read avg > 20 ms → 2
 *   active_sessions    active-sessions    ''                    0 (licence-free capture: aas per wait class)
 *   ash_sql            active-sql         sql_id                0
 *   ash_session        active-session     sid,serial            0
 *   sql_delta          top-sql-delta      sql_id:plan_hash      0 (per-interval deltas from V$SQLSTATS)
 *   plan_change        plan-change        sql_id                ratio ≥ 2 → 3 (outcome failure), else 1
 *   blocking           blocking-chain     waiter sid            wait_s ≥ 300 → 3, else 2
 *   long_query         long-query         sid,serial            elapsed_s ≥ 1800 → 2, else 1
 *   temp_undo          temp-undo          ''                    TEMP ≥ 85 % or ORA-01555 / no-space risk → 3
 *   memory             memory             ''                    PGA ≥ 90 % of pga_aggregate_limit or over-allocation → 2
 *   limits             resource-limit     resource name         ≥ 90 % of the limit → 3
 *   redo_rate          redo-rate          ''                    > 30 switches / h → 2
 *   archive_dest       archive-dest       dest_name | dest_id   status ERROR / BAD PARAM or an error text → 3
 *   asm                asm-diskgroup      disk group            free < 10 % or offline disks → 3, usable_file_mb < 0 → 4
 *   tablespace_growth  tablespace-growth  tablespace            days_to_full < 14 → 3, < 7 → 4
 *   host               host-stats         ''                    0
 *   pack_ash           sentra-enrichment     sql_id|event          0 (only with diagnostics_pack_licensed=true)
 *   stats_stale        stale-statistics   owner.table           1 (optimizer statistics marked STALE; the platform connection, hourly)
 *   gg_capture         gg-capture         Extract name          ABORTED / error → 4, DISABLED → 3, lag ≥ 1800 s → 3, ≥ 300 s → 2
 *   gg_apply           gg-apply           Replicat name         same rules as gg_capture
 *   dg_config          dg-config          ''                    primary with a standby: force logging off / protection level below its mode → 3,
 *                                                               switchover status naming a gap / failed destination → 3, flashback off → 1
 *   dg_dest            dg-transport       standby db_unique_name status ERROR / an error / unresolvable gap → 4, resolvable gap / apply IDLE → 3,
 *                                                               DEFERRED → 2
 *   dg_applied         dg-apply-lag       dest_id:thread        oldest shipped-but-not-applied log waiting ≥ 1800 s → 3, ≥ 300 s → 2
 *   dg_stats           dg-lag             'apply lag' | 'transport lag' | ...   (standby) ≥ 1800 s → 3, ≥ 300 s → 2
 *   dg_process         dg-process         ''                    0 (counts of MRP0 / RFS; "apply not running" is a finding of the standby role)
 *   rac_node           rac-node           redo thread           RAC: a configured instance not OPEN (NOT RUNNING / MOUNTED / STARTED) → 4
 *   sched_job          sched-job          owner.job             scheduler job running ≥ 20 min → 2, ≥ 60 min → 3 (the DBA's thresholds decide the alert)
 *   bulk_delete        bulk-delete        sql_id                rows one DELETE statement removed since the previous pass; ≥ 10 000 → 3
 *   code_change        code-change        owner.name (type)     PL/SQL code / trigger created or changed in the last 65 min → 2
 *   code_change_by     code-change-by     owner.name|user|at    who did it (unified audit), incl. TRUNCATE TABLE → 2; SYS / SYSDBA / Oracle users → 0
 *   app_session        app-session        service|machine|program|user   sessions of one application now (count, active, idle); 0
 *   lsnr_conn          lsnr-conn          service|client|program|code    listener log, last 65 min: connects (code 0) or refusals (12514 / 12519 ...) → 3
 *   db_link            db-link            owner.link            a database link: remote user and connect string; 0
 *   user_write         user-write         user                  what an application user can change (DBA roles, ANY privileges, tables); 0
 *   dg_gap             dg-gap             thread                4 (the standby is missing archived logs)
 *   dg_event           dg-error           error code            Fatal → 4, Error → 3
 *   dg_broker          dg-broker          member                status ≠ 0 (an ORA- error) → 3
 *   dg_srl             dg-standby-logs    ''                    0
 *   dg_nologging       dg-nologging       ''                    files > 0 → 2 (blocks changed NOLOGGING are not on the standby)
 *   db_server          db-server          ip                    (the host, over SSH from IT Asset Management) instance in oratab not running → 4,
 *                                                               memory available < 5 % / load > 2 per CPU → 3, swap > 50 % / NTP not synced → 2
 *   db_server_fs       db-server-fs       mount point           ≥ 95 % → 4, ≥ 90 % → 3, ≥ 85 % → 2
 *   audit_config       audit-config       ''                    no unified audit policy enabled → 3 (Database Audit checks the rest)
 *   change_txn         db-change          xid                   (Change Stream, LogMiner) DROP / TRUNCATE or a mass change with deletes → 3, other mass change → 2,
 *                                                               an interactive tool (sqlplus, SQL Developer, TOAD, ...) changing data → 2
 *   change_stream      change-stream      job                   stopped (a log gap) → 3
 *   repl_status        replication        job                   stopped (conflict / DDL / gap / account) → 4, lag ≥ 1800 s → 3, conflicts logged → 2
 *   verify_result      data-verify        job                   source and target differ → 3
 */
const MAX_SQL = 200;

const ACTIONS = {
  load_profile: 'load-profile', efficiency: 'efficiency', latch: 'latch-hotspot', wait_classes: 'wait-class-rate', wait_events: 'wait-event',
  active_sessions: 'active-sessions', ash_sql: 'active-sql', ash_session: 'active-session', sql_delta: 'top-sql-delta', plan_change: 'plan-change',
  blocking: 'blocking-chain', long_query: 'long-query', temp_undo: 'temp-undo', memory: 'memory', limits: 'resource-limit', redo_rate: 'redo-rate',
  archive_dest: 'archive-dest', asm: 'asm-diskgroup', tablespace_growth: 'tablespace-growth', host: 'host-stats', pack_ash: 'sentra-enrichment',
  stats_stale: 'stale-statistics', gg_capture: 'gg-capture', gg_apply: 'gg-apply',
  dg_config: 'dg-config', dg_dest: 'dg-transport', dg_applied: 'dg-apply-lag', dg_stats: 'dg-lag', dg_process: 'dg-process', dg_gap: 'dg-gap',
  dg_event: 'dg-error', dg_broker: 'dg-broker', dg_srl: 'dg-standby-logs', dg_nologging: 'dg-nologging',
  rac_node: 'rac-node', sched_job: 'sched-job', bulk_delete: 'bulk-delete', code_change: 'code-change', code_change_by: 'code-change-by',
  app_session: 'app-session', lsnr_conn: 'lsnr-conn', db_link: 'db-link', user_write: 'user-write',
  db_server: 'db-server', db_server_fs: 'db-server-fs', audit_config: 'audit-config',
  change_txn: 'db-change', change_stream: 'change-stream', repl_status: 'replication', verify_result: 'data-verify',
};
const KINDS = new Set(Object.keys(ACTIONS));
const PERF_ACTIONS = new Set(Object.values(ACTIONS));

// wait classes of the licence-free capture: collector field suffix (lower-case, non-alphanumerics → _) → Oracle class name
const CLASS_KEYS = {
  cpu: 'CPU', user_i_o: 'User I/O', system_i_o: 'System I/O', commit: 'Commit', concurrency: 'Concurrency', application: 'Application',
  cluster: 'Cluster', configuration: 'Configuration', network: 'Network', administrative: 'Administrative', scheduler: 'Scheduler',
  queueing: 'Queueing', other: 'Other',
};
// default thresholds — the alerting copies live in engine/detect/rules/oracle-perf.json (rule "params")
const DEFAULTS = { aas_per_cpu: 1, log_file_sync_ms: 10, seq_read_ms: 20, min_waits_s: 1, blocking_s: 300, long_query_s: 1800, plan_ratio: 2, temp_pct: 85, limit_pct: 90, days_to_full: 14, days_to_full_crit: 7, asm_free_pct: 10, pga_pct: 90, redo_switches_h: 30, gg_lag_s: 300, gg_lag_high_s: 1800, dg_lag_s: 300, dg_lag_high_s: 1800 };

function num(v) { if (v === '' || v === null || v === undefined) return null; const n = typeof v === 'number' ? v : parseFloat(v); return Number.isFinite(n) ? n : null; }
function s(v) { return v === undefined || v === null ? '' : String(v); }
function r(n, d = 3) { const p = 10 ** d; return Math.round(n * p) / p; }
/** Oracle interval text ('+00 00:01:05', '+01 02:00:00.000') -> seconds; null when empty or unreadable */
function intervalS(v) {
  const m = /^\s*\+?(\d+)\s+(\d+):(\d+):(\d+)(?:\.\d+)?\s*$/.exec(s(v));
  return m ? Number(m[1]) * 86400 + Number(m[2]) * 3600 + Number(m[3]) * 60 + Number(m[4]) : null;
}
const lagSev = (v) => (v === null ? 0 : v >= DEFAULTS.dg_lag_high_s ? 3 : v >= DEFAULTS.dg_lag_s ? 2 : 0);

/** Least-squares growth (MB / day) over the last `windowDays` daily points and days until max_mb.
 *  points: [{day (days since epoch) | ts (ms), used_mb}]; the latest point is the current size.
 *  → { growth_mb_day, days_to_full (null = not growing / unknown), history_days, span_days, used_mb } */
function forecast(points, maxMb, { windowDays = 30 } = {}) {
  const pts = (points || []).map((p) => ({ x: p.day !== undefined ? Number(p.day) : Math.floor(Number(p.ts) / 86400000), y: num(p.used_mb) }))
    .filter((p) => Number.isFinite(p.x) && p.y !== null);
  const byDay = new Map(); for (const p of pts) byDay.set(p.x, p.y); // one value per day (last wins)
  const days = [...byDay.keys()].sort((a, b) => a - b);
  if (!days.length) return { growth_mb_day: null, days_to_full: null, history_days: 0, span_days: 0, used_mb: null };
  const today = days[days.length - 1];
  const use = days.filter((d) => d >= today - windowDays);
  const used = byDay.get(today);
  let slope = null;
  if (use.length >= 2) {
    let sx = 0, sy = 0, sxx = 0, sxy = 0; const n = use.length;
    for (const d of use) { const x = d - today; const y = byDay.get(d); sx += x; sy += y; sxx += x * x; sxy += x * y; }
    const den = n * sxx - sx * sx;
    if (den > 0) slope = (n * sxy - sx * sy) / den;
  }
  const max = num(maxMb);
  let dtf = null;
  if (slope !== null && slope > 0 && max > 0) dtf = Math.max(0, (max - used) / slope);
  return { growth_mb_day: slope === null ? null : r(slope, 2), days_to_full: dtf === null ? null : r(dtf, 2), history_days: use.length, span_days: use.length ? use[use.length - 1] - use[0] : 0, used_mb: used };
}

/** Plan changes inside a set of per-(sql_id, plan_hash) aggregates: the newest plan (by last_ts) vs the best older plan
 *  (lowest elapsed per execution, ≥ minExecs executions on both sides). rows: [{sql_id, plan_hash, executions, elapsed_us, last_ts, first_ts}]
 *  → [{sql_id, new_plan, old_plan, new_ms_exec, old_ms_exec, ratio, worse}]   (worse = ratio ≥ minRatio) */
function planChanges(rows, { minRatio = DEFAULTS.plan_ratio, minExecs = 3 } = {}) {
  const by = new Map();
  for (const x of rows || []) {
    const id = s(x.sql_id); if (!id || !s(x.plan_hash) || s(x.plan_hash) === '0') continue;
    const e = num(x.executions) || 0; const ela = num(x.elapsed_us) || 0;
    if (e < minExecs) continue;
    (by.get(id) || by.set(id, []).get(id)).push({ plan: s(x.plan_hash), epe: ela / e, last: num(x.last_ts) || 0 });
  }
  const out = [];
  for (const [id, plans] of by) {
    if (plans.length < 2) continue;
    plans.sort((a, b) => b.last - a.last);
    const nw = plans[0]; const old = plans.slice(1).sort((a, b) => a.epe - b.epe)[0];
    if (!(old.epe > 0)) continue;
    const ratio = nw.epe / old.epe;
    out.push({ sql_id: id, new_plan: nw.plan, old_plan: old.plan, new_ms_exec: r(nw.epe / 1000), old_ms_exec: r(old.epe / 1000), ratio: r(ratio, 2), worse: ratio >= minRatio });
  }
  return out.sort((a, b) => b.ratio - a.ratio);
}

/** Blocking rows (one per waiter) → trees rooted at sessions that block but do not wait themselves.
 *  rows: [{sid, serial, user, wait_s, event, object, sql_id, blocker_sid, blocker_user, blocker_status, blocker_program, blocker_machine, blocker_sql_id, final_blocker_sid}] */
function blockingTree(rows) {
  const nodes = new Map();
  const node = (sid) => { const k = s(sid); if (!nodes.has(k)) nodes.set(k, { sid: k, waiting: false, children: [] }); return nodes.get(k); };
  for (const x of rows || []) {
    const w = node(x.sid);
    Object.assign(w, { waiting: true, serial: s(x.serial), user: s(x.user), wait_s: num(x.wait_s), event: s(x.event), object: s(x.object), sql_id: s(x.sql_id), program: s(x.program), machine: s(x.machine), blocker_sid: s(x.blocker_sid) });
    if (!s(x.blocker_sid)) continue;
    const b = node(x.blocker_sid);
    if (!b.waiting) {
      const info = { serial: s(x.blocker_serial), user: s(x.blocker_user), status: s(x.blocker_status), program: s(x.blocker_program), machine: s(x.blocker_machine), sql_id: s(x.blocker_sql_id), event: s(x.blocker_event) };
      for (const [k, v] of Object.entries(info)) if (v || b[k] === undefined) b[k] = v || b[k] || '';
      if (num(x.blocker_idle_s) !== null) b.idle_s = num(x.blocker_idle_s);
    }
  }
  for (const n of nodes.values()) if (n.waiting && n.blocker_sid && nodes.has(n.blocker_sid) && n.blocker_sid !== n.sid) nodes.get(n.blocker_sid).children.push(n);
  const roots = [...nodes.values()].filter((n) => !n.waiting || !n.blocker_sid || !nodes.has(n.blocker_sid) || n.blocker_sid === n.sid);
  const seen = new Set();
  const finish = (n, depth) => { if (seen.has(n.sid) || depth > 20) return null; seen.add(n.sid); const kids = n.children.map((c) => finish(c, depth + 1)).filter(Boolean).sort((a, b) => (b.wait_s || 0) - (a.wait_s || 0)); const out = Object.assign({}, n, { children: kids }); out.waiters = kids.reduce((t, k) => t + 1 + k.waiters, 0); out.max_wait_s = Math.max(n.wait_s || 0, ...kids.map((k) => k.max_wait_s || 0)); delete out.blocker_sid; return out; };
  return roots.filter((n) => n.children.length).map((n) => finish(n, 0)).filter(Boolean).sort((a, b) => (b.max_wait_s - a.max_wait_s) || (b.waiters - a.waiters));
}

/** parse(kind, o, ev, f, put, inst) — fills ev/f for a perf kind (called by oracle-health.js). */
function parse(kind, o, ev, f, put, inst) {
  ev.action = ACTIONS[kind];
  ev.tags.push('db-perf');
  const putN = (k, v) => { if (v !== null && v !== undefined && Number.isFinite(v)) f[k] = String(v); };
  const all = (keys) => keys.forEach((k) => put(k, o[k]));
  switch (kind) {
    case 'load_profile': {
      const scope = s(o.scope || 'instance').toLowerCase() === 'pdb' ? 'pdb' : 'instance';
      f.scope = scope;
      if (scope === 'pdb') f.key = s(o.con_name || o.con_id).toUpperCase();
      all(['aas', 'db_time_s', 'db_cpu_s', 'bg_cpu_s', 'executions_s', 'user_calls_s', 'transactions_s', 'commits_s', 'rollbacks_s', 'logical_reads_s', 'physical_reads_s',
        'physical_writes_s', 'physical_read_mb_s', 'physical_write_mb_s', 'redo_mb_s', 'hard_parses_s', 'parses_s', 'logons_s', 'network_mb_s', 'host_cpu_pct', 'os_load',
        'sessions_cur', 'cpu_count', 'inst_id', 'startup_time', 'version', 'interval_s', 'end_time', 'con_id', 'con_name']);
      let aas = num(o.aas); if (aas === null && num(o.db_time_s) !== null) { aas = num(o.db_time_s); putN('aas', aas); }
      const parses = num(o.parses_s); const hard = num(o.hard_parses_s);
      if (parses !== null && hard !== null) putN('soft_parses_s', r(Math.max(0, parses - hard), 2));
      const cpu = num(o.cpu_count);
      if (aas !== null && cpu > 0 && scope === 'instance') {
        const ratio = r(aas / cpu);
        putN('aas_per_cpu', ratio);
        f.over_cpu = ratio > DEFAULTS.aas_per_cpu ? '1' : '0';
        if (ratio > DEFAULTS.aas_per_cpu) ev.severity = 2;
      }
      ev.message = `Load on ${inst}${scope === 'pdb' ? ` PDB ${f.key}` : ''}: ${aas === null ? '?' : aas} active sessions${cpu ? ` (${cpu} CPUs)` : ''}, ${s(o.db_cpu_s) || '?'} DB CPU/s, ${s(o.executions_s) || '?'} executions/s, ${s(o.redo_mb_s) || '?'} MB redo/s`;
      break;
    }
    case 'efficiency': {
      all(['buffer_cache_hit_pct', 'library_cache_hit_pct', 'soft_parse_pct', 'execute_to_parse_pct', 'db_cpu_ratio_pct', 'db_wait_ratio_pct', 'pga_cache_hit_pct']);
      ev.message = `Efficiency on ${inst}: buffer cache hit ${s(o.buffer_cache_hit_pct) || '?'}%, library cache hit ${s(o.library_cache_hit_pct) || '?'}%, soft parse ${s(o.soft_parse_pct) || '?'}%, execute to parse ${s(o.execute_to_parse_pct) || '?'}%`;
      break;
    }
    case 'latch': {
      f.key = s(o.name);
      all(['name', 'type', 'sleeps_s', 'gets_s', 'miss_pct', 'wait_ms_s', 'elapsed_s', 'rank', 'top_by']);
      ev.message = `${s(o.type) || 'latch'} hot spot on ${inst}: ${f.key} ${s(o.sleeps_s) || '?'} sleeps/s`;
      break;
    }
    case 'wait_classes': {
      f.key = s(o.class);
      all(['class', 'time_s', 'waits_s', 'avg_ms', 'dbtime_pct', 'avg_waiters']);
      ev.message = `Wait class ${f.key} on ${inst}: ${s(o.time_s) || '?'} s waited per second, avg ${s(o.avg_ms) || '?'} ms`;
      break;
    }
    case 'wait_events': {
      f.key = s(o.event);
      all(['event', 'class', 'waits_s', 'avg_ms', 'time_s', 'fg_waits_s', 'fg_time_s', 'd_waits', 'd_time_us', 'elapsed_s', 'rank', 'watch', 'top_by']);
      const avg = num(o.avg_ms); const ws = num(o.waits_s) || 0;
      const lim = f.key === 'log file sync' ? DEFAULTS.log_file_sync_ms : f.key === 'db file sequential read' ? DEFAULTS.seq_read_ms : null;
      if (lim !== null && avg !== null && avg > lim && ws >= DEFAULTS.min_waits_s) { ev.severity = 2; ev.outcome = 'failure'; }
      ev.message = `Wait event "${f.key}" on ${inst}: avg ${avg === null ? '?' : avg} ms, ${s(o.waits_s) || '?'} waits/s, ${s(o.time_s) || '?'} s waited per second`;
      break;
    }
    case 'active_sessions': {
      all(['captures', 'active_total', 'aas', 'top_event', 'cpu_count']);
      for (const [k, v] of Object.entries(o)) if (/^aas_[a-z0-9_]+$/.test(k)) put(k, v);
      ev.message = `Active sessions on ${inst}: ${s(o.aas) || '0'} on average over ${s(o.captures) || '?'} captures, top: ${s(o.top_event) || '—'}`;
      break;
    }
    case 'ash_sql': {
      f.key = s(o.sql_id);
      all(['sql_id', 'count', 'aas', 'pct', 'top_event', 'module', 'captures', 'rank']);
      ev.user = s(o.user).toLowerCase();
      ev.message = `SQL ${f.key} active in ${s(o.pct) || '?'}% of captures on ${inst} (${s(o.aas) || '?'} sessions), top: ${s(o.top_event)}`;
      break;
    }
    case 'ash_session': {
      f.key = `${s(o.sid)},${s(o.serial)}`;
      all(['sid', 'serial', 'program', 'module', 'machine', 'count', 'aas', 'top_event', 'sql_id', 'state', 'captures', 'rank']);
      ev.user = s(o.user).toLowerCase();
      ev.message = `Session ${f.key} (${s(o.user)}) active ${s(o.aas) || '?'} on ${inst}, top: ${s(o.top_event)}`;
      break;
    }
    case 'sql_delta': {
      f.key = `${s(o.sql_id)}:${s(o.plan_hash)}`;
      all(['sql_id', 'plan_hash', 'module', 'executions', 'elapsed_s', 'cpu_s', 'buffer_gets', 'disk_reads', 'rows_processed', 'ela_ms_exec', 'cpu_ms_exec', 'gets_exec',
        'reads_exec', 'rows_exec', 'execs_s', 'period_s', 'top_by', 'rank']);
      // exact deltas for aggregation in ClickHouse (sum over a period, then divide)
      putN('d_execs', num(o.executions)); putN('d_ela_us', num(o.elapsed_s) === null ? null : Math.round(num(o.elapsed_s) * 1e6)); putN('d_cpu_us', num(o.cpu_s) === null ? null : Math.round(num(o.cpu_s) * 1e6));
      if (o.sql_text) f.sql_text = s(o.sql_text).replace(/\s+/g, ' ').slice(0, MAX_SQL);
      ev.user = s(o.user).toLowerCase();
      ev.message = `SQL ${s(o.sql_id)} plan ${s(o.plan_hash)} on ${inst}: ${s(o.executions) || 0} executions, ${s(o.ela_ms_exec) || '?'} ms/exec, ${s(o.elapsed_s) || '?'} s elapsed in ${s(o.period_s) || '?'} s`;
      break;
    }
    case 'plan_change': {
      f.key = s(o.sql_id);
      all(['sql_id', 'new_plan', 'old_plan', 'new_ms_exec', 'old_ms_exec', 'new_execs', 'old_execs', 'new_last_active', 'module']);
      let ratio = num(o.ratio);
      if (ratio === null && num(o.new_ms_exec) !== null && num(o.old_ms_exec) > 0) ratio = r(num(o.new_ms_exec) / num(o.old_ms_exec), 2);
      putN('ratio', ratio);
      if (o.sql_text) f.sql_text = s(o.sql_text).replace(/\s+/g, ' ').slice(0, MAX_SQL);
      ev.user = s(o.user).toLowerCase();
      const worse = ratio !== null && ratio >= DEFAULTS.plan_ratio;
      ev.severity = worse ? 3 : 1; ev.outcome = worse ? 'failure' : 'success';
      ev.message = `Plan change for SQL ${f.key} on ${inst}: plan ${s(o.old_plan)} → ${s(o.new_plan)}, ${s(o.old_ms_exec) || '?'} → ${s(o.new_ms_exec) || '?'} ms/exec (${ratio === null ? '?' : ratio}×)`;
      break;
    }
    case 'blocking': {
      f.key = s(o.sid);
      all(['sid', 'serial', 'wait_s', 'event', 'wait_class', 'sql_id', 'program', 'module', 'machine', 'blocker_sid', 'blocker_inst', 'final_blocker_sid', 'final_blocker_inst',
        'blocker_serial', 'blocker_user', 'blocker_status', 'blocker_program', 'blocker_machine', 'blocker_sql_id', 'blocker_event', 'blocker_idle_s', 'object']);
      ev.user = s(o.user).toLowerCase();
      const w = num(o.wait_s) || 0;
      ev.severity = w >= DEFAULTS.blocking_s ? 3 : 2; ev.outcome = 'failure';
      ev.message = `Session ${s(o.sid)} (${s(o.user)}) on ${inst} blocked ${w} s by ${s(o.blocker_sid)} (${s(o.blocker_user)}${o.final_blocker_sid && s(o.final_blocker_sid) !== s(o.blocker_sid) ? `, chain root ${s(o.final_blocker_sid)}` : ''}): ${s(o.event)}${o.object ? ` on ${s(o.object)}` : ''}`;
      break;
    }
    case 'long_query': {
      f.key = `${s(o.sid)},${s(o.serial)}`;
      all(['sid', 'serial', 'sql_id', 'elapsed_s', 'sql_exec_start', 'state', 'event', 'wait_class', 'program', 'module', 'machine']);
      if (o.sql_text) f.sql_text = s(o.sql_text).replace(/\s+/g, ' ').slice(0, MAX_SQL);
      ev.user = s(o.user).toLowerCase();
      const el = num(o.elapsed_s) || 0;
      ev.severity = el >= DEFAULTS.long_query_s ? 2 : 1;
      ev.message = `Long-running call on ${inst}: session ${f.key} (${s(o.user)}) SQL ${s(o.sql_id)} for ${Math.round(el / 60)} min, ${s(o.event)}`;
      break;
    }
    case 'temp_undo': {
      all(['temp_used_mb', 'temp_max_mb', 'temp_used_pct', 'temp_top_sql_id', 'temp_top_user', 'undo_tablespace', 'undo_used_pct', 'undo_retention_s', 'tuned_undoretention_s',
        'maxquerylen_s', 'maxquery_sql_id', 'ora1555_1h', 'nospace_1h', 'unexpired_steals_1h']);
      const tp = num(o.temp_used_pct);
      const reasons = [];
      if ((num(o.ora1555_1h) || 0) > 0) reasons.push(`${num(o.ora1555_1h)} ORA-01555 in 1 h`);
      if ((num(o.nospace_1h) || 0) > 0) reasons.push(`${num(o.nospace_1h)} undo no-space errors in 1 h`);
      const mq = num(o.maxquerylen_s); const tr = num(o.tuned_undoretention_s);
      if (mq > 0 && tr > 0 && mq >= tr && (num(o.unexpired_steals_1h) || 0) > 0) reasons.push(`longest query ${mq} s ≥ tuned retention ${tr} s with unexpired extents stolen`);
      f.undo_risk = reasons.length ? '1' : '0';
      if (reasons.length) f.undo_risk_reason = reasons.join('; ');
      if ((tp !== null && tp >= DEFAULTS.temp_pct) || reasons.length) { ev.severity = 3; ev.outcome = 'failure'; }
      ev.message = `TEMP ${tp === null ? '?' : tp}% used, UNDO ${s(o.undo_used_pct) || '?'}% used on ${inst}${reasons.length ? ` — ORA-01555 risk: ${reasons.join('; ')}` : ''}`;
      break;
    }
    case 'memory': {
      all(['sga_max_mb', 'sga_free_mb', 'buffer_cache_mb', 'shared_pool_mb', 'sga_target_mb', 'memory_target_mb', 'pga_alloc_mb', 'pga_inuse_mb', 'pga_max_alloc_mb',
        'pga_target_mb', 'pga_limit_mb', 'pga_over_alloc', 'pga_cache_hit_pct']);
      const alloc = num(o.pga_alloc_mb); const tgt = num(o.pga_target_mb); const lim = num(o.pga_limit_mb);
      if (alloc !== null && tgt > 0) putN('pga_pct_target', r(alloc / tgt * 100, 1));
      if (alloc !== null && lim > 0) putN('pga_pct_limit', r(alloc / lim * 100, 1));
      const smax = num(o.sga_max_mb); const sfree = num(o.sga_free_mb);
      if (smax > 0 && sfree !== null) putN('sga_used_pct', r((smax - sfree) / smax * 100, 1));
      if ((lim > 0 && alloc / lim * 100 >= DEFAULTS.pga_pct) || (num(o.pga_over_alloc) || 0) > 0) ev.severity = 2;
      ev.message = `Memory on ${inst}: SGA max ${s(o.sga_max_mb) || '?'} MB, PGA allocated ${alloc === null ? '?' : alloc} MB of target ${tgt === null ? '?' : tgt} MB${lim ? ` (limit ${lim} MB)` : ''}`;
      break;
    }
    case 'limits': {
      f.key = s(o.resource || o.resource_name).toLowerCase();
      put('resource', f.key);
      all(['current', 'max_util', 'limit', 'initial']);
      let pct = num(o.pct);
      if (pct === null && num(o.current) !== null && num(o.limit) > 0) pct = r(num(o.current) / num(o.limit) * 100, 1);
      putN('pct', pct);
      if (pct !== null && pct >= DEFAULTS.limit_pct) { ev.severity = 3; ev.outcome = 'failure'; }
      ev.message = `${f.key} on ${inst}: ${s(o.current) || '?'} of ${s(o.limit) || '?'}${pct === null ? '' : ` (${pct}%)`}, peak ${s(o.max_util) || '?'}`;
      break;
    }
    case 'redo_rate': {
      all(['thread', 'switches_1h', 'switches_24h', 'switches_max_hour_24h', 'log_groups', 'log_size_mb']);
      const sw = num(o.switches_1h);
      if (sw > 0) putN('avg_switch_min', r(60 / sw, 1));
      if (sw !== null && sw > DEFAULTS.redo_switches_h) ev.severity = 2;
      ev.message = `Redo on ${inst}: ${sw === null ? '?' : sw} log switches in the last hour (peak ${s(o.switches_max_hour_24h) || '?'}/h in 24 h), ${s(o.log_groups) || '?'} groups × ${s(o.log_size_mb) || '?'} MB`;
      break;
    }
    case 'archive_dest': {
      f.key = s(o.dest_name || o.dest_id);
      all(['dest_id', 'dest_name', 'status', 'target', 'binding', 'destination', 'log_sequence', 'fail_sequence', 'dest_error']);
      const st = s(o.status).toUpperCase();
      // DEFERRED / DISABLED = switched off by a DBA; Oracle keeps the last error text on it, which is not a current failure
      const bad = st === 'ERROR' || st === 'BAD PARAM' || (!!s(o.dest_error).trim() && !/^(DEFERRED|DISABLED|INACTIVE)$/.test(st));
      if (bad) { ev.severity = 3; ev.outcome = 'failure'; }
      ev.message = `Archive destination ${f.key} on ${inst}: ${st || '?'}${o.dest_error ? ` — ${s(o.dest_error).slice(0, 160)}` : ''}`;
      break;
    }
    case 'asm': {
      f.key = s(o.name).toUpperCase();
      all(['name', 'state', 'type', 'total_mb', 'free_mb', 'usable_file_mb', 'required_mirror_free_mb', 'offline_disks']);
      let fp = num(o.free_pct);
      if (fp === null && num(o.total_mb) > 0 && num(o.free_mb) !== null) fp = r(num(o.free_mb) / num(o.total_mb) * 100, 1);
      putN('free_pct', fp);
      if ((num(o.usable_file_mb) !== null && num(o.usable_file_mb) < 0)) { ev.severity = 4; ev.outcome = 'failure'; }
      else if ((fp !== null && fp < DEFAULTS.asm_free_pct) || (num(o.offline_disks) || 0) > 0) { ev.severity = 3; ev.outcome = 'failure'; }
      ev.message = `ASM disk group ${f.key} on ${ev.host || inst}: ${fp === null ? '?' : fp}% free, ${s(o.usable_file_mb) || '?'} MB usable${(num(o.offline_disks) || 0) > 0 ? `, ${o.offline_disks} offline disks` : ''}`;
      break;
    }
    case 'tablespace_growth': {
      f.key = s(o.name).toUpperCase();
      all(['name', 'used_mb', 'max_mb', 'used_pct', 'growth_mb_day', 'history_days', 'span_days']);
      let dtf = num(o.days_to_full);
      const g = num(o.growth_mb_day);
      if (dtf === null && g > 0 && num(o.max_mb) > 0 && num(o.used_mb) !== null) dtf = r(Math.max(0, (num(o.max_mb) - num(o.used_mb)) / g), 2);
      if (dtf !== null && dtf >= 0) putN('days_to_full', dtf);
      if (dtf !== null && dtf >= 0 && dtf < DEFAULTS.days_to_full) { ev.severity = dtf < DEFAULTS.days_to_full_crit ? 4 : 3; ev.outcome = 'failure'; }
      ev.message = `Tablespace ${f.key} on ${inst}: ${s(o.used_mb) || '?'} / ${s(o.max_mb) || '?'} MB, growing ${g === null ? '?' : g} MB/day${dtf === null ? '' : ` — full in ${dtf} days`}`;
      break;
    }
    case 'host': {
      all(['num_cpus', 'num_cpu_cores', 'load', 'mem_total_mb', 'mem_free_mb', 'host_cpu_pct']);
      const t = num(o.mem_total_mb); const fr = num(o.mem_free_mb);
      if (t > 0 && fr !== null) putN('mem_used_pct', r((t - fr) / t * 100, 1));
      ev.message = `Host ${ev.host || inst}: ${s(o.num_cpus) || '?'} CPUs, CPU ${s(o.host_cpu_pct) || '?'}%, load ${s(o.load) || '?'}, ${fr === null ? '?' : fr} MB memory free`;
      break;
    }
    case 'pack_ash': {
      f.key = `${s(o.sql_id)}|${s(o.event)}`;
      all(['sql_id', 'event', 'samples', 'rank']);
      ev.message = `Diagnostics Pack ASH on ${inst}: ${s(o.sql_id) || '(no SQL)'} / ${s(o.event)} ${s(o.samples)} samples in 5 min`;
      break;
    }
    case 'stats_stale': {
      f.key = `${s(o.owner)}.${s(o.table_name)}`;
      all(['owner', 'table_name', 'num_rows', 'last_analyzed', 'locked']);
      ev.severity = 1;
      ev.message = `Stale optimizer statistics on ${inst}: ${f.key} (${s(o.num_rows) || '?'} rows, last analyzed ${s(o.last_analyzed) || 'never'})`;
      break;
    }
    case 'gg_capture': case 'gg_apply': {
      // GoldenGate integrated Extract (capture) / Replicat (apply), as the database reports them
      f.key = s(o.name);
      all(['name', 'status', 'state', 'purpose', 'error', 'lag_s', 'messages', 'applied']);
      const st = s(o.status).toUpperCase(), lag = num(o.lag_s), what = kind === 'gg_capture' ? 'Extract' : 'Replicat';
      let sev = 0;
      if (st === 'ABORTED' || s(o.error)) sev = 4; else if (st === 'DISABLED') sev = 3;
      if (lag !== null) sev = Math.max(sev, lag >= DEFAULTS.gg_lag_high_s ? 3 : lag >= DEFAULTS.gg_lag_s ? 2 : 0);
      ev.severity = sev; ev.outcome = sev >= 3 ? 'failure' : 'success';
      ev.message = `GoldenGate ${what} ${f.key} on ${inst}: ${st || '?'}${s(o.state) ? ' / ' + s(o.state) : ''}${lag !== null ? `, lag ${lag} s` : ''}${s(o.error) ? ' - ' + s(o.error) : ''}`;
      break;
    }
    case 'change_txn': {
      f.key = s(o.xid);
      all(['job', 'xid', 'commit_scn', 'commit_ts', 'user', 'os_user', 'machine', 'program', 'rows', 'tables', 'inserts', 'updates', 'deletes', 'ddl', 'ddl_tables', 'mass']);
      if (s(o.user)) ev.user = s(o.user).toLowerCase();
      const ddl = s(o.ddl), mass = String(o.mass) === 'true', tool = /sqlplus|sql ?developer|sqldeveloper|toad|plsqldev|pl\/sql developer|dbeaver|sqlcl|navicat|datagrip/i.test(s(o.program)), del = (num(o.deletes) || 0) > 0;
      let sev = 0;
      if (/\b(drop|truncate)\b/i.test(ddl) || (mass && del)) sev = 3; else if (mass) sev = 2;
      if (tool && (num(o.rows) || 0) > 0) sev = Math.max(sev, 2);
      if (tool) f.interactive = '1';
      ev.severity = sev; ev.outcome = sev >= 3 ? 'failure' : 'success';
      ev.message = `Data change on ${inst} by ${s(o.user) || '?'}${s(o.program) ? ' (' + s(o.program) + ')' : ''}: ${num(o.rows) || 0} row(s)${s(o.tables) ? ' in ' + s(o.tables) : ''}${ddl ? ' - DDL: ' + ddl.slice(0, 160) : ''}`;
      break;
    }
    case 'change_stream': {
      f.key = s(o.job);
      all(['job', 'name', 'state', 'reason', 'detail', 'txns', 'lag_s', 'commit_scn']);
      const stopped = s(o.state) === 'stopped';
      ev.severity = stopped ? 3 : 0; ev.outcome = stopped ? 'failure' : 'success';
      ev.message = `Change Stream ${s(o.name) || s(o.job)} on ${inst}: ${stopped ? 'STOPPED - ' + (s(o.detail) || s(o.reason)) : (num(o.txns) || 0) + ' transaction(s), lag ' + (s(o.lag_s) || '?') + ' s'}`;
      break;
    }
    case 'repl_status': {
      f.key = s(o.job);
      all(['job', 'name', 'state', 'reason', 'detail', 'txns', 'rows', 'lag_s', 'conflicts']);
      const stopped = s(o.state) === 'stopped', lag = num(o.lag_s);
      let sev = stopped ? 4 : 0;
      if (!stopped && lag !== null && lag >= DEFAULTS.gg_lag_high_s) sev = 3;
      if (!stopped && (num(o.conflicts) || 0) > 0) sev = Math.max(sev, 2);
      ev.severity = sev; ev.outcome = sev >= 3 ? 'failure' : 'success';
      ev.message = `Replication ${s(o.name) || s(o.job)} from ${inst}: ${stopped ? 'STOPPED (' + s(o.reason) + ') ' + s(o.detail) : (num(o.rows) || 0) + ' row(s) applied, lag ' + (lag === null ? '?' : lag) + ' s'}`;
      break;
    }
    case 'verify_result': {
      f.key = s(o.job);
      all(['job', 'name', 'source', 'target', 'in_sync', 'tables', 'diverged', 'missing', 'different', 'extra']);
      const diff = String(o.in_sync) !== 'true';
      ev.severity = diff ? 3 : 0; ev.outcome = diff ? 'failure' : 'success';
      ev.message = `Data Verify ${s(o.name) || s(o.job)}: ${diff ? `source and target DIFFER - missing ${num(o.missing) || 0}, different ${num(o.different) || 0}, extra ${num(o.extra) || 0} (${s(o.diverged)})` : 'in sync'}`;
      break;
    }
    case 'audit_config': {
      all(['unified_pure', 'audit_trail', 'audit_sys_operations', 'policies', 'cleanup_jobs', 'last_archive']);
      const none = !s(o.policies).trim();
      ev.severity = none ? 3 : 0; ev.outcome = none ? 'failure' : 'success';
      ev.message = `Audit configuration on ${inst}: ${none ? 'NO unified audit policy enabled' : s(o.policies).split(',').length + ' polic(ies) enabled'}${s(o.unified_pure).toUpperCase() === 'TRUE' ? ', pure unified auditing' : ''}`;
      break;
    }
    case 'db_server': {
      f.key = s(o.ip);
      all(['ip', 'os', 'uptime_s', 'load5', 'ncpu', 'mem_total_mb', 'mem_avail_mb', 'swap_total_mb', 'swap_used_mb', 'ntp_synced', 'thp', 'pmon', 'listeners', 'oratab_down', 'last_patch']);
      const mt = num(o.mem_total_mb), ma = num(o.mem_avail_mb), ld = num(o.load5), nc = num(o.ncpu), st = num(o.swap_total_mb), su = num(o.swap_used_mb), why = [];
      let sev = 0;
      if (s(o.oratab_down)) { sev = 4; why.push('not running: ' + s(o.oratab_down)); }
      if (mt && ma !== null && ma / mt < 0.05) { sev = Math.max(sev, 3); why.push(`memory available ${Math.round(ma / mt * 100)} %`); }
      if (nc && ld !== null && ld / nc > 2) { sev = Math.max(sev, 3); why.push(`load ${ld} on ${nc} CPUs`); }
      if (st && su !== null && su / st > 0.5) { sev = Math.max(sev, 2); why.push(`swap ${Math.round(su / st * 100)} %`); }
      if (String(o.ntp_synced) === 'false') { sev = Math.max(sev, 2); why.push('clock not synchronised'); }
      ev.severity = sev; ev.outcome = sev >= 3 ? 'failure' : 'success';
      ev.message = `Database server ${s(o.ip)} (${inst}): ${why.length ? why.join('; ') : 'OK'}`;
      break;
    }
    case 'db_server_fs': {
      f.key = s(o.mount);
      all(['mount', 'used_pct', 'size_mb', 'avail_mb', 'oracle_fs']);
      const p = num(o.used_pct), sev = p === null ? 0 : p >= 95 ? 4 : p >= 90 ? 3 : p >= 85 ? 2 : 0;
      ev.severity = sev; ev.outcome = sev >= 3 ? 'failure' : 'success';
      ev.message = `Database server file system ${f.key} (${inst}): ${p === null ? '?' : p} % used${String(o.oracle_fs) === 'true' ? ' (Oracle file system)' : ''}`;
      break;
    }
    case 'dg_config': {
      all(['role', 'protection_mode', 'protection_level', 'switchover_status', 'broker', 'force_logging', 'flashback', 'open_mode', 'db_unique_name', 'fs_failover', 'log_mode', 'supplemental_min', 'supplemental_pk', 'standbys']);
      const role = s(o.role).toUpperCase(), sb = num(o.standbys) || 0, sw = s(o.switchover_status).toUpperCase();
      let sev = 0; const why = [];
      if (role === 'PRIMARY' && sb > 0) {
        if (s(o.force_logging).toUpperCase() === 'NO') { sev = 3; why.push('force logging off'); }
        if (s(o.protection_level) && s(o.protection_mode) && s(o.protection_level).toUpperCase() !== s(o.protection_mode).toUpperCase()) { sev = 3; why.push(`protection level ${s(o.protection_level)} below ${s(o.protection_mode)}`); }
        if (/GAP|FAILED DESTINATION/.test(sw)) { sev = 3; why.push('switchover status ' + sw); }
        if (s(o.flashback).toUpperCase() === 'NO') { sev = Math.max(sev, 1); why.push('flashback off'); }
      }
      ev.severity = sev; ev.outcome = sev >= 3 ? 'failure' : 'success';
      ev.message = `Data Guard on ${inst}: ${role || '?'}, ${s(o.protection_mode) || '?'}${sb ? `, ${sb} standby destination(s)` : ''}${why.length ? ' - ' + why.join('; ') : ''}`;
      break;
    }
    case 'dg_dest': {
      f.key = s(o.db_unique_name || o.dest_id).toUpperCase();
      all(['dest_id', 'db_unique_name', 'status', 'gap_status', 'error', 'recovery_mode', 'protection_mode', 'sync_status', 'synchronized', 'archived_seq', 'applied_seq', 'transmit_mode', 'affirm', 'valid_now', 'database_mode']);
      const st = s(o.status).toUpperCase(), gap = s(o.gap_status).toUpperCase(), rm = s(o.recovery_mode).toUpperCase();
      let sev = 0;
      if (st === 'ERROR' || s(o.error) || /UNRESOLVABLE/.test(gap)) sev = 4;
      else if (/GAP/.test(gap) && gap !== 'NO GAP') sev = 3;
      else if (rm === 'IDLE') sev = 3;
      else if (st === 'DEFERRED') sev = 2;
      ev.severity = sev; ev.outcome = sev >= 3 ? 'failure' : 'success';
      ev.message = `Data Guard redo to ${f.key} from ${inst}: ${st || '?'}${s(o.database_mode) ? ', standby ' + s(o.database_mode) : ''}${gap ? ', ' + gap : ''}${rm ? ', apply ' + rm : ''}${s(o.error) ? ' - ' + s(o.error) : ''}`;
      break;
    }
    case 'dg_applied': {
      f.key = `${s(o.dest_id)}:${s(o.thread)}`;
      all(['dest_id', 'thread', 'last_seq', 'applied_seq', 'unapplied', 'unapplied_since_s']);
      const w = num(o.unapplied_since_s), sev = lagSev(w);
      ev.severity = sev; ev.outcome = sev >= 3 ? 'failure' : 'success';
      ev.message = `Data Guard apply for destination ${s(o.dest_id)} thread ${s(o.thread)} on ${inst}: ${num(o.unapplied) || 0} log(s) not applied${w ? `, oldest waiting ${w} s` : ''}`;
      break;
    }
    case 'dg_stats': {
      f.key = s(o.name).toLowerCase();
      all(['name', 'value', 'unit', 'time_computed', 'datum_time']);
      const sec = intervalS(o.value); putN('value_s', sec);
      const sev = /lag/.test(f.key) ? lagSev(sec) : 0;
      ev.severity = sev; ev.outcome = sev >= 3 ? 'failure' : 'success';
      ev.message = `Data Guard ${f.key} on standby ${inst}: ${s(o.value) || '?'}${sec !== null ? ` (${sec} s)` : ''}`;
      break;
    }
    case 'dg_process': {
      all(['role', 'mrp', 'rfs', 'mrp_action', 'mrp_thread', 'mrp_sequence']);
      if (/STANDBY/i.test(s(o.role)) && num(o.mrp) === 0) { ev.severity = 4; ev.outcome = 'failure'; }
      ev.message = `Data Guard processes on ${inst}: MRP ${s(o.mrp) || 0}, RFS ${s(o.rfs) || 0}${s(o.mrp_action) ? ' - MRP ' + s(o.mrp_action) + (s(o.mrp_sequence) ? ' sequence ' + s(o.mrp_sequence) : '') : ''}`;
      break;
    }
    case 'sched_job': {
      f.key = `${s(o.owner)}.${s(o.job_name)}`.toUpperCase();
      all(['owner', 'job_name', 'session_id', 'running_instance', 'elapsed_s']);
      const el = num(o.elapsed_s) || 0;
      ev.severity = el >= 3600 ? 3 : el >= 1200 ? 2 : 0; ev.outcome = 'success';
      ev.message = `Scheduler job ${f.key} on ${inst} running for ${Math.round(el / 60)} min`;
      break;
    }
    case 'bulk_delete': {
      f.key = s(o.sql_id);
      all(['sql_id', 'rows_deleted', 'executions', 'table', 'module', 'period_s', 'new_cursor']);
      if (o.sql_text) f.sql_text = s(o.sql_text).replace(/\s+/g, ' ').slice(0, MAX_SQL);
      ev.user = s(o.user).toLowerCase(); put('db_user', o.user);
      const n = num(o.rows_deleted) || 0;
      ev.severity = n >= 10000 ? 3 : n >= 1000 ? 2 : 1;
      ev.message = `${n} row(s) deleted on ${inst}${s(o.table) ? ' from ' + s(o.table) : ''} by ${s(o.user) || '?'} (SQL ${s(o.sql_id)}) in ${Math.round((num(o.period_s) || 0) / 60)} min`;
      break;
    }
    case 'code_change': {
      f.key = `${s(o.owner)}.${s(o.name)} (${s(o.type)})`.toUpperCase();
      all(['owner', 'name', 'type', 'ddl_time', 'created', 'status']);
      ev.severity = 2;
      ev.message = `${s(o.type)} ${s(o.owner)}.${s(o.name)} on ${inst} ${s(o.created) === 'Y' ? 'created' : 'changed'} at ${s(o.ddl_time)}${s(o.status) === 'INVALID' ? ' - now INVALID' : ''}`;
      break;
    }
    case 'code_change_by': {
      f.key = `${s(o.owner)}.${s(o.name)}|${s(o.user)}|${s(o.at)}`.toUpperCase();
      all(['user', 'os_user', 'client_host', 'action', 'owner', 'name', 'at', 'sysdba', 'ok', 'oracle_user']);
      ev.user = s(o.user).toLowerCase();
      const excluded = /^(SYS)$/i.test(s(o.user)) || s(o.sysdba) === 'Y' || s(o.oracle_user) === 'Y';
      f.excluded = excluded ? 'Y' : 'N';
      ev.severity = excluded ? 0 : 2;
      ev.message = `${s(o.action)} ${s(o.owner)}.${s(o.name)} on ${inst} by ${s(o.user) || '?'}${s(o.sysdba) === 'Y' ? ' AS SYSDBA' : ''}${s(o.os_user) ? ' (' + s(o.os_user) + (s(o.client_host) ? '@' + s(o.client_host) : '') + ')' : ''}${s(o.ok) === 'N' ? ' - failed' : ''}`;
      break;
    }
    case 'app_session': {
      f.key = `${s(o.service)}|${s(o.machine)}|${s(o.program)}|${s(o.db_user)}`.slice(0, 300);
      all(['service', 'machine', 'program', 'db_user', 'module', 'sessions', 'active', 'max_idle_s', 'oldest_logon', 'instances']);
      ev.severity = 0;
      ev.message = `${s(o.program) || '?'} on ${s(o.machine) || '?'} as ${s(o.db_user) || '?'} (service ${s(o.service) || '?'}): ${num(o.sessions) || 0} session(s), ${num(o.active) || 0} active, on ${inst}`;
      break;
    }
    case 'lsnr_conn': {
      f.key = `${s(o.service)}|${s(o.client_host)}|${s(o.program)}|${s(o.code)}`.slice(0, 300);
      all(['service', 'client_host', 'program', 'code', 'n', 'last']);
      const ok = s(o.code) === '0';
      ev.severity = ok ? 0 : 3; ev.outcome = ok ? 'success' : 'failure';
      ev.message = `Listener on ${inst}: ${num(o.n) || 0} ${ok ? 'connection(s)' : 'REFUSED connection(s) (TNS-' + s(o.code) + ')'} from ${s(o.client_host) || '?'} ${s(o.program) ? '(' + s(o.program) + ') ' : ''}to service ${s(o.service) || '?'}`;
      break;
    }
    case 'db_link': {
      f.key = `${s(o.owner)}.${s(o.link)}`.toUpperCase();
      all(['owner', 'link', 'remote_user', 'host', 'created']);
      ev.severity = 0;
      ev.message = `Database link ${f.key} on ${inst} connects as ${s(o.remote_user) || '(current user)'} to ${s(o.host).slice(0, 120)}`;
      break;
    }
    case 'user_write': {
      f.key = s(o.db_user).toUpperCase();
      all(['db_user', 'status', 'dba', 'any_dml', 'own_tables', 'obj_write']);
      ev.severity = 0;
      ev.message = `User ${f.key} on ${inst}: ${s(o.dba) ? 'roles ' + s(o.dba) + ', ' : ''}${s(o.any_dml) ? s(o.any_dml) + ', ' : ''}owns ${num(o.own_tables) || 0} table(s), can write ${num(o.obj_write) || 0} other table(s)`;
      break;
    }
    case 'rac_node': {
      f.key = s(o.thread);
      all(['thread', 'thread_status', 'enabled', 'instance_name', 'host_name', 'status', 'database_status', 'startup_time', 'db_unique_name']);
      const st = s(o.status).toUpperCase();
      ev.severity = st === 'OPEN' ? 0 : 4; ev.outcome = st === 'OPEN' ? 'success' : 'failure';
      ev.message = `RAC ${s(o.db_unique_name) || inst} node ${s(o.instance_name) || 'thread ' + s(o.thread)}${s(o.host_name) ? ' on ' + s(o.host_name) : ''}: ${st || '?'}`;
      break;
    }
    case 'dg_gap': {
      f.key = s(o.thread);
      all(['thread', 'low_seq', 'high_seq']);
      ev.severity = 4; ev.outcome = 'failure';
      ev.message = `Data Guard gap on standby ${inst}: thread ${s(o.thread)} sequences ${s(o.low_seq)}-${s(o.high_seq)} missing`;
      break;
    }
    case 'dg_event': {
      f.key = s(o.error_code) || s(o.facility);
      all(['severity', 'facility', 'error_code', 'message', 'ts']);
      const fatal = /fatal/i.test(s(o.severity));
      ev.severity = fatal ? 4 : 3; ev.outcome = 'failure';
      ev.message = `Data Guard ${fatal ? 'FATAL' : 'error'} on ${inst}: ${s(o.message).slice(0, 240)}`;
      break;
    }
    case 'dg_broker': {
      f.key = s(o.member);
      all(['member', 'dg_role', 'redo_source', 'enabled', 'status']);
      const st = num(o.status), sev = st !== null && st !== 0 ? 3 : 0;
      ev.severity = sev; ev.outcome = sev ? 'failure' : 'success';
      ev.message = `Data Guard broker member ${f.key} (${s(o.dg_role) || '?'}) on ${inst}: ${sev ? 'ORA-' + String(st).padStart(5, '0') : 'SUCCESS'}`;
      break;
    }
    case 'dg_srl': {
      all(['srl_groups', 'online_groups', 'threads']);
      ev.message = `Standby redo logs on ${inst}: ${s(o.srl_groups) || 0} group(s), online ${s(o.online_groups) || 0} in ${s(o.threads) || 1} thread(s)`;
      break;
    }
    case 'dg_nologging': {
      all(['files', 'last']);
      const n = num(o.files) || 0;
      ev.severity = n > 0 ? 2 : 0; ev.outcome = n > 0 ? 'failure' : 'success';
      ev.message = n ? `NOLOGGING changes on ${inst}: ${n} datafile(s) since ${s(o.last)} - those blocks are not on a standby` : `No NOLOGGING changes on ${inst} in 7 days`;
      break;
    }
    default: break;
  }
  return ev;
}

module.exports = { KINDS, ACTIONS, PERF_ACTIONS, CLASS_KEYS, DEFAULTS, parse, forecast, planChanges, blockingTree, num, intervalS };
