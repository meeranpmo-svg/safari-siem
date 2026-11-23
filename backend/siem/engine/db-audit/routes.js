// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Database health + performance API (Oracle) — register(api, deps). {P} = config.api_prefix || '/api/soc'; same
 * proxy-secret + portal session auth as every SOC route. Read-only, any authenticated user (viewer); SQL text is
 * returned to operator / admin only. register() also:
 *   - registers the oracle-health / oracle-audit parsers in the router (db-audit/index.js registerParsers),
 *   - adds the in-memory "latest sample" stages to deps.pipeline (after detection — they never change events),
 *   - exposes deps.oracle = createOracleSummary(…) and deps.oracle_perf = createOraclePerf(…) for other modules.
 *
 *   GET {P}/db/oracle            ?hours=1-720 (default 24)
 *       → { generated_at, window_h, stale_after_s, clickhouse{ok,error},
 *           totals{instances, down, stale, with_issues, open_alerts, failed_logons_24h, blocked_sessions},
 *           instances[{ key:"host|INSTANCE", host, instance, db_name, version, status, up, open_mode, role, log_mode, uptime_s, last_seen, stale,
 *                       tablespaces[{name, used_pct, used_mb, max_mb, autoextend, severity}], sessions{total, active, blocked, max_sessions, processes, max_processes}|null,
 *                       blocked_sessions[{sid, user, blocking_sid, blocking_user, wait_s, event, sql_id}], waits[{class, pct, time_waited_s, rank}],
 *                       backup{status, input_type, age_h, end_time, output_mb, outcome, severity}|null, dataguard{role, apply_lag_s, transport_lag_s, protection_mode, severity}|null,
 *                       redo{log_mode, archive_lag_s, unarchived, switches_1h, severity}|null, fra{used_pct, space_used_mb, space_limit_mb, reclaimable_mb, severity}|null,
 *                       invalid_objects, listener{name, status, up, services}|null, alertlog{path, ora_errors, tail[]}|null, top_sql[{sql_id, elapsed_s, executions, user, sql_text}],
 *                       failed_logons_24h, failed_logons_last, collector{version, last, queries_failed, last_error}|null, open_alerts, worst_severity, issues[{severity, text, action, ts}] }],
 *           alerts[{id, rule_id, rule_name, severity, status, count, ts_last, summary, host, instance}] }
 *   GET {P}/db/oracle/perf       ?instance=host|INST|INST &con=PDB &from= &to= (ms / s / ISO; default last hour, max 31 days) &step= (s, ≥ 60; auto ≤ 720 points)
 *       → { generated_at, clickhouse{ok,error}, from, to, step_s, con, thresholds{aas_per_cpu, log_file_sync_ms, seq_read_ms},
 *           instances[{key, host, instance, db_name, pdbs[], cpu_count, version, last_seen, stale}], instance{…}|null,
 *           series{ts[], aas[], aas_max[], db_time_s[], db_cpu_s[], executions_s[], user_calls_s[], transactions_s[], logical_reads_s[], physical_reads_s[],
 *                  physical_writes_s[], physical_read_mb_s[], physical_write_mb_s[], redo_mb_s[], hard_parses_s[], soft_parses_s[], logons_s[], network_mb_s[], host_cpu_pct[], cpu_count[]},
 *           aas_by_class{ts[], classes[{key, name, values[]}]}, efficiency{ts[], buffer_cache_hit_pct[], library_cache_hit_pct[], soft_parse_pct[], execute_to_parse_pct[], latest{…}|null},
 *           wait_classes[{class, time_s, waits_s, dbtime_pct, pct}], wait_events[{event, class, avg_ms, waits_s, time_s, pct, waits, time_waited_s, over}],
 *           latches[{name, type, sleeps_s, miss_pct}], summary{points, cpu_count, aas_avg, aas_max, aas_latest, db_time_s_avg, db_cpu_s_avg, executions_s_avg, …}|null,
 *           alerts[{id, rule_id, rule_name, severity, status, count, ts_first, ts_last, summary, host, instance}] }
 *   GET {P}/db/oracle/perf-intel ?instance= (viewer) · POST {P}/db/oracle/perf-intel/ask (operator) - see perf-intel.js
 *   GET {P}/db/oracle/topsql     ?instance= &period=1h|6h|24h|7d &by=elapsed|cpu|gets|reads|execs &sql_id= (drawer)
 *       → { generated_at, clickhouse, period, period_s, by, plan_ratio, sql_text_visible, instances[], instance,
 *           sql[{sql_id, plan_hash, plan_count, plans[{plan_hash, executions, ela_ms_exec, last_ts}], executions, elapsed_s, cpu_s, buffer_gets, disk_reads, rows_processed,
 *                ela_ms_exec, cpu_ms_exec, gets_exec, reads_exec, rows_exec, module, user, sql_text (operator+), plan_change{old_plan, new_plan, ratio, worse}|null}],
 *           plan_changes[{sql_id, old_plan, new_plan, old_ms_exec, new_ms_exec, ratio, worse, ts, source:'collector'|'history'}],
 *           activity[{sql_id, aas, captured, top_event, module}], activity_minutes,
 *           detail{sql_id, module, user, step_s, plan_change, sql_text (operator+), plans[{plan_hash, executions, ela_ms_exec, cpu_ms_exec, gets_exec, points[{ts, executions, ela_ms_exec, cpu_ms_exec, gets_exec}]}]}|null }
 *   GET {P}/db/oracle/sessions   ?instance=   (latest collector cycle)
 *       → { generated_at, clickhouse, sql_text_visible, instances[], instance, snapshot_ts, stale,
 *           blocking{trees[{sid, serial, user, status, program, machine, sql_id, event, wait_s, object, waiters, max_wait_s, children[…]}], waiters, max_wait_s},
 *           long_running[{sid, serial, user, sql_id, elapsed_s, sql_exec_start, state, event, wait_class, module, program, machine, sql_text (operator+)}],
 *           top_sessions[{sid, serial, user, program, module, machine, count, aas, top_event, sql_id, state, rank}], top_sql[{sql_id, aas, pct, count, top_event, module, user, rank}],
 *           active{captures, aas, top_event, by_class[{key, name, aas}]}|null }
 *   GET {P}/db/oracle/capacity   ?instance= (optional; all instances otherwise)
 *       → { generated_at, clickhouse, thresholds{days_to_full, temp_pct, limit_pct, asm_free_pct},
 *           instances[{key, host, instance, db_name, last_seen, stale, tablespaces[{name, used_mb, max_mb, used_pct, growth_mb_day, days_to_full, history_days, source, severity}],
 *                      asm[{name, state, type, total_mb, free_mb, usable_file_mb, free_pct, offline_disks, severity}], limits[{resource, current, max_util, limit, pct, severity}],
 *                      temp_undo{…}|null, memory{…}|null, redo{switches_1h, switches_24h, switches_max_hour_24h, log_groups, log_size_mb, avg_switch_min}|null,
 *                      archive_dests[{dest, dest_id, status, target, destination, error, severity}], host{num_cpus, load, mem_total_mb, mem_free_mb, mem_used_pct, host_cpu_pct}|null}] }
 *   GET {P}/db/oracle/:key       one instance (key "host|INSTANCE" or just the instance name) → instance object, 404 when unknown
 *   GET {P}/db/oracle-stats      module counters (staged samples, ClickHouse queries / errors; perf counters under "perf")
 */
const { registerParsers, createOracleSummary, createOraclePerf } = require('./index');
const { HttpError, wrap, prefixOf, audit, body } = require('../soc/routeutil');
const { createTuning } = require('./tuning');

const SQL_TEXT_ROLES = new Set(['operator', 'admin']);

function register(api, deps) {
  const P = prefixOf(deps);
  const log = deps.log && deps.log.child ? deps.log.child({ mod: 'db-oracle' }) : deps.log;
  const types = registerParsers(deps.parserModule);
  if (log && log.info) log.info('oracle parsers registered', { types });
  const cfg = (deps.config && deps.config.db_oracle) || {};
  const oracle = deps.oracle || createOracleSummary({ ch: deps.ch, alerts: deps.alerts, log, windowH: cfg.window_h || 24, staleS: cfg.stale_s || 300, state: deps.state });
  deps.oracle = oracle;
  const perf = deps.oracle_perf || createOraclePerf({ ch: deps.ch, alerts: deps.alerts, log, staleS: cfg.stale_s || 300 });
  deps.oracle_perf = perf;
  if (deps.pipeline && typeof deps.pipeline.use === 'function' && !deps.oracle_staged) {
    deps.pipeline.use((ev) => { try { oracle.stage(ev); } catch (e) { if (log && log.every) log.every('oracle-stage', 60000, 'warn', 'oracle summary stage failed', { err: e.message }); } }, 'oracle-summary');
    deps.pipeline.use((ev) => { try { perf.stage(ev); } catch (e) { if (log && log.every) log.every('oracle-perf-stage', 60000, 'warn', 'oracle perf stage failed', { err: e.message }); } }, 'oracle-perf');
    deps.oracle_staged = true;
  }
  // Oracle Tuning: findings, AI recommendations (proposals only) and their approval trail - engine/db-audit/tuning.js
  const tuning = deps.oracle_tuning || createTuning({ ch: deps.ch, state: deps.state, config: deps.config, log, perf });
  deps.oracle_tuning = tuning;
  if (deps.pipeline && typeof deps.pipeline.use === 'function' && !deps.oracle_tuning_staged) {
    deps.pipeline.use((ev) => { try { tuning.stage(ev); } catch (e) { /* never stops the pipeline */ } }, 'oracle-tuning');
    deps.oracle_tuning_staged = true;
  }
  const withRole = (ctx) => Object.assign({}, ctx.query || {}, { _sql_text: SQL_TEXT_ROLES.has(String(ctx.role || '').toLowerCase()) });
  api.route('GET', `${P}/db/oracle`, wrap(deps, null, async (ctx) => ctx.ok(await oracle.summary(ctx.query || {}))));
  // remove an unknown / unused instance from the database pages (admin or the DBA approver); reappears if it reports again
  api.route('GET', `${P}/db/oracle-removed`, wrap(deps, null, (ctx) => ctx.ok({ items: oracle.forgotten() })));
  api.route('POST', `${P}/db/oracle-removed`, wrap(deps, 'approve:eng:dba', (ctx) => {
    const b = body(ctx); const r = oracle.forget(b.key, ctx.user, b.reason);
    audit(ctx, 'oracle.instance.remove', r.id, { reason: r.reason }); return ctx.ok(r);
  }));
  api.route('POST', `${P}/db/oracle-removed/restore`, wrap(deps, 'approve:eng:dba', (ctx) => {
    const b = body(ctx); oracle.unforget(b.key); audit(ctx, 'oracle.instance.restore', String(b.key || ''), {}); return ctx.ok({ ok: true });
  }));
  api.route('GET', `${P}/db/oracle-stats`, wrap(deps, null, (ctx) => ctx.ok(Object.assign(oracle.stats(), { perf: perf.stats() }))));
  // performance routes — registered BEFORE /db/oracle/:key so "perf", "topsql", … are not taken for instance keys
  api.route('GET', `${P}/db/oracle/perf`, wrap(deps, null, async (ctx) => ctx.ok(await perf.perf(withRole(ctx)))));
  // performance intelligence (perf-intel.js): normal band per hour, unusual episodes, bottleneck diagnosis, SQL regressions, CPU headroom, advisor
  require('./perf-intel').register(api, deps, P, withRole);
  api.route('GET', `${P}/db/oracle/topsql`, wrap(deps, null, async (ctx) => ctx.ok(await perf.topsql(withRole(ctx)))));
  api.route('GET', `${P}/db/oracle/sessions`, wrap(deps, null, async (ctx) => ctx.ok(await perf.sessions(withRole(ctx)))));
  api.route('GET', `${P}/db/oracle/capacity`, wrap(deps, null, async (ctx) => ctx.ok(await perf.capacity(withRole(ctx)))));
  // tuning intelligence (tuning-intel.js): did each fix work, success learned per kind, findings ranked by benefit, unstable plans, literal SQL
  require('./tuning-intel').register(api, deps, P, withRole, tuning);
  api.route('GET', `${P}/db/oracle/tuning`, wrap(deps, 'analyst', async (ctx) => ctx.ok(await tuning.view(ctx.query || {}))));
  // production / DR pairs for the Database Dashboard (database names, roles and replication state - no personal data)
  api.route('GET', `${P}/db/oracle/dr`, wrap(deps, null, async (ctx) => {
    let extra = []; try { extra = deps.dbaAlerts ? (deps.dbaAlerts.status().instances || []).map((i) => i.instance) : []; } catch (e) { extra = []; /* the DBA alert center not running: the tuning readings since start-up still answer */ }
    return ctx.ok(await tuning.drPairs(extra));
  }));
  // the Oracle reference library behind the AI DBA's advice (oracle/skills, fixed commit): list, or one guide by id - read-only
  api.route('GET', `${P}/db/oracle/reference`, wrap(deps, 'analyst', (ctx) => {
    const q = require('../util/check').body(ctx.query || {}).str('id', { max: 120, re: /^[A-Za-z0-9_/-]+$/, msg: 'id must be a guide id such as performance/wait-events' }).done();
    return ctx.ok(tuning.reference(q));
  }));
  api.route('POST', `${P}/db/oracle/tuning/advise`, wrap(deps, 'operator', async (ctx) => {
    const b = body(ctx); const r = await tuning.advise(Object.assign({}, b, { user: ctx.user, role: ctx.role }));
    audit(ctx, 'oracle.tuning.advise', r.id, { instance: r.instance, sql_id: r.sql_id, status: r.status, finding: r.finding_key });
    return ctx.ok(r);
  }));
  api.route('POST', `${P}/db/oracle/tuning/proposals`, wrap(deps, 'operator', async (ctx) => {
    const r = await tuning.proposeFromFinding(body(ctx), { user: ctx.user, role: ctx.role });
    audit(ctx, 'oracle.tuning.propose', r.id, { instance: r.instance, finding: r.finding_key });
    return ctx.ok(r);
  }));
  api.route('POST', `${P}/db/oracle/tuning/:id/decide`, wrap(deps, 'operator', async (ctx) => {
    const b = body(ctx); const r = tuning.decide(ctx.params.id, b, { user: ctx.user, role: ctx.role }, deps);
    audit(ctx, 'oracle.tuning.' + String(b.decision || ''), r.id, { instance: r.instance, note: b.note ? String(b.note).slice(0, 300) : '' });
    return ctx.ok(r);
  }));
  // Database Audit: who did what in the databases (unified audit trail) + audit configuration checks - engine/db-audit/audit-report.js.
  // Analyst and above (named people's activity); every read and export is itself audited.
  const auditRep = deps.oracle_audit_report || require('./audit-report').createAuditReport({ ch: deps.ch, dbInstances: () => (deps.dbaAlerts ? deps.dbaAlerts.status().instances || [] : []) });
  const auditQ = (q) => require('../util/check').body(q || {}).str('instance', { max: 64, re: /^[A-Za-z0-9_$#.-]+$/, msg: 'instance must be an Oracle instance name' })
    .str('database', { max: 64, re: /^[A-Za-z0-9_$#.-]+$/, msg: 'database must be an Oracle database name' }).oneOf('view', ['database', 'instance'])
    .str('hours', { max: 5, re: /^\d+$/, msg: 'hours must be a number' }).str('action', { max: 40 }).str('user', { max: 128 }).str('q', { max: 200 }).str('limit', { max: 6, re: /^\d+$/, msg: 'limit must be a number' }).str('export', { max: 5 })
    .rule((o) => (o.instance && o.database ? 'choose an instance or a database, not both' : null)).done();
  deps.oracle_audit_report = auditRep;
  api.route('GET', `${P}/db/oracle/audit`, wrap(deps, 'analyst', async (ctx) => {
    const q = auditQ(ctx.query), r = await auditRep.report(q);
    audit(ctx, 'oracle.audit.view', String(q.instance || q.database || 'all'), { hours: r.hours || null, events: r.total || 0, view: r.view || null });
    return ctx.ok(r);
  }));
  api.route('GET', `${P}/db/oracle/audit/events`, wrap(deps, 'analyst', async (ctx) => {
    const q = auditQ(ctx.query), r = await auditRep.events(q);
    audit(ctx, q.export ? 'oracle.audit.export' : 'oracle.audit.search', String(q.instance || q.database || 'all'), { filter: r.filter || null, rows: r.items ? r.items.length : 0 });
    return ctx.ok(r);
  }));
  api.route('GET', `${P}/db/oracle/:key`, wrap(deps, null, async (ctx) => {
    const i = await oracle.instance(ctx.params.key, ctx.query || {});
    if (!i) throw new HttpError(404, `oracle instance ${ctx.params.key} not found`);
    return ctx.ok(i);
  }));
  return oracle;
}

module.exports = { register };
