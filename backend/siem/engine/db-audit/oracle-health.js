// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Oracle health collector parser — source type "oracle-health" (agents/oracle/sentra-oracle-collector.sh / .ps1, docs/ORACLE.md).
 * Input: one JSON object per NDJSON line, {kind, t, host, instance, db_name, …} (shape per kind in docs/ORACLE.md
 * "Collector record reference"). Output: normalised events, category "database" (authentication for failed logons):
 *
 *   kind              action             notes
 *   instance          health-sample      status/open_mode/role/uptime; status != OPEN → action instance-down, severity 4
 *   tablespace        tablespace-usage   fields.key = tablespace name, used_pct; ≥ 90 % → sev 3, ≥ 95 % → sev 4
 *   sessions          session-count      total/active/blocked/max; blocked > 0 → sev 2
 *   blocked_session   blocked-session    one per blocked session (fields.key = sid)
 *   wait_class        wait-class         top 5 (fields.key = class)
 *   redo              redo-status        archive lag, unarchived logs; unarchived > 0 or lag > 900 s → sev 3
 *   backup            backup-status      V$RMAN_BACKUP_JOB_DETAILS last job; status not COMPLETED → outcome failure, sev 3; age_h ≥ 48 → sev 3
 *   dataguard         dataguard-lag      apply/transport lag (fields.key = role); apply_lag_s > 600 → sev 3
 *   invalid_objects   invalid-objects    count
 *   fra               fra-usage          used_pct; ≥ 85 % → sev 3
 *   top_sql           top-sql            fields.key = sql_id, sql_text truncated to 200 chars
 *   listener          listener-status    status != READY → action listener-down, sev 4
 *   failed_logon      logon-failed       category authentication, outcome failure, user / src_ip / fields.return_code (1017…)
 *   alertlog          alertlog-tail      path + last lines (ORA- count); ora_errors > 0 → sev 2
 *   heartbeat         agent-heartbeat    collector liveness (not evaluated by detection)
 *   unified_audit     (delegated)        rows from UNIFIED_AUDIT_TRAIL → oracle-audit.js parseRow()
 *   load_profile, efficiency, latch, wait_classes, wait_events, active_sessions, ash_sql, ash_session, sql_delta,
 *   plan_change, blocking, long_query, temp_undo, memory, limits, redo_rate, archive_dest, asm, tablespace_growth, host,
 *   pack_ash           (delegated)        performance kinds → oracle-perf.js parse() (extra tag "db-perf"; table there)
 * Every event: host (DB host), fields.instance, fields.db_name, fields.key (per-object id or ''), tags ["oracle","db-health"].
 */
const AUDIT = require('./oracle-audit');
const PERF = require('./oracle-perf');

const NAME = 'oracle-health';
const MAX_SQL = 200;
const SEV_FOR_PCT = (p, warn, crit) => (p >= crit ? 4 : p >= warn ? 3 : 0);

function num(v) { const n = typeof v === 'number' ? v : parseFloat(v); return Number.isFinite(n) ? n : null; }
function s(v) { return v === undefined || v === null ? '' : String(v); }
function ts(v, m) {
  if (typeof v === 'number') return v > 1e11 ? v : v * 1000;
  const t = Date.parse(s(v));
  return Number.isFinite(t) ? t : (m && m.rts) || Date.now();
}
function sniff(body, m) {
  const o = m && m.obj;
  return !!(o && typeof o === 'object' && (o.type === 'oracle-health' || (o.kind && o.instance && (o.collector || '').startsWith('sentra-oracle'))));
}

function parse(body, m = {}) {
  let o = m.obj;
  if (!o) { try { o = JSON.parse(body); } catch { return null; } }
  if (!o || typeof o !== 'object' || Array.isArray(o)) return null;
  const kind = s(o.kind).toLowerCase();
  if (!kind) return null;
  if (kind === 'unified_audit' || kind === 'audit_trail') return AUDIT.parseRow(o, m);
  const inst = s(o.instance || o.sid || o.db_name).toUpperCase();
  const f = { instance: inst, db_name: s(o.db_name || inst).toUpperCase(), key: '', kind, collector: s(o.collector) };
  const ev = { ts: ts(o.t || o.ts || o.time, m), host: s(o.host), category: 'database', action: '', outcome: 'success', severity: 0, message: '', fields: f, tags: ['oracle', 'db-health'] };
  const put = (k, v) => { if (v !== undefined && v !== null && v !== '') f[k] = s(v); };
  if (PERF.KINDS.has(kind)) { PERF.parse(kind, o, ev, f, put, inst); return ev; }
  switch (kind) {
    case 'instance': {
      const status = s(o.status).toUpperCase() || 'UNKNOWN';
      ['status', 'database_status', 'open_mode', 'role', 'log_mode', 'version', 'startup_time', 'uptime_s', 'db_unique_name', 'cdb', 'edition', 'platform', 'archiver', 'logins', 'shutdown_pending'].forEach((k) => put(k, o[k]));
      const up = status === 'OPEN' || status === 'MOUNTED' && /STANDBY/i.test(s(o.role));
      ev.action = up ? 'health-sample' : 'instance-down';
      ev.severity = up ? 0 : 4;
      ev.outcome = up ? 'success' : 'failure';
      if (s(o.database_status).toUpperCase() && s(o.database_status).toUpperCase() !== 'ACTIVE') { ev.severity = Math.max(ev.severity, 3); ev.outcome = 'failure'; }
      ev.message = `Oracle ${inst} ${status}${o.open_mode ? ` ${o.open_mode}` : ''}${o.role ? ` (${o.role})` : ''} version ${s(o.version) || '?'} up ${Math.round((num(o.uptime_s) || 0) / 3600)} h`;
      break;
    }
    case 'tablespace': {
      const pct = num(o.used_pct);
      f.key = s(o.name).toUpperCase();
      ['name', 'used_mb', 'max_mb', 'free_mb', 'used_pct', 'autoextend', 'contents', 'status'].forEach((k) => put(k, o[k]));
      ev.action = 'tablespace-usage';
      ev.severity = pct === null ? 0 : SEV_FOR_PCT(pct, num(o.warn_pct) || 90, num(o.crit_pct) || 95);
      if (ev.severity) ev.outcome = 'failure';
      ev.message = `Tablespace ${f.key} on ${inst}: ${pct === null ? '?' : pct.toFixed(1)}% used (${s(o.used_mb) || '?'} / ${s(o.max_mb) || '?'} MB)`;
      break;
    }
    case 'sessions': {
      ['total', 'active', 'inactive', 'blocked', 'max_sessions', 'processes', 'max_processes', 'user_sessions', 'background'].forEach((k) => put(k, o[k]));
      ev.action = 'session-count';
      const blocked = num(o.blocked) || 0;
      const pct = num(o.max_sessions) ? (num(o.total) || 0) / num(o.max_sessions) * 100 : 0;
      ev.severity = blocked > 0 ? 2 : pct >= 90 ? 3 : 0;
      ev.message = `Sessions on ${inst}: ${s(o.total) || 0} total, ${s(o.active) || 0} active, ${blocked} blocked${num(o.max_sessions) ? ` (max ${o.max_sessions})` : ''}`;
      break;
    }
    case 'blocked_session': {
      f.key = s(o.sid);
      ['sid', 'serial', 'blocking_sid', 'blocking_user', 'wait_s', 'event', 'sql_id', 'program', 'machine', 'module', 'status'].forEach((k) => put(k, o[k]));
      ev.user = s(o.user).toLowerCase();
      ev.action = 'blocked-session';
      ev.severity = (num(o.wait_s) || 0) >= 300 ? 3 : 2;
      ev.outcome = 'failure';
      ev.message = `Session ${s(o.sid)} (${s(o.user)}) on ${inst} blocked by ${s(o.blocking_sid)} (${s(o.blocking_user)}) for ${s(o.wait_s) || '?'} s: ${s(o.event)}`;
      break;
    }
    case 'wait_class': {
      f.key = s(o.class || o.name);
      ['class', 'time_waited_s', 'pct', 'rank', 'total_waits', 'avg_wait_ms'].forEach((k) => put(k, o[k]));
      ev.action = 'wait-class';
      ev.message = `Wait class ${f.key} on ${inst}: ${s(o.pct) || '?'}% of wait time (${s(o.time_waited_s) || '?'} s)`;
      break;
    }
    case 'redo': {
      ['log_mode', 'archive_lag_s', 'redo_switches_1h', 'last_archived_seq', 'last_archived_at', 'unarchived', 'current_seq', 'archiver', 'dest_status', 'dest_error'].forEach((k) => put(k, o[k]));
      ev.action = 'redo-status';
      const lag = num(o.archive_lag_s) || 0; const un = num(o.unarchived) || 0;
      // archive_lag_s = seconds since the last archived log: only a problem while logs are waiting (unarchived > 0)
      ev.severity = (un > 0 && lag > 900) || un > 1 || /ERROR/i.test(s(o.dest_status)) || s(o.dest_error) ? 3 : 0;
      if (ev.severity) ev.outcome = 'failure';
      ev.message = `Redo/archive on ${inst}: ${s(o.log_mode) || '?'}, ${un} unarchived, lag ${lag} s, ${s(o.redo_switches_1h) || 0} switches/h`;
      break;
    }
    case 'backup': {
      const status = s(o.status).toUpperCase();
      const age = num(o.age_h);
      ['status', 'input_type', 'start_time', 'end_time', 'age_h', 'output_mb', 'input_mb', 'elapsed_s', 'session_key', 'output_device_type', 'compression_ratio', 'max_age_h'].forEach((k) => put(k, o[k]));
      ev.action = 'backup-status';
      const failed = !!status && status !== 'COMPLETED';
      const old = age !== null && age >= (num(o.max_age_h) || 48);
      const never = status === '' || status === 'NONE';
      ev.outcome = failed || never ? 'failure' : 'success';
      ev.severity = failed ? 3 : never || old ? 3 : 0;
      if (status === 'RUNNING' || status === 'RUNNING WITH WARNINGS') { ev.outcome = 'unknown'; ev.severity = old ? 2 : 0; }
      ev.message = never ? `RMAN on ${inst}: no backup job found` : `RMAN ${s(o.input_type) || 'backup'} on ${inst}: ${status}${age !== null ? `, ${age.toFixed(1)} h ago` : ''}${o.output_mb ? `, ${o.output_mb} MB` : ''}`;
      break;
    }
    case 'dataguard': {
      f.key = s(o.role || 'STANDBY').toUpperCase();
      ['role', 'apply_lag_s', 'transport_lag_s', 'apply_finish_s', 'protection_mode', 'protection_level', 'switchover_status', 'recovery_mode', 'gap_status', 'dest_status'].forEach((k) => put(k, o[k]));
      ev.action = 'dataguard-lag';
      const lag = num(o.apply_lag_s); const tl = num(o.transport_lag_s);
      ev.severity = (lag !== null && lag > (num(o.max_lag_s) || 600)) || (tl !== null && tl > (num(o.max_lag_s) || 600)) || /ERROR|RESOLVABLE GAP|UNRESOLVABLE/i.test(s(o.gap_status) + s(o.dest_status)) ? 3 : 0;
      if (ev.severity) ev.outcome = 'failure';
      ev.message = `Data Guard on ${inst} (${f.key}): apply lag ${lag === null ? '?' : lag} s, transport lag ${tl === null ? '?' : tl} s`;
      break;
    }
    case 'invalid_objects': {
      ['count', 'by_owner'].forEach((k) => put(k, o[k]));
      ev.action = 'invalid-objects';
      ev.severity = (num(o.count) || 0) > (num(o.warn_count) || 50) ? 2 : 0;
      ev.message = `${s(o.count) || 0} invalid objects on ${inst}${o.by_owner ? ` (${o.by_owner})` : ''}`;
      break;
    }
    case 'fra': {
      const pct = num(o.used_pct);
      ['name', 'space_limit_mb', 'space_used_mb', 'reclaimable_mb', 'used_pct', 'files'].forEach((k) => put(k, o[k]));
      ev.action = 'fra-usage';
      ev.severity = pct === null ? 0 : SEV_FOR_PCT(pct, num(o.warn_pct) || 85, num(o.crit_pct) || 95);
      if (ev.severity) ev.outcome = 'failure';
      ev.message = `Fast recovery area on ${inst}: ${pct === null ? '?' : pct.toFixed(1)}% used (${s(o.space_used_mb) || '?'} / ${s(o.space_limit_mb) || '?'} MB, ${s(o.reclaimable_mb) || 0} MB reclaimable)`;
      break;
    }
    case 'top_sql': {
      f.key = s(o.sql_id);
      ['sql_id', 'elapsed_s', 'executions', 'cpu_s', 'buffer_gets', 'disk_reads', 'rows_processed', 'rank', 'module'].forEach((k) => put(k, o[k]));
      f.sql_text = s(o.sql_text).replace(/\s+/g, ' ').slice(0, MAX_SQL);
      ev.user = s(o.user || o.parsing_schema).toLowerCase();
      ev.action = 'top-sql';
      ev.message = `Top SQL ${f.key} on ${inst}: ${s(o.elapsed_s) || '?'} s elapsed, ${s(o.executions) || '?'} executions — ${f.sql_text.slice(0, 80)}`;
      break;
    }
    case 'listener': {
      const status = s(o.status).toUpperCase() || 'UNKNOWN';
      f.key = s(o.listener || 'LISTENER').toUpperCase();
      ['listener', 'status', 'services', 'version', 'start_time', 'uptime', 'output', 'port'].forEach((k) => put(k, o[k]));
      if (f.output) f.output = f.output.slice(0, 1000);
      const ok = /^(READY|UP|OK|RUNNING)$/.test(status) || /COMPLETED SUCCESSFULLY|STATUS READY|READY\b/.test(status); // lsnrctl status output or normalised word
      ev.action = ok ? 'listener-status' : 'listener-down';
      ev.severity = ok ? 0 : 4;
      ev.outcome = ok ? 'success' : 'failure';
      ev.message = `Listener ${f.key} on ${ev.host || inst}: ${status}${o.services ? `, ${o.services} services` : ''}`;
      break;
    }
    case 'failed_logon': {
      ['os_user', 'userhost', 'terminal', 'client_ip', 'return_code', 'program', 'source', 'auth_type', 'count'].forEach((k) => put(k, o[k]));
      ev.ts = ts(o.ts || o.event_time || o.t, m);
      ev.category = 'authentication';
      ev.action = 'logon-failed';
      ev.outcome = 'failure';
      ev.user = s(o.user || o.dbuser).toLowerCase();
      ev.src_ip = s(o.client_ip || (AUDIT.looksLikeIp(s(o.userhost)) ? o.userhost : ''));
      ev.severity = 2;
      f.failure_reason = AUDIT.returnCodeText(o.return_code);
      ev.tags.push('db-audit');
      ev.message = `Oracle logon failed on ${inst}: user ${ev.user || '?'} from ${s(o.userhost) || ev.src_ip || '?'} (${s(o.os_user) || '?'}) ORA-${s(o.return_code) || '?'} ${f.failure_reason}`;
      break;
    }
    case 'alertlog': {
      const lines = Array.isArray(o.tail) ? o.tail : s(o.tail).split('\n').filter(Boolean);
      put('path', o.path);
      f.ora_errors = s(o.ora_errors_5m !== undefined ? o.ora_errors_5m : lines.filter((l) => /ORA-\d{5}/.test(l)).length);
      f.tail = lines.slice(-200).join('\n').slice(0, 40000);   // the platform's hourly V$DIAG_ALERT_EXT read sends up to 200 ORA- lines (DBA error findings)
      ev.action = 'alertlog-tail';
      ev.severity = Number(f.ora_errors) > 0 ? 2 : 0;
      const first = lines.find((l) => /ORA-\d{5}/.test(l));
      ev.message = `Alert log ${s(o.path)} on ${inst}: ${f.ora_errors} ORA- errors in the last interval${first ? ` — ${first.slice(0, 160)}` : ''}`;
      break;
    }
    case 'heartbeat': {
      ['collector', 'version', 'interval_s', 'queries_ok', 'queries_failed', 'spool_files', 'sqlplus', 'perf', 'perf_baseline', 'perf_restart', 'captures', 'capture_errors', 'pack'].forEach((k) => put(k, o[k]));
      ev.action = 'agent-heartbeat';
      ev.category = 'system';
      ev.message = `sentra-oracle-collector heartbeat from ${ev.host || inst} (${s(o.queries_ok) || 0} ok / ${s(o.queries_failed) || 0} failed queries)`;
      if ((num(o.queries_failed) || 0) > 0) { ev.severity = 1; f.last_error = s(o.last_error).slice(0, 500); }
      break;
    }
    default: {
      for (const [k, v] of Object.entries(o)) if (!['kind', 't', 'ts', 'host', 'instance', 'db_name', 'type', 'collector'].includes(k) && v !== null && typeof v !== 'object') put(k, v);
      ev.action = `oracle-${kind.replace(/[^a-z0-9]+/g, '-')}`;
      ev.message = `Oracle ${kind} sample from ${inst}`;
    }
  }
  if (o.event_code !== undefined) ev.event_code = s(o.event_code);
  return ev;
}

module.exports = { name: NAME, sniff, parse };
