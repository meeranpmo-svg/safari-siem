// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const ZYB_ORG = require('../util/brand');
const { guard: guardJob } = require('../util/errors');
/*
 * DBA alert center - thresholds the DBA sets and sees, conditions evaluated from the Oracle health readings the SIEM
 * already holds (oracle-health records from the collector agent and from IT Asset Management's read-only platform pass),
 * notifications straight to the DBA, a daily database digest, and common ORA- error findings from the alert log.
 * Read-only: nothing here touches a database. Every number shown comes from a reading; a reading the collector did not send
 * is "not reported", never assumed healthy.
 *
 *   Thresholds   METRICS (defaults) → policy.metrics[id] {warn, crit, enabled} → overrides by scope, most specific wins:
 *                "INST/TABLESPACE" > "*\/TABLESPACE" > "INST" > global.  Every change carries a reason and is audited.
 *   Conditions   one per (metric, instance@host, key) while it breaches: open → (acknowledged | snoozed) → cleared.
 *                A reading older than the metric's freshness window leaves the condition as it is (stale, shown as such):
 *                "we cannot see it" is the collector-silent metric's job, never a silent clear.
 *   Errors       ORA- lines in the alert-log readings of the last 24 h, de-duplicated by line, classified by ORA_CATALOG
 *                (meaning + what the DBA checks). Unknown ORA- codes are listed as "other", never dropped.
 *   Notify       critical → e-mail at once (one mail per tick for all new problems), re-sent every renotify_h while open
 *                and unacknowledged; warning → the daily digest (or at once, if the DBA prefers); recovery mail when a
 *                critical clears. Maintenance windows per instance stop mail only - conditions are still tracked.
 *   Digest       each working day at digest.at (Riyadh): instance grid, open problems, tablespaces past warning with
 *                days-to-full, backups, Data Guard, error findings, what cleared, what is snoozed.
 *
 *   createDbaAlerts({ ch, state, log, now, calendar(), mail(msg), mailProblems(), portalUrl, table })
 *     → { catalog(), policy(), savePolicy(body, by), notifySettings(), saveNotify(body, by), status(), conditions(f), errors(),
 *         ack(id, by, note), snooze(id, hours, by, reason), unsnooze(id, by), maintenance(inst, hours, by, reason), endMaintenance(inst, by),
 *         evaluate(), tick(), digest(t), sendDigest(by), testMail(by), start(ms), stop() }
 */

const METRICS = [
  { id: 'instance_down', label: 'Instance down', group: 'Availability', kind: 'state', unit: '', crit: 1, help: 'the instance is not OPEN (or MOUNTED as a standby)' },
  { id: 'listener_down', label: 'Listener down', group: 'Availability', kind: 'state', unit: '', crit: 1, help: 'lsnrctl status is not READY' },
  { id: 'collector_silent', label: 'No reading from the database', group: 'Availability', unit: 'min', dir: 'above', warn: 15, crit: 30, help: 'minutes since the last reading - the SIEM cannot see this database' },
  { id: 'ts_used_pct', mailWarn: true, label: 'Tablespace used', group: 'Space', unit: '%', dir: 'above', warn: 87, crit: 95, keyed: true, tsScope: true, fresh: 120, help: 'used % of the maximum size (autoextend counted)' },
  { id: 'ts_days_to_full', label: 'Tablespace days to full', group: 'Space', unit: 'days', dir: 'below', warn: 14, crit: 7, keyed: true, tsScope: true, fresh: 1500, help: 'forecast from the last 30 days of growth' },
  { id: 'temp_pct', sustain: 10, label: 'TEMP used', group: 'Space', unit: '%', dir: 'above', warn: 85, crit: 95, fresh: 60 },
  { id: 'undo_pct', sustain: 10, label: 'UNDO used', group: 'Space', unit: '%', dir: 'above', warn: 85, crit: 95, fresh: 60 },
  { id: 'fra_pct', mailWarn: true, label: 'Recovery area (FRA) used', group: 'Space', unit: '%', dir: 'above', warn: 80, crit: 90, fresh: 120, help: 'archiving stops when it is full' },
  { id: 'asm_used_pct', mailWarn: true, label: 'ASM disk group used', group: 'Space', unit: '%', dir: 'above', warn: 80, crit: 90, keyed: true, fresh: 120, help: 'used % of the disk group (total - free); mirroring headroom is separate' },
  { id: 'asm_free_pct', label: 'ASM disk group free', group: 'Space', unit: '%', dir: 'below', warn: 15, crit: 10, keyed: true, fresh: 120, enabled: false, help: 'off by default - ASM disk group used % above replaces it' },
  { id: 'fs_pct', label: 'Database server file system used', group: 'Space', unit: '%', dir: 'above', warn: 85, crit: 95, keyed: true, fresh: 120 },
  { id: 'sessions_pct', sustain: 10, label: 'Sessions of the limit', group: 'Load', unit: '%', dir: 'above', warn: 85, crit: 95, fresh: 30 },
  { id: 'limit_pct', sustain: 10, label: 'Processes / resource limit', group: 'Load', unit: '%', dir: 'above', warn: 85, crit: 95, keyed: true, fresh: 60 },
  { id: 'blocked_s', sustain: 0, label: 'Session blocked', group: 'Load', unit: 's', dir: 'above', warn: 120, crit: 300, keyed: true, fresh: 15 },
  { id: 'long_query_s', mailWarn: true, sustain: 0, label: 'Long-running query', group: 'Load', unit: 's', dir: 'above', warn: 1800, crit: 3600, keyed: true, fresh: 15, help: 'one call running this long (session, SQL, user named)' },
  { id: 'job_run_min', mailWarn: true, sustain: 0, label: 'Scheduler job running long', group: 'Load', unit: 'min', dir: 'above', warn: 20, crit: 60, keyed: true, fresh: 15, help: 'a DBMS_SCHEDULER / DBMS_JOB job of an application schema still running' },
  { id: 'deadlocks', mailWarn: true, sustain: 0, label: 'Deadlocks', group: 'Load', unit: '', dir: 'above', warn: 1, crit: 5, fresh: 0, help: 'ORA-00060 deadlocks in the alert log in the last hour - the trace file named in the line shows both sessions' },
  { id: 'backup_age_h', label: 'Hours since the last good backup', group: 'Protection', unit: 'h', dir: 'above', warn: 26, crit: 48, fresh: 1500 },
  { id: 'backup_failed', label: 'Last backup failed / none on record', group: 'Protection', kind: 'state', unit: '', crit: 1, fresh: 1500 },
  { id: 'archive_lag_s', sustain: 10, label: 'Archive lag', group: 'Protection', unit: 's', dir: 'above', warn: 900, crit: 1800, fresh: 60 },
  { id: 'archive_dest', label: 'Archive destination error', group: 'Protection', kind: 'state', unit: '', crit: 1, fresh: 60 },
  { id: 'dg_lag_s', sustain: 10, label: 'Data Guard apply / transport lag', group: 'Protection', unit: 's', dir: 'above', warn: 300, crit: 1800, keyed: true, fresh: 60 },
  { id: 'bulk_delete_rows', mailWarn: true, sustain: 0, label: 'Bulk delete', group: 'Changes', unit: 'rows', dir: 'above', warn: 10000, crit: 100000, keyed: true, fresh: 30, help: 'rows one DELETE statement removed since the previous reading (application schemas)' },
  { id: 'table_truncate', mailWarn: true, label: 'Table truncated', group: 'Changes', kind: 'event', unit: '', keyed: true, fresh: 70, help: 'TRUNCATE TABLE by a user other than SYS / SYSDBA / Oracle\'s own (needs the code-change audit policy)' },
  { id: 'code_change', mailWarn: true, label: 'Code changed (package / procedure / function / trigger / type)', group: 'Changes', kind: 'event', unit: '', keyed: true, fresh: 70, help: 'created, altered, recompiled or dropped in an application schema; changes by SYS / SYSDBA / Oracle\'s own users are left out' },
  { id: 'app_disconnected', mailWarn: true, gone: true, label: 'Application disconnected', group: 'Connections', unit: 'sessions', dir: 'above', warn: 3, keyed: true, fresh: 0, help: 'an application (service / machine / program / user) that had at least this many sessions earlier in the day has none now' },
  { id: 'listener_refused', mailWarn: true, gone: true, label: 'Listener refused connections', group: 'Connections', unit: '', dir: 'above', warn: 5, crit: 50, keyed: true, fresh: 70, help: 'connections the listener refused in the last hour (TNS-12514 / 12519 / 12520 ...), per service, client and code' },
  { id: 'rac_node_down', label: 'RAC node down', group: 'Availability', kind: 'state', unit: '', crit: 1, keyed: true, fresh: 30, help: 'a configured RAC instance is not OPEN' },
  { id: 'dr_link', label: 'DR (Data Guard) link failing', group: 'Protection', kind: 'state', unit: '', crit: 1, keyed: true, fresh: 60, help: 'redo transport error, unresolvable gap or redo apply stopped on a standby' },
  { id: 'invalid_objects', label: 'Invalid objects', group: 'Hygiene', unit: '', dir: 'above', warn: 50, crit: 200, fresh: 1500, enabled: false, help: 'off by default: many databases carry a stable set of invalid objects' },
];
const MBY = Object.fromEntries(METRICS.map((m) => [m.id, m]));

// common ORA- errors: [code, level, title, what the DBA checks]  (read-only advice; nothing is run from here)
const ORA_CATALOG = [
  ['ORA-00600', 'crit', 'Internal error', 'Check the trace file named in the alert log and the incident in ADR (adrci show incident); search My Oracle Support with the first argument; raise an SR if it repeats.'],
  ['ORA-07445', 'crit', 'Exception (process crash)', 'Read the incident trace (adrci); note the function in the first argument; check for a matching patch.'],
  ['ORA-01578', 'crit', 'Data block corrupted', 'Identify the file/block (DBA_EXTENTS), run RMAN VALIDATE / DBVERIFY, recover the block from backup (RMAN RECOVER BLOCK).'],
  ['ORA-01110', 'warn', 'Data file named in an error', 'Usually follows another error on that file - read the lines around it.'],
  ['ORA-27072', 'crit', 'File I/O error', 'Storage or file-system problem under a data file: check the OS log, multipath and the storage array.'],
  ['ORA-27037', 'crit', 'Unable to obtain file status', 'A data/control/redo file is missing or unreadable: check the path, permissions and mounts.'],
  ['ORA-01157', 'crit', 'Cannot identify / lock data file', 'A data file is missing or locked: check the file and the storage; restore if lost.'],
  ['ORA-01113', 'crit', 'File needs media recovery', 'Recover the data file (RMAN RECOVER DATAFILE) before it can be opened.'],
  ['ORA-00257', 'crit', 'Archiver stuck', 'Free space in the archive destination / FRA (back up and delete archived logs, or enlarge DB_RECOVERY_FILE_DEST_SIZE).'],
  ['ORA-19809', 'crit', 'Recovery area limit exceeded', 'The FRA is full: back up and delete obsolete files (RMAN DELETE OBSOLETE) or raise its size.'],
  ['ORA-19815', 'warn', 'Recovery area nearly full', 'The FRA crossed its warning level: plan clean-up before archiving stops.'],
  ['ORA-16038', 'crit', 'Log cannot be archived', 'Read the next lines for the reason (usually space in the destination).'],
  ['ORA-16014', 'crit', 'Log not archived - no destination available', 'Every archive destination failed: check destinations and space.'],
  ['ORA-01653', 'crit', 'Unable to extend table', 'The tablespace is full: add or resize a data file / enable autoextend (within storage limits).'],
  ['ORA-01654', 'crit', 'Unable to extend index', 'The tablespace is full: add space to the index tablespace.'],
  ['ORA-01688', 'crit', 'Unable to extend table partition', 'The partition\'s tablespace is full: add space.'],
  ['ORA-01691', 'crit', 'Unable to extend LOB segment', 'The LOB tablespace is full: add space.'],
  ['ORA-01652', 'warn', 'Unable to extend TEMP segment', 'TEMP ran out during a sort / hash: find the SQL (V$TEMPSEG_USAGE), add TEMP space or tune the query.'],
  ['ORA-30036', 'warn', 'Unable to extend UNDO', 'UNDO full: check long transactions; add UNDO space.'],
  ['ORA-01555', 'warn', 'Snapshot too old', 'A query outlived UNDO retention: check UNDO_RETENTION / UNDO size and the long query.'],
  ['ORA-04031', 'crit', 'Shared pool / SGA memory exhausted', 'Check SGA sizing and shared-pool fragmentation (V$SGASTAT); look for literal SQL flooding the pool.'],
  ['ORA-04030', 'warn', 'Process memory (PGA) exhausted', 'Check PGA_AGGREGATE_LIMIT / OS memory; find the session (V$PROCESS).'],
  ['ORA-00020', 'crit', 'Maximum processes reached', 'New connections are refused: find who holds them; raise PROCESSES only with memory to spare.'],
  ['ORA-00018', 'crit', 'Maximum sessions reached', 'New sessions are refused: find leaking connection pools.'],
  ['ORA-00060', 'warn', 'Deadlock detected', 'Read the deadlock graph in the trace file; usually an application locking order to fix.'],
  ['ORA-04021', 'warn', 'Timeout waiting for a lock', 'A DDL or compile waited on a library-cache lock: find the holder.'],
  ['ORA-00470', 'crit', 'LGWR terminated', 'The instance went down with the log writer: read the trace; check redo log storage.'],
  ['ORA-00471', 'crit', 'DBWR terminated', 'The database writer died: read the trace; check data file storage.'],
  ['ORA-00474', 'crit', 'SMON terminated', 'Instance crash: read the trace and the lines before it.'],
  ['ORA-00603', 'warn', 'Server session ended by a fatal error', 'Read the error that follows it.'],
  ['ORA-03113', 'warn', 'End-of-file on communication channel', 'A server process died or the network dropped: check for ORA-00600 / 07445 around the same time.'],
  ['ORA-12514', 'warn', 'Listener does not know the service', 'Service not registered: check SERVICE_NAMES / LOCAL_LISTENER and the listener status.'],
  ['ORA-12541', 'warn', 'No listener', 'The listener is down or on another port.'],
  ['ORA-12170', 'warn', 'Connect timeout', 'Network / firewall between the client and the database.'],
  ['ORA-08103', 'warn', 'Object no longer exists', 'A segment changed under a running query (truncate / move); retry or check corruption if it repeats.'],
  ['ORA-01017', 'info', 'Invalid user name / password', 'Failed logons are tracked by the SOC (SENTRA-ORA-001); listed here for context only.'],
];
const OCAT = Object.fromEntries(ORA_CATALOG.map(([c, l, t, w]) => [c, { code: c, level: l, title: t, what: w }]));
const LEVELS = ['ok', 'info', 'warn', 'crit'];
const RANK = { ok: 0, unknown: 0, info: 1, warn: 2, crit: 3 };
const SCOPE_RE = /^(\*|[A-Z0-9_$#.-]{1,64})(\/[A-Z0-9_$#.-]{1,64})?$/;
const ADDR_RE = /^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$/;
const HM_RE = /^([01]\d|2[0-3]):([0-5]\d)$/;
const NOTIFY_DEFAULTS = { recipients: [], managers: [], warn_mode: 'digest', renotify_h: 4, recovery: true, digest: { enabled: true, at: '07:45' } };

const isObj = (v) => v && typeof v === 'object' && !Array.isArray(v);
const nz = (v) => { if (v === '' || v === null || v === undefined) return null; const n = parseFloat(v); return Number.isFinite(n) ? n : null; };
const bad = (msg, errors) => Object.assign(new Error(msg), { code: 400, errors: errors || [msg] });
const escH = (s) => String(s === undefined || s === null ? '' : s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const fmtVal = (v, unit) => (v === null || v === undefined ? 'not reported' : unit === 's' && v >= 120 ? `${Math.round(v / 60)} min` : unit === 'min' && v >= 120 ? `${Math.round(v / 60)} h` : `${Math.round(v * 10) / 10}${unit === '%' ? ' %' : unit ? ` ${unit}` : ''}`);

/** value of a metric for one latest-reading row ({act, k, f, last_ms}); null = this row is not about the metric */
function valueOf(id, row) {
  const f = row.f || {}; const a = row.act;
  switch (id) {
    case 'ts_used_pct': return a === 'tablespace-usage' && !/^(TEMPORARY|UNDO)$/i.test(f.contents || '') ? nz(f.used_pct) : null;
    case 'ts_days_to_full': return a === 'tablespace-growth' ? nz(f.days_to_full) : null;
    case 'temp_pct': return a === 'temp-undo' ? nz(f.temp_used_pct) : null;
    case 'undo_pct': return a === 'temp-undo' ? nz(f.undo_used_pct) : null;
    case 'fra_pct': return a === 'fra-usage' ? nz(f.used_pct) : null;
    case 'asm_free_pct': return a === 'asm-diskgroup' ? nz(f.free_pct) : null;
    case 'asm_used_pct': { if (a !== 'asm-diskgroup') return null; const u = nz(f.used_pct); if (u !== null) return u; const fr = nz(f.free_pct); return fr === null ? null : Math.round((100 - fr) * 10) / 10; }
    case 'job_run_min': return a === 'sched-job' && nz(f.elapsed_s) !== null ? Math.round(nz(f.elapsed_s) / 6) / 10 : null;
    case 'bulk_delete_rows': return a === 'bulk-delete' ? nz(f.rows_deleted) : null;
    case 'rac_node_down': return a === 'rac-node' ? (/^OPEN$/i.test(f.status || '') ? 0 : 1) : null;
    case 'listener_refused': return a === 'lsnr-conn' && String(f.code) !== '0' && f.code ? nz(f.n) : null;
    case 'dr_link': return a === 'dg-transport' ? ((/ERROR/i.test(f.status || '') || (f.error || '').trim() || /UNRESOLVABLE/i.test(f.gap_status || '') || /^IDLE$/i.test(f.recovery_mode || '')) ? 1 : 0) : null;
    case 'fs_pct': return a === 'db-server-fs' ? nz(f.used_pct) : null;
    case 'sessions_pct': { if (a !== 'session-count') return null; const t = nz(f.total), m = nz(f.max_sessions); return t !== null && m ? Math.round(t / m * 1000) / 10 : null; }
    case 'limit_pct': return a === 'resource-limit' ? nz(f.pct) : null;
    case 'blocked_s': return a === 'blocking-chain' || a === 'blocked-session' ? nz(f.wait_s) : null;
    case 'long_query_s': return a === 'long-query' ? nz(f.elapsed_s) : null;
    case 'backup_age_h': return a === 'backup-status' && /^COMPLETED/i.test(f.status || '') ? nz(f.age_h) : null;
    case 'backup_failed': return a === 'backup-status' ? (/^(COMPLETED|RUNNING)/i.test(f.status || '') ? 0 : 1) : null;
    case 'archive_lag_s': return a === 'redo-status' ? nz(f.archive_lag_s) : null;
    case 'archive_dest': return a === 'redo-status' ? ((/ERROR|BAD/i.test(f.dest_status || '') || (f.dest_error || '').trim()) ? 1 : 0) : a === 'archive-dest' ? (/^(DEFERRED|DISABLED|INACTIVE)$/i.test(String(f.status || '').trim()) ? 0 : /ERROR|BAD/i.test(f.status || '') || (f.error || '').trim() ? 1 : 0) : null;   // a destination a DBA switched off keeps its last error text: not an error
    case 'dg_lag_s': if (a === 'dataguard-lag') return Math.max(nz(f.apply_lag_s) || 0, nz(f.transport_lag_s) || 0) || (nz(f.apply_lag_s) === null && nz(f.transport_lag_s) === null ? null : 0);
      return a === 'dg-lag' && /lag/i.test(row.k || '') ? nz(f.value_s) : null;
    case 'invalid_objects': return a === 'invalid-objects' ? nz(f.count) : null;
    case 'listener_down': return a === 'listener-status' ? 0 : a === 'listener-down' ? 1 : null;
    default: return null;
  }
}
/** the words a DBA needs in the alert (who / which SQL / which job), from the same reading; '' when there is nothing to add */
function detailOf(id, f) {
  switch (id) {
    case 'long_query_s': return [f.user || f.db_user ? 'user ' + (f.user || f.db_user) : '', f.sql_id ? 'SQL ' + f.sql_id : '', f.module || f.program || '', f.event ? 'waiting on ' + f.event : ''].filter(Boolean).join(' · ');
    case 'job_run_min': return [f.owner && f.job_name ? `${f.owner}.${f.job_name}` : '', f.session_id ? 'session ' + f.session_id : '', f.running_instance ? 'instance ' + f.running_instance : ''].filter(Boolean).join(' · ');
    case 'bulk_delete_rows': return [f.table ? 'table ' + f.table : '', f.db_user ? 'by ' + f.db_user : '', f.module || '', f.sql_id ? 'SQL ' + f.sql_id : '', f.executions ? f.executions + ' execution(s)' : ''].filter(Boolean).join(' · ');
    case 'rac_node_down': return [f.instance_name ? 'node ' + f.instance_name : '', f.host_name ? 'on ' + f.host_name : '', f.status || ''].filter(Boolean).join(' · ');
    case 'listener_refused': { const t = require('./connections').tns(f.code); return [`TNS-${f.code} ${t.meaning}`, f.client_host ? 'from ' + f.client_host : '', f.program && f.program !== '?' ? f.program : '', f.service ? 'service ' + f.service : '', t.fix].filter(Boolean).join(' · '); }
    case 'dr_link': return [f.status ? 'transport ' + f.status : '', f.gap_status || '', f.recovery_mode ? 'apply ' + f.recovery_mode : '', f.error || ''].filter(Boolean).join(' · ');
    default: return '';
  }
}
const ACTIONS = ['health-sample', 'instance-down', 'tablespace-usage', 'tablespace-growth', 'temp-undo', 'fra-usage', 'asm-diskgroup', 'db-server-fs', 'session-count', 'resource-limit',
  'blocking-chain', 'blocked-session', 'long-query', 'backup-status', 'redo-status', 'archive-dest', 'dataguard-lag', 'dg-lag', 'invalid-objects', 'listener-status', 'listener-down',
  'sched-job', 'bulk-delete', 'code-change', 'code-change-by', 'rac-node', 'dg-transport', 'app-session', 'lsnr-conn'];

function oraLines(tail) {
  const out = [];
  for (const l of String(tail || '').split('\n')) { const m = l.match(/ORA-\d{5}/g); if (m) out.push({ line: l.trim().slice(0, 300), codes: [...new Set(m)] }); }
  return out;
}

function createDbaAlerts(o = {}) {
  const { state } = o;
  if (!state) throw new Error('the DBA alert center needs the state store');
  const ch = o.ch; const now = o.now || Date.now;
  const log = o.log || { info() {}, warn() {}, error() {} };
  const table = o.table || 'siem.events';
  const cal = typeof o.calendar === 'function' ? o.calendar : () => null;
  const portal = String(o.portalUrl || '').replace(/\/+$/, '');
  const polCol = state.collection('dba_policy');
  const conds = state.collection('dba_conditions');
  const errCol = state.collection('dba_errors');
  const runs = state.collection('dba_digests');
  const auditFn = (e) => { try { if (typeof state.audit === 'function') state.audit(e); } catch (x) { /* never stop alerting for the audit */ } };
  let timer = null; let busy = false; let last = { at: 0, ok: null, error: '', rows: 0, instances: 0 };
  let snapshot = { instances: new Map(), rows: [] };

  // ---------------------------------------------------------------- policy
  function policyDoc() { return polCol.get('policy') || { id: 'policy', metrics: {}, overrides: [], errors: { ignore: [], levels: {} }, version: 0, updated: 0, by: '' }; }
  function policy() {
    const d = policyDoc();
    return { metrics: METRICS.map((m) => Object.assign({ id: m.id, label: m.label, group: m.group, unit: m.unit, dir: m.dir || '', kind: m.kind || 'value', keyed: !!m.keyed, ts_scope: !!m.tsScope, help: m.help || '', mail_warn: !!m.mailWarn,
      default: { warn: m.warn === undefined ? null : m.warn, crit: m.crit === undefined ? null : m.crit, enabled: m.enabled !== false } },
    { warn: m.warn === undefined ? null : m.warn, crit: m.crit === undefined ? null : m.crit, enabled: m.enabled !== false }, d.metrics[m.id] || {})),
    overrides: d.overrides || [], errors: Object.assign({ ignore: [], levels: {} }, d.errors || {}), version: d.version || 0, updated: d.updated || 0, by: d.by || '' };
  }
  function thresholdFor(m, inst, key) {
    const P = policy(); const base = P.metrics.find((x) => x.id === m.id);
    let t = { warn: base.warn, crit: base.crit, enabled: base.enabled, scope: 'global' };
    const scopes = m.tsScope && key ? [`${inst}/${key}`, `*/${key}`, inst] : [inst];
    for (const sc of scopes) {
      const ov = P.overrides.find((x) => x.metric === m.id && x.scope === sc);
      if (ov) { t = { warn: ov.warn === undefined || ov.warn === null ? t.warn : ov.warn, crit: ov.crit === undefined || ov.crit === null ? t.crit : ov.crit, enabled: ov.enabled === undefined ? t.enabled : ov.enabled, scope: sc, reason: ov.reason }; break; }
    }
    return t;
  }
  function savePolicy(b, by) {
    if (!isObj(b)) throw bad('settings must be an object');
    const cur = policyDoc(); const errs = [];
    if (b.base_version !== undefined && b.base_version !== null && Number(b.base_version) !== (cur.version || 0)) throw Object.assign(new Error(`thresholds changed meanwhile (version ${cur.version || 0}) - reload and try again`), { code: 409 });
    const reason = String(b.reason || '').trim();
    if (reason.length < 3) errs.push('say why (reason) - every threshold change is recorded');
    const next = { id: 'policy', metrics: Object.assign({}, cur.metrics), overrides: (cur.overrides || []).slice(), errors: Object.assign({ ignore: [], levels: {} }, cur.errors || {}) };
    const chk = (m, x, name) => {
      const out = {};
      if (x.enabled !== undefined) { if (typeof x.enabled !== 'boolean') errs.push(`${name}.enabled must be true or false`); else out.enabled = x.enabled; }
      if (m.kind === 'state' || m.kind === 'event') return out;   // on / off only
      for (const k of ['warn', 'crit']) if (x[k] !== undefined && x[k] !== null && x[k] !== '') { const v = Number(x[k]); if (!Number.isFinite(v) || v < 0 || v > 1e7) errs.push(`${name}.${k} must be a number ≥ 0`); else out[k] = v; }
      const w = out.warn !== undefined ? out.warn : null, c = out.crit !== undefined ? out.crit : null;
      if (w !== null && c !== null && (m.dir === 'below' ? c > w : c < w)) errs.push(`${name}: critical must be ${m.dir === 'below' ? 'at or below' : 'at or above'} warning`);
      if (m.unit === '%' && ((w !== null && w > 100) || (c !== null && c > 100))) errs.push(`${name}: a percentage is at most 100`);
      return out;
    };
    if (b.metrics !== undefined) {
      if (!isObj(b.metrics)) errs.push('metrics must be an object');
      else for (const [id, x] of Object.entries(b.metrics)) { const m = MBY[id]; if (!m) { errs.push(`unknown metric ${String(id).slice(0, 40)}`); continue; } if (!isObj(x)) { errs.push(`metrics.${id} must be an object`); continue; } next.metrics[id] = Object.assign({}, next.metrics[id] || {}, chk(m, x, `metrics.${id}`)); }
    }
    if (b.overrides !== undefined) {
      if (!Array.isArray(b.overrides) || b.overrides.length > 500) errs.push('overrides: a list of up to 500');
      else next.overrides = b.overrides.map((x, i) => {
        const n = `overrides[${i}]`; if (!isObj(x)) { errs.push(`${n} must be an object`); return null; }
        const m = MBY[x.metric]; if (!m) { errs.push(`${n}: unknown metric`); return null; }
        const scope = String(x.scope || '').trim().toUpperCase();
        if (!SCOPE_RE.test(scope) || scope === '*') { errs.push(`${n}.scope: an instance (ORCLPRD), instance/tablespace (ORCLPRD/USERS) or */tablespace`); return null; }
        if (scope.includes('/') && !m.tsScope) { errs.push(`${n}: ${m.label} is set per instance, not per tablespace`); return null; }
        return Object.assign({ metric: m.id, scope, reason: String(x.reason || reason).trim().slice(0, 200), by: x.by || by || '', at: x.at || now() }, chk(m, x, n));
      }).filter(Boolean);
    }
    if (b.errors !== undefined) {
      const e = b.errors; if (!isObj(e)) errs.push('errors must be an object');
      else {
        if (e.ignore !== undefined) { if (!Array.isArray(e.ignore) || e.ignore.some((c) => !/^ORA-\d{5}$/.test(String(c).toUpperCase()))) errs.push('errors.ignore: a list of ORA-nnnnn codes'); else next.errors.ignore = [...new Set(e.ignore.map((c) => String(c).toUpperCase()))]; }
        if (e.levels !== undefined) { if (!isObj(e.levels) || Object.entries(e.levels).some(([c, l]) => !/^ORA-\d{5}$/.test(c) || !['info', 'warn', 'crit'].includes(l))) errs.push('errors.levels: {"ORA-nnnnn": "info" | "warn" | "crit"}'); else next.errors.levels = e.levels; }
      }
    }
    if (errs.length) throw bad(errs[0], errs);
    next.version = (cur.version || 0) + 1; next.updated = now(); next.by = by || ''; next.reason = reason;
    polCol.put(next);
    log.info('dba thresholds saved', { by: by || '', version: next.version, overrides: next.overrides.length });
    return policy();
  }

  function notifyDoc() { const d = polCol.get('notify'); return Object.assign({}, NOTIFY_DEFAULTS, d || {}, { digest: Object.assign({}, NOTIFY_DEFAULTS.digest, (d && d.digest) || {}) }, { maintenance: (d && d.maintenance) || [] }); }
  function saveNotify(b, by) {
    if (!isObj(b)) throw bad('settings must be an object');
    const cur = notifyDoc(); const errs = []; const n = Object.assign({}, cur);
    if (b.recipients !== undefined) {
      if (!Array.isArray(b.recipients) || b.recipients.length > 30) errs.push('recipients: up to 30 addresses');
      else { n.recipients = [...new Set(b.recipients.map((x) => String(x).trim().toLowerCase()).filter(Boolean))]; n.recipients.filter((a) => !ADDR_RE.test(a)).forEach((a) => errs.push(`"${a.slice(0, 60)}" is not an e-mail address`)); }
    }
    // infrastructure managers: receive the reports IT Asset Management sends for management (Oracle licence compliance), never the alerts
    if (b.managers !== undefined) {
      if (!Array.isArray(b.managers) || b.managers.length > 30) errs.push('managers: up to 30 addresses');
      else { n.managers = [...new Set(b.managers.map((x) => String(x).trim().toLowerCase()).filter(Boolean))]; n.managers.filter((a2) => !ADDR_RE.test(a2)).forEach((a2) => errs.push(`"${a2.slice(0, 60)}" is not an e-mail address`)); }
    }
    if (b.warn_mode !== undefined) { if (!['digest', 'immediate', 'off'].includes(b.warn_mode)) errs.push('warn_mode must be digest, immediate or off'); else n.warn_mode = b.warn_mode; }
    if (b.renotify_h !== undefined) { const v = Number(b.renotify_h); if (!Number.isInteger(v) || v < 0 || v > 72) errs.push('renotify_h must be 0-72 (0 = once)'); else n.renotify_h = v; }
    if (b.recovery !== undefined) { if (typeof b.recovery !== 'boolean') errs.push('recovery must be true or false'); else n.recovery = b.recovery; }
    if (b.digest !== undefined) {
      if (!isObj(b.digest)) errs.push('digest must be an object');
      else { if (b.digest.enabled !== undefined) n.digest.enabled = b.digest.enabled === true; if (b.digest.at !== undefined) { if (!HM_RE.test(String(b.digest.at))) errs.push('digest.at must be HH:MM (Riyadh)'); else n.digest.at = String(b.digest.at); } }
    }
    if (errs.length) throw bad(errs[0], errs);
    polCol.put(Object.assign({ id: 'notify' }, n, { updated: now(), by: by || '' }));
    return notifyDoc();
  }
  function inMaintenance(inst) { return notifyDoc().maintenance.find((m) => m.instance === inst && m.until > now()) || null; }
  function maintenance(inst, hours, by, reason) {
    const i = String(inst || '').trim().toUpperCase(); const h = Number(hours);
    if (!/^[A-Z0-9_$#.-]{1,64}$/.test(i)) throw bad('instance name required');
    if (!(h > 0 && h <= 72)) throw bad('hours must be 1-72');
    if (String(reason || '').trim().length < 3) throw bad('say why (reason)');
    const d = notifyDoc(); const list = d.maintenance.filter((m) => m.instance !== i && m.until > now());
    list.push({ instance: i, from: now(), until: now() + h * 3600000, by: by || '', reason: String(reason).trim().slice(0, 200) });
    polCol.put(Object.assign({ id: 'notify' }, d, { maintenance: list }));
    return list;
  }
  function endMaintenance(inst, by) { const d = notifyDoc(); const i = String(inst || '').toUpperCase(); polCol.put(Object.assign({ id: 'notify' }, d, { maintenance: d.maintenance.filter((m) => m.instance !== i && m.until > now()) })); log.info('dba maintenance ended', { instance: i, by }); return true; }

  // ---------------------------------------------------------------- readings
  async function read() {
    if (!ch || typeof ch.query !== 'function') throw new Error('ClickHouse client not available');
    const p = { a: { type: 'Array(String)', value: ACTIONS } };
    const latest = await ch.query(`/* sentra:dba-latest */ SELECT lower(host) AS h, upper(fields['instance']) AS inst, action AS act, fields['key'] AS k, argMax(fields, ts) AS f,
        max(toUnixTimestamp64Milli(ts)) AS last_ms FROM ${table}
      WHERE ts >= now64(3) - INTERVAL 26 HOUR AND has(tags, 'db-health') AND action IN {a:Array(String)} AND fields['instance'] != ''
      GROUP BY h, inst, act, k LIMIT 50000`, p, { readonly: true, timeout_ms: 30000 });
    const seen = await ch.query(`/* sentra:dba-seen */ SELECT lower(host) AS h, upper(fields['instance']) AS inst, max(toUnixTimestamp64Milli(ts)) AS last_ms, argMax(fields['db_name'], ts) AS db
      FROM ${table} WHERE ts >= now64(3) - INTERVAL 7 DAY AND has(tags, 'db-health') AND fields['instance'] != '' GROUP BY h, inst LIMIT 2000`, {}, { readonly: true, timeout_ms: 30000 });
    const alerts = await ch.query(`/* sentra:dba-alertlog */ SELECT lower(host) AS h, upper(fields['instance']) AS inst, toUnixTimestamp64Milli(ts) AS t, fields['tail'] AS tail, fields['path'] AS path
      FROM ${table} WHERE ts >= now64(3) - INTERVAL 24 HOUR AND has(tags, 'db-health') AND action = 'alertlog-tail' AND fields['ora_errors'] != '0' ORDER BY ts DESC LIMIT 3000`, {}, { readonly: true, timeout_ms: 30000 });
    return { latest: latest || [], seen: seen || [], alerts: alerts || [] };
  }

  function id(metric, inst, host, key) { return `${metric}|${inst}@${host}|${key || ''}`; }
  function hist(c, by, what) { c.history = (c.history || []).concat([{ at: now(), by, what }]).slice(-40); }

  async function evaluate() {
    const R = await read(); const t = now();
    const instances = new Map();
    const hid = state.collection('oracle_hidden');
    const removed = (inst, host, lastMs) => { const h = hid.get(`${String(host || '').toLowerCase()}|${String(inst || '').toUpperCase()}`); return !!h && !(Number(lastMs) > h.at + 60000); };
    R.seen = R.seen.filter((x) => !removed(x.inst, x.h, x.last_ms));
    const keep = new Set(R.seen.map((x) => `${x.inst}@${x.h}`));
    R.latest = R.latest.filter((x) => keep.has(`${x.inst}@${x.h}`));
    R.alerts = R.alerts.filter((x) => keep.has(`${x.inst}@${x.h}`));
    for (const s of R.seen) instances.set(`${s.inst}@${s.h}`, { instance: s.inst, host: s.h, db_name: s.db || s.inst, last_ms: Number(s.last_ms) || 0, values: {} });
    const found = new Map();   // condition id → {metric, inst, host, key, level, value, threshold, stale}
    const fresh = new Set();
    const consider = (m, inst, host, key, value, ts, detail) => {
      const th = thresholdFor(m, inst, key); if (!th.enabled) return;
      const stale = m.fresh && t - ts > m.fresh * 60000;
      const cid = id(m.id, inst, host, key);
      if (!stale) fresh.add(cid);
      let level = 'ok', limit = null;
      if (m.kind === 'state') { if (value >= 1) { level = 'crit'; limit = 1; } }
      else if (m.kind === 'event') { if (value >= 1) { level = 'warn'; limit = null; } }
      else if (m.dir === 'below') { if (th.crit !== null && value <= th.crit) { level = 'crit'; limit = th.crit; } else if (th.warn !== null && value <= th.warn) { level = 'warn'; limit = th.warn; } }
      else if (th.crit !== null && value >= th.crit) { level = 'crit'; limit = th.crit; } else if (th.warn !== null && value >= th.warn) { level = 'warn'; limit = th.warn; }
      if (level !== 'ok' && !stale) found.set(cid, { metric: m.id, instance: inst, host, key: key || '', level, value, threshold: limit, scope: th.scope, reading_ms: ts, detail: detail || '' });
    };
    // instance up / down: the newer of health-sample and instance-down decides
    const updown = new Map(), changes = [], ahead = [], appRows = [];   // ahead: space readings for the before-the-weekend list
    for (const r of R.latest) {
      const ik = `${r.inst}@${r.h}`; const ts = Number(r.last_ms) || 0;
      if (!instances.has(ik)) instances.set(ik, { instance: r.inst, host: r.h, db_name: (r.f || {}).db_name || r.inst, last_ms: ts, values: {} });
      const I = instances.get(ik);
      if (r.act === 'health-sample' || r.act === 'instance-down') { const cur = updown.get(ik); if (!cur || ts > cur.ts) updown.set(ik, { ts, down: r.act === 'instance-down', f: r.f || {} }); continue; }
      if (r.act === 'code-change' || r.act === 'code-change-by') { changes.push(r); continue; }   // judged together below (who did it)
      if (r.act === 'app-session') { appRows.push(r); continue; }   // compared across passes below
      if (r.act === 'tablespace-growth' || r.act === 'fra-usage' || r.act === 'asm-diskgroup') ahead.push({ inst: r.inst, host: r.h, act: r.act, key: r.k || '', f: r.f || {} });
      for (const m of METRICS) {
        if (m.kind === 'state' && m.id === 'instance_down') continue;
        const v = valueOf(m.id, r); if (v === null) continue;
        consider(m, r.inst, r.h, m.keyed || m.id === 'listener_down' ? r.k : '', v, ts, detailOf(m.id, r.f || {}));
        const slot = I.values[m.id];
        if (!slot || (m.dir === 'below' ? v < slot.value : v > slot.value)) I.values[m.id] = { value: v, key: r.k || '', ts };
      }
    }
    for (const [ik, u] of updown) { const I = instances.get(ik); I.status = u.down ? 'DOWN' : (u.f.status || 'OPEN'); I.role = u.f.role || ''; I.version = u.f.version || ''; consider(MBY.instance_down, I.instance, I.host, '', u.down ? 1 : 0, u.ts); }
    for (const I of instances.values()) {
      const mins = (t - I.last_ms) / 60000; I.silent_min = Math.round(mins);
      consider(MBY.collector_silent, I.instance, I.host, '', mins, t);
    }
    // code changes and truncates: DBA_OBJECTS says THAT it changed, the unified audit trail says WHO. Changes made by SYS, AS SYSDBA
    // or Oracle's own users are left out (as agreed with the DBA); a change nobody is audited for is still raised, saying so.
    const byObj = new Map(), objKey = (inst, h, o, n) => `${inst}@${h}|${String(o || '').toUpperCase()}.${String(n || '').toUpperCase()}`;
    for (const r of changes.filter((x) => x.act === 'code-change-by')) { const f = r.f || {}, k = objKey(r.inst, r.h, f.owner, f.name); if (!byObj.has(k)) byObj.set(k, []); byObj.get(k).push(Object.assign({ ts: Number(r.last_ms) || 0 }, f)); }
    const whoTxt = (w) => `${w.user || '?'}${w.os_user ? ' (' + w.os_user + (w.client_host ? '@' + w.client_host : '') + ')' : ''}${w.ok === 'N' ? ' - failed' : ''}`;
    const matched = new Set();
    for (const r of changes.filter((x) => x.act === 'code-change')) {
      const f = r.f || {}, k = objKey(r.inst, r.h, f.owner, f.name), who = byObj.get(k) || []; matched.add(k);
      const people = who.filter((w) => w.excluded !== 'Y' && !/^TRUNCATE/i.test(w.action || ''));
      if (who.length && !people.length) continue;   // only SYS / SYSDBA / Oracle's own users touched it
      consider(MBY.code_change, r.inst, r.h, r.k, 1, Number(r.last_ms) || 0, `${f.type || 'object'} ${f.created === 'Y' ? 'created' : 'changed'} at ${f.ddl_time || '?'}${f.status === 'INVALID' ? ' - now INVALID' : ''} · by ${people.length ? people.map(whoTxt).join(', ') : 'not recorded (no audit policy - install/oracle-code-change-audit.sql)'}`);
    }
    for (const [k, list] of byObj) for (const w of list) {
      if (w.excluded === 'Y') continue;
      const [ih] = k.split('|'), inst = ih.split('@')[0], host = ih.slice(inst.length + 1), key = `${String(w.owner || '').toUpperCase()}.${String(w.name || '').toUpperCase()}`;
      if (/^TRUNCATE/i.test(w.action || '')) consider(MBY.table_truncate, inst, host, key, 1, w.ts, `TRUNCATE TABLE at ${w.at || '?'} by ${whoTxt(w)}`);
      else if (/^DROP/i.test(w.action || '') && !matched.has(k)) consider(MBY.code_change, inst, host, `${key} (${String(w.action).replace(/^DROP\s+/i, '')})`, 1, w.ts, `${w.action} at ${w.at || '?'} by ${whoTxt(w)}`);
    }
    // applications that dropped off: connected (with enough sessions) earlier in the day, absent from the latest pass
    const passOf = new Map();
    for (const r of appRows) { const ik = `${r.inst}@${r.h}`; passOf.set(ik, Math.max(passOf.get(ik) || 0, Number(r.last_ms) || 0)); }
    for (const r of appRows) {
      const ik = `${r.inst}@${r.h}`, ps = passOf.get(ik), lm = Number(r.last_ms) || 0, f = r.f || {};
      if (lm >= ps - 10 * 60000 || t - ps > 30 * 60000) continue;   // still connected, or this database has no fresh pass (collector_silent says so)
      consider(MBY.app_disconnected, r.inst, r.h, r.k, nz(f.sessions) || 0, ps, `${f.program || '?'} on ${f.machine || '?'} as ${f.db_user || '?'} (service ${f.service || '?'}) had ${nz(f.sessions) || 0} session(s) at ${new Date(lm).toISOString().slice(11, 16)} UTC, none now`);
    }
    // deadlocks: ORA-00060 lines in the alert log in the last hour (each line once)
    const dl = new Map();
    for (const a of R.alerts) { if (t - Number(a.t) > 3600000) continue; for (const x of oraLines(a.tail)) if (x.codes.includes('ORA-00060')) { const ik = `${a.inst}@${a.h}`; if (!dl.has(ik)) dl.set(ik, new Set()); dl.get(ik).add(x.line); } }
    for (const I of instances.values()) { const n = (dl.get(`${I.instance}@${I.host}`) || new Set()).size; I.values.deadlocks = { value: n, key: '', ts: t }; consider(MBY.deadlocks, I.instance, I.host, '', n, t, n ? [...dl.get(`${I.instance}@${I.host}`)][0].slice(0, 200) : ''); }

    // ORA- error findings (24 h, de-duplicated by line)
    const P = policy(); const errMap = new Map(); const seenLine = new Set();
    for (const a of R.alerts) {
      for (const x of oraLines(a.tail)) {
        const lk = `${a.inst}@${a.h}|${x.line}`; if (seenLine.has(lk)) continue; seenLine.add(lk);
        for (const code of x.codes) {
          if (P.errors.ignore.includes(code)) continue;
          const k = `${a.inst}@${a.h}|${code}`; const cat = OCAT[code];
          const e = errMap.get(k) || { instance: a.inst, host: a.h, code, title: cat ? cat.title : 'Other ORA- error', what: cat ? cat.what : 'Look up the code and read the lines around it in the alert log.', level: P.errors.levels[code] || (cat ? cat.level : 'warn'), known: !!cat, count: 0, first_ms: Number(a.t), last_ms: Number(a.t), samples: [] };
          e.count++; e.first_ms = Math.min(e.first_ms, Number(a.t)); e.last_ms = Math.max(e.last_ms, Number(a.t)); if (e.samples.length < 5) e.samples.push(x.line);
          errMap.set(k, e);
        }
      }
    }
    const errs = [...errMap.values()].sort((x, y) => RANK[y.level] - RANK[x.level] || y.count - x.count);
    errCol.put({ id: 'latest', at: t, items: errs.slice(0, 500) });
    for (const e of errs) if (e.level !== 'info') found.set(id(`ora:${e.code}`, e.instance, e.host, ''), { metric: `ora:${e.code}`, instance: e.instance, host: e.host, key: '', level: e.level, value: e.count, threshold: null, scope: 'error', reading_ms: e.last_ms, title: e.title });

    // reconcile conditions
    const opened = [], escalated = [], cleared = [];
    for (const [cid, x] of found) {
      const c = conds.get(cid);
      if (!c || c.status === 'cleared') {
        const nc = { id: cid, metric: x.metric, instance: x.instance, host: x.host, key: x.key, level: x.level, value: x.value, threshold: x.threshold, scope: x.scope, title: x.title || '', detail: x.detail || '', status: 'open', since: t, last_eval: t, reading_ms: x.reading_ms, notified: null, history: [] };
        hist(nc, 'system', `${x.level === 'crit' ? 'critical' : x.level === 'warn' ? 'warning' : x.level}: ${x.metric} ${fmtVal(x.value, (MBY[x.metric] || {}).unit)}${x.threshold !== null ? ` (threshold ${x.threshold})` : ''}`);
        conds.put(nc); opened.push(nc);
      } else {
        const worse = RANK[x.level] > RANK[c.level];
        Object.assign(c, { value: x.value, threshold: x.threshold, scope: x.scope, last_eval: t, reading_ms: x.reading_ms, detail: x.detail || c.detail || '' });
        if (x.level !== c.level) { hist(c, 'system', `${worse ? 'worse' : 'better'}: ${c.level} → ${x.level}`); c.level = x.level; if (worse) escalated.push(c); }
        conds.put(c);
      }
    }
    for (const c of conds.all((y) => y.status !== 'cleared')) {
      if (found.has(c.id)) continue;
      if (removed(c.instance, c.host, 0)) { c.status = 'cleared'; c.cleared = t; c.stale = false; hist(c, 'system', 'instance removed from the database pages'); conds.put(c); continue; }   // no recovery mail: it did not recover
      const isErr = c.metric.startsWith('ora:') || (MBY[c.metric] || {}).kind === 'event' || !!(MBY[c.metric] || {}).gone;   // gone: no longer seen = over (an application back, refusals stopped)   // an event (code change, truncate) is not "fixed" - it ages out of its window
      if (!isErr && !fresh.has(c.id) && c.metric !== 'collector_silent' && c.metric !== 'instance_down') { if (!c.stale) { c.stale = true; hist(c, 'system', 'no fresh reading - kept open until one shows it is fixed'); conds.put(c); } continue; }
      c.status = 'cleared'; c.cleared = t; c.stale = false; hist(c, 'system', c.metric.startsWith('ora:') ? 'error not seen in the alert log for 24 h' : (MBY[c.metric] || {}).gone ? 'no longer seen - over' : isErr ? 'event older than its window - kept in the history' : 'back within the threshold'); conds.put(c); cleared.push(c);
    }
    // keep 30 days of cleared conditions
    for (const c of conds.all((y) => y.status === 'cleared' && y.cleared < t - 30 * 86400000)) conds.remove(c.id);
    snapshot = { instances, at: t, ahead };
    last = { at: t, ok: true, error: '', rows: R.latest.length, instances: instances.size };
    return { opened, escalated, cleared, instances: instances.size, errors: errs.length };
  }

  // ---------------------------------------------------------------- notifications
  const label = (c) => (c.metric.startsWith('ora:') ? `${c.metric.slice(4)} ${c.title || ''}`.trim() : (MBY[c.metric] || {}).label || c.metric);
  const onOff = (c) => { const k = (MBY[c.metric] || {}).kind; return k === 'state' || k === 'event'; };
  const line = (c) => `${c.instance}${c.key ? ` · ${c.key}` : ''} - ${label(c)}${onOff(c) ? '' : `: ${c.metric.startsWith('ora:') ? `${c.value} time(s) in 24 h` : fmtVal(c.value, (MBY[c.metric] || {}).unit)}`}${!onOff(c) && c.threshold !== null && c.threshold !== undefined ? ` (threshold ${c.threshold}${c.scope && c.scope !== 'global' ? `, ${c.scope}` : ''})` : ''}${c.detail ? ` - ${c.detail}` : ''}`;
  function link(p) { return portal ? `${portal}/${p}` : ''; }
  async function send(subject, text, html, withManagers) {
    const N = notifyDoc();
    if (!N.recipients.length) throw Object.assign(new Error('no DBA recipients set (Database dashboard → Notifications)'), { transient: false, code: 400 });
    if (typeof o.mail !== 'function') throw Object.assign(new Error('e-mail is not available in this engine'), { transient: false });
    const to = withManagers ? [...new Set(N.recipients.concat(N.managers || []))] : N.recipients;
    return o.mail({ to, subject, text, html });
  }
  function mailBody(title, items, foot) {
    const L = items.map(line); const u = link('db-dashboard.html');
    const text = [title, '', ...L.map((x) => `- ${x}`), '', foot || '', u ? `Open the database dashboard: ${u}` : '', '', (ZYB_ORG.short + ' SIEM · DBA alerts. Acknowledge or snooze on the dashboard to stop reminders.')].filter((x) => x !== null).join('\n');
    const html = `<div style="font-family:Segoe UI,Arial,sans-serif;font-size:14px;color:#111"><p><b>${escH(title)}</b></p><ul>${L.map((x, i) => `<li style="color:${items[i].level === 'crit' ? '#b42318' : '#9a6700'}">${escH(x)}</li>`).join('')}</ul>${foot ? `<p>${escH(foot)}</p>` : ''}${u ? `<p><a href="${escH(u)}">Open the database dashboard</a></p>` : ''}<p style="color:#666;font-size:12px">${ZYB_ORG.short} SIEM · DBA alerts. Acknowledge or snooze on the dashboard to stop reminders.</p></div>`;
    return { text, html };
  }
  async function notify(ev) {
    const N = notifyDoc(); const t = now(); const out = { sent: 0, held: 0 };
    if (!N.recipients.length) return out;
    const quiet = (c) => (c.snooze && c.snooze.until > t) || inMaintenance(c.instance);
    // warnings go to the digest unless the DBA chose 'immediate' - or the metric is one the DBA asked to hear about at once (mailWarn)
    const want = (c) => c.level === 'crit' || (c.level === 'warn' && (N.warn_mode === 'immediate' || ((MBY[c.metric] || {}).mailWarn && N.warn_mode !== 'off')));
    // a breach must last the metric's sustain minutes before it is mailed (one spike is not a page); errors and state problems at once
    const sustained = (c) => t - c.since >= (((MBY[c.metric] || {}).sustain) || 0) * 60000;
    const pending = conds.all((c) => c.status === 'open' && !c.notified && want(c) && sustained(c) && !ev.opened.concat(ev.escalated).some((x) => x.id === c.id));
    const fresh = ev.opened.concat(ev.escalated).filter((c) => want(c) && sustained(c)).concat(pending);
    const due = conds.all((c) => c.status === 'open' && c.level === 'crit' && !c.ack && N.renotify_h > 0 && c.notified && t - c.notified.at >= N.renotify_h * 3600000 && !fresh.some((f) => f.id === c.id));
    const items = fresh.concat(due).filter((c) => { if (quiet(c)) { out.held++; return false; } return true; });
    if (items.length) {
      const crit = items.filter((c) => c.level === 'crit').length;
      const insts = [...new Set(items.map((c) => c.instance))];
      const subj = `[DB]${crit ? '[CRITICAL]' : '[WARNING]'} ${items.length} problem(s) on ${insts.slice(0, 3).join(', ')}${insts.length > 3 ? ` +${insts.length - 3}` : ''}`;
      const { text, html } = mailBody(due.length && !fresh.length ? 'Still open and not acknowledged:' : 'New database problem(s):', items, due.length && fresh.length ? `${due.length} of them were reported before and are still open.` : '');
      try {
        await send(subj, text, html);
        for (const c of items) { const x = conds.get(c.id); if (!x) continue; x.notified = { at: t, level: x.level, count: ((x.notified && x.notified.count) || 0) + 1 }; hist(x, 'system', `e-mailed to the DBA (${x.notified.count})`); conds.put(x); }
        out.sent = items.length;
        auditFn({ at: t, user: 'system:dba-alerts', action: 'dba.notify', target: insts.join(','), detail: { problems: items.length, critical: crit } });
      } catch (e) { last.mail_error = `${e.stage ? e.stage + ': ' : ''}${String(e.message).slice(0, 200)}`; log.warn('dba alert mail failed', { stage: e.stage || '' }); }
    }
    if (N.recovery) {
      const rec = ev.cleared.filter((c) => c.notified && c.level === 'crit' && !inMaintenance(c.instance));
      if (rec.length) { const { text, html } = mailBody('Recovered:', rec, ''); try { await send(`[DB][RECOVERED] ${rec.length} problem(s) cleared`, text, html); } catch (e) { last.mail_error = String(e.message).slice(0, 200); } }
    }
    return out;
  }

  // ---------------------------------------------------------------- digest
  function workingDay(t) { const c = cal(); if (!c) return true; const p = c.parts(t); const w = c.window(); return w.daySet.has(p.dow) && !w.holSet.has(p.dn); }
  function local(t) { const off = ((cal() && cal().config && cal().config.utc_offset_min) || 180) * 60000; const d = new Date(t + off); return { date: d.toISOString().slice(0, 10), min: d.getUTCHours() * 60 + d.getUTCMinutes(), str: d.toISOString().slice(0, 16).replace('T', ' ') }; }
  // Thursday (the last working day before the weekend - the calendar decides, Sun-Thu by default): what will need a DBA before
  // the next working day - tablespaces forecast to fill, FRA / ASM close to their thresholds, warnings nobody has acknowledged
  function beforeWeekend(t) {
    if (!workingDay(t) || workingDay(t + 86400000)) return null;
    let n = 1; while (n < 10 && !workingDay(t + n * 86400000)) n++;
    const next = local(t + n * 86400000).date, horizon = n + 1, items = [];
    const thr = (id) => policy().metrics.find((m) => m.id === id) || {};
    for (const a of (snapshot.ahead || [])) {
      if (a.act === 'tablespace-growth') { const d = nz(a.f.days_to_full); if (d !== null && d <= horizon) items.push({ level: d <= n ? 'crit' : 'warn', what: `${a.inst} · ${a.key} tablespace forecast full in ${Math.round(d * 10) / 10} day(s)`, act: 'Add a data file or extend it before you leave.' }); }
      if (a.act === 'fra-usage') { const u = nz(a.f.used_pct), w = thr('fra_pct').warn; if (u !== null && w !== null && u >= w - 10) items.push({ level: u >= w ? 'warn' : 'info', what: `${a.inst} recovery area (FRA) ${u} % used`, act: 'Archive logs keep arriving over the weekend: back them up / delete obsolete ones (RMAN), or grow db_recovery_file_dest_size.' }); }
      if (a.act === 'asm-diskgroup') { const u = nz(a.f.used_pct) !== null ? nz(a.f.used_pct) : nz(a.f.free_pct) !== null ? 100 - nz(a.f.free_pct) : null, w = thr('asm_used_pct').warn; if (u !== null && w !== null && u >= w - 5) items.push({ level: u >= w ? 'warn' : 'info', what: `${a.inst} · ASM ${a.key} ${Math.round(u * 10) / 10} % used`, act: 'Add disks or free space before the weekend.' }); }
    }
    for (const c of conds.all((x) => x.status === 'open' && !x.ack && !(x.snooze && x.snooze.until > t))) items.push({ level: c.level, what: line(c), act: 'Open and not acknowledged - decide before the weekend who owns it.' });
    const R2 = { crit: 0, warn: 1, info: 2 };
    items.sort((x, y) => (R2[x.level] ?? 3) - (R2[y.level] ?? 3));
    return { next, days: n, items };
  }
  function digest(t) {
    t = t || now();
    const BW = beforeWeekend(t);
    const open = conds.all((c) => c.status === 'open').sort((a, b) => RANK[b.level] - RANK[a.level] || a.instance.localeCompare(b.instance));
    const cleared = conds.all((c) => c.status === 'cleared' && c.cleared > t - 86400000);
    const E = (errCol.get('latest') || { items: [] }).items;
    const S = status();
    const th = 'style="text-align:left;padding:4px 8px;border-bottom:1px solid #ccc;background:#f4f6f8"', td = 'style="padding:4px 8px;border-bottom:1px solid #eee"';
    const tb = (cols, rows) => (rows.length ? `<table style="border-collapse:collapse;font-size:13px;margin:4px 0 12px">${'<tr>' + cols.map((c) => `<th ${th}>${escH(c)}</th>`).join('') + '</tr>'}${rows.map((r) => `<tr>${r.map((c) => `<td ${td}>${escH(c)}</td>`).join('')}</tr>`).join('')}</table>` : '<p style="color:#666">None.</p>');
    const crit = open.filter((c) => c.level === 'crit').length, warn = open.filter((c) => c.level === 'warn').length;
    const subject = `Database digest ${local(t).date}: ${crit} critical, ${warn} warning across ${S.instances.length} database(s)`;
    const insRows = S.instances.map((i) => [i.instance, i.host, i.status || 'not reported', i.level === 'crit' ? 'CRITICAL' : i.level === 'warn' ? 'warning' : i.level === 'unknown' ? 'no reading' : 'ok',
      i.max_ts ? `${i.max_ts.key} ${i.max_ts.value} %` : '–', i.fra_pct !== null ? `${i.fra_pct} %` : '–', i.backup_age_h !== null ? `${Math.round(i.backup_age_h)} h` : '–', i.dg_lag_s !== null ? fmtVal(i.dg_lag_s, 's') : '–', i.maintenance ? 'maintenance' : '']);
    const html = `<div style="font-family:Segoe UI,Arial,sans-serif;font-size:14px;color:#111"><h2 style="margin:0 0 4px">Database digest · ${escH(local(t).date)}</h2><p style="color:#555;margin:0 0 12px">${crit} critical · ${warn} warning · ${cleared.length} cleared in 24 h · ${E.length} error finding(s)</p>`
      + (BW ? `<h3 style="margin:12px 0 4px;color:#9a3412">Before the weekend - next working day ${escH(BW.next)}</h3>` + (BW.items.length ? tb(['Level', 'What', 'Do before you leave'], BW.items.map((x) => [x.level === 'crit' ? 'CRITICAL' : x.level === 'warn' ? 'warning' : 'watch', x.what, x.act])) : '<p>Nothing forecast to need a DBA before the next working day.</p>') : '')
      + '<h3 style="margin:12px 0 4px">Databases</h3>' + tb(['Instance', 'Host', 'Status', 'Health', 'Fullest tablespace', 'FRA', 'Last backup', 'DG lag', ''], insRows)
      + '<h3 style="margin:12px 0 4px">Open problems</h3>' + tb(['Level', 'Problem', 'Since', 'Acknowledged / snoozed'], open.map((c) => [c.level === 'crit' ? 'CRITICAL' : 'warning', line(c), local(c.since).str, c.ack ? `ack ${c.ack.by}` : c.snooze && c.snooze.until > t ? `snoozed by ${c.snooze.by}` : '']))
      + '<h3 style="margin:12px 0 4px">Alert-log errors (24 h)</h3>' + tb(['Instance', 'Error', 'Count', 'What to check'], E.slice(0, 25).map((e) => [e.instance, `${e.code} ${e.title}`, String(e.count), e.what]))
      + '<h3 style="margin:12px 0 4px">Cleared in the last 24 h</h3>' + tb(['Problem', 'Cleared'], cleared.slice(0, 30).map((c) => [line(c), local(c.cleared).str]))
      + `${link('db-dashboard.html') ? `<p><a href="${escH(link('db-dashboard.html'))}">Open the database dashboard</a></p>` : ''}<p style="color:#666;font-size:12px">${ZYB_ORG.short} SIEM · read-only monitoring; nothing was changed on any database.</p></div>`;
    const text = [subject, '', ...S.instances.map((r) => `${r.instance}@${r.host}: ${r.status || 'not reported'} - ${r.level}`), '', 'Open problems:', ...(open.length ? open.map((c) => `- [${c.level}] ${line(c)}`) : ['- none']),
      '', 'Alert-log errors (24 h):', ...(E.length ? E.slice(0, 15).map((e) => `- ${e.instance} ${e.code} ${e.title} x${e.count}`) : ['- none']),
      ...(BW ? ['', `Before the weekend (next working day ${BW.next}):`, ...(BW.items.length ? BW.items.map((x) => `- [${x.level}] ${x.what} - ${x.act}`) : ['- nothing forecast'])] : [])].join('\n');
    return { id: local(t).date, at: t, subject: BW ? subject + ' · before the weekend' : subject, text, html, before_weekend: BW, counts: { critical: crit, warning: warn, cleared: cleared.length, errors: E.length, instances: S.instances.length } };
  }
  async function digestDue() {
    const N = notifyDoc(); if (!N.digest.enabled || !N.recipients.length) return null;
    const t = now(); const l = local(t); const [h, m] = N.digest.at.split(':').map(Number);
    if (!workingDay(t) || l.min < h * 60 + m || l.min > h * 60 + m + 360 || runs.get(l.date)) return null;
    const d = digest(t);
    try { await send(d.subject, d.text, d.html); d.sent = { status: 'ok', at: t }; } catch (e) { d.sent = { status: 'failed', at: t, error: String(e.message).slice(0, 200) }; }
    runs.put(d); return d.sent;
  }
  async function sendDigest(by) { const d = digest(now()); d.manual = by; try { await send(d.subject, d.text, d.html); d.sent = { status: 'ok', at: now(), by }; } catch (e) { d.sent = { status: 'failed', at: now(), error: String(e.message).slice(0, 200), by }; } runs.put(d); return d; }
  // the morning health check report, built by IT Asset Management (engine/db-morning.js) from its own read-only checks; sent to
  // the same DBA recipients. The subject always starts with [DB] and the size is capped.
  async function mailReport(r) {
    const subject = '[DB] ' + String(r.subject || 'Morning health check').replace(/^\[DB\]\s*/, '').replace(/[\r\n]+/g, ' ').slice(0, 200);
    const text = String(r.text || '').slice(0, 100000), html = String(r.html || '').slice(0, 300000);
    const managers = r.audience === 'dba+managers';   // management reports (Oracle licence compliance) also go to the infrastructure managers
    await send(subject, text, html || `<pre>${escH(text)}</pre>`, managers);
    const N = notifyDoc();
    return { ok: true, recipients: N.recipients.length + (managers ? (N.managers || []).filter((m) => !N.recipients.includes(m)).length : 0), managers: managers ? (N.managers || []).length : 0 };
  }
  async function testMail(by) { await send(('[DB] Test from the ' + ZYB_ORG.short + ' SIEM'), `This is a test of DBA alert e-mail, sent by ${by}.`, `<p>This is a test of DBA alert e-mail, sent by ${escH(by)}.</p>`); return { ok: true, recipients: notifyDoc().recipients.length }; }

  async function tick() {
    if (busy) return { busy: true };
    busy = true;
    try { const ev = await evaluate(); const n = await notify(ev); const d = await digestDue(); return Object.assign({}, ev, { notified: n, digest: d }); }
    catch (e) { last = Object.assign({}, last, { at: now(), ok: false, error: String(e.message).slice(0, 200) }); log.warn('dba alert evaluation failed', { err: e.message }); return { error: e.message }; }
    finally { busy = false; }
  }

  // ---------------------------------------------------------------- read side + actions
  function status() {
    const t = now(); const open = conds.all((c) => c.status === 'open');
    const list = [...(snapshot.instances || new Map()).values()].map((I) => {
      const mine = open.filter((c) => c.instance === I.instance && c.host === I.host);
      const v = (k) => (I.values[k] ? I.values[k].value : null);
      const mx = I.values.ts_used_pct;
      const lvl = mine.some((c) => c.level === 'crit') ? 'crit' : mine.some((c) => c.level === 'warn') ? 'warn' : t - I.last_ms > 30 * 60000 ? 'unknown' : 'ok';
      return { instance: I.instance, host: I.host, db_name: I.db_name, status: I.status || '', role: I.role || '', version: I.version || '', last_ms: I.last_ms, silent_min: I.silent_min, level: lvl,
        open: { crit: mine.filter((c) => c.level === 'crit').length, warn: mine.filter((c) => c.level === 'warn').length },
        max_ts: mx ? { key: mx.key, value: Math.round(mx.value * 10) / 10 } : null, min_days_to_full: v('ts_days_to_full'), fra_pct: v('fra_pct'), temp_pct: v('temp_pct'), undo_pct: v('undo_pct'),
        sessions_pct: v('sessions_pct'), backup_age_h: v('backup_age_h'), dg_lag_s: v('dg_lag_s'), maintenance: inMaintenance(I.instance) };
    }).sort((a, b) => RANK[b.level] - RANK[a.level] || a.instance.localeCompare(b.instance));
    let mail = [];
    try { mail = typeof o.mailProblems === 'function' ? o.mailProblems() : (typeof o.mail === 'function' ? [] : ['e-mail not available']); } catch (e) { mail = [e.message]; }
    const N = notifyDoc();
    if (!N.recipients.length) mail = mail.concat(['no DBA recipients set']);
    return { generated_at: t, last_eval: last, instances: list, open: { crit: open.filter((c) => c.level === 'crit').length, warn: open.filter((c) => c.level === 'warn').length, acknowledged: open.filter((c) => c.ack).length, snoozed: open.filter((c) => c.snooze && c.snooze.until > t).length },
      errors: ((errCol.get('latest') || {}).items || []).length, mail: { ok: !mail.length, problems: mail }, digest: N.digest, maintenance: N.maintenance.filter((m) => m.until > t) };
  }
  function conditions(f = {}) {
    const st = f.status || 'open'; const t = now();
    return conds.all((c) => (st === 'all' || c.status === st) && (!f.instance || c.instance === String(f.instance).toUpperCase()))
      .map((c) => Object.assign({}, c, { label: label(c), unit: (MBY[c.metric] || {}).unit || '', kind: (MBY[c.metric] || {}).kind || (c.metric.startsWith('ora:') ? 'error' : 'value'), snoozed: !!(c.snooze && c.snooze.until > t), maintenance: !!inMaintenance(c.instance), text: line(c) }))
      .sort((a, b) => (a.status === b.status ? 0 : a.status === 'open' ? -1 : 1) || RANK[b.level] - RANK[a.level] || b.since - a.since).slice(0, 1000);
  }
  function errors() { return (errCol.get('latest') || { at: 0, items: [] }); }
  function must(cid) { const c = conds.get(cid); if (!c) throw Object.assign(new Error('no such problem'), { code: 404 }); return c; }
  function ack(cid, by, note) { const c = must(cid); if (c.status !== 'open') throw Object.assign(new Error('already cleared'), { code: 409 }); c.ack = { by, at: now(), note: String(note || '').slice(0, 300) }; hist(c, by, `acknowledged${note ? `: ${String(note).slice(0, 120)}` : ''} - no more reminders`); conds.put(c); return c; }
  function snooze(cid, hours, by, reason) {
    const c = must(cid); const h = Number(hours);
    if (!(h > 0 && h <= 168)) throw bad('hours must be 1-168');
    if (String(reason || '').trim().length < 3) throw bad('say why (reason)');
    c.snooze = { until: now() + h * 3600000, by, reason: String(reason).trim().slice(0, 200) }; hist(c, by, `snoozed ${h} h: ${c.snooze.reason}`); conds.put(c); return c;
  }
  function unsnooze(cid, by) { const c = must(cid); delete c.snooze; hist(c, by, 'snooze ended'); conds.put(c); return c; }
  function catalog() { return { metrics: METRICS, ora: ORA_CATALOG.map(([code, level, title, what]) => ({ code, level, title, what })) }; }

  function start(ms = 300000) { if (!timer) { setTimeout(guardJob('db-audit.dba-alerts.tick', () => tick()), 20000).unref?.(); timer = setInterval(guardJob('db-audit.dba-alerts.tick', () => tick()), ms); if (timer.unref) timer.unref(); } return api; }
  function stop() { if (timer) clearInterval(timer); timer = null; }
  const api = { thresholdOf: (id, inst, key) => (MBY[id] ? thresholdFor(MBY[id], inst, key) : null), catalog, policy, savePolicy, notifySettings: notifyDoc, saveNotify, status, conditions, errors, ack, snooze, unsnooze, maintenance, endMaintenance, evaluate, notify, tick, digest, sendDigest, testMail, mailReport, start, stop, thresholdFor: (mid, inst, key) => thresholdFor(MBY[mid], inst, key) };
  return api;
}

module.exports = { createDbaAlerts, METRICS, ORA_CATALOG, valueOf, oraLines };
