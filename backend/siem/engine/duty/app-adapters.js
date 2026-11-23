// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Two more AI engineers on the duty desk (duty-core.js), built on data the SIEM already holds - nothing new is collected
 * and nothing is changed:
 *   dba   AI Oracle DBA            every issue the Oracle health collector reports (engine/db-audit: instance down, tablespace,
 *                                   blocked sessions, RMAN backup, Data Guard lag, redo / archive, FRA, listener, failed logons,
 *                                   alert-log ORA- errors, collector gone quiet) becomes a work item with the DBA's next step;
 *                                   with the performance feed (db-audit/perf-api.js, last hour): CPU-bound (active sessions
 *                                   above the CPU count), host CPU saturated, time dominated by one wait class. The same
 *                                   data whether it comes from the agent or from a database added in Connections & Setup.
 *                                   Verification re-reads the collector's latest sample; a stale instance is "not yet known",
 *                                   never "fixed".
 *   apps  AI Application Manager   per business service (Server Availability groups: by the service an administrator set, or
 *                                   by name): service down, running without redundancy, single point of failure, no / offline
 *                                   DR copy - and resource pressure (disk, CPU, memory) or unexpected shutdowns on the servers
 *                                   of a production service.
 * Both are rule-based: they diagnose and recommend; a DBA / application owner decides and applies. Database and
 * application changes are never proposed for automatic execution.
 */
const crypto = require('node:crypto');

const maskDigits = (s) => String(s || '').toLowerCase().replace(/\d+(\.\d+)?/g, '#').replace(/\s+/g, ' ').trim();
const shortHash = (s) => crypto.createHash('sha1').update(s).digest('hex').slice(0, 10);
const SEVN = { 4: 'critical', 3: 'high', 2: 'medium', 1: 'low', 0: 'low' };

const DBA_ADVICE = {
  'instance-down': 'Check the instance and listener on the host (srvctl / sqlplus as sysdba), read the alert log for the cause before starting it, and inform the application owners.',
  'status-unknown': 'The database is answering (other readings arrive) but its instance status is not: grant the monitoring account SELECT on V$INSTANCE and V$DATABASE (oracle-monitor-account.sql), then press Test on Databases.',
  'tablespace-usage': 'Add a datafile or resize / enable autoextend within the storage budget; check what grew (DBA_SEGMENTS) before adding space.',
  'session-count': 'Find the blocking session (V$SESSION.BLOCKING_SESSION), confirm with the application owner, then decide whether to end it.',
  'blocked-session': 'Find the blocking session (V$SESSION.BLOCKING_SESSION), confirm with the application owner, then decide whether to end it.',
  'backup-status': 'Check the last RMAN job (V$RMAN_BACKUP_JOB_DETAILS / the RMAN log), fix the cause and run a backup; confirm it completes.',
  'dataguard-lag': 'Check the standby apply / transport (V$DATAGUARD_STATS, alert log on the standby), network to the DR site, and archive gaps.',
  'redo-status': 'Check archiving (archive destination space and errors, V$ARCHIVE_DEST); unarchived logs put recovery at risk.',
  'fra-usage': 'Free the fast recovery area safely: delete obsolete backups / archived logs per the RMAN retention policy, or enlarge DB_RECOVERY_FILE_DEST_SIZE.',
  'listener-status': 'Check the listener (lsnrctl status) and its log; restart only in agreement with the application owners.',
  'logon-failed': 'Review the failing accounts and source addresses (unified audit); lock or reset accounts as needed and inform the SOC.',
  'alertlog-tail': 'Read the ORA- errors in the alert log; raise an Oracle SR if they are internal errors (ORA-600 / ORA-7445).',
  'invalid-objects': 'Recompile invalid objects (utlrp.sql) after confirming no deployment is in progress.',
  'stale': 'No recent sample. Added in Connections & Setup → Oracle databases: open it there - a paused database (refused login, or an account with more than read-only rights) shows why; press Test after fixing. With the collector agent: check it on the database host (agents/oracle) and its schedule.',
  'cpu-bound': 'More sessions want CPU than the server has: find the top SQL by CPU (Database Performance → Top SQL) and its plan, check for a recent plan change or a missing index, and agree any change with the application owner. Add CPU only after the SQL is ruled out.',
  'host-cpu': 'The database host is near 100% CPU: check whether Oracle (DB CPU on the Database Performance page) or another process on the host is the consumer, then tune the top SQL or move the other load.',
  'wait-dominated': 'Most database time is spent waiting in one class: open Database Performance for the wait events behind it (User I/O → storage latency / full scans; Commit → redo log latency; Concurrency → hot blocks / locks) and fix the cause, not the symptom.',
};
const APP_TEXT = {
  'service-down': ['critical', 'service down - every server of the service is offline', 'Treat as a major incident: inform the business owner, check the servers and their dependencies (database, network), and invoke the DR plan if recovery takes longer than the RTO.'],
  'no-redundancy-now': ['high', 'running without redundancy - a production server is offline', 'Restore the offline server: the service now depends on a single server.'],
  'dr-offline': ['high', 'DR copy is offline', 'Bring the DR server back: the service currently has no working recovery copy.'],
  'single-server': ['medium', 'single point of failure - one production server', 'Plan a second server or a documented recovery procedure with a tested RTO; record it in DR & BCM drills.'],
  'no-dr': ['medium', 'no DR copy', 'Add a DR server (or record where it is - set its role to "dr" in Server Availability) and test failover.'],
};
const HOST_TEXT = {
  'disk-full': ['high', 'disk 90% or fuller', 'Free or extend the disk before the application stops writing.'],
  'cpu-high': ['medium', 'CPU 90% or higher', 'Find the process using the CPU and agree a fix with the application owner.'],
  'memory-high': ['medium', 'memory 90% or higher', 'Check for a memory leak or under-sizing; plan more memory or a restart in a maintenance window.'],
  'unexpected-shutdowns': ['high', 'unexpected shutdowns in the last 30 days', 'Find the cause of the crashes (event log 6008 / kernel logs) - they interrupt the service.'],
};

// performance thresholds over the last hour (averages, so one busy minute does not open a work item)
const PERF_TH = { aas_per_cpu: 1, aas_per_cpu_high: 2, host_cpu_pct: 90, wait_dbtime_pct: 50, min_points: 3 };
// the performance problems of one instance, as health-style issues (same keys, same verify path)
async function perfIssues(P, i) {
  if (!P || typeof P.perf !== 'function') return [];
  let v; try { v = await P.perf({ instance: i.key }); } catch (e) { return []; }
  const sm = v && v.summary, out = [];
  if (!sm || (sm.points || 0) < PERF_TH.min_points) return out;          // too few samples to call it a trend
  const cpu = sm.cpu_count || null, aas = sm.aas_avg;
  if (cpu && aas != null && aas / cpu > PERF_TH.aas_per_cpu) out.push({ severity: aas / cpu > PERF_TH.aas_per_cpu_high ? 3 : 2, action: 'cpu-bound', text: `CPU-bound: ${aas} active sessions on average for ${cpu} CPUs over the last hour` });
  if (sm.host_cpu_pct_avg != null && sm.host_cpu_pct_avg >= PERF_TH.host_cpu_pct) out.push({ severity: 3, action: 'host-cpu', text: `host CPU at ${sm.host_cpu_pct_avg}% on average over the last hour` });
  const w = (v.wait_classes || []).filter((x) => x && x.class && !/^(cpu|idle)$/i.test(x.class)).sort((a, b) => (b.dbtime_pct || 0) - (a.dbtime_pct || 0))[0];
  if (w && w.dbtime_pct >= PERF_TH.wait_dbtime_pct) out.push({ severity: 2, action: 'wait-dominated', text: `${w.dbtime_pct}% of database time waiting on ${w.class}` });
  return out;
}

let REF = null;
const oracleRef = () => REF || (REF = require('../db-audit/oracle-ref').createOracleRef({}));
function dbaAdapter(O, P) {
  if (!O || typeof O.summary !== 'function') return [];
  const keyOf = (inst, iss) => `${inst.key}:${iss.action}:${shortHash(iss.action === 'cpu-bound' || iss.action === 'host-cpu' ? '' : maskDigits(iss.text))}`;
  async function current() {
    const s = await O.summary({});
    if (!s.instances.length) return null;                                     // no database reports: not connected, not healthy
    const out = [];
    for (const i of s.instances) {
      const name = `${i.instance}${i.db_name && i.db_name !== i.instance ? ' (' + i.db_name + ')' : ''} on ${i.host}`;
      const list = i.issues.slice();
      if (!i.stale) list.push(...await perfIssues(P, i));   // a stale instance's averages are old: only the staleness is reported
      const st = i.state || (i.up ? 'up' : 'down');   // older SIEM summaries have no state
      if (st === 'down' && !list.some((x) => x.action === 'instance-down')) list.unshift({ severity: 4, text: 'instance not open (status ' + (i.status || 'unknown') + ')', action: 'instance-down' });
      else if (st === 'unknown' && !i.stale) list.unshift({ severity: 2, text: 'status unknown - no instance status reading received (the database is not reported as down)', action: 'status-unknown' });
      for (const iss of list) out.push({ key: keyOf(i, iss), severity: SEVN[Math.min(4, iss.severity | 0)], kind: iss.action, title: `${name}: ${iss.text}`,
        evidence: [iss.text, i.version ? 'Oracle ' + i.version : '', i.role ? 'role ' + i.role : '', i.last_seen ? 'last sample ' + new Date(i.last_seen).toISOString() : ''].filter(Boolean),
        recommendation: DBA_ADVICE[iss.action] || 'Review the issue on the database and decide the fix.', target: { type: 'database', id: i.key, name }, stale: !!i.stale });
    }
    return out;
  }
  const { kindCount } = require('./duty-core');
  return [{
    id: 'dba', name: 'AI Oracle DBA',
    kpis: (open) => [
      { label: 'Instances with issues', value: new Set(open.map((x) => x.target && x.target.id)).size, target: 0 },
      { label: 'Instances down', value: kindCount(open, ['instance-down'], true), target: 0 },
      { label: 'Backup failures', value: kindCount(open, ['backup-status'], true), target: 0 },
      { label: 'Tablespaces ≥ 90 %', value: kindCount(open, ['tablespace-usage']), target: 0 },
      { label: 'Data Guard lag / archiving problems', value: kindCount(open, ['dataguard-lag', 'redo-status', 'fra-usage']), target: 0 },
      { label: 'Performance problems (CPU-bound, waits)', value: kindCount(open, ['cpu-bound', 'host-cpu', 'wait-dominated']), target: 0 }],
    async findings() { const f = await current(); return f && f.map((x) => { const y = Object.assign({}, x); delete y.stale; return y; }); },
    async investigate(it) {
      const i = await O.instance(it.target.id, {});
      if (!i) return { summary: 'The instance no longer reports to the SIEM.', checks: [], causes: [] };
      const chk = (name, status, detail) => ({ name, status, detail });
      const checks = [chk('Instance', i.up ? 'ok' : (i.state === 'unknown' ? 'warn' : 'fail'), `${i.status || '?'} · ${i.open_mode || '?'} · role ${i.role || '?'} · ${i.log_mode || ''}`.trim())];
      const tb = (i.tablespaces || []).slice(0, 3); if (tb.length) checks.push(chk('Fullest tablespaces', tb[0].used_pct >= 90 ? 'warn' : 'ok', tb.map((t) => `${t.name} ${t.used_pct}%`).join(', ')));
      if (i.sessions) checks.push(chk('Sessions', i.sessions.blocked ? 'warn' : 'ok', `${i.sessions.total}/${i.sessions.max_sessions || '?'} (${i.sessions.active} active, ${i.sessions.blocked} blocked)`));
      if ((i.blocked_sessions || []).length) checks.push(chk('Blocking', 'warn', i.blocked_sessions.slice(0, 3).map((b) => `SID ${b.sid} (${b.user}) waits ${b.wait_s}s on SID ${b.blocking_sid} (${b.blocking_user})`).join('; ')));
      if (i.backup) checks.push(chk('Last RMAN backup', i.backup.severity >= 3 ? 'fail' : 'ok', `${i.backup.status} ${i.backup.input_type} · ${i.backup.age_h} h ago`));
      if (i.dataguard) checks.push(chk('Data Guard', i.dataguard.severity >= 3 ? 'warn' : 'ok', `apply lag ${i.dataguard.apply_lag_s}s · transport lag ${i.dataguard.transport_lag_s}s`));
      if (i.fra) checks.push(chk('Fast recovery area', i.fra.used_pct >= 85 ? 'warn' : 'ok', `${i.fra.used_pct}% used`));
      if (i.listener) checks.push(chk('Listener', i.listener.up ? 'ok' : 'fail', `${i.listener.name || ''} ${i.listener.status || ''}`.trim()));
      if (i.alertlog && i.alertlog.ora_errors) checks.push(chk('Alert log', 'warn', `${i.alertlog.ora_errors} ORA- errors`));
      if (i.stale) checks.push(chk('Collector', 'warn', 'no recent sample - figures may be old'));
      if (P && typeof P.perf === 'function') {
        let v = null; try { v = await P.perf({ instance: i.key }); } catch (e) { v = null; }
        const sm = v && v.summary;
        if (sm) {
          checks.push(chk('Load (last hour)', sm.cpu_count && sm.aas_avg / sm.cpu_count > PERF_TH.aas_per_cpu ? 'warn' : 'ok', `${sm.aas_avg} active sessions avg (max ${sm.aas_max != null ? sm.aas_max : '?'}) for ${sm.cpu_count || '?'} CPUs · ${sm.db_cpu_s_avg != null ? sm.db_cpu_s_avg + ' DB CPU/s · ' : ''}${sm.executions_s_avg != null ? sm.executions_s_avg + ' executions/s' : ''}`.replace(/ · $/, '')));
          if (sm.host_cpu_pct_avg != null) checks.push(chk('Host CPU', sm.host_cpu_pct_avg >= PERF_TH.host_cpu_pct ? 'warn' : 'ok', `${sm.host_cpu_pct_avg}% avg`));
          const top = (v.wait_classes || []).filter((x) => x && x.class && !/^idle$/i.test(x.class)).slice(0, 3);
          if (top.length) checks.push(chk('Top wait classes', top[0].dbtime_pct >= PERF_TH.wait_dbtime_pct ? 'warn' : 'ok', top.map((x) => `${x.class} ${x.dbtime_pct}%`).join(', ')));
        } else checks.push(chk('Performance', 'skip', 'no performance samples for this instance yet'));
      }
      // where to read more: Oracle's own guides for this kind of finding (oracle/skills copy shipped with the engine)
      const refs = oracleRef().forTopic(it.kind);
      if (refs.length) checks.push(chk('Oracle reference', 'info', refs.map((r) => r.title + ' (' + r.id + ')' + (r.licensed ? ' - needs the Diagnostics Pack' : '')).join('; ')));
      return { summary: `${it.title}. ${it.recommendation || ''}`.trim(), checks, causes: [{ cause: it.title, confidence: 'high', fix: it.recommendation || '' }] };
    },
    async verify(it) {
      const f = await current(); if (!f) return { present: null, note: 'no database reports at the moment' };
      const x = f.find((y) => y.target.id === it.target.id);
      if (x && x.stale) return { present: null, note: 'the instance has no recent sample - not yet known' };
      const present = f.some((y) => y.key === it.key);
      return { present, note: present ? 'the latest collector sample still reports it' : 'the latest collector sample no longer reports it' };
    },
  }];
}

function appAdapter(A) {
  if (!A || typeof A.view !== 'function') return [];
  async function current() {
    const v = await A.view();
    if (!v.items.length) return null;                                         // nothing monitored: not connected
    const out = [], byId = {};
    for (const h of v.items) byId[h.id] = h;
    for (const g of v.groups) {
      const members = g.members.map((id) => byId[id]).filter(Boolean);
      const names = members.map((h) => h.name).join(', ');
      const site = (members.find((h) => h.site) || {}).site || '';
      for (const is of g.issues) {
        const t = APP_TEXT[is]; if (!t) continue;
        const sev = g.critical && t[0] === 'high' ? 'critical' : g.critical && t[0] === 'medium' ? 'high' : t[0];
        out.push({ key: `svc:${g.key}:${is}`, severity: sev, kind: is, title: `${g.name}: ${t[1]}`, site,
          evidence: [`servers: ${names || '-'}`, `production online ${g.production_online}/${g.production}`, g.inferred ? 'service grouped by server name (set the service in Server Availability to confirm)' : 'service set by an administrator', g.critical ? 'marked business-critical' : ''].filter(Boolean),
          recommendation: t[2], target: { type: 'service', id: g.key, name: g.name } });
      }
      if (!g.required) continue;                                               // resource findings only for production services
      for (const h of members) for (const fl of h.flags || []) {
        const t = HOST_TEXT[fl]; if (!t) continue;
        out.push({ key: `host:${h.id}:${fl}`, severity: t[0], kind: fl, title: `${g.name} - ${h.name}: ${t[1]}`, site: h.site || '',
          evidence: [h.resources ? `CPU ${h.resources.cpu_pct}% · memory ${h.resources.mem_pct}% · disk ${h.resources.disk_max_pct}%` : '', fl === 'unexpected-shutdowns' ? `${h.unexpected_shutdowns_30d} in 30 days` : '', `service ${g.name}`].filter(Boolean),
          recommendation: t[2], target: { type: 'server', id: h.id, name: h.name } });
      }
    }
    return out;
  }
  return [{
    id: 'apps', name: 'AI Application Manager',
    findings: current,
    async investigate(it) {
      const v = await A.view();
      const g = v.groups.find((x) => x.key === it.target.id) || v.groups.find((x) => (x.members || []).includes(it.target.id));
      if (!g) return { summary: 'The service is no longer monitored.', checks: [], causes: [] };
      const checks = g.members.map((id) => v.items.find((h) => h.id === id)).filter(Boolean).map((h) => ({ name: h.name + (h.dr_site ? ' (DR)' : ''), status: h.status === 'online' ? 'ok' : h.status === 'offline' ? 'fail' : 'warn',
        detail: `${h.status}${h.duration_s != null ? ' for ' + Math.round(h.duration_s / 60) + ' min' : ''}${h.availability && h.availability.d7 != null ? ' · 7-day availability ' + h.availability.d7 + '%' : ''}${(h.flags || []).length ? ' · ' + h.flags.join(', ') : ''}` }));
      return { summary: `${it.title}. ${it.recommendation || ''}`.trim(), checks, causes: [{ cause: it.title, confidence: 'high', fix: it.recommendation || '' }] };
    },
    async verify(it) { const f = await current(); if (!f) return { present: null, note: 'nothing monitored at the moment' }; const present = f.some((x) => x.key === it.key); return { present, note: present ? 'the latest availability check still shows it' : 'the latest availability check no longer shows it' }; },
  }];
}

module.exports = { dbaAdapter, appAdapter, DBA_ADVICE };
