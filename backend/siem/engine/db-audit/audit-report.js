// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Database Audit (Databases -> Database Audit): who did what in the Oracle databases, from the unified audit trail the
 * platform connection reads (IT Asset Management db-health, kind unified_audit -> oracle-audit parseRow) or an agent /
 * syslog sends - plus how each database is configured to audit (kind audit_config -> action audit-config).
 *
 *   createAuditReport({ ch, now, table }) -> { report(q), events(q) }
 *   summarize(rows, { posture, monitored, now, hours, capped, dbMap, view }) -> the report (pure; tested)
 *   ?database=ESP reads every RAC instance of ESP (db_name from the DBA Alert Center); ?view=instance keeps coverage per instance
 *
 * Sections: activity by action, failed logons (user / host / program / reason), privileged activity (SYS* privileges,
 * DBA accounts), account & privilege changes, schema changes, configuration changes, audit tampering (NOAUDIT / policy
 * dropped), privileged activity outside Riyadh working hours (Sun-Thu 07:00-18:00), audit configuration checks per
 * database (unified auditing, the ORA_* policies SAMA / NCA expect, trail cleanup and archive), and coverage: a monitored
 * database that sent no audit record in the period is said so - never read as "nothing happened".
 * SQL text arrives with its literals masked. Every finding names the rows it comes from.
 */
const MAX_ROWS = 50000;
const ACCOUNT = new Set(['user-created', 'user-deleted', 'user-modified', 'privilege-granted', 'privilege-revoked', 'role-created', 'role-deleted', 'role-modified']);
const TAMPER = new Set(['audit-disabled', 'audit-policy-changed']);
const WANT_POLICIES = [
  ['ORA_LOGON_FAILURES', 'high', 'failed logons are not audited - password guessing goes unseen (SAMA 3.3.5 / NCA ECC 2-12)'],
  ['ORA_SECURECONFIG', 'medium', 'the Oracle secure-configuration baseline (privilege use, user / role / profile changes, ALTER SYSTEM) is not audited'],
  ['ORA_ACCOUNT_MGMT', 'medium', 'user and role management is not audited as its own policy'],
  ['ORA_DATABASE_PARAMETER', 'low', 'database parameter changes (ALTER SYSTEM / ALTER DATABASE) are not audited as their own policy'],
];
const num = (v) => { const n = Number(v); return v === '' || v === null || v === undefined || !Number.isFinite(n) ? null : n; };
const s = (v, n = 300) => String(v == null ? '' : v).slice(0, n);
// Riyadh is UTC+3 all year: working hours Sun-Thu 07:00-18:00 (SPO_WORK / the Wazuh off-hours rules)
function afterHours(ts) { const d = new Date(Number(ts) + 3 * 3600000), day = d.getUTCDay(), h = d.getUTCHours(); return day === 5 || day === 6 || h < 7 || h >= 18; }
function row(e) {
  const f = e.fields || {};
  return { ts: new Date(Number(e.ts)).toISOString(), instance: s(f.instance, 64), host: s(e.host, 120), user: s(e.user || f.dbuser, 128), action: s(e.action, 64), action_name: s(f.action_name, 64),
    outcome: s(e.outcome, 16), object: s(f.object, 200), privilege: s(f.privilege || f.system_privilege, 120), program: s(f.client_program, 120), userhost: s(f.userhost, 120), os_user: s(f.os_user, 64),
    return_code: s(f.return_code, 12), reason: s(f.failure_reason, 120), grant: s(f.grant, 200), grantee: s(f.grantee, 200), grant_dba: f.grant_dba === '1', dba: f.dba === '1' || (e.tags || []).includes('dba'),
    policy: s(f.policy, 200), sql: s(f.sql, 500), severity: num(e.severity) || 0 };
}

function postureChecks(inst, f, at) {
  const out = [], add = (severity, title, rec) => out.push({ instance: inst, severity, area: 'Audit configuration', title, recommendation: rec, evidence: ['read ' + at] });
  const pol = new Set(String(f.policies || '').split(',').map((x) => x.trim().toUpperCase()).filter(Boolean));
  if (!pol.size) add('critical', `${inst}: no unified audit policy is enabled`, 'Auditing is effectively off. Enable at least ORA_LOGON_FAILURES and ORA_SECURECONFIG (AUDIT POLICY ora_logon_failures WHENEVER NOT SUCCESSFUL; AUDIT POLICY ora_secureconfig;).');
  else for (const [p, sev, why] of WANT_POLICIES) if (!pol.has(p)) add(sev, `${inst}: ${p} is not enabled`, `${why[0].toUpperCase() + why.slice(1)}. Enable it: AUDIT POLICY ${p.toLowerCase()}${p === 'ORA_LOGON_FAILURES' ? ' WHENEVER NOT SUCCESSFUL' : ''};`);
  if (String(f.unified_pure || '').toUpperCase() === 'FALSE') add('low', `${inst}: mixed-mode auditing (traditional + unified)`, 'Pure unified auditing (relink with uniaud_on at the next maintenance) gives one tamper-resistant trail.');
  if (num(f.cleanup_jobs) === 0) add('medium', `${inst}: no audit trail cleanup job`, 'The trail grows in SYSAUX until it fills: archive it to the SIEM (this platform already reads it) and schedule DBMS_AUDIT_MGMT.CREATE_PURGE_JOB with SET_LAST_ARCHIVE_TIMESTAMP.');
  else if (f.last_archive && Date.parse(f.last_archive + 'Z') < Date.parse(at) - 30 * 86400000) add('low', `${inst}: last archive timestamp ${f.last_archive}`, 'The purge job only removes records older than the last archive timestamp: keep DBMS_AUDIT_MGMT.SET_LAST_ARCHIVE_TIMESTAMP moving, or the trail is never purged.');
  return out;
}

// the database an instance belongs to (RAC: ESP1 and ESP2 are database ESP), from the DBA Alert Center's db_name reading;
// an instance it has no reading for is its own database - never guessed from the name
function dbMapOf(list) { const m = new Map(); for (const x of list || []) { const i = String(x.instance || '').toUpperCase(), d = String(x.db_name || '').toUpperCase(); if (i && d) m.set(i, d); } return m; }

function summarize(events, opt = {}) {
  const dbm = opt.dbMap || new Map(), dbOf = (i) => dbm.get(String(i || '').toUpperCase()) || String(i || '').toUpperCase();
  const byDb = opt.view !== 'instance';
  const now = opt.now || Date.now(), R = events.map(row).map((r) => Object.assign(r, { database: dbOf(r.instance) })).sort((a, b) => (a.ts < b.ts ? 1 : -1));
  const by = Object.create(null); for (const r of R) { const k = r.action || 'audit'; const x = by[k] || (by[k] = { action: k, count: 0, users: new Set(), failed: 0 }); x.count++; x.users.add(r.user); if (r.outcome === 'failure') x.failed++; }
  const byAction = Object.values(by).map((x) => ({ action: x.action, count: x.count, users: x.users.size, failed: x.failed })).sort((a, b) => b.count - a.count);
  const fl = Object.create(null); for (const r of R.filter((x) => x.action === 'logon-failed')) { const k = [r.instance, r.user, r.userhost, r.program, r.reason].join('|'); const x = fl[k] || (fl[k] = { instance: r.instance, database: r.database, user: r.user, userhost: r.userhost, program: r.program, reason: r.reason, count: 0, first: r.ts, last: r.ts }); x.count++; if (r.ts < x.first) x.first = r.ts; if (r.ts > x.last) x.last = r.ts; }
  const failed = Object.values(fl).sort((a, b) => b.count - a.count);
  const privileged = R.filter((r) => r.privilege || r.dba).filter((r) => r.action !== 'logoff');
  const accounts = R.filter((r) => ACCOUNT.has(r.action)), schema = R.filter((r) => r.action === 'schema-change'), config = R.filter((r) => r.action === 'config-change'), tamper = R.filter((r) => TAMPER.has(r.action));
  const offHours = privileged.filter((r) => r.outcome !== 'failure' && afterHours(Date.parse(r.ts)));
  const users = Object.create(null);   // keyed by values from the logs: no prototype (a user named __proto__ stays a user)
  for (const r of R) { const x = users[r.user] || (users[r.user] = { user: r.user, events: 0, failed: 0, privileged: 0, changes: 0, last: r.ts }); x.events++; if (r.outcome === 'failure') x.failed++; if (r.privilege || r.dba) x.privileged++; if (ACCOUNT.has(r.action) || r.action === 'schema-change' || r.action === 'config-change') x.changes++; if (r.ts > x.last) x.last = r.ts; }
  const findings = [], add = (severity, area, title, rec, evidence) => findings.push({ severity, area, title, recommendation: rec, evidence: (evidence || []).filter(Boolean).slice(0, 6) });
  for (const t of tamper.filter((r) => r.action === 'audit-disabled')) add('critical', 'Audit tampering', `${t.user} disabled auditing on ${t.instance} (${t.action_name})`, 'Find out who authorised it; re-enable the policy. Turning auditing off is the classic step before misuse.', [t.ts, t.sql]);
  for (const g of accounts.filter((r) => r.grant_dba)) add('high', 'Privilege', `${g.user} granted ${g.grant || 'DBA'} to ${g.grantee || '?'} on ${g.instance}`, 'Check the grant against an approved change; DBA / SYS-level roles should be held by named DBAs only.', [g.ts, g.sql]);
  for (const f of failed.filter((x) => x.count >= 10)) add(f.count >= 50 ? 'high' : 'medium', 'Authentication', `${f.count} failed logons for ${f.user || '?'} on ${f.instance} from ${f.userhost || '?'}`, 'Password guessing or a service with an old password: check the client and lock / rotate as needed.', [`${f.first} - ${f.last}`, f.program ? 'program ' + f.program : '', f.reason]);
  const offU = Object.create(null); for (const r of offHours) offU[r.user + '|' + r.instance] = (offU[r.user + '|' + r.instance] || 0) + 1;
  for (const [k, n] of Object.entries(offU)) { const [u, i] = k.split('|'); add('medium', 'Privileged use', `${n} privileged action(s) by ${u} on ${i} outside working hours`, 'Confirm each against an approved change or on-call ticket (Riyadh working hours Sun-Thu 07:00-18:00).', offHours.filter((r) => r.user === u && r.instance === i).slice(0, 3).map((r) => r.ts + ' ' + r.action_name)); }
  for (const u of accounts.filter((r) => r.action === 'user-created')) add('low', 'Accounts', `${u.user} created a database user on ${u.instance}`, 'Check it matches an access request.', [u.ts, u.object || u.sql]);
  // coverage + configuration
  const seen = new Set(R.map((r) => r.instance).filter(Boolean)), coverage = (opt.monitored || []).map((i) => ({ instance: i, events: R.filter((r) => r.instance === i).length, last: (R.find((r) => r.instance === i) || {}).ts || null }));
  const COV_FIX = 'Grant AUDIT_VIEWER to the platform\'s read-only account (Databases -> Add database script), or the trail is empty because auditing is off - see the configuration checks.';
  // per database: the unified audit trail is the database's, so one RAC instance reading it covers the database
  const covDb = Object.create(null); for (const c of coverage) { const d = dbOf(c.instance), x = covDb[d] || (covDb[d] = { database: d, instances: [], events: 0, last: null, silent: [] }); x.instances.push(c.instance); x.events += c.events; if (c.last && (!x.last || c.last > x.last)) x.last = c.last; if (!seen.has(c.instance)) x.silent.push(c.instance); }
  const coverage_db = Object.values(covDb).sort((a, b) => (a.database < b.database ? -1 : 1));
  if (byDb) { for (const c of coverage_db) if (!c.events) add('medium', 'Coverage', `${c.database}${c.instances.length > 1 || c.instances[0] !== c.database ? ' (' + c.instances.join(', ') + ')' : ''}: no audit record received in the period`, COV_FIX, []); }
  else for (const c of coverage) if (!seen.has(c.instance)) add('medium', 'Coverage', `${c.instance}: no audit record received in the period`, COV_FIX, []);
  const posture = (opt.posture || []).map((p) => ({ instance: p.instance, database: dbOf(p.instance), at: p.at, unified_pure: p.f.unified_pure || null, audit_trail: p.f.audit_trail || null, policies: String(p.f.policies || '').split(',').filter(Boolean), cleanup_jobs: num(p.f.cleanup_jobs), last_archive: p.f.last_archive || null, checks: postureChecks(p.instance, p.f, p.at) }));
  for (const p of posture) findings.push(...p.checks);
  const order = { critical: 0, high: 1, medium: 2, low: 3 };
  findings.sort((a, b) => order[a.severity] - order[b.severity]);
  return { generated_at: new Date(now).toISOString(), hours: opt.hours || 24, capped: !!opt.capped, total: R.length,
    summary: { events: R.length, users: Object.keys(users).length, failed_logons: R.filter((r) => r.action === 'logon-failed').length, privileged: privileged.length, account_changes: accounts.length,
      schema_changes: schema.length, config_changes: config.length, tamper: tamper.length, off_hours_privileged: offHours.length, databases: new Set([...seen].map(dbOf)).size, instances: seen.size, critical: findings.filter((f) => f.severity === 'critical').length, high: findings.filter((f) => f.severity === 'high').length },
    by_action: byAction, failed_logons: failed.slice(0, 100), privileged: privileged.slice(0, 500), accounts: accounts.slice(0, 500), schema_changes: schema.slice(0, 500), config_changes: config.slice(0, 500),
    tamper: tamper.slice(0, 200), off_hours: offHours.slice(0, 500), users: Object.values(users).sort((a, b) => b.events - a.events).slice(0, 200), coverage, coverage_db, posture, findings, view: byDb ? 'database' : 'instance',
    databases: coverage_db.map((c) => ({ database: c.database, instances: c.instances })) };
}

function createAuditReport({ ch, now = Date.now, table = 'siem.events', dbInstances = () => [] } = {}) {
  const ok = () => ch && typeof ch.query === 'function';
  const hoursOf = (q) => Math.min(24 * 90, Math.max(1, Number(q && q.hours) || 24));
  const toMs = (v) => (typeof v === 'number' ? v : Date.parse(String(v).replace(' ', 'T') + (/[Zz]$/.test(String(v)) ? '' : 'Z')));
  const dbMap = () => { try { return dbMapOf(dbInstances()); } catch (e) { return new Map(); /* the DBA Alert Center not running: each instance is its own database */ } };
  // instance=X → that instance; database=D → every instance of D (and an instance literally called D); neither → all
  function scope(q, m) {
    const inst = String((q && q.instance) || '').toUpperCase(), db = String((q && q.database) || '').toUpperCase();
    if (inst) return [inst];
    if (db) return [...new Set([db].concat([...m].filter(([, d]) => d === db).map(([i]) => i)))];
    return [];
  }
  async function rows(q, m) {
    const h = hoursOf(q), list = scope(q, m || dbMap()), params = { h: { type: 'UInt32', value: h }, insts: { type: 'Array(String)', value: list } };
    const r = await ch.query(`/* db-audit:rows */ SELECT ts, host, action, outcome, severity, user, tags, fields FROM ${table}
      WHERE has(tags, 'db-audit') AND ts >= now() - INTERVAL {h:UInt32} HOUR AND (empty({insts:Array(String)}) OR has({insts:Array(String)}, upper(fields['instance'])))
      ORDER BY ts DESC LIMIT ${MAX_ROWS + 1}`, params, { readonly: true, timeout_ms: 30000 });
    return { list: r.slice(0, MAX_ROWS).map((x) => Object.assign({}, x, { ts: toMs(x.ts) })), capped: r.length > MAX_ROWS, h };
  }
  async function report(q = {}) {
    if (!ok()) return { available: false, reason: 'the event store (ClickHouse) is not available' };
    const m = dbMap(), { list, capped, h } = await rows(q, m), sc = scope(q, m), inScope = (i) => !sc.length || sc.includes(i);
    const posture = (await ch.query(`/* db-audit:posture */ SELECT upper(fields['instance']) AS i, argMax(fields, ts) AS f, max(ts) AS t FROM ${table}
      WHERE action = 'audit-config' AND ts >= now() - INTERVAL 48 HOUR GROUP BY i`, {}, { readonly: true, timeout_ms: 15000 })).map((x) => ({ instance: x.i, f: x.f || {}, at: new Date(toMs(x.t)).toISOString() }));
    const monitored = (await ch.query(`/* db-audit:monitored */ SELECT DISTINCT upper(fields['instance']) AS i FROM ${table}
      WHERE src_type = 'oracle-health' AND action IN ('health-sample', 'agent-heartbeat', 'instance-down') AND ts >= now() - INTERVAL 24 HOUR`, {}, { readonly: true, timeout_ms: 15000 })).map((x) => x.i).filter(Boolean);
    return Object.assign({ available: true }, summarize(list, { posture: posture.filter((p) => inScope(p.instance)), monitored: monitored.filter(inScope).sort(), now: now(), hours: h, capped, dbMap: m, view: q.view === 'instance' ? 'instance' : 'database' }),
      { scope: { instance: String(q.instance || '').toUpperCase() || null, database: String(q.database || '').toUpperCase() || null, instances: sc } });
  }
  // the activity table / export: every row in the period that matches the filters (newest first)
  async function events(q = {}) {
    if (!ok()) return { available: false, reason: 'the event store (ClickHouse) is not available', items: [] };
    const { list, capped, h } = await rows(q);
    const want = String(q.action || ''), user = String(q.user || '').toLowerCase(), text = String(q.q || '').toLowerCase(), lim = Math.min(10000, Math.max(1, Number(q.limit) || 500));
    const m = dbMap(); let R = list.map(row).map((r) => Object.assign(r, { database: m.get(String(r.instance).toUpperCase()) || String(r.instance).toUpperCase() }));
    if (want === 'failed') R = R.filter((r) => r.outcome === 'failure'); else if (want === 'privileged') R = R.filter((r) => r.privilege || r.dba); else if (want) R = R.filter((r) => r.action === want);
    if (user) R = R.filter((r) => r.user.toLowerCase() === user);
    if (text) R = R.filter((r) => [r.user, r.action_name, r.object, r.program, r.userhost, r.sql, r.instance].join(' ').toLowerCase().includes(text));
    return { available: true, hours: h, capped, total: R.length, items: R.slice(0, lim), filter: { action: want || null, user: user || null, q: text || null, instance: String(q.instance || '').toUpperCase() || null, database: String(q.database || '').toUpperCase() || null } };
  }
  return { report, events };
}

module.exports = { createAuditReport, summarize, afterHours, postureChecks, dbMapOf, MAX_ROWS };
