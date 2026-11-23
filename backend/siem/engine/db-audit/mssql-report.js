// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * SQL Server Audit (Databases -> SQL Server Audit): who did what in the SQL Server instances, from the SQL Server Audit
 * records written to the Windows Application log (event 33205, parse/windows.js sqlAudit, collected by the SENTRA-WEF-SQL
 * subscription or the agent) plus the error-log login events 18456 / 18453 / 18454 (parse/windows.js sqlLogin).
 * The SQL Server counterpart of audit-report.js (Oracle), which it does not change; it reuses afterHours() from it.
 *
 *   classify(row)                  → failed-login | login | permission | account | schema | audit | config | data | other
 *   summarize(events, { now, hours, capped })  → the report (pure; tested)
 *   createMssqlReport({ ch, now, table })      → { report(q), events(q) }
 *
 * Sections: failed logins (login / client / application / reason), permission grants / revokes / denies and role
 * membership, account changes (logins, users, roles, password resets), schema changes (CREATE / ALTER / DROP of tables,
 * views, procedures …), audit changes (server audit / audit specifications altered, stopped or dropped), configuration
 * changes (server / database), administrative activity outside Riyadh working hours (Sun-Thu 07:00-18:00), and coverage:
 * an instance that sends login events but no audit record is said so - never read as "nothing happened".
 * Statements are returned with password / secret literals masked (CREATE LOGIN … PASSWORD = '***').
 */
const { afterHours } = require('./audit-report');

const MAX_ROWS = 50000;
const PERM = new Set(['G', 'GWG', 'R', 'RWG', 'RWC', 'D', 'DWC', 'APRL', 'DPRL']);
const ACCOUNT_CLASS = new Set(['SL', 'WL', 'WG', 'US', 'RL', 'SG', 'AR', 'CL', 'XL', 'LX']);
const ACCOUNT_ACT = new Set(['PWR', 'PWC', 'PWCS', 'PWU', 'PWEX', 'PWMC', 'TRO']);
const AUDIT_CLASS = new Set(['A', 'SA', 'DA']);
const DDL = new Set(['CR', 'AL', 'DR']);
const ADMIN = new Set(['permission', 'account', 'schema', 'audit', 'config']);
const ACTION_NAME = { LGIS: 'login succeeded', LGIF: 'login failed', LGO: 'logout', G: 'GRANT', GWG: 'GRANT WITH GRANT', R: 'REVOKE', RWG: 'REVOKE WITH GRANT', RWC: 'REVOKE WITH CASCADE',
  D: 'DENY', DWC: 'DENY WITH CASCADE', APRL: 'role member added', DPRL: 'role member removed', CR: 'CREATE', AL: 'ALTER', DR: 'DROP', AUSC: 'audit session changed',
  AUSF: 'audit shutdown on failure', PWR: 'password reset', PWC: 'password changed', PWCS: 'own password changed', PWU: 'account unlocked', TRO: 'ownership transferred',
  IMP: 'impersonate', BA: 'BACKUP', BAL: 'BACKUP LOG', SL: 'SELECT', IN: 'INSERT', UP: 'UPDATE', DL: 'DELETE', EX: 'EXECUTE' };
const s = (v, n = 300) => String(v == null ? '' : v).slice(0, n);
// password / secret literals never leave the report (SQL Server masks most, not all: CREATE CREDENTIAL SECRET, sp_addlinkedsrvlogin …)
function maskStatement(t) {
  return String(t || '').replace(/\b(PASSWORD|SECRET|IDENTIFIED\s+BY)(\s*=?\s*)N?'(?:[^']|'')*'/gi, "$1$2'***'")
    .replace(/(sp_addlinkedsrvlogin\b[^;]*?,\s*)N?'(?:[^']|'')*'(\s*;?\s*$)/i, "$1'***'$2").replace(/(@rmtpassword\s*=\s*)N?'(?:[^']|'')*'/gi, "$1'***'");
}
function classify(r) {
  const a = r.action_id, c = r.class_type;
  if (r.event_code === '18456' || a === 'LGIF') return 'failed-login';
  if (r.event_code === '18453' || r.event_code === '18454' || a === 'LGIS' || a === 'LGO') return 'login';
  if (PERM.has(a)) return 'permission';
  if (a === 'AUSC' || a === 'AUSF' || (DDL.has(a) && AUDIT_CLASS.has(c))) return 'audit';
  if (ACCOUNT_ACT.has(a) || (DDL.has(a) && ACCOUNT_CLASS.has(c))) return 'account';
  if (DDL.has(a) && (c === 'SR' || c === 'DB')) return 'config';
  if (DDL.has(a)) return 'schema';
  if (['SL', 'IN', 'UP', 'DL', 'EX'].includes(a)) return 'data';
  return 'other';
}
function row(e) {
  const f = e.fields || {}, code = String(e.event_code || ''), short = s(e.host, 120).split('.')[0].toUpperCase();
  // the error-log login events carry no instance name: the provider does (MSSQL$<instance>, MSSQLSERVER = the default instance)
  const pv = /^MSSQL\$(.+)$/i.exec(String(f.provider || '')), inst = f.sql_instance || (pv ? short + '\\' + pv[1] : short);
  const r = { ts: new Date(Number(e.ts)).toISOString(), event_code: code, host: short, instance: s(inst, 120).toUpperCase(), database: s(f.database, 128),
    object: s(f.object, 256), action_id: s(f.sql_action_id, 8).toUpperCase(), class_type: s(f.sql_class_type, 4).trim().toUpperCase(), user: s(e.user, 128), target: s(e.target_user, 128),
    client_ip: s(e.src_ip, 64), client_host: s(f.client_host, 128), application: s(f.application, 160), outcome: s(e.outcome, 16), reason: s(f.failure_reason, 160),
    statement: maskStatement(s(e.cmdline, 2000)).slice(0, 600) };
  r.action_name = ACTION_NAME[r.action_id] || (code === '18456' ? 'login failed (error log)' : /^1845[34]$/.test(code) ? 'login succeeded (error log)' : r.action_id || 'audit');
  r.category = classify(r);
  return r;
}

function summarize(events, opt = {}) {
  const now = opt.now || Date.now(), R = (events || []).map(row).sort((a, b) => (a.ts < b.ts ? 1 : -1));
  const pick = (c) => R.filter((r) => r.category === c);
  const fl = Object.create(null);   // keyed by values from the logs: no prototype
  for (const r of pick('failed-login')) { const k = [r.instance, r.user, r.client_ip || r.client_host, r.application, r.reason].join('|'); const x = fl[k] || (fl[k] = { instance: r.instance, user: r.user, client: r.client_ip || r.client_host, application: r.application, reason: r.reason, count: 0, first: r.ts, last: r.ts }); x.count++; if (r.ts < x.first) x.first = r.ts; if (r.ts > x.last) x.last = r.ts; }
  const failed = Object.values(fl).sort((a, b) => b.count - a.count);
  const perms = pick('permission'), accounts = pick('account'), schema = pick('schema'), audits = pick('audit'), config = pick('config');
  const admin = R.filter((r) => ADMIN.has(r.category) && r.outcome !== 'failure');
  const offHours = admin.filter((r) => afterHours(Date.parse(r.ts)));
  const findings = [], add = (severity, area, title, rec, evidence) => findings.push({ severity, area, title, recommendation: rec, evidence: (evidence || []).filter(Boolean).slice(0, 6) });
  for (const a of audits) {
    const off = /STATE\s*=\s*OFF/i.test(a.statement) || (a.action_id === 'DR');
    if (off) add('critical', 'Audit tampering', `${a.user || '?'} ${a.action_id === 'DR' ? 'dropped' : 'stopped'} ${a.object || 'a server audit'} on ${a.instance}`, 'Find out who authorised it and turn the audit back on (ALTER SERVER AUDIT … WITH (STATE = ON)). Stopping the audit is the classic step before misuse.', [a.ts, a.statement]);
    else add('medium', 'Audit configuration', `${a.user || '?'} changed audit ${a.object || a.action_name} on ${a.instance}`, 'Check the change against an approved change request; the audit specification decides what is recorded.', [a.ts, a.statement]);
  }
  for (const p of perms) {
    const txt = [p.object, p.statement, p.target].join(' ');
    if (/\b(sysadmin|securityadmin|serveradmin|db_owner|db_securityadmin|CONTROL\s+SERVER|IMPERSONATE\s+ANY|ALTER\s+ANY\s+LOGIN)\b/i.test(txt) && (p.action_id === 'APRL' || /^G/.test(p.action_id)))
      add('high', 'Privilege', `${p.user || '?'} gave ${p.target || '?'} ${(/(sysadmin|securityadmin|serveradmin|db_owner|db_securityadmin|CONTROL\s+SERVER|IMPERSONATE\s+ANY|ALTER\s+ANY\s+LOGIN)/i.exec(txt) || [])[1] || 'a high privilege'} on ${p.instance}`, 'Check the grant against an approved change; sysadmin / CONTROL SERVER should be held by named DBAs only.', [p.ts, p.statement]);
  }
  for (const f of failed.filter((x) => x.count >= 10)) add(f.count >= 50 ? 'high' : 'medium', 'Authentication', `${f.count} failed logins for ${f.user || '?'} on ${f.instance} from ${f.client || '?'}`, 'Password guessing or an application with an old password: check the client and lock / rotate as needed.', [`${f.first} - ${f.last}`, f.application ? 'application ' + f.application : '', f.reason]);
  const offU = Object.create(null); for (const r of offHours) offU[r.user + '|' + r.instance] = (offU[r.user + '|' + r.instance] || 0) + 1;
  for (const [k, n] of Object.entries(offU)) { const [u, i] = k.split('|'); add('medium', 'Administrative activity', `${n} administrative action(s) by ${u || '?'} on ${i} outside working hours`, 'Confirm each against an approved change or on-call ticket (Riyadh working hours Sun-Thu 07:00-18:00).', offHours.filter((r) => r.user === u && r.instance === i).slice(0, 3).map((r) => r.ts + ' ' + r.action_name + ' ' + (r.object || ''))); }
  for (const a of accounts.filter((r) => r.action_id === 'CR' && (r.class_type === 'SL' || r.class_type === 'WL' || r.class_type === 'WG'))) add('low', 'Accounts', `${a.user || '?'} created login ${a.object || a.target || '?'} on ${a.instance}`, 'Check it matches an access request.', [a.ts, a.statement]);
  // coverage per server: one that sends logins (error log) but no SQL Server Audit record
  const srv = Object.create(null);
  for (const r of R) { const x = srv[r.host] || (srv[r.host] = { host: r.host, instances: [], audit_records: 0, login_events: 0, last: r.ts }); if (!x.instances.includes(r.instance)) x.instances.push(r.instance); if (r.event_code === '33205') x.audit_records++; else x.login_events++; if (r.ts > x.last) x.last = r.ts; }
  const coverage = Object.values(srv).sort((a, b) => (a.host < b.host ? -1 : 1));
  for (const c of coverage.filter((x) => !x.audit_records)) add('medium', 'Coverage', `${c.host}: login events arrive but no SQL Server Audit record in the period`, 'Create a SERVER AUDIT TO APPLICATION_LOG with a server audit specification (FAILED_LOGIN_GROUP, SERVER_ROLE_MEMBER_CHANGE_GROUP, SERVER_PERMISSION_CHANGE_GROUP, DATABASE_PERMISSION_CHANGE_GROUP, SCHEMA_OBJECT_CHANGE_GROUP, AUDIT_CHANGE_GROUP, SERVER_PRINCIPAL_CHANGE_GROUP) and turn it on.', []);
  const users = Object.create(null);
  for (const r of R) { const x = users[r.user] || (users[r.user] = { user: r.user, events: 0, failed: 0, admin: 0, last: r.ts }); x.events++; if (r.outcome === 'failure') x.failed++; if (ADMIN.has(r.category)) x.admin++; if (r.ts > x.last) x.last = r.ts; }
  const by = Object.create(null); for (const r of R) { const k = r.action_name; const x = by[k] || (by[k] = { action: k, category: r.category, count: 0, failed: 0 }); x.count++; if (r.outcome === 'failure') x.failed++; }
  const order = { critical: 0, high: 1, medium: 2, low: 3 };
  findings.sort((a, b) => order[a.severity] - order[b.severity]);
  return { generated_at: new Date(now).toISOString(), hours: opt.hours || 24, capped: !!opt.capped, total: R.length,
    summary: { events: R.length, audit_records: R.filter((r) => r.event_code === '33205').length, instances: coverage.length, users: Object.keys(users).length, failed_logins: pick('failed-login').length,
      permission_changes: perms.length, account_changes: accounts.length, schema_changes: schema.length, audit_changes: audits.length, config_changes: config.length, off_hours_admin: offHours.length,
      critical: findings.filter((f) => f.severity === 'critical').length, high: findings.filter((f) => f.severity === 'high').length },
    by_action: Object.values(by).sort((a, b) => b.count - a.count), failed_logins: failed.slice(0, 100), permissions: perms.slice(0, 500), accounts: accounts.slice(0, 500), schema_changes: schema.slice(0, 500),
    audit_changes: audits.slice(0, 200), config_changes: config.slice(0, 500), off_hours: offHours.slice(0, 500), users: Object.values(users).sort((a, b) => b.events - a.events).slice(0, 200), coverage, findings };
}

function createMssqlReport({ ch, now = Date.now, table = 'siem.events' } = {}) {
  const ok = () => ch && typeof ch.query === 'function';
  const hoursOf = (q) => Math.min(24 * 90, Math.max(1, Number(q && q.hours) || 24));
  const toMs = (v) => (typeof v === 'number' ? v : Date.parse(String(v).replace(' ', 'T') + (/[Zz]$/.test(String(v)) ? '' : 'Z')));
  async function rows(q) {
    const h = hoursOf(q), inst = String((q && q.instance) || '').toLowerCase(), db = String((q && q.database) || '').toLowerCase();
    const r = await ch.query(`/* mssql-audit:rows */ SELECT ts, host, event_code, action, outcome, severity, user, target_user, src_ip, cmdline, tags, fields FROM ${table}
      WHERE src_type = 'windows' AND has(tags, 'mssql') AND event_code IN ('33205','18456','18453','18454') AND ts >= now() - INTERVAL {h:UInt32} HOUR
        AND (empty({i:String}) OR lower(fields['sql_instance']) = {i:String} OR lower(host) = {i:String}) AND (empty({d:String}) OR lower(fields['database']) = {d:String})
      ORDER BY ts DESC LIMIT ${MAX_ROWS + 1}`, { h: { type: 'UInt32', value: h }, i: { type: 'String', value: inst }, d: { type: 'String', value: db } }, { readonly: true, timeout_ms: 30000 });
    return { list: r.slice(0, MAX_ROWS).map((x) => Object.assign({}, x, { ts: toMs(x.ts) })), capped: r.length > MAX_ROWS, h };
  }
  async function report(q = {}) {
    if (!ok()) return { available: false, reason: 'the event store (ClickHouse) is not available' };
    const { list, capped, h } = await rows(q);
    return Object.assign({ available: true }, summarize(list, { now: now(), hours: h, capped }), { scope: { instance: String(q.instance || '').toUpperCase() || null, database: q.database || null } });
  }
  // the activity table / export: every row in the period that matches the filters (newest first)
  async function events(q = {}) {
    if (!ok()) return { available: false, reason: 'the event store (ClickHouse) is not available', items: [] };
    const { list, capped, h } = await rows(q);
    const want = String(q.category || ''), user = String(q.user || '').toLowerCase(), text = String(q.q || '').toLowerCase(), lim = Math.min(10000, Math.max(1, Number(q.limit) || 500));
    let R = list.map(row);
    if (want === 'failed') R = R.filter((r) => r.outcome === 'failure');
    else if (want === 'admin') R = R.filter((r) => ADMIN.has(r.category));
    else if (want === 'off-hours') R = R.filter((r) => ADMIN.has(r.category) && r.outcome !== 'failure' && afterHours(Date.parse(r.ts)));
    else if (want) R = R.filter((r) => r.category === want);
    if (user) R = R.filter((r) => r.user.toLowerCase() === user);
    if (text) R = R.filter((r) => [r.user, r.action_name, r.object, r.database, r.application, r.client_host, r.client_ip, r.statement, r.instance].join(' ').toLowerCase().includes(text));
    return { available: true, hours: h, capped, total: R.length, items: R.slice(0, lim), filter: { category: want || null, user: user || null, q: text || null, instance: String(q.instance || '').toUpperCase() || null } };
  }
  return { report, events };
}

module.exports = { createMssqlReport, summarize, classify, maskStatement, MAX_ROWS, CATEGORIES: ['failed-login', 'login', 'permission', 'account', 'schema', 'audit', 'config', 'data', 'other'] };
