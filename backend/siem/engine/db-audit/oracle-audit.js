// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Oracle Database audit parser — source type "oracle-audit" (docs/ORACLE.md "Audit trail to SIEM"). Three inputs:
 *
 *  A. Unified Auditing → syslog (UNIFIED_AUDIT_SYSTEMLOG, Oracle 12.2 / 18c / 19c / 21c; format per Database Security
 *     Guide "Writing unified audit records to syslog"; VERIFY against the customer's exact build):
 *       Oracle Unified Audit[20563]: LENGTH: "214" TYPE:"4" DBID:"1532165204" SESID:"4294967295" CLIENTID:"" ENTRYID:"1"
 *       STMTID:"1" DBUSER:"SYS" CURUSER:"SYS" ACTION:"100" RETCODE:"1017" SCHEMA:"" OBJNAME:"" PDB_GUID:"3BC5…"
 *     Only a subset of UNIFIED_AUDIT_TRAIL reaches syslog (no SQL text, no OS user) — the collector's NDJSON rows (C)
 *     carry the full record when needed.
 *  B. Traditional auditing → syslog (AUDIT_SYSLOG_LEVEL, Oracle 11g / 12c, still used by SYSDBA auditing):
 *       Oracle Audit[12345]: LENGTH : '169' ACTION :[7] 'CONNECT' DATABASE USER:[1] '/' PRIVILEGE :[6] 'SYSDBA'
 *       CLIENT USER:[6] 'oracle' CLIENT TERMINAL:[5] 'pts/1' STATUS:[1] '0' DBID:[10] '1234567890'
 *  C. NDJSON rows selected from UNIFIED_AUDIT_TRAIL by the collector ({kind:"unified_audit", EVENT_TIMESTAMP, DBUSERNAME,
 *     ACTION_NAME, RETURN_CODE, OS_USERNAME, USERHOST, TERMINAL, CLIENT_PROGRAM_NAME, OBJECT_SCHEMA, OBJECT_NAME, SQL_TEXT,
 *     UNIFIED_AUDIT_POLICIES, SYSTEM_PRIVILEGE_USED, AUTHENTICATION_TYPE, DBID, INSTANCE_ID, SESSIONID, AUDIT_TYPE, …}).
 *
 * Normalised actions (category): logon / logon-failed / logoff (authentication); user-created / user-deleted /
 * user-modified / privilege-granted / privilege-revoked / role-created / role-deleted (iam); audit-disabled /
 * audit-policy-changed (policy); data-access (database, fields.statement = SELECT|INSERT|UPDATE|DELETE|EXECUTE…);
 * config-change (database, ALTER SYSTEM/DATABASE); anything else → lower-cased action name (database).
 * Fields: dbuser, curuser, os_user, userhost, terminal, privilege, return_code, failure_reason, dbid, sesid, entryid,
 * object, policy, auth_type, client_program, sql (≤ 500 chars), grant / grantee, action_code, action_name, dba ("1" for
 * SYS / SYSTEM / SYSDBA-family privileges or DBA_ACCOUNTS), app_account ("1" when the user matches APP_ACCOUNT_RE).
 * Tags: oracle, db-audit (+ dba, app-account). user = DBUSER lower-cased; src_ip from USERHOST when it is an address.
 */
const net = require('node:net');

const NAME = 'oracle-audit';
const MAX_SQL = 500;
// AUDIT_ACTIONS codes (SELECT action, name FROM audit_actions) — the common subset; VERIFY on the customer's version.
const ACTION_CODES = {
  1: 'CREATE TABLE', 2: 'INSERT', 3: 'SELECT', 4: 'CREATE CLUSTER', 5: 'ALTER CLUSTER', 6: 'UPDATE', 7: 'DELETE', 8: 'DROP CLUSTER', 9: 'CREATE INDEX', 10: 'DROP INDEX',
  11: 'ALTER INDEX', 12: 'DROP TABLE', 13: 'CREATE SEQUENCE', 14: 'ALTER SEQUENCE', 15: 'ALTER TABLE', 16: 'DROP SEQUENCE', 17: 'GRANT OBJECT', 18: 'REVOKE OBJECT',
  19: 'CREATE SYNONYM', 20: 'DROP SYNONYM', 21: 'CREATE VIEW', 22: 'DROP VIEW', 26: 'LOCK', 27: 'NO-OP', 28: 'RENAME', 29: 'COMMENT', 30: 'AUDIT OBJECT', 31: 'NOAUDIT OBJECT',
  32: 'CREATE DATABASE LINK', 33: 'DROP DATABASE LINK', 34: 'CREATE DATABASE', 35: 'ALTER DATABASE', 36: 'CREATE ROLLBACK SEG', 37: 'ALTER ROLLBACK SEG', 38: 'DROP ROLLBACK SEG',
  39: 'CREATE TABLESPACE', 40: 'ALTER TABLESPACE', 41: 'DROP TABLESPACE', 42: 'ALTER SESSION', 43: 'ALTER USER', 44: 'COMMIT', 45: 'ROLLBACK', 46: 'SAVEPOINT', 47: 'PL/SQL EXECUTE',
  48: 'SET TRANSACTION', 49: 'ALTER SYSTEM', 50: 'EXPLAIN', 51: 'CREATE USER', 52: 'CREATE ROLE', 53: 'DROP USER', 54: 'DROP ROLE', 55: 'SET ROLE', 56: 'CREATE SCHEMA',
  57: 'CREATE CONTROL FILE', 59: 'CREATE TRIGGER', 60: 'ALTER TRIGGER', 61: 'DROP TRIGGER', 62: 'ANALYZE TABLE', 63: 'ANALYZE INDEX', 64: 'ANALYZE CLUSTER', 65: 'CREATE PROFILE',
  66: 'DROP PROFILE', 67: 'ALTER PROFILE', 68: 'DROP PROCEDURE', 70: 'ALTER RESOURCE COST', 71: 'CREATE MATERIALIZED VIEW LOG', 72: 'ALTER MATERIALIZED VIEW LOG',
  73: 'DROP MATERIALIZED VIEW LOG', 74: 'CREATE MATERIALIZED VIEW', 75: 'ALTER MATERIALIZED VIEW', 76: 'DROP MATERIALIZED VIEW', 77: 'CREATE TYPE', 78: 'DROP TYPE',
  79: 'ALTER ROLE', 80: 'ALTER TYPE', 81: 'CREATE TYPE BODY', 82: 'ALTER TYPE BODY', 83: 'DROP TYPE BODY', 84: 'DROP LIBRARY', 85: 'TRUNCATE TABLE', 86: 'TRUNCATE CLUSTER',
  91: 'CREATE FUNCTION', 92: 'ALTER FUNCTION', 93: 'DROP FUNCTION', 94: 'CREATE PACKAGE', 95: 'ALTER PACKAGE', 96: 'DROP PACKAGE', 97: 'CREATE PACKAGE BODY',
  98: 'ALTER PACKAGE BODY', 99: 'DROP PACKAGE BODY', 100: 'LOGON', 101: 'LOGOFF', 102: 'LOGOFF BY CLEANUP', 103: 'SESSION REC', 104: 'SYSTEM AUDIT', 105: 'SYSTEM NOAUDIT',
  106: 'AUDIT DEFAULT', 107: 'NOAUDIT DEFAULT', 108: 'SYSTEM GRANT', 109: 'SYSTEM REVOKE', 110: 'CREATE PUBLIC SYNONYM', 111: 'DROP PUBLIC SYNONYM', 112: 'CREATE PUBLIC DATABASE LINK',
  113: 'DROP PUBLIC DATABASE LINK', 114: 'GRANT ROLE', 115: 'REVOKE ROLE', 116: 'EXECUTE PROCEDURE', 117: 'USER COMMENT', 118: 'ENABLE TRIGGER', 119: 'DISABLE TRIGGER',
  120: 'ENABLE ALL TRIGGERS', 121: 'DISABLE ALL TRIGGERS', 122: 'NETWORK ERROR', 123: 'EXECUTE TYPE', 157: 'CREATE DIRECTORY', 158: 'DROP DIRECTORY', 159: 'CREATE LIBRARY',
  160: 'CREATE JAVA', 161: 'ALTER JAVA', 162: 'DROP JAVA', 163: 'CREATE OPERATOR', 167: 'ASSOCIATE STATISTICS', 168: 'DISASSOCIATE STATISTICS', 169: 'CALL METHOD',
  170: 'CREATE SUMMARY', 171: 'ALTER SUMMARY', 172: 'DROP SUMMARY', 173: 'CREATE DIMENSION', 174: 'ALTER DIMENSION', 175: 'DROP DIMENSION', 176: 'CREATE CONTEXT',
  177: 'DROP CONTEXT', 178: 'ALTER OUTLINE', 179: 'CREATE OUTLINE', 180: 'DROP OUTLINE', 181: 'UPDATE INDEXES', 182: 'ALTER OPERATOR', 183: 'CREATE SPFILE', 184: 'CREATE PFILE',
  185: 'MERGE', 186: 'PASSWORD CHANGE', 187: 'ALTER SYNONYM', 188: 'ALTER DISKGROUP', 189: 'CREATE DISKGROUP', 190: 'DROP DISKGROUP', 191: 'PURGE RECYCLEBIN',
  192: 'PURGE DBA_RECYCLEBIN', 193: 'PURGE TABLESPACE', 194: 'PURGE TABLE', 195: 'PURGE INDEX', 196: 'UNDROP OBJECT', 197: 'DROP DATABASE', 198: 'FLASHBACK DATABASE',
  199: 'FLASHBACK TABLE', 200: 'CREATE RESTORE POINT', 201: 'DROP RESTORE POINT', 202: 'PROXY AUTHENTICATION ONLY', 203: 'DECLARE REWRITE EQUIVALENCE',
  204: 'ALTER REWRITE EQUIVALENCE', 205: 'DROP REWRITE EQUIVALENCE', 206: 'CREATE EDITION', 207: 'ALTER EDITION', 208: 'DROP EDITION', 209: 'DROP ASSEMBLY', 210: 'CREATE ASSEMBLY',
  211: 'ALTER ASSEMBLY', 212: 'CREATE FLASHBACK ARCHIVE', 213: 'ALTER FLASHBACK ARCHIVE', 214: 'DROP FLASHBACK ARCHIVE', 215: 'DEBUG CONNECT', 217: 'DEBUG PROCEDURE',
  218: 'ALTER DATABASE LINK', 219: 'CREATE PLUGGABLE DATABASE', 220: 'ALTER PLUGGABLE DATABASE', 221: 'DROP PLUGGABLE DATABASE', 222: 'CREATE AUDIT POLICY', 223: 'ALTER AUDIT POLICY',
  224: 'DROP AUDIT POLICY', 225: 'CODE-BASED GRANT', 226: 'CODE-BASED REVOKE', 227: 'CREATE LOCKDOWN PROFILE', 228: 'DROP LOCKDOWN PROFILE', 229: 'ALTER LOCKDOWN PROFILE',
  230: 'TRANSLATE SQL', 231: 'ADMINISTER KEY MANAGEMENT', 232: 'CREATE MATERIALIZED ZONEMAP', 233: 'ALTER MATERIALIZED ZONEMAP', 234: 'DROP MATERIALIZED ZONEMAP',
  235: 'DROP MINING MODEL', 236: 'CREATE MINING MODEL', 237: 'ALTER MINING MODEL', 238: 'CREATE ATTRIBUTE DIMENSION', 239: 'ALTER ATTRIBUTE DIMENSION', 240: 'DROP ATTRIBUTE DIMENSION',
  241: 'CREATE HIERARCHY', 242: 'ALTER HIERARCHY', 243: 'DROP HIERARCHY', 244: 'CREATE ANALYTIC VIEW', 245: 'ALTER ANALYTIC VIEW', 246: 'DROP ANALYTIC VIEW', 305: 'ALTER PUBLIC DATABASE LINK',
};
const RETURN_CODES = {
  0: '', 1005: 'null password', 1017: 'invalid username/password', 1031: 'insufficient privileges', 1045: 'user lacks CREATE SESSION privilege',
  1109: 'not logged on', 1920: 'user already exists', 1918: 'user does not exist', 28000: 'account locked', 28001: 'password expired', 28002: 'password will expire',
  28003: 'password verification failed', 28007: 'password cannot be reused', 28009: 'connection as SYS should be as SYSDBA or SYSOPER', 28040: 'no matching authentication protocol',
  28150: 'proxy not authorized', 28221: 'original password not supplied', 12170: 'TNS connect timeout', 1012: 'not logged on',
};
const DBA_ACCOUNTS = new Set(['SYS', 'SYSTEM', 'SYSBACKUP', 'SYSDG', 'SYSKM', 'SYSRAC', 'DBSNMP', 'SYSMAN']);
const DBA_PRIVS = /^(SYSDBA|SYSOPER|SYSBACKUP|SYSDG|SYSKM|SYSRAC|SYSASM)$/i;
const APP_ACCOUNT_RE = /^(app[_-]|svc[_-]|srv[_-]|.*[_-]app$|.*[_-]svc$|.*_user$|.*_owner$)/i;
const DBA_ROLE_RE = /\b(DBA|SYSDBA|SYSOPER|SYSBACKUP|SYSDG|SYSKM|PDB_DBA|IMP_FULL_DATABASE|EXP_FULL_DATABASE|DATAPUMP_IMP_FULL_DATABASE|AUDIT_ADMIN|GRANT ANY PRIVILEGE|GRANT ANY ROLE|ALTER USER|CREATE USER|DROP USER|BECOME USER|ALTER SYSTEM|UNLIMITED TABLESPACE|SELECT ANY TABLE|READ ANY TABLE|EXEMPT ACCESS POLICY|ALTER ANY TABLE)\b/i;

function s(v) { return v === undefined || v === null ? '' : String(v); }
function looksLikeIp(v) { return !!v && net.isIP(String(v).replace(/^\[|\]$/g, '')) !== 0; }
function returnCodeText(code) { const n = parseInt(code, 10); if (!Number.isFinite(n)) return ''; return RETURN_CODES[n] !== undefined ? RETURN_CODES[n] : n === 0 ? '' : `ORA-${String(n).padStart(5, '0')}`; }
function actionName(code, name) {
  if (name) return String(name).toUpperCase().trim();
  const n = parseInt(code, 10);
  return ACTION_CODES[n] || (Number.isFinite(n) ? `ACTION ${n}` : '');
}

/** Map an Oracle action name (+ return code) to the normalised action / category / statement. */
function classify(name, rc) {
  const up = String(name || '').toUpperCase();
  const ok = !rc || rc === '0';
  if (up === 'LOGON' || up === 'CONNECT' || up === 'PROXY AUTHENTICATION ONLY' || up === 'DEBUG CONNECT') return ok ? ['logon', 'authentication'] : ['logon-failed', 'authentication'];
  if (/^LOGOFF/.test(up) || up === 'DISCONNECT') return ['logoff', 'authentication'];
  if (up === 'CREATE USER') return ['user-created', 'iam'];
  if (up === 'DROP USER') return ['user-deleted', 'iam'];
  if (up === 'ALTER USER' || up === 'PASSWORD CHANGE') return ['user-modified', 'iam'];
  if (/^(GRANT ROLE|GRANT OBJECT|SYSTEM GRANT|CODE-BASED GRANT|GRANT)$/.test(up)) return ['privilege-granted', 'iam'];
  if (/^(REVOKE ROLE|REVOKE OBJECT|SYSTEM REVOKE|CODE-BASED REVOKE|REVOKE)$/.test(up)) return ['privilege-revoked', 'iam'];
  if (up === 'CREATE ROLE') return ['role-created', 'iam'];
  if (up === 'DROP ROLE') return ['role-deleted', 'iam'];
  if (up === 'ALTER ROLE' || up === 'SET ROLE') return ['role-modified', 'iam'];
  if (/^(NOAUDIT|SYSTEM NOAUDIT|NOAUDIT OBJECT|NOAUDIT DEFAULT|NOAUDIT POLICY|DROP AUDIT POLICY)$/.test(up)) return ['audit-disabled', 'policy'];
  if (/AUDIT/.test(up)) return ['audit-policy-changed', 'policy'];
  if (/^(SELECT|INSERT|UPDATE|DELETE|MERGE|TRUNCATE TABLE|TRUNCATE CLUSTER|LOCK|EXECUTE|EXECUTE PROCEDURE|EXECUTE TYPE|CALL METHOD|PL\/SQL EXECUTE|FLASHBACK TABLE)$/.test(up)) return ['data-access', 'database', up.split(' ')[0]];
  if (/^(ALTER SYSTEM|ALTER DATABASE|CREATE SPFILE|CREATE PFILE|ALTER PLUGGABLE DATABASE|ADMINISTER KEY MANAGEMENT|CREATE LOCKDOWN PROFILE|ALTER LOCKDOWN PROFILE|DROP LOCKDOWN PROFILE|ALTER PROFILE|CREATE PROFILE|DROP PROFILE)$/.test(up)) return ['config-change', 'database'];
  if (/^(CREATE|ALTER|DROP|TRUNCATE|RENAME|PURGE|COMMENT|ANALYZE|UNDROP)\b/.test(up)) return ['schema-change', 'database'];
  if (up === 'NETWORK ERROR') return ['network-error', 'network'];
  return [up ? up.toLowerCase().replace(/[^a-z0-9]+/g, '-') : 'audit', 'database'];
}

function grantInfo(sql) {
  const m = /\b(GRANT|REVOKE)\s+([\s\S]+?)\s+(TO|FROM)\s+("?[\w$#.]+"?(?:\s*,\s*"?[\w$#.]+"?)*)/i.exec(String(sql || ''));
  if (!m) return null;
  return { grant: m[2].replace(/\s+/g, ' ').trim().slice(0, 300), grantee: m[4].replace(/"/g, '').trim().slice(0, 200) };
}

function build(core, m) {
  // core = { ts, dbuser, curuser, os_user, userhost, terminal, privilege, action_name, action_code, return_code, dbid, sesid, entryid, stmtid,
  //          schema, object, sql, policy, auth_type, client_program, instance, pdb_guid, audit_type, client_id, host, format }
  const rc = s(core.return_code).trim();
  const name = actionName(core.action_code, core.action_name);
  const [action, category, statement] = classify(name, rc);
  const dbuser = s(core.dbuser).toUpperCase();
  const priv = s(core.privilege).toUpperCase().replace(/^(NONE|-)$/, '');
  const dba = DBA_ACCOUNTS.has(dbuser) || DBA_PRIVS.test(priv) || /\bSYSDBA\b/.test(s(core.action_name).toUpperCase());
  const app = APP_ACCOUNT_RE.test(dbuser);
  const f = { dbuser, action_name: name, action_code: s(core.action_code), return_code: rc || '0', audit_format: core.format || '' };
  const put = (k, v) => { const x = s(v).trim(); if (x) f[k] = x; };
  put('curuser', s(core.curuser).toUpperCase()); put('os_user', core.os_user); put('userhost', core.userhost); put('terminal', core.terminal); put('privilege', priv);
  put('dbid', core.dbid); put('sesid', core.sesid); put('entryid', core.entryid); put('stmtid', core.stmtid); put('pdb_guid', core.pdb_guid); put('instance', s(core.instance).toUpperCase());
  put('auth_type', core.auth_type); put('client_program', core.client_program); put('policy', core.policy); put('audit_type', core.audit_type); put('client_id', core.client_id);
  if (core.schema || core.object) put('object', [s(core.schema).toUpperCase(), s(core.object).toUpperCase()].filter(Boolean).join('.'));
  if (statement) f.statement = statement;
  const sql = s(core.sql).replace(/\s+/g, ' ').trim();
  if (sql) f.sql = sql.slice(0, MAX_SQL);
  if (rc && rc !== '0') f.failure_reason = returnCodeText(rc);
  if (action === 'privilege-granted' || action === 'privilege-revoked') {
    const g = grantInfo(sql);
    if (g) { f.grant = g.grant; f.grantee = g.grantee; }
    else if (core.object) f.grant = f.object;
    if (DBA_ROLE_RE.test(f.grant || '') || DBA_ROLE_RE.test(sql)) f.grant_dba = '1';
  }
  if (dba) f.dba = '1';
  if (app) f.app_account = '1';
  const ev = {
    ts: core.ts, host: s(core.host), category, action, outcome: rc && rc !== '0' ? 'failure' : 'success',
    user: dbuser.toLowerCase(), target_user: '', severity: 0, fields: f, tags: ['oracle', 'db-audit'], event_code: name ? name.replace(/\s+/g, '_') : '',
    src_ip: looksLikeIp(core.userhost) ? s(core.userhost).replace(/^\[|\]$/g, '') : (looksLikeIp(core.client_ip) ? s(core.client_ip) : ''),
  };
  if (dba) ev.tags.push('dba');
  if (app) ev.tags.push('app-account');
  if (action === 'user-created' || action === 'user-deleted' || action === 'user-modified') {
    const um = /\bUSER\s+"?([\w$#]+)"?/i.exec(sql || '');
    ev.target_user = s(core.object || (um && um[1]) || '').toLowerCase();
  }
  if (action === 'privilege-granted' || action === 'privilege-revoked') ev.target_user = s(f.grantee || '').split(',')[0].trim().toLowerCase();
  switch (action) {
    case 'logon-failed': ev.severity = 2; break;
    case 'logon': ev.severity = dba ? 1 : 0; break;
    case 'user-created': case 'user-deleted': ev.severity = 2; break;
    case 'privilege-granted': ev.severity = f.grant_dba ? 3 : 1; break;
    case 'audit-disabled': ev.severity = 3; break;
    case 'audit-policy-changed': ev.severity = 1; break;
    case 'config-change': ev.severity = 1; break;
    default: ev.severity = 0;
  }
  const who = `${dbuser || '?'}${f.os_user ? ` (${f.os_user}@${f.userhost || '?'})` : f.userhost ? ` from ${f.userhost}` : ''}${priv ? ` as ${priv}` : ''}`;
  const what = statement && f.object ? `${statement} on ${f.object}` : f.grant ? `${name} ${f.grant}${f.grantee ? ` to ${f.grantee}` : ''}` : f.object ? `${name} ${f.object}` : name;
  ev.message = `Oracle audit${f.instance ? ` ${f.instance}` : ''}: ${what} by ${who}${rc && rc !== '0' ? ` FAILED ORA-${rc} ${f.failure_reason}` : ''}`;
  return ev;
}

// ---- A. unified audit syslog: KEY:"value" pairs after the LENGTH field
const UNIFIED_RE = /Oracle Unified Audit(?:\[\d+\])?:\s*/i;
function parseUnifiedSyslog(body, m) {
  const i = body.search(UNIFIED_RE);
  if (i < 0) return null;
  const text = body.slice(i).replace(UNIFIED_RE, '');
  const kv = {};
  const re = /([A-Z_]+)\s*:\s*"((?:[^"\\]|\\.)*)"/g;
  let x; let n = 0;
  while ((x = re.exec(text))) { kv[x[1]] = x[2]; n++; }
  if (!n || (!('ACTION' in kv) && !('DBUSER' in kv))) return null;
  return build({
    ts: (m.syslog && m.syslog.ts) || m.rts, host: m.syslog && m.syslog.host, format: 'unified-syslog',
    dbuser: kv.DBUSER, curuser: kv.CURUSER, os_user: kv.OS_USER || kv.OSUSER, userhost: kv.USERHOST, terminal: kv.TERMINAL, privilege: kv.PRIVILEGE || kv.SYSTEM_PRIVILEGE,
    action_code: kv.ACTION, action_name: kv.ACTION_NAME, return_code: kv.RETCODE || kv.RETURN_CODE, dbid: kv.DBID, sesid: kv.SESID, entryid: kv.ENTRYID, stmtid: kv.STMTID,
    schema: kv.SCHEMA, object: kv.OBJNAME, sql: kv.SQLTEXT || kv.SQL_TEXT, policy: kv.POLICY || kv.UNIFIED_AUDIT_POLICIES, auth_type: kv.AUTH_TYPE, client_program: kv.CLIENT_PROGRAM,
    instance: kv.INSTANCE || kv.INSTANCE_NAME || kv.SID_NAME, pdb_guid: kv.PDB_GUID, audit_type: kv.TYPE, client_id: kv.CLIENTID,
  }, m);
}

// ---- B. traditional audit syslog: KEY:[len] 'value' pairs
const TRAD_RE = /Oracle Audit(?:\[\d+\])?:\s*/i;
function parseTraditionalSyslog(body, m) {
  const i = body.search(TRAD_RE);
  if (i < 0) return null;
  const text = body.slice(i).replace(TRAD_RE, '');
  const kv = {};
  const re = /([A-Z][A-Z ]*?)\s*:\s*\[\d+\]\s*'((?:[^'\\]|\\.)*)'/g;
  let x; let n = 0;
  while ((x = re.exec(text))) { kv[x[1].trim()] = x[2]; n++; }
  if (!n || !('ACTION' in kv)) return null;
  const act = kv.ACTION;
  const core = {
    ts: (m.syslog && m.syslog.ts) || m.rts, host: m.syslog && m.syslog.host, format: 'traditional-syslog',
    dbuser: kv['DATABASE USER'] === '/' ? (kv['CLIENT USER'] || '/') : kv['DATABASE USER'], os_user: kv['CLIENT USER'], terminal: kv['CLIENT TERMINAL'], userhost: kv['USER HOST'] || kv['CLIENT HOST'],
    privilege: kv.PRIVILEGE, return_code: kv.STATUS, dbid: kv.DBID, sesid: kv['SESSION ID'], instance: kv['INSTANCE NAME'] || kv.SID, pdb_guid: '',
  };
  // traditional records carry either a verb (CONNECT / LOGOFF) or the statement text in ACTION
  if (/^(CONNECT|LOGON)$/i.test(act)) core.action_name = 'LOGON';
  else if (/^LOGOFF/i.test(act)) core.action_name = 'LOGOFF';
  else {
    core.sql = act;
    const verb = /^\s*([A-Z]+(?:\s+(?:USER|ROLE|TABLE|SYSTEM|SESSION|DATABASE|PROFILE|AUDIT POLICY|TABLESPACE|INDEX|VIEW|PROCEDURE|PACKAGE|TRIGGER|SYNONYM|SEQUENCE))?)/i.exec(act);
    let name = verb ? verb[1].toUpperCase() : act.toUpperCase().slice(0, 30);
    if (name === 'GRANT' && /\bTO\b/i.test(act)) name = /\bON\b/i.test(act) ? 'GRANT OBJECT' : 'GRANT ROLE';
    if (name === 'REVOKE' && /\bFROM\b/i.test(act)) name = /\bON\b/i.test(act) ? 'REVOKE OBJECT' : 'REVOKE ROLE';
    if (name === 'NOAUDIT') name = 'SYSTEM NOAUDIT';
    if (name === 'AUDIT') name = 'SYSTEM AUDIT';
    core.action_name = name;
  }
  if (core.dbuser && core.dbuser !== '/' && kv['DATABASE USER'] === '/' ) core.auth_type = 'OS';
  return build(core, m);
}

// ---- C. UNIFIED_AUDIT_TRAIL rows (collector NDJSON, {kind:"unified_audit", …upper-case column names})
function parseRow(o, m = {}) {
  const g = (k) => { if (o[k] !== undefined) return o[k]; const lk = k.toLowerCase(); return o[lk] !== undefined ? o[lk] : undefined; };
  const t = g('EVENT_TIMESTAMP_UTC') || g('EVENT_TIMESTAMP') || g('ts') || g('t');
  let ts = typeof t === 'number' ? (t > 1e11 ? t : t * 1000) : Date.parse(s(t));
  if (!Number.isFinite(ts)) ts = m.rts || Date.now();
  const ev = build({
    ts, host: s(g('host') || g('HOST')), format: 'unified-trail',
    dbuser: g('DBUSERNAME'), curuser: g('CURRENT_USER'), os_user: g('OS_USERNAME'), userhost: g('USERHOST'), terminal: g('TERMINAL'),
    privilege: g('SYSTEM_PRIVILEGE_USED') && DBA_PRIVS.test(s(g('SYSTEM_PRIVILEGE_USED'))) ? g('SYSTEM_PRIVILEGE_USED') : (g('AUTHENTICATION_TYPE') && /SYSDBA|SYSOPER|SYSBACKUP|SYSDG|SYSKM/i.test(s(g('AUTHENTICATION_TYPE'))) ? (/(SYSDBA|SYSOPER|SYSBACKUP|SYSDG|SYSKM)/i.exec(s(g('AUTHENTICATION_TYPE'))) || [])[1] : ''),
    action_name: g('ACTION_NAME'), action_code: g('ACTION'), return_code: g('RETURN_CODE'), dbid: g('DBID'), sesid: g('SESSIONID'), entryid: g('ENTRY_ID'), stmtid: g('STATEMENT_ID'),
    schema: g('OBJECT_SCHEMA'), object: g('OBJECT_NAME'), sql: g('SQL_TEXT'), policy: g('UNIFIED_AUDIT_POLICIES'), auth_type: g('AUTHENTICATION_TYPE'), client_program: g('CLIENT_PROGRAM_NAME'),
    instance: g('instance') || g('INSTANCE_NAME') || g('INSTANCE_ID'), pdb_guid: g('PDB_GUID'), audit_type: g('AUDIT_TYPE'), client_id: g('CLIENT_IDENTIFIER'), client_ip: g('client_ip') || g('CLIENT_IP'),
  }, m);
  if (g('SYSTEM_PRIVILEGE_USED')) ev.fields.system_privilege = s(g('SYSTEM_PRIVILEGE_USED')).slice(0, 300);
  if (g('db_name') || g('DB_NAME')) ev.fields.db_name = s(g('db_name') || g('DB_NAME')).toUpperCase();
  return ev;
}

function sniff(body, m) {
  const o = m && m.obj;
  if (o && typeof o === 'object') return o.kind === 'unified_audit' || o.kind === 'audit_trail' || (o.DBUSERNAME !== undefined && o.ACTION_NAME !== undefined);
  return /Oracle (Unified )?Audit(\[\d+\])?:/i.test(body);
}
function parse(body, m = {}) {
  const o = m.obj;
  if (o && typeof o === 'object' && !Array.isArray(o)) {
    if (o.kind === 'unified_audit' || o.kind === 'audit_trail' || o.DBUSERNAME !== undefined) return parseRow(o, m);
    return null;
  }
  return parseUnifiedSyslog(body, m) || parseTraditionalSyslog(body, m);
}

module.exports = { name: NAME, sniff, parse, parseRow, parseUnifiedSyslog, parseTraditionalSyslog, classify, actionName, returnCodeText, looksLikeIp, ACTION_CODES, RETURN_CODES, DBA_ACCOUNTS };
