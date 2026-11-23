// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Database Audit (engine/db-audit/audit-report.js): unified-audit rows exactly as the platform connection sends them
// (kind unified_audit through the oracle-health parser) -> the report: failed logons grouped, privileged activity, DBA grant,
// audit disabled, privileged use outside Riyadh working hours, audit configuration checks, and coverage (a monitored
// database with no audit record is a finding, never "nothing happened"). The ClickHouse half: filters and the row cap.
const test = require('node:test');
const assert = require('node:assert/strict');
const H = require('../engine/db-audit/oracle-health');
const { summarize, createAuditReport, afterHours } = require('../engine/db-audit/audit-report');

const ev = (row) => H.parse(JSON.stringify(Object.assign({ kind: 'unified_audit', collector: 'sentra-oracle-itam', host: 'eskauat', instance: 'ESS', db_name: 'ESS' }, row)));
// Tue 2026-10-20: 10:00 Riyadh = 07:00Z (working hours); 23:30 Riyadh = 20:30Z; Fri 2026-10-23 11:00 Riyadh = 08:00Z
const T = { work: '2026-10-20T07:00:00.000000Z', night: '2026-10-20T20:30:00.000000Z', friday: '2026-10-23T08:00:00.000000Z' };
const rows = [];
for (let i = 0; i < 12; i++) rows.push(ev({ EVENT_TIMESTAMP_UTC: T.work, DBUSERNAME: 'APP_ERP', ACTION_NAME: 'LOGON', RETURN_CODE: '1017', USERHOST: '10.1.1.50', CLIENT_PROGRAM_NAME: 'JDBC Thin Client', SESSIONID: String(i) }));
rows.push(ev({ EVENT_TIMESTAMP_UTC: T.night, DBUSERNAME: 'SYS', ACTION_NAME: 'LOGON', RETURN_CODE: '0', AUTHENTICATION_TYPE: '(TYPE=(OS));(CLIENT ADDRESS=((PROTOCOL=tcp)(HOST=10.1.1.9)));SYSDBA', USERHOST: 'dbadmin-pc', SYSTEM_PRIVILEGE_USED: 'SYSDBA' }));
rows.push(ev({ EVENT_TIMESTAMP_UTC: T.night, DBUSERNAME: 'SYS', ACTION_NAME: 'NOAUDIT POLICY', RETURN_CODE: '0', SQL_TEXT: 'NOAUDIT POLICY ora_logon_failures', SYSTEM_PRIVILEGE_USED: 'SYSDBA' }));
rows.push(ev({ EVENT_TIMESTAMP_UTC: T.friday, DBUSERNAME: 'DBA_RASHEED', ACTION_NAME: 'GRANT', RETURN_CODE: '0', SQL_TEXT: 'GRANT DBA TO app_report', SYSTEM_PRIVILEGE_USED: 'GRANT ANY ROLE' }));
rows.push(ev({ EVENT_TIMESTAMP_UTC: T.work, DBUSERNAME: 'DBA_RASHEED', ACTION_NAME: 'CREATE USER', RETURN_CODE: '0', OBJECT_NAME: 'APP_REPORT', SQL_TEXT: "CREATE USER app_report IDENTIFIED BY ':s'" }));
rows.push(ev({ EVENT_TIMESTAMP_UTC: T.work, DBUSERNAME: 'APP_OWNER', ACTION_NAME: 'ALTER TABLE', RETURN_CODE: '0', OBJECT_SCHEMA: 'APP', OBJECT_NAME: 'ORDERS' }));
rows.push(ev({ EVENT_TIMESTAMP_UTC: T.work, DBUSERNAME: 'DBA_RASHEED', ACTION_NAME: 'ALTER SYSTEM', RETURN_CODE: '0', SQL_TEXT: 'ALTER SYSTEM SET undo_retention = :n' }));

test('report: failed logons grouped, privileged, DBA grant, audit disabled, off-hours, configuration, coverage', () => {
  assert.equal(rows[0].action, 'logon-failed'); assert.equal(rows[0].fields.instance, 'ESS');
  const posture = [{ instance: 'ESS', at: '2026-10-20T12:00:00.000Z', f: { unified_pure: 'FALSE', policies: 'ORA_SECURECONFIG', cleanup_jobs: '0' } }, { instance: 'HRP', at: '2026-10-20T12:00:00.000Z', f: { policies: '' } }];
  const r = summarize(rows, { posture, monitored: ['ESS', 'HRP'], now: Date.UTC(2026, 9, 23, 12), hours: 168 });
  assert.equal(r.summary.failed_logons, 12);
  assert.equal(r.failed_logons[0].count, 12); assert.equal(r.failed_logons[0].user, 'app_erp'); assert.equal(r.failed_logons[0].userhost, '10.1.1.50');
  assert.ok(r.summary.privileged >= 3, 'SYSDBA logon, NOAUDIT, GRANT');
  assert.equal(r.tamper.length, 1); assert.equal(r.accounts.filter((x) => x.action === 'privilege-granted').length, 1); assert.equal(r.schema_changes.length, 1); assert.equal(r.config_changes.length, 1);
  const t = r.findings.map((f) => f.severity + ' ' + f.title);
  assert.ok(t.some((x) => /^critical sys disabled auditing on ESS/.test(x)), t.join('\n'));
  assert.ok(t.some((x) => /^high dba_rasheed granted DBA to app_report on ESS/.test(x)));
  assert.ok(t.some((x) => /^medium 12 failed logons for app_erp on ESS from 10\.1\.1\.50/.test(x)));
  assert.ok(t.some((x) => /privileged action\(s\) by sys on ESS outside working hours/.test(x)), 'SYS at 23:30 Riyadh');
  assert.ok(t.some((x) => /privileged action\(s\) by dba_rasheed on ESS outside working hours/.test(x)), 'Friday is outside working hours');
  assert.ok(t.some((x) => /^high ESS: ORA_LOGON_FAILURES is not enabled/.test(x)) && t.some((x) => /^medium ESS: no audit trail cleanup job/.test(x)) && t.some((x) => /^low ESS: mixed-mode/.test(x)));
  assert.ok(t.some((x) => /^critical HRP: no unified audit policy is enabled/.test(x)));
  assert.ok(t.some((x) => /^medium HRP: no audit record received in the period/.test(x)), 'coverage: HRP sent nothing');
  assert.ok(!r.privileged.some((x) => /IDENTIFIED BY '(?!:s')/.test(x.sql)), 'no password literal in the report');
  assert.equal(afterHours(Date.parse(T.work)), false); assert.equal(afterHours(Date.parse(T.night)), true); assert.equal(afterHours(Date.parse(T.friday)), true);
});

test('ClickHouse half: period + instance passed as parameters, row cap reported, filters on the activity table', async () => {
  const seen = [];
  const ch = { query: async (sql, params) => { seen.push({ sql, params }); if (/db-audit:rows/.test(sql)) return rows.map((e) => Object.assign({}, e, { ts: new Date(e.ts).toISOString().replace('T', ' ').replace('Z', '') })); if (/db-audit:posture/.test(sql)) return []; return [{ i: 'ESS' }]; } };
  const A = createAuditReport({ ch, now: () => Date.UTC(2026, 9, 23, 12) });
  const r = await A.report({ hours: '168', instance: 'ess' });
  assert.equal(seen[0].params.h.value, 168); assert.deepEqual(seen[0].params.insts.value, ['ESS']); assert.match(seen[0].sql, /has\(tags, 'db-audit'\)/);
  assert.equal(r.available, true); assert.equal(r.capped, false); assert.equal(r.total, rows.length);
  const f = await A.events({ hours: 24, action: 'failed' }); assert.equal(f.total, 12); assert.equal(f.filter.action, 'failed');
  const p = await A.events({ action: 'privileged', user: 'SYS' }); assert.equal(p.items.length, 2);
  const q = await A.events({ q: 'orders' }); assert.equal(q.items.length, 1); assert.equal(q.items[0].object, 'APP.ORDERS');
  const off = await createAuditReport({}).report({}); assert.equal(off.available, false);
});

test('RAC: database view reads every instance of the database; coverage per database; instance view stays per instance', async () => {
  const seen = [];
  const ch = { query: async (sql, params) => { seen.push({ sql, params }); if (/db-audit:rows/.test(sql)) return rows.slice(0, 3).map((e) => Object.assign({}, e, { ts: new Date(e.ts).toISOString().replace('T', ' ').replace('Z', ''), fields: Object.assign({}, e.fields, { instance: 'ESP1' }) })); if (/db-audit:posture/.test(sql)) return []; return [{ i: 'ESP1' }, { i: 'ESP2' }, { i: 'ODS' }]; } };
  const dbInstances = () => [{ instance: 'ESP1', db_name: 'esp' }, { instance: 'ESP2', db_name: 'ESP' }, { instance: 'ODS', db_name: 'ODS' }];
  const A = createAuditReport({ ch, now: () => Date.UTC(2026, 9, 23, 12), dbInstances });
  const r = await A.report({ database: 'esp' });
  assert.deepEqual([...seen[0].params.insts.value].sort(), ['ESP', 'ESP1', 'ESP2'], 'both RAC instances read');
  assert.deepEqual(r.scope.instances.sort(), ['ESP', 'ESP1', 'ESP2']);
  assert.equal(r.view, 'database');
  const all = await A.report({});
  const esp = all.coverage_db.find((c) => c.database === 'ESP');
  assert.deepEqual(esp.instances, ['ESP1', 'ESP2']); assert.deepEqual(esp.silent, ['ESP2']); assert.equal(esp.events, 3);
  const cov = all.findings.filter((f) => f.area === 'Coverage').map((f) => f.title);
  assert.ok(!cov.some((t) => /ESP/.test(t)), 'ESP1 reading the shared trail covers database ESP: ' + cov);
  assert.ok(cov.some((t) => /^ODS: no audit record/.test(t)), 'a silent single-instance database is said');
  assert.ok(all.privileged.concat(all.accounts, all.schema_changes).every((x) => x.database === 'ESP'), 'rows carry their database');
  const inst = await A.report({ view: 'instance' });
  assert.ok(inst.findings.some((f) => /^ESP2: no audit record/.test(f.title)), 'instance view: the silent instance is listed');
  const none = await createAuditReport({ ch, dbInstances: () => { throw new Error('dba off'); } }).report({});
  assert.ok(none.coverage_db.some((c) => c.database === 'ESP1'), 'no db_name reading: each instance is its own database (never guessed from the name)');
});

test('Database Audit routes: database / instance / view validated (400 names the field), analyst and up, audited with the scope', async () => {
  const routes = require('../engine/db-audit/routes'), R = {}, calls = [];
  const rep = { report: async (q) => { calls.push(q); return { total: 0, hours: 24, view: q.view || 'database' }; }, events: async (q) => ({ items: [], filter: {} }) };
  const st = { collection: () => ({ get: () => null, put: () => null, all: () => [], find: () => [] }) };
  routes.register({ route: (m, p, h) => { R[m + ' ' + p] = h; } }, { state: st, config: {}, log: { info() {}, warn() {}, error() {}, child() { return this; } }, oracle: {}, oracle_perf: {}, oracle_audit_report: rep });
  const h = Object.entries(R).find(([k]) => /GET .*\/db\/oracle\/audit$/.test(k))[1];
  const ctx = (role, query) => { const c = { role, user: 'u.syn', query: query || {}, code: 200, aud: [], audit(a, t, d) { c.aud.push([a, t, d]); }, need(r) { const K = { viewer: 0, analyst: 1, operator: 2, admin: 3 }; if (K[role] < K[r]) { c.code = 403; return false; } return true; }, ok: (x) => x, fail(code, msg) { c.code = code; c.msg = msg; return { error: msg }; } }; return c; };
  let c = ctx('viewer', { database: 'ESP' }); await h(c); assert.equal(c.code, 403, 'viewer refused (named people)');
  c = ctx('analyst', { database: 'ESP', view: 'database' }); await h(c); assert.equal(c.code, 200); assert.equal(calls[0].database, 'ESP');
  assert.deepEqual(c.aud[0].slice(0, 2), ['oracle.audit.view', 'ESP'], 'audited with the database');
  c = ctx('analyst', { database: "ESP' OR 1=1" }); await h(c); assert.equal(c.code, 400); assert.match(c.msg, /database must be/);
  c = ctx('analyst', { view: 'rac' }); await h(c); assert.equal(c.code, 400); assert.match(c.msg, /view/);
  c = ctx('analyst', { database: 'ESP', instance: 'ESP1' }); await h(c); assert.equal(c.code, 400); assert.match(c.msg, /not both/);
});
