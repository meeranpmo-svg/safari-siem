// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// SQL Server Audit (engine/db-audit/mssql-report.js): Application-log event 33205 records and error-log logins (18456) as the
// agent sends them -> parse/windows.js -> the report: failed logins grouped, sysadmin grant, audit stopped, schema / account /
// configuration changes, administrative work outside Riyadh working hours, coverage (logins but no audit record), password
// literals masked; the ClickHouse half (period, instance as parameters); routes (viewer refused, validation, audit). SYNTHETIC.
const test = require('node:test');
const assert = require('node:assert/strict');
const W = require('../engine/parse/windows');
const { summarize, createMssqlReport, classify, maskStatement } = require('../engine/db-audit/mssql-report');

// Tue 2026-10-20 07:00Z = 10:00 Riyadh (working hours); 20:30Z = 23:30 Riyadh; Fri 2026-10-23 08:00Z
const T = { work: '2026-10-20T07:00:00.000Z', night: '2026-10-20T20:30:00.000Z', friday: '2026-10-23T08:00:00.000Z' };
const audit33205 = (at, kv, host) => W.parse(JSON.stringify({ Channel: 'Application', ProviderName: 'MSSQL$FIN', EventID: 33205, TimeCreated: at, Computer: host || 'SQL01.synthetic.test',
  EventData: { Data0: 'Audit event: ' + Object.entries(Object.assign({ server_instance_name: 'SQL01\\FIN', succeeded: 'true', session_server_principal_name: 'SYN\\dba.syn', server_principal_name: 'SYN\\dba.syn' }, kv)).map(([k, v]) => k + ':' + v).join('\n') } }));
const err18456 = (at, user, ip, host) => W.parse(JSON.stringify({ Channel: 'Application', ProviderName: 'MSSQLSERVER', EventID: 18456, TimeCreated: at, Computer: host || 'SQL01.synthetic.test',
  EventData: { Data0: user, Data1: 'Reason: Password did not match that for the login provided.', Data2: '[CLIENT: ' + ip + ']' }, Message: `Login failed for user '${user}'. Reason: Password did not match that for the login provided. [CLIENT: ${ip}]` }));

const rows = [];
for (let i = 0; i < 12; i++) rows.push(audit33205(T.work, { action_id: 'LGIF', succeeded: 'false', server_principal_name: 'app_erp', client_ip: '10.1.1.50', application_name: 'ERP Synthetic', additional_information: 'bad password' }));
rows.push(audit33205(T.night, { action_id: 'APRL', class_type: 'SG', object_name: 'sysadmin', target_server_principal_name: 'app_report', statement: 'ALTER SERVER ROLE [sysadmin] ADD MEMBER [app_report]' }));
rows.push(audit33205(T.night, { action_id: 'AL', class_type: 'A', object_name: 'Audit_Syn', statement: 'ALTER SERVER AUDIT [Audit_Syn] WITH (STATE = OFF)' }));
rows.push(audit33205(T.work, { action_id: 'CR', class_type: 'SL', object_name: 'app_report', statement: "CREATE LOGIN [app_report] WITH PASSWORD = N'Synthetic#Pass1', CHECK_POLICY = OFF" }));
rows.push(audit33205(T.work, { action_id: 'AL', class_type: 'U', database_name: 'FinanceSyn', schema_name: 'dbo', object_name: 'Invoices', statement: 'ALTER TABLE dbo.Invoices ADD note nvarchar(100)' }));
rows.push(audit33205(T.friday, { action_id: 'G', class_type: 'U', database_name: 'FinanceSyn', schema_name: 'dbo', object_name: 'Invoices', target_database_principal_name: 'report_role', statement: 'GRANT SELECT ON dbo.Invoices TO report_role' }));
rows.push(audit33205(T.work, { action_id: 'AL', class_type: 'SR', statement: "EXEC sp_configure 'xp_cmdshell', 1" }));
rows.push(audit33205(T.work, { action_id: 'SL', class_type: 'U', database_name: 'FinanceSyn', object_name: 'Invoices', statement: 'SELECT * FROM dbo.Invoices' }));
rows.push(err18456(T.work, 'sa', '10.9.9.9', 'SQL02.synthetic.test'));

test('parser: 33205 fields (action, class, instance, database, object, statement, client) and 18456', () => {
  const f = rows[0]; assert.equal(f.action, 'logon-failed'); assert.equal(f.outcome, 'failure'); assert.equal(f.user, 'app_erp'); assert.equal(f.src_ip, '10.1.1.50');
  assert.equal(f.fields.sql_action_id, 'LGIF'); assert.equal(f.fields.sql_instance, 'SQL01\\FIN'); assert.ok(f.tags.includes('mssql'));
  const g = rows[12]; assert.equal(g.action, 'group-member-added'); assert.equal(g.target_user, 'app_report'); assert.equal(g.fields.sql_class_type, 'SG');
  assert.equal(rows[15].fields.object, 'dbo.Invoices'); assert.equal(rows[15].fields.database, 'FinanceSyn');
  assert.equal(rows[19].action, 'logon-failed'); assert.equal(rows[19].src_ip, '10.9.9.9'); assert.equal(rows[19].event_code, '18456');
});

test('classify + mask: categories from action / class; password and secret literals never leave the report', () => {
  const c = (action_id, class_type, event_code) => classify({ action_id, class_type, event_code: event_code || '33205' });
  assert.equal(c('LGIF'), 'failed-login'); assert.equal(c('', '', '18456'), 'failed-login'); assert.equal(c('APRL', 'SG'), 'permission'); assert.equal(c('G', 'U'), 'permission');
  assert.equal(c('AL', 'A'), 'audit'); assert.equal(c('AUSC'), 'audit'); assert.equal(c('CR', 'SL'), 'account'); assert.equal(c('PWR', 'SL'), 'account');
  assert.equal(c('AL', 'U'), 'schema'); assert.equal(c('AL', 'SR'), 'config'); assert.equal(c('SL', 'U'), 'data');
  assert.equal(maskStatement("CREATE LOGIN x WITH PASSWORD = N'abc''d', CHECK_POLICY=OFF"), "CREATE LOGIN x WITH PASSWORD = '***', CHECK_POLICY=OFF");
  assert.equal(maskStatement("CREATE CREDENTIAL c WITH IDENTITY='u', SECRET = 'xyz'"), "CREATE CREDENTIAL c WITH IDENTITY='u', SECRET = '***'");
  assert.equal(maskStatement("EXEC sp_addlinkedsrvlogin @rmtsrvname='s', @rmtpassword='pw'"), "EXEC sp_addlinkedsrvlogin @rmtsrvname='s', @rmtpassword='***'");
});

test('report: failed logins grouped, sysadmin grant, audit stopped, changes by section, off-hours admin, coverage, no password', () => {
  const r = summarize(rows, { now: Date.UTC(2026, 9, 23, 12), hours: 168 });
  assert.equal(r.summary.failed_logins, 13); assert.equal(r.failed_logins[0].count, 12); assert.equal(r.failed_logins[0].user, 'app_erp'); assert.equal(r.failed_logins[0].client, '10.1.1.50');
  assert.equal(r.summary.permission_changes, 2); assert.equal(r.summary.audit_changes, 1); assert.equal(r.summary.account_changes, 1); assert.equal(r.summary.schema_changes, 1); assert.equal(r.summary.config_changes, 1);
  const t = r.findings.map((f) => f.severity + ' ' + f.title);
  assert.ok(t.some((x) => /^critical dba\.syn stopped Audit_Syn on SQL01\\FIN/.test(x)), t.join('\n'));
  assert.ok(t.some((x) => /^high dba\.syn gave app_report sysadmin on SQL01\\FIN/.test(x)));
  assert.ok(t.some((x) => /^medium 12 failed logins for app_erp on SQL01\\FIN from 10\.1\.1\.50/.test(x)));
  assert.ok(t.some((x) => /administrative action\(s\) by dba\.syn on SQL01\\FIN outside working hours/.test(x)), 'night + Friday');
  assert.ok(t.some((x) => /^low dba\.syn created login app_report/.test(x)));
  assert.ok(t.some((x) => /^medium SQL02: login events arrive but no SQL Server Audit record/.test(x)), 'coverage: SQL02 sends logins only');
  assert.ok(!JSON.stringify(r).includes('Synthetic#Pass1'), 'the password literal is masked');
  assert.equal(r.off_hours.length, 3); assert.equal(r.findings[0].severity, 'critical');
});

test('ClickHouse half and routes: period / instance as parameters, filters; viewer refused, validation names the field, reads audited', async () => {
  const seen = [];
  const ch = { query: async (sql, params) => { seen.push({ sql, params }); return rows.map((e) => Object.assign({}, e, { ts: new Date(e.ts).toISOString().replace('T', ' ').replace('Z', '') })); } };
  const M = createMssqlReport({ ch, now: () => Date.UTC(2026, 9, 23, 12) });
  const r = await M.report({ hours: 168, instance: 'SQL01\\FIN' });
  assert.equal(seen[0].params.h.value, 168); assert.equal(seen[0].params.i.value, 'sql01\\fin'); assert.match(seen[0].sql, /has\(tags, 'mssql'\)/); assert.equal(r.available, true);
  assert.equal((await M.events({ category: 'failed' })).total, 13);
  assert.equal((await M.events({ category: 'off-hours' })).total, 3);
  assert.equal((await M.events({ category: 'schema', q: 'invoices' })).items[0].object, 'dbo.Invoices');
  assert.equal((await createMssqlReport({}).report({})).available, false);
  const routes = require('../engine/db-audit/mssql-routes'), R = {};
  routes.register({ route: (m, p, h) => { R[m + ' ' + p] = h; } }, { config: {}, mssql_audit_report: M });
  const call = async (p, role, query) => { const c = { role, user: role + '.syn', query: query || {}, code: 200, aud: [], audit(a, t, d) { c.aud.push([a, t, d]); }, need(x) { const K = { viewer: 0, analyst: 1, operator: 2, admin: 3 }; if (K[role] < K[x]) { c.code = 403; return false; } return true; }, ok: (x) => { c.res = x; return x; }, fail(code, msg) { c.code = code; c.msg = msg; return { error: msg }; } }; await R['GET /api/soc' + p](c); return c; };
  let c = await call('/db/mssql/audit', 'viewer'); assert.equal(c.code, 403, 'viewer refused (named people)');
  c = await call('/db/mssql/audit', 'analyst', { hours: '24', instance: 'SQL01\\FIN' }); assert.equal(c.code, 200); assert.deepEqual(c.aud[0].slice(0, 2), ['mssql.audit.view', 'SQL01\\FIN']);
  c = await call('/db/mssql/audit/events', 'analyst', { category: 'permission', export: '1' }); assert.equal(c.res.total, 2); assert.equal(c.aud[0][0], 'mssql.audit.export');
  c = await call('/db/mssql/audit/events', 'analyst', { category: 'everything' }); assert.equal(c.code, 400); assert.match(c.msg, /category must be one of/);
  c = await call('/db/mssql/audit', 'analyst', { instance: "x' OR 1=1" }); assert.equal(c.code, 400); assert.match(c.msg, /instance must be/);
  c = await call('/db/mssql/audit', 'analyst', { hours: '0' }); assert.equal(c.code, 400); assert.match(c.msg, /hours must be at least 1/);
});
