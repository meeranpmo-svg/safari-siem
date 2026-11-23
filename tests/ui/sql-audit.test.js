// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// SQL Server Audit (sql-audit.html), stubbed SIEM API, SYNTHETIC instances: KPI tiles and findings from the report; a tile opens
// its section; the sections (failed logins, permissions, audit changes, after hours, coverage) list their records; a record
// opens its detail with the masked statement; the instance and period reach the API; the Activity search sends its filters
// and exports CSV; a hostile value stays text; an empty period says what to set up (no invented rows); a 403 is explained;
// no browser dialog, no page error.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node sql-audit.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const DASH = path.resolve(__dirname, '../../ui');
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const Q = [];
let MODE = 'data';
const rec = (o) => Object.assign({ ts: '2026-10-20T20:30:00.000Z', event_code: '33205', host: 'SQL01', instance: 'SQL01\\FIN', database: 'FinanceSyn', object: '', action_id: '', class_type: '', user: 'syn\\dba.syn', target: '', client_ip: '10.250.1.5', client_host: 'ws-dba', application: 'SSMS', outcome: 'success', reason: '', statement: '', action_name: '', category: '' }, o);
const PERM = rec({ action_id: 'APRL', class_type: 'SG', object: 'sysadmin', target: 'app_report', action_name: 'role member added', category: 'permission', statement: 'ALTER SERVER ROLE [sysadmin] ADD MEMBER [app_report]' });
const AUD = rec({ action_id: 'AL', class_type: 'A', object: 'Audit_Syn', action_name: 'ALTER', category: 'audit', statement: 'ALTER SERVER AUDIT [Audit_Syn] WITH (STATE = OFF)' });
const ACC = rec({ ts: '2026-10-20T07:00:00.000Z', action_id: 'CR', class_type: 'SL', object: '<img src=x onerror=window.PWN=1>app_report', action_name: 'CREATE', category: 'account', statement: "CREATE LOGIN [app_report] WITH PASSWORD = '***'" });
const REPORT = { available: true, generated_at: '2026-10-23T12:00:00.000Z', hours: 168, capped: false, total: 20,
  summary: { events: 20, audit_records: 19, instances: 2, users: 3, failed_logins: 13, permission_changes: 1, account_changes: 1, schema_changes: 0, audit_changes: 1, config_changes: 0, off_hours_admin: 2, critical: 1, high: 1 },
  failed_logins: [{ instance: 'SQL01\\FIN', user: 'app_erp', client: '10.250.1.50', application: 'ERP Synthetic', reason: 'bad password', count: 12, first: '2026-10-20T07:00:00.000Z', last: '2026-10-20T07:05:00.000Z' }],
  permissions: [PERM], accounts: [ACC], schema_changes: [], audit_changes: [AUD], config_changes: [], off_hours: [PERM, AUD], users: [],
  coverage: [{ host: 'SQL01', instances: ['SQL01\\FIN'], audit_records: 19, login_events: 0, last: '2026-10-20T20:30:00.000Z' }, { host: 'SQL02', instances: ['SQL02'], audit_records: 0, login_events: 1, last: '2026-10-20T07:00:00.000Z' }],
  findings: [{ severity: 'critical', area: 'Audit tampering', title: 'syn\\dba.syn stopped Audit_Syn on SQL01\\FIN', recommendation: 'Turn the audit back on.', evidence: ['2026-10-20T20:30:00.000Z'] },
    { severity: 'medium', area: 'Coverage', title: 'SQL02: login events arrive but no SQL Server Audit record in the period', recommendation: 'Create a SERVER AUDIT TO APPLICATION_LOG.', evidence: [] }] };
const EMPTY = { available: true, generated_at: '2026-10-23T12:00:00.000Z', hours: 168, total: 0, summary: {}, failed_logins: [], permissions: [], accounts: [], schema_changes: [], audit_changes: [], config_changes: [], off_hours: [], users: [], coverage: [], findings: [] };
(async () => {
  const srv = http.createServer((q, r) => {
    const u = q.url.split('?')[0], j = (c, o) => { r.writeHead(c, { 'Content-Type': 'application/json' }); r.end(JSON.stringify(o)); };
    if (u.endsWith('whoami.json')) return j(200, { user: 'syed', role: 'analyst' });
    if (u.startsWith('/api/soc/db/mssql/')) { Q.push(q.url); if (MODE === 'deny') return j(403, { error: 'forbidden' }); }
    if (u === '/api/soc/db/mssql/audit') return j(200, MODE === 'empty' ? EMPTY : REPORT);
    if (u === '/api/soc/db/mssql/audit/events') return j(200, { available: true, hours: 168, total: 3, items: [PERM, AUD, ACC], filter: {} });
    if (u.startsWith('/api/')) return j(404, { error: 'not in this test' });
    fs.readFile(path.join(DASH, u.replace(/^\/dashboards\//, '/')), (e, d) => { if (e) { r.writeHead(404); return r.end(); } r.writeHead(200, { 'Content-Type': u.endsWith('.js') ? 'application/javascript' : u.endsWith('.css') ? 'text/css' : 'text/html' }); r.end(d); });
  });
  await new Promise((res) => srv.listen(0, '127.0.0.1', res));
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  const ctx = await browser.newContext({ viewport: { width: 1500, height: 900 }, acceptDownloads: true });
  const p = await ctx.newPage(); p.on('pageerror', (e) => errs.push(e.message)); p.on('dialog', (d) => { errs.push('dialog: ' + d.message()); d.dismiss(); });
  const wait = (fn, a) => p.waitForFunction(fn, a, { timeout: 10000 }).then(() => true, () => false);
  const waitQ = async (re) => { for (let i = 0; i < 200; i++) { if (re.test(Q[Q.length - 1] || '')) return true; await new Promise((r) => setTimeout(r, 50)); } return false; };
  const drawer = () => p.evaluate(() => (document.getElementById('zd-b') || {}).innerText || '');
  const url = 'http://127.0.0.1:' + srv.address().port + '/sql-audit.html?standalone=1';
  try {
    await p.goto(url);
    ok(await wait(() => document.querySelectorAll('#kpi [data-go]').length === 9), 'KPI tiles from the report');
    ok((await p.title()) === 'SQL Server Audit', 'page title');
    ok(/hours=168/.test(Q[0]), 'the default period (7 days) is sent');
    const f = await p.textContent('#find'); ok(/critical/i.test(f) && /stopped Audit_Syn/.test(f) && /SQL02: login events arrive but no SQL Server Audit record/.test(f), 'findings: audit stopped, coverage gap');
    ok(/app_erp/.test(await p.textContent('#sec')) && /12/.test(await p.textContent('#sec')), 'failed logins grouped');
    await p.click('#kpi [data-go="permissions"]'); ok(await wait(() => /role member added/.test(document.getElementById('sec').innerText)) && /Permission changes/.test(await p.textContent('#st')), 'a tile opens its section');
    await p.click('#sec tr[data-r="0"]'); ok(await wait(() => /ALTER SERVER ROLE \[sysadmin\]/.test((document.getElementById('zd-b') || {}).innerText || '')) && /password literals masked/i.test(await drawer()), 'a record opens with its statement');
    await p.evaluate(() => window.zybDetail.close());
    await p.click('[data-tab="audit"]'); ok(/STATE = OFF/.test(await p.textContent('#sec')), 'audit changes');
    await p.click('[data-tab="offhours"]'); ok((await p.$$('#sec tr[data-r]')).length === 2 && /Sunday to Thursday/.test(await p.textContent('#sn')), 'after-hours administrative work with the working hours said');
    await p.click('[data-tab="accounts"]'); ok(/<img src=x/.test(await p.textContent('#sec')) && !(await p.evaluate(() => window.PWN)) && !(await p.$('#sec img')), 'a hostile value stays text');
    await p.click('[data-tab="coverage"]'); ok(/no audit record/.test(await p.textContent('#sec')) && /SQL02/.test(await p.textContent('#sec')), 'coverage per server');
    // instance filter
    await p.selectOption('#inst', 'SQL01\\FIN'); ok(await waitQ(/instance=SQL01%5CFIN/), 'the instance reaches the API');
    // activity search + export
    await p.click('[data-tab="activity"]'); ok(await wait(() => document.querySelectorAll('#actt tr[data-r]').length === 3), 'activity lists the records');
    await p.selectOption('#cat', 'off-hours'); await p.fill('#usr', 'syn\\dba.syn'); await p.fill('#q', 'sysadmin'); await p.click('#go');
    ok(await waitQ(/category=off-hours/) && /user=syn%5Cdba\.syn/.test(Q[Q.length - 1]) && /q=sysadmin/.test(Q[Q.length - 1]), 'the activity filters reach the API');
    const [dl] = await Promise.all([p.waitForEvent('download', { timeout: 10000 }), p.click('#exp')]);
    const csv = fs.readFileSync(await dl.path(), 'utf8');
    ok(/export=1/.test(Q[Q.length - 1]) && /Statement \(masked\)/.test(csv) && /PASSWORD = '\*\*\*'/.test(csv), 'CSV export (marked as an export, masked statements)');
    // empty period: says what to set up, invents nothing
    MODE = 'empty'; await p.click('#refresh');
    ok(await wait(() => /No SQL Server audit record or login event in this period/.test(document.getElementById('find').innerText)), 'an empty period says what to set up');
    await p.click('[data-tab="failed"]'); ok(/No failed login in this period/.test(await p.textContent('#sec')), 'no invented rows');
    MODE = 'deny'; await p.click('#refresh');
    ok(await wait(() => /needs the analyst role or above/.test(document.getElementById('find').innerText)), 'a 403 is explained');
    ok(!errs.length, 'no page errors or dialogs: ' + errs.join(' | '));
  } finally { await browser.close(); srv.close(); }
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks'); process.exit(bad ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });
