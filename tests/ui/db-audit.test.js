// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for db-audit.html with the REAL SIEM report module (sentra-siem engine/db-audit/audit-report.js) over a fake
// ClickHouse holding unified-audit rows parsed by the real oracle-health parser. Checks: tiles, findings (audit disabled,
// DBA grant, failed-logon burst, off-hours, missing policies, coverage), each tab, activity search (server-side filter),
// the Excel report (a real .xlsx with every sheet and the filter written in), and the role refusal.
// Run: SENTRA_SIEM_DIR=/home/user/sentra-siem PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node db-audit.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const DASH = path.resolve(__dirname, '../../ui');
const SIEM = process.env.SENTRA_SIEM_DIR || path.resolve(__dirname, '../../backend/siem');
const OH = require(path.join(SIEM, 'engine/db-audit/oracle-health')), { createAuditReport } = require(path.join(SIEM, 'engine/db-audit/audit-report'));
let n = 0, bad = 0;
const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };

(async () => {
  const ev = (row) => OH.parse(JSON.stringify(Object.assign({ kind: 'unified_audit', collector: 'sentra-oracle-itam', host: 'eskauat', instance: 'ESS', db_name: 'ESS' }, row)));
  const now = Date.now(), iso = (msAgo) => new Date(now - msAgo).toISOString().replace('Z', '') + '000Z';
  const rows = [];
  for (let i = 0; i < 15; i++) rows.push(ev({ EVENT_TIMESTAMP_UTC: iso(3600000), DBUSERNAME: 'APP_ERP', ACTION_NAME: 'LOGON', RETURN_CODE: '1017', USERHOST: '10.1.1.50', CLIENT_PROGRAM_NAME: 'JDBC Thin Client', SESSIONID: String(i) }));
  rows.push(ev({ EVENT_TIMESTAMP_UTC: iso(7200000), DBUSERNAME: 'SYS', ACTION_NAME: 'NOAUDIT POLICY', RETURN_CODE: '0', SQL_TEXT: 'NOAUDIT POLICY ora_logon_failures', SYSTEM_PRIVILEGE_USED: 'SYSDBA' }));
  rows.push(ev({ EVENT_TIMESTAMP_UTC: iso(7300000), DBUSERNAME: 'DBA_RASHEED', ACTION_NAME: 'GRANT', RETURN_CODE: '0', SQL_TEXT: 'GRANT DBA TO app_report', SYSTEM_PRIVILEGE_USED: 'GRANT ANY ROLE' }));
  rows.push(ev({ EVENT_TIMESTAMP_UTC: iso(7400000), DBUSERNAME: 'APP_OWNER', ACTION_NAME: 'ALTER TABLE', RETURN_CODE: '0', OBJECT_SCHEMA: 'APP', OBJECT_NAME: 'ORDERS' }));
  // a RAC database ESP (instances ESP1 / ESP2): only ESP1 read the shared trail
  rows.push(ev({ instance: 'ESP1', db_name: 'ESP', EVENT_TIMESTAMP_UTC: iso(1800000), DBUSERNAME: 'DBA_SYN', ACTION_NAME: 'CREATE USER', RETURN_CODE: '0', OBJECT_NAME: 'RAC_SYN', SYSTEM_PRIVILEGE_USED: 'CREATE USER' }));
  const ch = { query: async (sql, params) => {
    const want = params && params.insts ? params.insts.value : [];
    if (/db-audit:rows/.test(sql)) return rows.filter((e) => !want.length || want.includes(String(e.fields.instance).toUpperCase())).map((e) => Object.assign({}, e, { ts: new Date(e.ts).toISOString().replace('T', ' ').replace('Z', '') }));
    if (/db-audit:posture/.test(sql)) return [{ i: 'ESS', f: { unified_pure: 'TRUE', policies: 'ORA_SECURECONFIG', cleanup_jobs: '1' }, t: new Date(now - 600000).toISOString().replace('T', ' ').replace('Z', '') }];
    return [{ i: 'ESS' }, { i: 'HRP' }, { i: 'ESP1' }, { i: 'ESP2' }];
  } };
  const A = createAuditReport({ ch, dbInstances: () => [{ instance: 'ESP1', db_name: 'ESP' }, { instance: 'ESP2', db_name: 'ESP' }, { instance: 'ESS', db_name: 'ESS' }] });
  let ROLE = 'analyst'; const audited = [];
  const srv = http.createServer(async (req, res) => {
    const u = new URL(req.url, 'http://x'), json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u.pathname === '/dashboards/whoami.json') return json(200, { user: 'syed', role: ROLE });
    if (u.pathname.startsWith('/api/soc/db/oracle/audit')) {
      if (ROLE === 'viewer') return json(403, { error: 'analyst or above' });
      const q = Object.fromEntries(u.searchParams);
      if (u.pathname.endsWith('/events')) { audited.push(q.export ? 'export' : 'search'); return json(200, await A.events(q)); }
      audited.push('view'); return json(200, await A.report(q));
    }
    if (u.pathname.startsWith('/api/')) return json(404, { error: 'not in this test' });
    fs.readFile(path.join(DASH, u.pathname), (err, d) => { if (err) { res.writeHead(404); res.end(); return; } res.writeHead(200, { 'Content-Type': u.pathname.endsWith('.js') ? 'application/javascript' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port + '/';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch();
  const ctx = await browser.newContext({ acceptDownloads: true, viewport: { width: 1400, height: 900 } });
  const page = await ctx.newPage(); const errs = [];
  page.on('pageerror', (x) => errs.push(x.message));
  page.on('console', (m) => { if (m.type() === 'error' && !/40[34]/.test(m.text())) errs.push(m.text()); });

  await page.goto(base + 'db-audit.html'); await page.waitForSelector('#kk .t');
  const kk = await page.$eval('#kk', (x) => x.innerText.replace(/\s+/g, ' '));
  ok(/Audit events 19/i.test(kk) && /Failed logons 15/i.test(kk) && /Audit tampering 1/i.test(kk), 'tiles: ' + kk);
  const f = await page.$eval('#body', (x) => x.innerText);
  ok(/sys disabled auditing on ESS/.test(f), 'finding: audit disabled');
  ok(/dba_rasheed granted DBA to app_report/.test(f), 'finding: DBA grant');
  ok(/15 failed logons for app_erp on ESS from 10\.1\.1\.50/.test(f), 'finding: failed logons');
  ok(/ESS: ORA_LOGON_FAILURES is not enabled/.test(f), 'finding: missing policy');
  ok(/HRP: no audit record received in the period/.test(f), 'finding: coverage');
  ok(await page.$$eval('#inst option', (o) => o.map((x) => x.value).join(',')) === ',ESP,ESS,HRP', 'database selector: RAC instances as one database');
  ok(/ESP \(ESP1, ESP2\)/.test(await page.$eval('#inst', (x) => x.innerText)), 'the database names its instances');
  ok(!/ESP2: no audit record/.test(f) && !/ESP[^:]*: no audit record/.test(f), 'ESP1 reading the shared trail covers database ESP');
  // by instance: the silent RAC instance is listed; back to by database, then one database
  await page.selectOption('#view', 'instance'); await page.waitForFunction(() => /ESP2: no audit record/.test(document.getElementById('body').innerText));
  ok(await page.$$eval('#inst option', (o) => o.map((x) => x.value).join(',')) === ',ESP1,ESP2,ESS,HRP', 'by instance: every instance');
  await page.selectOption('#view', 'database'); await page.waitForFunction(() => !/ESP2: no audit record/.test(document.getElementById('body').innerText) && /Audit events 19/i.test(document.getElementById('kk').innerText.replace(/\s+/g, ' ')));
  await page.selectOption('#inst', 'ESP'); await page.waitForFunction(() => /Audit events 1\b/i.test(document.getElementById('kk').innerText.replace(/\s+/g, ' ')));
  await page.click('[data-tab="acct"]'); let rt = await page.$eval('#body', (x) => x.innerText);
  ok(/dba_syn/i.test(rt) && /ESP1/.test(rt) && !/app_report/.test(rt), 'one database: only its rows, the instance shown under it');
  await page.click('[data-tab="config"]'); rt = await page.$eval('#body', (x) => x.innerText);
  ok(/read through ESP1/.test(rt), 'coverage per database says which instance read the trail');
  ok(await page.$$eval('#inst option', (o) => o.length) === 4, 'the list stays complete while one database is chosen');
  await page.selectOption('#inst', ''); await page.waitForFunction(() => /Audit events 19/i.test(document.getElementById('kk').innerText.replace(/\s+/g, ' ')));
  await page.click('[data-tab="overview"]');

  await page.click('[data-tab="failed"]'); let t = await page.$eval('#body', (x) => x.innerText);
  ok(/app_erp/.test(t) && /10\.1\.1\.50/.test(t) && /15/.test(t), 'failed logons tab');
  await page.click('[data-tab="acct"]'); t = await page.$eval('#body', (x) => x.innerText);
  ok(/GRANT DBA TO app_report/.test(t) && /NOAUDIT POLICY ora_logon_failures/.test(t), 'accounts + tampering tab');
  await page.click('[data-tab="changes"]'); t = await page.$eval('#body', (x) => x.innerText);
  ok(/APP\.ORDERS/.test(t), 'schema changes tab');
  await page.click('[data-tab="config"]'); t = await page.$eval('#body', (x) => x.innerText);
  ok(/ORA_SECURECONFIG/.test(t) && /none received/.test(t), 'configuration + coverage tab');
  await page.click('[data-tab="activity"]'); await page.waitForSelector('#alist table');
  await page.fill('#aq', 'orders'); await page.click('#ago');
  await page.waitForFunction(() => /1 matching/.test(document.getElementById('ac').textContent));
  ok((await page.$$eval('#alist tbody tr', (r) => r.length)) === 1, 'activity search filtered on the server');

  const [dl] = await Promise.all([page.waitForEvent('download'), page.click('#xlsx')]);
  const file = await dl.path(), buf = fs.readFileSync(file);
  ok(buf.slice(0, 2).toString() === 'PK' && /^database-audit-\d{4}-\d\d-\d\d\.xlsx$/.test(dl.suggestedFilename()), 'a real .xlsx: ' + dl.suggestedFilename());
  const txt = buf.toString('latin1');
  for (const sh of ['Summary', 'Findings', 'Failed logons', 'Privileged', 'Accounts &amp; grants', 'Audit tampering', 'Schema changes', 'Config changes', 'Outside working hours', 'Audit configuration', 'Coverage', 'All activity']) ok(txt.includes('name="' + sh + '"'), 'sheet ' + sh);
  ok(audited.includes('export'), 'the export is requested as an export (audited on the SIEM)');

  ROLE = 'viewer'; await page.goto(base + 'db-audit.html'); await page.waitForSelector('#body .err');
  ok(/Analysts, operators and administrators only/.test(await page.$eval('#body', (x) => x.innerText)), 'viewer refused');
  ok(!errs.length, 'page errors: ' + errs.join(' | '));
  await browser.close(); srv.close();
  console.log(bad ? 'FAILED ' + bad + ' of ' + n : 'OK ' + n + ' checks'); process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
