// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Databases page: a database whose monitoring account lacks grants says, in short, how many readings need a grant and that the
// status changes by itself; "How to fix" lists every failed reading by who fixes it (DBA grant / platform query error / timeout)
// with ONE read-only script naming the real account (built by the REAL engine/db-health.js missingDetail); after the DBA ran it,
// "Check again now" turns the status healthy. A database whose only problem is a platform query error reads "update pending"
// and is not counted as needing attention. Stub API, SYNTHETIC names.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node databases-fix.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const DASH = path.resolve(__dirname, '../../ui');
const { missingDetail, fixScript } = require(path.resolve(__dirname, '../../backend/itam/engine/db-health'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const ERR = [{ query: 'sessions', error: 'ORA-00937: not a single-group group function', ora: 'ORA-00937' }, { query: 'gg_capture', error: 'ORA-00942: table or view does not exist', ora: 'ORA-00942' },
  { query: 'dg_broker', error: 'ORA-00942', ora: 'ORA-00942' }, { query: 'audit_trail', error: 'ORA-01031: insufficient privileges', ora: 'ORA-01031' }];
const MD = missingDetail(ERR, 'ZYB_MONITOR'), MD2 = missingDetail([ERR[0]], 'ZYB_MONITOR');
const at = new Date(Date.now() - 120000).toISOString();
const res = (host, md) => ({ ip: host, host, ok: true, instance: host === '192.0.2.31' ? 'ESP2' : 'ODS', records: 127, at, account: 'ZYB_MONITOR', missing: md.map((m) => m.query), missing_detail: md, fix_script: fixScript(md) });
const DBS = [{ id: 'odb_1', label: 'ESKAPROD', host: '192.0.2.31', port: 1521, service: 'esp.example.test', credential: 'oracle-ESKAPROD', cred_id: 'c1', login_shared_with: [], last_test: null, paused: null },
  { id: 'odb_2', label: 'ODSPROD', host: '192.0.2.50', port: 1521, service: 'ODS', credential: 'oracle-ODS', cred_id: 'c2', login_shared_with: [], last_test: null, paused: null }];
let ROLE = 'admin', tested = 0;
(async () => {
  const srv = http.createServer((req, res2) => { const u = req.url.split('?')[0]; const json = (c, b) => { res2.writeHead(c, { 'Content-Type': 'application/json' }); res2.end(JSON.stringify(b)); };
    if (u === '/dashboards/whoami.json') return json(200, { user: 'syed', role: ROLE });
    if (u === '/api/itam/db-health') return json(200, { enabled: true, interval_min: 4, last: { at, results: [res('192.0.2.31', MD), res('192.0.2.50', MD2)] } });
    if (u === '/api/itam/db-health/databases') return json(200, { databases: DBS, credentials: [], dismissed: [] });
    if (u === '/api/itam/db-health/databases/odb_1/test' && req.method === 'POST') { tested++; DBS[0].last_test = { at: new Date().toISOString(), ok: true, instance: 'ESP2', records: 140, missing: [], missing_detail: [], fix_script: [] }; return json(200, { database: DBS[0] }); }
    if (u.startsWith('/api/itam/discovery/results')) return json(200, { devices: [] });
    if (u === '/api/itam/discovery/credentials') return json(200, { credentials: [] });
    if (u.startsWith('/api/')) return json(404, { error: 'x' });
    fs.readFile(path.join(DASH, u.replace(/^\/dashboards\//, '/')), (e, d) => { if (e) { res2.writeHead(404); return res2.end(); } res2.writeHead(200, { 'Content-Type': u.endsWith('.js') ? 'application/javascript' : u.endsWith('.css') ? 'text/css' : 'text/html' }); res2.end(d); }); });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r)); const base = 'http://127.0.0.1:' + srv.address().port + '/';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright'); const browser = await chromium.launch();
  const ctx = await browser.newContext({ viewport: { width: 1400, height: 900 } }); await ctx.grantPermissions(['clipboard-read', 'clipboard-write']);
  const p = await ctx.newPage(); const errs = []; p.on('pageerror', (e) => errs.push(e.message));
  try {
    await p.goto(base + 'databases.html?standalone=1'); await p.waitForSelector('[data-fix="odb_1"]');
    const row = await p.$eval('#tbl', (x) => x.innerText);
    ok(/3 readings need a grant \(your DBA runs the fix script\)/.test(row) && /1 refused by this Oracle release \(fixed by the platform update, nothing for the DBA\)/.test(row), 'short summary by who fixes it: ' + row.slice(0, 400));
    ok(/changes by itself/.test(row), 'says the status changes by itself');
    ok(!/GRANT SELECT/.test(row), 'no wall of grants in the table');
    ok(/update pending/.test(row), 'platform-only problem: update pending, not "check"');
    ok(/Needs attention\s*1/i.test(await p.$eval('#kk', (x) => x.innerText.replace(/\s+/g, ' '))), 'only the database with grants to add needs attention');
    await p.click('[data-fix="odb_1"]'); await p.waitForSelector('#fixsql');
    const sql = await p.textContent('#fixsql'), dr = await p.$eval('#zd-b', (x) => x.innerText);
    ok(/GRANT SELECT ON sys\.v_\$goldengate_capture TO zyb_monitor;/.test(sql) && /GRANT SELECT ON sys\.v_\$dg_broker_config TO zyb_monitor;/.test(sql) && /GRANT AUDIT_VIEWER TO zyb_monitor;/.test(sql), 'one script with the exact grants for the real account');
    ok(!/v_\$session|v_\$parameter/.test(sql), 'the ORA-00937 reading asks the DBA for nothing');
    ok(/Missing grant · 3/i.test(dr) && /Query refused by this Oracle release · 1/i.test(dr) && /ORA-00937/.test(dr), 'readings grouped by who fixes them');
    ok(/GoldenGate Extract/.test(dr) && /Data Guard broker/.test(dr) && /Database Audit/.test(dr), 'each reading named by what it feeds');
    await p.click('[data-copyfix]'); ok(/GRANT AUDIT_VIEWER/.test(await p.evaluate(() => navigator.clipboard.readText())), 'Copy puts the script on the clipboard');
    await p.click('[data-recheck="odb_1"]');
    await p.waitForFunction(() => { const t = document.getElementById('tbl').innerText; return /healthy/.test(t) && !document.querySelector('[data-fix="odb_1"]'); });
    ok(tested === 1, 'Check again read the database once'); ok(/read 140 records/.test(await p.$eval('#tbl', (x) => x.innerText)), 'the newest read decides the status - healthy after the fix');
    ok(/setInterval\(function\(\)\{var zd/.test(fs.readFileSync(path.join(DASH, 'databases.html'), 'utf8')), 'the page refreshes itself every minute');
    // a viewer sees how to fix but cannot press Check again
    ROLE = 'viewer'; DBS[0].last_test = null; await p.goto(base + 'databases.html?standalone=1'); await p.waitForSelector('[data-fix="odb_1"]'); await p.click('[data-fix="odb_1"]'); await p.waitForSelector('#fixsql');
    ok(!(await p.$('[data-recheck]')) && /An administrator can also press Check again now/.test(await p.$eval('#zd-b', (x) => x.innerText)), 'viewer: the fix, no Check again');
    ok(!errs.length, 'page errors: ' + errs.join(' | '));
  } finally { await browser.close(); srv.close(); }
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks'); process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
