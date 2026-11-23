// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// AI Oracle DBA page → Overview (dashboards/server/ai-dba.html + vendor/zyb-teamviz.js estate()) over a STUBBED API with
// SYNTHETIC databases: the AI Oracle DBA in the middle with its own duty state, every Oracle database around it - health from
// the SIEM's Oracle summary joined with the database inventory (PDBs, size) - each moving by its real state (radar = healthy,
// amber = needs attention, red + dots to the DBA = problems, grey = not reporting / login refused), an inventory-only
// database shown as such, changes waiting for a DBA, a hostile instance name stays text, a viewer still sees the health side.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node ai-dba-overview.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const DASH = path.join(__dirname, '..', '..', 'ui');
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const NOW = new Date().toISOString();
const ORA = { generated_at: NOW, totals: { instances: 4, down: 1, stale: 1, with_issues: 2 }, instances: [
  { instance: 'ORCL1', host: 'ora-syn-01', version: '19.0.0', up: true, status: 'OPEN', open_mode: 'READ WRITE', role: 'PRIMARY', issues: [], worst_severity: 0, sessions: { total: 80, max_sessions: 400 } },
  { instance: 'ERP1', host: 'erp-syn-01', up: true, status: 'OPEN', role: 'PRIMARY', issues: [{ text: 'tablespace USERS 92% full' }], worst_severity: 2 },
  { instance: 'HR1', host: 'hr-syn-01', up: false, status: 'MOUNTED', state: 'down', issues: [{ text: 'instance is not open' }, { text: 'backup failed' }], worst_severity: 4 },
  { instance: '<img src=x onerror=alert(1)>', host: 'old-syn-01', stale: true, up: false, issues: [] }] };
const INV = { servers: [
  { id: 'oracle|10.9.1.21|1521', engine: 'oracle', ip: '10.9.1.21', host: 'ORA-SYN-01', server: { instance: 'ORCL1', host_name: 'ora-syn-01' }, totals: { databases: 3, size_mb: 409600 }, notes: [] },
  { id: 'oracle|10.9.1.40|1521', engine: 'oracle', ip: '10.9.1.40', host: 'DWH-SYN', asset_name: 'DWH-SYN', server: { instance: 'DWH1', host_name: 'dwh-syn' }, totals: { databases: 1, size_mb: 2048000 }, notes: [{ severity: 'medium', text: 'NOARCHIVELOG' }] },
  { id: 'oracle|10.9.1.50|1521', engine: 'oracle', ip: '10.9.1.50', host: 'FIN-SYN', asset_name: 'FIN-SYN', error: 'ORA-01017', error_class: 'auth', server: {}, notes: [] },
  { id: 'mssql|10.9.0.11|1433', engine: 'mssql', ip: '10.9.0.11', host: 'SQL-SYN-01', server: {}, totals: { databases: 2, size_mb: 100 }, notes: [] }] };
let ROLE = 'operator';

(async () => {
  const srv = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://x'), json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u.pathname === '/dashboards/whoami.json') return json(200, { user: 'syn.user', role: ROLE });
    if (u.pathname === '/api/soc/db/oracle') return json(200, ORA);
    if (u.pathname === '/api/itam/db-inventory') return ROLE === 'viewer' ? json(403, { error: 'requires operator' }) : json(200, INV);
    if (u.pathname === '/api/soc/duty/engineers') return json(200, { engineers: [{ id: 'dba', name: 'AI Oracle DBA', on_duty: true, open: 5, by_status: { open: 3, 'awaiting-approval': 2 } }], policy: {} });
    if (u.pathname.startsWith('/api/soc/duty/')) return json(200, { items: [], reports: [], engineers: [] });
    if (u.pathname.startsWith('/api/')) return json(404, { error: 'not in this test' });
    const f = path.join(DASH, u.pathname.replace(/^\/dashboards\//, '/')); if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (err, d) => { if (err) { res.writeHead(404); res.end(); return; } res.writeHead(200, { 'Content-Type': u.pathname.endsWith('.js') ? 'application/javascript' : u.pathname.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port + '/';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  const wait = (p, fn, arg) => p.waitForFunction(fn, arg, { timeout: 15000 }).then(() => true, () => false);
  const node = (p, id) => p.$('#floor .tv-n[data-node="' + id + '"]');
  const cls = async (p, id) => (await node(p, id)).getAttribute('class');
  try {
    const p = await browser.newPage({ viewport: { width: 1440, height: 1000 } }); p.on('pageerror', (x) => errs.push(x.message));
    await p.goto(base + 'ai-dba.html?standalone=1');
    ok(await wait(p, () => document.querySelectorAll('#floor .tv-n').length === 6), 'four SIEM instances + two inventory-only Oracle databases (SQL Server left out)');
    ok(/AI Oracle DBA/.test(await p.textContent('#floor .tv-core')) && /on duty · 5 open/.test(await p.textContent('#floor .tv-core')), 'the DBA in the middle with its duty state');
    ok(/2 changes waiting for a DBA to approve/.test(await p.textContent('#floor .tv-hum')), 'changes waiting for a person');
    ok(/idle/.test(await cls(p, 'i:ORCL1@ora-syn-01')) && !!(await p.$('[data-node="i:ORCL1@ora-syn-01"] .tv-radar')), 'healthy: radar');
    ok(/3 DBs · 400\.0 GB/.test(await p.textContent('[data-node="i:ORCL1@ora-syn-01"]')), 'health joined with the inventory (PDBs, size)');
    ok(/tv-warn/.test(await cls(p, 'i:ERP1@erp-syn-01')) && /1 issue/.test(await p.textContent('[data-node="i:ERP1@erp-syn-01"]')), 'needs attention: amber');
    ok(/tv-bad/.test(await cls(p, 'i:HR1@hr-syn-01')) && /MOUNTED/.test(await p.textContent('[data-node="i:HR1@hr-syn-01"]')), 'down: red');
    ok((await p.$$('#floor svg circle[fill="#ff5c5c"]')).length === 2 && (await p.$$('#floor svg circle[fill="#ffc04d"]')).length === 2, 'problems travel to the DBA: 2 red (HR1) + 1 amber (ERP1) + 1 amber (DWH notes)');
    ok(/tv-off/.test(await cls(p, 'i:<img src=x onerror=alert(1)>@old-syn-01')) && /not reporting/.test(await p.textContent('#floor')), 'not reporting: grey');
    ok(!(await p.$('#floor img')) && (await p.textContent('#floor')).includes('<img'), 'a hostile instance name stays text');
    ok(/inventory only · 2\.0 TB/.test(await p.textContent('[data-node="v:oracle|10.9.1.40|1521"]')) && /tv-warn/.test(await cls(p, 'v:oracle|10.9.1.40|1521')), 'inventory-only Oracle database');
    ok(/login refused/.test(await p.textContent('[data-node="v:oracle|10.9.1.50|1521"]')) && /tv-off/.test(await cls(p, 'v:oracle|10.9.1.50|1521')), 'a refused login: grey, said');
    ok(/6 Oracle databases/.test(await p.textContent('#ovc')), 'counted');
    ok(!!(await p.$('#inst tr')) && /ORCL1/.test(await p.textContent('#inst')), 'the estate table is still there');
    ROLE = 'viewer'; await p.reload();
    ok(await wait(p, () => document.querySelectorAll('#floor .tv-n').length === 4 && /inventory details are for operators/.test(document.getElementById('ovc').textContent)), 'viewer: the health side, and why the inventory is missing');
  } finally { await browser.close(); srv.close(); }
  ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks');
  process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
