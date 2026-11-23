// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Databases page → "SQL Server · PostgreSQL · MySQL" against the REAL engine/db-inventory.js over SYNTHETIC servers (the
// database helper is stubbed): tiles per engine, every server read from its proven login with version, databases, size and
// what needs attention, the server drawer with each database (state, size, recovery model, last backup), a server where
// MySQL runs without a login offers "Set up a read-only login" pre-filled in the wizard, Read now reads again, a hostile
// database name stays text, a viewer is told the inventory is for operators.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node db-inventory.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const ITAM = path.join(__dirname, '..', '..', 'backend', 'itam'), DASH = path.join(__dirname, '..', '..', 'ui');
const H = require(path.join(ITAM, 'tests', 'helpers'));
const { registerDbInventory, createDbInventory } = require(path.join(ITAM, 'engine', 'db-inventory'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const XSS = '<img src=x onerror=alert(1)>';
const OP = { user: 'nora.syn', role: 'operator' }, ADM = { user: 'syed', role: 'admin' }, VIEW = { user: 'vera.syn', role: 'viewer' };

(async () => {
  const e = await H.startApp({ noAi: true });
  const mk = (x) => e.app.assets.create(Object.assign({ status: 'in_use', type: 'server' }, x), ADM).asset;
  const sqlA = mk({ name: 'SQL-SYN-01', mgmt_ip: '10.9.0.11' }), pgA = mk({ name: 'PG-SYN-01', mgmt_ip: '10.9.0.12' }), myA = mk({ name: 'MY-SYN-02', mgmt_ip: '10.9.0.14' });
  const D = e.app.store.collection('disc_devices');
  D.put({ id: 'd1', ip: '10.9.0.11', asset_id: sqlA.id, status: 'matched', extra: { db_login: { mssql: { credential: 'sql-ro' } } } });
  D.put({ id: 'd2', ip: '10.9.0.12', asset_id: pgA.id, status: 'matched', extra: { db_login: { postgres: { credential: 'pg-ro' } } } });
  const oraA = mk({ name: 'ORA-SYN-01', mgmt_ip: '10.9.0.21' });
  D.put({ id: 'd4', ip: '10.9.0.21', asset_id: oraA.id, status: 'matched', extra: { db_login: { oracle: { credential: 'ora-ro' } } } });
  e.app.store.collection('db_health_targets').put({ id: 'odb_9', label: 'ERP-SYN', host: '10.9.0.30', port: 1521, service: 'ERPPDB', cred_id: 'c9' });
  const creds = [{ id: 'c1', kind: 'db_login', label: 'sql-ro', target: { engine: 'mssql' } }, { id: 'c2', kind: 'db_login', label: 'pg-ro', target: { engine: 'postgres' } },
    { id: 'c8', kind: 'db_login', label: 'ora-ro', target: { engine: 'oracle', service: 'ORCLSYN' } }, { id: 'c9', kind: 'db_login', label: 'oracle-ERP-SYN', target: { engine: 'oracle', service: 'ERPPDB' } }];
  e.app.discovery = Object.assign({}, e.app.discovery, { vault: { list: () => creds, open: (id) => ({ target: creds.find((c) => c.id === id).target, secret: { username: 'zyb_monitor', password: 'Synthetic-1' }, release() {} }) } });
  e.app.addons = e.app.addons || {};
  e.app.addons.serviceMap = { view: () => ({ servers: [{ ip: '10.9.0.14', host: 'my-syn-02', asset: { id: myA.id, name: 'MY-SYN-02' }, services: [{ id: 'mysql', confidence: 'confirmed', evidence: [{ detail: 'process mysqld' }] }] }] }) };
  let reads = 0;
  const invRun = async (r) => {
    reads++;
    if (r.engine === 'oracle' && r.host === '10.9.0.30') return { ok: false, error: 'ORA-01017: invalid username/password; logon denied', error_class: 'auth' };
    if (r.engine === 'oracle') return { ok: true, engine: 'oracle', system: ['PDB$SEED'], errors: {}, server: [['ORCL1', 'ora-syn-01', '19.0.0.0.0', 'Oracle Database 19c Enterprise Edition Release 19.0.0.0.0 - Production', 'OPEN', 'PRIMARY', 'READ WRITE', 'ARCHIVELOG', 'ORCL', 'ORCL_DC']],
      started: [['2026-10-15T01:00:00', 16, 24576]], sessions: [[80, 400]], databases: [['PDB$SEED', 'READ ONLY', 900, 'NO'], ['CLAIMSPDB', 'READ WRITE', 204800, 'NO']], backup: [['2026-10-29T23:00:00', '2026-10-30T05:00:00']], replication: [['ORCL_DR', 'PHYSICAL STANDBY', 'MAXIMUM PERFORMANCE', '+00 00:00:04']] };
    if (r.engine === 'mssql') return { ok: true, engine: 'mssql', system: ['master', 'model', 'msdb', 'tempdb'], errors: {}, server: [['SQL-SYN-01', 'MSSQLSERVER', '15.0.4345.5', 'RTM', 'Standard Edition (64-bit)', 0, 1, 'Arabic_CI_AS']],
      started: [['2026-10-01T02:00:00', 8, 32768]], sessions: [[42]], replication: [['SQL-SYN-01', 'PRIMARY', 'HEALTHY']],
      databases: [['master', 'ONLINE', 'SIMPLE', 150, 6, '2026-10-29T22:00:00', null, 0, 'MULTI_USER'], ['ClaimsSyn', 'ONLINE', 'FULL', 150, 51200, new Date().toISOString().slice(0, 19), null, 0, 'MULTI_USER'], [XSS, 'OFFLINE', 'SIMPLE', 140, 900, null, null, 1, 'MULTI_USER']] };
    return { ok: true, engine: 'postgres', system: ['postgres'], errors: { replication: 'permission denied' }, server: [['PostgreSQL 15.4', '15.4', 5432, 100, false, '']], started: [['2026-10-20T03:00:00']], sessions: [[12]],
      databases: [['postgres', 'ONLINE', 'UTF8', 8, 1, 0, 100], ['portal_syn', 'ONLINE', 'UTF8', 1200, 6, 0, 9000]], replication: null };
  };
  registerDbInventory(e.app.srv, e.app, createDbInventory(e.app, { invRun, noTimer: true }));
  let WHO = OP;
  const srv = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://x'), json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u.pathname === '/dashboards/whoami.json') return json(200, WHO);
    if (u.pathname.startsWith('/api/itam/db-inventory')) {
      const h = Object.assign({}, req.headers, { 'x-sentra-proxy-secret': H.SECRET, 'x-auth-user': WHO.user, 'x-auth-role': WHO.role });
      const up = http.request({ host: '127.0.0.1', port: e.port, method: req.method, path: req.url.replace('/api/itam', '/api/itam'), headers: h }, (r) => { res.writeHead(r.statusCode, r.headers); r.pipe(res); });
      req.pipe(up); return;
    }
    if (u.pathname === '/api/itam/db-health') return json(200, { enabled: true, interval_min: 4, last: { at: new Date().toISOString(), results: [] } });
    if (u.pathname === '/api/itam/db-health/databases') return json(200, { databases: [], credentials: [], dismissed: [] });
    if (u.pathname.startsWith('/api/itam/discovery/results')) return json(200, { devices: [] });
    if (u.pathname === '/api/itam/discovery/credentials') return json(200, { credentials: [] });
    if (u.pathname.startsWith('/api/')) return json(404, { error: 'not in this test' });
    const f = path.join(DASH, u.pathname.replace(/^\/dashboards\//, '/')); if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (err, d) => { if (err) { res.writeHead(404); res.end(); return; } res.writeHead(200, { 'Content-Type': u.pathname.endsWith('.js') ? 'application/javascript' : u.pathname.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port + '/';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  const wait = (p, fn, arg) => p.waitForFunction(fn, arg, { timeout: 15000 }).then(() => true, () => false);
  try {
    const p = await browser.newPage({ viewport: { width: 1400, height: 950 } }); p.on('pageerror', (x) => errs.push(x.message));
    p.on('dialog', (d) => { errs.push('dialog: ' + d.message()); d.dismiss(); });
    await p.goto(base + 'databases.html?standalone=1');
    ok(await wait(p, () => /SQL Server/.test((document.getElementById('inv-k') || {}).textContent || '')), 'the engine tiles');
    ok(/No SQL Server, PostgreSQL or MySQL server has a proven/.test(await p.textContent('#inv-t')) || (await p.$$('#inv-t tr[data-inv]')).length === 0, 'nothing read yet: says how to start');
    ok(/MY-SYN-02/.test(await p.textContent('#inv-f')) && /process mysqld/.test(await p.textContent('#inv-f')), 'MySQL found on MY-SYN-02 without a login');
    ok(!(await p.$('[data-invlogin]')) && /an administrator adds the login/.test(await p.textContent('#inv-f')), 'an operator is told an administrator adds the login');
    await p.click('#inv-run');
    ok(await wait(p, () => document.querySelectorAll('#inv-t tr[data-inv]').length === 4), 'Read now: all four servers (Oracle, the registered Oracle database, SQL Server, PostgreSQL)');
    ok(reads === 4, 'each login read once');
    const t = await p.textContent('#inv-t');
    ok(/SQL-SYN-01/.test(t) && /15\.0\.4345\.5 · Standard Edition/.test(t) && /50\.9 GB/.test(t), 'SQL Server: asset, version, edition, size');
    ok(/PG-SYN-01/.test(t) && /12 \/ 100/.test(t) && /1 not readable/.test(t), 'PostgreSQL: sessions of max, a query the login may not run');
    ok(/Oracle1read1databases/.test((await p.textContent('#inv-k')).replace(/\s+/g, '')), 'the Oracle tile: one read, one PDB (PDB$SEED is a system container)');
    ok(/login refused/.test(t), 'the registered Oracle database with a refused login says so');
    await p.click('#inv-t tr[data-inv="oracle|10.9.0.21|1521"]');
    ok(await wait(p, () => /Last RMAN backup/.test((document.getElementById('zd') || {}).textContent || '')), 'Oracle drawer');
    const od = await p.textContent('#zd');
    ok(/CLAIMSPDB/.test(od) && /multitenant/.test(od) && /PRIMARY · READ WRITE/.test(od) && /ARCHIVELOG/.test(od) && /ORCL_DR/.test(od) && /lag 4 s/.test(od), 'Oracle: PDBs, role, log mode, Data Guard lag');
    await p.keyboard.press('Escape');
    await p.click('#inv-t tr[data-inv="oracle|10.9.0.30|1521"]');
    ok(await wait(p, () => /Not retried automatically/.test((document.getElementById('zd') || {}).textContent || '')), 'a refused login is not retried automatically - no lockout');
    await p.keyboard.press('Escape');
    ok(/SQLServer1read2databases/.test((await p.textContent('#inv-k')).replace(/\s+/g, '')), 'the SQL Server tile counts user databases only');
    await p.click('#inv-t tr[data-inv^="mssql"]');
    ok(await wait(p, () => /Last full backup/.test((document.getElementById('zd') || {}).textContent || '')), 'the server drawer with the databases');
    const dr = await p.textContent('#zd');
    ok(/ClaimsSyn/.test(dr) && /FULL/.test(dr) && /none recorded/.test(dr) && /OFFLINE/.test(dr), 'per database: recovery, last backup, state');
    ok(/no full backup recorded|is OFFLINE/.test(dr) && /FULL recovery but no log backup/.test(dr), 'what needs attention, from the facts');
    ok(/Always On/.test(dr) && /PRIMARY/.test(dr), 'Always On and the replica role');
    ok(!(await p.$('#zd img')) && dr.includes('<img'), 'a hostile database name stays text');
    await p.keyboard.press('Escape');
    // an administrator sets up the login for the found MySQL server: the wizard opens pre-filled
    WHO = ADM; await p.reload(); await wait(p, () => !!document.querySelector('[data-invlogin]'));
    await p.click('[data-invlogin]');
    ok(await wait(p, () => document.getElementById('w-eng') && document.getElementById('w-eng').value === 'mysql' && document.getElementById('w-host').value === '10.9.0.14' && document.getElementById('w-port').value === '3306'), 'the wizard opens for MySQL on 10.9.0.14:3306');
    ok(/GRANT SELECT ON performance_schema/.test(await p.textContent('#w-sql')) && !/GRANT ALL|SUPER/.test(await p.textContent('#w-sql')), 'the read-only login script');
    await p.keyboard.press('Escape');
    WHO = VIEW; await p.reload();
    ok(await wait(p, () => /for operators and administrators/.test((document.getElementById('inv-t') || {}).textContent || '')), 'a viewer is told the inventory is for operators');
  } finally { await browser.close(); srv.close(); await e.close(); }
  ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks');
  process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
