// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for db-performance.html after the static build: clickable tiles filter the database list, rows select a
// database, the stacked activity chart opens a moment's breakdown and hides wait classes, the trend metric switches, Top SQL
// opens a statement's plans (correct plan-change fields), sessions show blocking chains and open a session, capacity sorts
// tablespaces by days to full and opens one, health lists issues, deep links (#db=&tab=) work, and nothing invents data.
// API answers are SYNTHETIC, in the shapes engine/db-audit/routes.js documents.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node db-performance.test.js
const http = require('http'), fs = require('fs'), path = require('path'), os = require('os'), cp = require('child_process');
const SRC = path.resolve(__dirname, '../../ui');
let n = 0, bad = 0;
const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const B = fs.mkdtempSync(path.join(os.tmpdir(), 'dbperf-')); fs.mkdirSync(path.join(B, 'vendor'));
fs.readdirSync(SRC).filter((f) => f.endsWith('.html')).forEach((f) => fs.copyFileSync(path.join(SRC, f), path.join(B, f)));
fs.readdirSync(path.join(SRC, 'vendor')).filter((f) => /\.(js|json|css)$/.test(f)).forEach((f) => fs.copyFileSync(path.join(SRC, 'vendor', f), path.join(B, 'vendor', f)));
['zyb-menu.js', 'zyb-dash.js'].forEach((t) => fs.writeFileSync(path.join(B, 'vendor', t), fs.readFileSync(path.join(B, 'vendor/zyb-nav.js'), 'utf8') + '\n' + fs.readFileSync(path.join(B, 'vendor', t), 'utf8')));
cp.execFileSync(process.execPath, [path.join(SRC, 'build-static.js'), B, 't1'], { stdio: 'ignore' });
const now = Date.now(), ts = [now - 3 * 6e5, now - 2 * 6e5, now - 6e5];
const INV = { totals: { removed: 1, instances: 2, down: 1, stale: 0, with_issues: 1, open_alerts: 2, failed_logons_24h: 4, blocked_sessions: 2 }, clickhouse: { ok: true }, alerts: [],
  instances: [
    { key: 'db1|ORCLPRD', host: 'db1', instance: 'ORCLPRD', db_name: 'ORCLPRD', version: '19.21', role: 'PRIMARY', up: true, open_mode: 'READ WRITE', last_seen: now - 6e4, stale: false, worst_severity: 3, open_alerts: 2, failed_logons_24h: 4,
      tablespaces: [{ name: 'USERS', used_pct: 96 }, { name: 'SYSTEM', used_pct: 70 }], sessions: { total: 420, max_sessions: 500, blocked: 2 }, backup: { age_h: 30, status: 'COMPLETED', input_type: 'DB INCR', outcome: 'success' },
      dataguard: { apply_lag_s: 400, protection_mode: 'MAXIMUM PERFORMANCE' }, fra: { used_pct: 82, reclaimable_mb: 1200 }, redo: { archive_lag_s: 60 }, listener: { name: 'LISTENER', status: 'READY', up: true }, invalid_objects: 12,
      collector: { last: now - 6e4, queries_failed: 0 }, alertlog: { path: '/u01/alert.log', ora_errors: 1, tail: ['ORA-01653: unable to extend table APP.CLAIMS'] },
      issues: [{ severity: 3, text: 'Tablespace USERS 96 % used', action: 'Add a data file or enable autoextend' }] },
    { key: 'db2|HRDB', host: 'db2', instance: 'HRDB', db_name: 'HRDB', version: '19.21', role: 'PRIMARY', up: false, state: 'down', last_seen: now - 36e5, stale: false, worst_severity: 4, open_alerts: 0, tablespaces: [], issues: [] }] };
const PERF = { clickhouse: { ok: true }, step_s: 600, thresholds: { log_file_sync_ms: 10, seq_read_ms: 20 },
  summary: { points: 3, cpu_count: 8, aas_avg: 3.2, aas_max: 9.5, aas_latest: 4.1, executions_s_avg: 1200, db_cpu_s_avg: 2.1 },
  aas_by_class: { ts, classes: [{ key: 'cpu', name: 'CPU', values: [2, 6, 3] }, { key: 'user_io', name: 'User I/O', values: [1, 3.5, 1.1] }] },
  series: { ts, aas: [3, 9.5, 4.1], host_cpu_pct: [40, 92, 55], redo_mb_s: [null, null, null], executions_s: [1000, 1500, 1100] },
  efficiency: { latest: { buffer_cache_hit_pct: 99.1, library_cache_hit_pct: 98, soft_parse_pct: 85, execute_to_parse_pct: 70 } },
  wait_classes: [{ class: 'User I/O', time_s: 1.2, dbtime_pct: 45 }], wait_events: [{ event: 'db file sequential read', class: 'User I/O', avg_ms: 25, waits_s: 300, pct: 40, over: true }], latches: [],
  alerts: [{ severity: 3, rule_name: 'Oracle average active sessions above CPU count', summary: 'AAS 9.5 > 8 CPUs', count: 1, ts_last: now - 6e5, status: 'new' }] };
const TOPSQL = { period: '24h', sql_text_visible: true, sql: [{ sql_id: 'a1b2c3d4e5f6g', plan_count: 2, executions: 5000, elapsed_s: 900, ela_ms_exec: 180, cpu_s: 400, gets_exec: 12000, reads_exec: 300, module: 'CLAIMS', user: 'APP', sql_text: 'SELECT * FROM claims WHERE <b>x</b>', plan_change: { old_plan: '111', new_plan: '222', ratio: 3.2, worse: true } }],
  plan_changes: [{ sql_id: 'a1b2c3d4e5f6g', old_plan: '111', new_plan: '222', old_ms_exec: 56, new_ms_exec: 180, ratio: 3.2, worse: true, ts: now - 36e5 }], activity: [{ sql_id: 'a1b2c3d4e5f6g', aas: 1.4, top_event: 'db file sequential read', module: 'CLAIMS' }] };
const DETAIL = Object.assign({}, TOPSQL, { detail: { sql_id: 'a1b2c3d4e5f6g', module: 'CLAIMS', user: 'APP', step_s: 3600, sql_text: 'SELECT * FROM claims', plan_change: { old_plan: '111', new_plan: '222', ratio: 3.2, worse: true },
  plans: [{ plan_hash: '111', executions: 3000, ela_ms_exec: 56, cpu_ms_exec: 20, gets_exec: 4000, points: [{ ela_ms_exec: 50 }, { ela_ms_exec: 60 }] }, { plan_hash: '222', executions: 2000, ela_ms_exec: 180, cpu_ms_exec: 80, gets_exec: 20000, points: [{ ela_ms_exec: 170 }, { ela_ms_exec: 190 }] }] } });
const SESS = { snapshot_ts: now - 6e4, stale: false, sql_text_visible: true, blocking: { waiters: 2, max_wait_s: 420, trees: [{ sid: '55', user: 'BATCH', status: 'INACTIVE', idle_s: 900, sql_id: 'zz9', waiting: false, waiters: 2, max_wait_s: 420, children: [{ sid: '77', user: 'APP', waiting: true, wait_s: 420, event: 'enq: TX - row lock contention', sql_id: 'a1b2c3d4e5f6g', children: [] }] }] },
  long_running: [{ sid: '91', serial: '3', user: 'REPORTS', sql_id: 'a1b2c3d4e5f6g', elapsed_s: 5400, state: 'WAITING', event: 'direct path read', module: 'MONTH_END' }], top_sessions: [{ sid: '77', user: 'APP', program: 'jdbc', aas: 0.9, top_event: 'enq: TX', sql_id: 'a1b2c3d4e5f6g' }], active: { aas: 4.1, top_event: 'CPU' } };
const CAP = { thresholds: { days_to_full: 14, temp_pct: 85 }, instances: [{ key: 'db1|ORCLPRD', instance: 'ORCLPRD', tablespaces: [{ name: 'SYSTEM', used_pct: 70, used_mb: 7000, max_mb: 10000, growth_mb_day: 1, days_to_full: 3000, history_days: 30, severity: 0 }, { name: 'USERS', used_pct: 96, used_mb: 96000, max_mb: 100000, growth_mb_day: 800, days_to_full: 5, history_days: 30, severity: 4 }, { name: 'ARCH', used_pct: 40, used_mb: 400, max_mb: 1000, growth_mb_day: null, days_to_full: null, history_days: 2, severity: 0 }],
  asm: [{ name: 'DATA', state: 'MOUNTED', type: 'EXTERN', free_pct: 12, usable_file_mb: 50000, offline_disks: 0 }], limits: [{ resource: 'processes', current: 450, max_util: 480, limit: '500', pct: 90 }], temp_undo: { temp_used_pct: 30, undo_used_pct: 20 }, redo: { switches_1h: 12, avg_switch_min: 5 }, archive_dests: [], host: { host_cpu_pct: 55, num_cpus: 8, mem_used_pct: 70 } }] };
const GETS = [], POSTS = [];
// ✦ AI / ML tab: the REAL SIEM perf-intel module over 7 days of SYNTHETIC load with a spike an hour ago, I/O-bound waits and a slower SQL
const SIEM = process.env.SENTRA_SIEM_DIR || path.resolve(__dirname, '../../backend/siem');
const PI = require(path.join(SIEM, 'engine/db-audit/perf-intel')), { fakeApi } = require(path.join(SIEM, 'tests/soc-fakes'));
const piApi = fakeApi({ realRanks: true });
{ const H = 36e5, ST = 9e5, sts = [], aas = []; for (let t = now - 7 * 864e5; t <= now; t += ST) { const h = new Date(t + 3 * H).getUTCHours(); sts.push(t); aas.push(now - t <= 2 * H && now - t >= H ? 14 : h >= 8 && h <= 16 ? 3 : 1); }
  PI.register(piApi, { now: () => now, config: { netops: { ai: { enabled: false } } }, oracle_perf: {
    perf: async () => ({ step_s: 900, series: { ts: sts, aas, cpu_count: sts.map(() => 4) }, summary: { cpu_count: 4 }, thresholds: { seq_read_ms: 10 }, aas_by_class: { ts: sts, classes: [{ name: 'User I/O', values: aas.map((v) => v * 0.7) }] },
      wait_classes: [{ class: 'User I/O', dbtime_pct: 65 }], wait_events: [{ event: 'db file sequential read', avg_ms: 22 }], instance: { key: 'db1|ORCLPRD', instance: 'ORCLPRD', host: 'db1' } }),
    topsql: async (q) => (q.period === '24h' ? { sql: [{ sql_id: 'fx7a', executions: 400, ela_ms_exec: 120, elapsed_s: 48, module: '<img src=x onerror="window.__xss=1">' }] } : { sql: [{ sql_id: 'fx7a', executions: 2000, ela_ms_exec: 30 }] }) } }, '/api/soc', (ctx) => Object.assign({}, ctx.query || {})); }
(async () => {
  const srv = http.createServer((q, r) => {
    const u = q.url.split('?')[0], qs = new URLSearchParams(q.url.split('?')[1] || ''), j = (c, o) => { r.writeHead(c, { 'Content-Type': 'application/json' }); r.end(JSON.stringify(o)); };
    if (u.endsWith('whoami.json')) return j(200, { user: 'ahmed', role: 'admin' });
    if (u === '/api/soc/db/oracle/perf-intel') { piApi.call('GET', q.url, { role: 'admin', user: 'ahmed' }).then((x) => j(x.status, x.body)); return; }
    if (u.startsWith('/api/')) { GETS.push(q.url);
      if (u === '/api/soc/db/oracle') return j(200, INV);
      if (u === '/api/soc/db/oracle-removed' && q.method === 'GET') return j(200, { items: [{ id: '10.100.12.50|ESS', at: now - 6e5, by: 'ahmed', reason: 'same database as eskauat' }] });
      if (u.startsWith('/api/soc/db/oracle-removed') && q.method === 'POST') { let b = ''; q.on('data', (c) => { b += c; }); q.on('end', () => { POSTS.push(u + ' ' + b); j(200, { ok: true }); }); return; }
      if (u === '/api/soc/db/oracle/perf') return j(200, PERF);
      if (u === '/api/soc/db/oracle/topsql') return j(200, qs.get('sql_id') ? DETAIL : TOPSQL);
      if (u === '/api/soc/db/oracle/sessions') return j(200, SESS);
      if (u === '/api/soc/db/oracle/capacity') return j(200, CAP);
      if (u.startsWith('/api/itam/assets')) return j(200, { assets: [] });
      if (u === '/api/itam/db-health') return j(200, { enabled: true, interval_min: 4, source_registered: true, last: { at: now - 12e4, read: 1, failed: 0, sent: 40, results: [{ host: 'db1', ok: true, missing: ['V$DIAG_ALERT_EXT'] }] } });
      if (u === '/api/itam/db-health/databases' && q.method === 'GET') return j(200, { databases: [
        { id: 'r1', label: 'ORCLPRD', host: 'db1', port: 1521, service: 'ORCLPRD', last_test: { at: now - 864e5, ok: true } },
        { id: 'r2', label: 'FINDB', host: 'db3', port: 1521, service: 'FINPDB', paused: { at: now - 36e5, reason: 'the account has more than read-only monitoring privileges - not used; give it read-only rights or use a dedicated monitoring user, then test again' },
          last_test: { at: now - 36e5, ok: false, error: 'account holds more than read-only monitoring rights (DROP ANY TABLE, SELECT ANY TABLE) - not used.' } }] });
      if (u === '/api/itam/db-health/databases/r2/test') { POSTS.push(u); return j(200, { database: { last_test: { ok: false, error: 'still more than read-only' } } }); }
      return j(404, {}); }
    fs.readFile(path.join(B, u.replace(/^\/dashboards\//, '/')), (e, d) => { if (e) { r.writeHead(404); return r.end(); } r.writeHead(200, { 'Content-Type': u.endsWith('.js') ? 'application/javascript' : u.endsWith('.css') ? 'text/css' : 'text/html' }); r.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const url = 'http://127.0.0.1:' + srv.address().port + '/dashboards/db-performance.html';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  const open = async (hash) => { const p = await browser.newPage({ viewport: { width: 1400, height: 1000 } }); p.on('pageerror', (e) => errs.push(e.message)); await p.goto(url + (hash || ''));
    await p.waitForFunction(() => document.querySelector('#sum .t, #sum [class*=tile]') || /Loading/.test(document.getElementById('inv').innerText) === false, null, { timeout: 8000 }).catch(() => {}); await p.waitForTimeout(700); return p; };
  const txt = (p, id) => p.evaluate((i) => document.getElementById(i).innerText.replace(/\s+/g, ' '), id);
  const body = (p) => p.evaluate(() => document.body.textContent.replace(/\s+/g, ' '));

  let p = await open();
  await p.waitForTimeout(400);
  const col = await txt(p, 'col');
  ok(/ORCLPRD/.test(col) && /reading/.test(col) && /cannot read: V\$DIAG_ALERT_EXT/.test(col), 'collection: reading database and the view it cannot read: ' + col.slice(0, 200));
  ok(/FINDB/.test(col) && /paused/.test(col) && /DROP ANY TABLE/.test(col) && /CREATE SESSION, SELECT ANY DICTIONARY, SET CONTAINER/.test(col), 'collection: paused as over-privileged, names the extra privileges and the allowed ones');
  ok(/1 paused/.test(await txt(p, 'colc')), 'paused count in the header');
  ok(/DATABASES 2/i.test(await txt(p, 'kk')) && /BLOCKED SESSIONS 2/i.test(await txt(p, 'kk')) && /FAILED LOGONS 4/i.test(await txt(p, 'kk')), 'tiles: ' + (await txt(p, 'kk')).slice(0, 200));
  ok(/ORCLPRD/.test(await txt(p, 'inv')) && /USERS 96%/.test(await txt(p, 'inv')) && /420 \/ 500/.test(await txt(p, 'inv')) && /HRDB/.test(await txt(p, 'inv')), 'database table');
  await p.click('[data-f="down"]'); await p.waitForTimeout(200);
  ok(!/ORCLPRD/.test(await txt(p, 'inv')) && /HRDB/.test(await txt(p, 'inv')) && /filter: down/.test(await txt(p, 'filt')), 'Down tile filters the list');
  await p.click('[data-f="down"]'); await p.waitForTimeout(200); ok(/ORCLPRD/.test(await txt(p, 'inv')), 'clicking the tile again clears the filter');
  await p.fill('#q', 'hrdb'); await p.waitForTimeout(200); ok(!/ORCLPRD/.test(await txt(p, 'inv')), 'search filters'); await p.fill('#q', ''); await p.waitForTimeout(200);
  ok(/AAS NOW 4\.1/i.test(await txt(p, 'sum')) && /of 8 CPUs/.test(await txt(p, 'sum')), 'activity summary');
  ok(await p.evaluate(() => document.querySelectorAll('#act rect[data-bk]').length >= 5), 'stacked chart drawn');
  await p.click('#act rect[data-bk="1"]'); await p.waitForTimeout(300);
  ok(/Active sessions at/.test(await body(p)) && /CPU\s*6/.test(await body(p)), 'clicking a bar opens that moment');
  await p.evaluate(() => window.zybDetail.close());
  await p.click('[data-hid="cpu"]'); await p.waitForTimeout(200);
  ok(await p.evaluate(() => document.querySelector('[data-hid="cpu"]').classList.contains('off') && ![...document.querySelectorAll('#act rect')].some((r) => r.getAttribute('fill') === '#2f81f7')), 'legend hides a wait class');
  ok(await p.evaluate(() => [...document.querySelectorAll('#met option')].map((o) => o.value).join() === 'aas,host_cpu_pct,executions_s'), 'trend offers only metrics with samples');
  await p.selectOption('#met', 'host_cpu_pct'); await p.waitForTimeout(200); ok(/max 92/.test(await txt(p, 'trend')), 'trend metric switches');
  ok(/Soft parse 85 %/i.test(await txt(p, 'eff')), 'efficiency');

  await p.click('[data-pt="sql"]'); await p.waitForTimeout(200);
  ok(/a1b2c3d4e5f6g/.test(await txt(p, 'sql')) && /3\.2× slower/.test(await txt(p, 'sql')), 'top SQL with plan regression');
  ok(/111/.test(await txt(p, 'pc')) && /222/.test(await txt(p, 'pc')) && /56/.test(await txt(p, 'pc')) && /180/.test(await txt(p, 'pc')), 'plan changes show old / new plan and ms per exec (fields fixed)');
  ok(await p.evaluate(() => !document.querySelector('#sql b')), 'SQL text escaped');
  await p.selectOption('#by', 'gets'); await p.waitForTimeout(300); ok(GETS.some((g) => /topsql\?.*by=gets/.test(g)), 'rank by switches the query');
  await p.click('tr[data-sql="a1b2c3d4e5f6g"]'); await p.waitForTimeout(400);
  ok(/SQL a1b2c3d4e5f6g/.test(await body(p)) && /plan 222 is 3\.2× slower than 111/.test(await body(p)) && GETS.some((g) => /sql_id=a1b2c3d4e5f6g/.test(g)), 'statement detail with plans');
  await p.evaluate(() => window.zybDetail.close());

  await p.click('[data-pt="ses"]'); await p.waitForTimeout(200);
  ok(/SID 55/.test(await txt(p, 'blk')) && /blocker/.test(await txt(p, 'blk')) && /SID 77/.test(await txt(p, 'blk')) && /7 min/.test(await txt(p, 'blk')), 'blocking chain');
  ok(/1\.5 h/.test(await txt(p, 'lng')), 'long-running');
  await p.click('tr[data-sess="l0"]'); await p.waitForTimeout(300); ok(/Session 91/.test(await body(p)) && /MONTH_END/.test(await body(p)), 'session detail');
  await p.evaluate(() => window.zybDetail.close());

  await p.click('[data-pt="cap"]'); await p.waitForTimeout(200);
  const tbs = await p.evaluate(() => [...document.querySelectorAll('#tbs tr[data-ts] td:first-child')].map((t) => t.innerText.trim()));
  ok(tbs.join() === 'USERS,SYSTEM,ARCH', 'tablespaces sorted by days to full: ' + tbs);
  ok(/not growing \/ unknown/.test(await txt(p, 'tbs')) && /DATA/.test(await txt(p, 'asm')) && /processes/.test(await txt(p, 'lim')), 'capacity tables');
  await p.click('tr[data-ts="0"]'); await p.waitForTimeout(300); ok(/Tablespace USERS/.test(await body(p)) && /800 MB \/ day/.test(await body(p)), 'tablespace detail');
  await p.evaluate(() => window.zybDetail.close());

  await p.click('[data-pt="hea"]'); await p.waitForTimeout(200);
  ok(/Tablespace USERS 96 % used/.test(await txt(p, 'iss')) && /Add a data file/.test(await txt(p, 'iss')) && /ORA-01653/.test(await txt(p, 'alog')), 'health: issues and alert log');
  await p.click('[data-pt="alr"]'); await p.waitForTimeout(200); ok(/above CPU count/.test(await txt(p, 'alr')), 'alerts tab');
  ok(await p.evaluate(() => /tab=alr/.test(location.hash) && /db=db1/.test(decodeURIComponent(location.hash))), 'state kept in the address (deep link)');

  ok(/Removed \(1\)/.test(await p.evaluate(() => document.getElementById('rmlist').textContent)), 'removed count shown');
  await p.click('[data-rm="db2|HRDB"]'); await p.waitForTimeout(300);
  ok(!GETS.some((g) => /perf\?instance=db2%7CHRDB/.test(g)), 'Remove does not select the row');
  await p.fill('#rm-why', 'old test database'); await p.click('#rm-ok'); await p.waitForTimeout(300);
  ok(POSTS.some((x) => /^\/api\/soc\/db\/oracle-removed \{.*"key":"db2\|HRDB".*"reason":"old test database"/.test(x)), 'remove sends key and reason');
  await p.click('#rmlist'); await p.waitForTimeout(300);
  ok(/same database as eskauat/.test(await body(p)), 'removed list with reasons');
  await p.click('[data-rst="10.100.12.50|ESS"]'); await p.waitForTimeout(300);
  ok(POSTS.some((x) => /oracle-removed\/restore/.test(x)), 'restore');
  await p.click('[data-coltest="1"]'); await p.waitForTimeout(400);
  ok(POSTS.includes('/api/itam/db-health/databases/r2/test'), 'Test again sends the test for that database');
  await p.click('tr[data-db="db2|HRDB"]'); await p.waitForTimeout(400);
  ok(GETS.some((g) => /perf\?instance=db2%7CHRDB/.test(g)) && /HRDB/.test(await txt(p, 'dname')), 'clicking a row selects that database');
  await p.close();

  p = await open('#db=db1%7CORCLPRD&tab=cap'); await p.waitForTimeout(300);
  ok(await p.evaluate(() => !document.querySelector('[data-pane="cap"]').hidden) && /USERS/.test(await txt(p, 'tbs')), 'deep link opens the database and tab');
  await p.close();

  p = await open('#db=db1%7CORCLPRD&tab=ai');
  ok(await p.waitForFunction(() => /Performance health/.test((document.getElementById('pai') || {}).innerText || ''), null, { timeout: 20000 }).then(() => true, () => false), 'AI / ML tab analyses the database');
  const ai = await txt(p, 'pai');
  ok(await p.$('#pai svg path') && /normal band per hour of the day/.test(ai), 'load against its normal band');
  ok(await p.$$eval('#pai circle', (c) => c.length) >= 1, 'points far above usual marked');
  ok(/I\/O bound/.test(ai) && /22 ms \(threshold 10\)/.test(ai), 'diagnosis with its evidence');
  ok(/14 AAS against a usual/.test(ai), 'unusual load episode');
  ok(/fx7a/.test(ai) && /4x/.test(ai) && /36/.test(ai), 'SQL regression ranked by extra DB time');
  ok(/CPU headroom/.test(ai) && await p.$$eval('#pai rect', (r) => r.length) >= 7, 'daily peak against the CPUs');
  ok(/AI performance advisor is off: AI switched off/.test(ai), 'advisor off says why');
  ok(await p.evaluate(() => !window.__xss), 'hostile module name stays text');
  await p.click('#pai [data-goto="wai"]'); ok(await p.evaluate(() => !document.querySelector('[data-pane="wai"]').hidden), 'a diagnosis opens its tab');
  await p.close();

  ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  await browser.close(); srv.close();
  console.log(`${n - bad}/${n} checks passed`); process.exit(bad ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });
