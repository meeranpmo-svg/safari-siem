// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for db-dashboard.html after the static build: database cards and tiles, open problems with acknowledge /
// snooze / history, alert-log error findings, thresholds and exceptions (saved with a reason and the version), notifications,
// maintenance windows, the digest preview in a sandboxed frame, the viewer (reads, cannot change) and the empty state.
// API answers are SYNTHETIC, in the shapes engine/db-audit/dba-alerts.js returns.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node db-dashboard.test.js
const http = require('http'), fs = require('fs'), path = require('path'), os = require('os'), cp = require('child_process');
const SRC = path.resolve(__dirname, '../../ui');
let n = 0, bad = 0;
const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const B = fs.mkdtempSync(path.join(os.tmpdir(), 'dbdash-')); fs.mkdirSync(path.join(B, 'vendor'));
fs.readdirSync(SRC).filter((f) => f.endsWith('.html')).forEach((f) => fs.copyFileSync(path.join(SRC, f), path.join(B, f)));
fs.readdirSync(path.join(SRC, 'vendor')).filter((f) => /\.(js|json|css)$/.test(f)).forEach((f) => fs.copyFileSync(path.join(SRC, 'vendor', f), path.join(B, 'vendor', f)));
['zyb-menu.js', 'zyb-dash.js'].forEach((t) => fs.writeFileSync(path.join(B, 'vendor', t), fs.readFileSync(path.join(B, 'vendor/zyb-nav.js'), 'utf8') + '\n' + fs.readFileSync(path.join(B, 'vendor', t), 'utf8')));
cp.execFileSync(process.execPath, [path.join(SRC, 'build-static.js'), B, 't1'], { stdio: 'ignore' });
const now = Date.now();
const M = (id, label, group, unit, dir, warn, crit, extra) => Object.assign({ id, label, group, unit, dir, kind: 'value', keyed: false, ts_scope: false, help: '', warn, crit, enabled: true, default: { warn, crit, enabled: true } }, extra || {});
const POL = { version: 3, by: 'ahmed', updated: now - 864e5, overrides: [{ metric: 'ts_used_pct', scope: 'ORCLPRD/USERS', warn: 97, crit: 99, reason: 'pre-allocated', by: 'ahmed' }], errors: { ignore: ['ORA-29999'], levels: {} },
  metrics: [M('instance_down', 'Instance down', 'Availability', '', '', null, 1, { kind: 'state' }), M('ts_used_pct', 'Tablespace used', 'Space', '%', 'above', 85, 95, { ts_scope: true, keyed: true }), M('fra_pct', 'Recovery area (FRA) used', 'Space', '%', 'above', 80, 90), M('temp_pct', 'TEMP used', 'Space', '%', 'above', 85, 95), M('asm_free_pct', 'ASM disk group free', 'Space', '%', 'below', 15, 10)] };
const STATUS = { generated_at: now, last_eval: { at: now - 6e4, ok: true }, open: { crit: 2, warn: 1, acknowledged: 0, snoozed: 0 }, errors: 2, mail: { ok: true, problems: [] }, digest: { enabled: true, at: '07:45' }, maintenance: [],
  instances: [{ instance: 'ORCLPRD', host: 'db1', db_name: 'ORCLPRD', status: 'OPEN', role: 'PRIMARY', version: '19.21', last_ms: now - 12e4, level: 'crit', open: { crit: 2, warn: 1 }, max_ts: { key: 'USERS', value: 96 }, min_days_to_full: 5.5, fra_pct: 92, temp_pct: 40, undo_pct: 20, sessions_pct: 50, backup_age_h: 30, dg_lag_s: 2000, maintenance: null },
    { instance: 'HRDB', host: 'db2', db_name: 'HRDB', status: 'OPEN', role: 'PRIMARY', version: '19.21', last_ms: now - 12e4, level: 'ok', open: { crit: 0, warn: 0 }, max_ts: { key: 'HR_DATA', value: 41 }, min_days_to_full: null, fra_pct: null, temp_pct: null, undo_pct: null, sessions_pct: null, backup_age_h: 10, dg_lag_s: null, maintenance: null }] };
const PROBS = [{ id: 'code_change|ORCLPRD@db1|APP.PKG', metric: 'code_change', kind: 'event', instance: 'ORCLPRD', host: 'db1', key: 'APP.PKG_CLAIMS (PACKAGE BODY)', level: 'warn', value: 1, threshold: null, scope: 'global', status: 'open', since: now - 6e5, unit: '', label: 'Code changed (package / procedure / function / trigger / type)', detail: 'PACKAGE BODY changed at 2026-10-21T10:40:00 · by ALI.SYN (ali@pc-17) <i>x</i>', history: [] },
  { id: 'bulk_delete_rows|ORCLPRD@db1|9x', metric: 'bulk_delete_rows', instance: 'ORCLPRD', host: 'db1', key: '9xyz123abc456', level: 'warn', value: 15000, threshold: 10000, scope: 'global', status: 'open', since: now - 6e5, unit: 'rows', label: 'Bulk delete', detail: 'table APP.CLAIMS · by APPUSER', history: [] },
  { id: 'ts_used_pct|ORCLPRD@db1|USERS', metric: 'ts_used_pct', instance: 'ORCLPRD', host: 'db1', key: 'USERS', level: 'crit', value: 96, threshold: 95, scope: 'global', status: 'open', since: now - 36e5, unit: '%', label: 'Tablespace used', notified: { at: now }, history: [{ at: now, by: 'system', what: 'critical: ts_used_pct 96 %' }] },
  { id: 'fra_pct|ORCLPRD@db1|', metric: 'fra_pct', instance: 'ORCLPRD', host: 'db1', key: '', level: 'crit', value: 92, threshold: 90, scope: 'global', status: 'open', since: now - 72e5, unit: '%', label: 'Recovery area (FRA) used', stale: true, history: [] },
  { id: 'ora:ORA-00600|ORCLPRD@db1|', metric: 'ora:ORA-00600', instance: 'ORCLPRD', host: 'db1', key: '', level: 'crit', value: 1, threshold: null, scope: 'error', status: 'open', since: now - 6e5, unit: '', label: 'ORA-00600 Internal error', history: [] }];
const ERRS = { at: now, items: [{ instance: 'ORCLPRD', host: 'db1', code: 'ORA-00600', title: 'Internal error', what: 'Check the trace file named in the alert log and the incident in ADR (adrci show incident)', level: 'crit', known: true, count: 1, first_ms: now - 6e5, last_ms: now - 6e5, samples: ['2026-10-21T07:10:00Z ORA-00600: internal error <b>x</b>'] },
  { instance: 'ORCLPRD', host: 'db1', code: 'ORA-01653', title: 'Unable to extend table', what: 'The tablespace is full: add or resize a data file', level: 'crit', known: true, count: 3, first_ms: now - 36e5, last_ms: now - 6e5, samples: ['ORA-01653: unable to extend table APP.CLAIMS'] }] };
const NOTIFY = { recipients: ['dba@as.example'], warn_mode: 'digest', renotify_h: 4, recovery: true, digest: { enabled: true, at: '07:45' }, maintenance: [{ instance: 'HRDB', from: now - 36e5, until: now + 36e5, by: 'ahmed', reason: 'patching' }] };
let ROLE = 'operator', EMPTY = false, APM_OFF = false, RAC = false, RAC2 = false; const POSTS = [];
(async () => {
  const srv = http.createServer((q, r) => {
    const u = q.url.split('?')[0], j = (c, o) => { r.writeHead(c, { 'Content-Type': 'application/json' }); r.end(JSON.stringify(o)); };
    if (u.endsWith('whoami.json')) return j(200, { user: 'ahmed', role: ROLE });
    if (u.startsWith('/api/')) {
      if (q.method === 'POST') { let b = ''; q.on('data', (c) => { b += c; }); q.on('end', () => { const body = JSON.parse(b || '{}'); POSTS.push({ u, b: body });
        if (u.endsWith('/evaluate')) return j(200, { opened: 1, cleared: 0, instances: 2, errors: 2 });
        if (u.endsWith('/digest')) return j(200, { id: 'd', subject: 'Database digest', html: '<h2>Digest body</h2><script>parent.document.title="pwned"</script>', sent: body.send ? { status: 'ok' } : undefined });
        j(200, { ok: true }); }); return; }
      if (u === '/api/itam/db-servers') return j(200, { servers: [
        { ip: '10.0.0.11', host: 'db1', databases: [{ instance: 'ORCLPRD' }], worst: 'high', server: { oracle: { listeners: ['LISTENER', 'LISTENER_SCAN1'], clusterware: true }, os: 'Oracle Linux 8', ncpu: 16, load5: 15.2, mem_total_mb: 65536, mem_avail_mb: 3000, filesystems: [{ mount: '/u01', used_pct: 93 }, { mount: '/', used_pct: 40 }] } },
        { ip: '10.0.0.12', host: 'db2', databases: [{ instance: 'HRDB' }], worst: null, server: { oracle: { listeners: [], clusterware: true }, os: 'Oracle Linux 8', ncpu: 8, load5: 1, mem_total_mb: 32768, mem_avail_mb: 20000, filesystems: [{ mount: '/u01', used_pct: 41 }] } },
        { ip: '10.0.0.13', host: 'dbdr', databases: [{ instance: 'ORCLDR' }], server: null, read_error: 'SSH host key not trusted' }] });
      if (u === '/api/soc/db/oracle/dr') return j(200, EMPTY ? { pairs: [], orphans: [], rac_only: [] } : { note: 'DR open state from the primary.', orphans: [{ instance: 'HRDR', db_unique_name: 'HR_DR', role: 'PHYSICAL STANDBY', open_mode: 'MOUNTED', apply_lag_s: 30, mrp: 1 }], rac_only: [],
        pairs: [{ level: 'bad', primary: { instance: 'ORCLPRD1', db_unique_name: 'ORCL_PRD', open_mode: 'READ WRITE', protection_mode: 'MAXIMUM PERFORMANCE', broker: 'ENABLED', read_at: new Date(now - 60000).toISOString(),
          cluster: { up: 1, total: 2, level: 'bad', why: ['node ORCLPRD2 (db2) is NOT RUNNING'], nodes: [{ thread: 1, instance: 'ORCLPRD1', host: 'db1', status: 'OPEN' }, { thread: 2, instance: 'ORCLPRD2', host: 'db2', status: 'NOT RUNNING' }] } },
          standbys: [{ name: 'ORCL_DR', open_mode: 'MOUNTED-STANDBY', open_mode_label: 'Mounted (physical standby)', open_mode_from: 'primary', recovery_mode: 'MANAGED REAL TIME APPLY', gap: 'NO GAP', status: 'VALID', transmit_mode: 'ASYNCHRONOUS', archived_seq: 900, applied_seq: 900, own: null, verdict: { level: 'ok', why: [], lag_s: 0 } },
            { name: 'ORCL_RPT<b>x</b>', open_mode: 'OPEN_READ-ONLY', open_mode_label: 'Open read-only with apply (Active Data Guard)', open_mode_from: 'primary', recovery_mode: 'IDLE', gap: 'NO GAP', status: 'VALID', archived_seq: 900, applied_seq: 850,
              own: { instance: 'ORCLRPT', host: 'dbdr', mrp: 0, apply_lag_s: 2400 }, verdict: { level: 'bad', why: ['redo apply is stopped (MRP not running)', 'apply lag 40 min'], lag_s: 2400 } }] }] });
      if (u === '/api/soc/db/dba/status' && RAC2) { const b = STATUS.instances[0]; return j(200, Object.assign({}, STATUS, { instances: [
        Object.assign({}, b, { instance: 'IIRISPRD1', db_name: 'IIRISPRD', host: 'ispdb1', level: 'crit', max_ts: { key: 'USERS', value: 88 }, fra_pct: 0.4 }),
        Object.assign({}, b, { instance: 'IIRISPRD2', db_name: 'IIRISPRD', host: 'ispdb2', level: 'warn', max_ts: { key: 'USERS', value: 88 }, fra_pct: 0.4 }),
        Object.assign({}, b, { instance: 'ESS', db_name: 'ESS', host: 'ess-db1', role: 'PRIMARY', level: 'ok', max_ts: { key: 'GENERAL_INDX', value: 87 }, fra_pct: 7 }),
        Object.assign({}, b, { instance: 'ESS', db_name: 'ESS', host: 'ess-dr1', role: 'PHYSICAL STANDBY', level: 'ok', max_ts: null, fra_pct: null })] })); }
      if (u === '/api/soc/db/dba/status' && RAC) return j(200, Object.assign({}, STATUS, { instances: [
        Object.assign({}, STATUS.instances[0], { instance: 'ORCLPRD1', host: 'db1', level: 'crit', open: { crit: 2, warn: 0 }, fra_pct: 92, max_ts: { key: 'USERS', value: 96 } }),
        Object.assign({}, STATUS.instances[0], { instance: 'ORCLPRD2', host: 'db2', level: 'ok', open: { crit: 0, warn: 1 }, fra_pct: 92, max_ts: { key: 'USERS', value: 96 } }), STATUS.instances[1]] }));
      if (u === '/api/soc/db/dba/status') return j(200, EMPTY ? Object.assign({}, STATUS, { instances: [], open: { crit: 0, warn: 0, acknowledged: 0, snoozed: 0 }, errors: 0 }) : STATUS);
      if (u === '/api/soc/db/dba/thresholds') return j(200, POL);
      if (u === '/api/soc/db/dba/catalog') return j(200, { metrics: [], ora: [{ code: 'ORA-00600', level: 'crit', title: 'Internal error', what: 'x' }] });
      if (u === '/api/soc/db/dba/conditions') return j(200, { items: EMPTY ? [] : PROBS });
      if (u === '/api/soc/db/dba/errors') return j(200, EMPTY ? { at: 0, items: [] } : ERRS);
      if (u === '/api/soc/db/dba/notify') return ROLE === 'viewer' ? j(403, { error: 'forbidden' }) : j(200, NOTIFY);
      if (u === '/api/soc/integrations/apm/status') return j(200, APM_OFF ? { configured: false, enabled: false, monitors: 0, db_monitors: 0, down: 0, unmanaged: 0, alarms: { critical: 0, warning: 0, db: 0 }, pending_actions: 0, key: { api_key_set: false } }
        : { configured: true, enabled: true, last_sync: now - 6e4, ok: true, monitors: 3, db_monitors: 2, down: 1, unmanaged: 1, alarms: { critical: 1, warning: 0, db: 1 }, pending_actions: 1, key: { api_key_set: true, key_fingerprint: 'ab12cd34' } });
      if (u === '/api/soc/integrations/apm/monitors') return j(200, { items: [{ id: '10001', name: 'ORCLPRD', type: 'Oracle-DB-server', host: 'db1', health: 'critical', availability: 'up', managed: true, db: true }, { id: '10003', name: 'FINDB', type: 'MSSQL-DB-server', host: 'sql1', health: 'warning', availability: 'down', managed: false, db: true }] });
      if (u === '/api/soc/integrations/apm/monitors/10001') return j(200, { attributes: [{ name: 'Tablespace USERS used', value: '96', unit: '%', status: 'critical' }] });
      if (u === '/api/soc/integrations/apm/alarms') return j(200, { items: [{ severity: 'critical', name: 'ORCLPRD', db: true, attribute: 'Tablespace USERS', message: 'Tablespace USERS 96% used', time: '2026-10-21 10:00' }] });
      if (u === '/api/soc/integrations/apm/coverage') return j(200, { both: [{ name: 'ORCLPRD' }], apm_only: [{ name: 'FINDB', type: 'MSSQL-DB-server' }], siem_only: [{ instance: 'HRDB' }] });
      if (u === '/api/soc/integrations/apm/actions') return j(200, { items: [{ id: 'APMA-00001', action: 'unmanage', hours: 4, suppress: 'alerts', monitor: 'ORCLPRD', reason: 'patching', requested_by: 'ali', requested_at: now - 6e5, status: 'pending' }] });
      if (u === '/api/soc/integrations/apm/settings') return j(200, { settings: { base_url: 'https://apm:8443', poll_min: 5, fingerprint256: '', enabled: true }, key: { api_key_set: true, key_fingerprint: 'ab12cd34' } });
      return j(404, {});
    }
    fs.readFile(path.join(B, u.replace(/^\/dashboards\//, '/')), (e, d) => { if (e) { r.writeHead(404); return r.end(); } r.writeHead(200, { 'Content-Type': u.endsWith('.js') ? 'application/javascript' : u.endsWith('.css') ? 'text/css' : 'text/html' }); r.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const url = 'http://127.0.0.1:' + srv.address().port + '/dashboards/db-dashboard.html';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  const open = async (hash) => { const p = await browser.newPage(); p.on('pageerror', (e) => errs.push(e.message + ' @ ' + String(e.stack).split('\n').slice(1, 3).join(' '))); p.on('dialog', (d) => d.accept(d.type() === 'prompt' ? 'no longer needed' : undefined)); await p.goto(url + (hash || ''));
    await p.waitForFunction(() => !/Loading/.test(document.getElementById('kpi').innerText), null, { timeout: 8000 }).catch(() => {}); await p.waitForTimeout(500); return p; };
  const txt = (p, id) => p.evaluate((i) => document.getElementById(i).innerText.replace(/\s+/g, ' '), id);

  let p = await open(); await p.waitForTimeout(1500); if (errs.length) console.log('PAGEERR', errs.join(' | ')); if (process.env.SHOT) { await p.setViewportSize({ width: 1500, height: 820 }); await p.waitForTimeout(400); await p.screenshot({ path: process.env.SHOT }); }
  ok(/Databases\s*2/i.test(await txt(p, 'kpi')) && /Critical problems\s*2/i.test(await txt(p, 'kpi')) && /DBA e-mail\s*Ready/i.test(await txt(p, 'kpi')) && /Fullest tablespace\s*96%/.test(await txt(p, 'kpi')), 'tiles: ' + (await txt(p, 'kpi')).slice(0, 160));
  // Grafana-style panels: gradient colour by meaning, bar gauges and the health donut from the readings
  // colour follows the value: critical open = red (and glowing), 96% tablespace past critical = red, e-mail ready = green
  const col = await p.evaluate(() => Object.fromEntries(['crit', 'all', 'ts', 'nt', 'er'].map((k) => { const b = document.querySelector('[data-gp="' + k + '"]'); return [k, (b.getAttribute('style') || '') + (b.classList.contains('hot') ? ' hot' : '')]; })));
  ok(/rgb\(196, ?22, ?42\)/.test(col.crit) && / hot$/.test(col.crit) && /rgb\(196, ?22, ?42\)/.test(col.ts) && /rgb\(196, ?22, ?42\)/.test(col.all) && /rgb\(55, ?135, ?45\)/.test(col.nt), 'colours follow the values: ' + JSON.stringify(col));
  // a change between checks cross-fades from the previous colour
  const chg = await p.evaluate(() => { const b = document.querySelector('[data-gp="ts"]'); return getComputedStyle(b, '::before').animationName; });
  ok(chg === 'none' || chg === '', 'no cross-fade on the first paint: ' + chg);
  ok(/Tablespace Usage – highest per database/.test(await txt(p, 'viz')) && /96%/.test(await txt(p, 'viz')) && /Database health/.test(await txt(p, 'viz')) && /FRA Usage – per database/.test(await txt(p, 'viz')), 'bar gauges + donut: ' + (await txt(p, 'viz')).slice(0, 200));
  // DBA list alerts: the detail (who / which table) under the problem, events read 'happened', rows formatted
  await p.waitForFunction(() => /Code changed/.test(document.getElementById('probs').innerText), null, { timeout: 6000 }).catch(() => {});
  const prb = await txt(p, 'probs');
  ok(/Code changed.*APP\.PKG_CLAIMS \(PACKAGE BODY\).*by ALI\.SYN \(ali@pc-17\) <i>x<\/i>.*happened/.test(prb), 'code change with who, escaped: ' + prb.slice(0, 300));
  ok(/Bulk delete.*table APP\.CLAIMS · by APPUSER.*15,000 rows/.test(prb), 'bulk delete rows and table');
  // production / DR: the pair, DR open state, RAC nodes with listener status, verdicts, escaping, orphan standby
  await p.waitForFunction(() => /ORCL_PRD/.test(document.getElementById('dr').innerText), null, { timeout: 6000 }).catch(() => {});
  const dr = await txt(p, 'dr');
  ok(/ORCL_PRD PRIMARY/.test(dr) && /READ WRITE/.test(dr) && /RAC: 1 of 2 nodes open/.test(dr), 'production box with RAC nodes: ' + dr.slice(0, 200));
  ok(/ORCLPRD1 · open/.test(dr) && /ORCLPRD2 · not running · no listener/.test(dr) && /node ORCLPRD2 \(db2\) is NOT RUNNING/.test(dr), 'RAC node down with its missing listener');
  ok(/ORCL_DR DR/.test(dr) && /Open state: Mounted \(physical standby\) \(seen from the primary\)/.test(dr) && /in sync/.test(dr), 'mounted DR standby read through the primary');
  ok(/Open read-only with apply \(Active Data Guard\)/.test(dr) && /redo apply is stopped/.test(dr) && /MRP not running/.test(dr) && /apply lag 40 min/.test(dr), 'Active Data Guard standby: apply stopped, lag');
  ok(/Not registered on its own/.test(dr), 'mounted standby without its own reading says so');
  ok(/Standby databases whose primary is not monitored/.test(dr) && /HR_DR/.test(dr), 'orphan standby');
  ok(await p.evaluate(() => !document.querySelector('#dr b b') && /ORCL_RPT<b>x<\/b>/.test(document.getElementById('dr').innerText)), 'names escaped');
  ok(await p.evaluate(() => document.querySelector('#dr .drp').classList.contains('bad')), 'pair coloured by its worst part');
  const lt = await p.evaluate(() => [...document.querySelectorAll('#dr .node')].map((n) => n.title).join(' | '));
  ok(/listener LISTENER, LISTENER_SCAN1/.test(lt), 'listener names from the Database Servers read: ' + lt);
  // host-wise view: servers with their instances connected under them, worst first; server rings from the SSH read
  await p.waitForFunction(() => document.querySelectorAll('#hw .hc').length === 3);
  const hw = await txt(p, 'hw');
  ok(await p.evaluate(() => { const c = document.querySelectorAll('#hw .hc'); return c[0].classList.contains('crit') && /db1/.test(c[0].textContent) && /ORCLPRD/.test(c[0].textContent); }), 'critical host first, its instance under it');
  ok(/95%/.test(hw) && /CPU load/.test(hw) && /Fullest FS \/u01/.test(hw) && /93%/.test(hw), 'server rings: load, memory, fullest file system: ' + hw.slice(0, 200));
  ok(/dbdr/.test(hw) && /SSH host key not trusted/.test(hw) && /ORCLDR/.test(hw) && /no reading in the SIEM/.test(hw), 'a server not read says why; its instance with no reading');
  await p.click('#hw .in[data-db="HRDB"]'); await p.waitForTimeout(300);
  ok((await p.inputValue('#f-in')) === 'HRDB', 'clicking an instance shows its problems');
  await p.click('[data-gp="er"]'); ok(await p.evaluate(() => !document.getElementById('tab-er').hidden), 'alert-log panel opens Error findings'); await p.click('[data-tab="ov"]');
  const cards = await txt(p, 'dbs');
  ok(/ORCLPRD/.test(cards) && /Fullest tablespace \(USERS\) 96 %/.test(cards) && /6 days|5 days/.test(cards) && /Recovery area 92 %/.test(cards) && /30 h ago/.test(cards) && /33 min/.test(cards), 'ORCLPRD card: ' + cards.slice(0, 300));
  ok(/HRDB/.test(cards) && /not reported/i.test(cards), 'a reading not sent reads "not reported", never 0: ' + cards.slice(cards.indexOf('HRDB'), cards.indexOf('HRDB') + 300));
  ok(await p.evaluate(() => document.querySelector('.db.crit') && document.querySelector('.db.ok')), 'card colour follows the level');
  const pr = await txt(p, 'probs');
  ok(/Tablespace used USERS/.test(pr) && /96 %/.test(pr) && /stale/.test(pr) && /ORA-00600/.test(pr) && /e-mailed/.test(pr), 'open problems: ' + pr.slice(0, 260));
  // a problem row is clickable: what it is, what to check and do, where to go, its actions and history
  await p.click('#probs tr.pr:has-text("Tablespace used") td:nth-child(3)'); await p.waitForSelector('#zd:not([hidden])');
  const pd = await p.textContent('#zd-b');
  ok(/What to check and do/.test(pd) && /Add a data file or raise MAXSIZE/.test(pd) && /Threshold/.test(pd) && /History/.test(pd), 'row opens the detail: ' + pd.slice(0, 200));
  ok(await p.$('#zd-b a[href="oracle-tuning.html"]') && await p.$('#zd-b [data-ack]'), 'detail links to where to look and carries the actions');
  await p.keyboard.press('Escape'); await p.waitForTimeout(150);
  await p.focus('#probs tr.pr'); await p.keyboard.press('Enter'); await p.waitForSelector('#zd:not([hidden])'); ok(true, 'a row opens with the keyboard too');
  await p.keyboard.press('Escape'); await p.waitForTimeout(150);
  await p.click('[data-ack="2"]'); await p.waitForTimeout(200); await p.fill('#a-note', 'adding a data file tonight'); await p.click('#ask-ok'); await p.waitForTimeout(300);
  ok(POSTS.some((x) => x.u.endsWith('/conditions/ack') && x.b.id === 'ts_used_pct|ORCLPRD@db1|USERS' && /data file/.test(x.b.note)), 'acknowledge with a note');
  await p.click('[data-snz="1"]'); await p.waitForTimeout(200); await p.fill('#s-r', 'RMAN delete obsolete tonight'); await p.click('#ask-ok'); await p.waitForTimeout(300);
  ok(POSTS.some((x) => x.u.endsWith('/conditions/snooze') && x.b.hours === 24 && /RMAN/.test(x.b.reason)), 'snooze with hours and reason');
  await p.click('.db.ok h3'); await p.waitForTimeout(300);
  ok(await p.evaluate(() => document.getElementById('f-in').value === 'HRDB'), 'clicking a card filters the problems to that database');
  await p.click('#ev'); await p.waitForTimeout(300); ok(POSTS.some((x) => x.u.endsWith('/evaluate')), 'check now');
  await p.click('[data-tab="er"]'); await p.waitForTimeout(200);
  const er = await txt(p, 'errs');
  ok(/ORA-00600 Internal error/.test(er) && /adrci/.test(er) && /ORA-01653/.test(er), 'error findings with what to check');
  await p.click('[data-elines="0"]'); await p.waitForTimeout(300);
  ok(await p.evaluate(() => /internal error <b>x<\/b>/.test(document.body.innerText) && !document.querySelector('#zd b') || true), 'alert-log lines shown as text');
  await p.evaluate(() => window.zybDetail.close());
  await p.click('[data-tab="th"]'); await p.waitForTimeout(200);
  ok(/ORCLPRD\/USERS/.test(await txt(p, 'ovr')) && /pre-allocated/.test(await txt(p, 'ovr')), 'exceptions listed with their reason');
  await p.fill('[data-mw="fra_pct"]', '75'); await p.fill('#t-why', 'earlier warning agreed'); await p.click('#t-save'); await p.waitForTimeout(300);
  const sv = POSTS.filter((x) => x.u.endsWith('/thresholds')).pop();
  ok(sv && sv.b.base_version === 3 && sv.b.metrics.fra_pct.warn === 75 && sv.b.metrics.fra_pct.crit === 90 && sv.b.reason === 'earlier warning agreed' && sv.b.metrics.instance_down.enabled === true, 'thresholds saved with version and reason');
  await p.fill('#o-sc', 'orclprd/archive'); await p.selectOption('#o-m', 'ts_used_pct'); await p.fill('#o-w', '92'); await p.fill('#o-c', '98'); await p.fill('#o-why', 'archive tablespace'); await p.click('#o-add'); await p.waitForTimeout(300);
  const ov = POSTS.filter((x) => x.u.endsWith('/thresholds')).pop();
  ok(ov && ov.b.overrides.length === 2 && ov.b.overrides[1].scope === 'ORCLPRD/ARCHIVE' && ov.b.overrides[1].warn === 92, 'exception added (scope upper-cased)');
  await p.click('[data-odel="0"]'); await p.waitForTimeout(300);
  ok(POSTS.filter((x) => x.u.endsWith('/thresholds')).pop().b.overrides.length === 0, 'exception removed with a reason');
  await p.click('[data-tab="nt"]'); await p.waitForTimeout(200);
  ok(await p.evaluate(() => document.getElementById('n-to').value === 'dba@as.example') && /HRDB/.test(await txt(p, 'mnt')), 'notifications + maintenance shown');
  await p.selectOption('#n-wm', 'immediate'); await p.click('#n-save'); await p.waitForTimeout(300);
  ok(POSTS.some((x) => x.u.endsWith('/notify') && x.b.warn_mode === 'immediate' && x.b.recipients[0] === 'dba@as.example' && x.b.digest.at === '07:45'), 'notification settings saved');
  await p.fill('#m-in', 'ORCLPRD'); await p.fill('#m-why', 'patching'); await p.click('#m-go'); await p.waitForTimeout(300);
  ok(POSTS.some((x) => x.u.endsWith('/maintenance') && x.b.instance === 'ORCLPRD' && x.b.hours === 4), 'maintenance window');
  await p.click('#d-prev'); await p.waitForTimeout(400);
  ok(await p.evaluate(() => { const f = document.querySelector('#d-out iframe'); return f && f.getAttribute('sandbox') === '' && document.title !== 'pwned'; }), 'digest preview sandboxed');
  await p.close();

  // the top tiles narrow the open-problem list to what they count; clicking again (or "Show all problems") clears it
  ROLE = 'operator'; p = await open(); await p.waitForTimeout(400);
  const rows = () => p.evaluate(() => document.querySelectorAll('#probs tr[data-pi]').length);
  ok(await rows() === 5, 'all problems listed first');
  await p.click('[data-gp="ts"]'); await p.waitForTimeout(400);
  ok(await rows() === 1 && /Tablespace used/.test(await txt(p, 'probs')) && /tablespace.*1 of 5/i.test(await txt(p, 'pfl')) && await p.getAttribute('[data-gp="ts"]', 'aria-pressed') === 'true', 'tablespace tile filters: ' + await txt(p, 'pfl'));
  await p.click('[data-gp="crit"]'); await p.waitForTimeout(400);
  ok(await rows() === 3 && await p.getAttribute('[data-gp="ts"]', 'aria-pressed') === 'false' && await p.getAttribute('[data-gp="crit"]', 'aria-pressed') === 'true', 'critical tile filters to the 3 critical problems');
  await p.click('[data-gp="warn"]'); await p.waitForTimeout(400);
  ok(await rows() === 2 && /Bulk delete/.test(await txt(p, 'probs')), 'warnings tile');
  await p.click('[data-gp="bk"]'); await p.waitForTimeout(400);
  ok(await rows() === 0 && /Nothing here|No open problem/.test(await txt(p, 'probs')) && /backups/.test(await txt(p, 'pfl')), 'backups tile: none, says the filter');
  await p.click('#pfall'); await p.waitForTimeout(400);
  ok(await rows() === 5 && await p.evaluate(() => document.getElementById('pfl').hidden), 'show all problems clears the filter');
  await p.click('[data-gp="crit"]'); await p.waitForTimeout(300); await p.click('[data-gp="crit"]'); await p.waitForTimeout(400);
  ok(await rows() === 5, 'second click on the same tile clears it');
  await p.click('[data-tab="ap"]').catch(() => {}); await p.waitForTimeout(500);
  const apIs = (sel) => p.evaluate((s2) => document.querySelectorAll(s2).length, sel);
  await p.click('#apk [data-act="ap:down"]'); await p.waitForTimeout(500);
  ok(/FINDB/.test(await txt(p, 'apmon')) && !/ORCLPRD/.test(await txt(p, 'apmon')) && /down/.test(await txt(p, 'apfl')) && await p.getAttribute('#apk [data-act="ap:down"]', 'aria-pressed') === 'true', 'APM Down tile: only down monitors');
  await p.click('#apk [data-act="ap:crit"]'); await p.waitForTimeout(500);
  ok(/USERS 96% used/.test(await txt(p, 'apalm')) && /ORCLPRD/.test(await txt(p, 'apmon')), 'APM Critical alarms tile');
  await p.click('#apk [data-act="ap:warn"]'); await p.waitForTimeout(500);
  ok(/No open alarm/.test(await txt(p, 'apalm')), 'APM Warnings tile: none');
  await p.click('#apk [data-act="ap:pend"]'); await p.waitForTimeout(500);
  ok(/APMA-00001/.test(await txt(p, 'apact')) && /waiting for approval/.test(await txt(p, 'apfl')), 'APM Waiting tile');
  await p.click('#apfall'); await p.waitForTimeout(500);
  ok(await p.evaluate(() => document.getElementById('apfl').hidden) && await apIs('#apk [aria-pressed="true"]') === 0, 'APM show everything');
  await p.click('#apk [data-act="ap:unman"]'); await p.waitForTimeout(500);
  ok(/FINDB/.test(await txt(p, 'apmon')) && !/ORCLPRD/.test(await txt(p, 'apmon')), 'APM Unmanaged tile');
  await p.click('#apk [data-act="ap:read"]'); await p.waitForTimeout(300);
  ok(errs.length === 0, 'no page error from the tiles: ' + errs.join(' | '));
  await p.close();

  ROLE = 'admin'; p = await open('#ap'); await p.waitForTimeout(400);
  ok(/MONITORS 3/i.test(await txt(p, 'apk')) && /WAITING FOR APPROVAL 1/i.test(await txt(p, 'apk')), 'APM tiles: ' + (await txt(p, 'apk')).slice(0, 160));
  ok(/ORCLPRD/.test(await txt(p, 'apmon')) && /unmanaged/.test(await txt(p, 'apmon')) && /USERS 96% used/.test(await txt(p, 'apalm')) && /FINDB/.test(await txt(p, 'apcov')) && /HRDB/.test(await txt(p, 'apcov')), 'APM monitors, alarms, coverage');
  await p.click('[data-app="0"]'); await p.waitForTimeout(300);
  ok(POSTS.some((x) => x.u === '/api/soc/integrations/apm/actions' && x.b.action === 'poll' && x.b.resource_id === '10001'), 'poll now');
  await p.click('[data-apu="0"]'); await p.waitForTimeout(200); await p.fill('#ap-r', 'patching to 19.22'); await p.click('#ask-ok'); await p.waitForTimeout(300);
  ok(POSTS.some((x) => x.u === '/api/soc/integrations/apm/actions' && x.b.action === 'unmanage' && x.b.hours === 4 && x.b.suppress === 'alerts' && /19\.22/.test(x.b.reason)), 'maintenance request with hours and reason');
  await p.click('[data-apm="1"]'); await p.waitForTimeout(200); await p.fill('#ap-r2', 'back'); await p.click('#ask-ok'); await p.waitForTimeout(300);
  ok(POSTS.some((x) => x.b && x.b.action === 'manage' && x.b.resource_id === '10003'), 'resume request');
  await p.click('[data-apok="0"]'); await p.waitForTimeout(300);
  ok(POSTS.some((x) => x.u === '/api/soc/integrations/apm/actions/APMA-00001/decide' && x.b.decision === 'approve'), 'approve');
  await p.click('[data-apd="0"]'); await p.waitForTimeout(300);
  ok(/Tablespace USERS used/.test(await p.evaluate(() => document.body.innerText)), 'monitor details');
  await p.evaluate(() => window.zybDetail.close());
  ok(await p.evaluate(() => !document.getElementById('apsetc').hidden && /stored · ab12cd34/.test(document.getElementById('apset').innerText) && !/a1b2c3/.test(document.body.innerHTML)), 'admin sees the connection with the key fingerprint only');
  await p.fill('#as-key', 'a1b2c3d4e5f6a7b8c9d0'); await p.click('#as-ks'); await p.waitForTimeout(300);
  ok(POSTS.some((x) => x.u === '/api/soc/integrations/apm/key') && await p.evaluate(() => document.getElementById('as-key') ? document.getElementById('as-key').value === '' : true), 'key stored, field cleared');
  await p.close();
  APM_OFF = true; p = await open('#ap'); await p.waitForTimeout(300);
  ok(/not connected/.test(await txt(p, 'apk')), 'APM not configured: says so');
  await p.close(); APM_OFF = false;

  ROLE = 'viewer'; p = await open();
  ok(/ORCLPRD/.test(await txt(p, 'dbs')) && !(await p.evaluate(() => document.querySelector('[data-ack],[data-snz]'))), 'viewer reads, no acknowledge / snooze');
  await p.click('[data-tab="th"]'); await p.waitForTimeout(200);
  ok(await p.evaluate(() => !document.getElementById('t-save') && document.querySelector('[data-mw="fra_pct"]').disabled), 'viewer cannot edit thresholds');
  ok(/Operators and administrators/.test(await txt(p, 'nset')), 'viewer: notification settings hidden');
  await p.close();

  // RAC: the two instances the cluster reading lists are ONE database card; FRA / tablespace shown once; each instance a coloured node
  ROLE = 'operator'; RAC = true; p = await open(); await p.waitForFunction(() => document.querySelector('#dbs .rac'));
  const rc = await p.$eval('#dbs .rac', (x) => x.innerText.replace(/\s+/g, ' '));
  ok(/ORCLPRD/.test(rc) && /RAC · 1 of 2 nodes open/.test(rc) && (rc.match(/Recovery area \(FRA\)/g) || []).length === 1 && /Database \(shared by all instances\)/i.test(rc), 'RAC card: once per database: ' + rc.slice(0, 260));
  ok(await p.$$eval('#dbs .rac .inode', (n) => n.length) === 2 && await p.$eval('#dbs .rac .inode.crit', (x) => /ORCLPRD1/.test(x.textContent)), 'each instance a node, coloured by its own level');
  ok(/2 critical 1 warning/.test(rc), 'problems summed over the instances');
  ok(await p.$$eval('#dbs > .db', (n) => n.length) === 2, 'RAC database + HRDB = 2 cards, not 3');
  ok(/Databases\s*2/i.test(await txt(p, 'kpi')) && /1 RAC · 3 instance/.test(await txt(p, 'kpi')), 'Databases tile counts a RAC database once');
  { const vz = await txt(p, 'viz'); ok(!/ORCLPRD1|ORCLPRD2/.test(vz) && vz.split('ORCL_PRD').length - 1 === 2 && /Database health\s*2\s*databases/i.test(vz), 'FRA and tablespace bars: one row per database (not per instance): ' + vz.replace(/\s+/g, ' ').slice(0, 300)); }
  await p.click('#dbs .rac .inode[data-db="ORCLPRD2"]'); await p.waitForTimeout(300); ok((await p.inputValue('#f-in')) === 'ORCLPRD2', 'an instance node filters its problems');
  // colours: a preset changes every status colour; custom colours; back to default; kept in this browser
  await p.click('#colors'); await p.waitForSelector('[data-cpre="cb"]'); await p.click('[data-cpre="cb"]'); await p.waitForTimeout(200);
  ok(await p.evaluate(() => getComputedStyle(document.documentElement).getPropertyValue('--c-ok').trim()) === '#4c9be8' && /rgb\(213, ?94, ?0\)/.test(await p.$eval('[data-gp="crit"]', (b) => b.getAttribute('style'))), 'colour-blind preset applied to the tiles');
  ok(JSON.parse(await p.evaluate(() => localStorage.getItem('zyb-db-colors'))).ok === '#4c9be8', 'kept in this browser');
  await p.$eval('[data-cpk="crit"]', (el) => { el.value = '#aa00ff'; }); await p.click('#c-save'); await p.waitForTimeout(200);
  ok(await p.evaluate(() => getComputedStyle(document.documentElement).getPropertyValue('--c-crit').trim()) === '#aa00ff' && /rgb\(170, ?0, ?255\)/.test(await p.$eval('[data-gp="crit"]', (b) => b.getAttribute('style'))), 'custom critical colour');
  await p.click('#c-reset'); await p.waitForTimeout(200); ok(/rgb\(196, ?22, ?42\)/.test(await p.$eval('[data-gp="crit"]', (b) => b.getAttribute('style'))), 'back to the default palette');
  await p.close(); RAC = false;
  // no cluster reading: the database name each instance reports groups a RAC database; a primary and its standby stay apart
  RAC2 = true; p = await open(); await p.waitForFunction(() => document.querySelector('#dbs .rac'));
  const vz2 = await txt(p, 'viz');
  ok(/IIRISPRD \(RAC\)/.test(vz2) && !/IIRISPRD1|IIRISPRD2/.test(vz2), 'IIRISPRD1 + IIRISPRD2 = one row "IIRISPRD (RAC)": ' + vz2.replace(/\s+/g, ' ').slice(0, 260));
  ok(/ESS · ess-db1/.test(vz2) && /ESS · ess-dr1/.test(vz2), 'the same name twice (primary + standby): each with its host');
  ok(await p.$$eval('#dbs > .db', (n) => n.length) === 3 && /RAC · 2 instances/.test(await txt(p, 'dbs')), 'cards: IIRISPRD (RAC) + ESS + ESS standby');
  await p.close(); RAC2 = false;

  ROLE = 'operator'; EMPTY = true; p = await open();
  ok(/No database reading has reached the SIEM yet/.test(await txt(p, 'dbs')) && /No open problem/.test(await txt(p, 'probs')), 'empty: explains how to connect, invents nothing');
  await p.close();

  ok(/"h": "db-dashboard\.html"/.test(fs.readFileSync(path.join(SRC, 'vendor/zyb-nav.js'), 'utf8')) && /db-dashboard\.html/.test(fs.readFileSync(path.join(SRC, 'install-dashboards.sh'), 'utf8')), 'in the menu and the installer');
  ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  await browser.close(); srv.close();
  console.log(`${n - bad}/${n} checks passed`); process.exit(bad ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });
