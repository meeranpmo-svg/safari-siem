// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for db-replication.html: the REAL IT Asset Management engine (db-replicate.js; the database helper scripted)
// and the REAL SIEM tuning module (sentra-siem engine/db-audit/tuning.js) holding Data Guard / GoldenGate readings parsed by the
// real oracle-health parser. Checks: Data Guard tab (standby, gap / apply, force logging finding with its fix), GoldenGate,
// a comparison created through the form (passwords sealed, not echoed), run, results, repair proposed and approved by
// another person; a Change Stream started with its changes listed; a replication job created as a draft, readiness filling
// the primary key, approved by a second person (not the creator), started.
// Run: SENTRA_SIEM_DIR=/home/user/sentra-siem PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node db-replication.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const ITAM = path.resolve(__dirname, '../../backend/itam'), DASH = path.resolve(__dirname, '../../ui');
const SIEM = process.env.SENTRA_SIEM_DIR || path.resolve(__dirname, '../../backend/siem');
const H = require(path.join(ITAM, 'tests/helpers.js'));
const OH = require(path.join(SIEM, 'engine/db-audit/oracle-health')), { createTuning } = require(path.join(SIEM, 'engine/db-audit/tuning'));
let WHO = { user: 'syed', role: 'admin' };
let n = 0, bad = 0;
const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };

(async () => {
  // SIEM: Data Guard + GoldenGate readings for ESS
  const T = createTuning({ now: () => Date.now() });
  const st = (o) => { const e = OH.parse(JSON.stringify(Object.assign({ collector: 'sentra-oracle-itam', host: 'eskaprd', instance: 'ESS', t: new Date(Date.now() - 60000).toISOString() }, o))); e.src_type = 'oracle-health'; T.stage(e); };
  st({ kind: 'dg_config', role: 'PRIMARY', protection_mode: 'MAXIMUM PERFORMANCE', protection_level: 'MAXIMUM PERFORMANCE', force_logging: 'NO', flashback: 'YES', broker: 'DISABLED', db_unique_name: 'ESS_PRD', standbys: 1, switchover_status: 'TO STANDBY' });
  st({ kind: 'dg_dest', dest_id: 2, db_unique_name: 'ESS_DR', status: 'VALID', gap_status: 'RESOLVABLE GAP', recovery_mode: 'MANAGED REAL TIME APPLY', archived_seq: 900, applied_seq: 880, transmit_mode: 'ASYNCHRONOUS' });
  st({ kind: 'dg_applied', dest_id: 2, thread: 1, last_seq: 900, applied_seq: 880, unapplied: 20, unapplied_since_s: 2400 });
  st({ kind: 'gg_apply', name: 'RPROD', status: 'ABORTED', error: 'ORA-01403: no data found' });

  // ITAM engine with a scripted helper
  const e = await H.startApp({ noAi: true });
  const creds = [];
  const vault = { list: () => creds, get: (id) => creds.find((c) => c.id === id), create: (b) => { const c = Object.assign({ id: 'cr' + (creds.length + 1) }, b, { _s: b.secret }); delete c.secret; creds.push(c); return c; }, open: (id) => { const c = creds.find((x) => x.id === id); return { target: c.target, secret: Object.assign({}, c._s), release() {} }; } };
  const helper = async (r) => {
    if (r.op === 'verify_describe') return { ok: true, tables: [{ ok: true, src: { owner: 'APP', table: 'ORDERS' }, tgt: { owner: 'RPT', table: 'ORDERS' }, cmp: { pk: [['ID', 'ID']], data: [['AMT', 'AMT', 'NUMBER']] }, only_source: [], only_target: [], lob_columns: [] }] };
    if (r.op === 'verify_chunk') return r.phase === 'forward' ? { ok: true, rows: 1200, missing: [[17]], different: [[42]], extra: [], missing_n: 1, different_n: 1, extra_n: 0, next: [1200], done: true } : { ok: true, rows: 1200, missing: [], different: [], extra: [], missing_n: 0, different_n: 0, extra_n: 0, next: [1200], done: true };
    if (r.op === 'verify_keys') return { ok: true, missing: [[17]], different: [[42]], extra: [], equal: 0 };
    if (r.op === 'logminer_read') return !r.cursor ? { ok: true, txns: [], cursor: { commit_scn: 10, restart_scn: 10 }, info: {} } : { ok: true, cursor: { commit_scn: 20, restart_scn: 20 }, info: { lag_s: 5 }, txns: [{ xid: 'A1', commit_scn: 15, commit_ts: '2026-10-20T22:10:00', user: 'SCOTT', os_user: 'scott', machine: 'pc-17', program: 'sqlplus@pc-17', rows: 3, tables: { 'APP.ORDERS': { INSERT: 0, UPDATE: 3, DELETE: 0 } }, ddl: [] }] };
    if (r.op === 'repl_status') return { ok: true, source: { current_scn: 900, log_mode: 'ARCHIVELOG', supplemental_min: 'YES', tables: [{ table: 'APP.ORDERS', pk: ['ID'], pk_logging: true }] }, checkpoint: { commit_scn: 850, restart_scn: 850 } };
    if (r.op === 'repl_cycle') return { ok: true, stats: { txns: 4, rows: 9, conflicts: [] }, stopped: null, info: { lag_s: 3 } };
    return { ok: false, error_class: 'error', error: 'unexpected' };
  };
  const R = require(path.join(ITAM, 'engine/db-replicate')).registerReplicate(e.app.srv, e.app, { discovery: { vault }, dbHealth: { push: async (x) => x.length }, invRun: helper, later: (fn) => setTimeout(fn, 50), noTimer: true });

  const srv = http.createServer(async (req, res) => {
    const u = new URL(req.url, 'http://x'), json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u.pathname === '/dashboards/whoami.json') return json(200, WHO);
    if (u.pathname === '/api/soc/db/oracle/tuning') return json(200, await T.view(Object.fromEntries(u.searchParams)));
    if (u.pathname.startsWith('/api/itam/')) {
      const h = Object.assign({}, req.headers, { 'x-sentra-proxy-secret': H.SECRET, 'x-auth-user': WHO.user, 'x-auth-role': WHO.role });
      const up = http.request({ host: '127.0.0.1', port: e.port, method: req.method, path: req.url, headers: h }, (r) => { res.writeHead(r.statusCode, r.headers); r.pipe(res); });
      req.pipe(up); return;
    }
    if (u.pathname.startsWith('/api/')) return json(404, { error: 'not in this test' });
    fs.readFile(path.join(DASH, u.pathname), (err, d) => { if (err) { res.writeHead(404); res.end(); return; } res.writeHead(200, { 'Content-Type': u.pathname.endsWith('.js') ? 'application/javascript' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port + '/';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(); const page = await browser.newPage({ viewport: { width: 1400, height: 950 } }); const errs = [];
  let answer = 'CHG-2231';
  page.on('dialog', (d) => d.accept(answer)); page.on('pageerror', (x) => errs.push(x.message)); page.on('console', (m) => { if (m.type() === 'error' && !/40[034]/.test(m.text())) errs.push(m.text()); });
  const body = () => page.$eval('#body', (x) => x.innerText);

  await page.goto(base + 'db-replication.html'); await page.waitForSelector('#body .k, #body .err, #body .empty');
  let t = await body();
  ok(/PRIMARY/.test(t) && /ESS_DR/.test(t) && /RESOLVABLE GAP/.test(t) && /40 min/.test(t), 'Data Guard tab: standby, gap, waiting time');
  ok(/Force logging is off on a primary with a standby/.test(t) && /Standby ESS_DR has an archive gap/.test(t), 'Data Guard findings');
  await page.click('details summary'); t = await body(); ok(/ALTER DATABASE FORCE LOGGING;/.test(t) && /ALTER DATABASE NO FORCE LOGGING;/.test(t), 'fix + rollback shown');
  await page.click('[data-tab="gg"]'); t = await body(); ok(/RPROD/.test(t) && /ABORTED/.test(t) && /ORA-01403/.test(t), 'GoldenGate tab');

  // Data Verify: create through the form
  await page.click('[data-tab="verify"]'); await page.click('[data-new="verify"]'); await page.waitForSelector('#zd-b #nsave');
  const fill = async (sel, v) => page.fill('#zd-b ' + sel, v);
  await fill('#shost', '192.168.9.30'); await fill('#ssvc', 'ESS'); await fill('#suser', 'zyb_verify'); await fill('#spw', 'Src-Pw-1'); await fill('#slabel', 'ESS');
  await page.selectOption('#zd-b #teng', 'oracle'); await fill('#thost', '192.168.9.40'); await fill('#tsvc', 'RPT'); await fill('#tuser', 'zyb_verify'); await fill('#tpw', 'Tgt-Pw-1'); await fill('#tlabel', 'RPT');
  await fill('#nname', 'ERP copy'); await fill('#ntabs', 'APP.ORDERS -> RPT.ORDERS'); await page.fill('#zd-b #nre', '10');
  await page.click('#zd-b #nsave'); await page.waitForFunction(() => /VER-0001/.test(document.getElementById('body').innerText));
  const vj = e.app.store.collection('repl_jobs').get('VER-0001');
  ok(vj && vj.tables[0].tgt_owner === 'RPT' && creds.length === 2 && !JSON.stringify(vj).includes('Src-Pw-1'), 'job saved, logins sealed, no password in the job');
  await page.click('[data-run="VER-0001"]');
  for (let i = 0; i < 60 && (e.app.store.collection('repl_runs').all()[0] || {}).state !== 'done'; i++) await new Promise((r) => setTimeout(r, 100));
  await page.click('#refresh'); await page.waitForFunction(() => /Propose repair/.test(document.getElementById('body').innerText));
  t = await body(); ok(/1 table\(s\) differ/.test(t) && /APP\.ORDERS/.test(t), 'result: differs');
  answer = ''; await page.click('[data-repair]'); await page.waitForFunction(() => /REPAIR-0001/.test(document.getElementById('body').innerText));
  WHO = { user: 'syed', role: 'admin' };   // syed asked for it: approving must be refused
  await page.click('[data-prop="REPAIR-0001"]'); await page.waitForSelector('#zd-b [data-dec="approve"]'); await page.click('#zd-b [data-dec="approve"]');
  await new Promise((r) => setTimeout(r, 400));
  ok(e.app.store.collection('repl_proposals').get('REPAIR-0001').status === 'proposed', 'the requester cannot approve their own repair');
  WHO = { user: 'rasheed', role: 'admin' }; await page.reload(); await page.click('[data-tab="verify"]');
  await page.click('[data-prop="REPAIR-0001"]'); await page.waitForSelector('#zd-b [data-dec="approve"]'); await page.click('#zd-b [data-dec="approve"]');
  await page.waitForFunction(() => /approved/.test(document.getElementById('body').innerText));
  ok(e.app.store.collection('repl_proposals').get('REPAIR-0001').approve_by === 'rasheed', 'another person approved it');

  // Change Stream
  WHO = { user: 'syed', role: 'admin' }; await page.reload();
  await page.click('[data-tab="stream"]'); await page.click('[data-new="stream"]'); await page.waitForSelector('#zd-b #nsave');
  await fill('#shost', '192.168.9.30'); await fill('#ssvc', 'ESS'); await fill('#suser', 'zyb_miner'); await fill('#spw', 'Miner-Pw-1'); await fill('#nname', 'ERP changes'); await fill('#nown', 'APP');
  await page.click('#zd-b #nsave'); await page.waitForFunction(() => /CS-0001/.test(document.getElementById('body').innerText));
  await page.click('[data-start="CS-0001"]'); await new Promise((r) => setTimeout(r, 300)); R.stopTimer('CS-0001');
  await R.streamCycle(R.get('CS-0001'));
  await page.click('#refresh'); await page.waitForSelector('[data-changes="CS-0001"]'); await page.click('[data-changes="CS-0001"]'); await page.waitForSelector('#chg table');
  t = await page.$eval('#chg', (x) => x.innerText); ok(/SCOTT/.test(t) && /sqlplus@pc-17/.test(t) && /APP\.ORDERS/.test(t), 'changes listed (metadata only)');

  // Replication: draft -> readiness -> approval by a second person -> start
  await page.click('[data-tab="repl"]'); await page.click('[data-new="replicate"]'); await page.waitForSelector('#zd-b #nsave');
  await fill('#shost', '192.168.9.30'); await fill('#ssvc', 'ESS'); await fill('#suser', 'zyb_miner2'); await fill('#spw', 'M2-pw');
  await fill('#thost', '10.5.5.5'); await fill('#tsvc', 'rep'); await fill('#tuser', 'zyb_writer'); await fill('#tpw', 'W-pw'); await fill('#nname', 'ERP to reporting'); await fill('#ntabs', 'APP.ORDERS');
  await page.click('#zd-b #nsave'); await page.waitForFunction(() => /REP-0001/.test(document.getElementById('body').innerText));
  ok(/waiting for a second person/.test(await body()), 'draft waits for a second person');
  await page.click('[data-repl="REP-0001"]'); await page.waitForSelector('#zd-b #rchk'); await page.click('#zd-b #rchk');
  await page.waitForFunction(() => /ARCHIVELOG/.test((document.getElementById('zd-b') || {}).innerText || ''));
  ok(JSON.stringify(e.app.store.collection('repl_jobs').get('REP-0001').tables[0].pk) === '["ID"]', 'readiness filled the primary key');
  answer = 'CHG-2231'; await page.waitForSelector('#zd-b #rapp'); await page.click('#zd-b #rapp'); await new Promise((r) => setTimeout(r, 400));
  ok(e.app.store.collection('repl_jobs').get('REP-0001').state === 'draft', 'the creator cannot approve it');
  // an operator needs the AI Oracle DBA approver role (Roles & Functions) - the real gate refuses one without it
  WHO = { user: 'rasheed', role: 'admin' }; await page.reload(); await page.click('[data-tab="repl"]');
  await page.click('[data-repl="REP-0001"]'); await page.waitForSelector('#zd-b #rapp'); await page.click('#zd-b #rapp');
  await page.waitForFunction(() => /approved by rasheed/.test(document.getElementById('body').innerText));
  WHO = { user: 'syed', role: 'admin' }; await page.reload(); await page.click('[data-tab="repl"]');
  await page.click('[data-repl="REP-0001"]'); await page.waitForSelector('#zd-b #rstart'); await page.click('#zd-b #rstart');
  await page.waitForFunction(() => /running/.test(document.getElementById('body').innerText)); R.stopTimer('REP-0001');
  ok(e.app.store.collection('repl_jobs').get('REP-0001').approval.note === 'CHG-2231', 'approval reference recorded');

  ok(!errs.length, 'page errors: ' + errs.join(' | '));
  await browser.close(); srv.close(); await e.close();
  console.log(bad ? 'FAILED ' + bad + ' of ' + n : 'OK ' + n + ' checks'); process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
