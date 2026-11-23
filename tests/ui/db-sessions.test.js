// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for db-sessions.html (Long-Running Queries) after the static build: in the Databases menu, database picker,
// tiles, blockers first with why they hurt, session drawer, Cancel SQL / Kill session as requests with a reason, approve /
// reject (never shown on your own request), setup of the session-control login and the DBA script, viewer kept out.
// API answers are SYNTHETIC, in the shape engine/db-sessions.js returns.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node db-sessions.test.js
const http = require('http'), fs = require('fs'), path = require('path'), os = require('os'), cp = require('child_process');
const SRC = path.resolve(__dirname, '../../ui');
let n = 0, bad = 0;
const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const B = fs.mkdtempSync(path.join(os.tmpdir(), 'dbsess-')); fs.mkdirSync(path.join(B, 'vendor'));
fs.readdirSync(SRC).filter((f) => f.endsWith('.html')).forEach((f) => fs.copyFileSync(path.join(SRC, f), path.join(B, f)));
fs.readdirSync(path.join(SRC, 'vendor')).filter((f) => /\.(js|json|css)$/.test(f)).forEach((f) => fs.copyFileSync(path.join(SRC, 'vendor', f), path.join(B, 'vendor', f)));
['zyb-menu.js', 'zyb-dash.js'].forEach((t) => fs.writeFileSync(path.join(B, 'vendor', t), fs.readFileSync(path.join(B, 'vendor/zyb-nav.js'), 'utf8') + '\n' + fs.readFileSync(path.join(B, 'vendor', t), 'utf8')));
cp.execFileSync(process.execPath, [path.join(SRC, 'build-static.js'), B, 't1'], { stdio: 'ignore' });
const at = new Date().toISOString();
const SESS = [
  { key: '1:202:7002', inst_id: 1, sid: 202, serial: 7002, username: 'HR_BATCH', status: 'INACTIVE', elapsed_s: 900, blocks: 4, machine: 'hr-job', program: 'sqlplus', why: ['blocks 4 other sessions', 'idle but holding locks (an open transaction nobody is finishing)'], score: 1400, sql_id: '', sql_text: '' },
  { key: '1:101:5001', inst_id: 1, sid: 101, serial: 5001, username: 'APP_ERP', status: 'ACTIVE', elapsed_s: 5400, state: 'WAITING', event: 'db file scattered read', sql_id: 'abcd1234efgh5', sql_text: 'select * from gl_lines where amount > :n', blocks: 0, temp_mb: 3072, machine: 'erp-app1', why: ['running for 1.5 h', '3 GB of TEMP', 'waiting on db file scattered read'], score: 120, longop: { done: 40, total: 100, remaining_s: 600, op: 'Table Scan' } },
  { key: '2:303:9003', inst_id: 2, sid: 303, serial: 9003, username: '<img src=x onerror=alert(1)>', status: 'ACTIVE', elapsed_s: 120, state: 'ON CPU', sql_id: 'zzzz1234yyyy9', blocks: 0, why: ['running for 2 min', 'on CPU'], score: 2 }];
let ROLE = 'operator', USER = 'ali', CTL = { configured: false }; const POSTS = [];
let REQS = [{ id: 'DBK-00001', db: 'reg:odb1', database: 'ESS-PROD', mode: 'kill', reason: 'idle with locks', status: 'pending', requested_by: 'ahmed', requested_at: at, session: { sid: 202, serial: 7002, inst_id: 1, username: 'HR_BATCH', sql_id: '' } },
  { id: 'DBK-00002', db: 'reg:odb1', database: 'ESS-PROD', mode: 'cancel', reason: 'mine', status: 'pending', requested_by: 'ali', requested_at: at, session: { sid: 101, serial: 5001, inst_id: 1, username: 'APP_ERP', sql_id: 'abcd1234efgh5' } }];
(async () => {
  const srv = http.createServer((q, r) => {
    const u = q.url.split('?')[0], j = (c, o) => { r.writeHead(c, { 'Content-Type': 'application/json' }); r.end(JSON.stringify(o)); };
    if (u.endsWith('whoami.json')) return j(200, { user: USER, role: ROLE });
    if (u.startsWith('/api/')) {
      if (q.method === 'POST') { let b = ''; q.on('data', (c) => { b += c; }); q.on('end', () => { const body = JSON.parse(b || '{}'); POSTS.push({ u, b: body });
        if (u === '/api/itam/db-sessions/requests') return j(200, { id: 'DBK-00003', status: 'pending' });
        if (/decide$/.test(u)) return j(200, { id: 'DBK-00001', status: body.decision === 'approve' ? 'done' : 'rejected', result: 'DONE: session killed' });
        if (u === '/api/itam/db-sessions/control') { CTL = { configured: true, ok: true, by: 'syed', at }; return j(200, { databases: [{ key: 'reg:odb1', label: 'ESS-PROD', service: 'ESS', control: CTL }] }); }
        return j(200, {}); }); return; }
      if (u === '/api/itam/db-sessions') return j(200, { databases: [{ key: 'reg:odb1', label: 'ESS-PROD', service: 'ESS', control: CTL }, { key: 'reg:odb2', label: 'HR-DB', service: 'HR', control: { configured: false } }] });
      if (u === '/api/itam/db-sessions/long') return j(200, { at, database: { key: 'reg:odb1', label: 'ESS-PROD' }, min_s: 60, sessions: SESS, control: CTL, totals: { sessions: 3, blockers: 1, blocked: 4, over_1h: 1 } });
      if (u === '/api/itam/db-sessions/requests') return j(200, { items: REQS });
      return j(404, { error: 'not in this test' });
    }
    const f = path.join(B, u); if (!f.startsWith(B)) { r.writeHead(403); return r.end(); }
    fs.readFile(f, (e, d) => { if (e) { r.writeHead(404); return r.end(); } r.writeHead(200, { 'Content-Type': u.endsWith('.js') ? 'application/javascript' : u.endsWith('.css') ? 'text/css' : 'text/html' }); r.end(d); });
  });
  await new Promise((res) => srv.listen(0, '127.0.0.1', res));
  const base = 'http://127.0.0.1:' + srv.address().port + '/';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  const open = async (pg) => { const p = await browser.newPage({ viewport: { width: 1500, height: 950 } }); p.on('pageerror', (e) => errs.push(e.message)); return p; };
  const txt = (p, id) => p.evaluate((i) => (document.getElementById(i) || {}).textContent || '', id);

  let p = await open(); await p.goto(base + 'databases.html'); await p.waitForTimeout(800);
  ok(await p.evaluate(() => !!document.querySelector('a[href="db-sessions.html"]')), 'in the Databases menu');
  await p.evaluate(() => document.querySelector('a[href="db-sessions.html"]').click()); await p.waitForURL(/db-sessions/); await p.waitForSelector('#ses tr.sr');
  ok(/Blocking others1/.test(await txt(p, 'kp')) && /4 sessions waiting on them/.test(await txt(p, 'kp')), 'tiles: ' + (await txt(p, 'kp')).slice(0, 140));
  const names = await p.evaluate(() => [].map.call(document.querySelectorAll('#ses tr.sr td:nth-child(2) b'), (b) => b.textContent));
  ok(JSON.stringify(names) === JSON.stringify(['HR_BATCH', 'APP_ERP', '<img src=x onerror=alert(1)>']), 'blockers first, escaped: ' + JSON.stringify(names));
  ok(/blocking 4/.test(await txt(p, 'ses')) && /idle but holding locks/.test(await txt(p, 'ses')) && /Table Scan 40%/.test(await txt(p, 'ses')), 'why it hurts + progress');
  ok(await p.evaluate(() => !document.querySelector('#ses tr.sr:first-child [data-act="cancel"]') && !!document.querySelector('#ses tr.sr:first-child [data-act="kill"]')), 'idle blocker: kill only (cancel does nothing)');
  await p.fill('#q', 'erp-app1'); await p.dispatchEvent('#q', 'input'); ok((await p.$$('#ses tr.sr')).length === 1, 'search'); await p.fill('#q', ''); await p.dispatchEvent('#q', 'input');
  await p.click('#ses tr.sr:nth-child(2) td:nth-child(3)'); await p.waitForFunction(() => /scattered read/.test((document.getElementById('zd-b') || {}).textContent || ''));
  ok(/select \* from gl_lines/.test(await p.evaluate(() => document.getElementById('zd-b').textContent)), 'session drawer with masked statement');
  await p.keyboard.press('Escape'); await p.waitForTimeout(300);
  await p.click('#ses tr.sr:nth-child(2) [data-act="cancel"]'); await p.waitForSelector('#rq-why'); await p.fill('#rq-why', 'GL full scan, users waiting'); await p.click('#ask-ok'); await p.waitForTimeout(300);
  ok(POSTS.some((x) => /db-sessions\/requests$/.test(x.u) && x.b.mode === 'cancel' && x.b.sid === 101 && x.b.serial === 5001 && x.b.inst_id === 1 && x.b.reason === 'GL full scan, users waiting' && x.b.db === 'reg:odb1'), 'cancel request with reason');
  ok(await p.evaluate(() => !!document.querySelector('[data-ok="0"]') && !document.querySelector('[data-ok="1"]')), 'approve offered on someone else\'s request only');
  p.once('dialog', (d) => d.accept()); await p.click('[data-ok="0"]'); await p.waitForTimeout(300);
  ok(POSTS.some((x) => /DBK-00001\/decide$/.test(x.u) && x.b.decision === 'approve'), 'approve sent');
  await p.click('[data-no="0"]'); await p.waitForSelector('#rj-why'); await p.fill('#rj-why', 'business batch, wait'); await p.click('#ask-ok'); await p.waitForTimeout(300);
  ok(POSTS.some((x) => /decide$/.test(x.u) && x.b.decision === 'reject' && x.b.comment === 'business batch, wait'), 'reject with a reason');
  ok(/not set up/.test(await txt(p, 'set')) && /CREATE OR REPLACE PROCEDURE zyb_ops.session_ctl/.test(await txt(p, 'sqltxt')) && !(await p.$('#csave')), 'setup: script shown; operator cannot save the login');
  await p.close();

  ROLE = 'admin'; USER = 'syed'; p = await open(); await p.goto(base + 'db-sessions.html'); await p.waitForSelector('#csave');
  await p.fill('#cp', 'Ctl-pass-1'); await p.click('#csave'); await p.waitForTimeout(400);
  ok(POSTS.some((x) => /db-sessions\/control$/.test(x.u) && x.b.username === 'ZYB_CONTROL' && x.b.password === 'Ctl-pass-1') && /session control ready/.test(await txt(p, 'set')) && (await p.inputValue('#cp')) === '', 'admin saves the control login (tested by the server)');
  await p.close();

  ROLE = 'viewer'; p = await open(); await p.goto(base + 'db-sessions.html'); await p.waitForTimeout(600);
  ok(/Operators and administrators/.test(await txt(p, 'kp')) && !(await p.$('#ses tr')), 'viewer kept out (names people)');
  await p.close();
  ok(/db-sessions\.html/.test(fs.readFileSync(path.join(SRC, 'install-dashboards.sh'), 'utf8')), 'in the installer');
  ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  await browser.close(); srv.close();
  console.log(`${n - bad}/${n} checks passed`); process.exit(bad ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });
