// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Application Connections (db-connections.html), stubbed SIEM, SYNTHETIC data: tiles, applications connected / dropped with
// filter, listener refusals with meaning and fix, client time-outs joined to the application on that machine, DB links with
// the remote user's rights, escaping, database switch by hash, viewer refused, not installed, nothing reported.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node db-connections.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const DASH = path.resolve(__dirname, '../../ui');
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
let MODE = 'ok'; const ASKED = [];
const XSS = '<img src=x onerror=alert(1)>';
const V = { instance: 'ORCLPRD', read_at: Date.now() - 120000, note: 'Applications from GV$SESSION each pass.',
  reported: { sessions: true, listener: true, links: true },
  summary: { applications: 2, sessions: 82, dropped: 1, refused: 33, timeouts: 1, links: 3, links_write: 1 },
  applications: [{ service: 'HR', machine: 'hrapp', program: 'w3wp.exe', db_user: 'HR_APP', module: '', sessions: 0, active: 0, max_idle_s: null, oldest_logon: null, instances: null, state: 'dropped', last_seen: Date.now() - 95 * 60000, last_sessions: 12 },
    { service: 'CLAIMS', machine: '10.20.1.15', program: 'JDBC Thin Client', db_user: 'CLAIMS_APP', module: 'claims-api ' + XSS, sessions: 42, active: 3, max_idle_s: 900, oldest_logon: '2026-10-26T06:00:00', instances: 2, state: 'connected', last_seen: Date.now(), last_sessions: 42 },
    { service: 'CLAIMS', machine: 'app02', program: 'JDBC Thin Client', db_user: 'CLAIMS_APP', module: '', sessions: 40, active: 1, max_idle_s: 60, oldest_logon: '2026-10-26T06:01:00', instances: 1, state: 'connected', last_seen: Date.now(), last_sessions: 40 }],
  listener: [{ client_host: '10.20.1.15', service: 'CLAIMS', programs: ['JDBC'], ok: 300, refused: 25, reasons: [{ code: '12519', n: 25, meaning: 'no appropriate service handler found', fix: 'The database has reached its processes limit' }] }],
  timeouts: [{ client_host: '10.20.1.15', n: 4, last: Date.now() - 3600000 }],
  links: [{ owner: 'PUBLIC', link: 'TO_FIN_ADMIN', remote_user: 'FINOWNER', host: 'FINPRD', remote_db: 'FINPRD', verdict: 'write_all', why: ['role DBA', 'DELETE ANY TABLE'], fix: 'Give the link its own least-privileged user on FINPRD' },
    { owner: 'APP', link: 'TO_FIN', remote_user: 'FIN_RO', host: '(DESCRIPTION=...)', remote_db: 'FINPRD', verdict: 'read_only', why: ['no write right found'], fix: '' },
    { owner: 'APP', link: 'TO_LEGACY', remote_user: 'X', host: 'LEGACYDB', remote_db: null, verdict: 'not_monitored', why: ['the remote database is not monitored here'], fix: '' }] };
// the ✦ learning: the REAL SIEM module over 14 days of SYNTHETIC hourly history (HR usually connected now, a pool leaking)
const SIEM = process.env.SENTRA_SIEM_DIR || path.resolve(__dirname, '../../backend/siem');
const CI = require(path.join(SIEM, 'engine/db-audit/connections-intel'));
const intel = () => { const NOW = Date.now(), H = 36e5, D = 864e5, hist = [], A = V.applications;
  for (let d = 14; d >= 1; d--) for (let h = 0; h < 24; h++) { const t = Math.floor((NOW - d * D) / H) * H - h * H; hist.push({ k: CI.keyOf(A[0]), h: t, s: 10 }, { k: CI.keyOf(A[2]), h: t, s: 40 }, { k: CI.keyOf(A[1]), h: t, s: 15 }); }
  for (let i = 12; i >= 1; i--) hist.push({ k: CI.keyOf(A[1]), h: Math.floor(NOW / H) * H - i * H, s: 42 - i * 2 });
  return CI.analyse({ view: V, history: hist, now: NOW }); };
(async () => {
  const srv = http.createServer((req, res) => {
    const u = decodeURIComponent(req.url.split('?')[0]), json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u === '/dashboards/whoami.json' || u === '/auth/whoami') return json(200, { user: 'dba.syn', role: 'operator' });
    if (MODE === 'none' && u.startsWith('/api/')) return json(404, { error: 'not found' });
    if (u === '/api/soc/db/dba/status') return json(200, { instances: [{ instance: 'ORCLPRD' }, { instance: 'HRDB' }] });
    if (u === '/api/soc/db/oracle/connections') { const i = new URL('http://x' + req.url).searchParams.get('instance'); ASKED.push(i);
      if (MODE === 'viewer') return json(403, { error: 'requires operator role' });
      if (i === 'HRDB') return json(200, { instance: 'HRDB', reported: { sessions: false, listener: false, links: false }, summary: { applications: 0, sessions: 0, dropped: 0, refused: 0, timeouts: 0, links: 0, links_write: 0 }, applications: [], listener: [], timeouts: [], links: [] });
      return json(200, V); }
    if (u === '/api/soc/db/oracle/connections/intel') { if (MODE === 'viewer') return json(403, { error: 'requires operator role' }); const i = new URL('http://x' + req.url).searchParams.get('instance'); return json(200, i === 'HRDB' ? CI.analyse({ view: { instance: 'HRDB', applications: [] }, now: Date.now() }) : intel()); }
    if (u.startsWith('/api/')) return json(404, { error: 'not in this test' });
    const f = path.join(DASH, u.replace(/^\/dashboards\//, '')); if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (e, d) => { if (e) { res.writeHead(404); return res.end(); } res.writeHead(200, { 'Content-Type': f.endsWith('.js') ? 'application/javascript' : f.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port;
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright'); const browser = await chromium.launch();
  try {
    const p = await browser.newPage({ viewport: { width: 1400, height: 1000 } }); const errs = []; p.on('pageerror', (e) => errs.push(e.message));
    let alerted = false; p.on('dialog', (d) => { alerted = true; d.dismiss(); });
    await p.goto(base + '/dashboards/db-connections.html?standalone=1#ORCLPRD'); await p.waitForSelector('#apps table');
    const k = await p.textContent('#kk');
    ok(/Applications connected\s*2/.test(k) && /Dropped \(24 h\)\s*1/.test(k) && /Refused \(1 h\)\s*33/.test(k) && /Links that can write\s*1 \/ 3/.test(k), 'tiles: ' + k);
    const a = await p.textContent('#apps');
    ok(/dropped/.test(a) && /had 12 at/.test(a) && /w3wp\.exe/.test(a) && /hrapp/.test(a), 'dropped application with what it had');
    ok(/connected/.test(a) && /JDBC Thin Client/.test(a) && /on 2 instances/.test(a) && /15 min/.test(a), 'connected application with RAC instances and idle time');
    ok(!(await p.$('#apps img')) && /onerror/.test(a), 'escaped');
    ok(await p.evaluate(() => document.querySelector('#apps tbody tr').classList.contains('dropped')), 'dropped row marked');
    await p.fill('#q', 'app02'); ok((await p.$$('#apps tbody tr')).length === 1, 'filter');
    await p.fill('#q', ''); await p.check('#onlydrop'); ok((await p.$$('#apps tbody tr')).length === 1 && /hrapp/.test(await p.textContent('#apps')), 'only dropped');
    const l = await p.textContent('#lsnr');
    ok(/10\.20\.1\.15/.test(l) && /TNS-12519/.test(l) && /no appropriate service handler/.test(l) && /processes limit/.test(l) && /300/.test(l), 'listener refusal with meaning and fix');
    ok(await p.waitForFunction(() => /Dependency map/.test((document.getElementById('cai') || {}).textContent || ''), null, { timeout: 15000 }).then(() => true, () => false), '✦ section drawn');
    const ai = await p.textContent('#cai');
    ok(/MISSING/.test(ai) && /usually connected at/.test(ai), 'HR missing at a time it is usually connected');
    ok(/LEAK/.test(ai) && /a pool not returning connections/.test(ai), 'a leaking pool named with its evidence');
    ok(await p.$$eval('#cai svg path', (x) => x.length) >= 4 && /ORCLPRD/.test(ai), 'dependency map drawn: machines, services, the database, its links');
    ok(/Refusal rate per client/.test(ai) && /8%/.test(ai), 'refusal rate per client (25 of 325)');
    ok(/Connection health/.test(ai), 'connection health tile');
    const t = await p.textContent('#tmo'); ok(/10\.20\.1\.15/.test(t) && /4/.test(t) && /JDBC Thin Client/.test(t), 'time-outs joined to the application on that client');
    const L = await p.textContent('#links');
    ok(/PUBLIC\.TO_FIN_ADMIN/.test(L) && /can change everything/.test(L) && /role DBA · DELETE ANY TABLE/.test(L) && /least-privileged/.test(L), 'link that can write everything');
    ok(/read only/.test(L) && /remote not monitored/.test(L), 'read-only and not-monitored links');
    await p.selectOption('#inst', 'HRDB'); await p.waitForFunction(() => /No session reading/.test(document.getElementById('apps').textContent));
    ok(/No listener log reading/.test(await p.textContent('#lsnr')) && /No database link/.test(await p.textContent('#links')), 'nothing reported says what is missing, not zero');
    ok(/#HRDB$/.test(p.url()), 'database kept in the address');
    await p.goto(base + '/dashboards/db-connections.html?standalone=1#ORCLPRD'); await p.waitForFunction(() => document.querySelector('#apps table')); ok(ASKED.at(-1) === 'ORCLPRD', 'hash selects the database');
    ok(!alerted && errs.length === 0, 'no script ran, no page error: ' + errs.join(' | '));
    MODE = 'viewer'; await p.reload(); await p.waitForFunction(() => /operators and administrators/.test(document.getElementById('apps').textContent)); ok(true, 'viewer told why');
    MODE = 'none'; await p.reload(); await p.waitForFunction(() => /not readable|not installed/.test(document.body.textContent)); ok(true, 'not installed');
    await p.close();
  } finally { await browser.close(); srv.close(); }
  console.log(`${n - bad}/${n} passed`); process.exit(bad ? 1 : 0);
})();
