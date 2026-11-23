// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for the ✦ AI / ML section of the Database Dashboard (db-dashboard.html) against the REAL SIEM module
// (sentra-siem engine/db-audit/dba-intel.js) over a SYNTHETIC DBA status, 30 days of conditions, capacity and 14 days of snapshots:
// the fleet gauge and an itemised bar per instance (one without a reading not measured), the ranked "do first" list, the capacity
// runway with the date a tablespace fills, flapping and recurring problems learned, the unusual instance, the fleet trend, the
// advisor off says why; a hostile tablespace name stays text; a viewer reads; phone width; no page error.
// Run: SENTRA_SIEM_DIR=/home/user/sentra-siem PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node db-intel.test.js
const http = require('http'), fs = require('fs'), path = require('path'), os = require('os');
const SIEM = process.env.SENTRA_SIEM_DIR || path.resolve(__dirname, '../../backend/siem'), DASH = path.resolve(__dirname, '../../ui');
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const I = require(path.join(SIEM, 'engine/db-audit/dba-intel')), { createState } = require(path.join(SIEM, 'engine/soc/state')), { fakeApi } = require(path.join(SIEM, 'tests/soc-fakes'));
const quiet = { info() {}, warn() {}, error() {}, debug() {}, every() {}, child() { return quiet; } };
const XSS = '<img src=x onerror="window.__xss=1">';
(async () => {
  const H = 3600000, DAY = 864e5, NOW = Date.now();
  const inst = (o) => Object.assign({ host: 'db1', db_name: 'PRD', role: 'PRIMARY', level: 'ok', open: { crit: 0, warn: 0 }, backup_age_h: 10, fra_pct: 40, sessions_pct: 30, dg_lag_s: 5 }, o);
  const STATUS = { instances: [inst({ instance: 'ORCLPRD', level: 'crit', open: { crit: 1, warn: 2 }, backup_age_h: 60, min_days_to_full: 9 }), inst({ instance: 'HRDB', host: 'db2' }), inst({ instance: 'OLDDB', host: 'db3', level: 'unknown' })] };
  const COND = []; for (let i = 0; i < 6; i++) COND.push({ metric: 'sessions_pct', instance: 'HRDB', host: 'db2', title: 'Sessions of the limit', since: NOW - (i + 1) * DAY, cleared: NOW - (i + 1) * DAY + 20 * 60000, status: 'cleared' });
  for (let i = 0; i < 3; i++) COND.push({ metric: 'backup_age_h', instance: 'ORCLPRD', host: 'db1', title: 'Hours since the last good backup', since: NOW - (i * 9 + 2) * DAY, cleared: NOW - (i * 9 + 1) * DAY, status: 'cleared' });
  STATUS.instances[0].max_ts = { key: 'USERS', value: 96 };
  COND.push({ metric: 'ts_used_pct', instance: 'ORCLPRD', host: 'db1', level: 'crit', title: 'Tablespace used', since: NOW - 2 * DAY, cleared: NOW - 2 * DAY + 3 * H, ack: { at: NOW - 2 * DAY + 10 * 60000, by: 'ahmed' }, status: 'cleared' });
  COND.forEach((c) => { if (!c.level) c.level = 'warn'; });
  const D = { status: () => STATUS, conditions: () => COND, thresholdOf: (id) => ({ ts_used_pct: { warn: 87, crit: 95, enabled: true }, backup_age_h: { warn: 26, crit: 48, enabled: true } }[id] || { warn: 80, crit: 90, enabled: true }) };
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'dbi-')), state = createState({ dir, log: quiet });
  for (let d = 14; d >= 1; d--) { const day = new Date(NOW - d * DAY + 3 * H).toISOString().slice(0, 10); state.collection('dba_intel_snaps').put({ id: day, day, at: NOW - d * DAY, fleet: 70 + (d % 5), open: 1, inst: { 'ORCLPRD@db1': { open: d % 2 }, 'HRDB@db2': { open: 0 } } }); }
  const deps = { state, noTimers: true, log: quiet, config: { netops: { ai: { enabled: false } } }, oracle_perf: { capacity: async () => ({ instances: [{ instance: 'ORCLPRD', host: 'db1', tablespaces: [{ name: 'USERS ' + XSS, used_pct: 91, growth_mb_day: 800, days_to_full: 9, history_days: 30 }, { name: 'IDX', used_pct: 50, growth_mb_day: 20, days_to_full: 60, history_days: 30 }], asm: [] }] }) } };
  const api = fakeApi({ realRanks: true }); I.register(api, deps, D, '/api/soc');
  let WHO = { user: 'nora.syn', role: 'operator' };
  const srv = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://x'), json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u.pathname === '/dashboards/whoami.json') return json(200, WHO);
    if (u.pathname.startsWith('/api/soc/db/dba/intel')) { let b = ''; req.on('data', (c) => (b += c)); req.on('end', async () => { const r = await api.call(req.method, u.pathname, { role: WHO.role, user: WHO.user, body: b ? JSON.parse(b) : undefined }); json(r.status, r.body); }); return; }
    if (u.pathname === '/api/soc/db/dba/status') return json(200, Object.assign({ generated_at: NOW, open: { crit: 1, warn: 2, acknowledged: 0, snoozed: 0 }, errors: 0, mail: { ok: true, problems: [] }, maintenance: [] }, STATUS));
    if (u.pathname.startsWith('/api/')) return json(404, { error: 'not in this test' });
    const f = path.join(DASH, u.pathname.replace(/^\/dashboards\//, '/')); if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (err, d) => { if (err) { res.writeHead(404); res.end(); return; } res.writeHead(200, { 'Content-Type': u.pathname.endsWith('.js') ? 'application/javascript' : u.pathname.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port + '/dashboards/db-dashboard.html';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright'); const browser = await chromium.launch(), errs = [];
  const wait = (p, fn) => p.waitForFunction(fn, null, { timeout: 20000 }).then(() => true, () => false);
  try {
    const p = await browser.newPage({ viewport: { width: 1500, height: 1100 } }); p.on('pageerror', (x) => errs.push(x.message));
    await p.goto(base);
    ok(await wait(p, () => /Database health/.test((document.getElementById('dbai') || {}).innerText || '')), 'AI section drawn');
    const t = await p.evaluate(() => document.getElementById('dbai').innerText);
    ok(await p.$('#dbai svg linearGradient') && /average of the 2 instance/.test(t), 'fleet gauge over the measured instances');
    ok(/ORCLPRD[\s\S]*HRDB[\s\S]*OLDDB/.test(t) && /—/.test(t), 'a bar per instance, the unread one not measured');
    ok(/Do first[\s\S]*ORCLPRD: 1 critical problem/.test(t), 'ranked do-first list');
    ok(await p.evaluate(() => [...document.querySelectorAll('#dbai .hb2 .t i')].every((i) => parseFloat(i.style.width) >= 3)), 'every measured bar is visible, even at a low score');
    ok(/USERS/.test(t) && (await p.$$('#dbai rect')).length >= 2 && /\d{4}-\d{2}-\d{2}/.test(t), 'capacity runway with dates');
    ok(/FLAPPING[\s\S]*HRDB/.test(t) && /RECURRING[\s\S]*ORCLPRD/.test(t), 'flapping and recurring learned');
    ok(/ORCLPRD[\s\S]*3 problems open against a usual/.test(t), 'unusual instance');
    ok(/Fleet health over time/.test(t) && (await p.$$('#dbai path')).length >= 3, 'fleet trend');
    ok(/AI DBA advisor is off: AI switched off/.test(t), 'advisor off says why');
    ok(/Fleet at a glance/.test(t) && await p.evaluate(() => [...document.querySelectorAll('#dbai .fc')].some((x) => /96/.test(x.textContent) && /242, 73, 92/.test(getComputedStyle(x).backgroundColor))), 'fleet grid: tablespace 96 % red against its threshold');
    ok(await p.evaluate(() => [...document.querySelectorAll('#dbai .fc')].some((x) => x.textContent === '—')), 'a reading not sent is grey');
    ok(/Problem calendar/.test(t) && await p.$$eval('#dbai .cal i', (x) => x.length) >= 90, 'a 30-day calendar per database');
    ok(/Response/.test(t) && /10\s*min/.test(t) && /180\s*min/.test(t), 'MTTA 10 min and MTTR 180 min for criticals');
    ok(/Noisiest checks/.test(t) && /Sessions of the limit/.test(t), 'noisiest checks');
    ok(await p.evaluate(() => !window.__xss), 'hostile tablespace name stays text');
    WHO = { user: 'vera.syn', role: 'viewer' };
    const v = await browser.newPage({ viewport: { width: 390, height: 900 } }); v.on('pageerror', (x) => errs.push(x.message));
    await v.goto(base); ok(await wait(v, () => /Database health/.test((document.getElementById('dbai') || {}).innerText || '')), 'a viewer reads the section');
    ok(await v.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1), 'phone width: no sideways scroll'); await v.close();
    if (process.env.SHOT) await p.screenshot({ path: process.env.SHOT + '-dbai.png', fullPage: false });
  } finally { await browser.close(); srv.close(); state.close(); fs.rmSync(dir, { recursive: true, force: true }); }
  ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks'); process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
