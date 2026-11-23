// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for db-morning.html against the real IT Asset Management engine (engine/db-morning.js with stub database and
// server readers): in the Databases menu, Run now, tiles, per-database / per-server checklists (only problems by default),
// a check opens its evidence and what to do, sign-off needs a note when something failed, history, admin schedule.
// Data is SYNTHETIC. Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node db-morning.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const ITAM = path.resolve(__dirname, '../../backend/itam'), DASH = path.resolve(__dirname, '../../ui');
const H = require(path.join(ITAM, 'tests/helpers.js'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
let WHO = { user: 'ahmed', role: 'operator' };
(async () => {
  const e = await H.startApp({ noAi: true });
  const mails = [];
  const fakeH = { targets: () => ({ list: [{ key: 'reg:p', ip: '10.0.0.5', host: 'ESS-PRIMARY', service: 'ESS' }] }), push: async (r) => r.length,
    readOne: async () => ({ instance: 'ESS', version: '19.0', errors: [{ query: 'backup', error: 'privilege', ora: 'ORA-00942' }], recs: [
      { kind: 'instance', instance: 'ESS', status: 'OPEN', open_mode: 'READ WRITE', role: 'PRIMARY', log_mode: 'ARCHIVELOG', archiver: 'STARTED', logins: 'ALLOWED', uptime_s: 864000 },
      { kind: 'tablespace', name: 'USERS', used_pct: 97, used_mb: 9700, max_mb: 10000 }, { kind: 'redo', unarchived: 0 },
      { kind: 'archive_dest', dest_id: 1, status: 'VALID', destination: 'USE_DB_RECOVERY_FILE_DEST' }, { kind: 'fra', name: '+RECO', space_limit_mb: 1000, space_used_mb: 100, reclaimable_mb: 0 },
      { kind: 'alertlog_24h', lines: 0, codes: [] }, { kind: 'sessions', total: 10, max_sessions: 100, blocked: 0 }, { kind: 'invalid_objects', count: 0 }] }) };
  const fakeSV = { pass: async () => ({}), view: () => ({ servers: [{ ip: '10.0.0.5', host: 'ess-db1', databases: ['ESS'], server: { filesystems: [{ mount: '/u01', used_pct: 50 }], mem_total_mb: 1000, mem_avail_mb: 500, load5: 1, ncpu: 4, oracle: { pmon: ['ESS'], listeners: ['L'] }, ntp_synced: true } }], findings: [] }) };
  require(path.join(ITAM, 'engine/db-morning')).registerDbMorning(e.app.srv, e.app, { dbHealth: fakeH, dbServers: fakeSV, noTimer: true, discovery: { siem: { call: async (m, p, who, body) => { mails.push(body); return { status: 200, json: { ok: true, recipients: 1 } }; } } } });
  const srv = http.createServer((req, res) => {
    const u = req.url.split('?')[0], json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u === '/dashboards/whoami.json') return json(200, WHO);
    if (u.startsWith('/api/itam/')) { const h = Object.assign({}, req.headers, { 'x-sentra-proxy-secret': H.SECRET, 'x-auth-user': WHO.user, 'x-auth-role': WHO.role });
      const up = http.request({ host: '127.0.0.1', port: e.port, method: req.method, path: req.url, headers: h }, (r) => { res.writeHead(r.statusCode, r.headers); r.pipe(res); }); req.pipe(up); return; }
    if (u.startsWith('/api/')) return json(404, {});
    fs.readFile(path.join(DASH, u), (err, d) => { if (err) { res.writeHead(404); return res.end(); } res.writeHead(200, { 'Content-Type': u.endsWith('.js') ? 'application/javascript' : u.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port + '/';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), page = await browser.newPage({ viewport: { width: 1400, height: 950 } }), errs = [];
  page.on('pageerror', (x) => errs.push(x.message));
  const txt = (id) => page.evaluate((i) => document.getElementById(i).textContent, id);
  await page.goto(base + 'db-morning.html'); await page.waitForFunction(() => /No health check has run yet/.test(document.getElementById('kp').textContent));
  ok(true, 'empty state before the first run');
  await page.click('#run'); await page.waitForSelector('#dbs .box', { timeout: 15000 });
  ok(/Failed checks1/.test(await txt('kp')) && /Not checked1/.test(await txt('kp')) && /sent/.test(await txt('kp')), 'tiles: ' + (await txt('kp')).slice(0, 200));
  ok(/ESS-PRIMARY/.test(await txt('dbs')) && /Tablespaces/.test(await txt('dbs')) && /Last RMAN backup/.test(await txt('dbs')) && !/Instance open/.test(await txt('dbs')), 'only problems by default');
  await page.uncheck('#only'); ok(/Instance open/.test(await txt('dbs')) && /PASS/.test(await txt('dbs')), 'all checks on demand'); await page.check('#only');
  ok(/All 5 checks passed/.test(await txt('srv')), 'server box: all passed');
  await page.click('#dbs tr[data-k]:has-text("Tablespaces")'); await page.waitForFunction(() => /USERS 97%/.test((document.getElementById('zd-b') || {}).textContent || ''));
  ok(/Add a datafile/.test(await page.evaluate(() => document.getElementById('zd-b').textContent)), 'evidence + what to do');
  await page.keyboard.press('Escape'); await page.waitForTimeout(300);
  await page.click('#rvok'); await page.waitForTimeout(300);
  ok(!/signed off/.test(await txt('rv')), 'sign-off refused without a note when something failed');
  await page.fill('#rvn', 'USERS extended by 10 GB; backup grant asked'); await page.click('#rvok'); await page.waitForFunction(() => /signed off/.test(document.getElementById('rv').textContent));
  ok(/ahmed/.test(await txt('rv')) && /ahmed/.test(await txt('hist')), 'signed off, shown in history');
  ok(mails.length === 1 && /\[DB\] Morning health check/.test(mails[0].subject), 'mailed through the SIEM');
  ok(!(await page.$('#s-save')), 'operator: no settings form');
  WHO = { user: 'syed', role: 'admin' }; await page.goto('about:blank'); await page.goto(base + 'db-morning.html'); await page.waitForSelector('#s-save');
  await page.fill('#s-at', '06:45'); await page.click('#s-save'); await page.waitForTimeout(500);
  const st = (await e.req('GET', '/db-morning', { user: 'syed', role: 'admin' })).json;
  ok(st.settings.at === '06:45' && st.settings.by === 'syed', 'admin changes the schedule');
  const nav = fs.readFileSync(path.join(DASH, 'vendor/zyb-nav.js'), 'utf8'); ok(/"h": "db-morning\.html"/.test(nav) && /db-morning\.html/.test(fs.readFileSync(path.join(DASH, 'install-dashboards.sh'), 'utf8')), 'menu + installer');
  ok(!errs.length, 'page errors: ' + errs.join(' | '));
  await browser.close(); srv.close(); await e.close();
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks'); process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
