// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Databases page: an administrator edits a registered Oracle database (new password for the same login, or another saved
// login), opened from the row or from Database Performance's "Edit login" link (#edit=<id>); a viewer gets no Edit.
// Stub API; SYNTHETIC names. Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node databases-edit.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const DASH = path.resolve(__dirname, '../../ui');
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
let ROLE = 'admin', posted = null;
const DB = { id: 'odb_1', label: 'ESX-Aggregator', host: '192.168.9.29', port: 1521, service: 'ESXDR', credential: 'oracle-ESX-Aggregator', cred_id: 'cr1', login_shared_with: [],
  last_test: { at: '2026-10-22T10:00:00Z', ok: false, error: 'auth: ORA-01017: invalid username/password; logon denied', cls: 'auth' }, paused: { at: '2026-10-22T10:00:00Z', reason: 'login refused - tested again only by an administrator (no account lockout)' } };
(async () => {
  const srv = http.createServer((req, res) => { const u = req.url.split('?')[0]; const json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u === '/dashboards/whoami.json') return json(200, { user: 'syed', role: ROLE });
    if (u === '/api/itam/db-health') return json(200, { enabled: true, interval_min: 4, last: null });
    if (u === '/api/itam/db-health/databases') return json(200, { databases: [DB], credentials: [{ id: 'cr1', label: 'oracle-ESX-Aggregator' }, { id: 'cr2', label: 'oracle-dr-monitor' }], dismissed: [] });
    if (u === '/api/itam/db-health/databases/odb_1' && req.method === 'POST') { let b = ''; req.on('data', (c) => { b += c; }); req.on('end', () => { posted = JSON.parse(b); DB.paused = null; DB.last_test = { ok: true, instance: 'ESXDR', at: '2026-10-22T10:05:00Z' }; json(200, { database: DB }); }); return; }
    if (u.startsWith('/api/itam/discovery/results')) return json(200, { devices: [] });
    if (u === '/api/itam/discovery/credentials') return json(200, { credentials: [] });
    if (u.startsWith('/api/')) return json(404, { error: 'x' });
    fs.readFile(path.join(DASH, u.replace(/^\/dashboards\//, '/')), (e, d) => { if (e) { res.writeHead(404); return res.end(); } res.writeHead(200, { 'Content-Type': u.endsWith('.js') ? 'application/javascript' : u.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); }); });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r)); const base = 'http://127.0.0.1:' + srv.address().port + '/';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright'); const browser = await chromium.launch(); const p = await browser.newPage({ viewport: { width: 1366, height: 900 } });
  const errs = []; p.on('pageerror', (e) => errs.push(e.message));
  await p.goto(base + 'databases.html?standalone=1'); await p.waitForSelector('[data-edit="odb_1"]');
  await p.click('[data-edit="odb_1"]'); await p.waitForSelector('#e-mode');
  ok(/oracle-ESX-Aggregator/.test(await p.$eval('#zd-b', (x) => x.innerText)), 'the form names the current login');
  await p.selectOption('#e-mode', 'pass'); await p.click('#e-save'); await p.waitForTimeout(200);
  ok(posted === null, 'no password = nothing sent');
  await p.fill('#e-pass', 'Synthetic-New-1'); await p.click('#e-save'); await p.waitForFunction(() => { const b = document.querySelector('#e-save'); return !b || !b.offsetParent; });
  ok(posted && posted.password === 'Synthetic-New-1' && !posted.username && posted.service === 'ESXDR' && posted.host === '192.168.9.29', 'new password for the same login: ' + JSON.stringify(Object.assign({}, posted, { password: '***' })));
  // another saved login, opened from Database Performance's link
  posted = null; const p2 = await browser.newPage({ viewport: { width: 1366, height: 900 } }); p2.on('pageerror', (e) => errs.push(e.message));
  await p2.goto(base + 'databases.html?standalone=1#edit=odb_1'); await p2.waitForSelector('#e-mode', { state: 'visible' });
  await p2.selectOption('#e-mode', 'saved'); await p2.selectOption('#e-saved', 'cr2'); await p2.click('#e-save'); await p2.waitForTimeout(400);
  ok(posted && posted.cred_id === 'cr2' && !posted.password, 'switched to another saved login (from the #edit link)');
  // the link on Database Performance points here
  ok(/databases\.html#edit=/.test(fs.readFileSync(path.join(DASH, 'db-performance.html'), 'utf8')), 'Database Performance has an Edit login link');
  ROLE = 'viewer'; await p.goto(base + 'databases.html?standalone=1'); await p.waitForTimeout(1500);
  ok(!(await p.$('[data-edit="odb_1"]')), 'viewer: no Edit');
  ok(!errs.length, 'page errors: ' + errs.join(' | '));
  await browser.close(); srv.close(); console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks'); process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
