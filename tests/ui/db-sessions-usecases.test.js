// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for Long-Running Queries (db-sessions.html) with use cases and learning, against the REAL ITAM engines
// (engine/db-sessions.js + engine/db-sessions-intel.js; the Oracle helper is a fake with SYNTHETIC sessions, read on 6 earlier days):
// every session carries its verdict and why; the verdict filter; a suggested use case for the recurring query, reviewed and added by an
// administrator with a reason (audited) - the session then reads "over its expected time"; editing and removing; learned queries and the
// hour strip; an operator sees no editor; a hostile SQL text stays text; phone width; no page error.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node db-sessions-usecases.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const ITAM = path.join(__dirname, '..', '..', 'backend', 'itam'), DASH = path.join(__dirname, '..', '..', 'ui');
const H = require(path.join(ITAM, 'tests', 'helpers'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const XSS = '<img src=x onerror="window.__xss=1">';
(async () => {
  const e = await H.startApp({ noAi: true }); const clock = { t: Date.now() - 6 * 864e5 };
  const SESS = [{ inst_id: 1, sid: 11, serial: 1, status: 'ACTIVE', username: 'APP_ERP', module: 'NIGHTLY_SYNC', program: 'sync.exe', sql_id: 'nsync01', elapsed_s: 1500, sql_text: 'merge into stock ' + XSS, blocks: 0 },
    { inst_id: 1, sid: 12, serial: 2, status: 'ACTIVE', username: 'REP', sql_id: 'r1', elapsed_s: 200, blocks: 0 }];
  const creds = new Map([['c1', { id: 'c1', kind: 'db_login', target: { engine: 'oracle' }, secret: { username: 'mon', password: 'x' } }]]);
  const vault = { list: () => [...creds.values()], get: (id) => creds.get(id), open: (id) => ({ secret: creds.get(id).secret, target: creds.get(id).target, release() {} }) };
  const DBH = { targets: () => ({ list: [{ key: 'reg:prd', ip: '10.0.0.5', host: 'PRD', cred_id: 'c1', port: 1521, service: 'PRD' }] }) };
  const S = require(path.join(ITAM, 'engine/db-sessions')).registerDbSessions(e.app.srv, e.app, { dbHealth: DBH, discovery: { vault }, now: () => clock.t, invRun: async (r) => (r.op === 'oracle_long' ? { ok: true, sessions: JSON.parse(JSON.stringify(SESS)) } : { ok: true }) });
  for (let d = 0; d < 6; d++) { await S.readLong({ db: 'reg:prd', min_s: 60 }, { user: 'ali', role: 'operator' }); clock.t += 864e5; }
  let WHO = { user: 'syed', role: 'admin' };
  const web = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://x'), json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u.pathname === '/dashboards/whoami.json') return json(200, WHO);
    if (u.pathname.startsWith('/api/itam/')) {
      const h = Object.assign({}, req.headers, { 'x-sentra-proxy-secret': H.SECRET, 'x-auth-user': WHO.user, 'x-auth-role': WHO.role });
      const up = http.request({ host: '127.0.0.1', port: e.port, method: req.method, path: req.url, headers: h }, (r) => { res.writeHead(r.statusCode, r.headers); r.pipe(res); });
      req.pipe(up); return;
    }
    if (u.pathname.startsWith('/api/')) return json(404, { error: 'not in this test' });
    const f = path.join(DASH, u.pathname.replace(/^\/dashboards\//, '/')); if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (err, d) => { if (err) { res.writeHead(404); res.end(); return; } res.writeHead(200, { 'Content-Type': u.pathname.endsWith('.js') ? 'application/javascript' : u.pathname.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => web.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + web.address().port + '/dashboards/';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  const wait = (p, fn, arg) => p.waitForFunction(fn, arg, { timeout: 15000 }).then(() => true, () => false);
  const txt = (p, id) => p.evaluate((i) => document.getElementById(i).innerText, id);
  try {
    const p = await browser.newPage({ viewport: { width: 1500, height: 1100 } }); p.on('pageerror', (x) => errs.push(x.message));
    await p.goto(base + 'db-sessions.html');
    ok(await wait(p, () => document.querySelector('#ses .vd')), 'every session carries a verdict');
    ok(/usual/.test(await txt(p, 'ses')) && /seen on 7 days/.test(await txt(p, 'ses')), 'learned verdict with its reason');
    ok(await p.$('#lrq-vf [data-vf="usual"]'), 'verdict filter');
    ok(await wait(p, () => /Review and add/.test(document.getElementById('ucs').innerText)), 'a suggested use case for the recurring query');
    ok(/nsync01/.test(await txt(p, 'ucs')) && /expected up to/.test(await txt(p, 'ucs')), 'the suggestion names the query and a proposed time');
    ok(await wait(p, () => /APP_ERP/.test(document.getElementById('lrn').innerText)) && (await p.$$('#lrn-h .hh i')).length === 24, 'learned queries and the hour strip');
    await p.click('[data-ucs="0"]'); await wait(p, () => document.getElementById('u-save'));
    ok((await p.inputValue('#u-si')) === 'nsync01', 'the form is filled from the suggestion');
    await p.fill('#u-max', '15'); await p.fill('#u-note', 'Call the ERP team if it runs past 30 min'); await p.click('#u-save');
    ok(/reason/.test(await txt(p, 'u-err')), 'a reason is required');
    await p.fill('#u-why', 'agreed with the ERP team'); await p.click('#u-save');
    ok(await wait(p, () => /Use case saved/.test(document.body.innerText)), 'use case saved');
    ok(await wait(p, () => /over its expected time/.test(document.getElementById('ses').innerText)), 'the session now reads over its expected time');
    ok(/Nightly|NIGHTLY_SYNC|nsync01/.test(await txt(p, 'uc')) && /up to 15 min/.test(await txt(p, 'uc')), 'the use case is listed');
    ok(e.app.store.auditTail(50).some((a) => a.action === 'db.sessions.case.create' && a.by === 'syed'), 'audited in the admin name');
    await p.click('#lrq-vf [data-vf="over-expected"]'); ok(await p.evaluate(() => [...document.querySelectorAll('#ses tr.sr')].filter((t) => !t.hidden).length === 1), 'the verdict filter narrows the table');
    p.once('dialog', (d) => d.accept('job retired')); await p.click('[data-ucd]');
    ok(await wait(p, () => /Use case removed/.test(document.body.innerText)), 'removed with a reason');
    ok(await p.evaluate(() => !window.__xss), 'hostile SQL text stays text');
    WHO = { user: 'ali', role: 'operator' };
    const o = await browser.newPage({ viewport: { width: 390, height: 900 } }); o.on('pageerror', (x) => errs.push(x.message));
    await o.goto(base + 'db-sessions.html'); await wait(o, () => /Review and add|Nothing to suggest|use case/i.test(document.getElementById('ucs').innerText + document.getElementById('uc').innerText));
    ok(await o.evaluate(() => document.getElementById('uc-new').hidden && !document.querySelector('[data-ucs]')), 'an operator sees no editor');
    ok(await o.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1), 'phone width: no sideways scroll'); await o.close();
    if (process.env.SHOT) await p.screenshot({ path: process.env.SHOT + '-lrq.png', fullPage: true });
  } finally { await browser.close(); web.close(); await e.close(); }
  ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks'); process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
