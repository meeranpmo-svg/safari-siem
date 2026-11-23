// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Database Health Statement (db-health-statement.html), stubbed SIEM, SYNTHETIC data: databases listed, a statement prepared
// for a window (the request carries the window and the client IP), the verdict and every check with its reading shown,
// escaping, routing to a team (case id shown), statements list opens one, viewer refused, not installed.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node db-health-statement.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const DASH = path.resolve(__dirname, '../../ui');
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const POSTS = []; let MODE = 'ok';
const XSS = '<img src=x onerror=alert(1)>';
const STMT = { id: 'DHS-20261026-001', instance: 'ORCLPRD', from: '2026-10-26T08:00:00.000Z', to: '2026-10-26T09:00:00.000Z', client_ip: '10.20.1.15', db_ip: '10.10.5.20', app: 'Claims portal', complaint: 'slow saving ' + XSS, ticket: 'INC-4411',
  coverage: 100, conclusion: 'network', areas: ['network'], conclusion_text: 'Problems found in this window: network. The database recorded 2 dropped / timed-out connection(s) from 10.20.1.15.',
  prepared_by: 'dba.syn', prepared_at: Date.parse('2026-10-26T09:05:00Z'), digest: 'sha256:' + 'b'.repeat(64), routing: [],
  checks: [{ area: 'availability', status: 'ok', title: 'Readings cover 100% of the window', evidence: ['400 readings'], reading: 'SIEM oracle-health readings' },
    { area: 'database', status: 'ok', title: 'Wait times were within their normal range', evidence: ['db file sequential read: 4 ms avg'], reading: 'wait classes / top wait events' },
    { area: 'database', status: 'not_measured', title: 'Database load not measured in the window', evidence: [], reading: 'load profile' },
    { area: 'network', status: 'issue', title: 'The database recorded 2 dropped / timed-out connection(s) from 10.20.1.15', evidence: ['TNS-12170 ' + XSS], reading: 'alert log network errors' }],
  top_waits: [{ event: 'db file sequential read', class: 'User I/O', avg_ms: 4 }], top_sql: [{ sql_id: 'a1b2c3d4e5f6g', module: 'claims-api', elapsed_s: 40, executions: 900 }] };
let LIST = [];
(async () => {
  const srv = http.createServer((req, res) => {
    const u = decodeURIComponent(req.url.split('?')[0]), json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    const body = (fn) => { let b = ''; req.on('data', (c) => { b += c; }); req.on('end', () => { const j = JSON.parse(b || '{}'); POSTS.push([u, j]); fn(j); }); };
    if (u === '/dashboards/whoami.json' || u === '/auth/whoami') return json(200, { user: 'dba.syn', role: MODE === 'viewer' ? 'viewer' : 'operator' });
    if (MODE === 'none' && u.startsWith('/api/')) return json(404, { error: 'not found' });
    if (u === '/api/soc/db/dba/status') return json(200, { instances: [{ instance: 'ORCLPRD' }, { instance: 'HRDB' }, { instance: 'ORCLPRD' }] });
    if (MODE === 'viewer' && u.startsWith('/api/soc/db/statements')) return json(403, { error: 'requires operator role' });
    if (u === '/api/soc/db/statements' && req.method === 'GET') return json(200, { items: LIST });
    if (u === '/api/soc/db/statements' && req.method === 'POST') return body(() => { LIST = [{ id: STMT.id, instance: 'ORCLPRD', from: STMT.from, to: STMT.to, app: STMT.app, conclusion: 'network', prepared_by: 'dba.syn', routed: [] }]; json(200, STMT); });
    if (u === '/api/soc/db/statements/' + STMT.id && req.method === 'GET') return json(200, STMT);
    if (u === '/api/soc/db/statements/' + STMT.id + '/route') return body((b) => json(200, Object.assign({}, STMT, { routing: [{ team: b.team, note: b.note, by: 'dba.syn', at: Date.now(), case_id: 'CASE-000042' }] })));
    if (u.startsWith('/api/')) return json(404, { error: 'not in this test' });
    const f = path.join(DASH, u.replace(/^\/dashboards\//, '')); if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (e, d) => { if (e) { res.writeHead(404); return res.end(); } res.writeHead(200, { 'Content-Type': f.endsWith('.js') ? 'application/javascript' : f.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port;
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright'); const browser = await chromium.launch();
  try {
    const p = await browser.newPage({ viewport: { width: 1300, height: 1000 } }); const errs = []; p.on('pageerror', (e) => errs.push(e.message));
    let alerted = false; p.on('dialog', (d) => { alerted = true; d.dismiss(); });
    await p.goto(base + '/dashboards/db-health-statement.html?standalone=1'); await p.waitForFunction(() => document.querySelectorAll('#inst option').length > 1);
    const opts = await p.$$eval('#inst option', (o) => o.map((x) => x.textContent)); ok(opts.join('|') === 'choose…|HRDB|ORCLPRD', 'databases listed once each: ' + opts.join('|'));
    ok(/No statement yet/.test(await p.textContent('#list')), 'empty list says so');
    await p.selectOption('#inst', 'ORCLPRD'); await p.fill('#from', '2026-10-26T11:00'); await p.fill('#to', '2026-10-26T12:00');
    await p.fill('#cip', '10.20.1.15'); await p.fill('#app', 'Claims portal'); await p.fill('#tkt', 'INC-4411'); await p.fill('#cmp', 'slow saving');
    await p.click('#go'); await p.waitForSelector('#stmt .verdict');
    const post = POSTS.find((x) => x[0] === '/api/soc/db/statements')[1];
    ok(post.instance === 'ORCLPRD' && post.client_ip === '10.20.1.15' && post.app === 'Claims portal' && post.ticket === 'INC-4411' && /T\d\d:00:00\.000Z$/.test(post.from) && Date.parse(post.to) - Date.parse(post.from) === 3600000, 'request carries the window and inputs: ' + JSON.stringify(post));
    ok(!('db_ip' in post), 'empty fields are not sent');
    const t = await p.textContent('#stmt');
    ok(/Network issue · ORCLPRD/.test(t) && /dropped \/ timed-out connection\(s\) from 10\.20\.1\.15/.test(t), 'verdict');
    ok(/ISSUE/.test(t) && /not measured/.test(t) && /alert log network errors/.test(t) && /wait classes \/ top wait events/.test(t), 'each check with its status and reading');
    ok(/100% of the window/.test(t) && /DHS-20261026-001/.test(t) && /sha256:b{64}/.test(t) && /dba\.syn/.test(t), 'coverage, id, digest, who');
    ok(/db file sequential read/.test(t) && /a1b2c3d4e5f6g/.test(t), 'top waits and SQL');
    ok(!(await p.$('#stmt img')) && /onerror/.test(t), 'escaped');
    ok((await p.inputValue('#team')) === 'network', 'route defaults to the team the verdict points at');
    await p.click('#route'); ok(/Say what they should look at/.test(await p.textContent('#rmsg')), 'route needs a note');
    await p.fill('#note', 'firewall idle timeout between the claims app and the database'); await p.click('#route');
    await p.waitForFunction(() => /CASE-000042/.test(document.getElementById('stmt').textContent));
    const rp = POSTS.find((x) => /\/route$/.test(x[0]))[1]; ok(rp.team === 'network' && /idle timeout/.test(rp.note), 'route request');
    ok(/routed to network by dba\.syn · case CASE-000042/.test(await p.textContent('#stmt')), 'routing history with the case');
    ok(/DHS-20261026-001/.test(await p.textContent('#list')) && /Network issue/.test(await p.textContent('#list')), 'list updated');
    await p.evaluate(() => { document.getElementById('stmt').hidden = true; }); await p.click('#list tr[data-id]'); await p.waitForFunction(() => !document.getElementById('stmt').hidden);
    ok(true, 'a listed statement opens');
    ok(!alerted && errs.length === 0, 'no script ran, no page error: ' + errs.join(' | '));
    MODE = 'viewer'; await p.reload(); await p.waitForFunction(() => /operators and administrators/.test(document.getElementById('list').textContent)); ok(true, 'viewer told why');
    MODE = 'none'; await p.reload(); await p.waitForFunction(() => /not installed/.test(document.getElementById('list').textContent)); ok(true, 'not installed says so');
    await p.close();
  } finally { await browser.close(); srv.close(); }
  console.log(`${n - bad}/${n} passed`); process.exit(bad ? 1 : 0);
})();
