// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for the PDPL Control Monitor (dashboards/server/pdpl-monitor.html) against the REAL IT Asset Management engine
// (engine/pdpl-monitor.js) over SYNTHETIC records: run, matrix, a failing test opened and sent to GRC, an ambiguous system linked
// by hand, an acknowledgement campaign started by an admin, a viewer acknowledging for themselves, menu search, phone width.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node pdpl-monitor.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const ITAM = path.join(__dirname, '..', '..', 'backend', 'itam'), DASH = path.join(__dirname, '..', '..', 'ui');
const H = require(path.join(ITAM, 'tests', 'helpers'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
(async () => {
  const e = await H.startApp({ noAi: true });
  require(path.join(ITAM, 'engine/duty')).registerDuty(e.app.srv, e.app, { noTimer: true, python: process.env.PYTHON || 'python3', acovLogCoverage: async () => ({ ok: true, assets: [] }), acovAvail: async () => ({ ok: true, hosts: {} }) });
  const C = (x) => e.app.store.collection(x);
  C('assets').put({ id: 'AST-1', name: 'claims-db', ip: '10.9.0.11', classification: 'restricted', cia: { c: 'high' }, owner: 'dba.syn', eol: '2099-01-01', type: 'server', status: 'active' });
  C('assets').put({ id: 'AST-2', name: 'hr-app', ip: '10.9.0.12', classification: 'internal', cia: { c: 'medium' }, eol: '2020-01-01', type: 'server', status: 'active' });
  C('assets').put({ id: 'AST-3', name: 'portal', ip: '10.9.0.13', type: 'server', status: 'active' });
  C('assets').put({ id: 'AST-4', name: 'portal', ip: '10.9.0.14', type: 'server', status: 'active' });
  C('pdpl_records').put({ id: 'PD-ROPA-001', kind: 'ropa', name: 'Medical claims (synthetic)', systems: ['claims-db'], data_categories: ['identity', 'health'] });
  C('pdpl_records').put({ id: 'PD-ROPA-002', kind: 'ropa', name: 'HR (synthetic)', systems: ['hr-app', 'portal'], data_categories: ['identity', 'employment'] });
  C('pdpl_records').put({ id: 'PD-RET-001', kind: 'retention', name: 'Claims (synthetic)', systems: ['claims-db'] });
  const ctl = (st) => ({ edr: { state: st }, patch: { state: st }, backup: { state: st }, vuln_scan: { state: st }, siem_logs: { state: st } });
  e.app.addons.assetCoverage = { view: async () => ({ rows: [{ id: 'AST-1', type: 'server', controls: ctl('present') }, { id: 'AST-2', type: 'server', controls: ctl('missing') }] }) };
  let who = { user: 'nora.syn', role: 'operator' };
  const srv = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://x'), json = (code, b) => { res.writeHead(code, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u.pathname === '/dashboards/whoami.json') return json(200, who);
    if (u.pathname.startsWith('/api/itam/')) { const h = Object.assign({}, req.headers, { 'x-sentra-proxy-secret': H.SECRET, 'x-auth-user': who.user, 'x-auth-role': who.role });
      const up = http.request({ host: '127.0.0.1', port: e.port, method: req.method, path: req.url, headers: h }, (r) => { res.writeHead(r.statusCode, r.headers); r.pipe(res); }); req.pipe(up); return; }
    if (u.pathname.startsWith('/api/') || u.pathname === '/') return json(404, { error: 'not in this test' });
    const f = path.join(DASH, u.pathname.replace(/^\/dashboards\//, '/')); if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (err, d) => { if (err) { res.writeHead(404); res.end(); return; } res.writeHead(200, { 'Content-Type': u.pathname.endsWith('.js') ? 'application/javascript' : u.pathname.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port + '/';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  const wait = (p, fn, arg) => p.waitForFunction(fn, arg === undefined ? null : arg, { timeout: 30000 }).then(() => true, () => false);
  try {
    const p = await browser.newPage({ viewport: { width: 1400, height: 1000 } }); p.on('pageerror', (x) => errs.push(x.message));
    await p.goto(base + 'pdpl-monitor.html?standalone=1');
    ok(await wait(p, () => document.querySelectorAll('#matrix tbody tr').length === 3), 'three systems holding personal data');
    ok(/control score/.test(await p.textContent('#kpis')), 'KPIs');
    ok(/SENSITIVE/.test(await p.textContent('#matrix')), 'sensitive data flagged');
    await p.click('#run'); ok(await wait(p, () => /never/.test(document.getElementById('kpis').textContent) === false), 'run recorded');
    ok(await wait(p, () => document.querySelectorAll('#trend circle').length >= 1), 'trend point drawn');
    await p.check('#ffail'); ok(await wait(p, () => document.querySelectorAll('#matrix tbody tr').length === 2), 'failing only filter');
    await p.uncheck('#ffail');
    // a failing test on hr-app: classification
    await p.click('#matrix tr:has-text("hr-app") button[aria-label="M02 fail"]');
    ok(await wait(p, () => !document.getElementById('drawer').hidden && /internal/.test(document.getElementById('drawer').textContent)), 'drawer shows the evidence');
    await p.click('[data-grc]'); ok(await wait(p, () => Array.from(document.querySelectorAll('#matrix tr')).some((tr) => /hr-app/.test(tr.textContent) && /G/.test(tr.querySelector('button[aria-label="M02 fail"]').textContent))), 'sent to GRC, marked G');
    ok(C('grc_actions').all().some((a) => a.ref && a.ref.startsWith('monitor:')), 'GRC action exists');
    // ambiguous portal -> link by hand
    await p.click('#matrix tr:has-text("portal") button[aria-label="M01 fail"]');
    ok(await wait(p, () => /matches 2 assets/.test(document.getElementById('drawer').textContent)), 'never guesses between two assets');
    await p.fill('#lasset', 'AST-3'); await p.click('[data-map]');
    ok(await wait(p, () => Array.from(document.querySelectorAll('#matrix tr')).some((tr) => /portal/.test(tr.textContent) && tr.querySelector('button[aria-label="M01 pass"]'))), 'linked: M01 passes');
    // campaign by an admin
    who = { user: 'adam.syn', role: 'admin' };
    await p.reload(); ok(await wait(p, () => !document.getElementById('newcamp').hidden && document.getElementById('cpol').options.length > 0), 'campaign form with GRC policies');
    ok(/PP-01/.test(await p.textContent('#polnote')), 'says how to get an approved PDPL policy');
    await p.click('#newcamp summary'); await p.fill('#caud', 'vera.syn, nora.syn'); await p.fill('#cdue', new Date(Date.now() + 14 * 86400000).toISOString().slice(0, 10));
    await p.click('#cstart'); ok(await wait(p, () => /0 of 2/.test(document.getElementById('camps').textContent)), 'campaign listed 0 of 2');
    await p.fill('#zs-q', 'cyberarrow'); await p.waitForTimeout(150);
    ok((await p.$$eval('#zs-best a b', (x) => x.map((y) => y.textContent))).includes('PDPL Control Monitor'), 'menu search finds the page');
    // a viewer acknowledges for themselves, at phone width
    who = { user: 'vera.syn', role: 'viewer' };
    const v = await browser.newPage({ viewport: { width: 400, height: 900 } }); v.on('pageerror', (x) => errs.push(x.message));
    await v.goto(base + 'pdpl-monitor.html?standalone=1');
    ok(await wait(v, () => !document.getElementById('viewer').hidden && document.getElementById('work').hidden && !document.getElementById('mycard').hidden), 'viewer: summary + my acknowledgement');
    ok(await v.isDisabled('[data-ack]'), 'button waits for the confirmation');
    await v.check('[data-read]'); await v.click('[data-ack]');
    ok(await wait(v, () => /Acknowledged/.test(document.getElementById('mine').textContent)), 'acknowledged');
    ok(await v.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1), 'phone width: no sideways scroll');
    who = { user: 'adam.syn', role: 'admin' }; await p.reload();
    ok(await wait(p, () => /1 of 2/.test(document.getElementById('camps').textContent)), 'campaign shows 1 of 2');
  } finally { await browser.close(); srv.close(); await e.close(); }
  ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks'); process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
