// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for the what-if on solvency-capital.html against the REAL engine (engine/solvency.js) with a SYNTHETIC workbook
// (backend/itam/tests/sca-fixture.js): the KPI tiles are buttons; a tile opens the what-if on its own figure; typing a figure moves
// the ratio (with the change in points) without losing the cursor; the minimum capital requirement binding; reset; a plain operator
// cannot save a scenario, the Risk Head can, load and delete it; the return itself is unchanged; a viewer is refused; phone width.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node solvency-whatif.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const ITAM = path.join(__dirname, '..', '..', 'backend', 'itam'), DASH = path.join(__dirname, '..', '..', 'ui');
const H = require(path.join(ITAM, 'tests', 'helpers'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
(async () => {
  const e = await H.startApp({ noAi: true });
  require(path.join(ITAM, 'engine/duty')).registerDuty(e.app.srv, e.app, { noTimer: true, now: () => Date.parse('2026-02-20T08:00:00Z'), python: process.env.PYTHON || 'python3' });
  const F = require(path.join(ITAM, 'tests', 'sca-fixture'));
  await e.req('POST', '/roles/assign', { body: { user: 'rita.syn', role_id: 'risk-head' }, user: 'adam.syn', role: 'admin' });
  const id = (await e.req('POST', '/brisk/solvency/import', { body: { filename: 'sca.xlsx', xlsx_b64: F.b64() }, user: 'nora.syn', role: 'operator' })).json.id;
  let who = { user: 'omar.syn', role: 'operator' };
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
  const base = 'http://127.0.0.1:' + srv.address().port + '/solvency-capital.html?standalone=1';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  const wait = (p, fn, arg) => p.waitForFunction(fn, arg === undefined ? null : arg, { timeout: 15000 }).then(() => true, () => false);
  const toast = (p, re) => wait(p, (s) => [...document.querySelectorAll('.toast')].some((t) => new RegExp(s).test(t.textContent)), re);
  const res = (p) => p.textContent('#wires');
  try {
    const p = await browser.newPage({ viewport: { width: 1440, height: 1000 } }); p.on('pageerror', (x) => errs.push(x.message));
    await p.goto(base); await wait(p, () => document.querySelectorAll('#kpi button.t').length === 8);
    ok(await p.$eval('#kpi button[data-kpi="reg"]', (b) => b.tagName === 'BUTTON' && /What-if/.test(b.title)), 'the tiles are buttons');
    await p.click('#kpi button[data-kpi="reg"]');
    ok(await wait(p, () => !document.getElementById('wi').hidden && /225%/.test(document.getElementById('wires').textContent)), 'the what-if opens on the regulatory ratio (225 %)');
    ok(await p.evaluate(() => document.activeElement.getAttribute('data-wi') === 'admissible'), 'the cursor is on the figure behind it');
    // a loss on admissible assets: 900,000 -> 800,000 of net assets
    await p.fill('[data-wi="admissible"]', '2000000');
    ok(await wait(p, () => /200%/.test(document.getElementById('wires').textContent) && /-25 pts/.test(document.getElementById('wires').textContent)), 'the ratio follows: 200 %, -25 pts: ' + (await res(p)));
    ok(await p.evaluate(() => document.activeElement.getAttribute('data-wi') === 'admissible' && document.activeElement.classList.contains('chg')), 'typing keeps the cursor; the changed figure is marked');
    // the minimum capital requirement binds
    for (const k of ['claims_gh', 'premium_gh', 'req_ps']) await p.fill('[data-wi="' + k + '"]', '0');
    ok(await wait(p, () => /minimum capital requirement/.test(document.getElementById('wires').textContent) && /800%/.test(document.getElementById('wires').textContent)), 'with no margin the MCR binds: ' + (await res(p)));
    await p.click('#wireset'); ok(await wait(p, () => /225%/.test(document.getElementById('wires').textContent) && !/pts/.test(document.getElementById('wires').textContent)), 'reset');
    // the RBC tile focuses RBC
    await p.click('#kpi button[data-kpi="rbc"]'); await wait(p, () => document.activeElement && document.activeElement.getAttribute('data-wi') === 'rbc');
    await p.fill('[data-wi="rbc"]', '504000'); ok(await wait(p, () => /228\.2%/.test(document.getElementById('wires').textContent)), 'RBC +20 %: the RBC ratio 228.2 %');
    ok(/Sensitivity/.test(await p.textContent('#wi')), 'the sensitivity table');
    // saving: a plain operator cannot, the Risk Head can
    await p.click('#wisave'); await p.fill('#f-name', 'RBC +20 % (synthetic)'); await p.click('#dlgok'); ok(await toast(p, 'Not allowed'), 'a plain operator cannot save a scenario');
    await p.click('#dlgno');
    who = { user: 'rita.syn', role: 'operator' }; await p.reload(); await wait(p, () => document.querySelectorAll('#kpi button.t').length === 8);
    await p.click('#kpi button[data-kpi="rbc"]'); await wait(p, () => !!document.querySelector('[data-wi="rbc"]'));
    await p.fill('[data-wi="rbc"]', '504000'); await wait(p, () => /228\.2%/.test(document.getElementById('wires').textContent));
    await p.click('#wisave'); await p.fill('#f-name', 'RBC +20 % <img src=x onerror=window.__wx=1>'); await p.click('#dlgok');
    ok(await toast(p, 'Scenario saved') && /RBC \+20 % <img/.test(await p.textContent('#wi')) && !(await p.evaluate(() => window.__wx)), 'saved by the Risk Head, the name shown as text');
    await p.click('#wireset'); await p.click('[data-wiload]'); ok(await wait(p, () => /228\.2%/.test(document.getElementById('wires').textContent)), 'a saved scenario loads back');
    await p.click('[data-widel]'); await p.click('#dlgok'); ok(await toast(p, 'Scenario deleted'), 'deleted');
    ok(e.app.store.collection('sca_returns').get(id).headline.regulatory_ratio === 2.25, 'the return itself is unchanged');
    ok(e.app.store.auditTail(200).some((a) => a.action === 'brisk.solvency.scenario.save' && a.by === 'rita.syn'), 'saving audited');
    // viewer
    who = { user: 'vera.syn', role: 'viewer' }; await p.reload(); await wait(p, () => document.querySelectorAll('#kpi button.t').length === 8);
    await p.click('#kpi button[data-kpi="reg"]'); ok(await toast(p, 'Not allowed') && await p.$eval('#wi', (x) => x.hidden), 'a viewer is refused the what-if');
    const ph = await browser.newPage({ viewport: { width: 390, height: 900 } }); ph.on('pageerror', (x) => errs.push(x.message)); who = { user: 'rita.syn', role: 'operator' };
    await ph.goto(base); await wait(ph, () => document.querySelectorAll('#kpi button.t').length === 8); await ph.click('#kpi button[data-kpi="reg"]'); await wait(ph, () => !document.getElementById('wi').hidden);
    ok(await ph.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1), 'phone width: no sideways scroll'); await ph.close();
  } finally { await browser.close(); srv.close(); e.close(); }
  ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks'); process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
