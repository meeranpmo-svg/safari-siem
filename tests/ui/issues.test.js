// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for Issues Management (dashboards/server/issues.html) against the REAL IT Asset Management engine
// (engine/issues-hub.js) over SYNTHETIC records in four sources: KPIs, charts, the escalation list, a possible duplicate confirmed
// with one click, a link to a GRC risk, filters, menu search, a viewer sees counts only, phone width.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node issues.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const ITAM = path.join(__dirname, '..', '..', 'backend', 'itam'), DASH = path.join(__dirname, '..', '..', 'ui');
const H = require(path.join(ITAM, 'tests', 'helpers'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
(async () => {
  const e = await H.startApp({ noAi: true });
  require(path.join(ITAM, 'engine/duty')).registerDuty(e.app.srv, e.app, { noTimer: true, python: process.env.PYTHON || 'python3', acovLogCoverage: async () => ({ ok: true, assets: [] }), acovAvail: async () => ({ ok: true, hosts: {} }) });
  const C = (x) => e.app.store.collection(x), past = new Date(Date.now() - 90 * 86400000).toISOString();
  C('ia_findings').put({ id: 'ITA-001', title: 'Privileged access review not performed quarterly', rating: 'high', state: 'open', owner: 'it.manager.syn', due: past.slice(0, 10), raised_at: past, history: [] });
  C('grc_actions').put({ id: 'ACT-0001', title: 'Quarterly privileged access review not performed', source: 'manual', priority: 'high', status: 'open', owner: 'it.manager.syn', due: '2099-12-31', created_at: past });
  C('ar_findings').put({ id: 'ARF-00001', year: 2025, body: 'SAMA', title: 'Backup restore not tested (synthetic)', status: 'open', owner: 'infra.syn', due: past.slice(0, 10), created_at: past, repeat: [{ of: 'ARF-00000' }] });
  C('insp_actions').put({ id: 'act-0123456789', inspection: 'ins-0123456789', site: 'JED-SYN', item: 'n1', item_text: 'Network cabinet locked', severity: 'critical', likelihood: 4, impact: 5, state: 'open', due: '2099-01-01', created_at: past, history: [] });
  C('grc_risks').put({ id: 'RSK-001', title: 'Unauthorised privileged access (synthetic)' });
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
  const wait = (p, fn) => p.waitForFunction(fn, null, { timeout: 30000 }).then(() => true, () => false);
  try {
    const p = await browser.newPage({ viewport: { width: 1400, height: 1000 } }); p.on('pageerror', (x) => errs.push(x.message));
    await p.goto(base + 'issues.html?standalone=1');
    ok(await wait(p, () => document.querySelectorAll('#tbl tbody tr').length === 4), 'four open issues from four sources');
    ok(/open issues/.test(await p.textContent('#kpis')) && /regulator/.test(await p.textContent('#kpis')), 'KPIs');
    ok(/IT Audit Team/.test(await p.textContent('#bysrc')) && /Audit Repository/.test(await p.textContent('#bysrc')), 'by source');
    ok(/Backup restore not tested/.test(await p.textContent('#esc')) && /Privileged access review/.test(await p.textContent('#esc')), 'escalation list');
    ok(/REPEAT/.test(await p.textContent('#tbl')) && /REGULATOR/.test(await p.textContent('#tbl')), 'repeat and regulator tags');
    ok(/IT Audit Team · ITA-001/.test(await p.textContent('#tbl')), 'each issue links back to where it is worked');
    await p.click('[data-dup]');
    ok(await wait(p, () => /No likely duplicate/.test(document.getElementById('dups').textContent) && document.querySelectorAll('#tbl tbody tr').length === 3), 'confirmed duplicate: one issue, not two');
    await p.fill('tr[data-key="ia:ITA-001"] [data-risk]', 'RSK-001'); await p.click('tr[data-key="ia:ITA-001"] [data-link]');
    ok(await wait(p, () => /risk RSK-001/.test((document.querySelector('tr[data-key="ia:ITA-001"]') || {}).textContent || '')), 'linked to a GRC risk');
    await p.selectOption('#fsig', 'critical'); ok(await wait(p, () => document.querySelectorAll('#tbl tbody tr').length === 1), 'significance filter');
    await p.selectOption('#fsig', ''); await p.selectOption('#fst', 'overdue'); ok(await wait(p, () => document.querySelectorAll('#tbl tbody tr').length === 2), 'overdue filter');
    await p.fill('#zs-q', 'archer'); await p.waitForTimeout(150);
    ok((await p.$$eval('#zs-best a b', (x) => x.map((y) => y.textContent))).includes('Issues Management'), 'menu search finds the page');
    who = { user: 'vera.syn', role: 'viewer' };
    const v = await browser.newPage({ viewport: { width: 400, height: 900 } }); v.on('pageerror', (x) => errs.push(x.message));
    await v.goto(base + 'issues.html?standalone=1');
    ok(await wait(v, () => !document.getElementById('viewer').hidden && document.getElementById('work').hidden && /open issues/.test(document.getElementById('kpis').textContent)), 'viewer: counts only');
    ok(await v.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1), 'phone width: no sideways scroll');
  } finally { await browser.close(); srv.close(); await e.close(); }
  ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks'); process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
