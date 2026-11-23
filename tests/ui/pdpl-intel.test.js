// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for PDPL Intelligence (dashboards/server/pdpl-intel.html) against the REAL ITAM engine (engine/pdpl-intel.js
// over engine/pdpl.js registers) with SYNTHETIC records: KPIs, the model card says it is not trained, the review queue with
// probabilities, a column reviewed in the drawer (a short note refused with the reason), a hostile column name stays text,
// deadline risk for a breach and a request, a DPIA drafted from the rules, the requester refused and the DPO approving, the
// menu has the page under PDPL, a viewer refused without a broken page.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node pdpl-intel.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const ITAM = path.join(__dirname, '..', '..', 'backend', 'itam'), DASH = path.join(__dirname, '..', '..', 'ui');
const H = require(path.join(ITAM, 'tests', 'helpers'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const XSS = '<img src=x onerror=alert(1)>';
const OP = { user: 'nora.syn', role: 'operator' }, DPO = { user: 'dana.syn', role: 'operator' }, ADM = { user: 'syed', role: 'admin' }, VIEW = { user: 'vera.syn', role: 'viewer' };

(async () => {
  const e = await H.startApp({ noAi: true });
  require(path.join(ITAM, 'engine/duty')).registerDuty(e.app.srv, e.app, { noTimer: true, python: process.env.PYTHON || 'python3' });
  const PD = e.app.addons.pdpl, put = (r) => PD.putRecord(r, ADM), T = Date.now(), d = (n2) => new Date(T - n2 * 86400000).toISOString().slice(0, 10);
  put({ kind: 'profile', dpo_user: DPO.user });
  const ro = put({ kind: 'ropa', name: 'Claims fraud scoring (synthetic)', purpose: 'detect fraudulent claims', legal_basis: 'legitimate_interest', data_categories: ['identity', 'health'], fraud_scoring: true });
  put({ kind: 'dsr', ref: 'DSR-SYN-1', type: 'access', received: d(26), stage: 'received' });
  put({ kind: 'breach', ref: 'BR-SYN-1', aware_at: new Date(T - 64 * 3600000).toISOString().slice(0, 16) + 'Z', description: 'synthetic' });
  e.app.store.collection('pdpl_discovery').put({ id: 'db1', db: 'db1', engine: 'oracle', label: 'claims-db (synthetic)', at: new Date().toISOString(), ok: true, columns: [
    { owner: 'CLAIMS', table: 'CUST', column: 'NATIONAL_ID', type: 'VARCHAR2', rows: 1200, kind: 'national_id', category: 'identity', by: 'both', sampled: 20, matched: 19 },
    { owner: 'CLAIMS', table: 'DIAG', column: 'DIAGNOSIS ' + XSS, type: 'VARCHAR2', rows: 300, kind: 'diagnosis', category: 'health', by: 'name', sampled: 0, matched: 0 }] });
  let WHO = OP;
  const srv = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://x'), json = (c, b2) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b2)); };
    if (u.pathname === '/dashboards/whoami.json') return json(200, WHO);
    if (u.pathname.startsWith('/api/itam/')) {
      const h = Object.assign({}, req.headers, { 'x-sentra-proxy-secret': H.SECRET, 'x-auth-user': WHO.user, 'x-auth-role': WHO.role });
      const up = http.request({ host: '127.0.0.1', port: e.port, method: req.method, path: req.url, headers: h }, (r) => { res.writeHead(r.statusCode, r.headers); r.pipe(res); });
      req.pipe(up); return;
    }
    if (u.pathname.startsWith('/api/')) return json(404, { error: 'not in this test' });
    const f = path.join(DASH, u.pathname.replace(/^\/dashboards\//, '/')); if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (err, b) => { if (err) { res.writeHead(404); res.end(); return; } res.writeHead(200, { 'Content-Type': u.pathname.endsWith('.js') ? 'application/javascript' : u.pathname.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(b); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port + '/';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  const wait = (p, fn, arg) => p.waitForFunction(fn, arg, { timeout: 10000 }).then(() => true, () => false);
  const zd = (p, re) => wait(p, (src) => new RegExp(src).test((document.getElementById('zd') || {}).textContent || ''), re.source);
  try {
    const p = await browser.newPage({ viewport: { width: 1400, height: 950 } }); p.on('pageerror', (x) => errs.push(x.message));
    p.on('dialog', (x) => { errs.push('dialog: ' + x.message()); x.dismiss(); });
    await p.goto(base + 'pdpl-intel.html?standalone=1'); await p.waitForSelector('#queue tr[data-col]', { timeout: 15000 });
    ok(/Columns to review/.test(await p.textContent('#kpis')) && /Activities without an impact assessment/.test(await p.textContent('#kpis')), 'KPIs');
    ok(/not trained/.test(await p.textContent('#mdl')) && /needs 10/.test(await p.textContent('#mdl')), 'the model says it is not trained yet');
    ok((await p.$$('#queue tr[data-col]')).length === 2, 'two columns to review');
    ok(!(await p.$('#queue img')) && (await p.textContent('#queue')).includes('<img'), 'a hostile column name stays text');
    ok(/\d+%/.test(await p.textContent('#queue')), 'probabilities shown');
    await p.click('#queue tr[data-col]:has-text("NATIONAL_ID")'); ok(await zd(p, /What you checked/), 'review drawer');
    await p.fill('#fr-n', 'ok'); await p.click('[data-d="personal"]'); ok(await zd(p, /note/), 'a short note is refused with the field named');
    await p.fill('#fr-n', 'values are 10-digit national IDs (synthetic)'); await p.click('[data-d="personal"]');
    ok(await wait(p, () => /personal data/.test(document.getElementById('done').textContent) && /nora\.syn/.test(document.getElementById('done').textContent)), 'reviewed, shown with the person');
    ok(e.app.store.auditTail(30).some((x) => x.action === 'pdpl.intel.column.review' && x.by === OP.user), 'audited');
    await p.click('[data-tab="dl"]');
    ok(/BR-SYN-1/.test(await p.textContent('#br')) && /high risk/.test(await p.textContent('#br')), 'the breach is near its 72 hours');
    ok(/DSR-SYN-1/.test(await p.textContent('#ds')) && /by the rules/.test(await p.textContent('#ds')), 'the request with how its risk was computed');
    await p.click('[data-tab="dpia"]');
    ok(/fraud scoring/.test(await p.textContent('#dp')) && /none completed/.test(await p.textContent('#dp')), 'the activity that needs an assessment, with why');
    await p.click('[data-dd="' + ro.id + '"][data-ai="0"]'); ok(await zd(p, /Drafted by the rules/), 'the draft opens');
    await p.fill('#fx-n', 'I asked for it and approve it'); await p.click('[data-x="approve"]'); ok(await zd(p, /DPO/), 'the requester is refused');
    WHO = DPO; await p.reload(); await p.waitForSelector('#queue'); await p.click('[data-tab="dpia"]');
    await p.click('#dr tr[data-dr]'); await p.fill('#fx-n', 'measures confirmed with Claims (synthetic)'); await p.click('[data-x="approve"]');
    ok(await wait(p, () => /approved by the DPO/.test(document.getElementById('dr').textContent)), 'the DPO approves');
    ok(await p.evaluate(() => { const a = (window.ZYB_NAV || []).find((x) => x.id === 'pdpl'); return !!(a && a.pages.some((x) => x.h === 'pdpl-intel.html')); }), 'the menu has the page under PDPL');
    WHO = VIEW; await p.reload(); await p.waitForTimeout(1500);
    ok(/operator role|not loaded/.test(await p.textContent('body')) && !(await p.$('#queue tr[data-col]')), 'a viewer is refused and the page says why');
  } finally { await browser.close(); srv.close(); await e.close(); }
  ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks');
  process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
