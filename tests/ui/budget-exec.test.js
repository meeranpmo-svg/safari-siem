// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for the Execution tab of dashboards/server/budget.html against the REAL ITAM engine (engine/budget-exec.js) with
// SYNTHETIC approved lines, a purchase order and invoices: #exec opens the tab; KPIs, quarters and the cumulative chart; a line
// drawer with quarters and invoices; an operator records an invoice (reference required, a duplicate refused); warnings for an
// overspend; an admin voids with a reason and sets phasing that must add up; a viewer reads but has no record button; escaped
// titles; the portal budget view redirects here; no page error.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node budget-exec.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const ITAM = path.join(__dirname, '..', '..', 'backend', 'itam'), DASH = path.join(__dirname, '..', '..', 'ui');
const H = require(path.join(ITAM, 'tests', 'helpers'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const XSS = '<img src=x onerror="window.__xss=1">';

(async () => {
  const e = await H.startApp({ noAi: true });
  require(path.join(ITAM, 'engine/duty')).registerDuty(e.app.srv, e.app, { noTimer: true });
  const A1 = { user: 'syed', role: 'admin' };
  const B = e.app.addons.budget || (e.app.addons.budget = require(path.join(ITAM, 'engine/budget')).createBudget(e.app));
  const FY = new Date().getUTCFullYear(); B.putSettings({ fy: FY }, A1);
  const mk = (o) => { B.saveLine(Object.assign({ area: o.envelope === 'cyber' ? 'security' : 'infrastructure' }, o), A1); const id = B.build().lines.find((l) => l.title === o.title).id; B.decide(id, { status: 'approved', note: 'synthetic' }, A1); return id; };
  const wan = mk({ envelope: 'it_ops', kind: 'opex', title: 'WAN links SYN ' + XSS, amount: 120000 });
  const edr = mk({ envelope: 'cyber', kind: 'opex', title: 'EDR subscription SYN', amount: 200000 });
  const srv = mk({ envelope: 'it_ops', kind: 'capex', title: 'Server refresh SYN', amount: 400000, due: FY + '-08-15' });
  e.app.store.collection('purchase_orders').put({ id: 'PR-SYN-1', po_number: 'PO-SYN-1', budget_line: srv, approved: { by: 'cfo.syn' }, lines: [{ qty: 2, unit_cost: 100000 }], dates: { requested: FY + '-07-01' } });
  e.app.store.collection('budget_actuals').put({ id: 'bx_syn1', line_id: edr, date: FY + '-02-01', amount: 240000, reference: 'EDR-SYN-1', by: 'fin.syn', at: new Date().toISOString(), void: false });
  let WHO = { user: 'fin.syn', role: 'operator' };

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
    let p = await browser.newPage({ viewport: { width: 1500, height: 1100 } }); p.on('pageerror', (x) => errs.push(x.message));
    await p.goto(base + 'budget.html#exec');
    ok(await wait(p, () => !document.getElementById('tab-exec').hidden && /Plan/.test(document.getElementById('x-k').innerText)), '#exec opens the Execution tab');
    let k = await txt(p, 'x-k'); ok(/720,000/.test(k) && /Committed[\s\S]*200,000/.test(k), 'plan and committed');
    ok(/Q1[\s\S]*Q4/.test(await txt(p, 'x-q')), 'quarters'); ok(await p.$('#x-chart svg'), 'cumulative chart');
    ok(/overspend risk[\s\S]*EDR subscription SYN/.test(await txt(p, 'x-w')), 'overspend warning');
    ok(await p.evaluate(() => !window.__xss), 'titles escaped');
    // line drawer + record an invoice
    await p.evaluate((id) => document.querySelector('[data-xl="' + CSS.escape(id) + '"]').click(), wan);
    ok(await wait(p, () => document.getElementById('xi-go')), 'line drawer with the invoice form');
    await p.fill('#xi-a', '10000'); await p.click('#xi-go'); ok(/invoice reference/.test(await p.evaluate(() => document.getElementById('xi-e').innerText)), 'reference required');
    await p.fill('#xi-r', 'STC-SYN-1'); await p.click('#xi-go');
    ok(await wait(p, () => /Invoice recorded/.test(document.body.innerText)), 'invoice recorded');
    ok(e.app.store.collection('budget_actuals').all((a) => a.reference === 'STC-SYN-1' && a.by === 'fin.syn').length === 1, 'stored with who');
    await p.click('#x-add'); await p.selectOption('#xi-l', wan); await p.fill('#xi-a', '10000'); await p.fill('#xi-r', 'STC-SYN-1'); await p.click('#xi-go');
    ok(await wait(p, () => /already recorded/.test((document.getElementById('xi-e') || {}).innerText || '')), 'a duplicate invoice is refused');
    await p.close();
    // admin: void with a reason, phasing must add up
    WHO = A1; p = await browser.newPage({ viewport: { width: 1500, height: 1100 } }); p.on('pageerror', (x) => errs.push(x.message));
    await p.goto(base + 'budget.html#exec'); await wait(p, () => document.querySelector('[data-xl]'));
    await p.evaluate((id) => document.querySelector('[data-xl="' + CSS.escape(id) + '"]').click(), edr); await wait(p, () => document.querySelector('[data-xv]'));
    await p.click('[data-xv]'); await p.click('#xv-go'); ok(/Give the reason/.test(await p.evaluate(() => document.getElementById('xv-e').innerText)), 'void needs a reason');
    await p.fill('#xv-r', 'duplicate entry, synthetic'); await p.click('#xv-go'); ok(await wait(p, () => /Invoice voided/.test(document.body.innerText)), 'voided');
    ok(e.app.store.collection('budget_actuals').get('bx_syn1').void === true, 'kept, marked void');
    await p.evaluate((id) => document.querySelector('[data-xl="' + CSS.escape(id) + '"]').click(), srv); await wait(p, () => document.getElementById('xp-go'));
    await p.fill('#xp-q1', '5000'); await p.click('#xp-go'); ok(await wait(p, () => /add up/.test(document.getElementById('xp-e').innerText)), 'phasing must add up');
    await p.fill('#xp-q1', '0'); await p.fill('#xp-q2', '200000'); await p.fill('#xp-q3', '200000'); await p.fill('#xp-q4', '0'); await p.click('#xp-go');
    ok(await wait(p, () => /Phasing saved/.test(document.body.innerText)), 'phasing saved');
    await p.close();
    // viewer reads, no record button
    WHO = { user: 'vera.syn', role: 'viewer' }; p = await browser.newPage(); p.on('pageerror', (x) => errs.push(x.message));
    await p.goto(base + 'budget.html#exec'); await wait(p, () => /Plan/.test(document.getElementById('x-k').innerText)); await p.waitForTimeout(400);
    ok(await p.evaluate(() => document.getElementById('x-add').hidden), 'viewer: no record button'); await p.close();
    ok(/ budget: 'budget\.html#exec'/.test(fs.readFileSync(path.join(DASH, 'vendor/zyb-early.js'), 'utf8')), 'the portal Budgets view redirects here');
    ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  } finally { await browser.close(); web.close(); e.close(); }
  console.log(`${n - bad}/${n} checks passed`); process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
