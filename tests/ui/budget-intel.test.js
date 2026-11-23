// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for the AI / ML tab of dashboards/server/budget.html against the REAL ITAM engine (engine/budget-intel.js) with
// SYNTHETIC lines, purchase orders and invoices: #ai opens the tab; the year-end forecast per envelope (P50, range, chance over the
// ceiling - Cyber Security far over); a price suggestion learned from two purchases of the same model, accepted by an admin (the
// line is priced in the budget, audited); the best mix; an operator sees no Accept; a viewer is told the tab is for operators;
// escaped titles; no page error.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node budget-intel.test.js
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
  B.putSettings({ fy: FY, envelopes: { it_ops: 2000000, cyber: 150000 }, inflation_pct: 0 }, A1);
  e.app.store.collection('assets').put({ id: 'zs-syn-sw1', asset_tag: 'SYN-SW-1', name: 'core-sw-syn', type: 'switch', vendor: 'Aruba', model: 'CX 6300M SYN', lifecycle: { eol: FY + '-03-01' }, purchase: { cost: 61000, date: (FY - 1) + '-03-01' } });
  e.app.store.collection('assets').put({ id: 'zs-syn-sw2', asset_tag: 'SYN-SW-2', name: 'core-sw-syn2', type: 'switch', vendor: 'Aruba', model: 'CX 6300M SYN', purchase: { cost: 59000, date: FY + '-01-10' } });
  B.saveLine({ envelope: 'it_ops', area: 'infrastructure', kind: 'capex', title: 'Replace core switch SYN ' + XSS, amount: null, priority: 'must' }, A1);
  const un = B.build().lines.find((l) => /Replace core switch SYN/.test(l.title)).id;
  B.decide(un, { note: 'synthetic' }, A1);
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
    WHO = { user: 'syed', role: 'admin' };
    await p.goto(base + 'budget.html#ai');
    ok(await wait(p, () => !document.getElementById('tab-ai').hidden && /most likely/.test(document.getElementById('bi-fc').innerText)), '#ai opens the AI / ML tab with the forecast');
    const fc = await txt(p, 'bi-fc'); ok(/Cyber Security[\s\S]*Chance over ceiling[\s\S]*(100|9\d)%/.test(fc), 'cyber far over its ceiling: ' + fc.slice(0, 300));
    ok(/IT Operations/.test(fc) && /Range \(P10/.test(fc), 'range per envelope');
    ok(/simulated years/.test(await txt(p, 'bi-why')), 'what the forecast rests on');
    // no purchase evidence for this model yet -> said plainly; with the assets' costs a suggestion
    const pr = await txt(p, 'bi-pr'); ok(/Replace core switch SYN/.test(pr) || /no purchase of the same model/.test(pr), 'price section: ' + pr.slice(0, 200));
    ok(await p.evaluate(() => !window.__xss), 'titles escaped');
    ok(/Best mix/.test(await txt(p, 'bi-op')), 'best mix per envelope');
    const has = await p.$('[data-acc]');
    if (has) {
      p.once('dialog', (d) => d.accept('60000'));
      await has.click();
      ok(await wait(p, () => /Price set/.test(document.body.innerText)), 'admin accepts a price');
      const line = B.build().lines.find((l) => l.id === un); ok(line.amount === 60000 && line.priced, 'line priced in the budget: ' + line.amount);
      ok(e.app.store.auditTail(50).some((a) => a.action === 'budget.intel.price.accept' && a.by === 'syed'), 'audited in the admin\'s name');
    } else ok(false, 'a price suggestion with an Accept button for the admin');
    WHO = { user: 'fin.syn', role: 'operator' };
    const o = await browser.newPage({ viewport: { width: 1300, height: 900 } }); o.on('pageerror', (x) => errs.push(x.message));
    await o.goto(base + 'budget.html#ai'); await wait(o, () => /most likely/.test(document.getElementById('bi-fc').innerText));
    ok(!(await o.$('[data-acc]')), 'an operator reads but cannot accept a price'); await o.close();
    WHO = { user: 'vera.syn', role: 'viewer' };
    const v = await browser.newPage({ viewport: { width: 390, height: 900 } }); v.on('pageerror', (x) => errs.push(x.message));
    await v.goto(base + 'budget.html#ai');
    ok(await wait(v, () => /for operators and administrators/.test(document.getElementById('bi-fc').innerText)), 'a viewer is told who the tab is for');
    ok(await v.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1), 'phone width: no sideways scroll'); await v.close();
    if (process.env.SHOT) await p.screenshot({ path: process.env.SHOT + '-budget-ai.png', fullPage: true });
  } finally { await browser.close(); web.close(); await e.close(); }
  ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks'); process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
