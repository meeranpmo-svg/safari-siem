// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for Cost Studio (dashboards/server/cost-studio.html) against the REAL ITAM engine (engine/cost-studio.js, IT Budget,
// licences, Support Contracts, pyengine/cost_studio_rules.py; the model is stubbed) over SYNTHETIC records: the priced savings
// total, envelopes with the learned expected spend, savings cards with their basis (and "money not known" without a recorded
// cost), the kind filter, tracking, done with the saving realised, dismiss with a reason, the AI analyst's proposal accepted by
// another operator, last year's execution, the unusual line, showback tabs, a hostile licence name stays text, a viewer is
// refused, the menu has the page.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node cost-studio.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const ITAM = path.join(__dirname, '..', '..', 'backend', 'itam'), DASH = path.join(__dirname, '..', '..', 'ui');
const H = require(path.join(ITAM, 'tests', 'helpers'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const ADM = { user: 'syed', role: 'admin' }, OP = { user: 'nora.syn', role: 'operator' }, OP2 = { user: 'omar.syn', role: 'operator' }, VIEW = { user: 'vera.syn', role: 'viewer' };
const XSS = '<img src=x onerror=alert(1)>';

(async () => {
  const e = await H.startApp({ noAi: true });
  let turn = 0;
  const create = async () => {
    turn++;
    if (turn % 2 === 1) return { model: 'claude-opus-5-5', stop_reason: 'tool_use', content: [{ type: 'tool_use', id: 'u' + turn, name: 'propose_action', input: { key: 'lic|lic_x', reason: 'nobody has it installed (synthetic)' } }], usage: { input_tokens: 40, output_tokens: 10 } };
    return { model: 'claude-opus-5-5', stop_reason: 'end_turn', content: [{ type: 'text', text: 'Two licences are under-used. I proposed one action for your decision.' }], usage: { input_tokens: 60, output_tokens: 20 } };
  };
  const sdk = class { constructor() { this.messages = { create }; } };
  require(path.join(ITAM, 'engine/duty')).registerDuty(e.app.srv, e.app, { noTimer: true, python: process.env.PYTHON || 'python3', costSdk: sdk, costKey: () => 'sk-ant-synthetic' });
  const mk = (x) => e.app.assets.create(Object.assign({ status: 'in_use', type: 'workstation', site: 'HQ', department: 'Claims' }, x), ADM).asset.id;
  for (let i = 1; i <= 5; i++) { const id = mk({ name: 'PC-SYN-' + i }); e.app.store.collection('assets').patch(id, (a) => { a.software = [{ name: 'Microsoft Visio Professional' }]; a.purchase = { cost: 4000 }; }); }
  for (let i = 1; i <= 4; i++) { const id = mk({ name: 'ESX-SYN-' + i, type: 'server', os: 'VMware ESXi 8.0', site: 'DC1', department: 'IT' }); e.app.store.collection('assets').patch(id, (a) => { a.purchase = { cost: 60000 }; }); }
  e.app.store.collection('licences').put({ id: 'lic_visio', product: 'Visio Professional', seats: 20, cost: 20000, status: 'active', product_key_match: 'visio' });
  e.app.store.collection('licences').put({ id: 'lic_x', product: XSS, seats: 10, status: 'active', product_key_match: 'nothing-installed' });
  const SC = require(path.join(ITAM, 'engine/support-contracts')).createSupportContracts(e.app); e.app.addons.supportContracts = SC;
  SC.put({ family: 'vmware', vendor: 'VMware by Broadcom', product: 'vSphere Enterprise Plus', contract_number: 'SYN-VM-1', start: '2026-01-01', end: '2027-03-31', quantity: 10, unit: 'hosts', cost: 50000, currency: 'SAR' }, ADM);
  const B = require(path.join(ITAM, 'engine/budget')).createBudget(e.app); e.app.addons.budget = B; const fy = B.build().fy;
  e.app.store.collection('budget_previous').put({ id: 'current', fy: fy - 1, by: 'syed', at: new Date().toISOString(), rows: [1, 2, 3, 4, 5].map((i) => ({ key: String(i), title: 'Server maintenance ' + i, envelope: 'it_ops', area: 'infrastructure', kind: 'opex', approved: 100000, spent: 60000 })) });
  e.app.store.collection('budget_lines').put({ id: 'man:big', source: 'manual', fy, title: 'Data centre cooling (synthetic)', envelope: 'it_ops', area: 'infrastructure', kind: 'opex', amount: 900000, priority: 'must', status: 'proposed' });
  e.app.settings.update({ external_ai_allowed: true }, ADM);
  let WHO = OP;
  const srv = http.createServer((req, res) => {
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
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port + '/';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  const wait = (p, fn, arg) => p.waitForFunction(fn, arg, { timeout: 20000 }).then(() => true, () => false);
  try {
    const p = await browser.newPage({ viewport: { width: 1440, height: 1000 } }); p.on('pageerror', (x) => errs.push(x.message));
    p.on('dialog', (d) => { errs.push('dialog: ' + d.message()); d.dismiss(); });
    await p.goto(base + 'cost-studio.html?standalone=1');
    ok(await wait(p, () => document.querySelectorAll('#opps .opp').length === 3), 'three opportunities');
    ok(/SAR 45,000/.test(await p.textContent('#big')), 'the priced total');
    const vis = await p.textContent('[data-okey="lic|lic_visio"]');
    ok(/SAR 15,000/.test(vis) && /15 of 20 seats x recorded cost 20,000/.test(vis), 'a saving shows its basis');
    ok(/10 seat\(s\)/.test(await p.textContent('[data-okey="lic|lic_x"]')) && /money not known/.test(await p.textContent('[data-okey="lic|lic_x"]')), 'no recorded cost: the seats, not a price');
    ok(!(await p.$('main img')), 'a hostile licence name never becomes markup');
    const env = await p.textContent('#envs');
    ok(/expected spend/.test(env) && /Likely unspent/.test(env) && !!(await p.$('#envs .exp')), 'the envelope with the learned expected spend');
    ok(/60% of SAR 500,000/.test(await p.textContent('#exe')), 'last year execution');
    ok(/9\.0x the median/.test(await p.textContent('#unusual')), 'the unusual line');
    ok(/HQ/.test(await p.textContent('#show')) && /DC1/.test(await p.textContent('#show')), 'showback by site');
    await p.click('[data-dim="department"]'); ok(/Claims/.test(await p.textContent('#show')) && /SAR 20,000/.test(await p.textContent('#show')), 'showback by department');
    await p.click('[data-dim="type"]'); ok(/server/.test(await p.textContent('#show')) && /SAR 240,000/.test(await p.textContent('#show')), 'showback by type');
    await p.click('[data-kind="contract-quantity"]'); ok((await p.$$('#opps .opp')).length === 1, 'the kind filter'); await p.click('[data-kind=""]');
    // track, done with the saving realised
    await p.fill('[data-okey="lic|lic_visio"] [data-owner]', 'licensing team'); await p.click('[data-track="lic|lic_visio"]');
    ok(await wait(p, () => !document.querySelector('[data-okey="lic|lic_visio"]') && /1 open/.test(document.getElementById('ac').textContent)), 'tracked');
    ok(/SAR 15,000/.test(await p.textContent('#kpis')), 'being worked on');
    const it = '#board .it:has([data-st="done"])';
    await p.click(it + ' [data-st="done"]'); ok(await wait(p, () => /saving actually achieved/.test(document.body.textContent)), 'done asks for the saving realised');
    await p.fill(it + ' [data-real]', '12000'); await p.click(it + ' [data-st="done"]');
    ok(await wait(p, () => /realised SAR 12,000/.test(document.getElementById('board').textContent)), 'done with the saving realised');
    // dismiss with a reason
    const ck = await p.getAttribute('#opps .opp:has([data-dismiss^="con-qty"])', 'data-okey');
    await p.fill('[data-okey="' + ck + '"] [data-reason]', 'hosts arriving next quarter (synthetic)'); await p.click('[data-dismiss="' + ck + '"]');
    ok(await wait(p, (k2) => !document.querySelector('[data-okey="' + k2 + '"]'), ck), 'dismissed with a reason');
    // the AI proposes; another operator accepts
    ok(/Claude claude-opus-5-5/.test(await p.textContent('#ais')), 'AI analyst on');
    await p.fill('#q', 'Where can we save?'); await p.click('#go');
    ok(await wait(p, () => /proposed one action/.test(document.getElementById('out').textContent)), 'the analyst answers');
    ok(await wait(p, () => !!document.querySelector('#board .it.prop')), 'the proposal is on the board');
    WHO = OP2; await p.reload();
    ok(await wait(p, () => !!document.querySelector('#board .it.prop [data-st="open"]')), 'another operator can accept');
    await p.click('#board .it.prop [data-st="open"]');
    ok(await wait(p, () => /2 open|1 open · 0 proposed/.test(document.getElementById('ac').textContent) && !document.querySelector('#board .it.prop')), 'accepted');
    ok(e.app.store.auditTail(100).some((x) => x.action === 'cost.studio.action.open' && x.by === 'omar.syn'), 'audited');
    ok(await p.evaluate(() => { const a = (window.ZYB_NAV || []).find((x) => x.id === 'ast'); return !!(a && a.pages.some((x) => x.h === 'cost-studio.html')); }), 'the menu has the page');
    WHO = VIEW; await p.reload();
    ok(await wait(p, () => /for operators and administrators/.test(document.getElementById('err').textContent)), 'a viewer is refused');
  } finally { await browser.close(); srv.close(); await e.close(); }
  ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks');
  process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
