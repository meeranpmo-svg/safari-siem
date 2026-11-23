// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for Lifecycle Studio (dashboards/server/lifecycle-studio.html) against the REAL ITAM engine (engine/lifecycle-studio.js,
// End of Life, pyengine/lifecycle_studio_rules.py; the model is stubbed) over SYNTHETIC assets: the ring and KPIs, a KPI and a
// forecast quarter filter the list, the learned lifespan chip, the asset drawer with its timeline and every risk point, the link
// to isolation for an end-of-life server, adding to the plan, the AI planner's proposal accepted by another person and an item
// dropped with a reason, a hostile asset name stays text, a viewer sees no cost and cannot plan, the menu has the page.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node lifecycle-studio.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const ITAM = path.join(__dirname, '..', '..', 'backend', 'itam'), DASH = path.join(__dirname, '..', '..', 'ui');
const H = require(path.join(ITAM, 'tests', 'helpers'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const ADM = { user: 'syed', role: 'admin' }, OP = { user: 'nora.syn', role: 'operator' }, OP2 = { user: 'omar.syn', role: 'operator' }, VIEW = { user: 'vera.syn', role: 'viewer' };
const XSS = '<img src=x onerror=alert(1)>';

(async () => {
  const e = await H.startApp({ noAi: true });
  let turn = 0; const id = {};
  const create = async () => {
    turn++;
    if (turn % 2 === 1) return { model: 'claude-opus-5-5', stop_reason: 'tool_use', content: [{ type: 'tool_use', id: 'u' + turn, name: 'propose_plan', input: { id: id.w22, action: 'renew support', quarter: '2027-Q1', reason: 'no support contract on record (synthetic)' } }], usage: { input_tokens: 40, output_tokens: 10 } };
    return { model: 'claude-opus-5-5', stop_reason: 'end_turn', content: [{ type: 'text', text: 'One server needs support renewed. I proposed it for your decision.' }], usage: { input_tokens: 60, output_tokens: 20 } };
  };
  const sdk = class { constructor() { this.messages = { create }; } };
  require(path.join(ITAM, 'engine/duty')).registerDuty(e.app.srv, e.app, { noTimer: true, python: process.env.PYTHON || 'python3', lifecycleSdk: sdk, lifecycleKey: () => 'sk-ant-synthetic' });
  const C = e.app.store.collection('assets'), NOW = Date.now(), ymd = (y) => new Date(NOW - y * 365.25 * 86400000).toISOString().slice(0, 10);
  const mk = (k, x, patch) => { id[k] = e.app.assets.create(Object.assign({ status: 'in_use', type: 'server', site: 'HQ' }, x), ADM).asset.id; if (patch) C.patch(id[k], patch); };
  [2.9, 3.0, 3.1, 3.0].forEach((y, i) => { mk('r' + i, { name: 'LT-SYN-OLD' + i, type: 'laptop' }, (a) => { a.purchase = { date: ymd(y + 1), cost: 4000 + i * 100 }; });
    e.app.assets.transition(id['r' + i], 'retire', ADM, 'synthetic'); C.patch(id['r' + i], (a) => { a.lifecycle[a.lifecycle.length - 1].at = new Date(NOW - 365.25 * 86400000).toISOString(); }); });
  mk('lt', { name: 'LT-SYN-1', type: 'laptop' }, (a) => { a.purchase = { date: ymd(3.5) }; });
  mk('w12', { name: 'SRV-SYN-2012', os: 'Windows Server 2012 R2', mgmt_ip: '10.96.0.5' }, (a) => { a.purchase = { date: ymd(9) }; a.warranty = { end: ymd(4) }; });
  mk('w22', { name: 'SRV-SYN-2022', os: 'Windows Server 2022', mgmt_ip: '10.96.0.6' }, (a) => { a.purchase = { date: ymd(1) }; a.warranty = { end: ymd(-2) }; });
  mk('x', { name: XSS, type: 'network' });
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
  const rows = (p) => p.$$eval('#rows tr[data-asset]', (x) => x.length);
  try {
    const p = await browser.newPage({ viewport: { width: 1440, height: 1000 } }); p.on('pageerror', (x) => errs.push(x.message));
    p.on('dialog', (d) => { errs.push('dialog: ' + d.message()); d.dismiss(); });
    await p.goto(base + 'lifecycle-studio.html?standalone=1');
    ok(await wait(p, () => document.querySelectorAll('#rows tr[data-asset]').length === 4), 'four active assets');
    ok((await p.getAttribute('#rows tr[data-asset]:first-child', 'data-asset')) === id.w12, 'highest risk first');
    const k = (await p.textContent('#kpis')).replace(/\s+/g, '');
    ok(/1isolatenow/.test(k) && /1pastendoflife/.test(k), 'KPIs: ' + k);
    ok(/laptop 3 y · learned/.test(await p.textContent('#life')), 'the learned lifespan');
    ok((await p.$$('#fc .bar')).length === 9 && /overdue/.test(await p.textContent('#fc')), 'the forecast: overdue + 8 quarters');
    ok(/SAR 4,150/.test(await p.textContent('#fc')), 'the known cost in the forecast');
    ok(!(await p.$('main img')), 'a hostile asset name never becomes markup');
    await p.click('[data-k="isolate"]'); ok((await rows(p)) === 1, 'a KPI filters'); await p.click('[data-k="isolate"]');
    await p.click('#fc .bar[data-quarter="overdue"]'); ok((await rows(p)) >= 2, 'a forecast quarter filters'); await p.click('#clear'); ok((await rows(p)) === 4, 'clear');
    // drawer
    await p.click('#rows tr[data-asset="' + id.w12 + '"]');
    ok(await wait(p, () => document.getElementById('drawer').classList.contains('open')), 'the drawer opens');
    const d = await p.textContent('#drawer');
    ok(/past vendor end of life/.test(d) && /out of warranty/.test(d) && /\+40/.test(d), 'every risk point');
    ok(!!(await p.$('#drawer svg.tl circle')) && /today/.test(d), 'the timeline');
    ok(!!(await p.$('#drawer a[href="lifecycle.html"]')) && /CISO approves/.test(d), 'isolation goes to End of Life & Isolation');
    ok(/not known - fewer than 3 recorded purchases/.test(d), 'no guessed cost');
    await p.selectOption('#pact', 'replace'); await p.selectOption('#pq', { index: 1 }); await p.fill('#pnote', 'with Server 2025 (synthetic)'); await p.click('#padd');
    ok(await wait(p, () => /1 planned/.test(document.getElementById('pc').textContent)), 'added to the plan');
    await p.keyboard.press('Escape');
    // the AI proposes; another person accepts; an item is dropped with a reason
    ok(/Claude claude-opus-5-5/.test(await p.textContent('#ais')), 'AI planner on');
    await p.fill('#q', 'What needs support?'); await p.click('#go');
    ok(await wait(p, () => /proposed it for your decision/.test(document.getElementById('out').textContent)), 'the planner answers');
    ok(await wait(p, () => !!document.querySelector('#board .it.prop')), 'the proposal is on the board');
    WHO = OP2; await p.reload();
    ok(await wait(p, () => !!document.querySelector('#board .it.prop [data-st="planned"]')), 'another operator sees Accept');
    await p.click('#board .it.prop [data-st="planned"]');
    ok(await wait(p, () => /2 planned · 0 proposed/.test(document.getElementById('pc').textContent)), 'accepted');
    const it = await p.$('#board .it:not(.prop) [data-st="dropped"]');
    await it.click(); ok(await wait(p, () => /Say why/.test(document.body.textContent)), 'dropping asks for a reason');
    const box = await p.$('#board .it:not(.prop):has([data-st="dropped"])'); await (await box.$('[data-note]')).fill('budget moved to 2028 (synthetic)'); await (await box.$('[data-st="dropped"]')).click();
    ok(await wait(p, () => /1 planned/.test(document.getElementById('pc').textContent)), 'dropped');
    ok(e.app.store.auditTail(100).some((x) => x.action === 'lifecycle.studio.plan.planned' && x.by === 'omar.syn'), 'audited');
    ok(await p.evaluate(() => { const a = (window.ZYB_NAV || []).find((x) => x.id === 'ast'); return !!(a && a.pages.some((x) => x.h === 'lifecycle-studio.html')); }), 'the menu has the page');
    WHO = VIEW; await p.reload();
    ok(await wait(p, () => document.querySelectorAll('#rows tr[data-asset]').length === 4), 'a viewer reads');
    const vt = await p.innerText('main'); ok(!/SAR /.test(vt) && (await p.isHidden('#thcost')), 'a viewer sees no cost');
    await p.click('#rows tr[data-asset="' + id.lt + '"]');
    ok(await wait(p, () => document.getElementById('drawer').classList.contains('open')) && !(await p.$('#padd')) && !(await p.$('[data-st]')) && await p.isDisabled('#go'), 'and cannot plan or ask');
  } finally { await browser.close(); srv.close(); await e.close(); }
  ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks');
  process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
