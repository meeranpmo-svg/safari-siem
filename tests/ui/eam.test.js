// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Enterprise Asset Management (eam.html) against the REAL engine (engine/eam.js) with SYNTHETIC assets and people: an administrator
// sets who works what; procurement approves a purchase another person requested; the warehouse receives it (serials become assets in
// stock) and deploys one; a technician takes a corrective work order, completes it with a part from stock; the manager verifies it
// and sees the failure risk with its reasons; a facilities maintenance plan is created; a retirement is decided by a different
// administrator; a hostile asset name stays text; workspaces switch; no browser dialog, no page error.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node eam.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const ITAM = path.join(__dirname, '..', '..', 'backend', 'itam'), DASH = path.join(__dirname, '..', '..', 'ui');
const H = require(path.join(ITAM, 'tests', 'helpers'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
(async () => {
  const e = await H.startApp({ noAi: true });
  require(path.join(ITAM, 'engine/duty')).registerDuty(e.app.srv, e.app, { noTimer: true, python: process.env.PYTHON || 'python3' });
  const XSS = '<img src=x onerror="window.__x=1">';
  const A = (o) => e.app.assets.create(Object.assign({ type: 'printer', vendor: 'SynCo', model: 'P100' }, o), { user: 'syed', role: 'admin' }).asset.id;
  const PR = [1, 2, 3, 4].map((i) => A({ name: (i === 1 ? 'PRN-SYN-1 ' + XSS : 'PRN-SYN-' + i) }));
  let WHO = { user: 'syed', role: 'admin' };
  const srv = http.createServer((req, res) => {
    const u2 = new URL(req.url, 'http://x'), json = (c, b2) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b2)); };
    if (u2.pathname === '/dashboards/whoami.json' || u2.pathname === '/auth/whoami') return json(200, WHO);
    if (u2.pathname.startsWith('/api/itam/')) {
      const h = Object.assign({}, req.headers, { 'x-sentra-proxy-secret': H.SECRET, 'x-auth-user': WHO.user, 'x-auth-role': WHO.role });
      const up = http.request({ host: '127.0.0.1', port: e.port, method: req.method, path: req.url, headers: h }, (r) => { res.writeHead(r.statusCode, r.headers); r.pipe(res); });
      req.pipe(up); return;
    }
    if (u2.pathname.startsWith('/api/')) return json(404, { error: 'not in this test' });
    const f = path.join(DASH, u2.pathname.replace(/^\/dashboards\//, '/')); if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (err, d) => { if (err) { res.writeHead(404); res.end(); return; } res.writeHead(200, { 'Content-Type': u2.pathname.endsWith('.js') ? 'application/javascript' : u2.pathname.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port + '/eam.html';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  const p = await browser.newPage({ viewport: { width: 1440, height: 950 } });
  p.on('pageerror', (x) => errs.push(x.message)); p.on('dialog', (d) => { errs.push('dialog: ' + d.message()); d.dismiss(); });
  const wait = (fn, a) => p.waitForFunction(fn, a, { timeout: 10000 }).then(() => true, () => false);
  const toastHas = (re) => p.waitForFunction((s) => new RegExp(s).test([...document.querySelectorAll('.toast')].map((t) => t.textContent).join(' ')), re.source, { timeout: 10000 }).then(() => true, () => false);
  const as = async (who, ws) => { WHO = who; await p.goto('about:blank'); await p.goto(base + (ws ? '#ws=' + ws : '')); await p.waitForSelector('#kk .t'); await p.waitForTimeout(150); };
  const form = async (vals, btn) => { await p.waitForSelector('#dlgbg.open'); for (const [k, v] of Object.entries(vals)) { const el = await p.$('#' + k); const tag = await el.evaluate((x) => x.tagName); if (tag === 'SELECT') await p.selectOption('#' + k, v); else if (v === true) await p.check('#' + k); else await p.fill('#' + k, String(v)); } await p.click('#dlgok'); };
  const tab = async (ws) => { await p.click('[data-ws="' + ws + '"]'); await p.waitForTimeout(250); };
  try {
    await as({ user: 'syed', role: 'admin' });
    ok(!(await p.$eval('#tab-set', (b) => b.hidden)), 'admin sees Settings');
    ok(await wait(() => /In use/.test(document.getElementById('flow').textContent) && /4/.test(document.getElementById('flow').textContent)), 'lifecycle strip from the register');
    await tab('settings'); await p.fill('[data-role="technicians"]', 'tech.syn, tech2.syn'); await p.fill('[data-role="warehouse"]', 'wh.syn'); await p.fill('[data-role="procurement"]', 'proc.syn');
    await p.click('#setsave'); ok(await toastHas(/Saved/), 'settings saved');
    // purchase: requested by a technician, approved by procurement
    await as({ user: 'tech.syn', role: 'operator' }, 'procurement');
    await p.click('[data-new="po"]'); await form({ 'f-t': 'Printers Q4 (synthetic)', 'f-j': 'branch opening', 'f-in': 'Printer P100', 'f-k': 'device', 'f-q': 2, 'f-u': 900 });
    ok(await toastHas(/Purchase request sent/), 'purchase request sent');
    ok(await wait(() => document.querySelectorAll('[data-po="approve"]').length === 1), 'the request is listed');
    await p.click('[data-po="approve"]'); await form({}); ok(await toastHas(/Not done: .*procurement/), 'a technician outside procurement cannot approve');
    await as({ user: 'proc.syn', role: 'operator' }, 'procurement');
    await p.click('[data-po="approve"]'); await form({ 'f-x': 'budget ok' }); ok(await wait(() => document.querySelectorAll('[data-po="order"]').length === 1), 'approved by procurement');
    await p.click('[data-po="order"]'); await form({ 'f-o': 'PO-SYN-1' }); ok(await toastHas(/Ordered/), 'ordered');
    // warehouse receives with serials, deploys one
    await as({ user: 'wh.syn', role: 'operator' }, 'warehouse');
    await p.click('[data-new="stock"]'); await form({ 'f-n': 'Fuser (synthetic)', 'f-s': 'HQ', 'f-q': 3, 'f-r': 2 }); ok(await toastHas(/Stock item added/), 'stock item added');
    await p.click('[data-receive]'); await form({ 'f-s': 'HQ', 'f-sn0': 'SN-SYN-A\nSN-SYN-B' });
    ok(await toastHas(/Received/) && await wait(() => /SN-SYN-A/.test(document.body.textContent)), 'received: serials are assets in stock');
    const newId = await p.evaluate(() => null) || Object.values(e.app.store.collection('assets').all()).find((a) => a.serial === 'SN-SYN-A').id;
    await p.click('[data-new="deploy"]'); await form({ 'f-a': newId, 'f-o': 'branch.user.syn', 'f-s': 'Branch-7' });
    ok(await toastHas(/Deployed/) && e.app.assets.get(newId).status === 'in_use', 'deployed from stock');
    // a technician works a corrective work order with a part
    const stockId = e.app.store.collection('eam_stock').all()[0].id;
    await as({ user: 'syed', role: 'admin' }, 'manager');
    await p.click('[data-new="wo"]'); await form({ 'f-a': PR[0], 'f-k': 'corrective', 'f-p': 'high', 'f-t': 'Paper jam every morning' }); ok(await toastHas(/Work order created/), 'work order created');
    await p.click('#body tr[data-wo]'); await p.waitForSelector('#drawer.open'); ok(/PRN-SYN-1 <img/.test(await p.textContent('#drb')) && !(await p.evaluate(() => window.__x)), 'hostile asset name stays text');
    await p.click('[data-wa="assign"]'); await form({ 'f-u': 'tech.syn' }); ok(await wait(() => /assigned/.test(document.getElementById('drb').textContent)), 'assigned');
    await as({ user: 'tech.syn', role: 'operator' }, 'field');
    ok(await wait(() => document.querySelectorAll('#body tr[data-wo]').length >= 1), 'field: my work orders');
    await p.click('#body tr[data-wo]'); await p.waitForSelector('#drawer.open');
    await p.click('[data-wa="start"]'); ok(await wait(() => /in progress/.test(document.getElementById('drb').textContent)), 'started');
    ok(e.app.assets.get(PR[0]).status === 'in_repair', 'the asset is in repair');
    await p.click('[data-wa="complete"]'); await form({ 'f-n': 'Replaced the fuser', 'f-c': 120, 'f-ps': stockId, 'f-pq': 1 });
    ok(await wait(() => /Replaced the fuser/.test(document.getElementById('drb').textContent) && /Fuser/.test(document.getElementById('drb').textContent)), 'completed with the part used');
    ok(e.app.assets.get(PR[0]).status === 'in_use' && e.app.store.collection('eam_stock').get(stockId).qty === 2, 'back in use, stock down by one');
    ok(!(await p.$('[data-wa="verify"]')), 'the technician cannot verify their own work');
    await as({ user: 'syed', role: 'admin' }, 'manager');
    ok(await wait(() => /PRN-SYN-1/.test(document.getElementById('body').textContent) && /corrective work order/.test(document.getElementById('body').textContent)), 'failure risk with its reason');
    const wo = e.app.store.collection('eam_wo').all()[0].id;
    await p.evaluate((id) => { const a = document.createElement('a'); a.setAttribute('data-open', id); a.href = '#'; document.getElementById('body').appendChild(a); a.click(); }, wo);
    await p.waitForSelector('[data-wa="verify"]'); await p.click('[data-wa="verify"]'); await form({});
    ok(await wait(() => /verified/.test(document.getElementById('drb').textContent)), 'verified by the manager');
    await p.click('#drx');
    // facilities plan and a retirement decided by a different administrator
    await tab('facilities'); await p.click('[data-new="pm"]'); await form({ 'f-a': PR[1], 'f-t': 'Quarterly service', 'f-e': 90, 'f-n': '2026-12-01' });
    ok(await toastHas(/Plan created/) && await wait(() => /Quarterly service/.test(document.getElementById('body').textContent)), 'facilities maintenance plan');
    await tab('manager'); await p.click('[data-new="retire"]'); await form({ 'f-a': PR[3], 'f-r': 'end of life (synthetic)' });
    ok(await toastHas(/an administrator decides/), 'retirement requested');
    ok(!(await p.$('[data-rt="approve"]')) || (await p.click('[data-rt="approve"]'), await form({}), await toastHas(/four-eyes/)), 'the requester cannot approve it');
    await as({ user: 'admin2.syn', role: 'admin' }, 'manager');
    await p.click('[data-rt="approve"]'); await form({}); ok(await toastHas(/approved/) && e.app.assets.get(PR[3]).status === 'retired', 'a different administrator approved; the register says retired');
    await as({ user: 'view.syn', role: 'viewer' }, 'warehouse');
    ok(!(await p.$('[data-new]')) && !(await p.$('[data-adjust]')), 'viewer: read only');
    await tab('ai'); ok(await wait(() => /AI advisor/.test(document.getElementById('body').textContent)), 'AI tab shows');
    ok(!errs.length, 'no page errors or browser dialogs: ' + errs.join(' | '));
  } finally { await browser.close(); srv.close(); await e.close(); }
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks'); process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
