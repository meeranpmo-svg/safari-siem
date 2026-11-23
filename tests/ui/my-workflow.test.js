// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Role Workflows (my-workflow.html) against the REAL engine (engine/role-workflows.js) with SYNTHETIC assets and GRC records: seven
// roles; the Windows administrator's daily steps show the server not seen (a hostile name stays text) and the steps the platform cannot
// measure as "confirm"; a step needing attention cannot be signed off without a note, then is; weekly and monthly steps (end of life);
// the handover is written and acknowledged by another person (not the author); the GRC consultant sees the overdue action; an
// administrator names the members; a viewer cannot sign; no undefined / NaN, no page error, no browser dialog.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node my-workflow.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const ITAM = path.join(__dirname, '..', '..', 'backend', 'itam'), DASH = path.join(__dirname, '..', '..', 'ui');
const H = require(path.join(ITAM, 'tests', 'helpers'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
(async () => {
  const e = await H.startApp({ noAi: true });
  require(path.join(ITAM, 'engine/duty')).registerDuty(e.app.srv, e.app, { noTimer: true, python: process.env.PYTHON || 'python3' });
  const XSS = '<img src=x onerror="window.__x=1">';
  const AS = e.app.store.collection('assets'), ago = (d) => new Date(Date.now() - d * 86400000).toISOString();
  AS.put({ id: 'w1', name: 'WIN-SYN-1', type: 'server', os: 'Windows Server 2019', status: 'in_use', last_seen: ago(0.1) });
  AS.put({ id: 'w2', name: 'WIN-SYN-2 ' + XSS, type: 'server', os: 'Windows Server 2012 R2', status: 'in_use', last_seen: ago(5), eol: '2023-10-10' });
  e.app.store.collection('grc_actions').put({ id: 'ACT-0001', title: 'Close audit gap (synthetic)', status: 'open', due: '2026-01-01', owner: 'grc.syn' });
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
  const base = 'http://127.0.0.1:' + srv.address().port + '/my-workflow.html';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  const p = await browser.newPage({ viewport: { width: 1440, height: 950 } });
  p.on('pageerror', (x) => errs.push(x.message)); p.on('dialog', (d) => { errs.push('dialog: ' + d.message()); d.dismiss(); });
  const wait = (fn, a) => p.waitForFunction(fn, a, { timeout: 10000 }).then(() => true, () => false);
  const toastHas = (re) => p.waitForFunction((s) => new RegExp(s).test([...document.querySelectorAll('.toast')].map((t) => t.textContent).join(' ')), re.source, { timeout: 10000 }).then(() => true, () => false);
  const as = async (who, hash) => { WHO = who; await p.goto('about:blank'); await p.goto(base + (hash || '')); await p.waitForSelector('[data-stepcard]'); await p.waitForTimeout(200); };
  const body = () => p.evaluate(() => document.querySelector('main').innerText);
  const ADM = { user: 'syed', role: 'admin' }, WIN = { user: 'win.syn', role: 'operator' }, WIN2 = { user: 'win2.syn', role: 'operator' }, VIEW = { user: 'vera.syn', role: 'viewer' };
  try {
    await as(ADM, '#role=windows');
    ok(await p.$$eval('[data-role]', (b) => b.length) === 10, 'ten roles');
    let t = await body(); ok(/Windows servers not seen for over 1 days/.test(t) && /WIN-SYN-2 <img/.test(t) && !(await p.evaluate(() => window.__x)), 'live status: the server not seen, name as text');
    ok(/confirm on the page/.test(t), 'unmeasured steps say confirm');
    await p.fill('[data-mem="windows"]', 'win.syn, win2.syn'); await p.click('#set-save'); ok(await toastHas(/Saved/), 'members saved by the administrator');
    await as(WIN, '#role=windows'); ok(!(await p.$('#set-save')), 'operators see no settings');
    await p.click('[data-so="done"][data-step="seen"]'); ok(await toastHas(/Not done: note/), 'a step needing attention needs a note');
    await p.fill('#n-seen', 'WIN-SYN-2 rebooted, reporting again (synthetic)'); await p.click('[data-so="done"][data-step="seen"]'); ok(await toastHas(/Signed off: done/), 'signed off with a note');
    await p.click('[data-so="done"][data-step="events"]'); ok(await toastHas(/Signed off: done/), 'a confirm step signed off');
    ok(await p.waitForFunction(() => /2 \/ \d+/.test(document.getElementById('sum').innerText), null, { timeout: 8000 }).then(() => true, () => false), 'progress counts the sign-offs');
    await p.click('[data-cad="monthly"]'); ok(await p.waitForFunction(() => /past end of life/.test(document.getElementById('steps').innerText), null, { timeout: 8000 }).then(() => true, () => false), 'monthly: end of life');
    await p.click('[data-cad="daily"]'); await p.waitForTimeout(400);
    await p.fill('#h-notes', 'WIN-SYN-2 needs a replacement plan (synthetic)'); await p.click('#h-save'); ok(await toastHas(/Handover written/), 'handover written');
    await p.waitForSelector('[data-ack]'); await p.click('[data-ack]'); await p.waitForSelector('#dlgbg.open'); await p.click('#dlgok'); ok(await toastHas(/does not acknowledge/), 'the author cannot acknowledge');
    await as(WIN2, '#role=windows'); await p.click('[data-ack]'); await p.waitForSelector('#dlgbg.open'); await p.click('#dlgok'); ok(await toastHas(/acknowledged/), 'acknowledged by another person');
    await p.click('[data-role="grc"]'); ok(await p.waitForFunction(() => /ACT-0001/.test(document.getElementById('steps').innerText), null, { timeout: 8000 }).then(() => true, () => false), 'GRC consultant: the overdue action');
    let clean = true; for (const r of ['grc', 'exchange', 'windows', 'virt', 'network', 'security', 'desktop', 'soc', 'siem', 'pentest']) for (const c of ['daily', 'weekly', 'monthly']) {
      await p.click('[data-role="' + r + '"]'); await p.click('[data-cad="' + c + '"]'); await p.waitForTimeout(250); if (/undefined|NaN|\[object Object\]/.test(await body())) { clean = false; console.log(r, c, 'shows undefined'); } }
    ok(clean, 'every role and cadence renders cleanly');
    await as(VIEW, '#role=windows'); await p.click('[data-so="done"][data-step="events"]'); ok(await toastHas(/Not done/), 'a viewer cannot sign');
    ok(!errs.length, 'no page errors or browser dialogs: ' + errs.join(' | '));
  } finally { await browser.close(); srv.close(); await e.close(); }
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks'); process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
