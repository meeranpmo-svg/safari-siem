// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for SOC 2 & ISO 42001 readiness (dashboards/server/frameworks-x.html) against the REAL IT Asset Management engine
// (engine/frameworks-x.js) with SYNTHETIC NCA ECC levels: derived statuses, the not-required note, filters, the SOC 2 scope,
// confirm with evidence (refused without), four-eyes approval by a second admin, the ISO 42001 tab, export, menu search, a
// viewer sees no forms, phone width.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node frameworks-x.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const ITAM = path.join(__dirname, '..', '..', 'backend', 'itam'), DASH = path.join(__dirname, '..', '..', 'ui');
const H = require(path.join(ITAM, 'tests', 'helpers'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
(async () => {
  const e = await H.startApp({ noAi: true });
  require(path.join(ITAM, 'engine/duty')).registerDuty(e.app.srv, e.app, { noTimer: true, python: process.env.PYTHON || 'python3' });
  const L = { 'ZS-2-2-01': 'fully', 'ZS-2-1-01': 'fully', 'ZS-2-3-03': 'not', 'ZS-2-2-02': 'partially', 'ZS-1-3-01': 'fully' };
  e.app.addons.ncaEcc = { view: async () => ({ controls: Object.entries(L).map(([id, level]) => ({ id, title: id, level })) }) };
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
  const tab = (p, t) => p.click('[data-tab="' + t + '"]');
  try {
    const p = await browser.newPage({ viewport: { width: 1400, height: 1000 } }); p.on('pageerror', (x) => errs.push(x.message));
    await p.goto(base + 'frameworks-x.html?standalone=1');
    ok(await wait(p, () => /fully met/.test(document.getElementById('kpis').textContent)), 'KPIs');
    ok(/Is it required for a Saudi insurer\? No/.test(await p.textContent('#what')), 'states that SOC 2 is not required for insurers');
    ok(/CPA firm/.test(await p.textContent('#what')), 'readiness, not an attestation');
    const row = (id) => p.textContent('tr[data-id="' + id + '"]');
    ok(/fully/.test(await row('CC6.1')), 'CC6.1 fully from NCA ECC'); ok(/not met/.test(await row('CC6.8')), 'CC6.8 not met (EDR gap)');
    ok(/not assessed/.test(await row('CC3.2')), 'unmapped evidence is not assessed, never compliant');
    ok(/not applicable/.test(await row('A1.2')), 'Availability out of scope');
    ok(await p.isHidden('#savescope'), 'an operator cannot change the scope');
    await p.selectOption('#lv', 'not'); ok((await p.$$eval('tr.row', (r) => r.map((x) => x.dataset.id))).join() === 'CC6.8', 'filter: not met');
    await p.selectOption('#lv', ''); await p.fill('#q', 'ZS-2-3-03'); ok((await p.$$('tr.row')).length === 1, 'search by NCA ECC control'); await p.fill('#q', '');
    // confirm with evidence
    await p.click('tr[data-id="CC3.2"]'); ok(await wait(p, () => !document.getElementById('drawer').hidden), 'drawer opens');
    await p.selectOption('#clv', 'fully'); await p.click('#csave');
    ok(await wait(p, () => /evidence is required/.test((document.querySelector('.toast') || {}).textContent || '')), 'refused without evidence, field named');
    await p.fill('#cev', 'Risk assessment RA-2026 (synthetic)'); await p.click('#csave');
    ok(await wait(p, () => /pending fully/.test(document.querySelector('tr[data-id="CC3.2"]').textContent)), 'submitted, pending');
    ok(/submitted by/.test(await p.textContent('#drawer')) && !(await p.$('[data-dec]')), 'an operator sees no approve button');
    // a second admin approves
    who = { user: 'adam.syn', role: 'admin' };
    const a = await browser.newPage({ viewport: { width: 1400, height: 1000 } }); a.on('pageerror', (x) => errs.push(x.message));
    await a.goto(base + 'frameworks-x.html?standalone=1'); await wait(a, () => document.querySelector('tr[data-id="CC3.2"]'));
    ok(!(await a.isHidden('#savescope')), 'an admin can change the scope');
    await a.check('[data-cat="availability"]'); await a.click('#savescope');
    ok(await wait(a, () => !/not applicable/.test(document.querySelector('tr[data-id="A1.2"]').textContent)), 'Availability now in scope');
    await a.click('tr[data-id="CC3.2"]'); await a.click('[data-dec="reject"]');
    ok(await wait(a, () => /note is required to reject/.test((document.querySelector('.toast') || {}).textContent || '')), 'reject needs a reason');
    await a.click('[data-dec="approve"]');
    ok(await wait(a, () => /confirmed/.test(document.querySelector('tr[data-id="CC3.2"]').textContent) && /fully/.test(document.querySelector('tr[data-id="CC3.2"]').textContent)), 'approved: confirmed and fully');
    ok(/approved by adam\.syn/.test(await a.textContent('#drawer')), 'the drawer names the approver');
    // ISO 42001 tab
    await a.click('[data-fw="iso42001"]');
    ok(await wait(a, () => document.querySelector('tr[data-id="A.6.2.8"]')), 'ISO 42001 items');
    ok(/not assessed/.test(await a.textContent('tr[data-id="4.3"]')), 'AIMS scope needs evidence');
    ok(/voluntary/.test(await a.textContent('#what')) && await a.isHidden('#scopecard'), 'ISO note; no SOC 2 scope card');
    const [dl] = await Promise.all([a.waitForEvent('download'), a.click('#export')]); ok(/ISO-42001-readiness/.test(dl.suggestedFilename()), 'CSV export');
    await a.fill('#zs-q', 'iso 42001'); await a.waitForTimeout(150);
    ok((await a.$$eval('#zs-best a b', (x) => x.map((y) => y.textContent))).includes('SOC 2 & ISO 42001'), 'menu search finds the page');
    who = { user: 'vera.syn', role: 'viewer' };
    const v = await browser.newPage({ viewport: { width: 400, height: 900 } }); v.on('pageerror', (x) => errs.push(x.message));
    await v.goto(base + 'frameworks-x.html?standalone=1'); await wait(v, () => document.querySelector('tr[data-id="CC6.1"]'));
    await v.click('tr[data-id="CC6.1"]'); ok(!(await v.$('#csave')) && await v.isHidden('#export'), 'a viewer sees no forms and no export');
    ok(await v.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1), 'phone width: no sideways scroll');
  } finally { await browser.close(); srv.close(); await e.close(); }
  ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks'); process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
