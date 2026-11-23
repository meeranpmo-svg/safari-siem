// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for leaver business-application access on HR Offboarding (hr-offboarding.html) against the REAL ITAM engine,
// SYNTHETIC data only: an administrator adds an application to the register (helper text on every field; an Entra application
// without its id is refused with the reason); after the disable the application's owner has a task with a due date and a tile
// counts it; someone who is not the owner cannot confirm; the owner confirms with a reference (a hostile one stays text) and the
// step is done.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node hr-offboarding-apps.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const ITAM = path.join(__dirname, '..', '..', 'backend', 'itam'), DASH = path.join(__dirname, '..', '..', 'ui');
const H = require(path.join(ITAM, 'tests', 'helpers'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const XSS = '<img src=x onerror=alert(1)>';

(async () => {
  const e = await H.startApp({ noAi: true });
  require(path.join(ITAM, 'engine/duty')).registerDuty(e.app.srv, e.app, { noTimer: true, python: process.env.PYTHON || 'python3' });
  const api = async (m, p, body, who) => { const r = await e.req(m, p, Object.assign({ body }, who)); if (r.status !== 200) throw new Error(p + ': ' + JSON.stringify(r.json)); return r.json; };
  const ADM = { user: 'syed', role: 'admin' }, HRA = { user: 'hana.syn', role: 'admin' }, DESK = { user: 'desk.syn', role: 'operator' }, OWNER = { user: 'olaf.syn', role: 'operator' };
  await api('POST', '/onboarding/ad', { upn_suffix: 'corp.syn' }, ADM);
  let WHO = ADM;
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
    fs.readFile(f, (err, d) => { if (err) { res.writeHead(404); res.end(); return; } res.writeHead(200, { 'Content-Type': u.pathname.endsWith('.js') ? 'application/javascript' : u.pathname.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port + '/';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  const zd = (p, re) => p.waitForFunction((src) => new RegExp(src).test((document.getElementById('zd') || {}).textContent || ''), re.source, { timeout: 10000 }).then(() => true, () => false);
  const msg = (p, sel, re) => p.waitForFunction((a) => new RegExp(a[1]).test((document.querySelector(a[0] + ' [data-msg]') || {}).textContent || ''), [sel, re.source], { timeout: 8000 }).then(() => true, () => false);
  const openRow = async (p) => { await p.click('#list tr[data-id="OFF-001"]'); await p.waitForSelector('#zd .steps', { timeout: 8000 }); };
  const as = async (p, who) => { WHO = who; await p.reload(); await p.waitForSelector('#list table', { timeout: 15000 }); await openRow(p); };
  try {
    const p = await browser.newPage({ viewport: { width: 1400, height: 1100 } }); p.on('pageerror', (x) => errs.push(x.message)); p.on('dialog', (d) => { errs.push('dialog ' + d.message()); d.dismiss(); });
    await p.goto(base + 'hr-offboarding.html?standalone=1'); await p.waitForSelector('#kpis', { timeout: 15000 });
    await p.click('#appset'); await p.waitForSelector('#appform [name=name]', { timeout: 8000 });
    ok(await p.$$eval('#appform input[name]:not([type=checkbox]), #appform select[name], #appform textarea[name]', (x) => x.every((el) => el.getAttribute('data-hinted'))), 'helper text on every field');
    await p.fill('#appform [name=name]', 'Claims Portal'); await p.fill('#appform [name=owner]', 'olaf.syn'); await p.selectOption('#appform [name=method]', 'entra');
    await Promise.all([p.waitForResponse((r) => /offboarding\/apps$/.test(r.url()) && r.request().method() === 'POST'), p.click('#appform [type=submit]')]);
    ok(await msg(p, '#appform', /sp_id is required/), 'an Entra application without its id is refused');
    await p.fill('#appform [name=name]', 'Oracle Finance'); await p.selectOption('#appform [name=method]', 'manual'); await p.selectOption('#appform [name=applies]', 'all'); await p.fill('#appform [name=sla_days]', '3');
    await Promise.all([p.waitForResponse((r) => /offboarding\/apps$/.test(r.url()) && r.request().method() === 'POST'), p.click('#appform [type=submit]')]);
    ok(await zd(p, /APP-001 · Oracle Finance/) && await zd(p, /owner removes it/), 'added to the register');
    await api('POST', '/offboarding', { name: 'Khalid Al-Harbi', employee_id: 'E-20001', username: 'khalid.harbi', department: 'Claims', last_day: new Date().toISOString().slice(0, 10), manager: 'faisal.syn', reason: 'resignation' }, HRA);
    await api('POST', '/offboarding/OFF-001/confirm', { decision: 'confirm' }, { user: 'faisal.syn', role: 'operator' });
    await api('POST', '/offboarding/OFF-001/approve', { decision: 'approve' }, ADM);
    await api('POST', '/offboarding/OFF-001/disabled', { directory_ref: 'disabled in ADUC, CHG-9001' }, DESK);
    await p.reload(); await p.waitForSelector('#list table', { timeout: 15000 });
    ok(/Application removals waiting for owners/.test(await p.textContent('#kpis')), 'a tile counts the owner tasks');
    await as(p, DESK);
    ok(await zd(p, /waiting for the owner/) && await zd(p, /due /), 'the owner task with its due date');
    await p.selectOption('#oappc [name=app]', 'APP-001'); await p.selectOption('#oappc [name=outcome]', 'removed'); await p.fill('#oappc [name=reference]', 'end-dated');
    await Promise.all([p.waitForResponse((r) => /apps\/confirm$/.test(r.url())), p.click('#oappc [type=submit]')]);
    ok(await msg(p, '#oappc', /owner of Oracle Finance/), 'someone who is not the owner cannot confirm');
    await as(p, OWNER);
    await p.selectOption('#oappc [name=app]', 'APP-001'); await p.selectOption('#oappc [name=outcome]', 'removed'); await p.fill('#oappc [name=reference]', 'End-dated in Oracle ' + XSS);
    await Promise.all([p.waitForResponse((r) => /apps\/confirm$/.test(r.url())), p.click('#oappc [type=submit]')]);
    ok(await zd(p, /removed by the owner/) && await zd(p, /all done/), 'confirmed by the owner, the step done');
    ok(!(await p.$('#zd img')) && await zd(p, /End-dated in Oracle <img/), 'a hostile reference stays text');
  } finally { await browser.close(); srv.close(); e.close(); }
  ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks');
  process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
