// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for HR Onboarding (dashboards/server/hr-onboarding.html) against the REAL ITAM engine (engine/onboarding.js)
// with SYNTHETIC joiners and laptops: HR raises a joiner (helper text on every field), the requester cannot approve, the
// manager approves, the desk reserves an in-stock laptop, proposes the account (user name suggested; an admin group is
// refused), an administrator approves, the account is recorded as created, a password typed in a note is refused, the
// credentials and the handover complete it and the laptop is in use; a hostile value stays text; a viewer is refused; the
// menu has the page under User Desktops.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node hr-onboarding.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const ITAM = path.join(__dirname, '..', '..', 'backend', 'itam'), DASH = path.join(__dirname, '..', '..', 'ui');
const H = require(path.join(ITAM, 'tests', 'helpers'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const XSS = '<img src=x onerror=alert(1)>';

(async () => {
  const e = await H.startApp({ noAi: true });
  require(path.join(ITAM, 'engine/duty')).registerDuty(e.app.srv, e.app, { noTimer: true, python: process.env.PYTHON || 'python3' });
  const A = e.app.store.collection('assets');
  A.put({ id: 'ast_lap1', type: 'laptop', status: 'in_stock', vendor: 'Dell', model: 'Latitude 5450', serial: 'SYN-LAP-001', asset_tag: 'ZS-L-001', lifecycle: [] });
  let WHO = { user: 'hana.syn', role: 'operator' };
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
  const as = async (p, who) => { WHO = who; await p.reload(); await p.waitForSelector('#list table, #list .card-body', { state: 'attached', timeout: 15000 }); };
  const openRow = async (p) => { await p.click('#list tr[data-id="ONB-001"]'); await p.waitForSelector('#zd .steps', { timeout: 8000 }); };
  const submit = async (p, sel) => { await Promise.all([p.waitForResponse((r) => /\/api\/itam\/onboarding/.test(r.url()) && r.request().method() === 'POST'), p.click(sel + ' [type=submit]')]); };
  try {
    const p = await browser.newPage({ viewport: { width: 1400, height: 1000 } }); p.on('pageerror', (x) => errs.push(x.message));
    await p.goto(base + 'hr-onboarding.html?standalone=1'); await p.waitForSelector('#list .card-body, #list table', { state: 'attached', timeout: 15000 });
    ok(/No joiner yet/.test(await p.textContent('#list')), 'empty state says how to start');
    // HR raises the joiner
    await p.click('#new'); await p.waitForSelector('#oform .zyb-hint', { timeout: 8000 });
    ok(await p.$$eval('#oform input[name], #oform select[name], #oform textarea[name]', (x) => x.every((el) => el.getAttribute('data-hinted'))), 'every field has helper text');
    ok(/^e\.g\. Sara/.test(await p.getAttribute('#oform [name=name]', 'placeholder')), 'an example inside the name box');
    await p.fill('#oform [name=name]', 'Sara Al-Ghamdi'); await p.fill('#oform [name=employee_id]', 'E-10442'); await p.fill('#oform [name=job_title]', 'Claims Analyst ' + XSS);
    await p.fill('#oform [name=department]', 'Claims'); await p.fill('#oform [name=start_date]', '2099-01-15'); await p.fill('#oform [name=manager]', 'faisal.syn');
    await p.selectOption('#oform [name=laptop_profile]', 'standard');
    await submit(p, '#oform'); ok(await zd(p, /ONB-001/), 'request raised');
    ok(!(await p.$('#zd img')) && (await p.textContent('#zd')).includes(XSS), 'a hostile value stays text');
    await p.selectOption('#dform [name=decision]', 'approve'); await submit(p, '#dform');
    ok(await msg(p, '#dform', /requested ONB-001 and cannot also approve/), 'the requester cannot approve');
    // the manager approves
    await as(p, { user: 'faisal.syn', role: 'operator' }); await openRow(p);
    await p.selectOption('#dform [name=decision]', 'approve'); await submit(p, '#dform');
    ok(await zd(p, /Reserve a laptop/), 'approved; next: laptop');
    // the desk reserves the laptop and proposes the account
    await as(p, { user: 'desk.syn', role: 'operator' }); await openRow(p);
    await p.waitForFunction(() => (document.querySelector('#lform [name=asset_id]') || {}).options && document.querySelector('#lform [name=asset_id]').options.length > 1, null, { timeout: 8000 });
    ok(/ZS-L-001 · Dell · Latitude 5450 · serial SYN-LAP-001/.test(await p.textContent('#lform [name=asset_id]')), 'in-stock laptop offered');
    await p.selectOption('#lform [name=asset_id]', 'ast_lap1'); await submit(p, '#lform');
    ok(await zd(p, /Propose the account/) && /joiner ONB-001/.test(A.get('ast_lap1').custodian), 'laptop reserved in the asset register');
    await p.waitForFunction(() => (document.querySelector('#aform [name=username]') || {}).value === 'sara.ghamdi', null, { timeout: 8000 }).then(() => ok(true), () => ok(false, 'user name suggested'));
    await p.fill('#aform [name=groups]', 'GG-Claims-Users, Domain Admins'); await submit(p, '#aform');
    ok(await msg(p, '#aform', /Domain Admins is privileged/), 'an admin group is refused');
    await p.fill('#aform [name=groups]', 'GG-Claims-Users'); await p.fill('#aform [name=licences]', 'M365 E3'); await submit(p, '#aform');
    ok(await zd(p, /Approve the account/), 'proposed; waiting for an administrator');
    // an administrator approves; the desk records the account
    await as(p, { user: 'syed', role: 'admin' }); await openRow(p);
    await p.selectOption('#adform [name=decision]', 'approve'); await submit(p, '#adform');
    ok(await zd(p, /Record the account as created/), 'account approved');
    await as(p, { user: 'desk.syn', role: 'operator' }); await openRow(p);
    await p.fill('#acform [name=directory_ref]', 'CN=sara.ghamdi,OU=Claims,DC=corp'); await submit(p, '#acform');
    ok(await zd(p, /Credential delivery/), 'account recorded');
    await p.selectOption('#crform [name=method]', 'via_manager'); await p.selectOption('#crform [name=mfa]', 'at_first_sign_in'); await p.fill('#crform [name=note]', 'password is Winter2026!'); await submit(p, '#crform');
    ok(await msg(p, '#crform', /never holds one/), 'a password typed in the note is refused');
    await p.fill('#crform [name=note]', 'handed to the manager in a sealed envelope'); await submit(p, '#crform');
    ok(await zd(p, /Laptop handover/), 'credentials recorded');
    await p.check('#hform [name=acknowledged]'); await p.fill('#hform [name=evidence]', 'HF-2026-118'); await submit(p, '#hform');
    ok(await zd(p, /completed/), 'onboarding complete');
    ok(A.get('ast_lap1').status === 'in_use' && A.get('ast_lap1').custodian === 'sara.ghamdi', 'the laptop is in use with the joiner as custodian');
    ok(!JSON.stringify(e.app.store.auditTail(300)).includes('Winter2026'), 'the refused password is nowhere in the audit trail');
    ok(await p.evaluate(() => (window.ZYB_NAV || []).some((a) => a.id === 'eud' && a.pages.some((x) => x.h === 'hr-onboarding.html'))), 'in the User Desktops menu');
    // a viewer is refused
    await as(p, { user: 'v.syn', role: 'viewer' });
    ok(/operator|not allowed|forbidden|403/i.test(await p.textContent('#list')), 'a viewer is refused (personal data)');
  } finally { await browser.close(); srv.close(); e.close(); }
  ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks');
  process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
