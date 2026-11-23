// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for licence reclaim on HR Offboarding (hr-offboarding.html) against the REAL ITAM engine (offboarding.js +
// m365-licensing.js) and an in-process fake Microsoft Graph, SYNTHETIC data only: the reclaim settings are on the Microsoft
// 365 licensing form; a disabled leaver shows the licences proposed for reclaim with the due date and a KPI tile; the person
// who raised the request cannot approve; an administrator approves taking back one licence now (mailbox confirmed, a reason
// for the one kept) and it is removed in Entra ID and shown as reclaimed; helper text on the form.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node hr-offboarding-reclaim.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const ITAM = path.join(__dirname, '..', '..', 'backend', 'itam'), DASH = path.join(__dirname, '..', '..', 'ui');
const H = require(path.join(ITAM, 'tests', 'helpers'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const TENANT = '11111111-2222-3333-4444-555555555555', APPID = '66666666-7777-8888-9999-000000000000', SECRET = 'Synthetic-Graph-Secret-1';
const E3 = '05e9a617-0261-4cee-bb44-138d3ef5d965', VISIO = 'c5928f49-12ba-48f7-ada3-0d743a3601d5';

(async () => {
  const user = { id: 'id-khalid', userPrincipalName: 'khalid.harbi@corp.syn', accountEnabled: false, assignedLicenses: [{ skuId: E3 }, { skuId: VISIO }] };
  const g = http.createServer((req, res) => { let b = ''; req.on('data', (c) => { b += c; }); req.on('end', () => {
    const u = new URL(req.url, 'http://x'), J = (c, o) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(o)); };
    if (u.pathname.endsWith('/oauth2/v2.0/token')) return J(200, { access_token: 'tok' });
    if (u.pathname === '/v1.0/subscribedSkus') return J(200, { value: [{ skuId: E3, skuPartNumber: 'SPE_E3', consumedUnits: 50, prepaidUnits: { enabled: 50 } }, { skuId: VISIO, skuPartNumber: 'VISIOCLIENT', consumedUnits: 2, prepaidUnits: { enabled: 5 } }] });
    if (/^\/v1\.0\/users\/(khalid\.harbi%40corp\.syn|khalid\.harbi@corp\.syn|id-khalid)(\/assignLicense)?$/.test(u.pathname)) {
      if (req.method === 'POST') { const p = JSON.parse(b); user.assignedLicenses = user.assignedLicenses.filter((l) => !p.removeLicenses.includes(l.skuId)); }
      return J(200, user);
    }
    J(404, { error: { code: 'Request_ResourceNotFound', message: 'x' } });
  }); });
  await new Promise((r) => g.listen(0, '127.0.0.1', r));
  const gb = 'http://127.0.0.1:' + g.address().port;
  const e = await H.startApp({ noAi: true });
  require(path.join(ITAM, 'engine/duty')).registerDuty(e.app.srv, e.app, { noTimer: true, python: process.env.PYTHON || 'python3', graphLogin: gb, graphBase: gb + '/v1.0' });
  const api = async (m, p, body, who) => { const r = await e.req(m, p, Object.assign({ body }, who)); if (r.status !== 200) throw new Error(p + ': ' + JSON.stringify(r.json)); return r.json; };
  const ADM = { user: 'syed', role: 'admin' }, HRA = { user: 'hana.syn', role: 'admin' };
  await api('POST', '/onboarding/ad', { upn_suffix: 'corp.syn' }, ADM);
  await api('POST', '/onboarding/m365', { tenant_id: TENANT, client_id: APPID, client_secret: SECRET, catalogue: [{ name: 'Microsoft 365 E3', sku_id: E3 }], reclaim_enabled: true, reclaim_hold_days: 30 }, ADM);
  await api('POST', '/offboarding', { name: 'Khalid Al-Harbi', employee_id: 'E-20001', username: 'khalid.harbi', department: 'Claims', last_day: new Date().toISOString().slice(0, 10), manager: 'faisal.syn', reason: 'resignation' }, HRA);
  await api('POST', '/offboarding/OFF-001/confirm', { decision: 'confirm' }, { user: 'faisal.syn', role: 'operator' });
  await api('POST', '/offboarding/OFF-001/approve', { decision: 'approve' }, ADM);
  await api('POST', '/offboarding/OFF-001/disabled', { directory_ref: 'disabled in ADUC, CHG-9001' }, { user: 'desk.syn', role: 'operator' });
  let WHO = HRA;
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
  try {
    const p = await browser.newPage({ viewport: { width: 1400, height: 1000 } }); p.on('pageerror', (x) => errs.push(x.message));
    await p.goto(base + 'hr-onboarding.html?standalone=1'); await p.waitForSelector('#list', { timeout: 15000 });
    await p.click('#m3set'); await p.waitForSelector('#m3form [name=reclaim_hold_days]', { timeout: 8000 });
    ok((await p.inputValue('#m3form [name=reclaim_hold_days]')) === '30' && await p.isChecked('#m3form [name=reclaim_enabled]'), 'reclaim settings on the licensing form');
    await p.goto(base + 'hr-offboarding.html?standalone=1'); await p.waitForSelector('#list table', { timeout: 15000 });
    ok(/Licence reclaim waiting for approval/.test(await p.textContent('#kpis')), 'KPI tile');
    await openRow(p);
    ok(await zd(p, /waiting for approval/) && await zd(p, /Microsoft 365 E3, VISIOCLIENT/) && await zd(p, /Removal due/), 'licences proposed with the due date');
    ok(await p.$$eval('#ofrcl select[name], #ofrcl input[name=keep_reason]', (x) => x.every((el) => el.getAttribute('data-hinted'))), 'helper text');
    await p.selectOption('#ofrcl [name=decision]', 'approve'); await p.selectOption('#ofrcl [name=mailbox]', 'converted_to_shared');
    await Promise.all([p.waitForResponse((r) => /reclaim\/decide$/.test(r.url())), p.click('#ofrcl [type=submit]')]);
    ok(await msg(p, '#ofrcl', /raised OFF-001 and cannot also approve/), 'the person who raised it cannot approve');
    WHO = ADM; await p.reload(); await p.waitForSelector('#list table', { timeout: 15000 }); await openRow(p);
    await p.selectOption('#ofrcl [name=decision]', 'approve'); await p.selectOption('#ofrcl [name=mailbox]', 'converted_to_shared');
    await p.check('#ofrcl input[name=remove][value="Microsoft 365 E3"]'); await p.check('#ofrcl [name=now]');
    await Promise.all([p.waitForResponse((r) => /reclaim\/decide$/.test(r.url())), p.click('#ofrcl [type=submit]')]);
    ok(await msg(p, '#ofrcl', /keep_reason is required/), 'a reason for the licence kept');
    await p.fill('#ofrcl [name=keep_reason]', 'Visio goes to the successor next week');
    await Promise.all([p.waitForResponse((r) => /reclaim\/decide$/.test(r.url())), p.click('#ofrcl [type=submit]')]);
    ok(await zd(p, /reclaimed/) && await zd(p, /Freed: Microsoft 365 E3/) && await zd(p, /Converted to a shared mailbox/), 'shown as reclaimed with the mailbox confirmation');
    ok(user.assignedLicenses.map((l) => l.skuId).join() === VISIO, 'removed in Entra ID: only the approved licence');
  } finally { await browser.close(); srv.close(); g.close(); e.close(); }
  ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks');
  process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
