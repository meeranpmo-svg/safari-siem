// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for Microsoft 365 licence assignment on HR Onboarding (hr-onboarding.html) against the REAL ITAM engine
// (onboarding.js + m365-licensing.js) and an in-process fake Microsoft Graph, SYNTHETIC data only: an administrator saves the
// licensing settings (helper text, secret box never filled back) and "Test" lists the tenant's subscriptions with free seats;
// the account proposal offers the catalogue licences as tick boxes; after the account exists the joiner shows "waiting for
// Entra ID sync"; once the user appears, "Try now" assigns the licence and it shows as assigned and verified; an operator
// cannot change the settings.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node hr-onboarding-m365.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const ITAM = path.join(__dirname, '..', '..', 'backend', 'itam'), DASH = path.join(__dirname, '..', '..', 'ui');
const H = require(path.join(ITAM, 'tests', 'helpers'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const TENANT = '11111111-2222-3333-4444-555555555555', APPID = '66666666-7777-8888-9999-000000000000', SECRET = 'Synthetic-Graph-Secret-1';
const E3 = '05e9a617-0261-4cee-bb44-138d3ef5d965';

(async () => {
  const users = {}; let assigned = null;
  const g = http.createServer((req, res) => { let b = ''; req.on('data', (c) => { b += c; }); req.on('end', () => {
    const u = new URL(req.url, 'http://x'), J = (c, o) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(o)); };
    if (u.pathname.endsWith('/oauth2/v2.0/token')) return new URLSearchParams(b).get('client_secret') === SECRET ? J(200, { access_token: 'tok' }) : J(401, { error: 'invalid_client' });
    if (u.pathname === '/v1.0/subscribedSkus') return J(200, { value: [{ skuId: E3, skuPartNumber: 'SPE_E3', consumedUnits: 40, prepaidUnits: { enabled: 50 }, servicePlans: [] }] });
    const m = /^\/v1\.0\/users\/([^/]+)(\/assignLicense)?$/.exec(u.pathname);
    if (m) { const k = decodeURIComponent(m[1]).toLowerCase(), usr = Object.values(users).find((x) => x.id === k || x.userPrincipalName === k); if (!usr) return J(404, { error: { code: 'Request_ResourceNotFound', message: 'x' } });
      if (req.method === 'GET') return J(200, usr); const p = JSON.parse(b || '{}'); if (req.method === 'PATCH') { Object.assign(usr, p); return J(204, {}); }
      usr.assignedLicenses.push(...p.addLicenses.map((a) => ({ skuId: a.skuId }))); assigned = usr.userPrincipalName; return J(200, usr); }
    J(404, {});
  }); });
  await new Promise((r) => g.listen(0, '127.0.0.1', r));
  const gb = 'http://127.0.0.1:' + g.address().port;
  const e = await H.startApp({ noAi: true });
  require(path.join(ITAM, 'engine/duty')).registerDuty(e.app.srv, e.app, { noTimer: true, python: process.env.PYTHON || 'python3', graphLogin: gb, graphBase: gb + '/v1.0' });
  const api = async (m, p, body, who) => { const r = await e.req(m, p, Object.assign({ body }, who)); if (r.status !== 200) throw new Error(p + ': ' + JSON.stringify(r.json)); return r.json; };
  const ADM = { user: 'syed', role: 'admin' }, DESK = { user: 'desk.syn', role: 'operator' };
  await api('POST', '/onboarding/ad', { upn_suffix: 'corp.syn' }, ADM);
  await api('POST', '/onboarding', { name: 'Sara Al-Ghamdi', employee_id: 'E-10442', job_title: 'Claims Analyst', department: 'Claims', start_date: '2099-01-15', manager: 'faisal.syn', laptop_profile: 'standard' }, { user: 'hana.syn', role: 'operator' });
  await api('POST', '/onboarding/ONB-001/approve', { decision: 'approve' }, { user: 'faisal.syn', role: 'operator' });
  e.app.store.collection('assets').put({ id: 'ast_l1', type: 'laptop', status: 'in_stock', serial: 'SYN-1', lifecycle: [] });
  await api('POST', '/onboarding/ONB-001/laptop', { asset_id: 'ast_l1' }, DESK);
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
  const as = async (p, who) => { WHO = who; await p.reload(); await p.waitForSelector('#list table', { timeout: 15000 }); };
  const openRow = async (p) => { await p.click('#list tr[data-id="ONB-001"]'); await p.waitForSelector('#zd .steps', { timeout: 8000 }); };
  try {
    const p = await browser.newPage({ viewport: { width: 1400, height: 1000 } }); p.on('pageerror', (x) => errs.push(x.message));
    await p.goto(base + 'hr-onboarding.html?standalone=1'); await p.waitForSelector('#list table', { timeout: 15000 });
    await p.click('#m3set'); await p.waitForSelector('#m3form .zyb-hint', { timeout: 8000 });
    ok(await p.$$eval('#m3form input[name]:not([type=checkbox]), #m3form textarea[name]', (x) => x.every((el) => el.getAttribute('data-hinted'))), 'helper text on the settings');
    await p.check('#m3form [name=enabled]'); await p.fill('#m3form [name=tenant_id]', TENANT); await p.fill('#m3form [name=client_id]', APPID); await p.fill('#m3form [name=client_secret]', SECRET);
    await p.fill('#m3form [name=usage_location]', 'SA'); await p.fill('#m3form [name=catalogue]', 'Microsoft 365 E3 | ' + E3); await p.fill('#m3form [name=default_licences]', 'Microsoft 365 E3');
    await Promise.all([p.waitForResponse((r) => /onboarding\/m365$/.test(r.url()) && r.request().method() === 'POST'), p.click('#m3form [type=submit]')]);
    ok(await zd(p, /set \(sealed, never shown\)/), 'saved with the secret sealed');
    ok((await p.inputValue('#m3form [name=client_secret]')) === '' && !(await p.content()).includes(SECRET), 'the secret is never put back into the page');
    await Promise.all([p.waitForResponse((r) => /m365\/test$/.test(r.url())), p.click('[data-act="m3test"]')]);
    ok(await zd(p, /SPE_E3/) && await zd(p, /Subscriptions in the tenant/), 'the subscriptions are listed');
    // the account proposal offers the catalogue
    await as(p, DESK); await openRow(p);
    ok((await p.$$eval('#aform input[name=licences]', (x) => x.map((i) => i.value))).join() === 'Microsoft 365 E3', 'licences offered from the catalogue');
    await p.fill('#aform [name=username]', 'sara.ghamdi'); await p.check('#aform input[name=licences][value="Microsoft 365 E3"]');
    await Promise.all([p.waitForResponse((r) => /\/account$/.test(r.url())), p.click('#aform [type=submit]')]);
    await api('POST', '/onboarding/ONB-001/account/decide', { decision: 'approve' }, ADM);
    await api('POST', '/onboarding/ONB-001/account/created', { username: 'sara.ghamdi', directory_ref: 'CN=sara.ghamdi,OU=Joiners' }, DESK);
    await e.app.addons.onboarding.licensingTick();
    await as(p, ADM); await openRow(p);
    ok(await zd(p, /waiting for Entra ID sync/), 'waiting for the sync');
    users.s = { id: 'id-sara', userPrincipalName: 'sara.ghamdi@corp.syn', usageLocation: null, assignedLicenses: [] };
    await Promise.all([p.waitForResponse((r) => /licences\/retry$/.test(r.url())), p.click('[data-act="lretry"]')]);
    ok(await zd(p, /assigned and verified/), 'assigned and verified');
    ok(assigned === 'sara.ghamdi@corp.syn' && users.s.usageLocation === 'SA', 'assigned in Entra ID with the usage location');
    // an operator cannot change the settings
    await as(p, DESK); await p.click('#m3set'); await p.waitForSelector('#m3form', { timeout: 8000 });
    await Promise.all([p.waitForResponse((r) => /onboarding\/m365$/.test(r.url()) && r.request().method() === 'POST'), p.click('#m3form [type=submit]')]);
    ok(await p.waitForFunction(() => /\S/.test((document.querySelector('#m3form [data-msg]') || {}).textContent || '')).then(() => true, () => false), 'an operator is refused');
  } finally { await browser.close(); srv.close(); g.close(); e.close(); }
  ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks');
  process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
