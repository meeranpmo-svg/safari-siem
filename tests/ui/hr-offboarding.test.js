// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for HR Offboarding (dashboards/server/hr-offboarding.html) against the REAL ITAM engine (offboarding.js +
// onboarding-ad.js + ad-writer.js) and an in-process fake LDAPS directory, SYNTHETIC data only: HR raises a leaver (helper
// text on every field) and the page shows the directory account; the requester cannot confirm; the manager confirms; the
// confirmer cannot approve; another administrator approves an immediate termination and the account is disabled, moved and
// verified; the equipment goes back to stock and the request completes; a mismatched employee number is shown as a blocker;
// a hostile value stays text; a viewer is refused; the page is in the User Desktops menu.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node hr-offboarding.test.js
const http = require('http'), fs = require('fs'), os = require('os'), path = require('path');
const ITAM = path.join(__dirname, '..', '..', 'backend', 'itam'), DASH = path.join(__dirname, '..', '..', 'ui');
const H = require(path.join(ITAM, 'tests', 'helpers'));
const { makeCA, makeServerCert } = require(path.join(ITAM, 'tests', 'helpers', 'x509'));
const { startFakeLdap, makeDirectory } = require(path.join(ITAM, 'tests', 'helpers', 'fake-ldap'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const XSS = '<img src=x onerror=alert(1)>';
const BASE = 'DC=corp-hq,DC=com', STAFF = 'OU=Staff,' + BASE, LEAVERS = 'OU=Leavers,' + BASE, SVC = 'CN=svc-onboarding-syn,OU=Service,' + BASE, BIND_PW = 'Synthetic-Bind-Pass-9';
const PERSON = 'CN=Person,CN=Schema,CN=Configuration,' + BASE;

(async () => {
  const ca = makeCA('Synthetic AD CA leavers page'), leaf = makeServerCert(ca, { cn: ('dc01.' + 'corp-hq.com'), dns: [('dc01.' + 'corp-hq.com')], ip: ['127.0.0.1'] });
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'off-page-')), caFile = path.join(tmp, 'ad-root.pem'); fs.writeFileSync(caFile, ca.cert);
  const dir = makeDirectory();
  for (const ou of [BASE, 'OU=Service,' + BASE, STAFF, LEAVERS, 'OU=Joiners,' + BASE]) dir.add(ou, { objectClass: [ou === BASE ? 'domain' : 'organizationalUnit'] });
  dir.add(SVC, { objectClass: ['user'], objectCategory: PERSON, sAMAccountName: 'svc-onboarding-syn' });
  dir.add('CN=Khalid Al-Harbi,' + STAFF, { objectClass: ['user'], objectCategory: PERSON, sAMAccountName: 'khalid.harbi', displayName: 'Khalid Al-Harbi', employeeID: 'E-20001', userAccountControl: '512' });
  dir.add('CN=Other Person,' + STAFF, { objectClass: ['user'], objectCategory: PERSON, sAMAccountName: 'other.person', displayName: 'Other Person', employeeID: 'E-99999', userAccountControl: '512' });
  const ldap = await startFakeLdap({ key: leaf.key, cert: leaf.cert, dir, passwords: { [SVC]: BIND_PW } });
  const e = await H.startApp({ noAi: true });
  require(path.join(ITAM, 'engine/duty')).registerDuty(e.app.srv, e.app, { noTimer: true, python: process.env.PYTHON || 'python3' });
  const A = e.app.store.collection('assets');
  A.put({ id: 'ast_lap9', type: 'laptop', status: 'in_use', custodian: 'khalid.harbi', vendor: 'Dell', model: 'Latitude 5450', serial: 'SYN-LAP-009', asset_tag: 'ZS-L-009', lifecycle: [] });
  const s = await e.req('POST', '/onboarding/ad', { body: { servers: ['ldaps://127.0.0.1:' + ldap.port], ca_file: caFile, bind_dn: SVC, bind_password: BIND_PW, base_dn: BASE, ou: 'OU=Joiners,' + BASE, upn_suffix: 'corp-hq.com', leavers_enabled: true, leavers_ou: LEAVERS }, user: 'syed', role: 'admin' });
  if (s.status !== 200) throw new Error(JSON.stringify(s.json));
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
  const openRow = async (p, id) => { await p.click('#list tr[data-id="' + id + '"]'); await p.waitForSelector('#zd .steps', { timeout: 8000 }); };
  const submit = async (p, sel) => { await Promise.all([p.waitForResponse((r) => /\/api\/itam\/offboarding/.test(r.url()) && r.request().method() === 'POST'), p.click(sel + ' [type=submit]')]); };
  try {
    const p = await browser.newPage({ viewport: { width: 1400, height: 1000 } }); p.on('pageerror', (x) => errs.push(x.message));
    await p.goto(base + 'hr-offboarding.html?standalone=1'); await p.waitForSelector('#list .card-body, #list table', { state: 'attached', timeout: 15000 });
    ok(/No leaver yet/.test(await p.textContent('#list')), 'empty state says how to start');
    await p.click('#new'); await p.waitForSelector('#ofnew .zyb-hint', { timeout: 8000 });
    ok(await p.$$eval('#ofnew input[name], #ofnew select[name], #ofnew textarea[name]', (x) => x.every((el) => el.getAttribute('data-hinted'))), 'every field has helper text');
    await p.fill('#ofnew [name=name]', 'Khalid Al-Harbi'); await p.fill('#ofnew [name=employee_id]', 'E-20001'); await p.fill('#ofnew [name=username]', 'khalid.harbi');
    await p.fill('#ofnew [name=department]', 'Claims ' + XSS); await p.fill('#ofnew [name=last_day]', '2099-01-15'); await p.fill('#ofnew [name=manager]', 'faisal.syn');
    await p.selectOption('#ofnew [name=reason]', 'termination'); await p.check('#ofnew [name=immediate]');
    await submit(p, '#ofnew'); ok(await zd(p, /OFF-001/), 'request raised');
    ok(await zd(p, /E-20001/) && await zd(p, /CN=Khalid Al-Harbi,OU=Staff/), 'the directory account is shown');
    ok(!(await p.$('#zd img')) && (await p.textContent('#zd')).includes(XSS), 'a hostile value stays text');
    await p.selectOption('#ofconf [name=decision]', 'confirm'); await submit(p, '#ofconf');
    ok(await msg(p, '#ofconf', /raised OFF-001 and cannot also confirm/), 'the requester cannot confirm');
    // the manager (an administrator here) confirms, then cannot approve
    await as(p, { user: 'faisal.syn', role: 'admin' }); await openRow(p, 'OFF-001');
    await p.selectOption('#ofconf [name=decision]', 'confirm'); await submit(p, '#ofconf');
    await p.waitForSelector('#ofappr', { timeout: 8000 });
    await p.selectOption('#ofappr [name=decision]', 'approve'); await submit(p, '#ofappr');
    ok(await msg(p, '#ofappr', /confirmed the leaving/), 'the confirmer cannot approve');
    // another administrator approves an immediate termination
    await as(p, { user: 'syed', role: 'admin' }); await openRow(p, 'OFF-001');
    ok(await zd(p, /disabled as soon as you approve/), 'the immediate termination is explained');
    await p.selectOption('#ofappr [name=decision]', 'approve'); await submit(p, '#ofappr');
    ok(await zd(p, /disabled and verified/) && await zd(p, /moved to the leavers OU/), 'disabled, moved and verified');
    const u = dir.all().find((x) => dir.vals(x, 'sAMAccountName')[0] === 'khalid.harbi');
    ok(u && u.dn === 'CN=Khalid Al-Harbi,' + LEAVERS && dir.vals(u, 'userAccountControl')[0] === '514', 'disabled in the directory');
    // equipment
    await p.check('#ofequip input[value="ast_lap9"]'); await submit(p, '#ofequip');
    ok(await zd(p, /completed/), 'the request completes');
    ok(A.get('ast_lap9').status === 'in_stock', 'the laptop is back in stock');
    // a mismatched employee number
    await as(p, { user: 'hana.syn', role: 'operator' });
    await p.click('#new'); await p.waitForSelector('#ofnew', { timeout: 8000 });
    await p.fill('#ofnew [name=name]', 'Wrong Person'); await p.fill('#ofnew [name=employee_id]', 'E-30000'); await p.fill('#ofnew [name=username]', 'other.person');
    await p.fill('#ofnew [name=department]', 'Finance'); await p.fill('#ofnew [name=last_day]', '2099-02-01'); await p.fill('#ofnew [name=manager]', 'faisal.syn'); await p.selectOption('#ofnew [name=reason]', 'resignation');
    await submit(p, '#ofnew');
    ok(await zd(p, /Will not be disabled automatically/) && await zd(p, /belongs to employee E-99999/), 'a mismatch is shown before anyone approves');
    // viewer refused
    await as(p, { user: 'vera.syn', role: 'viewer' });
    ok(!/OFF-001/.test(await p.textContent('#list')), 'a viewer sees no leaver');
    const nav = fs.readFileSync(path.join(DASH, 'vendor', 'zyb-nav.js'), 'utf8');
    ok(/"h": "hr-offboarding\.html"/.test(nav) && nav.indexOf('hr-offboarding.html') > nav.indexOf('hr-onboarding.html'), 'in the menu next to HR Onboarding');
  } finally { await browser.close(); srv.close(); e.close(); ldap.close(); fs.rmSync(tmp, { recursive: true, force: true }); }
  ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks');
  process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
