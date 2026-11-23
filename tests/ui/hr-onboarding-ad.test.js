// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for automatic AD account creation on HR Onboarding (hr-onboarding.html) against the REAL ITAM engine
// (onboarding.js + onboarding-ad.js + ad-writer.js) and an in-process fake LDAPS directory, SYNTHETIC data only: an
// administrator saves Directory settings (helper text on every field, the password box never filled back) and tests the
// connection; an operator is refused; the account approval creates the account (shown as created and disabled until
// handover); the manager shows the temporary password once and it equals what the directory received; the button is gone
// afterwards; the handover enables the account; a re-issue asked by the manager is approved by an administrator.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node hr-onboarding-ad.test.js
const http = require('http'), fs = require('fs'), os = require('os'), path = require('path');
const ITAM = path.join(__dirname, '..', '..', 'backend', 'itam'), DASH = path.join(__dirname, '..', '..', 'ui');
const H = require(path.join(ITAM, 'tests', 'helpers'));
const { makeCA, makeServerCert } = require(path.join(ITAM, 'tests', 'helpers', 'x509'));
const { startFakeLdap, makeDirectory } = require(path.join(ITAM, 'tests', 'helpers', 'fake-ldap'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const BASE = 'DC=corp-hq,DC=com', OU = 'OU=Joiners,' + BASE, SVC = 'CN=svc-onboarding-syn,OU=Service,' + BASE, BIND_PW = 'Synthetic-Bind-Pass-9';

(async () => {
  const ca = makeCA('Synthetic AD CA page'), leaf = makeServerCert(ca, { cn: ('dc01.' + 'corp-hq.com'), dns: [('dc01.' + 'corp-hq.com')], ip: ['127.0.0.1'] });
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'onb-ad-page-')), caFile = path.join(tmp, 'ad-root.pem'); fs.writeFileSync(caFile, ca.cert);
  const dir = makeDirectory();
  dir.add(BASE, { objectClass: ['domain'] }); dir.add('OU=Service,' + BASE, { objectClass: ['organizationalUnit'] }); dir.add(OU, { objectClass: ['organizationalUnit'] });
  dir.add(SVC, { objectClass: ['user'], sAMAccountName: 'svc-onboarding-syn' }); dir.add('OU=Groups,' + BASE, { objectClass: ['organizationalUnit'] });
  dir.add('CN=GG-Claims-Users,OU=Groups,' + BASE, { objectClass: ['group'], sAMAccountName: 'GG-Claims-Users' });
  const ldap = await startFakeLdap({ key: leaf.key, cert: leaf.cert, dir, passwords: { [SVC]: BIND_PW } });
  const e = await H.startApp({ noAi: true });
  require(path.join(ITAM, 'engine/duty')).registerDuty(e.app.srv, e.app, { noTimer: true, python: process.env.PYTHON || 'python3' });
  e.app.store.collection('assets').put({ id: 'ast_lap1', type: 'laptop', status: 'in_stock', vendor: 'Dell', model: 'Latitude 5450', serial: 'SYN-LAP-001', lifecycle: [] });
  const api = async (m, p, b, who) => { const r = await e.req(m, p, Object.assign({ body: b }, who)); if (r.status !== 200) throw new Error(p + ': ' + JSON.stringify(r.json)); return r.json; };
  await api('POST', '/onboarding', { name: 'Sara Al-Ghamdi', employee_id: 'E-10442', job_title: 'Claims Analyst', department: 'Claims', start_date: '2099-01-15', manager: 'faisal.syn', laptop_profile: 'standard' }, { user: 'hana.syn', role: 'operator' });
  await api('POST', '/onboarding/ONB-001/approve', { decision: 'approve' }, { user: 'faisal.syn', role: 'operator' });
  await api('POST', '/onboarding/ONB-001/laptop', { asset_id: 'ast_lap1' }, { user: 'desk.syn', role: 'operator' });
  await api('POST', '/onboarding/ONB-001/account', { username: 'sara.ghamdi', groups: ['GG-Claims-Users'] }, { user: 'desk.syn', role: 'operator' });
  let WHO = { user: 'syed', role: 'admin' };
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
  const as = async (p, who) => { WHO = who; await p.reload(); await p.waitForSelector('#list table, #list .card-body', { state: 'attached', timeout: 15000 }); };
  const openRow = async (p) => { await p.click('#list tr[data-id="ONB-001"]'); await p.waitForSelector('#zd .steps', { timeout: 8000 }); };
  const post = (p, re) => p.waitForResponse((r) => re.test(r.url()) && r.request().method() === 'POST');
  try {
    const p = await browser.newPage({ viewport: { width: 1400, height: 1000 } }); p.on('pageerror', (x) => errs.push(x.message));
    await p.goto(base + 'hr-onboarding.html?standalone=1'); await p.waitForSelector('#list table', { timeout: 15000 });
    // Directory settings
    await p.click('#adset'); await p.waitForSelector('#adsform .zyb-hint', { timeout: 8000 });
    ok(await p.$$eval('#adsform input[name]', (x) => x.every((el) => el.getAttribute('data-hinted'))), 'every settings field has helper text');
    ok((await p.getAttribute('#adsform [name=bind_password]', 'type')) === 'password', 'the bind password is a password box');
    await p.check('#adsform [name=enabled]'); await p.fill('#adsform [name=servers]', 'ldaps://127.0.0.1:' + ldap.port); await p.fill('#adsform [name=ca_file]', caFile);
    await p.fill('#adsform [name=bind_dn]', SVC); await p.fill('#adsform [name=bind_password]', BIND_PW); await p.fill('#adsform [name=base_dn]', BASE);
    await p.fill('#adsform [name=ou]', OU); await p.fill('#adsform [name=upn_suffix]', 'corp-hq.com'); await p.fill('#adsform [name=allowed_groups]', 'GG-Claims-Users');
    await Promise.all([post(p, /\/onboarding\/ad$/), p.click('#adsform [type=submit]')]);
    ok(await zd(p, /set \(sealed in the vault/), 'saved: the password is set and sealed');
    ok((await p.inputValue('#adsform [name=bind_password]')) === '' && !(await p.content()).includes(BIND_PW), 'the password is never put back into the page');
    await Promise.all([post(p, /\/onboarding\/ad\/test$/), p.click('[data-act="adtest"]')]);
    ok(await zd(p, /connected, OU found/), 'connection test');
    // the account approval creates the account
    await as(p, { user: 'syed', role: 'admin' }); await openRow(p);
    await p.selectOption('#adform [name=decision]', 'approve');
    await Promise.all([post(p, /account\/decide$/), p.click('#adform [type=submit]')]);
    ok(await zd(p, /created in Active Directory and verified/) && await zd(p, /disabled until handover/), 'shown as created, disabled until handover');
    // an operator who is not the manager cannot reveal
    await as(p, { user: 'desk.syn', role: 'operator' }); await openRow(p);
    await Promise.all([post(p, /credentials\/reveal$/), p.click('[data-act="reveal"]')]);
    ok(await p.waitForFunction(() => /only the named manager/.test(document.body.textContent)).then(() => true, () => false), 'only the manager');
    // the manager reveals once
    await as(p, { user: 'faisal.syn', role: 'operator' }); await openRow(p);
    await Promise.all([post(p, /credentials\/reveal$/), p.click('[data-act="reveal"]')]);
    await p.waitForSelector('#pwbox .pw', { timeout: 8000 });
    const shown = (await p.textContent('#pwbox .pw')).trim(), dn = ('CN=Sara Al-Ghamdi,' + OU).toLowerCase();
    ok(shown.length === 16 && shown === ldap.passwords[dn], 'the password shown is the one the directory received');
    await as(p, { user: 'faisal.syn', role: 'operator' }); await openRow(p);
    ok(!(await p.$('[data-act="reveal"]')) && await zd(p, /No temporary password is waiting/), 'shown once');
    ok(!JSON.stringify(e.app.store.auditTail(300)).includes(shown), 'never in the audit trail');
    // re-issue: the manager asks, a different administrator approves
    await p.fill('#riform [name=reason]', 'The joiner lost the temporary password');
    await Promise.all([post(p, /credentials\/reissue$/), p.click('#riform [type=submit]')]);
    await as(p, { user: 'syed', role: 'admin' }); await openRow(p);
    await p.selectOption('#rdform [name=decision]', 'approve');
    await Promise.all([post(p, /reissue\/decide$/), p.click('#rdform [type=submit]')]);
    ok(ldap.passwords[dn] !== shown, 'a new password was set in the directory');
    // laptop + handover enables the account
    await as(p, { user: 'desk.syn', role: 'operator' }); await openRow(p);
    await p.check('#hform [name=acknowledged]');
    await Promise.all([post(p, /handover$/), p.click('#hform [type=submit]')]);
    const u = dir.all().find((x) => dir.vals(x, 'sAMAccountName')[0] === 'sara.ghamdi');
    ok(u && dir.vals(u, 'userAccountControl')[0] === '512', 'enabled at handover');
    // an operator cannot save the settings
    await as(p, { user: 'desk.syn', role: 'operator' });
    await p.click('#adset'); await p.waitForSelector('#adsform', { timeout: 8000 });
    await Promise.all([post(p, /\/onboarding\/ad$/), p.click('#adsform [type=submit]')]);
    ok(await p.waitForFunction(() => /\S/.test((document.querySelector('#adsform [data-msg]') || {}).textContent || '')).then(() => true, () => false), 'an operator is refused');
  } finally { await browser.close(); srv.close(); e.close(); ldap.close(); fs.rmSync(tmp, { recursive: true, force: true }); }
  ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks');
  process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
