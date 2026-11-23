// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for HR Movers (dashboards/server/hr-movers.html) against the REAL ITAM engine (movers.js + onboarding-ad.js +
// ad-writer.js) and an in-process fake LDAPS directory, SYNTHETIC data only: the user name is read first and the current
// groups offered to leave, the allowed list offered to join (admin groups never offered); helper text on every field; the
// requester cannot approve; the receiving manager approves; another administrator approves a move whose date has passed and
// the groups change at once, shown per group; a revert asked by one administrator and approved by another restores them;
// a hostile value stays text; a viewer is refused; the page is in the menu.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node hr-movers.test.js
const http = require('http'), fs = require('fs'), os = require('os'), path = require('path');
const ITAM = path.join(__dirname, '..', '..', 'backend', 'itam'), DASH = path.join(__dirname, '..', '..', 'ui');
const H = require(path.join(ITAM, 'tests', 'helpers'));
const { makeCA, makeServerCert } = require(path.join(ITAM, 'tests', 'helpers', 'x509'));
const { startFakeLdap, makeDirectory } = require(path.join(ITAM, 'tests', 'helpers', 'fake-ldap'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const XSS = '<img src=x onerror=alert(1)>';
const BASE = 'DC=corp-hq,DC=com', STAFF = 'OU=Staff,' + BASE, GR = 'OU=Groups,' + BASE, SVC = 'CN=svc-onboarding-syn,OU=Service,' + BASE, BIND_PW = 'Synthetic-Bind-Pass-9';
const PERSON = 'CN=Person,CN=Schema,CN=Configuration,' + BASE;

(async () => {
  const ca = makeCA('Synthetic AD CA movers page'), leaf = makeServerCert(ca, { cn: ('dc01.' + 'corp-hq.com'), dns: [('dc01.' + 'corp-hq.com')], ip: ['127.0.0.1'] });
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'mov-page-')), caFile = path.join(tmp, 'ad-root.pem'); fs.writeFileSync(caFile, ca.cert);
  const dir = makeDirectory();
  for (const ou of [BASE, 'OU=Service,' + BASE, STAFF, GR, 'OU=Joiners,' + BASE]) dir.add(ou, { objectClass: [ou === BASE ? 'domain' : 'organizationalUnit'] });
  dir.add(SVC, { objectClass: ['user'], objectCategory: PERSON, sAMAccountName: 'svc-onboarding-syn' });
  dir.add('CN=Sara Al-Ghamdi,' + STAFF, { objectClass: ['user'], objectCategory: PERSON, sAMAccountName: 'sara.ghamdi', displayName: 'Sara Al-Ghamdi', employeeID: 'E-10442', userAccountControl: '512', department: 'Claims', title: 'Claims Analyst' });
  for (const g of ['GG-Claims-Users', 'SH-Claims-Files', 'GG-UW-Users', 'Helpdesk Admins']) dir.add('CN=' + g + ',' + GR, { objectClass: ['group'], sAMAccountName: g });
  dir.addMember('CN=GG-Claims-Users,' + GR, 'CN=Sara Al-Ghamdi,' + STAFF); dir.addMember('CN=SH-Claims-Files,' + GR, 'CN=Sara Al-Ghamdi,' + STAFF);
  const ldap = await startFakeLdap({ key: leaf.key, cert: leaf.cert, dir, passwords: { [SVC]: BIND_PW } });
  const e = await H.startApp({ noAi: true });
  require(path.join(ITAM, 'engine/duty')).registerDuty(e.app.srv, e.app, { noTimer: true, python: process.env.PYTHON || 'python3' });
  const s = await e.req('POST', '/onboarding/ad', { body: { servers: ['ldaps://127.0.0.1:' + ldap.port], ca_file: caFile, bind_dn: SVC, bind_password: BIND_PW, base_dn: BASE, ou: 'OU=Joiners,' + BASE, upn_suffix: 'corp-hq.com', allowed_groups: ['GG-UW-Users', 'GG-Claims-Users', 'SH-Claims-Files'], movers_enabled: true }, user: 'syed', role: 'admin' });
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
  const openRow = async (p) => { await p.selectOption('#fst', ''); await p.click('#list tr[data-id="MOV-001"]'); await p.waitForSelector('#zd .steps', { timeout: 8000 }); };
  const submit = async (p, sel) => { await Promise.all([p.waitForResponse((r) => /\/api\/itam\/movers/.test(r.url()) && r.request().method() === 'POST'), p.click(sel + ' [type=submit]')]); };
  const groups = () => { const x = dir.all().find((y) => dir.vals(y, 'sAMAccountName')[0] === 'sara.ghamdi'); return dir.vals(x, 'memberOf').map((d) => /^CN=([^,]+)/.exec(d)[1]).sort().join(','); };
  try {
    const p = await browser.newPage({ viewport: { width: 1400, height: 1000 } }); p.on('pageerror', (x) => errs.push(x.message));
    await p.goto(base + 'hr-movers.html?standalone=1'); await p.waitForSelector('#list .card-body, #list table', { state: 'attached', timeout: 15000 });
    ok(/No mover yet/.test(await p.textContent('#list')), 'empty state says how to start');
    await p.click('#new'); await p.waitForSelector('#mvlook .zyb-hint', { timeout: 8000 });
    await p.fill('#mvlook [name=username]', 'sara.ghamdi');
    await Promise.all([p.waitForResponse((r) => /movers\/lookup/.test(r.url())), p.click('#mvlook [type=submit]')]);
    await p.waitForSelector('#mvnew .zyb-hint', { timeout: 8000 });
    ok(await p.$$eval('#mvnew input[name], #mvnew select[name], #mvnew textarea[name]', (x) => x.every((el) => el.getAttribute('data-hinted') || el.type === 'checkbox')), 'helper text on the fields');
    const leave = await p.$$eval('#mvnew input[name=remove_groups]', (x) => x.map((i) => i.value).sort().join(','));
    const join = await p.$$eval('#mvnew input[name=add_groups]', (x) => x.map((i) => i.value).join(','));
    ok(leave === 'GG-Claims-Users,SH-Claims-Files', 'the current groups are offered to leave: ' + leave);
    ok(join === 'GG-UW-Users' && !/Admins/.test(join), 'only the allowed groups not held are offered to join: ' + join);
    ok((await p.inputValue('#mvnew [name=from_department]')) === 'Claims', 'from department read from the directory');
    await p.fill('#mvnew [name=employee_id]', 'E-10442'); await p.fill('#mvnew [name=to_department]', 'Underwriting ' + XSS); await p.fill('#mvnew [name=to_title]', 'Underwriter');
    await p.fill('#mvnew [name=effective_date]', '2026-01-01'.replace('2026-01-01', new Date(Date.now() - 86400000).toISOString().slice(0, 10)));
    await p.fill('#mvnew [name=manager]', 'nadia.syn');
    await p.check('#mvnew input[name=remove_groups][value="GG-Claims-Users"]'); await p.check('#mvnew input[name=remove_groups][value="SH-Claims-Files"]'); await p.check('#mvnew input[name=add_groups][value="GG-UW-Users"]');
    await p.uncheck('#mvnew [name=update_attributes]');
    await submit(p, '#mvnew'); ok(await zd(p, /MOV-001/), 'request raised');
    ok(!(await p.$('#zd img')) && (await p.textContent('#zd')).includes(XSS), 'a hostile value stays text');
    await p.selectOption('#mvmgr [name=decision]', 'approve'); await submit(p, '#mvmgr');
    ok(await msg(p, '#mvmgr', /raised MOV-001 and cannot also approve/), 'the requester cannot approve');
    await as(p, { user: 'nadia.syn', role: 'operator' }); await openRow(p);
    await p.selectOption('#mvmgr [name=decision]', 'approve'); await submit(p, '#mvmgr');
    await as(p, { user: 'syed', role: 'admin' }); await openRow(p);
    await p.selectOption('#mvapp [name=decision]', 'approve'); await submit(p, '#mvapp');
    ok(await zd(p, /applied and verified/), 'applied at once (the date has passed) and verified');
    ok(groups() === 'GG-UW-Users', 'groups changed in the directory: ' + groups());
    ok(await zd(p, /leave GG-Claims-Users/) && await zd(p, /join GG-UW-Users/), 'each group\'s result shown');
    // revert
    await p.fill('#mvrev [name=reason]', 'Move postponed after it was applied'); await submit(p, '#mvrev');
    await as(p, { user: 'omar.syn', role: 'admin' }); await openRow(p);
    await p.selectOption('#mvrd [name=decision]', 'approve'); await submit(p, '#mvrd');
    ok(await zd(p, /reverted/), 'shown as reverted');
    ok(groups() === 'GG-Claims-Users,SH-Claims-Files', 'previous groups restored: ' + groups());
    await as(p, { user: 'vera.syn', role: 'viewer' });
    ok(!/MOV-001/.test(await p.textContent('#list')), 'a viewer sees no mover');
    const nav = fs.readFileSync(path.join(DASH, 'vendor', 'zyb-nav.js'), 'utf8');
    ok(/"h": "hr-movers\.html"/.test(nav), 'in the menu');
  } finally { await browser.close(); srv.close(); e.close(); ldap.close(); fs.rmSync(tmp, { recursive: true, force: true }); }
  ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks');
  process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
