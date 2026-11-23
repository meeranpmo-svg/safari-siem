// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for Privileged Access (dashboards/server/privileged-access.html) against the REAL ITAM engine (pam.js +
// onboarding-ad.js + ad-writer.js) and an in-process fake LDAPS directory, SYNTHETIC data only: an administrator saves the
// eligible groups (a tier-0 group is refused); an engineer requests a group with helper text on the fields; the engineer
// cannot approve it; the named approver approves and the membership appears in the directory with the time left; the
// engineer ends it early and the membership is removed; standing members are listed; a hostile reason stays text; a viewer
// is refused; the page is in the Identity & Microsoft 365 menu.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node privileged-access.test.js
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
  const ca = makeCA('Synthetic AD CA pam page'), leaf = makeServerCert(ca, { cn: ('dc01.' + 'corp-hq.com'), dns: [('dc01.' + 'corp-hq.com')], ip: ['127.0.0.1'] });
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'pam-page-')), caFile = path.join(tmp, 'ad-root.pem'); fs.writeFileSync(caFile, ca.cert);
  const dir = makeDirectory();
  for (const ou of [BASE, 'OU=Service,' + BASE, STAFF, GR, 'OU=Joiners,' + BASE]) dir.add(ou, { objectClass: [ou === BASE ? 'domain' : 'organizationalUnit'] });
  dir.add(SVC, { objectClass: ['user'], objectCategory: PERSON, sAMAccountName: 'svc-onboarding-syn' });
  for (const [cn, sam] of [['Sara Al-Ghamdi', 'sara.ghamdi'], ['Nadia Lead', 'nadia.syn'], ['Old Admin', 'old.admin']]) dir.add('CN=' + cn + ',' + STAFF, { objectClass: ['user'], objectCategory: PERSON, sAMAccountName: sam, displayName: cn, userAccountControl: '512' });
  dir.add('CN=GG-Server-Admins,' + GR, { objectClass: ['group'], sAMAccountName: 'GG-Server-Admins' });
  dir.addMember('CN=GG-Server-Admins,' + GR, 'CN=Old Admin,' + STAFF);
  const ldap = await startFakeLdap({ key: leaf.key, cert: leaf.cert, dir, passwords: { [SVC]: BIND_PW } });
  const e = await H.startApp({ noAi: true });
  require(path.join(ITAM, 'engine/duty')).registerDuty(e.app.srv, e.app, { noTimer: true, python: process.env.PYTHON || 'python3' });
  const s = await e.req('POST', '/onboarding/ad', { body: { servers: ['ldaps://127.0.0.1:' + ldap.port], ca_file: caFile, bind_dn: SVC, bind_password: BIND_PW, base_dn: BASE, ou: 'OU=Joiners,' + BASE, upn_suffix: 'corp-hq.com' }, user: 'syed', role: 'admin' });
  if (s.status !== 200) throw new Error(JSON.stringify(s.json));
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
  const has = (p, sel, re) => p.waitForFunction((a) => new RegExp(a[1]).test((document.querySelector(a[0]) || {}).textContent || ''), [sel, re.source], { timeout: 10000 }).then(() => true, () => false);
  const msg = (p, sel, re) => has(p, sel + ' [data-msg]', re);
  const as = async (p, who) => { WHO = who; await Promise.all([p.waitForResponse((r) => /\/api\/itam\/pam$/.test(r.url())), p.reload()]); await p.waitForTimeout(200); };
  const members = () => dir.vals(dir.get('CN=GG-Server-Admins,' + GR), 'member').map((d) => /^CN=([^,]+)/.exec(d)[1]).sort().join(',');
  try {
    const p = await browser.newPage({ viewport: { width: 1400, height: 1000 } }); p.on('pageerror', (x) => errs.push(x.message));
    await Promise.all([p.waitForResponse((r) => /\/api\/itam\/pam$/.test(r.url())), p.goto(base + 'privileged-access.html?standalone=1')]);
    ok(await has(p, '#alert', /No group can be requested yet/), 'empty state says what to do');
    await p.click('#cfg'); await p.waitForSelector('#pacfg .zyb-hint', { timeout: 8000 });
    await p.fill('#pacfg [name=groups]', 'Domain Admins | 2 |  | no');
    await Promise.all([p.waitForResponse((r) => /pam\/config$/.test(r.url())), p.click('#pacfg [type=submit]')]);
    ok(await msg(p, '#pacfg', /tier-0/), 'a tier-0 group is refused');
    await p.fill('#pacfg [name=groups]', 'GG-Server-Admins | 8 | nadia.syn | yes');
    await Promise.all([p.waitForResponse((r) => /pam\/config$/.test(r.url())), p.click('#pacfg [type=submit]')]);
    ok(await has(p, '#kpis', /Eligible groups/) && (await p.textContent('#kpis')).includes('1'), 'saved');
    // the engineer asks
    await as(p, { user: 'sara.ghamdi', role: 'operator' });
    await p.click('#new'); await p.waitForSelector('#pareq .zyb-hint', { timeout: 8000 });
    ok(await p.$$eval('#pareq input[name], #pareq select[name]', (x) => x.every((el) => el.getAttribute('data-hinted'))), 'helper text on every field');
    await p.selectOption('#pareq [name=group]', 'GG-Server-Admins'); await p.fill('#pareq [name=hours]', '3'); await p.fill('#pareq [name=reason]', 'Patch window ' + XSS);
    await Promise.all([p.waitForResponse((r) => /pam\/requests$/.test(r.url())), p.click('#pareq [type=submit]')]);
    ok(await msg(p, '#pareq', /ticket is required/), 'the ticket is required for this group');
    await p.fill('#pareq [name=ticket]', 'CHG-7001');
    await Promise.all([p.waitForResponse((r) => /pam\/requests$/.test(r.url())), p.click('#pareq [type=submit]')]);
    ok(await has(p, '#mine', /PAR-0001/) && await has(p, '#mine', /waiting for approval/), 'request sent');
    ok((await p.textContent('#mine')).includes(XSS) && !(await p.$('#mine img')), 'a hostile reason stays text');
    ok(!(await p.$('#appr [data-dec]')), 'the engineer cannot approve their own request');
    // the approver
    await as(p, { user: 'nadia.syn', role: 'operator' });
    await Promise.all([p.waitForResponse((r) => /decide$/.test(r.url())), p.click('#appr [data-dec="approve"]')]);
    ok(await has(p, '#act', /active/) && await has(p, '#act', /left/), 'active with the time left');
    ok(members() === 'Old Admin,Sara Al-Ghamdi', 'added in the directory: ' + members());
    // the engineer ends it early
    await as(p, { user: 'sara.ghamdi', role: 'operator' });
    await p.click('#mine [data-end]'); await p.waitForSelector('#paend', { timeout: 8000 });
    await Promise.all([p.waitForResponse((r) => /\/end$/.test(r.url())), p.click('#paend [type=submit]')]);
    ok(await has(p, '#mine', /ended early - removed/), 'ended');
    ok(members() === 'Old Admin', 'removed from the directory: ' + members());
    // standing members (administrator)
    await as(p, { user: 'syed', role: 'admin' });
    await p.click('#stand'); ok(await has(p, '#zd', /old\.admin/), 'the standing member is listed');
    await p.keyboard.press('Escape');
    WHO = { user: 'vera.syn', role: 'viewer' }; await Promise.all([p.waitForResponse((r) => /\/api\/itam\/pam$/.test(r.url())), p.reload()]); await p.waitForTimeout(300);
    ok(!/PAR-0001/.test(await p.textContent('body')), 'a viewer sees no request');
    const nav = fs.readFileSync(path.join(DASH, 'vendor', 'zyb-nav.js'), 'utf8');
    ok(/"h": "privileged-access\.html"/.test(nav), 'in the menu');
  } finally { await browser.close(); srv.close(); e.close(); ldap.close(); fs.rmSync(tmp, { recursive: true, force: true }); }
  ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks');
  process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
