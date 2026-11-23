// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for Access Reviews (dashboards/server/access-reviews.html) against the REAL ITAM engine (access-reviews.js +
// onboarding-ad.js + ad-writer.js) and an in-process fake LDAPS directory, SYNTHETIC data only: the scope saved by an
// administrator (helper text); the quarter started from the page; the manager sees only their people, a dormant account
// cannot be kept without a reason, decisions saved and the attestation signed (then locked); an administrator who is not
// the reviewer approves the removal and it is removed in the directory; the evidence CSV downloads; a hostile display name
// stays text; a viewer is refused; the page is in the Identity & Microsoft 365 menu.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node access-reviews.test.js
const http = require('http'), fs = require('fs'), os = require('os'), path = require('path');
const ITAM = path.join(__dirname, '..', '..', 'backend', 'itam'), DASH = path.join(__dirname, '..', '..', 'ui');
const H = require(path.join(ITAM, 'tests', 'helpers'));
const { makeCA, makeServerCert } = require(path.join(ITAM, 'tests', 'helpers', 'x509'));
const { startFakeLdap, makeDirectory } = require(path.join(ITAM, 'tests', 'helpers', 'fake-ldap'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const XSS = '<img src=x onerror=alert(1)>';
const BASE = 'DC=corp-hq,DC=com', STAFF = 'OU=Staff,' + BASE, GR = 'OU=Groups,' + BASE, SVC = 'CN=svc-onboarding-syn,OU=Service,' + BASE, BIND_PW = 'Synthetic-Bind-Pass-9';
const PERSON = 'CN=Person,CN=Schema,CN=Configuration,' + BASE;
const FT = (ms) => String((ms + 11644473600000) * 10000);

(async () => {
  const ca = makeCA('Synthetic AD CA reviews page'), leaf = makeServerCert(ca, { cn: ('dc01.' + 'corp-hq.com'), dns: [('dc01.' + 'corp-hq.com')], ip: ['127.0.0.1'] });
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'ar-page-')), caFile = path.join(tmp, 'ad-root.pem'); fs.writeFileSync(caFile, ca.cert);
  const dir = makeDirectory();
  for (const ou of [BASE, 'OU=Service,' + BASE, STAFF, GR, 'OU=Joiners,' + BASE]) dir.add(ou, { objectClass: [ou === BASE ? 'domain' : 'organizationalUnit'] });
  dir.add(SVC, { objectClass: ['user'], objectCategory: PERSON, sAMAccountName: 'svc-onboarding-syn' });
  const u = (cn, sam, extra) => dir.add('CN=' + cn + ',' + STAFF, Object.assign({ objectClass: ['user'], objectCategory: PERSON, sAMAccountName: sam, displayName: cn, userAccountControl: '512', lastLogonTimestamp: FT(Date.now() - 86400000) }, extra));
  u('Nadia Manager', 'nadia.syn', {});
  u('Sara Al-Ghamdi', 'sara.ghamdi', { manager: 'CN=Nadia Manager,' + STAFF, displayName: 'Sara ' + XSS });
  u('Khalid Al-Harbi', 'khalid.harbi', { manager: 'CN=Nadia Manager,' + STAFF, lastLogonTimestamp: FT(Date.now() - 200 * 86400000) });
  dir.add('CN=GG-Claims-Users,' + GR, { objectClass: ['group'], sAMAccountName: 'GG-Claims-Users' });
  dir.addMember('CN=GG-Claims-Users,' + GR, 'CN=Sara Al-Ghamdi,' + STAFF); dir.addMember('CN=GG-Claims-Users,' + GR, 'CN=Khalid Al-Harbi,' + STAFF);
  const ldap = await startFakeLdap({ key: leaf.key, cert: leaf.cert, dir, passwords: { [SVC]: BIND_PW } });
  const e = await H.startApp({ noAi: true });
  require(path.join(ITAM, 'engine/duty')).registerDuty(e.app.srv, e.app, { noTimer: true, python: process.env.PYTHON || 'python3' });
  const s = await e.req('POST', '/onboarding/ad', { body: { servers: ['ldaps://127.0.0.1:' + ldap.port], ca_file: caFile, bind_dn: SVC, bind_password: BIND_PW, base_dn: BASE, ou: 'OU=Joiners,' + BASE, upn_suffix: 'corp-hq.com' }, user: 'syed', role: 'admin' });
  if (s.status !== 200) throw new Error(JSON.stringify(s.json));
  let WHO = { user: 'syed', role: 'admin' };
  const srv = http.createServer((req, res) => {
    const u2 = new URL(req.url, 'http://x'), json = (c, b2) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b2)); };
    if (u2.pathname === '/dashboards/whoami.json') return json(200, WHO);
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
  const base = 'http://127.0.0.1:' + srv.address().port + '/';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  const has = (p, sel, re) => p.waitForFunction((a) => new RegExp(a[1]).test((document.querySelector(a[0]) || {}).textContent || ''), [sel, re.source], { timeout: 10000 }).then(() => true, () => false);
  const as = async (p, who) => { WHO = who; await p.reload(); await p.waitForSelector('#body .card, #tabs', { timeout: 15000 }); };
  try {
    const p = await browser.newPage({ viewport: { width: 1400, height: 1000 }, acceptDownloads: true }); p.on('pageerror', (x) => errs.push(x.message));
    await p.goto(base + 'access-reviews.html?standalone=1');
    ok(await has(p, '#body', /No group is in scope yet/), 'empty state says what to do');
    await p.click('#scope'); await p.waitForSelector('#arscope .zyb-hint', { timeout: 8000 });
    ok(await p.$$eval('#arscope input[name], #arscope textarea[name]', (x) => x.every((el) => el.getAttribute('data-hinted'))), 'helper text on the scope fields');
    await p.fill('#arscope [name=groups]', 'GG-Claims-Users | faisal.syn'); await p.fill('#arscope [name=due_days]', '21'); await p.check('#arscope [name=auto_remove]');
    await Promise.all([p.waitForResponse((r) => /access-reviews\/config$/.test(r.url())), p.click('#arscope [type=submit]')]);
    await p.waitForSelector('#start:not([hidden])', { timeout: 8000 });
    await Promise.all([p.waitForResponse((r) => /\/access-reviews$/.test(r.url()) && r.request().method() === 'POST'), p.click('#start')]);
    ok(await has(p, '#kpis', /Memberships/) && await has(p, '#kpis', /0 \/ 2/), 'the quarter started: 2 memberships');
    ok(await p.$eval('#start', (b) => b.hidden), 'one campaign per quarter');
    // the manager
    await as(p, { user: 'nadia.syn', role: 'operator' });
    ok((await p.$$('#pane tr[data-item]')).length === 2, 'the manager sees their two people');
    ok((await p.textContent('#pane')).includes('Sara ' + XSS) && !(await p.$('#pane img')), 'a hostile display name stays text');
    ok(await has(p, '#pane', /no sign-in 90 days/), 'the dormant account is flagged');
    await p.click('[data-act="keepall"]'); await Promise.all([p.waitForResponse((r) => /\/decide$/.test(r.url())), p.click('[data-act="save"]')]);
    ok(await has(p, '#savemsg', /dormant/), 'a dormant account is not kept without a reason');
    const kh = await p.$('#pane tr[data-item]:has-text("khalid.harbi")');
    await (await kh.$('input[value=remove]')).check(); await (await kh.$('input[type=text]')).fill('moved to Finance in August');
    await p.check('#stmt');
    await Promise.all([p.waitForResponse((r) => /\/sign$/.test(r.url())), p.click('[data-act="sign"]')]);
    ok(await has(p, '#pane', /signed - locked/), 'signed and locked');
    // an administrator approves the removal
    await as(p, { user: 'syed', role: 'admin' });
    await p.click('[data-tab="removals"]'); await p.waitForSelector('#arrem', { timeout: 8000 });
    await p.check('[data-pick="pend"]'); await p.selectOption('#arrem [name=decision]', 'approve');
    await Promise.all([p.waitForResponse((r) => /removals\/decide$/.test(r.url())), p.click('#arrem [type=submit]')]);
    await p.waitForTimeout(500);
    const mem = dir.vals(dir.get('CN=GG-Claims-Users,' + GR), 'member');
    ok(mem.length === 1 && /Sara/.test(mem[0]), 'removed in the directory');
    await p.click('[data-tab="report"]'); await p.waitForSelector('[data-act="export"]', { timeout: 8000 });
    ok(await has(p, '#pane', /nadia\.syn \(2 lines/), 'the attestation is in the report');
    const [dl] = await Promise.all([p.waitForEvent('download'), p.click('[data-act="export"]')]);
    ok(dl.suggestedFilename() === 'access-review-AR-' + require(path.join(ITAM, 'engine', 'access-reviews')).quarterOf(Date.now()) + '.csv', 'evidence CSV');
    ok(e.app.store.auditTail(300).some((a) => a.action === 'access-reviews.export'), 'the export is audited');
    WHO = { user: 'vera.syn', role: 'viewer' }; await Promise.all([p.waitForResponse((r) => /\/api\/itam\/access-reviews$/.test(r.url())), p.reload()]); await p.waitForTimeout(300);
    ok(!(await p.$('#tabs')), 'a viewer sees no review');
    const nav = fs.readFileSync(path.join(DASH, 'vendor', 'zyb-nav.js'), 'utf8');
    ok(/"h": "access-reviews\.html"/.test(nav) && nav.indexOf('access-reviews.html') < nav.indexOf('"h": "nhi.html"'), 'in the Identity menu');
  } finally { await browser.close(); srv.close(); e.close(); ldap.close(); fs.rmSync(tmp, { recursive: true, force: true }); }
  ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks');
  process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
