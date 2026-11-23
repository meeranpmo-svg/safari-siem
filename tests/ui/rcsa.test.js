// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const ZYB_ORG = require('../../brand/index');
// Browser test for RCSA Collection (dashboards/server/rcsa.html + vendor/zyb-rcsa.js, and the public form served by the engine under
// /agent/rcsa/form) against the REAL ITAM engine, SYNTHETIC data only. The test server proxies /api/itam with an identity and /agent/
// WITHOUT one (as nginx does). Flow: the Risk team opens a campaign (owners from the register) and issues an owner link; the owner
// opens it by clicking a link on ANOTHER SITE (localhost -> 127.0.0.1: a real cross-site top-level navigation), sees only their own
// risk and the company logo, the token is stripped from the address bar, submits; nothing changes in the register; the Risk team
// sees the proposal beside the current rating and accepts it - the register changes; a revoked link no longer opens; a viewer is
// refused; the page is in the menu and the install list.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node rcsa.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const ITAM = path.join(__dirname, '..', '..', 'backend', 'itam'), DASH = path.join(__dirname, '..', '..', 'ui');
const H = require(path.join(ITAM, 'tests', 'helpers'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const XSS = '<img src=x onerror=alert(1)>';
const LOGO = 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==';

(async () => {
  const e = await H.startApp({ noAi: true });
  require(path.join(ITAM, 'engine/duty')).registerDuty(e.app.srv, e.app, { noTimer: true, python: process.env.PYTHON || 'python3' });
  const GR = e.app.addons.grcRegisters, RISK = { user: 'risk.syn', role: 'admin' };
  const r1 = GR.riskCreate({ title: 'Single-source procurement ' + XSS, description: 'Emergency buys without committee (synthetic)', category: 'operational', owner: 'proc.head', likelihood: 3, impact: 4, treatment: 'reduce' }, RISK);
  GR.riskCreate({ title: 'Key-person dependency', category: 'strategic', owner: 'hr.head', likelihood: 2, impact: 3, treatment: 'reduce' }, RISK);
  e.app.store.collection('pentest_settings').put({ id: 'report_brand', values: { org_name: (ZYB_ORG.short + ' (synthetic)'), letterhead: LOGO } });
  let WHO = RISK;
  const proxy = (req, res, withIdentity) => {
    const h = Object.assign({}, req.headers, { 'x-sentra-proxy-secret': H.SECRET });
    if (withIdentity) Object.assign(h, { 'x-auth-user': WHO.user, 'x-auth-role': WHO.role }); else { delete h['x-auth-user']; delete h['x-auth-role']; }
    const up = http.request({ host: '127.0.0.1', port: e.port, method: req.method, path: req.url, headers: h }, (r) => { res.writeHead(r.statusCode, r.headers); r.pipe(res); });
    req.pipe(up);
  };
  const srv = http.createServer((req, res) => {
    const u2 = new URL(req.url, 'http://x'), json = (code, b2) => { res.writeHead(code, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b2)); };
    if (u2.pathname === '/dashboards/whoami.json') return json(200, WHO);
    if (u2.pathname.startsWith('/api/itam/')) return proxy(req, res, true);
    if (u2.pathname.startsWith('/agent/')) return proxy(req, res, false);          // like nginx: no session, identity stripped
    if (u2.pathname.startsWith('/api/')) return json(404, { error: 'not in this test' });
    const f = path.join(DASH, u2.pathname.replace(/^\/dashboards\//, '/')); if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (err, d) => { if (err) { res.writeHead(404); res.end(); return; } res.writeHead(200, { 'Content-Type': u2.pathname.endsWith('.js') ? 'application/javascript' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const port = srv.address().port, base = 'http://127.0.0.1:' + port + '/';
  // "another site": a mail page on localhost (a different site from 127.0.0.1) carrying the owner's link
  let mailHref = '';
  const mail = http.createServer((req, res) => { res.writeHead(200, { 'Content-Type': 'text/html' }); res.end('<!doctype html><title>mail</title><a id="go" href="' + mailHref.replace(/"/g, '&quot;') + '">Open your assessment</a>'); });
  await new Promise((r) => mail.listen(0, '127.0.0.1', r));
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  const has = (p, sel, re) => p.waitForFunction((a) => new RegExp(a[1], 'i').test((document.querySelector(a[0]) || {}).textContent || ''), [sel, re.source], { timeout: 10000 }).then(() => true, () => false);
  try {
    const p = await browser.newPage({ viewport: { width: 1400, height: 1000 } }); p.on('pageerror', (x) => errs.push(x.message));
    await p.goto(base + 'rcsa.html?standalone=1'); await p.waitForSelector('#newb:not([hidden])');
    ok(await has(p, '#list', /No campaign yet/), 'empty state');
    await p.click('#newb'); await p.waitForSelector('#f-period'); await p.fill('#f-title', 'RCSA Q4 2026'); await p.fill('#f-period', '2026-Q4');
    await Promise.all([p.waitForResponse((r) => /\/rcsa$/.test(r.url()) && r.request().method() === 'POST'), p.click('#dlgok')]);
    ok(await has(p, '#owners', /proc\.head/) && await has(p, '#owners', /hr\.head/), 'owners taken from the register');
    // issue the link for proc.head and read it from the dialog
    await Promise.all([p.waitForResponse((r) => /\/link$/.test(r.url())), p.click('[data-link="proc.head"]')]);
    await p.waitForSelector('#lnk'); const link = (await p.textContent('#lnk')).trim();
    ok(/\/agent\/rcsa\/form#t=/.test(link), 'the link carries the token in the fragment: ' + link.slice(0, 60));
    ok(/mailto:/.test(await p.getAttribute('#mail', 'href')), 'an e-mail draft is offered');
    await p.click('#dlgx');
    // the owner clicks the link on another site (a real cross-site top-level navigation)
    mailHref = link;
    const o = await browser.newPage({ viewport: { width: 900, height: 1000 } }); o.on('pageerror', (x) => errs.push('owner: ' + x.message));
    let formReq = null; o.on('request', (rq) => { if (/\/agent\/rcsa\/form$/.test(rq.url().split('#')[0])) formReq = rq; });
    await o.goto('http://localhost:' + mail.address().port + '/'); await Promise.all([o.waitForNavigation(), o.click('#go')]);
    ok(await has(o, '#who', /proc\.head/), 'the owner page opens from another site');
    const fh = formReq ? await formReq.allHeaders() : {}; ok(/cross-site|same-site/.test(fh['sec-fetch-site'] || '') && fh['sec-fetch-mode'] === 'navigate', 'it really was a navigation from another site: ' + fh['sec-fetch-site'] + ' / ' + fh['sec-fetch-mode']);
    ok(!/#t=/.test(o.url()), 'the token is stripped from the address bar');
    ok(await o.$eval('#logo', (i) => !i.hidden && /^data:image\/png/.test(i.src)), 'the company logo is on the owner page');
    ok(await has(o, '#org', new RegExp(ZYB_ORG.short + ' \\(synthetic\\)')), 'the company name');
    const titles = await o.$$eval('#risks h2', (L) => L.map((x) => x.textContent));
    ok(titles.length === 1 && titles[0].includes(XSS) && !(await o.$('#risks img')), 'only the owner\'s own risk, hostile title stays text');
    await o.selectOption('#l0', '5'); await o.selectOption('#m0', '5'); await o.fill('#c0', 'Committee approval above SAR 100k'); await o.fill('#k0', 'More emergency buys this quarter (synthetic)');
    await Promise.all([o.waitForResponse((r) => /\/agent\/rcsa\/submit$/.test(r.url())), o.click('#send')]);
    ok(await has(o, '#msg', /Thank you/), 'the owner sees the confirmation');
    ok(GR.riskList().items.find((x) => x.id === r1.id).likelihood === 3, 'the register is unchanged by the submission');
    // the Risk team reviews and accepts
    await p.click('#refresh'); await p.waitForSelector('[data-accept]');
    ok(await has(p, '#resp', /L 3 → 5/) && await has(p, '#resp', /Committee approval/), 'the proposal beside the current rating');
    await Promise.all([p.waitForResponse((r) => /\/accept$/.test(r.url())), p.click('[data-accept]')]);
    ok(await has(p, '#resp', /accepted/), 'accepted');
    ok(GR.riskList().items.find((x) => x.id === r1.id).likelihood === 5, 'the register now carries the new rating');
    // revoke: the link stops working
    await Promise.all([p.waitForResponse((r) => /\/revoke$/.test(r.url())), p.click('[data-revoke]')]);
    const o2 = await browser.newPage(); await o2.goto(link); ok(await has(o2, '#msg', /revoked/), 'a revoked link shows why it no longer opens');
    // viewer refused
    WHO = { user: 'vera.syn', role: 'viewer' }; await p.reload(); ok(await has(p, '#err', /internal/i), 'a viewer is refused');
    const nav = fs.readFileSync(path.join(DASH, 'vendor', 'zyb-nav.js'), 'utf8'), inst = fs.readFileSync(path.join(DASH, 'install-dashboards.sh'), 'utf8');
    ok(nav.includes('"rcsa.html"') && inst.includes('rcsa.html') && inst.includes('vendor/zyb-rcsa.js'), 'in the menu and installed');
    ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  } finally { await browser.close(); srv.close(); mail.close(); await e.close(); }
  console.log((bad ? 'FAILED ' : 'ok ') + (n - bad) + '/' + n);
  process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
