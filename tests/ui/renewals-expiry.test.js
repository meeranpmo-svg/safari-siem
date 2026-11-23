// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for dashboards/server/renewals-expiry.html against the REAL ITAM engine (engine/expiry-hub.js through duty.js) with
// SYNTHETIC records in the owning modules: KPIs, 12-month calendar (a month filters), kind and state chips, risk-ranked list, the
// drawer explains the risk point by point; owner set, renewed needs a reference and stays 'claimed' until the source shows the new
// date, then 'renewed'; viewers see no money and cannot track; escaped; menu + installer.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node asset-autofill.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const ITAM = path.join(__dirname, '..', '..', 'backend', 'itam'), DASH = path.join(__dirname, '..', '..', 'ui');
const H = require(path.join(ITAM, 'tests', 'helpers'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const ADM = { user: 'syed', role: 'admin' }, OP = { user: 'nora.syn', role: 'operator' }, VW = { user: 'vera.syn', role: 'viewer' };
const XSS = '<img src=x onerror="window.__xss=1">';

(async () => {
  const e = await H.startApp({ noAi: true });
  require(path.join(ITAM, 'engine/duty')).registerDuty(e.app.srv, e.app, { noTimer: true });
  const C = (n) => e.app.store.collection(n), inD = (n) => new Date(Date.now() + n * 86400000).toISOString().slice(0, 10);
  C('licences').put({ id: 'lic1', product: 'SynSuite ' + XSS, expiry: inD(20), cost: 1000, status: 'active' });
  C('dom_domains').put({ id: 'd1', name: 'syn-example.test', expires: inD(-3), auto_renew: false, cost: 80 });
  C('cert_endpoints').put({ id: 'ep1', host: 'portal.syn.test', port: 443 }); C('cert_scans').put({ id: 'ep1', scan: { ok: true, subject: 'CN=portal.syn.test', not_after_iso: inD(5) } });
  C('support_contracts').put({ id: 'sc1', vendor: 'SynVendor', product: 'ProSupport', end: inD(200), cost: 5000, status: 'active', owner: 'infra.syn' });
  let WHO = OP;
  const web = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://x'), json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
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
  await new Promise((r) => web.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + web.address().port + '/dashboards/';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  const wait = (p, fn, arg) => p.waitForFunction(fn, arg, { timeout: 15000 }).then(() => true, () => false);
  const txt = (p, id) => p.evaluate((i) => document.getElementById(i).innerText, id);
  try {
    const p = await browser.newPage({ viewport: { width: 1500, height: 1000 } }); p.on('pageerror', (x) => errs.push(x.message));
    await p.goto(base + 'renewals-expiry.html');
    ok(await wait(p, () => /Expired/.test(document.getElementById('kp').innerText)), 'KPIs');
    ok(/Expired\s*1/i.test(await txt(p, 'kp')), 'one expired (the domain)');
    let list = await txt(p, 'list');
    ok(list.indexOf('syn-example.test') >= 0 && list.indexOf('syn-example.test') < list.indexOf('portal.syn.test'), 'the expired domain ranks first');
    ok(await p.evaluate(() => !window.__xss) && !(await p.$('#list img')), 'names escaped');
    ok(/1,000/.test(list), 'operators see costs');
    // kind chip
    await p.click('[data-kind="certificate"]'); list = await txt(p, 'list'); ok(/portal\.syn\.test/.test(list) && !/syn-example/.test(list), 'kind chip filters');
    await p.click('[data-kind=""]');
    // calendar month
    const m = new Date(Date.now() + 200 * 86400000).toISOString().slice(0, 7);
    await p.click('[data-mon="' + m + '"]'); ok(/ProSupport/.test(await txt(p, 'list')) && !/portal\.syn/.test(await txt(p, 'list')), 'a month filters');
    await p.click('[data-mon="' + m + '"]'); await p.click('[data-state="open"]');
    // drawer: risk explained, owner, renewed claim
    await p.evaluate(() => document.querySelector('[data-key="licence:lic1"]').click());
    ok(await wait(p, () => /no owner/.test(document.getElementById('drw').innerText)), 'drawer explains the risk');
    await p.fill('#t-owner', 'apps.syn'); await p.click('[data-act="owner"]'); ok(await wait(p, () => /Saved/.test(document.body.innerText)), 'owner set');
    await wait(p, () => document.getElementById('t-ref'));
    await p.click('[data-act="renewed"]'); ok(/reference is required/.test(await txt(p, 't-err')), 'renewed needs a reference');
    await p.fill('#t-ref', 'INV-SYN-1'); await p.fill('#t-new', inD(385)); await p.click('[data-act="renewed"]');
    ok(await wait(p, () => /waiting for Software & Licences to show the new date/.test(document.getElementById('drw').innerText)), 'a claim, not verified');
    C('licences').put(Object.assign(C('licences').get('lic1'), { expiry: inD(385) }));
    await p.click('#d-rf'); ok(await wait(p, () => /verified by Software & Licences/.test(document.getElementById('drw').innerText)), 'verified once the licence record moves');
    ok(e.app.store.auditTail(30).some((a) => a.action === 'expiry.verified'), 'verification audited');
    // viewer
    WHO = VW; await p.reload(); await wait(p, () => /Expired/.test(document.getElementById('kp').innerText));
    ok(!/1,000/.test(await txt(p, 'list')) && !/Cost next/.test(await txt(p, 'kp')), 'viewer sees no money');
    await p.evaluate(() => document.querySelector('[data-key="domain:d1"]').click()); await p.fill('#t-owner', 'x'); await p.click('[data-act="owner"]');
    ok(await wait(p, () => /Operators and administrators track renewals/.test(document.getElementById('t-err').innerText)), 'viewer cannot track');
    await p.close();
    const q = await browser.newPage(); await q.goto(base + 'lifecycle-studio.html'); await q.waitForTimeout(800);
    ok(await q.evaluate(() => !!document.querySelector('a[href="renewals-expiry.html"]')), 'menu entry'); await q.close();
    ok(/ renewals-expiry\.html /.test(fs.readFileSync(path.join(DASH, 'install-dashboards.sh'), 'utf8')), 'in the installer');
    ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  } finally { await browser.close(); web.close(); e.close(); }
  console.log(`${n - bad}/${n} checks passed`); process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
