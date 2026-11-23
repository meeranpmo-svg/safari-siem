// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for the Implementation Roadmap pages (pdpl- / ndmo- / iso- / nca- / sama-roadmap.html, vendor/zyb-roadmap.js)
// against the REAL ITAM engine (engine/impl-roadmap.js), SYNTHETIC data only: each of the five pages loads its framework; the
// empty state invents nothing; a measured task follows the records; a phase tile filters; the task dialog saves owner, due date
// and evidence (audited) and refuses "done" without evidence; a manual task is set to done; an administrator sets the target; a
// viewer sees no form; a hostile owner name stays text; every page is in the menu.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node impl-roadmap.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const ITAM = path.join(__dirname, '..', '..', 'backend', 'itam'), DASH = path.join(__dirname, '..', '..', 'ui');
const H = require(path.join(ITAM, 'tests', 'helpers'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const XSS = '<img src=x onerror=alert(1)>';

(async () => {
  const e = await H.startApp({ noAi: true });
  require(path.join(ITAM, 'engine/duty')).registerDuty(e.app.srv, e.app, { noTimer: true, python: process.env.PYTHON || 'python3' });
  const c = (x) => e.app.store.collection(x);
  c('iso_profile').put({ id: 'profile', top_management: 'CEO (synthetic)', isms_manager: 'isms.syn', scope: 'Head office IT (synthetic)' });
  c('ecc_profile').put({ id: 'profile', ciso_user: 'ciso.syn', strategy_approved: '2026-02-01' });
  let WHO = { user: 'syed', role: 'admin' };
  const srv = http.createServer((req, res) => {
    const u2 = new URL(req.url, 'http://x'), json = (code, b2) => { res.writeHead(code, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b2)); };
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
  const has = (p, sel, re) => p.waitForFunction((a) => new RegExp(a[1], 'i').test((document.querySelector(a[0]) || {}).textContent || ''), [sel, re.source], { timeout: 10000 }).then(() => true, () => false);
  try {
    const p = await browser.newPage({ viewport: { width: 1400, height: 1000 } }); p.on('pageerror', (x) => errs.push(x.message));
    // every page loads its own framework
    for (const [fw, name, first] of [['pdpl', 'PDPL', /Appoint the Data Protection Officer/], ['ndmo', 'NDMO', /Chief Data Officer/], ['iso', 'ISO\\/IEC 27001', /ISMS manager/], ['nca', 'NCA ECC', /head of cybersecurity/], ['sama', 'SAMA', /Appoint the CISO/]]) {
      await p.goto(base + fw + '-roadmap.html?standalone=1');
      ok(await has(p, '#lead', new RegExp(name)), fw + ': lead names the framework');
      ok(await has(p, '#tasks', first), fw + ': first task listed');
      ok(await has(p, '#fc', /needs 2 weeks/), fw + ': forecast withheld without history');
    }
    // ISO: measured tasks follow the records
    await p.goto(base + 'iso-roadmap.html?standalone=1'); await p.waitForSelector('.tk[data-task="i-lead"]');
    ok(/done/.test(await p.textContent('.tk[data-task="i-lead"]')), 'ISO: leadership measured done from the profile');
    ok(/written, not approved/.test(await p.textContent('.tk[data-task="i-scope"]')), 'ISO: scope half done');
    // phase filter
    await p.click('#phases [data-ph="Assure"]');
    const ids = await p.$$eval('#tasks .tk', (L) => L.map((x) => x.getAttribute('data-task')));
    ok(ids.length > 0 && ids.every((i) => ['i-audit', 'i-nc', 'i-mr', 'i-cert'].includes(i)), 'phase tile filters: ' + ids.join(','));
    await p.click('#phases [data-ph="Assure"]');
    // NCA: dialog - done without evidence refused, then owner / due / evidence saved
    await p.goto(base + 'nca-roadmap.html?standalone=1'); await p.waitForSelector('.tk[data-task="e-aware"]');
    await p.click('.tk[data-task="e-aware"]'); await p.waitForSelector('#dlg[open] #f-st');
    await p.selectOption('#f-st', 'done'); await p.click('#dlgok');
    ok(await has(p, 'body', /Evidence: say where/), 'done without evidence refused on the page');
    await p.fill('#f-ow', 'owner.syn ' + XSS); await p.fill('#f-du', '2027-01-15'); await p.fill('#f-ev', 'Awareness plan AW-2026 (synthetic)');
    await Promise.all([p.waitForResponse((r) => /\/impl\/nca\/task\/e-aware$/.test(r.url())), p.click('#dlgok')]);
    ok(await has(p, '.tk[data-task="e-aware"]', /done/), 'manual task set to done');
    ok((await p.textContent('.tk[data-task="e-aware"]')).includes(XSS) && !(await p.$('#tasks img')), 'a hostile owner stays text');
    ok(await has(p, '.tk[data-task="e-aware"]', /due 2027-01-15/), 'due date shown');
    // admin target
    await p.fill('#tg', '2027-06-30'); await Promise.all([p.waitForResponse((r) => /\/impl\/nca\/target$/.test(r.url())), p.click('#tgs')]);
    ok(await has(p, '#kk', /2027-06-30/), 'target set by the administrator');
    // viewer: no form, no target setter
    WHO = { user: 'vera.syn', role: 'viewer' }; await p.reload(); await p.waitForSelector('.tk[data-task="e-head"]');
    ok(!(await p.$('#tg')), 'viewer: no target setter');
    await p.click('.tk[data-task="e-head"]'); await p.waitForSelector('#dlg[open]');
    ok(!(await p.$('#f-st')) && await p.$eval('#dlgok', (b) => b.hidden), 'viewer: no form in the dialog');
    // audit and the menu
    const au = e.app.store.auditTail(100).filter((a) => /^impl\./.test(a.action));
    ok(au.some((a) => a.action === 'impl.task' && a.target === 'nca:e-aware' && a.by === 'syed'), 'task update audited');
    ok(au.some((a) => a.action === 'impl.target' && a.target === 'nca'), 'target audited: ' + JSON.stringify(au.map((a) => a.target)));
    const nav = fs.readFileSync(path.join(DASH, 'vendor', 'zyb-nav.js'), 'utf8'), inst = fs.readFileSync(path.join(DASH, 'install-dashboards.sh'), 'utf8');
    for (const fw of ['pdpl', 'ndmo', 'iso', 'nca', 'sama']) { ok(nav.includes('"' + fw + '-roadmap.html"'), fw + ' roadmap in the menu'); ok(inst.includes(fw + '-roadmap.html'), fw + ' roadmap installed'); }
    ok(inst.includes('vendor/zyb-roadmap.js'), 'shared script installed');
    ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  } finally { await browser.close(); srv.close(); await e.close(); }
  console.log((bad ? 'FAILED ' : 'ok ') + (n - bad) + '/' + n);
  process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
