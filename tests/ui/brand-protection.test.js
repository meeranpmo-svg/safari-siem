// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for Brand Protection (dashboards/server/brand-protection.html) against the REAL ITAM engine (engine/brand-protect.js) with
// a stubbed network (SYNTHETIC look-alikes): no official domain says where to add one; Scan now; exposure ring and KPIs; findings
// (high-risk look-alike, new look-alike certificate); look-alike table with chips and search; detail with itemised reasons and triage;
// opening a case from a look-alike and moving it on the board (provider asked); weekly trend; CT list; settings (admin); viewer sees no
// Scan / triage / case buttons; AI off says why; Excel; a hostile page title stays text; no sample data; menu entry and redirect.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node brand-protection.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const ITAM = path.join(__dirname, '..', '..', 'backend', 'itam'), DASH = path.join(__dirname, '..', '..', 'ui');
const H = require(path.join(ITAM, 'tests', 'helpers'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const XSS = '<img src=x onerror="window.__xss=1">', DAY = 86400000, NOW = Date.now();
const SITES = {
  'corpgroup-test-login.com': { a: ['198.51.100.10'], mx: [{ exchange: 'mx.evil.test' }], cert: { issuer: "Let's Encrypt", from: new Date(NOW - 3 * DAY).toISOString() }, page: { status: 200, title: 'Corpgroup Test - Sign in ' + XSS, body: 'corpgroup-test password otp' } },
  'corpgroup-test.net': { a: ['198.51.100.11'], page: { status: 200, title: 'This domain is for sale', body: 'sedo' } },
  'corpgrouptest.com': { a: ['198.51.100.12'], page: { status: 200, title: 'Garden tools shop', body: 'shovels' } },
};
const s = (d) => SITES[d] || {};
const net = { resolve4: async (d) => s(d).a || [], resolveNs: async () => [], resolveMx: async (d) => s(d).mx || [], cert: async (h) => s(h).cert || null, page: async (h) => s(h).page || null,
  ct: async (d) => (d === 'corpgroup-test-login.com' ? [{ id: 9001, name_value: 'corpgroup-test-login.com', issuer_name: "O=Let's Encrypt", not_before: new Date(NOW - 2 * DAY).toISOString() }] : []) };

(async () => {
  const e = await H.startApp({ noAi: true });
  require(path.join(ITAM, 'engine/duty')).registerDuty(e.app.srv, e.app, { noTimer: true, bpNet: net });
  let WHO = { user: 'syed', role: 'admin' };
  const srv = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://x'), json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u.pathname === '/dashboards/whoami.json') return json(200, WHO);
    if (u.pathname.startsWith('/api/itam/')) {
      const h = Object.assign({}, req.headers, { 'x-sentra-proxy-secret': H.SECRET, 'x-auth-user': WHO.user, 'x-auth-role': WHO.role });
      const up = http.request({ host: '127.0.0.1', port: e.port, method: req.method, path: req.url, headers: h }, (r) => { res.writeHead(r.statusCode, r.headers); r.pipe(res); });
      req.pipe(up); return;
    }
    if (u.pathname.startsWith('/api/')) return json(404, { error: 'not in this test' });
    const f = path.join(DASH, u.pathname.replace(/^\/dashboards\//, '')); if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (err, d) => { if (err) { res.writeHead(404); return res.end(); } res.writeHead(200, { 'Content-Type': f.endsWith('.js') ? 'application/javascript' : f.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const url = 'http://127.0.0.1:' + srv.address().port + '/dashboards/brand-protection.html?standalone=1';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright'); const browser = await chromium.launch(), errs = [];
  const wait = (p, fn, arg) => p.waitForFunction(fn, arg, { timeout: 20000 }).then(() => true, () => false);
  try {
    const ctx = await browser.newContext({ viewport: { width: 1500, height: 1000 }, acceptDownloads: true });
    const p = await ctx.newPage(); p.on('pageerror', (x) => errs.push(x.message)); p.on('dialog', (d) => d.accept('Registrar abuse desk'));
    await p.goto(url); ok(await wait(p, () => /Add the company domains in Domains & Hosting/.test(document.getElementById('findings').textContent)), 'no official domain says where to add one');
    ok(!/BP-\d/.test(await p.textContent('#board')), 'no sample cases');
    e.app.store.collection('dom_domains').put({ id: 'D1', name: 'corpgroup-test.com', status: 'active' });
    await p.fill('#s-k', 'corpgroup-test'); await p.fill('#s-t', 'net, sa'); await p.click('#s-save'); ok(await wait(p, () => /Saved/.test(document.body.textContent)), 'settings saved');
    await p.fill('#wd', 'corpgroup-test-login.com'); await p.click('#watch'); ok(await wait(p, () => /Watching corpgroup-test-login/.test(document.body.textContent)), 'watch a domain');
    await p.click('#scan'); ok(await wait(p, () => /registered/.test(document.body.textContent) && document.querySelectorAll('tr[data-dom]').length >= 3), 'scan then look-alikes');
    if (process.env.SHOT) await p.screenshot({ path: process.env.SHOT, fullPage: true });   // optional: a picture for review
    const f = await p.textContent('#findings'); ok(/corpgroup-test-login\.com imitates the brand/.test(f) && /New TLS certificate for look-alike/.test(f), 'findings: high-risk look-alike and new certificate');
    ok(/High risk/.test(await p.textContent('#kpis')) && /\d+/.test(await p.textContent('#ring')), 'exposure ring and KPIs');
    ok((await p.$$('#tr1 i')).length === 9, 'weekly trend');
    ok(/look-alike/.test(await p.textContent('#ct')), 'certificate transparency list');
    await p.click('#chips [data-f="high"]'); ok(await wait(p, () => document.querySelectorAll('tr[data-dom]').length === 1), 'High chip');
    await p.click('tr[data-dom="corpgroup-test-login.com"]'); ok(await wait(p, () => !document.getElementById('dlg').hidden && /mail servers - can send phishing/.test(document.getElementById('dlg').textContent)), 'detail with itemised reasons');
    await p.click('[data-tri="confirmed"]'); ok(await wait(p, () => /the model learns/.test(document.body.textContent)), 'triage');
    await p.click('tr[data-dom="corpgroup-test-login.com"]'); await p.click('[data-case-dom]'); ok(await wait(p, () => /BP-0001/.test(document.getElementById('board').textContent)), 'case opened from the look-alike');
    await p.click('[data-case="BP-0001"][data-to="validated"]'); await wait(p, () => /Validated \(1\)/.test(document.getElementById('board').textContent));
    await p.click('[data-case="BP-0001"][data-to="takedown_requested"]'); ok(await wait(p, () => /Takedown requested \(1\)/.test(document.getElementById('board').textContent) && /Registrar abuse desk/.test(document.getElementById('board').textContent)), 'case moved with the provider named');
    ok(/analyst is off/.test(await p.textContent('#ai')), 'AI off says why');
    const [dl] = await Promise.all([p.waitForEvent('download', { timeout: 10000 }), p.click('#xls')]);
    ok(/^brand-protection-\d{4}-\d{2}-\d{2}\.xlsx$/.test(dl.suggestedFilename()), 'Excel export');
    ok(!(await p.evaluate(() => window.__xss)), 'hostile page title stayed text');
    WHO = { user: 'vera.syn', role: 'viewer' }; const q = await ctx.newPage(); await q.goto(url); await wait(q, () => document.querySelectorAll('tr[data-dom]').length >= 1);
    ok(!(await q.isVisible('#scan')) && !(await q.$('[data-case]')) && !(await q.isVisible('#setcard')), 'viewer: no Scan, case moves or settings');
    const nav = fs.readFileSync(path.join(DASH, 'vendor', 'zyb-nav.js'), 'utf8');
    ok(/"h": "brand-protection.html"/.test(nav) && /brand-protection\.html/.test(fs.readFileSync(path.join(DASH, 'install-dashboards.sh'), 'utf8')), 'menu entry and installer');
    ok(/brandprot: 'brand-protection\.html'/.test(fs.readFileSync(path.join(DASH, 'vendor', 'zyb-menu.js'), 'utf8')) && /brandprot: 'brand-protection\.html'/.test(fs.readFileSync(path.join(DASH, 'vendor', 'zyb-early.js'), 'utf8')), 'the portal\'s Brand Protection opens this page');
    ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  } finally { await browser.close(); srv.close(); await e.close(); }
  console.log((bad ? 'FAILED ' : 'ok ') + (n - bad) + '/' + n);
  process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
