// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// NCA ECC Compliance Studio (ecc-studio.html) against the REAL ITAM engines (NCA ECC register + engine/nca-ecc-intel.js) with SYNTHETIC
// facts: fully-compliant ring, KPIs and the stacked shares; five domains with their subdomains by NCA level; priorities ranked with the
// kind of work, the kind chips, the domain filter and search; leverage; regressions said honestly before any snapshot; the administrator
// sets the target; an operator cannot; the officer is off until allowed; menu entry, installer, the portal's ecc redirect.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node ecc-studio.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const ITAM = path.join(__dirname, '..', '..', 'backend', 'itam'), DASH = path.join(__dirname, '..', '..', 'ui');
const H = require(path.join(ITAM, 'tests', 'helpers'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const FACTS = () => ({ grc: { available: true, total: 20, reviews_overdue: 0, attested: 18, policies: [{ title: 'Information Security Policy (synthetic)', status: 'Approved', next_review: '2027-06-01' }], control_status: {} },
  risk: { available: true, total: 8, review_overdue: 0, actions_open: 3, actions_overdue: 0 }, ownership: { available: true, assets: 40, missing_it: 0, missing_business: 0 }, training_12m: 2 });

(async () => {
  const e = await H.startApp({ noAi: true });
  require(path.join(ITAM, 'engine/duty')).registerDuty(e.app.srv, e.app, { noTimer: true, python: process.env.PYTHON || 'python3', eccFacts: async () => FACTS() });
  let WHO = { user: 'nora.syn', role: 'operator' };
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
  const base = 'http://127.0.0.1:' + srv.address().port + '/dashboards/';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright'); const browser = await chromium.launch(), errs = [];
  const wait = (p, fn, arg) => p.waitForFunction(fn, arg, { timeout: 30000 }).then(() => true, () => false);
  const toast = (p, re) => wait(p, (s) => [...document.querySelectorAll('.toast')].some((t) => new RegExp(s).test(t.textContent)), re);
  let ANS = [];
  const page = async (ctx, f) => { const p = await ctx.newPage(); p.on('pageerror', (x) => errs.push(x.message)); p.on('dialog', (d) => { const a = ANS.shift(); if (a === undefined) { errs.push('unexpected dialog: ' + d.message()); d.dismiss(); } else d.accept(a); }); await p.goto(base + f + '?standalone=1'); await p.waitForSelector('#main:not([hidden])', { timeout: 60000 }); return p; };
  try {
    const ctx = await browser.newContext({ viewport: { width: 1500, height: 1000 } });
    let p = await page(ctx, 'ecc-studio.html');
    ok(/fully compliant/.test(await p.textContent('#ring')), 'fully-compliant ring');
    ok(/Quick wins/.test(await p.textContent('#kpis')) && /Sources connected/.test(await p.textContent('#kpis')), 'KPIs');
    ok(await p.$$eval('#stack i', (x) => x.length >= 2), 'stacked NCA shares');
    ok(await p.$$eval('#hm .hd', (x) => x.length === 5) && await p.$$eval('#hm .sd', (x) => x.length === 29), 'five domains and 29 subdomains');
    const rows = await p.$$eval('#pri tbody tr', (x) => x.length); ok(rows > 10, 'priorities listed');
    await p.click('[data-kf="confirm"]'); ok(await wait(p, () => [...document.querySelectorAll('#pri tbody tr')].every((r) => /CONFIRM/.test(r.textContent)) && document.querySelectorAll('#pri tbody tr').length > 0), 'Confirm (quick win) chip');
    await p.click('[data-kf="all"]'); await p.selectOption('#dom', '2'); ok(await wait(p, () => [...document.querySelectorAll('#pri tbody tr')].every((r) => /\b2-\d+\b/.test(r.textContent))), 'domain filter');
    await p.selectOption('#dom', ''); await p.fill('#q', 'strategy'); ok(await wait(p, () => document.querySelectorAll('#pri tbody tr').length >= 1 && [...document.querySelectorAll('#pri tbody tr')].every((r) => /strategy/i.test(r.textContent))), 'search');
    ok(/controls/.test(await p.textContent('#lev')), 'leverage groups');
    ok(/first is taken today/.test(await p.textContent('#reg')), 'regressions said honestly before any snapshot');
    ok(/needs 3 daily snapshots/.test(await p.textContent('#trend')), 'the forecast rule is stated');
    ok(/administrators set it/.test(await p.textContent('#set')) && !(await p.$('#sform')), 'an operator cannot set the target');
    ok(/Not available/.test(await p.textContent('#ai')), 'officer off until allowed');
    WHO = { user: 'syed', role: 'admin' }; p = await page(ctx, 'ecc-studio.html');
    await p.fill('#sform [name=target_pct]', '85'); await p.fill('#sform [name=target_date]', '2027-06-30'); await p.click('#sform button[type=submit]');
    ok(await toast(p, 'Target saved'), 'the administrator sets the target');
    ok(await wait(p, () => /Target date/.test(document.getElementById('trend').textContent) && /2027-06-30/.test(document.getElementById('trend').textContent)), 'the target date is judged');
    if (process.env.SHOT) await p.screenshot({ path: process.env.SHOT, fullPage: true });   // optional: a picture for review
    const nav = fs.readFileSync(path.join(DASH, 'vendor', 'zyb-nav.js'), 'utf8');
    ok(/"h": "ecc-studio.html"/.test(nav) && /ecc-studio\.html/.test(fs.readFileSync(path.join(DASH, 'install-dashboards.sh'), 'utf8')), 'menu entry and installer');
    ok(/[ ,]ecc: 'ecc-studio\.html'/.test(fs.readFileSync(path.join(DASH, 'vendor', 'zyb-menu.js'), 'utf8')) && /[ ,]ecc: 'ecc-studio\.html'/.test(fs.readFileSync(path.join(DASH, 'vendor', 'zyb-early.js'), 'utf8')), 'the portal NCA ECC view opens this page');
    ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  } finally { await browser.close(); srv.close(); await e.close(); }
  console.log((bad ? 'FAILED ' : 'ok ') + (n - bad) + '/' + n);
  process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
