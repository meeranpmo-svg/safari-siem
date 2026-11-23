// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// ISO 27001 Lifecycle (iso-lifecycle.html) against the REAL ITAM engines (ISO 27001 register + engine/iso-lifecycle.js) with SYNTHETIC facts:
// progress ring and KPIs; the nine-phase roadmap with the current phase; a phase's criteria with their clause and why; the ISMS manager sets
// the plan and records Stage 1 then Stage 2 (the certificate is issued, surveillance 1 becomes the next audit with its due date); the
// forecast against the plan; an operator who is not the ISMS manager sees no forms; a hostile certification-body name stays text; menu
// entry, installer, the portal's iso redirect.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node iso-lifecycle.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const ITAM = path.join(__dirname, '..', '..', 'backend', 'itam'), DASH = path.join(__dirname, '..', '..', 'ui');
const H = require(path.join(ITAM, 'tests', 'helpers'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const FACTS = () => ({ grc: { available: true, total: 20, reviews_overdue: 0, attested: 18, policies: [{ title: 'Information Security Policy (synthetic)', status: 'Approved', next_review: '2027-06-01' }], control_status: {} },
  risk: { available: true, total: 8, review_overdue: 0, actions_open: 3, actions_overdue: 0 }, ownership: { available: true, assets: 40, missing_it: 0, missing_business: 0 }, training_12m: 2 });

(async () => {
  const e = await H.startApp({ noAi: true });
  require(path.join(ITAM, 'engine/duty')).registerDuty(e.app.srv, e.app, { noTimer: true, python: process.env.PYTHON || 'python3', eccFacts: async () => FACTS() });
  const r0 = await e.req('POST', '/iso27001/profile', { body: { isms_manager: 'mona.syn', top_management: 'CEO (synthetic)' }, user: 'syed', role: 'admin' }); if (r0.status !== 200) throw new Error(r0.raw);
  let WHO = { user: 'mona.syn', role: 'operator' };
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
    let p = await page(ctx, 'iso-lifecycle.html');
    ok(/criteria met/.test(await p.textContent('#ring')), 'progress ring');
    ok(await p.$$eval('#road .ph', (x) => x.length === 9), 'nine phases');
    ok(await p.$eval('#road .ph.done', (x) => /Initiate/.test(x.textContent)), 'initiate done (ISMS manager and sponsor named)');
    ok(await p.$eval('#road .ph.cur', (x) => /Context/.test(x.textContent)), 'the current phase is Context & scope');
    ok(/4\.3 Determining the scope/.test(await p.textContent('#phd')) && /clause 4\.3/.test(await p.textContent('#phd')), 'current phase criteria with their clause');
    await p.click('[data-ph="implement"]'); ok(await wait(p, () => /Annex A/.test(document.getElementById('phd').textContent)), 'clicking a phase shows its criteria');
    await p.fill('#pform [name=target_stage1]', '2027-02-01'); await p.fill('#pform [name=target_stage2]', '2027-04-01'); await p.click('#pform button[type=submit]');
    ok(await toast(p, 'Plan saved'), 'the ISMS manager saves the plan');
    ok(await wait(p, () => /Planned Stage 2/.test(document.getElementById('fc').textContent)), 'the forecast is set against the plan');
    await p.selectOption('#cform [name=event]', 'stage1'); await p.fill('#cform [name=date]', '2025-08-01'); await p.fill('#cform [name=body]', 'Synthetic CB <img src=x onerror="window.__xss=1">'); await p.selectOption('#cform [name=result]', 'minor'); await p.fill('#cform [name=minor]', '2');
    await p.click('#cform button[type=submit]'); ok(await toast(p, 'Certification audit recorded'), 'Stage 1 recorded');
    ok(await wait(p, () => /Stage 2 next/.test(document.getElementById('cyc').textContent)), 'Stage 2 is next');
    await p.selectOption('#cform [name=event]', 'stage2'); await p.fill('#cform [name=date]', '2025-09-01'); await p.fill('#cform [name=body]', 'Synthetic CB'); await p.selectOption('#cform [name=result]', 'recommended');
    await p.click('#cform button[type=submit]'); ok(await wait(p, () => /Certificate issued 2025-09-01/.test(document.getElementById('cert').textContent) && /expires 2028-09-01/.test(document.getElementById('cert').textContent)), 'the certificate is issued for three years');
    ok(/due 2026-09-01/.test(await p.textContent('#cyc')), 'surveillance 1 due 12 months after the certificate');
    ok(await p.evaluate(() => !window.__xss && /<img src=x/.test(document.getElementById('cyc').textContent)), 'a hostile certification-body name stays text');
    if (process.env.SHOT) await p.screenshot({ path: process.env.SHOT, fullPage: true });   // optional: a picture for review
    WHO = { user: 'nora.syn', role: 'operator' }; p = await page(ctx, 'iso-lifecycle.html');
    ok(!(await p.$('#cform')) && !(await p.$('#pform')) && /ISMS manager or an administrator records/.test(await p.textContent('#cert')), 'an operator who is not the ISMS manager sees no forms');
    const nav = fs.readFileSync(path.join(DASH, 'vendor', 'zyb-nav.js'), 'utf8');
    ok(/"h": "iso-lifecycle.html"/.test(nav) && /iso-lifecycle\.html/.test(fs.readFileSync(path.join(DASH, 'install-dashboards.sh'), 'utf8')), 'menu entry and installer');
    ok(/[ ,]iso: 'iso-lifecycle\.html'/.test(fs.readFileSync(path.join(DASH, 'vendor', 'zyb-menu.js'), 'utf8')) && /[ ,]iso: 'iso-lifecycle\.html'/.test(fs.readFileSync(path.join(DASH, 'vendor', 'zyb-early.js'), 'utf8')), 'the portal ISO 27001 view opens this page');
    ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  } finally { await browser.close(); srv.close(); await e.close(); }
  console.log((bad ? 'FAILED ' : 'ok ') + (n - bad) + '/' + n);
  process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
