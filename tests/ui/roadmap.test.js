// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Remediation Roadmap (roadmap.html) against the REAL ITAM engines (crosswalk over the NCA ECC register + GRC registers + engine/roadmap.js)
// with SYNTHETIC facts and SYNTHETIC GRC actions: KPIs; six lanes; framework chips, owner filter and search; an item's detail with its
// slip risk; setting a due date moves it between lanes; pace, capacity, slip and the proposal; accepting a proposal schedules the item; a
// viewer sees no controls; the planner off until allowed; menu entry, installer, the portal's roadmap redirect.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node roadmap.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const ITAM = path.join(__dirname, '..', '..', 'backend', 'itam'), DASH = path.join(__dirname, '..', '..', 'ui');
const H = require(path.join(ITAM, 'tests', 'helpers'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const FACTS = () => ({ grc: { available: true, total: 20, reviews_overdue: 3, attested: 18, policies: [{ title: 'Information Security Policy (synthetic)', status: 'Approved', next_review: '2027-06-01' }], control_status: {} },
  risk: { available: true, total: 8, review_overdue: 0, actions_open: 3, actions_overdue: 0 }, ownership: { available: true, assets: 40, missing_it: 0, missing_business: 0 }, training_12m: 2 });

(async () => {
  const e = await H.startApp({ noAi: true });
  require(path.join(ITAM, 'engine/duty')).registerDuty(e.app.srv, e.app, { noTimer: true, python: process.env.PYTHON || 'python3', eccFacts: async () => FACTS() });
  let WHO = { user: 'nora.syn', role: 'operator' };
  const DAY = 86400000, d = (k) => new Date(Date.now() + k * DAY).toISOString().slice(0, 10), ts = (k) => new Date(Date.now() + k * DAY).toISOString();
  const acts = e.app.store.collection('grc_actions');
  const seed = (id, o) => acts.put(Object.assign({ id, title: 'Synthetic action ' + id, source: 'manual', ref: '', priority: 'medium', status: 'open', owner: '', due: null, framework: '', evidence: [], history: [], created_by: 'seed', created_at: ts(-200) }, o));
  [['ACT-9001', 'nora.syn', -60, -50, -40], ['ACT-9002', 'nora.syn', -50, -45, -30], ['ACT-9003', 'omar.syn', -40, -20, -25], ['ACT-9004', 'omar.syn', -60, -30, -35]]
    .forEach(([id, owner, c, due, cl]) => seed(id, { owner, created_at: ts(c), due: d(due), status: 'closed', closed_at: ts(cl), done_by: owner, closed_by: 'syed' }));
  seed('ACT-9011', { title: 'Synthetic: renew the firewall support contract', owner: 'nora.syn', due: d(5), framework: 'SAMA CSF' });
  seed('ACT-9012', { title: 'Synthetic: rotate the backup service password', owner: 'lina.syn', due: d(-5), priority: 'low' });
  seed('ACT-9013', { title: 'Synthetic: write the patch exception procedure', priority: 'high', framework: 'ISO 27001' });
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
    const ctx = await browser.newContext({ viewport: { width: 1600, height: 1000 } });
    let p = await page(ctx, 'roadmap.html');
    ok(/Open items/.test(await p.textContent('#kpis')) && /Backlog cleared/.test(await p.textContent('#kpis')), 'KPIs');
    ok(await p.$$eval('#lanes .lane', (x) => x.length === 6), 'six lanes');
    ok(/ACT-9012/.test(await p.textContent('#lanes .lane.overdue')), 'overdue lane');
    ok(/ACT-9013/.test(await p.textContent('#lanes .lane.unscheduled')) && /ECC:/.test(await p.textContent('#lanes .lane.unscheduled')), 'unscheduled: an action and framework gaps');
    ok(/ACT-9001/.test(await p.textContent('#lanes .lane.done')), 'closed in the last 90 days');
    await p.click('[data-fw="iso"]'); ok(await wait(p, () => /ACT-9013/.test(document.getElementById('lanes').textContent) && !/ACT-9012/.test(document.getElementById('lanes').textContent)), 'framework chip');
    await p.click('[data-fw=""]'); await p.selectOption('#own', 'lina.syn'); ok(await wait(p, () => [...document.querySelectorAll('#lanes .it')].length === 1 && /ACT-9012/.test(document.getElementById('lanes').textContent)), 'owner filter');
    await p.selectOption('#own', ''); await p.fill('#q', 'firewall support'); ok(await wait(p, () => [...document.querySelectorAll('#lanes .it')].length === 1), 'search');
    await p.fill('#q', '');
    ok(/Per week/.test(await p.textContent('#pace')) && /Median days to close/.test(await p.textContent('#pace')), 'pace and burn-down');
    ok(await p.$$eval('#cap .qbar', (x) => x.length === 4), 'capacity for four quarters');
    ok(/ACT-9011/.test(await p.textContent('#slip')) && /nora.syn/.test(await p.textContent('#slip')) && /\+20 points/.test(await p.textContent('#slip')), 'slip risk with its reason');
    ok(await p.$$eval('#prop [data-acc]', (x) => x.length > 0), 'a proposal to accept');
    await p.click('#lanes .lane.unscheduled [data-open^="action|ACT-9013"]'); ok(await wait(p, () => !document.getElementById('dlg').hidden && /ACT-9013/.test(document.getElementById('dlgb').textContent)), 'item detail');
    await p.fill('#dform [name=due]', d(120)); await p.click('#dform button[type=submit]');
    ok(await toast(p, 'ACT-9013 scheduled'), 'set a due date'); ok(await wait(p, () => !/ACT-9013/.test(document.querySelector('#lanes .lane.unscheduled').textContent) && /ACT-9013/.test(document.getElementById('lanes').textContent)), 'the item left Unscheduled');
    ok(acts.get('ACT-9013').due === d(120), 'the date is written on the GRC action');
    const first = await p.getAttribute('#prop [data-acc]', 'data-acc'); await p.click('#prop [data-acc]');
    ok(await toast(p, 'scheduled for'), 'accept a proposal'); ok(await wait(p, (id) => !document.querySelector('#lanes .lane.unscheduled').textContent.includes(id), first.split('|')[1]), 'the accepted item is scheduled');
    ok(/Not available/.test(await p.textContent('#ai')), 'planner off until allowed');
    if (process.env.SHOT) await p.screenshot({ path: process.env.SHOT, fullPage: true });   // optional: a picture for review
    WHO = { user: 'vera.syn', role: 'viewer' }; p = await page(ctx, 'roadmap.html');
    ok(!(await p.$('#prop [data-acc]')) && /operators and administrators/.test(await p.textContent('#ai')), 'a viewer cannot schedule or ask');
    await p.click('#lanes .it'); ok(await wait(p, () => !document.getElementById('dlg').hidden) && !(await p.$('#dform')), 'a viewer sees detail without the date form');
    const nav = fs.readFileSync(path.join(DASH, 'vendor', 'zyb-nav.js'), 'utf8');
    ok(/"h": "roadmap.html"/.test(nav) && /roadmap\.html/.test(fs.readFileSync(path.join(DASH, 'install-dashboards.sh'), 'utf8')), 'menu entry and installer');
    ok(/[ ,]roadmap: 'roadmap\.html'/.test(fs.readFileSync(path.join(DASH, 'vendor', 'zyb-menu.js'), 'utf8')) && /[ ,]roadmap: 'roadmap\.html'/.test(fs.readFileSync(path.join(DASH, 'vendor', 'zyb-early.js'), 'utf8')), 'the portal roadmap view opens this page');
    ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  } finally { await browser.close(); srv.close(); await e.close(); }
  console.log((bad ? 'FAILED ' : 'ok ') + (n - bad) + '/' + n);
  process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
