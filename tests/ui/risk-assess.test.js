// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Automated Risk Assessment (risk-assess.html) against the REAL ITAM engines (engine/risk-assess.js + GRC risk register) with a SYNTHETIC
// AI CISO overview: exposure ring and KPIs; heat map with residual / inherent; scenario cards with band chips; not-assessed said; a
// scenario's detail with itemised likelihood, controls, signals and register; proposing to the register; the administrator sets the
// appetite and impact; a viewer has no controls; the assessor off until allowed; menu entry, installer, the portal's risk redirect.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node risk-assess.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const ITAM = path.join(__dirname, '..', '..', 'backend', 'itam'), DASH = path.join(__dirname, '..', '..', 'ui');
const H = require(path.join(ITAM, 'tests', 'helpers'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const FACTS = () => ({ grc: { available: true, total: 20, reviews_overdue: 3, attested: 18, policies: [{ title: 'Information Security Policy (synthetic)', status: 'Approved', next_review: '2027-06-01' }], control_status: {} },
  risk: { available: true, total: 8, review_overdue: 0, actions_open: 3, actions_overdue: 0 }, ownership: { available: true, assets: 40, missing_it: 0, missing_business: 0 }, training_12m: 2 });

(async () => {
  const CISO = { overview: async () => ({ sources: [{ id: 'grc', name: 'GRC', state: 'live' }],
    risks: [{ ref: 'duty:SYN-1', severity: 'critical', title: 'Kaspersky endpoint protection disabled on 12 hosts (synthetic)', source: 'AI security engineer', age_h: 5 },
      { ref: 'drill-system:Core (synthetic)', severity: 'critical', title: 'Core (synthetic): recovery test never performed', source: 'DR & BCM drills', age_h: null },
      { ref: 'duty:SYN-9', severity: 'high', title: 'Something odd happened (synthetic)', source: 'misc', age_h: null }],
    posture: [{ id: 'detection', name: 'Detection & response', measured: true, score: 40 }, { id: 'exposure', name: 'Exposure & vulnerabilities', measured: true, score: 50 },
      { id: 'governance', name: 'Governance & policy', measured: true, score: 80 }, { id: 'compliance', name: 'SAMA CSF compliance', measured: false, score: null, not_measured_why: 'not connected (synthetic)' },
      { id: 'resilience', name: 'Resilience (DR / BCM)', measured: false, score: null }, { id: 'operations', name: 'Security operations hygiene', measured: false, score: null }] }) };
  const e = await H.startApp({ noAi: true });
  require(path.join(ITAM, 'engine/duty')).registerDuty(e.app.srv, e.app, { noTimer: true, python: process.env.PYTHON || 'python3', eccFacts: async () => FACTS(), raCiso: CISO });
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
    const ctx = await browser.newContext({ viewport: { width: 1600, height: 1000 } });
    let p = await page(ctx, 'risk-assess.html');
    ok(/risk exposure/.test(await p.textContent('#ring')) && /Above appetite/.test(await p.textContent('#kpis')), 'exposure ring and KPIs');
    ok(await p.$$eval('#heat .hm5 td', (x) => x.length === 25) && await p.$$eval('#heat .n', (x) => x.length > 3), 'heat map 5 x 5 with scenarios');
    await p.click('[data-hk="inherent"]'); ok(await wait(p, () => document.querySelector('[data-hk="inherent"]').getAttribute('aria-pressed') === 'true' && /Before controls/.test(document.getElementById('heat').textContent)), 'inherent heat map');
    ok(await p.$$eval('#scs .sc', (x) => x.length === 10), 'ten scenarios');
    ok(/Not assessed - no signal/.test(await p.textContent('#scs .sc.na')), 'not assessed is said');
    await p.click('[data-bf="not assessed"]'); ok(await wait(p, () => [...document.querySelectorAll('#scs .sc')].every((c) => c.classList.contains('na'))), 'band chip');
    await p.click('[data-bf="uncovered"]'); ok(await wait(p, () => /Critical service outage/.test(document.getElementById('scs').textContent)), 'not-in-the-register chip');
    ok(/duty:SYN-9/.test(await p.textContent('#unm')), 'unmatched signals are listed');
    ok(/first daily snapshot/.test(await p.textContent('#trend')) && /needs 3 daily snapshots/.test(await p.textContent('#trend')), 'trend honest before history');
    await p.click('#scs .sc[data-sc="outage"]'); ok(await wait(p, () => !document.getElementById('dlg').hidden), 'scenario detail');
    const d = await p.textContent('#dlgb'); ok(/Likelihood 3/.test(d) && /critical signal/.test(d) && /no control domain measured/.test(d) && /drill-system:Core/.test(d), 'itemised likelihood, controls and signals');
    await p.fill('#rform [name=owner]', 'nora.syn'); await p.click('#rform button[type=submit]');
    ok(await toast(p, 'RSK-\\d+ recorded in the register'), 'proposed to the register');
    ok(await wait(p, () => !/Critical service outage/.test(document.getElementById('scs').textContent)), 'no longer uncovered');
    ok(/administrators/.test(await p.textContent('#set')) && !(await p.$('#sform')), 'an operator cannot change settings');
    ok(/Not available/.test(await p.textContent('#ai')), 'assessor off until allowed');
    WHO = { user: 'syed', role: 'admin' }; p = await page(ctx, 'risk-assess.html');
    await p.fill('#sform [name=appetite]', '8'); await p.fill('#sform [data-imp="ransomware"]', '4'); await p.click('#sform button[type=submit]');
    ok(await toast(p, 'Settings saved'), 'the administrator saves the settings');
    ok(await wait(p, () => /appetite 8/.test(document.querySelector('#kpis').innerHTML)), 'the appetite applies');
    await p.click('#scs .sc[data-sc="ransomware"]'); ok(await wait(p, () => /Impact 4 \(set by an administrator\)/.test(document.getElementById('dlgb').textContent)), 'the impact setting applies');
    await p.keyboard.press('Escape');
    if (process.env.SHOT) await p.screenshot({ path: process.env.SHOT, fullPage: true });   // optional: a picture for review
    WHO = { user: 'vera.syn', role: 'viewer' }; p = await page(ctx, 'risk-assess.html');
    await p.click('#scs .sc[data-sc="ransomware"]'); ok(await wait(p, () => !document.getElementById('dlg').hidden) && !(await p.$('#rform')) && /operators and administrators/.test(await p.textContent('#ai')), 'a viewer reads without controls');
    const nav = fs.readFileSync(path.join(DASH, 'vendor', 'zyb-nav.js'), 'utf8');
    ok(/"h": "risk-assess.html"/.test(nav) && /risk-assess\.html/.test(fs.readFileSync(path.join(DASH, 'install-dashboards.sh'), 'utf8')), 'menu entry and installer');
    ok(/[ ,]risk: 'risk-assess\.html'/.test(fs.readFileSync(path.join(DASH, 'vendor', 'zyb-menu.js'), 'utf8')) && /[ ,]risk: 'risk-assess\.html'/.test(fs.readFileSync(path.join(DASH, 'vendor', 'zyb-early.js'), 'utf8')), 'the portal risk view opens this page');
    ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  } finally { await browser.close(); srv.close(); await e.close(); }
  console.log((bad ? 'FAILED ' : 'ok ') + (n - bad) + '/' + n);
  process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
