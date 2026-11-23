// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for 24/7 Email Availability (dashboards/server/mail-ops.html, vendor/zyb-mailops.js) against the REAL ITAM engine with
// the mail measurements stubbed (SYNTHETIC): the admin names the team, the design gap is shown with its fix, a runbook is written by
// one person and approved by another, a maintenance window is requested, the outage gets a review, the report step links to the
// Email Dashboard; a viewer is refused; in the menu.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node mail-ops.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const ITAM = path.join(__dirname, '..', '..', 'backend', 'itam'), DASH = path.join(__dirname, '..', '..', 'ui');
const H = require(path.join(ITAM, 'tests', 'helpers'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };

(async () => {
  const e = await H.startApp({ noAi: true });
  require(path.join(ITAM, 'engine/duty')).registerDuty(e.app.srv, e.app, { noTimer: true, python: process.env.PYTHON || 'python3' });
  let WHO = { user: 'syed', role: 'admin' };
  const api = (m, p, body, who) => e.req(m, p, Object.assign(body !== undefined ? { body } : {}, who));
  const T = Date.now(), DAY = 86400000;
  const F = { av: { target: 99.99, windows: [{ label: 'Last 30 days', availability: 99.98, state: 'met', budget_left_minutes: 2 }], outages: [{ start: T - 5 * DAY, end: T - 5 * DAY + 600000, minutes: 10, hosts: ['mx1.syn.test'] }],
    gaps: [{ severity: 'high', title: 'syn.test has one MX host - any outage of it stops inbound mail', fix: ['Add a second gateway node as a second MX'] }], current: { up: true, last_at: T - 60000 } },
    route: { lanes: { inbound: [] } }, alerts: { open: [], state: { at: T - 600000, gaps: [] } }, reports: [] };
  e.app.addons.mailReputation = { availability: async () => F.av, routeView: async () => F.route, alertView: () => F.alerts, reports: () => F.reports };
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
    await p.goto(base + 'mail-ops.html?standalone=1'); await p.waitForSelector('#steps li');
    ok((await p.$$('#steps li')).length === 9, 'nine steps listed');
    ok(await has(p, '#ready', /Readiness/), 'readiness shown');
    // 1 the admin names the team
    ok(await has(p, '#panel', /at least two on-call/), 'step 1 says what is needed');
    await p.fill('#p-own', 'karim.syn'); await p.fill('#p-esc', 'syed'); await p.fill('#p-onc', 'omar.syn, nora.syn'); await p.fill('#p-rto', '30'); await p.fill('#p-rpo', '0'); await p.click('#p-save');
    ok(await has(p, '#panel', /omar\.syn, nora\.syn/), 'profile saved');
    // 4 the design gap is named with its fix
    await p.click('[data-step="4"]'); ok(await has(p, '#panel', /one MX host/) && await has(p, '#panel', /second gateway node/), 'redundancy gap with its fix');
    // 5 a runbook: written by one person, approved by another
    WHO = { user: 'omar.syn', role: 'operator' }; await p.click('#refresh'); await p.waitForTimeout(400); await p.click('[data-step="5"]');
    await p.click('[data-rb="gateway-down"]'); await p.fill('#d-own', 'omar.syn'); await p.fill('#d-steps', '1. Check the gateway node. 2. Fail over to node 2. 3. Confirm mail flows (synthetic).'); await p.fill('#d-esc', 'After 15 minutes call the escalation manager'); await p.click('#dlgok');
    ok(await has(p, '#panel', /draft/), 'runbook saved as a draft');
    WHO = { user: 'nora.syn', role: 'operator' }; await p.click('#refresh'); await p.waitForTimeout(400); await p.click('[data-step="5"]');
    await p.click('[data-rba="gateway-down"]'); ok(await has(p, '#panel', /approved/) && await has(p, '#panel', /nora\.syn/), 'a different person approves the runbook');
    // 6 a maintenance window
    await p.click('[data-step="6"]'); await p.click('#w-new'); await p.fill('#d-title', 'Patch gateway node 2'); await p.fill('#d-start', '2026-12-05T01:00'); await p.fill('#d-end', '2026-12-05T03:00'); await p.fill('#d-sys', 'esg2'); await p.fill('#d-imp', 'none expected - node 1 carries mail'); await p.fill('#d-rb', 'restore the node snapshot'); await p.click('#dlgok');
    ok(await has(p, '#panel', /Patch gateway node 2/) && await has(p, '#panel', /requested/), 'window requested');
    // 8 the outage needs a review
    await p.click('[data-step="8"]'); ok(await has(p, '#panel', /no review/), 'the outage has no review yet');
    await p.click('[data-rv]'); await p.fill('#d-rc', 'MX1 rebooted for patching outside a window'); await p.fill('#d-act', 'Second MX; patch only in approved windows'); await p.fill('#d-own', 'omar.syn'); await p.click('#dlgok');
    ok(await has(p, '#panel', /awaiting approval/), 'review saved, awaiting a different person');
    // 9 the report step links to the Email Dashboard
    await p.click('[data-step="9"]'); ok(await has(p, '#panel', /No report prepared yet/) && !!(await p.$('#panel a[href="email-dashboard.html"]')), 'report step');
    // a viewer is refused
    const v = await browser.newPage(); WHO = { user: 'vera.syn', role: 'viewer' }; await v.goto(base + 'mail-ops.html?standalone=1');
    ok(await has(v, '#err', /mail team/), 'viewer refused'); await v.close();
    const nav = fs.readFileSync(path.join(DASH, 'vendor', 'zyb-nav.js'), 'utf8'), inst = fs.readFileSync(path.join(DASH, 'install-dashboards.sh'), 'utf8');
    ok(/"h": "mail-ops.html"/.test(nav) && inst.includes('mail-ops.html') && inst.includes('vendor/zyb-mailops.js'), 'in the menu and the install list');
    ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  } finally { await browser.close(); srv.close(); await e.close(); }
  console.log((bad ? 'FAILED ' : 'ok ') + (n - bad) + '/' + n);
  process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
