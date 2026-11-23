// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for the Service Agreement page (dashboards/server/service-agreement.html) against the REAL ITAM engine
// (engine/service-agreement.js) with SYNTHETIC parties: the administrator saves the terms in the form (a bad value refused with
// the field named), drafts the SLA from them, sends it for approval; the Customer and the Provider signatories each approve and it
// is published to everyone; the Customer opens a P1 case, the Provider responds and resolves it, the Customer confirms it; the
// statement shows the targets and the deduction and exports to Excel; a hostile case title stays text; an outsider reads only.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node service-agreement.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const ITAM = path.join(__dirname, '..', '..', 'backend', 'itam'), DASH = path.join(__dirname, '..', '..', 'ui');
const H = require(path.join(ITAM, 'tests', 'helpers'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const ADM = { user: 'syed', role: 'admin' }, CUS = { user: 'cust.syn', role: 'operator' }, CSIG = { user: 'cust.sign', role: 'viewer' }, PRO = { user: 'prov.syn', role: 'viewer' }, PSIG = { user: 'prov.sign', role: 'viewer' }, OUT = { user: 'vera.syn', role: 'viewer' };
const XSS = '<img src=x onerror="window.__xss=1">';

(async () => {
  const e = await H.startApp({ noAi: true });
  const clock = { t: Date.parse('2026-10-05T07:00:00Z') };
  require(path.join(ITAM, 'engine/duty')).registerDuty(e.app.srv, e.app, { noTimer: true, now: () => clock.t });
  if (e.app.addons.updateHealth) e.app.addons.updateHealth.view = () => ({ pages: [] });
  let WHO = ADM;
  const srv = http.createServer((req, res) => {
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
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const url = 'http://127.0.0.1:' + srv.address().port + '/dashboards/service-agreement.html';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  const wait = (p, fn, arg) => p.waitForFunction(fn, arg, { timeout: 15000 }).then(() => true, () => false);
  const tab = (p, t) => p.click('#tabs [data-tab="' + t + '"]');
  const as = async (p, who) => { WHO = who; await p.goto(url); await wait(p, () => !document.getElementById('main').hidden); };
  try {
    const ctx = await browser.newContext({ viewport: { width: 1440, height: 1000 }, acceptDownloads: true });
    const p = await ctx.newPage(); p.on('pageerror', (x) => errs.push(x.message)); p.on('dialog', (d) => d.accept());
    await as(p, ADM);
    ok(/Not published yet/.test(await p.textContent('#view')), 'nothing published yet - says so');
    await tab(p, 'terms');
    await p.fill('#t-mc', 'cust.syn\ncust.sign'); await p.fill('#t-mp', 'prov.syn\nprov.sign');
    await p.fill('#t-customer-su', 'cust.sign'); await p.fill('#t-customer-sn', 'Customer Signatory (synthetic)'); await p.fill('#t-provider-su', 'prov.sign'); await p.fill('#t-provider-sn', 'Provider Signatory (synthetic)');
    await p.fill('#t-customer-cr', '1010000001'); await p.fill('#t-provider-cr', '1010000002'); await p.fill('#t-fee', '100000');
    await p.fill('#t-P1-z', '0.1'); await p.click('#t-save');
    ok(await wait(p, () => /priorities\.P1\.resolve_h must be at least 0\.5/.test(document.body.textContent)), 'a bad value is refused with the field named');
    await p.fill('#t-P1-z', '4'); await p.click('#t-save');
    ok(await wait(p, () => /Terms saved/.test(document.body.textContent)), 'terms saved');
    await tab(p, 'agreements'); await p.click('[data-gen="sla"]');
    ok(await wait(p, () => /Draft created/.test(document.body.textContent) && document.querySelector('[data-sh]')), 'SLA drafted from the terms');
    ok(/Citynet Work/.test(await p.inputValue('[data-st="0"]')) && /Zyberon Information Technology, Saudi Arabia/.test(await p.inputValue('[data-st="0"]')), 'parties in the draft');
    ok(/P1 Critical[^\n]*response 30 minutes, resolution 4 hours/.test(await p.inputValue('[data-st="4"]')), 'priority targets from the terms');
    await p.click('[data-addsec]'); const last = await p.$$eval('[data-sh]', (L) => L.length - 1);
    await p.fill('[data-sh="' + last + '"]', '16. Special terms'); await p.fill('[data-st="' + last + '"]', 'Monthly on-site review at the Riyadh head office (synthetic).');
    await p.click('[data-dact^="edit:"]'); ok(await wait(p, () => /Saved/.test(document.body.textContent)), 'section added');
    await p.click('[data-dact^="submit:"]'); ok(await wait(p, () => /Sent to both signatories/.test(document.body.textContent)), 'sent for approval');
    await as(p, CSIG); ok(await wait(p, () => document.querySelector('[data-dact^="approve:"]')), 'Customer signatory: Approve offered');
    await p.click('[data-dact^="approve:"]'); ok(await wait(p, () => /Approved/.test(document.body.textContent)), 'Customer approved');
    await as(p, PSIG); await p.click('[data-dact^="approve:"]');
    ok(await wait(p, () => /Published version 1/.test(document.body.textContent)), 'both approved: published');
    await as(p, OUT);
    ok(await wait(p, () => /Monthly on-site review/.test(document.getElementById('view').textContent) && /Approved for the customer by Customer Signatory/.test(document.getElementById('view').textContent)), 'everyone reads the published SLA with its approvals');
    ok(/Read-only/.test(await p.textContent('#me')), 'an outsider is read-only');
    // a P1 case through its life
    await as(p, CUS); await tab(p, 'cases');
    ok(await wait(p, () => document.getElementById('nc-title')), 'Customer: open-a-case form');
    await p.fill('#nc-title', 'SIEM not receiving logs ' + XSS); await p.selectOption('#nc-pri', 'P1'); await p.fill('#nc-desc', 'No alerts since 09:00 (synthetic).'); await p.click('#nc-go');
    ok(await wait(p, () => /Case opened/.test(document.body.textContent)), 'case opened');
    clock.t += 75 * 60000;
    await as(p, PRO); await tab(p, 'cases'); await wait(p, () => document.querySelector('[data-case]')); await p.click('[data-case]');
    await p.click('[data-ca="respond"]'); await wait(p, () => document.querySelector('[data-ca="resolve"]') && !document.querySelector('[data-ca="respond"]'));
    await p.fill('#cnote', 'Collector restarted, backlog ingested (synthetic).'); await p.click('[data-ca="resolve"]');
    ok(await wait(p, () => /resolution met/.test(document.getElementById('view').textContent) && /response missed/.test(document.getElementById('view').textContent)), 'response missed (75 min), resolution met');
    await as(p, CUS); await tab(p, 'cases'); await wait(p, () => document.querySelector('[data-case]')); await p.click('[data-case]'); await p.click('[data-ca="close"]');
    ok(await wait(p, () => /closed/.test(document.querySelector('[data-case]').textContent)), 'Customer confirmed it fixed');
    await tab(p, 'statement');
    ok(await wait(p, () => /P1 response/.test(document.getElementById('view').textContent)), 'statement lists the targets');
    ok(/2%/.test(await p.textContent('#view')) && /SAR 2,000/.test(await p.textContent('#view')), 'deduction 2% = SAR 2,000');
    const [dl] = await Promise.all([p.waitForEvent('download', { timeout: 10000 }), p.click('#xls')]);
    ok(/sla-statement-2026-10\.xlsx/.test(dl.suggestedFilename()), 'Excel export');
    ok(!(await p.evaluate(() => window.__xss)), 'hostile case title stayed text');
    const nav = fs.readFileSync(path.join(DASH, 'vendor', 'zyb-nav.js'), 'utf8');
    ok(/"h": "service-agreement.html"/.test(nav) && /service-agreement\.html/.test(fs.readFileSync(path.join(DASH, 'install-dashboards.sh'), 'utf8')), 'menu entry and installer');
    ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  } finally { await browser.close(); srv.close(); await e.close(); }
  console.log((bad ? 'FAILED ' : 'ok ') + (n - bad) + '/' + n);
  process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
