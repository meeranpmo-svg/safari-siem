// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const ZYB_ORG = require('../../brand/index');
// Browser test for the Risk & Control Hub (dashboards/server/risk-control.html) against the REAL IT Asset Management engine
// (engine/risk-control.js) over SYNTHETIC records: hierarchy, a control created in the drawer, a risk linked and its calculated
// residual explained, an independent test raising a GRC action, a KRI breach, a loss event, the acceptances register, menu
// search, a viewer sees roll-ups only, phone width.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node risk-control.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const ITAM = path.join(__dirname, '..', '..', 'backend', 'itam'), DASH = path.join(__dirname, '..', '..', 'ui');
const H = require(path.join(ITAM, 'tests', 'helpers'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
(async () => {
  const e = await H.startApp({ noAi: true });
  require(path.join(ITAM, 'engine/duty')).registerDuty(e.app.srv, e.app, { noTimer: true, python: process.env.PYTHON || 'python3', acovLogCoverage: async () => ({ ok: true, assets: [] }), acovAvail: async () => ({ ok: true, hosts: {} }) });
  const rows = Array.from({ length: 20 }, (_, i) => ({ id: 'A' + i, controls: { edr: { state: i < 19 ? 'present' : 'missing' }, siem_logs: { state: i < 10 ? 'present' : 'missing' } } }));
  e.app.addons.assetCoverage = { view: async () => ({ rows, sources: { edr: { ok: true }, siem_logs: { ok: true } } }) };
  const C = (x) => e.app.store.collection(x);
  C('grc_risks').put({ id: 'RSK-0001', title: 'Ransomware on claims servers (synthetic)', likelihood: 4, impact: 5, residual_likelihood: 1, residual_impact: 2, owner: 'risk.owner.syn', treatment: 'mitigate', status: 'open', controls: [], assets: [] });
  C('rc_units').put({ id: 'BU-001', name: (ZYB_ORG.short + ' (synthetic)'), kind: 'company', parent: '' });
  C('rc_units').put({ id: 'BU-002', name: 'Claims', kind: 'division', parent: 'BU-001' });
  C('grc_exceptions').put({ id: 'EXC-0001', policy_id: 'IT-GOV-001', title: 'Legacy fax server (synthetic)', status: 'approved', expires: '2020-01-01', decided_by: 'adam.syn' });
  let who = { user: 'nora.syn', role: 'admin' };
  const srv = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://x'), json = (code, b) => { res.writeHead(code, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u.pathname === '/dashboards/whoami.json') return json(200, who);
    if (u.pathname.startsWith('/api/itam/')) { const h = Object.assign({}, req.headers, { 'x-sentra-proxy-secret': H.SECRET, 'x-auth-user': who.user, 'x-auth-role': who.role });
      const up = http.request({ host: '127.0.0.1', port: e.port, method: req.method, path: req.url, headers: h }, (r) => { res.writeHead(r.statusCode, r.headers); r.pipe(res); }); req.pipe(up); return; }
    if (u.pathname.startsWith('/api/') || u.pathname === '/') return json(404, { error: 'not in this test' });
    const f = path.join(DASH, u.pathname.replace(/^\/dashboards\//, '/')); if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (err, d) => { if (err) { res.writeHead(404); res.end(); return; } res.writeHead(200, { 'Content-Type': u.pathname.endsWith('.js') ? 'application/javascript' : u.pathname.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port + '/';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  const wait = (p, fn, arg) => p.waitForFunction(fn, arg === undefined ? null : arg, { timeout: 30000 }).then(() => true, () => false);
  const tab = (p, t) => p.click('[data-tab="' + t + '"]');
  try {
    const p = await browser.newPage({ viewport: { width: 1400, height: 1000 } }); p.on('pageerror', (x) => errs.push(x.message));
    await p.goto(base + 'risk-control.html?standalone=1');
    ok(await wait(p, () => /open risks/.test(document.getElementById('kpis').textContent)), 'KPIs');
    ok(/Claims/.test(await p.textContent('#units')), 'business units rolled up');
    ok(/Risks no control treats \(1\)/.test(await p.textContent('#gaps')), 'gap: a risk with no control');
    // a control from the drawer, bound to a signal
    await tab(p, 'controls'); await p.click('#newctl');
    await p.fill('#cf-title', 'Endpoint protection on every asset'); await p.selectOption('#cf-type', 'preventive'); await p.selectOption('#cf-nature', 'automated');
    await p.selectOption('#cf-signal', 'cov:edr'); await p.fill('#cf-cite', 'SAMA:3.3.6\nNCA:2-3-1'); await p.fill('#cf-owner', 'ciso.syn'); await p.click('#cf-save');
    ok(await wait(p, () => /CTL-001/.test(document.getElementById('controls').textContent) && /effective/.test(document.getElementById('controls').textContent)), 'control saved, effective from the signal');
    await p.click('#newctl'); await p.fill('#cf-title', 'Bad citation'); await p.fill('#cf-cite', 'SAMA 3.3.6'); await p.click('#cf-save');
    ok(await wait(p, () => /citations/.test((document.querySelector('.toast') || {}).textContent || '')), 'a malformed citation is refused with the field named');
    await p.click('#dclose');
    // link it to the risk, see the calculated residual
    await tab(p, 'risks'); await p.click('button[data-risk="RSK-0001"]');
    await p.selectOption('#lc', 'CTL-001'); await p.selectOption('#ls', 'primary'); await p.click('[data-link]');
    await tab(p, 'risks');
    ok(await wait(p, () => /−60%/.test(document.getElementById('risks').textContent)), 'calculated residual: 60 % mitigation');
    ok(/claimed \(2\) below what the controls show \(8\)/.test(await p.textContent('#risks')), 'owner residual below what the controls support is flagged');
    await p.click('button[data-risk="RSK-0001"]'); ok(/How the residual is calculated/.test(await p.textContent('#drawer')) && /60%/.test(await p.textContent('#drawer')), 'breakdown in the drawer');
    await p.selectOption('#ru', 'BU-002'); await p.click('[data-runit]');
    // an independent test that fails raises an action
    who = { user: 'omar.syn', role: 'operator' }; await p.reload();
    await wait(p, () => document.querySelector('[data-tab="controls"]')); await tab(p, 'controls');
    await p.click('button[data-test="CTL-001"]'); await p.selectOption('#tf-kind', 'design'); await p.selectOption('#tf-result', 'fail'); await p.fill('#tf-ev', 'two servers excluded from the policy (synthetic)'); await p.click('#tf-save');
    ok(await wait(p, () => /ACT-/.test(document.body.textContent)), 'a failed test raises a remediation action');
    ok(C('grc_actions').all().some((a) => a.source === 'control'), 'GRC action stored with source control');
    // KRI breach and a loss event
    await tab(p, 'kri'); await p.click('#newkri'); await p.selectOption('#kf-risk', 'RSK-0001'); await p.fill('#kf-name', 'Endpoints without EDR'); await p.fill('#kf-measure', 'count');
    await p.fill('#kf-amber', '2'); await p.fill('#kf-red', '5'); await p.click('#kf-save');
    await tab(p, 'kri'); ok(await wait(p, () => /KRI-001/.test(document.getElementById('kris').textContent)), 'KRI saved');
    await p.fill('[data-kv="KRI-001"]', '7'); await p.click('[data-kval="KRI-001"]');
    await tab(p, 'kri'); ok(await wait(p, () => /red/.test(document.getElementById('kris').textContent)), 'KRI red');
    await p.click('#newloss'); await p.fill('#lf-date', '2026-10-01'); await p.fill('#lf-gross', '120000'); await p.fill('#lf-rec', '20000'); await p.selectOption('#lf-risk', 'RSK-0001'); await p.fill('#lf-desc', 'Recovery cost after an incident (synthetic)'); await p.click('#lf-save');
    await tab(p, 'kri'); ok(await wait(p, () => /100,000 SAR/.test(document.getElementById('losses').textContent)), 'loss recorded with net amount');
    await tab(p, 'acc'); ok(/expired/.test(await p.textContent('#acc')) && /Legacy fax server/.test(await p.textContent('#acc')), 'acceptances register shows an expired exception');
    await p.fill('#zs-q', 'archer'); await p.waitForTimeout(150);
    ok((await p.$$eval('#zs-best a b', (x) => x.map((y) => y.textContent))).includes('Risk & Control Hub'), 'menu search finds the page');
    who = { user: 'vera.syn', role: 'viewer' };
    const v = await browser.newPage({ viewport: { width: 400, height: 900 } }); v.on('pageerror', (x) => errs.push(x.message));
    await v.goto(base + 'risk-control.html?standalone=1');
    ok(await wait(v, () => !document.getElementById('viewer').hidden && document.querySelectorAll('[data-tab]').length === 1), 'viewer: roll-ups only');
    ok(await v.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1), 'phone width: no sideways scroll');
  } finally { await browser.close(); srv.close(); await e.close(); }
  ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks'); process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
