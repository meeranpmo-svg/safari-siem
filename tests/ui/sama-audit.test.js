// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const ZYB_ORG = require('../../brand/index');
// SAMA CSF Audit (dashboards/server/sama-audit.html) against the REAL ITAM engine (engine/sama-audit.js on engine/sama-ia.js and
// pyengine/sama_ia_rules.py) over SYNTHETIC facts: implementation ring and KPIs; implementation by domain; the tracker sorted by
// priority with chips; a gap opened, an owner and plan saved, closure requested with evidence; the requester cannot confirm, an
// administrator does from the attention list → "closed - not yet verified"; the Closed chip; the rule memo drafted by an operator
// and approved by an administrator; Excel; a hostile plan stays text; viewer sees no names, no Excel and no edit form; the menu
// entry and the installer.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node sama-audit.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const ITAM = path.join(__dirname, '..', '..', 'backend', 'itam'), DASH = path.join(__dirname, '..', '..', 'ui');
const H = require(path.join(ITAM, 'tests', 'helpers'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const XSS = '<img src=x onerror="window.__xss=1">';
const FACTS = () => ({
  grc: { available: true, total: 20, reviews_overdue: 0, attested: 15, policies: [{ title: 'Cryptography Standard (synthetic)', status: 'Approved', next_review: '2027-06-01' }], control_status: {} },
  hardening: { available: true, assets: 40, scanned: 38, coverage_pct: 95, score: 82, fail: 30, critical_fail: 2 },
  pentest: { available: true, assets: 12, findings: 4, by_severity: { critical: 0, high: 0 }, internet_facing: 3, exposed_assets: 0 },
  cadence: { available: true, assets: 12, out_of_policy: 3 },
  siem: { available: true, sama: { '3.3.14': 'covered', '3.3.15': 'partial', '3.3.16': 'covered' }, retention_days: 400, logflow: { required: 10, silent: 0, not_onboarded: 0, no_connector: 0 } },
});

(async () => {
  const e = await H.startApp({ noAi: true });
  require(path.join(ITAM, 'engine/duty')).registerDuty(e.app.srv, e.app, { noTimer: true, python: process.env.PYTHON || 'python3', samaFacts: async () => FACTS(), eccFacts: async () => FACTS() });
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
  const url = 'http://127.0.0.1:' + srv.address().port + '/dashboards/sama-audit.html?standalone=1';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright'); const browser = await chromium.launch(), errs = [];
  const wait = (p, fn, arg) => p.waitForFunction(fn, arg, { timeout: 30000 }).then(() => true, () => false);
  try {
    const ctx = await browser.newContext({ viewport: { width: 1500, height: 1000 }, acceptDownloads: true });
    const p = await ctx.newPage(); p.on('pageerror', (x) => errs.push(x.message)); p.on('dialog', (d) => { errs.push('unexpected dialog'); d.dismiss(); });
    await p.goto(url); ok(await wait(p, () => document.querySelectorAll('tr[data-gap]').length > 3), 'tracker rows');
    ok(/Implementation rate/.test(await p.textContent('#ring')) && /\d+%/.test(await p.textContent('#ring')), 'implementation ring');
    ok((await p.$$('#doms tbody tr')).length === 5 && /Insurance Authority/.test(await p.textContent('#doms')), 'implementation by domain incl. IA');
    ok(/needs 3 daily counts/.test(await p.textContent('#fc')), 'forecast says what it needs');
    ok((await p.$$('#mat [data-sub]')).length === 32, 'maturity: all 32 SAMA subdomains');
    ok(/at level 3 or above/.test(await p.textContent('#matc')), 'maturity summary against the level-3 minimum');
    const id = await p.getAttribute('tr[data-gap]', 'data-gap');
    await p.click('tr[data-gap="' + id + '"]'); ok(await wait(p, () => !document.getElementById('dlg').hidden && /Why the assessment does not show it met/.test(document.getElementById('dlg').textContent)), 'gap detail');
    await p.fill('#gown', 'nora.syn'); await p.fill('#gplan', 'Fix the baseline ' + XSS); await p.selectOption('#gst', 'in_progress'); await p.click('#gsave');
    ok(await wait(p, (i) => /nora\.syn/.test(document.querySelector('tr[data-gap="' + i + '"]').textContent) && /In progress/.test(document.querySelector('tr[data-gap="' + i + '"]').textContent), id), 'owner and status saved');
    ok(await wait(p, () => /Fix the baseline/.test(document.getElementById('dlg').textContent)), 'dialog refreshed with the plan');
    await p.fill('#gev', 'Change CHG-SYN-1 baseline remediation report'); await p.click('#gclose');
    ok(await wait(p, () => /Awaiting confirmation/.test(document.getElementById('dlg').textContent) && document.querySelector('[data-dec="approve"]') && document.querySelector('[data-dec="approve"]').disabled), 'closure requested; the requester cannot confirm');
    ok(!(await p.evaluate(() => window.__xss)), 'a hostile plan stayed text');
    await p.click('#dlgx');
    { const sub = await p.evaluate((i) => (document.querySelector('tr[data-gap="' + i + '"] .sm.mute') || {}).textContent, id);
      await p.click('#mat [data-sub="' + sub + '"]'); ok(await wait(p, (x) => [...document.querySelectorAll('tr[data-gap]')].length > 0 && [...document.querySelectorAll('tr[data-gap]')].every((r) => r.querySelector('.sm.mute').textContent === x), sub), 'a subdomain filters the tracker');
      await p.click('#mat [data-sub="' + sub + '"]'); }
    await p.click('[data-memo="rules"]'); ok(await wait(p, () => new RegExp('Internal audit of ' + ZYB_ORG.short).test(document.getElementById('memo').textContent)), 'rule memo drafted');
    const [dl] = await Promise.all([p.waitForEvent('download', { timeout: 15000 }), p.click('#xls')]);
    ok(/^sama-csf-audit-\d{4}-\d{2}-\d{2}\.xlsx$/.test(dl.suggestedFilename()), 'Excel audit sheet');
    { const x = fs.readFileSync(await dl.path(), 'latin1'); ok(x.includes(id) && x.includes('Verified by the assessment'), 'the Excel file holds the header and the requirements'); }
    if (process.env.SHOT) await p.screenshot({ path: process.env.SHOT, fullPage: true });   // optional: a picture for review
    // administrator confirms from the attention list
    WHO = { user: 'sara.syn', role: 'admin' }; const a = await ctx.newPage(); a.on('pageerror', (x) => errs.push(x.message));
    await a.goto(url); ok(await wait(a, (i) => [...document.querySelectorAll('#attn .att')].some((x) => x.getAttribute('data-open') === i && /waits for the CISO/.test(x.textContent)), id), 'attention: closure waiting');
    await a.click('#attn .att[data-open="' + id + '"]'); await a.click('[data-dec="approve"]');
    ok(await wait(a, () => /closed - not yet verified/.test(document.getElementById('dlg').textContent)), 'closed, not verified by the assessment');
    await a.click('#dlgx'); await a.click('[data-chip="closed"]'); ok(await wait(a, () => document.querySelectorAll('tr[data-gap]').length === 1), 'Closed chip');
    ok(/1 \/ \d+\s*Gaps closed/.test(await a.textContent('#kpis')), 'KPI counts the closure');
    await a.click('[data-mdec="approve"]'); ok(await wait(a, () => /approved/.test(document.getElementById('memo').textContent)), 'memo approved by someone else');
    // viewer
    WHO = { user: 'vera.syn', role: 'viewer' }; const v = await ctx.newPage(); v.on('pageerror', (x) => errs.push(x.message));
    await v.goto(url); await wait(v, () => document.querySelectorAll('tr[data-gap]').length > 3);
    ok(!(await v.isVisible('#xls')) && /assigned/.test(await v.textContent('#gaps')) && !/nora\.syn/.test(await v.textContent('#gaps')), 'viewer: no Excel, no names');
    await v.click('tr[data-gap]'); ok(await wait(v, () => !document.getElementById('dlg').hidden) && !(await v.$('#gsave')), 'viewer: no edit form');
    ok(/shown to operators and administrators/.test(await v.textContent('#memo')), 'viewer: no memo');
    const nav = fs.readFileSync(path.join(DASH, 'vendor', 'zyb-nav.js'), 'utf8');
    ok(/"h": "sama-audit.html"/.test(nav) && /sama-audit\.html/.test(fs.readFileSync(path.join(DASH, 'install-dashboards.sh'), 'utf8')), 'menu entry and installer');
    ok(/sama: 'sama-audit\.html', 'sama-validation': 'sama-audit\.html'/.test(fs.readFileSync(path.join(DASH, 'vendor', 'zyb-menu.js'), 'utf8')) && /sama: 'sama-audit\.html'/.test(fs.readFileSync(path.join(DASH, 'vendor', 'zyb-early.js'), 'utf8')), 'the portal\'s SAMA CSF and SAMA Controls Validation open this page');
    ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  } finally { await browser.close(); srv.close(); await e.close(); }
  console.log((bad ? 'FAILED ' : 'ok ') + (n - bad) + '/' + n);
  process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
