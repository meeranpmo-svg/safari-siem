// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// SAMA coverage from SIEM evidence (sama-siem.html) against the REAL SIEM module (engine/compliance/sama-intel-routes.js) over a SYNTHETIC
// coverage engine with four days of history: coverage ring and KPIs; controls by domain with status colours and the regression dot;
// status chips; a control's detail with checks, actions and reliability; leverage with its gain; quick wins; regressions; trend and the
// forecast rule; the administrator sets the target, an operator cannot; a hostile check reason stays text; the advisor off without a key;
// a viewer reads; menu entry, installer, the portal's siem-sama redirect.
// Run: SENTRA_SIEM_DIR=/home/user/sentra-siem PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node sama-siem.test.js
const http = require('http'), fs = require('fs'), os = require('os'), path = require('path');
const DASH = path.join(__dirname, '..', '..', 'ui');
const SIEM = process.env.SENTRA_SIEM_DIR || path.resolve(__dirname, '../../backend/siem');
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const RANK = { viewer: 0, analyst: 1, operator: 2, admin: 3 };
const ck = (id, result, reason) => ({ id, title: 'Check ' + id + ' (synthetic)', result, value: null, reason: reason || (result === 'pass' ? 'ok' : 'not met (synthetic)') });

(async () => {
  const C = [
    { id: '3.3.14', title: 'Security event management (synthetic)', domain: '3.3', siem_evidenced: true, status: 'gap', checks: [ck('retention', 'pass'), ck('src_ad', 'fail', '<img src=x onerror="window.__xss=1"> no DC events')], actions: [{ check: 'src_ad', action: 'Onboard the domain controllers' }] },
    { id: '3.3.5', title: 'Identity and access management (synthetic)', domain: '3.3', siem_evidenced: true, status: 'partial', checks: [ck('src_ad', 'fail')], actions: [{ check: 'src_ad', action: 'Onboard the domain controllers' }] },
    { id: '3.3.7', title: 'Malware protection (synthetic)', domain: '3.3', siem_evidenced: true, status: 'covered', checks: [ck('edr', 'pass')], actions: [] },
    { id: '3.3.8', title: 'Patch management (synthetic)', domain: '3.3', siem_evidenced: true, status: 'covered', checks: [ck('patch', 'pass')], actions: [] },
    { id: '3.1.1', title: 'Governance (synthetic)', domain: '3.1', siem_evidenced: false, status: 'n/a', checks: [], actions: [], reasons: ['not SIEM-evidenced — owned by GRC'] },
  ];
  const sama = { async summary() {
    const ev = C.filter((c) => c.siem_evidenced), counts = { covered: 0, partial: 0, gap: 0, 'n/a': 0 }; for (const c of C) counts[c.status]++;
    return { generated_at: new Date().toISOString(), clickhouse: { ok: true }, summary: { coverage_pct: Math.round(((counts.covered + counts.partial * 0.5) / ev.length) * 1000) / 10, evidenced: ev.length, total: C.length, counts, by_domain: { '3.1': { title: 'Cyber Security Leadership & Governance' }, '3.3': { title: 'Cyber Security Operations & Technology' } }, scoring: { covered: 1, partial: 0.5, gap: 0 } },
      controls: JSON.parse(JSON.stringify(C)).map((c) => Object.assign({ reasons: ['synthetic reason'], capped: false, rules: { tagged: 2, enabled: 1 } }, c)) };
  } };
  const sreq = (m) => require(path.join(SIEM, 'engine', m));
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sentra-samasiem-')), Lq = { info() {}, warn() {}, error() {} };
  let clock = Date.now() - 4 * 86400000;
  const deps = { state: sreq('soc/state').createState({ dir: path.join(dir, 'state'), log: Lq }), config: { soc_analyst: {} }, log: Lq, noTimers: true, samaCoverage: sama, now: () => clock };
  const R = {}, AUD = [];
  sreq('compliance/sama-intel-routes').register({ route: (m, p, h) => { R[m + ' ' + p] = { re: new RegExp('^' + p.replace(/:([a-zA-Z]+)/g, '(?<$1>[^/]+)') + '$'), h }; } }, deps);
  for (let d = 0; d < 4; d++) { await deps.samaIntel.snapshot(); clock += 86400000; }
  const c8 = C.find((c) => c.id === '3.3.8'); c8.status = 'gap'; c8.checks = [ck('patch', 'fail', 'no patch events in 30 days (synthetic)')];
  let WHO = { user: 'nora.syn', role: 'operator' };
  const srv = http.createServer((rq, res) => {
    const url = new URL(rq.url, 'http://x'), u = url.pathname, json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u === '/dashboards/whoami.json') return json(200, WHO);
    const hit = Object.entries(R).find(([k, v]) => k.startsWith(rq.method + ' ') && v.re.test(u));
    if (hit) { let b = ''; rq.on('data', (x) => { b += x; }); rq.on('end', async () => {
      const o = {}, m = hit[1].re.exec(u), ctx = { role: WHO.role, user: WHO.user, body: b ? JSON.parse(b) : {}, params: m.groups ? Object.fromEntries(Object.entries(m.groups).map(([k, v]) => [k, decodeURIComponent(v)])) : {}, query: Object.fromEntries(url.searchParams), path: u,
        need(r) { if (RANK[WHO.role] < RANK[r]) throw Object.assign(new Error('requires role ' + r), { status: 403 }); return true; }, audit: (a, t, d) => AUD.push({ a, t, d }), ok: (x) => { o.body = x; return x; }, fail(code, msg) { o.status = code; o.error = msg; } };
      try { await hit[1].h(ctx); if (o.status) return json(o.status, { error: o.error || 'refused' }); json(200, o.body); } catch (x) { json(x.code || x.status || 500, { error: x.message }); } }); return; }
    if (u.startsWith('/api/')) return json(404, { error: 'not in this test' });
    const f = path.join(DASH, u.replace(/^\/dashboards\//, '')); if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (err, d) => { if (err) { res.writeHead(404); return res.end(); } res.writeHead(200, { 'Content-Type': f.endsWith('.js') ? 'application/javascript' : f.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port + '/dashboards/sama-siem.html?standalone=1';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright'); const browser = await chromium.launch(), errs = [];
  const wait = (p, fn, arg) => p.waitForFunction(fn, arg, { timeout: 30000 }).then(() => true, () => false);
  const toast = (p, re) => wait(p, (s) => [...document.querySelectorAll('.toast')].some((t) => new RegExp(s).test(t.textContent)), re);
  const page = async (ctx) => { const p = await ctx.newPage(); p.on('pageerror', (x) => errs.push(x.message)); p.on('dialog', (d) => { errs.push('unexpected dialog'); d.dismiss(); }); await p.goto(base); await p.waitForSelector('#main:not([hidden]), #err:not([hidden])'); return p; };
  try {
    const ctx = await browser.newContext({ viewport: { width: 1500, height: 1000 } });
    let p = await page(ctx);
    ok(/SIEM coverage/.test(await p.textContent('#ring')) && /37\.5%/.test(await p.textContent('#ring')), 'coverage ring');
    ok(/Regressions/.test(await p.textContent('#kpis')) && /Quick wins/.test(await p.textContent('#kpis')), 'KPIs');
    ok(await p.$$eval('#dz .ct button', (x) => x.length === 5) && await p.$$eval('#dz .ct button.s-na', (x) => x.length === 1), 'controls by domain, n/a in grey');
    ok(await p.$$eval('#dz button[data-ctl="3.3.8"] .rg', (x) => x.length === 1), 'regression dot');
    ok(await p.evaluate(() => !!document.querySelector('#dz .sfr .sfg') && ['d31', 'd32', 'd33', 'd34'].filter((c) => document.querySelector('#dz .dzc.' + c)).length >= 2 && /%|not SIEM/.test(document.querySelector('#dz .dzc .pc').textContent)), 'drawn as the SAMA framework: domains in their places with coverage per domain');
    await p.click('[data-sf="gap"]'); ok(await wait(p, () => [...document.querySelectorAll('#dz .ct button')].every((b) => b.classList.contains('s-gap'))), 'gap chip');
    await p.click('[data-sf="regressed"]'); ok(await wait(p, () => document.querySelectorAll('#dz .ct button').length === 1), 'regressed chip');
    await p.click('[data-sf="all"]');
    ok(/\+25/.test(await p.textContent('#lev')) && /fixing it covers 3\.3\.14, 3\.3\.5/.test(await p.textContent('#lev')), 'leverage with its gain');
    ok(/3\.3\.14/.test(await p.textContent('#qw')) && /3\.3\.8/.test(await p.textContent('#qw')), 'quick wins');
    ok(/3\.3\.8/.test(await p.textContent('#reg')) && /covered on/.test(await p.textContent('#reg')), 'regressions');
    ok(/Snapshots/.test(await p.textContent('#trend')) && await p.$('#trend svg') !== null, 'trend and forecast');
    await p.click('#dz button[data-ctl="3.3.14"]'); ok(await wait(p, () => !document.getElementById('dlg').hidden), 'control detail');
    const d = await p.textContent('#dlgb'); ok(/Onboard the domain controllers/.test(d) && /Covered on 17% of 4/.test(d) && /Detection rules tagged 2/.test(d), 'checks, actions, reliability, rules');
    ok(await p.evaluate(() => !window.__xss && /<img/.test(document.getElementById('dlgb').textContent)), 'a hostile check reason stays text');
    await p.keyboard.press('Escape');
    ok(/administrators set it/.test(await p.textContent('#set')) && !(await p.$('#sform')), 'an operator cannot set the target');
    ok(/Not available/.test(await p.textContent('#ai')), 'advisor off without a key');
    ok(/days=30/.test(await p.getAttribute('#pack', 'href')), 'evidence pack link'); await p.selectOption('#days', '90'); ok(await wait(p, () => /days=90/.test(document.getElementById('pack').href)), 'period follows the selector');
    WHO = { user: 'syed', role: 'admin' }; p = await page(ctx);
    await p.fill('#sform [name=target_pct]', '90'); await p.click('#sform button[type=submit]');
    ok(await toast(p, 'Target saved'), 'the administrator sets the target'); ok(await wait(p, () => /90%/.test(document.getElementById('trend').textContent)), 'the target applies');
    ok(AUD.some((a) => a.a === 'compliance.sama-intel.settings'), 'the change is audited');
    if (process.env.SHOT) await p.screenshot({ path: process.env.SHOT, fullPage: true });   // optional: a picture for review
    WHO = { user: 'vera.syn', role: 'viewer' }; p = await page(ctx);
    ok(/operators and administrators/.test(await p.textContent('#ai')) && !(await p.$('#sform')), 'a viewer reads without controls');
    const nav = fs.readFileSync(path.join(DASH, 'vendor', 'zyb-nav.js'), 'utf8');
    ok(/"h": "sama-siem.html"/.test(nav) && /sama-siem\.html/.test(fs.readFileSync(path.join(DASH, 'install-dashboards.sh'), 'utf8')), 'menu entry and installer');
    ok(/'siem-sama': 'sama-siem\.html'/.test(fs.readFileSync(path.join(DASH, 'vendor', 'zyb-menu.js'), 'utf8')) && /'siem-sama': 'sama-siem\.html'/.test(fs.readFileSync(path.join(DASH, 'vendor', 'zyb-early.js'), 'utf8')), 'the portal siem-sama view opens this page');
    ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  } finally { await browser.close(); srv.close(); fs.rmSync(dir, { recursive: true, force: true }); }
  console.log((bad ? 'FAILED ' : 'ok ') + (n - bad) + '/' + n);
  process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
