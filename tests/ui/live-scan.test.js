// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Live Scan Engine & Attack Simulation (live-scan.html) against the REAL ITAM engines (Vulnerability Scans, VAPT Center) and the REAL SIEM
// breach-&-attack simulator with detection assurance (engine/bas/routes.js, assurance.js), SYNTHETIC records: Greenbone connected with a
// scope; a stale critical finding becomes a smart target; an operator picks it and requests a scan (the requester cannot approve); an
// administrator approves; a hostile scan name stays text; the administrator runs every simulation scenario, the scenario table, ranked gaps
// (the control scenario by design) and sets a daily schedule; a viewer sees no host and cannot run; menu entry, installer, the portal's
// scanlive redirect.
// Run: SENTRA_SIEM_DIR=/home/user/sentra-siem PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node live-scan.test.js
const http = require('http'), fs = require('fs'), os = require('os'), path = require('path');
const ITAM = path.join(__dirname, '..', '..', 'backend', 'itam'), DASH = path.join(__dirname, '..', '..', 'ui');
const SIEM = process.env.SENTRA_SIEM_DIR || path.resolve(__dirname, '../../backend/siem');
const H = require(path.join(ITAM, 'tests', 'helpers'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const RANK = { viewer: 0, analyst: 1, operator: 2, admin: 3 };

(async () => {
  const e = await H.startApp({ noAi: true });
  require(path.join(ITAM, 'engine/duty')).registerDuty(e.app.srv, e.app, { noTimer: true, python: process.env.PYTHON || 'python3' });
  const col = (c) => e.app.store.collection(c), old = new Date(Date.now() - 45 * 86400000).toISOString();
  col('vulnscan').put({ id: 'cfg', socket: '/run/gvmd/gvmd.sock', username: 'svc-gvm-synthetic', port_list: 'all', scanner: 'default', min_qod: 70, by: 'syed', at: old });
  col('vulnscan').put({ id: 'scope', allowed: ['10.20.0.0/24'], exclude: ['10.20.0.250'], by: 'syed', at: old });
  col('vulnscan_findings').put({ id: 'VF-1', host: '10.20.0.5', hostname: 'claims-db (synthetic)', port: '1521/tcp', name: 'Remote code execution in synthetic listener', severity: 'critical', score: 9.8, cves: ['CVE-2099-0001'], status: 'open', first_seen: old, last_seen: old, history: [] });
  col('vulnscan_scans').put({ id: 'VS-900', name: 'Old scan <img src=x onerror="window.__xss=1">', targets: ['10.20.0.9'], exclude: [], hosts: 1, profile: 'full', window_start: old, window_end: old, reason: 'synthetic', state: 'done', requested_by: 'adel.syn', approved_by: 'syed', counts: { critical: 1, high: 0, medium: 0, low: 0 }, history: [] });
  // the SIEM simulator, isolated, on a temporary state store
  const sreq = (m) => require(path.join(SIEM, 'engine', m));
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sentra-livescan-')), Lq = { info() {}, warn() {}, error() {} };
  const deps = { state: sreq('soc/state').createState({ dir: path.join(dir, 'state'), log: Lq }), config: { soc_analyst: { enabled: false } }, log: Lq, noTimers: true };
  const R = {}, AUD = [];
  sreq('bas/routes').register({ route: (m, p, h) => { R[m + ' ' + p] = { re: new RegExp('^' + p.replace(/:([a-zA-Z]+)/g, '(?<$1>[^/]+)') + '$'), h }; } }, deps);
  let WHO = { user: 'laila.syn', role: 'operator' };
  const srv = http.createServer((rq, res) => {
    const url = new URL(rq.url, 'http://x'), u = url.pathname, json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u === '/dashboards/whoami.json') return json(200, WHO);
    if (u.startsWith('/api/itam/')) {
      const h = Object.assign({}, rq.headers, { 'x-sentra-proxy-secret': H.SECRET, 'x-auth-user': WHO.user, 'x-auth-role': WHO.role });
      const up = http.request({ host: '127.0.0.1', port: e.port, method: rq.method, path: rq.url, headers: h }, (r) => { res.writeHead(r.statusCode, r.headers); r.pipe(res); });
      rq.pipe(up); return;
    }
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
  const base = 'http://127.0.0.1:' + srv.address().port + '/dashboards/live-scan.html?standalone=1';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright'); const browser = await chromium.launch(), errs = [];
  const wait = (p, fn, arg) => p.waitForFunction(fn, arg, { timeout: 30000 }).then(() => true, () => false);
  const toast = (p, re) => wait(p, (s) => [...document.querySelectorAll('.toast')].some((t) => new RegExp(s).test(t.textContent)), re);
  let ANS = [];
  const page = async (ctx) => { const p = await ctx.newPage(); p.on('pageerror', (x) => errs.push(x.message)); p.on('dialog', (d) => { const a = ANS.shift(); if (a === undefined) { errs.push('unexpected dialog'); d.dismiss(); } else d.accept(a); }); await p.goto(base); return p; };
  try {
    const ctx = await browser.newContext({ viewport: { width: 1500, height: 1000 } });
    let p = await page(ctx);
    ok(await wait(p, () => /Open critical/.test(document.getElementById('vs').textContent)), 'scanning KPIs');
    ok(/10\.20\.0\.0\/24/.test(await p.textContent('#vs')) && /excluded 10\.20\.0\.250/.test(await p.textContent('#vs')), 'the scope is shown');
    ok(await p.evaluate(() => !window.__xss && /<img/.test(document.getElementById('vs').textContent)), 'a hostile scan name stays text');
    ok(await wait(p, () => !!document.querySelector('[data-pick="10.20.0.5"]')), 'a stale critical finding becomes a smart target');
    await p.click('[data-pick="10.20.0.5"]'); ok((await p.inputValue('#vt')) === '10.20.0.5', 'picking fills the targets');
    await p.fill('#vform [name=reason]', 'retest of the critical listener finding (synthetic)'); await p.click('#vform button[type=submit]');
    ok(await toast(p, 'Scan requested'), 'scan requested');
    ok(await wait(p, () => /a different person approves/.test(document.getElementById('vs').textContent)) && !(await p.$('[data-sa]')), 'the requester cannot approve');
    ok(/Administrators run simulations/.test(await p.textContent('#bas')), 'an operator does not run simulations');
    WHO = { user: 'syed', role: 'admin' }; p = await page(ctx);
    ok(await wait(p, () => !!document.querySelector('[data-sa]')), 'an administrator sees Approve');
    await p.click('[data-sa]'); ok(await toast(p, 'Scan approved'), 'approved by a different person');
    ok(await wait(p, () => /approved/.test(document.getElementById('vs').textContent)), 'state approved');
    ok(/no simulation has run yet/.test(await p.textContent('#bas')), 'no simulation yet - said, not scored');
    await p.click('#brun'); ok(await toast(p, 'Simulation done'), 'run every scenario');
    ok(await wait(p, () => document.querySelectorAll('#scn tbody tr').length >= 5), 'scenario table');
    ok(/control/.test(await p.textContent('#gaps')), 'ranked gaps include the control scenario (by design)');
    ok(/detection assurance/.test(await p.textContent('#bas')) && /test scenario\(s\) detected in the last run/.test(await p.textContent('#bas')), 'assurance score with its reason');
    await p.selectOption('#sform [name=schedule]', 'daily'); await p.fill('#sform [name=hour]', '2'); await p.click('#sform button[type=submit]');
    ok(await toast(p, 'Schedule saved'), 'daily schedule saved'); ok(await wait(p, () => /Next scheduled run/.test(document.getElementById('sched').textContent)), 'next run shown');
    ok(AUD.some((a) => a.a === 'bas.assurance.run') && AUD.some((a) => a.a === 'bas.assurance.settings'), 'SIEM audit records');
    if (process.env.SHOT) await p.screenshot({ path: process.env.SHOT, fullPage: true });   // optional: a picture for review
    WHO = { user: 'vera.syn', role: 'viewer' }; p = await page(ctx);
    ok(await wait(p, () => /operators and administrators see them/.test(document.getElementById('vs').textContent)), 'a viewer sees no host');
    ok(await wait(p, () => document.querySelectorAll('#scn tbody tr').length >= 5) && !(await p.$('#brun')), 'a viewer reads the simulation, cannot run it');
    const nav = fs.readFileSync(path.join(DASH, 'vendor', 'zyb-nav.js'), 'utf8');
    ok(/"h": "live-scan.html"/.test(nav) && /live-scan\.html/.test(fs.readFileSync(path.join(DASH, 'install-dashboards.sh'), 'utf8')), 'menu entry and installer');
    ok(/scanlive: 'live-scan\.html'/.test(fs.readFileSync(path.join(DASH, 'vendor', 'zyb-menu.js'), 'utf8')) && /scanlive: 'live-scan\.html'/.test(fs.readFileSync(path.join(DASH, 'vendor', 'zyb-early.js'), 'utf8')), 'the portal Live Scan Engine opens this page');
    ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  } finally { await browser.close(); srv.close(); await e.close(); fs.rmSync(dir, { recursive: true, force: true }); }
  console.log((bad ? 'FAILED ' : 'ok ') + (n - bad) + '/' + n);
  process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
