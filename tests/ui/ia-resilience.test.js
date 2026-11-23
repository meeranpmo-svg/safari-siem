// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// IA Cyber & Operational Resilience (ia-resilience.html) against the REAL ITAM engines (SAMA CSF + IA register, DR drills, backup,
// engine/ia-resilience.js) with SYNTHETIC facts and drills: the resilience index and its explanation; five areas with a score or why
// not measured (backup); an area's requirements; the critical-system matrix with the weakest link and the drill-pass chance; the IA
// items with circular 277; attention; Excel with content; a hostile system name stays text; a viewer gets no Excel and no advisor;
// menu entry, the portal IA Framework redirect and the installer.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node ia-resilience.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const ITAM = path.join(__dirname, '..', '..', 'backend', 'itam'), DASH = path.join(__dirname, '..', '..', 'ui');
const H = require(path.join(ITAM, 'tests', 'helpers'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const FACTS = () => ({
  grc: { available: true, total: 20, reviews_overdue: 0, attested: 15, policies: [{ title: 'Information Security Policy (synthetic)', status: 'Approved', next_review: '2027-06-01' }], control_status: {} },
  hardening: { available: true, assets: 40, scanned: 38, coverage_pct: 95, score: 82, fail: 30, critical_fail: 2 },
  pentest: { available: true, assets: 12, findings: 4, by_severity: { critical: 0, high: 0 }, internet_facing: 3, exposed_assets: 0 },
  siem: { available: true, retention_days: 400, logflow: { required: 10, silent: 0, not_onboarded: 0, no_connector: 0 } },
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
  const base = 'http://127.0.0.1:' + srv.address().port + '/dashboards/';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright'); const browser = await chromium.launch(), errs = [];
  const wait = (p, fn, arg) => p.waitForFunction(fn, arg, { timeout: 30000 }).then(() => true, () => false);
  const toast = (p, re) => wait(p, (s) => [...document.querySelectorAll('.toast')].some((t) => new RegExp(s).test(t.textContent)), re);
  const page = async (ctx, f) => { const p = await ctx.newPage(); p.on('pageerror', (x) => errs.push(x.message)); p.on('dialog', (d) => { errs.push('unexpected dialog'); d.dismiss(); }); await p.goto(base + f + '?standalone=1'); await p.waitForSelector('#main:not([hidden])', { timeout: 60000 }); return p; };
  try {
    const G = e.app.addons.grc, w = { user: 'nora.syn', role: 'operator' };
    for (const [res, rto] of [['pass', 60], ['pass', 90]]) { const d = G.drillPut({ title: 'Failover core (synthetic)', system: 'CoreBanking', rto_target_min: 120, rpo_target_min: 15 }, w); G.drillResult(d.id, { result: res, rto_actual_min: rto, rpo_actual_min: 5 }, w); }
    const c = G.drillPut({ title: 'Claims restore (synthetic)', system: 'ClaimsPortal', rto_target_min: 60 }, w); G.drillResult(c.id, { result: 'fail', rto_actual_min: 240 }, w);
    G.drillPut({ title: 'HR tabletop (synthetic)', system: 'HR <img src=x onerror="window.__xss=1">', type: 'tabletop' }, w);
    const ctx = await browser.newContext({ viewport: { width: 1500, height: 1000 }, acceptDownloads: true });
    const p = await page(ctx, 'ia-resilience.html');
    ok(/^\d+$/.test((await p.textContent('#ring svg text')).trim()) && /Backup not measured and left out/.test(await p.textContent('#ring')), 'index with its explanation, backup left out');
    ok((await p.$$('#pls [data-area]')).length === 5 && /not measured: no backup platform connected/.test(await p.textContent('#pls [data-area="backup"]')), 'five areas, backup not measured');
    ok(/2 of 3 system\(s\) drilled within cadence/.test(await p.textContent('#pls [data-area="recover"]')), 'recoverability from the drills');
    await p.click('#pls [data-area="cyber"]'); ok(await wait(p, () => !document.getElementById('dlg').hidden && document.querySelectorAll('#dlgb tbody tr').length > 10), 'cyber area lists its requirements');
    await p.keyboard.press('Escape');
    const rows = await p.$$eval('#mx tbody tr', (r) => r.map((x) => x.textContent));
    ok(rows.length === 3 && /never drilled/.test(rows[0]), 'matrix: the never-drilled system first (weakest link)');
    ok(rows.some((r) => /ClaimsPortal/.test(r) && /missed/.test(r)) && rows.some((r) => /CoreBanking/.test(r) && /75%/.test(r)), 'RTO missed and the drill-pass chance');
    ok(rows.every((r) => /no backup matched/.test(r)), 'backup unknown when nothing matched, never ok');
    ok(/277/.test(await p.textContent('#circ')) && (await p.$$('#ia tbody tr')).length >= 1, 'IA items with the circular');
    ok(/never drilled/.test(await p.textContent('#attn')), 'attention');
    const [dl] = await Promise.all([p.waitForEvent('download', { timeout: 15000 }), p.click('#xls')]);
    ok(/^ia-cyber-operational-resilience-\d{4}-\d{2}-\d{2}\.xlsx$/.test(dl.suggestedFilename()), 'Excel');
    { const x = fs.readFileSync(await dl.path(), 'latin1'); ok(x.includes('CoreBanking') && x.includes('Weakest link') && x.includes('requirement'), 'Excel holds the matrix and the requirements'); }
    ok(!(await p.evaluate(() => window.__xss)), 'a hostile system name stayed text');
    if (process.env.SHOT) await p.screenshot({ path: process.env.SHOT, fullPage: true });   // optional: a picture for review
    WHO = { user: 'vera.syn', role: 'viewer' }; const v = await page(ctx, 'ia-resilience.html');
    ok(!(await v.isVisible('#xls')) && /shown to operators and administrators/.test(await v.textContent('#ai')), 'viewer: no Excel, no advisor');
    const nav = fs.readFileSync(path.join(DASH, 'vendor', 'zyb-nav.js'), 'utf8');
    ok(/"h": "ia-resilience.html"/.test(nav) && /ia-resilience\.html/.test(fs.readFileSync(path.join(DASH, 'install-dashboards.sh'), 'utf8')), 'menu entry and installer');
    ok(/iafw: 'ia-resilience\.html'/.test(fs.readFileSync(path.join(DASH, 'vendor', 'zyb-menu.js'), 'utf8')) && /iafw: 'ia-resilience\.html'/.test(fs.readFileSync(path.join(DASH, 'vendor', 'zyb-early.js'), 'utf8')), 'the portal IA Framework opens this page');
    ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  } finally { await browser.close(); srv.close(); await e.close(); }
  console.log((bad ? 'FAILED ' : 'ok ') + (n - bad) + '/' + n);
  process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
