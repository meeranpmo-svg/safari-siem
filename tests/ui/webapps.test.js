// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Applications, Web Servers & APIs (webapps.html) against the REAL SIEM module (engine/integrations/webtier-routes.js) over a SYNTHETIC
// Applications Manager and the REAL ITAM Business Services and Certificates: health ring and KPIs; tier cards with itemised deductions; a
// host with two monitors down shown as the probable cause and its monitors grouped; the history learned (flapping, new problem); tier and
// problem chips, search; a server running IIS with no monitor listed as not monitored; a hostile monitor message stays text; the advisor
// is off without a key; a viewer reads; menu entry, installer, the portal's webapi redirect.
// Run: SENTRA_SIEM_DIR=/home/user/sentra-siem PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node webapps.test.js
const http = require('http'), fs = require('fs'), os = require('os'), path = require('path');
const ITAM = path.join(__dirname, '..', '..', 'backend', 'itam'), DASH = path.join(__dirname, '..', '..', 'ui');
const SIEM = process.env.SENTRA_SIEM_DIR || path.resolve(__dirname, '../../backend/siem');
const H = require(path.join(ITAM, 'tests', 'helpers'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const RANK = { viewer: 0, analyst: 1, operator: 2, admin: 3 };

(async () => {
  const e = await H.startApp({ noAi: true });
  require(path.join(ITAM, 'engine/duty')).registerDuty(e.app.srv, e.app, { noTimer: true, python: process.env.PYTHON || 'python3' });
  require(path.join(ITAM, 'engine/service-map')).registerServiceMap(e.app.srv, e.app, { noTimer: true, probe: { tcp: async () => false, http: async () => null, sql: async () => [] }, invRun: async () => ({ ok: false }) });   // as main.js does (install/add-service-map.sh)
  const col = (c) => e.app.store.collection(c);
  col('assets').put({ id: 'A-1', name: 'web09.syn', type: 'server', status: 'active', mgmt_ip: '10.30.0.9' });
  col('svc_map').put({ id: '10.30.0.9', at: Date.now(), probe: { open: [443], http: [{ port: 443, tls: true, server: 'Microsoft-IIS/10.0' }] } });
  // the SIEM module over a synthetic Applications Manager
  const sreq = (m) => require(path.join(SIEM, 'engine', m));
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sentra-webapps-')), Lq = { info() {}, warn() {}, error() {} };
  let clock = Date.now();
  const M = [
    { id: '101', name: 'Customer portal URL', type: 'URL Monitor', host: 'web01.syn', health: 'clear', availability: 'up', managed: true },
    { id: '201', name: 'Claims WebLogic', type: 'WebLogic Server', host: 'app01.syn', health: 'clear', availability: 'up', managed: true },
    { id: '202', name: 'Claims JVM', type: 'Java Runtime', host: 'app01.syn', health: 'clear', availability: 'up', managed: true },
    { id: '301', name: 'Partner quote API', type: 'REST API Monitor', host: 'api.partner.test', health: 'clear', availability: 'up', managed: true, message: '' },
  ];
  let APMCONF = true;
  const apm = { status: () => ({ configured: APMCONF, enabled: true, last_sync: clock, ok: true, error: '' }), monitors: () => M.map((m) => Object.assign({}, m)), alarms: () => [{ resource_id: '201', severity: 'critical', message: 'unreachable (synthetic)' }] };
  const deps = { state: sreq('soc/state').createState({ dir: path.join(dir, 'state'), log: Lq }), config: { soc_analyst: {} }, log: Lq, noTimers: true, meApm: apm, now: () => clock };
  const R = {}, AUD = [];
  sreq('integrations/webtier-routes').register({ route: (m, p, h) => { R[m + ' ' + p] = { re: new RegExp('^' + p.replace(/:([a-zA-Z]+)/g, '(?<$1>[^/]+)') + '$'), h }; } }, deps);
  const W = deps.webTier;
  for (let i = 0; i < 20; i++) { W.sample(); clock += 5 * 60000; }
  for (const m of M) if (m.host === 'app01.syn') { m.availability = 'down'; m.health = 'critical'; }
  const api = M.find((m) => m.id === '301'); api.availability = 'down'; api.message = '<img src=x onerror="window.__xss=1"> timeout';
  for (let i = 0; i < 6; i++) { M[0].availability = i % 2 ? 'down' : 'up'; W.sample(); clock += 5 * 60000; }
  M[0].availability = 'up';
  let WHO = { user: 'nora.syn', role: 'operator' };
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
  const base = 'http://127.0.0.1:' + srv.address().port + '/dashboards/webapps.html?standalone=1';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright'); const browser = await chromium.launch(), errs = [];
  const wait = (p, fn, arg) => p.waitForFunction(fn, arg, { timeout: 30000 }).then(() => true, () => false);
  const toast = (p, re) => wait(p, (s) => [...document.querySelectorAll('.toast')].some((t) => new RegExp(s).test(t.textContent)), re);
  let ANS = [];
  const page = async (ctx) => { const p = await ctx.newPage(); p.on('pageerror', (x) => errs.push(x.message)); p.on('dialog', (d) => { const a = ANS.shift(); if (a === undefined) { errs.push('unexpected dialog'); d.dismiss(); } else d.accept(a); }); await p.goto(base); return p; };
  try {
    const ctx = await browser.newContext({ viewport: { width: 1500, height: 1000 } });
    // regression: Applications Manager not connected must not crash the page (it read cov.length on null)
    APMCONF = false; let p = await page(ctx);
    ok(await wait(p, () => /not connected/.test(document.getElementById('probs').textContent) && document.getElementById('err').hidden), 'not connected: the reason, not "Could not load"');
    ok(await wait(p, () => /web09\.syn/.test(document.getElementById('gaps').textContent)), 'not connected: servers running web software are still listed as not monitored');
    APMCONF = true; p = await page(ctx);
    ok(await wait(p, () => /application health/.test(document.getElementById('ring').textContent)), 'health ring');
    ok(/Probable-cause hosts/.test(await p.textContent('#kpis')) && /Servers not monitored/.test(await p.textContent('#kpis')), 'KPIs');
    const tiers = await p.textContent('#tiers'); ok(/Application servers[\s\S]*0 of 2 up/.test(tiers) && /critical alarm/.test(tiers), 'tier cards with itemised deductions');
    ok(/Web tier[\s\S]*flapping monitor/.test(tiers), 'flapping deducted on the web tier');
    ok(/app01\.syn[\s\S]*probable cause/.test(await p.textContent('#probs')), 'probable-cause host');
    ok(!/Claims JVM/.test(await p.$eval('#probs', (x) => [...x.querySelectorAll('.att')].slice(1).map((a) => a.textContent).join(' '))), 'its monitors are grouped, not listed again');
    ok(/Partner quote API[\s\S]*new/.test(await p.textContent('#probs')), 'a new problem');
    ok(await p.evaluate(() => !window.__xss && /<img/.test(document.getElementById('probs').textContent)), 'a hostile monitor message stays text');
    ok(await wait(p, () => /web09\.syn/.test(document.getElementById('gaps').textContent) && /Microsoft IIS/.test(document.getElementById('gaps').textContent)), 'a server running IIS with no monitor is listed');
    await p.click('[data-tf="api"]'); ok(await wait(p, () => document.querySelectorAll('#mons tbody tr').length === 1 && /Partner quote API/.test(document.getElementById('mons').textContent)), 'API chip');
    await p.click('[data-tf="flapping"]'); ok(await wait(p, () => document.querySelectorAll('#mons tbody tr').length === 1 && /Customer portal URL/.test(document.getElementById('mons').textContent)), 'flapping chip');
    await p.click('[data-tf="all"]'); await p.fill('#q', 'jvm'); ok(await wait(p, () => document.querySelectorAll('#mons tbody tr').length === 1), 'search');
    ok(/availability|samples up/.test(await p.textContent('#mons')), 'learned availability shown');
    ok(/No certificate endpoint is registered/.test(await p.textContent('#certs')), 'certificates: what to do when none is registered');
    ok(/Not available/.test(await p.textContent('#ai')), 'advisor off without a key');
    if (process.env.SHOT) await p.screenshot({ path: process.env.SHOT, fullPage: true });   // optional: a picture for review
    WHO = { user: 'vera.syn', role: 'viewer' }; p = await page(ctx);
    ok(await wait(p, () => /probable cause/.test(document.getElementById('probs').textContent)) && /operators and administrators/.test(await p.textContent('#ai')), 'a viewer reads; the advisor is for operators');
    const nav = fs.readFileSync(path.join(DASH, 'vendor', 'zyb-nav.js'), 'utf8');
    ok(/"h": "webapps.html"/.test(nav) && /webapps\.html/.test(fs.readFileSync(path.join(DASH, 'install-dashboards.sh'), 'utf8')), 'menu entry and installer');
    ok(/webapi: 'webapps\.html'/.test(fs.readFileSync(path.join(DASH, 'vendor', 'zyb-menu.js'), 'utf8')) && /webapi: 'webapps\.html'/.test(fs.readFileSync(path.join(DASH, 'vendor', 'zyb-early.js'), 'utf8')), 'the portal Web, Apps & APIs opens this page');
    ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  } finally { await browser.close(); srv.close(); await e.close(); fs.rmSync(dir, { recursive: true, force: true }); }
  console.log((bad ? 'FAILED ' : 'ok ') + (n - bad) + '/' + n);
  process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
