// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Network Configuration Management (ncm.html + vendor/zyb-ncm.js) against the REAL SIEM module (engine/netops/ncm.js through
// netops/routes.js) with SYNTHETIC Cisco configurations: KPIs and filters, the device table ranked by risk, an unauthorised
// change flagged off-hours in the timeline, the device detail with versions and the line diff, set golden (then drift shown),
// download, a hostile config line stays text, a viewer sees counts only, menu entry, installer and the portal's ncm redirect.
// Run: SENTRA_SIEM_DIR=/home/user/sentra-siem PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node ncm.test.js
const http = require('http'), fs = require('fs'), os = require('os'), path = require('path'), crypto = require('crypto');
const DASH = path.join(__dirname, '..', '..', 'ui');
const SIEM = process.env.SENTRA_SIEM_DIR || path.resolve(__dirname, '../../backend/siem');
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const RANK = { viewer: 0, analyst: 1, operator: 2, admin: 3 }, H = 3600000, DAY = 24 * H;
const sha = (t) => crypto.createHash('sha256').update(t).digest('hex');
const CFG1 = 'hostname SW-JED-SYN\ninterface Gi1/0/24\n switchport access vlan 20\nlogging host 10.0.0.9';
const CFG2 = CFG1.replace('vlan 20', 'vlan 45') + '\nusername <img src=x onerror="window.__xss=1"> privilege 15';

(async () => {
  const sreq = (m) => require(path.join(SIEM, 'engine', m));
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sentra-ncmp-'));
  const state = await sreq('soc/state').createState({ dir });
  const config = { netops: { enabled: false } }; Object.defineProperty(config, 'secrets', { value: {}, enumerable: false, writable: true });
  const routes = sreq('netops/routes'), t0 = Date.now();
  const N = routes.createNetops({ state, config, log: { info() {}, warn() {}, error() {} }, poller: { snapshot: () => null, snapshots: () => ({}), stats: () => ({}), forget() {}, start() {} }, alerts: { raise: () => ({}) } });
  N.inventory.put({ id: 'sw-jed', name: 'SW-JED-SYN', vendor: 'cisco-ios', ip: '10.2.0.2', site: 'Jeddah Branch', role: 'access' }, 'test');
  const C = state.collection('netops_config_audit');
  const read = (text, t) => { const s = sha(text), p = C.get('sw-jed'), h = (p && p.history) || []; if (!p || p.sha256 !== s) h.push({ sha256: s, first_seen: t, previous_read: p ? p.at : null }); C.put({ id: 'sw-jed', name: 'SW-JED-SYN', vendor: 'cisco-ios', site: 'Jeddah Branch', at: t, checked: t, error: '', sha256: s, history: h, text }); N.ncm.capture(); };
  const night = new Date(t0 - DAY); night.setUTCHours(21, 0, 0, 0);   // 00:00 Riyadh: outside working hours
  read(CFG1, t0 - 5 * DAY); read(CFG2, night.getTime()); read(CFG2, t0 - H);
  const R = {}, AUD = [];
  routes.register({ route: (m, p, h) => { R[m + ' ' + p] = { re: new RegExp('^' + p.replace(/:([a-zA-Z]+)/g, '(?<$1>[^/]+)') + '$'), h }; } }, { state, config, log: { error() {}, info() {} }, netops: N });
  let WHO = { user: 'nora.syn', role: 'operator' };
  const srv = http.createServer((rq, res) => {
    const url = new URL(rq.url, 'http://x'), u = url.pathname, json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u === '/dashboards/whoami.json') return json(200, WHO);
    const hit = Object.entries(R).find(([k, v]) => k.startsWith(rq.method + ' ') && v.re.test(u));
    if (hit) { let b = ''; rq.on('data', (x) => { b += x; }); rq.on('end', async () => {
      const o = {}, m = hit[1].re.exec(u), ctx = { role: WHO.role, user: WHO.user, body: b ? JSON.parse(b) : {}, params: m.groups ? Object.fromEntries(Object.entries(m.groups).map(([k, v]) => [k, decodeURIComponent(v)])) : {}, query: Object.fromEntries(url.searchParams),
        need(r) { if (RANK[WHO.role] < RANK[r]) { o.status = 403; o.error = 'requires role ' + r; return false; } return true; }, audit: (a, t, d) => AUD.push({ a, t, d }), ok: (x) => x, fail(code, msg) { o.status = code; o.error = msg; } };
      try { const rv = await hit[1].h(ctx); if (o.status) return json(o.status, { error: o.error || 'refused' }); json(200, rv); } catch (x) { json(x.code || x.status || 500, { error: x.message }); } }); return; }
    if (u.startsWith('/api/')) return json(404, { error: 'not in this test' });
    const f = path.join(DASH, u.replace(/^\/dashboards\//, '')); if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (err, d) => { if (err) { res.writeHead(404); return res.end(); } res.writeHead(200, { 'Content-Type': f.endsWith('.js') ? 'application/javascript' : f.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port + '/dashboards/ncm.html?standalone=1';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright'); const browser = await chromium.launch(), errs = [];
  const wait = (p, fn, arg) => p.waitForFunction(fn, arg, { timeout: 20000 }).then(() => true, () => false);
  const toast = (p, re) => wait(p, (s) => [...document.querySelectorAll('.toast-zyb')].some((t) => new RegExp(s).test(t.textContent)), re);
  try {
    const ctx = await browser.newContext({ viewport: { width: 1500, height: 1000 }, acceptDownloads: true });
    let p = await ctx.newPage(); p.on('pageerror', (x) => errs.push(x.message));
    await p.goto(base);
    ok(await wait(p, () => !document.getElementById('main').hidden), 'page loads');
    ok(/1\s*Unauthorised \(30 d\)/i.test(await p.textContent('#kpis')), 'KPI: one unauthorised change');
    const tl = await p.textContent('#recent'); ok(/no change plan/.test(tl) && /outside working hours/.test(tl), 'timeline: unauthorised and off-hours: ' + tl.slice(0, 200));
    ok(/no approved change plan/.test(await p.$eval('#devs td[title]', (x) => x.getAttribute('title'))), 'risk points named on hover');
    await p.click('[data-f="unauth"]'); ok(await wait(p, () => document.querySelectorAll('#devs tbody tr').length === 1), 'Unauthorised tile filters');
    await p.click('[data-f="unauth"]');
    // device detail: versions and the diff
    await p.click('#devs tr[data-dev="sw-jed"] td:nth-child(2)');
    ok(await wait(p, () => document.querySelectorAll('#nd table tbody tr').length === 2 && /switchport access vlan 45/.test(document.getElementById('ndiff').textContent)), 'versions and the latest diff');
    ok(await p.evaluate(() => !window.__xss && /<img/.test(document.getElementById('ndiff').textContent)), 'a hostile configuration line stays text');
    ok(await p.$$eval('#ndiff .a', (L) => L.length) === 2 && await p.$$eval('#ndiff .r', (L) => L.length) === 1, 'added and removed lines coloured');
    // download
    const [dl] = await Promise.all([p.waitForEvent('download'), p.click('#nd [data-dl]')]);
    ok(/^sw-jed-[0-9a-f]{12}\.cfg$/.test(dl.suggestedFilename()), 'download: ' + dl.suggestedFilename());
    // golden on the first version, then drift
    await p.click('#nd [data-gold][data-sha="' + sha(CFG1) + '"]'); ok(await toast(p, 'Golden baseline set'), 'golden set');
    await p.evaluate(() => window.zybDetail.close());
    ok(await wait(p, () => /\+2 −1 lines/.test(document.getElementById('devs').textContent)), 'drift from golden shown');
    ok(AUD.some((a) => a.a === 'netops.ncm.golden') && AUD.some((a) => a.a === 'netops.ncm.download'), 'audited');
    // a viewer
    WHO = { user: 'vera.syn', role: 'viewer' }; p = await ctx.newPage(); p.on('pageerror', (x) => errs.push(x.message)); await p.goto(base + '&v=2');
    ok(await wait(p, () => !document.getElementById('main').hidden && /analysts and above/.test(document.getElementById('devs').textContent)), 'a viewer sees counts only');
    ok(await p.$eval('#backup', (b) => b.hidden), 'no Back up now for a viewer');
    const nav = fs.readFileSync(path.join(DASH, 'vendor', 'zyb-nav.js'), 'utf8'), inst = fs.readFileSync(path.join(DASH, 'install-dashboards.sh'), 'utf8');
    ok(/"h": "ncm\.html"/.test(nav) && / ncm\.html /.test(inst) && /zyb-ncm\.js/.test(inst), 'menu entry and installer');
    ok(/ncm: 'ncm\.html'/.test(fs.readFileSync(path.join(DASH, 'vendor', 'zyb-menu.js'), 'utf8')) && /ncm: 'ncm\.html'/.test(fs.readFileSync(path.join(DASH, 'vendor', 'zyb-early.js'), 'utf8')), 'the portal Network Config Management view opens this page');
    ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  } finally { await browser.close(); srv.close(); fs.rmSync(dir, { recursive: true, force: true }); }
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n);
  process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
