// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for wan-optimization.html after the static build. The answers come from the REAL SIEM engine (sentra-siem
// engine/netops/wanopt.js through netops/routes.js) over a SYNTHETIC Orchestrator snapshot: one appliance down, one measured at
// 70 % reduction, one whose WAN counters are not reported, a critical and a warning tunnel, a critical alarm, a failed statistics
// call. Checks: reachable from the menu, tiles, actions in order, "not reported" never shown as zero, tunnel filter, escaping,
// thresholds (admin saves, operator cannot), nothing configured says what to do, the portal's infra-wanopt view redirects here.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node wan-optimization.test.js
const http = require('http'), fs = require('fs'), path = require('path'), os = require('os'), cp = require('child_process');
const SRC = path.resolve(__dirname, '../../ui');
let n = 0, bad = 0;
const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const B = fs.mkdtempSync(path.join(os.tmpdir(), 'apmpage-')); fs.mkdirSync(path.join(B, 'vendor'));
fs.readdirSync(SRC).filter((f) => f.endsWith('.html')).forEach((f) => fs.copyFileSync(path.join(SRC, f), path.join(B, f)));
fs.readdirSync(path.join(SRC, 'vendor')).filter((f) => /\.(js|json|css)$/.test(f)).forEach((f) => fs.copyFileSync(path.join(SRC, 'vendor', f), path.join(B, 'vendor', f)));
['zyb-menu.js', 'zyb-dash.js'].forEach((t) => fs.writeFileSync(path.join(B, 'vendor', t), fs.readFileSync(path.join(B, 'vendor/zyb-nav.js'), 'utf8') + '\n' + fs.readFileSync(path.join(B, 'vendor', t), 'utf8')));
cp.execFileSync(process.execPath, [path.join(SRC, 'build-static.js'), B, 't1'], { stdio: 'ignore' });



const SIEM = process.env.SENTRA_SIEM_DIR || path.resolve(__dirname, '../../backend/siem');
const { createState } = require(path.join(SIEM, 'engine/soc/state'));
const routes = require(path.join(SIEM, 'engine/netops/routes'));
const XSS = '<img src=x onerror="window.__xss=1">';
const snaps = { orc: { at: Date.now(), ok: true, sources: ['api'], errors: [],
  sdwan: { appliances: [{ name: 'EC-RUH', site: 'Riyadh', up: true, state: 'normal', model: 'EC-S' }, { name: 'EC-JED ' + XSS, site: 'Jeddah', up: true, state: 'normal' }, { name: 'EC-DMM', site: 'Dammam', up: false, state: 'unreachable' }],
    alarms: [{ severity: 'critical', appliance: 'EC-DMM', text: 'Appliance unreachable' }] },
  wanopt: { at: Date.now(), window_s: 3600, errors: ['applications: HTTP 403'], keys: { appliances: ['LAN_TX_BYTES', 'WAN_TX_BYTES'] },
    appliances: [{ name: 'EC-RUH', lan_tx: 6e9, lan_rx: 4e9, wan_tx: 2.5e9, wan_rx: 0.5e9 }, { name: 'EC-JED ' + XSS, lan_tx: 2e9, lan_rx: null, wan_tx: null, wan_rx: null }],
    applications: [{ name: 'SMB', lan_tx: 3e9, wan_tx: 0.6e9 }],
    tunnels: [{ name: 'RUH-JED', appliance: 'EC-RUH', loss_pct: 12, latency_ms: 40, jitter_ms: 2 }, { name: 'RUH-DMM', appliance: 'EC-RUH', loss_pct: 0.1, latency_ms: 180, jitter_ms: 5 }, { name: 'RUH-DR', appliance: 'EC-RUH', loss_pct: 0, latency_ms: 20, jitter_ms: 1 }] } } };
let ROLE = 'admin', EMPTY = false; const POSTS = [];
(async () => {
  const state = await createState({ dir: fs.mkdtempSync(path.join(os.tmpdir(), 'wopage-st-')) });
  const config = { netops: { enabled: false } }; Object.defineProperty(config, 'secrets', { value: {}, enumerable: false, writable: true });
  const poller = { snapshot: (id) => (EMPTY ? null : snaps[id] || null), snapshots: () => snaps, stats: () => ({}), forget() {}, start() {} };
  const N = routes.createNetops({ state, config, log: { info() {}, warn() {}, error() {} }, poller });
  N.inventory.put({ id: 'orc', name: 'ORCH-SYN', vendor: 'edgeconnect', ip: '10.0.0.9', role: 'sdwan-orchestrator' }, 'test');
  const R = {}; routes.register({ route: (m, p, h) => { R[m + ' ' + p] = h; } }, { state, config, log: { error() {}, info() {} }, netops: N });
  const RANK = { viewer: 0, analyst: 1, operator: 2, admin: 3 };
  const srv = http.createServer((q, r) => {
    const u = q.url.split('?')[0], j = (c, o) => { r.writeHead(c, { 'Content-Type': 'application/json' }); r.end(JSON.stringify(o)); };
    if (u.endsWith('whoami.json')) return j(200, { user: 'syed', role: ROLE });
    if (u.startsWith('/api/soc/netops/')) {
      let b = ''; q.on('data', (c) => { b += c; }); q.on('end', async () => {
        const bodyIn = b ? JSON.parse(b) : {}; if (q.method === 'POST') POSTS.push({ u, body: bodyIn });
        if (EMPTY && q.method === 'GET') return j(200, { configured: false, reason: 'No Silver Peak / EdgeConnect Orchestrator is connected - add it in Network Onboarding (vendor edgeconnect, API key), then its appliances and statistics appear here.' });
        const h = R[q.method + ' ' + u]; if (!h) return j(404, { error: 'not in this test' });
        const out = {}; const ctx = { role: ROLE, user: 'syed', body: bodyIn, params: {}, query: {}, need(x) { if (RANK[ROLE] < RANK[x]) { out.c = 403; out.e = 'requires ' + x; return false; } return true; }, audit() {}, fail(c, e) { out.c = c; out.e = e; } };
        try { const rv = await h(ctx); if (out.c) return j(out.c, { error: out.e }); return j(200, rv); } catch (e) { return j(e.code || e.status || 500, { error: e.message }); }
      }); return;
    }
    if (u.startsWith('/api/')) return j(404, { error: 'not in this test' });
    const f = path.join(B, u === '/' ? 'index.html' : u); if (!f.startsWith(B)) { r.writeHead(403); return r.end(); }
    fs.readFile(f, (e, d) => { if (e) { r.writeHead(404); return r.end(); } r.writeHead(200, { 'Content-Type': u.endsWith('.js') ? 'application/javascript' : u.endsWith('.css') ? 'text/css' : 'text/html' }); r.end(d); });
  });
  await new Promise((res) => srv.listen(0, '127.0.0.1', res));
  const base = 'http://127.0.0.1:' + srv.address().port + '/';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  const open = async (pg) => { const p = await browser.newPage({ viewport: { width: 1500, height: 950 } }); p.on('pageerror', (e) => errs.push(e.message)); p.on('dialog', (d) => { errs.push('dialog ' + d.message()); d.dismiss(); }); await p.goto(base + (pg || 'wan-optimization.html')); return p; };
  const txt = (p, id) => p.evaluate((i) => (document.getElementById(i) || {}).textContent || '', id);

  let p = await open('sdwan.html'); await p.waitForTimeout(800);
  const link = await p.evaluate(() => { const a = document.querySelector('a[href="wan-optimization.html"]'); return a ? a.textContent.trim() : null; });
  ok(/WAN Optimization/.test(link || ''), 'menu entry exists: ' + link);
  await p.evaluate(() => document.querySelector('a[href="wan-optimization.html"]').click());
  await p.waitForURL(/wan-optimization\.html/); await p.waitForSelector('#x-app');
  const kp = await txt(p, 'kp');
  ok(/Data reduction70 %/i.test(kp) && /1 of 3 appliances measured/.test(kp), 'reduction tile: ' + kp.slice(0, 160));
  ok(/Bytes saved7 GB/i.test(kp), 'bytes saved tile');
  ok(/Appliances down1/i.test(kp) && /Tunnels critical1/i.test(kp), 'down + tunnel tiles');
  const acts = await p.evaluate(() => [].map.call(document.querySelectorAll('#x-act .act b'), (b) => b.textContent));
  ok(/appliance\(s\) down/.test(acts[0]) && /tunnel\(s\) over the critical/.test(acts[1]) && /critical \/ major/.test(acts[2]), 'actions in order: ' + acts.join(' | '));
  ok(acts.some((a) => /not read from the Orchestrator/.test(a)), 'a failed statistics call is surfaced');
  const jedRow = await p.evaluate(() => [].find.call(document.querySelectorAll('#x-app tr'), (r) => /EC-JED/.test(r.textContent)).textContent);
  ok(/not reported/i.test(jedRow) && !/0 B/.test(jedRow), 'WAN counters missing: "not reported", never 0');
  ok(await p.evaluate(() => !window.__xss) && !(await p.$('#body img')), 'appliance names are escaped');
  await p.click('[data-tf="critical"]');
  ok((await p.$$('#x-tun tbody tr')).length === 1 && /RUH-JED/.test(await txt(p, 'x-tun')), 'tunnel filter: critical only');
  ok(/SMB/.test(await txt(p, 'x-aps')) && /80 %/.test(await txt(p, 'x-aps')), 'application reduction');
  ok(/LAN_TX_BYTES/.test(await txt(p, 'x-con')) && /HTTP 403/.test(await txt(p, 'x-con')), 'fields used and the failed call are shown');
  await p.fill('#th-loss_crit', '8'); await p.click('#ths'); await p.waitForTimeout(500);
  ok(POSTS.some((x) => x.u.endsWith('/netops/wanopt/config') && x.body.loss_crit === 8), 'admin saves the thresholds');
  await p.close();

  ROLE = 'operator'; p = await open(); await p.waitForSelector('#x-con');
  ok(!(await p.$('#ths')) && await p.evaluate(() => document.getElementById('th-loss_warn').disabled), 'operator: thresholds read only');
  await p.close();

  EMPTY = true; p = await open(); await p.waitForFunction(() => /Network Onboarding/.test(document.getElementById('body').textContent));
  ok(!(await p.$('#x-app')), 'nothing configured: says what to do, nothing invented');
  await p.close();

  ok(/'infra-wanopt': 'wan-optimization\.html'/.test(fs.readFileSync(path.join(SRC, 'vendor/zyb-menu.js'), 'utf8')), 'the portal infra-wanopt view redirects here');
  ok(/ wan-optimization\.html /.test(fs.readFileSync(path.join(SRC, 'install-dashboards.sh'), 'utf8')), 'in the installer');
  ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  await browser.close(); srv.close();
  console.log(`${n - bad}/${n} checks passed`); process.exit(bad ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });
