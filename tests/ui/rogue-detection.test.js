// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// rogue-detection.html against the REAL SIEM rogue detection (sentra-siem engine/netops/rogue.js via routes.js; polls stubbed, the
// port map's reads written as SYNTHETIC data): KPIs and source counts, the riskiest device first, a row opens its itemised risk,
// a KPI filters, search, Guest for N days and Trust with a reason, bulk Suspect, a device off any read port cannot be blocked from
// here and says where to block it, a hostile host name stays text, a viewer sees counts only, menu / installer / portal redirect.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node rogue-detection.test.js
const http = require('http'), fs = require('fs'), os = require('os'), path = require('path');
const DASH = path.resolve(__dirname, '../../ui');
const SIEM = process.env.SENTRA_SIEM || path.resolve(__dirname, '../..', 'backend', 'siem');
const routes = require(path.join(SIEM, 'engine/netops/routes'));
const { createState } = require(path.join(SIEM, 'engine/soc/state'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const XSS = '<img src=x onerror="window.__xss=1">';
const DAY = 86400000, H = 3600000;

(async () => {
  const NOW = Date.now();
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'rg-page-')), secrets = path.join(dir, 'secrets.json'); fs.writeFileSync(secrets, '{}', { mode: 0o600 });
  const oui = path.join(dir, 'oui.csv'); fs.writeFileSync(oui, 'MA-L,B827EB,"Raspberry Pi Foundation (synthetic)",x\nMA-L,3C5282,"Synthetic HP Inc.",y\nMA-L,0026B9,"Synthetic Dell Inc.",z\n');
  const state = await createState({ dir: path.join(dir, 'state') });
  const config = { netops: { enabled: false, portmap: { oui_file: oui } } };
  Object.defineProperty(config, 'secrets', { value: {}, enumerable: false, writable: true }); Object.defineProperty(config, '_paths', { value: { secrets }, enumerable: false });
  const snaps = {
    'fw-syn': { at: NOW, ok: true, dhcp: [{ ip: '10.10.0.50', mac: 'b8:27:eb:00:00:01', host: '' }, { ip: '10.10.0.21', mac: '3c:52:82:aa:00:01', host: 'PC-FIN-01' }], arp: [{ ip: '10.10.0.77', mac: '7a:11:22:33:44:55', iface: 'guest-wifi' }] },
    'nac-syn': { at: NOW, ok: true, nac: { items: [{ mac: '3C:52:82:AA:00:01', ip: '10.10.0.21', host: 'PC-FIN-01', status: 'Authorized' }, { mac: 'b8:27:eb:00:00:01', ip: '10.10.0.50', host: XSS, status: 'Unauthorized' }] } },
  };
  const poller = { snapshot: (id) => snaps[id] || null, snapshots: () => snaps, stats: () => ({}), forget() {}, start() {} };
  const N = routes.createNetops({ state, config, log: { info() {}, warn() {}, error() {} }, poller });
  N.inventory.put({ id: 'fw-syn', name: 'FW-SYN', vendor: 'fortigate', ip: '10.0.0.1', role: 'firewall' }, 'test');
  N.inventory.put({ id: 'nac-syn', name: 'GENIAN-SYN', vendor: 'genian', ip: '10.0.5.9', role: 'nac' }, 'test');
  N.inventory.put({ id: 'acc-syn', name: 'ACC-SYN', vendor: 'cisco-ios', ip: '10.0.5.2', site: 'Riyadh HQ', role: 'access' }, 'test');
  state.collection('portmap_reads').put({ id: 'acc-syn', at: NOW - H, ports: [], trunks: [], vlans: { 10: 'USERS', 30: 'SERVERS' }, errors: [], neighbours: [],
    macs: [{ vlan: 30, mac: 'b827eb000001', port: 'Gi1/0/9' }, { vlan: 10, mac: '3c5282aa0001', port: 'Gi1/0/1' }, { vlan: 10, mac: '0026b9000004', port: 'Gi1/0/4' }, { vlan: 10, mac: '0026b9000005', port: 'Gi1/0/4' }, { vlan: 10, mac: '0026b9000006', port: 'Gi1/0/4' }], arp: [] });
  const pm = state.collection('portmap_macs');
  pm.put({ id: 'b827eb000001', device: 'acc-syn', port: 'gi1/0/9', first: NOW - 2 * H, last: NOW - H, moves: [] });
  pm.put({ id: '3c5282aa0001', device: 'acc-syn', port: 'gi1/0/1', first: NOW - 90 * DAY, last: NOW - H, moves: [] });
  for (const m of ['0026b9000004', '0026b9000005', '0026b9000006']) pm.put({ id: m, device: 'acc-syn', port: 'gi1/0/4', first: NOW - 30 * DAY, last: NOW - H, moves: [] });
  const R = []; routes.register({ route: (m, p, h) => { R.push({ m, re: new RegExp('^' + p.replace(/:[a-z]+/g, '([^/]+)') + '$'), h }); } }, { state, config, log: { error() {}, info() {} }, netops: N, noTimers: true });
  const RANK = { viewer: 0, analyst: 1, operator: 2, admin: 3 };
  async function dispatch(method, pathname, body, role, user) {
    const r = R.find((x) => x.m === method && x.re.test(pathname)); if (!r) return { c: 404, b: { error: 'not found' } };
    const out = {}, ctx = { role, user, body, params: {}, query: {}, path: pathname, need(x) { if (RANK[role] < RANK[x]) { out.c = 403; out.e = 'requires ' + x; return false; } return true; }, audit() {}, fail(c, e) { out.c = c; out.e = e; } };
    const rv = await r.h(ctx); return out.c ? { c: out.c, b: { error: out.e } } : { c: 200, b: rv };
  }
  let WHO = { user: 'nora.syn', role: 'operator' };
  const srv = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://x'), json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u.pathname === '/dashboards/whoami.json') return json(200, WHO);
    if (u.pathname.startsWith('/api/soc/netops/')) { let b = ''; req.on('data', (c) => { b += c; }); req.on('end', async () => { const r = await dispatch(req.method, u.pathname, b ? JSON.parse(b) : {}, WHO.role, WHO.user); json(r.c, r.b); }); return; }
    if (u.pathname.startsWith('/api/')) return json(404, { error: 'not found' });
    const f = path.join(DASH, u.pathname.replace(/^\/dashboards\//, '/')); if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (err, d) => { if (err) { res.writeHead(404); res.end(); return; } res.writeHead(200, { 'Content-Type': u.pathname.endsWith('.js') ? 'application/javascript' : u.pathname.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const url = 'http://127.0.0.1:' + srv.address().port + '/dashboards/rogue-detection.html';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  const wait = (p, fn, arg) => p.waitForFunction(fn, arg, { timeout: 15000 }).then(() => true, () => false);
  const L = (p) => p.textContent('#list');
  try {
    const p = await browser.newPage({ viewport: { width: 1500, height: 1000 } }); p.on('pageerror', (x) => errs.push(x.message));
    let answer = ''; p.on('dialog', (d) => d.accept(answer));
    await p.goto(url); ok(await wait(p, () => document.querySelectorAll('tr.dv').length === 6), 'six devices from four sources');
    const K = await p.textContent('#kpis'); ok(/1\s*rogue/.test(K) && /1\s*trusted/.test(K) && /1\s*ports with an unmanaged switch/.test(K), 'KPIs');
    ok(/switch ports 5/.test(await p.textContent('#src')) && /firewall DHCP 2/.test(await p.textContent('#src')) && /Genian NAC 2/.test(await p.textContent('#src')), 'source counts');
    ok(/b8:27:eb:00:00:01/.test(await p.$eval('tr.dv', (r) => r.textContent)) && /Raspberry Pi/.test(await p.$eval('tr.dv', (r) => r.textContent)), 'the riskiest device first, with its vendor');
    await p.click('tr.dv[data-d="b8:27:eb:00:00:01"]');
    ok(await wait(p, () => /maker board/.test(document.getElementById('list').textContent) && /NAC refused it/.test(document.getElementById('list').textContent) && /SERVERS/.test(document.getElementById('list').textContent)), 'itemised risk points');
    ok(!(await p.evaluate(() => window.__xss)), 'a hostile host name stayed text');
    await p.click('[data-k="trusted"]'); ok(await wait(p, () => document.querySelectorAll('tr.dv').length === 1) && /PC-FIN-01/.test(await L(p)), 'a KPI filters the list');
    await p.click('[data-k="trusted"]'); await p.fill('#q', 'guest-wifi'); ok(await wait(p, () => document.querySelectorAll('tr.dv').length === 1), 'search');
    // guest for 1 day, then trust with a reason
    await p.click('tr.dv[data-d="7a:11:22:33:44:55"]'); await wait(p, () => document.getElementById('gd-7a:11:22:33:44:55'));
    ok(/Not on a read switch port - block it in Genian NAC/.test(await L(p)), 'a device on no read port says where to block it');
    await p.selectOption('[id="gd-7a:11:22:33:44:55"]', '1'); await p.click('[data-lab="guest"][data-m="7a:11:22:33:44:55"]');
    ok(await wait(p, () => /1 device\(s\): guest/.test(document.body.textContent)), 'guest label');
    await p.fill('#q', ''); ok(await wait(p, () => /1\s*guests/.test(document.getElementById('kpis').textContent)), 'guest counted');
    answer = 'synthetic lab switch, asset SYN-77';
    await p.check('[data-sel="00:26:b9:00:00:04"]'); await p.check('[data-sel="00:26:b9:00:00:05"]');
    ok(await wait(p, () => /2 selected/.test(document.body.textContent)), 'bulk selection');
    await p.click('[data-bulk="trusted"]'); ok(await wait(p, () => /2 device\(s\): trusted/.test(document.body.textContent)), 'bulk trust with the reason asked');
    ok(await wait(p, () => /3\s*trusted/.test(document.getElementById('kpis').textContent)), 'now three trusted');
    // phone
    const ph = await browser.newPage({ viewport: { width: 390, height: 900 } }); await ph.goto(url); await wait(ph, () => document.querySelector('tr.dv'));
    ok(await ph.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1), 'phone width: no sideways scroll'); await ph.close();
    // viewer
    WHO = { user: 'vera.syn', role: 'viewer' }; await p.goto(url); await wait(p, () => !document.getElementById('main').hidden);
    ok(/for analysts and above/.test(await L(p)) && !(await p.$('tr.dv')) && /devices/.test(await p.textContent('#kpis')), 'viewer: counts only, says why');
    const nav = fs.readFileSync(path.join(DASH, 'vendor', 'zyb-nav.js'), 'utf8');
    ok(/"h": "rogue-detection.html"/.test(nav) && / rogue-detection\.html /.test(fs.readFileSync(path.join(DASH, 'install-dashboards.sh'), 'utf8')), 'menu entry and installer');
    ok(/rogue: 'rogue-detection\.html'/.test(fs.readFileSync(path.join(DASH, 'vendor', 'zyb-menu.js'), 'utf8')), 'the portal\'s old "Advanced Rogue Detection" opens this page');
    ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  } finally { await browser.close(); srv.close(); }
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n);
  process.exit(bad ? 1 : 0);
})();
