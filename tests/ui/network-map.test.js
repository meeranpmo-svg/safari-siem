// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// network-map.html against the REAL SIEM network-map engine (sentra-siem engine/netops/netmap.js via routes.js; the polls stubbed and
// the port map's neighbour reads written as a SYNTHETIC network): the map draws the devices in layers with their links; a device
// opens with its detail and links; "what fails with it" highlights what is cut off; a path is traced hop by hop; findings name the
// single point of failure, the down switch, the unmanaged switch and the one-sided link and open on the map; a snapshot then a
// change shows under Changes; an operator drags a device and saves the layout; a hostile device name stays text; a viewer sees no
// IP and no impact / path; with nothing read the page says where the map comes from; the menu entry, installer and portal redirect.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node network-map.test.js
const http = require('http'), fs = require('fs'), os = require('os'), path = require('path');
const DASH = path.resolve(__dirname, '../../ui');
const SIEM = process.env.SENTRA_SIEM || path.resolve(__dirname, '../..', 'backend', 'siem');
const routes = require(path.join(SIEM, 'engine/netops/routes'));
const { createState } = require(path.join(SIEM, 'engine/soc/state'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const XSS = '<img src=x onerror="window.__xss=1">';

(async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'nm-page-')), secrets = path.join(dir, 'secrets.json'); fs.writeFileSync(secrets, '{}', { mode: 0o600 });
  const state = await createState({ dir: path.join(dir, 'state') });
  const config = { netops: { enabled: false } };
  Object.defineProperty(config, 'secrets', { value: {}, enumerable: false, writable: true }); Object.defineProperty(config, '_paths', { value: { secrets }, enumerable: false });
  const now = Date.now();
  const snaps = {
    'fw-syn': { at: now, ok: true, sources: ['ping'], reach: { sent: 3, received: 3, rtt_avg_ms: 1 } },
    'core-syn': { at: now, ok: true, sources: ['ping', 'snmp'], reach: { sent: 3, received: 3 }, interfaces: [{ name: 'TenGigabitEthernet1/1/1', oper: 'up', util_in: 12, util_out: 30 }, { name: 'TenGigabitEthernet1/1/2', oper: 'down' }] },
    'acc-a': { at: now, ok: true, sources: ['ping'], reach: { sent: 3, received: 3 } },
    'acc-b': { at: now, ok: false, sources: ['ping'], reach: { sent: 3, received: 0 } },
  };
  const poller = { snapshot: (id) => snaps[id] || null, snapshots: () => snaps, stats: () => ({}), forget() {}, start() {} };
  const N = routes.createNetops({ state, config, log: { info() {}, warn() {}, error() {} }, poller });
  const put = (d) => N.inventory.put(d, 'test');
  put({ id: 'fw-syn', name: 'FW-SYN', vendor: 'paloalto', ip: '10.0.0.1', site: 'Riyadh HQ', role: 'firewall' });
  put({ id: 'core-syn', name: 'CORE-SYN', vendor: 'cisco-ios', ip: '10.0.0.2', site: 'Riyadh HQ', role: 'core' });
  put({ id: 'acc-a', name: 'ACC-A-SYN', vendor: 'cisco-ios', ip: '10.0.5.2', site: 'Riyadh HQ', role: 'access' });
  put({ id: 'acc-b', name: 'ACC-B-SYN', vendor: 'cisco-ios', ip: '10.0.5.3', site: 'Riyadh HQ', role: 'access' });
  put({ id: 'lonely', name: 'LONELY-SYN', vendor: 'fortigate', ip: '10.9.9.9', site: 'Jeddah', role: 'branch-router' });
  const nb = (local, name, ip, caps, remote_port) => ({ local, name, ip, caps, remote_port, platform: '', via: 'cdp' });
  const reads = state.collection('portmap_reads');
  const R = []; routes.register({ route: (m, p, h) => { R.push({ m, re: new RegExp('^' + p.replace(/:[a-z]+/g, '([^/]+)') + '$'), keys: (p.match(/:[a-z]+/g) || []).map((k) => k.slice(1)), h }); } }, { state, config, log: { error() {}, info() {} }, netops: N, noTimers: true });
  const RANK = { viewer: 0, analyst: 1, operator: 2, admin: 3 };
  async function dispatch(method, pathname, query, body, role, user) {
    const r = R.find((x) => x.m === method && x.re.test(pathname)); if (!r) return { c: 404, b: { error: 'not found' } };
    const mm = r.re.exec(pathname), params = {}; r.keys.forEach((k, i) => { params[k] = decodeURIComponent(mm[i + 1]); });
    const out = {}, ctx = { role, user, body, params, query, path: pathname, need(x) { if (RANK[role] < RANK[x]) { out.c = 403; out.e = 'requires ' + x; return false; } return true; }, audit() {}, fail(c, e) { out.c = c; out.e = e; } };
    const rv = await r.h(ctx); return out.c ? { c: out.c, b: { error: out.e } } : { c: 200, b: rv };
  }
  let WHO = { user: 'nora.syn', role: 'operator' };
  const srv = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://x'), json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u.pathname === '/dashboards/whoami.json') return json(200, WHO);
    if (u.pathname.startsWith('/api/soc/netops/')) { let b = ''; req.on('data', (c) => { b += c; }); req.on('end', async () => { const r = await dispatch(req.method, u.pathname, Object.fromEntries(u.searchParams), b ? JSON.parse(b) : {}, WHO.role, WHO.user); json(r.c, r.b); }); return; }
    if (u.pathname.startsWith('/api/')) return json(404, { error: 'not found' });
    const f = path.join(DASH, u.pathname.replace(/^\/dashboards\//, '/')); if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (err, d) => { if (err) { res.writeHead(404); res.end(); return; } res.writeHead(200, { 'Content-Type': u.pathname.endsWith('.js') ? 'application/javascript' : u.pathname.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const url = 'http://127.0.0.1:' + srv.address().port + '/dashboards/network-map.html';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  const wait = (p, fn, arg) => p.waitForFunction(fn, arg, { timeout: 15000 }).then(() => true, () => false);
  try {
    const ctx = await browser.newContext({ viewport: { width: 1500, height: 1000 } });
    const p = await ctx.newPage(); p.on('pageerror', (x) => errs.push(x.message));
    // nothing read yet: says where the map comes from, lists the inventory as not placed
    await p.goto(url); await wait(p, () => !document.getElementById('main').hidden);
    ok(/No link discovered yet/.test(await p.textContent('#view')) && /Switch Port Map/.test(await p.textContent('#view')), 'empty: says the map comes from the switches\' neighbour tables');
    await p.click('[data-tab="placed"]'); ok(/LONELY-SYN/.test(await p.textContent('#view')) && /not read yet on the Switch Port Map/.test(await p.textContent('#view')), 'not placed, with why');
    // the synthetic network is read
    reads.put({ id: 'core-syn', at: now - 3600000, ports: [], trunks: [], macs: [], errors: [], neighbours: [nb('Gi1/0/1', 'fw-syn', '10.0.0.1', ['Router'], 'ethernet1/3'), nb('Te1/1/1', 'ACC-A-SYN.as.local', '', ['Switch'], 'Te1/1/1'), nb('Te1/1/2', 'x', '10.0.5.3', ['Switch'], 'Te1/1/1')] });
    reads.put({ id: 'acc-a', at: now - 3600000, ports: [], trunks: [], macs: [{ port: 'Gi1/0/1', mac: 'a' }], errors: [], neighbours: [nb('Te1/1/1', 'CORE-SYN', '10.0.0.2', ['Router', 'Switch'], 'Te1/1/1'), nb('Gi1/0/8', XSS, '10.0.9.9', ['Switch'], 'Gi0/1'), nb('Gi1/0/2', 'SEP001122334455', '10.20.0.5', ['Host', 'Phone'], 'Port 1')] });
    reads.put({ id: 'acc-b', at: now - 3600000, ports: [], trunks: [], macs: [], errors: [], neighbours: [] });
    await p.click('#refresh'); await p.click('[data-tab="map"]');
    ok(await wait(p, () => document.querySelectorAll('#map .node').length === 5), 'five connected devices drawn (phone counted, not drawn)');
    ok((await p.$$('#map .lnk')).length === 4, 'four links');
    ok(/4 \/ 5/.test(await p.textContent('#kpis')) && /1\s*devices down/i.test(await p.textContent('#kpis')), 'KPIs: placed and down');
    const stroke = (id) => p.$eval('#map .node[data-node="' + id + '"] rect.b', (r) => r.getAttribute('stroke'));
    ok((await stroke('acc-b')) === '#e5484d' && (await stroke('core-syn')) === '#2fb344', 'state colours');
    ok(await p.$('#map .node[data-node="core-syn"] rect[stroke="#f59f00"]'), 'the core is ringed as a single point of failure');
    // a device
    await p.click('#map .node[data-node="core-syn"]');
    ok(await wait(p, () => /CORE-SYN/.test(document.getElementById('side').textContent) && /10\.0\.0\.2/.test(document.getElementById('side').textContent)), 'device detail with IP for an operator');
    ok(/Te1\/1\/2/.test(await p.textContent('#side')) && /one side/.test(await p.textContent('#side')), 'links with ports, one-sided flagged');
    await p.click('#impact');
    ok(await wait(p, () => /lose their path if CORE-SYN fails/.test(document.getElementById('side').textContent)), 'what fails with it');
    ok((await p.$$('#map .node.hit')).length === 3, 'the cut-off devices are highlighted');
    await p.click('#clearhit');
    // path
    await p.click('#map .node[data-node="fw-syn"]'); await wait(p, () => document.getElementById('pf'));
    await p.selectOption('#pf', 'fw-syn'); await p.selectOption('#pt', 'acc-b'); await p.click('#pgo');
    ok(await wait(p, () => document.querySelectorAll('.hop').length === 2), 'path hop by hop');
    ok(/ACC-B-SYN is down|link CORE-SYN Te1\/1\/2 is down/.test(await p.textContent('#pout')), 'the path says what is down on it');
    // findings
    await p.click('[data-tab="findings"]'); const F = await p.textContent('#view');
    ok(/CORE-SYN is a single point of failure/.test(F) && /ACC-B-SYN is down/.test(F) && /Unmanaged switch/.test(F) && /seen only by CORE-SYN/.test(F), 'findings');
    await p.click('[data-tab="spof"]'); ok(/CORE-SYN/.test(await p.textContent('#view')) && /ACC-A-SYN/.test(await p.textContent('#view')), 'single points of failure table');
    await p.click('[data-tab="findings"]'); await p.click('.li[data-fnode="core-syn"]');
    ok(await wait(p, () => document.querySelector('#map') && /cut off/.test(document.getElementById('view').textContent)), 'a finding opens on the map with what it cuts off');
    // changes
    await p.click('[data-tab="changes"]'); ok(/No snapshot recorded yet/.test(await p.textContent('#view')), 'no snapshot yet');
    await p.click('#snap'); ok(await wait(p, () => /Snapshot recorded: 6 devices, 4 links/.test(document.body.textContent)), 'snapshot');
    reads.put(Object.assign({}, reads.get('acc-a'), { neighbours: reads.get('acc-a').neighbours.filter((x) => x.name !== XSS) }));
    await p.click('#refresh'); await p.click('[data-tab="changes"]');
    ok(await wait(p, () => /Link gone/.test(document.getElementById('view').textContent)), 'a removed link shows under Changes');
    // layout: drag and save
    await p.click('[data-tab="map"]'); ok(await wait(p, () => document.querySelector('#map .node[data-node="lonely"]') === null && document.querySelector('#map .node[data-node="acc-a"]')), 'a device with no link is not drawn (it is under Not on the map)');
    await p.$eval('.mapwrap', (e) => e.scrollIntoView());
    const box = await p.$eval('#map .node[data-node="acc-a"] rect.b', (r) => { const b = r.getBoundingClientRect(); return { x: b.x + b.width / 2, y: b.y + b.height / 2 }; });
    await p.mouse.move(box.x, box.y); await p.mouse.down(); await p.mouse.move(box.x + 80, box.y + 40, { steps: 5 }); await p.mouse.up();
    ok(!(await p.$eval('#savelay', (b) => b.disabled)), 'drag enables Save layout');
    await p.click('#savelay'); ok(await wait(p, () => /Layout saved \(1 moved\)/.test(document.body.textContent)), 'layout saved');
    ok(await wait(p, () => document.getElementById('resetlay')), 'reset offered once a layout is saved');
    ok(!(await p.evaluate(() => window.__xss)), 'a hostile device name stayed text');
    // viewer
    WHO = { user: 'vera.syn', role: 'viewer' }; await p.goto(url); await wait(p, () => document.querySelector('#map .node'));
    ok(await p.$eval('#snap', (b) => b.hidden), 'viewer: no snapshot button');
    await p.click('#map .node[data-node="core-syn"]'); await wait(p, () => /CORE-SYN/.test(document.getElementById('side').textContent));
    ok(!/10\.0\.0\.2/.test(await p.textContent('#side')) && !(await p.$('#impact')) && !(await p.$('#pgo')), 'viewer: no IP, no impact, no path');
    ok(!(await p.$('#savelay')), 'viewer: cannot arrange the layout');
    // narrow screen does not break
    const ph = await browser.newPage({ viewport: { width: 390, height: 900 } }); await ph.goto(url); await wait(ph, () => document.querySelector('#map .node'));
    ok(await ph.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1), 'phone width: no sideways scroll (the map pans in its box)'); await ph.close();
    // menu, installer, portal redirect
    const nav = fs.readFileSync(path.join(DASH, 'vendor', 'zyb-nav.js'), 'utf8');
    ok(/"h": "network-map.html"/.test(nav) && / network-map\.html /.test(fs.readFileSync(path.join(DASH, 'install-dashboards.sh'), 'utf8')), 'menu entry and installer');
    ok(/topology: 'network-map\.html'/.test(fs.readFileSync(path.join(DASH, 'vendor', 'zyb-menu.js'), 'utf8')), 'the portal\'s old "Intelligent Network Map" opens this page');
    ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  } finally { await browser.close(); srv.close(); }
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n);
  process.exit(bad ? 1 : 0);
})();
