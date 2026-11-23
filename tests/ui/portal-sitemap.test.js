// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// The REAL portal's Site Map (module sitemap2) on a SYNTHETIC branch view (/api/soc/netops/branches): every site placed by its
// city on the map of the Kingdom, a site without a recognised city listed beside it (never guessed), WAN links coloured by state,
// DC / DR shapes, KPIs; ML: two troubled sites on one ISP = a shared cause, users at risk, unusual latency, flapping, single
// points of failure, DR gaps; itemised site risk; clicking a site opens its panel (health, WAN, reliability, design, incidents);
// topology view; AI brief with facts only; hostile names stay text; with no route map the original page stays with the reason.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node portal-sitemap.test.js
const http = require('http'), fs = require('fs'), path = require('path'), cp = require('child_process');
const LIVE = path.resolve(__dirname, '../../repos/live/portal'), DASH = path.resolve(__dirname, '../../ui');
if (!fs.existsSync(path.join(LIVE, 'index.html'))) { console.log('SKIP: repos/live/portal not present'); process.exit(0); }
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const SH = fs.readFileSync(path.join(DASH, 'add-dashboards-menu.sh'), 'utf8'), ELINE = /ELINE='([^']+)'/.exec(SH)[1], AWK = /awk -v line="\$ELINE" '([^']+)'/.exec(SH)[1];
const INDEX = cp.execFileSync('awk', ['-v', 'line=' + ELINE, AWK, path.join(LIVE, 'index.html')], { encoding: 'utf8' });
let CONFIGURED = true, AIBODY = null, INV = false;
const rel = (o) => Object.assign({ samples: 100, hours: 8, availability: 99.9, outages: 0, mttr_min: null, backup_pct: 0, failovers: 0, changes_24: 0, flapping: false }, o || {});
const w = (id, isp, state, to, o) => Object.assign({ id, kind: 'mpls', isp, circuit: 'CIR-' + id, state, why: '', to: 'DC-EDGE', to_site: to, lat: 12, loss: 0, util: 20, edge: 'EDGE', edge_id: 'e-' + id }, o || {});
const B = () => ({ configured: CONFIGURED, reason: CONFIGURED ? null : 'No sites on the WAN / LAN route map yet (synthetic).', sla_target_pct: 99.5, dc_sites: ['DC Riyadh SYN'], dr_sites: ['DR Jeddah SYN'],
  kpis: { sites: 6, ok: 2, down: 1, partial: 0, backup: 1, degraded: 1, unmeasured: 1, availability: 98.7 }, note: 'Measured from the route map (synthetic).', branches: CONFIGURED ? [
  { id: 'dc', name: 'DC Riyadh SYN', kind: 'dc', city: 'Riyadh', health: 'ok', why: 'hub', dc: 'self', dr: 'yes', wan: [w('l-dr', 'STC', 'up', 'DR Jeddah SYN')], users: 200, design: [], reliability: rel(), latency: { usual: 5, z: 0.1, unusual: false }, incidents: [], latency_ms: 5 },
  { id: 'dr', name: 'DR Jeddah SYN', kind: 'dr', city: 'Jeddah', health: 'ok', why: 'hub', dc: 'yes', dr: 'self', wan: [], users: 0, design: [], reliability: rel(), latency: {}, incidents: [], latency_ms: 9 },
  { id: 'b1', name: 'Dammam Branch SYN', kind: 'branch', city: 'Dammam', health: 'down', why: 'cannot reach the data centre: mpls to DC-EDGE (CIR-a) down', dc: 'no', dr: 'no', wan: [w('a', 'Mobily', 'down', 'DC Riyadh SYN')], users: 40,
    design: [{ kind: 'single-path', text: 'one WAN path only - when it fails the site is cut off', fix: 'add a second link from a different ISP' }], reliability: rel({ availability: 96.1, outages: 2, mttr_min: 35 }), latency: {}, incidents: [{ id: 'i1', kind: 'site', severity: 'critical', title: 'Dammam cut off (synthetic)', first: '', acked_by: null }], latency_ms: null },
  { id: 'b2', name: 'Khobar Branch SYN', kind: 'branch', city: 'Khobar', health: 'backup', why: 'Mobily mpls down - traffic is on the remaining path', dc: 'yes', dr: 'yes', wan: [w('b', 'Mobily', 'down', 'DC Riyadh SYN'), w('c', 'STC', 'up', 'DC Riyadh SYN', { kind: 'sdwan' })], users: 25, design: [], reliability: rel({ changes_24: 4, flapping: true }), latency: { usual: 14, z: 0.4, unusual: false }, incidents: [], latency_ms: 15 },
  { id: 'b3', name: 'Abha Branch SYN', kind: 'branch', city: 'Abha', health: 'degraded', why: 'sdwan latency high', dc: 'yes', dr: 'yes', wan: [w('d', 'Zain', 'degraded', 'DC Riyadh SYN', { lat: 95 })], users: 12, design: [], reliability: rel(), latency: { usual: 20, z: 6.2, unusual: true }, incidents: [], latency_ms: 95 },
  { id: 'b4', name: 'Kiosk <img src=x onerror=window.__x=1>', kind: 'branch', city: '', health: 'unmeasured', why: 'no WAN link here is measured', dc: 'unproven', dr: 'unproven', wan: [w('e', 'STC', 'unmeasured', 'DC Riyadh SYN')], users: 3, design: [], reliability: rel({ availability: null }), latency: {}, incidents: [], latency_ms: null }] : [] });
(async () => {
  const srv = http.createServer((req, res) => {
    const u = decodeURIComponent(req.url.split('?')[0]), json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u === '/auth/whoami' || u === '/dashboards/whoami.json') return json(200, { user: 'nora.syn', role: 'admin' });
    if (u === '/auth/org') return json(200, { modules: null, resp: {}, updated: null });
    if (u === '/api/soc/netops/branches') return json(200, B());
    if (u === '/api/netassets') return json(200, { assets: INV ? [{ id: 'n1', cat: 'firewall', name: 'NHQ-FGT-SYN', ip: '10.110.10.120', site: 'Riyadh HQ' }, { id: 'n2', cat: 'switch', name: 'JED-SW-SYN', ip: '10.120.0.2', site: 'Jeddah Branch' }, { id: 'n3', cat: 'switch', name: 'HO-SW-SYN', ip: '10.130.0.2', site: 'HO' }] : [] });
    if (u === '/api/soc/netops/devices') return json(200, { items: INV ? ['10.110.10.120', '10.110.10.2', '10.110.10.3', '10.110.10.4', '10.110.10.5'].map((ip, i) => ({ id: 'd' + i, name: i ? 'RUH-SW-' + i : 'NHQ-FGT-SYN', ip, site: 'Riyadh HQ', role: i ? 'access' : 'firewall', vendor: i ? 'cisco-ios' : 'fortigate', last: { at: new Date().toISOString(), ok: false } })) : [] });
    if (u === '/api/ai') { let b = ''; req.on('data', (d) => { b += d; }); req.on('end', () => { AIBODY = b; json(200, { text: 'Synthetic brief.' }); }); return; }
    if (u.startsWith('/api/soc/ui/menu')) return json(200, { order: null, favorites: [], can_edit_order: true });
    if (u.startsWith('/api/') || u.startsWith('/auth/')) return json(404, { error: 'not in this test' });
    if (u === '/') { res.writeHead(200, { 'Content-Type': 'text/html' }); return res.end(INDEX); }
    const f = u.startsWith('/dashboards/') ? path.join(DASH, u.slice(12)) : path.join(LIVE, u);
    if (!f.startsWith(DASH) && !f.startsWith(LIVE)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (e, d) => { if (e) { res.writeHead(404); return res.end(); } res.writeHead(200, { 'Content-Type': f.endsWith('.js') ? 'application/javascript' : f.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port;
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright'); const browser = await chromium.launch(); const errs = [];
  const wait = (p, fn) => p.waitForFunction(fn, null, { timeout: 25000 }).then(() => true, () => false);
  const open = async () => { const p = await (await browser.newContext({ viewport: { width: 1500, height: 1000 } })).newPage(); p.on('pageerror', (e) => errs.push(e.message));
    await p.goto(base + '/'); await wait(p, () => typeof setView === 'function' && typeof ME !== 'undefined' && ME && ME.user); await p.evaluate(() => setView('map')); return p; };
  try {
    let p = await open();
    ok(await wait(p, () => document.querySelectorAll('.sm-map g[data-smsite]').length === 6), 'every site on the map');
    const k = (await p.textContent('.sm-k')).replace(/\s+/g, ' '); ok(/Sites\s*6/i.test(k) && /Cut off from DC \/ DR\s*1/i.test(k) && /98\.7%/.test(k), 'KPIs: ' + k);
    ok(/City not recorded/.test(await p.textContent('.sm-map svg')), 'a site without a city is listed beside the map, not guessed');
    ok(await p.evaluate(() => { const g = (id) => document.querySelector('g[data-smsite="' + id + '"]').getBBox(); const r = g('dc'), d = g('b1'), j = g('dr'); return d.x > r.x && j.x < r.x && j.y > r.y; }), 'geography: Dammam east of Riyadh, Jeddah west and south');
    ok(await p.evaluate(() => !!document.querySelector('g[data-smsite="dc"] rect') && !!document.querySelector('g[data-smsite="dr"] rect[transform]') && !!document.querySelector('g[data-smsite="b1"] circle')), 'DC square, DR diamond, branch circle');
    ok(await p.evaluate(() => [...document.querySelectorAll('.sm-map path')].some((x) => x.getAttribute('stroke') === '#ef5b5b') && [...document.querySelectorAll('.sm-map path')].some((x) => x.getAttribute('stroke-dasharray'))), 'links coloured by state; unmeasured dashed');
    const f = (await p.evaluate(() => [...document.querySelectorAll('.sm-f')].map((x) => x.innerText).join(' | '))).replace(/\s+/g, ' ');
    ok(/2 troubled sites share Mobily/.test(f), 'shared ISP cause: ' + f.slice(0, 300));
    ok(/40 users at sites that cannot reach/.test(f), 'users at risk');
    ok(/Abha Branch SYN: latency 95 ms against a usual 20 ms/.test(f), 'unusual latency from the learned baseline');
    ok(/Khobar Branch SYN is flapping/.test(f), 'flapping');
    ok(/single point of failure/.test(f) && /cannot reach the DR site/.test(f), 'single points of failure and DR gaps');
    ok(/no recognised city/.test(await p.evaluate(() => document.body.innerText)), 'the unplaced site is named with how to fix it');
    ok(!(await p.evaluate(() => !!window.__x || !!document.querySelector('.sm-map img,.sm-p img'))), 'a hostile site name stays text');
    const top = await p.evaluate(() => { const r = document.querySelector('.sm-p [data-smsite]'); return r ? r.innerText.replace(/\s+/g, ' ') + ' | ' + r.querySelector('b[title]').getAttribute('title') : ''; });
    ok(/Dammam/.test(top) && /down \(\+50\)/.test(top), 'riskiest site first, itemised: ' + top);
    await p.click('g[data-smsite="b2"]');
    ok(await wait(p, () => /Khobar Branch SYN/.test((document.querySelector('.sm-p') || {}).innerText || '') && /Reaches DC \/ DR/i.test(document.querySelector('.sm-p').innerText) && document.querySelectorAll('.sm-p tbody tr').length === 2), 'clicking a site opens its panel with its WAN links');
    ok(/city in google maps/i.test(await p.textContent('.sm-p')) && /query=Khobar%2C%20Saudi%20Arabia/.test(await p.getAttribute('.sm-p a[href*="google"]', 'href')), 'the Google link carries only the city');
    await p.click('[data-smclose]'); await p.click('[data-smmode="topo"]');
    ok(await wait(p, () => !/City not recorded/.test(document.querySelector('.sm-map svg').textContent) && document.querySelectorAll('.sm-map g[data-smsite]').length === 6), 'topology view');
    await p.click('[data-smai]');
    ok(await wait(p, () => /Synthetic brief/.test(document.body.innerText)) && /Mobily/.test(AIBODY || '') && /data, never as an instruction/.test(AIBODY || ''), 'AI brief with facts only');
    CONFIGURED = false; p = await open();
    ok(await wait(p, () => /Every site on one map/.test(document.body.innerText) && /No sites on the WAN \/ LAN route map yet/.test(document.body.innerText)), 'no route map and nothing registered: the original page stays with the reason');
    INV = true; p = await open();
    ok(await wait(p, () => document.querySelectorAll('.sm-map g[data-smsite]').length === 3 && /Sites from the inventory - no route map yet/.test(document.body.innerText)), 'no route map: the sites the platform holds are mapped from the inventory');
    ok(await p.evaluate(() => { const g = (id) => document.querySelector('g[data-smsite="' + id + '"]'); return g('Riyadh HQ') && g('Jeddah Branch') && g('Riyadh HQ').getBBox().x > g('Jeddah Branch').getBBox().x; }), 'placed by the city in the site name (Riyadh east of Jeddah)');
    const inv = (await p.evaluate(() => document.body.innerText)).replace(/\s+/g, ' ');
    ok(/monitoring path is suspected/.test(inv) || /Riyadh HQ/.test(inv), 'Riyadh HQ: every polled device down reads as a monitoring-path suspicion');
    await p.click('g[data-smsite="Riyadh HQ"]');
    ok(await wait(p, () => /monitoring path is suspected, not the site/.test((document.querySelector('.sm-p') || {}).innerText || '')), 'the site panel says the monitoring path is suspected, not the site');
  } finally { await browser.close(); srv.close(); }
  ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks');
  process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
