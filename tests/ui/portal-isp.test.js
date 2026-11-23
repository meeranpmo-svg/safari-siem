// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// The REAL portal's ISP & Bandwidth view (repos/live/portal, module isp-intel) over a SYNTHETIC WAN Route Map
// (/api/soc/netops/routemap): circuits least healthy first with utilisation against what is usual for this hour, health points
// itemised on click, daily-peak trend (history route), days until full; KPIs; provider scorecard; failover per site (redundant / on
// one circuit / single); the route map's incidents; no circuit says what to draw; route map missing is said; hostile names stay text.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node portal-isp.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const LIVE = path.resolve(__dirname, '../../repos/live/portal');
if (!fs.existsSync(path.join(LIVE, 'index.html'))) { console.log('SKIP: repos/live/portal not present'); process.exit(0); }
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const XSS = '<img src=x onerror="window.__xss=1">';
let MODE = 'map';
const MAP = () => ({ at: new Date().toISOString(), thresholds: { util_warn: 70, util_crit: 90, lat_warn: 80, lat_crit: 150, loss_warn: 1, loss_crit: 5 },
  sites: [{ id: 'hq', name: 'Riyadh HQ (syn)' }, { id: 'jed', name: 'Jeddah DR (syn)' }],
  nodes: [{ id: 'fw-hq', label: 'HQ-FGT', site: 'hq' }, { id: 'isp1', label: 'STC edge', site: 'hq' }, { id: 'isp2', label: 'Mobily edge', site: 'hq' }, { id: 'fw-jed', label: 'JED-FGT', site: 'jed' }, { id: 'isp3', label: 'Zain edge', site: 'jed' }],
  links: MODE === 'empty' ? [{ id: 'lan', a: 'fw-hq', b: 'isp1', kind: 'lan', state: 'up' }] : [
    { id: 'L1', a: 'fw-hq', b: 'isp1', kind: 'internet', isp: 'STC ' + XSS, circuit: 'DIA-SYN-1', capacity_mbps: 500, state: 'degraded', util: 92, lat: 30, loss: 0.2, jitter: 3, ml: { baseline: { util: { mean: 40, sd: 8, n: 120 } }, anomalies: [{ metric: 'util', text: 'utilisation 92% - usually 40% on Sundays at 10:00 (120 samples)' }], forecast: { days_to_full: 6, limit: 90, days: 21 } } },
    { id: 'L2', a: 'fw-hq', b: 'isp2', kind: 'mpls', isp: 'Mobily', circuit: 'MPLS-SYN-2', capacity_mbps: 200, state: 'up', util: 20, lat: 12, loss: 0, jitter: 1, ml: { baseline: { util: { mean: 22 } }, anomalies: [] } },
    { id: 'L3', a: 'fw-jed', b: 'isp3', kind: 'internet', isp: 'Zain', capacity_mbps: 100, state: 'up', util: 35, lat: 40, loss: 0, ml: { anomalies: [] } },
    { id: 'L4', a: 'fw-jed', b: 'fw-hq', kind: 'ipsec', state: 'unmeasured', ml: { learning: 'no history yet' } }],
  incidents: MODE === 'empty' ? [] : [{ id: 'cap:L1', kind: 'capacity', severity: 'high', title: 'Capacity: STC full in about 6 days' }, { id: 'x', kind: 'node-down', severity: 'critical', title: 'unrelated', covered_by: 'y' }] });
(async () => {
  const srv = http.createServer((req, res) => {
    const u = decodeURIComponent(req.url.split('?')[0]), json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u === '/auth/whoami' || u === '/dashboards/whoami.json') return json(200, { user: 'nora.syn', role: 'admin' });
    if (u === '/api/soc/netops/routemap') { if (MODE === 'missing') { res.writeHead(404, { 'Content-Type': 'text/html' }); return res.end('<html></html>'); } return json(200, MAP()); }
    const h = /^\/api\/soc\/netops\/routemap\/links\/([^/]+)\/history$/.exec(u); if (h) return json(200, { link: h[1], peaks: Array.from({ length: 10 }, (_, i) => [20000 + i, 40 + i * 5]) });
    if (u.startsWith('/api/')) return json(404, { error: 'not in this test' });
    const f = u === '/' ? path.join(LIVE, 'index.html') : path.join(LIVE, u);
    if (!f.startsWith(LIVE)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (e, d) => { if (e) { res.writeHead(404); return res.end(); } res.writeHead(200, { 'Content-Type': f.endsWith('.js') ? 'application/javascript' : f.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port;
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright'); const browser = await chromium.launch(); const errs = [];
  const wait = (p, fn) => p.waitForFunction(fn, null, { timeout: 20000 }).then(() => true, () => false);
  const open = async () => { const p = await (await browser.newContext({ viewport: { width: 1500, height: 1000 } })).newPage(); p.on('pageerror', (e) => errs.push(e.message));
    await p.goto(base + '/'); await wait(p, () => typeof setView === 'function' && typeof ME !== 'undefined' && ME && ME.user); await p.evaluate(() => setView('isp')); return p; };   // eslint-disable-line no-undef
  try {
    let p = await open();
    ok(await wait(p, () => document.querySelector('[data-isp-kpi]')), 'ISP view drawn from the route map (no feed gate)');
    const k = (await p.$$eval('[data-isp-kpi] .x-tile', (t) => t.map((x) => x.querySelector('.k').textContent + ' ' + x.querySelector('.v').textContent + ' ' + ((x.querySelector('.s') || {}).textContent || '')).join(' | '))).replace(/\s+/g, ' ');
    ok(/Circuits up 3 \/ 4 none down · 1 not measured/.test(k), 'circuits up counts only measured circuits: ' + k);
    ok(/Busiest now 92 %.*usual 40 %/.test(k) && /Fills up first 6 days/.test(k) && /Unusual now 1/.test(k) && /Sites without failover 1/.test(k), 'busiest with its usual, fills up first, unusual, sites without failover: ' + k);
    const rows = await p.$$eval('tr[data-isp-c]', (r) => r.map((x) => x.getAttribute('data-isp-c')));
    ok(rows[0] === 'L1' && rows[rows.length - 1] === 'L4', 'least healthy first, the unmeasured circuit last: ' + rows.join(','));
    const r1 = await p.textContent('tr[data-isp-c="L1"]'); ok(/92 % of 500 Mbps · usual now 40 %/.test(r1) && /6 days/.test(r1), 'circuit row: utilisation of capacity against usual, days to full');
    ok(/not measured/.test(await p.textContent('tr[data-isp-c="L4"]')), 'unmeasured circuit is not scored');
    ok(await wait(p, () => document.querySelector('tr[data-isp-c="L1"] svg polyline')), 'daily peak trend from the history route');
    await p.click('tr[data-isp-c="L1"]'); ok(await wait(p, () => /-25 utilisation 92 %/.test((document.querySelector('[data-isp-why="L1"]') || {}).textContent || '') && /usually 40%/.test(document.querySelector('[data-isp-why="L1"]').textContent)), 'health points itemised with the anomaly');
    const t = await p.textContent('[data-isp-root]');
    ok(/Provider scorecard/.test(t) && /Mobily/.test(t) && /Zain/.test(t), 'provider scorecard'); const fo = await p.$$eval('tr[data-isp-site]', (r) => r.map((x) => x.getAttribute('data-isp-site') + ':' + x.lastElementChild.textContent));
    ok(fo.join(',') === 'jed:failover not measured,hq:redundant', 'failover per site: HQ redundant (two measured circuits), Jeddah one circuit with an unmeasured backup: ' + fo.join(','));
    ok(/Capacity: STC full in about 6 days/.test(t) && !/unrelated/.test(t), 'route map incidents shown, covered ones left out');
    ok(await p.evaluate(() => !window.__xss && /<img src=x/.test(document.querySelector('[data-isp-root]').innerText)), 'a hostile provider name stays text');
    MODE = 'empty'; p = await open(); ok(await wait(p, () => /No WAN circuit on the route map yet/.test(document.body.innerText)), 'no circuit: says what to draw, no sample');
    MODE = 'missing'; p = await open(); ok(await wait(p, () => /WAN Route Map is not answering/.test(document.body.innerText)), 'route map missing is said');
    ok(!errs.length, 'no page errors: ' + errs.slice(0, 3).join(' | '));
  } catch (x) { console.error(x); bad++; } finally { await browser.close(); srv.close(); }
  console.log((bad ? 'portal-isp: FAIL ' : 'portal-isp: OK ') + (n - bad) + '/' + n + ' checks'); process.exit(bad ? 1 : 0);
})();
