// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Operations Command page + the colour layer: every module panel draws from its own API with a chart; a module that is not set
// up says what to connect; one that fails says why and the others still draw; the findings of every module are ranked together
// (critical first), hostile text stays text; KPI tiles carry their status colour; the colour layer is on (html.zyb-color).
// Stub APIs; every device, host and endpoint is SYNTHETIC.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node ops-command.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const DASH = path.resolve(__dirname, '../../ui');
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const NOW = new Date().toISOString();
const API = {
  '/api/soc/fortimanager/fleet': { status: { last_poll_at: NOW }, kpis: { devices: 4, ok: 2, watch: 0, attention: 1, down: 1, links_down: 1, firmware_behind: 2 },
    findings: [{ severity: 'critical', device: 'FGT-SYN-01', title: 'offline <img src=x onerror=alert(1)>', fix: 'Check power and the uplink' }, { severity: 'medium', device: 'FGT-SYN-02', title: 'firmware behind target', fix: 'Plan an upgrade' }] },
  '/api/soc/nac/endpoints': { total: 3, learning: false, endpoints: [{ mac: '02:00:00:00:00:01', host: 'PC-SYN-1', risk: 70, reasons: [{ why: 'cloned MAC' }] }, { mac: '02:00:00:00:00:02', risk: 10, reasons: [] }, { mac: '02:00:00:00:00:03', risk: 40, reasons: [] }],
    sites: [{ site: 'Site SYN-A', endpoints: 2, risky: 1 }, { site: 'Site SYN-B', endpoints: 1, risky: 1 }] },
  '/api/soc/ndr': { ran: false, note: 'NDR has not run yet - it runs every hour over the firewalls\' traffic logs, or press Run now.' },
  '/api/itam/hyperv': { kpis: { hosts: 1, vms: 3, running: 2, high: 0, stale_hosts: 0 }, hosts: [{ name: 'HV-SYN-01', cpu_pct: 40, mem_total_mb: 1000, mem_free_mb: 300, vms: [] }], findings: [{ severity: 'medium', host: 'HV-SYN-01', title: 'checkpoint older than 7 days', fix: 'Merge it' }] },
  '/api/itam/aramco-ccc': { controls_total: 10, score: 62, assessed: 8, applicable: 10, stages: [{ name: 'Scope', done: true }, { name: 'Evidence', done: false, why: '3 controls without evidence', next: 'Collect evidence' }] },
  '/api/soc/duty/items': { items: [{ engineer_name: 'AI Firewall Engineer (FortiGate)', severity: 'high' }, { engineer_name: 'AI Firewall Engineer (FortiGate)', severity: 'low' }] },
  '/api/itam/duty/items': { items: [{ engineer_name: 'AI Hyper-V Administrator', severity: 'medium' }] },
};
(async () => {
  const srv = http.createServer((req, res) => {
    const u = req.url.split('?')[0]; const json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u === '/dashboards/whoami.json') return json(200, { user: 'nora.syn', role: 'operator' });
    if (u === '/api/itam/cucm') return json(500, { error: 'internal error' });
    if (API[u]) return json(200, API[u]);
    if (u.startsWith('/api/')) return json(404, { error: 'not in this test' });
    fs.readFile(path.join(DASH, u.replace(/^\/dashboards\//, '/')), (err, d) => { if (err) { res.writeHead(404); res.end(); return; } res.writeHead(200, { 'Content-Type': u.endsWith('.js') ? 'application/javascript' : u.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(); const errs = [];
  const p = await browser.newPage({ viewport: { width: 1400, height: 1000 } }); p.on('pageerror', (x) => errs.push(x.message));
  await p.goto('http://127.0.0.1:' + srv.address().port + '/ops-command.html?standalone=1');
  await p.waitForSelector('#p-fw canvas', { timeout: 15000 }); await p.waitForTimeout(800);
  const s = await p.evaluate(() => ({ color: document.documentElement.classList.contains('zyb-color'), css: !!document.getElementById('zyb-color-css'),
    drawn: ['fw', 'nac', 'hv', 'cc', 'wk'].filter((id) => { const c = document.getElementById('c-' + id); return c && !c.hidden && c.getAttribute('role') === 'img'; }),
    ndr: (document.getElementById('p-ndr') || {}).textContent || '', uc: (document.getElementById('p-uc') || {}).textContent || '',
    tiles: [...document.querySelectorAll('#kp .t')].map((t) => t.className + '|' + t.textContent), att: document.getElementById('att').innerText,
    first: (document.querySelector('#att .act') || {}).className || '' }));
  ok(s.color && s.css, 'the colour layer is on every page: ' + JSON.stringify({ c: s.color, css: s.css }));
  ok(s.drawn.length === 5, 'charts drawn for fleet, NAC, Hyper-V, Aramco and AI work: ' + s.drawn.join(','));
  ok(/has not run yet/.test(s.ndr), 'a module not set up says what to do');
  ok(/internal error/.test(s.uc), 'a failing module says why; the others still draw');
  ok(s.tiles.some((t) => /\bbad\b/.test(t) && /FortiGates healthy/.test(t) && /2\/4/.test(t)), 'fleet tile red with 2/4 healthy');
  ok(s.tiles.some((t) => /\bwarn\b/.test(t) && /Aramco/.test(t) && /62%/.test(t)), 'Aramco readiness tile amber with 62%');
  ok(s.tiles.some((t) => /Open AI work/.test(t) && /3/.test(t)), 'open work from both engines counted');
  ok(/bad/.test(s.first) && /FGT-SYN-01/.test(s.att.split('\n')[0] + s.att), 'critical finding ranked first');
  ok(/Hyper-V/.test(s.att) && /NAC/.test(s.att) && /Aramco CCC/.test(s.att), 'findings of every module listed together');
  ok(!(await p.$('img[src="x"]')), 'hostile text stays text');
  // light theme still readable: the KPI number is darker than its tile
  await p.evaluate(() => document.documentElement.setAttribute('data-zyb-theme', 'light'));
  const lc = await p.evaluate(() => getComputedStyle(document.querySelector('#kp .t .v')).color);
  ok(/rgb\((\d+), (\d+), (\d+)\)/.test(lc) && RegExp.$1 < 200, 'light theme: KPI number dark enough: ' + lc);
  ok(!errs.length, 'page errors: ' + errs.join(' | '));
  await browser.close(); srv.close();
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks'); process.exit(bad ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });
