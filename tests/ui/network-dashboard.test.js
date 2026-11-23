// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for network-dashboard.html after the static build. The six network endpoints are stubbed with SYNTHETIC
// data in the shape engine/netops/routes.js returns: KPI strip, open incidents (root cause only), devices by vendor, site
// health, branch connectivity, SD-WAN, NAC. Checks: reachable from the menu, the figures, every value escaped, a single
// dead feed degrades its own card only (never blanks the page), and the all-dead case says "not reachable" everywhere.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node network-dashboard.test.js
const http = require('http'), fs = require('fs'), path = require('path'), os = require('os'), cp = require('child_process');
const SRC = path.resolve(__dirname, '../../ui');
let n = 0, bad = 0;
const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const B = fs.mkdtempSync(path.join(os.tmpdir(), 'netdash-')); fs.mkdirSync(path.join(B, 'vendor'));
fs.readdirSync(SRC).filter((f) => f.endsWith('.html')).forEach((f) => fs.copyFileSync(path.join(SRC, f), path.join(B, f)));
fs.readdirSync(path.join(SRC, 'vendor')).filter((f) => /\.(js|json|css)$/.test(f)).forEach((f) => fs.copyFileSync(path.join(SRC, 'vendor', f), path.join(B, 'vendor', f)));
cp.execFileSync(process.execPath, [path.join(SRC, 'build-static.js'), B, 't1'], { stdio: 'ignore' });

const XSS = '<img src=x onerror="window.__xss=1">';
const DATA = {
  '/netops/overview': { sites: [
      { site: 'Riyadh HQ', status: 'ok', devices: 8, polled: 8, reachable: 8, rtt_avg_ms: 2 },
      { site: 'Jeddah ' + XSS, status: 'degraded', devices: 3, polled: 3, reachable: 2, rtt_avg_ms: 14 },
      { site: 'Dammam', status: 'down', devices: 2, polled: 2, reachable: 0, rtt_avg_ms: null }],
    findings: [{ severity: 'high', title: 'OSPF neighbour down ' + XSS, site: 'Dammam' }, { severity: 'medium', title: 'Interface errors rising', device: 'SW1' }], poller: { polled: 13 }, ai: { enabled: true } },
  '/netops/npm': { counts: { up: 10, warning: 1, critical: 2, unknown: 0, unpolled: 0 }, nodes: new Array(13),
    vendors: [{ vendor: 'Cisco IOS', count: 7, nodes: [{ state: 'critical' }, { state: 'up' }] }, { vendor: 'Palo Alto', count: 2, nodes: [{ state: 'up' }] }, { vendor: 'Fortinet ' + XSS, count: 4, nodes: [{ state: 'critical' }] }] },
  '/netops/routemap': { summary: { incidents: 2, critical: 1, links_down: 1, nodes_down: 1 },
    incidents: [{ id: 'node:dmm', severity: 'critical', title: 'FGT-DMM is down ' + XSS, site: 'Dammam' }, { id: 'link:jed', severity: 'high', title: 'SD-WAN path degraded', site: 'Jeddah' }, { id: 'c1', severity: 'low', title: 'covered', covered_by: ['node:dmm'] }] },
  '/netops/branches': { configured: true, kpis: { sites: 5, ok: 3, down: 1, partial: 1, backup: 0, degraded: 0, unmeasured: 0, availability: 99.1, isp_below_sla: 1 }, actions: [{ title: '1 site cannot reach the data centre', filter: 'down' }] },
  '/netops/sdwan': { inventory: { total: 4 }, health: { normal: 3, warning: 1, error: 0, unknown: 0 }, siteHealth: { full: 3, partial: 1, none: 0 }, edges: [{}, {}, {}, {}], polled: true },
  '/netops/nac': { connected: true, counts: { total: 420, unauthorized: 3, quarantined: 1 }, enforcement_pct: 92, endpoints: 420, bypass_count: 2 },
};
let MODE = 'full';

(async () => {
  const srv = http.createServer((q, r) => {
    const u = q.url.split('?')[0], j = (c, o) => { r.writeHead(c, { 'Content-Type': 'application/json' }); r.end(JSON.stringify(o)); };
    if (u.endsWith('whoami.json')) return j(200, { user: 'syed', role: 'operator' });
    if (u.startsWith('/api/soc/netops/')) {
      const key = u.slice('/api/soc'.length);
      if (MODE === 'dead') return j(502, { error: 'the AI Network Engineer is not reachable' });
      if (MODE === 'one-dead' && key === '/netops/sdwan') return j(502, { error: 'down' });
      const d = DATA[key]; return d ? j(200, d) : j(404, { error: 'not in this test' });
    }
    // Workflow Automation attention(who), synthetic, in the engine's shape (not installed when everything is dead)
    if (u === '/api/itam/workflow/attention') return MODE === 'dead' ? j(404, { error: 'not found' }) : j(200, { summary: { approvals: 1, queue_open: 2, overdue: 1, at_risk: 0, to_accept: 0, raised_open: 0, raised_late: 0, functions: [], all_overdue: 2, recurring: 0,
        teams: [{ team: 'network', name: 'Network team', open: 2, overdue: 1, n: 4, on_time: 3, rate: 0.67 }], items: [] },
      priorities: [{ kind: 'Request approval', ref: 'REQ-2026-0061', text: 'Open 443 for the <img src=x onerror=window.__wfx=1> portal - Network change', page: 'workflow-automation.html#req=REQ-2026-0061', why: [['a business request waiting for your approval', 45]] },
        { kind: 'Request overdue', ref: 'REQ-2026-0058', text: 'Firewall rule review evidence - Network team', page: 'workflow-automation.html#req=REQ-2026-0058', why: [['a request to the IT team past its due date', 40], ['escalated', 10]] }] });
    if (u.startsWith('/api/')) return j(404, {});
    const f = path.join(B, u === '/' ? 'index.html' : u); if (!f.startsWith(B)) { r.writeHead(403); return r.end(); }
    fs.readFile(f, (e, d) => { if (e) { r.writeHead(404); return r.end(); } r.writeHead(200, { 'Content-Type': u.endsWith('.js') ? 'application/javascript' : u.endsWith('.css') ? 'text/css' : 'text/html' }); r.end(d); });
  });
  await new Promise((res) => srv.listen(0, '127.0.0.1', res));
  const base = 'http://127.0.0.1:' + srv.address().port + '/';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  const open = async (pg) => { const p = await browser.newPage({ viewport: { width: 1500, height: 950 } }); p.on('pageerror', (e) => errs.push(e.message)); p.on('dialog', (d) => { errs.push('dialog ' + d.message()); d.dismiss(); }); await p.goto(base + (pg || 'network-dashboard.html')); return p; };
  const txt = (p, id) => p.evaluate((i) => (document.getElementById(i) || {}).textContent || '', id);

  // reachable from the menu
  let p = await open('network-engineer.html'); await p.waitForTimeout(800);
  const link = await p.evaluate(() => { const a = document.querySelector('a[href="network-dashboard.html"]'); return a ? a.textContent.trim() : null; });
  ok(/Network Dashboard/.test(link || ''), 'menu entry exists: ' + link);
  await p.evaluate(() => document.querySelector('a[href="network-dashboard.html"]').click());
  await p.waitForURL(/network-dashboard\.html/); await p.waitForSelector('#cards .card');

  const kp = await txt(p, 'kp');
  ok(/Devices up10\/13/.test(kp) && /2 down/.test(kp), 'device KPI: ' + kp.slice(0, 80));
  ok(/Sites3/.test(kp) && /1 down/.test(kp), 'sites KPI');
  ok(/Branches reach DC4\/5/.test(kp), 'branch KPI (ok+partial reach DC)');
  ok(/Open incidents2/.test(kp) && /1 critical/.test(kp), 'incident KPI');
  ok(/NAC enforcement92 %/.test(kp), 'NAC KPI');
  const cards = await txt(p, 'cards');
  ok(/FGT-DMM is down/.test(cards) && !/covered/.test(cards), 'incidents card shows root cause only, not covered');
  ok(/Cisco IOS/.test(cards) && /Palo Alto/.test(cards), 'devices-by-vendor card');
  ok(/Riyadh HQ/.test(cards) && /Dammam/.test(cards), 'site health card');
  ok(/of 5 sites healthy/.test(cards) && /99\.1 %/.test(cards), 'branch connectivity card');
  ok(/SD-WAN/.test(cards) && /3 normal/.test(cards), 'SD-WAN card');
  ok(/Endpoints seen/.test(cards) && /420/.test(cards), 'NAC card');
  ok(await p.evaluate(() => !window.__xss) && !(await p.$('#cards img')), 'synthetic payloads are escaped, no injected node');
  await p.close();

  // one feed dead: its card says so, the rest still render
  { p = await open(); await p.waitForSelector('#cards .card'); await p.waitForFunction(() => !document.getElementById('wfcard').hidden, null, { timeout: 10000 }).catch(() => null);
    const k = await txt(p, 'wfk'), l = await txt(p, 'wfl');
    ok(/Network team · open\s*2/.test(k) && /Network team · overdue\s*1/.test(k) && /Network team · on time\s*75%/.test(k) && /Waiting for your approval\s*1/.test(k), 'Workflow Automation: the network team\'s tiles: ' + k.replace(/\s+/g, ' '));
    ok(l.indexOf('REQ-2026-0058') < l.indexOf('REQ-2026-0061') && /<img src=x/.test(l) && !(await p.$('#wfl img')) && !(await p.evaluate(() => window.__wfx)) && !!(await p.$('#wfl a[href="workflow-automation.html#req=REQ-2026-0061"]')), 'Workflow: ranked by points, a hostile title stays text, linked'); await p.close(); }
  MODE = 'one-dead'; p = await open(); await p.waitForSelector('#cards .card');
  ok(/down|not reachable/i.test(await p.evaluate(() => { const h = [].find.call(document.querySelectorAll('#cards .card'), (c) => /SD-WAN/.test(c.textContent)); return h ? h.textContent : ''; })), 'the dead SD-WAN card degrades on its own');
  ok(/Cisco IOS/.test(await txt(p, 'cards')) && /Riyadh HQ/.test(await txt(p, 'cards')), 'the other cards still render');
  ok(!errs.length, 'no page error when one feed is down');
  await p.close();

  // everything dead: KPI and cards say not reachable, nothing invented
  MODE = 'dead'; p = await open(); await p.waitForSelector('#cards .card');
  ok(/not reachable/i.test(await txt(p, 'kp')), 'all dead: KPI says the engineer is not reachable');
  ok(!/\b\d+ %/.test(await txt(p, 'cards')), 'all dead: no invented percentage');
  ok(await p.evaluate(() => document.getElementById('wfcard').hidden), 'Workflow Automation not installed: its card hidden');
  await p.close();

  ok(/network-dashboard\.html/.test(fs.readFileSync(path.join(SRC, 'install-dashboards.sh'), 'utf8')), 'in the installer');
  ok(/'dash-net': 'network-dashboard\.html'/.test(fs.readFileSync(path.join(SRC, 'vendor/zyb-menu.js'), 'utf8')), 'portal sample page redirects here');
  ok(!errs.length, 'no page errors overall: ' + errs.join(' | '));
  await browser.close(); srv.close();
  console.log(`${n - bad}/${n} checks passed`); process.exit(bad ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });
