// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for the Operations Wall (dashboards/server/ops-wall.html) against the REAL ITAM engine (engine/ops-wall.js) with
// SYNTHETIC sources and a stubbed SIEM alert queue: the big figures, a source not connected reads "not connected" (no zero), live
// alerts with a new one flashing, the views and a big figure opening its view, rotation and the keyboard, kiosk mode hides the
// controls, the trends, the shift card, the unusual-for-this-hour banner, the SOC down said in words, AI off says why, a hostile
// alert / incident title stays text, the menu entry and the portal redirect.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node ops-wall.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const ITAM = path.join(__dirname, '..', '..', 'backend', 'itam'), DASH = path.join(__dirname, '..', '..', 'ui');
const H = require(path.join(ITAM, 'tests', 'helpers'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const XSS = '<img src=x onerror="window.__xss=1">';

(async () => {
  const e = await H.startApp({ noAi: true });
  const W = {
    soc: { sources: [{ id: 'soc', name: 'SOC metrics', state: 'live' }], posture: { overall: 78, grade: 'adequate' },
      soc: { open_by_severity: { 0: 0, 1: 3, 2: 5, 3: 2, 4: 3 }, mttd_s: 300, mttr_s: 5400, sla: { breaching_now: 1 }, alerts_by_day: [{ day: '2026-10-30', total: 9 }, { day: '2026-10-31', total: 14 }] },
      decisions: [{ kind: 'approve-change', severity: 'high', title: 'Approve FW-SYN-1 rule change', who: 'admin (not the requester)' }] },
    platform: { summary: { score: 84, issues: 3, critical: 0, high: 1, connected: 4, tiers: 5 }, tiers: [{ id: 'virt', label: 'Virtualization', state: 'ok', score: 95, issues: [1] }, { id: 'db', label: 'Databases', state: 'warn', score: 70, issues: [1, 2] }, { id: 'cloud', label: 'Cloud', state: 'not_connected', score: null, issues: [] }], feed: [{ severity: 'high', title: 'WIN-SRV-01: 4 critical patches missing', link: 'update-studio.html' }] },
    notify: { summary: { open: 1, acked: 0, critical: 0, unrouted: 0, escalating: 0, failed_deliveries: 0 }, oncall: [{ team: 'noc', name: 'NOC', now: { name: 'omar.syn' } }], incidents: [{ title: 'Link down Jeddah ' + XSS, severity_name: 'high', status: 'open', minutes_open: 12 }] },
    inventory: null,
    health: { summary: { pages: 120, working: 119, not_working: 1, last_update: new Date().toISOString() } },
  };
  const src = {}; for (const k of Object.keys(W)) src[k] = () => W[k];
  require(path.join(ITAM, 'engine/duty')).registerDuty(e.app.srv, e.app, { noTimer: true, owSources: src });
  if (e.app.addons.updateHealth) e.app.addons.updateHealth.view = () => ({ pages: [] });
  // history: 7 days around this hour with 0 critical, 2 high; and a sample at the start of this shift
  const T = Date.now(), wall = e.app.addons.opsWall;
  for (let d = 7; d >= 1; d--) for (const off of [-20, 0, 20]) e.app.store.collection('ow_samples').put({ id: 'h' + d + off, t: T - d * 86400000 + off * 60000, m: { soc_critical: 0, soc_high: 2, soc_open: 10, posture: 78 } });
  e.app.store.collection('ow_samples').put({ id: 'shift', t: wall.shiftStart(T) + 60000, m: { soc_critical: 0, soc_high: 1, soc_open: 8, posture: 80 } });
  let WHO = { user: 'nora.syn', role: 'operator' }, SOC = { up: true, items: [{ id: 'A1', severity: 4, rule_name: 'Ransomware behaviour ' + XSS, host: 'FIN-PC-01', ts_last: 't1' }] };
  const srv = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://x'), json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u.pathname === '/dashboards/whoami.json') return json(200, WHO);
    if (u.pathname === '/api/soc/alerts') return SOC.up ? json(200, { items: SOC.items }) : json(502, { error: 'bad gateway' });
    if (u.pathname === '/api/soc/netops/npm') return json(200, { vendors: [{ vendor: 'Fortinet', nodes: [{ id: 'fw-hq', name: 'FW-HQ', site: 'Riyadh HQ', role: 'firewall', state: 'up' }, { id: 'fw-jed', name: 'FW-JED', site: 'Jeddah', role: 'branch-router', state: 'critical', reason: 'no reply to ping (3 sent)' }] },
      { vendor: 'Cisco IOS', nodes: [{ id: 'core', name: 'CORE-HQ', site: 'Riyadh HQ', role: 'core', state: 'up' }, { id: 'acc1', name: 'ACC-HQ-1', site: 'Riyadh HQ', role: 'access', state: 'warning', reason: 'snmp timeout' }, { id: 'acc2', name: 'ACC-' + XSS, site: 'Riyadh HQ', role: 'access', state: 'up' }] }] });
    if (u.pathname === '/api/soc/netops/avail') return json(200, { items: [{ name: 'SRV-APP-01', site: 'Riyadh HQ', status: 'online' }, { name: 'SRV-DB-02', site: 'Riyadh HQ', status: 'offline' }, { name: 'SRV-JED-01', site: 'Jeddah', status: 'online' }] });
    if (u.pathname === '/api/soc/m365/security') return json(200, { configured: true, score: { pct: 64 }, mfa: { not_registered: 12 } });
    if (u.pathname === '/api/soc/netops/rogue') return json(200, { kpis: { rogue: 3 } });
    if (u.pathname === '/api/soc/ksc/overview') return json(502, { error: 'bad gateway' });
    if (u.pathname.startsWith('/api/itam/')) {
      const h = Object.assign({}, req.headers, { 'x-sentra-proxy-secret': H.SECRET, 'x-auth-user': WHO.user, 'x-auth-role': WHO.role });
      const up = http.request({ host: '127.0.0.1', port: e.port, method: req.method, path: req.url, headers: h }, (r) => { res.writeHead(r.statusCode, r.headers); r.pipe(res); });
      req.pipe(up); return;
    }
    if (u.pathname.startsWith('/api/')) return json(404, { error: 'not in this test' });
    const f = path.join(DASH, u.pathname.replace(/^\/dashboards\//, '/')); if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (err, d) => { if (err) { res.writeHead(404); res.end(); return; } res.writeHead(200, { 'Content-Type': u.pathname.endsWith('.js') ? 'application/javascript' : u.pathname.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port + '/dashboards/ops-wall.html';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  const wait = (p, fn, arg, ms) => p.waitForFunction(fn, arg, { timeout: ms || 15000 }).then(() => true, () => false);
  const V = (p) => p.textContent('#view');
  try {
    const ctx = await browser.newContext({ viewport: { width: 1920, height: 1080 } });
    const p = await ctx.newPage(); p.on('pageerror', (x) => errs.push(x.message));
    await p.goto(base); await wait(p, () => !document.getElementById('main').hidden);
    const big = await p.textContent('#big');
    ok(/critical alerts/.test(big) && /78/.test(big) && /84/.test(big), 'big figures: alerts, posture, platform');
    ok(/action needed/.test(await p.textContent('#state')) && /\b5 of 11 sources/.test(await p.textContent('#state')), 'overall state and sources');
    ok(/Unusual for this time of day/.test(await p.textContent('#banner')) && /Open critical alerts is 3 - usually 0/.test(await p.textContent('#banner')), 'banner: a critical alert is unusual for this hour');
    ok(await wait(p, () => /Ransomware behaviour/.test(document.getElementById('view').textContent)), 'live alerts from the SIEM');
    ok(/omar\.syn/.test(await V(p)) && /Approve FW-SYN-1/.test(await V(p)), 'on-call and decisions on the command view');
    ok(/Open high alerts/.test(await V(p)) && /1 → 2/.test(await V(p)), 'this shift: high alerts 1 → 2');
    // a new alert arrives and flashes
    SOC.items = SOC.items.concat([{ id: 'A2', severity: 3, rule_name: 'Brute force on VPN', host: 'vpn-gw', ts_last: 't2' }]);
    ok(await wait(p, () => !!document.querySelector('a.al.new[href*="A2"]'), null, 25000), 'a new alert is highlighted');
    // views
    await p.click('#views [data-view="infra"]'); ok(/Databases/.test(await V(p)) && /not connected/.test(await V(p)) && /WIN-SRV-01/.test(await V(p)), 'infrastructure view; inventory not connected');
    ok(!/Assets\s*0/.test(await V(p)), 'a source not connected shows no zero');
    await p.click('#views [data-view="incidents"]'); ok(/Link down Jeddah/.test(await V(p)), 'incidents view');
    await p.click('#views [data-view="trends"]'); ok((await p.$$('[data-metric]')).length >= 10 && !!(await p.$('[data-metric="soc_high"] svg')), 'trends with spark lines');
    await p.click('#views [data-view="handover"]'); ok(/AI shift analyst is off/.test(await V(p)), 'AI off says why');
    await p.click('.stat[data-view="soc"]'); ok(/Alerts per day/.test(await V(p)) && !!(await p.$('#view svg rect')), 'a big figure opens its view');
    await p.keyboard.press('2'); const ev = await V(p);
    ok(/FortiGate fleet/.test(ev) && /Hyper-V servers/.test(ev) && /AI engineers - automation/.test(ev) && /nothing is shown rather than a zero/.test(ev), 'estate view: every estate panel, a module not set up is not a zero');
    ok((await p.$$('#view .est .et')).length >= 6, 'colourful estate strip on the estate view');
    await p.keyboard.press('5'); ok(/Databases/.test(await V(p)), 'number keys switch views (5 = infrastructure; 2 = estate)');
    // rotation
    await p.click('#rot'); ok(/Rotating/.test(await p.textContent('#rot')) && await p.isVisible('#prog'), 'rotation on');
    ok(await wait(p, () => document.querySelector('#views [aria-selected="true"]').dataset.view !== 'infra', null, 40000), 'rotation moves to the next view');
    await p.keyboard.press(' '); ok(/^\s*Rotate\s*$/.test(await p.textContent('#rot')), 'space pauses rotation');
    // SOC down
    SOC.up = false; await p.click('#views [data-view="command"]');
    ok(await wait(p, () => /SOC is not answering/.test(document.getElementById('view').textContent), null, 40000), 'SOC down said in words');
    // NOC sites, threat level, security strip (the old portal wall's per-site tiles and SOC tiles)
    await p.click('[data-view="sites"]');
    ok(await wait(p, () => document.querySelectorAll('.site').length === 2), 'one tile per site');
    const st = await p.textContent('#view');
    ok(/2 sites/.test(st) && /2 with something down/.test(st), 'site summary');
    ok(/FW-JED - no reply to ping/.test(st) && /SRV-DB-02 - server offline/.test(st), 'what is down, with the reason');
    ok(/SRV 1\/2/.test(st) && /SW 3/.test(st) && /FW/.test(st) && /RTR/.test(st), 'role chips with counts and servers online / total');
    ok(await p.$eval('.site', (x) => /Jeddah|Riyadh HQ/.test(x.textContent)), 'sites listed worst first');
    ok(await wait(p, () => /THREAT (CRITICAL|ELEVATED)/.test(document.getElementById('thr').textContent)), 'threat level in the header');
    ok(/rogue device/.test(await p.getAttribute('#thr', 'title')) && /site\(s\) with something down/.test(await p.getAttribute('#thr', 'title')), 'threat level says why');
    await p.click('[data-view="soc"]');
    ok(await wait(p, () => /Security posture/.test(document.getElementById('view').textContent)), 'security strip on the SOC view');
    const sv = await p.textContent('#view');
    ok(/64%/.test(sv) && /12/.test(sv) && /3\s*rogue devices/.test(sv) && (/—\s*endpoints unprotected/.test(sv) || /—\s*endpoints at risk \(NAC\)/.test(sv)), 'Secure Score, MFA, rogue; endpoint protection (or NAC where Kaspersky is not used) not answering reads —');
    ok(!(await p.evaluate(() => window.__xss)), 'hostile titles stayed text');
    // kiosk
    const k = await ctx.newPage(); k.on('pageerror', (x) => errs.push(x.message)); await k.goto(base + '?kiosk=1&rotate=20'); await wait(k, () => !document.getElementById('main').hidden);
    ok(!(await k.isVisible('#views')) && !(await k.isVisible('#rot')) && await k.isVisible('#clock'), 'kiosk hides the controls, keeps the clock');
    ok(await k.isVisible('#prog'), 'kiosk rotates by itself');
    const nav = fs.readFileSync(path.join(DASH, 'vendor', 'zyb-nav.js'), 'utf8');
    ok(/"h": "ops-wall.html"/.test(nav) && /ops-wall\.html/.test(fs.readFileSync(path.join(DASH, 'install-dashboards.sh'), 'utf8')), 'menu entry and installer');
    ok(/noc: 'ops-wall\.html\?view=sites'/.test(fs.readFileSync(path.join(DASH, 'vendor', 'zyb-menu.js'), 'utf8')) && /wall: 'ops-wall\.html'/.test(fs.readFileSync(path.join(DASH, 'vendor', 'zyb-menu.js'), 'utf8')) && /wall: 'ops-wall\.html'/.test(fs.readFileSync(path.join(DASH, 'vendor', 'zyb-early.js'), 'utf8')), 'the portal\'s Operations Wall opens this page');
    ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  } finally { await browser.close(); srv.close(); await e.close(); }
  console.log((bad ? 'FAILED ' : 'ok ') + (n - bad) + '/' + n);
  process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
