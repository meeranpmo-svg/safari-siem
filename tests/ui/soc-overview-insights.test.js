// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for the AI / ML section of the Security Operations Overview (soc-overview.html + GET /soc/overview/insights) against
// the REAL SIEM modules (sentra-siem engine/soc/alerts.js, cases.js, analyst-routes.js, overview-insights.js) with SYNTHETIC history:
// the 7-day volume forecast drawn and labelled, a silent rule and a new rule named, the entities most at risk ranked by summed
// priority with their tactics and a click that opens the queue filtered, detection efficacy (high value / noise), SLA attainment per
// week, the shift brief put to the SOC Copilot (stubbed) with the page as context, a hostile rule name stays text, a viewer gets no
// section and no request, phone width, no page errors.
// Run: SENTRA_SIEM_DIR=/home/user/sentra-siem PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node soc-overview-insights.test.js
const http = require('http'), fs = require('fs'), path = require('path'), os = require('os');
const SIEM = process.env.SENTRA_SIEM_DIR || path.resolve(__dirname, '../../backend/siem');
const DASH = path.resolve(__dirname, '../../ui');
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const { createState } = require(path.join(SIEM, 'engine/soc/state'));
const { createAlerts } = require(path.join(SIEM, 'engine/soc/alerts'));
const { createCases } = require(path.join(SIEM, 'engine/soc/cases'));
const { fakeApi } = require(path.join(SIEM, 'tests/soc-fakes'));
const quiet = { info() {}, warn() {}, error() {}, debug() {}, child() { return quiet; } };

(async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'socoi-'));
  const state = createState({ dir, log: quiet }), alerts = createAlerts({ state, log: quiet }), cases = createCases({ state, alerts, log: quiet });
  const T = Date.now(), H = 3600e3, DAY = 864e5; let k = 0;
  const raise = (o, at) => { const a = alerts.raise(Object.assign({ severity: 2, group: {}, fields: {}, summary: 'synthetic', ts_first: at, ts_last: at, source: 'engine', count: 1, group_key: 'g' + (++k) }, o)).alert;
    state.collection('alerts').patch(a.id, (x) => { x.created = at; }); return a; };
  // 20 days: a firewall rule that fires 6 times a day and stopped today; a ransomware rule closed as true positive; a scan closed as noise
  for (let d = 1; d <= 20; d++) {
    for (let i = 0; i < 6; i++) { const a = raise({ rule_id: 'SENTRA-SYN-FW', rule_name: 'Synthetic firewall deny <img src=x onerror=window.__ox=1>' }, T - d * DAY - H); if (d > 2) alerts.setStatus(a.id, 'closed-false-positive', 'syn.ana', 'routine'); }
    if (d <= 5) { const r = raise({ rule_id: 'SENTRA-SYN-RW', rule_name: 'Synthetic ransomware', severity: 4 }, T - d * DAY - 2 * H); alerts.setStatus(r.id, 'acknowledged', 'syn.ana'); alerts.setStatus(r.id, 'closed-true-positive', 'syn.ana', 'contained'); }
  }
  // today: a rule that never fired before, and open alerts on one host from two rules
  for (let i = 0; i < 4; i++) raise({ rule_id: 'SENTRA-SYN-NEW', rule_name: 'Synthetic new detection', group: { host: 'pc-syn-9' } }, T - 2 * H);
  raise({ rule_id: 'SENTRA-SYN-CRED', rule_name: 'Synthetic LSASS read', severity: 4, tactic: 'credential-access', group: { host: 'pc-syn-9' } }, T - H);
  const asked = [];
  const deps = { state, alerts, cases, log: quiet, noTimers: true, config: { soc_analyst: {} } };
  const api = fakeApi({ realRanks: true });
  require(path.join(SIEM, 'engine/soc/routes')).register(api, deps);
  require(path.join(SIEM, 'engine/soc/analyst-routes')).register(api, deps);
  let WHO = { user: 'nora.syn', role: 'analyst' }, insCalls = 0;
  const srv = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://x'), json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u.pathname === '/dashboards/whoami.json') return json(200, WHO);
    if (u.pathname === '/api/soc/soc/copilot/status') return json(200, { enabled: true, model: 'synthetic-model' });
    if (u.pathname === '/api/soc/soc/copilot/conversations') return json(200, { items: [] });
    if (u.pathname === '/api/soc/soc/copilot/ask') { let b = ''; req.on('data', (c) => (b += c)); req.on('end', () => { asked.push(JSON.parse(b)); json(200, { answer: 'Synthetic brief: start with pc-syn-9.', conversation: 'CPC-000000000001', steps: [{ tool: 'queue', ok: true }], proposals: [] }); }); return; }
    if (u.pathname.startsWith('/api/soc/')) {
      if (u.pathname === '/api/soc/soc/overview/insights') insCalls++;
      let b = ''; req.on('data', (c) => { b += c; }); req.on('end', async () => {
        const r = await api.call(req.method, '/api/soc' + u.pathname.slice(8) + u.search, { role: WHO.role, user: WHO.user, body: b ? JSON.parse(b) : undefined });
        json(r.status, r.body);
      }); return;
    }
    if (u.pathname.startsWith('/api/')) return json(404, { error: 'not in this test' });
    const f = path.join(DASH, u.pathname.replace(/^\/dashboards\//, '/')); if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (err, d) => { if (err) { res.writeHead(404); res.end(); return; } res.writeHead(200, { 'Content-Type': u.pathname.endsWith('.js') ? 'application/javascript' : u.pathname.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port + '/soc-overview.html?standalone=1';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  const wait = (p, fn, arg) => p.waitForFunction(fn, arg === undefined ? null : arg, { timeout: 15000 }).then(() => true, () => false);
  const T2 = (p, id) => p.textContent('#' + id);
  try {
    const p = await browser.newPage({ viewport: { width: 1500, height: 1100 } }); p.on('pageerror', (x) => errs.push(x.message));
    await p.goto(base);
    ok(await wait(p, () => !document.getElementById('ml').hidden && !!document.querySelector('#fc svg')), 'the AI / ML section is shown to an analyst');
    ok(/forecast/.test(await p.getAttribute('#fc svg', 'aria-label')) && /a projection, not a promise/.test(await T2(p, 'fc')), 'volume forecast drawn, labelled and framed: ' + (await T2(p, 'fc')).slice(-160));
    const sh = await T2(p, 'shift');
    ok(/Silent/.test(sh) && /Synthetic firewall deny/.test(sh) && /check the detection and its log source/.test(sh), 'a rule that went silent is named first: ' + sh.slice(0, 200));
    ok(/New/.test(sh) && /Synthetic new detection/.test(sh), 'a rule that never fired before');
    ok(!(await p.$('#ml img')) && !(await p.evaluate(() => window.__ox)), 'a hostile rule name stays text');
    const rk = await T2(p, 'risk');
    ok(/host:pc-syn-9/.test(rk) && /credential-access/.test(rk) && /5 alert\(s\)/.test(rk), 'most at risk: the host with its tactics: ' + rk.slice(0, 200));
    const ef = await T2(p, 'eff');
    ok(/Synthetic ransomware/.test(ef) && /high value/.test(ef) && /noise/.test(ef), 'detection efficacy: high value and noise: ' + ef.slice(0, 200));
    ok(await p.$$eval('#slaw tbody tr', (r) => r.length) === 4 && /%/.test(await T2(p, 'slaw')), 'SLA attainment for 4 weeks');
    // the shift brief through the Copilot
    ok(await wait(p, () => !!document.getElementById('briefme')), 'brief button once the Copilot is ready');
    await p.click('#briefme');
    ok(await wait(p, () => /Synthetic brief: start with pc-syn-9/.test(document.body.innerText)), 'the brief is shown in the Copilot');
    ok(asked.length === 1 && asked[0].context.page === 'soc-overview' && /Brief me for this shift/.test(asked[0].question), 'asked with the page as context');
    // a click on an entity opens the queue filtered to it
    await p.click('#cop-x');
    await Promise.all([p.waitForURL(/soc-alerts\.html\?q=host%3Apc-syn-9/), p.click('#risk li[data-q="host:pc-syn-9"]')]);
    ok(true, 'entity opens the queue filtered');
    // a viewer: no section, no request
    WHO = { user: 'v.syn', role: 'viewer' }; insCalls = 0;
    const v = await browser.newPage({ viewport: { width: 1300, height: 900 } }); v.on('pageerror', (x) => errs.push(x.message));
    await v.goto(base); await v.waitForFunction(() => /updated/.test(document.getElementById('up').textContent), null, { timeout: 15000 });
    ok(await v.evaluate(() => document.getElementById('ml').hidden) && insCalls === 0, 'a viewer gets no insights (they name people and hosts)');
    await v.close();
    WHO = { user: 'nora.syn', role: 'analyst' };
    const ph = await browser.newPage({ viewport: { width: 390, height: 900 } }); ph.on('pageerror', (x) => errs.push(x.message));
    await ph.goto(base); await wait(ph, () => !!document.querySelector('#fc svg'));
    ok(await ph.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1), 'phone width: no sideways scroll: ' + (process.env.WIDE ? await require(process.env.WIDE)(ph) : '')); await ph.close();
    if (process.env.SHOT) { const s2 = await browser.newPage({ viewport: { width: 1500, height: 1100 } }); await s2.goto(base); await wait(s2, () => !!document.querySelector('#fc svg')); await s2.waitForTimeout(800); await s2.screenshot({ path: process.env.SHOT + '-overview-ml.png', fullPage: true }); await s2.close(); }
  } finally { await browser.close(); srv.close(); fs.rmSync(dir, { recursive: true, force: true }); }
  ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks'); process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
