// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Portal "the organisation SIEM — Live" (view siemlive, the REAL portal: repos/live/portal index.html + app.js). It used
// to read /api/siem/status (a proof-of-concept engine, absent in production) and stayed on "Connecting to the SIEM engine…"
// for ever. Now it reads the SIEM engine through /api/soc: open alerts, 24-hour measures, log sources. With the engine down
// it names each call and the HTTP status instead of spinning; with one call failing the rest still show; Refresh recovers.
// Synthetic data. Skips when the live copy is not in the repository.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node portal-siemlive.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const LIVE = path.resolve(__dirname, '../../repos/live/portal'), DASH = path.resolve(__dirname, '../../ui');
if (!fs.existsSync(path.join(LIVE, 'index.html'))) { console.log('SKIP: repos/live/portal not present'); process.exit(0); }
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
let MODE = 'down'; const hits = [];
const now = Date.now();
const ALERTS = { total: 2, items: [{ id: 'ALR-1', severity: 4, rule_name: 'Ransomware SYN', mitre: ['T1486'], group: { host: 'srv-syn-2' }, count: 2, summary: 'encryption burst <b>x</b>', ts_last: now - 120000 },
  { id: 'ALR-2', severity: 3, rule_name: 'Brute force SYN', mitre: ['T1110'], group: { src_ip: '198.51.100.7' }, count: 40, summary: 'failed logons', ts_last: now - 600000 }] };
const METRICS = { open_by_severity: { 0: 0, 1: 0, 2: 1, 3: 1, 4: 1 }, totals: { alerts: 9, events: 1234, open_alerts: 3 }, top_hosts: [{ host: 'srv-syn-2', alerts: 4 }], top_users: [{ user: 'user.syn', alerts: 2 }],
  top_rules: [{ rule_id: 'r1', rule_name: 'Brute force SYN', alerts: 5 }], mitre: { T1110: 5, T1486: 1 } };
const SOURCES = { sources: [{ id: 'fw1', label: 'Firewall SYN', kind: 'fortigate', site: 'HQ', state: 'receiving', events_24h: 5000, last_seen: new Date(now - 30000).toISOString() },
  { id: 'dc1', label: 'DC SYN', kind: 'windows', site: 'HQ', state: 'silent', events_24h: 0, last_seen: null }], summary: { receiving: 1, silent: 1, waiting: 0, total: 2 } };
(async () => {
  const srv = http.createServer((req, res) => {
    const u = decodeURIComponent(req.url.split('?')[0]), json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u === '/dashboards/whoami.json' || u === '/auth/whoami') return json(200, { user: 'syed', role: 'admin' });
    if (u.startsWith('/api/soc/ui/menu')) return json(200, { order: null, favorites: [], can_edit_order: true });
    if (u.startsWith('/api/siem/')) hits.push(u);
    if (['/api/soc/alerts', '/api/soc/metrics', '/api/soc/onboard/sources'].includes(u)) {
      if (MODE === 'down') return json(502, { error: 'bad gateway' });
      if (u === '/api/soc/alerts') return json(200, ALERTS);
      if (u === '/api/soc/metrics') return MODE === 'partial' ? json(500, { error: 'internal error' }) : json(200, METRICS);
      return json(200, SOURCES);
    }
    if (u.startsWith('/api/')) return json(404, { error: 'not in this test' });
    const f = u.startsWith('/dashboards/') ? path.join(DASH, u.slice(12)) : u === '/' ? path.join(LIVE, 'index.html') : path.join(LIVE, u);
    if (!f.startsWith(DASH) && !f.startsWith(LIVE)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (e, d) => { if (e) { res.writeHead(404); return res.end(); } res.writeHead(200, { 'Content-Type': f.endsWith('.js') ? 'application/javascript' : f.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright'); const browser = await chromium.launch();
  const p = await browser.newPage({ viewport: { width: 1400, height: 900 } }); const errs = []; p.on('pageerror', (e) => errs.push(e.message));
  const body = () => p.evaluate(() => document.getElementById('viewFocus') ? document.getElementById('viewFocus').innerText : document.body.innerText);
  try {
    await p.goto('http://127.0.0.1:' + srv.address().port + '/'); await p.waitForTimeout(500);
    await p.evaluate(() => setView('siemlive'));   // eslint-disable-line no-undef
    await p.waitForFunction(() => /did not answer/i.test(document.body.innerText), null, { timeout: 15000 });
    let t = await body();
    ok(!/Connecting to the SIEM engine/.test(t), 'no endless "Connecting…"');
    ok(/GET \/api\/soc\/alerts → HTTP 502/.test(t) && /not answering - check the sentra-siem service/.test(t), 'engine down: names the call, the status and what to check');
    ok(/SIEM engine not reachable/i.test(t), 'status pill says not reachable');
    ok(!/POC|public-facing|LogRhythm/.test(t), 'no proof-of-concept or LogRhythm claims');

    MODE = 'partial'; await p.click('[data-siemref]');
    await p.waitForFunction(() => /Ransomware SYN/.test(document.body.innerText), null, { timeout: 15000 });
    t = await body();
    ok(/GET \/api\/soc\/metrics → HTTP 500/.test(t), 'one failed call is named in its own card');
    ok(/Firewall SYN/.test(t) && /Brute force SYN/.test(t), 'the calls that answered still show');

    MODE = 'live'; await p.click('[data-siemref]');
    await p.waitForFunction(() => /srv-syn-2/.test((document.body.innerText.match(/Top hosts[\s\S]*/i) || [''])[0]), null, { timeout: 15000 });
    t = await body();
    ok(/LIVE — SIEM engine/i.test(t), 'live pill');
    ok(/1 \/ 2/.test(t), 'log sources receiving 1 / 2');
    ok(/1,234/.test(t), 'events in 24 h from the measures');
    ok(/T1110 ·\s*5/i.test(t), 'MITRE techniques from the measures');
    ok(/198\.51\.100\.7/.test(t), 'alert entity from the alert group');
    ok(await p.evaluate(() => !document.querySelector('#viewFocus b b') && /<b>x<\/b>/.test(document.body.innerText)), 'alert summary is escaped');
    ok(!hits.length, 'the absent /api/siem POC route is never called: ' + hits.join(','));
    await p.click('[data-siemgo="soc-dashboard"]'); await p.waitForTimeout(300);
    ok(await p.evaluate(() => currentView === 'soc-dashboard'), 'Open SIEM SOC Overview goes to the SOC console');   // eslint-disable-line no-undef
    ok(!errs.length, 'no page errors: ' + errs.slice(0, 3).join(' | '));
  } finally { await browser.close(); srv.close(); }
  console.log(bad ? 'FAILED ' + bad + '/' + n + ' checks' : 'OK ' + n + '/' + n + ' checks'); process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
