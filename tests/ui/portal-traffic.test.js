// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Portal Traffic (portal-traffic.html), stubbed SIEM, SYNTHETIC data: site list then the chosen site, tiles, status chart,
// latency (and the 'not in the log format' state), pages, error paths, countries from the firewall with the unseen count,
// error IPs only when returned (operator), escaping, no web log at all, not installed. No sample data anywhere.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node portal-traffic.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const DASH = path.resolve(__dirname, '../../ui');
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
let MODE = 'ok'; const ASKED = [];
const XSS = '<img src=x onerror=alert(1)>';
const NOW = Date.now();
const SITES = [{ site: 'portal.corpgroup.test', requests: 12000 }, { site: 'intranet.corpgroup.test', requests: 400 }];
const series = Array.from({ length: 96 }, (_, i) => ({ t: NOW - (96 - i) * 900000, s2: 100 + i, s3: 5, s4: i % 7, s5: i === 50 ? 30 : 0, bytes: 1000, p95_s: i === 50 ? 4.2 : 0.8 }));
const FULL = { site: 'portal.corpgroup.test', hours: 24, bucket_ms: 900000, sites: SITES,
  totals: { requests: 12000, visitors: 3100, visitors_5min: 42, bytes: 900000000, s2: 10800, s3: 600, s4: 500, s5: 100, ok_pct: 99.17 },
  latency: { p50_s: 0.12, p95_s: 1.84, max_s: 9.3, measured: 11000 }, series,
  pages: [{ path: '/claims/new' + XSS, requests: 3000, server_errors: 40, visitors: 900 }], error_paths: [{ path: '/api/quote', e4: 120, e5: 60, codes: ['404', '502'] }],
  codes: [{ code: '200', n: 10800 }, { code: '502', n: 60 }], countries: [{ name: 'Saudi Arabia', visitors: 2800, requests: 10000 }, { name: 'Netherlands', visitors: 3, requests: 320 }],
  not_seen_by_firewall: { visitors: 40, requests: 90 }, error_ips: [{ ip: '203.0.113.50', e4: 300, e5: 0, requests: 320, country: 'Netherlands' }], note: 'Countries are as the firewall logged each client IP.' };
(async () => {
  const srv = http.createServer((req, res) => {
    const u = decodeURIComponent(req.url.split('?')[0]), json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u === '/dashboards/whoami.json' || u === '/auth/whoami') return json(200, { user: 'syed', role: 'operator' });
    if (MODE === 'none' && u.startsWith('/api/')) return json(404, { error: 'not found' });
    if (u === '/api/soc/web/traffic') { const sp = new URL('http://x' + req.url).searchParams, site = sp.get('site'); ASKED.push([site, sp.get('hours')]);
      if (MODE === 'nolog') return json(200, { site: null, sites: [] });
      if (!site) return json(200, { site: null, sites: SITES });
      if (MODE === 'viewer') return json(200, Object.assign({}, FULL, { error_ips: null, latency: null, series: series.map((x) => Object.assign({}, x, { p95_s: null })), note: 'Request time is not in this web server\'s log format - add $request_time.' }));
      return json(200, FULL); }
    if (u.startsWith('/api/')) return json(404, { error: 'not in this test' });
    const f = path.join(DASH, u.replace(/^\/dashboards\//, '')); if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (e, d) => { if (e) { res.writeHead(404); return res.end(); } res.writeHead(200, { 'Content-Type': f.endsWith('.js') ? 'application/javascript' : f.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port;
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright'); const browser = await chromium.launch();
  try {
    const p = await browser.newPage({ viewport: { width: 1400, height: 1000 } }); const errs = []; p.on('pageerror', (e) => errs.push(e.message));
    let alerted = false; p.on('dialog', (d) => { alerted = true; d.dismiss(); });
    await p.goto(base + '/dashboards/portal-traffic.html?standalone=1'); await p.waitForSelector('#pages table');
    ok(ASKED[0][0] === null && ASKED[1][0] === 'portal.corpgroup.test', 'sites first, then the busiest site');
    const html = await p.content(); ok(!/sample data/i.test(html) && !/corp\.example/.test(html), 'no sample data left on the page');
    const k = await p.textContent('#kk');
    ok(/Requests\s*12,000/.test(k) && /Unique visitors\s*3,100/.test(k) && /Visitors now\s*42/.test(k) && /99\.17 %/.test(k) && /1\.84 s/.test(k) && /858\.3 MB|900 MB|0\.9 GB/.test(k), 'tiles: ' + k);
    ok((await p.$$('#bars i')).length === 96 && (await p.$$('#bars b.c5')).length === 1, 'status chart with the 5xx bucket');
    ok((await p.$$('#lat i.slow')).length === 1 && /Median 120 ms · 95th percentile 1\.84 s/.test(await p.textContent('#latnote')), 'latency chart, slow bucket red');
    const pg = await p.textContent('#pages'); ok(/\/claims\/new/.test(pg) && /3,000/.test(pg) && !(await p.$('#pages img')), 'pages, escaped');
    ok(/\/api\/quote/.test(await p.textContent('#errs')) && /404, 502/.test(await p.textContent('#errs')), 'error paths');
    const c = await p.textContent('#ctry'); ok(/Saudi Arabia/.test(c) && /2,800/.test(c) && /40 visitor IP\(s\) \(90 requests\) were not seen by the firewall/.test(c), 'countries from the firewall, unseen counted');
    ok(/502/.test(await p.textContent('#codes')) && /0\.5 %/.test(await p.textContent('#codes')), 'status share');
    ok(!(await p.isHidden('#ipcard')) && /203\.0\.113\.50/.test(await p.textContent('#ips')) && /Netherlands/.test(await p.textContent('#ips')), 'error IPs for an operator');
    await p.selectOption('#hours', '168'); await p.waitForTimeout(300); ok(ASKED.at(-1)[1] === '168', 'period');
    ok(!alerted && errs.length === 0, 'no script ran, no page error: ' + errs.join(' | '));
    MODE = 'viewer'; await p.reload(); await p.waitForSelector('#pages table');
    ok(await p.isHidden('#ipcard'), 'no IP card without IPs'); ok(/not in log/.test(await p.textContent('#kk')) && /\$request_time/.test(await p.textContent('#latnote')), 'latency not in the log format, never 0');
    MODE = 'nolog'; await p.goto(base + '/dashboards/portal-traffic.html?standalone=1&x=1'); await p.waitForFunction(() => /No web server access log has reached the SIEM/.test(document.getElementById('nc').textContent));
    ok(true, 'no web log: says what to send');
    MODE = 'none'; await p.reload(); await p.waitForFunction(() => /not installed/.test(document.getElementById('nc').textContent)); ok(true, 'not installed');
    await p.close();
  } finally { await browser.close(); srv.close(); }
  console.log(`${n - bad}/${n} passed`); process.exit(bad ? 1 : 0);
})();
