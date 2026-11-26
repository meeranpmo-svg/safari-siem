// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// AI Network Engineer - the AI / ML overview (network-engineer.html): tiles and four charts drawn from the poller's readings
// (problems by severity, reachability by site, latency by site, problems by kind), each with a readable summary; "Ask AI" on a
// problem (AI on, analyst and above) opens the Ask tab with a question about it, while the row itself still opens the detail;
// a click on a problem kind asks the AI for the lasting fix; AI off or a viewer: no Ask AI; hostile site names stay text; no
// devices yet: no tiles or charts, the page says what to add; without the charts library the charts hide.
// Stubbed API, SYNTHETIC data. Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node network-engineer-insights.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const DASH = path.resolve(__dirname, '../../ui');
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const XSS = '<img src=x onerror=window.PWN=1>';
const FULL = (ai) => ({ poller: { devices: 7, interval_s: 60 }, ai: ai ? { enabled: true, model: 'synthetic-model' } : { enabled: false, reason: 'no key (synthetic)' }, changes_pending: 0,
  sites: [{ site: 'Riyadh HQ', status: 'ok', devices: 4, reachable: 4, rtt_avg_ms: 3, loss_avg_pct: 0, findings: {} },
    { site: XSS, status: 'critical', devices: 3, reachable: 1, rtt_avg_ms: 140, loss_avg_pct: 12, findings: { critical: 1 } }],
  findings: [{ severity: 'critical', kind: 'device-down', title: 'FW-SYN-02 is not answering', site: XSS, device: 'fw-syn-02', device_name: 'FW-SYN-02', vendor: 'fortinet', evidence: [], recommendation: 'Check power and uplink' },
    { severity: 'medium', kind: 'interface-errors', title: 'port1 CRC errors rising', site: 'Riyadh HQ', device: 'sw-syn-01', device_name: 'SW-SYN-01', vendor: 'h3c', evidence: [], recommendation: 'Replace the cable' }] });
let OV = FULL(false), WHO = { user: 'ana.syn', role: 'analyst' };
(async () => {
  const srv = http.createServer((q, r) => { const u = decodeURIComponent(q.url.split('?')[0]), j = (c, o) => { r.writeHead(c, { 'Content-Type': 'application/json' }); r.end(JSON.stringify(o)); };
    if (u.endsWith('whoami.json')) return j(200, WHO);
    if (u === '/api/soc/netops/overview') return j(200, OV);
    if (u.startsWith('/api/')) return j(404, { error: 'not in this test' });
    fs.readFile(path.join(DASH, u.replace(/^\/dashboards\//, '/')), (e, d) => { if (e) { r.writeHead(404); return r.end(); } r.writeHead(200, { 'Content-Type': u.endsWith('.js') ? 'application/javascript' : u.endsWith('.css') ? 'text/css' : 'text/html' }); r.end(d); }); });
  await new Promise((res) => srv.listen(0, '127.0.0.1', res));
  const url = 'http://127.0.0.1:' + srv.address().port + '/dashboards/network-engineer.html?standalone=1';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright'); const browser = await chromium.launch(), errs = [];
  const open = async (block) => { const p = await browser.newPage({ viewport: { width: 1400, height: 1000 } }); p.on('pageerror', (e) => errs.push(e.message)); if (block) await p.route('**/chart.umd.js', (r) => r.fulfill({ status: 404, body: '' })); await p.goto(url); await p.waitForSelector('#findings table, #findings .ne-empty', { state: 'attached', timeout: 15000 }); return p; };
  try {
    let p = await open();
    const kk = (await p.$eval('#nek', (e) => e.innerText)).replace(/\s+/g, ' ');
    ok(/Sites 2/.test(kk) && /1 down or critical/.test(kk) && /Devices reachable 5 \/ 7/.test(kk) && /Average latency 72 ms/.test(kk) && /Critical \/ high 1 \/ 0/.test(kk), 'tiles from the readings: ' + kk);
    await p.waitForFunction(() => (document.getElementById('cv-kind') || {}).getAttribute && document.getElementById('cv-kind').getAttribute('aria-label'), null, { timeout: 8000 }).catch(() => {});
    const lab = await p.$$eval('#aiband canvas', (x) => x.map((c) => c.getAttribute('aria-label') || ''));
    ok(lab.length === 4 && /Problems by severity/.test(lab[0]) && /Reachability by site/.test(lab[1]) && /Latency by site/.test(lab[2]) && /Problems by kind/.test(lab[3]), 'four charts that say what they show: ' + lab.map((l) => l.slice(0, 40)).join(' | '));
    ok(!(await p.$('[data-askf]')), 'AI off: no Ask AI');
    ok(!(await p.evaluate(() => window.PWN)) && /<img src=x/.test(await p.textContent('#sites')), 'a hostile site name stays text');
    await p.close();
    // AI on, analyst: Ask AI on a problem
    OV = FULL(true); p = await open(); await p.waitForSelector('[data-askf]');
    await p.click('[data-askf="0"]');
    ok(!(await p.$eval('#tab-ask', (e) => e.hidden)), 'the Ask tab opens');
    ok(/Investigate this problem on FW-SYN-02 at .*FW-SYN-02 is not answering/.test(await p.$eval('#q', (e) => e.value)), 'the question names the device, site and problem');
    await p.click('[data-tab="overview"]'); await p.click('#findings tr[data-k="1"] td:nth-child(2)');
    ok(await p.waitForFunction(() => /port1 CRC errors rising/.test(document.body.innerText) && /Replace the cable/.test(document.body.innerText), null, { timeout: 5000 }).then(() => true, () => false), 'the row still opens the problem detail');
    await p.close();
    // viewer: no Ask AI
    WHO = { user: 'vera.syn', role: 'viewer' }; p = await open(); ok(!(await p.$('[data-askf]')), 'viewer: no Ask AI'); await p.close();
    // without the charts library: charts hidden, tiles and problems still there
    WHO = { user: 'ana.syn', role: 'analyst' }; p = await open(true);
    ok(await p.$eval('#aiband', (e) => e.hidden) && /Devices reachable/.test(await p.textContent('#nek')) && (await p.$$('#findings tr[data-k]')).length === 2, 'no charts library: charts hidden, tiles and problems stay');
    await p.close();
    // no devices yet
    OV = { poller: { devices: 0, interval_s: 60 }, ai: { enabled: false, reason: 'x' }, sites: [], findings: [] }; p = await open();
    ok(!(await p.textContent('#nek')).trim() && await p.$eval('#aiband', (e) => e.hidden) && /No devices yet/.test(await p.textContent('#sites')), 'no devices: no figures, says what to add');
    await p.close();
    ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  } finally { await browser.close(); srv.close(); }
  console.log((bad ? 'FAILED ' : 'ok ') + (n - bad) + '/' + n + ' network-engineer-insights checks'); process.exit(bad ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });
