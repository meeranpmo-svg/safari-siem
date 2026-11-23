// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// AIOps Center (aiops.html), stubbed engines, SYNTHETIC data: the KPIs come from the SIEM metrics (events → alerts noise
// reduction, MTTD / MTTA / MTTR), XDR (open correlated incidents) and the AI engineers (fixed & verified, waiting for
// approval); the funnel, response times, correlated incidents (escaped, linked to XDR), predictive capacity / SLA alerts,
// noisy rules with their FP rate and the self-healing table are drawn. With every engine down each section says what is
// missing and nothing invents a figure. Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node aiops.test.js
const http = require('http'), path = require('path'), fs = require('fs');
const DASH = path.resolve(__dirname, '../../ui');
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
let DOWN = false; const H = 3600000;
const METRICS = { mttd_s: 240, mttr_s: 5 * 3600, mttd: { n: 40, avg_ms: 240000, median_ms: 120000, p90_ms: 600000 },
  mtta: { alerts: { n: 30, avg_ms: 20 * 60000, median_ms: 600000, p90_ms: H }, cases: { n: 4, avg_ms: 30 * 60000, median_ms: 1200000, p90_ms: H } },
  mttr: { alerts: { n: 20, avg_ms: 2 * H }, cases: { n: 3, avg_ms: 5 * H } },
  totals: { events: 100000, alerts: 500, open_alerts: 12 }, sla: { cases: 4, ack_compliance_pct: 75, resolve_compliance_pct: 100, at_risk: 2 },
  noisy_rules: [{ rule_id: 'r1', rule_name: 'SYN failed logon burst', alerts: 300, per_day: 10, noisy: true }, { rule_id: 'r2', rule_name: 'SYN port scan', alerts: 20, per_day: 0.7, noisy: false }],
  fp_rate: [{ rule_id: 'r1', closed: 10, fp_rate: 0.6 }] };
const XDR = { total: 3, summary: { incidents: 3, open: 2, cross_domain: 1, high: 1 }, domain_names: { identity: 'Identity', endpoint: 'Endpoint' },
  items: [{ id: 'XDR-SYN1', title: '<img src=x onerror=alert(1)> lateral movement', score: 82, severity: 4, status: 'open', alerts: 7, domains: { identity: 3, endpoint: 4 } }] };
const eng = (id, name, o) => Object.assign({ id, name, on_duty: true, open: 1, by_status: {}, resolved_24h: 0 }, o);
const CAP = { clusters: [{ name: 'SYN-CL1', platform: 'vmware', forecast: { memory: { days_to_limit: 20, per_month: 4, days_of_history: 45, reliable: true }, cpu: { days_to_limit: null }, storage: { days_to_limit: 400 } } }] };
(async () => {
  const srv = http.createServer((req, res) => {
    const u = decodeURIComponent(req.url.split('?')[0]), json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u === '/dashboards/whoami.json' || u === '/auth/whoami') return json(200, { user: 'syed', role: 'operator' });
    if (u.startsWith('/api/')) { if (DOWN) return json(404, { error: 'not found' });
      if (u === '/api/soc/metrics') return json(200, METRICS);
      if (u === '/api/soc/xdr/incidents') return json(200, XDR);
      if (u === '/api/soc/duty/engineers') return json(200, { engineers: [eng('network', 'AI Network Engineer', { by_status: { 'awaiting-approval': 2, approved: 1 }, resolved_24h: 3 })] });
      if (u === '/api/itam/duty/engineers') return json(200, { engineers: [eng('virt', 'AI Virtualization Administrator', { resolved_24h: 2, not_connected: true }), eng('desktop', 'AI Desktop Support Engineer', { on_duty: false })] });
      if (u === '/api/itam/virt/capacity') return json(200, CAP);
      return json(404, { error: 'not in this test' }); }
    const f = path.join(DASH, u.replace(/^\/dashboards\//, '')); if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (e, d) => { if (e) { res.writeHead(404); return res.end(); } res.writeHead(200, { 'Content-Type': f.endsWith('.js') ? 'application/javascript' : f.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port;
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright'); const browser = await chromium.launch();
  try {
    const p = await browser.newPage(); const errs = []; let dialogs = 0; p.on('pageerror', (e) => errs.push(e.message)); p.on('dialog', (d) => { dialogs++; d.dismiss(); });
    await p.goto(base + '/dashboards/aiops.html?standalone=1'); await p.waitForFunction(() => /updated/.test(document.getElementById('up').textContent), null, { timeout: 15000 });
    const k = await p.$$eval('#kk .t', (a) => a.map((t) => t.innerText.replace(/\s+/g, ' ')));
    ok(/Noise reduction 99.5%/.test(k[0]) && /100,000 events → 500 alerts/.test(k[0]), 'noise reduction from events → alerts: ' + k[0]);
    ok(/Correlated incidents 2 /.test(k[1]) && /1 across domains/.test(k[1]), 'open correlated incidents: ' + k[1]);
    ok(/MTTD 4 min/.test(k[2]) && /MTTA 30 min/.test(k[3]) && /MTTR 5.0 h/.test(k[4]), 'MTTD / MTTA / MTTR: ' + k.slice(2, 5).join(' | '));
    ok(/Fixed & verified \(24 h\) 5/.test(k[5]) && /2 waiting/.test(k[5]), 'fixed & verified and waiting for approval (approved-not-applied is not counted as waiting): ' + k[5]);
    const fun = await p.$eval('#funnel', (e) => e.innerText);
    ok(/Raw events\s*100,000/.test(fun) && /Alerts raised\s*500/.test(fun) && /Correlated incidents\s*3/.test(fun), 'funnel: ' + fun.replace(/\s+/g, ' ').slice(0, 120));
    ok(/75%/.test(await p.$eval('#times', (e) => e.innerText)), 'response SLA compliance shown');
    const inc = await p.$eval('#inc', (e) => ({ t: e.innerText, img: e.querySelectorAll('img').length, href: (e.querySelector('a') || {}).getAttribute && e.querySelector('a').getAttribute('href') }));
    ok(inc.img === 0 && /<img src=x/.test(inc.t) && /Identity, Endpoint/.test(inc.t) && inc.href === 'soc-xdr.html#XDR-SYN1', 'incidents escaped, sources named, linked to XDR: ' + JSON.stringify(inc).slice(0, 160));
    const pred = await p.$eval('#pred', (e) => e.innerText);
    ok(/SYN-CL1: memory reaches its limit/.test(pred) && /about 20 days/.test(pred) && /2 open case/.test(pred) && !/storage/.test(pred), 'predictive: capacity within 180 days + SLA at risk, beyond 180 days left out: ' + pred.replace(/\s+/g, ' ').slice(0, 200));
    const noisy = await p.$eval('#noisy', (e) => e.innerText);
    ok(/SYN failed logon burst/.test(noisy) && /60% of 10 closed/.test(noisy) && /tune/.test(noisy) && /not enough closed/.test(noisy), 'noisy rules with FP rate: ' + noisy.replace(/\s+/g, ' ').slice(0, 160));
    const heal = await p.$eval('#heal', (e) => e.parentElement.innerText);
    ok(/AI Network Engineer/.test(heal) && /source not connected/.test(heal) && /off duty/.test(heal) && /never the requester/.test(heal), 'self-healing table + the approval rule stated');
    ok(!errs.length && !dialogs, 'no page errors, no injected script ran: ' + errs.join(' | '));
    // every engine down: each section says what is missing, no figure invented
    DOWN = true; await p.click('#refresh'); await p.waitForTimeout(800);
    const all = await p.$eval('main', (e) => e.innerText);
    ok(/not installed - run the update/.test(all) && !/\d+%/.test(await p.$eval('#kk', (e) => e.innerText)) && /AI engineers are not reachable/.test(all) && !/NaN|undefined|null/.test(all), 'engines down: honest empty states, no NaN / invented figure');
    ok(!errs.length, 'no page errors with engines down: ' + errs.join(' | '));
  } finally { await browser.close(); srv.close(); }
  console.log(bad ? 'FAILED ' + bad + '/' + n + ' checks' : 'OK ' + n + '/' + n + ' checks'); process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
