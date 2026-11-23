// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Email Dashboard (email-dashboard.html), stubbed SIEM + IT Asset Management, SYNTHETIC data: status strip (service DOWN,
// 30-day availability against 99.99%, receiving route stopped at a named hop), KPI tiles, the world map (countries
// coloured from SMTP sessions, mostly-blocked outlined, Riyadh marked, inbound / outbound toggle, country table, top IPs),
// services in detail (state, numbers, top issue and fix, links), mail volume, escaping, nothing connected.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node email-dashboard.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const DASH = path.resolve(__dirname, '../../ui');
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const POSTS = []; let MODE = 'ok'; let STATSQ = '';
const XSS = '<img src=x onerror=alert(1)>';
const AVAIL = { target: 99.99, ever_up: true, note: 'n', current: { up: false, down_since: Date.parse('2026-10-26T07:55:00Z'), last_at: Date.parse('2026-10-26T08:00:00Z'), hosts: [] },
  windows: [{ days: 30, label: 'Last 30 days', availability: 99.9931, down_minutes: 3, allowed_minutes: 4.3, budget_left_minutes: 1.3, budget_used_pct: 69.8, state: 'met' }], outages: [],
  gaps: [{ severity: 'high', title: 'corpgroup.test has one MX host', fix: ['Add a second gateway node as a second MX'] }] };
const REP = { dqs_configured: false, registered: [], last: { counts: { listed: 1, clean: 2, not_checked: 0 }, findings: [{ title: 'Mail server IP 198.51.100.77 is listed on Spamhaus XBL', recommendation: 'Treat as a possible compromise' }] } };
const ROUTE = { siem: true, issues: [{ severity: 'critical', hop: 'exchange_in', title: 'No mail through Exchange receive in the last hour ' + XSS, fix: ['Check the Exchange transport services are running'] }],
  lanes: { inbound: [{ id: 'internet_in', label: 'Internet senders', state: 'info' }, { id: 'gateway_in', label: 'Email gateway (inbound)', state: 'ok', counts: { delivered: 800 } }, { id: 'exchange_in', label: 'Exchange - receive', state: 'down', counts: { receive: 700 } }],
    outbound: [{ id: 'exchange_out', label: 'Exchange - send', state: 'not_connected', counts: {} }, { id: 'internet_out', label: 'Internet receivers', state: 'info' }] },
  blocked: { inbound: { hop: 'exchange_in', label: 'Exchange - receive', state: 'down', reason: 'No mail through Exchange receive in the last hour', fix: [] } } };
const GEO = { connected: true, range: 10080, note: 'SMTP sessions through the firewalls.', hist: [],
  inbound: { total: 130, denied: 40, countries: [{ name: 'United States', allow: 80, deny: 0 }, { name: 'CN', allow: 5, deny: 40 }, { name: 'SG', allow: 5, deny: 0 }] },
  outbound: { total: 20, denied: 0, countries: [{ name: 'Germany', allow: 20, deny: 0 }] }, top_sources: [{ src: '198.51.100.9', country: 'CN', n: 40, deny: 40 }] };
const RPT = { id: 'MR-0001', regulator: 'sama', kind: 'both', from: Date.parse('2026-10-26T07:40:00Z'), to: Date.parse('2026-10-26T08:10:00Z'), state: 'draft', prepared_by: 'nora.syn', prepared_at: Date.parse('2026-10-26T08:20:00Z'), digest: 'sha256:' + 'a'.repeat(64),
  doc: { title: 'Cyber security incident report - SAMA Cyber Security Framework', kind: 'E-mail service outage and attack', missing: ['Business and customer impact'], statement: 'it is not sent from the platform',
    sections: [{ heading: '1. Summary', paragraphs: ['inbound e-mail service was unavailable for 7 minutes ' + XSS] }, { heading: '3. Timeline', table: { columns: ['Time', 'Event'], rows: [['2026-10-26 10:55 Riyadh', 'Inbound e-mail unavailable']] } },
      { heading: '4. Impact', rows: [['Total downtime in the window', '7 minutes']] }, { heading: '6. Cause', paragraphs: ['Root cause: to be completed'], list_title: 'Platform findings', list: ['No mail through Exchange receive'] }] } };
let RLIST = [];
const STATS = { range_days: 7, from: Date.parse('2026-10-19T09:00:00Z'), source: 'exchange', exchange: true, gateway: true, domains_used: ['corpgroup.test'],
  totals: { received_external: 1200, sent_external: 640, internal: 3100 }, spam: { total: 210, by_action: { quarantined: 200, delivered: 10 }, share_of_inbound_pct: 14.9 },
  phishing: { total: 12, by_action: { blocked: 12 } }, malware: { total: 2, by_action: { blocked: 2 } },
  series: Array.from({ length: 7 }, (_, i) => ({ t: Date.parse('2026-10-19T09:00:00Z') + i * 86400000, received: 100 + i, sent: 50, internal: 400 })),
  top_received_domains: [{ domain: 'partner' + XSS + '.test', n: 90 }], top_sent_domains: [{ domain: 'reinsurer.test', n: 40 }], note: 'Messages counted once each' };
(async () => {
  const srv = http.createServer((req, res) => {
    const u = decodeURIComponent(req.url.split('?')[0]), json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    const body = (fn) => { let b = ''; req.on('data', (c) => { b += c; }); req.on('end', () => { const j = JSON.parse(b || '{}'); POSTS.push([u, j]); fn(j); }); };
    if (u === '/dashboards/whoami.json' || u === '/auth/whoami') return json(200, { user: 'syed', role: 'analyst' });
    if (MODE === 'none' && u.startsWith('/api/')) return json(503, { error: 'unavailable' });
    if (u === '/api/itam/mail-availability') return json(200, AVAIL);
    if (u === '/api/itam/mail-reputation') return json(200, REP);
    if (u === '/api/itam/mail-route') return body(() => json(200, ROUTE));
    if (u === '/api/itam/mail-report' && req.method === 'GET') return json(200, { reports: RLIST });
    if (u === '/api/itam/mail-report' && req.method === 'POST') return body(() => { RLIST = [Object.assign({ missing: 1 }, RPT)]; json(200, RPT); });
    if (u === '/api/itam/mail-report/MR-0001' && req.method === 'GET') return json(200, RPT);
    if (u === '/api/itam/mail-report/MR-0001/approve') return body(() => json(403, { error: 'four-eyes: the person who prepared the report cannot approve it' }));
    if (u === '/api/itam/domains') return json(200, { domains: [{ name: 'corpgroup.test', status: 'active' }, { name: 'old.test', status: 'retired' }] });
    if (u === '/api/soc/mail/stats') { STATSQ = req.url; return json(200, STATS); }
    if (u === '/api/soc/flows/mail') return json(200, GEO);
    if (u === '/api/soc/top') return body((b) => json(200, { values: b.field === 'fields.email_action' ? (/verdict/.test(b.q) ? [{ v: 'blocked', n: 30 }, { v: 'delivered', n: 2 }] : [{ v: 'delivered', n: 800 }, { v: 'blocked', n: 50 }]) : b.field === 'action' ? [{ v: 'receive', n: 700 }, { v: 'fail', n: 4 }, { v: 'defer', n: 2 }] : [] }));
    if (u === '/api/soc/histogram') return body((b) => json(200, { step_ms: 10800000, buckets: [{ t: Date.now() - 7200000, n: /verdict/.test(b.q) ? 3 : 40 }, { t: Date.now() - 3600000, n: /verdict/.test(b.q) ? 1 : 20 }] }));
    if (u.startsWith('/api/')) return json(404, { error: 'not in this test' });
    const f = path.join(DASH, u.replace(/^\/dashboards\//, '')); if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (e, d) => { if (e) { res.writeHead(404); return res.end(); } res.writeHead(200, { 'Content-Type': f.endsWith('.js') ? 'application/javascript' : f.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port;
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright'); const browser = await chromium.launch();
  try {
    const p = await browser.newPage({ viewport: { width: 1400, height: 1000 } }); const errs = []; p.on('pageerror', (e) => errs.push(e.message));
    await p.goto(base + '/dashboards/email-dashboard.html?standalone=1'); await p.waitForSelector('#svc > div h3'); await p.waitForSelector('#map path');
    const st = await p.$eval('#sts', (e) => e.innerText);
    ok(/DOWN/.test(st) && /99\.993%/.test(st) && /target 99\.99%/i.test(st) && /Stopped/.test(st) && /Exchange - receive/.test(st), 'status strip: down, availability vs target, where receiving stopped');
    const kk = await p.$eval('#kk', (e) => e.innerText);
    ok(/850/.test(kk) && /Threats delivered/.test(kk) && /Spamhaus listings/.test(kk), 'KPI tiles from the SIEM and IT Asset Management');
    // mail volume
    await p.waitForSelector('#mvt .v');
    const mv = await p.$eval('#mvt', (e) => e.innerText);
    ok(/1,200|1200/.test(mv) && /640/.test(mv) && /3,100|3100/.test(mv) && /210/.test(mv) && /14\.9% of inbound/.test(mv) && /quarantined 200/.test(mv), 'sent, received, internal and spam shown');
    ok(/domains=corpgroup\.test/.test(decodeURIComponent(STATSQ)) && !/old\.test/.test(decodeURIComponent(STATSQ)) && /range=7/.test(STATSQ), 'our active domains and the period passed to the SIEM');
    ok(await p.$$eval('#mvs i', (a) => a.length) === 7, 'daily stacked bars');
    ok(/reinsurer\.test/.test(await p.$eval('#mvx', (e) => e.innerText)) && await p.$$eval('#mvr img', (a) => a.length) === 0, 'top external domains, escaped');
    // the map
    const nPaths = await p.$$eval('#map path.c', (a) => a.length); ok(nPaths > 150, 'world drawn (' + nPaths + ' countries)');
    const fills = await p.$$eval('#map path.c', (a) => a.filter((x) => x.getAttribute('fill') !== '#161b22').length); ok(fills === 2, 'two countries coloured from the sessions (SG not on the 110m map)');
    ok(await p.$$eval('#map path.c', (a) => a.some((x) => x.getAttribute('stroke') === '#f85149')), 'mostly-blocked country outlined');
    ok(await p.$$eval('#map circle', (a) => a.length) === 1, 'Riyadh marked');
    ok(/Singapore 5/.test(await p.$eval('#mapnote', (e) => e.textContent)), 'country not on the map listed in the note');
    const ct = await p.$eval('#ctry', (e) => e.innerText); ok(/United States/.test(ct) && /China/.test(ct) && /40/.test(ct), 'country table with blocked counts');
    ok(/198\.51\.100\.9/.test(await p.$eval('#srcs', (e) => e.innerText)), 'top sending IPs for an analyst');
    await p.click('[data-dir="out"]'); ok(/Germany/.test(await p.$eval('#ctry', (e) => e.innerText)) && /20 sessions/.test(await p.$eval('#mapn', (e) => e.textContent)), 'outbound toggle');
    // services
    const sv = await p.$eval('#svc', (e) => e.innerText);
    ok(/Availability/.test(sv) && /Email gateway \(inbound\)/.test(sv) && /Exchange - receive/.test(sv) && /DOWN/.test(sv) && /transport services/.test(sv) && /Spamhaus reputation/.test(sv) && /possible compromise/.test(sv), 'services with state, top issue and fix');
    ok(/not connected/.test(sv) && /connect this service/.test(sv), 'a service without data says not connected');
    ok(await p.$$eval('#svc a[href="email-route-map.html"]', (a) => a.length) >= 2, 'details link to the route');
    ok(await p.$$eval('#sts img, #kk img, #svc img, #ctry img, #srcs img, #mapnote img', (a) => a.length) === 0, 'issue text escaped');
    const rp = POSTS.find((x) => x[0] === '/api/itam/mail-route'); ok(rp && rp[1].siem && rp[1].siem.exchange.receive === 700, 'route judged with the SIEM counts');
    ok(await p.$$eval('#vol i', (a) => a.length) === 2, 'mail volume bars');
    // regulator report
    ok(/No regulator report/.test(await p.$eval('#rptlist', (e) => e.innerText)), 'no report yet - said so');
    await p.click('#rptnew summary'); await p.waitForFunction(() => document.getElementById('rf').value !== '');
    await p.fill('#ri', 'Customers could not e-mail claims for 7 minutes'); await p.selectOption('#rk', 'both'); await p.click('#rptform button[type=submit]'); await p.waitForSelector('#rptdoc .rpt');
    const rq = POSTS.find((x) => x[0] === '/api/itam/mail-report');
    ok(rq && rq[1].regulator === 'sama' && rq[1].kind === 'both' && /Z$/.test(rq[1].from) && rq[1].notes.impact && rq[1].siem && rq[1].siem.threats.blocked === 30, 'report prepared with window, notes and the SIEM threat counts');
    const doc = await p.$eval('#rptdoc', (e) => e.innerText);
    ok(/SAMA Cyber Security Framework/.test(doc) && /DRAFT/.test(doc) && /To be completed by the CISO/.test(doc) && /Business and customer impact/.test(doc) && /Inbound e-mail unavailable/.test(doc) && /not sent from the platform/.test(doc), 'draft shown with sections, timeline and what is missing');
    ok(await p.$$eval('#rptdoc img', (a) => a.length) === 0, 'report text escaped');
    ok(/MR-0001/.test(await p.$eval('#rptlist', (e) => e.innerText)), 'listed');
    await p.click('#rptappr'); await p.waitForTimeout(300);
    ok(/four-eyes/.test(await p.$eval('#rptamsg', (e) => e.textContent)), 'four-eyes refusal shown');
    ok(POSTS.find((x) => x[0].endsWith('/approve'))[1].digest === RPT.digest, 'approval carries the digest');
    MODE = 'none'; await p.reload(); await p.waitForFunction(() => /not checked|has not been checked/.test(document.getElementById('svc').innerText));
    ok(/not available/.test(await p.$eval('#ctry', (e) => e.innerText)), 'nothing connected: says so, nothing invented');
    ok(await p.$$eval('#map path.c', (a) => a.filter((x) => x.getAttribute('fill') !== '#161b22').length) === 0, 'map empty without data');
    ok(errs.length === 0, 'no page errors: ' + errs.join(' | '));
  } finally { await browser.close(); srv.close(); }
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks');
  process.exit(bad ? 1 : 0);
})();
