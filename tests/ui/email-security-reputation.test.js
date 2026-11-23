// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Email Security → Mail route flow (graphical lanes, blocked hop, fixes) and Mail server reputation card (email-security.html, IT Asset Management /mail-reputation), stubbed APIs,
// SYNTHETIC data (RFC 5737 addresses): listed / clean / not-checked rows with the Spamhaus list and the advice, the
// public-resolver warning, Check now, Add IP, the DQS key (never shown back, admin refusal shown), escaping, not installed.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node email-security-reputation.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const DASH = path.resolve(__dirname, '../../ui');
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const POSTS = []; let MODE = 'ok';
const XSS = '<img src=x onerror=alert(1)>';
const VIEW = () => ({ dqs_configured: POSTS.some((p) => p[0].endsWith('/key')), every_hours: 6, note: 'n', registered: [{ id: 'MIP-001', ip: '192.0.2.50', label: 'gateway egress', role: 'outbound' }],
  last: { at: Date.parse('2026-10-26T08:00:00Z'), by: 'system:mail-reputation', dqs: false, counts: { listed: 1, clean: 1, not_checked: 1 }, changes: [], findings: [],
    warning: MODE === 'refused' ? 'Nothing could be checked: Spamhaus refuses queries through public / open resolvers. an administrator adds the DQS key.' : null,
    notes: ['example sends through Microsoft 365 ' + XSS],
    rows: [{ kind: 'ip', target: '203.0.113.10', roles: ['inbound'], sources: ['MX mx1.corpgroup.test'], provider: null, state: 'listed', severity: 'critical', changed: 'clean',
      lists: [{ code: '127.0.0.4', list: 'XBL', meaning: 'Exploits Block List ' + XSS, severity: 'critical' }], advice: ['Treat as a possible compromise', 'request removal at https://check.spamhaus.org/'] },
    { kind: 'domain', target: 'corpgroup.test', roles: ['mail domain'], sources: ['Domains & Hosting'], provider: null, state: 'clean', lists: [], advice: [] },
    { kind: 'ip', target: '198.51.100.20', roles: ['inbound'], sources: ['MX'], provider: 'Microsoft 365 / Exchange Online Protection', state: 'not_checked', why: 'Spamhaus refuses queries through public / open resolvers', lists: [], advice: [] }] } });
const ROUTE = { siem: true, note: 'n', profile: { expected_mx: ['gw.corpgroup.test'], platform: 'hybrid', isp_links: 2 }, counts: {},
  lanes: { inbound: [{ id: 'internet_in', label: 'Internet senders', state: 'info', issues: 0 }, { id: 'mx', label: 'MX record (DNS)', state: 'ok', issues: 0, detail: '10 gw.corpgroup.test' },
    { id: 'gateway_in', label: 'Email gateway (inbound)', state: 'ok', issues: 0, counts: { delivered: 800 } }, { id: 'exchange_in', label: 'Exchange - receive', state: 'down', issues: 1, counts: { receive: 700 } },
    { id: 'mailbox', label: 'Mailbox - deliver', state: 'warn', issues: 0 }],
    outbound: [{ id: 'mailbox_out', label: 'Mailbox - submit', state: 'ok', issues: 0 }, { id: 'egress', label: XSS + ' Egress IP', state: 'bad', issues: 1 }, { id: 'internet_out', label: 'Internet receivers', state: 'info', issues: 0 }] },
  blocked: { inbound: { hop: 'exchange_in', label: 'Exchange - receive', state: 'down', reason: 'No mail through Exchange receive in the last hour (700 in the period)', fix: ['Check the Exchange transport services are running'] },
    outbound: { hop: 'egress', label: 'Egress IP', state: 'bad', reason: 'no reverse DNS', fix: ['Ask the ISP to set the PTR'] } },
  issues: [{ severity: 'critical', hop: 'exchange_in', title: 'No mail through Exchange receive in the last hour', evidence: ['last hour: 0'], fix: ['Check the receive connector bound to the gateway'] },
    { severity: 'high', hop: 'egress', title: '198.51.100.77 has no reverse DNS ' + XSS, evidence: [], fix: ['Ask the ISP to set the PTR'] }] };
const AVAIL = () => ({ target: 99.99, ever_up: true, note: 'about 53 minutes of downtime a year',
  current: MODE === 'down' ? { up: false, down_since: Date.parse('2026-10-26T07:55:00Z'), last_at: Date.parse('2026-10-26T08:00:00Z'), hosts: [{ host: 'mx1.corpgroup.test', up: false }] } : { up: true, last_at: Date.parse('2026-10-26T08:00:00Z'), hosts: [{ host: 'mx1.corpgroup.test', up: true }] },
  windows: [{ days: 30, label: 'Last 30 days', availability: 99.9931, down_minutes: 3, allowed_minutes: 4.3, budget_left_minutes: 1.3, budget_used_pct: 69.8, coverage_pct: 100, partial: false, state: 'met', measured_minutes: 43200 },
    { days: 90, label: 'Last 90 days', availability: 99.98, down_minutes: 26, allowed_minutes: 13, budget_left_minutes: -13, budget_used_pct: 200, coverage_pct: 40, partial: true, state: 'breached', measured_minutes: 51840 },
    { days: 365, label: 'Last 365 days', availability: null, down_minutes: null, allowed_minutes: 52.6, coverage_pct: 10, partial: true, state: 'no_data', measured_minutes: 0 }],
  outages: [{ start: Date.parse('2026-10-20T03:10:00Z'), minutes: 3, hosts: ['mx1.corpgroup.test: ECONNREFUSED ' + XSS] }],
  gaps: [{ severity: 'high', title: 'corpgroup.test has one MX host - any outage of it stops inbound mail', fix: ['Add a second gateway node as a second MX'] }] });
const SOCQ = [];
(async () => {
  const srv = http.createServer((req, res) => {
    const u = decodeURIComponent(req.url.split('?')[0]), json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    const body = (fn) => { let b = ''; req.on('data', (c) => { b += c; }); req.on('end', () => { const j = JSON.parse(b || '{}'); POSTS.push([u, j]); fn(j); }); };
    if (u === '/dashboards/whoami.json' || u === '/auth/whoami') return json(200, { user: 'syed', role: 'operator' });
    if (u.startsWith('/api/itam/mail-reputation') && MODE === 'missing') return json(404, { error: 'not found' });
    if (u === '/api/itam/mail-reputation') return json(200, VIEW());
    if (u === '/api/itam/mail-reputation/check') return body(() => json(200, VIEW()));
    if (u === '/api/itam/mail-reputation/ips') return body((b) => json(200, { id: 'MIP-002', ip: b.ip }));
    if (u === '/api/itam/mail-availability' && MODE === 'missing') return json(404, { error: 'nf' });
    if (u === '/api/itam/mail-availability') return json(200, AVAIL());
    if (u === '/api/itam/mail-availability/target') return body(() => json(403, { error: 'requires role admin' }));
    if (u === '/api/soc/top') return body((b) => { SOCQ.push(b); const v = b.field === 'fields.email_action' ? [{ v: 'delivered', n: 800 }, { v: 'blocked', n: 50 }] : b.field === 'action' ? (b.from === 'now-1h' ? [{ v: 'send', n: 4 }] : [{ v: 'receive', n: 700 }, { v: 'send', n: 110 }, { v: 'deliver', n: 690 }]) : b.field === 'fields.email_direction' ? [{ v: 'inbound', n: 30 }, { v: 'outbound', n: 5 }] : [{ v: '451 4.4.1 timed out', n: 3 }]; json(200, { values: v }); });
    if (u === '/api/itam/mail-route' && MODE === 'missing') return json(404, { error: 'nf' });
    if (u === '/api/itam/mail-route') return body(() => json(200, ROUTE));
    if (u === '/api/itam/mail-route/profile') return body((b) => json(200, b));
    if (u === '/api/itam/mail-reputation/key') return body(() => json(403, { error: 'requires role admin' }));
    if (u.startsWith('/api/')) return json(404, { error: 'not in this test' });
    const f = path.join(DASH, u.replace(/^\/dashboards\//, '')); if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (e, d) => { if (e) { res.writeHead(404); return res.end(); } res.writeHead(200, { 'Content-Type': f.endsWith('.js') ? 'application/javascript' : f.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port;
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright'); const browser = await chromium.launch();
  try {
    const p = await browser.newPage(); const errs = []; p.on('pageerror', (e) => errs.push(e.message));
    await p.goto(base + '/dashboards/email-security.html?standalone=1'); await p.waitForSelector('#repl table'); await p.waitForSelector('#rtsvg svg');
    await p.waitForSelector('#avwin .big');
    const av = await p.$eval('#avail', (e) => e.innerText);
    ok(/Mail service up/.test(av) && /99\.993%/.test(av) && /meeting the target/.test(av) && /target missed/.test(av) && /down 3 min of 4\.3 min allowed/.test(av) && /1\.3 min left/.test(av), 'availability per window against 99.99% with the budget');
    ok(/measured 40% of the period/.test(av) && /no data yet/.test(av), 'partial coverage and no data said so');
    ok(/one MX host/.test(av) && /second gateway node/.test(av), 'design gap with its fix');
    ok(await p.$$eval('#avail img', (a) => a.length) === 0, 'outage hosts escaped');
    ok(await p.$eval('#avsel', (e) => e.value) === '99.99', 'target shown');
    await p.selectOption('#avsel', '99.999'); await p.click('#avtgt button'); await p.waitForTimeout(300);
    ok(/administrator/.test(await p.$eval('#avmsg', (e) => e.textContent)), 'target change refused for a non-admin, explained');
    const rp = POSTS.find((x) => x[0] === '/api/itam/mail-route');
    ok(rp && rp[1].siem && rp[1].siem.gateway_in.delivered === 800 && rp[1].siem.exchange.receive === 700 && rp[1].siem.recent.exchange_receive === 0 && rp[1].siem.recent.gateway_in === 30 && rp[1].siem.exchange_reasons[0].n === 3, 'page sends SIEM period and last-hour counts');
    ok(SOCQ.some((q) => q.from === 'now-1h'), 'last-hour window queried');
    ok(await p.$$eval('#rtsvg g[data-hop]', (a) => a.length) === 8, 'every hop drawn in the two lanes');
    const sv = await p.$eval('#rtsvg svg', (e) => e.textContent);
    ok(/BLOCKED HERE/.test(sv) && /DOWN/.test(sv) && /Receiving \(inbound\)/.test(sv) && /Sending \(outbound\)/.test(sv), 'lanes, down hop and blocked marker drawn');
    ok((sv.match(/✕/g) || []).length === 2, 'broken arrow after each blocked hop');
    const bn = await p.$eval('#rtbanner', (e) => e.innerText);
    ok(/Receiving mail is stopped at: Exchange - receive/.test(bn) && /transport services/.test(bn) && /Sending mail is failing at: Egress IP/.test(bn), 'banner names where mail stops and the fix');
    ok(await p.$$eval('#route img', (a) => a.length) === 0, 'labels and issues escaped (also inside the SVG)');
    await p.click('#rtsvg g[data-hop="exchange_in"]'); await p.waitForSelector('#rtdetail:not([hidden])');
    ok(/receive connector/.test(await p.$eval('#rtdetail', (e) => e.innerText)), 'clicking a hop shows its issues and fixes');
    await p.click('#rtsvg g[data-hop="mx"]'); ok(/No issue found/.test(await p.$eval('#rtdetail', (e) => e.innerText)), 'healthy hop says so');
    ok(await p.$eval('#rtprof input[name="mx"]', (e) => e.value) === 'gw.corpgroup.test', 'expected MX shown');
    ok(await p.$eval('#rtplat', (e) => e.value) === 'hybrid' && await p.$eval('#rtisp', (e) => e.value) === '2', 'platform and Internet links shown');
    await p.fill('#rtprof input[name="mx"]', 'gw.corpgroup.test, gw2.corpgroup.test'); await p.selectOption('#rtplat', 'online'); await p.fill('#rtisp', '3'); await p.click('#rtprof button'); await p.waitForTimeout(300);
    const pf = POSTS.find((x) => x[0].endsWith('/mail-route/profile')); ok(pf && pf[1].expected_mx.length === 2 && pf[1].platform === 'online' && pf[1].isp_links === 3, 'route profile saved (MX, platform, links)');
    const t = await p.$eval('#rep', (e) => e.innerText);
    ok(/203\.0\.113\.10/.test(t) && /listed/.test(t) && /XBL/.test(t) && /possible compromise/.test(t) && /was clean/.test(t), 'listed IP with list, change and advice');
    ok(/corpgroup\.test/.test(t) && /clean/.test(t), 'domain checked against DBL');
    ok(/not checked/.test(t) && /public \/ open resolvers/.test(t) && /Microsoft 365/.test(t), 'refused query shown as not checked, provider named');
    ok(/192\.0\.2\.50 gateway egress/.test(t), 'registered IPs listed');
    ok(await p.$$eval('#rep img', (a) => a.length) === 0, 'listing text and notes escaped');
    await p.click('#repchk'); await p.waitForTimeout(300); ok(POSTS.some((x) => x[0].endsWith('/mail-reputation/check')), 'Check now posts');
    await p.fill('#repip input[name="ip"]', '192.0.2.60'); await p.fill('#repip input[name="label"]', 'Exchange egress'); await p.click('#repip button'); await p.waitForTimeout(300);
    const ip = POSTS.find((x) => x[0].endsWith('/ips')); ok(ip && ip[1].ip === '192.0.2.60' && ip[1].role === 'outbound', 'Add IP posts the address and role');
    ok(await p.$eval('#repkey input', (e) => e.type) === 'password', 'DQS key field is masked');
    await p.fill('#repkey input', 'abcdefghij0123456789abcdef'); await p.click('#repkey button'); await p.waitForTimeout(300);
    ok(/administrator/.test(await p.$eval('#repwarn', (e) => e.textContent)), 'admin-only refusal explained');
    ok(await p.$eval('#repkey input', (e) => e.value) === 'abcdefghij0123456789abcdef', 'key kept in the field on refusal, never echoed elsewhere');
    ok(!/abcdefghij0123456789abcdef/.test(await p.$eval('#rep', (e) => e.innerText)), 'key not displayed');
    MODE = 'down'; await p.reload(); await p.waitForSelector('#avwin .big');
    ok(/DOWN since/.test(await p.$eval('#avnow', (e) => e.textContent)) && await p.$eval('#avnow', (e) => e.className.includes('down')), 'outage shown as DOWN since');
    MODE = 'refused'; await p.reload(); await p.waitForSelector('#repl table');
    ok(!(await p.$eval('#repwarn', (e) => e.hidden)) && /DQS key/.test(await p.$eval('#repwarn', (e) => e.textContent)), 'all-refused warning names the DQS key');
    MODE = 'missing'; await p.reload(); await p.waitForFunction(() => /not installed/.test(document.getElementById('repl').innerText) && /not installed/.test(document.getElementById('rtsvg').innerText) && /not installed/.test(document.getElementById('avwin').innerText));
    ok(true, 'not installed message');
    ok(errs.length === 0, 'no page errors: ' + errs.join(' | '));
  } finally { await browser.close(); srv.close(); }
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks');
  process.exit(bad ? 1 : 0);
})();
