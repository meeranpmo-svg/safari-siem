// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const ZYB_ORG = require('../../brand/index');
// Email Route Map (email-route-map.html), stubbed SIEM + IT Asset Management, SYNTHETIC data: topology drawn from the
// Python route rules (DNS at Cloudflare, two Internet links, MX hosts, gateway, Exchange, Exchange Online hybrid, egress
// IPs), the blocked hop and the line into it in red, click-through detail with fixes, Check now (operator refused),
// escaping, not installed / nothing connected.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node email-route-map.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const DASH = path.resolve(__dirname, '../../ui');
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const ADDR = { read: false }; const POSTS = []; let MODE = 'ok', ROLE = 'analyst'; const DNS = { connected: false, changes: [] };
const XSS = '<img src=x onerror=alert(1)>';
const ROUTE = { siem: true, checked_at: '2026-10-26T08:00:00Z', profile: { platform: 'hybrid', isp_links: 2, expected_mx: [], servers: [{ name: 'GW01', role: 'gateway', dns_name: 'gw1.corpgroup.test', private_ip: '10.1.2.5', public_ips: ['198.51.100.5'] }, { name: 'EX01', role: 'exchange', dns_name: null, private_ip: '10.1.3.10', public_ips: ['203.0.113.9'] }] }, note: 'Inbound and outbound route hop by hop.',
  issues: [
    { severity: 'critical', hop: 'mx', title: 'corpgroup.test: MX host mx2.corpgroup.test resolves to a Cloudflare proxy address - SMTP is not carried by the proxy', evidence: ['104.16.0.10'], fix: ['Set the A record of mx2.corpgroup.test to "DNS only" (grey cloud)'] },
    { severity: 'high', hop: 'mx', title: 'Two Internet links but every MX address is on one of them - a failure of that link stops inbound mail', evidence: ['198.51.100.0/24'], fix: ['Publish a second MX on the second ISP'] },
    { severity: 'high', hop: 'egress', title: '203.0.113.9 has no reverse DNS (PTR) ' + XSS, evidence: ['PTR lookup: none'], fix: ['Ask the ISP to set the PTR'] },
    { severity: 'high', hop: 'egress', title: '203.0.113.9 is not authorised by the SPF record of corpgroup.test', evidence: ['SPF evaluation'], fix: ['Add ip4:203.0.113.9'] },
    { severity: 'high', hop: 'auth', title: 'corpgroup.test: SPF does not include Microsoft 365 (include:spf.protection.outlook.com)', evidence: ['v=spf1 -all'], fix: ['Add include:spf.protection.outlook.com'] },
    { severity: 'critical', hop: 'exchange_in', title: 'No mail through Exchange receive in the last hour', evidence: [], fix: ['Check the Exchange transport services are running'] }],
  lanes: { inbound: [{ id: 'internet_in', label: 'Internet senders', state: 'info' }, { id: 'gateway_in', label: 'Email gateway (inbound)', state: 'ok', counts: { delivered: 800 } }, { id: 'exchange_in', label: 'Exchange - receive', state: 'down', counts: { receive: 700 } }, { id: 'mailbox', label: 'Mailbox - deliver', state: 'ok', counts: { deliver: 690 } }],
    outbound: [{ id: 'mailbox_out', label: 'Mailbox - submit', state: 'ok', counts: { submit: 300 } }, { id: 'exchange_out', label: 'Exchange - send', state: 'ok', counts: { send: 290 } }, { id: 'gateway_out', label: 'Email gateway (outbound)', state: 'ok', counts: {} }, { id: 'internet_out', label: 'Internet receivers', state: 'info' }] },
  blocked: { inbound: { hop: 'exchange_in', label: 'Exchange - receive', state: 'down', reason: 'No mail through Exchange receive in the last hour', fix: ['Check the Exchange transport services are running'] } },
  topology: { platform: 'hybrid', exo: true, declared_links: 2, note: 'Internet links are told apart by public network (/24).',
    dns: { provider: 'Cloudflare', ns: ['ada.ns.cloudflare.com'] },
    mx: [{ host: 'mx1.corpgroup.test', priority: 10, ips: ['198.51.100.5'], links: [0], proxied: false, cf_routing: false, eop: false, probed: true, connected: true, starttls: true },
      { host: 'mx2.corpgroup.test', priority: 20, ips: ['104.16.0.10'], links: [1], proxied: true, cf_routing: false, eop: false, probed: true, connected: false, starttls: null }],
    egress: [{ ip: '203.0.113.9', ptr: null, link: 2 }], domains: ['corpgroup.test'],
    servers: [{ name: 'GW01', role: 'gateway', dns_name: 'gw1.corpgroup.test', private_ip: '10.1.2.5', public_ips: ['198.51.100.5'], mx: ['mx1.corpgroup.test'], egress: [], dns_ips: ['198.51.100.5'], notes: [] },
      { name: 'EX01', role: 'exchange', dns_name: null, private_ip: '10.1.3.10', public_ips: ['203.0.113.9'], mx: [], egress: ['203.0.113.9'], dns_ips: null, notes: ['not reached by any MX record ' + XSS] }],
    rdns: [{ ip: '198.51.100.5', role: 'inbound (MX)', link: 1, ptr: '5-100-51-198.dsl.isp.example', fcrdns: true, expected: 'gw1.corpgroup.test', server: 'GW01', ok: false },
      { ip: '203.0.113.9', role: 'outbound', link: 3, ptr: null, fcrdns: false, expected: 'mail.corpgroup.test', server: 'EX01', ok: false }],
    links: [{ n: 1, network: '198.51.100.0/24', mx: ['mx1.corpgroup.test'], egress: [], state: 'inbound', rdns: [{ ip: '198.51.100.5', role: 'inbound (MX)', link: 1, ptr: '5-100-51-198.dsl.isp.example', fcrdns: true, expected: 'gw1.corpgroup.test', server: 'GW01', ok: false }], ptr_request: ['Please set the reverse DNS (PTR) of 198.51.100.5 to gw1.corpgroup.test ' + XSS] }, { n: 2, network: '104.16.0.0/24', mx: ['mx2.corpgroup.test'], egress: [], state: 'inbound' }, { n: 3, network: '203.0.113.0/24', mx: [], egress: ['203.0.113.9'], state: 'outbound' }],
    states: { mx: 'bad', smtp: 'bad', gateway_in: 'ok', exchange_in: 'down', mailbox: 'ok', mailbox_out: 'ok', exchange_out: 'ok', gateway_out: 'ok', egress: 'bad', auth: 'bad' } } };
const ALERTS = { open: [{ id: 'MA-1', severity: 'high', source: 'route', title: 'SMTP certificate of mx1.corpgroup.test expires in 9 days', detail: 'issuer Synthetic CA', fix: ['Renew the certificate'], first_seen: Date.parse('2026-10-26T06:00:00Z') },
  { id: 'MA-2', severity: 'high', source: 'exchange', title: 'Mail queue EX01\\Submission: 150 messages ' + XSS, detail: 'EX01', fix: ['Check the next hop'], first_seen: Date.parse('2026-10-26T07:00:00Z') }],
  cleared: [{ id: 'MA-3', title: 'MX records of corpgroup.test changed since the last check', first_seen: Date.parse('2026-10-20T06:00:00Z'), cleared_at: Date.parse('2026-10-21T06:00:00Z') }],
  state: { at: Date.parse('2026-10-26T08:00:00Z'), gaps: [], mail: { ok: true, at: Date.parse('2026-10-26T07:00:00Z'), count: 2 } } };
let RCPT = ['mail.admin@corpgroup.test'];
let ESGS = { configured: true, base_url: 'https://esg.corpgroup.test', username: 'zyb-api', switch_user: 'readonly@corpgroup.test', password_set: true, endpoints: { status: '/api/v2/system/status', queue: '/api/v2/queue' }, catalogue: [1, 2, 3, 4, 5], last_test: { at: Date.parse('2026-10-26T07:50:00Z'), ok: true } };
(async () => {
  const srv = http.createServer((req, res) => {
    const u = decodeURIComponent(req.url.split('?')[0]), json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    const body = (fn) => { let b = ''; req.on('data', (c) => { b += c; }); req.on('end', () => { const j = JSON.parse(b || '{}'); POSTS.push([u, j]); fn(j); }); };
    if (u === '/dashboards/whoami.json' || u === '/auth/whoami') return json(200, { user: 'syed', role: ROLE });
    if (MODE === 'none' && u.startsWith('/api/')) return json(404, { error: 'not found' });
    if (u === '/api/itam/mail-route') return body(() => json(200, ROUTE));
    if (u === '/api/itam/mail-route/alerts') return json(200, ALERTS);
    if (u === '/api/itam/mail-route/alerts/check') return body(() => json(403, { error: 'requires role operator' }));
    const can = (r) => (r === 'admin' ? ROLE === 'admin' : ROLE === 'admin' || ROLE === 'operator');
    if (u === '/api/itam/dns-fix' && req.method === 'GET') return json(200, DNS);
    if (u === '/api/itam/dns-fix/spf') return body((b) => { if (!can('operator')) return json(403, { error: 'requires role operator' }); if (!DNS.connected) return json(424, { error: 'Cloudflare is not connected' }); const c = { id: 'DNS-000' + (DNS.changes.length + 1), domain: b.domain, before: 'v=spf1 -all', after: 'v=spf1 ip4:' + b.add[0] + ' -all', status: 'pending', requested_by: 'syed', reason: b.reason }; DNS.changes.unshift(c); json(200, c); });
    if (u === '/api/itam/dns-fix/token') return body((b) => { if (!can('admin')) return json(403, { error: 'requires role admin' }); DNS.connected = !b.clear; json(200, { connected: DNS.connected }); });
    if (/^\/api\/itam\/dns-fix\/DNS-\d+\/approve$/.test(u)) return body(() => { if (!can('admin')) return json(403, { error: 'requires role admin' }); const c = DNS.changes.find((x) => u.includes(x.id)); c.status = 'applied'; c.approved_by = 'omar.syn'; json(200, c); });
    if (u === '/api/itam/mail-reputation' && req.method === 'GET') return json(200, { registered: [{ id: 'MIP-001', ip: '203.0.113.9', label: 'EX01 outbound', role: 'outbound' }] });
    if (/^\/api\/itam\/mail-reputation\/ips\/MIP-\d+\/replace$/.test(u)) return body((b) => { if (!can('operator')) return json(403, { error: "requires role operator" }); json(200, { id: "MIP-002", ip: b.ip }); });
    if (u === '/api/itam/mail-reputation/ips') return body((b) => (can('operator') ? json(200, { id: 'MIP-001', ip: b.ip }) : json(403, { error: 'requires role operator' })));
    if (u === '/api/itam/esg/config') return body(() => (can('admin') ? json(200, { configured: true }) : json(403, { error: 'requires role admin' })));
    if (u === '/api/soc/onboard/sources' && req.method === 'POST') return body(() => (can('admin') ? json(200, { ok: true, siem: { ip: ZYB_ORG.platform_addr, syslog_port: 5514, tls_port: 6514, host: 'soc.example.test' } }) : json(403, { error: 'requires role admin' })));
    if (u === '/api/itam/mail-reputation/check' && can('operator')) return body(() => json(200, { ok: true }));
    if (u === '/api/itam/mail-route/troubleshoot' && req.method === 'GET') return json(200, { last: null });
    if (u === '/api/itam/mail-route/troubleshoot' || u === '/api/itam/mail-route/troubleshoot/action') return body((b) => { if (!can('operator')) return json(403, { error: 'requires role operator' }); if (b && b.action) POSTS.push([u, b]);
      json(200, { at: '2026-10-29T10:00:00Z', by: 'nora.syn', ok: false, counts: { fail: 1, warn: 1, fixed: 1 }, note: 'Read-only by itself (synthetic).', steps: [
        { id: 'mx:corpgroup.test', title: 'MX record - corpgroup.test', status: 'fixed', detail: 'The platform had reported no MX. Public DNS has it: 10 esg.corpgroup.test', evidence: ['Cloudflare 1.1.1.1: 1 MX', "This server's DNS answers with NO record " + XSS], fix: 'Nothing to change at the DNS provider.', actions: [] },
        { id: 'egress', title: 'Egress IP (where mail leaves from)', status: 'warn', detail: 'None registered.', evidence: ['203.0.113.25 - in the SPF record of corpgroup.test'], fix: 'Register the public IP the gateway sends from.', actions: [{ action: 'register-egress', label: 'Register 203.0.113.25', role: 'operator', ip: '203.0.113.25' }] },
        { id: 'gateway', title: 'Libraesva ESG', status: 'fail', detail: 'Stopped at "Login": refused', fix: 'Use the ESG API user', actions: [] }] }); });
    if (u === '/api/itam/esg/test' && can('operator')) return body(() => json(200, { last_test: { ok: true }, catalogue: [1, 2] }));
    if (u === '/api/itam/esg/diagnose' && can('operator')) return body(() => json(200, { ok: false, steps: [{ step: 'HTTPS and certificate', status: 'ok', detail: 'TLS 1.2', fix: '' }, { step: 'Login', status: 'fail', detail: 'login refused by the gateway (HTTP 401) ' + XSS, fix: 'Use the ESG API user, not the GUI user' }] }));
    if (u === '/api/itam/mail-route/profile') return body((b) => json(200, { servers: b.servers }));
    // EX02 has two NICs: the second address only appears once the servers were asked (refresh) - never guessed before
    if (u === '/api/soc/sysadmin/addresses/refresh') return body(() => { if (!can('operator')) return json(403, { error: 'requires role operator' }); ADDR.read = true; json(200, { items: [{ id: 'S1', name: 'EX01', status: 'no-login' }, { id: 'S2', name: 'EX02', status: 'ok', addresses: ['10.1.3.11', '10.99.0.11'] }] }); });
    if (u === '/api/soc/sysadmin/targets') return json(200, { items: [{ id: 'S1', name: 'EX01', ip: '10.1.3.10', findings: 1, worst: 'high', last_check: Date.parse('2026-10-26T07:45:00Z'), addresses: null }, { id: 'S2', name: 'EX02', ip: '10.1.3.11', findings: 0, worst: null, last_check: null,
      addresses: ADDR.read ? { at: Date.parse('2026-10-26T08:00:00Z'), items: [{ ip: '10.1.3.11', interface: 'MAPI', prefix: 24 }, { ip: '10.99.0.11', interface: 'Replication <b>' + XSS + '</b>', prefix: 24 }] } : null }] });
    if (u === '/api/soc/mail/notify' && req.method === 'GET') return json(200, { recipients: RCPT, problems: [], recent: [] });
    if (u === '/api/soc/mail/notify' && req.method === 'POST') return body((b) => { RCPT = b.recipients; json(200, { recipients: RCPT }); });
    if (u === '/api/soc/mail/notify/test') return body(() => json(200, { ok: true, recipients: RCPT.length }));
    if (u === '/api/itam/esg') return json(200, ESGS);
    if (u === '/api/itam/esg/read/status') return json(200, { rows: [{ version: '5.6.2-SYN', cluster: '2 nodes', health: 'ok' }], total: 1 });
    if (u === '/api/itam/esg/read/queue') return json(200, { rows: [{ id: 'q1', to: 'user@corpgroup.test', reason: 'deferred ' + XSS }], total: 12 });
    if (u === '/api/itam/esg/test' || u === '/api/itam/esg/diagnose') return body(() => json(403, { error: 'requires role operator' }));
    if (u === '/api/itam/mail-reputation/check') return body(() => json(403, { error: 'requires role operator' }));
    if (u === '/api/soc/top') return body((b) => json(200, { values: b.field === 'fields.email_action' ? [{ v: 'delivered', n: 800 }] : b.field === 'action' ? [{ v: 'receive', n: 700 }] : [] }));
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
    await p.goto(base + '/dashboards/email-route-map.html?standalone=1'); await p.waitForSelector('#svg svg g[data-node]');
    const ids = await p.$$eval('#svg g[data-node]', (g) => g.map((x) => x.getAttribute('data-node')));
    for (const id of ['inet', 'dns', 'auth', 'link0', 'link1', 'link2', 'mx0', 'mx1', 'gwi', 'exi', 'mbi', 'mbo', 'exo', 'gwo', 'eg0', 'eol']) ok(ids.includes(id), 'node drawn: ' + id);
    const svgText = await p.textContent('#svg svg');
    ok(/DNS - MX/.test(svgText) && /hosted: Cloudflare/.test(svgText), 'DNS box names Cloudflare');
    ok(/Internet link 1/.test(svgText) && /Internet link 2/.test(svgText), 'one box per Internet link');
    ok(/Exchange Online/.test(svgText) && /hybrid connectors/.test(svgText), 'Exchange Online drawn with the hybrid connectors');
    const stroke = (id) => p.$eval('#svg g[data-node="' + id + '"] rect', (r) => r.getAttribute('stroke'));
    ok(await stroke('exi') === '#ff2d55', 'Exchange receive DOWN in red');
    ok(await stroke('mx1') === '#f85149', 'Cloudflare-proxied MX host failing');
    ok(await stroke('mx0') === '#3fb950', 'healthy MX host green');
    ok(await stroke('eg0') === '#f85149', 'egress without PTR failing');
    ok(await stroke('eol') === '#f85149', 'Exchange Online flagged by the SPF / Microsoft 365 issue');
    ok((await p.$$eval('#svg text', (t) => t.filter((x) => x.textContent === '✕').length)) >= 2, 'broken lines carry a cross');
    ok(/Receiving mail is stopped at: Exchange - receive/.test(await p.textContent('#banner')), 'banner names the blocked hop');
    ok(/Check the Exchange transport services/.test(await p.textContent('#banner')), 'banner gives the fix');
    await p.click('#svg g[data-node="mx1"]');
    let d = await p.textContent('#detail');
    ok(/mx2\.corpgroup\.test/.test(d) && /Cloudflare proxy/.test(d) && /DNS only/.test(d), 'MX detail: what is wrong and how to fix');
    await p.click('#svg g[data-node="link1"]');
    ok(/Carries: inbound/.test(await p.textContent('#detail')), 'link detail says what it carries');
    await p.focus('#svg g[data-node="auth"]'); await p.keyboard.press('Enter');
    ok(/spf\.protection\.outlook\.com/.test(await p.textContent('#detail')), 'keyboard opens the SPF detail');
    const f = await p.textContent('#facts');
    ok(/Hybrid/.test(f) && /2 declared/.test(f) && /mx1\.corpgroup\.test/.test(f), 'facts card');
    ok((await p.$$('#issues tbody tr')).length === 6, 'issues table');
    ok(!(await p.$('#issues img')) && /onerror/.test(await p.textContent('#issues')), 'issue text escaped');
    // NAT target and sender on the map
    ok(/198\.51\.100\.5 → GW01 10\.1\.2\.5/.test(svgText), 'MX box shows the NAT target and its internal IP');
    ok(/from EX01/.test(svgText), 'egress box names the sending server');
    ok(await p.textContent('#svg g[data-node="eg0"]').then((t) => /not in SPF/.test(t) && /no reverse DNS/.test(t)), 'the egress box names what is wrong (SPF, reverse DNS) instead of only the PTR');
    // reverse DNS per link with the ISP request
    const rd = await p.textContent('#rdns');
    ok(/Internet link 1/.test(rd) && /5-100-51-198\.dsl\.isp\.example/.test(rd) && /gw1\.corpgroup\.test/.test(rd) && /ask the ISP/.test(rd), 'reverse DNS rows');
    ok(/Request to send this ISP/.test(rd) && /Please set the reverse DNS \(PTR\) of 198\.51\.100\.5 to gw1\.corpgroup\.test/.test(rd) && !(await p.$('#rdns img')), 'ISP request text, escaped');
    ok((await stroke('link0')) === '#d29922', 'a link with a wrong PTR is amber');
    // mail servers
    await p.waitForSelector('#srv table');
    const srvT = await p.textContent('#srv');
    ok(/GW01/.test(srvT) && /gw1\.corpgroup\.test/.test(srvT) && /10\.1\.2\.5/.test(srvT) && /198\.51\.100\.5/.test(srvT), 'register row: DNS name, internal and public IPs');
    ok(/PTR 5-100-51-198\.dsl\.isp\.example - should be gw1\.corpgroup\.test/.test(srvT) && /PTR none - should be mail\.corpgroup\.test/.test(srvT), 'PTR per public IP in the servers table');
    ok(/EX01/.test(srvT) && /1 finding/.test(srvT), 'Exchange health from the SIEM joined by name');
    ok(/EX02/.test(srvT) && /not in the register/.test(srvT) && /not checked yet/.test(srvT), 'SIEM Exchange server missing from the register is shown, never-checked is not healthy');
    ok(!(await p.$('#srv img')), 'server notes escaped');
    await p.click('#srvedit summary'); await p.click('#srvadd');
    const rows = await p.$$('#srvrows tr'); ok(rows.length === 3, 'editor rows: 2 recorded + 1 new');
    await rows[2].$eval('[name=name]', (i) => { i.value = 'EDGE01'; }); await rows[2].$eval('[name=public_ips]', (i) => { i.value = '192.0.2.40, 192.0.2.41'; });
    await p.click('#srvf button[type=submit]'); await p.waitForFunction(() => /Saved/.test(document.getElementById('srvmsg').textContent));
    const sv = POSTS.filter((x) => x[0] === '/api/itam/mail-route/profile').pop();
    ok(sv && sv[1].servers.length === 3 && sv[1].servers[2].name === 'EDGE01' && sv[1].servers[2].public_ips[1] === '192.0.2.41' && sv[1].servers[0].private_ip === '10.1.2.5', 'register saved with every field');
    // early warnings
    const wt = await p.textContent('#warn');
    ok(/HIGH · SMTP certificate of mx1\.corpgroup\.test expires in 9 days/.test(wt) && /Renew the certificate/.test(wt), 'warning with fix');
    ok(/Mail queue/.test(wt) && !(await p.$('#warn img')), 'Exchange warning, escaped');
    ok(/last mail/.test(await p.textContent('#warnst')), 'last alert mail shown');
    ok(/MX records of corpgroup\.test changed/.test(await p.$eval('#warncl', (e) => e.textContent)), 'cleared history');
    await p.click('#evalnow'); await p.waitForFunction(() => /operator role/.test(document.getElementById('warnst').textContent));
    ok(true, 'Evaluate now refused for a viewer');
    // recipients
    ok((await p.inputValue('#rcpt')) === 'mail.admin@corpgroup.test', 'recipients loaded from the SIEM');
    await p.fill('#rcpt', 'mail.admin@corpgroup.test; exchange.team@corpgroup.test'); await p.click('#rcptf button[type=submit]');
    await p.waitForFunction(() => /2 recipient/.test(document.getElementById('rcptst').textContent));
    ok(POSTS.some((x) => x[0] === '/api/soc/mail/notify' && x[1].recipients.length === 2), 'recipients saved');
    await p.click('#rcpttest'); await p.waitForFunction(() => /Test sent to 2/.test(document.getElementById('rcptst').textContent)); ok(true, 'test mail');
    await p.click('#chk'); await p.waitForFunction(() => /operator role/.test(document.getElementById('banner').textContent));
    ok(true, 'Check now refused for a viewer with a readable message');
    const sb = POSTS.find((x) => x[0] === '/api/itam/mail-route'); ok(sb && sb[1].siem && sb[1].siem.gateway_in, 'SIEM counts sent with the route request');
    ok(!alerted && errs.length === 0, 'no script ran, no page error: ' + errs.join(' | '));
    // the email gateway: Libraesva ESG in the route and its own card
    ok(/Libraesva ESG/.test(await p.textContent('#svg g[data-node="gwi"]')), 'gateway hop named after Libraesva when it is connected');
    await p.click('#svg g[data-node="gwi"]'); ok(/Libraesva ESG https:\/\/esg\.corpgroup\.test: API connected/.test(await p.textContent('#detail')), 'gateway detail: API connection state');
    await p.waitForFunction(() => /5\.6\.2-SYN/.test(document.getElementById('esg').textContent) && /12 rows/.test(document.getElementById('esg').textContent));
    const eg = await p.textContent('#esg'); ok(/connected/.test(eg) && /acting as readonly@corpgroup\.test/.test(eg) && /mapped: status, queue/.test(eg), 'Libraesva card: connection, status, queue: ' + eg.slice(0, 200));
    ok(!(await p.$('#esg img')), 'queue values are text, never HTML');
    // the API connected but no gateway mail log in the SIEM: the boxes say so (in use, not grey "not connected") and the detail gives the syslog setting
    { const st = ROUTE.topology.states, keep = [st.gateway_in, st.gateway_out], lanes = [].concat(ROUTE.lanes.inbound || [], ROUTE.lanes.outbound || []).filter((l) => /^gateway_/.test(l.id)), kc = lanes.map((l) => l.counts); delete st.gateway_in; delete st.gateway_out; lanes.forEach((l) => { delete l.counts; });
      await p.reload(); await p.waitForSelector('#svg g[data-node="gwi"]'); await p.waitForFunction(() => /no mail log/.test(document.querySelector('#svg g[data-node="gwi"]').textContent), null, { timeout: 15000 }).catch(() => {});
      const gt = await p.textContent('#svg g[data-node="gwi"]'); ok(/API ok · no mail log/.test(gt) && !/not connected/.test(gt), 'API connected, no mail log: said on the box: ' + gt);
      await p.click('#svg g[data-node="gwi"]'); ok(/Remote syslog/.test(await p.textContent('#detail')) && /514/.test(await p.textContent('#detail')), 'the detail gives the syslog setting');
      st.gateway_in = keep[0]; st.gateway_out = keep[1]; lanes.forEach((l, i) => { l.counts = kc[i]; }); await p.reload(); await p.waitForSelector('#svg g[data-node="gwi"]'); }
    ok(await p.$('#esgcard a[href="connections.html#cn-esg"]') && await p.$('#esgcard a[href="libraesva.html"]'), 'links to configure (Connections & Setup) and manage (Libraesva page)');
    // the troubleshooter: steps with status, evidence and fix; a proposed action is sent as such; hostile text stays text
    { const was = ROLE; ROLE = 'operator'; await p.click('#doc');
      await p.waitForFunction(() => /fixed by the troubleshooter/.test(document.getElementById('docout').textContent), null, { timeout: 8000 }).then(() => ok(true, 'troubleshooter ran'), () => ok(false, 'troubleshooter ran'));
      const dt = await p.textContent('#docout'); ok(/1 failing step/.test(dt) && /What to do: Nothing to change at the DNS provider/.test(dt) && /Stopped at "Login"/.test(dt) && !(await p.$('#docout img')), 'steps, fixes, evidence as text: ' + dt.slice(0, 200));
      await p.click('#docout [data-dact="register-egress"]');
      await p.waitForFunction(() => true); await new Promise((r) => setTimeout(r, 500));
      ok(POSTS.some((x) => x[0] === '/api/itam/mail-route/troubleshoot/action' && x[1].action === 'register-egress' && x[1].ip === '203.0.113.25'), 'the proposed egress action is sent with its IP');
      ROLE = was; }
    await p.click('#esgtest'); await p.waitForFunction(() => /operator role/.test(document.getElementById('esgmsg').textContent)); ok(true, 'test refused for a viewer, readable');
    // bug fix: the card said "Test failed:" with no reason - it now runs the step-by-step check and names the failing step and its fix
    { const was = ROLE; ROLE = 'operator'; await p.click('#esgtest');
      await p.waitForFunction(() => /Stopped at "Login"/.test(document.getElementById('esgmsg').textContent), null, { timeout: 8000 }).then(() => ok(true, 'test names the failing step'), () => ok(false, 'test names the failing step: ' + 'x'));
      const em = await p.textContent('#esgmsg'); ok(/HTTP 401/.test(em) && /Fix: Use the ESG API user/.test(em) && !(await p.$('#esgmsg img')), 'reason and fix shown, as text: ' + em);
      ROLE = was; }
    ESGS = { configured: false, endpoints: {}, catalogue: [] }; await p.reload(); await p.waitForFunction(() => /not connected/.test(document.getElementById('esg').textContent));
    ok(/Connections &? ?Setup/.test(await p.textContent('#esg')) && /Email gateway/.test(await p.textContent('#svg g[data-node="gwi"]')), 'not connected: says where to configure; hop keeps its generic name');
    // ---- set up from the box. A viewer sees who sets it up, no form
    ESGS = { configured: true, base_url: 'https://esg.corpgroup.test', username: 'zyb-api', switch_user: 'readonly@corpgroup.test', endpoints: {}, catalogue: [], last_test: null };
    await p.reload(); await p.waitForSelector('#svg svg g[data-node]');
    await p.click('#svg g[data-node="dns"]'); ok(/Set up by an operator or administrator/.test(await p.textContent('#detail')) && !(await p.$('#detail form[data-setup] input')), 'viewer: who sets it up, no inputs');
    // operator: the route register and IPs; the gateway credentials stay with an administrator
    ROLE = 'operator'; await p.reload(); await p.waitForSelector('#svg svg g[data-node]');
    await p.click('#svg g[data-node="dns"]'); await p.fill('#detail [name="expected_mx"]', 'mx1.corpgroup.test, mx2.corpgroup.test');
    POSTS.length = 0; await p.click('#detail form[data-setup="mx"] button[type="submit"]');
    await p.waitForFunction(() => /Saved and checked/.test(document.getElementById('detail').textContent));
    const pr = POSTS.find((x) => x[0] === '/api/itam/mail-route/profile');
    ok(pr && pr[1].expected_mx.join(',') === 'mx1.corpgroup.test,mx2.corpgroup.test' && pr[1].servers.length === 2 && pr[1].servers[0].name === 'GW01', 'expected MX saved, the server register kept');
    ok(POSTS.some((x) => x[0] === '/api/itam/mail-reputation/check'), 'and checked at once');
    await p.click('#svg g[data-node="exi"]'); await p.fill('#detail [name="name"]', 'EX02'); await p.fill('#detail [name="private_ip"]', '10.1.3.11'); await p.fill('#detail [name="dns_name"]', 'ex02.corpgroup.test');
    POSTS.length = 0; await p.click('#detail form[data-setup="exch"] button[type="submit"]');
    await p.waitForFunction(() => /Added - DNS names/.test(document.getElementById('detail').textContent));
    const ex = POSTS.find((x) => x[0] === '/api/itam/mail-route/profile')[1].servers;
    ok(ex.length === 3 && ex[2].name === 'EX02' && ex[2].role === 'exchange' && ex[2].private_ip === '10.1.3.11', 'Exchange server added to the register from the box');
    await p.click('#svg g[data-node="exi"]'); await p.fill('#detail [name="name"]', 'ex01'); await p.click('#detail form[data-setup="exch"] button[type="submit"]');
    await p.waitForFunction(() => /already in the register/.test(document.getElementById('detail').textContent)); ok(true, 'a duplicate server is refused on the page');
    // change the registered egress address in one step (old retired with a reason, new one checked)
    await p.click('#svg g[data-node="eg0"]'); ok(/Set up: change 203\.0\.113\.9/.test(await p.textContent('#detail')), 'the egress box offers to change its address');
    await p.fill('#detail form[data-setup="egchange"] [name="ip"]', '203.0.113.50'); await p.fill('#detail form[data-setup="egchange"] [name="reason"]', 'wrong NAT address registered');
    POSTS.length = 0; await p.click('#detail form[data-setup="egchange"] button[type="submit"]');
    await p.waitForFunction(() => /Changed and checked/.test(document.getElementById('detail').textContent));
    ok(POSTS.some((x) => x[0] === '/api/itam/mail-reputation/ips/MIP-001/replace' && x[1].ip === '203.0.113.50' && /wrong NAT/.test(x[1].reason)) && POSTS.some((x) => x[0] === '/api/itam/mail-reputation/check'), 'the change is sent with the registered id and checked at once');
    ok(POSTS.some((x) => x[0] === '/api/itam/dns-fix/spf' && x[1].domain === 'corpgroup.test' && x[1].add[0] === '203.0.113.50' && x[1].remove[0] === '203.0.113.9'), 'changing the IP also proposes the SPF change (old out, new in)');
    ok(/Cloudflare is not connected/.test(await p.textContent('#detail')), 'not connected is said where the change was made');
    // Fix SPF from the box: needs Cloudflare (an administrator connects it)
    await p.click('#svg g[data-node="eg0"]'); ok(await p.isVisible('#detail form[data-setup="spffix"]') && /not connected yet/.test(await p.textContent('#detail form[data-setup="spffix"]')), 'the box offers "fix SPF" and says Cloudflare is not connected');
    ok(/Cloudflare not connected/.test(await p.textContent('#dnsfix')) && !(await p.$('#cftok')), 'operator: no token form');
    await p.click('#svg g[data-node="eg0"]'); await p.fill('#detail form[data-setup="egress"] [name="ip"]', '203.0.113.30'); await p.fill('#detail form[data-setup="egress"] [name="label"]', 'Libraesva outbound - ISP 2');
    POSTS.length = 0; await p.click('#detail form[data-setup="egress"] button[type="submit"]');
    await p.waitForFunction(() => /Added and checked/.test(document.getElementById('detail').textContent));
    ok(POSTS.some((x) => x[0] === '/api/itam/mail-reputation/ips' && x[1].ip === '203.0.113.30' && x[1].role === 'outbound'), 'egress IP registered from its box');
    await p.click('#svg g[data-node="gwi"]'); ok(/Set up by an administrator/.test(await p.textContent('#detail')) && !(await p.$('#detail form[data-setup="esg"] input')), 'operator: gateway credentials are for an administrator');
    // administrator: connect the gateway API and register the syslog sender from the gateway box
    ROLE = 'admin'; await p.reload(); await p.waitForSelector('#svg svg g[data-node]');
    await p.waitForSelector('#cftok'); await p.fill('#cftok [name="token"]', 'cfTOKENsynthetic0123456789abcdefABCDEF'); await p.click('#cftok button[type="submit"]');
    ok(await p.waitForFunction(() => /Cloudflare connected/.test(document.getElementById('dnsfix').textContent)).then(() => true, () => false), 'administrator connects Cloudflare');
    await p.click('#svg g[data-node="eg0"]'); await p.fill('#detail form[data-setup="spffix"] [name="reason"]', 'outbound IP missing from SPF');
    POSTS.length = 0; await p.click('#detail form[data-setup="spffix"] button[type="submit"]');
    ok(await p.waitForFunction(() => /waiting for a different administrator/.test(document.getElementById('detail').textContent)).then(() => true, () => false), 'SPF fix proposed from the box');
    ok(POSTS.some((x) => x[0] === '/api/itam/dns-fix/spf' && x[1].add[0] === '203.0.113.9' && x[1].domain === 'corpgroup.test'), 'proposal carries the box IP and domain');
    ok(await p.waitForFunction(() => /waiting for an administrator other than syed/.test(document.getElementById('dnsfix').textContent)).then(() => true, () => false) && !(await p.$('[data-dns="approve"]')), 'the proposer is not offered Approve (four-eyes)');
    DNS.changes[0].requested_by = 'nora.syn'; await p.reload(); await p.waitForSelector('[data-dns="approve"]');
    await p.click('[data-dns="approve"]'); ok(await p.waitForFunction(() => /applied/.test(document.getElementById('dnsfix').textContent)).then(() => true, () => false), 'another administrator approves and it is applied');

    await p.click('#svg g[data-node="gwi"]');
    ok(await p.inputValue('#detail form[data-setup="esg"] [name="base_url"]') === 'https://esg.corpgroup.test' && await p.inputValue('#detail [name="password"]') === '', 'current address shown, the password never');
    await p.fill('#detail [name="password"]', 'Syn-Esg-Pass-1'); POSTS.length = 0; await p.click('#detail form[data-setup="esg"] button[type="submit"]');
    await p.waitForFunction(() => /Connected - 2 endpoints/.test(document.getElementById('detail').textContent));
    const ec = POSTS.find((x) => x[0] === '/api/itam/esg/config');
    ok(ec && ec[1].password === 'Syn-Esg-Pass-1' && ec[1].username === 'zyb-api' && POSTS.some((x) => x[0] === '/api/itam/esg/test'), 'saved then tested');
    ok(await p.inputValue('#detail [name="password"]') === '', 'the password field is cleared after saving');
    await p.fill('#detail form[data-setup="esglog"] [name="id"]', 'hq'); await p.fill('#detail form[data-setup="esglog"] [name="match_ip"]', '10.100.20.25');
    POSTS.length = 0; await p.click('#detail form[data-setup="esglog"] button[type="submit"]');
    await p.waitForFunction(() => /Registered esg-hq/.test(document.getElementById('detail').textContent));
    const sl = POSTS.find((x) => x[0] === '/api/soc/onboard/sources');
    ok(sl && sl[1].id === 'esg-hq' && sl[1].kind === 'email-security-gateway' && sl[1].match_ip === '10.100.20.25', 'syslog sender registered on the SIEM');
    ok(new RegExp(ZYB_ORG.platform_addr_re + ' port 5514 TCP').test(await p.textContent('#detail')), 'tells what to enter on the gateway');
    await p.click('#svg g[data-node="eol"]'); await p.selectOption('#detail [name="platform"]', 'online'); POSTS.length = 0;
    await p.click('#detail form[data-setup="platform"] button[type="submit"]'); await p.waitForFunction(() => /Saved\./.test(document.getElementById('detail').textContent));
    ok(POSTS.find((x) => x[0] === '/api/itam/mail-route/profile')[1].platform === 'online', 'platform set from the Exchange Online box');
    ok(!alerted && !errs.length, 'no dialog, no page error: ' + errs.join(' | '));
    // every IP of a mail server: not read yet → said; an operator asks every server; a second NIC appears; no-login is named
    ROLE = 'operator'; await p.reload(); await p.waitForSelector('#srv table');
    ok(/other addresses not read yet/.test(await p.textContent('#srv')) && await p.isVisible('#srvaddr'), 'before reading: says the other addresses are not read yet; operator has the button');
    await p.click('#srvaddr'); await p.waitForFunction(() => /10\.99\.0\.11/.test(document.getElementById('srv').textContent));
    { const t = await p.textContent('#srv'); ok(/10\.1\.3\.11\/24/.test(t) && /10\.99\.0\.11\/24/.test(t) && /managed by/.test(t), 'hqmail-style second NIC shown with its interface'); }
    ok(/1 of 2 server\(s\) read/.test(await p.textContent('#srvaddrmsg')) && /no login for EX01/.test(await p.textContent('#srvaddrmsg')), 'result names the server with no login');
    ok(!(await p.$('#srv b img')) && !(await p.evaluate(() => window.__xss)), 'interface names stay text');
    ROLE = 'analyst'; await p.reload(); await p.waitForSelector('#srv table'); ok(!(await p.isVisible('#srvaddr')), 'a viewer / analyst has no fetch button');
    MODE = 'none'; await p.reload(); await p.waitForFunction(() => /not installed/.test(document.getElementById('svg').textContent));
    ok(true, 'not installed says so');
    ok((await p.$$('#svg g[data-node]')).length === 0, 'nothing drawn without data');
    await p.close();
  } finally { await browser.close(); srv.close(); }
  console.log(`${n - bad}/${n} passed`); process.exit(bad ? 1 : 0);
})();
