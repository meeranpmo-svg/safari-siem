// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// network-connectivity.html (Connectivity Troubleshooter): an analyst picks RDP, narrows to a user subnet and a server and
// runs the diagnosis; the page shows the summary, the path, the ranked causes with evidence and the per-device fix +
// rollback as TEXT (a command holding markup is not rendered); Copy puts fix + rollback on the clipboard. An operator also
// gets "re-read the firewall settings" and "Propose as change" (posts a change plan for another engineer to approve); a
// custom service needs a port; a viewer cannot run it. Stubbed SIEM API, SYNTHETIC data.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node network-connectivity.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const DASH = path.resolve(__dirname, '../../ui');
let n = 0, bad = 0, ROLE = 'analyst', asked = [], proposed = [];
const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const RESULT = { service: 'rdp', label: 'Remote Desktop (RDP)', ports: [3389], users: '10.20.0.0/16', server: '10.0.10.21', minutes: 120,
  scope: { firewalls: [{ id: 'fg-users', name: 'FG-USERS-SYN', vendor: 'fortigate', facts_at: Date.parse('2026-10-27T06:00:00Z') }, { id: 'pa-dc', name: 'PA-DC-SYN', vendor: 'paloalto', facts_at: null }] },
  path: [{ hop: 'Users', detail: '10.20.0.0/16' }, { hop: 'FG-USERS-SYN', detail: '60 sessions logged' }, { hop: 'PA-DC-SYN', detail: '15 sessions logged' }, { hop: 'Server', detail: '10.0.10.21' }],
  checks: [{ name: 'Return path (asymmetric routing)', status: 'fail', detail: 'sessions without replies', evidence: ['FortiGate: 37 % of sessions with no reply'] }],
  causes: [{ rank: 1, id: 'asymmetric', title: 'Asymmetric routing between the FortiGate and the Palo Alto', confidence: 'high', explanation: 'The reply comes back another way.', evidence: ['PA-DC-SYN: 4812 non-SYN TCP drops'],
    steps: [{ vendor: 'routing', device: 'pa-dc', title: 'Make the reply return through the same firewall', risk: 'medium', commands: ['set network virtual-router default routing-table ip static-route SENTRA-USERS-RETURN destination 10.20.0.0/16 nexthop ip-address 10.0.0.2', '<img src=x data-x="injected">'], rollback: ['delete network virtual-router default routing-table ip static-route SENTRA-USERS-RETURN'] },
      { vendor: 'client', device: null, title: 'RDP keep-alives', risk: 'low', commands: ['reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services" /v KeepAliveEnable /t REG_DWORD /d 1 /f'], rollback: [] }] }],
  summary: 'Most likely: Asymmetric routing between the FortiGate and the Palo Alto.' };
(async () => {
  const srv = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://x'), json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    const body = () => new Promise((r) => { let b = ''; req.on('data', (c) => { b += c; }); req.on('end', () => r(b ? JSON.parse(b) : {})); });
    if (u.pathname === '/dashboards/whoami.json') return json(200, { user: 'omar.syn', role: ROLE });
    if (u.pathname === '/api/soc/netops/connectivity' && req.method === 'POST') return body().then((b) => { asked.push(b); json(200, Object.assign({}, RESULT, { service: b.service })); });
    if (u.pathname === '/api/soc/netops/changes' && req.method === 'POST') return body().then((b) => { proposed.push(b); json(200, { id: 'NCHG-000042', status: 'proposed' }); });
    if (u.pathname.startsWith('/api/')) return json(404, { error: 'not found' });
    const f = path.join(DASH, u.pathname.replace(/^\/dashboards\//, '/')); if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (err, d) => { if (err) { res.writeHead(404); res.end(); return; } res.writeHead(200, { 'Content-Type': u.pathname.endsWith('.js') ? 'application/javascript' : u.pathname.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  const ctx = await browser.newContext({ viewport: { width: 1300, height: 900 } }); await ctx.grantPermissions(['clipboard-read', 'clipboard-write']);
  const url = 'http://127.0.0.1:' + srv.address().port + '/dashboards/network-connectivity.html';
  let page;
  const as = async (role) => { ROLE = role; if (page) await page.close(); page = await ctx.newPage(); page.on('pageerror', (x) => errs.push(x.message)); await page.goto(url); await page.waitForFunction(() => document.readyState === 'complete'); await page.waitForTimeout(300); };
  try {
    await as('analyst');
    ok(!(await page.isVisible('#refl')), 'an analyst does not get the live re-read');
    await page.click('[data-svc="rdp"]'); await page.fill('#users', '10.20.0.0/16'); await page.fill('#server', '10.0.10.21');
    await page.click('#go'); await page.waitForSelector('[data-cause="asymmetric"]');
    ok(asked.length === 1 && asked[0].service === 'rdp' && asked[0].users === '10.20.0.0/16' && asked[0].server === '10.0.10.21' && asked[0].minutes === 120 && !asked[0].refresh, 'request: ' + JSON.stringify(asked[0]));
    ok(/Most likely: Asymmetric routing/.test(await page.textContent('#sum')), 'summary shown');
    const txt = await page.$eval('#out', (x) => x.innerText);
    ok(/FG-USERS-SYN[\s\S]*PA-DC-SYN/.test(txt) && /60 sessions logged/.test(txt), 'the path users → FortiGate → Palo Alto → server');
    ok(/high confidence/i.test(txt) && /4812 non-SYN/.test(txt), 'cause with confidence and evidence');
    ok(/settings not read yet/.test(txt), 'a firewall whose settings were not read says so');
    ok(!(await page.$('#out img')) && /<img src=x/.test(await page.textContent('#cmd-0-0')), 'a command with markup is shown as text, never rendered');
    ok(/delete network virtual-router/.test(await page.textContent('#rb-0-0')), 'rollback beside the fix');
    ok(!(await page.$('[data-propose]')), 'an analyst cannot propose a change');
    await page.click('[data-copy="0:1"]'); ok(/KeepAliveEnable/.test(await page.evaluate(() => navigator.clipboard.readText())), 'Copy puts the step on the clipboard');
    // custom service needs a port
    await page.click('[data-svc="custom"]'); ok(await page.isVisible('#portl'), 'custom service asks for a port');
    await page.click('#go'); await page.waitForTimeout(200); ok(asked.length === 1 && /TCP port/.test(await page.evaluate(() => document.body.innerText)), 'no request without a port');
    await page.fill('#port', '1521'); await page.click('#go'); await page.waitForSelector('[data-cause]');
    ok(asked[1] && asked[1].service === 'custom' && asked[1].port === 1521, 'custom port sent');
    // operator
    await as('operator');
    ok(await page.isVisible('#refl'), 'an operator can ask for a live re-read');
    await page.check('#refresh'); await page.click('#go'); await page.waitForSelector('[data-propose="0:0"]');
    ok(asked[2].refresh === true, 'refresh sent for an operator');
    ok(!(await page.$('[data-propose="0:1"]')), 'a client-side step has no device: nothing to propose');
    await page.click('[data-propose="0:0"]'); await page.waitForFunction(() => /NCHG-000042/.test(document.body.innerText));
    const p = proposed[0] || {};
    ok(p.device === 'pa-dc' && /Asymmetric routing/.test(p.title) && p.commands.length === 2 && p.rollback.length === 1 && p.risk === 'medium' && /4812 non-SYN/.test(p.reason), 'change plan proposed with fix, rollback, risk and evidence: ' + JSON.stringify(p).slice(0, 200));
    ok(/another engineer approves/.test(await page.evaluate(() => document.body.innerText)), 'says who approves');
    // viewer
    await as('viewer');
    ok(await page.isVisible('#denied') && await page.isDisabled('#go'), 'a viewer cannot run the diagnosis');
    ok(!errs.length, 'page errors: ' + errs.join(' | '));
  } finally { await browser.close(); srv.close(); }
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks'); process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
