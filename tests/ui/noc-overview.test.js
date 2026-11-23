// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// NOC Overview (noc-overview.html) - the Workflow Automation card, on a STUBBED API with SYNTHETIC data in the engine's shape
// (GET /api/itam/workflow/attention): the network team's open / overdue / on-time tiles, approvals and overdue across IT, the
// requests that need the person ranked by points and linked, a hostile title stays text; Workflow Automation not installed hides
// the card, a failure is said; the network monitoring itself not answering still leaves the card working; no page error.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node noc-overview.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const DASH = path.resolve(__dirname, '../../ui');
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const ATT = { summary: { approvals: 1, queue_open: 2, overdue: 1, at_risk: 0, to_accept: 0, raised_open: 0, raised_late: 0, functions: [], all_overdue: 3, recurring: 0,
    teams: [{ team: 'network', name: 'Network team', open: 2, overdue: 1, n: 4, on_time: 3, rate: 0.67 }, { team: 'dba', name: 'Database team (DBA)', open: 1, overdue: 2, n: 0, on_time: 0, rate: 0.5 }], items: [] },
  priorities: [{ kind: 'Request approval', ref: 'REQ-2026-0041', text: 'Open 443 for the <img src=x onerror=window.__wfx=1> portal - Network change, from Administration (adm.syn)', page: 'workflow-automation.html#req=REQ-2026-0041', why: [['a business request waiting for your approval', 45]] },
    { kind: 'Request overdue', ref: 'REQ-2026-0038', text: 'Firewall rule review evidence - Network team, due 2026-11-10 08:00', page: 'workflow-automation.html#req=REQ-2026-0038', why: [['a request to the IT team past its due date', 40], ['escalated', 10]] }] };
let MODE = 'live';
(async () => {
  const srv = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://x'), json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u.pathname === '/dashboards/whoami.json' || u.pathname === '/auth/whoami') return json(200, { user: 'net.syn', role: 'operator' });
    if (u.pathname === '/api/itam/workflow/attention') return MODE === 'live' ? json(200, ATT) : MODE === 'broken' ? json(424, { error: 'synthetic failure' }) : json(404, { error: 'not found' });
    if (u.pathname.startsWith('/api/') || u.pathname.startsWith('/auth/')) return json(404, { error: 'not in this test' });
    const f = path.join(DASH, u.pathname.replace(/^\/dashboards\//, '/')); if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (err, d) => { if (err) { res.writeHead(404); res.end(); return; } res.writeHead(200, { 'Content-Type': u.pathname.endsWith('.js') ? 'application/javascript' : u.pathname.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const url = 'http://127.0.0.1:' + srv.address().port + '/noc-overview.html?standalone=1';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  try {
    const p = await browser.newPage({ viewport: { width: 1440, height: 1000 } }); p.on('pageerror', (x) => errs.push(x.message)); p.on('dialog', (d) => { errs.push('dialog: ' + d.message()); d.dismiss(); });
    const wait = (fn) => p.waitForFunction(fn, null, { timeout: 10000 }).then(() => true, () => false);
    await p.goto(url);
    ok(await wait(() => !document.getElementById('wfcard').hidden && document.querySelectorAll('#wfk .t').length === 5), 'the Workflow Automation card, even with the network monitoring not answering');
    const k = await p.textContent('#wfk');
    ok(/Network team · open\s*2/.test(k) && /Network team · overdue\s*1/.test(k) && /Network team · on time\s*75%/.test(k) && /3 of 4 fulfilled/.test(k) && /Waiting for your approval\s*1/.test(k) && /Overdue across IT\s*3/.test(k), 'the network team\'s open / overdue / on time, approvals, overdue across IT: ' + k.replace(/\s+/g, ' '));
    const l = await p.textContent('#wfl');
    ok(l.indexOf('REQ-2026-0038') < l.indexOf('REQ-2026-0041') && /escalated \+10/.test(l) && /<img src=x/.test(l) && !(await p.$('#wfl img')) && !(await p.evaluate(() => window.__wfx)), 'ranked by points (50 before 45) with the reasons; a hostile title stays text');
    ok(!!(await p.$('#wfl a[href="workflow-automation.html#req=REQ-2026-0041"]')) && !!(await p.$('#wfcard a[href="workflow-automation.html#tab=queue"]')), 'each request and the team queue are linked');
    MODE = 'broken'; await p.goto(url); ok(await wait(() => /could not be read: synthetic failure/.test(document.getElementById('wfl').textContent)), 'a failure is said, never zeros');
    MODE = 'none'; await p.goto(url); await p.waitForTimeout(800); ok(await p.evaluate(() => document.getElementById('wfcard').hidden), 'Workflow Automation not installed: the card hidden');
    ok(!errs.length, 'no page errors or dialogs: ' + errs.join(' | '));
  } finally { await browser.close(); srv.close(); }
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks'); process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
