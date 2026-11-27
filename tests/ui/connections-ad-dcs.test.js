// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Connections & Setup: the Active Directory card lists the domain controllers the Windows agent reports from (GET /ad-directory
// domain_controllers) even before the directory-users read is set - each DC with its role and domain, connected, and a hint to read
// the users; a DC whose last snapshot is old is stale; once the directory read is set it is a row of its own; hostile text stays text.
// Stub APIs; names and addresses are SYNTHETIC. Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node connections-ad-dcs.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const DASH = path.resolve(__dirname, '../../ui'), D = 86400000;
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
let AD = { connection: { ok: false, why: 'not set' }, last: null, users: [], domain_controllers: [
  { host: 'dc-syn-01', ip: '10.9.1.10', at: new Date(Date.now() - 3600000).toISOString(), agent_version: '1.4.0', role: 'primary', domain: 'corp.syn.test', domain_mode: 'Windows2016Domain' },
  { host: '<img src=x onerror=window.PWN=1>', ip: '10.9.1.11', at: new Date(Date.now() - 4 * D).toISOString(), role: 'domain controller', domain: 'corp.syn.test' }] };
(async () => {
  const srv = http.createServer((req, res) => { const u = req.url.split('?')[0], json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u === '/dashboards/whoami.json') return json(200, { user: 'admin.syn', role: 'admin' });
    if (u === '/api/itam/ad-directory') return json(200, AD);
    if (u.startsWith('/api/')) return json(404, { error: 'not in this test' });
    fs.readFile(path.join(DASH, u.replace(/^\/dashboards\//, '/')), (err, d) => { if (err) { res.writeHead(404); return res.end(); } res.writeHead(200, { 'Content-Type': u.endsWith('.js') ? 'application/javascript' : u.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); }); });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port + '/dashboards/connections.html?standalone=1';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright'); const browser = await chromium.launch(), errs = [];
  try {
    let p = await browser.newPage({ viewport: { width: 1400, height: 900 } }); p.on('pageerror', (x) => errs.push(x.message));
    await p.goto(base); await p.waitForSelector('#cn-ad', { timeout: 20000 }); await p.waitForFunction(() => /dc-syn-01/.test(document.querySelector('#cn-ad').innerText), null, { timeout: 15000 });
    const t = await p.textContent('#cn-ad');
    ok(!/No connection yet/.test(t), 'the card is not empty when DCs report: ' + t.slice(0, 200));
    ok(/primary domain controller/.test(t) && /corp\.syn\.test/.test(t) && /reported by the Windows agent/.test(t), 'role, domain, via the agent');
    ok(/directory users not read yet/.test(t), 'says the users are not read yet');
    ok(/stale/.test(t), 'an old snapshot is stale');
    ok(!(await p.evaluate(() => window.PWN)), 'hostile text stays text'); await p.close();
    AD = Object.assign({}, AD, { connection: { ok: true, servers: ['dc-syn-01.corp.syn.test'], base_dn: 'DC=corp,DC=syn,DC=test' }, last: { at: new Date().toISOString(), count: 42 } });
    p = await browser.newPage({ viewport: { width: 1400, height: 900 } }); p.on('pageerror', (x) => errs.push(x.message));
    await p.goto(base); await p.waitForFunction(() => /42 users/.test((document.querySelector('#cn-ad') || {}).innerText || ''), null, { timeout: 20000 });
    const t2 = await p.textContent('#cn-ad'); ok(/DC=corp,DC=syn,DC=test/.test(t2) && /dc-syn-01/.test(t2) && !/directory users not read yet/.test(t2), 'directory read is its own row next to the DCs');
    await p.close();
    ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  } finally { await browser.close(); srv.close(); }
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks'); process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
