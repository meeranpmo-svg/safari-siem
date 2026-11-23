// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const ZYB_ORG = require('../../brand/index');
// Connections & Setup: the DLP card lists DLP log sources registered in the SIEM (Somansa / Forcepoint …), shows receiving
// vs waiting, needs no password, and Add registers the sender through POST /onboard/sources and gives the syslog address.
// Stub SIEM; names and addresses are SYNTHETIC. Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node connections-dlp.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const DASH = path.resolve(__dirname, '../../ui');
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const SRC = [{ id: 'somansa-hq', kind: 'somansa-privacy-i', type: 'somansa', label: 'Somansa HQ', match_ip: '10.20.0.40', state: 'receiving', last_seen: Date.now() - 60000, events_24h: 42, created_at: '2026-10-01T00:00:00Z' },
  { id: 'fw-1', kind: 'fortigate', type: 'fortigate', label: 'FW', state: 'receiving' }];
let posted = null;
(async () => {
  const srv = http.createServer((req, res) => {
    const u = req.url.split('?')[0]; const json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u === '/dashboards/whoami.json') return json(200, { user: 'syed', role: 'admin' });
    if (u === '/api/soc/onboard/sources' && req.method === 'GET') return json(200, { sources: SRC });
    if (u === '/api/soc/onboard/sources' && req.method === 'POST') { let b = ''; req.on('data', (d) => { b += d; }); req.on('end', () => { posted = JSON.parse(b); SRC.push(Object.assign({ state: 'waiting', created_at: new Date().toISOString() }, posted)); json(200, { source: posted, siem: { ip: ZYB_ORG.platform_addr, syslog_port: 5514 } }); }); return; }
    if (u.startsWith('/api/')) return json(404, { error: 'not in this test' });
    fs.readFile(path.join(DASH, u.replace(/^\/dashboards\//, '/')), (err, d) => { if (err) { res.writeHead(404); res.end(); return; } res.writeHead(200, { 'Content-Type': u.endsWith('.js') ? 'application/javascript' : u.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(); const page = await browser.newPage({ viewport: { width: 1400, height: 900 } }); const errs = [];
  page.on('pageerror', (x) => errs.push(x.message));
  let alertText = ''; page.on('dialog', (d) => { alertText = d.message(); d.accept(); });
  await page.goto('http://127.0.0.1:' + srv.address().port + '/connections.html?standalone=1');
  await page.waitForSelector('#cn-dlp table');
  const t = await page.$eval('#cn-dlp', (x) => x.innerText.replace(/\s+/g, ' '));
  ok(/Data Loss Prevention/.test(t) && /Somansa HQ/.test(t) && /sender 10\.20\.0\.40/.test(t) && /42 events/.test(t), 'DLP source listed: ' + t.slice(0, 300));
  ok(!/FW/.test(t), 'non-DLP sources are not on the DLP card');
  ok(/not needed \(syslog\)/.test(t) && /1\/1 connected/.test(t), 'no password, receiving = connected');
  await page.click('#cn-dlp [data-act=add]'); await page.waitForSelector('#mf');
  await page.selectOption('#mf select[name=kind]', 'somansa-mail-i');
  await page.fill('#mf input[name=id]', 'hq'); await page.fill('#mf input[name=match_ip]', '10.20.0.41');
  await page.click('#msave'); await page.waitForTimeout(800);
  ok(posted && posted.kind === 'somansa-mail-i' && posted.id === 'somansa-ml-hq' && posted.match_ip === '10.20.0.41', 'registered: ' + JSON.stringify(posted));
  ok(new RegExp(ZYB_ORG.platform_addr_re).test(alertText) && /5514/.test(alertText), 'syslog address shown: ' + alertText);
  await page.waitForFunction(() => /waiting for the first incident/.test(document.querySelector('#cn-dlp').innerText));
  ok(true, 'new source reads waiting');
  ok(!errs.length, 'errors: ' + errs.join(' | '));
  await browser.close(); srv.close();
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks'); process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
