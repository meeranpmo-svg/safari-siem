// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Call Manager page: not set up says what to connect (and an administrator sees the connection form); polled: KPIs, findings
// (hostile text stays text), pools, trunks; an operator selects phones and proposes a restart; the proposer is not offered
// Approve, another administrator is; Run carries it out; a viewer sees no phone list. Stub ITAM; phones and people SYNTHETIC.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node cucm.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const DASH = path.resolve(__dirname, '../../ui');
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
let USER = 'admin.syn', ROLE = 'admin', POLLED = false, CH = [];
const VIEW = () => (POLLED ? { status: { configured: true, write_enabled: true, poll_min: 15 }, polled: true, at: '2026-11-25T08:00:00Z', learning: false,
  kpis: { phones: 3, registered: 2, unregistered: 1, trunks: 1, trunks_down: 1, active_calls: 4, failed_pct: 12 },
  pools: [{ pool: 'DP_SITE7', phones: 2, registered: 1, pct: 50, usual: 100 }, { pool: 'DP_HQ', phones: 1, registered: 1, pct: 100, usual: 100 }],
  trunks: [{ name: 'SIP-CARRIER-SYN', class: 'SIPTrunk', status: 'UnRegistered', ip: '10.30.0.9' }],
  findings: [{ severity: 'high', code: 'trunk-down', title: 'SIP trunk SIP-CARRIER-SYN: UnRegistered <img src=x onerror=alert(1)>', fix: 'Check the far end' }], errors: [], changes: CH }
  : { status: { configured: false, poll_min: 15 }, polled: false, note: 'no CUCM login chosen - an administrator picks it in the settings below' });
const PHONES = [{ name: 'SEP000000000010', description: 'Ext 0010', model: 'Cisco 8845', device_pool: 'DP_SITE7', status: 'UnRegistered', ip: '', changes_24h: 3, unregistered_since: '2026-11-20T00:00:00Z' }, { name: 'SEP000000000011', device_pool: 'DP_SITE7', status: 'Registered', ip: '10.7.10.5', changes_24h: 0 }];
const posts = [];
(async () => {
  const srv = http.createServer((req, res) => {
    const u = req.url.split('?')[0]; const json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    const body = (fn) => { let b = ''; req.on('data', (d) => { b += d; }); req.on('end', () => { const j = b ? JSON.parse(b) : null; posts.push([req.method, u, j]); fn(j); }); };
    if (u === '/dashboards/whoami.json') return json(200, { user: USER, role: ROLE });
    if (u === '/api/itam/cucm') return json(200, VIEW());
    if (u === '/api/itam/cucm/phones') return ROLE === 'viewer' ? json(403, { error: 'forbidden' }) : json(200, { phones: PHONES });
    if (u === '/api/itam/cucm/settings') return body(() => { POLLED = true; json(200, { configured: true }); });
    if (u === '/api/itam/cucm/changes') return body((b) => { const c = Object.assign({ id: 'UCCH-00001', status: 'proposed', proposed_by: USER }, b); CH = [c]; json(200, c); });
    if (/\/decide$/.test(u)) return body((b) => { CH[0].status = b.decision; CH[0].decided_by = USER; json(200, CH[0]); });
    if (/\/run$/.test(u)) return body(() => { CH[0].status = 'done'; json(200, CH[0]); });
    if (u.startsWith('/api/')) return json(404, { error: 'not in this test' });
    fs.readFile(path.join(DASH, u.replace(/^\/dashboards\//, '/')), (err, d) => { if (err) { res.writeHead(404); res.end(); return; } res.writeHead(200, { 'Content-Type': u.endsWith('.js') ? 'application/javascript' : u.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const URL0 = 'http://127.0.0.1:' + srv.address().port + '/cucm.html?standalone=1';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(); const errs = [];
  const open = async () => { const p = await browser.newPage({ viewport: { width: 1400, height: 900 } }); p.on('pageerror', (x) => errs.push(x.message)); p.on('dialog', (d) => d.accept()); await p.goto(URL0); return p; };
  const toast = async (p) => { await p.waitForSelector('.toast', { timeout: 8000 }); const t = await p.$$eval('.toast', (x) => x.map((e) => e.textContent).join(' | ')); await p.$$eval('.toast', (x) => x.forEach((e) => e.remove())); return t; };
  let p = await open(); await p.waitForSelector('#s-save');
  ok(/no CUCM login chosen/.test(await p.textContent('#body')), 'not set up says so');
  await p.fill('#s-ro', 'cr_ro'); await p.fill('#s-rw', 'cr_rw'); await p.selectOption('#s-we', 'true'); await p.click('#s-save'); await toast(p);
  const st = posts.find((x) => x[1] === '/api/itam/cucm/settings'); ok(st && st[2].credential_id === 'cr_ro' && st[2].write_credential_id === 'cr_rw' && st[2].write_enabled === true, 'settings sent');
  await p.waitForSelector('[data-sel]');
  ok(!(await p.$('img[src="x"]')), 'hostile text stays text');
  ok(/Trunks \/ gateways\s*1/.test(await p.textContent('#kp')) && /12 %/.test(await p.textContent('#kp')), 'KPIs');
  ok(/DP_SITE7/.test(await p.textContent('#body')) && /SIP-CARRIER-SYN/.test(await p.textContent('#body')), 'pools and trunks');
  await p.check('[data-sel="SEP000000000010"]'); await p.fill('#c-r', 'stuck after the outage (synthetic)'); await p.click('#c-go');
  ok(/UCCH-00001 proposed/.test(await toast(p)), 'proposed');
  const pr = posts.find((x) => x[1] === '/api/itam/cucm/changes'); ok(pr && pr[2].type === 'restart' && pr[2].phones.join() === 'SEP000000000010', 'change body');
  await p.waitForSelector('#body .act .pill'); ok(!(await p.$('[data-dec="approved"]')), 'the proposer is not offered Approve');
  await p.close();
  USER = 'sec.syn'; p = await open(); await p.waitForSelector('[data-dec="approved"]'); await p.click('[data-dec="approved"]'); ok(/approved/.test(await toast(p)), 'another administrator approves');
  await p.waitForSelector('[data-run]'); await p.click('[data-run]'); ok(/done/.test(await toast(p)), 'run'); await p.close();
  USER = 'vera.syn'; ROLE = 'viewer'; p = await open(); await p.waitForSelector('#kp .t');
  ok(!(await p.$('[data-sel]')) && /operators and above see it/.test(await p.textContent('#body')) && !(await p.$('#s-save')), 'viewer: no phone list, no settings'); await p.close();
  ok(!errs.length, 'errors: ' + errs.join(' | '));
  await browser.close(); srv.close();
  console.log(bad ? `${bad}/${n} FAILED` : `OK ${n}/${n} checks`); process.exit(bad ? 1 : 0);
})();
