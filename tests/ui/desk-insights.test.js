// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// AI Desktop Support Engineer - the AI / ML insight band (desk-support.html): four charts from the computers' own reports
// (desktop health, issues across the computers, attention by branch, operating systems) and "What the AI noticed", each line
// with its own figure (attention now, missing critical patches, silent for 7+ days, no agent, end-of-support OS, the most common
// issue, the branch with most attention, high-priority tickets); hostile names stay text; no computers: the band is hidden;
// without the charts library only the noticed list shows. Stubbed API, SYNTHETIC data.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node desk-insights.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const DASH = path.resolve(__dirname, '../../ui');
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const XSS = '<img src=x onerror=window.PWN=1>', now = Date.now(), ago = (d) => new Date(now - d * 86400000).toISOString();
const ITEMS = [
  { name: 'PC-SYN-01', user: 'a.syn', os: 'Windows 11 Pro', branch: 'Riyadh HQ', worst: null, issues: [], critical: 0, last_contact: ago(0), source: 'endpoint central', resource_id: 'r1' },
  { name: 'PC-SYN-02', user: 'b.syn', os: 'Windows 10 Enterprise', branch: 'Jeddah', worst: 'high', issues: ['3 critical patches missing', 'Disk C: 96% full'], critical: 3, last_contact: ago(0), source: 'endpoint central', resource_id: 'r2' },
  { name: 'PC-SYN-03', user: 'c.syn', os: 'Windows 7 Professional', branch: 'Jeddah', worst: 'high', issues: ['5 critical patches missing'], critical: 5, last_contact: ago(10), source: 'endpoint central', resource_id: 'r3' },
  { name: XSS, user: 'd.syn', os: 'Windows 11 Pro', branch: XSS, worst: 'medium', issues: ['Antivirus out of date'], critical: 0, last_contact: ago(1), source: 'endpoint central', resource_id: 'r4' },
  { name: 'LT-SYN-05', user: 'e.syn', os: 'Windows 11 Pro', branch: 'Riyadh HQ', worst: null, issues: [], source: 'asset register', asset_id: 'a5' }];
const FULL = () => ({ status: { configured: { sdp: true, ec: true }, mode: 'suggest', technicians: 3, proposed: 1, applied: 4, desktops: { total: 5, healthy: 1, needs_patch: 2, offline: 1 } },
  triage: [{ request_id: '1001', subject: 'VPN down', requester: 'f.syn', proposed: { priority: 'High', group: 'Network', status: 'Open' } }], desktops: { items: ITEMS }, patch_proposals: [] });
let DATA = FULL();
(async () => {
  const srv = http.createServer((q, r) => { const u = decodeURIComponent(q.url.split('?')[0]), j = (c, o) => { r.writeHead(c, { 'Content-Type': 'application/json' }); r.end(JSON.stringify(o)); };
    if (u.endsWith('whoami.json')) return j(200, { user: 'op.syn', role: 'operator' });
    if (u === '/api/itam/me/desk') return j(200, DATA);
    if (u.startsWith('/api/')) return j(404, { error: 'not in this test' });
    fs.readFile(path.join(DASH, u.replace(/^\/dashboards\//, '/')), (e, d) => { if (e) { r.writeHead(404); return r.end(); } r.writeHead(200, { 'Content-Type': u.endsWith('.js') ? 'application/javascript' : u.endsWith('.css') ? 'text/css' : 'text/html' }); r.end(d); }); });
  await new Promise((res) => srv.listen(0, '127.0.0.1', res));
  const url = 'http://127.0.0.1:' + srv.address().port + '/dashboards/desk-support.html?standalone=1';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright'); const browser = await chromium.launch(), errs = [];
  const open = async (block) => { const p = await browser.newPage({ viewport: { width: 1400, height: 1000 } }); p.on('pageerror', (e) => errs.push(e.message)); if (block) await p.route('**/chart.umd.js', (r) => r.fulfill({ status: 404, body: '' })); await p.goto(url); await p.waitForFunction(() => /updated/.test((document.getElementById('up') || {}).textContent || ''), null, { timeout: 15000 }); return p; };
  try {
    let p = await open();
    ok(!(await p.$eval('#aiwrap', (e) => e.hidden)), 'the insight band shows');
    const lab = await p.$$eval('#aiwrap canvas', (x) => x.map((c) => c.getAttribute('aria-label') || ''));
    ok(lab.length === 4 && /Desktop health/.test(lab[0]) && /Issues across/.test(lab[1]) && /Attention by branch/.test(lab[2]) && /Operating systems/.test(lab[3]), 'four charts that say what they show: ' + lab.map((l) => l.slice(0, 40)).join(' | '));
    ok(/Windows 11/.test(lab[3]) && /Windows 7/.test(lab[3]), 'the OS mix is read from the computers: ' + lab[3].slice(0, 120));
    const ins = await p.$eval('#ins', (e) => e.innerText);
    ok(/2 of 5 computers need attention now and 1 more to watch/.test(ins), 'attention now and to watch: ' + ins);
    ok(/2 computers miss critical patches \(8 patches in all\)/.test(ins), 'missing critical patches with the total');
    ok(/1 computers have not reported for more than 7 days/.test(ins), 'silent for 7+ days');
    ok(/1 computers in the asset register have no Endpoint Central agent/.test(ins), 'no agent');
    ok(/1 computers run an operating system past its end of support/.test(ins), 'end-of-support OS');
    ok(/most common issue is # critical patches missing on 2 computers/.test(ins), 'the most common issue, numbers grouped');
    ok(/Jeddah has the most computers needing attention \(2 of 2\)/.test(ins), 'the branch with most attention');
    ok(/1 waiting tickets were triaged as high or urgent/.test(ins), 'high-priority tickets');
    ok(!(await p.evaluate(() => window.PWN)) && !(await p.$('#aiwrap img, #ins img')), 'hostile names stay text');
    await p.close();
    // without the charts library: only the noticed list
    p = await open(true);
    ok(await p.$eval('#aiwrap .aig', (e) => e.hidden) && /need attention/.test(await p.$eval('#ins', (e) => e.innerText)), 'no charts library: the noticed list still shows');
    await p.close();
    // no computers: the band is hidden
    DATA = FULL(); DATA.desktops = { items: [] }; p = await open();
    ok(await p.$eval('#aiwrap', (e) => e.hidden), 'no computers: no insight band'); await p.close();
    ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  } finally { await browser.close(); srv.close(); }
  console.log((bad ? 'FAILED ' : 'ok ') + (n - bad) + '/' + n + ' desk-insights checks'); process.exit(bad ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });
