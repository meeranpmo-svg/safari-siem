// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// AI Application Manager (ai-app-manager.html): the AI / ML band (service health, resilience gaps, production servers online),
// "What the AI noticed" with its figures, and the ERP programme from the brand setting (erp.current -> erp.target, Safari:
// Microsoft Dynamics -> Oracle Fusion): the services matching each system are found by service or server name with their
// status, HA and DR; the migration watch says what to keep reliable until cutover and what to monitor before go-live; with no
// Fusion integration monitored it says what to add (nothing invented); without an erp setting the card is hidden; hostile
// names stay text. Stubbed Server Availability, SYNTHETIC data.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node app-manager-erp.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const DASH = path.resolve(__dirname, '../../ui');
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const XSS = '<img src=x onerror=window.PWN=1>';
const items = [{ id: 'h1', name: 'D365-AOS01', status: 'online' }, { id: 'h2', name: 'D365-SQL01', status: 'online' }, { id: 'h3', name: 'OIC-AGENT01', status: 'offline' },
  { id: 'h4', name: 'FILE-SYN-01', status: 'online' }, { id: 'h5', name: XSS, status: 'online' }];
const G = (fusion) => [
  { name: 'Microsoft Dynamics 365', status: 'spof', critical: true, inferred: false, required: true, production: 2, production_online: 2, ha: false, members: ['h1', 'h2'], issues: ['single-server', 'no-dr'] },
  { name: 'File services', status: 'ok', critical: false, inferred: true, required: true, production: 1, production_online: 1, ha: true, members: ['h4'], issues: [] },
  { name: XSS, status: 'down', critical: false, inferred: false, required: true, production: 1, production_online: 0, ha: false, members: ['h5'], issues: ['service-down'] }]
  .concat(fusion ? [{ name: 'Oracle Fusion integration', status: 'down', critical: true, inferred: false, required: true, production: 1, production_online: 0, ha: false, members: ['h3'], issues: ['service-down'] }] : []);
let AV = { groups: G(true), items, summary: { offline: 1 } };
(async () => {
  const srv = http.createServer((q, r) => { const u = decodeURIComponent(q.url.split('?')[0]), j = (c, o) => { r.writeHead(c, { 'Content-Type': 'application/json' }); r.end(JSON.stringify(o)); };
    if (u.endsWith('whoami.json')) return j(200, { user: 'op.syn', role: 'operator' });
    if (u === '/api/soc/netops/avail') return j(200, AV);
    if (u.startsWith('/api/')) return j(404, { error: 'not in this test' });
    fs.readFile(path.join(DASH, u.replace(/^\/dashboards\//, '/')), (e, d) => { if (e) { r.writeHead(404); return r.end(); } r.writeHead(200, { 'Content-Type': u.endsWith('.js') ? 'application/javascript' : u.endsWith('.css') ? 'text/css' : 'text/html' }); r.end(d); }); });
  await new Promise((res) => srv.listen(0, '127.0.0.1', res));
  const url = 'http://127.0.0.1:' + srv.address().port + '/dashboards/ai-app-manager.html?standalone=1';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright'); const browser = await chromium.launch(), errs = [];
  const erp = { current: 'Microsoft Dynamics', target: 'Oracle Fusion Cloud ERP', state: 'migrating' };
  const open = async (orgErp) => { const p = await browser.newPage({ viewport: { width: 1400, height: 1000 } }); p.on('pageerror', (e) => errs.push(e.message));
    await p.addInitScript((e) => { Object.defineProperty(window, 'ZYB_ORG', { configurable: true, set(v) { this._o = Object.assign({}, v, { erp: e }); }, get() { return this._o; } }); }, orgErp);
    await p.goto(url); await p.waitForFunction(() => /updated/.test(document.getElementById('gen').textContent), null, { timeout: 15000 }); return p; };
  try {
    // the real brand setting carries the programme
    ok(/"erp":\{"current":"Microsoft Dynamics","target":"Oracle Fusion Cloud ERP","state":"migrating"\}/.test(fs.readFileSync(path.join(DASH, 'vendor/zyb-org.js'), 'utf8')), 'the Safari brand names Dynamics -> Oracle Fusion Cloud ERP');
    let p = await open(erp);
    ok(!(await p.$eval('#erpcard', (e) => e.hidden)) && /migrating · Microsoft Dynamics → Oracle Fusion Cloud ERP/.test(await p.textContent('#erpsub')), 'the ERP programme card shows');
    const cur = await p.$eval('#erpcur', (e) => e.innerText), tgt = await p.$eval('#erptgt', (e) => e.innerText);
    ok(/Today/i.test(cur) && /Microsoft Dynamics 365/.test(cur) && /2 \/ 2 servers online/.test(cur) && /Single server/.test(cur) && /no DR/.test(cur), 'Dynamics side from its services: ' + cur.replace(/\s+/g, ' '));
    ok(/Target/i.test(tgt) && /Oracle Fusion integration/.test(tgt) && /0 \/ 1 servers online/.test(tgt) && /Down/.test(tgt), 'Fusion side from its integration servers: ' + tgt.replace(/\s+/g, ' '));
    const w = (await p.$eval('#erpwatch', (e) => e.innerText)).replace(/\s+/g, ' ');
    ok(/1 of the 1 Microsoft Dynamics services are not fully healthy/.test(w) && /1 Microsoft Dynamics services have no DR copy/.test(w) && /Oracle Fusion Cloud ERP: 1 integration services monitored - some are not healthy/.test(w) && /side by side/.test(w), 'migration watch: ' + w.replace(/\s+/g, ' '));
    const lab = await p.$$eval('#aiband canvas', (x) => x.map((c) => c.getAttribute('aria-label') || ''));
    ok(lab.length === 3 && /Service health/.test(lab[0]) && /Resilience gaps/.test(lab[1]) && /Production servers online/.test(lab[2]), 'three charts: ' + lab.map((l) => l.slice(0, 40)).join(' | '));
    const ins = (await p.$eval('#ins', (e) => e.innerText)).replace(/\s+/g, ' ');
    ok(/2 services are down now/.test(ins) && /2 business-critical services are not fully healthy/.test(ins) && /1 services run on a single server/.test(ins) && /1 services have no DR copy/.test(ins) && /1 services are grouped by server name only/.test(ins), 'noticed with figures: ' + ins.replace(/\s+/g, ' '));
    ok(!(await p.evaluate(() => window.PWN)) && !(await p.$('#svc img, #ins img, #erpcard img')), 'hostile names stay text');
    await p.close();
    // no Fusion integration monitored yet: says what to add
    AV = { groups: G(false), items: items.filter((h) => h.id !== 'h3'), summary: {} }; p = await open(erp);
    ok(/runs in Oracle’s cloud, so it has no servers here/.test(await p.$eval('#erptgt', (e) => e.innerText)) && /No Oracle Fusion Cloud ERP integration is monitored yet/.test(await p.$eval('#erpwatch', (e) => e.innerText)), 'no Fusion integration: what to monitor before go-live');
    await p.close();
    // an organisation without an ERP programme: no card
    p = await open(null); ok(await p.$eval('#erpcard', (e) => e.hidden), 'no erp setting: no card'); await p.close();
    // nothing monitored: no figures
    AV = { groups: [], items: [], summary: {} }; p = await open(erp);
    ok(await p.$eval('#aiband', (e) => e.hidden) && await p.$eval('#inscard', (e) => e.hidden) && /No service named like Microsoft Dynamics/.test(await p.$eval('#erpcur', (e) => e.innerText)), 'nothing monitored: no charts, the ERP card says what to set');
    await p.close();
    ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  } finally { await browser.close(); srv.close(); }
  console.log((bad ? 'FAILED ' : 'ok ') + (n - bad) + '/' + n + ' app-manager-erp checks'); process.exit(bad ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });
