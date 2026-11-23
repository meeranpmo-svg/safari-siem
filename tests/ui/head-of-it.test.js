// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for head-of-it.html (IT Command Center) against stubbed IT Asset Management and SIEM APIs: with sources
// connected every figure is the live one (application availability, open problems from the duty desk, SLA summed from
// each engineer's "x of y on time", change success from applied vs failed in 30 days, backups, patches, storage, one
// expiring-next list over certificates / licences / contracts / warranty); with nothing connected every card says what to
// connect - no 0 %, no NaN, no sample text; with every server failing the page still draws; a viewer is told the role.
// Data is SYNTHETIC. Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node head-of-it.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const DASH = path.resolve(__dirname, '../../ui');
let WHO = { user: 'omar.syn', role: 'operator' }, MODE = 'live';
let n = 0, bad = 0;
const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const NOW = Date.now(), D = 864e5, iso = (t) => new Date(t).toISOString();

const LIVE = {
  '/api/itam/infra-overview': {
    register: { available: true, total: 5, servers: { total: 4, physical: 2, virtual: 2, by_os: {} }, network: { total: 1, by_vendor: {} }, storage: { total: 1 },
      warranty: { expired: 0, within_90d: 1, items: [{ id: 'a1', name: 'ESX-SYN-02', type: 'server', end: iso(NOW + 40 * D).slice(0, 10) }] } },
    backup: { available: true, assets: 4, protected: 3, stale: 0, failed: 1, none: 0, exempt: 0, protected_pct: 75 },
    patch: { available: true, computers: 4, reported: 4, compliant: 3, critical_missing: 1, compliant_pct: 75, worst: [] },
    lifecycle: { available: true, eol: 1, soon: 0, items: [{ name: 'SW-SYN-01', type: 'network', product: 'Cisco IOS 12.2', status: 'eol', eol: '2023-07-31', days: -400 }] },
    storage: { available: true, arrays: 1, read: 1, used_pct: 83.4, size_bytes: 2e13, used_bytes: 1.668e13, failed_disks: 0, list: [{ name: 'NETAPP-SYN-HQ', used_pct: 83.4, size_bytes: 2e13, failed_disks: 0 }] },
    contracts: { available: true, contracts: 1, expired: 0, expiring: 1, renewing: [{ vendor: 'Cisco', product: 'SmartNet SYN', end: iso(NOW + 17 * D).slice(0, 10), days_left: 17, state: 'expiring' }] },
    databases: { available: true, registered: 2 },
  },
  '/api/itam/certs': { counts: { expiring: 1 }, endpoints: [{ id: 'CE-0001', label: 'claims-syn.example', host: 'claims-syn.example', port: 443, owner: 'apps team', days_left: 9 }, { id: 'CE-0002', host: 'far-syn', port: 443, days_left: 300 }] },
  '/api/itam/licences': { licences: [{ publisher: 'Microsoft', product: 'M365 E3 SYN', expiry: iso(NOW + 60 * D).slice(0, 10) }, { publisher: 'Adobe', product: 'Far away SYN', expiry: iso(NOW + 400 * D).slice(0, 10) }] },
  '/api/soc/netops/avail': { summary: { total: 10, online: 9, offline: 1, unknown: 0 }, items: [{ id: 'h1', name: 'FW-SYN-DR', ip: '10.9.0.1', site: 'DR', status: 'offline', duration_s: 7200 }] },
  '/api/soc/db/oracle': { instances: [{ instance: 'ERP', host: 'db-syn-1', state: 'up', issues: [] }, { instance: 'HR', host: 'db-syn-2', state: 'up', issues: [{ text: 'tablespace USERS 93% full' }] }] },
  '/api/soc/integrations/apm/status': { configured: true, enabled: true },
  '/api/soc/integrations/apm/monitors': { items: [{ name: 'IIRIS Portal', type: 'URL', availability: 'up', managed: true }, { name: 'Claims API', type: 'REST', host: 'app-syn-3', availability: 'down', managed: true, message: 'connection refused' },
    { name: 'Old app', availability: 'down', managed: false }, { name: 'CRM', availability: 'up', managed: true }] },
  '/api/soc/integrations/apm/alarms': { items: [{ name: 'Claims API', severity: 'critical', attribute: 'Availability' }, { name: 'CRM', severity: 'clear' }] },
  '/api/soc/duty/items': { items: [{ id: 'DI-1', title: '<b>Core switch CPU 97%</b>', severity: 'critical', engineer: 'network', status: 'open', detected_at: NOW - 5 * 36e5 },
    { id: 'DI-2', title: 'Exchange queue growing', severity: 'high', engineer: 'exchange', status: 'investigating', owner: 'ali.syn', detected_at: NOW - 36e5 },
    { id: 'DI-3', title: 'Disk 81% on APP-SYN-01', severity: 'medium', engineer: 'windows', status: 'open', detected_at: NOW - 2 * D }] },
  '/api/soc/duty/kpis': { engineers: [
    { engineer: 'network', name: 'AI Network Engineer', kpis: [{ id: 'sla_pct', value: 75, status: 'bad', detail: '3 of 4 on time' }, { id: 'fix_h', value: 6, status: 'ok' }], counts: { open: 1 } },
    { engineer: 'windows', name: 'AI Windows Administrator', kpis: [{ id: 'sla_pct', value: 100, status: 'ok', detail: '6 of 6 on time' }, { id: 'fix_h', value: 2, status: 'ok' }], counts: { open: 1 } },
    { engineer: 'pki', name: 'Not connected SYN', not_connected: true, kpis: [{ id: 'sla_pct', value: null, detail: '0 of 0 on time' }], counts: { open: 0 } }] },
  '/api/soc/netops/changes': { items: [{ id: 'CP-7', device: 'sw-syn-01', title: 'IOS upgrade SW-SYN-01', status: 'approved', decided_at: NOW - D, decided_by: 'syed' },
    { id: 'CP-6', title: 'VLAN 40 added', status: 'validated', applied_at: NOW - 2 * D }, { id: 'CP-5', title: 'Old change', status: 'applied', applied_at: NOW - 60 * D },
    { id: 'CP-4', title: 'ACL rewrite SYN', status: 'execution-failed', history: [{ at: NOW - 3 * D, action: 'rolled back' }] }] },
  '/api/soc/sysadmin/changes': { items: [{ id: 'SCHG-3', title: 'Install KB5031', status: 'applied', applied_at: NOW - 4 * D }, { id: 'SCHG-2', title: 'Raise IIS queue SYN', status: 'proposed', requested_by: 'omar.syn' }] },
};
// Workflow Automation's attention(who), synthetic, in the engine's shape
LIVE['/api/itam/workflow/attention'] = { summary: { approvals: 1, queue_open: 3, overdue: 1, at_risk: 1, to_accept: 0, raised_open: 0, raised_late: 0, functions: [], all_overdue: 2, recurring: 1,
    teams: [{ team: 'dba', name: 'Database team (DBA)', open: 2, overdue: 1, n: 5, on_time: 4, rate: 0.71 }, { team: 'network', name: 'Network team', open: 1, overdue: 1, n: 0, on_time: 0, rate: 0.5 }], items: [] },
  priorities: [{ kind: 'Request approval', ref: 'REQ-2026-0007', text: '<b>Open 443 for the portal</b> - Network change, from Administration (adm.syn)', page: 'workflow-automation.html#req=REQ-2026-0007', why: [['a business request waiting for your approval', 45]] },
    { kind: 'Request overdue', ref: 'REQ-2026-0003', text: 'Q4 DB accounts - Database team (DBA), due 2026-11-10 08:00', page: 'workflow-automation.html#req=REQ-2026-0003', why: [['a request to the IT team past its due date', 40], ['escalated', 10]] }] };
let S = JSON.parse(JSON.stringify(LIVE));

(async () => {
  const srv = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://x'), json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u.pathname === '/dashboards/whoami.json') return json(200, WHO);
    if (u.pathname.startsWith('/api/')) {
      if (MODE === 'down') return json(404, { error: 'not found' });
      if (WHO.role === 'viewer' && /infra-overview|changes/.test(u.pathname)) return json(403, { error: 'forbidden' });
      return S[u.pathname] ? json(200, S[u.pathname]) : json(404, { error: 'not found' });
    }
    const f = path.join(DASH, u.pathname.replace(/^\/dashboards\//, '/')); if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (err, d) => { if (err) { res.writeHead(404); res.end(); return; } res.writeHead(200, { 'Content-Type': u.pathname.endsWith('.js') ? 'application/javascript' : u.pathname.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const url = 'http://127.0.0.1:' + srv.address().port + '/dashboards/head-of-it.html';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  let page;
  const as = async (who) => { WHO = who; if (page) await page.close(); page = await browser.newPage({ viewport: { width: 1400, height: 1000 } }); page.on('pageerror', (x) => errs.push(x.message)); await page.goto(url); await page.waitForFunction(() => /updated/.test(document.getElementById('up').textContent), null, { timeout: 15000 }); };
  const txt = (sel) => page.innerText(sel);
  const all = async () => (await txt('#rings')) + (await txt('#kk')) + (await page.evaluate(() => [].map.call(document.querySelectorAll('.g'), (g) => g.innerText).join('\n')));   // the hero's own wording aside
  try {
    await as({ user: 'omar.syn', role: 'operator' });
    const k = await txt('#kk'), rg = await txt('#rings');
    ok(/66\.7%/.test(rg) && /2 of 3 application monitors up/.test(rg), 'service availability: managed monitors only: ' + rg.replace(/\s+/g, ' '));
    ok(/90%/.test(rg) && /9 of 10 reachable/.test(rg), 'host availability ring');
    ok(/90%/.test(rg) && /9 of 10 serious problems on time/.test(rg), 'SLA summed across engineers (3/4 + 6/6), not an average of percentages; not-connected engineer skipped');
    ok(/APPLICATIONS\s*3\s*1 down · 1 critical alarms/i.test(k), 'applications tile: ' + k.slice(0, 200));
    ok(/OPEN PROBLEMS\s*3\s*2 critical \/ high · 1 unassigned/i.test(k), 'open problems from the duty desk');
    ok(/CHANGE SUCCESS\s*66\.7%\s*2 applied · 1 failed/i.test(k), 'change success: applied/validated vs execution-failed in 30 days, old change ignored');
    ok(/PATCH COMPLIANCE\s*75%/i.test(k) && /BACKUP SUCCESS\s*75%/i.test(k), 'patch + backup tiles');
    ok(/TIME TO FIX \(MEDIAN\)\s*2 h/i.test(k), 'median time to fix across engineers');
    const ap = await txt('#apps'); ok(/Claims API/.test(ap) && /connection refused/.test(ap) && !/Old app/.test(ap), 'down monitors listed, unmanaged ignored');
    const pr = await txt('#prob'); ok(pr.indexOf('Core switch') < pr.indexOf('Exchange queue') && /unassigned/.test(pr) && /ali\.syn/.test(pr), 'problems by severity with owner');
    ok(!(await page.$('#prob b b')), 'problem title is escaped text');
    const sl = await txt('#sla'); ok(/AI Network Engineer/.test(sl) && /3 of 4 on time/.test(sl) && !/Not connected SYN/.test(sl), 'SLA per engineer, not-connected left out');
    const ch = await txt('#chg'); ok(/IOS upgrade SW-SYN-01/.test(ch) && /Raise IIS queue SYN/.test(ch) && /ACL rewrite SYN/.test(ch) && !/Old change/.test(ch), 'changes: failed, waiting, approved');
    const ex = await txt('#exp');
    ok(/claims-syn\.example/.test(ex) && /in 9 d/.test(ex) && /M365 E3 SYN/.test(ex) && /SmartNet SYN/.test(ex) && /ESX-SYN-02/.test(ex) && !/far-syn|Far away SYN/.test(ex), 'expiring next: certificate, licence, contract, warranty within 90 days');
    ok(ex.indexOf('claims-syn') < ex.indexOf('SmartNet') && ex.indexOf('SmartNet') < ex.indexOf('M365'), 'expiring list sorted by date');
    ok(/NETAPP-SYN-HQ/.test(await txt('#sto')) && /forecast needs history/.test(await txt('#sto')), 'storage now, no invented forecast');
    ok(/tablespace USERS 93% full/.test(await txt('#db')) && /SW-SYN-01/.test(await txt('#eol')) && /FW-SYN-DR/.test(await txt('#off')), 'databases, end of life, offline hosts');
    let a = await all(); ok(!/NaN|undefined|null|sample|demonstration/i.test(a), 'no NaN / undefined / sample text: ' + (a.match(/.{0,60}(NaN|undefined|null|sample|demonstration).{0,60}/i) || [''])[0]);
    ok(await page.isVisible('#live'), 'live badge');
    const wf = await txt('#wf');
    ok(/2\s*overdue across the IT teams/.test(wf) && /1\s*waiting for your approval/.test(wf) && /Database team \(DBA\)/.test(wf) && /4 of 5/.test(wf) && /no history/.test(wf), 'Workflow Automation: counts and each team: ' + wf.replace(/\s+/g, ' ').slice(0, 200));
    ok(wf.indexOf('REQ-2026-0003') < wf.indexOf('REQ-2026-0007') && /<b>Open 443/.test(wf) && !(await page.$('#wf b')) && !!(await page.$('#wf a[href="workflow-automation.html#req=REQ-2026-0007"]')) && /keep coming back/.test(wf), 'Workflow: ranked by points (50 before 45), a hostile title stays text, links to the request');
    await page.click('#kk [data-go="backup.html"]'); await page.waitForURL(/backup\.html/); ok(true, 'a tile opens its page');

    // nothing connected
    S = { '/api/itam/infra-overview': { register: { available: false, why: 'x' }, backup: { available: false, why: 'Backup Status is not installed (install/add-backup.sh)' }, patch: { available: false, why: 'ManageEngine is not installed' },
      lifecycle: { available: false, why: 'End of Life is not installed' }, storage: { available: false, why: 'Storage is not installed' }, contracts: { available: false, why: 'no support contract recorded' } },
      '/api/itam/licences': { licences: [] }, '/api/soc/integrations/apm/status': { configured: false }, '/api/soc/db/oracle': { instances: [] }, '/api/soc/netops/avail': { summary: { total: 0, online: 0, offline: 0, unknown: 0 }, items: [] },
      '/api/soc/duty/items': { items: [] }, '/api/soc/duty/kpis': { engineers: [] }, '/api/soc/netops/changes': { items: [] }, '/api/soc/sysadmin/changes': { items: [] } };
    await as({ user: 'omar.syn', role: 'operator' });
    a = await all();
    ok(/not measured/.test(await txt('#rings')) && !/\b0%/.test(await txt('#rings')), 'rings: not measured, never 0 %');
    ok(/Applications Manager is not connected/.test(await txt('#apps')) && /No host or device is monitored yet/.test(await txt('#off')) && /No Oracle instance reports/.test(await txt('#db')), 'SIEM cards say what to connect');
    ok(/not installed/.test(await txt('#sto')) && /not installed/.test(await txt('#bk')) && /not installed/.test(await txt('#eol')), 'ITAM cards name the add-on');
    ok(/Workflow Automation is not installed on the server/.test(await txt('#wf')), 'Workflow Automation not installed: said, never zeros');
    ok(/No open problem/.test(await txt('#prob')) && /No engineer has a connected source/.test(await txt('#sla')) && /certificates: Certificates is not installed/.test(await txt('#exp')), 'duty desk, SLA and expiring list honest');
    ok(!/NaN|undefined|null|sample/i.test(a), 'no NaN / sample: ' + (a.match(/.{0,60}(NaN|undefined|null|sample).{0,60}/i) || [''])[0]);

    MODE = 'down';
    await as({ user: 'omar.syn', role: 'operator' });
    a = await all();
    ok(/is not installed on the server/.test(a) && !/NaN|undefined/.test(a) && !(await page.isVisible('#live')), 'every server failing: each card says so, no live badge');

    MODE = 'live'; S = JSON.parse(JSON.stringify(LIVE));
    await as({ user: 'nora.syn', role: 'viewer' });
    ok(/needs a higher role/.test(await txt('#kk')) && /needs a higher role/.test(await txt('#chg')), 'viewer told a higher role is needed');
    ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  } finally { await browser.close(); srv.close(); }
  console.log(bad ? 'FAILED ' + bad + '/' + n + ' checks' : 'OK ' + n + '/' + n + ' checks'); process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
