// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for infra-manager.html (IT Infrastructure Manager) against the REAL IT Asset Management engine
// (engine/infra-overview.js, register + add-ons) and a stubbed SIEM: with sources connected every figure is the live one
// (servers from the register, availability, Oracle, Applications Manager, approved changes only, backups, Endpoint Central,
// storage, end of life, contracts); with nothing connected every card says what to connect - no 0 %, no NaN, no sample
// badge; a viewer is told the role. Data is SYNTHETIC. Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node infra-manager.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const ITAM = path.resolve(__dirname, '../../backend/itam'), DASH = path.resolve(__dirname, '../../ui');
const H = require(path.join(ITAM, 'tests/helpers.js'));
let WHO = { user: 'omar.syn', role: 'operator' }, SIEM = 'live';
let n = 0, bad = 0;
const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const ADM = { user: 'syed', role: 'admin', ip: '' }, NOW = Date.now();

(async () => {
  const e = await H.startApp({ noAi: true });
  const A = e.app.assets, mk = (o) => A.create(Object.assign({ status: 'in_use' }, o), ADM);
  mk({ name: 'ESX-SYN-01', type: 'server', os: 'VMware ESXi 7.0', mgmt_ip: '10.6.0.1' }); mk({ name: 'ESX-SYN-02', type: 'server', os: 'VMware ESXi 7.0', mgmt_ip: '10.6.0.2' });
  mk({ name: 'APP-SYN-01', type: 'vm', os: 'Windows Server 2019' }); mk({ name: '<i>VM-SYN-X</i>', type: 'vm', os: 'Oracle Linux 8' });
  mk({ name: 'SW-SYN-01', type: 'network', vendor: 'Cisco', mgmt_ip: '10.6.1.1', warranty: { end: '2025-02-01' } });
  require(path.join(ITAM, 'engine/infra-overview')).registerInfraOverview(e.app.srv, e.app);
  { // Workflow Automation (the real engine): omar leads the network team (a change waits for him) and works in the DBA team (a request is overdue there)
    const WFM = require(path.join(ITAM, 'engine/workflow-auto')), W = WFM.createWorkflow(e.app, { noTimer: true }); WFM.registerWorkflow(e.app.srv, e.app, W);
    W.settingsSave({ version: 0, teams: { dba: ['omar.syn'], network: ['net.syn'] }, leads: { network: ['omar.syn'] } }, { user: 'syed', role: 'admin', ip: '' });
    W.create({ type: 'net-change', from: 'admin', title: 'Open 443 for the <img src=x onerror=window.__wfx=1> portal', details: 'new portal', priority: 'high' }, { user: 'adm.syn', role: 'admin', ip: '' });
    const late = W.create({ type: 'db-user-review', from: 'audit', title: 'Q4 DB accounts', details: 'all DBA accounts' }, { user: 'aud.syn', role: 'viewer', ip: '' });
    const col = e.app.store.collection('wf_requests'), lr = col.get(late.id); lr.due = new Date(Date.now() - 3600000).toISOString(); col.put(lr); }
  const live = () => {
    e.app.addons.backup = { view: () => ({ platforms: [{ id: 'veeam' }], summary: { assets: 4, protected: 3, stale: 0, failed: 1, none: 0, exempt: 0 } }) };
    e.app.addons.manageengine = { computers: () => ({ computers: [{ name: 'APP-SYN-01', missing: 0, critical: 0 }, { name: 'PC-SYN-7', missing: 4, critical: 1 }, { name: 'PC-SYN-8', missing: 0, critical: 0 }, { name: 'PC-SYN-9', missing: 0, critical: 0 }] }) };
    e.app.addons.storage = { view: () => ({ arrays: [{ at: new Date(NOW).toISOString(), platform: { id: 'n1', label: 'NETAPP-SYN-HQ' }, capacity: { used_pct: 83.4, size_bytes: 2e13 }, disks: { failed: 0 }, worst: 'medium' }], summary: { arrays: 1, read: 1, used_pct: 83.4, size_bytes: 2e13, used_bytes: 1.668e13, failed_disks: 0 } }) };
    e.app.addons.supportContracts = { view: () => ({ contracts: [{ vendor: 'Cisco', product: 'SmartNet SYN', end: '2026-11-10', days_left: 17, state: 'expiring' }], summary: { contracts: 1, expiring: 1, expired: 0, uncovered_assets: 2 } }) };
    e.app.addons.lifecycle = { view: () => ({ summary: { eol: 1, soon: 1, isolation_required: 1 }, items: [{ name: 'SW-SYN-01', type: 'network', product: 'Cisco IOS 12.2', status: 'eol', eol: '2023-07-31', days: -400 }, { name: 'ESX-SYN-02', type: 'server', product: 'VMware ESXi 7.0', status: 'soon', eol: '2027-04-02', days: 160 }] }) };
    e.app.addons.dbHealth = { databases: () => ({ databases: [{ id: 'd1' }, { id: 'd2' }] }) };
  };
  const none = () => { ['backup', 'manageengine', 'storage', 'supportContracts', 'lifecycle', 'dbHealth'].forEach((k) => { delete e.app.addons[k]; }); };
  const S = {
    '/api/soc/netops/avail': { summary: { total: 10, online: 9, offline: 1, unknown: 0 }, items: [{ id: 'h1', name: 'FW-SYN-DR', ip: '10.9.0.1', site: 'DR', status: 'offline', duration_s: 7200 }, { id: 'h2', name: 'ESX-SYN-01', ip: '10.6.0.1', status: 'online' }] },
    '/api/soc/db/oracle': { instances: [{ instance: 'ERP', host: 'db-syn-1', state: 'up', up: true, issues: [] }, { instance: 'HR', host: 'db-syn-2', state: 'up', up: true, issues: [{ text: 'tablespace USERS 93% full' }] }] },
    '/api/soc/integrations/apm/status': { configured: true, enabled: true },
    '/api/soc/integrations/apm/monitors': { items: [{ name: 'IIRIS Portal', type: 'URL', availability: 'up', managed: true }, { name: 'Claims API', type: 'REST', host: 'app-syn-3', availability: 'down', managed: true }, { name: 'Old app', availability: 'down', managed: false }, { name: 'CRM', availability: 'up', managed: true }] },
    '/api/soc/netops/changes': { items: [{ id: 'CP-7', device: 'sw-syn-01', title: 'IOS upgrade SW-SYN-01', status: 'approved', decided_at: NOW - 864e5, decided_by: 'syed' }, { id: 'CP-6', device: 'fw', title: 'already applied', status: 'applied', decided_at: NOW - 2 * 864e5 }] },
    '/api/soc/sysadmin/changes': { items: [{ id: 'SCHG-3', device: 'app-syn-01', title: 'Install KB5031', status: 'approved', decided_at: NOW - 3600e3, decided_by: 'ali.syn' }, { id: 'SCHG-2', title: 'waiting', status: 'proposed' }] },
  };
  const srv = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://x'), json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u.pathname === '/dashboards/whoami.json') return json(200, WHO);
    if (u.pathname.startsWith('/api/itam/')) {
      if (SIEM === 'none') return json(404, { error: 'not found' });
      const h = Object.assign({}, req.headers, { 'x-sentra-proxy-secret': H.SECRET, 'x-auth-user': WHO.user, 'x-auth-role': WHO.role });
      const up = http.request({ host: '127.0.0.1', port: e.port, method: req.method, path: req.url, headers: h }, (r) => { res.writeHead(r.statusCode, r.headers); r.pipe(res); });
      req.pipe(up); return;
    }
    if (u.pathname.startsWith('/api/soc/')) {
      if (SIEM === 'none') return json(404, { error: 'not found' });
      if (WHO.role === 'viewer' && /changes/.test(u.pathname)) return json(403, { error: 'forbidden' });
      return S[u.pathname] ? json(200, S[u.pathname]) : json(404, { error: 'not found' });
    }
    if (u.pathname.startsWith('/api/')) return json(404, { error: 'not in this test' });
    const f = path.join(DASH, u.pathname.replace(/^\/dashboards\//, '/')); if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (err, d) => { if (err) { res.writeHead(404); res.end(); return; } res.writeHead(200, { 'Content-Type': u.pathname.endsWith('.js') ? 'application/javascript' : u.pathname.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const url = 'http://127.0.0.1:' + srv.address().port + '/dashboards/infra-manager.html';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  let page;
  const as = async (who) => { WHO = who; if (page) await page.close(); page = await browser.newPage({ viewport: { width: 1400, height: 1000 } }); page.on('pageerror', (x) => errs.push(x.message)); await page.goto(url); await page.waitForFunction(() => /updated/.test(document.getElementById('up').textContent), null, { timeout: 15000 }); };
  const txt = (sel) => page.innerText(sel);
  try {
    live(); SIEM = 'live';
    await as({ user: 'omar.syn', role: 'operator' });
    const k = await txt('#kk'), rg = await txt('#rings'), all = (await txt('#rings')) + (await txt('#kk')) + (await txt('.g'));
    ok(/SERVERS\s*4\s*2 physical · 2 virtual/i.test(k), 'servers from the register: ' + k.slice(0, 120));
    ok(/NETWORK DEVICES\s*1/i.test(k) && /1 monitored offline/.test(k), 'network devices from the register, offline from Server Availability');
    ok(/DATABASE INSTANCES\s*2\s*1 with issues · 2 registered/i.test(k), 'databases: Oracle collector + registered');
    ok(/BACKUPS OK\s*75%/i.test(k) && /1 failed/.test(k), 'backups 3 of 4');
    ok(/PATCH COMPLIANCE\s*75%/i.test(k) && /3 of 4 computers fully patched · 1 missing critical/.test(k), 'patch compliance from Endpoint Central');
    ok(/LEGACY \/ EOL DEVICES\s*1/i.test(k), 'end of life from the lifecycle page');
    ok(/66\.7%/.test(rg) && /2 of 3 monitors up/.test(rg), 'application availability: managed monitors only (2 of 3): ' + rg.replace(/\s+/g, ' '));
    ok(/90%/.test(rg) && /9 of 10 reachable/.test(rg) && /3 of 4 protected/.test(rg), 'availability and backup rings');
    ok(/Claims API/.test(await txt('#apps')) && !/Old app/.test(await txt('#apps')), 'down monitors listed, unmanaged ignored');
    ok(/FW-SYN-DR/.test(await txt('#off')) && /2 h/.test(await txt('#off')), 'offline host with duration');
    ok(/tablespace USERS 93% full/.test(await txt('#db')), 'Oracle issue shown');
    ok(/NETAPP-SYN-HQ/.test(await txt('#sto')) && /83\.4%/.test(await txt('#sto')) && /forecast needs capacity history/.test(await txt('#sto')), 'storage: current reading, no invented forecast');
    ok(/PC-SYN-7/.test(await txt('#pat')), 'worst-patched computer listed');
    ok(/SW-SYN-01/.test(await txt('#eol')) && /isolation/.test(await txt('#eol')), 'end of life list');
    const ch = await txt('#chg'); ok(/IOS upgrade SW-SYN-01/.test(ch) && /Install KB5031/.test(ch) && !/already applied/.test(ch) && !/waiting/.test(ch), 'approved, not applied, changes only (network + server)');
    ok(/Cisco/.test(await txt('#ren')) && /in 17 d/.test(await txt('#ren')) && /warranty: 1 expired/i.test(await txt('#ren')), 'contracts renewing and warranty');
    ok(!/NaN|undefined|null|sample/i.test(all), 'no NaN / undefined / sample text: ' + (all.match(/.{0,60}(NaN|undefined|null|sample).{0,60}/i) || [''])[0]);
    ok(!(await page.$('#kk i, #ren i')) && (await page.isVisible('#live')), 'names are text; live badge');
    { const w = await txt('#wf');
      ok(/1\s*overdue across the IT teams/.test(w) && /1\s*waiting for your approval/.test(w) && /1\s*open in your team queue/.test(w) && /1\s*overdue in your queue/.test(w) && /Database team \(DBA\)/.test(w), 'Workflow Automation from the real engine: counts and teams: ' + w.replace(/\s+/g, ' ').slice(0, 240));
      ok(/Open 443 for the <img/.test(w) && !(await page.$('#wf img')) && !(await page.evaluate(() => window.__wfx)) && /Q4 DB accounts/.test(w) && !!(await page.$('#wf a[href^="workflow-automation.html#req=REQ-"]')), 'Workflow: the approval and the overdue request listed and linked; a hostile title stays text'); }
    await page.click('#kk [data-go="backup.html"]'); await page.waitForURL(/backup\.html/); ok(true, 'a tile opens its page');

    none(); SIEM = 'live'; S['/api/soc/integrations/apm/status'] = { configured: false }; S['/api/soc/db/oracle'] = { instances: [] }; S['/api/soc/netops/avail'] = { summary: { total: 0, online: 0, offline: 0, unknown: 0 }, items: [] };
    await as({ user: 'omar.syn', role: 'operator' });
    let b = (await txt('#rings')) + (await txt('#kk')) + (await txt('.g'));
    ok(/not measured/.test(await txt('#rings')) && !/\b0%/.test(await txt('#rings')), 'rings: not measured, never 0 %');
    ok(/Applications Manager is not connected/.test(await txt('#apps')) && /No host or device is monitored yet/.test(await txt('#off')) && /No Oracle instance reports/.test(await txt('#db')), 'SIEM cards say what to connect');
    ok(/not installed/.test(await txt('#sto')) && /not installed/.test(await txt('#pat')) && /not installed/.test(await txt('#eol')), 'ITAM cards name the add-on to install');
    ok(/SERVERS\s*4/i.test(await txt('#kk')), 'the register still counts');
    ok(!/NaN|undefined|null|sample/i.test(b), 'no NaN / sample: ' + (b.match(/.{0,60}(NaN|undefined|null|sample).{0,60}/i) || [''])[0]);

    SIEM = 'none';
    await as({ user: 'omar.syn', role: 'operator' });
    b = (await txt('#rings')) + (await txt('#kk')) + (await txt('.g'));
    ok(/is not installed on the server/.test(b) && !/NaN|undefined/.test(b) && !(await page.isVisible('#live')), 'every server failing: each card says so, no live badge: ' + b.slice(0, 900));

    SIEM = 'live'; live();
    await as({ user: 'nora.syn', role: 'viewer' });
    ok(/needs a higher role/.test(await txt('#kk')), 'viewer told a higher role is needed: ' + (await txt('#kk')));
    ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  } finally { await browser.close(); srv.close(); await e.close(); }
  console.log(bad ? 'FAILED ' + bad + '/' + n + ' checks' : 'OK ' + n + '/' + n + ' checks'); process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
