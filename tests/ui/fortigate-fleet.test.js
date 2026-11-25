// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// FortiGate Fleet page: not connected says what to connect; connected shows the KPIs, what to fix first, the device list
// (health filter, search, model), SD-WAN link state and firmware by model; an operator selects FortiGates and proposes a change;
// another person approves; an approved package install runs; hostile text stays text; a viewer sees no change buttons.
// Stub SIEM; FortiGates, serials and people are SYNTHETIC.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node fortigate-fleet.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const DASH = path.resolve(__dirname, '../../ui');
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
let ROLE = 'operator', USER = 'op.syn', CONNECTED = false;
const dev = (name, health, extra) => Object.assign({ id: 'SN' + name, serial: 'SN' + name, name, adom: 'Sites', model: 'FortiGate-40F', ip: '10.0.0.1', site: 'Site', firmware: '7.2.8', conn: 'up', conf: 'in-sync', ha_mode: 'standalone', ha_members: [], metrics: { cpu: 10, mem: 40, sessions: 900 }, tunnels: [{ name: 't1', up: true }], links: [], findings: [], health }, extra || {});
const FLEET = () => ({ status: { configured: CONNECTED, devices: 3, last_poll_at: '2026-11-25T09:50:00Z', last_error: '', poll_min: 10 },
  kpis: { devices: 3, ok: 1, watch: 0, attention: 1, down: 1, out_of_sync: 1, firmware_behind: 1, tunnels: { up: 2, down: 1 }, links_down: 1, links_out_of_sla: 0, licences_due: 0 },
  devices: [dev('FGT-SITE-09', 'down', { conn: 'down', metrics: null, findings: [{ severity: 'critical', code: 'offline', title: 'FortiManager cannot reach the FortiGate', fix: 'Check FGFM' }] }),
    dev('FGT-SITE-07', 'attention', { conf: 'modified', firmware: '7.2.4', metrics: { cpu: 20, mem: 91, sessions: 5000 }, findings: [{ severity: 'critical', code: 'conserve', title: 'Memory 91 % <img src=x onerror=alert(1)>', fix: 'x' }] }),
    dev('FGT-HQ-01', 'ok', { model: 'FortiGate-60F', firmware: '7.2.10', name: 'FGT-HQ-01' })],
  models: [{ model: 'FortiGate-40F', devices: 2, versions: { '7.2.8': 1, '7.2.4': 1 }, target: null, newest: '7.2.8' }, { model: 'FortiGate-60F', devices: 1, versions: { '7.2.10': 1 }, target: '7.2.10', newest: '7.2.10' }],
  links: [{ device: 'FGT-SITE-07', site: 'Site 7', check: 'hc-internet', member: 'wan2', state: 'down', latency: null, jitter: null, loss: null, sla_ok: null }],
  findings: [{ device: 'FGT-SITE-09', severity: 'critical', title: 'FortiManager cannot reach the FortiGate', fix: 'Check FGFM' }, { device: 'FGT-SITE-07', severity: 'critical', title: 'Memory 91 %', fix: 'x' }], changes_open: 0 });
let CHANGES = [];
const posts = [];
(async () => {
  const srv = http.createServer((req, res) => {
    const u = req.url.split('?')[0]; const json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    const body = (fn) => { let b = ''; req.on('data', (d) => { b += d; }); req.on('end', () => { const j = b ? JSON.parse(b) : null; posts.push([req.method, u, j]); fn(j); }); };
    if (u === '/dashboards/whoami.json') return json(200, { user: USER, role: ROLE });
    if (u === '/api/soc/fortimanager/fleet') return json(200, FLEET());
    if (u === '/api/soc/fortimanager/changes' && req.method === 'GET') return json(200, { changes: CHANGES, types: { 'install-package': 'Install a policy package', 'retrieve-config': 'Retrieve the configuration into FortiManager', 'firmware-upgrade': 'Upgrade FortiOS' }, write_enabled: true });
    if (u === '/api/soc/fortimanager/changes' && req.method === 'POST') return body((b) => { const c = Object.assign({ id: 'FGCH-000001', title: 'Install a policy package', status: 'proposed', proposed_by: USER, executed_here: b.type === 'install-package' }, b); CHANGES = [c]; json(200, c); });
    if (/\/decide$/.test(u)) return body((b) => { CHANGES[0].status = b.decision; CHANGES[0].decided_by = USER; json(200, CHANGES[0]); });
    if (/\/run$/.test(u)) return body(() => { CHANGES[0].status = 'running'; CHANGES[0].task = 77; json(200, CHANGES[0]); });
    if (u === '/api/soc/fortimanager/poll') return body(() => json(200, { devices: 3, last_error: '' }));
    if (u.startsWith('/api/')) return json(404, { error: 'not in this test' });
    fs.readFile(path.join(DASH, u.replace(/^\/dashboards\//, '/')), (err, d) => { if (err) { res.writeHead(404); res.end(); return; } res.writeHead(200, { 'Content-Type': u.endsWith('.js') ? 'application/javascript' : u.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const URL0 = 'http://127.0.0.1:' + srv.address().port + '/fortigate-fleet.html?standalone=1';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(); const errs = [];
  const open = async () => { const p = await browser.newPage({ viewport: { width: 1400, height: 900 } }); p.on('pageerror', (x) => errs.push(x.message)); p.on('dialog', (d) => d.accept('looks right')); await p.goto(URL0); return p; };
  const toast = async (p) => { await p.waitForSelector('.toast', { timeout: 8000 }); const t = await p.$$eval('.toast', (x) => x.map((e) => e.textContent).join(' | ')); await p.$$eval('.toast', (x) => x.forEach((e) => e.remove())); return t; };
  // not connected
  let p = await open();
  await p.waitForFunction(() => /not connected/.test(document.body.innerText));
  ok(await p.$('a[href="connections.html#cn-fmg"]'), 'not connected: links to the connection');
  await p.close();
  // connected
  CONNECTED = true; p = await open();
  await p.waitForSelector('#x-dev table');
  const txt = await p.evaluate(() => document.body.innerText);
  ok(/FortiGates\s*3/.test(txt) && /Down\s*1/.test(txt), 'KPIs: ' + txt.slice(0, 200).replace(/\s+/g, ' '));
  ok(/What to fix first/.test(txt) && /FortiManager cannot reach the FortiGate/.test(txt), 'what to fix first');
  ok(/hc-internet/.test(txt) && /wan2/.test(txt), 'SD-WAN link state');
  ok(/7\.2\.4 × 1/.test(txt) && /behind/.test(txt), 'firmware by model');
  ok(!(await p.$('img[src="x"]')), 'hostile text stays text');
  ok(await p.$$eval('#x-dev tbody tr', (r) => r[0].innerText.includes('FGT-SITE-09')), 'down first');
  await p.click('[data-h="attention"]'); ok((await p.$$('#x-dev tbody tr')).length === 1, 'health filter');
  await p.click('[data-h=""]'); await p.fill('#q', 'HQ'); ok((await p.$$('#x-dev tbody tr')).length === 1, 'search');
  await p.fill('#q', ''); await p.selectOption('#fm', 'FortiGate-40F'); ok((await p.$$('#x-dev tbody tr')).length === 2, 'model filter');
  // propose
  await p.check('[data-sel="FGT-SITE-07"]'); await p.check('[data-sel="FGT-SITE-09"]');
  ok(/2 selected/.test(await p.textContent('#selc')), 'selection counted');
  await p.click('#plan'); await p.waitForSelector('#pf');
  await p.fill('#pk', 'sites-std'); await p.fill('#rs', 'undo the change made on the device (synthetic)'); await p.click('#psend');
  ok(/FGCH-000001 proposed/.test(await toast(p)), 'proposed');
  const pr = posts.find((x) => x[1] === '/api/soc/fortimanager/changes');
  ok(pr && pr[2].type === 'install-package' && pr[2].package === 'sites-std' && pr[2].devices.join() === 'FGT-SITE-07,FGT-SITE-09', 'propose body: ' + JSON.stringify(pr && pr[2]));
  await p.waitForSelector('#x-chg .act');
  ok(!(await p.$('[data-dec="approved"]')), 'the proposer is not offered Approve');
  await p.close();
  // another person approves, then runs
  USER = 'sec.syn'; p = await open(); await p.waitForSelector('[data-dec="approved"]');
  await p.click('[data-dec="approved"]'); ok(/approved/.test(await toast(p)), 'approved by another person');
  await p.waitForSelector('[data-run]'); await p.click('[data-run]'); ok(/running \(FortiManager task 77\)/.test(await toast(p)), 'run');
  await p.close();
  // viewer: no buttons
  ROLE = 'viewer'; USER = 'view.syn'; p = await open(); await p.waitForSelector('#x-dev table');
  ok(!(await p.$('[data-sel]')) && !(await p.$('#plan')) && await p.$eval('#poll', (b) => b.hidden), 'viewer: read only');
  await p.close();
  ok(!errs.length, 'errors: ' + errs.join(' | '));
  await browser.close(); srv.close();
  console.log(bad ? `${bad}/${n} FAILED` : `OK ${n}/${n} checks`); process.exit(bad ? 1 : 0);
})();
