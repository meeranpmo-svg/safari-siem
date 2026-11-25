// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Hyper-V Servers page: no host says how to set up the report script; hosts with CPU / memory / volumes and the forecast, VMs with
// demand against assigned (hostile text stays text), findings; an operator proposes a VM action with a reason; the proposer is
// not offered Approve, another administrator is; a viewer gets no action menu. Stub ITAM; hosts and VMs SYNTHETIC.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node hyperv.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const DASH = path.resolve(__dirname, '../../ui');
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
let USER = 'nora.syn', ROLE = 'operator', HOSTS = false, ACTS = [], INVITED = [];
const VERBS = { start: 'Start', shutdown: 'Shut down (guest)', 'turn-off': 'Turn off', restart: 'Restart (reset)', checkpoint: 'Take a checkpoint' };
const VIEW = () => (HOSTS ? { kpis: { hosts: 1, vms: 2, running: 2, high: 1, stale_hosts: 0 }, verbs: VERBS, actions: ACTS, note: '',
  findings: [{ severity: 'high', code: 'heartbeat', host: 'HV-SYN-01', target: 'DB-SYN-01', title: 'DB-SYN-01: heartbeat LostCommunication <img src=x onerror=alert(1)>', fix: 'Check it from the console' }],
  hosts: [{ name: 'HV-SYN-01', at: new Date().toISOString(), stale: false, cores: 8, cpu_pct: 35, mem_total_mb: 262144, mem_free_mb: 60000,
    nics: [{ name: 'Team-SYN-10G', link_mbps: 10000, rx_bps: 8.6e9, tx_bps: 4e8 }, { name: 'Mgmt-SYN', link_mbps: 100, rx_bps: 2e6, tx_bps: 1e6 }], disk: { latency_ms: 23.5, read_bps: 5e7, write_bps: 2e7 },
    trend: Array.from({ length: 6 }, (_, i) => ({ t: new Date(Date.now() - (6 - i) * 900000).toISOString(), cpu: 30 + i, mem_pct: 70, rx_bps: 8e9, tx_bps: 3e8, disk_ms: 20 })), volumes: [{ name: 'C:\\ClusterStorage\\Volume1', size_gb: 2000, free_gb: 800 }], capacity: { memory: 21, volumes: [{ name: 'C:\\ClusterStorage\\Volume1', days: 90 }] }, vcpu_ratio: 5, snapshots: 14,
    vms: [{ name: 'DB-SYN-01', state: 'running', vcpus: 24, cpu_pct: 40, mem_assigned_mb: 16384, mem_demand_mb: 15800, heartbeat: 'LostCommunication', checkpoints: 0, replication: { state: 'Replicating', health: 'Critical' }, net_rx_bps: 7.2e9, net_tx_bps: 5e7 }, { name: 'APP-SYN-01', state: 'running', vcpus: 16, cpu_pct: 20, mem_assigned_mb: 32768, mem_demand_mb: 6000, heartbeat: 'OkApplicationsHealthy', checkpoints: 1, replication: {} }] }] }
  : { kpis: { hosts: 0 }, hosts: [], findings: [], actions: [], verbs: VERBS, note: 'No Hyper-V host has reported metrics yet: run install/hyperv-report.ps1 on each host' });
const posts = [];
(async () => {
  const srv = http.createServer((req, res) => {
    const u = req.url.split('?')[0]; const json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    const body = (fn) => { let b = ''; req.on('data', (d) => { b += d; }); req.on('end', () => { const j = b ? JSON.parse(b) : null; posts.push([req.method, u, j]); fn(j); }); };
    if (u === '/dashboards/whoami.json') return json(200, { user: USER, role: ROLE });
    if (u === '/api/itam/hyperv') return json(200, VIEW());
    if (u === '/api/itam/hyperv/onboard' && req.method === 'GET') return ROLE === 'admin' ? json(200, { script: { name: 'hyperv-report.ps1', sha256: 'ab'.repeat(32), bytes: 9000 }, invited: INVITED }) : json(403, { error: 'admin only' });
    if (u === '/api/itam/hyperv/onboard') return body((b) => { INVITED = b.hosts.map((h) => ({ host: h, state: 'waiting for the host', created_at: new Date().toISOString(), created_by: USER, expires_at: new Date(Date.now() + 86400000).toISOString() }));
      json(200, { script_sha256: 'ab'.repeat(32), hosts: b.hosts.map((h, i) => ({ host: h, token: 'synthetic' + i + "'tok", expires_at: new Date().toISOString() })) }); });
    if (u === '/api/itam/hyperv/actions') return body((b) => { const a = Object.assign({ id: 'HVAC-00001', status: 'proposed', proposed_by: USER }, b); ACTS = [a]; json(200, a); });
    if (/\/decide$/.test(u)) return body((b) => { ACTS[0].status = b.decision; ACTS[0].decided_by = USER; json(200, ACTS[0]); });
    if (u.startsWith('/api/')) return json(404, { error: 'not in this test' });
    fs.readFile(path.join(DASH, u.replace(/^\/dashboards\//, '/')), (err, d) => { if (err) { res.writeHead(404); res.end(); return; } res.writeHead(200, { 'Content-Type': u.endsWith('.js') ? 'application/javascript' : u.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const URL0 = 'http://127.0.0.1:' + srv.address().port + '/hyperv.html?standalone=1';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(); const errs = [];
  const open = async () => { const p = await browser.newPage({ viewport: { width: 1400, height: 900 } }); p.on('pageerror', (x) => errs.push(x.message)); p.on('dialog', (d) => d.accept('guest stopped answering (synthetic)')); await p.goto(URL0); return p; };
  const toast = async (p) => { await p.waitForSelector('.toast', { timeout: 8000 }); const t = await p.$$eval('.toast', (x) => x.map((e) => e.textContent).join(' | ')); await p.$$eval('.toast', (x) => x.forEach((e) => e.remove())); return t; };
  let p = await open(); await p.waitForFunction(() => /hyperv-report/.test(document.body.innerText));
  ok(/EnrolToken/.test(await p.textContent('#body')), 'setup steps shown'); await p.close();
  HOSTS = true; p = await open(); await p.waitForSelector('.host');
  ok(!(await p.$('img[src="x"]')), 'hostile text stays text');
  const t = await p.textContent('#body');
  ok(/95 % in ~21 days/.test(t) && /full in ~90 days/.test(t) && /vCPU ratio 5:1/.test(t), 'capacity shown');
  ok(/15800 \/ 16384 MB/.test(t) && /Critical/.test(t), 'VM memory and replication');
  ok(/Team-SYN-10G/.test(t) && /10 Gbps/.test(t) && /8\.6 Gbps/.test(t) && /86 %/.test(t) && /Mgmt-SYN/.test(t) && /100 Mbps\s*slow/.test(t), 'network speed per NIC against its link, a slow link flagged');
  ok(/disk latency 23\.5 ms/.test(t) && /7\.2 Gbps \/ 50 Mbps/.test(t), 'disk latency and VM network in / out');
  ok(await p.$eval('#hvr0', (c) => c.getAttribute('role') === 'img' && /CPU %/.test(c.getAttribute('aria-label'))) && await p.$eval('#hvn0', (c) => /Receive Mbps/.test(c.getAttribute('aria-label'))), '24 h trend charts: resources and network');
  ok(await p.$eval('#addh', (b) => b.hidden), 'an operator is not offered Add Hyper-V hosts');
  await p.selectOption('[data-vm="DB-SYN-01"]', 'restart'); ok(/HVAC-00001 proposed/.test(await toast(p)), 'proposed');
  const pr = posts.find((x) => x[1] === '/api/itam/hyperv/actions'); ok(pr && pr[2].host === 'HV-SYN-01' && pr[2].vm === 'DB-SYN-01' && pr[2].action === 'restart' && /synthetic/.test(pr[2].reason), 'action body');
  await p.waitForSelector('.act .pill'); ok(!(await p.$('[data-dec="approved"]')), 'the proposer is not offered Approve'); await p.close();
  USER = 'sec.syn'; ROLE = 'admin'; p = await open(); await p.waitForSelector('[data-dec="approved"]'); await p.click('[data-dec="approved"]'); ok(/approved/.test(await toast(p)), 'another administrator approves');
  await p.waitForFunction(() => /the host runs it on its next report/.test(document.body.innerText)); ok(true, 'says the host runs it'); await p.close();
  // adding hosts: an administrator types the names and gets one command per host (the key only in that command)
  p = await open(); await p.waitForSelector('.host'); await p.click('#addh'); await p.waitForFunction(() => /script fingerprint abab/.test(document.getElementById('onbsha').textContent));
  await p.fill('#onbh', 'HV-SYN-02\nHV-SYN-03'); await p.click('#onbgo'); await p.waitForSelector('#onbout pre');
  const cmds = await p.$$eval('#onbout pre', (x) => x.map((e) => e.textContent));
  const ob = posts.find((x) => x[1] === '/api/itam/hyperv/onboard');
  ok(ob && JSON.stringify(ob[2]) === '{"hosts":["HV-SYN-02","HV-SYN-03"]}', 'the host names, nothing else, sent: ' + JSON.stringify(ob && ob[2]));
  ok(cmds.length === 2 && cmds.every((c, i) => c.includes("'synthetic" + i + "''tok'") && c.includes("'" + 'ab'.repeat(32) + "'") && /\/agent'; /.test(c) && /\/hyperv\/script/.test(c) && /schtasks \/Create \/F \/TN 'Sentra Hyper-V report'/.test(c) && /throw 'the downloaded script does not match/.test(c)),
    'one command per host: its own key (quoted for PowerShell), the fingerprint check, enrol, the scheduled task: ' + cmds[0]);
  ok(/Copy each command now/.test(await p.textContent('#onbout')) && /HV-SYN-02/.test(await p.textContent('#onbinv')) && /waiting for the host/.test(await p.textContent('#onbinv')), 'shown once, and the added hosts listed with their state');
  await p.close();
  USER = 'vera.syn'; ROLE = 'viewer'; p = await open(); await p.waitForSelector('.host'); ok(!(await p.$('[data-vm]')), 'viewer: no action menu'); await p.close();
  ok(!errs.length, 'errors: ' + errs.join(' | '));
  await browser.close(); srv.close();
  console.log(bad ? `${bad}/${n} FAILED` : `OK ${n}/${n} checks`); process.exit(bad ? 1 : 0);
})();
