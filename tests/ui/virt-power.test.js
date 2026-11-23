// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for virt-power.html against the REAL IT Asset Management engine (engine/virt-power.js) holding a synthetic
// vCenter + Nutanix collection. Clicks through: hosts and VMs with only the actions their state allows; an operator asks
// for an ESXi host restart (the plan shows the failed cluster-room check and commands addressed by ID); the requester sees
// no Approve; an administrator approves with an accepted risk; the approver sees no "Record as run"; another operator
// records it; an admin records a host's iDRAC address; a viewer sees no action buttons. Data is SYNTHETIC.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node virt-power.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const ITAM = path.resolve(__dirname, '../../backend/itam'), DASH = path.resolve(__dirname, '../../ui');
const H = require(path.join(ITAM, 'tests/helpers.js'));
let WHO = { user: 'ali', role: 'operator' };
let n = 0, bad = 0;
const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const GB = 1073741824;

(async () => {
  const e = await H.startApp({ noAi: true });
  const at = new Date(Date.now() - 5 * 60000).toISOString(), S = e.app.store;
  S.collection('virt_platforms').put({ id: 'vp_v', kind: 'vcenter', label: 'VC-SYN' });
  S.collection('virt_capacity').put({ id: 'vp_v', kind: 'vcenter', label: 'VC-SYN', at, clusters: [{ id: 'domain-c1', name: 'SYN-PROD', drs: true }],
    hosts: [{ id: 'host-11', name: 'esx-syn-01', cluster_id: 'domain-c1', cluster: 'SYN-PROD', state: 'connected', maintenance: false, mem_bytes: 512 * GB, mem_used_bytes: 300 * GB, ip: '10.99.0.11' },
      { id: 'host-12', name: 'esx-syn-02', cluster_id: 'domain-c1', cluster: 'SYN-PROD', state: 'connected', maintenance: false, mem_bytes: 512 * GB, mem_used_bytes: 480 * GB },
      { id: 'host-14', name: 'esx-syn-04', cluster_id: null, cluster: 'Standalone hosts', state: 'notResponding', maintenance: false }],
    vms: [{ id: 'vm-101', name: 'APP-SYN-1', host_id: 'host-11', power: 'on', mem_mb: 131072, tools: 'running', ips: ['10.99.1.101', '10.99.2.101', 'fd00::1'] },
      { id: 'vm-102', name: '<img src=x onerror=alert(1)>', host_id: 'host-11', power: 'on', mem_mb: 4096, tools: 'not-running' },
      { id: 'vm-103', name: 'OFF-SYN-1', host_id: 'host-12', power: 'off', mem_mb: 4096 }] });
  require(path.join(ITAM, 'engine/virt-power')).registerVirtPower(e.app.srv, e.app, { noTimer: true });
  e.app.addons.virtCapacity = { report: () => ({}), run: async () => ({}) };   // "installed"; the plans read the store

  const srv = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://x'), json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u.pathname === '/dashboards/whoami.json') return json(200, WHO);
    if (u.pathname.startsWith('/api/itam/')) {
      const h = Object.assign({}, req.headers, { 'x-sentra-proxy-secret': H.SECRET, 'x-auth-user': WHO.user, 'x-auth-role': WHO.role });
      const up = http.request({ host: '127.0.0.1', port: e.port, method: req.method, path: req.url, headers: h }, (r) => { res.writeHead(r.statusCode, r.headers); r.pipe(res); });
      req.pipe(up); return;
    }
    if (u.pathname.startsWith('/api/')) return json(404, { error: 'not in this test' });
    const f = path.join(DASH, u.pathname); if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (err, d) => { if (err) { res.writeHead(404); res.end(); return; } res.writeHead(200, { 'Content-Type': u.pathname.endsWith('.js') ? 'application/javascript' : u.pathname.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const url = 'http://127.0.0.1:' + srv.address().port + '/virt-power.html';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  let page;
  const as = async (who) => { WHO = who; if (page) await page.close(); page = await browser.newPage({ viewport: { width: 1450, height: 950 } }); page.on('pageerror', (x) => errs.push(x.message)); page.on('dialog', (d) => { errs.push('dialog: ' + d.message()); d.dismiss(); }); await page.goto(url); await page.waitForSelector('#targets table'); };
  const txt = (sel) => page.textContent(sel);
  const drawer = () => page.textContent('#zd-b');
  try {
    // operator: hosts with the actions their state allows
    await as({ user: 'ali', role: 'operator' });
    ok(/esx-syn-01/.test(await txt('#targets')) && /not recorded/.test(await txt('#targets')), 'hosts listed, controller not recorded');
    const hostActs = await page.evaluate(() => [].map.call(document.querySelectorAll('#targets [data-ask]'), (b) => b.getAttribute('data-ask') + ':' + b.getAttribute('data-a')));
    ok(hostActs.includes('vp_v:host-11:restart') && hostActs.includes('vp_v:host-11:shutdown') && !hostActs.includes('vp_v:host-11:start'), 'connected host: restart / shut down only: ' + hostActs);
    ok(hostActs.includes('vp_v:host-14:start') && hostActs.includes('vp_v:host-14:power-cycle') && !hostActs.includes('vp_v:host-14:restart'), 'not responding host: start / power-cycle');
    ok(!(await page.$('[data-bmc]')), 'operators cannot edit controllers');
    ok(/10\.99\.0\.11/.test(await txt('#targets')) && /host address not reported/.test(await txt('#targets')), 'host address on the hosts tab, missing one said');
    await page.click('#tchips [data-t="vm"]');
    const vt = await txt('#targets');
    ok(/10\.99\.1\.101, 10\.99\.2\.101 \+1/.test(vt), 'VM addresses shown under the VM: ' + vt.slice(0, 300));
    ok(/esx-syn-0110\.99\.0\.11/.test(vt.replace(/\s+/g, '')), 'the host address shown beside the VM host');
    ok(/no IP reported/.test(vt), 'a VM without an address says so');
    await page.fill('#q', '10.99.1.101'); await page.waitForTimeout(150);
    ok(/APP-SYN-1/.test(await txt('#targets')) && !/OFF-SYN-1/.test(await txt('#targets')), 'search by IP');
    await page.fill('#q', ''); await page.dispatchEvent('#q', 'input'); await page.waitForTimeout(150);
    const vmActs = await page.evaluate(() => [].map.call(document.querySelectorAll('#targets [data-ask]'), (b) => b.getAttribute('data-ask') + ':' + b.getAttribute('data-a')));
    ok(vmActs.includes('vp_v:vm-101:shutdown') && !vmActs.includes('vp_v:vm-102:shutdown') && vmActs.includes('vp_v:vm-102:power-off') && vmActs.includes('vp_v:vm-103:start'), 'VM actions: no guest shutdown without Tools: ' + vmActs);
    ok(!(await page.$('#targets img')) && /<img src=x/.test(await txt('#targets')), 'a VM name is shown as text, never as HTML');
    await page.fill('#q', 'OFF-SYN'); await page.waitForTimeout(100);
    ok((await page.$$('#targets tbody tr')).length === 1, 'search narrows the list');
    await page.fill('#q', '');
    const rows = async () => page.evaluate(() => [].map.call(document.querySelectorAll('#targets tbody tr td:first-child b'), (x) => x.textContent).join(','));
    const pc = await page.$eval('#pwchips', (x) => x.innerText.replace(/\s+/g, ' '));
    ok(/All 3/.test(pc) && /Powered on 2/.test(pc) && /Powered off 1/.test(pc) && !/not reported/.test(pc), 'power buttons with counts: ' + pc);
    await page.click('#pwchips [data-pwc="off"]'); await page.waitForTimeout(100);
    ok(await rows() === 'OFF-SYN-1' && await page.$eval('#pw', (x) => x.value) === 'off' && await page.$eval('#pwchips [data-pwc="off"]', (b) => b.classList.contains('on')), 'Powered off button filters, highlighted, dropdown follows');
    await page.click('#pwchips [data-pwc=""]'); await page.waitForTimeout(100); ok((await rows()).split(',').length === 3, 'All button clears the filter');
    ok(await page.$eval('#q', (x) => parseFloat(getComputedStyle(x).height) >= 30), 'search box is a visible, full-height control');
    await page.selectOption('#pw', 'off'); await page.waitForTimeout(100);
    ok(await rows() === 'OFF-SYN-1', 'power filter: powered-off VMs only: ' + await rows());
    await page.selectOption('#pw', 'on'); await page.waitForTimeout(100);
    ok(/APP-SYN-1/.test(await rows()) && !/OFF-SYN-1/.test(await rows()), 'power filter: powered-on VMs only');
    await page.selectOption('#pw', 'unknown'); await page.waitForTimeout(100);
    ok(/Nothing matches/.test(await txt('#targets')), 'power not reported: none here, said so');
    await page.click('#tchips [data-t="host"]'); await page.selectOption('#pw', 'off'); await page.waitForTimeout(100);
    ok(await rows() === 'esx-syn-04', 'power filter on hosts: the host not connected: ' + await rows());
    await page.selectOption('#pw', 'on'); await page.waitForTimeout(100);
    ok(await rows() === 'esx-syn-01,esx-syn-02', 'power filter on hosts: connected ones: ' + await rows());
    await page.selectOption('#pw', '');
    // ask for a host restart
    await page.click('[data-ask="vp_v:host-11"][data-a="restart"]');
    await page.click('#rq-go'); await page.waitForTimeout(150);
    ok(/at least 10/.test(await page.textContent('body')), 'a reason is required in the page too');
    await page.fill('#rq-r', 'ESXi patch 8.0U3, CAB-SYN-7'); await page.fill('#rq-w', 'tonight 22:00');
    await page.click('#rq-go');
    await page.waitForFunction(() => /Power plan VPW-0001/.test(document.getElementById('zd-e').textContent));
    let d = await drawer();
    ok(/failed/.test(d) && /The rest of the cluster can carry them/.test(d) && /32 GB free on 1 other host\(s\), 132 GB needed/.test(d), 'the failed check is shown with its figures');
    ok(/Get-VMHost -Id 'HostSystem-host-11'/.test(d) && /Restart-VMHost/.test(d) && /DRS moves the VMs/.test(d), 'commands by ID, DRS check');
    ok(!(await page.$('#pl-ok')), 'the requester has no Approve button');
    ok(await page.$('#pl-cx') !== null, 'the requester can cancel');
    // an admin approves; a failed check needs the accepted risk
    await as({ user: 'syed', role: 'admin' });
    await page.click('[data-plan="VPW-0001"]'); await page.waitForSelector('#pl-ok');
    ok(await page.$('#pl-r') !== null, 'a blocked plan asks for the accepted risk');
    await page.click('#pl-ok'); await page.waitForTimeout(300);
    ok(/check\(s\) failed/.test(await page.textContent('body')), 'approving without an accepted risk is refused by the engine, and said');
    await page.fill('#pl-r', 'APP-SYN-1 is shut down by its owner before the window');
    await page.click('#pl-ok'); await page.waitForTimeout(400);
    ok(/approved - to run/.test(await txt('#plans')), 'approved');
    await page.click('[data-plan="VPW-0001"]'); await page.waitForTimeout(150);
    ok(!(await page.$('#pl-ap')) && /Accepted risk/.test(await drawer()), 'the approver cannot record it as run; the accepted risk is shown');
    await page.click('#zd [data-zd-close]');
    // admin: record the iDRAC of the hung host
    await page.click('[data-bmc="vp_v:host-14"]'); await page.fill('#bm-a', 'idrac-syn-04.syn.local'); await page.selectOption('#bm-k', 'idrac'); await page.click('#bm-ok'); await page.waitForTimeout(400);
    ok(/idrac-syn-04\.syn\.local/.test(await txt('#targets')) && /Dell iDRAC/.test(await txt('#targets')), 'controller recorded');
    // another operator runs it and records it
    await as({ user: 'omar', role: 'operator' });
    await page.click('[data-plan="VPW-0001"]'); await page.waitForSelector('#pl-ap');
    await page.fill('#pl-n', 'ran 22:05, host back 22:24, out of maintenance'); await page.click('#pl-ap'); await page.waitForTimeout(400);
    ok(/run - verifying/.test(await txt('#plans')), 'recorded as run, waiting for verification');
    // power-cycle plan for the hung host uses its controller, and no password
    await page.click('[data-ask="vp_v:host-14"][data-a="power-cycle"]'); await page.fill('#rq-r', 'host hung after a PSOD, owner informed'); await page.click('#rq-go');
    await page.waitForFunction(() => /VPW-0002/.test(document.getElementById('zd-e').textContent));
    d = await drawer();
    ok(/https:\/\/idrac-syn-04\.syn\.local\/redfish\/v1\/Systems\/System\.Embedded\.1/.test(d) && /'<your-bmc-login>'/.test(d) && !/--insecure| -k /.test(d), 'Redfish command with the engineer\'s own login, TLS checking on');
    // the platform is shut down (vCenter cannot be read): the last collection still says connected, so Power on is offered
    S.collection('virt_capacity').patch('vp_v', (x) => { x.last_error = 'connect ETIMEDOUT'; x.last_error_at = new Date().toISOString(); return x; });
    await as({ user: 'omar', role: 'operator' });
    const btn = await page.$('[data-ask="vp_v:host-12"][data-a="start"]');
    ok(btn && (await btn.textContent()) === 'Power on', 'Power on offered for a host whose platform cannot be read');
    ok(/last known - platform not read now/.test(await txt('#targets')), 'the state is shown as last known');
    await btn.click(); await page.fill('#rq-r', 'power on after the Nutanix downtime'); await page.click('#rq-go');
    await page.waitForFunction(() => /VPW-0003/.test(document.getElementById('zd-e').textContent));
    ok(/Is it really off\?/.test(await drawer()) && /Power on: esx-syn-02/.test(await page.textContent('#zd-t')), 'Power on plan written, with the check to confirm it is off');
    // a viewer reads, never acts
    await as({ user: 'nora', role: 'viewer' });
    ok(!(await page.$('#targets [data-ask]')) && /operators ask/.test(await txt('#targets')), 'viewer: no action buttons');
    await page.click('[data-plan="VPW-0001"]'); await page.waitForTimeout(150);
    ok(!(await page.$('#pl-ok')) && !(await page.$('#pl-ap')) && !(await page.$('#pl-cx')), 'viewer: no decisions in the plan');
    ok(!errs.length, 'no page errors or dialogs: ' + errs.join(' | '));
  } finally { await browser.close(); srv.close(); await e.close(); }
  console.log(bad ? 'FAILED ' + bad + '/' + n + ' checks' : 'OK ' + n + '/' + n + ' checks'); process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
