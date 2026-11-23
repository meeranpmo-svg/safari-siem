// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for the server pages of Servers & Virtualization (servers.html, vmware-, windows-, exchange-, solaris-,
// oracle-linux-servers.html + vendor/zyb-servers.js). The stubbed /api/itam/servers answers with what the REAL server rules
// (pyengine/server_rules.py) decide for synthetic servers, so the page and the engine cannot drift apart. Checks: each page
// shows only its platform; tabs carry counts; tiles filter; a row opens the detail with the platform reason, findings and
// fix, and the OS reading; the admin can choose the SSH login (operator cannot); Read now posts and reports; VMware shows
// ESXi hosts from vCenter, Windows / Exchange the AI administrators' checks; with nothing connected each card says what to
// connect; a viewer is told the operator role is needed; names are text, never HTML. Data is SYNTHETIC.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node servers.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const { spawnSync } = require('child_process');
const DASH = path.resolve(__dirname, '../../ui'), RULES = path.resolve(__dirname, '../../backend/itam/pyengine');
let n = 0, bad = 0;
const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const NOW = Date.now(), iso = (t) => new Date(t).toISOString();
const SERVERS = [
  { id: 'a1', name: 'APP-SYN-01', type: 'vm', os: 'Windows Server 2019', ip: '10.8.0.11', ips: [{ ip: '10.8.0.11', src: 'asset register' }, { ip: '30.30.30.11', src: 'vcenter' }], hypervisor: 'vcenter', host_name: 'ESX-SYN-01', power: 'on', backup: { status: 'protected' }, ssh: {} },
  { id: 'a2', name: 'EXCH01', type: 'server', os: 'Windows Server 2016', ip: '10.8.0.12', software: ['Microsoft Exchange Server 2016 CU23'], backup: { status: 'failed', last_attempt: '2026-10-25' }, patch: { missing: 9, critical: 3 }, ssh: {} },
  { id: 'a3', name: 'SOL-SYN-DB', type: 'server', os: 'Oracle Solaris 11.4', ip: '10.8.0.21', backup: { status: 'none' }, ssh: { credential: 'SSH-RO', via: 'proven by Asset Discovery', host_key: 'trusted' },
    os_read: { at: iso(NOW - 120000), server: { os: 'Oracle Solaris 11.4 SPARC', kernel: 'SunOS 5.11', ncpu: 8, load5: 1.2, mem_total_mb: 65536, mem_avail_mb: 30000, swap_total_mb: 4096, swap_used_mb: 100,
      filesystems: [{ mount: '/', used_pct: 96, avail_kb: 400000 }, { mount: '/export', used_pct: 40, avail_kb: 9e7 }], inodes: [], failed_services: [{ name: 'svc:/network/ntp:default', state: 'maintenance' }], last_patch: '2026-09-01', uptime_s: 1728000 } } },
  { id: 'a4', name: 'OL-SYN-APP', type: 'vm', os: 'Oracle Linux Server 8.9', ip: '10.8.0.22', power: 'off', power_at: iso(NOW - 3600e3), hypervisor: 'vcenter', ssh: { credential: 'SSH-RO', host_key: 'seen' }, lifecycle: { status: 'soon', days: 90, product: 'Oracle Linux 8' } },
  { id: 'a5', name: 'OL-SYN-DB2', type: 'server', os: 'Oracle Linux 7', ip: '10.8.0.23', lifecycle: { status: 'eol', product: 'Oracle Linux 7', eol: '2024-12-31' }, ssh: {} },
  { id: 'a6', name: 'ESX-SYN-01', type: 'server', os: 'VMware ESXi 7.0.3', ip: '10.8.0.31', ssh: {}, warranty_end: '2025-06-30', site: 'HQ-SYN', owner: 'infra.syn' },
  { id: 'a7', name: '<img src=x onerror=alert(1)>', type: 'server', ssh: {} },
];
function assess(platform, sources) {
  const code = 'import sys,json\nsys.path.insert(0,sys.argv[1])\nimport server_rules\nprint(json.dumps(server_rules.assess(json.loads(sys.stdin.read()))))';
  const r = spawnSync('python3', ['-I', '-c', code, RULES], { input: JSON.stringify({ servers: SERVERS, platform, sources, now: NOW }), encoding: 'utf8' });
  if (r.status !== 0) throw new Error(r.stderr);
  return Object.assign(JSON.parse(r.stdout), { generated_at: iso(NOW), sources, last_pass: { at: iso(NOW - 300000), read: 1, shared: 0, skipped: 1, failed: 0 }, ssh_logins: [{ id: 'c1', label: 'SSH-RO' }, { id: 'c2', label: 'SSH-OTHER' }] });
}
const SRC = { backup: true, lifecycle: true, patch: true, facts: true };
const VC = { last_run: { at: iso(NOW - 600000) }, platforms: [{ id: 'vc1', label: 'VC-SYN', kind: 'vcenter' }, { id: 'nx', label: 'PRISM-SYN', kind: 'nutanix' }],
  hosts: [{ platform: 'VC-SYN', name: 'ESX-SYN-01', ip: '10.8.0.31', vmks: [{ vmk: 'vmk0', portgroup: 'Management Network', ip: '10.8.0.31' }, { vmk: 'vmk1', portgroup: 'vMotion', ip: '10.9.0.31' }], cluster: 'SYN-PROD', version: '7.0.3', state: 'connected', cpu_used_pct: 45, mem_used_pct: 92, vms: 12, vms_on: 10, vendor: 'Dell', model: 'R740' },
    { platform: 'PRISM-SYN', name: 'AHV-SYN-1', cluster: 'NX', state: 'connected', vms: 3, vms_on: 3 }], datastores: [{ platform: 'VC-SYN', name: 'DS-SYN-1', used_pct: 81 }] };
const SYS = { windows: { items: [{ id: 'app-syn-01', name: 'APP-SYN-01', ip: '10.8.0.11', logins: { windows: 'win-ro: zyb_ro' }, last_check: NOW - 600000, findings: 2, worst: 'medium' }, { id: 'ghost-syn', name: 'GHOST-SYN', ip: '10.9.9.9', logins: { windows: null }, last_check: null, findings: 0 }] },
  exchange: { items: [{ id: 'exch01', name: 'EXCH01', ip: '10.8.0.12', logins: { exchange: 'ex-ro: zyb_ex' }, last_check: NOW - 60000, findings: 1, worst: 'high' }] } };
let WHO = { user: 'omar.syn', role: 'operator' }, MODE = 'live', posts = [];

(async () => {
  const srv = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://x'), json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u.pathname === '/dashboards/whoami.json') return json(200, WHO);
    if (u.pathname.startsWith('/api/')) {
      if (MODE === 'down') return json(404, { error: 'not found' });
      if (u.pathname === '/api/itam/servers' && req.method === 'GET') {
        if (WHO.role === 'viewer') return json(403, { error: 'forbidden' });
        if (MODE === 'empty') return json(200, Object.assign(assess(u.searchParams.get('platform') || '', {}), { servers: [], findings: [], summary: { servers: 0, critical: 0, high: 0, read: 0, unix: 0, eol: 0, no_backup: null, powered_off: 0 } }));
        return json(200, assess(u.searchParams.get('platform') || '', SRC));
      }
      // EXCH01 has a second NIC: it appears only once an operator asked every server for its addresses
      if (u.pathname === '/api/soc/sysadmin/addresses/refresh') { if (!['operator', 'admin'].includes(WHO.role)) return json(403, { error: 'requires operator role' }); posts.push({ p: u.pathname, role: WHO.role });
        SYS.exchange.items[0].addresses = { at: NOW - 1000, items: [{ ip: '10.8.0.12', interface: 'MAPI', prefix: 24 }, { ip: '30.30.30.21', interface: 'Replication <img src=x onerror=window.__x=1>', prefix: 24 }] };
        return json(200, { items: [{ id: 'exch01', name: 'EXCH01', status: 'ok', addresses: ['10.8.0.12', '30.30.30.21'] }, { id: 'exch02', name: 'EXCH02', status: 'no-login' }] }); }
      if (req.method === 'POST') {
        let b = ''; req.on('data', (c) => { b += c; }); req.on('end', () => {
          posts.push({ p: u.pathname, b: b ? JSON.parse(b) : null, role: WHO.role });
          if (u.pathname === '/api/itam/servers/ssh') return WHO.role === 'admin' ? json(200, { asset_id: 'a4', cred_id: 'c2' }) : json(403, { error: 'forbidden' });
          if (u.pathname === '/api/itam/servers/run') return json(200, { read: 2, shared: 1, skipped: 0, failed: 0, unix: 3 });
          if (u.pathname === '/api/itam/sysadmin-sync/run') return WHO.role === 'admin' ? json(200, { ok: true, added: [{ name: 'EXCH02' }], exchange_log_senders: 2 }) : json(403, { error: 'forbidden' });
          json(404, {});
        }); return;
      }
      if (u.pathname === '/api/itam/virt/capacity') return MODE === 'empty' ? json(200, { platforms: [], hosts: [], datastores: [] }) : json(200, VC);
      if (u.pathname === '/api/soc/sysadmin/targets') return json(200, MODE === 'empty' ? { items: [] } : SYS[u.searchParams.get('role')]);
      return json(404, { error: 'not found' });
    }
    const f = path.join(DASH, u.pathname.replace(/^\/dashboards\//, '/')); if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (err, d) => { if (err) { res.writeHead(404); res.end(); return; } res.writeHead(200, { 'Content-Type': u.pathname.endsWith('.js') ? 'application/javascript' : u.pathname.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port + '/dashboards/';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  let page;
  const open = async (file, who) => { WHO = who || { user: 'omar.syn', role: 'operator' }; if (page) await page.close(); page = await browser.newPage({ viewport: { width: 1400, height: 1000 } }); page.on('pageerror', (x) => errs.push(file + ': ' + x.message)); page.on('dialog', (d) => { errs.push('dialog ' + d.message()); d.dismiss(); }); await page.goto(base + file); await page.waitForFunction(() => /updated/.test(document.getElementById('sv-up').textContent), null, { timeout: 20000 }); };
  const txt = (sel) => page.innerText(sel);
  const names = () => page.evaluate(() => [].map.call(document.querySelectorAll('#sv-list tbody tr td:first-child b'), (b) => b.textContent));
  try {
    // all servers
    await open('servers.html');
    ok((await names()).length === 7, 'all servers: 7 rows');
    const tb = await txt('#sv-tabs'); ok(/Windows · 2/.test(tb) && /Exchange · 1/.test(tb) && /Solaris · 1/.test(tb) && /Oracle Linux · 2/.test(tb) && /VMware · 3/.test(tb), 'tabs carry counts: ' + tb.replace(/\s+/g, ' '));
    ok(!(await page.$('#sv-list img')) && /<img src=x/.test(await txt('#sv-list')), 'a server name is text, never HTML');
    ok(/OS unknown/.test(await txt('#sv-list')), 'OS unknown is shown, not guessed');
    let k = await txt('#sv-kk'); ok(/PAST END OF SUPPORT\s*1/i.test(k) && /NO \/ FAILED BACKUP\s*2/i.test(k) && /OS READ OVER SSH\s*1 \/ 3/i.test(k) && /POWERED OFF\s*1/i.test(k), 'tiles: ' + k.replace(/\s+/g, ' '));
    await page.click('#sv-kk [data-f="backup"]'); ok(JSON.stringify((await names()).sort()) === JSON.stringify(['EXCH01', 'SOL-SYN-DB']), 'backup tile filters: ' + await names());
    await page.click('#sv-kk [data-f="backup"]'); ok((await names()).length === 7, 'tile again: filter off');
    await page.fill('#sv-q', 'oracle linux'); await page.waitForTimeout(100); ok((await names()).length === 2, 'search by OS');
    await page.fill('#sv-q', '');
    // estate intelligence
    const ei = (await txt('#sv-intel')).replace(/\s+/g, ' ');
    ok(/Estate intelligence/.test(ei) && /Physical \d/.test(ei) && /VMware VM 2/.test(ei), 'estate mix: physical and VMs: ' + ei.slice(0, 300));
    ok(/Compound risk/.test(ei) && /EXCH01/.test(ei) && /backup failed/.test(ei) && /3 critical patches/.test(ei), 'compound risk: EXCH01 has a failed backup and critical patches');
    ok(!/OL-SYN-DB2/.test(await txt('#sv-intel table')), 'a single risk is not a compound risk');
    const hp = await page.$eval('#sv-intel tr.sv-r td[title]', (x) => x.getAttribute('title')); ok(/backup -15/.test(hp) && /patch -15/.test(hp), 'health is itemised: ' + hp);
    await page.click('#sv-intel tr.sv-r'); ok(await page.waitForFunction(() => /Findings/.test(document.body.innerText) && /EXCH01/.test(document.body.innerText)).then(() => true, () => false), 'a row opens the server detail');
    await page.keyboard.press('Escape'); await page.evaluate(() => { const c = document.querySelector('.zd-close,[data-close]'); if (c) c.click(); });
    await page.click('[data-sv-itab="health"]'); ok(/What took the points/.test(await txt('#sv-intel')) && /100 minus the findings/.test(await txt('#sv-intel')), 'lowest health tab with the method');
    await page.click('[data-sv-itab="peers"]'); ok(/needs 5 OS readings/.test(await txt('#sv-intel')), 'peers: says what it needs instead of inventing an outlier');
    await page.click('[data-sv-itab="life"]'); const lf = (await txt('#sv-intel')).replace(/\s+/g, ' ');
    ok(/Expired 1/.test(lf) && /no warranty date recorded/.test(lf) && /in 90 days/.test(lf), 'refresh: expired warranty, missing dates, OS end of support within a year: ' + lf.slice(0, 400));
    await page.click('[data-sv-itab="cap"]'); const cp2 = (await txt('#sv-intel')).replace(/\s+/g, ' ');
    ok(/Powered-off VMs/.test(cp2) && /OL-SYN-APP/.test(cp2) && /a light moment is not the peak/.test(cp2), 'reclaim: the powered-off VM; consolidation caveat');
    await page.click('[data-sv-itab="cov"]'); const cv = (await txt('#sv-intel')).replace(/\s+/g, ' ');
    ok(/Owner recorded 1 · 14%/.test(cv) && /never "fine"/.test(cv), 'data coverage per source: ' + cv.slice(0, 300));
    ok(!(await page.$('#sv-intel img')), 'names stay text in the intelligence section');
    ok(await page.isVisible('#sv-run'), 'operator: Read now offered on All servers');
    await page.click('#sv-run'); await page.waitForFunction(() => /Read 2, from Database Servers 1/.test(document.getElementById('sv-pass').textContent));
    ok(posts.some((p) => p.p === '/api/itam/servers/run'), 'Read now posts');

    // Solaris page: only Solaris, OS reading, detail with fix
    await open('solaris-servers.html');
    ok(JSON.stringify(await names()) === '["SOL-SYN-DB"]', 'Solaris page: Solaris only');
    ok(/\/ 96% · 46% mem free · load 1.2\/8/.test(await txt('#sv-list')), 'OS reading in the row: ' + await txt('#sv-list'));
    const fd = await txt('#sv-find'); ok(/\/ 96% full/.test(fd) && /svc:\/network\/ntp:default is maintenance/.test(fd) && /svcadm clear/.test(fd) && /no backup found/.test(fd), 'findings with the fix');
    await page.click('#sv-list tr.sv-r'); await page.waitForSelector('#zd:not([hidden])');
    const d = await txt('#zd-b'); ok(/OS: Solaris/.test(d) && /Operating system \(read over SSH\)/i.test(d) && /SSH login: SSH-RO \(proven by Asset Discovery\) · host key trusted/.test(d) && /\/export/.test(d), 'detail: reason, OS reading, SSH');
    ok(!(await page.$('#sv-cred')), 'operator cannot choose the SSH login');

    // Oracle Linux: admin chooses the SSH login
    await open('oracle-linux-servers.html', { user: 'syed', role: 'admin' });
    ok(JSON.stringify((await names()).sort()) === '["OL-SYN-APP","OL-SYN-DB2"]', 'Oracle Linux page');
    ok(/OS not read - host key seen/.test(await txt('#sv-list')) && /past end of support/.test(await txt('#sv-list')), 'not read: says why; EoL pill');
    await page.click('#sv-list tr.sv-r[data-id="a4"]'); await page.waitForSelector('#sv-cred');
    await page.selectOption('#sv-cred', 'c2'); await page.click('#sv-cred-save'); await page.waitForFunction(() => /Saved/.test(document.getElementById('sv-cred-msg').textContent));
    const sp = posts.find((p) => p.p === '/api/itam/servers/ssh'); ok(sp && sp.b.asset_id === 'a4' && sp.b.cred_id === 'c2', 'SSH login saved for that server');

    // VMware: ESXi hosts from vCenter only (not Prism), VMs on vCenter
    await open('vmware-servers.html');
    await page.waitForFunction(() => /ESX-SYN-01/.test(document.getElementById('sv-extra').textContent));
    const ex = await txt('#sv-extra'); ok(/ESX-SYN-01/.test(ex) && /92%/.test(ex) && /10 \/ 12/.test(ex) && /DS-SYN-1 81%/.test(ex) && !/AHV-SYN-1/.test(ex), 'ESXi hosts from vCenter, not Prism: ' + ex.slice(0, 200));
    ok(/10\.9\.0\.31 · vmk1 vMotion/.test(ex), 'every VMkernel address of the host, not only management');
    ok(JSON.stringify((await names()).sort()) === '["APP-SYN-01","ESX-SYN-01","OL-SYN-APP"]', 'VMware: hosts and the VMs on vCenter');
    await page.click('#sv-kk [data-f="off"]'); ok(JSON.stringify(await names()) === '["OL-SYN-APP"]', 'powered-off filter');

    // Windows / Exchange: AI administrators' checks joined to the register
    await open('windows-servers.html');
    await page.waitForFunction(() => /GHOST-SYN/.test(document.getElementById('sv-extra').textContent));
    const w = await txt('#sv-extra'); ok(/APP-SYN-01/.test(w) && /10 min ago/.test(w) && /not found/.test(w) && /not set/.test(w), 'Windows: SIEM checks, register join, login state: ' + w.slice(0, 300));
    ok(!(await page.isVisible('#sv-run')), 'no SSH read on the Windows page');
    // a server with several addresses: all of them, before WinRM has read it (from VMware Tools / the register, with the source)
    ok(/30\.30\.30\.11 VMware Tools \(vCenter\)/.test(w) && /2 addresses from the platform's own sources - WinRM has not read the server yet/.test(w), 'every known address on the Windows card: ' + w.slice(0, 400));
    ok(/30\.30\.30\.11/.test(await txt('#sv-list')), 'the server list shows the second address too');
    await open('exchange-servers.html');
    ok(JSON.stringify(await names()) === '["EXCH01"]', 'Exchange page: Exchange only');
    ok(/3 critical patches missing/.test(await txt('#sv-find')) && /last backup failed/.test(await txt('#sv-find')), 'Exchange findings');
    await page.click('#sv-list tr.sv-r'); await page.waitForSelector('#zd:not([hidden])');
    ok(/software: Microsoft Exchange Server 2016/.test(await txt('#zd-b')), 'why it is Exchange');
    ok(!(await page.isVisible('#sv-exsync')), 'operator: no SIEM sync button');
    // every IP of each server: not read yet → said; the operator fetches; the second NIC appears; a server without a login is named
    ok(/WinRM has not read the server yet/.test(await txt('#sv-extra')) && await page.isVisible('#sv-addr'), 'addresses not read yet, operator has Fetch');
    await page.keyboard.press('Escape'); if (await page.isVisible('#zd')) await page.click('#zd [data-zd-close]:not(.zd-bg)').catch(() => page.evaluate(() => { document.getElementById('zd').hidden = true; }));   // close the detail drawer opened above
    await page.click('#sv-addr'); await page.waitForFunction(() => /30\.30\.30\.21/.test(document.getElementById('sv-extra').textContent));
    { const a = await txt('#sv-extra'); ok(/10\.8\.0\.12\/24/.test(a) && /managed by/.test(a) && /30\.30\.30\.21\/24/.test(a), 'both NICs shown'); ok(/1 of 2 server\(s\) read/.test(a) && /no WinRM login for EXCH02/.test(a), 'result names the server without a login'); }
    ok(!(await page.evaluate(() => window.__x)), 'interface name stays text');
    await open('exchange-servers.html', { user: 'syed', role: 'admin' });
    ok(await page.isVisible('#sv-exsync'), 'admin: Sync with the SIEM now');
    await page.click('#sv-exsync'); await page.waitForFunction(() => /2 server\(s\) send Exchange logs to the SIEM/.test(document.getElementById('sv-pass').textContent));
    ok(posts.some((p) => p.p === '/api/itam/sysadmin-sync/run' && p.role === 'admin'), 'runs the sysadmin sync');

    // nothing connected
    MODE = 'empty';
    await open('windows-servers.html'); await page.waitForFunction(() => /AI Windows Administrator's list/.test(document.getElementById('sv-extra').textContent));
    ok(/No Windows Server server in the asset register/.test(await txt('#sv-list')) && /no backup platform connected/.test(await txt('#sv-kk')), 'empty: says what to connect');
    await open('vmware-servers.html'); await page.waitForFunction(() => /No vCenter or ESXi host is connected/.test(document.getElementById('sv-extra').textContent)); ok(true, 'VMware empty: what to connect');
    let all = (await txt('main')); ok(!/NaN|undefined|null/.test(all), 'no NaN / undefined / null: ' + (all.match(/.{0,40}(NaN|undefined|null).{0,40}/) || [''])[0]);

    MODE = 'down'; await open('solaris-servers.html'); ok(/not installed on the server/.test(await txt('#sv-list')), 'every server failing: says so');
    ok(await page.waitForFunction(() => { const a = document.querySelector('#sv-list a.zyb-uh-link'); return a && /Update Health/.test(a.textContent) && /update-health\.html$/.test(a.getAttribute('href')); }, null, { timeout: 5000 }).then(() => true, () => false), 'the 404 links to Update Health for the cause');
    MODE = 'live'; await open('exchange-servers.html', { user: 'nora.syn', role: 'viewer' }); ok(!(await page.$('#sv-addr')), 'viewer: no Fetch button');
    await open('servers.html', { user: 'nora.syn', role: 'viewer' }); ok(/needs the operator role/.test(await txt('#sv-list')) && !(await page.isVisible('#sv-run')), 'viewer: operator role needed, no Read now');
    ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  } finally { await browser.close(); srv.close(); }
  console.log(bad ? 'FAILED ' + bad + '/' + n + ' checks' : 'OK ' + n + '/' + n + ' checks'); process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
