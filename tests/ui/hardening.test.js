// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Baseline Hardening (hardening.html) against the REAL IT Asset Management engine (engine/duty.js -> hardening.js, Python
// rules): a Windows server matched to its agent snapshot, a Windows 11 laptop, an Oracle Linux server read over SSH, a Cisco
// switch and a FortiGate from the SIEM, a Windows server with no agent (not scanned, says what to connect). The operator opens
// a server, sees failed / not-checked / passed checks with CIS and SAMA references, builds the fix script for two checks and
// copies it; filters by platform and by state; exports CSV. A Hyper-V host with IIS (agent 1.3) and the Oracle database on
// the Linux server (db_harden read) are judged too, and a domain controller (AD, agent 1.4); database fixes download as a .sql script. A viewer sees scores but not
// the checks. SYNTHETIC data.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node hardening.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const ITAM = path.resolve(__dirname, '../../backend/itam'), DASH = path.resolve(__dirname, '../../ui');
const H = require(path.join(ITAM, 'tests/helpers.js'));
let WHO = { user: 'omar.syn', role: 'operator' }, n = 0, bad = 0;
const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const NOW = Date.now();
const WIN = { os: { caption: 'Microsoft Windows Server 2022 Standard', product_type: 3 }, secpol: { MinimumPasswordLength: '8', PasswordComplexity: '1', LockoutBadCount: '0' },
  reg: { LmCompatibilityLevel: 5, RdpDeny: 1 }, smb: { smb1: true, signing_required: true }, firewall: [{ name: 'Domain', enabled: true, inbound: 'Block' }], last_hotfix: new Date(NOW - 10 * 864e5).toISOString().slice(0, 10) };
const W11 = { os: { caption: 'Microsoft Windows 11 Enterprise', product_type: 1 }, secpol: { MinimumPasswordLength: '14' }, reg: {}, bitlocker: [{ drive: 'C:', protection: 1 }] };
const HV = { os: { caption: 'Microsoft Windows Server 2022 Datacenter', product_type: 3 }, secpol: {}, reg: {}, iis: { sites: [{ name: 'Intranet-SYN', state: 'Started', protocols: ['http'], directory_browse: false, logging: true }], error_mode: 'DetailedLocalOnly', pools: [] },
  hyperv: { migration_enabled: false, enhanced_session: false, vms: [{ name: 'VM-SYN', generation: 2, secure_boot: true, mac_spoofing: false, dhcp_guard: true, router_guard: true, guest_service: false }] } };
const DC = { os: { caption: 'Microsoft Windows Server 2022 Standard', product_type: 2, domain_role: 5 }, secpol: {}, reg: {}, ad: { domain: 'corp.syn.test', domain_mode: 'Windows2016Domain', pwd: { min_length: 8, complexity: true, history: 24, lockout_threshold: 5, reversible: false }, krbtgt_age_days: 900, groups: { domain_admins: { count: 3, names: ['adm.syn'] } }, accounts: { pwd_never_expires: { count: 4, names: ['svc.syn'] } }, ldap_signing: 2, ldap_channel_binding: 1 } };
const siem = async (p) => {
  if (p === '/hardening/snapshots') return { available: true, hosts: [{ host: 'hv-syn', at: new Date(NOW - 3600000).toISOString(), settings: HV }, { host: 'dc-syn', at: new Date(NOW - 3600000).toISOString(), settings: DC }, { host: 'app-syn-01.corp.test', at: new Date(NOW - 7200000).toISOString(), settings: WIN }, { host: 'laptop-syn', at: new Date(NOW).toISOString(), settings: W11 }] };
  if (p === '/audit/evidence/network') return { available: true, devices: [{ id: 'fw1', name: 'FW-SYN', vendor: 'fortigate', ip: '10.9.0.1', monitoring: { api: true }, security_at: NOW - 3600000, security: [{ kind: 'fw-any-any', key: 'policy 12', title: 'any-any' }] }, { id: 'sw1', name: 'SW-SYN', vendor: 'cisco-ios', ip: '10.9.0.2', config: { sha256: 'a'.repeat(64) } }] };
  if (p === '/audit/evidence/network/config/sw1') return { text: 'hostname SW-SYN\nservice password-encryption\nenable secret 9 <removed>\nip ssh version 2\nline vty 0 4\n transport input telnet ssh\n', at: new Date(NOW).toISOString() };
  return { _down: 'not in this test' };
};

(async () => {
  const e = await H.startApp({ noAi: true });
  const ADM = { user: 'syed', role: 'admin' }, mk = (o) => e.app.assets.create(Object.assign({ status: 'in_use' }, o), ADM).asset;
  mk({ name: 'APP-SYN-01', type: 'vm', os: 'Windows Server 2022', mgmt_ip: '10.8.0.11' });
  mk({ name: 'LAPTOP-SYN', type: 'laptop', os: 'Windows 11 Enterprise' });
  mk({ name: 'NOAGENT-SYN', type: 'server', os: 'Windows Server 2019', mgmt_ip: '10.8.0.12' });
  const ol = mk({ name: 'OL-SYN-APP', type: 'vm', os: 'Oracle Linux Server 8.9', mgmt_ip: '10.8.0.22' });
  mk({ name: 'SW-SYN', type: 'network', vendor: 'Cisco', os: 'IOS 15.2', mgmt_ip: '10.9.0.2' });
  mk({ name: 'FW-SYN', type: 'network', vendor: 'Fortinet', model: 'FortiGate 200F', mgmt_ip: '10.9.0.1' });
  mk({ name: 'DC-SYN', type: 'server', os: 'Windows Server 2022', mgmt_ip: '10.8.0.10' });
  mk({ name: 'HV-SYN', type: 'server', os: 'Windows Server 2022 Datacenter', mgmt_ip: '10.8.0.41' });
  e.app.store.collection('db_hardening').put({ id: 'oracle|10.8.0.22|1521', engine: 'oracle', ip: '10.8.0.22', port: 1521, asset_id: ol.id, instance: 'ORCLSYN', login: 'mon_syn', at: new Date(NOW - 3600000).toISOString(), error: null,
    results: { params: [['remote_os_authent', 'FALSE']], unified: [['TRUE']], defpwd: [['SCOTT']], profile: [['FAILED_LOGIN_ATTEMPTS', '5']], public_exec: [], dba_role: [], sample: [] }, errors: {} });
  e.app.store.collection('server_os_health').put({ id: ol.id, at: new Date(NOW - 3600000).toISOString(), server: { harden: { sshd: 'PermitRootLogin no\nX11Forwarding no\n', selinux: 'Enforcing', uid0: 'root\n', firewall: 'active', auditd: 'active', updates: '0' } } });
  require(path.join(ITAM, 'engine/duty')).registerDuty(e.app.srv, e.app, { noTimer: true, python: process.env.PYTHON || 'python3', hardeningSiem: siem });
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
  const url = 'http://127.0.0.1:' + srv.address().port + '/hardening.html';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  const ctx = await browser.newContext({ viewport: { width: 1400, height: 950 }, acceptDownloads: true }); await ctx.grantPermissions(['clipboard-read', 'clipboard-write']);
  let page;
  const as = async (who) => { WHO = who; if (page) await page.close(); page = await ctx.newPage(); page.on('pageerror', (x) => errs.push(x.message)); await page.goto(url); await page.waitForSelector('#list tr.rw'); };
  const txt = (sel) => page.$eval(sel, (x) => x.innerText.replace(/\s+/g, ' '));
  try {
    await as({ user: 'omar.syn', role: 'operator' });
    const kk = await txt('#kk');
    ok(/Coverage 88%/i.test(kk) && /7 of 8 assets scanned/.test(kk), 'coverage tile: ' + kk);
    ok(/Not scanned 1/i.test(kk), 'one asset not scanned');
    const plats = await txt('#plats');
    ok(/Windows Server/i.test(plats) && /Oracle Linux/i.test(plats) && /FortiGate/i.test(plats) && /Cisco switches/i.test(plats) && /Hyper-V hosts/i.test(plats) && /Active Directory/i.test(plats), 'every platform shown: ' + plats.slice(0, 300));
    const list = await txt('#list');
    ok(/NOAGENT-SYN.*SIEM Windows agent/.test(list), 'the asset without an agent says what to connect');
    ok(/SMBv1 is disabled/.test(await txt('#top')), 'most common failures listed');
    // tiles and filters
    await page.click('[data-act="s:not_scanned"]'); ok(/1 of 8/.test(await txt('#ac')), 'Not scanned tile filters the list');
    await page.click('[data-act="s:not_scanned"]'); ok(/8 of 8/.test(await txt('#ac')), 'clicking again clears it');
    await page.click('[data-plat="oracle_linux"]'); ok(/1 of 8/.test(await txt('#ac')) && /OL-SYN-APP/.test(await txt('#list')), 'platform card filters');
    await page.click('[data-plat="oracle_linux"]');
    await page.fill('#q', 'fw-syn'); ok(/1 of 8/.test(await txt('#ac')), 'search'); await page.fill('#q', '');
    // detail + fix script
    await page.click('#list tr.rw:has-text("APP-SYN-01")'); await page.waitForSelector('[data-ck="WIN-PW-LEN"]');
    const dr = await txt('#zd-b');
    ok(/Failed · \d+/i.test(dr) && /Not checked · \d+/i.test(dr) && /Passed · \d+/i.test(dr), 'checks grouped failed / not checked / passed');
    ok(/SAMA CSF 3\.3\.8/.test(dr) && /CIS Microsoft Windows Server 2022 Benchmark/.test(dr), 'CIS benchmark and SAMA clause shown');
    ok(/auditpol could not be read/.test(dr), 'unread audit policy is not checked, with the reason');
    await page.$$eval('[data-ck]', (cs) => cs.forEach((c) => { c.checked = ['WIN-PW-LEN', 'WIN-SMB1'].includes(c.getAttribute('data-ck')); }));
    await page.click('#mkscr'); await page.waitForSelector('#scrt');
    const scr = await page.textContent('#scrt');
    ok(/REVIEW BEFORE RUNNING/.test(scr) && /minpwlen:14/.test(scr) && /EnableSMB1Protocol \$false/.test(scr) && !/lockoutthreshold/.test(scr), 'script holds exactly the ticked fixes');
    ok(/ROLLBACK/.test(scr), 'with the rollback');
    await page.click('#scrc'); ok(/minpwlen:14/.test(await page.evaluate(() => navigator.clipboard.readText())), 'Copy puts the script on the clipboard');
    const log = e.app.store.auditTail(50).map((x) => x.action); ok(log.includes('hardening.script'), 'script generation audited');
    await page.keyboard.press('Escape');
    // the Oracle database on the Linux server: its checks beside the OS ones; a database-only script downloads as .sql
    await page.click('#list tr.rw:has-text("OL-SYN-APP")'); await page.waitForSelector('[data-ck="ORA-DEFPWD-1"]');
    const od = await txt('#zd-b');
    ok(/\[Oracle ORCLSYN\] No open account uses a default password/.test(od) && /SCOTT/.test(od), 'database check with its instance and evidence');
    ok(/CIS Oracle Database Benchmark/.test(od) && /CIS Oracle Linux Benchmark/.test(od), 'both benchmarks named');
    await page.$$eval('[data-ck]', (cs) => cs.forEach((c) => { c.checked = c.getAttribute('data-ck') === 'ORA-DEFPWD-1'; }));
    await page.click('#mkscr'); await page.waitForSelector('#scrt');
    ok(/^-- ===== REVIEW BEFORE RUNNING/.test(await page.textContent('#scrt')), 'SQL section with -- comments');
    const [sq] = await Promise.all([page.waitForEvent('download'), page.click('#scrd')]);
    ok(/\.sql$/.test(sq.suggestedFilename()), 'database fixes download as .sql: ' + sq.suggestedFilename());
    await page.keyboard.press('Escape');
    await page.click('#list tr.rw:has-text("HV-SYN")'); await page.waitForSelector('#zd-b table, #zd-b p');
    await page.waitForFunction(() => /IIS-HTTPS/.test(document.getElementById('zd-b').innerText));
    const hv = await txt('#zd-b');
    ok(/Hyper-V hosts/.test(hv) && /IIS-HTTPS/.test(hv) && /Intranet-SYN/.test(hv) && /HV-SECUREBOOT/.test(hv), 'Hyper-V host with IIS and Hyper-V checks');
    await page.keyboard.press('Escape');
    await page.click('#list tr.rw:has-text("DC-SYN")'); await page.waitForFunction(() => /AD-KRBTGT/.test(document.getElementById('zd-b').innerText));
    const dc = await txt('#zd-b');
    ok(/Active Directory/.test(dc) && /krbtgt password set 900 days ago/.test(dc) && /corp\.syn\.test/.test(dc) && /svc\.syn/.test(dc), 'domain controller with its AD checks and evidence');
    await page.keyboard.press('Escape');
    // CSV
    const [dl] = await Promise.all([page.waitForEvent('download'), page.click('#csv')]);
    const csv = fs.readFileSync(await dl.path(), 'utf8');
    ok(/^# Baseline hardening - exported/.test(csv) && /"NOAGENT-SYN"/.test(csv) && /"not_scanned"/.test(csv), 'CSV with the filter line and every asset');
    // scan now
    ok(await page.isVisible('#scan'), 'operator sees Scan now');
    await page.click('#scan'); await page.waitForFunction(() => /Scanned again/.test(document.body.innerText));
    ok(e.app.store.auditTail(50).some((x) => x.action === 'hardening.scan'), 'scan audited');
    // viewer
    await as({ user: 'v.syn', role: 'viewer' });
    ok(!(await page.isVisible('#scan')), 'viewer has no Scan now');
    await page.click('#list tr.rw:has-text("APP-SYN-01")'); await page.waitForSelector('#zd-b');
    ok(/only operators and administrators see them/.test(await txt('#zd-b')) && !(await page.$('[data-ck]')), 'viewer: score only, no checks');
    ok(!errs.length, 'page errors: ' + errs.join(' | '));
  } finally { await browser.close(); srv.close(); e.close(); }
  console.log(bad ? 'FAILED ' + bad + ' of ' + n : 'OK ' + n + ' checks'); process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
