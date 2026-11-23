// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// switch-port-map.html against the REAL SIEM port-map engine (sentra-siem engine/netops/portmap.js via routes.js; the SSH helper
// and the polls stubbed) with a SYNTHETIC Cisco switch: a switch without a login says what to set up; an operator reads the
// other one and its front panel is drawn port by port; a port opens with what is plugged in (the CDP phone and the PC behind
// it, vendor, IP, NAC); the lenses recolour the panel with their legend; findings list the problem ports and a fix becomes a
// change plan; a person confirms a device type; "where is it plugged in" finds a device by IP; capacity and the Excel export;
// a hostile host name stays text; a viewer sees port states but no MAC, IP or host name; the menu entry and portal redirect.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node switch-port-map.test.js
const http = require('http'), fs = require('fs'), os = require('os'), path = require('path');
const DASH = path.resolve(__dirname, '../../ui');
const SIEM = process.env.SENTRA_SIEM || path.resolve(__dirname, '../..', 'backend', 'siem');
const routes = require(path.join(SIEM, 'engine/netops/routes'));
const { createState } = require(path.join(SIEM, 'engine/soc/state'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const XSS = '<img src=x onerror="window.__xss=1">';
const row = (a, b, c, d, e, f, g) => a.padEnd(10) + b.padEnd(19) + c.padEnd(13) + d.padEnd(11) + e.padEnd(8) + f.padEnd(7) + g;
const STATUS = [row('Port', 'Name', 'Status', 'Vlan', 'Duplex', 'Speed', 'Type')].concat(Array.from({ length: 24 }, (_, i) => {
  const p = 'Gi1/0/' + (i + 1), nm = { 1: 'PC-FIN-01', 2: 'Phone desk 12', 8: 'old-ap' }[i + 1] || '';
  const st = i + 1 === 5 ? 'err-disabled' : i + 1 <= 8 ? 'connected' : 'notconnect';
  return row(p, nm, st, i + 1 === 7 ? '20' : '10', st === 'connected' ? (i + 1 === 3 ? 'a-half' : 'a-full') : 'auto', st === 'connected' ? 'a-1000' : 'auto', '10/100/1000BaseTX');
})).concat([row('Te1/1/1', 'Uplink CORE-SYN', 'connected', 'trunk', 'full', '10G', 'SFP-10GBase-SR'), row('Te1/1/2', '', 'notconnect', 'trunk', 'full', '10G', 'SFP-10GBase-SR')]).join('\n');
const mac = (v, m, p) => '  ' + String(v).padEnd(6) + m + '    DYNAMIC     ' + p;
const MACS = ['Vlan    Mac Address       Type        Ports', mac(10, '3c52.82aa.0001', 'Gi1/0/1'), mac(10, '0011.2233.4455', 'Gi1/0/2'), mac(10, '3c52.82aa.0002', 'Gi1/0/2'), mac(10, '3c52.82aa.0003', 'Gi1/0/3'),
  mac(10, '3c52.82aa.0101', 'Gi1/0/4'), mac(10, '3c52.82aa.0102', 'Gi1/0/4'), mac(10, '3c52.82aa.0103', 'Gi1/0/4'), mac(10, '3c52.82aa.0104', 'Gi1/0/4'), mac(20, '0026.73bb.0007', 'Gi1/0/7'), mac(10, '00aa.bbcc.0008', 'Gi1/0/8'), mac(10, 'aaaa.0000.0001', 'Te1/1/1')].join('\n');
const CDP = '-------------------------\nDevice ID: SEP001122334455\n  IP address: 10.20.0.5\nPlatform: Cisco IP Phone 8845,  Capabilities: Host Phone Two-port Mac Relay\nInterface: GigabitEthernet1/0/2,  Port ID (outgoing port): Port 1\n'
  + '-------------------------\nDevice ID: SW-HIDDEN.as.local\n  IP address: 10.0.9.9\nPlatform: cisco WS-C2960-8TC-L,  Capabilities: Switch IGMP\nInterface: GigabitEthernet1/0/8,  Port ID (outgoing port): GigabitEthernet0/1\n'
  + '-------------------------\nDevice ID: CORE-SYN.as.local\n  IP address: 10.0.0.2\nPlatform: cisco C9500-24Y4C,  Capabilities: Router Switch IGMP\nInterface: TenGigabitEthernet1/1/1,  Port ID (outgoing port): TwentyFiveGigE1/0/24\n';
const OUT = { 'show interfaces status': STATUS, 'show mac address-table': MACS, 'show cdp neighbors detail': CDP, 'show lldp neighbors detail': '% LLDP is not enabled',
  'show power inline': 'Module   Available     Used     Remaining\n1          370.0        96.3       273.7\nGi1/0/2   auto   on         6.3     IP Phone 8845       2     30.0',
  'show interfaces trunk': 'Port        Mode             Encapsulation  Status        Native vlan\nTe1/1/1     on               802.1q         trunking      1\n', 'show ip arp': 'Internet  10.10.0.21              3   3c52.82aa.0001  ARPA   Vlan10',
  'show vlan brief': '10   USERS                            active    Gi1/0/1\n20   PRINTERS                         active    Gi1/0/7' };
const runner = async (q) => (q.op === 'version' ? { ok: true, netmiko: '4.8.0' } : q.op === 'hostkey' ? { ok: true, type: 'ssh-rsa', key: 'AAAAKEY1', fingerprint: 'SHA256:abc' }
  : q.op === 'run' ? { ok: true, prompt: 'ACC#', results: q.commands.map((c) => ({ command: c, output: OUT[c] || '' })) } : { ok: false, error: 'bad op' });

(async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pm-page-')), secrets = path.join(dir, 'secrets.json'); fs.writeFileSync(secrets, '{}', { mode: 0o600 });
  const ouiFile = path.join(dir, 'oui.csv'); fs.writeFileSync(ouiFile, 'MA-L,3C5282,"Synthetic HP Inc.",x\nMA-L,002673,RICOH COMPANY (synthetic),y\n');
  const state = await createState({ dir: path.join(dir, 'state') });
  const config = { netops: { enabled: false, portmap: { oui_file: ouiFile } } };
  Object.defineProperty(config, 'secrets', { value: {}, enumerable: false, writable: true }); Object.defineProperty(config, '_paths', { value: { secrets }, enumerable: false });
  const snaps = { nac: { at: Date.now(), ok: true, nac: { items: [{ mac: '3c52.82aa.0003', ip: '10.10.0.33', host: 'LT-' + XSS, status: 'unauthorized' }] } } };
  const poller = { snapshot: (id) => snaps[id] || null, snapshots: () => snaps, stats: () => ({}), forget() {}, start() {} };
  const N = routes.createNetops({ state, config, log: { info() {}, warn() {}, error() {} }, poller, cliRunner: runner });
  N.inventory.put({ id: 'acc-syn', name: 'ACC-SYN', vendor: 'cisco-ios', ip: '10.0.5.2', site: 'Riyadh HQ', role: 'access' }, 'test');
  N.inventory.put({ id: 'acc-two', name: 'ACC-TWO-SYN', vendor: 'cisco-ios', ip: '10.0.5.3', site: 'Riyadh HQ', role: 'access' }, 'test');
  N.inventory.put({ id: 'nac', name: 'GENIAN-SYN', vendor: 'genian', ip: '10.0.5.9', role: 'nac' }, 'test');
  const R = []; routes.register({ route: (m, p, h) => { R.push({ m, re: new RegExp('^' + p.replace(/:[a-z]+/g, '([^/]+)') + '$'), keys: (p.match(/:[a-z]+/g) || []).map((k) => k.slice(1)), h }); } }, { state, config, log: { error() {}, info() {} }, netops: N });
  const RANK = { viewer: 0, analyst: 1, operator: 2, admin: 3 };
  async function dispatch(method, pathname, query, body, role, user) {
    const r = R.find((x) => x.m === method && x.re.test(pathname)); if (!r) return { c: 404, b: { error: 'not found' } };
    const mm = r.re.exec(pathname), params = {}; r.keys.forEach((k, i) => { params[k] = decodeURIComponent(mm[i + 1]); });
    const out = {}, ctx = { role, user, body, params, query, path: pathname, need(x) { if (RANK[role] < RANK[x]) { out.c = 403; out.e = 'requires ' + x; return false; } return true; }, audit() {}, fail(c, e) { out.c = c; out.e = e; } };
    const rv = await r.h(ctx); return out.c ? { c: out.c, b: { error: out.e } } : { c: 200, b: rv };
  }
  await dispatch('PUT', '/api/soc/netops/devices/acc-syn/credentials', {}, { ssh: { username: 'ro', password: 'Pw-ro-123' } }, 'admin', 'syed');
  await dispatch('POST', '/api/soc/netops/devices/acc-syn/ssh/hostkey', {}, {}, 'admin', 'syed');
  await dispatch('POST', '/api/soc/netops/devices/acc-syn/ssh/trust', {}, { fingerprint: 'SHA256:abc' }, 'admin', 'syed');
  let WHO = { user: 'nora.syn', role: 'operator' };
  const srv = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://x'), json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u.pathname === '/dashboards/whoami.json') return json(200, WHO);
    if (u.pathname.startsWith('/api/soc/netops/')) { let b = ''; req.on('data', (c) => { b += c; }); req.on('end', async () => { const r = await dispatch(req.method, u.pathname, Object.fromEntries(u.searchParams), b ? JSON.parse(b) : {}, WHO.role, WHO.user); json(r.c, r.b); }); return; }
    if (u.pathname.startsWith('/api/')) return json(404, { error: 'not found' });
    const f = path.join(DASH, u.pathname.replace(/^\/dashboards\//, '/')); if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (err, d) => { if (err) { res.writeHead(404); res.end(); return; } res.writeHead(200, { 'Content-Type': u.pathname.endsWith('.js') ? 'application/javascript' : u.pathname.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const url = 'http://127.0.0.1:' + srv.address().port + '/dashboards/switch-port-map.html';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  const wait = (p, fn, arg) => p.waitForFunction(fn, arg, { timeout: 15000 }).then(() => true, () => false);
  const T = (p) => p.textContent('#sw');
  try {
    const ctx = await browser.newContext({ viewport: { width: 1500, height: 1000 }, acceptDownloads: true });
    const p = await ctx.newPage(); p.on('pageerror', (x) => errs.push(x.message)); p.on('dialog', (d) => d.accept('SW-HIDDEN'));
    await p.goto(url); await wait(p, () => !document.getElementById('main').hidden && document.querySelector('[data-sw]'));
    ok(/0 \/ 2/.test(await p.textContent('#kpis')), 'nothing read yet');
    await p.click('[data-sw="acc-two"]'); ok(await wait(p, () => /no SSH login stored for ACC-TWO-SYN/.test(document.getElementById('sw').textContent)), 'a switch without a login says what to set up');
    await p.click('[data-sw="acc-syn"]'); await wait(p, () => document.getElementById('readnow'));
    await p.click('#readnow');
    ok(await wait(p, () => document.querySelectorAll('.face .port').length === 26), 'front panel: 24 copper ports + 2 uplinks');
    ok(/Read 26 ports/.test(await p.textContent('body')), 'read toast');
    ok(await p.$('.face .port[data-port="Te1/1/1"]') && /uplinks/.test(await p.textContent('.face')), 'uplink module drawn');
    const fill = (port) => p.$eval('.face .port[data-port="' + port + '"] rect.p', (r) => r.getAttribute('fill'));
    ok((await fill('Gi1/0/1')) === '#2fb344' && (await fill('Gi1/0/5')) === '#e5484d', 'status colours: connected green, err-disabled red');
    ok(/not read: show lldp/i.test(await T(p)), 'LLDP off is said, not hidden');
    // a port
    await p.click('.face .port[data-port="Gi1/0/2"]');
    ok(await wait(p, () => /SEP001122334455/.test(document.getElementById('sw').textContent)), 'port detail with the CDP neighbour');
    ok(/0011\.2233\.4455/.test(await T(p)) && /IP phone/.test(await T(p)) && /PC \/ laptop/.test(await T(p)), 'the phone and the PC behind it, typed apart');
    ok(/Synthetic HP Inc\./.test(await T(p)) && /6\.3 W/.test(await T(p)), 'vendor and PoE');
    // lenses
    await p.click('[data-lens="vlan"]'); ok(await wait(p, () => /VLAN 10 USERS/.test(document.querySelector('.legend').textContent)), 'VLAN lens with names');
    await p.click('[data-lens="type"]'); ok(/IP phone/.test(await p.textContent('.legend')) && (await fill('Gi1/0/4')) === '#fab005', 'type lens: the hub port reads as several devices');
    await p.click('[data-lens="find"]'); ok((await fill('Gi1/0/3')) === '#e5484d', 'findings lens');
    // findings + a fix
    ok(/err-disabled/.test(await T(p)) && /half duplex/.test(await T(p)) && /not authorised in Genian NAC/.test(await T(p)) && /A switch \(SW-HIDDEN\.as\.local\) is connected/.test(await T(p)), 'findings');
    await p.click('tr[data-goport="Gi1/0/8"] [data-fix]');
    ok(await wait(p, () => /Change plan .* proposed/.test(document.body.textContent)), 'a fix becomes a change plan');
    const plan = N.changes.list().find((x) => x.task && x.task.type === 'port-description');
    ok(!!plan && (plan.task.params.description === 'SW-HIDDEN' && plan.status === 'proposed'), 'the plan waits for approval with the description typed');
    // confirm a type
    await p.click('.face .port[data-port="Gi1/0/3"]'); await wait(p, () => document.querySelector('[data-label]'));
    await p.selectOption('[data-label="3c52.82aa.0003"]', 'camera');
    ok(await wait(p, () => /Recorded: 3c52\.82aa\.0003 is a Camera/.test(document.body.textContent)), 'a person confirms a device type');
    // where is it plugged in
    await p.fill('#fq', '10.10.0.21'); await p.click('#fgo');
    ok(await wait(p, () => /Gi1\/0\/1/.test(document.getElementById('fres').textContent) && /ACC-SYN/.test(document.getElementById('fres').textContent)), 'found by IP');
    // capacity + Excel
    await p.click('[data-tab="capacity"]'); ok(/forecast needs 7 daily samples/.test(await T(p)) && /Module 1: 96\.3 of 370 W/.test(await T(p)), 'capacity and PoE');
    const [dl] = await Promise.all([p.waitForEvent('download', { timeout: 10000 }), p.click('#xls')]);
    ok(/^switch-ports-ACC-SYN-\d{4}-\d{2}-\d{2}\.xlsx$/.test(dl.suggestedFilename()), 'Excel export');
    await p.click('[data-tab="ai"]'); ok(/AI port engineer is off/.test(await T(p)), 'AI off says why');
    ok(!(await p.evaluate(() => window.__xss)), 'a hostile host name stayed text');
    // viewer
    WHO = { user: 'vera.syn', role: 'viewer' }; await p.goto(url); await wait(p, () => document.querySelector('.face .port'));
    ok(await p.$eval('#findcard', (e) => e.hidden), 'viewer: no search');
    await p.click('.face .port[data-port="Gi1/0/2"]');
    ok(await wait(p, () => /visible to analysts and above/.test(document.getElementById('sw').textContent)), 'viewer: devices hidden, says why');
    ok(!/3c52\.82aa|0011\.2233|10\.10\.0\.21|LT-/.test(await p.textContent('body')), 'viewer: no MAC, IP or host name anywhere');
    ok(!(await p.$('#readnow')) && !(await p.$('[data-fix]')), 'viewer: no actions');
    const nav = fs.readFileSync(path.join(DASH, 'vendor', 'zyb-nav.js'), 'utf8');
    ok(/"h": "switch-port-map.html"/.test(nav) && /switch-port-map\.html/.test(fs.readFileSync(path.join(DASH, 'install-dashboards.sh'), 'utf8')), 'menu entry and installer');
    ok(/portmap: 'switch-port-map\.html'/.test(fs.readFileSync(path.join(DASH, 'vendor', 'zyb-menu.js'), 'utf8')), 'the portal\'s sample "Switch Port Mapping" opens this page');
    ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  } finally { await browser.close(); srv.close(); }
  console.log((bad ? 'FAILED ' : 'ok ') + (n - bad) + '/' + n);
  process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
