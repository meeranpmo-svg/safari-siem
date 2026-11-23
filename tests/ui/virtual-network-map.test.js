// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for the Virtual Network Map (dashboards/server/virtual-network-map.html) against the REAL ITAM engine
// (engine/virt-network.js; the vCenter / Prism read stubbed with SYNTHETIC facts): with nothing connected it says what to
// connect; the map shows each host's uplinks (link / no link), switches and port groups with VLANs, the odd one marked; the VLAN
// matrix marks a differing VLAN and a missing port group; a finding shows the learned confidence, the fix and the rollback; an
// operator proposes it, cannot approve it, a second administrator approves, the operator marks it run, the next read verifies it
// and records the change; Trace a VM shows the path and the problem on it; Nutanix networks; a hostile port-group name stays text;
// a viewer reads only; the menu entry.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node virtual-network-map.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const ITAM = path.join(__dirname, '..', '..', 'backend', 'itam'), DASH = path.join(__dirname, '..', '..', 'ui');
const H = require(path.join(ITAM, 'tests', 'helpers'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const ADM = { user: 'syed', role: 'admin' }, ADM2 = { user: 'asif.syn', role: 'admin' }, OP = { user: 'nora.syn', role: 'operator' }, VW = { user: 'vera.syn', role: 'viewer' };
const XSS = '<img src=x onerror="window.__xss=1">';
const pn = (d, up = true) => ({ device: d, mac: '00:50:56:00:00:0' + d.slice(-1), up, speed_mb: up ? 10000 : null });
function host(id) { return { id, name: id + '.syn', cluster_id: 'c1', state: 'connected', pnics: [pn('vmnic0'), pn('vmnic1')], switches: [{ id: 'vss:vSwitch0', kind: 'standard', name: 'vSwitch0', mtu: 1500, uplinks: ['vmnic0', 'vmnic1'], active: [], standby: [], security: { promiscuous: false, mac_changes: false, forged: false } }],
  portgroups: [{ name: 'Servers', vlan: 20, switch: 'vss:vSwitch0' }, { name: 'DMZ', vlan: 30, switch: 'vss:vSwitch0' }, { name: 'Lab ' + XSS, vlan: 99, switch: 'vss:vSwitch0' }], vmks: [{ device: 'vmk0', portgroup: 'Management', ip: '10.0.0.1', mtu: 1500, services: ['management'] }] }; }
function facts(fixed) {
  const h = ['esx1', 'esx2', 'esx3'].map(host);
  if (!fixed) h[2].portgroups[0] = { name: 'Servers', vlan: 21, switch: 'vss:vSwitch0' };
  h[1].portgroups = h[1].portgroups.filter((p) => p.name !== 'DMZ'); h[1].pnics[1] = pn('vmnic1', false);
  return [{ id: 'vc1', label: 'VC-SYN', kind: 'vsphere', at: new Date().toISOString(), clusters: [{ id: 'c1', name: 'PROD-SYN' }], hosts: h, dvs: [], read_errors: [],
    networks: [{ id: 'network-1', name: 'Servers', kind: 'standard' }], vms: [{ id: 'vm-1', name: 'app01-syn', host_id: 'esx3', power: 'on', network_ids: ['network-1'], nics: [{ network: 'Servers', mac: '00:50:56:aa:00:01', connected: true, ips: ['10.0.20.5'] }], guest_read: true }] },
  { id: 'ntx1', label: 'PRISM-SYN', kind: 'nutanix', at: new Date().toISOString(), clusters: [{ id: 'n1', name: 'NTX-SYN' }], read_errors: [], hosts: [{ id: 'a1', name: 'ahv1', cluster_id: 'n1', state: 'connected', pnics: [{ device: 'eth0', up: true, speed_mb: 10000 }, { device: 'eth1', up: true, speed_mb: 1000 }] }],
    networks: [{ id: 'n-1', name: 'VLAN20-Servers', kind: 'ahv', vlan: 20 }, { id: 'n-2', name: 'Old-Servers', kind: 'ahv', vlan: 20 }], vms: [] }];
}

(async () => {
  const e = await H.startApp({ noAi: true });
  let F = [], sources = [];
  const capacity = { networkFacts: () => F, networkRead: async () => F.map((p) => ({ platform_id: p.id, label: p.label, ok: true })), networkSources: () => sources };
  require(path.join(ITAM, 'engine/duty')).registerDuty(e.app.srv, e.app, { noTimer: true, vnCapacity: capacity });
  if (e.app.addons.updateHealth) e.app.addons.updateHealth.view = () => ({ pages: [] });
  let WHO = ADM;
  const srv = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://x'), json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u.pathname === '/dashboards/whoami.json') return json(200, WHO);
    if (u.pathname.startsWith('/api/itam/')) {
      const h = Object.assign({}, req.headers, { 'x-sentra-proxy-secret': H.SECRET, 'x-auth-user': WHO.user, 'x-auth-role': WHO.role });
      const up = http.request({ host: '127.0.0.1', port: e.port, method: req.method, path: req.url, headers: h }, (r) => { res.writeHead(r.statusCode, r.headers); r.pipe(res); });
      req.pipe(up); return;
    }
    if (u.pathname.startsWith('/api/')) return json(404, { error: 'not in this test' });
    const f = path.join(DASH, u.pathname.replace(/^\/dashboards\//, '/')); if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (err, d) => { if (err) { res.writeHead(404); res.end(); return; } res.writeHead(200, { 'Content-Type': u.pathname.endsWith('.js') ? 'application/javascript' : u.pathname.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const url = 'http://127.0.0.1:' + srv.address().port + '/dashboards/virtual-network-map.html';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  const wait = (p, fn, arg) => p.waitForFunction(fn, arg, { timeout: 15000 }).then(() => true, () => false);
  const tab = (p, t) => p.click('#tabs [data-tab="' + t + '"]');
  try {
    const p = await browser.newPage({ viewport: { width: 1440, height: 1000 } }); p.on('pageerror', (x) => errs.push(x.message));
    p.on('dialog', (d) => d.accept());
    await p.goto(url);
    ok(await wait(p, () => /No vCenter or Nutanix Prism is connected/.test(document.body.textContent)), 'nothing connected: says what to connect, nothing invented');
    F = facts(); sources = [{ id: 'vc1', label: 'VC-SYN', kind: 'vcenter', has_login: true }];
    WHO = OP; await p.goto(url);
    await wait(p, () => !document.getElementById('read').hidden); await p.click('#read');   // the first read: the baseline the next read is compared with
    ok(await wait(p, () => /Read 2 platform/.test(document.body.textContent)), 'first read');
    ok(await wait(p, () => document.querySelectorAll('.host').length === 3), 'map: the 3 hosts of PROD-SYN');
    ok(!(await p.$eval('#read', (b) => b.hidden)), 'operator: Read now offered');
    ok(/vmnic1 no link/.test(await p.textContent('#view')), 'uplink without link shown');
    ok(await p.$$eval('.host .chip.c-bad', (L) => L.some((c) => /Servers · VLAN 21/.test(c.textContent))), 'the odd VLAN marked on its host');
    await tab(p, 'matrix');
    ok(await wait(p, () => document.querySelector('td.mx.bad') && /21/.test(document.querySelector('td.mx.bad').textContent)), 'matrix: the differing VLAN in red');
    ok(await p.$$eval('td.mx.miss', (L) => L.length >= 1), 'matrix: the missing port group in orange');
    ok(/VLAN 20 \(2\/3\)/.test(await p.textContent('#view')), 'matrix: the learned value with its agreement');
    await tab(p, 'findings');
    await p.click('[data-f^="vlan-mismatch:"]');
    ok(await wait(p, () => /Learned from the peer hosts: 67%/.test(document.getElementById('fdet').textContent)), 'finding: the learned confidence');
    const det = await p.textContent('#fdet');
    ok(/esxcli network vswitch standard portgroup set -p "Servers" -v 20/.test(det) && /-v 21/.test(det), 'fix and rollback shown');
    await p.click('[data-prop]');
    ok(await wait(p, () => /proposed - another administrator approves/.test(document.body.textContent)), 'operator proposed the fix');
    await tab(p, 'proposals');
    ok(!(await p.$('[data-dec]')), 'operator cannot approve');
    WHO = ADM; await p.goto(url); await tab(p, 'proposals');
    ok(await wait(p, () => document.querySelector('[data-dec^="approve:"]')), 'admin sees Approve');
    // the requester's own proposal is refused for the requester: here the requester is the operator, so a second admin approves
    WHO = ADM2; await p.goto(url); await tab(p, 'proposals'); await p.click('[data-dec^="approve:"]');
    ok(await wait(p, () => /Approved/.test(document.body.textContent)), 'second administrator approved');
    WHO = OP; await p.goto(url); await tab(p, 'proposals');
    ok(await wait(p, () => document.querySelector('[data-done]')), 'operator: I ran it');
    await p.click('[data-done]');
    ok(await wait(p, () => /Marked as run/.test(document.body.textContent)), 'marked as run');
    F = facts(true); await p.click('#read');
    ok(await wait(p, () => /Read 2 platform/.test(document.body.textContent)), 'read now');
    await tab(p, 'proposals');
    ok(await wait(p, () => /verified/.test(document.getElementById('view').textContent)), 'the next read verified the fix');
    await tab(p, 'changes');
    ok(/"Servers" VLAN 21 -> 20/.test(await p.textContent('#view')), 'the change is recorded');
    F = facts(); await p.click('#read'); await wait(p, () => /Read 2 platform/.test(document.body.textContent));
    await tab(p, 'trace'); await p.fill('#vmq', 'app01'); await p.click('#trgo');
    ok(await wait(p, () => /VLAN 21/.test(document.getElementById('trout').textContent) && /vSwitch0/.test(document.getElementById('trout').textContent)), 'trace: the path with its VLAN and switch');
    ok(/Problems on this path/i.test(await p.textContent('#trout')), 'trace: the problem on the path');
    await tab(p, 'map'); await p.selectOption('#pl', 'ntx1');
    ok(await wait(p, () => /AHV networks/.test(document.body.textContent) && /Old-Servers/.test(document.body.textContent)), 'Nutanix networks');
    WHO = VW; await p.goto(url);
    ok(await wait(p, () => document.querySelectorAll('.host').length === 3), 'viewer reads the map');
    ok(await p.$eval('#read', (b) => b.hidden) && !(await p.$('#tabs [data-tab="ai"]')), 'viewer: no Read now, no AI');
    await tab(p, 'findings'); await p.click('[data-f^="vlan-mismatch:"]');
    ok(await wait(p, () => /Fix/.test(document.getElementById('fdet').textContent)) && !(await p.$('[data-prop]')), 'viewer: no Propose');
    ok(!(await p.evaluate(() => window.__xss)), 'a hostile port-group name stayed text');
    const nav = fs.readFileSync(path.join(DASH, 'vendor', 'zyb-nav.js'), 'utf8');
    ok(/"h": "virtual-network-map.html"/.test(nav) && /virtual-network-map\.html/.test(fs.readFileSync(path.join(DASH, 'install-dashboards.sh'), 'utf8')), 'menu entry and installer');
    ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  } finally { await browser.close(); srv.close(); await e.close(); }
  console.log((bad ? 'FAILED ' : 'ok ') + (n - bad) + '/' + n);
  process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
