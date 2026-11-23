// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for vSphere Studio (dashboards/server/vsphere-studio.html) against the REAL ITAM engine (engine/vsphere-studio.js,
// pyengine/vsphere_studio_rules.py; the capacity collection, the AI Virtualization Administrator and the model stubbed) on SYNTHETIC
// vCenter data: health ring and KPIs, cluster cards with the host rack (a host not responding is marked), the host heat map, the
// look-first list, the workload-profile scatter, datastores, findings and plans, the VM table (search, filters, sort), a VM's drawer
// with its explained score and its 7-day lines, a host click filters the table, the read-only AI analyst, a hostile VM name stays
// text, nothing invented with nothing connected, and a viewer reads but cannot ask.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node vsphere-studio.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const ITAM = path.join(__dirname, '..', '..', 'backend', 'itam'), DASH = path.join(__dirname, '..', '..', 'ui');
const H = require(path.join(ITAM, 'tests', 'helpers'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const ADM = { user: 'syed', role: 'admin' }, OP = { user: 'nora.syn', role: 'operator' }, VIEW = { user: 'vera.syn', role: 'viewer' };
const XSS = '<img src=x onerror=alert(1)>';

(async () => {
  const e = await H.startApp({ noAi: true });
  const NOW = Date.now(), DAY = 86400000; let connected = true, histCalls = 0;
  const create = async (req) => {
    if (!req.messages.some((m) => Array.isArray(m.content) && m.content.some((c) => c.type === 'tool_result'))) return { model: 'claude-opus-5-5', stop_reason: 'tool_use', content: [{ type: 'tool_use', id: 'u1', name: 'clusters', input: {} }], usage: { input_tokens: 40, output_tokens: 10 } };
    return { model: 'claude-opus-5-5', stop_reason: 'end_turn', content: [{ type: 'text', text: 'PROD cannot survive a host failure: HA is off (synthetic).' }], usage: { input_tokens: 60, output_tokens: 20 } };
  };
  const sdk = class { constructor() { this.messages = { create }; } };
  require(path.join(ITAM, 'engine/duty')).registerDuty(e.app.srv, e.app, { noTimer: true, python: process.env.PYTHON || 'python3', vssSdk: sdk, vssKey: () => 'sk-ant-synthetic' });
  const P = 'vCenter HQ (synthetic)';
  const host = (name, cpu, mem, version, extra) => Object.assign({ platform: P, cluster: 'PROD', name, version, state: 'connected', maintenance: false, status: 'green', cpu_used_pct: cpu, mem_used_pct: mem, vcpu_ratio: 2, vms_on: 6, cores: 32, mem_gb: 512 }, extra || {});
  const vms = [];
  for (let i = 1; i <= 16; i++) vms.push({ id: 'vm-' + i, pid: 'vc1', platform: P, kind: 'vcenter', cluster: 'PROD', name: 'APP-SYN-' + String(i).padStart(2, '0'), host: i % 2 ? 'esx01' : 'esx02', power: 'on', vcpus: 4, mem_gb: 16, disk_gb: 80, cpu_pct: 10 + i, mem_used_pct: 30, guest_os: 'Windows Server 2022', snapshots: { count: 0, oldest: null }, consolidate: false, tools: 'running' });
  vms[0].snapshots = { count: 5, oldest: new Date(NOW - 10 * DAY).toISOString() }; vms[0].consolidate = true;
  vms[1].cpu_pct = 95; vms[2].name = XSS;
  vms.push({ id: 'vm-off', pid: 'vc1', platform: P, kind: 'vcenter', cluster: 'PROD', name: 'OLD-SYN', host: 'esx01', power: 'off', vcpus: 8, mem_gb: 64 });
  const rows = vms.filter((v) => v.power === 'on').map((v, i) => ({ platform: P, pid: 'vc1', id: v.id, samples: 300, cpu_p95: i < 8 ? 3 : i < 12 ? 20 : 75, mem_p95: i < 8 ? 15 : i < 12 ? 45 : 80 }));
  rows[3].vcpus_to = 2; rows[3].save_vcpu = 2;
  const report = () => (connected ? { settings: { cpu_max_pct: 80, mem_max_pct: 90, storage_max_pct: 80, vcpu_ratio: 4 }, last_run: { at: new Date(NOW).toISOString() },
    platforms: [{ id: 'vc1', label: P, kind: 'vcenter' }],
    clusters: [{ platform: P, kind: 'vcenter', name: 'PROD', hosts: 3, hosts_up: 2, vms: 17, vms_on: 16, cores: 96, vcpus: 64, mem_gb: 1536, vm_mem_gb: 256, cpu_used_pct: 50, mem_used_pct: 60, vcpu_ratio: 0.67, ha: false, drs: false, n_plus_1: true, room: { cpu: 10, mem: 0, limit: 'memory' }, status: 'green' }],
    hosts: [host('esx01', 92, 85, 'VMware ESXi 8.0.2'), host('esx02', 30, 40, 'VMware ESXi 8.0.2'), host('esx03', 20, 35, 'VMware ESXi 7.0.3', { state: 'notResponding' })],
    datastores: [{ platform: P, name: 'DS-SYN-01', capacity_gb: 1000, free_gb: 30, used_pct: 97, provisioned_pct: 120, accessible: true }, { platform: P, name: 'DS-SYN-02', capacity_gb: 1000, free_gb: 600, used_pct: 40, provisioned_pct: 200, accessible: true }],
    vms, storage_trend: { [P]: { days_of_history: 20, per_month: 3, days_to_limit: null } } } : { settings: {}, platforms: [], clusters: [], hosts: [], datastores: [], vms: [] });
  e.app.addons.virtCapacity = { report, overprov: () => ({ vms: connected ? rows : [] }), vmHistory: (q) => { histCalls++; return { days: 7, pid: q.pid, vm: q.vm, points: [0, 1, 2, 3, 4, 5].map((i) => ({ t: NOW - (5 - i) * 3600000, cpu: 10 + i * 5, mem: 30 + i })) }; } };
  e.app.addons.virtAdmin = { current: () => (connected ? [{ key: 'ha:PROD', kind: 'ha-off', severity: 'high', title: 'PROD: vSphere HA is off - a host failure leaves its VMs down', target: { type: 'cluster', name: 'PROD', cluster: 'PROD', platform: P, kind: 'vcenter' } }] : []),
    plans: () => [{ id: 'VCH-0001', item_key: 'ha:PROD', state: 'proposed', title: 'Turn on vSphere HA on PROD', requested_by: 'duty:virt' }], policy: () => ({ snapshot_warn_days: 3, snapshot_high_days: 7 }) };
  e.app.settings.update({ external_ai_allowed: true }, ADM);
  let WHO = OP;
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
  const base = 'http://127.0.0.1:' + srv.address().port + '/';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  const wait = (p, fn, arg) => p.waitForFunction(fn, arg, { timeout: 20000 }).then(() => true, () => false);
  try {
    const p = await browser.newPage({ viewport: { width: 1440, height: 1000 } }); p.on('pageerror', (x) => errs.push(x.message));
    p.on('dialog', (d) => { errs.push('dialog: ' + d.message()); d.dismiss(); });
    await p.goto(base + 'dashboards/vsphere-studio.html');
    ok(await wait(p, () => !document.getElementById('main').hidden && document.querySelectorAll('#vms tr[data-vm]').length === 17), 'all 17 VMs listed');
    ok(/critical|attention/i.test(await p.textContent('#state')) && /^\d+$/.test((await p.textContent('#ring b')).trim()), 'health ring and state');
    ok(/2 \/ 3/.test(await p.textContent('#kpis')) && /16 \/ 17/.test(await p.textContent('#kpis')), 'KPIs: hosts connected, VMs running');
    ok((await p.$$('#clusters .hst')).length === 3 && !!(await p.$('#clusters .hst.down')), 'host rack: three hosts, the one not responding is marked');
    const cl = await p.textContent('#clusters');
    ok(/HA off/.test(cl) && /DRS off/.test(cl) && /out of balance/.test(cl) && /version drift/.test(cl) && /N\+1/.test(cl), 'cluster card explains its score');
    ok((await p.$$('#heat tr')).length === 4, 'host heat map, a row per host');
    ok((await p.$$('#first .lf')).length >= 5 && /not responding/.test(await p.textContent('#first')), 'look-first list, ranked');
    ok((await p.$$('#scatter circle.p')).length === 16 && /idle/.test(await p.textContent('#leg')), 'workload profile scatter with its legend');
    ok(/DS-SYN-01/.test(await p.textContent('#ds')) && /full/.test(await p.textContent('#ds')) && /overcommitted/.test(await p.textContent('#ds')), 'datastores with risk');
    ok(/VCH-0001/.test(await p.textContent('#fnd')) && /HA is off/.test(await p.textContent('#fnd')), 'findings and change plans from the AI Virtualization Administrator');
    ok((await p.textContent('#vms')).includes(XSS) && !(await p.$('#vms img')), 'a hostile VM name stays text');
    // filters and sort
    await p.selectOption('#fi', 'unusual'); ok((await p.$$('#vms tr[data-vm]')).length === 1 && /usually at most/.test(await p.textContent('#vms')), 'unusual CPU filter');
    await p.selectOption('#fi', 'snap'); ok((await p.$$('#vms tr[data-vm]')).length === 1, 'old snapshots filter');
    await p.selectOption('#fi', 'rs'); ok((await p.$$('#vms tr[data-vm]')).length === 1 && /4 → 2 vCPU/.test(await p.textContent('#vms')), 'right-size filter');
    await p.selectOption('#fi', ''); await p.selectOption('#fp', 'off'); ok((await p.$$('#vms tr[data-vm]')).length === 1, 'power filter');
    await p.selectOption('#fp', ''); await p.selectOption('#fg', 'idle'); ok((await p.$$('#vms tr[data-vm]')).length === 8, 'profile filter');
    await p.selectOption('#fg', ''); await p.fill('#q', 'APP-SYN-1'); ok((await p.$$('#vms tr[data-vm]')).length >= 7, 'search');
    await p.fill('#q', ''); await p.click('table.vm th[data-s="name"]');
    ok(await p.evaluate(() => { const r = [...document.querySelectorAll('#vms tr[data-vm] td:first-child b')].map((b) => b.textContent); return r[0] <= r[1]; }), 'sort by name');
    // host click filters the table; VM drawer
    await p.click('#clusters .hst[data-host$="esx02"]');
    ok(await wait(p, () => document.getElementById('q').value === 'esx02' && document.querySelectorAll('#vms tr[data-vm]').length === 8), 'a host click shows its VMs');
    await p.fill('#q', '');
    await p.click('#vms tr[data-vm="vc1|vm-1"]');
    ok(await wait(p, () => !document.getElementById('dr').hidden && /Health \d+ \/ 100/.test(document.getElementById('dr').textContent)), 'the VM drawer opens');
    const dr = await p.textContent('#dr');
    ok(/oldest 10 days/.test(dr) && /consolidation/.test(dr) && /idle/.test(dr), 'its score explained and its profile');
    ok(await wait(p, () => document.querySelectorAll('#drh svg polyline').length === 2) && histCalls === 1, 'its 7-day CPU and memory lines');
    await p.keyboard.press('Escape'); ok(await p.isHidden('#dr'), 'Escape closes the drawer');
    await p.click('#scatter circle.p', { force: true }); ok(await wait(p, () => !document.getElementById('dr').hidden), 'a dot opens its VM'); await p.click('#drx');
    // AI
    ok(/Claude claude-opus-5-5/.test(await p.textContent('#ais')), 'AI analyst on');
    await p.fill('#aq', 'Which cluster cannot survive a host failure?'); await p.click('#go');
    ok(await wait(p, () => /cannot survive a host failure/.test(document.getElementById('out').textContent)) && /1 step\(s\): clusters/.test(await p.textContent('#out')), 'the analyst answers, its step shown');
    ok(e.app.store.auditTail(50).some((x) => x.action === 'vsphere.studio.ai.ask' && x.by === 'nora.syn'), 'the question is audited');
    ok(await p.evaluate(() => { const a = (window.ZYB_NAV || []).find((x) => x.id === 'srv'); return !!(a && a.pages.some((x) => x.h === 'vsphere-studio.html' && x.g === 'Virtualization')); }), 'the menu has the page under Virtualization');
    WHO = VIEW; await p.reload();
    ok(await wait(p, () => document.querySelectorAll('#vms tr[data-vm]').length === 17) && await p.isDisabled('#go'), 'a viewer reads but cannot ask');
    connected = false; await p.reload();
    ok(await wait(p, () => /not connected/i.test(document.getElementById('state').textContent)), 'nothing connected: NOT CONNECTED');
    ok(/No vCenter or ESXi host connected/.test(await p.textContent('#clusters')) && /No VM reported/.test(await p.textContent('#vms')), 'says what to connect, never a sample');
  } finally { await browser.close(); srv.close(); await e.close(); }
  ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks');
  process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
