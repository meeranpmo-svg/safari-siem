// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// network-onboarding.html against the REAL SIEM onboarding engine (sentra-siem engine/netops/onboard.js via routes.js; device reads
// stubbed) with SYNTHETIC devices: the administrator picks FortiGate, sees the read-only account guide and the syslog setup, a
// missing key is refused with the field named, then the device is onboarded and verified step by step; a Cisco UCS with an admin
// login is blocked as over-privileged; a Cisco core switch is onboarded; both are added to the route map; the architecture draws
// the layers and links; the configuration matrix opens a failing control and a fix becomes a change plan (FortiGate change and
// rollback; Cisco IOS automatic after approval); Excel; a hostile finding title stays text; operator and viewer rights.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node network-onboarding.test.js
const http = require('http'), fs = require('fs'), os = require('os'), path = require('path');
const DASH = path.resolve(__dirname, '../../ui');
const SIEM = process.env.SENTRA_SIEM || path.resolve(__dirname, '../..', 'backend', 'siem');
const routes = require(path.join(SIEM, 'engine/netops/routes'));
const { createState } = require(path.join(SIEM, 'engine/soc/state'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const XSS = '<img src=x onerror="window.__xss=1">';

(async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ob-page-')), secrets = path.join(dir, 'secrets.json'); fs.writeFileSync(secrets, '{}', { mode: 0o600 });
  const state = await createState({ dir: path.join(dir, 'state') });
  const config = { netops: { enabled: false, syslog_target: '10.0.0.50' } };
  Object.defineProperty(config, 'secrets', { value: {}, enumerable: false, writable: true }); Object.defineProperty(config, '_paths', { value: { secrets }, enumerable: false });
  const snaps = {}, SNAP = {
    'fgt-jed-01': { reach: { sent: 3, received: 3, rtt_avg_ms: 11 }, sources: ['ping', 'api'], system: { model: 'FortiGate-100F', version: 'v7.4.3' }, security: { at: Date.now(), facts: { fg: true }, items: [{ kind: 'mgmt-telnet', severity: 'high', key: 'port1', title: 'Telnet administration enabled on port1 ' + XSS, evidence: ['allowaccess: ping https ssh telnet'], rec: 'Remove telnet' }] } },
    'ucs-dc-01': { reach: { sent: 3, received: 3 }, sources: ['ping', 'api'], system: { model: 'UCSB-5108-AC2', version: 'UCS Manager 4.2(3h)' }, ucs: { read_only: false, privileges: ['admin'], faults: [] } },
    'core-dc-01': { reach: { sent: 3, received: 3 }, sources: ['ping', 'snmp'], system: { model: 'C9500-24Y4C', version: '17.9.4' }, security: { at: Date.now(), items: [{ kind: 'telnet-open', severity: 'high', key: 'telnet', title: 'Telnet is open on CORE-DC-01', evidence: [] }] } } };
  const poller = { snapshot: (id) => snaps[id] || null, snapshots: () => snaps, stats: () => ({}), forget() {}, start() {}, pollDevice: async (id) => { snaps[id] = Object.assign({ device_id: id, at: Date.now(), ok: true, errors: [], sources: ['ping'] }, SNAP[id] || {}); return snaps[id]; } };
  const runner = async (q) => (q.op === 'version' ? { ok: true } : q.op === 'hostkey' ? { ok: true, type: 'ssh-rsa', key: 'K', fingerprint: 'SHA256:core' } : { ok: false, error: 'not in this test' });
  const N = routes.createNetops({ state, config, log: { info() {}, warn() {}, error() {} }, poller, cliRunner: runner });
  const R = []; routes.register({ route: (m, p, h) => { R.push({ m, re: new RegExp('^' + p.replace(/:[a-z]+/g, '([^/]+)') + '$'), keys: (p.match(/:[a-z]+/g) || []).map((k) => k.slice(1)), h }); } }, { state, config, log: { error() {}, info() {} }, netops: N });
  const RANK = { viewer: 0, analyst: 1, operator: 2, admin: 3 };
  let WHO = { user: 'syed', role: 'admin' };
  const srv = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://x'), json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u.pathname === '/dashboards/whoami.json') return json(200, WHO);
    if (u.pathname.startsWith('/api/soc/netops/')) { let b = ''; req.on('data', (c) => { b += c; }); req.on('end', async () => {
      const r = R.find((x) => x.m === req.method && x.re.test(u.pathname)); if (!r) return json(404, { error: 'not found' });
      const mm = r.re.exec(u.pathname), params = {}; r.keys.forEach((k, i) => { params[k] = decodeURIComponent(mm[i + 1]); });
      const out = {}, ctx = { role: WHO.role, user: WHO.user, body: b ? JSON.parse(b) : {}, params, query: Object.fromEntries(u.searchParams), path: u.pathname, need(x) { if (RANK[WHO.role] < RANK[x]) { out.c = 403; out.e = 'requires ' + x; return false; } return true; }, audit() {}, fail(c, e) { out.c = c; out.e = e; } };
      const rv = await r.h(ctx); if (out.c) return json(out.c, { error: out.e }); json(200, rv); }); return; }
    if (u.pathname.startsWith('/api/')) return json(404, { error: 'not found' });
    const f = path.join(DASH, u.pathname.replace(/^\/dashboards\//, '/')); if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (err, d) => { if (err) { res.writeHead(404); res.end(); return; } res.writeHead(200, { 'Content-Type': u.pathname.endsWith('.js') ? 'application/javascript' : u.pathname.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const url = 'http://127.0.0.1:' + srv.address().port + '/dashboards/network-onboarding.html';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  const wait = (p, fn, arg) => p.waitForFunction(fn, arg, { timeout: 15000 }).then(() => true, () => false);
  const V = (p) => p.textContent('#view');
  const fill = async (p, o) => { for (const [k, v] of Object.entries(o)) await p.fill('#' + k, v); };
  try {
    const ctx = await browser.newContext({ viewport: { width: 1500, height: 1000 }, acceptDownloads: true });
    const p = await ctx.newPage(); p.on('pageerror', (x) => errs.push(x.message));
    await p.goto(url); await wait(p, () => !document.getElementById('main').hidden && document.querySelector('[data-vendor]'));
    ok((await p.$$('[data-vendor]')).length === 7, 'seven device types (UPS included)');
    ok(/UPS-MIB/.test(await p.evaluate(() => document.body.innerText)), 'the UPS type is offered');
    // FortiGate
    await p.click('[data-vendor="fortigate"]');
    ok(await wait(p, () => /REST API Admin/.test(document.getElementById('view').textContent) && /set server 10\.0\.0\.50/.test(document.getElementById('view').textContent)), 'read-only account guide and syslog setup');
    await fill(p, { 'o-name': 'FGT-JED-01', 'o-ip': '10.2.0.1', 'o-site': 'Jeddah Branch' }); await p.click('#go');
    ok(await wait(p, () => /credentials\.api\.token/.test(document.body.textContent)), 'a missing API key is refused with the field named');
    await p.fill('#c-token', 'fg-key-synthetic-123'); await p.click('#go');
    ok(await wait(p, () => /Verification - fgt-jed-01/.test(document.getElementById('view').textContent)), 'verification shown');
    ok(/Reachable from the SIEM/.test(await V(p)) && /ping 11 ms/.test(await V(p)) && /does not tell its account/.test(await V(p)) && /1 finding\(s\), 1 high/.test(await V(p)), 'steps: reach, read, privilege (manual), baseline');
    // UCS with an admin login
    await p.click('[data-vendor="cisco-ucs"]'); await wait(p, () => document.getElementById('c-user'));
    ok(/create role read-only/.test(await V(p)), 'UCS read-only user steps');
    await fill(p, { 'o-name': 'UCS-DC-01', 'o-ip': '10.0.7.1', 'o-site': 'Riyadh DC', 'c-user': 'admin', 'c-pass': 'Pw-ucs-1' }); await p.click('#go');
    ok(await wait(p, () => /over-privileged: admin/.test(document.getElementById('view').textContent) && /blocked/.test(document.getElementById('view').textContent)), 'an admin UCS login is refused');
    ok(N.inventory.get('ucs-dc-01').poll.api === false, 'its polling is switched off');
    // Cisco core switch
    await p.click('[data-vendor="cisco-ios"]'); await wait(p, () => document.getElementById('s-user'));
    await p.selectOption('#o-role', 'core');
    await fill(p, { 'o-name': 'CORE-DC-01', 'o-ip': '10.0.0.2', 'o-site': 'Riyadh DC', 's-user': 'sentra-snmp', 's-auth': 'auth-pass-1', 's-priv': 'priv-pass-1', 'h-user': 'sentra-ro', 'h-pass': 'Pw-ssh-1' }); await p.click('#go');
    ok(await wait(p, () => /SHA256:core/.test(document.getElementById('view').textContent)), 'SSH host key fingerprint to compare and trust');
    // onboarded list + route map
    await p.click('[data-tab="devices"]'); ok(await wait(p, () => document.querySelectorAll('[data-map]').length >= 2), 'onboarded devices with "Add to the route map"');
    await p.click('[data-map="core-dc-01"]'); ok(await wait(p, () => /In the route map \(version 1/.test(document.body.textContent)), 'core switch placed in the route map');
    await wait(p, () => !document.querySelector('[data-map="core-dc-01"]'));
    await p.click('[data-map="fgt-jed-01"]'); ok(await wait(p, () => /In the route map \(version 2/.test(document.body.textContent)), 'FortiGate placed (next version)');
    ok(N.routemap.map().nodes.some((x) => x.device === 'fgt-jed-01'), 'the route map holds it');
    // architecture
    await p.click('[data-tab="arch"]');
    ok(await wait(p, () => document.querySelectorAll('.arch .nd').length === 3), 'three devices drawn');
    ok(/Internal & branch firewalls/.test(await V(p)) && /Core/.test(await V(p)) && /Compute \(UCS\)/.test(await V(p)), 'layers');
    await p.click('.arch .nd[data-node="fgt-jed-01"]'); ok(await wait(p, () => /Secure management \(SSH \/ HTTPS only\)/.test(document.getElementById('view').textContent)), 'device controls on click');
    // configuration architecture + fix
    await p.click('[data-tab="config"]'); ok(await wait(p, () => document.querySelector('table.mx')), 'matrix');
    await p.click('td[data-cell="fgt-jed-01|MGMT"]'); ok(await wait(p, () => /NCA ECC 2-5, 2-8/.test(document.getElementById('view').textContent)), 'control detail with its framework');
    await p.click('[data-fix="fgt-jed-01|MGMT"]');
    ok(await wait(p, () => /Change plan proposed/.test(document.getElementById('view').textContent) && /set allowaccess ping https ssh telnet/.test(document.getElementById('view').textContent)), 'FortiGate change plan with change and rollback');
    ok(/applied by an engineer after approval/.test(await V(p)), 'firewall fix applied by a person after approval');
    await p.click('td[data-cell="core-dc-01|MGMT"]'); await p.click('[data-fix="core-dc-01|MGMT"]');
    ok(await wait(p, () => /runs automatically after approval/.test(document.getElementById('view').textContent)), 'Cisco IOS fix runs automatically after approval');
    const [dl] = await Promise.all([p.waitForEvent('download', { timeout: 10000 }), p.click('#xls')]);
    ok(/^network-architecture-\d{4}-\d{2}-\d{2}\.xlsx$/.test(dl.suggestedFilename()), 'Excel export');
    ok(!(await p.evaluate(() => window.__xss)), 'a hostile finding title stayed text');
    // operator / viewer
    WHO = { user: 'nora.syn', role: 'operator' }; await p.goto(url); await wait(p, () => !document.getElementById('main').hidden);
    await p.click('[data-vendor="paloalto"]'); ok(/An administrator onboards devices/.test(await V(p)) && !(await p.$('#go')), 'operator: no onboarding form');
    await p.click('[data-tab="config"]'); await p.click('td[data-cell="fgt-jed-01|MGMT"]'); ok(!!(await p.$('[data-fix]')), 'operator can propose a fix');
    WHO = { user: 'vera.syn', role: 'viewer' }; await p.goto(url); await wait(p, () => !document.getElementById('main').hidden);
    await p.click('[data-tab="devices"]'); ok(!(await p.$('[data-verify]')) && !(await p.$('[data-map]')), 'viewer: read-only');
    const nav = fs.readFileSync(path.join(DASH, 'vendor', 'zyb-nav.js'), 'utf8');
    ok(/"h": "network-onboarding.html"/.test(nav) && /network-onboarding\.html/.test(fs.readFileSync(path.join(DASH, 'install-dashboards.sh'), 'utf8')), 'menu entry and installer');
    ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  } finally { await browser.close(); srv.close(); }
  console.log((bad ? 'FAILED ' : 'ok ') + (n - bad) + '/' + n);
  process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
