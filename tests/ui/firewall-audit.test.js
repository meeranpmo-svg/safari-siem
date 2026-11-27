// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Firewall & Security Device Audit page (firewall-audit.html) driven by the REAL audit routes (backend/siem engine/netops/fw-audit.js)
// over a fake FortiManager and switch capture, SYNTHETIC configurations: nothing run yet → the operator runs it; tiles, three charts,
// what the AI noticed, the most common failures; a device opens with its tests by area, evidence, fix and references; findings
// filter by severity; an administrator accepts a risk (shown as accepted); the runner cannot sign off, another administrator can;
// a viewer is refused; CSV export; hostile text stays text; menu entry and installer.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node firewall-audit.test.js
const http = require('http'), fs = require('fs'), os = require('os'), path = require('path');
const DASH = path.resolve(__dirname, '../../ui'), SIEM = path.resolve(__dirname, '../../backend/siem');
const FA = require(path.join(SIEM, 'engine/netops/fw-audit')), { createState } = require(path.join(SIEM, 'engine/soc/state'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const XSS = '<img src=x onerror=window.PWN=1>';
const pol = (id, o) => Object.assign({ policyid: id, name: 'r' + id, status: 'enable', action: 'accept', srcintf: [{ name: 'internal' }], dstintf: [{ name: 'wan1' }], srcaddr: [{ name: 'LAN-SYN' }], dstaddr: [{ name: 'all' }], service: [{ name: 'HTTPS' }], schedule: 'always', logtraffic: 'all', 'utm-status': 'enable' }, o || {});
const S1 = { global: { admintimeout: 480, 'strong-crypto': 'disable' }, admins: [{ name: 'admin', trusthost1: '0.0.0.0 0.0.0.0', 'two-factor': 'disable' }, { name: XSS, trusthost1: '0.0.0.0 0.0.0.0' }], password_policy: { status: 'disable' },
  interfaces: [{ name: 'wan1', role: 'wan', allowaccess: 'ping https ssh' }], policies: [pol(1, { srcintf: [{ name: 'any' }], dstintf: [{ name: 'any' }], srcaddr: [{ name: 'all' }], service: [{ name: 'ALL' }] }), pol(2, { logtraffic: 'disable' })], hits: [{ policyid: 1, hit_count: 10 }, { policyid: 2, hit_count: 0 }],
  ntp: { ntpsync: 'enable' }, log_setting: {}, syslog: { status: 'enable', server: '10.0.0.9' }, faz: {}, snmp_community: [], snmp_user: [], ha: { mode: 'a-p' }, autoupdate: { status: 'enable' }, phase1: [], sslvpn: { status: 'disable' } };
(async () => {
  const state = createState({ dir: fs.mkdtempSync(path.join(os.tmpdir(), 'fwa-ui-')) }), R = {};
  const fmgApi = { readAudit: async () => [{ dev: { id: 'FG1', name: 'FW-SYN-HQ', model: 'FortiGate-200F', site: 'Riyadh' }, sections: S1, unread: {} }, { dev: { id: 'FG2', name: 'FW-SYN-JUB', model: 'FortiGate-60F', site: 'Jubail' }, sections: Object.fromEntries(Object.entries(S1).filter(([k]) => !['admins', 'password_policy', 'global', 'hits', 'phase1', 'sslvpn', 'snmp_user', 'snmp_community'].includes(k))), unread: { admins: 'no permission (synthetic)' } }],
    fleet: () => ({ devices: [{ name: 'FW-SYN-HQ', model: 'FortiGate-200F', firmware: '7.2.8', conf: 'insync', findings: [], licences: [] }] }) };
  const configAudit = { list: () => [{ id: 'sw1', name: 'SW-SYN-CORE', vendor: 'h3c-comware', site: 'Riyadh', text: 'telnet server enable\nsnmp-agent community read cipher x', at: new Date().toISOString() }] };
  FA.register({ route: (m, p, h) => { R[m + ' ' + p] = h; } }, { config: {}, state, log: { error() {} }, fmgApi, netopsInstance: { configAudit }, noTimers: true });
  const RANK = { viewer: 1, analyst: 2, operator: 3, admin: 4 };
  let WHO = { user: 'op.syn', role: 'operator' };
  const srv = http.createServer((req, res) => { const u = new URL(req.url, 'http://x');
    const json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u.pathname === '/dashboards/whoami.json') return json(200, WHO);
    if (u.pathname.startsWith('/api/soc/')) { let raw = ''; req.on('data', (c) => { raw += c; }); req.on('end', async () => {
      const h = R[req.method + ' ' + u.pathname]; if (!h) return json(404, { error: 'not here' });
      const o = {}, ctx = { role: WHO.role, user: WHO.user, body: raw ? JSON.parse(raw) : undefined, params: {}, audit() {}, ok(x) { o.s = 200; o.b = x; }, fail(c, m) { o.s = c; o.b = { error: m }; }, need(r) { if ((RANK[WHO.role] || 0) >= (RANK[r] || 0)) return true; this.fail(403, 'forbidden'); return false; } };
      const rv = await h(ctx); if (o.s === undefined) { o.s = 200; o.b = rv; } json(o.s, o.b); }); return; }
    if (u.pathname.startsWith('/api/')) return json(404, {});
    fs.readFile(path.join(DASH, u.pathname.replace(/^\/dashboards\//, '/')), (err, d) => { if (err) { res.writeHead(404); return res.end(); } res.writeHead(200, { 'Content-Type': u.pathname.endsWith('.js') ? 'application/javascript' : u.pathname.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); }); });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const url = 'http://127.0.0.1:' + srv.address().port + '/dashboards/firewall-audit.html?standalone=1';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright'); const browser = await chromium.launch(), errs = [];
  let PROMPTS = [];
  const open = async (sel) => { const p = await browser.newPage({ viewport: { width: 1500, height: 1100 }, acceptDownloads: true }); p.on('pageerror', (x) => errs.push(x.message)); p.on('dialog', (d) => d.accept(d.type() === 'prompt' ? (PROMPTS.shift() || '') : undefined)); await p.goto(url); await p.waitForSelector(sel, { timeout: 15000 }); return p; };
  try {
    let p = await open('#none:not([hidden])');
    ok(/No audit yet/.test(await p.textContent('#none')) && !(await p.$eval('#rf', (x) => x.hidden)), 'nothing run yet: the operator can run it');
    await p.click('#rf'); await p.waitForSelector('#main:not([hidden])', { timeout: 15000 });
    const kp = (await p.$eval('#kp', (x) => x.innerText)).replace(/\s+/g, ' ');
    ok(/Devices audited 3 2 firewall\(s\) · 1 switch/.test(kp) && /Critical \d+/.test(kp) && /2 any-any/.test(kp), 'tiles: ' + kp);
    ok((await p.$$('.g3 canvas')).length === 3, 'three charts');
    if (process.env.SHOT) { await p.waitForTimeout(800); await p.screenshot({ path: process.env.SHOT }); }   // optional: a picture for review
    ok(/critical finding/.test(await p.textContent('#ins')) && /partly checked/.test(await p.textContent('#ins')), 'what the AI noticed');
    ok(/FW-01/.test(await p.textContent('#top')), 'most common failures');
    ok(!(await p.evaluate(() => window.PWN)), 'hostile text stays text');
    await p.click('tr[data-dev="FG2"]'); await p.waitForSelector('#drw.open');
    const dr = await p.textContent('#db'); ok(/Rule base/.test(dr) && /not checked/.test(dr) && /admins \(no permission/.test(dr) && /NCA ECC 2-5-3/.test(dr) && /set logtraffic all/.test(dr), 'a device: tests by area, not checked, fix, references');
    await p.click('#dclose');
    await p.click('[data-sf="critical"]'); ok((await p.$$eval('#finds tbody tr', (r) => r.every((x) => /critical/.test(x.innerText)))), 'filter: critical');
    ok(!(await p.$('[data-acc]')), 'an operator does not accept risk');
    ok(/another person signs off/.test(await p.textContent('#runs')), 'the runner cannot sign off');
    const dl = p.waitForEvent('download'); await p.click('#csv'); const f = await dl; ok(/firewall-audit-.*\.csv/.test(f.suggestedFilename()), 'CSV export');
    await p.close();
    WHO = { user: 'sec.syn', role: 'admin' }; p = await open('#main:not([hidden])');
    PROMPTS = ['compensated by the jump host only (synthetic)', '2027-01-15']; await p.click('[data-sf="all"]');
    await p.click('[data-acc="FG1"][data-test="FW-13"]'); await p.waitForFunction(() => /accepted to 2027-01-15/.test(document.getElementById('finds').textContent), null, { timeout: 8000 }).catch(() => {});
    ok(/accepted to 2027-01-15/.test(await p.textContent('#finds')), 'an administrator accepts a risk with an end date');
    PROMPTS = ['reviewed (synthetic)']; await p.click('[data-sign]'); await p.waitForFunction(() => /signed by sec\.syn/.test(document.getElementById('runs').textContent), null, { timeout: 8000 }).catch(() => {});
    ok(/signed by sec\.syn/.test(await p.textContent('#runs')), 'another administrator signs off');
    await p.close();
    WHO = { user: 'vera.syn', role: 'viewer' }; p = await open('#err .err'); ok(/analysts and above/.test(await p.textContent('#err')), 'a viewer is refused'); await p.close();
    ok(fs.readFileSync(path.join(DASH, 'vendor/zyb-nav.js'), 'utf8').includes('"h": "firewall-audit.html"') && / firewall-audit\.html /.test(fs.readFileSync(path.join(DASH, 'install-dashboards.sh'), 'utf8')), 'menu entry and installer');
    ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  } finally { await browser.close(); srv.close(); }
  console.log((bad ? 'FAILED ' : 'ok ') + (n - bad) + '/' + n + ' firewall-audit checks'); process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
