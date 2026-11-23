// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for dashboards/server/cisco-update.html against the REAL ITAM engine (engine/cisco-update.js through duty.js), with a
// SYNTHETIC cisco-support (PSIRT advisories per release, Smart Net rows). An administrator sets the target release on Policy; the
// overview names what to do first; Devices filters and the drawer names every priority point; Advisories shows Cisco links only for
// cisco.com; an operator plans the Critical device and submits it; the same person is offered no Approve; a second person approves;
// "Verify & complete" keeps the plan open until the device reports the target, then completes it; a hash opens its tab; every value
// (a hostile device name) is escaped; the portal's six Cisco Update views redirect here.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node cisco-update.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const ITAM = path.join(__dirname, '..', '..', 'backend', 'itam'), DASH = path.join(__dirname, '..', '..', 'ui');
const H = require(path.join(ITAM, 'tests', 'helpers'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const ADM = { user: 'syed', role: 'admin' }, ADM2 = { user: 'omar.syn', role: 'admin' }, OP = { user: 'nora.syn', role: 'operator' };
const XSS = '<img src=x onerror="window.__xss=1">';

(async () => {
  const state = { devices: [
    { id: 'sw-core-1', name: 'SW-CORE-1', vendor: 'cisco-ios', ostype: 'iosxe', version: '17.6.1', key: 'iosxe|17.6.1' },
    { id: 'sw-edge-2', name: 'SW-EDGE-2 ' + XSS, vendor: 'cisco-ios', ostype: 'iosxe', version: '17.6.1', key: 'iosxe|17.6.1' },
    { id: 'sw-acc-3', name: 'SW-ACC-3', vendor: 'cisco-ios', ostype: 'ios', version: '15.2(7)E8', key: 'ios|15.2(7)E8' }] };
  const cs = {
    psirtView: () => ({ api: { enabled: true, secret_set: true }, last_check: new Date().toISOString(), last_error: null, devices: state.devices,
      versions: [{ key: 'iosxe|17.6.1', ostype: 'iosxe', version: '17.6.1', count: 2, worst: 'Critical',
        advisories: [{ id: 'cisco-sa-syn-crit', title: 'Synthetic web UI flaw', sir: 'Critical', cvss: 10, cves: ['CVE-2026-0001'], first_fixed: ['17.9.4a'], url: 'https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-syn-crit' },
          { id: 'cisco-sa-syn-evil', title: 'Lookalike link', sir: 'High', cvss: 7, cves: [], first_fixed: [], url: 'https://cisco.com.evil.test/x' }] },
        { key: 'ios|15.2(7)E8', ostype: 'ios', version: '15.2(7)E8', count: 0, worst: null, advisories: [] }] }),
    report: () => ({ rows: [{ name: 'SW-CORE-1', status: 'covered', end: '2027-06-30' }] }),
  };
  const e = await H.startApp({ noAi: true });
  require(path.join(ITAM, 'engine/duty')).registerDuty(e.app.srv, e.app, { noTimer: true, ciscoSupport: cs });
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
  const base = 'http://127.0.0.1:' + srv.address().port + '/dashboards/';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  const wait = (p, fn, arg) => p.waitForFunction(fn, arg, { timeout: 15000 }).then(() => true, () => false);
  const open = async (h) => { const p = await browser.newPage({ viewport: { width: 1500, height: 1000 } }); p.on('pageerror', (x) => errs.push(x.message)); p.on('dialog', (d) => { errs.push('dialog ' + d.message()); d.dismiss(); }); await p.goto(base + 'cisco-update.html' + (h || '')); await wait(p, () => !/Loading/.test(document.getElementById('body').textContent)); return p; };
  const body = (p) => p.evaluate(() => document.getElementById('body').innerText);
  const plans = () => e.app.store.collection('cisco_update_plans').all();
  try {
    // administrator sets the target release on Policy (opened by hash)
    WHO = ADM; let p = await open('#view=policy');
    ok(await p.evaluate(() => document.querySelector('#tabs .on').getAttribute('data-tab') === 'policy'), 'the hash opens the Policy tab');
    await p.click('#addr'); await p.selectOption('#rules tr[data-r="0"] [data-k="ostype"]', 'iosxe'); await p.fill('#rules tr[data-r="0"] [data-k="target"]', '17.9.4a'); await p.fill('#rules tr[data-r="0"] [data-k="minimum"]', '17.3.1');
    await p.fill('[data-sla="Critical"]', '7'); await p.click('#savep');
    ok(await wait(p, () => /last saved by syed/.test(document.body.textContent)), 'policy saved by the administrator');
    const pol = e.app.store.collection('cisco_update_cfg').get('policy'); ok(pol && pol.rules[0].target === '17.9.4a' && pol.sla.Critical === 7, 'stored: target 17.9.4a, Critical 7 days');
    await p.click('#addr'); await p.fill('#rules tr[data-r="1"] [data-k="target"]', 'latest!'); await p.click('#savep');
    ok(await wait(p, () => [].some.call(document.querySelectorAll('.toast'), (t) => /target is not a version/.test(t.textContent))), 'an invalid target is refused with the field named');
    await p.close();

    // overview: KPIs and what to do first
    WHO = OP; p = await open();
    let b = await body(p);
    ok(/Critical advisory\s*2/i.test(b) && /Behind target\s*2/i.test(b), 'KPIs: 2 on a Critical release, 2 behind: ' + b.replace(/\s+/g, ' ').slice(0, 200));
    ok(/Critical advisory and no plan/.test(b), 'what to do first names the Critical devices');
    ok(await p.evaluate(() => !window.__xss) && !(await p.$('#body img')), 'a hostile device name is escaped');
    // devices: filter, drawer with every point
    await p.click('#tabs [data-tab="devices"]'); await p.click('.chip[data-f="critical"]');
    ok((await p.$$('tr.dv')).length === 2, 'Critical filter: 2 devices');
    ok(await p.evaluate(() => { const a = document.getElementById('cnlink'); return !!a && a.getAttribute('href') === 'cisco-network.html'; }), 'devices view links the Cisco Network Inventory (model, serial, support per switch)');
    await p.click('tr.dv[data-dev="sw-core-1"] td:first-child');
    ok(await wait(p, () => /Priority \d+/.test((document.getElementById('zd-b') || {}).textContent || '') && /Critical advisory on 17\.6\.1/.test(document.getElementById('zd-b').textContent)), 'drawer names the priority points');
    await p.keyboard.press('Escape');
    // advisories: only cisco.com links are clickable
    await p.click('#tabs [data-tab="advisories"]');
    ok(await p.$('a[href^="https://sec.cloudapps.cisco.com/"]') && !(await p.$('a[href*="evil.test"]')), 'advisory link only to cisco.com, the lookalike is plain text');
    ok(/yes/.test(await p.evaluate(() => [].find.call(document.querySelectorAll('#body tr'), (r) => /cisco-sa-syn-crit/.test(r.textContent)).textContent)), 'the target fixes the Critical advisory (same train)');
    // plan the Critical device: draft, submit
    await p.click('#tabs [data-tab="devices"]'); await p.click('tr.dv[data-dev="sw-core-1"] [data-plan]');
    await p.waitForSelector('.dlg'); await p.fill('#p-why', 'Critical PSIRT advisory cisco-sa-syn-crit'); await p.click('.dlg [data-ok]');
    ok(await wait(p, () => document.querySelector('#tabs .on').getAttribute('data-tab') === 'plans' && /draft/.test(document.getElementById('body').textContent)), 'plan saved as a draft, Plans tab shown');
    ok(plans().length === 1 && plans()[0].device_ids[0] === 'sw-core-1' && plans()[0].target === '17.9.4a', 'stored with the target from the policy');
    await p.click('[data-pa="submit"]');
    ok(await wait(p, () => /submitted/.test(document.getElementById('body').textContent)), 'submitted');
    ok(!(await p.$('[data-pa="approve"]')), 'the requester is offered no Approve');
    await p.close();

    // a second person approves; verify keeps it open until the device reports the target
    WHO = ADM2; p = await open('#view=plans');
    await p.click('[data-pa="approve"]');
    ok(await wait(p, () => /approved by omar\.syn/.test(document.getElementById('body').textContent)), 'approved by a second person');
    ok(/ios-stage\s+image=/.test(await body(p)), 'the AI Network Engineer task parameters are shown');
    await p.click('[data-pa="complete"]');
    ok(await wait(p, () => [].some.call(document.querySelectorAll('.toast'), (t) => /not yet on the target/.test(t.textContent))), 'verification: not done while the device runs 17.6.1');
    ok(plans()[0].status === 'approved', 'plan stays approved');
    state.devices[0].version = '17.9.4a';
    await p.evaluate(() => [].forEach.call(document.querySelectorAll('.toast'), (t) => t.remove()));
    await p.click('[data-pa="complete"]');
    ok(await wait(p, () => /completed/.test(document.getElementById('body').textContent)), 'completed once the device reports the target');
    ok(plans()[0].status === 'completed', 'stored as completed');
    await p.close();

    ok(/"h": "cisco-update\.html"/.test(fs.readFileSync(path.join(DASH, 'vendor/zyb-nav.js'), 'utf8')), 'menu entry exists');
    const menu = fs.readFileSync(path.join(DASH, 'vendor/zyb-menu.js'), 'utf8');
    ok(['upd-overview', 'upd-inventory', 'upd-advisories', 'upd-plans', 'upd-policy', 'upd-connections'].every((k) => menu.indexOf("'" + k + "': 'cisco-update.html") >= 0), 'the six portal views redirect here');
    ok(/ cisco-update\.html /.test(fs.readFileSync(path.join(DASH, 'install-dashboards.sh'), 'utf8')), 'in the installer');
    ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  } finally { await browser.close(); srv.close(); await e.close(); }
  console.log(`${n - bad}/${n} checks passed`); process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
