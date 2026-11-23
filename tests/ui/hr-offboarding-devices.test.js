// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for leaver devices on HR Offboarding (hr-offboarding.html) against the REAL ITAM engine (offboarding.js + mdm.js)
// and a fake ManageEngine MDM Plus, SYNTHETIC data only: an administrator chooses ManageEngine in MDM settings (token never put
// back on the page) and tests it; after the disable the devices are listed with the asset tag, a hostile device name stays text;
// the person who raised the request cannot decide; a full wipe without the serial is refused with the reason; with the serial
// typed, the laptop is wiped, the phone retired, the Mac kept with a reason; the page follows them to done.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node hr-offboarding-devices.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const ITAM = path.join(__dirname, '..', '..', 'backend', 'itam'), DASH = path.join(__dirname, '..', '..', 'ui');
const H = require(path.join(ITAM, 'tests', 'helpers'));
const { fakeMdm, TOKEN } = require(path.join(ITAM, 'tests', 'helpers', 'fake-mdm'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const XSS = '<img src=x onerror=alert(1)>';

(async () => {
  const F = fakeMdm(); F.st.devices['1002'].device_name = 'Khalid Pixel ' + XSS;
  await new Promise((r) => F.srv.listen(0, '127.0.0.1', r));
  const e = await H.startApp({ noAi: true });
  require(path.join(ITAM, 'engine/duty')).registerDuty(e.app.srv, e.app, { noTimer: true, python: process.env.PYTHON || 'python3' });
  const api = async (m, p, body, who) => { const r = await e.req(m, p, Object.assign({ body }, who)); if (r.status !== 200) throw new Error(p + ': ' + JSON.stringify(r.json)); return r.json; };
  const ADM = { user: 'syed', role: 'admin' }, HRA = { user: 'hana.syn', role: 'admin' }, DESK = { user: 'desk.syn', role: 'operator' };
  await api('POST', '/onboarding/ad', { upn_suffix: 'corp.syn' }, ADM);
  e.app.store.collection('assets').put({ id: 'ast_1', asset_tag: 'AST-0107', name: 'Claims laptop 7', serial: 'SN-LAP-1', status: 'in_use', type: 'laptop', lifecycle: [] });
  await api('POST', '/offboarding', { name: 'Khalid Al-Harbi', employee_id: 'E-20001', username: 'khalid.harbi', department: 'Claims', last_day: new Date().toISOString().slice(0, 10), manager: 'faisal.syn', reason: 'resignation' }, HRA);
  await api('POST', '/offboarding/OFF-001/confirm', { decision: 'confirm' }, { user: 'faisal.syn', role: 'operator' });
  await api('POST', '/offboarding/OFF-001/approve', { decision: 'approve' }, ADM);
  let WHO = ADM;
  const srv = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://x'), json = (c, b2) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b2)); };
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
  const zd = (p, re) => p.waitForFunction((src) => new RegExp(src).test((document.getElementById('zd') || {}).textContent || ''), re.source, { timeout: 10000 }).then(() => true, () => false);
  const msg = (p, sel, re) => p.waitForFunction((a) => new RegExp(a[1]).test((document.querySelector(a[0] + ' [data-msg]') || {}).textContent || ''), [sel, re.source], { timeout: 8000 }).then(() => true, () => false);
  const openRow = async (p) => { await p.click('#list tr[data-id="OFF-001"]'); await p.waitForSelector('#zd .steps', { timeout: 8000 }); };
  const as = async (p, who) => { WHO = who; await p.reload(); await p.waitForSelector('#list table', { timeout: 15000 }); await openRow(p); };
  try {
    const p = await browser.newPage({ viewport: { width: 1400, height: 1100 } }); p.on('pageerror', (x) => errs.push(x.message)); p.on('dialog', (d) => { errs.push('dialog ' + d.message()); d.dismiss(); });
    await p.goto(base + 'hr-offboarding.html?standalone=1'); await p.waitForSelector('#list table', { timeout: 15000 });
    await p.click('#mdmset'); await p.waitForSelector('#mdmform [name=provider]', { timeout: 8000 });
    ok(await p.$$eval('#mdmform input[name], #mdmform select[name]', (x) => x.every((el) => el.getAttribute('data-hinted'))), 'helper text on the MDM settings');
    await p.selectOption('#mdmform [name=provider]', 'manageengine'); await p.fill('#mdmform [name=base_url]', 'https://mdm.corp.syn:9383'); await p.fill('#mdmform [name=api_token]', TOKEN);
    await Promise.all([p.waitForResponse((r) => /offboarding\/mdm$/.test(r.url()) && r.request().method() === 'POST'), p.click('#mdmform [type=submit]')]);
    ok(await zd(p, /set \(sealed, never shown\)/) && !(await p.content()).includes(TOKEN), 'saved; the token is never put back');
    e.app.store.collection('mdm_cfg').put(Object.assign({}, e.app.store.collection('mdm_cfg').get('cfg'), { base_url: 'http://127.0.0.1:' + F.srv.address().port }));   // the fake
    await Promise.all([p.waitForResponse((r) => /mdm\/test$/.test(r.url())), p.click('[data-act="mdmtest"]')]);
    ok(await zd(p, /connected - 4 devices/), 'connection test');
    await api('POST', '/offboarding/OFF-001/disabled', { directory_ref: 'disabled in ADUC, CHG-9001' }, DESK);
    await as(p, HRA);
    ok(await zd(p, /through ManageEngine MDM/) && await zd(p, /AST-0107/) && await zd(p, /MBP-CLAIMS-02/), 'devices listed with the asset tag');
    ok(!(await p.$('#zd img')) && await zd(p, /Khalid Pixel <img/), 'a hostile device name stays text');
    await Promise.all([p.waitForResponse((r) => /devices\/decide$/.test(r.url())), p.click('#odev [type=submit]')]);
    ok(await msg(p, '#odev', /four eyes/), 'the person who raised it cannot decide');
    await as(p, ADM);
    const box = (d) => '#odev [data-dev="' + d + '"] ';
    await p.selectOption(box('1003') + '[data-f=action]', 'keep');
    await Promise.all([p.waitForResponse((r) => /devices\/decide$/.test(r.url())), p.click('#odev [type=submit]')]);
    ok(await msg(p, '#odev', /type the serial of LAP-CLAIMS-07/), 'a full wipe without the serial is refused');
    ok((await p.$$eval(box('1002') + '[data-f=action] option', (x) => x.map((o) => o.value))).indexOf('wipe') < 0, 'the personal phone offers no full wipe');
    await p.fill(box('1001') + '[data-f=confirm]', 'SN-LAP-1'); await p.fill(box('1003') + '[data-f=reason]', 'returned to IT, re-imaged on the bench');
    await Promise.all([p.waitForResponse((r) => /devices\/decide$/.test(r.url())), p.click('#odev [type=submit]')]);
    ok(await zd(p, /sent - waiting for the device/) && await zd(p, /returned to IT, re-imaged/), 'sent; the Mac kept with its reason');
    ok(F.st.calls.includes('POST /api/v1/mdm/devices/1001/actions/complete_wipe') && F.st.calls.includes('POST /api/v1/mdm/devices/1002/actions/corporate_wipe'), 'the actions reached the MDM');
    await e.app.addons.offboarding.runDue(null); await e.app.addons.offboarding.runDue(null);
    await as(p, ADM);
    ok(await zd(p, /all done/) && await zd(p, /wiped/) && await zd(p, /company data removed/), 'followed to done');
  } finally { await browser.close(); srv.close(); F.srv.close(); e.close(); }
  ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks');
  process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
