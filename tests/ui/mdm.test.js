// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for dashboards/server/mdm.html (Endpoint & Mobile Management) against the REAL ITAM engine (engine/mdm.js) and the
// in-process fake ManageEngine MDM Plus (SYNTHETIC devices, one with a hostile name): tiles, platform / ownership bars, stale devices
// first and filtered, search keeps focus, "Read the MDM now" refreshes, a viewer is told why it cannot see devices, no MDM says what
// to do, and the portal's sample MDM / SOC dashboard / agents / managed-service views now open live pages.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node mdm.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const ITAM = path.join(__dirname, '..', '..', 'backend', 'itam'), DASH = path.join(__dirname, '..', '..', 'ui');
const H = require(path.join(ITAM, 'tests', 'helpers'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const ADM = { user: 'syed', role: 'admin' }, OP = { user: 'nora.syn', role: 'operator' }, VW = { user: 'vera.syn', role: 'viewer' };
const { fakeMdm, TOKEN } = require(path.join(ITAM, 'tests', 'helpers', 'fake-mdm'));
const XSS = '<img src=x onerror="window.__xss=1">';

(async () => {
  const F = fakeMdm(); await new Promise((r) => F.srv.listen(0, '127.0.0.1', r));
  const day = (n) => String(Date.now() - n * 86400000);
  F.st.devices['1001'].last_contact_time = day(1); F.st.devices['1002'].last_contact_time = day(2); F.st.devices['1003'].last_contact_time = day(30);
  F.st.devices['1004'].device_name = 'Kiosk ' + XSS;
  const e = await H.startApp({ noAi: true });
  require(path.join(ITAM, 'engine/duty')).registerDuty(e.app.srv, e.app, { noTimer: true, python: process.env.PYTHON || 'python3' });
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
  const open = async () => { const p = await browser.newPage({ viewport: { width: 1500, height: 1000 } }); p.on('pageerror', (x) => errs.push(x.message)); await p.goto(base + 'mdm.html'); await wait(p, () => !/Loading/.test(document.getElementById('body').textContent)); return p; };
  const txt = (p, id) => p.evaluate((i) => (document.getElementById(i) || {}).innerText || '', id);
  try {
    // no MDM yet: says what to do
    WHO = OP; let p = await open();
    ok(/HR Offboarding/.test(await txt(p, 'body')) && !(await p.$('table')), 'no MDM: points to HR Offboarding -> MDM, nothing invented');
    await p.close();
    // connect the fake MDM (an administrator does this on HR Offboarding)
    let r = await e.req('POST', '/offboarding/mdm', { body: { provider: 'manageengine', base_url: 'https://mdm.corp.syn', api_token: TOKEN }, user: 'syed', role: 'admin' }); ok(r.status === 200, 'MDM connected');
    e.app.store.collection('mdm_cfg').put(Object.assign({}, e.app.store.collection('mdm_cfg').get('cfg'), { base_url: 'http://127.0.0.1:' + F.srv.address().port }));
    p = await open();
    const kp = await txt(p, 'kp');
    ok(/Managed devices\s*4/i.test(kp) && /Company-owned\s*3/i.test(kp) && /Personal \(BYOD\)\s*1/i.test(kp) && /Not checking in\s*2/i.test(kp), 'tiles: ' + kp.replace(/\s+/g, ' ').slice(0, 160));
    ok(/windows\s*2/i.test(await txt(p, 'body')), 'platform bars');
    ok(await p.evaluate(() => !window.__xss) && !(await p.$('#body img')), 'a hostile device name is escaped');
    const first = await p.evaluate(() => document.querySelector('#body tbody tr').innerText);
    ok(/never|30 d ago/.test(first), 'stale devices first: ' + first.replace(/\s+/g, ' '));
    await p.click('[data-f="stale"]'); ok((await p.$$('#body tbody tr')).length === 2, 'stale filter: 2 devices');
    await p.click('[data-f="stale"]'); await p.fill('#q', 'pixel');
    ok((await p.$$('#body tbody tr')).length === 1 && await p.evaluate(() => document.activeElement && document.activeElement.id === 'q'), 'search keeps focus');
    const n0 = F.st.calls.length; await p.click('#rf');
    ok(await wait(p, () => [].some.call(document.querySelectorAll('.toast'), (t) => /Read from the MDM/.test(t.textContent))) && F.st.calls.length > n0, 'Read the MDM now refreshes');
    ok(e.app.store.auditTail(30).some((a) => a.action === 'mdm.inventory.refresh' && a.by === 'nora.syn'), 'the refresh is audited');
    await p.close();
    WHO = VW; p = await open();
    ok(/operators and administrators only/.test(await txt(p, 'body')), 'viewer told why devices are not shown (PDPL)');
    await p.close();
    ok(/"h": "mdm\.html"/.test(fs.readFileSync(path.join(DASH, 'vendor/zyb-nav.js'), 'utf8')), 'menu entry exists');
    const menu = fs.readFileSync(path.join(DASH, 'vendor/zyb-menu.js'), 'utf8');
    ok(/'intune': 'mdm\.html'/.test(menu) && /'dash-soc': 'soc-overview\.html'/.test(menu) && /'agents': 'ai-team\.html'/.test(menu) && /'managed': 'service-agreement\.html'/.test(menu), 'the four sample portal views now open live pages');
    ok(/ mdm\.html /.test(fs.readFileSync(path.join(DASH, 'install-dashboards.sh'), 'utf8')), 'in the installer');
    ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  } finally { await browser.close(); srv.close(); F.srv.close(); await e.close(); }
  console.log(`${n - bad}/${n} checks passed`); process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
