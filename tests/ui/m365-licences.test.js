// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Microsoft 365 Licences & Security page (m365-licences.html) against the REAL engine (engine/m365-licence-intel.js) over a
// SYNTHETIC tenant: tiles, four charts, what the AI noticed, the licences table with the forecast, the reclaim candidates with
// reason chips (operator sees names, a viewer only counts), security coverage with who has no Entra ID P1, Refresh for an
// operator, Settings for an administrator turning prices into money; not connected says where to connect; hostile names stay
// text; menu entry and installer. Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node m365-licences.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const ITAM = path.resolve(__dirname, '../../backend/itam'), DASH = path.resolve(__dirname, '../../ui');
const H = require(path.join(ITAM, 'tests/helpers')), { createM365LicenceIntel, registerM365LicenceIntel } = require(path.join(ITAM, 'engine/m365-licence-intel'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const XSS = '<img src=x onerror=window.PWN=1>', P = (id, name) => ({ id, name }), L = (...ids) => ids.map((skuId) => ({ skuId, disabledPlans: [] }));
const day = (d) => new Date(Date.now() - d * 86400000).toISOString().slice(0, 10);
const SKUS = [{ sku_id: 'e3', part: 'SPE_E3', enabled: 10, consumed: 8, warning: 2, plans: [P('ex', 'EXCHANGE_S_ENTERPRISE'), P('off', 'OFFICESUBSCRIPTION'), P('aad', 'AAD_PREMIUM')] },
  { sku_id: 'exo', part: 'EXCHANGEENTERPRISE', enabled: 5, consumed: 3, plans: [P('ex', 'EXCHANGE_S_ENTERPRISE')] }];
const USERS = [{ userPrincipalName: 'a.syn@corp.test', displayName: XSS, accountEnabled: false, assignedLicenses: L('e3') },
  { userPrincipalName: 'b.syn@corp.test', displayName: 'B Syn', accountEnabled: true, assignedLicenses: L('e3', 'exo') },
  { userPrincipalName: 'c.syn@corp.test', displayName: 'C Syn', accountEnabled: true, assignedLicenses: L('exo') }];
const ACT = [{ userPrincipalName: 'b.syn@corp.test', exchangeLastActivityDate: day(1) }, { userPrincipalName: 'c.syn@corp.test', exchangeLastActivityDate: day(1) }];
(async () => {
  const e = await H.startApp({ noAi: true }), st = { connected: true };
  const X = createM365LicenceIntel(e.app, { source: () => ({ connected: () => st.connected, userApps: async () => ({ skus: SKUS, users: USERS, act: ACT, apps: [], errors: [] }) }) });
  registerM365LicenceIntel(e.app.srv, e.app, X, { noTimer: true });
  for (let i = 10; i >= 1; i--) e.app.store.collection('m365lic_daily').put({ id: day(i), skus: { SPE_E3: { enabled: 10, consumed: 4 + (10 - i) * 0.4 }, EXCHANGEENTERPRISE: { enabled: 5, consumed: 3 } } });
  let WHO = { user: 'op.syn', role: 'operator' };
  const srv = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://x');
    if (u.pathname === '/dashboards/whoami.json') { res.writeHead(200, { 'Content-Type': 'application/json' }); return res.end(JSON.stringify(WHO)); }
    if (u.pathname.startsWith('/api/itam/')) { const h = Object.assign({}, req.headers, { 'x-sentra-proxy-secret': H.SECRET, 'x-auth-user': WHO.user, 'x-auth-role': WHO.role });
      const up = http.request({ host: '127.0.0.1', port: e.port, method: req.method, path: req.url, headers: h }, (r) => { res.writeHead(r.statusCode, r.headers); r.pipe(res); }); req.pipe(up); return; }
    if (u.pathname.startsWith('/api/')) { res.writeHead(404); return res.end('{}'); }
    fs.readFile(path.join(DASH, u.pathname.replace(/^\/dashboards\//, '/')), (err, d) => { if (err) { res.writeHead(404); return res.end(); } res.writeHead(200, { 'Content-Type': u.pathname.endsWith('.js') ? 'application/javascript' : u.pathname.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const url = 'http://127.0.0.1:' + srv.address().port + '/dashboards/m365-licences.html?standalone=1';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright'); const browser = await chromium.launch(), errs = [];
  const open = async () => { const p = await browser.newPage({ viewport: { width: 1400, height: 1000 } }); p.on('pageerror', (x) => errs.push(x.message)); await p.goto(url); await p.waitForSelector('#main:not([hidden]), #conn:not([hidden])', { timeout: 15000 }); return p; };
  try {
    // not read yet: an operator refreshes
    let p = await open();
    ok(/Not read yet/.test(await p.textContent('#conn')), 'not read yet');
    await p.click('#rf'); await p.waitForSelector('#main:not([hidden])', { timeout: 15000 });
    const kp = (await p.$eval('#kp', (x) => x.innerText)).replace(/\s+/g, ' ');
    ok(/Paid seats bought 15/.test(kp) && /Assigned 11/.test(kp) && /Reclaimable 2/.test(kp) && /Entra ID P1 coverage 50%/.test(kp) && /First to run out \d+ days/.test(kp), 'tiles: ' + kp);
    const lab = await p.$$eval('canvas', (x) => x.map((c) => c.getAttribute('aria-label') || ''));
    ok(lab.length === 4 && lab.every(Boolean) && /Seats per licence/.test(lab[0]) && /Where the waste is/.test(lab[1]) && /Security the licences buy/.test(lab[2]) && /Assigned seats over time/.test(lab[3]), 'four charts: ' + lab.map((l) => l.slice(0, 40)).join(' | '));
    const ins = (await p.$eval('#ins', (x) => x.innerText)).replace(/\s+/g, ' ');
    ok(/1 paid licences sit on disabled accounts/.test(ins) && /2 seats are in the expiry warning/.test(ins) && /no Entra ID P1/.test(ins) && /runs out of seats in about \d+ days/.test(ins), 'what the AI noticed: ' + ins);
    const lic = await p.$eval('#lic', (x) => x.innerText); ok(/Microsoft 365 E3/.test(lic) && /2 expiring/.test(lic) && /days/.test(lic), 'licences table');
    const w = await p.$eval('#waste', (x) => x.innerText); ok(/Disabled account/.test(w) && /Overlapping/.test(w) && /Exchange Online \(Plan 2\)/.test(w) && /a\.syn@corp\.test/.test(w), 'reclaim candidates with reasons and names');
    ok(!(await p.evaluate(() => window.PWN)) && /<img src=x/.test(await p.textContent('#waste')), 'a hostile name stays text');
    await p.click('[data-wf="overlap"]'); ok((await p.$$('#waste tbody tr')).length === 1, 'reason chip filters');
    ok(/C Syn/.test(await p.textContent('#nop1')), 'who has no Entra ID P1');
    ok(await p.$eval('#setc', (x) => x.hidden), 'an operator has no settings');
    await p.close();
    // administrator: prices -> money
    WHO = { user: 'admin.syn', role: 'admin' }; p = await open();
    await p.fill('[data-price="SPE_E3"]', '135'); await p.fill('[data-price="EXCHANGEENTERPRISE"]', '30'); await p.click('#sf button[type=submit]');
    ok(await p.waitForFunction(() => /165 SAR/.test(document.getElementById('kp').innerText), null, { timeout: 8000 }).then(() => true, () => false), 'prices turn the waste into money (135 + 30)');
    ok(e.app.store.auditTail(30).some((a) => a.action === 'm365lic.settings' && a.by === 'admin.syn'), 'settings audited');
    await p.close();
    // viewer: counts, no names
    WHO = { user: 'vera.syn', role: 'viewer' }; p = await open();
    ok(/2 paid licences are flagged/.test(await p.textContent('#waste')) && !/corp\.test/.test(await p.textContent('#main')) && await p.$eval('#rf', (x) => x.hidden), 'viewer: counts only, no names, no Refresh');
    await p.close();
    // not connected
    st.connected = false; e.app.store.collection('m365lic_latest').remove('cur'); WHO = { user: 'admin.syn', role: 'admin' }; p = await open();
    ok(/Connect Microsoft 365/.test(await p.textContent('#conn')) && /HR Onboarding/.test(await p.textContent('#conn')), 'not connected: where to connect'); await p.close();
    ok(fs.readFileSync(path.join(DASH, 'vendor/zyb-nav.js'), 'utf8').includes('"h": "m365-licences.html"') && / m365-licences\.html /.test(fs.readFileSync(path.join(DASH, 'install-dashboards.sh'), 'utf8')), 'menu entry and installer');
    ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  } finally { await browser.close(); srv.close(); await e.close(); }
  console.log((bad ? 'FAILED ' : 'ok ') + (n - bad) + '/' + n + ' m365-licences checks'); process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
