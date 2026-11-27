// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Asset Onboarding page (asset-onboarding.html) against the REAL IT Asset Management engine (engine/asset-onboard.js), SYNTHETIC
// assets: the ways in; tiles and the branch table with accuracy; the AI helper reads a pasted list (type, branch and the reason,
// already-in-the-register matched and not selectable), a person changes a branch and adds - the assets are created, the page
// reloads; what the AI noticed (no branch, duplicates, conflicts); records to fix with names for an operator; a viewer sees no
// helper and no names; hostile text stays text; menu entry and installer.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node asset-onboarding.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const DASH = path.resolve(__dirname, '../../ui'), ITAM = path.resolve(__dirname, '../../backend/itam');
const H = require(path.join(ITAM, 'tests/helpers'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const XSS = '<img src=x onerror=window.PWN=1>';
(async () => {
  const e = await H.startApp({ noAi: true }); require(path.join(ITAM, 'engine/duty')).registerDuty(e.app.srv, e.app, { noTimer: true });
  const ADM = { user: 'admin.syn', role: 'admin' }, A = (o) => e.app.assets.create(Object.assign({ status: 'in_use' }, o), ADM);
  A({ name: 'JED-PC-SYN01', type: 'workstation', site: 'Jeddah', mgmt_ip: '10.20.1.11', serial: 'S1', owner: 'a.syn', os: 'Windows 11' });
  A({ name: 'JED-PC-SYN02', type: 'workstation', site: 'Jeddah', mgmt_ip: '10.20.1.12', serial: 'S2' });
  A({ name: 'RUH-SRV-SYN01', type: 'server', site: 'Riyadh', mgmt_ip: '10.10.5.20', mac: '00:11:22:33:44:55' });
  A({ name: 'NOSITE-SYN', type: 'workstation', mac: '00:11:22:33:44:55' });
  let WHO = { user: 'op.syn', role: 'operator' };
  const srv = http.createServer((req, res) => { const u = new URL(req.url, 'http://x');
    if (u.pathname === '/dashboards/whoami.json') { res.writeHead(200, { 'Content-Type': 'application/json' }); return res.end(JSON.stringify(WHO)); }
    if (u.pathname.startsWith('/api/itam/')) { const h = Object.assign({}, req.headers, { 'x-sentra-proxy-secret': H.SECRET, 'x-auth-user': WHO.user, 'x-auth-role': WHO.role });
      const up = http.request({ host: '127.0.0.1', port: e.port, method: req.method, path: req.url, headers: h }, (r) => { res.writeHead(r.statusCode, r.headers); r.pipe(res); }); req.pipe(up); return; }
    if (u.pathname.startsWith('/api/')) { res.writeHead(404, { 'Content-Type': 'application/json' }); return res.end('{}'); }
    fs.readFile(path.join(DASH, u.pathname.replace(/^\/dashboards\//, '/')), (err, d) => { if (err) { res.writeHead(404); return res.end(); } res.writeHead(200, { 'Content-Type': u.pathname.endsWith('.js') ? 'application/javascript' : u.pathname.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); }); });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const url = 'http://127.0.0.1:' + srv.address().port + '/dashboards/asset-onboarding.html?standalone=1';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright'); const browser = await chromium.launch(), errs = [];
  const open = async () => { const p = await browser.newPage({ viewport: { width: 1400, height: 1000 } }); p.on('pageerror', (x) => errs.push(x.message)); await p.goto(url); await p.waitForSelector('#br table, #br .empty', { timeout: 15000 }); return p; };
  try {
    let p = await open();
    ok((await p.$$('.way')).length === 5 && !!(await p.$('.way a[href="discovery-studio.html"]')) && !!(await p.$('.way a[href="agents.html"]')), 'the ways in');
    const kp = (await p.$eval('#kp', (x) => x.innerText)).replace(/\s+/g, ' ');
    ok(/Assets 4 2 branches/.test(kp) && /No branch 1/.test(kp) && /Duplicates 2/.test(kp), 'tiles: ' + kp);
    await p.fill('#tx', 'name,ip,branch\nJED-LT-SYN05,10.20.1.55,\nJED-PC-SYN01,,\n' + XSS + ',10.30.0.1,\nPRN-SYN-1,10.40.0.9,Dammam');
    await p.click('#rd'); await p.waitForSelector('#prev table');
    const rows = await p.$$eval('#prev tbody tr', (x) => x.map((r) => r.innerText.replace(/\s+/g, ' ')));
    ok(/JED-LT-SYN05/.test(rows[0]) && /site learned/.test(rows[0]) && /laptop/.test(await p.$eval('[data-t="0"]', (x) => x.value)) && (await p.$eval('[data-s="0"]', (x) => x.value)) === 'Jeddah', 'type and branch guessed with the reason: ' + rows[0]);
    ok(/JED-PC-SYN01 \(name\)/.test(rows[1]) && await p.$eval('[data-k="1"]', (x) => x.disabled), 'already in the register: matched, not selectable');
    ok(!(await p.evaluate(() => window.PWN)), 'hostile text stays text');
    await p.fill('[data-s="0"]', 'Jeddah North'); await p.dispatchEvent('[data-s="0"]', 'change');
    await p.click('#add'); await p.waitForFunction(() => /added/.test(document.getElementById('addm') ? document.getElementById('addm').textContent : '') || /assets added/.test(document.body.innerText), null, { timeout: 10000 });
    const L = e.app.store.collection('assets').all().find((a) => a.name === 'JED-LT-SYN05'), PR = e.app.store.collection('assets').all().find((a) => a.name === 'PRN-SYN-1');
    ok(L && L.type === 'laptop' && L.site === 'Jeddah North' && PR && PR.type === 'printer' && PR.site === 'Dammam', 'added with the person\'s branch: ' + JSON.stringify(L && { t: L.type, s: L.site }));
    await p.waitForFunction(() => /Jeddah North/.test(document.getElementById('br').textContent), null, { timeout: 8000 }).catch(() => {}); ok(/Jeddah North/.test(await p.textContent('#br')), 'the branch table reloads');
    const ins = (await p.$eval('#ins', (x) => x.innerText)).replace(/\s+/g, ' ');
    ok(/assets have no branch/.test(ins) && /share a serial number or MAC/.test(ins), 'what the AI noticed: ' + ins);
    ok(!(await p.$eval('#issc', (x) => x.hidden)) && /NOSITE-SYN/.test(await p.textContent('#iss')), 'records to fix with names');
    ok((await p.$$('#band canvas[aria-label]')).length >= 2, 'charts by branch');
    await p.close();
    WHO = { user: 'vera.syn', role: 'viewer' }; p = await open();
    ok(await p.$eval('#helper', (x) => x.hidden) && await p.$eval('#issc', (x) => x.hidden), 'a viewer: no helper, no names'); await p.close();
    ok(fs.readFileSync(path.join(DASH, 'vendor/zyb-nav.js'), 'utf8').includes('"h": "asset-onboarding.html"') && / asset-onboarding\.html /.test(fs.readFileSync(path.join(DASH, 'install-dashboards.sh'), 'utf8')), 'menu entry and installer');
    ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  } finally { await browser.close(); srv.close(); await e.close(); }
  console.log((bad ? 'FAILED ' : 'ok ') + (n - bad) + '/' + n + ' asset-onboarding checks'); process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
