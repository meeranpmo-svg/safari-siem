// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for dashboards/server/stocktake.html against the REAL ITAM engine (stocktake routes + engine/stocktake-intel.js) with a
// SYNTHETIC register: honest empty state; an operator cannot open a count, an admin opens one for a site; scanning with Enter (found,
// wrong site, unexpected); the unexpected code offers the closest asset and counting it; missing ranked with reasons; explain needs a
// note; mark lost sets the asset Lost and records it; move a misplaced record; next-count plan; CSV; close; viewer cannot scan;
// names escaped; the portal itam-stocktake redirect; menu + installer.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node stocktake.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const ITAM = path.join(__dirname, '..', '..', 'backend', 'itam'), DASH = path.join(__dirname, '..', '..', 'ui');
const H = require(path.join(ITAM, 'tests', 'helpers'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const ADM = { user: 'syed', role: 'admin' }, OP = { user: 'nora.syn', role: 'operator' }, VW = { user: 'vera.syn', role: 'viewer' };
const XSS = '<img src=x onerror="window.__xss=1">';

(async () => {
  const e = await H.startApp({ noAi: true });
  require(path.join(ITAM, 'engine/duty')).registerDuty(e.app.srv, e.app, { noTimer: true });
  const A = e.app.store.collection('assets'), ago = (d) => new Date(Date.now() - d * 86400000).toISOString(), now = new Date().toISOString();
  let WHO = OP;
  const web = http.createServer((req, res) => {
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
  await new Promise((r) => web.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + web.address().port + '/dashboards/';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  const wait = (p, fn, arg) => p.waitForFunction(fn, arg, { timeout: 15000 }).then(() => true, () => false);
  const txt = (p, id) => p.evaluate((i) => document.getElementById(i).innerText, id);
  try {
    // empty register
    let p = await browser.newPage({ viewport: { width: 1500, height: 1000 } }); p.on('pageerror', (x) => errs.push(x.message));
    await p.goto(base + 'stocktake.html'); ok(await wait(p, () => !document.getElementById('none').hidden && /No stocktake yet/.test(document.getElementById('none').innerText)), 'honest empty state'); await p.close();
    const put = (o) => A.put(Object.assign({ status: 'in_use', updated_at: now, created_at: now }, o));
    put({ id: 'a1', name: 'WS-SYN-1 ' + XSS, type: 'workstation', site: 'Riyadh', department: 'Finance', asset_tag: 'ZS-0001', last_seen: ago(1) });
    put({ id: 'a2', name: 'WS-SYN-2', type: 'workstation', site: 'Riyadh', department: 'Finance', asset_tag: 'ZS-0002', last_seen: ago(1) });
    put({ id: 'a3', name: 'SRV-SYN-3', type: 'server', site: 'Riyadh', department: 'IT', asset_tag: 'ZS-0003', classification: 'secret', last_seen: ago(150) });
    put({ id: 'a4', name: 'LT-SYN-4', type: 'laptop', site: 'Riyadh', department: 'Sales', asset_tag: 'ZS-0004', owner: 'owner.syn' });
    put({ id: 'j1', name: 'WS-SYN-J1', type: 'workstation', site: 'Jeddah', asset_tag: 'ZS-0101' });
    // an operator cannot open; an admin can
    p = await browser.newPage({ viewport: { width: 1500, height: 1000 } }); p.on('pageerror', (x) => errs.push(x.message));
    await p.goto(base + 'stocktake.html'); await wait(p, () => /Sites never counted/.test(document.getElementById('kp').innerText));
    await p.click('#b-new'); await p.selectOption('#n-site', 'Riyadh'); await p.click('#dlg-ok');
    ok(await wait(p, () => /Administrators open a stocktake/.test(document.getElementById('dlg-e').innerText)), 'operator cannot open a count'); await p.click('#dlg-x');
    WHO = ADM; await p.click('#b-new'); await p.fill('#n-name', 'SYN Q4'); await p.selectOption('#n-site', 'Riyadh'); await p.click('#dlg-ok');
    ok(await wait(p, () => /4 assets expected/.test(document.body.innerText) && !document.getElementById('cur').hidden), 'admin opens a count');
    WHO = OP;
    await p.fill('#code', 'ZS-0001'); await p.press('#code', 'Enter'); ok(await wait(p, () => /Found: WS-SYN-1/.test(document.getElementById('res').innerText)), 'scan with Enter: found');
    ok(await p.evaluate(() => !window.__xss), 'names escaped');
    ok(await wait(p, () => document.activeElement && document.activeElement.id === 'code'), 'the scan box keeps focus for the next scan');
    await p.fill('#code', 'ZS-0101'); await p.press('#code', 'Enter'); ok(await wait(p, () => /recorded at Jeddah/.test(document.getElementById('res').innerText)), 'found at the wrong site');
    await p.fill('#code', 'ZS-OOO2'); await p.press('#code', 'Enter'); ok(await wait(p, () => /Not in the register/.test(document.getElementById('res').innerText)), 'unexpected code');
    ok(/1 of 4 found/.test(await txt(p, 'c-pt')), 'progress');
    // unexpected -> closest
    await p.click('[data-t="unx"]'); ok(/WS-SYN-2/.test(await txt(p, 'v-unx')), 'closest asset suggested');
    await p.click('[data-rescan="ZS-0002"]'); ok(await wait(p, () => /2 of 4 found/.test(document.getElementById('c-pt').innerText)), 'counted as the suggested asset');
    // missing ranked
    await p.click('[data-t="miss"]'); let t = await txt(p, 'v-miss');
    ok(t.indexOf('SRV-SYN-3') < t.indexOf('LT-SYN-4') && /not seen for 150 days/.test(t) && /portable/.test(t), 'missing ranked with reasons');
    await p.click('[data-res="explained"][data-a="a4"]'); await p.click('#dlg-ok'); ok(/Say what happened/.test(await txt(p, 'dlg-e')), 'explain needs a note');
    await p.fill('#r-note', 'with the user on leave, synthetic'); await p.click('#dlg-ok'); ok(await wait(p, () => /Recorded: explained/.test(document.body.innerText)), 'explained');
    await p.click('[data-res="lost"][data-a="a3"]'); await p.fill('#r-note', 'not in the rack, synthetic'); await p.click('#dlg-ok');
    ok(await wait(p, () => /Recorded: lost/.test(document.body.innerText)), 'marked lost'); ok(A.get('a3').status === 'lost', 'asset status set to lost');
    ok(e.app.store.auditTail(50).some((x) => x.action === 'stocktake.resolve' && x.detail.outcome === 'lost' && x.by === OP.user), 'audited');
    // misplaced
    await p.click('[data-t="mis"]'); await p.click('[data-move="j1"]'); ok(await wait(p, () => /Record moved to Riyadh/.test(document.body.innerText)), 'moved'); ok(A.get('j1').site === 'Riyadh', 'stored');
    // breakdown + plan
    await p.click('[data-t="brk"]'); ok(/Finance/.test(await txt(p, 'v-brk')), 'by department');
    await p.click('[data-t="plan"]'); ok(/never counted|last counted/.test(await txt(p, 'v-plan')), 'next-count plan');
    const dl = p.waitForEvent('download'); await p.click('#b-csv'); ok(/stocktake-missing-/.test((await dl).suggestedFilename()), 'CSV export');
    // close
    WHO = ADM; await p.click('#b-close'); await p.click('#dlg-ok'); ok(await wait(p, () => /Stocktake closed/.test(document.body.innerText) && document.getElementById('scanbox').hidden), 'closed, scanning stops');
    await p.close();
    // viewer
    WHO = ADM; const r0 = await new Promise((ok2) => { const x = http.request({ host: '127.0.0.1', port: e.port, method: 'POST', path: '/api/itam/stocktake', headers: { 'content-type': 'application/json', 'x-sentra-proxy-secret': H.SECRET, 'x-auth-user': ADM.user, 'x-auth-role': 'admin' } }, (r) => { let b = ''; r.on('data', (c) => { b += c; }); r.on('end', () => ok2(JSON.parse(b))); }); x.end(JSON.stringify({ site: 'Riyadh' })); });
    ok(r0 && r0.id, 'second count opened');
    WHO = VW; const q = await browser.newPage(); q.on('pageerror', (x) => errs.push(x.message)); await q.goto(base + 'stocktake.html');
    await wait(q, () => !document.getElementById('scanbox').hidden); await q.fill('#code', 'ZS-0001'); await q.press('#code', 'Enter');
    ok(await wait(q, () => /Operators scan and resolve/.test(document.getElementById('res').innerText)), 'viewer cannot scan'); await q.close();
    ok(/'itam-stocktake': 'stocktake\.html'/.test(fs.readFileSync(path.join(DASH, 'vendor/zyb-early.js'), 'utf8')), 'the portal Stocktake view redirects here');
    ok(/ stocktake\.html /.test(fs.readFileSync(path.join(DASH, 'install-dashboards.sh'), 'utf8')), 'in the installer');
    ok(/"h": "stocktake.html"/.test(fs.readFileSync(path.join(DASH, 'vendor/zyb-nav.js'), 'utf8')), 'menu entry');
    ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  } finally { await browser.close(); web.close(); e.close(); }
  console.log(`${n - bad}/${n} checks passed`); process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
