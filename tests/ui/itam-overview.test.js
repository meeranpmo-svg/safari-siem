// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for dashboards/server/itam-overview.html against the REAL ITAM engine (engine/itam-overview.js over the module views)
// with SYNTHETIC data: empty register says the score is withheld and what to connect; with data the ring shows the score, every part
// with its weight (unmeasured shown as such), the ranked actions link to the fixing page, tiles open their module, breakdowns render,
// a viewer sees "operators" for purchasing; the trend says one day so far; names escaped; portal itam redirect; menu + installer.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node itam-overview.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const ITAM = path.join(__dirname, '..', '..', 'backend', 'itam'), DASH = path.join(__dirname, '..', '..', 'ui');
const H = require(path.join(ITAM, 'tests', 'helpers'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const ADM = { user: 'syed', role: 'admin' }, VW = { user: 'vera.syn', role: 'viewer' };
const XSS = '<img src=x onerror="window.__xss=1">';

(async () => {
  const e = await H.startApp({ noAi: true });
  require(path.join(ITAM, 'engine/duty')).registerDuty(e.app.srv, e.app, { noTimer: true });
  const A = e.app.store.collection('assets'), ago = (d) => new Date(Date.now() - d * 86400000).toISOString(), now = new Date().toISOString();
  let WHO = VW;

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
    let p = await browser.newPage({ viewport: { width: 1500, height: 1000 } }); p.on('pageerror', (x) => errs.push(x.message));
    await p.goto(base + 'itam-overview.html');
    ok(await wait(p, () => /withheld/.test(document.getElementById('ring').innerText)), 'empty: score withheld');
    ok(/not measured/.test(await txt(p, 'comp')), 'empty: parts not measured'); ok(/Add assets/.test(await txt(p, 'acts')), 'empty: says what to connect');
    ok(/operators/.test(await txt(p, 'mods')), 'viewer: purchasing is for operators'); await p.close();
    for (let i = 0; i < 4; i++) A.put({ id: 'w' + i, name: 'WS-SYN-' + i + (i === 0 ? XSS : ''), type: 'workstation', status: 'in_use', networked: true, site: 'Riyadh', serial: 'SERSYN' + i, owner: 'o' + i, department: 'IT', vendor: 'SynV', model: 'M1', last_seen: ago(1), updated_at: now });
    A.put({ id: 'dup', name: 'WS-SYN-0b', type: 'workstation', status: 'in_use', serial: 'SERSYN0', site: 'Jeddah', last_seen: ago(1), updated_at: now });
    e.app.store.collection('findings').put({ id: 'f1', key: 'k1', kind: 'warranty_expired', severity: 'high', asset_id: 'w1', title: 'Warranty expired on WS-SYN-1', status: 'open', created_at: ago(40), evidence: {} });
    e.app.store.collection('stocktakes').put({ id: 'stk_syn', name: 'SYN', site: 'Riyadh', status: 'closed', opened_at: ago(10), closed_at: ago(9), expected: ['w0', 'w1', 'w2', 'w3'], scanned: [{ asset_id: 'w0' }, { asset_id: 'w1' }, { asset_id: 'w2' }], unexpected: [], missing: ['w3'] });
    WHO = ADM; await e.app.addons.itamOverview.snapshot();
    p = await browser.newPage({ viewport: { width: 1500, height: 1000 } }); p.on('pageerror', (x) => errs.push(x.message));
    await p.goto(base + 'itam-overview.html');
    ok(await wait(p, () => /\d+/.test(document.getElementById('ring').innerText) && !/withheld/.test(document.getElementById('ring').innerText)), 'score shown');
    let t = await txt(p, 'comp'); ok(/Last stocktake accuracy[\s\S]*75%/.test(t) && /weight 25/.test(t) && /not measured/.test(t), 'parts itemised, unmeasured shown');
    t = await txt(p, 'acts'); ok(/Warranty expired on WS-SYN-1/.test(t) && /duplicate/.test(t), 'actions ranked');
    ok(await p.evaluate(() => [].every.call(document.querySelectorAll('#acts a.act'), (a) => /\.html$/.test(a.getAttribute('href')))), 'actions link to their page');
    ok(await p.evaluate(() => !!document.querySelector('#tiles a[href="stocktake.html"]') && /75 %/.test(document.getElementById('tiles').innerText)), 'tiles open their module');
    ok(/workstation/.test(await txt(p, 'b-type')) && /Riyadh/.test(await txt(p, 'b-site')), 'breakdowns');
    ok(/One day recorded/.test(await txt(p, 'trend')), 'trend honest with one day');
    ok(await p.evaluate(() => !window.__xss), 'escaped');
    ok(/Purchasing/.test(await txt(p, 'mods')) && !/operators/.test(await txt(p, 'mods')), 'admin sees purchasing');
    await p.close();
    ok(/ itam: 'itam-overview\.html'/.test(fs.readFileSync(path.join(DASH, 'vendor/zyb-early.js'), 'utf8')), 'the portal ITAM view redirects here');
    ok(/ itam-overview\.html /.test(fs.readFileSync(path.join(DASH, 'install-dashboards.sh'), 'utf8')), 'in the installer');
    ok(/"h": "itam-overview.html"/.test(fs.readFileSync(path.join(DASH, 'vendor/zyb-nav.js'), 'utf8')), 'menu entry');
    ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  } finally { await browser.close(); web.close(); e.close(); }
  console.log(`${n - bad}/${n} checks passed`); process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
