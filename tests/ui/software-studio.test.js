// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for dashboards/server/software-studio.html against the REAL ITAM engine (engine/software-studio.js through duty.js) with
// SYNTHETIC installed software and licences: KPIs, findings (remote access, unlicensed, rare), licence compliance with waste and
// true-up (operators) and no money for viewers, reclaim list, a licence recorded on the page (validated), approve / block with a
// required reason, product search, escaping, the portal itam-software redirect, menu + installer.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node asset-autofill.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const ITAM = path.join(__dirname, '..', '..', 'backend', 'itam'), DASH = path.join(__dirname, '..', '..', 'ui');
const H = require(path.join(ITAM, 'tests', 'helpers'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const ADM = { user: 'syed', role: 'admin' }, OP = { user: 'nora.syn', role: 'operator' }, VW = { user: 'vera.syn', role: 'viewer' };
const XSS = '<img src=x onerror="window.__xss=1">';

(async () => {
  const e = await H.startApp({ noAi: true });
  require(path.join(ITAM, 'engine/duty')).registerDuty(e.app.srv, e.app, { noTimer: true });
  const A = e.app.store.collection('assets'), now = new Date().toISOString();
  for (let i = 0; i < 22; i++) A.put({ id: 'ws' + i, name: 'WS-' + i, type: 'workstation', status: i === 1 ? 'in_stock' : 'in_use', last_seen: now,
    software: [{ name: 'Microsoft Visio Professional', publisher: 'Microsoft', version: '16.0' }].concat(i === 0 ? [{ name: 'AnyDesk', publisher: 'AnyDesk Software' }, { name: 'Autodesk AutoCAD ' + XSS, publisher: 'Autodesk' }, { name: 'SynOddTool', publisher: 'SynSoft' }] : []) });
  e.app.store.collection('licences').put({ id: 'lic_visio', product: 'Visio', product_key_match: 'visio', seats: 20, cost: 20000, status: 'active' });
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
    const p = await browser.newPage({ viewport: { width: 1500, height: 1000 } }); p.on('pageerror', (x) => errs.push(x.message));
    await p.goto(base + 'software-studio.html');
    ok(await wait(p, () => /Products/i.test(document.getElementById('kp').innerText)), 'KPIs');
    const fi = await txt(p, 'find');
    ok(/AnyDesk[\s\S]*remote access/i.test(fi) && /no licence/i.test(fi) && /rare for its type/i.test(fi), 'findings: remote access, unlicensed, rare');
    ok(await p.evaluate(() => !window.__xss) && !(await p.$('#find img')), 'names escaped');
    await p.click('[data-tab="li"]'); let li = await txt(p, 'lic');
    ok(/Visio[\s\S]*20[\s\S]*22[\s\S]*over \+2/.test(li) && /2,000/.test(li), 'licence over by 2, true-up 2 000 shown to operators: ' + li.replace(/\s+/g, ' ').slice(0, 300));
    ok(/1 seat/.test(li), 'reclaim: the in-stock workstation');
    // record a licence
    await p.click('#b-lic'); await p.click('#l-save'); ok(/Product is required/.test(await txt(p, 'l-err')), 'the page checks the product');
    await p.fill('#l-prod', 'Autodesk AutoCAD'); await p.fill('#l-seats', '1'); await p.fill('#l-cost', '7000'); await p.fill('#l-match', 'autocad'); await p.click('#l-save');
    ok(await wait(p, () => /Licence saved/.test(document.body.innerText)), 'licence recorded');
    await p.click('[data-tab="fi"]'); ok(await wait(p, () => !/AutoCAD[^\n]*\n?[^\n]*no licence/i.test(document.getElementById('find').innerText)), 'AutoCAD is no longer unlicensed');
    // approve AnyDesk with a reason
    await p.evaluate(() => [...document.querySelectorAll('#find [data-pol="approved"]')].find((b) => /AnyDesk/.test(b.dataset.name)).click());
    await p.click('#dlg-ok'); ok(await p.evaluate(() => document.getElementById('dlg').open), 'a reason is required');
    await p.fill('#dlg-r', 'sanctioned IT support tool'); await p.click('#dlg-ok');
    ok(await wait(p, () => !/AnyDesk/.test(document.getElementById('find').innerText)), 'approved: no longer a finding');
    await p.click('[data-tab="po"]'); ok(/AnyDesk[\s\S]*approved[\s\S]*sanctioned/.test(await txt(p, 'pol')), 'policy list');
    await p.click('[data-tab="pr"]'); await p.fill('#q', 'visio'); ok(/Visio/.test(await txt(p, 'prod')) && !/SynOddTool/.test(await txt(p, 'prod')), 'product search');
    // a viewer sees no money and cannot set policy
    WHO = VW; await p.reload(); await wait(p, () => /Products/i.test(document.getElementById('kp').innerText));
    await p.click('[data-tab="li"]'); ok(!/True-up/.test(await txt(p, 'lic')) && !/2,000/.test(await txt(p, 'lic')), 'viewer: no costs');
    await p.click('[data-tab="pr"]'); await p.evaluate(() => document.querySelector('#prod [data-pol="blocked"]').click()); await p.fill('#dlg-r', 'x'); await p.click('#dlg-ok');
    ok(await wait(p, () => /Operators and administrators set the policy/.test(document.body.innerText)), 'viewer refused');
    await p.close();
    const q = await browser.newPage(); await q.goto(base + 'lifecycle-studio.html'); await q.waitForTimeout(800);
    ok(await q.evaluate(() => !!document.querySelector('a[href="software-studio.html"]')), 'menu entry'); await q.close();
    ok(/'itam-software': 'software-studio\.html'/.test(fs.readFileSync(path.join(DASH, 'vendor/zyb-menu.js'), 'utf8')) && /'itam-software': 'software-studio\.html'/.test(fs.readFileSync(path.join(DASH, 'vendor/zyb-early.js'), 'utf8')), 'the portal Software & licences view redirects here');
    ok(/ software-studio\.html /.test(fs.readFileSync(path.join(DASH, 'install-dashboards.sh'), 'utf8')), 'in the installer');
    ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  } finally { await browser.close(); web.close(); e.close(); }
  console.log(`${n - bad}/${n} checks passed`); process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
