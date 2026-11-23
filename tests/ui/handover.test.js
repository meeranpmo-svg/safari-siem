// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for handover.html against the REAL IT Asset Management engine (engine/handover.js): the manager opens a
// handover and sees what the leaver owns; assigns everything to a successor; the successor accepts each item themselves
// (the manager has no Accept button); the leaver cannot close access items and has their secret-looking note refused;
// someone else closes the access checklist with evidence; the manager signs off and the owner fields move; a viewer is
// refused (personal data). Data is SYNTHETIC. Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node handover.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const ITAM = path.resolve(__dirname, '../../backend/itam'), DASH = path.resolve(__dirname, '../../ui');
const H = require(path.join(ITAM, 'tests/helpers.js'));
let WHO = { user: 'sara.syn', role: 'operator' };
let n = 0, bad = 0;
const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const ADM = { user: 'syed', role: 'admin', ip: '' };

(async () => {
  const e = await H.startApp({ noAi: true });
  const A = e.app.assets, S = e.app.store;
  const lap = A.create({ name: 'LAP-SYN-01', type: 'laptop', status: 'in_use', custodian: 'khalid.syn' }, ADM).asset.id;
  const fw = A.create({ name: '<img src=x onerror=alert(1)>', type: 'network', status: 'in_use', owner: 'khalid.syn' }, ADM).asset.id;
  S.collection('grc_risks').put({ id: 'RSK-0001', status: 'open', description: 'Firewall end of support', owner: 'khalid.syn' });
  require(path.join(ITAM, 'engine/handover')).registerHandover(e.app.srv, e.app, {});

  const srv = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://x'), json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u.pathname === '/dashboards/whoami.json') return json(200, WHO);
    if (u.pathname.startsWith('/api/itam/')) {
      const h = Object.assign({}, req.headers, { 'x-sentra-proxy-secret': H.SECRET, 'x-auth-user': WHO.user, 'x-auth-role': WHO.role });
      const up = http.request({ host: '127.0.0.1', port: e.port, method: req.method, path: req.url, headers: h }, (r) => { res.writeHead(r.statusCode, r.headers); r.pipe(res); });
      req.pipe(up); return;
    }
    if (u.pathname.startsWith('/api/')) return json(404, { error: 'not in this test' });
    const f = path.join(DASH, u.pathname); if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (err, d) => { if (err) { res.writeHead(404); res.end(); return; } res.writeHead(200, { 'Content-Type': u.pathname.endsWith('.js') ? 'application/javascript' : u.pathname.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const url = 'http://127.0.0.1:' + srv.address().port + '/handover.html';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  let page;
  const as = async (who, ready = '#list') => { WHO = who; if (page) await page.close(); page = await browser.newPage({ viewport: { width: 1400, height: 950 } }); page.on('pageerror', (x) => errs.push(x.message)); page.on('dialog', (d) => d.accept('synthetic reason')); await page.goto(url); await page.waitForFunction((sel) => !/Loading/.test(document.querySelector(sel).textContent), ready); };
  const body = () => page.textContent('body');
  const openIt = async () => { await page.click('[data-open="HO-0001"]'); await page.waitForSelector('#detail .card'); };
  try {
    // the manager opens it
    await as({ user: 'sara.syn', role: 'operator' });
    ok(/No handovers yet/.test(await page.textContent('#list')), 'empty state');
    await page.click('#new'); await page.fill('#n-l', 'khalid.syn'); await page.fill('#n-ln', 'Khalid (synthetic)'); await page.selectOption('#n-t', 'Cyber Security');
    await page.fill('#n-d', '2026-11-30'); await page.fill('#n-m', 'sara.syn'); await page.click('#n-go');
    await page.waitForSelector('#detail .card');
    let t = await page.textContent('#detail');
    ok(/HO-0001/.test(t) && /LAP-SYN-01/.test(t) && /Firewall end of support/.test(t) && /0 of 3 handed over/.test(t), 'items found: laptop, firewall, risk');
    ok(!(await page.$('#detail img')) && /<img src=x/.test(t), 'asset names shown as text');
    ok(/Before sign-off/.test(t) && !(await page.$('#detail [data-acc]')), 'blockers listed; the manager has no Accept button');
    ok(await page.isDisabled('#so-go'), 'sign-off disabled while not ready');
    await page.fill('#d-succ', 'omar.syn'); await page.click('#d-aall'); await page.waitForTimeout(300);
    ok(/waiting for the successor/.test(await page.textContent('#detail')), 'assigned - waiting for the successor');
    // the successor accepts in person
    await as({ user: 'omar.syn', role: 'operator' }); await openIt();
    for (let i = 0; i < 3; i++) { await page.click('#detail [data-acc]'); await page.waitForTimeout(250); }
    ok(/3 of 3 handed over/.test(await page.textContent('#detail')), 'the successor accepted all three');
    // the leaver: no access buttons, secret-looking notes refused, location accepted
    await as({ user: 'khalid.syn', role: 'operator' }); await openIt();
    ok(!(await page.$('[data-ad]')) && /Someone other than you confirms/.test(await page.textContent('#detail')), 'the leaver cannot close access items');
    await page.fill('#nt-systems', 'FortiGate HA pair, Wazuh rules'); await page.fill('#nt-secrets_location', 'root password is P@ssw0rd123'); await page.click('#nt-save'); await page.waitForTimeout(300);
    ok(/looks like it contains a password/.test(await body()), 'a password in the notes is refused, with the reason');
    await page.fill('#nt-secrets_location', 'kept in CyberArk safe NET-FW'); await page.click('#nt-save'); await page.waitForTimeout(300);
    ok(/Notes saved/.test(await body()), 'notes saved');
    // someone else closes the checklist
    await as({ user: 'ali.syn', role: 'operator' }); await openIt();
    const ids = await page.evaluate(() => [].map.call(document.querySelectorAll('[data-ad]'), (b) => b.getAttribute('data-ad')));
    ok(ids.length === 10, 'ten access items');
    await page.click(`[data-ad="${ids[0]}"]`); await page.waitForTimeout(200);
    ok(/Write the evidence/.test(await body()), 'evidence required in the page too');
    for (const id of ids) { await page.fill(`[data-ev="${id}"]`, 'SR-SYN-' + id); await page.click(id === 'physical' ? `[data-ana="${id}"]` : `[data-ad="${id}"]`); await page.waitForSelector(`[data-ev="${id}"]`, { state: 'attached' }).catch(() => {}); await page.waitForTimeout(150); }
    ok(/10 of 10 closed/.test(await page.textContent('#detail')), 'checklist closed');
    ok(!(await page.$('#so-go')), 'only the manager / an administrator sees sign-off');
    // the manager signs off
    await as({ user: 'sara.syn', role: 'operator' }); await openIt();
    ok(!(await page.isDisabled('#so-go')), 'ready to sign off');
    await page.fill('#so-c', 'handover complete'); await page.click('#so-go'); await page.waitForTimeout(400);
    t = await page.textContent('#detail');
    ok(/Signed off by sara\.syn/.test(t) && /moved/.test(t), 'signed off, items moved');
    ok(S.collection('assets').get(lap).custodian === 'omar.syn' && S.collection('assets').get(fw).owner === 'omar.syn' && S.collection('grc_risks').get('RSK-0001').owner === 'omar.syn', 'owner fields moved to the successor');
    ok(await page.$('#d-print') !== null, 'print / PDF button');
    // a viewer is refused
    await as({ user: 'nora.syn', role: 'viewer' });
    ok(/operators and administrators only/.test(await page.textContent('#list')), 'viewer refused (personal data)');
    ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  } finally { await browser.close(); srv.close(); await e.close(); }
  console.log(bad ? 'FAILED ' + bad + '/' + n + ' checks' : 'OK ' + n + '/' + n + ' checks'); process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
