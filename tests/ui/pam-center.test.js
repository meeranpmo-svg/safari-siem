// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// PAM Center page (pam-center.html) against the REAL IT Asset Management engine, SYNTHETIC accounts and passwords: tiles, maturity,
// charts, what the AI noticed, privileged accounts with reasons; an administrator adds a safe entry (the password field is cleared,
// the value never appears on the page); an operator requests a checkout and cannot approve it; another administrator approves; the
// requester reveals it in a dialog that closes and keeps nothing; check-in marks it for rotation; a viewer is refused; hostile text
// stays text; menu entry and installer.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node pam-center.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const DASH = path.resolve(__dirname, '../../ui'), ITAM = path.resolve(__dirname, '../../backend/itam');
const H = require(path.join(ITAM, 'tests/helpers'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const XSS = '<img src=x onerror=window.PWN=1>', SECRET = 'Synthetic-Page-BG-4!k';
(async () => {
  const e = await H.startApp({ noAi: true }); require(path.join(ITAM, 'engine/duty')).registerDuty(e.app.srv, e.app, { noTimer: true, copilotAiOff: true });
  const d = (k) => new Date(Date.now() - k * 864e5).toISOString();
  e.app.store.collection('ad_directory').put({ id: 'last', at: d(0), users: [{ sam: 'administrator', enabled: true, last_logon: d(1), admin_count: 1 }, { sam: 'a.harbi', display_name: XSS, enabled: true, last_logon: d(1), admin_count: 1 }, { sam: 'old-adm', enabled: true, last_logon: null, admin_count: 1 }] });
  let WHO = { user: 'admin.syn', role: 'admin' }, PROMPTS = [];
  const srv = http.createServer((req, res) => { const u = new URL(req.url, 'http://x');
    if (u.pathname === '/dashboards/whoami.json') { res.writeHead(200, { 'Content-Type': 'application/json' }); return res.end(JSON.stringify(WHO)); }
    if (u.pathname.startsWith('/api/itam/')) { const h = Object.assign({}, req.headers, { 'x-sentra-proxy-secret': H.SECRET, 'x-auth-user': WHO.user, 'x-auth-role': WHO.role });
      const up = http.request({ host: '127.0.0.1', port: e.port, method: req.method, path: req.url, headers: h }, (r) => { res.writeHead(r.statusCode, r.headers); r.pipe(res); }); req.pipe(up); return; }
    if (u.pathname.startsWith('/api/')) { res.writeHead(404, { 'Content-Type': 'application/json' }); return res.end('{}'); }
    fs.readFile(path.join(DASH, u.pathname.replace(/^\/dashboards\//, '/')), (err, x) => { if (err) { res.writeHead(404); return res.end(); } res.writeHead(200, { 'Content-Type': u.pathname.endsWith('.js') ? 'application/javascript' : u.pathname.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(x); }); });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const url = 'http://127.0.0.1:' + srv.address().port + '/dashboards/pam-center.html?standalone=1';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright'); const browser = await chromium.launch(), errs = [];
  const open = async (sel) => { const p = await browser.newPage({ viewport: { width: 1500, height: 1100 } }); p.on('pageerror', (x) => errs.push(x.message)); p.on('dialog', (dd) => dd.accept(dd.type() === 'prompt' ? (PROMPTS.shift() || '') : undefined)); await p.goto(url); await p.waitForSelector(sel || '#main:not([hidden])', { timeout: 15000 }); return p; };
  try {
    let p = await open();
    const kp = (await p.$eval('#kp', (x) => x.innerText)).replace(/\s+/g, ' ');
    ok(/Privileged accounts 3 3 with standing privilege/.test(kp) && /PAM maturity \d+/.test(kp), 'tiles: ' + kp);
    ok((await p.$$('.g3 canvas')).length === 4 && /hold admin rights all the time/.test(await p.textContent('#ins')), 'maturity, charts and what the AI noticed');
    ok(/never signed in/.test(await p.textContent('#ids')) && !(await p.evaluate(() => window.PWN)), 'reasons; hostile text stays text');
    await p.fill('#af [name=system]', 'Riyadh DC (synthetic)'); await p.fill('#af [name=account]', 'BG-DomainAdmin'); await p.selectOption('#af [name=kind]', 'break-glass'); await p.fill('#af [name=owner]', 'owner.syn'); await p.fill('#af [name=secret]', SECRET);
    await p.click('#af button[type=submit]'); await p.waitForFunction(() => /BG-DomainAdmin/.test(document.getElementById('safe').textContent), null, { timeout: 8000 });
    ok(!(await p.content()).includes(SECRET) && (await p.$eval('#af [name=secret]', (x) => x.value)) === '', 'added; the password is not on the page');
    await p.close();
    WHO = { user: 'net.syn', role: 'operator' }; p = await open(); PROMPTS = ['patch the domain controllers (synthetic)', '2', 'CHG-2001'];
    await p.click('[data-co]'); await p.waitForFunction(() => /pending/.test(document.getElementById('cos').textContent), null, { timeout: 8000 });
    ok(/another administrator approves/.test(await p.textContent('#cos')) && !(await p.$('[data-dec]')), 'requested; the requester cannot approve'); await p.close();
    WHO = { user: 'admin2.syn', role: 'admin' }; p = await open(); await p.click('[data-dec="approve"]'); await p.waitForFunction(() => /approved/.test(document.getElementById('cos').textContent), null, { timeout: 8000 });
    ok(!(await p.$('[data-rev]')), 'the approver cannot reveal'); await p.close();
    WHO = { user: 'net.syn', role: 'operator' }; p = await open(); await p.click('[data-rev]'); await p.waitForSelector('#dlg[open]');
    ok((await p.textContent('#sec')) === SECRET, 'the requester sees the password in the dialog'); await p.click('#dlgx');
    ok(!(await p.content()).includes(SECRET), 'closed: nothing kept on the page');
    await p.click('[data-in]'); await p.waitForFunction(() => /checked-in/.test(document.getElementById('cos').textContent), null, { timeout: 8000 });
    ok(/due/.test(await p.textContent('#safe')), 'checked in: due for rotation'); await p.close();
    WHO = { user: 'vera.syn', role: 'viewer' }; p = await open('#err .err'); ok(/operators and administrators/.test(await p.textContent('#err')), 'a viewer is refused'); await p.close();
    ok(fs.readFileSync(path.join(DASH, 'vendor/zyb-nav.js'), 'utf8').includes('"h": "pam-center.html"') && / pam-center\.html /.test(fs.readFileSync(path.join(DASH, 'install-dashboards.sh'), 'utf8')), 'menu entry and installer');
    ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  } finally { await browser.close(); srv.close(); await e.close(); }
  console.log((bad ? 'FAILED ' : 'ok ') + (n - bad) + '/' + n + ' pam-center checks'); process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
