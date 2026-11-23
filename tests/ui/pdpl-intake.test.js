// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for the request intake on the Data Subject Requests page (pdpl-dsar.html) against the REAL ITAM engine
// (engine/pdpl-intake.js + pyengine/pdpl_intake.py) with SYNTHETIC data: an administrator issues an intake key (shown once in
// the drawer), saves the handler and the accepted identity checks, the sending system posts requests with the key, the page
// lists them with where they came from and the automation applied, a duplicate stays one request, the drawer shows the flags,
// a hostile system name stays text, and an operator sees the intake without the admin controls, a viewer is refused.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node pdpl-intake.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const ITAM = path.join(__dirname, '..', '..', 'backend', 'itam'), DASH = path.join(__dirname, '..', '..', 'ui');
const H = require(path.join(ITAM, 'tests', 'helpers'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const XSS = '<img src=x onerror=alert(1)>';

(async () => {
  const e = await H.startApp({ noAi: true });
  require(path.join(ITAM, 'engine/duty')).registerDuty(e.app.srv, e.app, { noTimer: true, python: process.env.PYTHON || 'python3' });
  let WHO = { user: 'syed', role: 'admin' };
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
  const send = (key, body) => e.req('POST', '/agent/dsar/intake', { body, bearer: key, user: '', role: '' });
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  try {
    const p = await browser.newPage({ viewport: { width: 1400, height: 950 } }); p.on('pageerror', (x) => errs.push(x.message));
    p.on('dialog', (d) => d.accept());
    await p.goto(base + 'pdpl-dsar.html?standalone=1'); await p.waitForSelector('#inkform', { state: 'attached', timeout: 15000 });
    ok(/Nothing sent in yet/.test(await p.textContent('#inbody')), 'empty state says what to connect');
    // issue a key with a hostile name: shown once in the drawer
    await p.fill('#inkform [name=name]', 'Portal ' + XSS); await p.click('#inkform button[type=submit]');
    await p.waitForSelector('#newkey', { timeout: 8000 });
    const key = await p.textContent('#newkey');
    ok(/^dk_[0-9a-f]{48}$/.test(key), 'the key is shown once');
    await p.keyboard.press('Escape');
    await p.waitForFunction(() => /DK-001/.test(document.getElementById('inbody').textContent), null, { timeout: 8000 });
    ok(!(await p.$('#inbody img')) && (await p.textContent('#inbody')).includes(XSS), 'a hostile system name stays text');
    ok(!(await p.textContent('#inbody')).includes(key), 'the key is not listed afterwards');
    // settings
    await p.fill('#in-def', 'huda.syn'); await p.check('#insform input[name=strong][value=nafath]'); await p.click('#insform button[type=submit]');
    await p.waitForFunction(() => /Handler: huda\.syn/.test(document.getElementById('inbody').textContent), null, { timeout: 8000 });
    ok(/Nafath/.test(await p.textContent('#inbody')) && /automatic search: off/.test(await p.textContent('#inbody')), 'settings saved and shown');
    // the sending system posts requests
    let r = await send(key, { ref: 'WEB-SYN-101', type: 'access', channel: 'web', identity_method: 'nafath', id_type: 'national_id', id_value: '1012345678', language: 'both' });
    ok(r.status === 200 && r.json.identity_verified && /2026|20\d\d/.test(r.json.due) && /الاطلاع/.test(r.json.acknowledgement.ar), 'request accepted: verified by the channel, due date, Arabic acknowledgement');
    r = await send(key, { ref: 'WEB-SYN-102', type: 'access', channel: 'web', identity_method: 'nafath', id_type: 'national_id', id_value: '1012345678' });
    ok(r.json.duplicate_of === r.json.request, 'the same open request from the same person stays one request');
    await send(key, { ref: 'CC-SYN-7', type: 'destruction', channel: 'call_centre', identity_method: 'registered_email' });
    await p.click('#refresh');
    await p.waitForFunction(() => /CC-SYN-7/.test(document.getElementById('list').textContent) && /CC-SYN-7/.test(document.getElementById('inbody').textContent), null, { timeout: 10000 });
    ok((await p.$$eval('#list tbody tr', (x) => x.length)) === 2, 'two requests (the duplicate folded into the first)');
    const inb = await p.textContent('#inbody');
    ok(/verified by channel/.test(inb) && /to verify/.test(inb), 'the intake log shows what the automation did');
    // the drawer
    await p.click('#list tr[data-id] >> text=CC-SYN-7');
    await p.waitForFunction(() => /Sent in automatically/.test((document.getElementById('zd') || document.body).textContent), null, { timeout: 8000 });
    const dz = await p.textContent('#zd');
    ok(/verify identity/i.test(dz) && /not accepted as verification/.test(dz), 'the drawer shows the flag and why');
    ok(!(await p.$('#zd img')), 'no markup from the system name in the drawer');
    await p.keyboard.press('Escape');
    // an operator: the intake without admin controls; a viewer: refused
    WHO = { user: 'nora.syn', role: 'operator' }; await p.reload(); await p.waitForFunction(() => /WEB-SYN-101/.test(document.getElementById('inbody').textContent), null, { timeout: 10000 });
    ok(!(await p.$('#insform')) && !(await p.$('#inkform')), 'an operator sees the intake without the admin controls');
    WHO = { user: 'v.syn', role: 'viewer' }; await p.reload(); await p.waitForFunction(() => /operator role/.test(document.getElementById('inbody').textContent), null, { timeout: 10000 }).then(() => ok(true), () => ok(false, 'a viewer is refused with the reason'));
    ok(e.app.store.auditTail(80).some((a) => a.action === 'pdpl.dsar.intake') && e.app.store.auditTail(80).some((a) => a.action === 'pdpl.intake.settings' && a.by === 'syed'), 'audited');
  } finally { await browser.close(); srv.close(); e.close(); }
  ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks');
  process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
