// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// door-access.html against the REAL SIEM door access engine (sentra-siem engine/facilities) and an in-process fake ZKBioSecurity
// (SYNTHETIC controllers, doors and events): nothing connected says what to do; an admin adds the server and the token (the token is
// never shown again); an operator reads now; controllers online / offline / not reported; door alarms ranked; no person in the page;
// names escaped; a viewer cannot change the connection; reachable from the menu and linked from Facilities.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node door-access.test.js
const http = require('http'), fs = require('fs'), os = require('os'), path = require('path'), crypto = require('crypto');
const DASH = path.resolve(__dirname, '../../ui');
const SIEM = process.env.SENTRA_SIEM || path.resolve(__dirname, '../..', 'backend', 'siem');
const KD = fs.mkdtempSync(path.join(os.tmpdir(), 'da-key-')); process.env.SENTRA_SIEM_SECRETS_KEY = path.join(KD, 'secrets.key');
fs.writeFileSync(process.env.SENTRA_SIEM_SECRETS_KEY, crypto.randomBytes(32).toString('hex'), { mode: 0o440 });
const routes = require(path.join(SIEM, 'engine/facilities/routes'));
const { createState } = require(path.join(SIEM, 'engine/soc/state'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const XSS = '<img src=x onerror="window.__xss=1">', TOKEN = 'zk-page-token-777';

(async () => {
  // fake ZKBio
  const zk = http.createServer((q, r) => {
    const u = new URL(q.url, 'http://x'), j = (o) => { r.writeHead(200, { 'Content-Type': 'application/json' }); r.end(JSON.stringify(o)); };
    if (q.method !== 'GET' || u.searchParams.get('access_token') !== TOKEN) return j({ code: 401, message: 'invalid token' });
    const t = (m) => new Date(Date.now() - m * 60000 + 3 * 3600000).toISOString().replace('T', ' ').slice(0, 19);
    if (u.pathname === '/api/device/list') return j({ code: 0, data: [{ devName: 'CTRL-RUH-01 ' + XSS, sn: 'SYN01', ipAddress: '10.1.5.10', connectState: 1, areaName: 'Riyadh HQ' }, { devName: 'CTRL-JED-01', sn: 'SYN02', connectState: 0, areaName: 'Jeddah' }, { devName: 'CTRL-DMM-01', sn: 'SYN03', connectState: 9 }] });
    if (u.pathname === '/api/door/list') return j({ code: 0, data: [{ doorName: 'Server Room', devName: 'CTRL-RUH-01' }, { doorName: 'Lobby' }] });
    if (u.pathname === '/api/transaction/list') return j({ code: 0, data: { rows: [{ eventName: 'Door Forced Open', eventPointName: 'Server Room', eventTime: t(15), name: 'Synthetic Person', pin: '4711' }, { eventName: 'Door Opened Too Long', eventPointName: 'Lobby', eventTime: t(40) }] } });
    r.writeHead(404); r.end();
  });
  await new Promise((r) => zk.listen(0, '127.0.0.1', r));
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'da-page-')), secrets = path.join(dir, 'secrets.json');
  const state = await createState({ dir: path.join(dir, 'state') });
  const config = {}; Object.defineProperty(config, 'secrets', { value: {}, writable: true }); Object.defineProperty(config, '_paths', { value: { secrets } });
  const D = routes.createDoors({ state, config, log: { info() {}, warn() {}, error() {} }, allowHttp: true });
  const R = []; routes.register({ route: (m, p, h) => { R.push({ m, re: new RegExp('^' + p.replace(/:[a-z]+/g, '([^/]+)') + '$'), keys: (p.match(/:[a-z]+/g) || []).map((k) => k.slice(1)), h }); } }, { state, config, log: { error() {}, info() {} }, doors: D });
  const RANK = { viewer: 0, analyst: 1, operator: 2, admin: 3 };
  let WHO = { user: 'syed', role: 'admin' };
  const srv = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://x'), json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u.pathname.endsWith('whoami.json')) return json(200, WHO);
    if (u.pathname.startsWith('/api/soc/facilities/')) { let b = ''; req.on('data', (c) => { b += c; }); req.on('end', async () => {
      const r = R.find((x) => x.m === req.method && x.re.test(u.pathname)); if (!r) return json(404, { error: 'not found' });
      const mm = r.re.exec(u.pathname), params = {}; r.keys.forEach((k, i) => { params[k] = decodeURIComponent(mm[i + 1]); });
      const out = {}, ctx = { role: WHO.role, user: WHO.user, body: b ? JSON.parse(b) : {}, params, query: {}, need(x) { if (RANK[WHO.role] < RANK[x]) { out.c = 403; out.e = 'requires ' + x; return false; } return true; }, audit() {}, fail(c, e) { out.c = c; out.e = e; } };
      try { const rv = await r.h(ctx); if (out.c) return json(out.c, { error: out.e }); json(200, rv); } catch (e) { json(e.status || 500, { error: e.message }); } }); return; }
    if (u.pathname.startsWith('/api/')) return json(404, { error: 'not found' });
    const f = path.join(DASH, u.pathname.replace(/^\/dashboards\//, '/')); if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (err, d) => { if (err) { res.writeHead(404); res.end(); return; } res.writeHead(200, { 'Content-Type': u.pathname.endsWith('.js') ? 'application/javascript' : u.pathname.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port + '/dashboards/';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  const wait = (p, fn, arg) => p.waitForFunction(fn, arg, { timeout: 15000 }).then(() => true, () => false);
  const txt = (p, s) => p.evaluate((q) => document.querySelector(q).innerText, s);
  try {
    const p = await browser.newPage({ viewport: { width: 1500, height: 1000 } }); p.on('pageerror', (e) => errs.push(e.message));
    await p.goto(base + 'door-access.html');
    ok(await wait(p, () => /API Authorization/.test(document.getElementById('body').innerText)), 'nothing connected: says what to connect');
    ok(!/\d+ \/ \d+/.test(await txt(p, '#kp')), 'no figure invented');
    await p.click('[data-tab="cn"]');
    await p.fill('#c-id', 'Bad ID!'); await p.click('#c-save'); ok(/ID: 2-40/.test(await txt(p, '#c-msg')), 'the page checks the id');
    await p.fill('#c-id', 'zk-hq'); await p.fill('#c-label', 'ZKBio HQ'); await p.fill('#c-site', 'Riyadh HQ'); await p.fill('#c-host', '127.0.0.1'); await p.fill('#c-port', String(zk.address().port));
    await p.fill('#c-pev', '/api/../x'); await p.click('#c-save');
    ok(await wait(p, () => /path_events/.test(document.getElementById('c-msg').innerText)), 'the server re-checks a path and names the field');
    await p.fill('#c-pev', ''); await p.click('#c-save'); ok(await wait(p, () => /Saved zk-hq/.test(document.getElementById('c-msg').innerText)), 'admin saves the server');
    await p.fill('#c-token', TOKEN); await p.click('#c-tok'); ok(await wait(p, () => /Token saved/.test(document.getElementById('c-msg').innerText)), 'admin saves the token');
    ok(await wait(p, () => /token set/.test(document.getElementById('srv').innerText)), 'the list says a token is set');
    ok(!(await p.content()).includes(TOKEN) && (await p.inputValue('#c-token')) === '', 'the token is never shown again');
    WHO = { user: 'op.syn', role: 'operator' };
    await p.click('[data-sync="zk-hq"]'); ok(await wait(p, () => /Read: 3 controllers, 2 doors, 2 alarm events/.test(document.getElementById('c-msg').innerText)), 'an operator reads now');
    await p.click('[data-tab="ov"]');
    ok(await wait(p, () => /Controllers online\s*1 \/ 3/i.test(document.getElementById('kp').innerText)), 'controllers online from the read');
    const kp = await txt(p, '#kp'), body = await txt(p, '#body');
    ok(/1 offline · 1 not reported/.test(kp), 'an unknown state code is "not reported", not online');
    ok(/forced open/i.test(body) && /Server Room/.test(body) && /Held open/i.test(body), 'door alarms ranked and per door');
    ok(/CTRL-JED-01[\s\S]*offline/.test(body), 'offline controller listed');
    ok(!/Synthetic Person|4711/.test(body), 'no person in the page (PDPL)');
    ok(await p.evaluate(() => !window.__xss) && !(await p.$('#body img')), 'names escaped');
    WHO = { user: 'vera.syn', role: 'viewer' };
    await p.click('[data-tab="cn"]'); await p.fill('#c-id', 'zk-hq'); await p.fill('#c-host', '127.0.0.1'); await p.click('#c-save');
    ok(await wait(p, () => /Only an administrator/.test(document.getElementById('c-msg').innerText)), 'a viewer cannot change the connection');
    await p.close();
    // menu + Facilities link
    const q = await browser.newPage(); q.on('pageerror', (e) => errs.push(e.message)); await q.goto(base + 'facilities.html'); await q.waitForTimeout(800);
    ok(await q.evaluate(() => !!document.querySelector('a[href="door-access.html"]')), 'linked from Facilities');
    ok(/"h": "door-access.html"/.test(fs.readFileSync(path.join(DASH, 'vendor/zyb-nav.js'), 'utf8')), 'menu entry');
    ok(/ door-access\.html /.test(fs.readFileSync(path.join(DASH, 'install-dashboards.sh'), 'utf8')), 'in the installer');
    await q.close();
    ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  } finally { await browser.close(); srv.close(); zk.close(); }
  console.log(`${n - bad}/${n} checks passed`); process.exit(bad ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });
