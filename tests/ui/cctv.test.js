// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// CCTV / NVR (dashboards/server/cctv.html) against the REAL SIEM module (engine/facilities/cctv.js + routes.js) with an injected
// SYNTHETIC recorder client: nothing connected says what to do; an admin adds a recorder and its read-only login (admin user refused);
// the operator reads it now; tiles (online, offline, flapping, availability, disks); ranked actions with the failed disk first; a group
// outage named as one shared cause; camera grid filtered from a tile; recorders and disks; cameras missing from the asset register;
// a hostile camera name stays text; viewer sees no connection controls; Facilities shows the CCTV card; menu, installer, redirect.
// Run: SENTRA_SIEM_DIR=/home/user/sentra-siem PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node cctv.test.js
const http = require('http'), fs = require('fs'), os = require('os'), path = require('path'), crypto = require('crypto');
const KEYDIR = fs.mkdtempSync(path.join(os.tmpdir(), 'sentra-cctvp-key-')); process.env.SENTRA_SIEM_SECRETS_KEY = path.join(KEYDIR, 'secrets.key'); fs.writeFileSync(process.env.SENTRA_SIEM_SECRETS_KEY, crypto.randomBytes(32).toString('hex'), { mode: 0o440 });
const DASH = path.resolve(__dirname, '../../ui');
const SIEM = process.env.SENTRA_SIEM_DIR || path.resolve(__dirname, '../../backend/siem');
const req = (m) => require(path.join(SIEM, 'engine', m));
const { createState } = req('soc/state');
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const XSS = '<img src=x onerror="window.__xss=1">';
let ROLE = 'viewer', USER = 'vera.syn';
const RANK = { viewer: 0, analyst: 1, operator: 2, admin: 3 };

(async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sentra-cctvp-')), Lq = { info() {}, warn() {}, error() {} }, secFile = path.join(dir, 'secrets.json');
  const state = createState({ dir: path.join(dir, 'state'), log: Lq });
  const config = {}; Object.defineProperty(config, '_paths', { value: { secrets: secFile } }); Object.defineProperty(config, 'secrets', { value: {}, writable: true });
  let T = Date.now() - 2 * 3600e3, reads = 0;
  // camera 1-3 drop together at the last read; 4 flaps; 5 always up; disk failed
  const client = () => ({ snapshot: async (at) => { reads++; const last = reads >= 20, flapUp = reads % 2 === 0;
    return { at, errors: [], info: { name: 'NVR-SYN', model: 'DS-SYN-7716', serial: 'SYN0001', firmware: 'V4.SYN' },
      channels: [1, 2, 3, 4, 5].map((i) => ({ id: String(i), name: i === 1 ? 'Lobby ' + XSS : 'Cam-' + i, ip: '10.10.20.' + i })),
      status: [1, 2, 3, 4, 5].map((i) => ({ id: String(i), online: i <= 3 ? !last : i === 4 ? flapUp : true })), disks: [{ id: '1', name: 'hdd1', capacity_gb: 3726, free_gb: 0, status: 'error' }] }; } });
  const C = req('facilities/cctv').createCctv({ state, config, log: Lq, now: () => T, client });
  const deps = { state, config, log: Lq, cctv: C, doors: { view() { return { configured: false }; }, list() { return []; }, get() {} } };
  const R = {}, AUD = [];
  const api = { route: (m, p, h) => { R[m + ' ' + p] = { re: new RegExp('^' + p.replace(/:([a-zA-Z]+)/g, '(?<$1>[^/]+)') + '$'), h }; } };
  req('facilities/routes').register(api, deps);
  const srv = http.createServer((rq, res) => {
    const url = new URL(rq.url, 'http://x'), u = url.pathname, json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u === '/dashboards/whoami.json') return json(200, { user: USER, role: ROLE });
    if (u === '/api/itam/assets') return json(200, { total: 2, assets: [{ id: 'a1', name: 'Cam-2', mgmt_ip: '10.10.20.2' }, { id: 'a2', name: 'Cam-5', mgmt_ip: '10.10.20.5' }] });
    const hit = Object.entries(R).find(([k, v]) => k.startsWith(rq.method + ' ') && v.re.test(u));
    if (hit) { let b = ''; rq.on('data', (x) => { b += x; }); rq.on('end', async () => {
      const o = {}, m = hit[1].re.exec(u), ctx = { role: ROLE, user: USER, body: b ? JSON.parse(b) : {}, params: m.groups ? Object.fromEntries(Object.entries(m.groups).map(([k, v]) => [k, decodeURIComponent(v)])) : {}, query: Object.fromEntries(url.searchParams), path: u,
        need(r) { if (RANK[ROLE] < RANK[r]) { o.status = 403; o.error = 'requires ' + r; return false; } return true; }, audit: (a, t, d) => AUD.push({ a, t, d }), ok: (x) => { o.body = x; return x; }, fail(code, msg) { o.status = code; o.error = msg; } };
      try { const rv = await hit[1].h(ctx); if (o.status) return json(o.status, { error: o.error || 'refused' }); json(200, o.body !== undefined ? o.body : rv); } catch (e) { json(e.code || e.status || 500, { error: e.message }); } }); return; }
    if (u.startsWith('/api/')) return json(404, { error: 'not in this test' });
    const f = path.join(DASH, u.replace(/^\/dashboards\//, '')); if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (e, d) => { if (e) { res.writeHead(404); return res.end(); } res.writeHead(200, { 'Content-Type': f.endsWith('.js') ? 'application/javascript' : f.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port + '/dashboards/';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  const wait = (p, fn, a) => p.waitForFunction(fn, a, { timeout: 15000 }).then(() => true, () => false);
  const open = async (role, user, page) => { ROLE = role; USER = user; const p = await browser.newPage({ viewport: { width: 1500, height: 1000 } }); p.on('pageerror', (e) => errs.push(e.message)); await p.goto(base + (page || 'cctv.html') + '?standalone=1'); await wait(p, () => !document.getElementById('main') || !document.getElementById('main').hidden); return p; };
  try {
    let p = await open('admin', 'sec.admin');
    await p.click('[data-tab="conn"]'); ok(await wait(p, () => /No recorder is connected/.test(document.getElementById('conn').innerText)), 'nothing connected: says what to do');
    await p.fill('#r-id', 'nvr-hq'); await p.fill('#r-label', 'NVR HQ'); await p.fill('#r-site', 'Riyadh HQ'); await p.fill('#r-host', '10.10.20.250'); await p.click('#r-save');
    ok(await wait(p, () => /NVR HQ/.test(document.getElementById('conn').innerText) && /not set/.test(document.getElementById('conn').innerText)), 'recorder added');
    await p.click('[data-cred="nvr-hq"]'); await p.fill('#c-u', 'admin'); await p.fill('#c-p', 'x'); await p.click('#dlg-ok');
    ok(await wait(p, () => /read-only operator account/.test(document.getElementById('dlg-e').innerText)), 'admin user refused');
    await p.fill('#c-u', 'viewer-syn'); await p.fill('#c-p', 'Syn-Passw0rd!'); await p.click('#dlg-ok');
    ok(await wait(p, () => /password set/.test(document.getElementById('conn').innerText)), 'login saved, password not shown');
    ok(!fs.readFileSync(secFile, 'utf8').includes('Syn-Passw0rd!'), 'password sealed');
    for (let i = 0; i < 19; i++) { await C.sync('nvr-hq'); T += 5 * 60e3; }
    await p.click('[data-sync="nvr-hq"]'); await wait(p, () => /Cameras online/.test(document.getElementById('kk').innerText) && /2 \/ 5/.test(document.getElementById('kk').innerText));
    const k = await p.evaluate(() => document.getElementById('kk').innerText);
    ok(/2 \/ 5/.test(k) && /Offline\s*3/.test(k) && /Disks not healthy\s*1/.test(k), 'tiles: ' + k.replace(/\s+/g, ' '));
    await p.click('[data-tab="sum"]'); const sm = await p.evaluate(() => document.getElementById('acts').innerText + '|' + document.getElementById('outs').innerText);
    ok(/disk\(s\) not healthy/.test(sm.split('\n')[0]), 'failed disk ranks first');
    ok(/shared cause/.test(sm) && /3 cameras/.test(sm), 'group outage named as one shared cause');
    await p.click('[data-act="f:flap"]'); ok(await wait(p, () => document.querySelectorAll('#cams .cam').length === 1 && /Cam-4/.test(document.getElementById('cams').innerText)), 'flapping tile filters to the camera going on and off');
    ok(await p.evaluate(() => !window.__xss), 'hostile camera name stays text');
    await p.click('[data-tab="recs"]'); ok(await wait(p, () => /DS-SYN-7716/.test(document.getElementById('recs').innerText) && /error/.test(document.getElementById('disks').innerText)), 'recorders and disks');
    await p.click('[data-tab="reg"]'); ok(await wait(p, () => /2 of 5 cameras are in the asset register/.test(document.getElementById('reg').innerText)), 'asset register cross-check');
    await p.close();
    p = await open('viewer', 'vera.syn'); await p.click('[data-tab="conn"]');
    ok(await wait(p, () => /NVR HQ/.test(document.getElementById('conn').innerText)) && !(await p.$('[data-cred]')) && !(await p.$('[data-sync]')) && await p.evaluate(() => document.getElementById('conn-form').hidden), 'viewer: no connection controls'); await p.close();
    p = await open('operator', 'nora.syn', 'facilities.html');
    ok(await wait(p, () => /CCTV cameras offline/.test(document.body.innerText) && /Cameras online/.test(document.body.innerText)), 'Facilities shows the CCTV card'); await p.close();
    ok(['facilities.cctv.put', 'facilities.cctv.credential', 'facilities.cctv.sync'].every((a) => AUD.some((x) => x.a === a)), 'audited');
    const nav = fs.readFileSync(path.join(DASH, 'vendor', 'zyb-nav.js'), 'utf8');
    ok(/"h": "cctv.html"/.test(nav) && / cctv\.html /.test(fs.readFileSync(path.join(DASH, 'install-dashboards.sh'), 'utf8')), 'menu entry and installer');
    ok(/cctv: 'cctv\.html'/.test(fs.readFileSync(path.join(DASH, 'vendor', 'zyb-menu.js'), 'utf8')) && /cctv: 'cctv\.html'/.test(fs.readFileSync(path.join(DASH, 'vendor', 'zyb-early.js'), 'utf8')), 'the portal\'s CCTV / NVR opens this page');
    ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  } finally { await browser.close(); srv.close(); fs.rmSync(dir, { recursive: true, force: true }); }
  console.log((bad ? 'FAILED ' : 'ok ') + (n - bad) + '/' + n);
  process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
