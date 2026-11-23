// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for Asset Studio (dashboards/server/asset-studio.html) against the REAL ITAM engine (engine/asset-studio.js,
// pyengine/asset_studio_rules.py; the model is stubbed) over SYNTHETIC assets: the health ring and KPIs, a KPI and a type tile
// filter the register, search, sort, the asset detail drawer with every health point explained, applying a learned suggestion
// and dismissing another with a reason, the ghost anomaly, the AI analyst recording a suggestion that waits for a person, a
// hostile asset name stays text, a viewer reads but cannot change anything, the menu has the page.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node asset-studio.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const ITAM = path.join(__dirname, '..', '..', 'backend', 'itam'), DASH = path.join(__dirname, '..', '..', 'ui');
const H = require(path.join(ITAM, 'tests', 'helpers'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const ADM = { user: 'syed', role: 'admin' }, VIEW = { user: 'vera.syn', role: 'viewer' };
const XSS = '<img src=x onerror=alert(1)>';

(async () => {
  const e = await H.startApp({ noAi: true });
  let turn = 0; const id = {};
  const create = async () => {
    turn++;
    if (turn % 2 === 1) return { model: 'claude-opus-5-5', stop_reason: 'tool_use', content: [{ type: 'tool_use', id: 'u' + turn, name: 'propose_fix', input: { id: id.x, field: 'os', value: 'Windows Server 2022', reason: 'synthetic evidence' } }], usage: { input_tokens: 40, output_tokens: 10 } };
    return { model: 'claude-opus-5-5', stop_reason: 'end_turn', content: [{ type: 'text', text: 'One server is stale. I recorded one suggestion for your decision.' }], usage: { input_tokens: 60, output_tokens: 20 } };
  };
  const sdk = class { constructor() { this.messages = { create }; } };
  require(path.join(ITAM, 'engine/duty')).registerDuty(e.app.srv, e.app, { noTimer: true, python: process.env.PYTHON || 'python3', assetSdk: sdk, assetKey: () => 'sk-ant-synthetic' });
  const C = e.app.store.collection('assets'), day = (d) => new Date(Date.now() - d * 86400000).toISOString();
  const mk = (k, x, seen) => { id[k] = e.app.assets.create(Object.assign({ status: 'in_use', type: 'server', site: 'HQ' }, x), ADM).asset.id; if (seen != null) C.patch(id[k], (a) => { a.last_seen = day(seen); }); };
  for (let i = 1; i <= 5; i++) mk('e' + i, { name: 'ESX-SYN-' + i, mgmt_ip: '10.90.1.' + i, vendor: 'Dell', model: 'R750', os: 'ESXi 8', owner: 'infra', serial: 'SYN' + i }, 1);
  mk('bare', { name: 'ESX-SYN-9', mgmt_ip: '10.90.1.9', site: '' }, 45);
  mk('x', { name: XSS, type: 'workstation', site: 'Branch' });
  mk('ghost', { name: 'SRV-SYN-GONE', mgmt_ip: '10.91.0.5' });
  e.app.assets.transition(id.ghost, 'retire', ADM, 'synthetic'); C.patch(id.ghost, (a) => { a.last_seen = day(2); });
  e.app.settings.update({ external_ai_allowed: true }, ADM);
  let WHO = ADM, HOLD = null, HELD = 0;   // HOLD: a promise the asset-detail request waits on (a slow refresh, on purpose)
  const srv = http.createServer(async (req, res) => {
    const u = new URL(req.url, 'http://x'), json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u.pathname === '/dashboards/whoami.json') return json(200, WHO);
    if (u.pathname.startsWith('/api/itam/')) {
      if (HOLD && /\/asset-studio\/asset\//.test(u.pathname)) { HELD++; await HOLD; }
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
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  const wait = (p, fn, arg) => p.waitForFunction(fn, arg, { timeout: 20000 }).then(() => true, () => false);
  const rows = (p) => p.$$eval('#rows tr[data-asset]', (x) => x.length);
  try {
    const p = await browser.newPage({ viewport: { width: 1440, height: 1000 } }); p.on('pageerror', (x) => errs.push(x.message));
    p.on('dialog', (d) => { errs.push('dialog: ' + d.message()); d.dismiss(); });
    await p.goto(base + 'asset-studio.html?standalone=1');
    ok(await wait(p, () => document.querySelectorAll('#rows tr[data-asset]').length === 7), 'the register lists the 7 active assets');
    const k = (await p.textContent('#kpis')).replace(/\s+/g, '');
    ok(/7activeassets/.test(k) && /1notseen30days/.test(k) && /1retired,stillseen/.test(k), 'KPIs: ' + k);
    ok(/average health/.test(await p.textContent('#ring')), 'the health ring');
    ok((await p.$$('#tiles .tile')).length === 2, 'one tile per type');
    ok((await p.getAttribute('#rows tr[data-asset]:first-child', 'data-asset')) === id.x || (await p.getAttribute('#rows tr[data-asset]:first-child', 'data-asset')) === id.bare, 'worst health first');
    ok(!(await p.$('main img')), 'a hostile asset name never becomes markup');
    await p.click('[data-issue="stale"]'); ok((await rows(p)) === 1, 'a KPI filters the register'); await p.click('[data-issue="stale"]');
    await p.click('[data-type="workstation"]'); ok((await rows(p)) === 1, 'a type tile filters'); await p.click('#clear'); ok((await rows(p)) === 7, 'clear filters');
    await p.fill('#find', 'ESX-SYN-3'); ok((await rows(p)) === 1, 'search'); await p.fill('#find', '');
    await p.click('th[data-sort="name"]'); ok(/▲/.test(await p.textContent('th[data-sort="name"]')), 'sort by name');
    // detail drawer
    await p.click('#rows tr[data-asset="' + id.bare + '"]');
    ok(await wait(p, () => document.getElementById('drawer').classList.contains('open') && /Why \d+ \/ 100/.test(document.getElementById('drawer').textContent)), 'the drawer opens');
    const d = await p.textContent('#drawer');
    ok(/no source has seen it for 45 days/.test(d) && /missing/.test(d), 'every health point explained in the drawer');
    // apply a learned suggestion from the drawer, dismiss another from the queue
    const osKey = 'os|' + id.bare + '|ESXi 8';
    await p.click('#drawer [data-apply="' + osKey + '"]');
    ok(await wait(p, (k2) => !document.querySelector('[data-skey="' + k2 + '"]'), osKey), 'applied: gone from the suggestions');
    ok(C.get(id.bare).os === 'ESXi 8', 'the asset was edited');
    await p.keyboard.press('Escape');
    const vKey = 'vendor|' + id.bare + '|Dell';
    await p.click('#sl [data-dismiss="' + vKey + '"]'); ok(await wait(p, () => /Say why/.test(document.body.textContent)), 'dismiss asks for a reason');
    await p.fill('#sl [data-skey="' + vKey + '"] [data-reason]', 'it is an HPE box (synthetic)'); await p.click('#sl [data-dismiss="' + vKey + '"]');
    ok(await wait(p, (k2) => !document.querySelector('[data-skey="' + k2 + '"]'), vKey), 'dismissed');
    ok(/retired, still seen/.test(await p.textContent('#al')), 'the ghost anomaly');
    // AI
    ok(/Claude claude-opus-5-5/.test(await p.textContent('#ais')), 'AI analyst on');
    await p.fill('#q', 'What is stale?'); await p.click('#go');
    ok(await wait(p, () => /recorded one suggestion/.test(document.getElementById('out').textContent)), 'the analyst answers');
    ok(await wait(p, () => !!document.querySelector('#sl .q.ai')), 'the AI suggestion waits for a person');
    ok(!C.get(id.x).os, 'the AI changed nothing');
    ok(await p.evaluate(() => { const a = (window.ZYB_NAV || []).find((x) => x.id === 'ast'); return !!(a && a.pages[0].h === 'asset-studio.html'); }), 'the menu has the page first in IT Assets');
    // information classification
    await p.reload(); await wait(p, () => document.querySelectorAll('#rows tr[data-asset]').length === 7);
    ok(/0% classified/.test(await p.textContent('#clsc')) && /7\s*not classified/.test(await p.textContent('#kpis')), 'nothing classified yet: coverage and the KPI');
    await p.fill('#find', 'ESX-SYN-'); ok(await wait(p, () => /Classify the 6 asset/.test(document.getElementById('bulk').textContent)), 'bulk classify follows the register filter');
    await p.selectOption('#bulkv', 'secret'); await p.click('#bulkgo');
    ok(await wait(p, () => /6 asset\(s\) classified/.test(document.body.textContent)), 'bulk classified');
    ok(C.get(id.e1).classification === 'secret' && C.get(id.e1).locked.classification === true, 'stored on the asset and locked against discovery');
    await p.fill('#find', ''); C.patch(id.e5, (a) => { a.classification = null; }); await p.click('#refresh');
    ok(await wait(p, (i) => !!document.querySelector('[data-clsapply="' + i + '"]'), id.e5), 'a suggestion learned from 5 classified peers');
    ok(/5 of 5 classified server assets are Secret/.test(await p.textContent('#clssugg')), 'the reason is the counts');
    await p.click('[data-clsapply="' + id.e5 + '"]'); ok(await wait(p, () => /Classified - the change was audited/.test(document.body.textContent)), 'suggestion applied');
    await p.click('#rows tr[data-asset="' + id.x + '"]'); await wait(p, () => !!document.getElementById('dcls'));
    // picks made while a refresh is still loading the drawer survive its redraw (they were lost: Save then said "Choose a classification")
    let release; HOLD = new Promise((r) => { release = r; }); HELD = 0;
    await p.evaluate(() => document.getElementById('refresh').click());   /* the drawer covers the button; a background refresh does the same */
    for (let i = 0; i < 100 && !HELD; i++) await new Promise((r) => setTimeout(r, 50));
    ok(HELD > 0, 'the refresh reloads the open drawer');
    await p.selectOption('#dcls', 'secret'); await p.selectOption('#dcia-c', 'low'); await p.selectOption('#dcia-a', 'high');
    const redrawn = p.waitForResponse((r) => /\/asset-studio\/asset\//.test(r.url())); HOLD = null; release(); await redrawn; await p.waitForTimeout(300);
    ok(JSON.stringify(await p.evaluate(() => ['dcls', 'dcia-c', 'dcia-i', 'dcia-a'].map((k) => document.getElementById(k).value))) === JSON.stringify(['secret', 'low', '', 'high']), 'picks made while the drawer was reloading are kept when it is redrawn');
    await p.click('#dclsgo');
    ok(await wait(p, () => /Secret but confidentiality rated low/.test(document.getElementById('clsinc').textContent)), 'drawer edit + inconsistency flagged');
    ok(JSON.stringify(C.get(id.x).cia) === JSON.stringify({ c: 'low', i: null, a: 'high' }), 'CIA stored');
    await p.keyboard.press('Escape');
    await p.click('#clsbar [data-cls="secret"]'); ok(await wait(p, () => document.querySelectorAll('#rows tr[data-asset]').length === 7), 'the bar filters the register by level');
    ok(/Secret/.test(await p.textContent('#rows')), 'the register shows the level');
    ok(e.app.store.auditTail(200).filter((x) => x.action === 'assets.studio.classify').length === 8, 'every classification audited');
    WHO = VIEW; await p.reload();
    ok(await wait(p, () => document.querySelectorAll('#rows tr[data-asset]').length === 7), 'a viewer reads the register');
    ok(!(await p.$('[data-apply]')) && await p.isDisabled('#go'), 'a viewer cannot apply or ask');
    ok(!(await p.$('#bulkgo')) && !(await p.$('[data-clsapply]')), 'a viewer cannot classify');
  } finally { await browser.close(); srv.close(); await e.close(); }
  ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks');
  process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
