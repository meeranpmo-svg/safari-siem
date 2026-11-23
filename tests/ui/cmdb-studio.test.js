// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for CMDB Studio (dashboards/server/cmdb-studio.html) against the REAL ITAM engine (engine/cmdb-studio.js,
// pyengine/cmdb_rules.py; the model is stubbed) over SYNTHETIC CIs and relationships: the quality ring and KPIs, the radial
// graph (confirmed solid, proposed dashed, ML proposals dotted), recentre by clicking a node and Back, blast radius, the ML
// proposal confirmed and another dismissed with a reason, a sensor proposal confirmed by a different person, single points
// of failure / duplicates / anomalies, the AI analyst recording a proposal that waits for a person, a hostile CI name stays
// text, a viewer reads but cannot decide, the menu has the page.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node cmdb-studio.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const ITAM = path.join(__dirname, '..', '..', 'backend', 'itam'), DASH = path.join(__dirname, '..', '..', 'ui');
const H = require(path.join(ITAM, 'tests', 'helpers'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const ADM = { user: 'syed', role: 'admin' }, OP = { user: 'nora.syn', role: 'operator' }, VIEW = { user: 'vera.syn', role: 'viewer' };
const XSS = '<img src=x onerror=alert(1)>';

(async () => {
  const e = await H.startApp({ noAi: true });
  let turn = 0, id;
  const create = async () => {
    turn++;
    if (turn % 2 === 1) return { model: 'claude-opus-5-5', stop_reason: 'tool_use', content: [{ type: 'tool_use', id: 'u' + turn, name: 'propose_relationship', input: { from: id.db, to: id.esx, type: 'runs_on', reason: 'same subnet as its peers (synthetic)' } }], usage: { input_tokens: 40, output_tokens: 10 } };
    return { model: 'claude-opus-5-5', stop_reason: 'end_turn', content: [{ type: 'text', text: 'ESX-SYN-1 hosts two VMs. I proposed one more link for your decision.' }], usage: { input_tokens: 60, output_tokens: 20 } };
  };
  const sdk = class { constructor() { this.messages = { create }; } };
  require(path.join(ITAM, 'engine/duty')).registerDuty(e.app.srv, e.app, { noTimer: true, python: process.env.PYTHON || 'python3', cmdbSdk: sdk, cmdbKey: () => 'sk-ant-synthetic' });
  const mk = (x) => e.app.assets.create(Object.assign({ status: 'in_use', type: 'server', site: 'HQ' }, x), ADM).asset.id;
  id = {
    esx: mk({ name: 'ESX-SYN-1', mgmt_ip: '10.80.1.2', serial: 'SYNSER1' }),
    a1: mk({ name: 'APP-SYN-1', type: 'vm', mgmt_ip: '10.80.1.11' }), a2: mk({ name: 'APP-SYN-2', type: 'vm', mgmt_ip: '10.80.1.12' }),
    a3: mk({ name: XSS, type: 'vm', mgmt_ip: '10.80.1.13' }), db: mk({ name: 'DB-SYN-1', type: 'vm', mgmt_ip: '10.80.1.14' }),
    sw: mk({ name: 'SW-SYN-CORE', type: 'network', mgmt_ip: '10.80.1.1' }), dup: mk({ name: 'ESX-SYN-1-OLD', serial: 'SYNSER1' }),
    prn: mk({ name: 'PRN-SYN-1', type: 'printer', mgmt_ip: '10.80.1.40' }), lonely: mk({ name: 'SRV-SYN-LONELY', mgmt_ip: '10.81.0.5' }),
  };
  const rel = (from, to, type) => e.app.assets.addRelationship({ from, to, type }, ADM, { source: 'manual', autoConfirm: true });
  rel(id.a1, id.esx, 'runs_on'); rel(id.a2, id.esx, 'runs_on'); rel(id.a1, id.sw, 'connected_to'); rel(id.a2, id.sw, 'connected_to'); rel(id.a3, id.prn, 'runs_on');
  const sensor = e.app.assets.addRelationship({ from: id.lonely, to: id.sw, type: 'connected_to' }, OP, { source: 'sensor', autoConfirm: false });
  e.app.settings.update({ external_ai_allowed: true }, ADM);
  let WHO = ADM;
  const srv = http.createServer((req, res) => {
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
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port + '/';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  const wait = (p, fn, arg) => p.waitForFunction(fn, arg, { timeout: 20000 }).then(() => true, () => false);
  try {
    const p = await browser.newPage({ viewport: { width: 1440, height: 1000 } }); p.on('pageerror', (x) => errs.push(x.message));
    p.on('dialog', (d) => { errs.push('dialog: ' + d.message()); d.dismiss(); });
    await p.goto(base + 'cmdb-studio.html?standalone=1');
    ok(await wait(p, () => /%/.test(document.getElementById('ring').textContent) && /configuration items/.test(document.getElementById('kpis').textContent)), 'the overview: quality ring and KPIs');
    const k = (await p.textContent('#kpis')).replace(/\s+/g, '');
    ok(/9configurationitems/.test(k) && /1waitingforaperson/.test(k) && /criticalitymismatches/.test(k) && /servicegroups/.test(k), 'KPIs: ' + k);
    ok(await wait(p, () => document.querySelectorAll('#actions .act').length >= 2), 'what to do next, ranked');
    ok(/daily snapshot|No snapshot yet/.test(await p.textContent('#health')), 'health over time');
    await p.click('[data-panel-go="explorer"]');
    ok(await wait(p, () => document.querySelectorAll('#graph [data-node]').length >= 3), 'the explorer draws around the most important CI');
    ok(/ESX-SYN-1/.test(await p.textContent('#side')) && /If it fails: 2 CI/.test(await p.textContent('#side')), 'the side panel: the CI and its blast radius');
    ok((await p.$$('#graph path.ed.ml')).length >= 1, 'an ML proposal is drawn dotted on the graph');
    ok((await p.$$('#graph path.ed.prop')).length === 0 && (await p.$$('#graph path.ed:not(.ml)')).length >= 2, 'confirmed edges solid');
    await p.check('#blast'); ok((await p.$$('#graph .nd.hit')).length === 2, 'blast radius highlights what fails with it');
    await p.selectOption('#colorby', 'importance'); ok(await wait(p, () => !!document.querySelector('#graph circle.b')), 'colour by importance');
    ok(/Importance/.test(await p.textContent('#side')), 'the side panel shows importance');
    ok(/same serial number/.test(await p.textContent('#dups')) && /printer/.test(await p.textContent('#anom')) && /ESX-SYN-1/.test(await p.textContent('#spof')), 'duplicates, anomalies, SPOF');
    await p.click('[data-panel-go="importance"]'); ok(/ESX-SYN-1/.test(await p.textContent('#imp')), 'crown jewels ranked'); ok(/ESX-SYN-1/.test(await p.textContent('#mism')) && /no criticality but 2 CI/.test(await p.textContent('#mism')), 'the host the VMs stand on is flagged: no criticality');
    await p.click('[data-panel-go="groups"]'); ok(/CIs/.test(await p.textContent('#groups')), 'service groups');
    await p.click('[data-panel-go="quality"]'); ok(/by type/.test(await p.textContent('#cov-type')) && /HQ/.test(await p.textContent('#cov-site')), 'coverage heat maps');
    await p.click('[data-panel-go="explorer"]');
    ok(!(await p.$('main img')), 'a hostile CI name never becomes markup');
    // recentre and back
    await p.click('#graph [data-node="' + id.sw + '"]');
    ok(await wait(p, () => /SW-SYN-CORE/.test(document.querySelector('#side h3').textContent)), 'clicking a node recentres the graph');
    await p.click('#back'); ok(await wait(p, () => /ESX-SYN-1/.test(document.querySelector('#side h3').textContent)), 'Back returns');
    // confirm an ML proposal, dismiss another with a reason
    await p.click('[data-panel-go="decisions"]');
    const learnedKey = 'runs_on|' + id.db + '|' + id.esx;
    ok(!!(await p.$('[data-pkey="' + learnedKey + '"]')), 'learned: DB-SYN-1 likely runs on ESX-SYN-1');
    const gwKey = await p.evaluate(() => { const q = [...document.querySelectorAll('#props [data-pkey]')].find((x) => /likely gateway|LLDP|learned/.test(x.textContent) && !/runs on/.test(x.textContent)); return q && q.getAttribute('data-pkey'); });
    await p.click('[data-accept="' + learnedKey + '"]');
    ok(await wait(p, (k2) => !document.querySelector('[data-pkey="' + k2 + '"]'), learnedKey), 'confirmed: gone from proposals');
    ok(e.app.store.collection('relationships').all((r) => r.from === id.db && r.to === id.esx && r.status === 'confirmed').length === 1, 'recorded as confirmed');
    if (gwKey) {
      await p.click('[data-dismiss="' + gwKey + '"]'); ok(await wait(p, () => /Say why/.test(document.body.textContent)), 'dismiss without a reason asks for one');
      await p.fill('[data-pkey="' + gwKey + '"] [data-reason]', 'not this switch (synthetic)'); await p.click('[data-dismiss="' + gwKey + '"]');
      ok(await wait(p, (k2) => !document.querySelector('[data-pkey="' + k2 + '"]'), gwKey), 'dismissed with a reason');
    } else ok(false, 'a second proposal to dismiss');
    // a sensor proposal by nora, confirmed by syed
    await p.click('[data-tab="pending"]');
    ok(/proposed by nora\.syn/.test(await p.textContent('#pending')), 'the proposer is shown');
    await p.click('[data-decide="confirm"][data-id="' + sensor.id + '"]');
    ok(await wait(p, () => !document.querySelector('#pending [data-rel]')), 'confirmed by a different person');
    ok(e.app.store.collection('relationships').get(sensor.id).status === 'confirmed', 'sensor proposal confirmed');
    // the AI analyst records a proposal that waits for a person
    await p.click('[data-tab="calib"]'); ok(await wait(p, () => /Rejected/.test(document.getElementById('calib').textContent) && /Learned from peers/.test(document.getElementById('calib').textContent)), 'what the ML learned from people');
    const [dl] = await Promise.all([p.waitForEvent('download', { timeout: 10000 }), p.click('#xls')]); ok(/^cmdb-studio-\d{4}-\d{2}-\d{2}\.xlsx$/.test(dl.suggestedFilename()), 'Excel export');
    await p.click('#snapbtn'); ok(await wait(p, () => /Health snapshot recorded/.test(document.body.textContent)), 'health snapshot');
    await p.click('[data-panel-go="ai"]');
    ok(/Claude claude-opus-5-5/.test(await p.textContent('#ais')), 'AI analyst on');
    e.app.store.collection('relationships').all((r) => r.from === id.db && r.to === id.esx).forEach((r) => e.app.store.collection('relationships').remove(r.id));
    await p.fill('#q', 'What runs on ESX-SYN-1?'); await p.click('#go');
    ok(await wait(p, () => /proposed one more link/.test(document.getElementById('out').textContent)), 'the analyst answers');
    await p.click('[data-panel-go="decisions"]'); await p.click('[data-tab="pending"]');
    ok(await wait(p, () => /AI analyst/.test(document.getElementById('pending').textContent)), 'the AI proposal waits for a person');
    ok(e.app.store.collection('relationships').all((r) => r.source === 'ai' && r.status === 'proposed').length === 1, 'not confirmed by the AI');
    ok(await p.evaluate(() => { const a = (window.ZYB_NAV || []).find((x) => x.id === 'ast'); return !!(a && a.pages.some((x) => x.h === 'cmdb-studio.html')); }), 'the menu has the page');
    WHO = VIEW; await p.reload();
    ok(await wait(p, () => !document.getElementById('main').hidden), 'a viewer opens the page'); await p.click('[data-panel-go="explorer"]');
    ok(await wait(p, () => document.querySelectorAll('#graph [data-node]').length >= 3), 'a viewer reads the CMDB');
    ok(!(await p.isVisible('#snapbtn')), 'a viewer cannot take a snapshot');
    ok(!(await p.$('[data-accept]')) && !(await p.$('[data-decide]')) && await p.isDisabled('#go'), 'a viewer cannot decide or ask');
  } finally { await browser.close(); srv.close(); await e.close(); }
  ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks');
  process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
