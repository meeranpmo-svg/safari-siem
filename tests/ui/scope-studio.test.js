// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for Scope Studio (dashboards/server/scope-studio.html) against the REAL ITAM engine (Asset Discovery,
// engine/discovery-advisor.js, pyengine/scope_rules.py; the model is stubbed) over SYNTHETIC scopes, runs, devices and assets:
// the coverage ring and KPIs, the coverage map (covered / gap / devices only, gaps-only filter, a gap opens its proposal),
// proposals with the methods and their learned confidence, creating a scope from a proposal, dismissing one with a reason,
// scope health with the trend line, the anomaly and the recommendations, the AI advisor drafting a proposal that waits for a
// person, a hostile asset site stays text, a viewer is refused, the menu has the page.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node scope-studio.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const ITAM = path.join(__dirname, '..', '..', 'backend', 'itam'), DASH = path.join(__dirname, '..', '..', 'ui');
const H = require(path.join(ITAM, 'tests', 'helpers'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const ADM = { user: 'syed', role: 'admin' }, VIEW = { user: 'vera.syn', role: 'viewer' };
const XSS = '<img src=x onerror=alert(1)>';

(async () => {
  const e = await H.startApp({ noAi: true });
  let turn = 0;
  const create = async () => {
    turn++;
    if (turn % 2 === 1) return { model: 'claude-opus-5-5', stop_reason: 'tool_use', content: [{ type: 'tool_use', id: 'u' + turn, name: 'draft_scope_proposal', input: { name: 'Printers floor 3 (synthetic)', site: SITE, targets: ['10.60.3.0/24'], methods: ['sweep', 'snmp'], reason: 'printers seen by AD, no scope' } }], usage: { input_tokens: 40, output_tokens: 10 } };
    return { model: 'claude-opus-5-5', stop_reason: 'end_turn', content: [{ type: 'text', text: 'Two subnets are not scanned. I drafted one proposal for your decision.' }], usage: { input_tokens: 60, output_tokens: 20 } };
  };
  const sdk = class { constructor() { this.messages = { create }; } };
  require(path.join(ITAM, 'engine/duty')).registerDuty(e.app.srv, e.app, { noTimer: true, python: process.env.PYTHON || 'python3', advisorSdk: sdk, advisorKey: () => 'sk-ant-synthetic' });
  const D = e.app.discovery, SITE = D.sites()[0];
  const core = D.createScope({ name: 'HQ servers (synthetic)', site: SITE, targets: ['10.20.1.0/24'], methods: { sweep: { enabled: true }, arp: { enabled: true } }, schedule: { type: 'manual' } }, ADM);
  const runs = e.app.store.collection('disc_runs'), NOW = Date.now();
  [40, 41, 39, 40, 42, 40, 8].forEach((k, i) => { const st = NOW - (8 - i) * 86400000; runs.put({ id: 'dr_' + i, scope_id: core.id, scope_name: core.name, status: 'finished', started_at: new Date(st).toISOString(), finished_at: new Date(st + 300000).toISOString(), devices_seen: k, devices_new: 1, methods_run: ['sweep', 'arp'], progress: { hosts_total: 254, alive: k } }); });
  for (let i = 1; i <= 6; i++) e.app.store.collection('disc_devices').put({ id: 'dd_' + i, ip: '10.20.1.' + (10 + i), type: 'server', open_ports: [22, 1433], methods: { sweep: {} }, scope_id: core.id, site: SITE, status: 'new' });
  for (let i = 1; i <= 5; i++) e.app.assets.create({ name: 'SW-SYN-' + i, type: 'network', status: 'in_use', mgmt_ip: '10.30.5.' + i, site: SITE }, ADM);
  e.app.assets.create({ name: 'SRV-SYN-9', type: 'server', status: 'in_use', mgmt_ip: '10.40.7.9', site: SITE }, ADM);
  e.app.assets.create({ name: XSS, type: 'server', status: 'in_use', mgmt_ip: '10.40.7.10', site: SITE }, ADM);
  e.app.assets.create({ name: 'SRV-SYN-1', type: 'server', status: 'in_use', mgmt_ip: '10.20.1.11', site: SITE }, ADM);
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
    let promptAnswer = null; p.on('dialog', (d) => { if (d.type() === 'prompt' && promptAnswer) d.accept(promptAnswer); else { errs.push('dialog: ' + d.message()); d.dismiss(); } });
    await p.goto(base + 'scope-studio.html?standalone=1');
    ok(await wait(p, () => document.querySelectorAll('#map .cell').length === 3), 'coverage map: three known subnets');
    ok(/13%/.test(await p.textContent('#ring')), 'the ring: 1 of 8 assets with an IP covered');
    ok(/1 \/ 8/.test(await p.textContent('#kpis')) && /2subnetsmissed/.test((await p.textContent('#kpis')).replace(/\s+/g, '')), 'KPIs');
    ok((await p.$$('#map .cell.gap')).length === 2 && (await p.$$('#map .cell.ok')).length === 1, 'covered vs gaps');
    await p.check('#onlygap'); ok((await p.$$('#map .cell')).length === 2, 'gaps-only filter'); await p.uncheck('#onlygap');
    ok((await p.$$('#props .prop')).length === 2, 'two learned proposals');
    const pr = await p.textContent('[data-prop="new:10.30.5.0/24"]');
    ok(/5 asset\(s\) in the register/.test(pr) && /SNMP/.test(pr) && /network device/.test(pr), 'the proposal says why and which methods');
    ok(!(await p.$('#props img')) && !(await p.$('#map img')), 'a hostile asset name never becomes markup');
    await p.click('#map [data-sub="10.30.5.0/24"]'); ok(await wait(p, () => document.querySelector('#map .cell.sel')), 'a gap is selected and its proposal shown');
    // scope health
    const sc = await p.textContent('[data-scope="' + core.id + '"]');
    ok(/usually 40/.test(sc) && /ARP cache ran 7 times and found nothing/.test(sc) && /Enable Unix \/ SSH/.test(sc) && /Enable Database listeners/.test(sc), 'health: anomaly and recommendations');
    ok(!!(await p.$('[data-scope="' + core.id + '"] svg.spark polyline')), 'the trend line');
    // create a scope from a proposal
    await p.fill('[data-prop="new:10.30.5.0/24"] [data-pname]', 'HQ switches (synthetic)');
    await p.click('[data-accept="new:10.30.5.0/24"]');
    ok(await wait(p, () => !document.querySelector('[data-prop="new:10.30.5.0/24"]') && document.querySelectorAll('#map .cell.ok').length === 2), 'accepted: the subnet is now covered');
    ok(D.listScopes(false).some((s) => s.name === 'HQ switches (synthetic)' && s.schedule.type === 'manual' && !s.gate.open), 'the scope exists, manual, gate closed');
    // dismiss with a reason
    promptAnswer = 'lab network, not ours (synthetic)';
    await p.click('[data-dismiss="new:10.40.7.0/24"]');
    ok(await wait(p, () => !document.querySelector('[data-prop="new:10.40.7.0/24"]')), 'dismissed with a reason');
    // the AI advisor drafts a proposal that waits for a person
    ok(/Claude claude-opus-5-5/.test(await p.textContent('#ais')), 'AI advisor on');
    await p.fill('#q', 'Which subnets are we missing?'); await p.click('#go');
    ok(await wait(p, () => /drafted one proposal/.test(document.getElementById('out').textContent)), 'the advisor answers');
    ok(await wait(p, () => !!document.querySelector('.prop.ai')), 'the AI draft appears in Proposals');
    ok(/AI draft/.test(await p.textContent('.prop.ai')) && /10\.60\.3\.0\/24/.test(await p.textContent('.prop.ai')), 'marked as an AI draft');
    ok(!D.listScopes(false).some((s) => /Printers floor 3/.test(s.name)), 'the draft is not a scope until a person accepts it');
    ok(await p.evaluate(() => { const a = (window.ZYB_NAV || []).find((x) => x.id === 'ast'); return !!(a && a.pages.some((x) => x.h === 'scope-studio.html' && x.g === 'Discovery')); }), 'the menu has the page');
    WHO = VIEW; await p.reload();
    ok(await wait(p, () => /for operators and System Admins/.test(document.getElementById('err').textContent)), 'a viewer is refused');
  } finally { await browser.close(); srv.close(); await e.close(); }
  ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks');
  process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
