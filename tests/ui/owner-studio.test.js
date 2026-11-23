// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for Accountability Studio (dashboards/server/owner-studio.html) against the REAL ITAM engine (engine/owner-studio.js,
// Asset Ownership, pyengine/owner_studio_rules.py; Reconciliation stubbed; the model stubbed) over SYNTHETIC assets: the three
// coverage rings, suggestions by kind with their evidence, applying one (written to Asset Ownership), dismissing with a reason,
// owner load, assets still without an owner, differences with the learned recommendation, a cluster and a stale source, Fix /
// Accept for an admin only, the AI analyst's suggestion applied by a person, a hostile name stays text, a viewer is refused.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node owner-studio.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const ITAM = path.join(__dirname, '..', '..', 'backend', 'itam'), DASH = path.join(__dirname, '..', '..', 'ui');
const H = require(path.join(ITAM, 'tests', 'helpers'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const ADM = { user: 'syed', role: 'admin' }, OP = { user: 'nora.syn', role: 'operator' }, VIEW = { user: 'vera.syn', role: 'viewer' };
const XSS = '<img src=x onerror=alert(1)>';

(async () => {
  const e = await H.startApp({ noAi: true });
  const id = {}; let turn = 0;
  const create = async () => {
    turn++;
    if (turn % 2 === 1) return { model: 'claude-opus-5-5', stop_reason: 'tool_use', content: [{ type: 'tool_use', id: 'u' + turn, name: 'propose_owner', input: { id: id.x, field: 'business_owner', value: 'Head of Claims', reason: 'same department as the claims servers (synthetic)' } }], usage: { input_tokens: 40, output_tokens: 10 } };
    return { model: 'claude-opus-5-5', stop_reason: 'end_turn', content: [{ type: 'text', text: 'Two assets have no owner. I suggested one for your decision.' }], usage: { input_tokens: 60, output_tokens: 20 } };
  };
  const sdk = class { constructor() { this.messages = { create }; } };
  const issues = [];
  for (let i = 1; i <= 6; i++) issues.push({ id: 'iss_n' + i, sig: 's' + i, kind: 'name', sev: 'warn', asset_id: 'x', field: 'name', have: 'SRV' + i, found: 'srv' + i + '.corp.syn', source: 'vcenter', fix: 'apply' });
  const calls = [];
  e.app.addons = e.app.addons || {};
  e.app.addons.reconcile = { view: () => ({ report: { issues: issues.filter((x) => !x.gone) }, freshness: [{ source: 'Nutanix', age_h: 700 }] }), compare: async () => ({ issues }),
    fix: async (iid) => { calls.push(iid); const x = issues.find((y) => y.id === iid); if (x) x.gone = true; return { fixed: iid, kind: 'name' }; }, accept: async (b) => { calls.push(b.id); const x = issues.find((y) => y.id === b.id); if (x) x.gone = true; } };
  require(path.join(ITAM, 'engine/duty')).registerDuty(e.app.srv, e.app, { noTimer: true, python: process.env.PYTHON || 'python3', ownerSdk: sdk, ownerKey: () => 'sk-ant-synthetic' });
  const mk = (x) => e.app.assets.create(Object.assign({ status: 'in_use', type: 'server', site: 'HQ', department: 'Claims' }, x), ADM).asset.id;
  for (let i = 1; i <= 4; i++) id['c' + i] = mk({ name: 'CLM-SYN-' + i, mgmt_ip: '10.70.2.' + i });
  id.c5 = mk({ name: 'CLM-SYN-5', mgmt_ip: '10.70.2.5' });
  id.x = mk({ name: XSS, mgmt_ip: '10.70.7.7' });
  const O = e.app.addons.ownership || require(path.join(ITAM, 'engine/ownership')).createOwnership(e.app); e.app.addons.ownership = O;
  O.assign({ ids: [id.c1, id.c2, id.c3, id.c4], it_owner: 'Claims IT team', business_owner: 'Head of Claims', business_service: 'Claims (synthetic)', reason: 'synthetic' }, ADM);
  for (let i = 0; i < 4; i++) e.app.store.collection('reconcile_accepted').put({ id: 'acc' + i, sig: 'z' + i, kind: 'name', reason: 'FQDN (synthetic)', by: 'syed' });
  e.app.settings.update({ external_ai_allowed: true }, ADM);
  let WHO = OP;
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
    await p.goto(base + 'owner-studio.html?standalone=1');
    ok(await wait(p, () => document.querySelectorAll('#rings .ring').length === 3), 'three coverage rings');
    ok(/67%/.test(await p.textContent('#rings')), 'IT owner coverage: 4 of 6');
    ok(await wait(p, () => document.querySelectorAll('#sugg .q').length >= 3), 'suggestions');
    const k5 = 'it_owner|' + id.c5 + '|Claims IT team';
    ok(/4 of 4 assets named CLM-\* in 10\.70\.2\.0\/24/.test(await p.textContent('[data-skey="' + k5 + '"]')), 'the evidence is shown');
    ok(!(await p.$('main img')), 'a hostile asset name never becomes markup');
    await p.click('[data-sk="peers"]'); ok(await p.$$eval('#sugg .q', (q) => q.length > 0 && q.every((x) => /from peers/.test(x.textContent))), 'filter by kind'); await p.click('[data-sk=""]');
    await p.click('[data-apply="' + k5 + '"]');
    ok(await wait(p, (k) => !document.querySelector('[data-skey="' + k + '"]'), k5), 'applied');
    ok(O.view({}).items.find((x) => x.id === id.c5).it_owner === 'Claims IT team', 'written to Asset Ownership');
    const kb = 'business_service|' + id.c5 + '|Claims (synthetic)';
    await p.click('[data-dismiss="' + kb + '"]'); ok(await wait(p, () => /Say why/.test(document.body.textContent)), 'dismiss asks for a reason');
    await p.fill('[data-skey="' + kb + '"] [data-reason]', 'it is the claims test box (synthetic)'); await p.click('[data-dismiss="' + kb + '"]');
    ok(await wait(p, (k) => !document.querySelector('[data-skey="' + k + '"]'), kb), 'dismissed');
    ok(/Claims IT team/.test(await p.textContent('#load')), 'owner load');
    ok(/1 asset\(s\)/.test(await p.textContent('#miss')), 'one asset still without an IT owner');
    ok(/accept/.test(await p.textContent('#issues')) && /people accepted 4 of 4 "name" differences/.test(await p.textContent('#issues')), 'the learned recommendation');
    ok(/6 × name from vcenter/.test(await p.textContent('#clusters')) && /Nutanix/.test(await p.textContent('#stale')), 'cluster and stale source');
    ok(!(await p.$('[data-fix]')) && /for administrators/.test(await p.textContent('#radm')), 'an operator cannot fix or accept');
    // AI: suggestion applied by a person
    ok(/Claude claude-opus-5-5/.test(await p.textContent('#ais')), 'AI analyst on');
    await p.fill('#q', 'Who owns what?'); await p.click('#go');
    ok(await wait(p, () => /suggested one for your decision/.test(document.getElementById('out').textContent)), 'the analyst answers');
    ok(await wait(p, () => !!document.querySelector('#sugg .q.ai')), 'the AI suggestion is listed');
    ok(!O.view({}).items.find((x) => x.id === id.x).business_owner, 'not assigned by the AI');
    await p.click('#sugg .q.ai [data-apply]');
    ok(await wait(p, () => !document.querySelector('#sugg .q.ai')) && O.view({}).items.find((x) => x.id === id.x).business_owner === 'Head of Claims', 'a person applies it');
    // admin: fix and accept
    WHO = ADM; await p.reload();
    ok(await wait(p, () => !!document.querySelector('[data-fix="iss_n1"]')), 'an admin can fix');
    await p.click('[data-fix="iss_n1"]'); ok(await wait(p, () => !document.querySelector('[data-issue="iss_n1"]')), 'fixed');
    await p.fill('[data-issue="iss_n2"] [data-areason]', 'vCenter uses the FQDN (synthetic)'); await p.click('[data-accept="iss_n2"]');
    ok(await wait(p, () => !document.querySelector('[data-issue="iss_n2"]')), 'accepted');
    ok(calls.join() === 'iss_n1,iss_n2', 'delegated to Reconciliation');
    ok(await p.evaluate(() => { const a = (window.ZYB_NAV || []).find((x) => x.id === 'ast'); return !!(a && a.pages.some((x) => x.h === 'owner-studio.html')); }), 'the menu has the page');
    WHO = VIEW; await p.reload();
    ok(await wait(p, () => /for operators and administrators/.test(document.getElementById('err').textContent)), 'a viewer is refused');
  } finally { await browser.close(); srv.close(); await e.close(); }
  ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks');
  process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
