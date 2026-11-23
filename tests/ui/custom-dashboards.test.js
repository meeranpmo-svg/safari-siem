// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for Custom Dashboards (dashboards/server/custom-dashboards.html) against the REAL IT Asset Management engine
// (engine/dash-builder.js) over SYNTHETIC records: empty state, the starter dashboard (KPI with result / target / current, gauge,
// grouped table, split, bar), the query builder (condition rows write the query, preview, an error naming the field), adding and
// removing a widget, the AI proposal filling the builder (fake model), a viewer seeing it read-only, phone width, menu entry.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node custom-dashboards.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const ITAM = path.join(__dirname, '..', '..', 'backend', 'itam'), DASH = path.join(__dirname, '..', '..', 'ui');
const H = require(path.join(ITAM, 'tests', 'helpers'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
(async () => {
  const e = await H.startApp({ noAi: true });
  class Fake { constructor() { this.messages = { create: async () => ({ model: 'synthetic-model', stop_reason: 'tool_use', usage: { input_tokens: 5, output_tokens: 5 }, content: [{ type: 'tool_use', id: 't1', name: 'propose_widget', input: { title: 'Linux without EDR', dataset: 'assets', q: 'os~linux edr:missing', viz: 'kpi', why: 'unprotected Linux (synthetic)' } }] }) }; } }
  require(path.join(ITAM, 'engine/duty')).registerDuty(e.app.srv, e.app, { noTimer: true, python: process.env.PYTHON || 'python3', acovLogCoverage: async () => ({ ok: true, assets: [] }), acovAvail: async () => ({ ok: true, hosts: {} }), dashSdk: Fake, dashKey: () => 'sk-ant-synthetic' });
  const ADM = { user: 'syed', role: 'admin' }; e.app.settings.update({ external_ai_allowed: true }, ADM);
  const col = e.app.store.collection('assets'), now = new Date().toISOString();
  const mk = (x, sw) => { const id = e.app.assets.create(Object.assign({ status: 'in_use', type: 'server', site: 'HQ' }, x), ADM).asset.id; col.put(Object.assign({}, col.get(id), { software: sw, sources: [{ source: 'agent', last_seen: now }] })); };
  mk({ name: 'SRV-SYN-1', os: 'Windows Server 2019', mgmt_ip: '10.1.0.1' }, [{ name: 'Kaspersky Endpoint Security for Windows' }]);
  mk({ name: 'SRV-SYN-2', os: 'Red Hat Enterprise Linux 9', mgmt_ip: '10.1.0.2' }, [{ name: 'Notepad++ (synthetic)' }]);
  e.app.store.collection('vulnscan_findings').put({ id: 'v1', status: 'open', name: 'OpenSSH < 9.6 (synthetic)', severity: 'high', host: '10.1.0.2', cves: ['CVE-2024-6387'] });
  let who = { user: 'nora.syn', role: 'operator' };
  const srv = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://x'), json = (code, b) => { res.writeHead(code, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u.pathname === '/dashboards/whoami.json') return json(200, who);
    if (u.pathname.startsWith('/api/itam/')) { const h = Object.assign({}, req.headers, { 'x-sentra-proxy-secret': H.SECRET, 'x-auth-user': who.user, 'x-auth-role': who.role });
      const up = http.request({ host: '127.0.0.1', port: e.port, method: req.method, path: req.url, headers: h }, (r) => { res.writeHead(r.statusCode, r.headers); r.pipe(res); }); req.pipe(up); return; }
    if (u.pathname.startsWith('/api/')) return json(404, { error: 'not in this test' });
    const f = path.join(DASH, u.pathname.replace(/^\/dashboards\//, '/')); if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (err, d) => { if (err) { res.writeHead(404); res.end(); return; } res.writeHead(200, { 'Content-Type': u.pathname.endsWith('.js') ? 'application/javascript' : u.pathname.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port + '/';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  const wait = (p, fn, a) => p.waitForFunction(fn, a, { timeout: 20000 }).then(() => true, () => false);
  try {
    const p = await browser.newPage({ viewport: { width: 1500, height: 1000 } }); p.on('pageerror', (x) => errs.push(x.message));
    await p.goto(base + 'custom-dashboards.html?standalone=1');
    ok(await wait(p, () => !!document.getElementById('starter')), 'empty state offers the starter dashboard');
    await p.click('#starter');
    ok(await wait(p, () => document.querySelectorAll('#board .w').length === 9), 'starter dashboard: 9 widgets');
    ok(await p.evaluate(() => [...document.querySelectorAll('.tab')].some((t) => /Security overview/.test(t.textContent) && t.getAttribute('aria-selected') === 'true')), 'its tab is selected');
    const edr = await p.evaluate(() => [...document.querySelectorAll('.w')].find((w) => /Endpoint protection installed/.test(w.textContent)).textContent);
    ok(/Result/.test(edr) && /Target/.test(edr) && /98%/.test(edr) && /50%/.test(edr), 'KPI: result, target 98 %, current 50 %');
    ok(await p.evaluate(() => !!document.querySelector('.w svg path[stroke-linecap]')), 'gauge drawn');
    ok(await p.evaluate(() => /CVE-2024-6387/.test(document.getElementById('board').textContent)), 'top vulnerabilities table');
    ok(await p.evaluate(() => /withheld/.test(document.getElementById('board').textContent)), 'ML says the trend is withheld with one day of history');
    // query builder
    await p.click('#addw'); ok(await p.isVisible('#builder'), 'builder opens');
    await p.fill('#wtitle', 'Linux servers (synthetic)');
    await p.selectOption('.cond [data-c="f"]', 'os'); await p.selectOption('.cond [data-c="o"]', '~'); await p.fill('.cond [data-c="v"]', 'linux'); await p.dispatchEvent('.cond [data-c="v"]', 'change');
    ok(await p.inputValue('#wq') === 'os~linux', 'condition row writes the query');
    await p.click('#prev'); ok(await wait(p, () => { const b = document.querySelector('#preview .big'); return b && b.textContent === '1'; }), 'preview computes 1 record');
    await p.fill('#wq', 'colour:red'); await p.click('#prev');
    ok(await wait(p, () => /colour/.test(document.getElementById('preview').textContent)), 'an unknown field is refused, naming it');
    await p.fill('#wq', 'os~linux'); await p.click('#save');
    ok(await wait(p, () => document.querySelectorAll('#board .w').length === 10), 'widget added');
    const last = await p.evaluate(() => { const w = [...document.querySelectorAll('#board .w')].pop(); return w.getAttribute('data-w'); });
    await p.click('[data-del="' + last + '"]'); ok(await wait(p, () => document.querySelectorAll('#board .w').length === 9), 'widget removed');
    // AI proposes
    await p.click('#addw'); await p.fill('#aireq', 'Linux servers with no endpoint protection'); await p.click('#aigo');
    ok(await wait(p, () => document.getElementById('wq').value === 'os~linux edr:missing'), 'AI proposal fills the builder');
    ok(/check it, preview, then add/.test(await p.textContent('#aiwhy')), 'a person adds it');
    ok(await wait(p, () => /Linux without EDR/.test(document.getElementById('preview').textContent)), 'and it is previewed, not saved');
    ok(await p.evaluate(() => document.querySelectorAll('#board .w').length === 9), 'nothing saved by the AI');
    ok(await p.evaluate(() => (window.ZYB_NAV || []).some((a) => (a.pages || []).some((x) => x.h === 'custom-dashboards.html'))), 'the menu has the page');
    // viewer: read-only
    who = { user: 'vera.syn', role: 'viewer' };
    const v = await browser.newPage({ viewport: { width: 400, height: 900 } }); v.on('pageerror', (x) => errs.push(x.message));
    await v.goto(base + 'custom-dashboards.html?standalone=1');
    ok(await wait(v, () => document.querySelectorAll('#board .w').length === 9), 'viewer sees the shared dashboard');
    ok(await v.evaluate(() => document.getElementById('addw').hidden && document.getElementById('newb').hidden && !document.querySelector('[data-edit]')), 'viewer: no edit controls');
    await v.waitForTimeout(400);
    ok(await v.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1), 'phone width: no sideways scroll');
  } finally { await browser.close(); srv.close(); await e.close(); }
  ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks'); process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
