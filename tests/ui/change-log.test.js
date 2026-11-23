// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// change-log.html against the REAL SIEM change log (sentra-siem engine/netops/changecorr.js via routes.js; polls and the alert store
// stubbed with SYNTHETIC data): carried-out plans from two desks, KPIs that filter, a change opens its timeline of SOC alerts after
// it, the window switch reaches a later alert, an operator records a change (refused with the field named, then recorded and
// correlated), a hostile change title stays text, a viewer sees counts but no alert text and no Record button, and the menu entry,
// installer and portal redirect.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node change-log.test.js
const http = require('http'), fs = require('fs'), os = require('os'), path = require('path');
const DASH = path.resolve(__dirname, '../../ui');
const SIEM = process.env.SENTRA_SIEM || path.resolve(__dirname, '../..', 'backend', 'siem');
const routes = require(path.join(SIEM, 'engine/netops/routes'));
const { createState } = require(path.join(SIEM, 'engine/soc/state'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const XSS = '<img src=x onerror="window.__xss=1">';
const MIN = 60000, H = 3600000;

(async () => {
  const NOW = Date.now();
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cl-page-')), secrets = path.join(dir, 'secrets.json'); fs.writeFileSync(secrets, '{}', { mode: 0o600 });
  const state = await createState({ dir: path.join(dir, 'state') });
  const config = { netops: { enabled: false } };
  Object.defineProperty(config, 'secrets', { value: {}, enumerable: false, writable: true }); Object.defineProperty(config, '_paths', { value: { secrets }, enumerable: false });
  const snaps = { 'sw-a': { at: NOW, ok: false, sources: ['ping'], reach: { sent: 3, received: 0 } }, 'core-syn': { at: NOW, ok: true, sources: ['ping'], reach: { sent: 3, received: 3 } } };
  const poller = { snapshot: (id) => snaps[id] || null, snapshots: () => snaps, stats: () => ({}), forget() {}, start() {} };
  const AL = []; const alerts = { raise() {}, all: (fn) => AL.filter(fn) };
  const N = routes.createNetops({ state, config, log: { info() {}, warn() {}, error() {} }, poller, alerts });
  N.inventory.put({ id: 'core-syn', name: 'CORE-SYN', vendor: 'cisco-ios', ip: '10.0.0.2', site: 'Riyadh HQ', role: 'core' }, 'test');
  N.inventory.put({ id: 'sw-a', name: 'SW-A-SYN', vendor: 'cisco-ios', ip: '10.0.5.2', site: 'Riyadh HQ', role: 'access' }, 'test');
  const plan = (col, o) => state.collection(col).put(Object.assign({ risk: 'medium', proposed_by: 'nora.syn', proposed_at: NOW - 10 * H, history: [] }, o));
  plan('netops_changes', { id: 'NCHG-000001', device: 'core-syn', title: 'Raise OSPF cost ' + XSS, status: 'validated', decided_by: 'adam.syn', applied_by: 'nora.syn', applied_at: NOW - 3 * H, risk: 'high', rollback: ['ip ospf cost 10'] });
  plan('netops_changes', { id: 'NCHG-000002', device: 'sw-a', title: 'Shut unused ports', status: 'execution-failed', decided_by: 'adam.syn', run: { started: NOW - 2 * H, finished: NOW - 2 * H + 5 * MIN } });
  plan('sysadmin_changes', { id: 'SCHG-000001', device: 'app-syn-01', title: 'Patch IIS', status: 'applied', applied_by: 'omar.syn', applied_at: NOW - 40 * H });
  const A = (id, host, t, sev) => AL.push({ id, rule_name: 'Synthetic rule ' + id, severity: sev, status: 'new', host, ts_first: t, ts_last: t, created: t, summary: 'synthetic alert on ' + host });
  A('ALR-1', 'CORE-SYN.as.local', NOW - 3 * H + 30 * MIN, 3); A('ALR-5', 'SW-A-SYN', NOW - 2 * H + 10 * MIN, 2); A('ALR-6', 'app-syn-01', NOW - 10 * H, 2);
  const R = []; routes.register({ route: (m, p, h) => { R.push({ m, re: new RegExp('^' + p.replace(/:[a-z]+/g, '([^/]+)') + '$'), h }); } }, { state, config, log: { error() {}, info() {} }, netops: N, noTimers: true });
  const RANK = { viewer: 0, analyst: 1, operator: 2, admin: 3 };
  async function dispatch(method, pathname, query, body, role, user) {
    const r = R.find((x) => x.m === method && x.re.test(pathname)); if (!r) return { c: 404, b: { error: 'not found' } };
    const out = {}, ctx = { role, user, body, params: {}, query, path: pathname, need(x) { if (RANK[role] < RANK[x]) { out.c = 403; out.e = 'requires ' + x; return false; } return true; }, audit() {}, fail(c, e) { out.c = c; out.e = e; } };
    const rv = await r.h(ctx); return out.c ? { c: out.c, b: { error: out.e } } : { c: 200, b: rv };
  }
  let WHO = { user: 'nora.syn', role: 'operator' };
  const srv = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://x'), json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u.pathname === '/dashboards/whoami.json') return json(200, WHO);
    if (u.pathname.startsWith('/api/soc/netops/')) { let b = ''; req.on('data', (c) => { b += c; }); req.on('end', async () => { const r = await dispatch(req.method, u.pathname, Object.fromEntries(u.searchParams), b ? JSON.parse(b) : {}, WHO.role, WHO.user); json(r.c, r.b); }); return; }
    if (u.pathname.startsWith('/api/')) return json(404, { error: 'not found' });
    const f = path.join(DASH, u.pathname.replace(/^\/dashboards\//, '/')); if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (err, d) => { if (err) { res.writeHead(404); res.end(); return; } res.writeHead(200, { 'Content-Type': u.pathname.endsWith('.js') ? 'application/javascript' : u.pathname.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const url = 'http://127.0.0.1:' + srv.address().port + '/dashboards/change-log.html';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  const wait = (p, fn, arg) => p.waitForFunction(fn, arg, { timeout: 15000 }).then(() => true, () => false);
  const L = (p) => p.textContent('#list');
  try {
    const p = await browser.newPage({ viewport: { width: 1500, height: 1000 } }); p.on('pageerror', (x) => errs.push(x.message));
    await p.goto(url); ok(await wait(p, () => document.querySelectorAll('tr.ch').length === 3), 'three carried-out changes listed');
    const K = await p.textContent('#kpis'); ok(/3\s*changes/.test(K) && /2\s*followed by alerts/.test(K) && /1\s*failed/.test(K) && /1\s*system down now/.test(K), 'KPIs');
    ok(/network \(1\)|network \(2\)/.test(await p.textContent('#src')) && /server \(1\)/.test(await p.textContent('#src')), 'sources with counts');
    await p.click('[data-k="failed"]'); ok(await wait(p, () => document.querySelectorAll('tr.ch').length === 1) && /Shut unused ports/.test(await L(p)), 'a KPI filters the register');
    await p.click('[data-k="failed"]'); await wait(p, () => document.querySelectorAll('tr.ch').length === 3);
    await p.click('tr.ch[data-c="NCHG-000001"]');
    ok(await wait(p, () => /\+30 min/.test(document.getElementById('list').textContent)), 'a change opens its SOC timeline: +30 min');
    ok(/Synthetic rule ALR-1/.test(await L(p)) && /ip ospf cost 10/.test(await L(p)), 'the alert and the roll-back');
    ok(!(await p.evaluate(() => window.__xss)), 'a hostile change title stayed text');
    // the window: the IIS patch is 40 h ago, its alert 30 h after
    ok(/none/.test(await p.$eval('tr.ch[data-c="SCHG-000001"]', (r) => r.textContent)), '24 h window: no alert after the IIS patch');
    await p.selectOption('#win', '72'); ok(await wait(p, () => /1 alert/.test((document.querySelector('tr.ch[data-c="SCHG-000001"]') || {}).textContent || '')), '72 h window reaches it');
    // record a change
    await p.click('#new'); await p.fill('#fwhat', 'Firmware upgrade on the core'); await p.click('#fsave');
    ok(await wait(p, () => /target is required/.test(document.getElementById('fmsg').textContent)), 'refused with the field named');
    await p.fill('#ftarget', 'CORE-SYN'); await p.selectOption('#frisk', 'high'); await p.fill('#fticket', 'SYN-123');
    const t = new Date(NOW - H - new Date().getTimezoneOffset() * 60000).toISOString().slice(0, 16); await p.fill('#fat', t);
    A('ALR-9', 'core-syn', NOW - H + 5 * MIN, 4);
    await p.click('#fsave'); ok(await wait(p, () => /Recorded CHG-000001/.test(document.body.textContent)), 'recorded');
    ok(await wait(p, () => /\+[56] min/.test(document.getElementById("list").textContent)), "the recorded change is correlated at once: +5 min (the form keeps minutes)");
    // phone
    const ph = await browser.newPage({ viewport: { width: 390, height: 900 } }); await ph.goto(url); await wait(ph, () => document.querySelector('tr.ch'));
    ok(await ph.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1), 'phone width: no sideways scroll'); await ph.close();
    // viewer
    WHO = { user: 'vera.syn', role: 'viewer' }; await p.goto(url); await wait(p, () => document.querySelector('tr.ch'));
    ok(await p.$eval('#new', (b) => b.hidden), 'viewer: no Record button');
    await p.click('tr.ch[data-c="NCHG-000001"]'); ok(await wait(p, () => /details are for analysts and above/.test(document.getElementById('list').textContent)) && !/Synthetic rule ALR-1/.test(await L(p)) && !/10\.0\.0\.2/.test(await L(p)), 'viewer: counts, no alert text, no IP');
    const nav = fs.readFileSync(path.join(DASH, 'vendor', 'zyb-nav.js'), 'utf8');
    ok(/"h": "change-log.html"/.test(nav) && / change-log\.html /.test(fs.readFileSync(path.join(DASH, 'install-dashboards.sh'), 'utf8')), 'menu entry and installer');
    ok(/changelog: 'change-log\.html'/.test(fs.readFileSync(path.join(DASH, 'vendor', 'zyb-menu.js'), 'utf8')), 'the portal\'s old "Change Log" opens this page');
    ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  } finally { await browser.close(); srv.close(); }
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n);
  process.exit(bad ? 1 : 0);
})();
