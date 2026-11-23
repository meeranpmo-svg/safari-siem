// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const ZYB_ORG = require('../../brand/index');
// Device Configuration (device-config.html) against the REAL SIEM module (sentra-siem engine/onboard/devconfig.js) over a SYNTHETIC
// log-flow model: tiles with real counts, one card per device type with its state bar, clicking a type shows its devices and its
// setup guide (copy button), findings (waiting longer than usual, stopped), record today (operator; a viewer does not see it), AI off
// says why, Excel, a hostile device name stays text, the asset register down is said, the menu entry and the portal redirect.
// Run: SENTRA_SIEM_DIR=/home/user/sentra-siem PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node device-config.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const DASH = path.resolve(__dirname, '../../ui');
const SIEM = process.env.SENTRA_SIEM_DIR || path.resolve(__dirname, '../../backend/siem');
const dc = require(path.join(SIEM, 'engine/onboard/devconfig'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const XSS = '<img src=x onerror="window.__xss=1">';
const DAY = 86400000, NOW = Date.now(), iso = (t) => new Date(t).toISOString();
let INV = { connected: true, assets_total: 6 };
const model = () => ({ policy: { waiting_grace_h: 24 }, inventory: INV, summary: { required: 5, covered: 2, waiting: 1, silent: 1, 'not-onboarded': 0, 'no-connector': 1, coverage_pct: 50 },
  assets: [
    { asset_id: 'f1', name: 'FGT-HQ', type: 'network', sla_class: 'firewall', sla_min: 15, mgmt_ip: '10.0.0.1', site: 'HQ', state: 'covered', last_seen: NOW - 60000, source_id: 'fg-1', source_kind: 'fortigate' },
    { asset_id: 'f2', name: 'FGT-JED ' + XSS, type: 'network', sla_class: 'firewall', sla_min: 15, mgmt_ip: '10.1.0.1', site: 'Jeddah', state: 'silent', last_seen: NOW - 3 * 3600000, source_id: 'fg-2', source_kind: 'fortigate' },
    { asset_id: 'f3', name: 'FGT-DMM', type: 'network', sla_class: 'firewall', sla_min: 15, mgmt_ip: '10.2.0.1', site: 'Dammam', state: 'waiting', source_id: 'fg-3', source_kind: 'fortigate', waiting_since: NOW - 6 * DAY },
    { asset_id: 'w1', name: 'SRV-01', type: 'server', sla_class: 'server', sla_min: 60, state: 'covered', last_seen: NOW, source_id: 'win-1', source_kind: 'windows' },
    { asset_id: 'x1', name: 'OLD-NAS', type: 'storage', sla_class: 'other', sla_min: 120, state: 'no-connector' }],
  sources: [{ src_id: 'fg-1', kind: 'fortigate', created_at: iso(NOW - 30 * DAY) }] });
const byKind = (k) => ({ fortigate: { kind: 'fortigate', mode: 'syslog', title: { en: 'Fortinet FortiGate' } }, windows: { kind: 'windows', mode: 'token', title: { en: 'Windows (SIEM agent)' } } })[k] || null;
const setupFor = (s) => ({ mode: 'syslog', kind: s.kind, syslog_target: (ZYB_ORG.platform_addr + ':5514/tcp'), summary: { en: ('Point the device syslog at ' + ZYB_ORG.platform_addr + ':5514 (tcp)') }, instructions: [{ title: { en: 'FortiOS CLI' }, body: ('config log syslogd setting\n set status enable\n set server ' + ZYB_ORG.platform_addr + '\nend') }] });
const store = new Map(), state = { collection: () => ({ all: () => [...store.values()], put: (x) => store.set(x.id, x), remove: (id) => store.delete(id) }) };
const routes = {}, AUD = [];
dc.register({ route: (m, p, fn) => { routes[m + ' ' + p] = fn; } }, { now: () => Date.now(), state, noTimers: true, config: {}, connectorCatalog: { byKind } }, { setupFor }, { model: async () => model() }, '/api/soc/collection');
let ROLE = 'operator'; const RANK = { viewer: 1, analyst: 2, operator: 3, admin: 4 };

(async () => {
  const srv = http.createServer((req, res) => {
    const url = new URL(req.url, 'http://x'), u = url.pathname, json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u === '/dashboards/whoami.json' || u === '/auth/whoami') return json(200, { user: ROLE + '.syn', role: ROLE });
    const key = req.method + ' ' + u;
    if (routes[key]) { let b = ''; req.on('data', (c) => { b += c; }); req.on('end', async () => { let out = null;
      const ctx = { query: Object.fromEntries(url.searchParams), body: b ? JSON.parse(b) : {}, role: ROLE, user: ROLE + '.syn', path: u, ok: (x) => { out = [200, x]; return out; }, fail: (s, m) => { out = [s, { error: m }]; return out; },
        need: (r) => { if ((RANK[ROLE] || 0) < RANK[r]) { out = [403, { error: 'requires role ' + r }]; return false; } return true; }, audit: (a, t, d) => AUD.push({ a, t, d }) };
      await routes[key](ctx); json(out[0], out[1]); }); return; }
    if (u.startsWith('/api/')) return json(404, { error: 'not in this test' });
    const f = path.join(DASH, u.replace(/^\/dashboards\//, '')); if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (e, d) => { if (e) { res.writeHead(404); return res.end(); } res.writeHead(200, { 'Content-Type': f.endsWith('.js') ? 'application/javascript' : f.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const url = 'http://127.0.0.1:' + srv.address().port + '/dashboards/device-config.html';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright'); const browser = await chromium.launch(), errs = [];
  const wait = (p, fn, arg) => p.waitForFunction(fn, arg, { timeout: 15000 }).then(() => true, () => false);
  try {
    const ctx = await browser.newContext({ viewport: { width: 1500, height: 1000 }, acceptDownloads: true, permissions: ['clipboard-read', 'clipboard-write'] });
    const p = await ctx.newPage(); p.on('pageerror', (e) => errs.push(e.message));
    await p.goto(url); ok(await wait(p, () => document.querySelectorAll('.ty').length === 3), 'one card per device type (FortiGate, Windows, no connector)');
    const k = await p.textContent('#kk'); ok(/Devices that must log\s*5/.test(k) && /Waiting for the device\s*1/.test(k) && /Stopped\s*1/.test(k) && /50 %/.test(k), 'tiles with the real counts');
    ok(/Fortinet FortiGate/.test(await p.textContent('.ty[aria-pressed="true"]')) && /2 to fix/.test(await p.textContent('.ty[aria-pressed="true"]')), 'the type with the most to fix first, with its count');
    ok((await p.$$('.ty[data-kind="fortigate"] .seg i')).length === 3, 'state bar per type');
    ok((await p.$$('tr[data-dev]')).length === 3 && /waiting for the device/.test(await p.textContent('#view')) && /6 day/.test(await p.textContent('#view')), 'devices of the type with state and days waiting');
    await p.click('#tabs [data-tab="setup"]'); ok(new RegExp(ZYB_ORG.platform_addr_re + ':5514\\/tcp').test(await p.textContent('#view')) && new RegExp('set server ' + ZYB_ORG.platform_addr_re).test(await p.textContent('#view')), 'setup guide for the type');
    await p.click('[data-copy="0"]'); ok(await wait(p, () => /Copied|Copy not allowed/.test(document.body.textContent)), 'copy button');
    await p.click('.ty[data-kind="no-connector"]'); await p.click('#tabs [data-tab="setup"]'); ok(/not in the connector catalogue/.test(await p.textContent('#view')), 'no connector says what to do');
    await p.click('#tabs [data-tab="findings"]'); ok(/FGT-DMM has waited 6 days/.test(await p.textContent('#view')) && /stopped sending logs/.test(await p.textContent('#view')), 'findings: waiting long, stopped');
    await p.click('#tabs [data-tab="ai"]'); ok(/AI configuration assistant is off/.test(await p.textContent('#view')), 'AI off says why');
    ok(await p.isVisible('#sample')); await p.click('#sample'); ok(await wait(p, () => /Recorded 4 sources/.test(document.body.textContent)), 'record today');
    ok(AUD.some((x) => x.a === 'collection.devices.sample'), 'sample audited');
    const [dl] = await Promise.all([p.waitForEvent('download', { timeout: 10000 }), p.click('#xls')]);
    ok(/^device-configuration-\d{4}-\d{2}-\d{2}\.xlsx$/.test(dl.suggestedFilename()), 'Excel export');
    ok(!(await p.evaluate(() => window.__xss)), 'hostile device name stayed text');
    ROLE = 'viewer'; const q = await ctx.newPage(); await q.goto(url); await wait(q, () => document.querySelectorAll('.ty').length === 3);
    ok(!(await q.isVisible('#sample')), 'viewer: no Record today');
    INV = { connected: false, error: 'connection refused' }; const r = await ctx.newPage(); await r.goto(url);
    ok(await wait(r, () => /asset register did not answer/.test(document.getElementById('nc').textContent)), 'asset register down is said');
    const nav = fs.readFileSync(path.join(DASH, 'vendor', 'zyb-nav.js'), 'utf8');
    ok(/"h": "device-config.html"/.test(nav) && /device-config\.html/.test(fs.readFileSync(path.join(DASH, 'install-dashboards.sh'), 'utf8')), 'menu entry and installer');
    ok(/configure: 'device-config\.html'/.test(fs.readFileSync(path.join(DASH, 'vendor', 'zyb-menu.js'), 'utf8')) && /configure: 'device-config\.html'/.test(fs.readFileSync(path.join(DASH, 'vendor', 'zyb-early.js'), 'utf8')), 'the portal\'s Device Configuration opens this page');
    ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  } finally { await browser.close(); srv.close(); }
  console.log((bad ? 'FAILED ' : 'ok ') + (n - bad) + '/' + n);
  process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
