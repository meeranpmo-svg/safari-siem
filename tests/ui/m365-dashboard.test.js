// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// m365-dashboard.html (Microsoft 365, Users & Endpoints) against the REAL SIEM insights module (sentra-siem
// engine/collect/m365-insights.js; the Graph snapshot is SYNTHETIC): not connected says what to connect; the KPIs, the ordered
// actions (admin without MFA first), the posture donuts; a block without permission is named and reads "—"; licences with the
// reclaimable seats; identity risk with every reason to an analyst and hidden from a viewer; the fleet with the usual build and
// leavers' devices; sign-in bursts and a new country; an expired app secret; the AI analyst answer stays text; the portal's
// sample "dash-m365" view now opens this page; the menu entry.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node m365-dashboard.test.js
const http = require('http'), fs = require('fs'), os = require('os'), path = require('path');
const DASH = path.resolve(__dirname, '../../ui');
const SIEM = process.env.SENTRA_SIEM || path.resolve(__dirname, '../..', 'backend', 'siem');
const MI = require(path.join(SIEM, 'engine/collect/m365-insights'));
const { createState } = require(path.join(SIEM, 'engine/soc/state'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const XSS = '<img src=x onerror="window.__xss=1">';
const D = 86400000, iso = (ms) => new Date(Date.now() - ms).toISOString();
const SNAP = { configured: true, updated: new Date().toISOString(), sync: {}, blocks: { users: { ok: true }, licenses: { ok: true }, intune: { ok: true }, signins: { ok: true }, mfa: { ok: true }, riskyUsers: { ok: false, perm: 'IdentityRiskyUser.Read.All' }, apps: { ok: true } },
  licenses: [{ sku: 'SPE_E3', total: 10, consumed: 4, renews: '2026-11-20', days: 18 }],
  users: { list: [{ name: 'Admin Syn ' + XSS, upn: 'admin.syn@as.test', enabled: true, lic: 1, skus: ['SPE_E3'], last: iso(D) }, { name: 'Left Syn', upn: 'left.syn@as.test', enabled: false, lic: 1, skus: ['SPE_E3'], last: iso(200 * D) },
    { name: 'Idle Syn', upn: 'idle.syn@as.test', enabled: true, lic: 1, skus: ['SPE_E3'], last: iso(120 * D) }, { name: 'Busy Syn', upn: 'busy.syn@as.test', enabled: true, lic: 1, skus: ['SPE_E3'], last: iso(D) },
    { name: 'Guest Never SYN', upn: 'gn_ext#EXT#@as.test', enabled: true, guest: true, lic: 0, last: null, created: iso(30 * D) }, { name: 'Guest Old SYN', upn: 'go_ext#EXT#@as.test', enabled: true, guest: true, lic: 0, last: iso(150 * D) }] },
  intuneOk: true, intune: ['PC1', 'PC2', 'PC3', 'PC5', 'PC6'].map((x, i) => ({ name: x, user: 'Busy Syn', upn: i === 3 ? 'left.syn@as.test' : 'busy.syn@as.test', os: 'Windows 10.0.22631.4317', compliance: 'compliant', lastSync: iso(D), serial: 'S' + i }))
    .concat([{ name: 'PC4', user: 'Idle Syn', upn: 'idle.syn@as.test', os: 'Windows 10.0.19045.4651', compliance: 'noncompliant', lastSync: iso(40 * D) }]),
  signinsOk: true, signins: Array.from({ length: 6 }, (_, i) => ({ time: iso((10 - i) * 3600000), user: 'Busy Syn', upn: 'busy.syn@as.test', ip: '203.0.113.' + i, status: 'Failed', location: 'Riyadh, SA' }))
    .concat([{ time: iso(20 * 3600000), user: 'Admin Syn', upn: 'admin.syn@as.test', ip: '10.0.0.5', status: 'Success', location: 'Riyadh, SA' }, { time: iso(3600000), user: 'Admin Syn', upn: 'admin.syn@as.test', ip: '198.51.100.7', status: 'Success', location: 'Lagos, NG' }]),
  security: { mfa: { ok: true, data: { users: 4, registered: 2, notRegistered: [{ name: 'Admin Syn', upn: 'admin.syn@as.test', admin: true }, { name: 'Idle Syn', upn: 'idle.syn@as.test', admin: false }] } }, secureScore: { ok: true, data: { current: 41, max: 80 } } },
  apps: [{ name: 'HR connector (synthetic)', app_id: 'a1', owners: [], secrets: [{ name: 's1', end: iso(-5 * D) }], certs: [] }] };

(async () => {
  const state = await createState({ dir: fs.mkdtempSync(path.join(os.tmpdir(), 'm365p-')) });
  SNAP.signins.push({ time: iso(90 * 60000), user: 'Trav Syn', upn: 'trav.syn@as.test', ip: '192.0.2.10', status: 'Success', location: 'Riyadh, SA', app: 'Outlook' }, { time: iso(60 * 60000), user: 'Trav Syn', upn: 'trav.syn@as.test', ip: '192.0.2.11', status: 'Success', location: 'London, GB', app: 'Outlook' });
  for (let i = 0; i < 5; i++) SNAP.signins.push({ time: iso((30 + i) * 60000), user: 'Sprayed ' + i, upn: 's' + i + '.syn@as.test', ip: '203.0.113.200', status: 'Failed', location: 'Riyadh, SA', app: 'Exchange ActiveSync' });
  { const H = state.collection('m365_insights_hist'); for (let i = 6; i >= 1; i--) { const d = new Date(Date.now() + 3 * 3600000 - i * D).toISOString().slice(0, 10); H.put({ id: d, day: d, members: 3, mfa_pct: 20 + (6 - i) * 5, compliance_pct: 70, secure_pct: 41, seats_used: 4, noncompliant: 1, failed_pct: 30, lic: { SPE_E3: 4 } }); } }
  let data = { configured: false, reason: 'tenant ID missing' };
  class Fake { constructor() { this.messages = { create: async () => ({ stop_reason: 'end_turn', content: [{ type: 'text', text: 'Register MFA for Admin Syn first. ' + XSS }] }) }; } }
  const config = { netops: { ai: {} } }; Object.defineProperty(config, 'secrets', { value: { netops: { anthropic_api_key: 'k' } }, enumerable: false });
  const R = []; MI.register({ route: (m, p, h) => R.push({ m, p, h }) }, { state, config, log: { info() {}, warn() {}, error() {} }, m365Graph: { data: () => data }, anthropicSdk: Fake });
  let ROLE = 'analyst'; const asked = [];
  const srv = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://x'), json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u.pathname === '/dashboards/whoami.json') return json(200, { user: 'nora.syn', role: ROLE });
    if (u.pathname.startsWith('/api/soc/m365/insights')) {
      let b = ''; req.on('data', (c) => { b += c; }); req.on('end', async () => {
        const r = R.find((x) => x.m === req.method && x.p === u.pathname); if (!r) return json(404, { error: 'not found' });
        const RANK = { viewer: 0, analyst: 1, operator: 2, admin: 3 }, out = {}; if (b) asked.push(JSON.parse(b));
        const ctx = { role: ROLE, user: 'nora.syn', body: b ? JSON.parse(b) : {}, params: {}, query: {}, path: u.pathname, need(x) { if (RANK[ROLE] < RANK[x]) { out.c = 403; out.e = 'requires ' + x; return false; } return true; }, audit() {}, fail(c, e) { out.c = c; out.e = e; } };
        const rv = await r.h(ctx); if (out.c) return json(out.c, { error: out.e }); json(200, rv);
      }); return;
    }
    if (u.pathname.startsWith('/api/')) return json(404, { error: 'not found' });
    const f = path.join(DASH, u.pathname.replace(/^\/dashboards\//, '/')); if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (err, d) => { if (err) { res.writeHead(404); res.end(); return; } res.writeHead(200, { 'Content-Type': u.pathname.endsWith('.js') ? 'application/javascript' : u.pathname.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const url = 'http://127.0.0.1:' + srv.address().port + '/dashboards/m365-dashboard.html';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  const wait = (p, fn, arg) => p.waitForFunction(fn, arg, { timeout: 15000 }).then(() => true, () => false);
  const tab = (p, t) => p.click('#tabs [data-tab="' + t + '"]');
  try {
    const p = await browser.newPage({ viewport: { width: 1440, height: 1000 } }); p.on('pageerror', (x) => errs.push(x.message));
    await p.goto(url);
    ok(await wait(p, () => /not connected yet \(tenant ID missing\)/.test(document.body.textContent)), 'not connected: says so, nothing invented');
    data = SNAP; await p.goto(url);
    ok(await wait(p, () => document.querySelectorAll('.kpi').length === 6), 'six KPIs');
    ok(/50%/.test(await p.textContent('#kpis')) && /1 admins/.test(await p.textContent('#kpis')), 'MFA coverage and admins without MFA');
    ok(/riskyUsers \(needs IdentityRiskyUser\.Read\.All\)/.test(await p.textContent('#warn')), 'a block without permission is named');
    const first = await p.textContent('.act .t'); ok(/Register MFA for 1 administrator/.test(first), 'first action: the admin without MFA');
    ok(/SPE_E3 renews in 18 days/.test(await p.textContent('#view')), 'renewal action with the reclaim advice');
    ok(await p.$$eval('.donut svg', (L) => L.length === 3), 'posture donuts');
    const ov = (await p.textContent('#view')).replace(/\s+/g, ' ');
    ok(/What drives identity risk/.test(ov) && /administrator without MFA/.test(ov) && /no MFA registered/.test(ov), 'identity-risk drivers summed across the tenant: ' + ov.slice(ov.indexOf('What drives'), ov.indexOf('What drives') + 200));
    ok(/MFA coverage \d+% → 100% in about \d+ days/.test(ov), 'MFA reaches target at the current pace (least squares)');
    ok(/Device compliance .*not moving towards 95%/.test(ov), 'a flat trend says it needs an action, not time');
    await tab(p, 'licences');
    ok(await wait(p, () => /SPE_E3/.test(document.getElementById('view').textContent)), 'licences tab');
    ok(await p.$eval('#view tbody tr', (tr) => /4 \/ 10/.test(tr.textContent) && /2/.test(tr.children[5].textContent)), 'seats used and 2 to reclaim');
    await tab(p, 'identities');
    ok(await wait(p, () => /administrator without MFA \(\+40\)/.test(document.getElementById('view').textContent)), 'identity risk with its reasons');
    ok(/NG, new for this account/.test(await p.textContent('#view')), 'new-country sign-in counted');
    await tab(p, 'devices');
    ok(await wait(p, () => /usual build 10\.0\.22631/.test(document.getElementById('view').textContent)), 'usual build learned from the fleet');
    ok(/PC4/.test(await p.textContent('#view')) && /PC5/.test(await p.textContent('#view')), 'behind / stale device and the leaver\'s device');
    await tab(p, 'signins');
    ok(await wait(p, () => /busy\.syn@as\.test/.test(document.getElementById('view').textContent)), 'failure burst listed');
    const sg = (await p.textContent('#view')).replace(/\s+/g, ' ');
    ok(/Impossible travel/.test(sg) && /Trav Syn/.test(sg) && /SA → GB/.test(sg) && /30 min/.test(sg), 'impossible travel shown');
    ok(/203\.0\.113\.200/.test(sg) && /5 accounts/.test(sg), 'spraying address shown');
    ok((await p.$$('#view [title*="sign-in(s)"]')).length === 7 * 24 && /outside working hours/.test(sg), 'hour-of-week heat map in Riyadh time');
    ok(/Exchange ActiveSync/.test(sg) && /100% failed/.test(sg), 'failures per app');
    await tab(p, 'guests');
    ok(await wait(p, () => /Guest Never SYN/.test(document.getElementById('view').textContent) && /Guest Old SYN/.test(document.getElementById('view').textContent)), 'guests: never signed in and idle 90 days');
    await tab(p, 'apps');
    ok(await wait(p, () => /5 d left|4 d left/.test(document.getElementById('view').textContent)), 'expiring app secret');
    await tab(p, 'ai'); await p.fill('#q', 'what should we fix first?'); await p.click('#ask');
    ok(await wait(p, () => /Register MFA for Admin Syn first/.test(document.body.textContent)), 'AI answer shown');
    ROLE = 'viewer'; await p.goto(url); await wait(p, () => document.querySelectorAll('.kpi').length === 6);
    ok(!(await p.$('#tabs [data-tab="ai"]')), 'viewer: no AI tab');
    await tab(p, 'identities');
    ok(await wait(p, () => /names are shown to analysts and above/.test(document.getElementById('view').textContent)), 'viewer: names hidden (PDPL)');
    ok(!/admin\.syn@as\.test/.test(await p.content()), 'no personal e-mail in the page for a viewer');
    ok(!(await p.evaluate(() => window.__xss)), 'hostile names and the AI answer stayed text');
    const menu = fs.readFileSync(path.join(DASH, 'vendor', 'zyb-menu.js'), 'utf8'), early = fs.readFileSync(path.join(DASH, 'vendor', 'zyb-early.js'), 'utf8');
    ok(/'dash-m365': 'm365-dashboard\.html'/.test(menu) && /'dash-m365': 'm365-dashboard\.html'/.test(early), 'the portal\'s sample dashboard opens this page');
    ok(/"h": "m365-dashboard.html"/.test(fs.readFileSync(path.join(DASH, 'vendor', 'zyb-nav.js'), 'utf8')) && /m365-dashboard\.html/.test(fs.readFileSync(path.join(DASH, 'install-dashboards.sh'), 'utf8')), 'menu entry and installer');
    ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  } finally { await browser.close(); srv.close(); }
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks');
  process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
