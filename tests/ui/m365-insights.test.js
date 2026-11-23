// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// m365.html -> Insights tab (vendor/zyb-m365x.js) against the REAL SIEM insights module (sentra-siem engine/collect/m365-insights.js)
// with a SYNTHETIC Graph snapshot: the tab opens from its button and from #insights; actions ranked; licence seats to reclaim;
// identities with every reason to an analyst and counted for a viewer; impossible travel and one address failing across many
// accounts; the day x hour heatmap; stale / never-used guests; a hostile display name stays text; the AI analyst for analysts.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node m365-insights.test.js
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
    { name: 'Idle Syn', upn: 'idle.syn@as.test', enabled: true, lic: 1, skus: ['SPE_E3'], last: iso(120 * D) }, { name: 'Busy Syn', upn: 'busy.syn@as.test', enabled: true, lic: 1, skus: ['SPE_E3'], last: iso(D) }] },
  intuneOk: true, intune: ['PC1', 'PC2', 'PC3', 'PC5', 'PC6'].map((x, i) => ({ name: x, user: 'Busy Syn', upn: i === 3 ? 'left.syn@as.test' : 'busy.syn@as.test', os: 'Windows 10.0.22631.4317', compliance: 'compliant', lastSync: iso(D), serial: 'S' + i }))
    .concat([{ name: 'PC4', user: 'Idle Syn', upn: 'idle.syn@as.test', os: 'Windows 10.0.19045.4651', compliance: 'noncompliant', lastSync: iso(40 * D) }]),
  signinsOk: true, signins: Array.from({ length: 6 }, (_, i) => ({ time: iso((10 - i) * 3600000), user: 'Busy Syn', upn: 'busy.syn@as.test', ip: '203.0.113.' + i, status: 'Failed', location: 'Riyadh, SA' }))
    .concat([{ time: iso(20 * 3600000), user: 'Admin Syn', upn: 'admin.syn@as.test', ip: '10.0.0.5', status: 'Success', location: 'Riyadh, SA' }, { time: iso(3600000), user: 'Admin Syn', upn: 'admin.syn@as.test', ip: '198.51.100.7', status: 'Success', location: 'Lagos, NG' }]),
  security: { mfa: { ok: true, data: { users: 4, registered: 2, notRegistered: [{ name: 'Admin Syn', upn: 'admin.syn@as.test', admin: true }, { name: 'Idle Syn', upn: 'idle.syn@as.test', admin: false }] } }, secureScore: { ok: true, data: { current: 41, max: 80 } } },
  apps: [{ name: 'HR connector (synthetic)', app_id: 'a1', owners: [], secrets: [{ name: 's1', end: iso(-5 * D) }], certs: [] }] };

// rev 2 patterns: a Riyadh sign-in 30 minutes before the Lagos one (impossible travel); one address failing on six accounts; guests
SNAP.signins.push({ time: iso(90 * 60000), user: 'Admin Syn', upn: 'admin.syn@as.test', ip: '10.0.0.5', status: 'Success', app: 'Outlook', location: 'Riyadh, SA' });
for (let i = 0; i < 6; i++) SNAP.signins.push({ time: iso(5 * 3600000 + i * 60000), user: 'U' + i, upn: 'u' + i + '@as.test', ip: '192.0.2.99', status: 'Failed', app: 'Azure Portal', location: 'Amsterdam, NL' });
SNAP.users.list.push({ name: 'Old Guest Syn', upn: 'old@ext.test', enabled: true, guest: true, lic: 0, skus: [], last: iso(200 * D) }, { name: 'Never Guest Syn', upn: 'never@ext.test', enabled: true, guest: true, lic: 0, skus: [], last: null });

(async () => {
  const state = await createState({ dir: fs.mkdtempSync(path.join(os.tmpdir(), 'm365p-')) });
  let data = { configured: false, reason: 'tenant ID missing' };
  class Fake { constructor() { this.messages = { create: async () => ({ stop_reason: 'end_turn', content: [{ type: 'text', text: 'Register MFA for Admin Syn first. ' + XSS }] }) }; } }
  const config = { netops: { ai: {} } }; Object.defineProperty(config, 'secrets', { value: { netops: { anthropic_api_key: 'k' } }, enumerable: false });
  const R = []; MI.register({ route: (m, p, h) => R.push({ m, p, h }) }, { state, config, log: { info() {}, warn() {}, error() {} }, m365Graph: { data: () => data }, anthropicSdk: Fake });
  let ROLE = 'analyst'; const asked = [];
  data = SNAP;
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
    if (u.pathname === '/api/soc/m365/graph') return json(200, data);
    if (u.pathname === '/api/soc/m365/config') return json(200, { config: {}, permissions: [] });
    if (u.pathname.startsWith('/api/')) return json(404, { error: 'not found' });
    const f = path.join(DASH, u.pathname.replace(/^\/dashboards\//, '/')); if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (err, d) => { if (err) { res.writeHead(404); res.end(); return; } res.writeHead(200, { 'Content-Type': u.pathname.endsWith('.js') ? 'application/javascript' : u.pathname.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port + '/dashboards/m365.html?standalone=1';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright'); const browser = await chromium.launch(), errs = [];
  const wait = (p, fn, arg) => p.waitForFunction(fn, arg, { timeout: 20000 }).then(() => true, () => false);
  try {
    let p = await browser.newPage(); p.on('pageerror', (x) => errs.push(x.message));
    await p.goto(base); await p.click('[data-tab="ins"]');
    ok(await wait(p, () => /What to do first/.test((document.getElementById('m365x') || {}).textContent || '')), 'the Insights tab opens and loads');
    const t = await p.textContent('#m365x');
    ok(/Register MFA for 1 administrator/.test(t), 'admin without MFA first');
    ok(/impossible-travel/.test(t) && /SA → NG in 30 min/.test(t), 'impossible travel');
    ok(/192\.0\.2\.99/.test(t) && /6 accounts/.test(t), 'one address failing on many accounts');
    ok(await p.$$eval('[aria-label="sign-ins by day and hour"] tr', (L) => L.length) === 8, 'heatmap 7 days + hour axis');
    ok(/1<\/b> stale/.test(await p.innerHTML('#m365x')) && /Never Guest Syn/.test(t), 'stale and never-used guests named for an analyst');
    ok(/Reclaimable/.test(t) && /disabled/.test(t), 'licence seats to reclaim');
    ok(/administrator without MFA \(\+40\)/.test(t), 'identity risk with each point');
    ok(await p.evaluate(() => !window.__xss), 'nothing injected runs');
    await p.fill('#m365xq', 'who first?'); await p.click('#m365xf button');
    ok(await wait(p, () => /Register MFA for Admin Syn first/.test(document.getElementById('m365xa').textContent)) && await p.evaluate(() => !window.__xss), 'AI answer, as text');
    ROLE = 'viewer'; p = await browser.newPage(); p.on('pageerror', (x) => errs.push(x.message)); await p.goto(base + '#insights');
    ok(await wait(p, () => /names are shown to analysts and above/.test((document.getElementById('m365x') || {}).textContent || '')), 'viewer: identities counted, not named (opened from #insights)');
    const tv = await p.textContent('#m365x');
    ok(!/admin\.syn@as\.test/.test(tv) && !/192\.0\.2\.99/.test(tv) && /names for analysts and above/.test(tv), 'viewer: no account or address shown');
    ok(/zyb-m365x\.js/.test(fs.readFileSync(path.join(DASH, 'install-dashboards.sh'), 'utf8')), 'installer ships the script');
    ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  } finally { await browser.close(); srv.close(); }
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n);
  process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
