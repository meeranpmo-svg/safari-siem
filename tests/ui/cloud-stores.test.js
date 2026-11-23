// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Cloud Data Stores (cloud-stores.html) over the REAL SIEM routes (sentra-siem engine/collect/cloud-data-routes.js: validation and
// roles are the real ones) with a stand-in collector holding SYNTHETIC stores. An analyst: stores with region in / outside the
// Kingdom, public with the reason, encryption, data found, the most exposed objects; Scan now for operators. An administrator:
// connects Azure with the Microsoft 365 app, AWS with a key (the secret field is cleared and never shown back), a bad OCI
// fingerprint is refused naming the field, Test. A viewer: counts, no object names, no Connect tab. A hostile store name stays
// text. Nothing connected: the page says what to connect. No page error.
// Run: SENTRA_SIEM_DIR=/home/user/sentra-siem PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node cloud-stores.test.js
const http = require('http'), fs = require('fs'), os = require('os'), path = require('path');
const DASH = path.resolve(__dirname, '../../ui');
const SIEM = process.env.SENTRA_SIEM_DIR || path.resolve(__dirname, '../../backend/siem');
const R = require(path.join(SIEM, 'engine/collect/cloud-data-routes'));
const { createState } = require(path.join(SIEM, 'engine/soc/state'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const XSS = '<img src=x onerror="window.__xss=1">', RANK = { viewer: 1, analyst: 2, operator: 3, admin: 4 };
let ROLE = 'analyst', CONNECTED = true;
const T0 = Date.parse('2026-11-14T06:00:00Z');
const STORES = [
  { id: 'azure:stsynfin:claims', provider: 'azure', account: 'stsynfin', name: 'claims-exports', region: 'uaenorth', in_kingdom: false, public: true, public_why: 'container public access: blob', encrypted: true, cmk: false, objects_seen: 900, objects_scanned: 900, objects_with_findings: 42, kinds: { national_id: 40, iban: 3 }, categories: { identity: 40, financial: 3 }, truncated: false, last_scan: T0 },
  { id: 'oci:synns:backups', provider: 'oci', account: 'synns', name: 'db-backups ' + XSS, region: 'me-jeddah-1', in_kingdom: true, public: false, public_why: '', encrypted: true, cmk: true, objects_seen: 5000, objects_scanned: 2000, objects_with_findings: 3, kinds: { api_key: 3 }, categories: { credentials: 3 }, truncated: true, last_scan: T0 },
  { id: 'aws:syn:logs', provider: 'aws', account: 'syn', name: 'app-logs', region: null, in_kingdom: null, public: null, public_why: 'public access block not readable', encrypted: false, cmk: false, objects_seen: 10, objects_scanned: 10, objects_with_findings: 0, kinds: {}, categories: {}, truncated: false, last_scan: T0 },
];
const saved = [], creds = [];
const fake = {
  view: ({ keys }) => !CONNECTED ? { configured: false, note: 'No cloud provider is connected. An administrator connects Azure, AWS or Oracle Cloud on the Connect tab.', providers: [], stores: [], totals: {}, top_objects: keys ? [] : { hidden: true }, scan: { running: false } } : {
    configured: true, providers: [{ provider: 'azure', configured: true, last_scan: T0, last_ok: T0, error: null, stores: 1 }, { provider: 'aws', configured: true, last_scan: T0, last_ok: null, error: 'AccessDenied on GetPublicAccessBlock', stores: 1 }, { provider: 'oci', configured: true, last_scan: T0, last_ok: T0, error: null, stores: 1 }],
    stores: STORES, totals: { stores: 3, public: 1, outside_kingdom: 1, unencrypted: 1, objects_scanned: 2910, objects_with_findings: 45 },
    top_objects: keys ? [{ store_id: 'azure:stsynfin:claims', key: 'exports/customers-2026.csv', size: 4000, modified: T0, kinds: { national_id: 40 }, categories: { identity: 40 }, exposure: { score: 85, why: [{ text: 'holds identity data' }, { text: 'the container is public' }] } }] : { hidden: true, reason: 'analyst and above' },
    scan: { running: false } },
  settingsView: () => ({ settings: { azure: { enabled: false, discover: true }, aws: {}, oci: {}, in_kingdom_regions: [], schedule_hours: 24 }, credentials: Object.fromEntries(creds.map((c) => [c.provider, { configured: true, set_at: T0 }])), m365_app_available: true }),
  saveSettings: (s) => { saved.push(s); return { changed: Object.keys(s) }; },
  setCredentials: (p, v) => { creds.push({ provider: p, fields: Object.keys(v) }); return { configured: true, set_at: T0 }; },
  deleteCredentials: () => ({ removed: true }),
  startScan: (by) => ({ started: true, providers: ['azure', 'aws', 'oci'], scan: { running: true, by } }),
  testProvider: async (p) => ({ ok: true, provider: p, count: 4, what: 'storage accounts' }),
  schedule() {},
};

(async () => {
  const state = await createState({ dir: fs.mkdtempSync(path.join(os.tmpdir(), 'sentra-cloud-ui-')) });
  const routes = {}, audits = [], api = { route: (m, p, fn) => { routes[m + ' ' + p] = fn; } };
  R.register(api, { state, config: {}, log: { info() {}, warn() {}, error() {}, every() {} }, cloudData: fake, noTimers: true });
  const srv = http.createServer((req, res) => {
    const url = new URL(req.url, 'http://x'), u = url.pathname, json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u === '/dashboards/whoami.json') return json(200, { user: ROLE + '.syn', role: ROLE });
    const key = Object.keys(routes).find((k) => { const [m, p] = k.split(' '); return m === req.method && new RegExp('^' + p.replace(/:[a-z]+/g, '([^/]+)') + '$').test(u); });
    if (key) { let b = ''; req.on('data', (c) => { b += c; }); req.on('end', async () => { let out = null;
      const ctx = { query: Object.fromEntries(url.searchParams), body: b ? JSON.parse(b) : {}, params: {}, role: ROLE, user: ROLE + '.syn', ip: '10.0.0.5', path: u, headers: {},
        ok: (x) => { out = [200, x]; return out; }, fail: (s, m) => { out = [s, { error: m }]; return out; },
        need: (r) => { if ((RANK[ROLE] || 0) < RANK[r]) { out = [403, { error: 'requires role ' + r }]; return false; } return true; }, audit: (a, t, d) => audits.push({ a, t, d, by: ROLE }) };
      const rv = await routes[key](ctx); if (!out) out = [200, rv]; json(out[0], out[1]); }); return; }
    if (u.startsWith('/api/')) return json(404, { error: 'not in this test' });
    const f = path.join(DASH, u.replace(/^\/dashboards\//, '')); if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (e, d) => { if (e) { res.writeHead(404); return res.end(); } res.writeHead(200, { 'Content-Type': f.endsWith('.js') ? 'application/javascript' : f.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const url = 'http://127.0.0.1:' + srv.address().port + '/dashboards/cloud-stores.html';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright'); const browser = await chromium.launch(), errs = [];
  const wait = (p, fn, arg) => p.waitForFunction(fn, arg, { timeout: 15000 }).then(() => true, () => false);
  try {
    const p = await (await browser.newContext({ viewport: { width: 1500, height: 1000 } })).newPage(); p.on('pageerror', (e) => errs.push(e.message));
    await p.goto(url);
    ok(await wait(p, () => /claims-exports/.test(document.getElementById('stores').textContent)), 'stores load');
    const k = await p.textContent('#kpis'); ok(/3\s*stores/.test(k) && /1\s*public/.test(k) && /1\s*outside the Kingdom/.test(k), 'tiles: ' + k.replace(/\s+/g, ' '));
    const st = await p.textContent('#stores');
    ok(/uaenorth[\s\S]*no[\s\S]*yes[\s\S]*container public access: blob/.test(st), 'outside the Kingdom and public with the reason');
    ok(/partly read/.test(st) && /own key/.test(st) && /not read/.test(st), 'partly read, customer key, and unknown said as "not read" - never assumed');
    ok(/<img src=x/.test(st) && !(await p.evaluate(() => window.__xss)), 'a hostile store name stays text');
    ok(/AccessDenied on GetPublicAccessBlock/.test(await p.textContent('#prov')), 'a provider problem is shown');
    ok(/exports\/customers-2026\.csv/.test(await p.textContent('#objs')) && /container is public/.test(await p.textContent('#objs')), 'an analyst sees the most exposed objects with why');
    ok(!(await p.isVisible('#scan')) && !(await p.isVisible('#tab-conn')), 'an analyst cannot scan or connect');

    ROLE = 'operator'; await p.reload(); await wait(p, () => !document.getElementById('scan').hidden);
    await p.click('#scan'); ok(await wait(p, () => /Scan started/.test(document.body.textContent)), 'an operator starts a scan');
    ok(audits.some((a) => a.a === 'cloud-data.scan' && a.by === 'operator'), 'the scan is audited');

    ROLE = 'admin'; await p.reload(); await wait(p, () => !document.getElementById('tab-conn').hidden); await p.click('#tab-conn');
    ok(await wait(p, () => /Microsoft 365 app is available/.test(document.getElementById('az-cred').textContent)), 'the Microsoft 365 app is offered for Azure');
    await p.check('#az-en'); await p.check('#az-m365'); await p.fill('#az-subs', '0f0e0d0c-0b0a-4908-8706-050403020100'); await p.click('#f-azure button[type=submit]');
    ok(await wait(p, () => document.querySelector('[data-msg="azure"]').textContent === 'Saved.'), 'Azure saved with the Microsoft 365 app');
    ok(saved.some((s) => s.azure && s.azure.use_m365_app === true && s.azure.subscription_ids[0] === '0f0e0d0c-0b0a-4908-8706-050403020100') && !creds.some((c) => c.provider === 'azure'), 'no second Azure secret stored');
    await p.check('#aw-en'); await p.fill('#aw-regions', 'me-central-1'); await p.fill('#aw-key', 'AKIASYNTHETICEXAMPLE1'); await p.fill('#aw-secret', 'SyntheticSecretKeyValue0123456789abcdefgh'); await p.click('#f-aws button[type=submit]');
    ok(await wait(p, () => document.querySelector('[data-msg="aws"]').textContent === 'Saved.'), 'AWS saved');
    ok(creds.some((c) => c.provider === 'aws' && c.fields.join() === 'access_key_id,secret_access_key') && await p.inputValue('#aw-secret') === '', 'the AWS secret is sent once and the field is cleared');
    ok(!JSON.stringify(audits).includes('SyntheticSecretKeyValue'), 'no secret in the audit');
    await p.fill('#oc-fp', 'not-a-fingerprint'); await p.click('#f-oci button[type=submit]');
    ok(await wait(p, () => /fingerprint/.test(document.querySelector('[data-msg="oci"]').textContent)), 'a bad OCI fingerprint is refused naming the field');
    await p.click('[data-test="azure"]'); ok(await wait(p, () => /Connected: 4 storage accounts/.test(document.querySelector('[data-msg="azure"]').textContent)), 'Test proves the connection');
    await p.fill('#g-hours', '12'); await p.click('#f-gen button[type=submit]'); ok(await wait(p, () => document.getElementById('g-msg').textContent === 'Saved.'), 'schedule saved');

    ROLE = 'viewer'; await p.reload(); await wait(p, () => /claims-exports/.test(document.getElementById('stores').textContent));
    ok(/analysts and above/.test(await p.textContent('#objs')) && !/customers-2026/.test(await p.textContent('main')) && !(await p.isVisible('#tab-conn')), 'a viewer: counts, no object names, no Connect');

    CONNECTED = false; ROLE = 'admin'; await p.reload();
    ok(await wait(p, () => /No cloud provider is connected/.test(document.getElementById('note').textContent)), 'nothing connected: the page says what to do');
  } finally { await browser.close(); srv.close(); }
  ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks'); process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
