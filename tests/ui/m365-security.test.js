// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Microsoft 365 Security (m365-security.html + vendor/zyb-m365sec.js) against the REAL SIEM module (engine/collect/m365-security.js)
// with a SYNTHETIC Graph snapshot: KPI tiles that open their tab, the admin-without-MFA action first with its Microsoft link, the
// Secure Score ring and weakest controls, people ranked with every point in the drawer, the detection + alert chain, Defender
// alerts filtered by severity, Conditional Access baseline by name, MFA admins first, a dataset not read names its permission and
// never reads 0, a hostile alert title stays text, CSV export, a viewer sees counts only, the portal view redirects, menu + installer.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node m365-security.test.js
const http = require('http'), fs = require('fs'), os = require('os'), path = require('path');
const DASH = path.resolve(__dirname, '../../ui');
const SIEM = process.env.SENTRA_SIEM || path.resolve(__dirname, '../..', 'backend', 'siem');
const M = require(path.join(SIEM, 'engine/collect/m365-security'));
const { createState } = require(path.join(SIEM, 'engine/soc/state'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const XSS = '<img src=x onerror="window.__xss=1">';
const D = 86400000, iso = (ms) => new Date(Date.now() - ms).toISOString(), okb = (data) => ({ ok: true, data });
const SNAP = { configured: true, updated: iso(0), signinsOk: true,
  blocks: { secureScore: { ok: true }, mfa: { ok: true }, riskyUsers: { ok: true }, riskDetections: { ok: true }, conditionalAccess: { ok: true }, defenderAlerts: { ok: true }, signins: { ok: false, perm: 'AuditLog.Read.All', error: 'permission not granted' } },
  signins: [],
  security: {
    secureScore: okb({ current: 41.5, max: 100, lowest: [{ name: 'MFARegistrationV2', cat: 'Identity', score: 0 }] }),
    mfa: okb({ users: 50, registered: 45, notRegistered: [{ name: 'Admin Syn', upn: 'admin.syn@as.test', admin: true }, { name: 'Omar Syn', upn: 'omar.syn@as.test' }] }),
    riskyUsers: okb([{ name: 'Omar Syn', upn: 'omar.syn@as.test', level: 'high', state: 'atRisk' }]),
    riskDetections: okb([{ when: iso(5 * 3600000), upn: 'omar.syn@as.test', type: 'impossibleTravel', level: 'high', state: 'atRisk', ip: '198.51.100.7', city: 'Lagos', country: 'NG' }]),
    conditionalAccess: okb([{ name: 'Require MFA for administrators', state: 'enabledForReportingButNotEnforced', modified: iso(60 * D) }, { name: 'Block legacy authentication', state: 'enabled', modified: iso(2 * D) }]),
    defenderAlerts: okb([{ created: iso(2 * 3600000), title: XSS, category: 'Exfiltration', severity: 'high', status: 'new', product: 'microsoftDefenderForOffice365', user: 'omar.syn@as.test' }, { created: iso(9 * D), title: 'Low thing', category: 'Other', severity: 'low', status: 'new', product: 'x', user: '' }]),
  } };

(async () => {
  const state = await createState({ dir: fs.mkdtempSync(path.join(os.tmpdir(), 'm365s-p-')) });
  const R = []; M.register({ route: (m, p, h) => R.push({ m, p, h }) }, { state, config: {}, log: { info() {}, warn() {}, error() {} }, m365Graph: { data: () => SNAP } });
  let ROLE = 'analyst', asked = 0;
  const srv = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://x'), json = (c, b2) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b2)); };
    if (u.pathname === '/dashboards/whoami.json') return json(200, { user: 'nora.syn', role: ROLE });
    if (u.pathname === '/api/soc/m365/insights/ask') { asked++; return json(200, { answer: 'Look at ' + XSS + ' first', steps: [] }); }
    const r = R.find((x) => x.m === req.method && x.p === u.pathname);
    if (r) { const RANK = { viewer: 0, analyst: 1, operator: 2, admin: 3 }, out = {}; const ctx = { role: ROLE, user: 'nora.syn', body: {}, params: {}, query: {}, need(x) { if (RANK[ROLE] < RANK[x]) { out.c = 403; return false; } return true; }, audit() {}, fail(c, m) { out.c = c; out.e = m; }, ok: (x) => x };
      Promise.resolve(r.h(ctx)).then((rv) => (out.c ? json(out.c, { error: out.e }) : json(200, rv))); return; }
    if (u.pathname.startsWith('/api/')) return json(404, { error: 'not found' });
    const f = path.join(DASH, u.pathname.replace(/^\/dashboards\//, '/')); if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (err, d) => { if (err) { res.writeHead(404); res.end(); return; } res.writeHead(200, { 'Content-Type': u.pathname.endsWith('.js') ? 'application/javascript' : u.pathname.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port + '/dashboards/m365-security.html?standalone=1';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright'); const browser = await chromium.launch(), errs = [];
  const wait = (p, fn, arg) => p.waitForFunction(fn, arg, { timeout: 15000 }).then(() => true, () => false);
  try {
    const ctx = await browser.newContext({ viewport: { width: 1500, height: 1000 }, acceptDownloads: true });
    let p = await ctx.newPage(); p.on('pageerror', (x) => errs.push(x.message));
    await p.goto(base);
    ok(await wait(p, () => !document.getElementById('main').hidden), 'page loads');
    ok(/administrator account\(s\) without MFA/.test(await p.$eval('#acts .act', (x) => x.textContent)), 'admins without MFA is the first action');
    ok(await p.$eval('#acts .act a', (a) => a.href.startsWith('https://entra.microsoft.com/') && a.rel.includes('noopener')), 'the action opens the Microsoft page');
    ok(/41\.5%/.test(await p.textContent('#score')) && /MFARegistrationV2/.test(await p.textContent('#score')), 'Secure Score ring and weakest controls');
    ok(/1/.test(await p.$eval('[data-go="chains"] .au-num', (x) => x.textContent)), 'one detection + alert chain');
    // people
    ok(/omar\.syn@as\.test/.test(await p.$eval('#tb tbody tr', (r) => r.textContent)), 'the person where signals agree is first');
    await p.click('#tb tr[data-person="omar.syn@as.test"] td:nth-child(2)');
    ok(await wait(p, () => /Entra ID user risk high/.test(document.getElementById('zd').textContent) && /open Defender alert/.test(document.getElementById('zd').textContent) && /Impossible travel/.test(document.getElementById('zd').textContent)), 'the drawer lists every point, the alert and the detection');
    ok(await p.evaluate(() => !window.__xss) && /<img/.test(await p.textContent('#zd')), 'a hostile alert title stays text');
    await p.evaluate(() => window.zybDetail.close());
    // tiles open tabs
    await p.click('[data-go="chains"]'); ok(await wait(p, () => /Impossible travel/.test(document.getElementById('tb').textContent) && /3 h/.test(document.getElementById('tb').textContent)), 'chains tab: detection and alert 3 h apart');
    await p.click('[data-go="alerts"]'); ok(await wait(p, () => document.querySelectorAll('#tb tbody tr').length === 2), 'alerts tab');
    await p.click('[data-sev="high"]'); ok(await wait(p, () => document.querySelectorAll('#tb tbody tr').length === 1), 'severity filter');
    await p.click('[data-go="access"]'); ok(await wait(p, () => /only report-only: "Require MFA for administrators"/.test(document.getElementById('tb').textContent) && /by name only/.test(document.getElementById('tb').textContent)), 'Conditional Access baseline by name');
    await p.click('[data-go="mfa"]'); ok(await wait(p, () => /90%/.test(document.getElementById('tb').textContent) && /admin\.syn@as\.test/.test(document.getElementById('tb').textContent)), 'MFA tab with admins first');
    await p.click('[data-go="coverage"]'); ok(await wait(p, () => /not read/.test(document.getElementById('tb').textContent) && /AuditLog\.Read\.All/.test(document.getElementById('tb').textContent)), 'a dataset not read names its permission');
    const [dl] = await Promise.all([p.waitForEvent('download'), p.click('#csv')]); ok(/^m365-security-\d{4}-\d\d-\d\d\.csv$/.test(dl.suggestedFilename()), 'CSV export');
    await p.fill('#af-q', 'Which accounts first?'); await p.click('#af button[type=submit]');
    ok(await wait(p, () => /Look at/.test(document.getElementById('aa').textContent)) && asked === 1 && await p.evaluate(() => !window.__xss), 'the analyst answers, escaped');
    // a viewer
    ROLE = 'viewer'; p = await ctx.newPage(); p.on('pageerror', (x) => errs.push(x.message)); await p.goto(base + '&v=2');
    ok(await wait(p, () => !document.getElementById('main').hidden && /names are shown to analysts and above/.test(document.getElementById('tb').textContent)), 'a viewer sees counts only');
    ok(!/omar\.syn/.test(await p.textContent('main')) && await p.$eval('#askc', (x) => x.hidden), 'no name and no analyst for a viewer');
    // not connected
    const keep = SNAP.configured; SNAP.configured = false; ROLE = 'analyst'; p = await ctx.newPage(); p.on('pageerror', (x) => errs.push(x.message)); await p.goto(base + '&v=3');
    ok(await wait(p, () => /not connected/.test(document.getElementById('acts').textContent)), 'not connected says what to do'); SNAP.configured = keep;
    const nav = fs.readFileSync(path.join(DASH, 'vendor', 'zyb-nav.js'), 'utf8'), inst = fs.readFileSync(path.join(DASH, 'install-dashboards.sh'), 'utf8'), menu = fs.readFileSync(path.join(DASH, 'vendor', 'zyb-menu.js'), 'utf8'), early = fs.readFileSync(path.join(DASH, 'vendor', 'zyb-early.js'), 'utf8');
    ok(/"h": "m365-security\.html"/.test(nav) && / m365-security\.html /.test(inst) && /zyb-m365sec\.js/.test(inst), 'menu entry and installer');
    ok(/m365sec: 'm365-security\.html'/.test(menu) && /m365sec: 'm365-security\.html'/.test(early) && /m365sec: \['\/dashboards\/m365-security\.html'/.test(menu), 'the portal M365 Security view opens this page');
    ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  } finally { await browser.close(); srv.close(); }
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n);
  process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
