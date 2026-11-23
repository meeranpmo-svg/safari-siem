// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// OneDrive & SharePoint (sharepoint.html + vendor/zyb-spo.js) against the REAL SIEM module (engine/collect/m365-files-insights.js)
// with a SYNTHETIC discovery result: KPIs that filter, actions ranked (anonymous link first), the sharing bar, sites ranked with
// coverage gaps, files ranked with every point in the detail, a site click filters its files, search, a hostile file name and a
// javascript: site URL stay harmless, CSV export, a viewer sees counts only, menu entry and installer.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node sharepoint.test.js
const http = require('http'), fs = require('fs'), os = require('os'), path = require('path');
const DASH = path.resolve(__dirname, '../../ui');
const SIEM = process.env.SENTRA_SIEM || path.resolve(__dirname, '../..', 'backend', 'siem');
const FI = require(path.join(SIEM, 'engine/collect/m365-files-insights'));
const { createState } = require(path.join(SIEM, 'engine/soc/state'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const D = 86400000, iso = (ms) => new Date(Date.now() - ms).toISOString();
const hit = (name, kinds, shared, ageDays, nameKinds, p) => ({ id: name, drive: 'd', name, path: p || '/HR/Payroll', size: 1000, modified: iso(ageDays * D), kinds, name_kinds: nameKinds || [], by: Object.keys(kinds).length ? 'content' : 'name', shared });
const SNAP = { at: new Date().toISOString(), sources: [
  { key: 'sp:hr', kind: 'sharepoint', label: 'HR (synthetic)', url: 'https://as.sharepoint.test/sites/hr', files_seen: 400, files_read: 300, files_unreadable: 1, errors: [],
    hits: [hit('medical-claims.xlsx', { national_id: 12, mobile: 9 }, 'anonymous', 10, ['health']), hit('salaries-2022.csv', { iban: 40 }, 'organization', 4 * 365), hit('cv-<img src=x onerror="window.__xss=1">.docx', {}, null, 20, ['cv'])] },
  { key: 'od:u1', kind: 'onedrive', label: 'OneDrive: nora.syn@as.test', url: 'javascript:alert(1)', files_seen: 50, files_read: 40, truncated: true, errors: ['Files.Read.All not granted'], hits: [hit('passport-scan.pdf', {}, 'external', 30, ['passport'], '/Documents')] }] };

(async () => {
  const state = await createState({ dir: fs.mkdtempSync(path.join(os.tmpdir(), 'spo-p-')) });
  const R = []; FI.register({ route: (m, p, h) => R.push({ m, p, h }) }, { state, config: {}, log: { info() {}, warn() {}, error() {} }, m365Files: { data: () => SNAP } });
  let ROLE = 'analyst', runs = 0;
  const srv = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://x'), json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u.pathname === '/dashboards/whoami.json') return json(200, { user: 'nora.syn', role: ROLE });
    if (u.pathname === '/api/soc/pii/sharepoint/run') { runs++; return json(200, { started: true }); }
    const r = R.find((x) => x.m === req.method && x.p === u.pathname);
    if (r) { const RANK = { viewer: 0, analyst: 1, operator: 2, admin: 3 }, out = {}; const ctx = { role: ROLE, user: 'nora.syn', body: {}, params: {}, query: {}, need(x) { if (RANK[ROLE] < RANK[x]) { out.c = 403; return false; } return true; }, audit() {}, fail(c, m) { out.c = c; out.e = m; }, ok: (x) => x };
      Promise.resolve(r.h(ctx)).then((rv) => (out.c ? json(out.c, { error: out.e }) : json(200, rv))); return; }
    if (u.pathname.startsWith('/api/')) return json(404, { error: 'not found' });
    const f = path.join(DASH, u.pathname.replace(/^\/dashboards\//, '/')); if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (err, d) => { if (err) { res.writeHead(404); res.end(); return; } res.writeHead(200, { 'Content-Type': u.pathname.endsWith('.js') ? 'application/javascript' : u.pathname.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port + '/dashboards/sharepoint.html?standalone=1';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright'); const browser = await chromium.launch(), errs = [];
  const wait = (p, fn, arg) => p.waitForFunction(fn, arg, { timeout: 20000 }).then(() => true, () => false);
  try {
    const ctx = await browser.newContext({ viewport: { width: 1500, height: 1000 }, acceptDownloads: true });
    let p = await ctx.newPage(); p.on('pageerror', (x) => errs.push(x.message));
    await p.goto(base);
    ok(await wait(p, () => !document.getElementById('main').hidden), 'page loads');
    ok(/anonymous link/.test(await p.$eval('#acts .act', (x) => x.textContent)), 'anonymous link is the first action');
    ok(await p.$$eval('[aria-label="sharing breakdown"] i', (L) => L.length) === 4, 'sharing bar: anonymous, external, organisation, unknown');
    ok(await p.$eval('#srcs tbody tr', (r) => /HR \(synthetic\)/.test(r.textContent)), 'the site holding the most exposure first');
    ok(/limit reached/.test(await p.textContent('#srcs')) && /Files\.Read\.All not granted/.test(await p.textContent('#srcs')), 'coverage gaps named');
    ok(!(await p.$('#srcs a[href^="javascript"]')), 'a javascript: site URL is not rendered as a link');
    ok(/medical-claims\.xlsx/.test(await p.$eval('#files tbody tr', (r) => r.textContent)), 'files ranked by exposure');
    ok(await p.evaluate(() => !window.__xss) && /<img/.test(await p.textContent('#files')), 'a hostile file name stays text');
    await p.click('[data-f="anonymous"]'); ok(await wait(p, () => document.querySelectorAll('#files tbody tr').length === 1), 'Anonymous tile filters files');
    await p.click('[data-f="anonymous"]'); await p.click('[data-f="old"]'); ok(await wait(p, () => document.querySelectorAll('#files tbody tr').length === 1 && /salaries-2022/.test(document.getElementById('files').textContent)), '3-year tile filters');
    await p.click('[data-f="old"]');
    await p.click('#srcs tr[data-src="od:u1"] td:nth-child(2)'); ok(await wait(p, () => document.querySelectorAll('#files tbody tr').length === 1 && /passport-scan/.test(document.getElementById('files').textContent)), 'a site click filters its files');
    await p.fill('#q', '');
    await p.dispatchEvent('#q', 'input');
    await p.click('#files tr[data-file] td:nth-child(2)');
    ok(await wait(p, () => /Exposure \d+ \/ 100/.test(document.body.textContent) && /anyone with the link/.test(document.body.textContent)), 'file detail lists every point');
    await p.evaluate(() => window.zybDetail.close());
    const [dl] = await Promise.all([p.waitForEvent('download'), p.click('#csv')]); ok(/^sharepoint-onedrive-\d{4}-\d\d-\d\d\.csv$/.test(dl.suggestedFilename()), 'CSV: ' + dl.suggestedFilename());
    ok(await p.$eval('#run', (b) => b.hidden), 'Read now is admin only');
    ROLE = 'viewer'; p = await ctx.newPage(); p.on('pageerror', (x) => errs.push(x.message)); await p.goto(base + '&v=2');
    ok(await wait(p, () => !document.getElementById('main').hidden && /analysts and above/.test(document.getElementById('files').textContent)), 'a viewer sees counts only');
    ok(!/medical-claims/.test(await p.textContent('main')), 'no file name for a viewer');
    ROLE = 'admin'; p = await ctx.newPage(); p.on('pageerror', (x) => errs.push(x.message)); await p.goto(base + '&v=3'); await wait(p, () => !document.getElementById('run').hidden);
    await p.click('#run'); ok(await wait(p, () => /Reading every site now/.test(document.body.textContent)) && runs === 1, 'Read now (admin)');
    const nav = fs.readFileSync(path.join(DASH, 'vendor', 'zyb-nav.js'), 'utf8'), inst = fs.readFileSync(path.join(DASH, 'install-dashboards.sh'), 'utf8');
    ok(/"h": "sharepoint\.html"/.test(nav) && / sharepoint\.html /.test(inst) && /zyb-spo\.js/.test(inst), 'menu entry and installer');
    ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  } finally { await browser.close(); srv.close(); }
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n);
  process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
