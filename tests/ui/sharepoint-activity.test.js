// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for SharePoint & OneDrive's Activity tab (sharepoint.html + vendor/zyb-spo.js) against the REAL SIEM modules
// (engine/collect/m365-files-activity.js and m365-files-insights.js) over SYNTHETIC unified-audit events: the two tabs (content and
// activity, #activity opens activity - where the old portal page now lands), KPIs, a mass download against the user's own week, an
// after-hours change, external and anonymous sharing with the target, anonymous links used, the per-day chart labelled, the scope
// filter and search, a hostile file name stays text, a viewer is told why it sees no names, the menu has ONE SharePoint & OneDrive
// (the portal's copy is hidden and redirects here), phone width, no page errors.
// Run: SENTRA_SIEM_DIR=/home/user/sentra-siem PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node sharepoint-activity.test.js
const http = require('http'), fs = require('fs'), path = require('path'), os = require('os');
const SIEM = process.env.SENTRA_SIEM_DIR || path.resolve(__dirname, '../../backend/siem');
const DASH = path.resolve(__dirname, '../../ui');
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const ACT = require(path.join(SIEM, 'engine/collect/m365-files-activity')), FI = require(path.join(SIEM, 'engine/collect/m365-files-insights'));
const { createState } = require(path.join(SIEM, 'engine/soc/state'));
const { fakeApi } = require(path.join(SIEM, 'tests/soc-fakes'));
const { parse } = require(path.join(SIEM, 'engine/api/query'));
const XSS = '<img src=x onerror=window.__sx=1>.xlsx';

(async () => {
  const NOW = Date.now(), H = 3600e3, DAY = 24 * H;
  const e = (o) => Object.assign({ src_type: 'm365', host: 'sharepoint', user: 'syn.lina@corp.example', event_code: 'FileAccessed', ts: NOW - H, fields: { SourceFileName: 'report.xlsx', SiteUrl: 'https://tenant.example/sites/finance-syn' } }, o);
  const EV = [e({ user: 'syn.omar@corp.example' }),
    e({ event_code: 'AnonymousLinkCreated', fields: { SourceFileName: XSS, SiteUrl: 'https://tenant.example/sites/hr-syn' } }),
    e({ event_code: 'SharingInvitationCreated', fields: { SourceFileName: 'claims-syn.docx', TargetUserOrGroupName: 'partner@outside.example', TargetUserOrGroupType: 'Member' } }),
    e({ event_code: 'CompanyLinkCreated', fields: { SourceFileName: 'memo-syn.docx' } }),
    e({ event_code: 'AnonymousLinkUsed', user: 'anonymous', fields: { SourceFileName: XSS } })];
  for (let i = 0; i < 70; i++) EV.push(e({ event_code: 'FileDownloaded', ts: NOW - 2 * H + i * 20000, fields: { SourceFileName: 'f' + i + '.pdf', SiteUrl: 'https://tenant.example/sites/hr-syn' } }));
  for (let i = 0; i < 22; i++) EV.push(e({ user: 'syn.omar@corp.example', ts: NOW - DAY + i * 60000 - ((new Date(NOW - DAY + 3 * H).getUTCHours() - 22) * H) }));   // 22:00 Riyadh yesterday
  const state = await createState({ dir: fs.mkdtempSync(path.join(os.tmpdir(), 'spoa-')) });
  const deps = { state, config: {}, log: { info() {}, warn() {}, error() {} }, m365Files: { data: () => ({ at: new Date().toISOString(), sources: [] }) },
    search: { fetchEvents: async (o) => { parse(o.q); return EV; } } };
  const api = fakeApi({ realRanks: true }); ACT.register(api, deps); FI.register(api, deps);
  let WHO = { user: 'nora.syn', role: 'analyst' };
  const srv = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://x'), json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u.pathname === '/dashboards/whoami.json') return json(200, WHO);
    if (u.pathname.startsWith('/api/soc/')) { api.call(req.method, u.pathname + u.search, { role: WHO.role, user: WHO.user }).then((r) => json(r.status, r.body)); return; }
    if (u.pathname.startsWith('/api/')) return json(404, { error: 'not in this test' });
    const f = path.join(DASH, u.pathname.replace(/^\/dashboards\//, '/')); if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (err, d) => { if (err) { res.writeHead(404); res.end(); return; } res.writeHead(200, { 'Content-Type': u.pathname.endsWith('.js') ? 'application/javascript' : u.pathname.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port + '/dashboards/sharepoint.html?standalone=1';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright'); const browser = await chromium.launch(), errs = [];
  const wait = (p, fn, arg) => p.waitForFunction(fn, arg === undefined ? null : arg, { timeout: 15000 }).then(() => true, () => false);
  const T = (p, id) => p.textContent('#' + id);
  try {
    const p = await browser.newPage({ viewport: { width: 1500, height: 1100 } }); p.on('pageerror', (x) => errs.push(x.message));
    await p.goto(base + '#activity');
    ok(/SharePoint & OneDrive/.test(await p.title()) && /SharePoint & OneDrive/.test(await p.textContent('.page-title')), 'named SharePoint & OneDrive');
    ok(await wait(p, () => !document.getElementById('amain').hidden && document.body.classList.contains('sp-act')), '#activity opens the Activity tab');
    ok(await p.evaluate(() => getComputedStyle(document.getElementById('main')).display === 'none'), 'the content tab is out of the way');
    const k = (await T(p, 'akpis')).replace(/\s+/g, ' ');
    ok(/1\s*mass downloads/.test(k) && /2\s*external \/ anonymous shares/.test(k) && /1\s*anonymous link uses/.test(k), 'KPIs: ' + k);
    ok(/syn\.lina@corp\.example/.test(await T(p, 'adl')) && /70 downloads in one hour with no download history/.test(await T(p, 'adl')), 'mass download with the reason');
    ok(/syn\.omar@corp\.example/.test(await T(p, 'aah')) && /outside Riyadh working hours/.test(await T(p, 'aah')), 'after-hours change');
    const ex = await T(p, 'aext');
    ok(/partner@outside\.example/.test(ex) && /Outside the organisation/.test(ex) && /Anyone with the link/.test(ex), 'external and anonymous sharing with the target');
    ok(!(await p.$('#actw img')) && !(await p.evaluate(() => window.__sx)) && /<img src=x/.test(ex), 'a hostile file name stays text');
    ok(/File events per day/.test(await p.getAttribute('#aday [role=img]', 'aria-label')), 'per-day chart labelled');
    await p.selectOption('#ascope', 'organisation'); ok(/memo-syn\.docx/.test(await T(p, 'ashare')) && !/claims-syn/.test(await T(p, 'ashare')), 'scope filter');
    await p.selectOption('#ascope', ''); await p.fill('#aq', 'claims'); ok(/claims-syn/.test(await T(p, 'ashare')) && !/memo-syn/.test(await T(p, 'ashare')), 'search');
    // back to the content tab
    await p.click('[data-sptab="content"]'); ok(await p.evaluate(() => !document.body.classList.contains('sp-act') && location.hash === '#content'), 'content tab');
    // viewer
    WHO = { user: 'vera.syn', role: 'viewer' };
    const v = await browser.newPage({ viewport: { width: 1300, height: 900 } }); v.on('pageerror', (x) => errs.push(x.message));
    await v.goto(base + '#activity'); ok(await wait(v, () => /analysts and above \(PDPL\)/.test(document.getElementById('aerr').textContent)), 'a viewer is told why it sees no names'); await v.close();
    WHO = { user: 'nora.syn', role: 'analyst' };
    // one SharePoint & OneDrive in the menu: the portal's copy is hidden and redirects here
    const menu = fs.readFileSync(path.join(DASH, 'vendor/zyb-menu.js'), 'utf8');
    ok(/spo: 'sharepoint\.html#activity'/.test(menu) && /spo: \['\/dashboards\/sharepoint\.html', 'SharePoint & OneDrive'\]/.test(menu), 'the portal page redirects to the merged page and is hidden as a duplicate');
    const ph = await browser.newPage({ viewport: { width: 390, height: 900 } }); ph.on('pageerror', (x) => errs.push(x.message));
    await ph.goto(base + '#activity'); await wait(ph, () => !document.getElementById('amain').hidden);
    ok(await ph.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1), 'phone width: no sideways scroll: ' + (process.env.WIDE ? await require(process.env.WIDE)(ph) : '')); await ph.close();
    if (process.env.SHOT) { await p.click('[data-sptab="activity"]'); await p.waitForTimeout(500); await p.screenshot({ path: process.env.SHOT + '-spo-activity.png', fullPage: true }); }
  } finally { await browser.close(); srv.close(); }
  ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks'); process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
