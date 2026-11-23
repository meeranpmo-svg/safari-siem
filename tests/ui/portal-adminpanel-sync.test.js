// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// The REAL portal Admin Panel (repos/live/portal) with the platform menu (zyb-early.js + zyb-menu.js + zyb-nav.js): the
// dashboards pages count in "Pages available" and on their module (Pipeline Health under SIEM & SOC, the IT Budget under Licences,
// renewals & cost); every workspace in the registry maps to a module of the catalogue; with "Licences, renewals & cost" switched off
// an operator no longer sees the IT Budget page in the menu and an administrator sees it locked. SYNTHETIC identities and settings.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node portal-adminpanel-sync.test.js
const http = require('http'), fs = require('fs'), path = require('path'), cp = require('child_process');
const LIVE = path.resolve(__dirname, '../../repos/live/portal'), DASH = path.resolve(__dirname, '../../ui');
if (!fs.existsSync(path.join(LIVE, 'index.html'))) { console.log('SKIP: repos/live/portal not present'); process.exit(0); }
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const SH = fs.readFileSync(path.join(DASH, 'add-dashboards-menu.sh'), 'utf8'), ELINE = /ELINE='([^']+)'/.exec(SH)[1], AWK = /awk -v line="\$ELINE" '([^']+)'/.exec(SH)[1];
const INDEX = cp.execFileSync('awk', ['-v', 'line=' + ELINE, AWK, path.join(LIVE, 'index.html')], { encoding: 'utf8' });
let WHO = { user: 'syed.syn', role: 'admin' }, ORG = { modules: null, resp: {}, updated: null };
(async () => {
  const srv = http.createServer((req, res) => {
    const u = decodeURIComponent(req.url.split('?')[0]), json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u === '/auth/whoami' || u === '/dashboards/whoami.json') return json(200, WHO);
    if (u === '/auth/org') return json(200, ORG);
    if (u.startsWith('/api/soc/ui/menu')) return json(200, { order: null, favorites: [], can_edit_order: true });
    if (u.startsWith('/api/') || u.startsWith('/auth/')) return json(404, { error: 'not in this test' });
    if (u === '/') { res.writeHead(200, { 'Content-Type': 'text/html' }); return res.end(INDEX); }
    const f = u.startsWith('/dashboards/') ? path.join(DASH, u.slice(12)) : path.join(LIVE, u);
    if (!f.startsWith(DASH) && !f.startsWith(LIVE)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (e, d) => { if (e) { res.writeHead(404); return res.end(); } res.writeHead(200, { 'Content-Type': f.endsWith('.js') ? 'application/javascript' : f.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port;
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright'); const browser = await chromium.launch(); const errs = [];
  const wait = (p, fn, a) => p.waitForFunction(fn, a === undefined ? null : a, { timeout: 25000 }).then(() => true, () => false);
  global.window = { ZYB_ORG: Object.assign({}, require('../../brand/index'), { frameworks_all: true }) }; eval(fs.readFileSync(path.join(DASH, 'vendor/zyb-nav.js'), 'utf8')); const NAV = window.ZYB_NAV;
  const portal = fs.readFileSync(path.join(LIVE, 'app.js'), 'utf8'), dm = /var DASHMOD = (\{[\s\S]*?\n  \});/.exec(portal)[1];
  const DASHMOD = Function('return ' + dm)(), CATIDS = [...portal.matchAll(/\['([a-z0-9-]+)', '[A-Z][^']+', '[^']+', '[^']+', \[/g)].map((x) => x[1]);
  ok(NAV.every((w) => DASHMOD[w.id]), 'every dashboard workspace maps to a module: ' + NAV.filter((w) => !DASHMOD[w.id]).map((w) => w.id).join(','));
  ok(Object.values(DASHMOD).every((m) => CATIDS.includes(m)), 'every mapped module exists in the catalogue: ' + Object.values(DASHMOD).filter((m) => !CATIDS.includes(m)).join(','));
  const open = async () => { const p = await (await browser.newContext({ viewport: { width: 1500, height: 1000 } })).newPage(); p.on('pageerror', (e) => errs.push(e.message));
    await p.goto(base + '/'); await wait(p, () => document.querySelector('.nav li[data-zyb-href*="budget.html"]') && typeof setView === 'function'); await p.waitForTimeout(800); return p; };   // eslint-disable-line no-undef
  try {
    let p = await open();
    await p.evaluate(() => setView('adminpanel'));   // eslint-disable-line no-undef
    ok(await wait(p, () => /Pages available/i.test(document.body.innerText) && /Modules on/i.test(document.body.innerText)), 'Admin Panel drawn');
    const pages = await p.evaluate(() => { const t = [...document.querySelectorAll('.x-tile, .x-tiles > *')].find((x) => /Pages available/i.test(x.innerText)); return t ? parseInt(t.innerText.replace(/[^\d]/g, ''), 10) : 0; });
    const total = NAV.reduce((s, w) => s + w.pages.length, 0);
    ok(pages >= 300, 'Pages available counts the dashboards (' + pages + ', dashboards ' + total + ')');
    const titles = await p.evaluate(() => [...document.querySelectorAll('[title]')].map((x) => x.getAttribute('title')).join('\n'));
    ok(/Pipeline Health/.test(titles) && /IT Budget/.test(titles), 'module page lists include the new pages');
    // Licences, renewals & cost switched off
    ORG = { modules: ['core-dash', 'core-admin', 'siem-core', 'itam'], resp: {}, updated: '2026-11-19T08:00:00Z' };
    WHO = { user: 'nora.syn', role: 'operator' };
    const o = await open(); await o.waitForTimeout(1500);
    const st = await o.evaluate(() => { const b = document.querySelector('.nav li[data-zyb-href*="budget.html"]'), ph = document.querySelector('.nav li[data-zyb-href*="pipeline-health.html"]'); return { b: b && b.classList.contains('ss-off'), ph: ph && ph.classList.contains('ss-off') }; });
    ok(st.b === true, 'operator: IT Budget hidden when its module is off'); ok(st.ph === false, 'operator: Pipeline Health (SIEM & SOC on) still shown');
    WHO = { user: 'syed.syn', role: 'admin' };
    const a = await open(); await a.waitForTimeout(1500);
    ok(await a.evaluate(() => { const b = document.querySelector('.nav li[data-zyb-href*="budget.html"]'); return b && b.classList.contains('ss-locked') && !b.classList.contains('ss-off') && !!b.querySelector('.ss-lock'); }), 'admin: IT Budget shown locked');
  } finally { await browser.close(); srv.close(); }
  ok(!errs.length, 'no page errors: ' + errs.slice(0, 3).join(' | '));
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks'); process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
