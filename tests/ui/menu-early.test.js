// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// "When I refresh, the old pages come and go": the REAL portal (repos/live/portal) with our menu scripts, loaded
// with and without vendor/zyb-early.js in <head> (added by add-dashboards-menu.sh). Watched every 30 ms from the first
// paint: with the early script no replaced portal entry and no old menu layout is ever visible, a refresh on #sam goes
// straight to the live page without drawing the sample one, #assetreg opens ITAM Inventory; the early page maps equal
// zyb-menu.js; the installer's awk puts the tag right after <head>. Skips when the live copy is not in the repository.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node menu-early.test.js
const http = require('http'), fs = require('fs'), path = require('path'), os = require('os'), cp = require('child_process');
const LIVE = path.resolve(__dirname, '../../repos/live/portal'), DASH = path.resolve(__dirname, '../../ui');
if (!fs.existsSync(path.join(LIVE, 'index.html'))) { console.log('SKIP: repos/live/portal not present'); process.exit(0); }
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };

// 1. the page maps agree (one list of replaced pages, two files)
const early = fs.readFileSync(path.join(DASH, 'vendor/zyb-early.js'), 'utf8'), menu = fs.readFileSync(path.join(DASH, 'vendor/zyb-menu.js'), 'utf8');
const obj = (src, re) => { const m = re.exec(src); return m ? Function('return ' + m[1])() : null; };
const eLive = obj(early, /var LIVE = window\.ZYB_EARLY_LIVE = (\{[\s\S]*?\});/), mLive = obj(menu, /var LIVE = (\{[\s\S]*?\});/);
const mCov = obj(menu, /var COVERED = (\{[\s\S]*?\});/), eAlias = obj(early, /var ALIAS = window\.ZYB_EARLY_ALIAS = (\{[\s\S]*?\});/), mAlias = obj(menu, /var ALIAS = window\.ZYB_PORTAL_ALIAS = (\{[\s\S]*?\});/);
const replaced = Object.keys(mLive).filter((k) => mCov[k]);   // live pages that REPLACE a portal page
ok(JSON.stringify(Object.keys(eLive).sort()) === JSON.stringify(replaced.sort()) && replaced.every((k) => eLive[k] === mLive[k]), 'zyb-early LIVE = zyb-menu LIVE ∩ COVERED: ' + Object.keys(eLive).join(',') + ' vs ' + replaced.join(','));
ok(JSON.stringify(eAlias) === JSON.stringify(mAlias), 'zyb-early ALIAS = zyb-menu ALIAS');

// 2. the installer's line goes right after <head>
const sh = fs.readFileSync(path.join(DASH, 'add-dashboards-menu.sh'), 'utf8'), ELINE = /ELINE='([^']+)'/.exec(sh)[1];
const awk = /awk -v line="\$ELINE" '([^']+)'/.exec(sh)[1];
const tmp = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'zybearly-')), 'index.html'); fs.copyFileSync(path.join(LIVE, 'index.html'), tmp);
const patched = cp.execFileSync('awk', ['-v', 'line=' + ELINE, awk, tmp], { encoding: 'utf8' });
const hi = patched.search(/<head[ >]/i), ei = patched.indexOf(ELINE), ai = patched.indexOf('app.js?v=');
ok(hi >= 0 && ei > hi && ei < ai && patched.split(ELINE).length === 2, 'installer: the early tag right after <head>, before the portal code, once');

(async () => {
  let USE_EARLY = true;
  const srv = http.createServer((req, res) => {
    const u = decodeURIComponent(req.url.split('?')[0]), json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u === '/dashboards/whoami.json' || u === '/auth/whoami') return json(200, { user: 'syed', role: 'admin' });
    if (u.startsWith('/api/soc/ui/menu')) return setTimeout(() => json(200, { order: null, favorites: [], can_edit_order: true }), 400);
    if (u.startsWith('/api/')) return json(404, { error: 'not in this test' });
    if (u === '/') { res.writeHead(200, { 'Content-Type': 'text/html' }); return res.end(USE_EARLY ? patched : fs.readFileSync(path.join(LIVE, 'index.html'))); }
    const f = u.startsWith('/dashboards/') ? path.join(DASH, u.slice(12)) : path.join(LIVE, u);
    if (!f.startsWith(DASH) && !f.startsWith(LIVE)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (e, d) => { if (e) { res.writeHead(404); return res.end(); } res.writeHead(200, { 'Content-Type': f.endsWith('.js') ? 'application/javascript' : f.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port;
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright'); const browser = await chromium.launch();
  const REPL = Object.keys(eLive).concat(Object.keys(eAlias));
  // from the first paint, every 30 ms: is a replaced entry visible? is the old (un-arranged) menu visible? old sample page?
  const watch = (repl) => { window.__flash = { entry: [], oldMenu: 0, sample: 0 };
    const tick = () => { try {
      const nav = document.querySelector('ul.nav'); if (nav && getComputedStyle(nav).visibility !== 'hidden') {
        repl.forEach((v) => { const li = nav.querySelector('li[data-view="' + v + '"]'); if (li && li.offsetParent && !li.hasAttribute('data-zyb-start') && window.__flash.entry.indexOf(v) < 0) window.__flash.entry.push(v); });   // a Start here entry is kept on purpose: it opens the live page (checked below)
        if (!nav.querySelector('[data-zyb-menu="group"], li.zyb-area')) window.__flash.oldMenu++; }
      const vf = document.querySelector('#viewFocus'); if (vf && getComputedStyle(vf).visibility !== 'hidden' && vf.offsetParent && /SAMPLE TELEMETRY|SAMPLE DATA|SAMPLE HEALTH|SAMPLE CONTENT|Sample record/.test(vf.innerText)) window.__flash.sample++;
    } catch (e) { /* page still loading */ } };
    setInterval(tick, 30); document.addEventListener('DOMContentLoaded', tick); };
  const run = async (hash) => { const ctx = await browser.newContext({ viewport: { width: 1366, height: 768 } }); await ctx.addInitScript(watch, REPL); const p = await ctx.newPage(); const errs = []; p.on('pageerror', (e) => errs.push(e.message));
    await p.goto(base + '/' + (hash || '')); await p.waitForTimeout(6500);
    const f = await p.evaluate(() => ({ flash: window.__flash, url: location.pathname + location.search + location.hash, cur: typeof currentView !== 'undefined' ? currentView : '', iframe: (() => { const fr = document.querySelector('iframe'); try { return fr && fr.offsetParent ? fr.contentWindow.location.pathname : ''; } catch (e) { return ''; } })() }));   // eslint-disable-line no-undef
    await ctx.close(); return Object.assign(f, { errs }); };
  try {
    USE_EARLY = false; const before = await run();
    ok(before.flash.entry.length || before.flash.oldMenu, 'without the early script the old entries / menu do flash (the reported problem): ' + JSON.stringify(before.flash));
    USE_EARLY = true; const after = await run();
    ok(!after.flash.entry.length, 'refresh: no replaced portal entry is ever visible: ' + after.flash.entry.join(','));
    ok(after.flash.oldMenu === 0, 'refresh: the old (un-arranged) menu is never shown: ' + after.flash.oldMenu + ' ticks');
    ok(!after.errs.length, 'no page errors: ' + after.errs.slice(0, 3).join(' | '));
    { // Start here no longer repeats Asset Discovery (it lives under IT Assets -> Discovery); the portal address #discovery still opens the live Discovery Studio
      const ctx = await browser.newContext({ viewport: { width: 1366, height: 768 } }); const p = await ctx.newPage(); await p.goto(base + '/?zybportal=1'); await p.waitForTimeout(4000);
      const li = await p.$('ul.nav li[data-view="discovery"][data-zyb-start]');
      ok(!li, 'Start here does not repeat Asset Discovery');
      await ctx.close();
      const d = await run('#discovery');
      ok(/discovery-studio\.html/.test(d.url + (d.iframe || '')), '#discovery opens the live Discovery Studio: ' + JSON.stringify({ url: d.url, iframe: d.iframe }));
    }
    USE_EARLY = false; const samOld = await run('#sam');
    console.log('(without the early script, #sam: ' + JSON.stringify(samOld.flash) + ')');   // timing-dependent: shown, not asserted
    USE_EARLY = true; const sam = await run('#sam');
    ok(sam.flash.sample === 0 && /zybdash=apm\.html/.test(sam.url) && /apm\.html/.test(sam.iframe), 'refresh on #sam: straight to the live Applications Manager, the sample page never drawn: ' + JSON.stringify({ url: sam.url, iframe: sam.iframe, flash: sam.flash }));
    // the portal's own old User Management view goes to the new User Management page
    const usr = await run('#users');
    ok(/zybdash=user-management\.html/.test(usr.url) && /user-management\.html/.test(usr.iframe || ''), 'refresh on #users: the new User Management page, not the portal\'s old one: ' + JSON.stringify({ url: usr.url, iframe: usr.iframe }));
    // the portal's sample Executive Command Center / Risk Posture go to the live pages that already do the job
    const cmd = await run('#command');
    ok(cmd.flash.sample === 0 && /zybdash=executive-dashboard\.html/.test(cmd.url) && /executive-dashboard\.html/.test(cmd.iframe), 'refresh on #command: the live Executive Dashboard, no sample: ' + JSON.stringify({ url: cmd.url, iframe: cmd.iframe }));
    const pos = await run('#posture');
    ok(pos.flash.sample === 0 && /zybdash=risk-command\.html/.test(pos.url) && /risk-command\.html/.test(pos.iframe), 'refresh on #posture: the live Risk Command Center (posture score), no sample: ' + JSON.stringify({ url: pos.url, iframe: pos.iframe }));
    const ar = await run('#assetreg');
    ok(ar.cur === 'itam-assets' && ar.flash.sample === 0, 'refresh on #assetreg: ITAM Inventory, no sample record: ' + JSON.stringify({ cur: ar.cur, flash: ar.flash }));
    // the portal's own address lands on the platform home; "Portal home" (?zybportal=1) still opens the portal itself
    ok(/zybdash=index\.html/.test(after.url) && /index\.html/.test(after.iframe), 'a plain / lands on the platform home: ' + JSON.stringify({ url: after.url, iframe: after.iframe }));
    const portal = await run('?zybportal=1');
    ok(!/zybdash=/.test(portal.url) && !portal.iframe, 'Portal home (?zybportal=1) opens the portal itself: ' + JSON.stringify({ url: portal.url, iframe: portal.iframe }));
  } finally { await browser.close(); srv.close(); }
  console.log(bad ? 'FAILED ' + bad + '/' + n + ' checks' : 'OK ' + n + '/' + n + ' checks'); process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
