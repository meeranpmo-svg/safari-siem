// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Menu hide / show and full screen (vendor/zyb-fullview.js) on the REAL portal (repos/live/portal + our menu
// scripts) and on a dashboard page: Ctrl+B and ☰ hide / show the menu and the content takes the full width; the choice
// survives a reload; ⛶ hides the menu for full screen; Ctrl+B inside a text field is left to the field; the menu's
// scrollbar is visible and the wheel stays in the menu; a dashboard page gets ☰ / ⛶ and a ☰ to bring a hidden menu back.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node menu-fullview.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const LIVE = path.resolve(__dirname, '../../repos/live/portal'), DASH = path.resolve(__dirname, '../../ui');
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
(async () => {
  const srv = http.createServer((req, res) => {
    const u = decodeURIComponent(req.url.split('?')[0]), json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u === '/dashboards/whoami.json' || u === '/auth/whoami') return json(200, { user: 'syed', role: 'admin' });
    if (u.startsWith('/api/soc/ui/menu')) return json(200, { order: null, favorites: [], can_edit_order: true });
    if (u.startsWith('/api/')) return json(404, { error: 'not in this test' });
    const f = u.startsWith('/dashboards/') ? path.join(DASH, u.slice(12)) : u === '/' ? path.join(LIVE, 'index.html') : path.join(LIVE, u);
    if (!f.startsWith(DASH) && !f.startsWith(LIVE)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (e, d) => { if (e) { res.writeHead(404); return res.end(); } res.writeHead(200, { 'Content-Type': f.endsWith('.js') ? 'application/javascript' : f.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port;
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright'); const browser = await chromium.launch(); const errs = [];
  try {
    if (fs.existsSync(path.join(LIVE, 'index.html'))) {
      const ctx = await browser.newContext({ viewport: { width: 1366, height: 768 } }), p = await ctx.newPage(); p.on('pageerror', (e) => errs.push('portal: ' + e.message));
      await p.goto(base + '/'); await p.waitForSelector('li.zyb-area', { state: 'attached', timeout: 20000 }); await p.waitForSelector('[data-zyb-fv="full"]', { timeout: 10000 });
      const st = () => p.evaluate(() => { const s = document.querySelector('aside.side'); return { hidden: document.body.classList.contains('nav-hidden'), side: getComputedStyle(s).display, main: Math.round((document.querySelector('.main') || document.querySelector('main') || document.body).getBoundingClientRect().width), sb: getComputedStyle(s).scrollbarWidth, os: getComputedStyle(s).overscrollBehaviorY }; });
      let s = await st(); ok(!s.hidden && s.side !== 'none', 'portal: menu shown at first');
      ok(s.sb === 'auto' && s.os === 'contain', 'portal: a full-width scrollbar and the wheel stays in the menu: ' + JSON.stringify(s));
      await p.keyboard.press('Control+b'); await p.waitForTimeout(300); s = await st();
      ok(s.hidden && s.side === 'none' && s.main >= 1300, 'portal: Ctrl+B hides the menu, content full width: ' + JSON.stringify(s));
      await p.reload(); await p.waitForSelector('[data-zyb-fv="full"]', { timeout: 20000 }); s = await st(); ok(s.hidden, 'portal: hidden after a reload (remembered)');
      ok(/Show the menu \(Ctrl\+B\)/.test(await p.getAttribute('#navToggle', 'title')), 'portal: ☰ says what it does and the shortcut');
      await p.click('#navToggle'); await p.waitForTimeout(300); s = await st(); ok(!s.hidden && s.side !== 'none', 'portal: ☰ brings the menu back');
      await p.click('[data-zyb-fv="full"]'); await p.waitForTimeout(400); s = await st(); ok(s.hidden, 'portal: ⛶ hides the menu for full screen');
      await p.evaluate(() => document.fullscreenElement && document.exitFullscreen()); await p.waitForTimeout(300);
      // a dashboard shown inside the portal: Ctrl+B pressed in the dashboard hides / shows the portal's menu
      await p.goto(base + '/?zybdash=' + encodeURIComponent('infra-manager.html')); await p.waitForSelector('iframe', { state: 'attached', timeout: 20000 }); await p.waitForTimeout(3000);
      const fr = p.frames().find((f) => /infra-manager\.html/.test(f.url()));
      if (fr) { await fr.waitForFunction(() => !!window.zybFullview, null, { timeout: 10000 }).catch(() => {}); const was = (await st()).hidden; await fr.evaluate(() => document.body.focus()); await p.keyboard.press('Control+b'); await p.waitForTimeout(400);
        ok((await st()).hidden === !was, 'portal: Ctrl+B inside a dashboard shown in the portal toggles the portal menu'); }
      else ok(false, 'the dashboard did not open inside the portal');
      await ctx.close();
    } else console.log('(portal part skipped: repos/live/portal not present)');

    const ctx2 = await browser.newContext({ viewport: { width: 1366, height: 768 } }), d = await ctx2.newPage(); d.on('pageerror', (e) => errs.push('dash: ' + e.message));
    await d.goto(base + '/dashboards/infra-manager.html?standalone=1'); await d.waitForSelector('#zyb-bar [data-zyb-fv="menu"]', { timeout: 15000 });
    const ds = () => d.evaluate(() => ({ hidden: document.body.classList.contains('zyb-side-hidden'), side: getComputedStyle(document.getElementById('zyb-side')).display, pad: parseInt(getComputedStyle(document.body).paddingLeft, 10) || 0, open: getComputedStyle(document.getElementById('zyb-fv-open')).display }));
    let x = await ds(); ok(!x.hidden && x.side !== 'none' && x.pad > 0 && x.open === 'none', 'dashboard: menu shown, no reopen button: ' + JSON.stringify(x));
    await d.click('#zyb-bar [data-zyb-fv="menu"]'); await d.waitForTimeout(300); x = await ds();
    ok(x.hidden && x.side === 'none' && x.pad === 0 && x.open !== 'none', 'dashboard: ☰ hides the menu, content full width, ☰ to bring it back: ' + JSON.stringify(x));
    await d.click('#zyb-fv-open'); await d.waitForTimeout(300); x = await ds(); ok(!x.hidden && x.side !== 'none', 'dashboard: the floating ☰ brings it back');
    await d.keyboard.press('Control+b'); await d.waitForTimeout(200); ok((await ds()).hidden, 'dashboard: Ctrl+B hides');
    await d.reload(); await d.waitForSelector('#zyb-bar [data-zyb-fv="menu"]', { state: 'attached' }); await d.waitForTimeout(300); ok((await ds()).hidden, 'dashboard: remembered after a reload');
    await d.keyboard.press('Control+b'); await d.waitForTimeout(200); ok(!(await ds()).hidden, 'dashboard: Ctrl+B shows it again');
    await d.evaluate(() => { const i = document.createElement('input'); i.id = 'tf'; document.body.appendChild(i); }); await d.focus('#tf'); await d.keyboard.press('Control+b'); await d.waitForTimeout(200);
    ok(!(await ds()).hidden, 'dashboard: Ctrl+B inside a text field is left to the field');
    ok(await d.evaluate(() => getComputedStyle(document.querySelector('#zyb-side .zs-nav')).overscrollBehaviorY === 'contain'), 'dashboard: the menu wheel never scrolls the page');
    await ctx2.close();
    ok(!errs.length, 'no page errors: ' + errs.slice(0, 3).join(' | '));
  } finally { await browser.close(); srv.close(); }
  console.log(bad ? 'FAILED ' + bad + '/' + n + ' checks' : 'OK ' + n + '/' + n + ' checks'); process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
