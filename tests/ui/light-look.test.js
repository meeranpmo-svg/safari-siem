// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// The "Light look" company switch drives the platform theme on every dashboard (vendor/zyb-dash.js): turning it on makes the whole
// page light (data-zyb-theme=light, white body and menu), not just the accents - the bug was the page staying dark. The dark look
// only steps back from light; a Dark or Midnight theme the person chose is left alone.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node light-look.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const DASH = path.resolve(__dirname, '../../ui');
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
(async () => {
  const srv = http.createServer((q, r) => { const u = decodeURIComponent(q.url.split('?')[0]), j = (c, o) => { r.writeHead(c, { 'Content-Type': 'application/json' }); r.end(JSON.stringify(o)); };
    if (u.endsWith('whoami.json')) return j(200, { user: 's', role: 'admin' }); if (u.startsWith('/api/')) return j(404, {});
    fs.readFile(path.join(DASH, u.replace(/^\/dashboards\//, '/')), (e, d) => { if (e) { r.writeHead(404); return r.end(); } r.writeHead(200, { 'Content-Type': u.endsWith('.js') ? 'application/javascript' : u.endsWith('.css') ? 'text/css' : 'text/html' }); r.end(d); }); });
  await new Promise((res) => srv.listen(0, '127.0.0.1', res));
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright'); const browser = await chromium.launch(), errs = [];
  const lum = (c) => { const m = (c.match(/\d+/g) || []).map(Number); return 0.2126 * m[0] + 0.7152 * m[1] + 0.0722 * m[2]; };
  const state = async (pre) => {
    const ctx = await browser.newContext({ viewport: { width: 1200, height: 800 } });
    await ctx.addInitScript((p) => { try { for (const k in p) localStorage.setItem(k, p[k]); } catch (e) { /* */ } }, pre);
    const p = await ctx.newPage(); p.on('pageerror', (e) => errs.push(e.message));
    await p.goto('http://127.0.0.1:' + srv.address().port + '/dashboards/ops-command.html'); await p.waitForTimeout(1200);
    const s = await p.evaluate(() => ({ cls: document.documentElement.className, theme: document.documentElement.getAttribute('data-zyb-theme'),
      body: getComputedStyle(document.body).backgroundColor, side: getComputedStyle(document.getElementById('zyb-side')).backgroundColor }));
    await ctx.close(); return s;
  };
  // light look on: the dashboard is fully light (theme light, white body and menu)
  let s = await state({ 'zyb-dash-prefs': JSON.stringify({ brand: 'org', brandLook: 'light' }) });
  ok(s.theme === 'light' && /org-light/.test(s.cls), 'light look -> the light theme on a dashboard: ' + JSON.stringify({ t: s.theme, l: /org-light/.test(s.cls) }));
  ok(lum(s.body) > 230 && lum(s.side) > 230, 'light look -> white page and menu (the bug was a dark page): body ' + s.body + ' menu ' + s.side);
  // dark look: the page is dark
  s = await state({ 'zyb-dash-prefs': JSON.stringify({ brand: 'org', brandLook: 'dark' }) });
  ok(s.theme !== 'light' && lum(s.body) < 60, 'dark look -> a dark page: ' + s.theme + ' ' + s.body);
  // a Midnight theme the person chose is left alone by the dark look (not clobbered to plain dark)
  s = await state({ 'zyb-dash-prefs': JSON.stringify({ brand: 'org', brandLook: 'dark' }), 'noc_theme': 'midnight' });
  ok(s.theme === 'midnight', 'the dark look does not override a chosen Midnight theme: ' + s.theme);
  // the platform Light theme, chosen directly, still makes the company look light (the other direction)
  s = await state({ 'noc_theme': 'light', 'zyb-dash-prefs': JSON.stringify({ brand: 'org' }) });
  ok(s.theme === 'light' && /org-light/.test(s.cls), 'the Light theme chosen directly -> the light company look: ' + JSON.stringify({ t: s.theme, l: /org-light/.test(s.cls) }));
  // the brand banner on a Tabler-style page in the light look: every word on it is light (the bug was dark blue on blue)
  { const ctx = await browser.newContext({ viewport: { width: 1300, height: 800 } });
    await ctx.addInitScript(() => { try { localStorage.setItem('zyb-dash-prefs', JSON.stringify({ brand: 'org', brandLook: 'light' })); } catch (e) { /* */ } });
    const p = await ctx.newPage(); await p.goto('http://127.0.0.1:' + srv.address().port + '/dashboards/connections.html'); await p.waitForTimeout(1200);
    const dark = await p.evaluate(() => { const h = document.querySelector('.page-header'); if (!h) return ['no banner'];
      const out = []; for (const el of h.querySelectorAll('*')) { if (el.closest('button,.btn,svg')) continue; let t = ''; for (const n of el.childNodes) if (n.nodeType === 3) t += n.nodeValue; if (!t.trim()) continue;
        const m = (getComputedStyle(el).color.match(/[\d.]+/g) || []).map(Number); const L = 0.2126 * m[0] + 0.7152 * m[1] + 0.0722 * m[2]; if (L < 180) out.push(t.trim().slice(0, 30) + ' ' + getComputedStyle(el).color); }
      return out; });
    ok(!dark.length, 'light look: every word on the brand banner is light: ' + dark.join(' | ')); await ctx.close(); }
  ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  await browser.close(); srv.close();
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks'); process.exit(bad ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });
