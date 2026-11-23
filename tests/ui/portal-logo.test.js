// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// The old logos must never flash while the portal loads (bug: the portal's two big logo boxes were drawn first and replaced a
// moment later by zyb-menu.js's compact header, so the old logo "came and went" on every load). The REAL portal copy
// (repos/live/portal) with the early tag the installer adds after <head>; zyb-menu.js is slowed down on purpose so the
// gap is wide. Every 30 ms until the compact header is shown, no old logo may be visible; afterwards the header is visible
// and its logo is the inline one from zyb-brand.js (never a cached /logo.webp); the 5-second fallback never hides it for good.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node portal-logo.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const LIVE = path.resolve(__dirname, '../../repos/live/portal'), DASH = path.resolve(__dirname, '../../ui');
if (!fs.existsSync(path.join(LIVE, 'index.html'))) { console.log('SKIP: repos/live/portal not present'); process.exit(0); }
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
(async () => {
  let delayMenu = 1500, blockBrand = false;
  const srv = http.createServer((req, res) => { const u = decodeURIComponent(req.url.split('?')[0]); const json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u === '/dashboards/whoami.json' || u === '/auth/whoami') return json(200, { user: 'syed', role: 'admin' });
    if (u.startsWith('/api/soc/ui/menu')) return json(200, { order: null, favorites: [], can_edit_order: true });
    if (u.startsWith('/api/')) return json(404, { error: 'not in this test' });
    if (u === '/' || u === '/index.html') {   // as add-dashboards-menu.sh installs it: the early tag right after <head>
      const html = fs.readFileSync(path.join(LIVE, 'index.html'), 'utf8').replace(/<head([^>]*)>/i, (m) => m + '<script src="/dashboards/vendor/zyb-early.js"></script><!--ZYB-EARLY-->');
      res.writeHead(200, { 'Content-Type': 'text/html' }); return res.end(html);
    }
    if (blockBrand && u === '/dashboards/vendor/zyb-brand.js') { res.writeHead(404); return res.end(); }
    const f = u.startsWith('/dashboards/') ? path.join(DASH, u.slice(12)) : path.join(LIVE, u);
    if (!f.startsWith(DASH) && !f.startsWith(LIVE)) { res.writeHead(403); return res.end(); }
    const send = () => fs.readFile(f, (e, d) => { if (e) { res.writeHead(404); return res.end(); } res.writeHead(200, { 'Content-Type': f.endsWith('.js') ? 'application/javascript' : f.endsWith('.webp') ? 'image/webp' : 'text/html' }); res.end(d); });
    if (u === '/dashboards/vendor/zyb-menu.js') setTimeout(send, delayMenu); else send();
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright'); const browser = await chromium.launch();
  const base = 'http://127.0.0.1:' + srv.address().port + '/';
  try {
    const p = await browser.newPage({ viewport: { width: 1366, height: 768 } }); const errs = []; p.on('pageerror', (e) => errs.push(e.message));
    // sample from the first script on the page, before the portal draws anything
    await p.addInitScript(() => {
      window.__flash = []; window.__samples = 0;
      const tick = () => {
        const html = document.documentElement;
        if (!html) return setTimeout(tick, 5);
        if (!html.classList.contains('zyb-brand-on') && !document.getElementById('zyb-brand')) {
          window.__samples++;
          document.querySelectorAll('aside.side img').forEach((im) => {
            if (im.closest('#zyb-brand') || !/logo/i.test(im.getAttribute('src') || '')) return;
            const r = im.getBoundingClientRect(), cs = getComputedStyle(im);
            if (r.width > 0 && cs.visibility !== 'hidden' && !im.closest('[data-zyb-hidden]')) window.__flash.push(im.getAttribute('src'));
          });
          setTimeout(tick, 30);
        }
      };
      tick();
    });
    await p.goto(base);
    await p.waitForFunction(() => document.documentElement.classList.contains('zyb-brand-on') || document.getElementById('zyb-brand'), null, { timeout: 15000 }); await p.waitForTimeout(500);
    const st = await p.evaluate(() => { const b = document.getElementById('zyb-brand'), im = b && b.querySelector('img');
      return { flash: window.__flash, samples: window.__samples, brand: !!b, src: im ? im.getAttribute('src').slice(0, 22) : '', visible: !!(im && im.getBoundingClientRect().width > 0 && getComputedStyle(im).visibility !== 'hidden'),
        oldHidden: [...document.querySelectorAll('aside.side img')].filter((x) => !x.closest('#zyb-brand') && /logo/i.test(x.getAttribute('src') || '')).every((x) => !!x.closest('[data-zyb-hidden]')) }; });
    ok(st.samples >= 10, 'sampled the load (' + st.samples + ' frames while the menu script was still coming)');
    ok(!st.flash.length, 'no old logo was ever visible during the load: ' + [...new Set(st.flash)].join(', '));
    ok(st.brand && st.visible, 'the compact brand header is shown');
    ok(st.src === 'data:image/webp;base64', 'its logo is the inline one, not a cached file: ' + st.src);
    ok(st.oldHidden, 'the old logo boxes stay hidden');
    ok(!errs.length, 'no page errors: ' + errs.slice(0, 3).join(' | '));
    // zyb-brand.js unreachable: the file logo with the build stamp, still shown
    blockBrand = true; delayMenu = 0;
    const p2 = await browser.newPage({ viewport: { width: 1366, height: 768 } });
    await p2.goto(base); await p2.waitForFunction(() => document.documentElement.classList.contains('zyb-brand-on'), null, { timeout: 15000 });
    const s2 = await p2.evaluate(() => { const im = document.querySelector('#zyb-brand img'); return im ? im.getAttribute('src') : ''; });
    ok(/^\/logo\.webp\?v=/.test(s2), 'without zyb-brand.js: the logo file with a cache stamp: ' + s2);
    // the menu script never arrives: the early fallback shows the portal's own logos after 5 s
    delayMenu = 12000;
    const p3 = await browser.newPage({ viewport: { width: 1366, height: 768 } });
    await p3.goto(base, { waitUntil: 'commit' });
    const shown = await p3.waitForFunction(() => document.documentElement.classList.contains('zyb-brand-on'), null, { timeout: 8000 }).then(() => true, () => false);
    ok(shown, 'never hidden for good: the 5-second fallback shows the logos');
  } finally { await browser.close(); srv.close(); }
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks');
  process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
