#!/usr/bin/env node
// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
// tools/fit-check.js [page.html,...] - // Loads every page at 1280, 1024, 768 and 390 px and reports the ones wider than the screen (horizontal page scroll) and the element that sticks out.
const http = require('http'), fs = require('fs'), path = require('path');
const D = '/home/user/safari-platform/ui';
const only = process.argv[2] ? process.argv[2].split(',') : null;
const pages = fs.readdirSync(D).filter((f) => f.endsWith('.html') && (!only || only.includes(f)));
const srv = http.createServer((q, r) => {
  const u = new URL(q.url, 'http://x');
  if (u.pathname.startsWith('/dashboards/whoami')) return r.end('{"user":"admin.syn","role":"admin"}');
  if (u.pathname.startsWith('/api/') || u.pathname.endsWith('.json')) { r.writeHead(200, { 'Content-Type': 'application/json' }); return r.end('{}'); }
  fs.readFile(path.join(D, u.pathname.replace(/^\/dashboards\//, '/')), (e, d) => { if (e) { r.writeHead(404); return r.end(); } r.writeHead(200, { 'Content-Type': u.pathname.endsWith('.js') ? 'application/javascript' : u.pathname.endsWith('.css') ? 'text/css' : 'text/html' }); r.end(d); });
});
srv.listen(0, async () => {
  const { chromium } = require('/opt/node22/lib/node_modules/playwright');
  const b = await chromium.launch(), out = [];
  for (const w of [1280, 1024, 768, 390]) {
    const ctx = await b.newContext({ viewport: { width: w, height: 800 } });
    for (const pg of pages) {
      const p = await ctx.newPage();
      try {
        await p.goto('http://127.0.0.1:' + srv.address().port + '/dashboards/' + pg, { timeout: 15000 }); await p.waitForTimeout(700);
        const r = await p.evaluate(() => { const W = document.documentElement.clientWidth, sw = document.documentElement.scrollWidth; if (sw <= W + 2) return null;
          let worst = null; for (const el of document.querySelectorAll('body *')) { const b = el.getBoundingClientRect(); if (b.right > W + 2 && b.width > 0 && getComputedStyle(el).position !== 'fixed') { const sel = el.tagName.toLowerCase() + (el.id ? '#' + el.id : '') + (el.className && typeof el.className === 'string' ? '.' + el.className.trim().split(/\s+/).slice(0, 2).join('.') : ''); if (!worst || b.right > worst.r) worst = { sel, r: Math.round(b.right) }; } }
          return { sw, W, worst }; });
        if (r) out.push(w + 'px ' + pg + ' scrollWidth ' + r.sw + ' > ' + r.W + ' :: ' + (r.worst ? r.worst.sel + ' right=' + r.worst.r : ''));
      } catch (e) { /* a page that does not load is reported by the page-errors test */ }
      await p.close();
    }
    await ctx.close();
  }
  console.log(out.length + ' overflow(s)'); console.log(out.join('\n'));
  await b.close(); srv.close();
});
