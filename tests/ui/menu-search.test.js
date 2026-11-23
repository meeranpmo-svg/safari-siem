// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Menu search (vendor/zyb-dash.js shared engine): the sidebar filter and Ctrl+K find a page by words in any order, by an acronym,
// by a synonym (llm -> AI Engine), by a page keyword (switch), with one typo; best matches are ranked and Enter opens the best one;
// Ctrl+K opens the palette; with an empty query the palette lists recently opened pages first; a keystroke stays fast.
// No API is needed: every /api/ call answers 404 (the pages must still render). Run:
//   PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node menu-search.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const DASH = path.join(__dirname, '..', '..', 'ui');
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
(async () => {
  const srv = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://x');
    if (u.pathname === '/dashboards/whoami.json') { res.writeHead(200, { 'Content-Type': 'application/json' }); return res.end(JSON.stringify({ user: 'demo.syn', role: 'admin' })); }
    if (u.pathname.startsWith('/api/') || u.pathname === '/') { res.writeHead(404, { 'Content-Type': 'application/json' }); return res.end('{"error":"not in this test"}'); }
    const f = path.join(DASH, u.pathname.replace(/^\/dashboards\//, '/')); if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (err, d) => { if (err) { res.writeHead(404); res.end(); return; } res.writeHead(200, { 'Content-Type': u.pathname.endsWith('.js') ? 'application/javascript' : u.pathname.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port + '/';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  try {
    const p = await browser.newPage({ viewport: { width: 1400, height: 900 } }); p.on('pageerror', (x) => errs.push(x.message));
    await p.goto(base + 'platform-map.html');
    await p.waitForSelector('#zs-q', { timeout: 20000 });
    const side = async (q) => { await p.fill('#zs-q', q); await p.waitForTimeout(80); return p.$$eval('#zs-best a b', (x) => x.map((y) => y.textContent)); };
    ok((await side('ai engine'))[0] === 'AI Engine', 'sidebar: exact name');
    ok((await side('engine ai'))[0] === 'AI Engine', 'sidebar: words in any order');
    ok((await side('ai switch'))[0] === 'AI Engine', 'sidebar: a page keyword (switch)');
    ok((await side('llm')).includes('AI Engine'), 'sidebar: a synonym (llm)');
    ok((await side('anthropic'))[0] === 'AI Engine', 'sidebar: anthropic');
    ok((await side('enigne')).includes('AI Engine'), 'sidebar: two swapped letters');
    ok((await side('mfa')).some((x) => /sign-in/i.test(x)), 'sidebar: mfa finds Identity & Sign-in');
    ok((await side('vulnerabilities'))[0] === 'Vulnerabilities', 'sidebar: Vulnerabilities first');
    ok(await p.$$eval('.zs-it:not([hidden])', (x) => x.length) < await p.$$eval('.zs-it', (x) => x.length), 'sidebar: the tree is filtered too');
    await side('qqqzzz'); ok(await p.isVisible('#zs-empty') && await p.$eval('#zs-best', (x) => x.hidden), 'sidebar: nothing matches says so');
    await p.press('#zs-q', 'Escape'); ok(await p.$eval('#zs-q', (x) => x.value === '') && await p.$eval('#zs-best', (x) => x.hidden), 'sidebar: Escape clears');
    await side('engine ai'); await p.press('#zs-q', 'Enter'); await p.waitForURL(/ai-engine\.html/, { timeout: 10000 }).catch(() => null);
    ok(/ai-engine\.html/.test(p.url()), 'sidebar: Enter opens the best match');
    // ---- palette
    await p.waitForSelector('#zs-q', { timeout: 20000 });
    await p.click('body', { position: { x: 900, y: 500 } }).catch(() => null);
    await p.keyboard.press('Control+k'); ok(await p.isVisible('#zp-q'), 'Ctrl+K opens the palette');
    const first = await p.$eval('#zp-l li b', (x) => x.textContent); ok(first === 'Platform Map' || first === 'AI Engine', 'empty palette: recently opened pages first (' + first + ')');
    await p.fill('#zp-q', 'claude'); ok((await p.$eval('#zp-l li b', (x) => x.textContent)) === 'AI Engine', 'palette: claude -> AI Engine');
    await p.fill('#zp-q', 'cve deduplicate'); ok((await p.$eval('#zp-l li b', (x) => x.textContent)) === 'Vulnerabilities', 'palette: keywords across words');
    await p.fill('#zp-q', 'cmdb'); ok((await p.$$eval('#zp-l li b', (x) => x.map((y) => y.textContent))).some((x) => /CMDB/.test(x)), 'palette: acronym');
    await p.keyboard.press('Escape');
    // ---- speed: one keystroke ranks every page quickly
    const ms = await p.evaluate(() => { const S = window.zybSearch, idx = [].concat(...window.ZYB_NAV.map((a) => a.pages.map((x) => S.prep({ h: x.h, s: x.s, t: x.t, d: x.d, k: (x.k || []).join(' '), kl: x.k || [], fw: x.fw, a })))); const t0 = performance.now(); for (let i = 0; i < 50; i++) S.rank(idx, ['ai', 'ai sw', 'vuln', 'enigne', 'risk prior'][i % 5]); return { per: (performance.now() - t0) / 50, n: idx.length }; });
    ok(ms.per < 15, 'a keystroke ranks ' + ms.n + ' pages in ' + ms.per.toFixed(2) + ' ms');
  } finally { await browser.close(); srv.close(); }
  ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks'); process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
