// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Shared harness for the GRC intelligence pages (vendor/zyb-intel.js): the REAL ITAM app + duty modules behind a proxy that sets the
// signed-in user, the dashboards served from dashboards/server, Chromium, and the checks every such page needs (menu entry, installer,
// portal redirect, no page error, a hostile record stays text).
//   require('./intel-harness')({ file, view, seed(e, col), clockStart? }, async (h) => { ... h.page(), h.who(u, r), h.ok(c, m) ... })
const http = require('http'), fs = require('fs'), path = require('path');
const ITAM = path.join(__dirname, '..', '..', 'backend', 'itam'), DASH = process.env.DASH_DIR ? path.resolve(process.env.DASH_DIR) : path.join(__dirname, '..', '..', 'ui');   // DASH_DIR: a built copy (build-static.js)
const H = require(path.join(ITAM, 'tests', 'helpers'));
module.exports = function run(spec, body) {
  let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
  (async () => {
    const e = await H.startApp({ noAi: true }), col = (c) => e.app.store.collection(c);
    let clock = spec.clockStart || Date.now();
    if (spec.seed) await spec.seed(e, col);
    require(path.join(ITAM, 'engine/duty')).registerDuty(e.app.srv, e.app, Object.assign({ noTimer: true, now: () => clock, python: process.env.PYTHON || 'python3' }, spec.duty || {}));
    if (spec.after) await spec.after(e, col, (ms) => { clock += ms; });
    let WHO = { user: 'nora.syn', role: 'operator' };
    const srv = http.createServer((req, res) => {
      const u = new URL(req.url, 'http://x'), json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
      if (u.pathname === '/dashboards/whoami.json') return json(200, WHO);
      if (u.pathname.startsWith('/api/itam/')) {
        const h = Object.assign({}, req.headers, { 'x-sentra-proxy-secret': H.SECRET, 'x-auth-user': WHO.user, 'x-auth-role': WHO.role });
        const up = http.request({ host: '127.0.0.1', port: e.port, method: req.method, path: req.url, headers: h }, (r) => { res.writeHead(r.statusCode, r.headers); r.pipe(res); });
        req.pipe(up); return;
      }
      if (u.pathname.startsWith('/api/')) return json(404, { error: 'not in this test' });
      const f = path.join(DASH, u.pathname.replace(/^\/dashboards\//, '')); if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
      fs.readFile(f, (err, d) => { if (err) { res.writeHead(404); return res.end(); } res.writeHead(200, { 'Content-Type': f.endsWith('.js') ? 'application/javascript' : f.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
    });
    await new Promise((r) => srv.listen(0, '127.0.0.1', r));
    const base = 'http://127.0.0.1:' + srv.address().port + '/dashboards/';
    const { chromium } = require(process.env.PLAYWRIGHT || 'playwright'); const browser = await chromium.launch(), errs = [];
    const ctx = await browser.newContext({ viewport: { width: 1500, height: 1000 } });
    const wait = (p, fn, arg) => p.waitForFunction(fn, arg, { timeout: 30000 }).then(() => true, () => false);
    const h = { e, col, ok, errs, tick: (ms) => { clock += ms; }, who: (user, role) => { WHO = { user, role }; },
      wait, toast: (p, re) => wait(p, (s) => [...document.querySelectorAll('.zi-toast')].some((t) => new RegExp(s).test(t.textContent)), re),
      page: async (f) => { const p = await ctx.newPage(); p.on('pageerror', (x) => errs.push(x.message)); p.on('dialog', (d) => { errs.push('unexpected dialog: ' + d.message()); d.dismiss(); }); await p.goto(base + (f || spec.file) + '?standalone=1'); await p.waitForSelector('#zi-main:not([hidden]), #zi-err:not([hidden])'); return p; },
      text: (p, sel) => p.textContent(sel),
      openCard: async (p, sec, id) => { await p.click('#sec-' + sec + ' [data-open="' + sec + ':' + id + '"]'); return wait(p, () => !document.getElementById('zi-dlg').hidden); },
      closeDlg: (p) => p.keyboard.press('Escape') };
    try {
      await body(h);
      // the tiles open what they count: a page the engine names, or the section of this page they summarise
      { const p = await h.page(); await wait(p, () => document.querySelectorAll('#zi-hero .zi-kpi').length > 0);
        const T = await p.evaluate(() => [...document.querySelectorAll('.zi-kpi')].map((t) => ({ l: (t.querySelector('.l') || {}).textContent, href: t.getAttribute('href'), sec: t.getAttribute('data-zsec'), chip: t.getAttribute('data-zchip') })));
        if (process.env.TILES) console.log('TILES ' + spec.file + ': ' + T.map((t) => t.l + ' -> ' + (t.href || t.sec + (t.chip ? '|' + t.chip : ''))).join(' ; '));
        ok(T.every((t) => t.href == null || (t.href && !/undefined|null/.test(t.href))), 'no tile links to undefined');
        ok(T.every((t) => t.href || t.sec), 'every tile opens something - a page or a part of this page: ' + JSON.stringify(T));
        const z = T.find((t) => t.sec);
        if (z) { await p.click('.zi-kpi[data-zsec="' + z.sec + '"]'); ok(await wait(p, (id) => document.getElementById('sec-' + id).classList.contains('zi-flash'), z.sec), 'a tile without a page opens its section on this page (' + z.sec + ')'); }
        await p.close(); }
      const nav = fs.readFileSync(path.join(DASH, 'vendor', 'zyb-nav.js'), 'utf8'), key = /^[a-z]+$/.test(spec.view) ? spec.view : "'" + spec.view + "'";
      ok(nav.includes('"h": "' + spec.file + '"') && fs.readFileSync(path.join(DASH, 'install-dashboards.sh'), 'utf8').includes(' ' + spec.file), 'menu entry and installer');
      ok(['zyb-menu.js', 'zyb-early.js'].every((f) => fs.readFileSync(path.join(DASH, 'vendor', f), 'utf8').includes(key + ": '" + spec.file + "'")), 'the portal ' + spec.view + ' view opens this page');
      ok(!errs.length, 'no page errors: ' + errs.join(' | '));
    } catch (x) { console.error(x); bad++; } finally { await browser.close(); srv.close(); await e.close(); }
    console.log((bad ? 'FAILED ' : 'ok ') + (n - bad) + '/' + n);
    process.exit(bad ? 1 : 0);
  })().catch((x) => { console.error(x); process.exit(1); });
};
