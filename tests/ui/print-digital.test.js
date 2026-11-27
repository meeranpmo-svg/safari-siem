// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Print to Digital page (print-digital.html) driven by the REAL routes (backend/siem engine/printers/digital.js) over a SYNTHETIC
// printer fleet: tiles, the target bar, two charts, what the AI noticed, one idea per department with its saving, the roadmap and
// the printers to consolidate; an administrator saves the cost per page and the target (the figures follow); a viewer sees no
// settings; hostile text stays text; menu entry and installer.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node print-digital.test.js
const http = require('http'), fs = require('fs'), os = require('os'), path = require('path');
const DASH = path.resolve(__dirname, '../../ui'), SIEM = path.resolve(__dirname, '../../backend/siem');
const PD = require(path.join(SIEM, 'engine/printers/digital')), { createState } = require(path.join(SIEM, 'engine/soc/state'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const XSS = '<img src=x onerror=window.PWN=1>';
(async () => {
  const items = [['1', 'Finance', 9000], ['2', 'Human Resources', 4000], ['3', 'Projects and Site Workforce', 6000], ['4', XSS, 2000], ['5', 'Finance', 100]].map(([id, d, p]) => ({ id, name: 'PRN-SYN-' + id, department: d, site: 'Riyadh Head Office', pages_30d: p, pages_by_day: [{ day: '2026-11-01', pages: p / 2 }, { day: '2026-11-02', pages: p / 2 }], snapshot: { ok: true } }));
  const state = createState({ dir: fs.mkdtempSync(path.join(os.tmpdir(), 'pd-ui-')) }), R = {}, RANK = { viewer: 1, analyst: 2, operator: 3, admin: 4 };
  PD.register({ route: (m, p, h) => { R[m + ' ' + p] = h; } }, { state, log: { error() {} } }, { view: async () => ({ items }), usage: () => ({ periods: [] }) });
  let WHO = { user: 'admin.syn', role: 'admin' };
  const srv = http.createServer((req, res) => { const u = new URL(req.url, 'http://x'), json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u.pathname === '/dashboards/whoami.json') return json(200, WHO);
    if (u.pathname.startsWith('/api/soc/')) { let raw = ''; req.on('data', (c) => { raw += c; }); req.on('end', async () => { const h = R[req.method + ' ' + u.pathname]; if (!h) return json(404, {});
      const o = {}, ctx = { role: WHO.role, user: WHO.user, body: raw ? JSON.parse(raw) : undefined, params: {}, audit() {}, ok(x) { o.s = 200; o.b = x; }, fail(c, m) { o.s = c; o.b = { error: m }; }, need(r) { if ((RANK[WHO.role] || 0) >= (RANK[r] || 0)) return true; this.fail(403, 'forbidden'); return false; } };
      const rv = await h(ctx); if (o.s === undefined) { o.s = 200; o.b = rv; } json(o.s, o.b); }); return; }
    if (u.pathname.startsWith('/api/')) return json(404, {});
    fs.readFile(path.join(DASH, u.pathname.replace(/^\/dashboards\//, '/')), (err, d) => { if (err) { res.writeHead(404); return res.end(); } res.writeHead(200, { 'Content-Type': u.pathname.endsWith('.js') ? 'application/javascript' : u.pathname.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); }); });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const url = 'http://127.0.0.1:' + srv.address().port + '/dashboards/print-digital.html?standalone=1';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright'); const browser = await chromium.launch(), errs = [];
  const open = async () => { const p = await browser.newPage({ viewport: { width: 1500, height: 1100 } }); p.on('pageerror', (x) => errs.push(x.message)); await p.goto(url); await p.waitForSelector('#main:not([hidden])', { timeout: 15000 }); return p; };
  try {
    let p = await open();
    const kp = (await p.$eval('#kp', (x) => x.innerText)).replace(/\s+/g, ' ');
    ok(/Pages a month 21,100/.test(kp) && /Paper a year \(reams\) 506/.test(kp), 'tiles: ' + kp);
    ok((await p.$$('.g3 canvas')).length === 2 && /Finance prints the most/.test(await p.textContent('#ins')), 'charts and what the AI noticed');
    ok(/Oracle Fusion/.test(await p.textContent('#ideas')) && /tablets/.test(await p.textContent('#ideas')) && (await p.$$('.ph')).length === 3, 'ideas per department and the roadmap');
    ok(/PRN-SYN-5/.test(await p.textContent('#fleet')), 'a printer to consolidate');
    ok(!(await p.evaluate(() => window.PWN)), 'hostile text stays text');
    await p.fill('#sf [name=cost_mono]', '0.10'); await p.fill('#sf [name=target_pct]', '25'); await p.click('#sf button[type=submit]');
    await p.waitForFunction(() => /2,110/.test(document.getElementById('kp').innerText), null, { timeout: 8000 }).catch(() => {});
    ok(/Cost a month \(SAR\) 2,110/.test((await p.$eval('#kp', (x) => x.innerText)).replace(/\s+/g, ' ')), 'an administrator sets the cost per page; the figures follow');
    await p.close();
    WHO = { user: 'vera.syn', role: 'viewer' }; p = await open(); ok(await p.$eval('#setc', (x) => x.hidden), 'a viewer sees no settings'); await p.close();
    ok(fs.readFileSync(path.join(DASH, 'vendor/zyb-nav.js'), 'utf8').includes('"h": "print-digital.html"') && / print-digital\.html /.test(fs.readFileSync(path.join(DASH, 'install-dashboards.sh'), 'utf8')), 'menu entry and installer');
    ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  } finally { await browser.close(); srv.close(); }
  console.log((bad ? 'FAILED ' : 'ok ') + (n - bad) + '/' + n + ' print-digital checks'); process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
