// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for "Compare two years" on solvency-capital.html against the REAL engine (engine/solvency.js compare) with two SYNTHETIC
// workbooks (backend/itam/tests/sca-fixture.js, 2024 and 2025): the card appears with two returns, defaults to the latest against the
// one before, shows both years with the change and the ratio bridge, swaps when picked the other way round, the same return twice is
// refused, exports to Excel; a viewer can compare; phone width.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node solvency-compare.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const ITAM = path.join(__dirname, '..', '..', 'backend', 'itam'), DASH = path.join(__dirname, '..', '..', 'ui');
const H = require(path.join(ITAM, 'tests', 'helpers'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
(async () => {
  const e = await H.startApp({ noAi: true });
  require(path.join(ITAM, 'engine/duty')).registerDuty(e.app.srv, e.app, { noTimer: true, now: () => Date.parse('2026-02-20T08:00:00Z'), python: process.env.PYTHON || 'python3' });
  const F = require(path.join(ITAM, 'tests', 'sca-fixture'));
  await e.req('POST', '/roles/assign', { body: { user: 'rita.syn', role_id: 'risk-head' }, user: 'adam.syn', role: 'admin' });
  const up = async (o, fn) => (await e.req('POST', '/brisk/solvency/import', { body: { filename: fn, xlsx_b64: F.b64(o) }, user: 'nora.syn', role: 'operator' })).json.id;
  const id24 = await up({ asAt: '2024-12-31', ratio: 2 }, 'sca-2024.xlsx'), id25 = await up({ asAt: '2025-12-31', ratio: 2.5 }, 'sca-2025.xlsx');
  let who = { user: 'omar.syn', role: 'operator' };
  const srv = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://x'), json = (code, b) => { res.writeHead(code, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u.pathname === '/dashboards/whoami.json') return json(200, who);
    if (u.pathname.startsWith('/api/itam/')) { const h = Object.assign({}, req.headers, { 'x-sentra-proxy-secret': H.SECRET, 'x-auth-user': who.user, 'x-auth-role': who.role });
      const up = http.request({ host: '127.0.0.1', port: e.port, method: req.method, path: req.url, headers: h }, (r) => { res.writeHead(r.statusCode, r.headers); r.pipe(res); }); req.pipe(up); return; }
    if (u.pathname.startsWith('/api/') || u.pathname === '/') return json(404, { error: 'not in this test' });
    const f = path.join(DASH, u.pathname.replace(/^\/dashboards\//, '/')); if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (err, d) => { if (err) { res.writeHead(404); res.end(); return; } res.writeHead(200, { 'Content-Type': u.pathname.endsWith('.js') ? 'application/javascript' : u.pathname.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port + '/solvency-capital.html?standalone=1';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  const wait = (p, fn, arg) => p.waitForFunction(fn, arg === undefined ? null : arg, { timeout: 15000 }).then(() => true, () => false);
  const toast = (p, re) => wait(p, (s) => [...document.querySelectorAll('.toast')].some((t) => new RegExp(s).test(t.textContent)), re);
  const res = (p) => p.textContent('#wires');
  try {
    const p = await browser.newPage({ viewport: { width: 1440, height: 1000 } }); p.on('pageerror', (x) => errs.push(x.message));
    await p.goto(base); ok(await wait(p, () => !document.getElementById('cmpc').hidden), 'the compare card shows with two returns');
    ok((await p.inputValue('#cmpa')) === id24 && (await p.inputValue('#cmpb')) === id25, 'defaults: the latest against the one before');
    await p.click('#cmpgo'); ok(await wait(p, () => /Why the regulatory ratio moved/.test(document.getElementById('cmp').textContent)), 'the comparison draws');
    const t = await p.textContent('#cmp');
    ok(/2024-12-31/.test(t) && /2025-12-31/.test(t) && /200%/.test(t) && /250%/.test(t) && /\+50 pts/.test(t), 'both years, the ratios and the change');
    ok(/required margin \+50 pts/.test(t) && /Required minimum margin/.test(t) && /-20%/.test(t), 'the bridge and the % change of the margin');
    ok(/not approved/.test(t), 'draft returns are said to be drafts');
    await p.selectOption('#cmpa', id25); await p.selectOption('#cmpb', id24); await p.click('#cmpgo');
    ok(await wait(p, () => /From 2024-12-31/.test(document.getElementById('cmp').textContent.replace(/\s+/g, ' '))), 'picked the other way round, the older is still "from"');
    await p.selectOption('#cmpb', id25); await p.click('#cmpgo'); ok(await toast(p, 'two different'), 'the same return twice is refused');
    await p.selectOption('#cmpa', id24); await p.click('#cmpgo'); await wait(p, () => !document.getElementById('cmpx').hidden);
    const [dl] = await Promise.all([p.waitForEvent('download'), p.click('#cmpx')]); ok(/2024-12-31-vs-2025-12-31\.xlsx$/.test(dl.suggestedFilename()), 'Excel export: ' + dl.suggestedFilename());
    const XB = require(path.join(ITAM, 'engine/xlsx-book')).readBook(fs.readFileSync(await dl.path())); ok(XB.sheets.some((s) => s.name === 'Side by side'), 'the workbook has the side-by-side sheet');
    who = { user: 'vera.syn', role: 'viewer' }; await p.reload(); await wait(p, () => !document.getElementById('cmpc').hidden); await p.click('#cmpgo');
    ok(await wait(p, () => /250%/.test(document.getElementById('cmp').textContent)), 'a viewer can compare');
    const ph = await browser.newPage({ viewport: { width: 390, height: 900 } }); ph.on('pageerror', (x) => errs.push(x.message));
    await ph.goto(base); await wait(ph, () => !document.getElementById('cmpc').hidden); await ph.click('#cmpgo'); await wait(ph, () => /250%/.test(document.getElementById('cmp').textContent));
    ok(await ph.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1), 'phone width: no sideways scroll'); await ph.close();
  } finally { await browser.close(); srv.close(); e.close(); }
  ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks'); process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
