// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for business-risk-years.html (Risk Register by Year) against the REAL engine (engine/business-risk.js) with SYNTHETIC
// workbooks (backend/itam/tests/brisk-fixture.js): a past year imported through the page (preview, then import), the years table and
// trend, 2024 against the live register risk by risk (new / gone / worse), the change filter, Excel export, the Risk Head closes a year,
// a plain operator is refused, a viewer sees no close / import; in the menu and the install list; phone width.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node business-risk-years.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const ITAM = path.join(__dirname, '..', '..', 'backend', 'itam'), DASH = path.join(__dirname, '..', '..', 'ui');
const H = require(path.join(ITAM, 'tests', 'helpers'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
(async () => {
  const e = await H.startApp({ noAi: true });
  require(path.join(ITAM, 'engine/duty')).registerDuty(e.app.srv, e.app, { noTimer: true, now: () => Date.parse('2026-11-11T08:00:00Z'), python: process.env.PYTHON || 'python3' });
  const F = require(path.join(ITAM, 'tests', 'brisk-fixture'));
  await e.req('POST', '/roles/assign', { body: { user: 'rita.syn', role_id: 'risk-head' }, user: 'adam.syn', role: 'admin' });
  await e.req('POST', '/brisk/import/register', { body: { filename: 'reg.xlsx', xlsx_b64: await F.registerB64(), apply: true }, user: 'adam.syn', role: 'admin' });
  const H2 = F.REG_H, ci = (h) => H2.indexOf(h), rows = F.registerRows().map((r) => r.slice()), first = rows[0][ci('Risk Code')], second = rows[1][ci('Risk Code')];
  const prev = rows.slice(1); prev[0][ci('Impact')] = '1 – Negligible'; const gone = rows[0].slice(); gone[ci('Risk Code')] = 'SYN-OLD-1'; gone[ci('Risk Title')] = 'A synthetic risk closed since 2024'; prev.push(gone);
  const x24 = Buffer.from(await F.b64([{ name: 'Risk Register', columns: H2.map((h) => ({ h })), rows: prev }]), 'base64');
  let who = { user: 'adam.syn', role: 'admin' };
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
  const base = 'http://127.0.0.1:' + srv.address().port + '/business-risk-years.html?standalone=1';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  const wait = (p, fn, arg) => p.waitForFunction(fn, arg === undefined ? null : arg, { timeout: 15000 }).then(() => true, () => false);
  const toast = (p, re) => wait(p, (s) => [...document.querySelectorAll('.toast')].some((t) => new RegExp(s).test(t.textContent)), re);
  const txt = (id) => 'document.getElementById("' + id + '").textContent';
  try {
    const p = await browser.newPage({ viewport: { width: 1440, height: 1000 } }); p.on('pageerror', (x) => errs.push(x.message));
    await p.goto(base); ok(await wait(p, () => /No year recorded yet/.test(document.getElementById('years').textContent)), 'empty state says what to do');
    ok(!(await p.$eval('#impc', (x) => x.hidden)) && !(await p.$eval('#closec', (x) => x.hidden)), 'an admin sees close and import');
    await p.fill('#i-year', '2024'); await p.setInputFiles('#i-file', { name: 'register-2024.xlsx', mimeType: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', buffer: x24 });
    await p.click('#i-prev'); ok(await wait(p, (n) => new RegExp(n + ' risks').test(document.getElementById('i-res').textContent), String(prev.length)), 'preview counts the risks');
    await p.click('#i-apply'); ok(await toast(p, '2024 imported') && await wait(p, () => /2024/.test(document.getElementById('years').textContent) && /imported/.test(document.getElementById('years').textContent)), 'imported 2024 is listed');
    ok(await wait(p, () => !!document.querySelector('#trend svg')), 'the trend draws with two points');
    ok((await p.inputValue('#ca')) === '2024' && (await p.inputValue('#cb')) === 'current', 'defaults: last year against the live register');
    await p.click('#cgo'); ok(await wait(p, () => /Risk by risk/.test(document.getElementById('cmp').textContent)), 'the comparison draws');
    const c = await p.textContent('#cmp');
    ok(c.includes(first) && c.includes('SYN-OLD-1') && /new/.test(c) && /gone/.test(c) && /worse/.test(c), 'new, gone and worse risks are shown');
    await p.click('[data-ch="gone"]'); ok(await wait(p, () => /Risk by risk \(1\)/.test(document.getElementById('cmp').textContent)), 'the change filter');
    const [dl] = await Promise.all([p.waitForEvent('download'), p.click('#cx')]); ok(/2024-vs-current\.xlsx$/.test(dl.suggestedFilename()), 'Excel export: ' + dl.suggestedFilename());
    // closing a year: a plain operator is refused, the Risk Head closes it
    who = { user: 'omar.syn', role: 'operator' }; await p.reload(); await wait(p, () => /2024/.test(document.getElementById('years').textContent));
    ok(await p.$eval('#impc', (x) => x.hidden), 'an operator sees no import');
    await p.fill('#c-year', '2025'); await p.click('#c-go'); ok(await toast(p, 'Not allowed'), 'a plain operator cannot close a year');
    who = { user: 'rita.syn', role: 'operator' }; await p.reload(); await wait(p, () => /2024/.test(document.getElementById('years').textContent));
    await p.fill('#c-year', '2025'); await p.click('#c-go'); ok(await toast(p, '2025 closed') && await wait(p, () => /closed/.test(document.getElementById('years').textContent)), 'the Risk Head closes 2025');
    who = { user: 'vera.syn', role: 'viewer' }; await p.reload(); await wait(p, () => /2025/.test(document.getElementById('years').textContent));
    ok(await p.$eval('#closec', (x) => x.hidden) && await p.$eval('#impc', (x) => x.hidden), 'a viewer sees no close / import');
    await p.selectOption('#ca', '2024'); await p.selectOption('#cb', '2025'); await p.click('#cgo'); ok(await wait(p, () => /Risk by risk/.test(document.getElementById('cmp').textContent)), 'a viewer compares two recorded years');
    ok(!(await p.evaluate(() => window.__x)), 'no script from data');
    const ph = await browser.newPage({ viewport: { width: 390, height: 900 } }); ph.on('pageerror', (x) => errs.push(x.message));
    await ph.goto(base); await wait(ph, () => /2025/.test(document.getElementById('years').textContent)); await ph.click('#cgo'); await wait(ph, () => /Risk by risk/.test(document.getElementById('cmp').textContent));
    ok(await ph.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1), 'phone width: no sideways scroll'); await ph.close();
    const nav = fs.readFileSync(path.join(DASH, 'vendor/zyb-nav.js'), 'utf8'), inst = fs.readFileSync(path.join(DASH, 'install-dashboards.sh'), 'utf8');
    ok(/"h": "business-risk-years.html"/.test(nav) && inst.includes('business-risk-years.html'), 'in the menu and the install list');
  } finally { await browser.close(); srv.close(); e.close(); }
  ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks'); process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
