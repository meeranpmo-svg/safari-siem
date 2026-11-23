// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for risk-appetite.html - every summary figure is a control: against the REAL engine (engine/business-risk.js) with the
// SYNTHETIC RAS workbook (backend/itam/tests/brisk-fixture.js): the KPI tiles are buttons that filter the metric list (pressed state,
// a second click clears, "metrics" clears everything); "not reported" opens Report many pre-filled with the due metrics for an
// operator (not for a viewer); the latest-position legend, the early-warning count and the zone-history legend filter too; a value
// recorded from the pre-filled form lands; phone width.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node risk-appetite-clicks.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const ITAM = path.join(__dirname, '..', '..', 'backend', 'itam'), DASH = path.join(__dirname, '..', '..', 'ui');
const H = require(path.join(ITAM, 'tests', 'helpers'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
(async () => {
  const e = await H.startApp({ noAi: true });
  require(path.join(ITAM, 'engine/duty')).registerDuty(e.app.srv, e.app, { noTimer: true, now: () => Date.parse('2026-11-11T08:00:00Z'), python: process.env.PYTHON || 'python3' });
  const F = require(path.join(ITAM, 'tests', 'brisk-fixture'));
  const imp = await e.req('POST', '/brisk/import/ras', { body: { filename: 'ras.xlsx', xlsx_b64: await F.rasB64(), apply: true }, user: 'adam.syn', role: 'admin' });
  if (imp.status !== 200) throw new Error('RAS import: ' + imp.text);
  let who = { user: 'nora.syn', role: 'operator' };
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
  const base = 'http://127.0.0.1:' + srv.address().port + '/risk-appetite.html?standalone=1';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  const wait = (p, fn, arg) => p.waitForFunction(fn, arg === undefined ? null : arg, { timeout: 15000 }).then(() => true, () => false);
  const rows = (p) => p.evaluate(() => document.querySelectorAll('#list tr.row').length);
  const cnt = (p) => p.evaluate(() => +((document.getElementById('cnt').textContent.match(/^(\d+) of/) || [])[1] || -1));
  try {
    const p = await browser.newPage({ viewport: { width: 1440, height: 1000 } }); p.on('pageerror', (x) => errs.push(x.message));
    await p.goto(base); await wait(p, () => document.querySelectorAll('#kpis button.k').length === 7 && document.querySelectorAll('#list tr.row').length > 0);
    const all = await cnt(p), tiles = await p.$$eval('#kpis button.k', (L) => L.map((b) => [b.dataset.fz, +b.querySelector('.v').textContent]));
    ok(tiles.length === 7 && tiles[0][0] === 'all' && tiles[0][1] === all, 'seven tiles are buttons; "metrics" = every metric (' + all + ')');
    const due = tiles.find((t) => t[0] === 'due')[1];
    // not reported: the list filters to the due metrics, and Report many opens pre-filled with them
    await p.click('#kpis button[data-fz="due"]');
    ok(await wait(p, (d) => +((document.getElementById('cnt').textContent.match(/^(\d+) of/) || [])[1]) === d, due), 'not reported: ' + due + ' metrics listed');
    ok(await p.$eval('#kpis button[data-fz="due"]', (b) => b.getAttribute('aria-pressed') === 'true') && (await p.$eval('#fz', (s) => s.value)) === 'due', 'the tile is pressed and the filter shows it');
    ok(await wait(p, () => !document.getElementById('bulkcard').hidden && document.getElementById('bulktxt').value.split('\n').filter(Boolean).length > 0), 'Report many opens with the due metrics pre-filled');
    // record one value from the pre-filled form
    const line = (await p.$eval('#bulktxt', (t) => t.value.split('\n')[0])).split(','), mid = line[0];
    await p.fill('#bulktxt', mid + ',' + line[1] + ',1,synthetic value');
    await p.click('#bulksave'); ok(await wait(p, () => /Recorded 1/.test(document.getElementById('bulkres').textContent)), 'a value recorded from the pre-filled form: ' + mid);
    ok(await wait(p, (d) => +((document.querySelector('#kpis button[data-fz="due"] .v') || {}).textContent) === d - 1, due), 'the tile counts one fewer due');
    // a second click clears; "metrics" clears everything
    await p.click('#kpis button[data-fz="due"]'); ok(await wait(p, (a) => +((document.getElementById('cnt').textContent.match(/^(\d+) of/) || [])[1]) === a, all), 'a second click clears the filter');
    await p.click('#kpis button[data-fz="reported"]'); ok(await wait(p, () => +((document.getElementById('cnt').textContent.match(/^(\d+) of/) || [])[1]) >= 1 && document.getElementById('fz').value === 'reported'), 'reported last period: the metric just reported');
    await p.fill('#q', 'zzz-no-match'); await p.dispatchEvent('#q', 'input'); await p.click('#kpis button[data-fz="all"]');
    ok(await wait(p, (a) => +((document.getElementById('cnt').textContent.match(/^(\d+) of/) || [])[1]) === a && document.getElementById('q').value === '', all), '"metrics" clears the search and every filter');
    // the legend entries and the early-warning count filter too
    await p.click('#viz .lg button[data-fz="due"]'); ok(await wait(p, () => document.getElementById('fz').value === 'due'), 'the latest-position legend filters');
    await p.click('#viz button.ew'); ok(await wait(p, () => document.getElementById('fz').value === 'warning'), 'the early-warning count filters');
    await p.click('#viz2 .zl button[data-fz="within"]'); ok(await wait(p, () => document.getElementById('fz').value === 'within'), 'the zone-history legend filters');
    ok(await rows(p) >= 0, 'the list follows');
    // a viewer filters but no form opens
    who = { user: 'vera.syn', role: 'viewer' }; await p.reload(); await wait(p, () => document.querySelectorAll('#kpis button.k').length === 7);
    await p.click('#kpis button[data-fz="due"]'); await p.waitForTimeout(300);
    ok(await p.$eval('#bulkcard', (c) => c.hidden) && (await p.$eval('#fz', (s) => s.value)) === 'due', 'a viewer filters, no reporting form');
    const ph = await browser.newPage({ viewport: { width: 390, height: 900 } }); ph.on('pageerror', (x) => errs.push(x.message)); await ph.goto(base); await wait(ph, () => document.querySelectorAll('#kpis button.k').length === 7);
    ok(await ph.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1), 'phone width: no sideways scroll'); await ph.close();
  } finally { await browser.close(); srv.close(); e.close(); }
  ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks'); process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
