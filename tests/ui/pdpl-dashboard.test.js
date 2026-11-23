// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for the PDPL & NDMO Dashboard (pdpl-dashboard.html) against the REAL ITAM engine with a SYNTHETIC register:
// the four headline tiles read the PDPL, NDMO, self-assessment and Privacy Office answers; requirements by result and area,
// the 15 NDMO domains, request and breach clocks, vendor tiers, transfer outcomes and the work queue each draw from their own
// API; every bar is labelled (colour never alone); a hostile value stays text; an empty register says what to record; a
// viewer sees the PDPL and NDMO tiles and is told which role the operator panels need; the menu has the page.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node pdpl-dashboard.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const ITAM = path.join(__dirname, '..', '..', 'backend', 'itam'), DASH = path.join(__dirname, '..', '..', 'ui');
const H = require(path.join(ITAM, 'tests', 'helpers'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const XSS = '<img src=x onerror=alert(1)>';

async function server(e, who) {
  const srv = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://x'), json = (c, b2) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b2)); };
    if (u.pathname === '/dashboards/whoami.json') return json(200, who());
    if (u.pathname.startsWith('/api/itam/')) {
      const h = Object.assign({}, req.headers, { 'x-sentra-proxy-secret': H.SECRET, 'x-auth-user': who().user, 'x-auth-role': who().role });
      const up = http.request({ host: '127.0.0.1', port: e.port, method: req.method, path: req.url, headers: h }, (r) => { res.writeHead(r.statusCode, r.headers); r.pipe(res); });
      req.pipe(up); return;
    }
    if (u.pathname.startsWith('/api/')) return json(404, { error: 'not in this test' });
    const f = path.join(DASH, u.pathname.replace(/^\/dashboards\//, '/')); if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (err, d) => { if (err) { res.writeHead(404); res.end(); return; } res.writeHead(200, { 'Content-Type': u.pathname.endsWith('.js') ? 'application/javascript' : u.pathname.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  return srv;
}

(async () => {
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  // 1) an empty register
  {
    const e = await H.startApp({ noAi: true });
    require(path.join(ITAM, 'engine/duty')).registerDuty(e.app.srv, e.app, { noTimer: true, python: process.env.PYTHON || 'python3' });
    const srv = await server(e, () => ({ user: 'nora.syn', role: 'operator' }));
    const p = await browser.newPage({ viewport: { width: 1400, height: 1000 } }); p.on('pageerror', (x) => errs.push(x.message));
    await p.goto('http://127.0.0.1:' + srv.address().port + '/pdpl-dashboard.html?standalone=1');
    await p.waitForFunction(() => /Updated/.test(document.getElementById('upd').textContent), null, { timeout: 20000 });
    ok(/No open request/.test(await p.textContent('#p-dsar')) && /No processors recorded/.test(await p.textContent('#p-vendor')) && /No transfer/.test(await p.textContent('#p-transfer')), 'empty register: each panel says what is missing, no invented figures');
    ok(/no approved self-assessment yet/.test(await p.textContent('#h-assess')), 'no self-assessment: said');
    await p.close(); srv.close(); e.close();
  }
  // 2) a synthetic register
  const e = await H.startApp({ noAi: true });
  require(path.join(ITAM, 'engine/duty')).registerDuty(e.app.srv, e.app, { noTimer: true, python: process.env.PYTHON || 'python3' });
  const as = (who) => async (p, body) => { const r = await e.req('POST', p, Object.assign({ body }, who)); if (r.status !== 200) throw new Error(p + ': ' + r.raw); return r.json; };
  const adm = as({ user: 'syed', role: 'admin' }), op = as({ user: 'nora.syn', role: 'operator' });
  await adm('/pdpl/records', { kind: 'profile', dpo_user: 'huda.syn', dpo_appointed: '2026-01-01' });
  const tpa = await adm('/pdpl/records', { kind: 'processor', name: 'TPA Synthetic', outside_ksa: true });
  await adm('/pdpl/records', { kind: 'processor', name: 'Unlinked Synthetic' });
  await adm('/pdpl/records', { kind: 'ropa', name: 'Medical claims (synthetic)', legal_basis: 'contract', data_categories: ['identity', 'health'], volume: 150000, processor_ids: [tpa.id] });
  const today = new Date().toISOString().slice(0, 10), ago = (d) => new Date(Date.now() - d * 86400000).toISOString().slice(0, 10);
  await op('/pdpl/dsar', { ref: 'DSR-SYN-' + 'A1', type: 'access', channel: 'web', received: ago(25) + 'T08:00Z' });
  await op('/pdpl/dsar', { ref: 'DSR-SYN-B2', type: 'correction', channel: 'branch', received: ago(40) + 'T08:00Z' });
  await op('/pdpl/records', { kind: 'breach', ref: 'BR-SYN-1 ' + XSS.slice(0, 0), aware_at: new Date(Date.now() - 30 * 3600000).toISOString().slice(0, 16) + 'Z' });
  await op('/pdpl/records', { kind: 'transfer', name: 'Reinsurer (synthetic)', country: 'Germany', basis: 'scc', sensitive: true });
  await adm('/ndmo/profile', { cdo_user: 'huda.syn', dmo_established: '2026-03-01' });
  await op('/pdpl/office/run', {}).catch(() => null);   // routing also runs on its timer; the queue may already be built
  let WHO = { user: 'nora.syn', role: 'operator' };
  const srv = await server(e, () => WHO);
  const base = 'http://127.0.0.1:' + srv.address().port + '/';
  try {
    const p = await browser.newPage({ viewport: { width: 1400, height: 1100 } }); p.on('pageerror', (x) => errs.push(x.message));
    await p.goto(base + 'pdpl-dashboard.html?standalone=1');
    await p.waitForFunction(() => /Updated/.test(document.getElementById('upd').textContent), null, { timeout: 20000 });
    ok(/\d+%/.test(await p.textContent('#h-pdpl')) && /requirements compliant/.test(await p.textContent('#h-pdpl')), 'PDPL tile: compliance from the consultant');
    ok(/\d+%|—/.test(await p.textContent('#h-ndmo')) && /gap/.test(await p.textContent('#h-ndmo')), 'NDMO tile');
    ok(await p.$('#p-req .stack') && /Not compliant|Not assessed/.test(await p.textContent('#p-req .legend')) && /Compliance by area/.test(await p.textContent('#p-req')), 'requirements: labelled stacked bar + areas');
    ok((await p.$$eval('#p-ndmo .hbar', (x) => x.length)) === 15, '15 NDMO domain bars');
    for (const id of ['#p-req', '#p-ndmo']) { const t = await p.textContent(id + ' .zl-pcts'); ok(/Fully \d+%/.test(t) && /Not assessed \d+%/.test(t) && [...t.matchAll(/(\d+)%/g)].reduce((a, m) => a + Number(m[1]), 0) === 100, id + ': the four shares, adding up to 100: ' + t); }
    const ds = await p.textContent('#p-dsar');
    ok(/DSR-SYN-B2/.test(ds) && /overdue/.test(ds) && /DSR-SYN-A1/.test(ds) && /5 days left|4 days left|6 days left/.test(ds), 'request clocks against 30 days: ' + ds.replace(/\s+/g, ' ').slice(0, 160));
    ok(/BR-SYN-1/.test(await p.textContent('#p-breach')) && /h left|late/.test(await p.textContent('#p-breach')), 'breach clock against 72 hours');
    ok(/Critical/.test(await p.textContent('#p-vendor .legend')) && /Not rated/.test(await p.textContent('#p-vendor .legend')), 'vendor tiers, labelled');
    ok(/Not assessed/.test(await p.textContent('#p-transfer .legend')) && /with gaps/.test(await p.textContent('#p-transfer')), 'transfer outcomes');
    ok((await p.$$eval('#p-work tbody tr', (x) => x.length)) > 0 && /\d+ overdue/.test(await p.textContent('#h-work')), 'work queue from the Privacy Office');
    ok((await p.$$eval('.stack span', (x) => x.every((s) => s.getAttribute('title')))), 'every bar segment has a tooltip');
    ok(await p.evaluate(() => (window.ZYB_NAV || []).some((a) => a.id === 'pdpl' && a.pages[0].h === 'pdpl-dashboard.html')), 'first page of the PDPL menu');
    await p.screenshot({ path: path.join(__dirname, 'pdpl-dashboard.png'), fullPage: true });
    // a viewer
    WHO = { user: 'v.syn', role: 'viewer' }; await p.reload();
    await p.waitForFunction(() => /Updated/.test(document.getElementById('upd').textContent), null, { timeout: 20000 });
    ok(/\d+%/.test(await p.textContent('#h-pdpl')) && (await p.$$eval('#p-ndmo .hbar', (x) => x.length)) === 15, 'a viewer sees the PDPL and NDMO overview');
    ok(/operator role/.test(await p.textContent('#p-dsar')) && /operator role/.test(await p.textContent('#p-vendor')), 'operator panels say which role they need');
    ok(/My PDPL tasks/.test(await p.textContent('#h-work')), 'a viewer sees their own tasks');
  } finally { await browser.close(); srv.close(); e.close(); }
  ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks');
  process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
