// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for the shared print look (dashboards/server/vendor/zyb-print.js, loaded by zyb-dash.js) against the REAL ITAM engine,
// SYNTHETIC data only. Each page is rendered for PRINT: the page and its panels are white with dark text (no grey panels, no light
// text left from the dark theme), the menu, top bar and buttons are not printed, and a header carries the company logo and name from
// the shared report brand; a viewer (no access to the brand) gets the header with the title and date but no invented name. A PDF of
// a page is written for a visual check (PRINT_PDF=1).
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node print-look.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const ITAM = path.join(__dirname, '..', '..', 'backend', 'itam'), DASH = path.join(__dirname, '..', '..', 'ui');
const H = require(path.join(ITAM, 'tests', 'helpers'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const LOGO = 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==';
const PAGES = ['risk-reports.html', 'ras-cockpit.html', 'business-risk.html', 'erm-capital.html', 'pricing-adequacy.html', 'risk-assessments.html', 'vapt-workflow.html', 'rbc-assessment.html'];

(async () => {
  const e = await H.startApp({ noAi: true });
  require(path.join(ITAM, 'engine/duty')).registerDuty(e.app.srv, e.app, { noTimer: true, python: process.env.PYTHON || 'python3' });
  e.app.store.collection('pentest_settings').put({ id: 'report_brand', values: { org_name: 'Synthetic Finance Co', letterhead: LOGO } });
  let WHO = { user: 'risk.syn', role: 'admin' };
  const srv = http.createServer((req, res) => {
    const u2 = new URL(req.url, 'http://x'), json = (code, b2) => { res.writeHead(code, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b2)); };
    if (u2.pathname === '/dashboards/whoami.json') return json(200, WHO);
    if (u2.pathname.startsWith('/api/itam/')) {
      const h = Object.assign({}, req.headers, { 'x-sentra-proxy-secret': H.SECRET, 'x-auth-user': WHO.user, 'x-auth-role': WHO.role });
      const up = http.request({ host: '127.0.0.1', port: e.port, method: req.method, path: req.url, headers: h }, (r) => { res.writeHead(r.statusCode, r.headers); r.pipe(res); });
      req.pipe(up); return;
    }
    if (u2.pathname.startsWith('/api/')) return json(404, { error: 'not in this test' });
    const f = path.join(DASH, u2.pathname.replace(/^\/dashboards\//, '/')); if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (err, d) => { if (err) { res.writeHead(404); res.end(); return; } res.writeHead(200, { 'Content-Type': u2.pathname.endsWith('.js') ? 'application/javascript' : u2.pathname.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port + '/';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch();
  // luminance of a CSS colour (0 dark .. 1 light); transparent counts as the page (white in print)
  const probe = () => {
    const lum = (c) => { const m = /rgba?\(([\d.]+),\s*([\d.]+),\s*([\d.]+)(?:,\s*([\d.]+))?/.exec(c || ''); if (!m) return 1; if (m[4] !== undefined && Number(m[4]) < 0.05) return 1; return (0.2126 * m[1] + 0.7152 * m[2] + 0.0722 * m[3]) / 255; };
    const vis = (el) => { const s = getComputedStyle(el); return s.display !== 'none' && s.visibility !== 'hidden' && el.getClientRects().length > 0; };
    const out = { body: lum(getComputedStyle(document.body).backgroundColor), darkPanels: [], lightText: [], chrome: [] };
    for (const el of document.querySelectorAll('.card,.t,section,.panel,.tile,table,th,td,.src,.tk')) { if (!vis(el)) continue; const b = lum(getComputedStyle(el).backgroundColor); if (b < 0.8) out.darkPanels.push((el.className || el.tagName) + ':' + getComputedStyle(el).backgroundColor); }
    for (const el of document.querySelectorAll('h1,h2,h3,p,td,th,li,label,.v,.l,.s')) { if (!vis(el) || !el.textContent.trim()) continue; const c = lum(getComputedStyle(el).color); if (c > 0.7) out.lightText.push(el.tagName + ':' + el.textContent.trim().slice(0, 30) + ':' + getComputedStyle(el).color); }
    for (const sel of ['#zyb-side', '#zyb-bar', 'button']) for (const el of document.querySelectorAll(sel)) if (vis(el)) out.chrome.push(sel);
    const h = document.getElementById('zyb-print-head');
    out.head = h && vis(h) ? { text: h.textContent, logo: !!h.querySelector('img') } : null;
    return out;
  };
  try {
    const p = await browser.newPage({ viewport: { width: 1300, height: 1000 } });
    for (const pg of PAGES) {
      await p.goto(base + pg + '?standalone=1'); await p.waitForTimeout(900);
      await p.emulateMedia({ media: 'print' });
      await p.evaluate(() => { if (window.zybPrintHead) window.zybPrintHead(); });
      const r = await p.evaluate(probe);
      ok(r.body > 0.95, pg + ': white page (' + r.body.toFixed(2) + ')');
      ok(!r.darkPanels.length, pg + ': no grey / dark panels: ' + r.darkPanels.slice(0, 3).join(' | '));
      ok(!r.lightText.length, pg + ': no light text left from the dark theme: ' + r.lightText.slice(0, 3).join(' | '));
      ok(!r.chrome.length, pg + ': menu, top bar and buttons not printed: ' + [...new Set(r.chrome)].join(','));
      ok(r.head && r.head.logo && /Synthetic Finance Co/.test(r.head.text) && /Printed/.test(r.head.text), pg + ': header with logo, company name and print time');
      if (process.env.PRINT_PDF && pg === 'risk-reports.html') await p.pdf({ path: path.join(process.env.PRINT_PDF, 'risk-reports.pdf'), format: 'A4', printBackground: true });
      await p.emulateMedia({ media: 'screen' });
    }
    // on screen nothing changes: the header is hidden
    await p.goto(base + 'risk-reports.html?standalone=1'); await p.waitForTimeout(600);
    ok(await p.evaluate(() => { const h = document.getElementById('zyb-print-head'); return !h || getComputedStyle(h).display === 'none'; }), 'the print header is hidden on screen');
    // a viewer cannot read the brand: header with title and date, no name made up
    const v = await browser.newPage(); WHO = { user: 'vera.syn', role: 'viewer' };
    await v.goto(base + 'risk-reports.html?standalone=1'); await v.waitForTimeout(800); await v.emulateMedia({ media: 'print' }); await v.evaluate(() => window.zybPrintHead && window.zybPrintHead());
    const rv = await v.evaluate(probe);
    ok(rv.head && !rv.head.logo && !/Synthetic Finance Co/.test(rv.head.text) && /Printed/.test(rv.head.text), 'viewer: header without logo or name');
    const inst = fs.readFileSync(path.join(DASH, 'install-dashboards.sh'), 'utf8'), dash = fs.readFileSync(path.join(DASH, 'vendor', 'zyb-dash.js'), 'utf8');
    ok(inst.includes('vendor/zyb-print.js') && dash.includes('vendor/zyb-print.js'), 'installed and loaded on every page');
  } finally { await browser.close(); srv.close(); await e.close(); }
  console.log((bad ? 'FAILED ' : 'ok ') + (n - bad) + '/' + n);
  process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
