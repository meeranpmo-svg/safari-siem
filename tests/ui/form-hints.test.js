// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Helper text on the compliance forms (vendor/zyb-form-hints.js): every field name used by a PDPL, NDMO or NCA ECC form has
// a help line in English and Arabic (static check over the pages), and in the browser the fields show it - an example inside
// text boxes, one line under each field, one line per checkbox group, a form-specific line where a name means something
// else there - on the ECC profile and control drawer, the NDMO profile and the PDPL register form. Real ITAM engine,
// SYNTHETIC data. Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node form-hints.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const ITAM = path.join(__dirname, '..', '..', 'backend', 'itam'), DASH = path.join(__dirname, '..', '..', 'ui');
const H = require(path.join(ITAM, 'tests', 'helpers'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };

// ---- static: every field name on the compliance pages has a hint (q_ / m_ / as_ carry their own text, see the file)
{
  global.window = {}; global.document = { readyState: 'complete', querySelectorAll: () => [], addEventListener() {}, body: {} };
  require(path.join(DASH, 'vendor', 'zyb-form-hints.js'));
  const HT = global.window.zybFormHints.H; delete global.window; delete global.document;
  const pages = fs.readdirSync(DASH).filter((f) => /^(pdpl-.*|ai-pdpl|ndmo|nca-ecc)\.html$/.test(f));
  const names = new Set();
  for (const f of pages) {
    const t = fs.readFileSync(path.join(DASH, f), 'utf8');
    for (const m of t.matchAll(/\[\s*["']([a-z_0-9]+)["']\s*,\s*["'](text|area|date|dtl|num|sel|list|multi|bool)["']/g)) names.add(m[1]);
    for (const m of t.matchAll(/<(?:input|select|textarea)[^>]*\bname=\\?["']([a-z_0-9]+)/g)) names.add(m[1]);
  }
  const missing = [...names].filter((x) => !/^(q|m|as)_$/.test(x) && !HT[x]);
  ok(names.size > 150, 'field names found on ' + pages.length + ' pages: ' + names.size);
  ok(!missing.length, 'every field has a hint; missing: ' + missing.join(' '));
  const badAr = Object.keys(HT).filter((k) => !/[\u0600-\u06FF]/.test(HT[k][2]) || !HT[k][1]);
  ok(!badAr.length, 'every hint has English and Arabic: ' + badAr.join(' '));
  ok(!Object.keys(HT).some((k) => /password|secret|token/i.test(HT[k][0] + HT[k][3])), 'no example looks like a credential');
}

(async () => {
  const e = await H.startApp({ noAi: true });
  require(path.join(ITAM, 'engine/duty')).registerDuty(e.app.srv, e.app, { noTimer: true, python: process.env.PYTHON || 'python3', ndmoCatalogFiles: false, eccFacts: async () => ({}) });
  const WHO = { user: 'syed', role: 'admin' };
  const srv = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://x'), json = (c, b2) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b2)); };
    if (u.pathname === '/dashboards/whoami.json') return json(200, WHO);
    if (u.pathname.startsWith('/api/itam/')) {
      const h = Object.assign({}, req.headers, { 'x-sentra-proxy-secret': H.SECRET, 'x-auth-user': WHO.user, 'x-auth-role': WHO.role });
      const up = http.request({ host: '127.0.0.1', port: e.port, method: req.method, path: req.url, headers: h }, (r) => { res.writeHead(r.statusCode, r.headers); r.pipe(res); });
      req.pipe(up); return;
    }
    if (u.pathname.startsWith('/api/')) return json(404, { error: 'not in this test' });
    const f = path.join(DASH, u.pathname.replace(/^\/dashboards\//, '/')); if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (err, d) => { if (err) { res.writeHead(404); res.end(); return; } res.writeHead(200, { 'Content-Type': u.pathname.endsWith('.js') ? 'application/javascript' : u.pathname.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port + '/';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  // every visible named field in a form has a help line next to it (or its checkbox group does)
  const audit = (p, sel) => p.evaluate((s) => {
    const fm = document.querySelector(s); if (!fm) return { error: 'no form ' + s };
    const out = { fields: 0, without: [], hints: fm.querySelectorAll('.zyb-hint').length, placeholders: 0 };
    fm.querySelectorAll('input[name], select[name], textarea[name]').forEach((el) => {
      if (el.type === 'hidden') return; out.fields++;
      if (!el.getAttribute('data-hinted')) out.without.push(el.name);
      if (el.placeholder) out.placeholders++;
    });
    return out;
  }, sel);
  try {
    const p = await browser.newPage({ viewport: { width: 1400, height: 950 } }); p.on('pageerror', (x) => errs.push(x.message));
    // NCA ECC profile + control drawer
    await p.goto(base + 'nca-ecc.html?standalone=1'); await p.waitForSelector('#list table', { state: 'attached', timeout: 15000 });
    await p.click('[data-tab="profile"]'); await p.waitForSelector('#pform .zyb-hint', { timeout: 5000 });
    let a = await audit(p, '#pform');
    ok(a.fields >= 9 && !a.without.length && a.hints >= a.fields, 'ECC profile: a hint per field ' + JSON.stringify(a));
    ok(/^e\.g\. khalid/.test(await p.getAttribute('#pform [name=ciso_user]', 'placeholder')), 'an example inside the CISO box');
    ok(/independent of IT/.test(await p.textContent('#pform')), 'the reports-to hint explains why it matters');
    await p.click('[data-tab="controls"]'); await p.click('#list tr[data-id="ZS-2-14-01"]'); await p.waitForSelector('#cform .zyb-hint', { timeout: 8000 });
    a = await audit(p, '#cform');
    ok(!a.without.length && /needs evidence; non-compliant or not applicable needs a note/.test(await p.textContent('#cform')), 'control drawer: the form-specific status hint');
    ok(/someone else will check it/.test(await p.textContent('#cform')), 'control drawer: the evidence hint');
    await p.keyboard.press('Escape');
    // NDMO profile
    await p.goto(base + 'ndmo.html?standalone=1'); await p.waitForSelector('#list table', { state: 'attached', timeout: 15000 });
    await p.click('[data-tab="profile"]'); await p.waitForSelector('#pform .zyb-hint', { timeout: 5000 });
    a = await audit(p, '#pform');
    ok(a.fields >= 8 && !a.without.length && a.placeholders >= 1, 'NDMO profile: a hint per field ' + JSON.stringify(a));
    // PDPL register form (records of processing): a checkbox group gets one line, not one per box
    await p.goto(base + 'ai-pdpl.html?standalone=1'); await p.waitForTimeout(800);
    const tab = await p.$('[data-tab="registers"], [data-tab="recs"], [data-tab="reg"]'); if (tab) await tab.click();
    const add = await p.waitForSelector('#addrec', { timeout: 10000 }).catch(() => null);
    if (add) {
      await p.click('[data-kind="ropa"]').catch(() => {}); await p.click('#addrec'); await p.waitForSelector('#rform .zyb-hint', { timeout: 8000 });
      a = await audit(p, '#rform');
      ok(!a.without.length && a.placeholders >= 3, 'PDPL register form: every field decorated ' + JSON.stringify(a));
      const grp = await p.$$eval('#rform .zyb-hint', (x) => x.filter((h) => /Tick every kind of data/.test(h.textContent)).length);
      ok(grp === 1, 'one help line for the data-categories checkbox group: ' + grp);
    } else ok(false, 'the PDPL register form could not be opened');
  } finally { await browser.close(); srv.close(); e.close(); }
  ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks');
  process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
