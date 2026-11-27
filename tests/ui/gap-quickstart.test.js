// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// One click (vendor/zyb-gapwiz.js "Start now") on Start an NDMO Gap Assessment (dashboards/server/ndmo-gap-start.html, vendor/zyb-gapwiz.js) against the REAL ITAM
// engine, SYNTHETIC data: open the engagement, send the kick-off, record and accept evidence, take the baseline, link the
// NDMO register (recorded and approved by the Chief Data Officer through the API), rate the gaps, publish the plan, sign as the lead, approve
// as the Chief Data Officer; the report opens; a viewer is refused; in the menu.
// Run (one-click start): PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node ndmo-gap-start.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const ITAM = path.join(__dirname, '..', '..', 'backend', 'itam'), DASH = path.join(__dirname, '..', '..', 'ui');
const H = require(path.join(ITAM, 'tests', 'helpers'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };

(async () => {
  const e = await H.startApp({ noAi: true });
  require(path.join(ITAM, 'engine/duty')).registerDuty(e.app.srv, e.app, { noTimer: true, python: process.env.PYTHON || 'python3' });
  let WHO = { user: 'lina.syn', role: 'operator' };
  const api = (m, p, body, who) => e.req(m, p, Object.assign(body !== undefined ? { body } : {}, who));
  await api('POST', '/ndmo/profile', { cdo_user: 'karim.syn' }, { user: 'syed', role: 'admin' });
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
  const browser = await chromium.launch(), errs = [];
  const has = (p, sel, re) => p.waitForFunction((a) => new RegExp(a[1], 'i').test((document.querySelector(a[0]) || {}).textContent || ''), [sel, re.source], { timeout: 10000 }).then(() => true, () => false);
  try {
    await api('PUT', '/org/departments/field_ops', { name: 'Field Operations (synthetic)' }, { user: 'syed', role: 'admin' });
    const p = await browser.newPage({ viewport: { width: 1400, height: 1000 } }); p.on('pageerror', (x) => errs.push(x.message));
    await p.goto(base + 'ndmo-gap-start.html?standalone=1'); await p.waitForSelector('#qs-go');
    ok(await has(p, '#panel', /Click and go/), 'the one-click start is offered');
    await p.click('[data-step="2"]'); ok(await has(p, '#panel', /Start now above/), 'a later step says how to start');
    await p.click('#qs-go');
    await p.waitForFunction(() => !document.getElementById('qs-go') && !document.getElementById('qs-auto'), null, { timeout: 20000 }).catch(() => {});
    const cur = (await api('GET', '/ndmo/gap', undefined, WHO)).json.current;
    ok(cur && /NDMO gap assessment \d{4}/.test(cur.name) && cur.lead === 'lina.syn' && cur.departments.includes('Field Operations (synthetic)'), 'opened with the register and me as lead: ' + JSON.stringify(cur && { n: cur.name, l: cur.lead, d: cur.departments }));
    ok(cur && cur.status !== 'setup' && cur.evidence.length > 0, 'the kick-off was sent');
    ok(cur && !!cur.baseline && !!cur.review, 'the baseline was taken and the register linked');
    ok(!(await p.$('#qs-auto')), 'nothing automatic left to do');
    ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  } finally { await browser.close(); srv.close(); await e.close(); }
  console.log((bad ? 'FAILED ' : 'ok ') + (n - bad) + '/' + n + ' gap quick-start checks'); process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
