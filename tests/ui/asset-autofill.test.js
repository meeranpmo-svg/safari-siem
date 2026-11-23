// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for dashboards/server/asset-autofill.html against the REAL ITAM engine (engine/asset-autofill.js through duty.js) with
// SYNTHETIC assets: coverage per field with "after accepting"; proposals with verified / estimate pills, source and reason; a coverage
// tile filters; "Accept all verified" writes only the vendor end-of-life date; accepting one estimate; dismiss needs a reason and the
// proposal does not come back; Serial / MAC gaps say why; What was learned shows the learned warranty term; a viewer cannot accept;
// an administrator saves the policy life; a hostile asset name is escaped; reachable from the menu.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node asset-autofill.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const ITAM = path.join(__dirname, '..', '..', 'backend', 'itam'), DASH = path.join(__dirname, '..', '..', 'ui');
const H = require(path.join(ITAM, 'tests', 'helpers'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const ADM = { user: 'syed', role: 'admin' }, OP = { user: 'nora.syn', role: 'operator' }, VW = { user: 'vera.syn', role: 'viewer' };
const XSS = '<img src=x onerror="window.__xss=1">';

(async () => {
  const e = await H.startApp({ noAi: true });
  require(path.join(ITAM, 'engine/duty')).registerDuty(e.app.srv, e.app, { noTimer: true });
  const mk = async (o) => { const r = await e.req('POST', '/assets', Object.assign({ body: o }, ADM)); return (r.json.asset || r.json).id; };
  for (let i = 0; i < 3; i++) await mk({ name: 'LT-W-' + i, type: 'laptop', vendor: 'SynVendor', serial: 'SYNW' + i, mac: '00:11:22:33:44:5' + i, warranty: { start: '2024-01-01', end: '2027-01-01' } });
  const srv = await mk({ name: 'SRV-OLD ' + XSS, type: 'server', os: 'Windows Server 2012 R2', serial: 'SYNS1', mac: '00:11:22:33:44:99', purchase: { date: '2021-01-01' } });
  const lt = await mk({ name: 'LT-NEW', type: 'laptop', vendor: 'SynVendor', purchase: { date: '2025-03-01' } });
  let WHO = OP;
  const web = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://x'), json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
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
  await new Promise((r) => web.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + web.address().port + '/dashboards/';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  const wait = (p, fn, arg) => p.waitForFunction(fn, arg, { timeout: 15000 }).then(() => true, () => false);
  const txt = (p, id) => p.evaluate((i) => document.getElementById(i).innerText, id);
  const A = e.app.store.collection('assets');
  try {
    const p = await browser.newPage({ viewport: { width: 1500, height: 1000 } }); p.on('pageerror', (x) => errs.push(x.message));
    await p.goto(base + 'asset-autofill.html');
    ok(await wait(p, () => /End of life/i.test(document.getElementById('cov').innerText)), 'coverage tiles');
    const cov = await txt(p, 'cov');
    ok(/End of life\s*0 %/i.test(cov) && /proposed/.test(cov), 'end of life coverage now 0 %, with proposals: ' + cov.replace(/\s+/g, ' ').slice(0, 200));
    let list = await txt(p, 'list');
    ok(/verified/i.test(list) && /estimate/i.test(list) && /vendor lifecycle/.test(list) && /Windows Server 2012/.test(list), 'verified + estimate, source and reason');
    ok(/36 months, the term on 3 of 3/.test(list), 'the warranty end comes from the learned term');
    ok(await p.evaluate(() => !window.__xss) && !(await p.$('#list img')), 'asset names escaped');
    // tile filter
    await p.click('[data-f="eol"]'); list = await txt(p, 'list');
    ok(!/36 months/.test(list) && /End of life/.test(list), 'a coverage tile filters the proposals');
    await p.click('[data-f="eol"]');
    // accept all verified: only the vendor date
    await p.click('#b-ver'); ok(await wait(p, () => /value\(s\) written/.test(document.body.innerText)), 'accept all verified');
    ok(String(A.get(srv).eol).startsWith('2023-10-10') && !A.get(lt).eol, 'only the verified end of life was written');
    // accept one estimate (the laptop warranty)
    await wait(p, () => document.querySelectorAll('[data-acc]').length > 0);
    const wk = await p.evaluate((id) => { const b = [...document.querySelectorAll('[data-acc]')].find((x) => x.dataset.acc === id + '|warranty'); if (b) b.click(); return !!b; }, lt);
    ok(wk && await wait(p, () => /written to the register/.test(document.body.innerText)) && await (async () => { await new Promise((r) => setTimeout(r, 400)); return (A.get(lt).warranty || {}).end && String(A.get(lt).warranty.end).startsWith('2028-03-01'); })(), 'one estimate accepted: warranty end 2028-03-01');
    // dismiss with a reason
    await p.evaluate((id) => document.querySelector('[data-dis="' + id + '|eol"]').click(), lt);
    await p.click('#dlg-ok'); ok(await p.evaluate(() => document.getElementById('dlg').open), 'a reason is required to dismiss');
    await p.fill('#dlg-r', 'leased laptop: lease end applies'); await p.click('#dlg-ok');
    ok(await wait(p, (id) => !document.querySelector('[data-dis="' + id + '|eol"]'), lt), 'dismissed proposal gone');
    ok(e.app.store.auditTail(50).some((a) => a.action === 'asset.autofill.dismiss' && a.by === 'nora.syn'), 'dismiss audited');
    // gaps + learned
    await p.click('[data-tab="gp"]'); ok(/LT-NEW[\s\S]*Serial number/.test(await txt(p, 'gaps')), 'serial gap with reason');
    await p.click('[data-tab="ml"]'); ok(/SynVendor[\s\S]*36 months/i.test(await txt(p, 'terms')), 'learned warranty term shown');
    // a viewer cannot accept
    WHO = VW; await p.reload(); await wait(p, () => document.querySelectorAll('[data-acc]').length > 0);
    await p.evaluate(() => document.querySelector('[data-acc]').click());
    ok(await wait(p, () => /Your role cannot do this/.test(document.body.innerText)), 'viewer refused');
    // admin saves the policy life
    WHO = ADM; await p.reload(); await wait(p, () => document.querySelector('[data-ly="laptop"]'));
    await p.click('[data-tab="st"]'); await p.fill('[data-ly="laptop"]', '3'); await p.click('#st-save');
    ok(await wait(p, () => /Settings saved/.test(document.body.innerText)), 'admin saves the policy life');
    ok(e.app.addons.assetAutofill.settings().lifespan_years.laptop === 3, 'stored');
    await p.close();
    const q = await browser.newPage(); await q.goto(base + 'lifecycle-studio.html'); await q.waitForTimeout(800);
    ok(await q.evaluate(() => !!document.querySelector('a[href="asset-autofill.html"]')), 'menu entry');
    await q.close();
    ok(/ asset-autofill\.html /.test(fs.readFileSync(path.join(DASH, 'install-dashboards.sh'), 'utf8')), 'in the installer');
    ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  } finally { await browser.close(); web.close(); e.close(); }
  console.log(`${n - bad}/${n} checks passed`); process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
