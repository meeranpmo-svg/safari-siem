// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for the NDMO page (dashboards/server/ndmo.html) against the REAL ITAM engine (engine/ndmo.js +
// pyengine/ndmo_rules.py) with a SYNTHETIC register: the 15 domain tiles filter the controls, the PDPL card reads the PDPL
// register, a control is recorded in the drawer and approved by a different person, the official list is imported from CSV
// and a suggestion accepted, the profile saved, export and gaps-to-GRC work, and a hostile value stays text.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node ndmo.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const ITAM = path.join(__dirname, '..', '..', 'backend', 'itam'), DASH = path.join(__dirname, '..', '..', 'ui');
const H = require(path.join(ITAM, 'tests', 'helpers'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const XSS = '<img src=x onerror=alert(1)>';

(async () => {
  const e = await H.startApp({ noAi: true });
  require(path.join(ITAM, 'engine/duty')).registerDuty(e.app.srv, e.app, { noTimer: true, python: process.env.PYTHON || 'python3', ndmoCatalogFiles: false });
  const as = (who) => async (p, body) => { const r = await e.req('POST', p, Object.assign({ body }, who)); if (r.status !== 200) throw new Error(p + ': ' + r.raw); return r.json; };
  const adm = as({ user: 'syed', role: 'admin' });
  await adm('/pdpl/records', { kind: 'profile', dpo_user: 'huda.syn', dpo_appointed: '2026-01-01' });
  await adm('/pdpl/records', { kind: 'ropa', name: 'Medical claims (synthetic)', owner: 'Claims', legal_basis: 'legitimate_interest', data_categories: ['identity', 'health'], systems: ['CLAIMS-SQL'] });
  await adm('/ndmo/profile', { cdo_user: 'huda.syn', dmo_established: '2026-03-01' });
  let WHO = { user: 'nora.syn', role: 'operator' };
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
  try {
    const p = await browser.newPage({ viewport: { width: 1400, height: 950 } }); p.on('pageerror', (x) => errs.push(x.message));
    p.on('dialog', (d) => d.accept('not signed off (synthetic)'));
    await p.goto(base + 'ndmo.html?standalone=1'); await p.waitForSelector('#list table');
    ok((await p.$$eval('#domains .dom', (a) => a.length)) === 15, '15 domain tiles');
    ok(/PDPL compliance/.test(await p.textContent('#pdpl')) && await p.$('#pdpl a[href="ai-pdpl.html"]'), 'the PDPL card reads the PDPL register and links to it');
    ok(/Register score/.test(await p.textContent('#kpis')), 'KPIs');
    // the same language as NCA ECC: overall status and the four shares, and on every domain tile
    const nk = (await p.textContent('#kpis')).replace(/\s+/g, ' ');
    ok(/Overall \(fully \/ partially \/ not compliant\)/.test(nk) && /Fully compliant/.test(nk) && /Partially compliant/.test(nk) && /Not compliant/.test(nk) && /Not assessed yet/.test(nk), 'NDMO KPIs in the compliance language: ' + nk.slice(0, 200));
    const dsum = await p.$$eval('#domains .dom .zl-pcts', (x) => x.map((e) => [...e.textContent.matchAll(/(\d+)%/g)].reduce((a, m) => a + Number(m[1]), 0)));
    ok(dsum.length >= 10 && dsum.every((n) => n === 100), 'each NDMO domain: four shares adding up to 100: ' + dsum.join(','));
    ok(/Not assessed/.test(await p.textContent('#domains .zl-legend')), 'legend explains not assessed');
    const all = await p.$$eval('#list tbody tr', (r) => r.length);
    await p.click('#domains .dom[data-dom="PDP"]'); await p.waitForTimeout(200);
    const pdp = await p.$$eval('#list tbody tr', (r) => r.map((x) => x.textContent));
    ok(pdp.length === 7 && pdp.every((t) => /ZS-PDP-/.test(t)), 'a domain tile filters the controls (' + pdp.length + ')');
    ok(pdp.some((t) => /ZS-PDP-01/.test(t) && /gap/.test(t)), 'PDPL non-compliance shows as an NDMO gap');
    await p.click('#domains .dom[data-dom="PDP"]'); await p.waitForTimeout(200);
    ok((await p.$$eval('#list tbody tr', (r) => r.length)) === all, 'clicking it again clears the filter');
    await p.selectOption('#fres', 'gap'); await p.waitForTimeout(150);
    ok((await p.$$eval('#list tbody tr', (r) => r.map((x) => x.textContent))).every((t) => /gap/.test(t)), 'the result filter');
    await p.selectOption('#fres', '');
    // record a control in the drawer (with a hostile evidence value), then approve as the CDO
    await p.click('#list tr[data-id="ZS-DQ-01"]'); await p.waitForSelector('#cform');
    await p.selectOption('#cform [name="status"]', 'compliant'); await p.fill('#cform [name="evidence"]', XSS);
    await p.click('#cform button[type=submit]');
    const wt = (re) => p.waitForFunction((src) => new RegExp(src).test(document.getElementById('zd').textContent), re.source, { timeout: 15000 }).then(() => true, () => false);
    ok(await wt(/waiting for approval/), 'recorded: waiting for approval');
    ok(!(await p.$('#zd img')) && (await p.textContent('#zd')).includes(XSS), 'the evidence is shown as text, never as markup');
    await p.click('[data-decide="approve"]'); await p.waitForSelector('.toast-zyb', { timeout: 15000 });
    ok(/four eyes|Chief Data Officer/.test(await p.textContent('.toast-zyb:last-of-type')), 'the recorder (not the CDO) cannot approve: ' + await p.textContent('.toast-zyb:last-of-type'));
    WHO = { user: 'huda.syn', role: 'operator' };
    await p.click('[data-decide="approve"]');
    ok(await wt(/Approved by huda\.syn/), 'the CDO approves');
    ok(/Result\s*met/.test(await p.textContent('#zd')), 'the control is met');
    await p.keyboard.press('Escape');
    // validation message from the server, in the form
    await p.click('#list tr[data-id="ZS-DQ-02"]'); await p.waitForSelector('#cform');
    await p.selectOption('#cform [name="status"]', 'non_compliant'); await p.click('#cform button[type=submit]');
    ok(await wt(/note is required/), 'a validation error is shown in the form');
    await p.keyboard.press('Escape');
    // official list: import as an administrator, accept a suggestion
    WHO = { user: 'syed', role: 'admin' };
    await p.click('[data-tab="official"]');
    ok(/No official list imported/.test(await p.textContent('#cov')), 'empty state says what to do');
    await p.fill('#paste', 'code,domain,title,specification\nDG.1.1,Data Governance,"Data management strategy, approved (synthetic)",x\nDQ.2.1,Data Quality,Data quality rules for critical data (synthetic),\nbad!,DG,x,');
    await p.click('#imp'); await p.waitForTimeout(1200);
    ok(/2 imported, 1 refused/.test(await p.textContent('#impmsg')), 'import result: ' + await p.textContent('#impmsg'));
    await p.waitForSelector('[data-accept]');
    ok((await p.$$eval('[data-accept]', (a) => a.length)) === 2, 'two suggestions offered');
    await p.click('#acceptall'); await p.waitForTimeout(1200);
    ok(/>2<\/div><div class="au-lbl">mapped/.test(await p.innerHTML('#cov')), 'both mapped');
    // profile: decide OD needs a reason
    await p.click('[data-tab="profile"]');
    await p.selectOption('#pform [name="od"]', 'not_applicable'); await p.click('#pform button[type=submit]'); await p.waitForTimeout(500);
    ok(/applicability_note.OD is required/.test(await p.textContent('#pform')), 'not applicable needs a reason');
    await p.fill('#pform [name="od_note"]', 'private insurer, no open data obligation (synthetic)'); await p.click('#pform button[type=submit]'); await p.waitForTimeout(900);
    ok(/Last saved by syed/.test(await p.textContent('#prof')), 'profile saved');
    // export and gaps to GRC
    const [dl] = await Promise.all([p.waitForEvent('download'), p.click('#csv')]);
    ok(/^ndmo-register-\d{4}-\d{2}-\d{2}\.csv$/.test(dl.suggestedFilename()), 'export downloads a CSV');
    await p.click('#grc'); await p.waitForTimeout(1200);
    ok(/GRC action\(s\) created/.test(await p.textContent('.toast-zyb:last-of-type')), 'gaps to GRC');
    // the menu: an NDMO area with this page
    ok(await p.evaluate(() => (window.ZYB_NAV || []).some((a) => a.id === 'pdpl' && a.pages.some((x) => x.h === 'ndmo.html' && x.g === 'Data management (NDMO)'))), 'NDMO has its own sub-menu under Data Privacy (PDPL · NDMO)');
    // a viewer reads; recording is refused with a message
    WHO = { user: 'vera.syn', role: 'viewer' };
    await p.reload(); await p.waitForSelector('#list table');
    await p.click('#list tr[data-id="ZS-DQ-03"]'); await p.waitForSelector('#cform');
    await p.selectOption('#cform [name="status"]', 'compliant'); await p.fill('#cform [name="evidence"]', 'x'); await p.click('#cform button[type=submit]'); await p.waitForTimeout(500);
    ok(/operator role|requires/i.test(await p.textContent('#cform')), 'a viewer is refused with a message: ' + await p.textContent('#cform [data-msg]'));
  } finally { await browser.close(); srv.close(); e.close(); }
  ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks');
  process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
