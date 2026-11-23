// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for the leaver OneDrive hand-over on HR Offboarding (hr-offboarding.html) against the REAL ITAM engine
// (offboarding.js + exo.js) with a stubbed SharePoint runner, SYNTHETIC data only: an administrator adds the SharePoint admin
// address and a default period; the approval form offers the OneDrive decision with that period; after the disable the manager
// has access until the end date; the manager (also an administrator) cannot extend their own access, another administrator
// can; an operator ends it early and the page shows it ended, with a hostile reason kept as text; a tile counts running access.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node hr-offboarding-onedrive.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const ITAM = path.join(__dirname, '..', '..', 'backend', 'itam'), DASH = path.join(__dirname, '..', '..', 'ui');
const H = require(path.join(ITAM, 'tests', 'helpers'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const XSS = '<img src=x onerror=alert(1)>';

(async () => {
  const admins = new Set(['khalid.harbi@corp.syn']), URL_ = 'https://corp-my.sharepoint.com/personal/khalid_harbi_corp_syn';
  const exoRun = async (op, p) => {
    if (op === 'get-mailbox' || op === 'get-forwarding') return { ok: true, data: { found: false } };
    if (op === 'get-onedrive') return { ok: true, data: { found: true, url: URL_, storage_mb: 3072, lock: 'Unlock', owner: 'khalid.harbi@corp.syn', admins: [...admins] } };
    if (op === 'add-site-admin') { admins.add(p.user); return { ok: true, data: { granted: true } }; }
    if (op === 'remove-site-admin') { admins.delete(p.user); return { ok: true, data: { removed: true } }; }
    if (op === 'test') return { ok: true, data: { organization: 'Corp Synthetic' } };
    if (op === 'spo-test') return { ok: true, data: {} };
    return { ok: false, error: 'x' };
  };
  const e = await H.startApp({ noAi: true });
  require(path.join(ITAM, 'engine/duty')).registerDuty(e.app.srv, e.app, { noTimer: true, python: process.env.PYTHON || 'python3', exoRun });
  const api = async (m, p, body, who) => { const r = await e.req(m, p, Object.assign({ body }, who)); if (r.status !== 200) throw new Error(p + ': ' + JSON.stringify(r.json)); return r.json; };
  const ADM = { user: 'syed', role: 'admin' }, HRA = { user: 'hana.syn', role: 'admin' }, DESK = { user: 'desk.syn', role: 'operator' }, MGRA = { user: 'faisal.syn', role: 'admin' };
  await api('POST', '/onboarding/ad', { upn_suffix: 'corp.syn' }, ADM);
  await api('POST', '/offboarding/exo', { enabled: true, organization: 'corp.onmicrosoft.com', app_id: '66666666-7777-8888-9999-000000000000', cert_path: '/etc/sentra/exo-app.pfx', cert_password: 'Synthetic-Pfx-Pass-7' }, ADM);
  await api('POST', '/offboarding', { name: 'Khalid Al-Harbi', employee_id: 'E-20001', username: 'khalid.harbi', department: 'Claims', last_day: new Date().toISOString().slice(0, 10), manager: 'faisal.syn', reason: 'resignation' }, HRA);
  await api('POST', '/offboarding/OFF-001/confirm', { decision: 'confirm' }, { user: 'faisal.syn', role: 'operator' });
  let WHO = ADM;
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
  const zd = (p, re) => p.waitForFunction((src) => new RegExp(src).test((document.getElementById('zd') || {}).textContent || ''), re.source, { timeout: 10000 }).then(() => true, () => false);
  const msg = (p, sel, re) => p.waitForFunction((a) => new RegExp(a[1]).test((document.querySelector(a[0] + ' [data-msg]') || {}).textContent || ''), [sel, re.source], { timeout: 8000 }).then(() => true, () => false);
  const openRow = async (p) => { await p.click('#list tr[data-id="OFF-001"]'); await p.waitForSelector('#zd .steps', { timeout: 8000 }); };
  const as = async (p, who) => { WHO = who; await p.reload(); await p.waitForSelector('#list table', { timeout: 15000 }); await openRow(p); };
  try {
    const p = await browser.newPage({ viewport: { width: 1400, height: 1000 } }); p.on('pageerror', (x) => errs.push(x.message)); p.on('dialog', (d) => { errs.push('dialog ' + d.message()); d.dismiss(); });
    await p.goto(base + 'hr-offboarding.html?standalone=1'); await p.waitForSelector('#list table', { timeout: 15000 });
    // settings
    await p.click('#exoset'); await p.waitForSelector('#exoform [name=spo_admin_url]', { timeout: 8000 });
    ok(!!(await p.getAttribute('#exoform [name=spo_admin_url]', 'data-hinted')), 'helper text on the SharePoint address');
    await p.fill('#exoform [name=spo_admin_url]', 'https://corp-admin.sharepoint.com'); await p.fill('#exoform [name=onedrive_days]', '45');
    await Promise.all([p.waitForResponse((r) => /offboarding\/exo$/.test(r.url()) && r.request().method() === 'POST'), p.click('#exoform [type=submit]')]);
    ok(await zd(p, /OneDrive hand-over\s*on/), 'OneDrive hand-over switched on');
    // the approval
    await as(p, ADM);
    ok((await p.inputValue('#ofappr [name=onedrive]')) === 'manager' && (await p.inputValue('#ofappr [name=onedrive_days]')) === '45', 'approval offers the manager, with the default period');
    await p.selectOption('#ofappr [name=decision]', 'approve'); await p.fill('#ofappr [name=onedrive_days]', '30');
    await Promise.all([p.waitForResponse((r) => /\/approve$/.test(r.url())), p.click('#ofappr [type=submit]')]);
    await api('POST', '/offboarding/OFF-001/disabled', { directory_ref: 'disabled in ADUC, CHG-9001' }, DESK);
    await as(p, ADM);
    ok(await zd(p, /access given/) && await zd(p, /Access forfaisal\.syn@corp\.syn/) && admins.has('faisal.syn@corp.syn'), 'the manager has access');
    ok(await zd(p, /3\.0 GB/) && await zd(p, /personal\/khalid_harbi_corp_syn/), 'size and address shown');
    // extend: not by the person who has the access
    await as(p, MGRA);
    await p.fill('#odext [name=days]', '10'); await p.fill('#odext [name=reason]', 'I still need the files');
    await Promise.all([p.waitForResponse((r) => /onedrive\/extend$/.test(r.url())), p.click('#odext [type=submit]')]);
    ok(await msg(p, '#odext', /has this access/), 'the manager cannot extend their own access');
    await as(p, ADM);
    await p.fill('#odext [name=days]', '10'); await p.fill('#odext [name=reason]', 'the claims audit runs to December');
    await Promise.all([p.waitForResponse((r) => /onedrive\/extend$/.test(r.url())), p.click('#odext [type=submit]')]);
    ok(await zd(p, /\+10 days by syed/), 'extended by another administrator');
    await p.reload(); await p.waitForSelector('#list table', { timeout: 15000 });
    ok(/OneDrive access running/.test(await p.textContent('#kpis')), 'a tile counts running access');
    // end early, hostile reason stays text
    await as(p, DESK);
    await p.fill('#odend [name=reason]', 'copied ' + XSS);
    await Promise.all([p.waitForResponse((r) => /onedrive\/end$/.test(r.url())), p.click('#odend [type=submit]')]);
    ok(await zd(p, /access ended/) && await zd(p, /copied <img/) && !(await p.$('#zd img')), 'ended, the reason kept as text');
    ok(!admins.has('faisal.syn@corp.syn') && admins.has('khalid.harbi@corp.syn'), 'taken back in SharePoint, the owner untouched');
  } finally { await browser.close(); srv.close(); e.close(); }
  ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks');
  process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
