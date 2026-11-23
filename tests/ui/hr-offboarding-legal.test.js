// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for a leaver legal hold on HR Offboarding (hr-offboarding.html) against the REAL ITAM engine (offboarding.js +
// m365-licensing.js) and an in-process fake Microsoft Purview eDiscovery, SYNTHETIC data only: an operator asks for a hold with
// helper text on every field and a hostile reason that stays text; the person who asked cannot approve; another administrator
// approves and the page shows the case; once Purview applies the hold and finishes the export, the page shows the estimate and the
// export files (names and sizes, never a link) and says the download is in Purview; a release can then be asked.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node hr-offboarding-legal.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const ITAM = path.join(__dirname, '..', '..', 'backend', 'itam'), DASH = path.join(__dirname, '..', '..', 'ui');
const H = require(path.join(ITAM, 'tests', 'helpers'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const XSS = '<img src=x onerror=alert(1)>';
const TENANT = '11111111-2222-3333-4444-555555555555';

(async () => {
  const st = { hold: 'notApplied', polls: 0, est: 0, ops: [] };
  const G = http.createServer((req, res) => { let b = ''; req.on('data', (c) => { b += c; }); req.on('end', () => {
    const u = new URL(req.url, 'http://x'), J = (c, o) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(o === undefined ? '' : JSON.stringify(o)); };
    if (u.pathname === '/' + TENANT + '/oauth2/v2.0/token') return J(200, { access_token: 'tok' });
    const P = u.pathname.replace('/v1.0/security/cases/ediscoveryCases', '~');
    if (P === '~' && req.method === 'POST') return J(201, { id: 'case-1', displayName: JSON.parse(b).displayName });
    if (/\/custodians$/.test(P)) return req.method === 'POST' ? J(201, { id: 'cu-1' }) : J(200, { value: [] });
    if (/\/userSources$/.test(P)) return req.method === 'POST' ? J(201, { id: 'us-1', includedSources: 'mailbox,site' }) : J(200, { value: [] });
    if (/applyHold$/.test(P)) { st.hold = 'applying'; return J(202); }
    if (/\/custodians\/cu-1$/.test(P)) { if (++st.polls >= 2) st.hold = 'applied'; return J(200, { id: 'cu-1', holdStatus: st.hold }); }
    if (/\/searches$/.test(P)) return J(201, { id: 'se-1' });
    if (/custodianSources\/\$ref$|estimateStatistics$/.test(P)) return J(202);
    if (/lastEstimateStatisticsOperation$/.test(P)) return J(200, ++st.est < 2 ? { status: 'running' } : { status: 'succeeded', indexedItemCount: 5120, indexedItemsSize: 2147483648, unindexedItemCount: 3, unindexedItemsSize: 1048576 });
    if (/exportResult$/.test(P)) { st.ops.push({ id: 'op-1', action: 'exportResult', status: 'running', p: 0, createdDateTime: new Date(Date.now() + 86400000).toISOString() }); return J(202); }
    if (/\/operations$/.test(P)) { st.ops.forEach((o) => { if (++o.p >= 2) { o.status = 'succeeded'; o.exportFileMetadata = [{ fileName: 'Exchange.pst', size: 2000000000, downloadUrl: 'https://download.example/SECRET-LINK' }]; } }); return J(200, { value: st.ops.map((o) => Object.assign({}, o, { p: undefined })) }); }
    J(404, { error: { code: 'x', message: P } });
  }); });
  await new Promise((r) => G.listen(0, '127.0.0.1', r));
  const gb = 'http://127.0.0.1:' + G.address().port;
  const e = await H.startApp({ noAi: true });
  require(path.join(ITAM, 'engine/duty')).registerDuty(e.app.srv, e.app, { noTimer: true, python: process.env.PYTHON || 'python3', graphLogin: gb, graphBase: gb + '/v1.0' });
  const api = async (m, p, body, who) => { const r = await e.req(m, p, Object.assign({ body }, who)); if (r.status !== 200) throw new Error(p + ': ' + JSON.stringify(r.json)); return r.json; };
  const ADM = { user: 'syed', role: 'admin' }, HRA = { user: 'hana.syn', role: 'admin' }, DESK = { user: 'desk.syn', role: 'operator' }, DESKA = { user: 'desk.syn', role: 'admin' };
  await api('POST', '/onboarding/ad', { upn_suffix: 'corp.syn' }, ADM);
  await api('POST', '/onboarding/m365', { tenant_id: TENANT, client_id: '66666666-7777-8888-9999-000000000000', client_secret: 'Synthetic-Graph-Secret-1', legal_enabled: true }, ADM);
  await api('POST', '/offboarding', { name: 'Khalid Al-Harbi', employee_id: 'E-20001', username: 'khalid.harbi', department: 'Claims', last_day: new Date().toISOString().slice(0, 10), manager: 'faisal.syn', reason: 'resignation' }, HRA);
  await api('POST', '/offboarding/OFF-001/confirm', { decision: 'confirm' }, { user: 'faisal.syn', role: 'operator' });
  let WHO = DESK;
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
    await p.goto(base + 'hr-offboarding.html?standalone=1'); await p.waitForSelector('#list table', { timeout: 15000 }); await openRow(p);
    await p.waitForSelector('#olg', { timeout: 8000 });
    ok(await p.$$eval('#olg input[name]:not([type=checkbox]), #olg textarea[name]', (x) => x.every((el) => el.getAttribute('data-hinted'))), 'helper text on every field');
    await p.fill('#olg [name=matter]', 'Broker dispute 2026'); await p.fill('#olg [name=reason]', 'Named in the broker claim ' + XSS); await p.fill('#olg [name=from]', '2025-01-01');
    await Promise.all([p.waitForResponse((r) => /\/legal$/.test(r.url())), p.click('#olg [type=submit]')]);
    ok(await zd(p, /waiting for approval/) && await zd(p, /Named in the broker claim <img/) && !(await p.$('#zd img')), 'asked; the hostile reason stays text');
    await as(p, DESKA);
    await p.selectOption('#olgd [name=decision]', 'approve');
    await Promise.all([p.waitForResponse((r) => /legal\/decide$/.test(r.url())), p.click('#olgd [type=submit]')]);
    ok(await msg(p, '#olgd', /four eyes/), 'the person who asked cannot approve');
    await as(p, ADM);
    await p.selectOption('#olgd [name=decision]', 'approve');
    await Promise.all([p.waitForResponse((r) => /legal\/decide$/.test(r.url())), p.click('#olgd [type=submit]')]);
    ok(await zd(p, /hold being applied/) && await zd(p, /Leaver OFF-001 - Broker dispute 2026/) && await zd(p, /mailbox,OneDrive/), 'approved: the case and the custodian shown');
    for (let i = 0; i < 4; i++) await e.app.addons.offboarding.runDue(null);
    await as(p, ADM);
    ok(await zd(p, /exported in Purview/) && await zd(p, /5120 items · 2\.00 GB/) && await zd(p, /Exchange\.pst/), 'estimate and export files shown');
    ok(await zd(p, /download[s]? it there/) && !(await p.content()).includes('SECRET-LINK'), 'the download is in Purview; no link on the page');
    ok(!!(await p.$('#olgr')), 'a release can be asked');
    await p.reload(); await p.waitForSelector('#list table', { timeout: 15000 });
    ok(/Leavers under legal hold/.test(await p.textContent('#kpis')), 'a tile counts leavers under hold');
  } finally { await browser.close(); srv.close(); G.close(); e.close(); }
  ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks');
  process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
