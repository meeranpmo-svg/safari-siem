// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for Non-Human Identities (dashboards/server/nhi.html) against the REAL ITAM engine (engine/nhi.js +
// pyengine/nhi_rules.py) with a stubbed SIEM and SYNTHETIC identities: KPIs and sources, the kind chips and risk filter, an
// identity's risks with their fixes, an owner recorded (helper text on the fields), the owner's review asking to
// decommission, an administrator who did not request it approving, "done" recorded and contradicted by the directory, the
// policy saved by an administrator, CSV export, a hostile name kept as text, a viewer refused, the menu entry.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node nhi.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const ITAM = path.join(__dirname, '..', '..', 'backend', 'itam'), DASH = path.join(__dirname, '..', '..', 'ui');
const H = require(path.join(ITAM, 'tests', 'helpers'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const XSS = '<img src=x onerror=alert(1)>';
const ago = (d) => new Date(Date.now() - d * 86400000).toISOString();
const SIEM = () => ({ ad: { available: true, synced: ago(0), accounts: [
  { id: 'ad:svc-backup', name: 'svc-backup', kind: 'service_user', why: ['name pattern'], description: 'Veeam backup ' + XSS, privileged: true, privileged_groups: ['Domain Admins'], pwd_age_days: 900, spn: [], last_logon: ago(1) },
  { id: 'ad:svc-old', name: 'svc-old', kind: 'service_user', why: ['name pattern'], dormant: true, pwd_age_days: 50, last_logon: ago(200) },
  { id: 'ad:gmsa-sql$', name: 'gmsa-sql$', kind: 'gmsa', managed: true, why: ['group managed service account'], pwd_age_days: 10, last_logon: ago(1) }] },
entra: { available: false, reason: 'grant Application.Read.All to the SIEM app registration' } });

(async () => {
  const e = await H.startApp({ noAi: true });
  require(path.join(ITAM, 'engine/duty')).registerDuty(e.app.srv, e.app, { noTimer: true, python: process.env.PYTHON || 'python3', nhiSiem: async () => SIEM() });
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
  const zd = (p, re) => p.waitForFunction((src) => new RegExp(src).test((document.getElementById('zd') || {}).textContent || ''), re.source, { timeout: 10000 }).then(() => true, () => false);
  const as = async (p, who) => { WHO = who; await p.reload(); await p.waitForSelector('#list table, #list .card-body, #list .alert', { state: 'attached', timeout: 15000 }); };
  const openRow = async (p, id) => { await p.click('#list tr[data-id="' + id + '"]'); await p.waitForSelector('#zd .risk-list, #zd .text-green', { timeout: 8000 }); };
  const submit = async (p, sel) => { await Promise.all([p.waitForResponse((r) => /\/api\/itam\/nhi/.test(r.url()) && r.request().method() !== 'GET'), p.click(sel + ' [type=submit]')]); };
  try {
    const p = await browser.newPage({ viewport: { width: 1400, height: 1000 }, acceptDownloads: true }); p.on('pageerror', (x) => errs.push(x.message));
    await p.goto(base + 'nhi.html?standalone=1'); await p.waitForSelector('#list table', { state: 'attached', timeout: 15000 });
    ok(/Without an owner/.test(await p.textContent('#kpis')) && /Critical \/ high risk/.test(await p.textContent('#kpis')), 'KPIs');
    ok(/Application\.Read\.All/.test(await p.textContent('#srcs')) && /not connected/.test(await p.textContent('#srcs')), 'an unconnected source says what to do');
    const lt = await p.textContent('#list');
    ok(/svc-backup/.test(lt) && /privileged/.test(lt) && lt.includes(XSS) && !(await p.$('#list img')), 'risky identity listed; a hostile value stays text');
    ok((await p.$$eval('#list tbody tr', (x) => x[0].getAttribute('data-id'))) === 'ad:svc-backup', 'worst risk first');
    await p.click('[data-kind="gmsa"]'); ok((await p.$$eval('#list tbody tr', (x) => x.length)) === 1, 'kind chip filters');
    await p.click('[data-kind=""]'); await p.selectOption('#frisk', 'high'); ok((await p.$$eval('#list tbody tr', (x) => x.every((r) => /high|critical/.test(r.textContent)))), 'risk filter');
    await p.selectOption('#frisk', '');
    await openRow(p, 'ad:svc-backup');
    ok(/Domain Admins/.test(await p.textContent('#zd')) && /Fix: /.test(await p.textContent('#zd')), 'risks with the fix');
    await p.keyboard.press('Escape');
    // owner
    await openRow(p, 'ad:svc-old'); await p.waitForSelector('#owform .zyb-hint', { timeout: 8000 });
    ok(/accountable/.test(await p.textContent('#owform')), 'owner field explains itself');
    await p.fill('#owform [name=owner]', 'omar.syn'); await p.fill('#owform [name=purpose]', 'old file sync (synthetic)'); await submit(p, '#owform');
    ok(await zd(p, /Owner review/), 'owner recorded');
    // the owner reviews and asks to decommission
    await as(p, { user: 'omar.syn', role: 'operator' }); await openRow(p, 'ad:svc-old');
    await p.selectOption('#rvform [name=decision]', 'decommission'); await p.fill('#rvform [name=note]', 'the file sync was retired'); await submit(p, '#rvform');
    ok(await zd(p, /Decommission request/), 'decommissioning requested by the review');
    // an administrator approves; a person records it done; the directory still says enabled
    await as(p, { user: 'syed', role: 'admin' }); await openRow(p, 'ad:svc-old');
    await p.selectOption('#ddform [name=decision]', 'approve'); await submit(p, '#ddform');
    ok(await zd(p, /Decommission approved/), 'approved');
    await p.fill('#dnform [name=evidence]', 'CHG-2026-0412 account disabled'); await submit(p, '#dnform');
    ok(await zd(p, /still reports it enabled/), 'a "done" the directory contradicts is flagged');
    await p.keyboard.press('Escape');
    // policy
    await p.click('[data-tab="policy"]'); await p.fill('#polform [name=rotation_days]', '180'); await submit(p, '#polform');
    ok(e.app.store.auditTail(200).some((a) => a.action === 'nhi.policy' && a.by === 'syed'), 'policy saved and audited');
    await p.click('[data-tab="list"]');
    const [dl] = await Promise.all([p.waitForEvent('download'), p.click('#csv')]);
    ok(/^non-human-identities-\d{4}-\d{2}-\d{2}\.csv$/.test(dl.suggestedFilename()), 'CSV export');
    ok(await p.evaluate(() => (window.ZYB_NAV || []).some((a) => a.id === 'usr' && a.pages.some((x) => x.h === 'nhi.html'))), 'in the Identity & Microsoft 365 menu');
    await as(p, { user: 'v.syn', role: 'viewer' });
    ok(/operator|not allowed|forbidden|403/i.test(await p.textContent('#list')), 'a viewer is refused the list');
  } finally { await browser.close(); srv.close(); e.close(); }
  ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks');
  process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
