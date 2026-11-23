// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for Servers, Cloud & Applications (dashboards/server/servers-dashboard.html) against the REAL ITAM engine
// (engine/servers-dashboard.js) with SYNTHETIC sources: health ring and KPIs, five tier cards (one not connected), a tier card
// filters the issue feed, a KPI filters by severity, the capacity forecast, the trend after recorded days, sources, Excel, record
// today (operator; a viewer does not see it), AI off says why, a hostile finding title stays text, the menu entry and the redirect.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node servers-dashboard.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const ITAM = path.join(__dirname, '..', '..', 'backend', 'itam'), DASH = path.join(__dirname, '..', '..', 'ui');
const H = require(path.join(ITAM, 'tests', 'helpers'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const XSS = '<img src=x onerror="window.__xss=1">';

(async () => {
  const e = await H.startApp({ noAi: true });
  const W = {
    virt: { platforms: [{ id: 'vc1' }], clusters: [{ name: 'CL-PROD-SYN', platform: 'vcenter', forecast: { memory: { days_to_limit: 25, per_month: 4.1, reliable: true, days_of_history: 40 }, storage: { days_to_limit: 200, per_month: 1.2, reliable: false } } }],
      hosts: [{ name: 'esx-01', state: 'connected' }, { name: 'esx-02', state: 'notResponding' }], vms: [{ name: 'a', power: 'on' }], datastores: [{ name: 'ds1', used_pct: 91 }] },
    virtFindings: [{ kind: 'snapshot-old', severity: 'medium', title: 'APP-VM-01 ' + XSS + ' snapshot 40 days old', recommendation: 'Delete the snapshot.' }],
    updates: { summary: { servers: 10, pct: 70, critical_missing: 4, not_measured: 2, overdue_patches: 3, drifting: 0, open_closeout: 0, events_30d: 6 }, servers: [{ name: 'WIN-SRV-01', prod: true, ec: { critical: 4 }, checks: [{ rule: 'UPD-01', state: 'fail' }] }] },
    infra: null,
    db: { registered: 2, oracle_logins: 1, last: { at: new Date().toISOString(), read: 1, failed: 1, results: [{ host: 'ora1', instance: 'PRODSYN', error: 'ORA-01017 invalid username/password' }] } },
    dr: { summary: { streams: 4, past_rpo: 1, at_risk: 0, never_tested: 0, readiness: 70, compliance_7d: 88 } },
  };
  const src = {}; for (const k of Object.keys(W)) src[k] = () => W[k];
  require(path.join(ITAM, 'engine/duty')).registerDuty(e.app.srv, e.app, { noTimer: true, sdSources: src });
  if (e.app.addons.updateHealth) e.app.addons.updateHealth.view = () => ({ pages: [] });
  // two earlier days of history so the trend draws
  const day = (d) => new Date(Date.now() + 3 * 3600000 - d * 86400000).toISOString().slice(0, 10);
  for (const d of [2, 1]) for (const t of ['virt', 'servers', 'db', 'dr']) e.app.store.collection('sd_hist').put({ id: t + '@' + day(d), tier: t, day: day(d), t: Date.now() - d * 86400000, score: 95, issues: 1 });
  { // Workflow Automation (the real engine): nora leads the server team (a new server waits for her approval); the DBA team has an overdue request
    const W = e.app.addons.workflow, wc = e.app.store.collection('wf_requests');
    W.settingsSave({ version: 0, teams: { servers: ['srv.syn'], dba: ['dba.syn'], network: ['net.syn'] }, leads: { servers: ['nora.syn'] } }, { user: 'syed', role: 'admin', ip: '' });
    W.create({ type: 'server-provision', from: 'admin', title: 'New Oracle Linux server for <img src=x onerror=window.__wfx=1> claims', details: '8 vCPU', priority: 'high' }, { user: 'adm.syn', role: 'admin', ip: '' });
    const late = W.create({ type: 'db-user-review', from: 'audit', title: 'Q4 DB accounts', details: 'all DBA accounts' }, { user: 'aud.syn', role: 'viewer', ip: '' });
    const lr = wc.get(late.id); lr.due = new Date(Date.now() - 3600000).toISOString(); wc.put(lr);
    W.create({ type: 'net-change', from: 'admin', title: 'Network change not for this page', details: 'x' }, { user: 'adm.syn', role: 'admin', ip: '' }); }
  let WHO = { user: 'nora.syn', role: 'operator' };
  const srv = http.createServer((req, res) => {
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
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const url = 'http://127.0.0.1:' + srv.address().port + '/dashboards/servers-dashboard.html';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  const wait = (p, fn, arg) => p.waitForFunction(fn, arg, { timeout: 15000 }).then(() => true, () => false);
  const tab = (p, t) => p.click('#tabs [data-tab="' + t + '"]');
  const V = (p) => p.textContent('#view');
  try {
    const ctx = await browser.newContext({ viewport: { width: 1440, height: 1000 }, acceptDownloads: true });
    const p = await ctx.newPage(); p.on('pageerror', (x) => errs.push(x.message));
    await p.goto(url); await wait(p, () => !document.getElementById('main').hidden);
    { await wait(p, () => !document.getElementById('wfcard').hidden); const w = await p.textContent('#wfcard');
      ok(/2\s*open with these teams/.test(w) && /1\s*overdue/.test(w) && /1\s*waiting for your approval/.test(w) && /Server team/.test(w) && /Database team/.test(w) && !/Network team/.test(w), 'Workflow Automation: the server / database teams, open, overdue, approval - not the network team: ' + w.replace(/\s+/g, ' ').slice(0, 260));
      ok(/New Oracle Linux server for <img/.test(w) && !(await p.$('#wfcard img')) && !(await p.evaluate(() => window.__wfx)) && /waiting for your approval \+45, high priority \+10/.test(w) && !!(await p.$('#wf a[href^="workflow-automation.html#req=REQ-"]')), 'Workflow: the approval ranked with reasons and linked; a hostile title stays text'); }
    ok(/platform health/.test(await p.textContent('#ring')) && /4 \/ 5/.test(await p.textContent('#kpis')), 'ring and tiers connected KPI');
    ok((await p.$$('#tiers .tier')).length === 5, 'five tier cards');
    ok(/not connected/.test(await p.textContent('.tier[data-tier="cloud"]')), 'cloud with no source says not connected');
    ok(/hosts down/.test(await p.textContent('.tier[data-tier="virt"]')), 'virtualization figures');
    // tier filters the feed
    await p.click('.tier[data-tier="db"]');
    ok(await wait(p, () => document.querySelectorAll('tr[data-issue]').length === 1 && /PRODSYN: health read failed/.test(document.getElementById('view').textContent)), 'a tier card filters the issue feed');
    await p.click('#clr'); ok(await wait(p, () => document.querySelectorAll('tr[data-issue]').length >= 5), 'clear shows every issue');
    await p.click('.kpi[data-go="issues:high"]');
    ok(await wait(p, () => [...document.querySelectorAll('tr[data-issue]')].every((r) => /high/.test(r.cells[0].textContent))), 'the high KPI filters by severity');
    await p.selectOption('#fsev', ''); ok(await wait(p, () => document.querySelectorAll('tr[data-issue]').length >= 5), 'severity filter cleared');
    // capacity, trend, sources
    await tab(p, 'capacity'); ok((await p.$$('tr[data-fc]')).length === 2 && /indicative/.test(await V(p)) && /CL-PROD-SYN/.test(await V(p)), 'capacity forecast with basis');
    await tab(p, 'trends'); ok(await wait(p, () => !!document.querySelector('#view svg polyline')), 'health trend drawn');
    await tab(p, 'sources'); ok(/no cloud|not installed|nothing reported/.test(await V(p)), 'sources say what is missing');
    await tab(p, 'ai'); ok(/AI operations analyst is off/.test(await V(p)), 'AI off says why');
    // Excel, record today
    const [dl] = await Promise.all([p.waitForEvent('download', { timeout: 10000 }), p.click('#xls')]);
    ok(/^servers-cloud-applications-\d{4}-\d{2}-\d{2}\.xlsx$/.test(dl.suggestedFilename()), 'Excel export');
    ok(await p.isVisible('#sample'), 'operator sees Record today');
    await p.click('#sample'); ok(await wait(p, () => /recorded/.test(document.body.textContent)), 'record today');
    ok(e.app.store.auditTail(20).some((a) => a.action === 'servers-dashboard.sample' && a.by === 'nora.syn'), 'sample audited');
    ok(!(await p.evaluate(() => window.__xss)), 'hostile finding title stayed text');
    // viewer
    WHO = { user: 'vera.syn', role: 'viewer' };
    const q = await ctx.newPage(); q.on('pageerror', (x) => errs.push(x.message)); await q.goto(url); await wait(q, () => !document.getElementById('main').hidden);
    ok(!(await q.isVisible('#sample')) && /Read-only/.test(await q.textContent('#me')), 'viewer: read-only, no Record today');
    const nav = fs.readFileSync(path.join(DASH, 'vendor', 'zyb-nav.js'), 'utf8');
    ok(/"h": "servers-dashboard.html"/.test(nav) && /servers-dashboard\.html/.test(fs.readFileSync(path.join(DASH, 'install-dashboards.sh'), 'utf8')), 'menu entry and installer');
    ok(/'dash-srv': 'servers-dashboard\.html'/.test(fs.readFileSync(path.join(DASH, 'vendor', 'zyb-menu.js'), 'utf8')) && /'dash-srv': 'servers-dashboard\.html'/.test(fs.readFileSync(path.join(DASH, 'vendor', 'zyb-early.js'), 'utf8')), 'the portal\'s Servers dashboard opens this page');
    ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  } finally { await browser.close(); srv.close(); await e.close(); }
  console.log((bad ? 'FAILED ' : 'ok ') + (n - bad) + '/' + n);
  process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
