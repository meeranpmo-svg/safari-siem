// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for the CISO Dashboard (dashboards/server/ciso-dashboard.html) against the REAL ITAM engine (engine/ciso.js +
// pyengine/ciso_insights_rules.py; the SIEM link stubbed with SYNTHETIC records) and a stubbed SOC alert API: posture ring, grade,
// trend with its forecast, KPIs, the domain radar (now and 7 days ago), what moved, focus, alerts per day with the unusual-day flag
// and the 7-day forecast, response times, risks, decisions, the board brief; the LIVE alert feed - synced on its own, a new alert
// appears without a reload and is highlighted, the severity filter, the SOC going down shows "not reachable · retrying" and comes
// back; a hostile alert name stays text; the portal's CISO view and the menu point here.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node ciso-dashboard.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const ITAM = path.join(__dirname, '..', '..', 'backend', 'itam'), DASH = path.join(__dirname, '..', '..', 'ui');
const H = require(path.join(ITAM, 'tests', 'helpers'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const XSS = '<img src=x onerror=alert(1)>';
const DAY = 86400000;

(async () => {
  const e = await H.startApp({ noAi: true });
  const NOW = Date.now(), day = (i) => new Date(NOW - i * DAY).toISOString().slice(0, 10);
  const byDay = []; for (let i = 20; i >= 1; i--) byDay.push({ day: day(i), total: 6 + (i % 3) }); byDay.push({ day: day(0), total: 45 });
  const siem = (method, p) => {
    if (p === '/duty/engineers') return Promise.resolve({ engineers: [{ id: 'network', name: 'AI Network Engineer', open: 1, critical: 1, high: 0 }] });
    if (p.startsWith('/duty/items')) return Promise.resolve({ items: [{ id: 'DW-1', engineer: 'network', severity: 'critical', status: 'awaiting-approval', title: 'core-sw (synthetic): uplink errors', site: 'HQ', detected_at: NOW - 3600000 }] });
    if (p === '/metrics') return Promise.resolve({ open_by_severity: { 4: 2, 3: 4 }, mttd_s: 300, mttr_s: 7200, sla: { breaching_now: [{ id: 'C-1' }], ack_compliance_pct: 92, resolve_compliance_pct: 81 }, alerts_by_day: byDay });
    if (p === '/compliance/sama') return Promise.resolve({ summary: { coverage_pct: 68, counts: { covered: 17, partial: 8, gap: 5 } }, controls: [{ id: '3.3.14', title: 'Event management (synthetic)', status: 'gap' }] });
    if (p === '/collection/assurance') return Promise.resolve({ summary: { required: 20, covered: 15, silent: 2, coverage_pct: 75 }, inventory: { connected: true }, collector: { quiet: false }, unknown_senders: [] });
    if (p.startsWith('/approvals')) return Promise.resolve({ items: [] });
    return Promise.reject(new Error('unexpected ' + p));
  };
  require(path.join(ITAM, 'engine/ciso')).registerCiso(e.app.srv, e.app, { siem, python: process.env.PYTHON || 'python3' });
  { // Workflow Automation (the real engine): the CISO office's request late with the security team, another fulfilled and waiting for acceptance
    const WFM = require(path.join(ITAM, 'engine/workflow-auto')), W = WFM.createWorkflow(e.app, { noTimer: true }); WFM.registerWorkflow(e.app.srv, e.app, W);
    W.settingsSave({ version: 0, functions: { ciso: ['syed', 'deputy.syn'] }, teams: { security: ['sec.syn'], identity: ['idm.syn'] } }, { user: 'syed', role: 'admin', ip: '' });
    const late = W.create({ type: 'vuln-remediation', from: 'ciso', title: 'Criticals on the DMZ <img src=x onerror=window.__wfx=1>', details: 'status', priority: 'high' }, { user: 'deputy.syn', role: 'viewer', ip: '' });
    const col = e.app.store.collection('wf_requests'), lr = col.get(late.id); lr.due = new Date(Date.now() - 3600000).toISOString(); col.put(lr);
    const done = W.create({ type: 'priv-access-list', from: 'ciso', title: 'Privileged accounts list Q4', details: 'all domain admins' }, { user: 'syed', role: 'admin', ip: '' });
    W.act(done.id, 'evidence', { kind: 'note', text: 'exported' }, { user: 'idm.syn', role: 'operator', ip: '' }); W.act(done.id, 'fulfil', { response: 'attached' }, { user: 'idm.syn', role: 'operator', ip: '' }); }
  const Hc = e.app.store.collection('ciso_history');
  for (let i = 12; i >= 1; i--) Hc.put({ id: day(i), day: day(i), at: NOW - i * DAY, overall: 82 - (12 - i) * 1.5, domains: { detection: 88 - (12 - i) * 3, compliance: 68, governance: 70 } });
  const ALERTS = [{ id: 'A-1', rule_name: 'Brute force on VPN (synthetic)', summary: '120 failed logons', host: 'vpn01', severity: 4, ts_last: NOW - 60000, count: 120 },
    { id: 'A-2', rule_name: XSS, summary: 'synthetic', host: 'ws-22', severity: 3, ts_last: NOW - 300000, count: 1 },
    { id: 'A-3', rule_name: 'Port scan (synthetic)', summary: 'internal', severity: 2, ts_last: NOW - 600000, count: 3 }];
  const socCalls = []; let socUp = true;
  let WHO = { user: 'syed', role: 'admin' };
  const srv = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://x'), json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u.pathname === '/dashboards/whoami.json') return json(200, WHO);
    if (u.pathname.startsWith('/api/itam/')) {
      const h = Object.assign({}, req.headers, { 'x-sentra-proxy-secret': H.SECRET, 'x-auth-user': WHO.user, 'x-auth-role': WHO.role });
      const up = http.request({ host: '127.0.0.1', port: e.port, method: req.method, path: req.url, headers: h }, (r) => { res.writeHead(r.statusCode, r.headers); r.pipe(res); });
      req.pipe(up); return;
    }
    if (u.pathname === '/api/soc/alerts') { socCalls.push(u.search); if (!socUp) return json(503, { error: 'down' }); const min = Number(u.searchParams.get('min_severity') || 0); const items = ALERTS.filter((a) => a.severity >= min); return json(200, { total: items.length, items }); }
    if (u.pathname.startsWith('/api/')) return json(404, { error: 'not in this test' });
    const f = path.join(DASH, u.pathname.replace(/^\/dashboards\//, '/')); if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (err, d) => { if (err) { res.writeHead(404); res.end(); return; } res.writeHead(200, { 'Content-Type': u.pathname.endsWith('.js') ? 'application/javascript' : u.pathname.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port + '/';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  const wait = (p, fn, arg) => p.waitForFunction(fn, arg, { timeout: 20000 }).then(() => true, () => false);
  try {
    const p = await browser.newPage({ viewport: { width: 1440, height: 1000 } }); p.on('pageerror', (x) => errs.push(x.message));
    p.on('dialog', (d) => { errs.push('dialog: ' + d.message()); d.dismiss(); });
    await p.clock.install();
    await p.goto(base + 'dashboards/ciso-dashboard.html');
    ok(await wait(p, () => !document.getElementById('main').hidden), 'page loads');
    ok(/^\d+$/.test((await p.textContent('#ring b')).trim()) && (await p.textContent('#grade')).trim().length > 0, 'posture ring and grade');
    ok((await p.$$('#trend polyline')).length === 1 && (await p.$$('#trend line')).length === 1 && /falling/.test(await p.textContent('#fct')), 'trend with a falling forecast');
    const k = await p.textContent('#kpis'); ok(/2critical alerts open/.test(k) && /SAMA CSF coverage/.test(k) && /68%/.test(k), 'KPIs: critical alerts, SAMA');
    ok((await p.$$('#radar polygon')).length === 6, 'domain radar: grid, now and 7 days ago');
    ok(/Detection/.test(await p.textContent('#movers')) && /−|-/.test(await p.textContent('#movers')), 'what moved');
    ok(/unusual/.test(await p.textContent('#focus')) && /2 critical alert/.test(await p.textContent('#focus')), 'focus from the ML');
    ok((await p.$$('#aline polyline')).length === 2 && /unusual/.test(await p.textContent('#alt')) && /expected in the next 7 days/.test(await p.textContent('#alt')), 'alerts per day with anomaly and forecast');
    { const w = await p.textContent('#wfcard');
      ok(await wait(p, () => !document.getElementById('wfcard').hidden) && /1\s*open with the IT teams/.test(w) && /1\s*late with the IT teams/.test(w) && /1\s*results for you to accept/.test(w) && /100 %\s*IT teams on time \(1 of 1\)/.test(w), 'Workflow Automation: open, late, to accept, on time - from the real engine: ' + w.replace(/\s+/g, ' ').slice(0, 260));
      ok(w.indexOf('Criticals on the DMZ') < w.indexOf('Privileged accounts list') && /Criticals on the DMZ <img/.test(w) && !(await p.$('#wfcard img')) && !(await p.evaluate(() => window.__wfx)) && /late with the IT team \+35, high priority \+10/.test(w) && !!(await p.$('#wfcard a[href="workflow-automation.html#tab=new"]')), 'Workflow: ranked by points with the reasons, a hostile title stays text, New request'); }
    ok(/Mean time to resolve/.test(await p.textContent('#resp')) && /81%/.test(await p.textContent('#resp')), 'response times');
    ok(/core-sw \(synthetic\)/.test(await p.textContent('#risks')) || /SAMA/.test(await p.textContent('#risks')), 'top risks');
    ok((await p.$$('#dec .rk')).length >= 1, 'decisions waiting');
    // live feed
    ok(await wait(p, () => document.querySelectorAll('#feed a.al').length === 2), 'live feed: high and critical by default');
    ok((await p.textContent('#feed')).includes(XSS) && !(await p.$('#feed img')), 'a hostile alert name stays text');
    ok(/live · synced/.test(await p.textContent('#livet')), 'live indicator');
    ALERTS.unshift({ id: 'A-9', rule_name: 'Ransomware behaviour (synthetic)', summary: 'mass rename', host: 'fs01', severity: 4, ts_last: Date.now(), count: 1 });
    await p.clock.runFor(10500);
    ok(await wait(p, () => document.querySelectorAll('#feed a.al').length === 3 && !!document.querySelector('#feed a.al.new')), 'a new alert appears on its own (no reload), highlighted');
    ok(/1 new since you opened/.test(await p.textContent('#newc')), 'new-alert counter');
    ok((await p.getAttribute('#feed a.al.new', 'href')) === 'soc-alerts.html?id=A-9', 'it opens in the alert queue');
    await p.selectOption('#minsev', '2'); ok(await wait(p, () => document.querySelectorAll('#feed a.al').length === 4), 'severity filter');
    await p.selectOption('#minsev', '4'); ok(await wait(p, () => document.querySelectorAll('#feed a.al').length === 2), 'critical only');
    socUp = false; await p.clock.runFor(10500);
    ok(await wait(p, () => /SOC not reachable · retrying in/.test(document.getElementById('livet').textContent) && document.getElementById('live').classList.contains('off')), 'the SOC down is shown, with a retry');
    socUp = true; await p.clock.runFor(25000);
    ok(await wait(p, () => /live · synced/.test(document.getElementById('livet').textContent)), 'it recovers on its own');
    ok(socCalls.length >= 5 && socCalls.every((q) => /status=open/.test(q)), 'polled the open alerts repeatedly');
    // menu
    ok(await p.evaluate(() => { const a = (window.ZYB_NAV || []).find((x) => x.id === 'cmd'); return !!(a && a.pages.some((x) => x.h === 'ciso-dashboard.html')); }), 'CISO Dashboard is in Command & Leadership');
    const early = fs.readFileSync(path.join(DASH, 'vendor/zyb-early.js'), 'utf8'); ok(/cisodash: 'ciso-dashboard\.html'/.test(early), 'the portal\'s CISO view opens it');
  } finally { await browser.close(); srv.close(); await e.close(); }
  ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks');
  process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
