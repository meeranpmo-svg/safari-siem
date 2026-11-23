// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for the Executive Dashboard (dashboards/server/executive-dashboard.html) against the REAL ITAM engine
// (engine/exec-dashboard.js) with SYNTHETIC Reporting Center / AI CISO / Risk Studio sources: index ring with grade, trend and
// forecast after 10 recorded days, five pillar cards (one NOT measured, linking to its page), the history chart and its line
// toggles, the ranked "needs the executive" list, movers, coverage (a not-installed area said), Record today (admin only), the AI
// brief (operator; asked through the Reporting Center with the executive report), Excel, a hostile decision title stays text,
// the menu entry and the portal redirect (view "ciso").
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node executive-dashboard.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const ITAM = path.join(__dirname, '..', '..', 'backend', 'itam'), DASH = path.join(__dirname, '..', '..', 'ui');
const H = require(path.join(ITAM, 'tests', 'helpers'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const XSS = '<img src=x onerror="window.__xss=1">';
const K = (key, label, value, unit) => ({ key, label, value, unit: unit || '', good: 'up' });

(async () => {
  const e = await H.startApp({ noAi: true });
  require(path.join(ITAM, 'engine/duty')).registerDuty(e.app.srv, e.app, { noTimer: true });
  const asked = [];
  e.app.addons.reportCenter = {
    build: async () => ({ id: 'executive', sections: [
      { id: 'compliance', title: 'Compliance posture', state: 'ok', kpis: [K('compliance.sama', 'SAMA CSF + IA score', 70, '%'), K('compliance.nca', 'NCA ECC score', 80, '%')] },
      { id: 'resilience', title: 'DR & backup', state: 'ok', kpis: [K('dr.readiness', 'DR readiness', 90, '%'), K('backup.coverage', 'Backup coverage', 70, '%')] },
      { id: 'security', title: 'Vulnerabilities', state: 'not_installed', note: 'Connect VAPT Studio (FireCompass / Tenable) or Greenbone scans.', kpis: [] },
      { id: 'assets', title: 'Asset register', state: 'ok', kpis: [K('assets.health', 'Register health', 84, '%')] },
      { id: 'platform', title: 'Platform health', state: 'ok', kpis: [K('platform.pages_working', 'Checked pages working', 95), K('platform.pages_down', 'Pages not working', 5)] }] }),
    insights: async () => ({ ok: true, days: 10, kpis: [{ key: 'dr.readiness', label: 'DR readiness', verdict: 'worsening', change: { delta: -6 }, forecast: 82 }], notable: [{ key: 'dr.readiness', label: 'DR readiness', why: 'worse than last week', text: '96 → 90' }] }),
    aiStatus: () => ({ enabled: true, model: 'm' }), ask: async (b, who) => { asked.push({ b, who }); return { answer: 'Headline: posture adequate, DR readiness slipping.', steps: [{ tool: 'report' }, { tool: 'insights' }] }; },
  };
  e.app.addons.ciso = { overview: async () => ({ posture: { overall: 72, domains: [{ name: 'Detection & response', score: 65, measured: true }] }, decisions: [{ severity: 'high', title: 'Approve firewall change ' + XSS, who: 'admin', from: 'AI network engineer', link: 'network-engineer.html' }] }) };
  { // Workflow Automation (the real engine): one change waiting for approval, one request overdue with the DBA team, one fulfilled on time
    const W = e.app.addons.workflow, col = e.app.store.collection('wf_requests');
    W.settingsSave({ version: 0, teams: { dba: ['dba.syn'], network: ['net.syn'] } }, { user: 'syed', role: 'admin', ip: '' });
    W.create({ type: 'net-change', from: 'admin', title: 'Open 443 for the <img src=x onerror=window.__xss=1> portal', details: 'new portal' }, { user: 'adm2.syn', role: 'admin', ip: '' });
    const late = W.create({ type: 'db-user-review', from: 'audit', title: 'Q4 DB accounts', details: 'all DBA accounts' }, { user: 'aud.syn', role: 'viewer', ip: '' });
    const lr = col.get(late.id); lr.due = new Date(Date.now() - 3600000).toISOString(); col.put(lr);
    const ok1 = W.create({ type: 'db-licence', from: 'governance', title: 'Oracle licence position', details: 'Q4' }, { user: 'gov.syn', role: 'viewer', ip: '' });
    W.act(ok1.id, 'fulfil', { response: 'attached' }, { user: 'dba.syn', role: 'operator', ip: '' }); }
  // no Risk Studio: the risk pillar is NOT measured
  delete e.app.addons.riskStudio;
  const day = (d) => new Date(Date.now() + 3 * 3600000 - d * 86400000).toISOString().slice(0, 10);
  for (let d = 10; d >= 1; d--) e.app.store.collection('exec_hist').put({ id: day(d), day: day(d), at: Date.now() - d * 86400000, index: 70 + (10 - d) * 0.6, pillars: { cyber: 70, compliance: 70 + (10 - d), resilience: 82, operations: 86, risk: null } });
  let WHO = { user: 'syed', role: 'admin' };
  const srv = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://x'), json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u.pathname === '/dashboards/whoami.json') return json(200, WHO);
    if (u.pathname.startsWith('/api/itam/')) {
      const h = Object.assign({}, req.headers, { 'x-sentra-proxy-secret': H.SECRET, 'x-auth-user': WHO.user, 'x-auth-role': WHO.role });
      const up = http.request({ host: '127.0.0.1', port: e.port, method: req.method, path: req.url, headers: h }, (r) => { res.writeHead(r.statusCode, r.headers); r.pipe(res); });
      req.pipe(up); return;
    }
    if (u.pathname.startsWith('/api/')) return json(404, { error: 'not in this test' });
    const f = path.join(DASH, u.pathname.replace(/^\/dashboards\//, '')); if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (err, d) => { if (err) { res.writeHead(404); return res.end(); } res.writeHead(200, { 'Content-Type': f.endsWith('.js') ? 'application/javascript' : f.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const url = 'http://127.0.0.1:' + srv.address().port + '/dashboards/executive-dashboard.html?standalone=1';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright'); const browser = await chromium.launch(), errs = [];
  const wait = (p, fn, arg) => p.waitForFunction(fn, arg, { timeout: 15000 }).then(() => true, () => false);
  try {
    const ctx = await browser.newContext({ viewport: { width: 1500, height: 1000 }, acceptDownloads: true });
    const p = await ctx.newPage(); p.on('pageerror', (x) => errs.push(x.message));
    await p.goto(url); ok(await wait(p, () => document.querySelectorAll('.pl').length === 5), 'five pillar cards');
    if (process.env.SHOT) await p.screenshot({ path: process.env.SHOT, fullPage: true });   // optional: a picture for review
    const idx = await p.textContent('#idx'); ok(/adequate/.test(idx) && /improving/.test(idx) && /in 30 days ≈/.test(idx) && /4 of 5 pillars measured/.test(idx), 'index, grade, trend, forecast, measured count');
    ok(/Enterprise IT risk[\s\S]*—[\s\S]*not measured: Risk Studio not installed/.test(await p.textContent('#pills')), 'a pillar with no source is not measured, with its reason');
    ok((await p.getAttribute('.pl[data-pid="resilience"]', 'href')) === 'dr-studio.html', 'pillar links to its page');
    ok(await p.$('#chart svg polyline') !== null, 'history chart');
    await p.click('#lg [data-line="compliance"]'); ok((await p.$$('#chart svg polyline')).length === 2, 'a pillar line toggles on');
    { const w = await p.textContent('#wf');
      ok(/100 %\s*fulfilled on time \(1 of 1\)/i.test(w) && /1\s*overdue across the IT teams/i.test(w) && /2\s*open with the IT teams/i.test(w) && /1\s*waiting for your approval/i.test(w), 'Workflow Automation: on time, overdue, open, approvals - from the real engine: ' + w.replace(/\s+/g, ' ').slice(0, 240));
      ok(w.indexOf('Database team') < w.indexOf('Network team') && /Request approval/i.test(w) && /Open 443 for the <img/.test(w) && !!(await p.$('#wf a[href^="workflow-automation.html#req=REQ-"]')), 'Workflow: teams most overdue first, the approval ranked and linked, a hostile title stays text'); }
    const att = await p.textContent('#att'); ok(/Approve firewall change/.test(att) && /DR readiness/.test(att) && /Enterprise IT risk is not measured/.test(att), 'ranked attention: decision, worsening KPI, gap');
    ok(/DR readiness[\s\S]*worsening[\s\S]*-6/.test(await p.textContent('#movers')), 'movers');
    ok(/Vulnerabilities[\s\S]*not installed/.test(await p.textContent('#cov')), 'coverage says what is not installed');
    ok(await p.isVisible('#snap'), 'admin sees Record today'); await p.click('#snap'); ok(await wait(p, () => /Recorded \d+ for/.test(document.body.textContent)), 'Record today');
    ok(e.app.store.auditTail(50).some((a) => a.action === 'exec.snapshot' && a.by === 'syed'), 'snapshot audited');
    await p.click('#brief'); ok(await wait(p, () => /DR readiness slipping/.test(document.getElementById('ai').textContent)), 'AI brief');
    ok(asked[0] && asked[0].b.report === 'executive' && asked[0].who.user === 'syed', 'brief asked through the Reporting Center as the person');
    const [dl] = await Promise.all([p.waitForEvent('download', { timeout: 10000 }), p.click('#xls')]);
    ok(/^executive-dashboard-\d{4}-\d{2}-\d{2}\.xlsx$/.test(dl.suggestedFilename()), 'Excel export');
    ok(!(await p.evaluate(() => window.__xss)), 'hostile title stayed text');
    WHO = { user: 'vera.syn', role: 'viewer' }; const q = await ctx.newPage(); await q.goto(url); await wait(q, () => document.querySelectorAll('.pl').length === 5);
    ok(!(await q.isVisible('#snap')) && /for operators and administrators/.test(await q.textContent('#ai')), 'viewer: no Record today, no AI brief');
    const nav = fs.readFileSync(path.join(DASH, 'vendor', 'zyb-nav.js'), 'utf8');
    ok(/"h": "executive-dashboard.html"/.test(nav) && /executive-dashboard\.html/.test(fs.readFileSync(path.join(DASH, 'install-dashboards.sh'), 'utf8')), 'menu entry and installer');
    ok(/ciso: 'executive-dashboard\.html'/.test(fs.readFileSync(path.join(DASH, 'vendor', 'zyb-menu.js'), 'utf8')) && /ciso: 'executive-dashboard\.html'/.test(fs.readFileSync(path.join(DASH, 'vendor', 'zyb-early.js'), 'utf8')), 'the portal\'s Executive Dashboard opens this page');
    ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  } finally { await browser.close(); srv.close(); await e.close(); }
  console.log((bad ? 'FAILED ' : 'ok ') + (n - bad) + '/' + n);
  process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
