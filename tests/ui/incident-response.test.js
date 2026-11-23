// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Incident Response Center (dashboards/server/incident-response.html) against the REAL SIEM modules (engine/soc/ircenter-routes.js and
// the case / approval routes in engine/soc/routes.js) with SYNTHETIC cases: KPIs and the SLA ring; attention; the lifecycle board;
// an incident opened from the board; similar past incidents and the likely resolution; the recommended playbook applied → its
// response actions appear; assign to me; a task ticked; move to contained; the response action decided by a different administrator
// (the requester cannot); closing needs a resolution; performance, weekly bars and the backlog; an XDR incident opened as a case;
// AI off says why; Excel; a hostile title stays text; viewer sees no write controls; menu entry, installer and the portal redirect.
// Run: SENTRA_SIEM_DIR=/home/user/sentra-siem PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node incident-response.test.js
const http = require('http'), fs = require('fs'), os = require('os'), path = require('path');
const DASH = path.resolve(__dirname, '../../ui');
const SIEM = process.env.SENTRA_SIEM_DIR || path.resolve(__dirname, '../../backend/siem');
const req = (m) => require(path.join(SIEM, 'engine', m));
const { createState } = req('soc/state'), { createAlerts } = req('soc/alerts'), { createCases } = req('soc/cases');
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const XSS = '<img src=x onerror="window.__xss=1">', H = 3600e3, DAY = 24 * H;
let ROLE = 'operator', USER = 'omar.syn';
const RANK = { viewer: 0, analyst: 1, operator: 2, admin: 3 };

(async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sentra-irpage-')), Lq = { info() {}, warn() {}, error() {} };
  let clock = Date.now() - 60 * DAY;
  const state = createState({ dir: path.join(dir, 'state'), log: Lq }), alerts = createAlerts({ state, log: Lq, now: () => clock }), cases = createCases({ state, alerts, log: Lq, now: () => clock });
  const raise = (o) => alerts.raise(Object.assign({ rule_id: 'SENTRA-AUTH-001', rule_name: 'Brute force then success', severity: 3, group: { user: 'dana.syn' }, fields: { src_ip: '198.51.100.7' }, mitre: ['T1110'], summary: 'synthetic', ts_first: clock, ts_last: clock, source: 'engine', count: 1 }, o)).alert;
  for (let i = 0; i < 6; i++) { const a = raise({}); const c = cases.create({ title: 'Brute force dana (synthetic) #' + i, alert_ids: [a.id] }, 'nora.syn'); cases.assign(c.id, 'omar.syn', 'nora.syn'); clock += 2 * H; cases.setStatus(c.id, 'contained', 'omar.syn'); clock += (8 + 10 * i) * H; cases.setStatus(c.id, 'closed', 'omar.syn', { resolution: 'true-positive' }); clock += 5 * DAY; }
  clock = Date.now() - 2 * H;
  const a1 = raise({ severity: 4 }); const inc = cases.create({ title: 'Brute force dana again ' + XSS, alert_ids: [a1.id], auto_playbook: false }, 'nora.syn');
  cases.create({ title: 'Lost laptop (synthetic)', severity: 1, auto_playbook: false }, 'nora.syn');
  clock = Date.now(); setInterval(() => { clock = Date.now(); }, 500).unref();
  const xdr = { incidents: () => ({ incidents: [{ id: 'XDR-SYN1', title: 'Lateral movement - pc-syn', score: 80, severity: 3, alerts: 4, tactics: ['TA0008'], domains: { endpoint: 2, identity: 2 }, cases: [] }] }) };
  const deps = { state, alerts, cases, config: { soc_analyst: { enabled: false } }, log: Lq, now: () => clock, xdr };
  const R = {}, AUD = [];
  const api = { route: (m, p, h) => { R[m + ' ' + p] = { re: new RegExp('^' + p.replace(/:([a-zA-Z]+)/g, '(?<$1>[^/]+)') + '$'), h }; } };
  req('soc/routes').register(api, deps); req('soc/ircenter-routes').register(api, deps);
  let promoted = 0;
  api.route('POST', '/api/soc/xdr/incidents/:id/case', async (ctx) => { promoted++; const c = cases.create({ title: 'From ' + ctx.params.id, severity: 3, auto_playbook: false }, ctx.user); return ctx.ok({ case_id: c.id, created: true }); });
  const srv = http.createServer((rq, res) => {
    const url = new URL(rq.url, 'http://x'), u = url.pathname, json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u === '/dashboards/whoami.json') return json(200, { user: USER, role: ROLE });
    const hit = Object.entries(R).find(([k, v]) => k.startsWith(rq.method + ' ') && v.re.test(u));
    if (hit) { let b = ''; rq.on('data', (x) => { b += x; }); rq.on('end', async () => {
      const o = {}, m = hit[1].re.exec(u), ctx = { role: ROLE, user: USER, body: b ? JSON.parse(b) : {}, params: m.groups ? Object.fromEntries(Object.entries(m.groups).map(([k, v]) => [k, decodeURIComponent(v)])) : {}, query: Object.fromEntries(url.searchParams), path: u,
        need(r) { if (RANK[ROLE] < RANK[r]) { o.status = 403; o.error = 'requires ' + r; return false; } return true; }, audit: (a, t, d) => AUD.push({ a, t, d }), ok: (x) => { o.body = x; return x; }, fail(code, msg) { o.status = code; o.error = msg; } };
      try { await hit[1].h(ctx); if (o.status) return json(o.status, { error: o.error || 'refused' }); json(200, o.body); } catch (e) { json(e.code || e.status || 500, { error: e.message }); } }); return; }
    if (u.startsWith('/api/')) return json(404, { error: 'not in this test' });
    const f = path.join(DASH, u.replace(/^\/dashboards\//, '')); if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (e, d) => { if (e) { res.writeHead(404); return res.end(); } res.writeHead(200, { 'Content-Type': f.endsWith('.js') ? 'application/javascript' : f.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const url = 'http://127.0.0.1:' + srv.address().port + '/dashboards/incident-response.html?standalone=1';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright'); const browser = await chromium.launch(), errs = [];
  const wait = (p, fn, arg) => p.waitForFunction(fn, arg, { timeout: 15000 }).then(() => true, () => false);
  const dlg = () => 'document.getElementById("dlg").textContent';
  try {
    const ctx = await browser.newContext({ viewport: { width: 1500, height: 1000 }, acceptDownloads: true });
    const p = await ctx.newPage(); p.on('pageerror', (e) => errs.push(e.message)); p.on('dialog', (d) => { errs.push('unexpected dialog'); d.dismiss(); });
    await p.goto(url); ok(await wait(p, () => document.querySelectorAll('#board .inc').length === 2), 'two open incidents on the board');
    ok(/Open incidents/.test(await p.textContent('#kpis')) && /Within SLA|No open/.test(await p.textContent('#ring')), 'KPIs and the SLA ring');
    ok(/has not been acknowledged within its SLA/.test(await p.textContent('#attn')), 'attention: unacknowledged critical');
    ok(/Time to resolve/.test(await p.textContent('#perf')) && (await p.$$('#wk .w')).length === 8, 'performance and 8 weekly bars');
    ok(/XDR-SYN1/.test(await p.textContent('#xdr')), 'XDR incident without a case');
    await p.click('#board .inc[data-open="' + inc.id + '"]'); ok(await wait(p, () => /Similar past incidents/.test(document.getElementById('dlg').textContent)), 'incident detail');
    ok(await wait(p, () => /ended as true-positive/.test(document.getElementById('dlg').textContent)), 'likely resolution from similar cases');
    ok(!(await p.evaluate(() => window.__xss)), 'a hostile title stayed text');
    await p.click('[data-apply="PB-BRUTE-FORCE"]'); ok(await wait(p, () => /Block the external source IP/.test(document.getElementById('dlg').textContent) && document.querySelectorAll('#dlg [data-task]').length > 3), 'recommended playbook applied with its tasks');
    ok(await wait(p, () => /pending/.test(document.getElementById('dlg').textContent)), 'response actions waiting for approval');
    await p.click('#ownme'); ok(await wait(p, () => document.getElementById('own') && document.getElementById('own').value === 'omar.syn'), 'assigned to me');
    await p.click('#dlg [data-task]'); ok(await wait(p, () => document.querySelector('#dlg [data-task]') && document.querySelector('#dlg [data-task]').checked), 'task ticked');
    await p.click('[data-phase="contained"]'); ok(await wait(p, () => document.querySelector('#dlg .flow .on') && document.querySelector('#dlg .flow .on').textContent === 'contained'), 'moved to contained');
    await p.click('[data-phase="closed"]'); await p.click('#doclose'); ok(await wait(p, () => /Choose a resolution/.test(document.body.textContent)), 'closing needs a resolution');
    if (process.env.SHOT) await p.screenshot({ path: process.env.SHOT, fullPage: true });   // optional: a picture for review
    ok(/analyst is off|commander is off/.test(await p.textContent('#ai')), 'AI off says why');
    await p.click('#dlgx');
    await p.click('[data-promote="XDR-SYN1"]'); ok(await wait(p, () => /CASE-\d+ opened/.test(document.body.textContent)) && promoted === 1, 'XDR incident opened as a case');
    ok(await wait(p, () => !document.getElementById('dlg').hidden && /From XDR-SYN1/.test(document.getElementById('dlg').textContent)), 'the new case opens');
    await p.keyboard.press('Escape'); await wait(p, () => document.getElementById('dlg').hidden);
    const [dl] = await Promise.all([p.waitForEvent('download', { timeout: 10000 }), p.click('#xls')]);
    ok(/^incident-response-\d{4}-\d{2}-\d{2}\.xlsx$/.test(dl.suggestedFilename()), 'Excel export');
    { const x = fs.readFileSync(await dl.path(), 'latin1'); ok(x.includes(inc.id) && x.includes('Chance of breach'), 'the Excel file holds the header and the incidents'); }
    // approvals: the requester (omar applied the playbook) cannot decide; another administrator can
    ROLE = 'admin'; USER = 'omar.syn'; const a = await ctx.newPage(); a.on('pageerror', (e) => errs.push(e.message)); await a.goto(url);
    await wait(a, () => document.querySelectorAll('#board .inc').length >= 2); await a.click('#board .inc[data-open="' + inc.id + '"]');
    await wait(a, () => document.querySelector('[data-apr="approved"]')); await a.click('[data-apr="approved"]');
    ok(await wait(a, () => /another administrator must decide/.test(document.body.textContent)), 'the requester cannot decide the response action');
    USER = 'sara.syn'; const a2 = await ctx.newPage(); a2.on('pageerror', (e) => errs.push(e.message)); await a2.goto(url);
    await wait(a2, () => document.querySelectorAll('#board .inc').length >= 2); await a2.click('#board .inc[data-open="' + inc.id + '"]');
    await wait(a2, () => document.querySelector('[data-apr="approved"]')); await a2.click('[data-apr="approved"]');
    ok(await wait(a2, () => /approved/.test(document.getElementById('dlg').textContent) && /sara\.syn/.test(document.getElementById('dlg').textContent)), 'a different administrator approves');
    ok(AUD.some((x) => x.a === 'approval.approved') && AUD.some((x) => x.a === 'case.playbook') && AUD.some((x) => x.a === 'case.status'), 'writes are audited by the case routes');
    // viewer
    ROLE = 'viewer'; USER = 'vera.syn'; const v = await ctx.newPage(); v.on('pageerror', (e) => errs.push(e.message)); await v.goto(url);
    await wait(v, () => document.querySelectorAll('#board .inc').length >= 2); ok(!(await v.$('[data-promote]')), 'viewer: no Open a case');
    await v.click('#board .inc[data-open="' + inc.id + '"]'); await wait(v, () => !document.getElementById('dlg').hidden && /Lifecycle/.test(document.getElementById('dlg').textContent));
    ok(!(await v.$('#ownme')) && !(await v.$('[data-phase]')) && !(await v.$('[data-apr]')), 'viewer: no write controls');
    const nav = fs.readFileSync(path.join(DASH, 'vendor', 'zyb-nav.js'), 'utf8');
    ok(/"h": "incident-response.html"/.test(nav) && /incident-response\.html/.test(fs.readFileSync(path.join(DASH, 'install-dashboards.sh'), 'utf8')), 'menu entry and installer');
    ok(/ir: 'incident-response\.html'/.test(fs.readFileSync(path.join(DASH, 'vendor', 'zyb-menu.js'), 'utf8')) && /ir: 'incident-response\.html'/.test(fs.readFileSync(path.join(DASH, 'vendor', 'zyb-early.js'), 'utf8')), 'the portal\'s Incident Response opens this page');
    void dlg;
    ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  } finally { await browser.close(); srv.close(); fs.rmSync(dir, { recursive: true, force: true }); }
  console.log((bad ? 'FAILED ' : 'ok ') + (n - bad) + '/' + n);
  process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
