// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for the Security Operations Overview (soc-overview.html) and the Alert Queue (soc-alerts.html) against the REAL
// SIEM modules (sentra-siem engine/soc/alerts.js, cases.js, routes.js, analyst-routes.js + alert-ml.js) with a scripted model and
// SYNTHETIC alerts: KPI tiles and charts drawn (labelled), tiles and lists link into the queue, the priority bands filter, the
// itemised score, grouping of near-identical alerts, search, the AI triage drafted with cited / unverified evidence, accepting
// it to close the alert in the person's name, rejecting needs a note, a hostile value stays text, a viewer cannot triage.
// Run: SENTRA_SIEM_DIR=/home/user/sentra-siem PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node soc-alerts.test.js
const http = require('http'), fs = require('fs'), path = require('path'), os = require('os');
const SIEM = process.env.SENTRA_SIEM_DIR || path.resolve(__dirname, '../../backend/siem');
const DASH = path.resolve(__dirname, '../../ui');
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const XSS = '<img src=x onerror=alert(1)>';
const { createState } = require(path.join(SIEM, 'engine/soc/state'));
const { createAlerts } = require(path.join(SIEM, 'engine/soc/alerts'));
const { createCases } = require(path.join(SIEM, 'engine/soc/cases'));
const { fakeApi } = require(path.join(SIEM, 'tests/soc-fakes'));
const quiet = { info() {}, warn() {}, error() {}, debug() {}, child() { return quiet; } };

(async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'socq-'));
  const state = createState({ dir, log: quiet }), alerts = createAlerts({ state, log: quiet }), cases = createCases({ state, alerts, log: quiet });
  const T = Date.now(), H = 3600e3;
  const raise = (o) => alerts.raise(Object.assign({ rule_id: 'SENTRA-AUTH-001', rule_name: 'Brute force then success', severity: 3, group: {}, fields: {}, summary: 'synthetic', ts_first: T - H, ts_last: T - H, source: 'engine', count: 1 }, o)).alert;
  const hot = raise({ rule_id: 'SENTRA-M365-001', rule_name: 'Risky sign-in', severity: 4, mitre: ['T1078'], tactic: 'initial-access', group: { user: 'carol' }, fields: { src_ip: '203.0.113.66' }, summary: 'Risky sign-in for carol ' + XSS });
  for (let i = 0; i < 4; i++) raise({ rule_id: 'SENTRA-NET-009', rule_name: 'Port scan', severity: 1, group_key: 's' + i, group: { host: 'pc-' + i }, summary: 'Port scan from 10.1.1.' + i + ' to 40 ports' });
  const mid = raise({ rule_id: 'SENTRA-WIN-007', rule_name: 'Admin share access', severity: 2, group: { host: 'srv-fs1' }, summary: 'Admin share access on srv-fs1' });
  // a scripted model: investigates, then submits a draft citing one real alert and one invented id
  let script = [];
  class FakeAnthropic { constructor() { this.messages = { create: async () => { const r = script.shift(); if (!r) throw new Error('script ended'); return r; } }; } }
  const turn = (content, stop = 'tool_use') => ({ content, stop_reason: stop, usage: { input_tokens: 50, output_tokens: 10 } });
  const deps = { state, alerts, cases, log: quiet, sdk: FakeAnthropic, noTimers: true, intel: { lookup: (v) => (v === '203.0.113.66' ? ['abuse-ch-synthetic'] : []) },
    config: { soc_analyst: {}, secrets: { netops: { anthropic_api_key: 'sk-ant-synthetic-for-tests' } }, ai_limits: { per_user_hour: 100, per_user_day: 1000, daily_tokens: 1e9, max_prompt_chars: 1e6 } } };
  const api = fakeApi();
  require(path.join(SIEM, 'engine/soc/routes')).register(api, deps);
  require(path.join(SIEM, 'engine/soc/analyst-routes')).register(api, deps);
  let WHO = { user: 'nora.syn', role: 'operator' };
  const srv = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://x'), json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u.pathname === '/dashboards/whoami.json') return json(200, WHO);
    if (u.pathname.startsWith('/api/soc/')) {
      let b = ''; req.on('data', (c) => { b += c; }); req.on('end', async () => {
        const r = await api.call(req.method, '/api/soc' + u.pathname.slice(8) + u.search, { role: WHO.role, user: WHO.user, body: b ? JSON.parse(b) : undefined });
        json(r.status, r.body);
      }); return;
    }
    // Workflow Automation attention(who), synthetic, in the engine's shape: the security team's queue and an exception waiting for approval
    if (u.pathname === '/api/itam/workflow/attention') return json(200, { summary: { approvals: 1, queue_open: 2, overdue: 1, at_risk: 0, to_accept: 0, raised_open: 0, raised_late: 0, functions: [], all_overdue: 3, recurring: 0,
        teams: [{ team: 'security', name: 'Security engineering', open: 2, overdue: 1, n: 5, on_time: 4, rate: 0.71 }, { team: 'dba', name: 'Database team (DBA)', open: 1, overdue: 2, n: 0, on_time: 0, rate: 0.5 }], items: [] },
      priorities: [{ kind: 'Request approval', ref: 'REQ-2026-0031', text: 'Security exception for the <img src=x onerror=window.__wfx=1> legacy portal - from CISO office (deputy.syn)', page: 'workflow-automation.html#req=REQ-2026-0031', why: [['a business request waiting for your approval', 45]] },
        { kind: 'Request overdue', ref: 'REQ-2026-0029', text: 'Critical vulnerability status - Security engineering, due 2026-11-10 08:00', page: 'workflow-automation.html#req=REQ-2026-0029', why: [['a request to the IT team past its due date', 40], ['escalated', 10]] }] });
    if (u.pathname.startsWith('/api/')) return json(404, { error: 'not in this test' });
    const f = path.join(DASH, u.pathname.replace(/^\/dashboards\//, '/')); if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (err, d) => { if (err) { res.writeHead(404); res.end(); return; } res.writeHead(200, { 'Content-Type': u.pathname.endsWith('.js') ? 'application/javascript' : u.pathname.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port + '/';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  const zd = (p, re) => p.waitForFunction((src) => new RegExp(src).test((document.getElementById('zd') || {}).textContent || ''), re.source, { timeout: 10000 }).then(() => true, () => false);
  try {
    const p = await browser.newPage({ viewport: { width: 1500, height: 1000 } }); p.on('pageerror', (x) => errs.push(x.message));
    p.on('dialog', (d) => { errs.push('dialog: ' + d.message()); d.dismiss(); });
    // ---- Overview
    await p.goto(base + 'soc-overview.html?standalone=1'); await p.waitForFunction(() => /updated/.test(document.getElementById('up').textContent), null, { timeout: 15000 });
    const kp = await p.textContent('#kpis');
    ok(/Open alerts\s*6/.test(kp) && /Act now\s*1/.test(kp), 'KPIs: ' + kp.replace(/\s+/g, ' ').slice(0, 200));
    ok(await p.$$eval('canvas', (c) => c.length >= 4 && c.every((x) => x.getAttribute('role') === 'img' && x.getAttribute('aria-label'))), 'every chart is drawn and labelled for screen readers');
    ok(/Raised/.test(await p.getAttribute('#c-vol', 'aria-label')), 'volume chart reads its data');
    { await p.waitForFunction(() => !document.getElementById('wfgrid').hidden, null, { timeout: 10000 }).catch(() => null); const w = await p.textContent('#wf');
      ok(/Security team · open\s*2/.test(w) && /Security team · overdue\s*1/.test(w) && /Security team · on time\s*80%/.test(w) && /Waiting for your approval\s*1/.test(w) && /Overdue across IT\s*3/.test(w), 'Workflow Automation: the security team\'s open / overdue / on time, approvals, overdue across IT: ' + w.replace(/\s+/g, ' ').slice(0, 260));
      ok(w.indexOf('REQ-2026-0029') < w.indexOf('REQ-2026-0031') && /legacy portal/.test(w) && !(await p.$('#wf img')) && !(await p.evaluate(() => window.__wfx)) && !!(await p.$('#wf a[href="workflow-automation.html#req=REQ-2026-0031"]')), 'Workflow: ranked by points (50 before 45), a hostile title stays text, linked'); }
    if (process.env.SHOT) { await p.waitForTimeout(600); await p.screenshot({ path: process.env.SHOT + '-overview.png', fullPage: true }); }
    ok(/Risky sign-in/.test(await p.textContent('#act')) && !(await p.$('#act img')), 'act-now list, hostile text stays text');
    ok(/Port scan/.test(await p.textContent('#rules')), 'top rules');
    ok(/AI analyst/.test(await p.textContent('#srcs')), 'source chips');
    await p.click('#refresh'); await p.waitForTimeout(500); await p.click('#refresh'); await p.waitForTimeout(500);
    ok(!(await p.textContent('#err')).trim() && await p.$('#c-src') && await p.$('#c-tac'), 'refreshing twice keeps every chart and shows no error');
    await Promise.all([p.waitForURL(/soc-alerts\.html\?label=act-now/), p.click('.so-kpi:has-text("Act now")')]);
    // ---- Queue
    await p.waitForSelector('#list table', { timeout: 15000 });
    ok((await p.$$eval('#list tbody tr', (x) => x.length)) === 1, 'the Act now tile opened the queue filtered to act-now');
    ok(await p.getAttribute('[data-band="act-now"]', 'aria-pressed') === 'true', 'the band is shown as selected');
    await p.click('[data-band=""]'); await p.waitForFunction(() => document.querySelectorAll('#list tbody tr').length === 3, null, { timeout: 8000 }).then(() => ok(true), () => ok(false, 'grouped: 3 rows (4 port scans are one)'));
    ok(/× 4/.test(await p.textContent('#list')), 'the cluster size is shown');
    const first = await p.$eval('#list tbody tr', (r) => r.getAttribute('data-id'));
    ok(first === hot.id, 'highest priority first');
    await p.uncheck('#collapse'); await p.waitForFunction(() => document.querySelectorAll('#list tbody tr').length === 6, null, { timeout: 8000 }).then(() => ok(true), () => ok(false, 'ungrouped: 6 rows'));
    await p.fill('#q', 'srv-fs1'); await p.waitForFunction(() => document.querySelectorAll('#list tbody tr').length === 1, null, { timeout: 8000 }).then(() => ok(true), () => ok(false, 'search'));
    await p.fill('#q', ''); await p.waitForFunction(() => document.querySelectorAll('#list tbody tr').length === 6, null, { timeout: 8000 });
    // ---- drawer: itemised score and the AI analyst
    await p.click('#list tr[data-id="' + hot.id + '"]');
    ok(await zd(p, /Why this priority/), 'drawer opens with the itemised score');
    const dz = await p.textContent('#zd');
    ok(/threat intel/.test(dz) && /203\.0\.113\.66 on abuse-ch-synthetic/.test(dz) && /UEBA not available/.test(dz), 'each factor and missing input explained');
    ok(!(await p.$('#zd img')), 'hostile summary stays text in the drawer');
    script = [turn([{ type: 'tool_use', id: 't1', name: 'get_alert', input: { id: hot.id } }]),
      turn([{ type: 'tool_use', id: 't2', name: 'submit_triage', input: { verdict: 'true_positive', confidence: 'medium', severity: 4, summary: 'Sign-in for carol from an IP on an abuse list.', evidence: [{ ref: hot.id, fact: 'risky sign-in' }, { ref: 'ALR-9999999', fact: 'invented' }], next_steps: ['Call carol to confirm'], mitre: ['T1078'], playbook: 'PB-ACCOUNT-COMPROMISE' } }])];
    await p.click('[data-tri="' + hot.id + '"]');
    ok(await zd(p, /AI draft/), 'AI draft shown');
    const d2 = await p.textContent('#zd');
    ok(/True positive/.test(d2) && /✓/.test(d2) && /⚠/.test(d2) && /1 evidence item\(s\) cite something no tool returned/.test(d2), 'verdict with verified and unverified evidence');
    ok(/PB-ACCOUNT-COMPROMISE/.test(d2), 'proposed playbook shown');
    if (process.env.SHOT) await p.screenshot({ path: process.env.SHOT + '-queue.png' });
    // reject without a note is refused by the SIEM
    await p.click('#dform [data-dec="reject"]');
    ok(await p.waitForFunction(() => /note is required/.test((document.getElementById('dform') || {}).textContent || ''), null, { timeout: 8000 }).then(() => true, () => false), 'reject needs a note');
    await p.selectOption('#dform [name=close]', 'true-positive'); await p.check('#dform [name=open_case]'); await p.click('#dform [data-dec="accept"]');
    ok(await zd(p, /accepted by nora\.syn/), 'accepted by the person');
    ok(alerts.get(hot.id).status === 'closed-true-positive' && (alerts.get(hot.id).history || []).some((h) => h.by === 'nora.syn'), 'closed in the person\'s name');
    const cs = state.collection('cases').all()[0]; ok(cs && cs.playbook_id === 'PB-ACCOUNT-COMPROMISE' && state.collection('approvals').all().length > 0, 'case opened with approval requests, nothing executed');
    await p.keyboard.press('Escape');
    // ---- acknowledge from the drawer, bulk assign
    await p.click('#list tr[data-id="' + mid.id + '"]'); await p.waitForSelector('[data-ack]', { timeout: 8000 }); await p.click('[data-ack]');
    await p.waitForFunction(() => /acknowledged/.test((document.getElementById('zd') || {}).textContent || ''), null, { timeout: 8000 }).then(() => ok(true), () => ok(false, 'acknowledged'));
    await p.keyboard.press('Escape');
    await p.check('#all'); await p.click('#b-me');
    await p.waitForFunction(() => /nora\.syn/.test(document.getElementById('list').textContent), null, { timeout: 8000 }).then(() => ok(true), () => ok(false, 'bulk assign'));
    ok(alerts.all((a) => a.assignee === 'nora.syn').length >= 5, 'assigned in the SIEM');
    // ---- a viewer reads but cannot run the AI
    WHO = { user: 'v.syn', role: 'viewer' }; await p.goto(base + 'soc-alerts.html?standalone=1&id=' + encodeURIComponent(mid.id));
    ok(await zd(p, /needs the operator role/), 'a viewer is told the AI needs the operator role');
    ok(!(await p.$('[data-tri]')) && !(await p.$('#all')), 'no triage button, no bulk selection for a viewer');
    ok(await p.evaluate(() => (window.ZYB_NAV || []).some((a) => a.id === 'soc' && a.sn === 'SOC & Response' && a.pages[0].h === 'soc-overview.html' && a.pages[1].h === 'soc-alerts.html')), 'menu: Security Operations starts with Overview and Alert Queue');
  } finally { await browser.close(); srv.close(); fs.rmSync(dir, { recursive: true, force: true }); }
  ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks');
  process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
