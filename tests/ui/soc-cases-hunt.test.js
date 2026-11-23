// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const ZYB_ORG = require('../../brand/index');
// Browser test for Investigations & Cases (soc-cases.html) and Threat Hunting & Search (soc-hunt.html) against the REAL SIEM
// modules (sentra-siem engine/soc/routes.js, analyst-routes.js, investigate-routes.js, xdr/routes.js) with a scripted model and a
// SYNTHETIC event store: KPIs and charts, KPI tiles filter the list, the workspace tabs (stage stepper, alerts with priority,
// merged timeline, tasks, evidence, approvals, suggested alerts added to the case), stage change, note, the AI brief with
// verified / unverified refs added as the person's note; search with histogram, facets, event detail, add a value to the query,
// add an event to a case as evidence, save / share a hunt, rare values, the hunt library, the AI hunt assistant's queries run
// by the analyst; hostile values stay text; a viewer reads cases but is refused hunting.
// Run: SENTRA_SIEM_DIR=/home/user/sentra-siem PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node soc-cases-hunt.test.js
const http = require('http'), fs = require('fs'), path = require('path'), os = require('os');
const SIEM = process.env.SENTRA_SIEM_DIR || path.resolve(__dirname, '../../backend/siem');
const DASH = path.resolve(__dirname, '../../ui');
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const XSS = '<img src=x onerror=alert(1)>';
const { createState } = require(path.join(SIEM, 'engine/soc/state'));
const { createAlerts } = require(path.join(SIEM, 'engine/soc/alerts'));
const { createCases } = require(path.join(SIEM, 'engine/soc/cases'));
const { parse } = require(path.join(SIEM, 'engine/api/query'));
const { fakeApi } = require(path.join(SIEM, 'tests/soc-fakes'));
const quiet = { info() {}, warn() {}, error() {}, debug() {}, child() { return quiet; } };

(async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'socch-'));
  const state = createState({ dir, log: quiet }), alerts = createAlerts({ state, log: quiet }), cases = createCases({ state, alerts, log: quiet });
  const T = Date.now(), H = 3600e3;
  const raise = (o) => alerts.raise(Object.assign({ rule_id: 'SENTRA-AUTH-001', rule_name: 'Brute force then success', severity: 3, group: {}, fields: {}, summary: 'synthetic', ts_first: T - 3 * H, ts_last: T - 2 * H, source: 'engine', count: 1 }, o)).alert;
  const a1 = raise({ group: { user: 'dave' }, fields: { src_ip: '198.51.100.9' }, summary: 'Brute force then success for dave ' + XSS });
  const a2 = raise({ rule_id: 'SENTRA-EXO-001', rule_name: 'Forwarding rule', severity: 2, group: { user: 'dave' }, summary: 'Inbox forwarding to an external address' });
  const c1 = cases.create({ title: 'Account compromise dave (synthetic) ' + XSS, alert_ids: [a1.id] }, 'nora.syn');
  cases.create({ title: 'Old phishing case (synthetic)', severity: 1, auto_playbook: false }, 'nora.syn');
  // synthetic event store with the real query parser
  const EV = [{ id: 'e-1', ts: new Date(T - H).toISOString(), src_type: 'windows', host: 'pc-9', user: 'dave', src_ip: '10.0.0.9', action: 'logon', outcome: 'success', message: 'logon (synthetic) ' + XSS },
    { id: 'e-2', ts: new Date(T - 2 * H).toISOString(), src_type: 'windows', host: 'pc-9', user: 'dave', src_ip: '10.0.0.9', action: 'logon', outcome: 'failure', message: 'failed logon (synthetic)' }];
  const searches = [];
  const search = {
    parse,
    search: async (o) => { parse(o.q); searches.push(o.q); return { rows: EV.filter((e) => !o.q || /dave|logon|pc-9/.test(o.q)), total_estimate: 2 }; },
    histogram: async (o) => { parse(o.q); return { buckets: Array.from({ length: 24 }, (_, i) => ({ t: T - (24 - i) * H, n: i % 5 })) }; },
    top: async (o) => { parse(o.q); return { values: [{ v: o.field === 'user' ? 'dave' : 'pc-9', n: 2 }] }; },
    fetchEvents: async (o) => { parse(o.q); if (/category:process/.test(o.q)) return o.from > T - 2 * 864e5 ? [{ ts: T - H, host: 'pc-9', user: 'dave', parent_process: 'C:\\Program Files\\Microsoft Office\\WINWORD.EXE', process: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe' }] : [];
      if (/category:authentication/.test(o.q)) return Array.from({ length: 7 }, (_, i) => ({ ts: T - 2 * H + i * 60000, user: 'dave', host: 'pc-' + i })); return []; },
    rare: async (o) => (o.field === 'dns_query' ? { values: [{ v: 'xk7q9zt2vbn4mwp8.com', n: 3, hosts: 1 }, { v: ZYB_ORG.domain, n: 2, hosts: 1 }] } : { values: [{ v: 'mimikatz.exe', n: 1, hosts: 1, first: new Date(T - H).toISOString(), last: new Date(T - H).toISOString() }] }),
    newValues: async (o) => ({ values: [], baseline_days: o.baselineDays }),
  };
  let script = [];
  class FakeAnthropic { constructor() { this.messages = { create: async () => { const r = script.shift(); if (!r) throw new Error('script ended'); return r; } }; } }
  const turn = (content, stop = 'tool_use') => ({ content, stop_reason: stop, usage: { input_tokens: 50, output_tokens: 10 } });
  const deps = { state, alerts, cases, search, log: quiet, sdk: FakeAnthropic, noTimers: true,
    config: { soc_analyst: {}, secrets: { netops: { anthropic_api_key: 'sk-ant-synthetic-for-tests' } }, ai_limits: { per_user_hour: 100, per_user_day: 1000, daily_tokens: 1e9, max_prompt_chars: 1e6 } } };
  const api = fakeApi({ realRanks: true });
  // the core server's search routes (engine/api/routes.js): analyst and above
  for (const [p, fn] of [['/api/soc/search', 'search'], ['/api/soc/histogram', 'histogram'], ['/api/soc/top', 'top']]) api.route('POST', p, async (ctx) => { ctx.need('analyst'); return search[fn](ctx.body || {}); });
  require(path.join(SIEM, 'engine/soc/routes')).register(api, deps);
  require(path.join(SIEM, 'engine/xdr/routes')).register(api, deps);
  require(path.join(SIEM, 'engine/soc/analyst-routes')).register(api, deps);
  require(path.join(SIEM, 'engine/soc/investigate-routes')).register(api, deps);
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
    if (u.pathname.startsWith('/api/')) return json(404, { error: 'not in this test' });
    const f = path.join(DASH, u.pathname.replace(/^\/dashboards\//, '/')); if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (err, d) => { if (err) { res.writeHead(404); res.end(); return; } res.writeHead(200, { 'Content-Type': u.pathname.endsWith('.js') ? 'application/javascript' : u.pathname.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port + '/';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  const wait = (p, fn, arg) => p.waitForFunction(fn, arg, { timeout: 10000 }).then(() => true, () => false);
  try {
    const p = await browser.newPage({ viewport: { width: 1500, height: 1000 } }); p.on('pageerror', (x) => errs.push(x.message));
    p.on('dialog', (d) => { errs.push('dialog: ' + d.message()); d.dismiss(); });
    // ================= Cases
    await p.goto(base + 'soc-cases.html?standalone=1'); await p.waitForSelector('#list table', { timeout: 15000 });
    const kp = await p.textContent('#kpis');
    ok(/Open cases\s*2/.test(kp) && /Actions awaiting approval\s*[1-9]/.test(kp), 'KPIs: ' + kp.replace(/\s+/g, ' ').slice(0, 220));
    ok(await p.$$eval('canvas:not([hidden])', (c) => c.length >= 2 && c.every((x) => x.getAttribute('role') === 'img' && x.getAttribute('aria-label'))) && /No case has an owner yet/.test(await p.textContent('body')), 'charts drawn and labelled; the empty workload chart says so');
    ok((await p.$$eval('#list tbody tr', (x) => x.length)) === 2 && !(await p.$('#list img')), 'two cases listed, hostile title stays text');
    await p.click('.so-kpi:has-text("Unassigned")'); ok(await wait(p, () => document.getElementById('own').value === '-'), 'Unassigned tile filters the list');
    await p.selectOption('#own', ''); await p.waitForTimeout(300);
    await p.click('#list tr[data-case="' + c1.id + '"]'); await p.waitForSelector('#wsp', { timeout: 10000 });
    ok(await p.$$eval('.so-step', (s) => s.length === 6) && /open/.test(await p.textContent('.so-step.cur')), 'stage stepper shows the current stage');
    ok(/user:dave/.test(await p.textContent('#tabb')), 'scope on the overview');
    await p.click('[data-tab="alerts"]'); ok(/Brute force then success/.test(await p.textContent('#tabb')) && !(await p.$('#tabb img')), 'alerts tab');
    await p.click('[data-tab="timeline"]'); ok(/alert:first-seen/.test(await p.textContent('#tabb')) && /case:created/.test(await p.textContent('#tabb')), 'merged timeline');
    await p.click('[data-tab="approvals"]'); ok(/awaiting|pending/.test(await p.textContent('#tabb')), 'approvals tab shows the playbook actions waiting');
    await p.click('[data-tab="suggested"]'); ok(/Forwarding rule/.test(await p.textContent('#tabb')), 'the forwarding alert for dave is suggested');
    await p.check('[data-sug="' + a2.id + '"]'); await p.click('#addsug');
    ok(await wait(p, (id) => document.querySelector('[data-tab="alerts"]') && /2/.test(document.querySelector('[data-tab="alerts"]').textContent), a2.id), 'suggested alert added');
    ok(cases.get(c1.id).alerts.includes(a2.id), 'the case holds the alert in the SIEM');
    await p.click('[data-tab="overview"]'); await p.selectOption('#f-stage [name=status]', 'investigating'); await p.fill('#f-stage [name=note]', 'starting (synthetic)'); await p.click('#f-stage [type=submit]');
    ok(await wait(p, () => /investigating/.test((document.querySelector('.so-step.cur') || {}).textContent || '')), 'stage moved to investigating');
    await p.click('#mine'); ok(await wait(p, () => /nora\.syn/.test(document.getElementById('tabb').textContent)), 'took ownership');
    await p.fill('#f-note [name=text]', 'Called dave, he did not log in at 03:00 (synthetic).'); await p.click('#f-note [type=submit]');
    ok(await wait(p, () => true) && cases.get(c1.id).timeline.some((x) => x.kind === 'note' && /did not log in/.test(x.text)), 'note added');
    await p.click('[data-tab="tasks"]'); await p.fill('#f-task [name=title]', 'Reset dave password (synthetic)'); await p.click('#f-task [type=submit]');
    ok(await wait(p, () => /Reset dave password/.test(document.getElementById('tabb').textContent)), 'task added');
    // AI brief
    script = [turn([{ type: 'tool_use', id: 'b1', name: 'get_case', input: { id: c1.id } }]),
      turn([{ type: 'tool_use', id: 'b2', name: 'submit_brief', input: { summary: 'Dave signed in after failures (synthetic).', containment: 'none', timeline: [{ what: 'brute force then success', ref: a1.id }, { what: 'invented', ref: 'ALR-0099999' }], scope: { users: ['dave'] }, gaps: ['no EDR on pc-9'], next_steps: ['Reset password'], report: 'Synthetic report.' } }])];
    await p.click('[data-tab="brief"]'); await p.click('#brief');
    ok(await wait(p, () => /AI draft/.test(document.getElementById('tabb').textContent)), 'brief drafted');
    const bt = await p.textContent('#tabb'); ok(/✓/.test(bt) && /⚠/.test(bt) && /2 item\(s\) cite something no tool returned/.test(bt), "verified and unverified refs shown (the invented alert id and dave, whom get_case does not return)");
    if (process.env.SHOT) await p.screenshot({ path: process.env.SHOT + '-cases.png', fullPage: true });
    await p.click('#f-brief [data-bd="add"]');
    ok(await wait(p, () => /added by nora\.syn/.test(document.getElementById('tabb').textContent)), 'brief added');
    ok(cases.get(c1.id).timeline.some((x) => x.kind === 'note' && x.by === 'nora.syn' && /reviewed and added by nora\.syn/.test(x.text)), 'the brief is a note in the person\'s name');
    ok(!(await p.textContent('#err')).trim(), 'no error after the summary reloaded with an empty chart: ' + (await p.textContent('#err')));
    // new case form
    await p.click('#new'); await p.fill('#newf [name=title]', 'Suspicious VPN logon (synthetic)'); await p.selectOption('#newf [name=severity]', '3'); await p.click('#newf [type=submit]');
    ok(await wait(p, () => /Suspicious VPN logon/.test(document.getElementById('list').textContent)), 'new case opened from the inline form');
    // ================= Hunting
    await p.goto(base + 'soc-hunt.html?standalone=1'); await p.waitForFunction(() => /Event store/.test(document.getElementById('srcs').textContent), null, { timeout: 15000 });
    await p.fill('#q', 'user:dave AND action:logon'); await p.click('#qf [type=submit]');
    ok(await wait(p, () => document.querySelectorAll('#res tbody tr').length === 2), 'search results');
    ok(!(await p.$('#res img')), 'hostile event text stays text');
    ok(/Matching events over time/.test(await p.getAttribute('#c-hist', 'aria-label') || ''), 'histogram drawn and labelled');
    ok(await wait(p, () => /dave/.test(document.getElementById('facl').textContent)), 'top values');
    if (process.env.SHOT) { await p.waitForTimeout(500); await p.screenshot({ path: process.env.SHOT + '-hunt.png' }); }
    await p.click('#res tr[data-ev="0"]'); ok(await wait(p, () => /pc-9/.test((document.getElementById('zd') || {}).textContent || '')), 'event detail');
    await p.fill('#evf [name=case]', c1.id); await p.click('#evf [type=submit]');
    ok(await wait(p, () => document.getElementById('zd').hidden), 'evidence added, drawer closed');
    ok(cases.get(c1.id).evidence.some((e) => /query: user:dave/.test(e.ref) && e.by === 'nora.syn'), 'event recorded as case evidence with its query');
    await p.click('#res tr[data-ev="0"]'); await p.waitForSelector('#zd [data-add]', { timeout: 8000 });
    await p.click('#zd [data-add*="host:"]');
    ok(await wait(p, () => /host:"pc-9"/.test(document.getElementById('q').value)), 'a value from the detail is added to the query');
    await p.click('#save'); await p.fill('#savef [name=name]', 'Dave logons (synthetic)'); await p.check('#savef [name=shared]'); await p.click('#savef [type=submit]');
    ok(await wait(p, () => document.getElementById('savef').hidden), 'hunt saved');
    await p.click('[data-tab="saved"]'); ok(await wait(p, () => /Dave logons/.test(document.getElementById('saved').textContent) && /shared/.test(document.getElementById('saved').textContent)), 'saved and shared hunt listed');
    await p.click('[data-tab="rare"]'); await p.selectOption('#rfield', 'process'); await p.click('#rf [type=submit]');
    ok(await wait(p, () => /mimikatz\.exe/.test(document.getElementById('rout').textContent)), 'rare values');
    await p.click('[data-tab="lib"]'); ok(/Encoded or obfuscated PowerShell/.test(await p.textContent('#lib')), 'hunt library');
    await p.click('[data-lib="0"]'); ok(await wait(p, () => /-enc/.test(document.getElementById('q').value)), 'library hunt loaded and run');
    // machine-learning hunts
    await p.click('[data-tab="ml"]');
    ok(await wait(p, () => /xk7q9zt2vbn4mwp8\.com/.test(document.getElementById('ml-dga').textContent)), 'ML hunts: a DGA-like domain');
    ok(!new RegExp(ZYB_ORG.domain_re).test(await p.textContent('#ml-dga')) && /entropy/.test(await p.textContent('#ml-dga')), 'a normal domain is not a lead; features named');
    ok(/winword\.exe → powershell\.exe/.test(await p.textContent('#ml-lin')) && /macro and document exploits/.test(await p.textContent('#ml-lin')), 'ML hunts: Office starting a shell');
    ok(/dave/.test(await p.textContent('#ml-fan')) && /7 hosts within one hour/.test(await p.textContent('#ml-fan')), 'ML hunts: logon fan-out');
    if (process.env.SHOT) await p.screenshot({ path: process.env.SHOT + '-mlhunt.png', fullPage: true });
    await p.click('#ml-lin [data-huntq]');
    ok(await wait(p, () => /parent_process:\*winword\.exe AND process:\*powershell\.exe/.test(document.getElementById('q').value) && !document.getElementById('tab-search').hidden), 'Hunt this puts the query in the search and runs it');
    ok(searches.some((q) => /parent_process:\*winword\.exe/.test(q)), 'the lead query is valid for the query language');
    script = [turn([{ type: 'tool_use', id: 'h1', name: 'count_events', input: { q: 'process:powershell.exe', hours: 24 } }]),
      turn([{ type: 'tool_use', id: 'h2', name: 'submit_hunt', input: { explanation: 'Encoded PowerShell (synthetic) ' + XSS, queries: [{ q: 'process:powershell.exe AND cmdline:"-enc"', purpose: 'encoded commands', mitre: ['T1059.001'] }, { q: 'user:(broken', purpose: 'x' }] } }])];
    await p.click('[data-tab="ai"]'); await p.fill('#aq', 'Which hosts ran encoded PowerShell?'); await p.click('#ask');
    ok(await wait(p, () => /Run this query/.test(document.getElementById('aout').textContent)), 'AI hunt queries shown');
    ok(/1 proposed query\(ies\) did not compile/.test(await p.textContent('#aout')) && !(await p.$('#aout img')), 'broken query dropped; hostile explanation stays text');
    await p.click('[data-runq="0"]'); ok(await wait(p, () => /cmdline:"-enc"/.test(document.getElementById('q').value) && !document.getElementById('tab-search').hidden), 'the analyst runs the proposed query');
    ok(api.audits.some((x) => x.action === 'soc.hunt.assist') && api.audits.some((x) => x.action === 'soc.hunt.save') && api.audits.some((x) => x.action === 'soc.case.brief.decide'), 'audited');
    // ================= a viewer
    // entity timeline: one user across events, alerts and cases; a missing source is named; a hostile value stays text
    await p.goto(base + 'soc-hunt.html?standalone=1&entity=dave'); 
    ok(await wait(p, () => !document.getElementById('tab-entity').hidden && /events in the window/.test(document.getElementById('eout').textContent)), 'the entity timeline opens from a link (?entity=dave)');
    const et = await p.textContent('#eout');
    ok(/Event \(|Events \(\d+\)/.test(et) && /alerts: ok/.test(et) && /ueba: not available/.test(et), 'events listed; each source says what it answered, a missing one is named');
    await p.click('[data-ef="event"]'); ok(await wait(p, () => document.querySelectorAll('#eout tbody tr').length >= 1), 'filter to one source');
    await p.click('[data-esearch]'); ok(await wait(p, () => !document.getElementById('tab-search').hidden && /user:"dave"/.test(document.getElementById('q').value)), '"Search these events" runs the same query on the Search tab');
    await p.click('[data-tab="entity"]'); await p.fill('#eq', XSS); await p.click('#ef [type=submit]');
    ok(await wait(p, () => /no quotes or angle brackets/.test(document.getElementById('eout').textContent)), 'a hostile value is refused by the server and stays text');
    WHO = { user: 'v.syn', role: 'viewer' };
    await p.goto(base + 'soc-cases.html?standalone=1'); await p.waitForSelector('#list table', { timeout: 15000 });
    ok(await p.$eval('#new', (b) => b.hidden), 'a viewer cannot open cases');
    await p.goto(base + 'soc-hunt.html?standalone=1'); await p.waitForFunction(() => /Event store/.test(document.getElementById('srcs').textContent), null, { timeout: 15000 });
    await p.fill('#q', 'user:dave'); await p.click('#qf [type=submit]');
    ok(await wait(p, () => /requires role analyst/.test(document.getElementById('res').textContent)), 'a viewer is refused raw-event search');
    ok(await p.evaluate(() => { const a = (window.ZYB_NAV || []).find((x) => x.id === 'soc'); const g = (n) => a.pages.filter((x) => x.g === n).map((x) => x.h); return a && g('Monitor').slice(0, 2).join() === 'soc-overview.html,soc-alerts.html' && g('Investigate').slice(0, 2).join() === 'soc-cases.html,soc-hunt.html'; }), 'menu order: Monitor starts with Overview, Alert Queue; Investigate with Cases, Hunting');
  } finally { await browser.close(); srv.close(); fs.rmSync(dir, { recursive: true, force: true }); }
  ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks');
  process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
