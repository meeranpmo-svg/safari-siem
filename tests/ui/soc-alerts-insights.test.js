// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for the Alert Queue insights panel (soc-alerts.html + GET /soc/queue/insights) against the REAL SIEM modules
// (sentra-siem engine/soc/alerts.js, cases.js, analyst-routes.js, queue-insights.js) with a scripted model and SYNTHETIC alerts:
// KPIs, the priority histogram and the raised / closed chart drawn and labelled, a possible campaign of three rules on one host
// in kill-chain order with its drawer and an entity that filters the queue, an overdue SLA, how similar alerts were closed before
// (row bar and drawer), "AI triage the top N" running drafts one after the other (a person still decides), the panel hidden and
// shown, a hostile value stays text, a viewer gets no panel, phone width, no page errors.
// Run: SENTRA_SIEM_DIR=/home/user/sentra-siem PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node soc-alerts-insights.test.js
const http = require('http'), fs = require('fs'), path = require('path'), os = require('os');
const SIEM = process.env.SENTRA_SIEM_DIR || path.resolve(__dirname, '../../backend/siem');
const DASH = path.resolve(__dirname, '../../ui');
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const { createState } = require(path.join(SIEM, 'engine/soc/state'));
const { createAlerts } = require(path.join(SIEM, 'engine/soc/alerts'));
const { createCases } = require(path.join(SIEM, 'engine/soc/cases'));
const { fakeApi } = require(path.join(SIEM, 'tests/soc-fakes'));
const quiet = { info() {}, warn() {}, error() {}, debug() {}, child() { return quiet; } };

(async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'socqi-'));
  const state = createState({ dir, log: quiet }), alerts = createAlerts({ state, log: quiet }), cases = createCases({ state, alerts, log: quiet });
  const T = Date.now(), H = 3600e3;
  const raise = (o) => alerts.raise(Object.assign({ severity: 2, group: {}, fields: {}, summary: 'synthetic', ts_first: T - H, ts_last: T - H, source: 'engine', count: 1 }, o)).alert;
  // a possible campaign: three rules on one host, initial access -> execution -> credential access
  const c1 = raise({ rule_id: 'SENTRA-SYN-PH', rule_name: 'Synthetic phishing click <img src=x onerror=window.__cx=1>', severity: 3, tactic: 'initial-access', group: { host: 'pc-syn-7', user: 'syn.lina' } });
  const c2 = raise({ rule_id: 'SENTRA-SYN-PS', rule_name: 'Synthetic encoded PowerShell', severity: 3, tactic: 'execution', group: { host: 'pc-syn-7' } });
  const c3 = raise({ rule_id: 'SENTRA-SYN-LS', rule_name: 'Synthetic LSASS read', severity: 4, tactic: 'credential-access', group: { host: 'pc-syn-7' } });
  state.collection('alerts').patch(c3.id, (x) => { x.created = T - 3 * H; });   // critical, nobody acknowledged it for 3 h: SLA (1 h) overdue
  // precedent: the VPN rule on syn.omar was closed as false positive three times
  for (let i = 0; i < 5; i++) { const a = raise({ rule_id: 'SENTRA-SYN-VPN', rule_name: 'Synthetic VPN from a new country', group_key: 'p' + i, group: { user: 'syn.omar' } }); alerts.setStatus(a.id, 'closed-false-positive', 'syn.ana', 'travel to the Riyadh office'); }
  const vpn = raise({ rule_id: 'SENTRA-SYN-VPN', rule_name: 'Synthetic VPN from a new country', group_key: 'p9', group: { user: 'syn.omar' } });
  let script = [], asked = 0;
  class FakeAnthropic { constructor() { this.messages = { create: async () => { asked++; const r = script.shift(); if (!r) throw new Error('script ended'); return r; } }; } }
  const turn = (content, stop = 'tool_use') => ({ content, stop_reason: stop, usage: { input_tokens: 50, output_tokens: 10 } });
  const deps = { state, alerts, cases, log: quiet, sdk: FakeAnthropic, noTimers: true,
    config: { soc_analyst: {}, secrets: { netops: { anthropic_api_key: 'sk-ant-synthetic-for-tests' } }, ai_limits: { per_user_hour: 100, per_user_day: 1000, daily_tokens: 1e9, max_prompt_chars: 1e6 } } };
  const api = fakeApi({ realRanks: true });
  require(path.join(SIEM, 'engine/soc/routes')).register(api, deps);
  require(path.join(SIEM, 'engine/soc/analyst-routes')).register(api, deps);
  let WHO = { user: 'nora.syn', role: 'operator' }, insCalls = 0;
  const srv = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://x'), json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u.pathname === '/dashboards/whoami.json') return json(200, WHO);
    if (u.pathname.startsWith('/api/soc/')) {
      if (u.pathname === '/api/soc/soc/queue/insights') insCalls++;
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
  const base = 'http://127.0.0.1:' + srv.address().port + '/soc-alerts.html?standalone=1';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  const wait = (p, fn, arg) => p.waitForFunction(fn, arg === undefined ? null : arg, { timeout: 10000 }).then(() => true, () => false);
  const zd = (p, re) => wait(p, (src) => new RegExp(src).test((document.getElementById('zd') || {}).textContent || ''), re.source);
  try {
    const p = await browser.newPage({ viewport: { width: 1500, height: 1100 } }); p.on('pageerror', (x) => errs.push(x.message));
    p.on('dialog', (d) => { errs.push('dialog: ' + d.message()); d.dismiss(); });
    await p.goto(base);
    ok(await wait(p, () => !document.getElementById('ins').hidden && /Possible campaigns/.test(document.getElementById('ins-kpi').textContent)), 'insights panel shown');
    const k = (await p.textContent('#ins-kpi')).replace(/\s+/g, ' ');
    ok(/Possible campaigns\s*1\s*1 across 3\+ ATT&CK tactics/.test(k) && /SLA breached\s*[1-9]/.test(k) && /Past closures known\s*1/.test(k), 'KPIs: ' + k);
    ok(/not enough history/.test(k), 'backlog forecast withheld without 7 days of history');
    ok(/Open alerts by priority/.test(await p.getAttribute('#ins-hist svg', 'aria-label')) && /raised and closed per day/.test(await p.getAttribute('#ins-flow svg', 'aria-label')), 'charts drawn and labelled');
    const cm = await p.textContent('#ins-cmp');
    ok(/3 alerts · 3 rules/.test(cm) && /progression/.test(cm) && /host:pc-syn-7/.test(cm) && /initial-access → execution → credential-access/.test(cm), 'campaign in kill-chain order: ' + cm.slice(0, 200));
    ok(!(await p.$('#ins img')) && !(await p.evaluate(() => window.__cx)), 'a hostile rule name stays text');
    ok(/Synthetic LSASS read · acknowledge/.test(await p.textContent('#ins-sla')) && /overdue/.test(await p.textContent('#ins-sla')) && /critical 1h \/ 24h/.test(await p.textContent('#ins-pol')), 'overdue SLA with the policy shown');
    // precedent in the row and in the drawer
    ok(await wait(p, (id) => /mostly false positive · 5 past/.test((document.querySelector('#list tr[data-id="' + id + '"]') || {}).textContent || ''), vpn.id), 'row shows how similar alerts were closed');
    ok(await wait(p, (id) => /suggested: syn\.ana/.test((document.querySelector('#list tr[data-id="' + id + '"]') || {}).textContent || ''), vpn.id), 'row shows the suggested owner');
    const tu = await p.textContent('#ins-tune');
    ok(/Synthetic VPN from a new country/.test(tu) && /user:syn\.omar/.test(tu) && /consider an exclusion/.test(tu) && /nothing is changed from here/.test(tu), 'noisy rule to tune with the dominant entity: ' + tu.slice(0, 200));
    ok(/syn\.ana/.test(await p.textContent('#ins-own')), 'suggested owners summary');
    ok(/hourly baseline building/.test(await p.textContent('#ins-kpi')) && !(await p.$('#ins-surge [role=alert]')), 'surge: baseline building, no false alarm');
    if (process.env.SHOT) await p.screenshot({ path: process.env.SHOT + '-queue-ins.png', fullPage: true });
    // bulk: the campaign rows have no history, so no suggestion
    await p.check('[data-sel="' + c1.id + '"]'); await p.click('#b-sugg');
    ok(await wait(p, () => /No selected unassigned alert has a suggested owner/.test(document.body.innerText)), 'bulk: says when no suggestion applies');
    await p.uncheck('[data-sel="' + c1.id + '"]');
    await p.click('#list tr[data-id="' + vpn.id + '"]');
    ok(await zd(p, /How similar alerts were closed/) && await zd(p, /closed 5 times: 0 true positive, 5 false positive, 0 benign/) && await zd(p, /not a prediction/), 'drawer: precedent with the counts, framed as past decisions');
    ok(await zd(p, /Similar past alerts/) && await zd(p, /travel to the Riyadh office/) && await zd(p, /syn\.ana/), 'drawer: similar past alerts with how they were closed and the note');
    ok(await zd(p, /Suggested owner/) && await zd(p, /syn\.ana closed 5 alert\(s\) of this rule in 90 days/), 'drawer: suggested owner with the reason');
    await p.click('#zd [data-sugg]');
    ok(await wait(p, () => /Assigned to syn\.ana/.test(document.body.innerText)) && alerts.get(vpn.id).assignee === 'syn.ana', 'assigned to the suggested owner in the SIEM, in the person\'s name');
    ok((alerts.get(vpn.id).history || []).some((h) => h.by === 'nora.syn'), 'the assignment is recorded as done by the person who clicked');
    ok(await wait(p, () => { const z = document.getElementById('zd'); return z && !z.hidden && !z.querySelector('[data-sugg]') && /syn\.ana/.test(z.textContent); }), 'the alert reopens with its new owner and no suggestion');
    await p.keyboard.press('Escape'); await wait(p, () => { const z = document.getElementById('zd'); return !z || z.hidden; });
    // campaign drawer and an entity that filters the queue
    await p.click('#ins-cmp [data-cmp="0"]');
    ok(await zd(p, /Possible campaign/) && await zd(p, /not proven to be one attack/), 'campaign drawer, framed as a lead');
    ok(await p.$$eval('#zd [data-open]', (x) => x.length) === 3, 'its three alerts are listed');
    await p.click('#zd [data-qent="host:pc-syn-7"]');
    ok(await wait(p, () => document.getElementById('q').value === 'host:pc-syn-7' && document.querySelectorAll('#list tbody tr').length === 3), 'a shared entity filters the queue to the campaign');
    // AI triage of the top N, one after the other; drafts wait for a person
    ok(await wait(p, () => !document.getElementById('ai5').hidden), 'operator sees the batch triage button');
    const top = await p.textContent('#ai5'); const N = +(/top (\d+)/.exec(top) || [])[1];
    ok(N >= 4, 'top N untriaged: ' + top);
    script = []; for (let i = 0; i < N; i++) script.push(turn([{ type: 'tool_use', id: 's' + i, name: 'submit_triage', input: { verdict: 'needs_more_data', confidence: 'low', summary: 'Synthetic draft.', evidence: [] } }]));
    await p.click('#ai5');
    ok(await p.waitForFunction(() => [...document.querySelectorAll('.toast')].some((x) => /AI draft\(s\) ready - a person still accepts or rejects each/.test(x.textContent)), null, { timeout: 20000 }).then(() => true, () => false), 'batch finished and said so');
    const drafts = state.collection('soc_ai_triage').all();
    ok(drafts.length === N && drafts.every((d) => d.state === 'draft') && asked === N, 'one draft per alert, each still a draft for a person (' + drafts.length + ')');
    ok([c1, c2, c3].every((a) => alerts.get(a.id).status === 'new'), 'nothing closed or changed by the batch');
    // hide / show
    await p.click('#instog'); ok(await p.evaluate(() => document.getElementById('ins').hidden), 'insights hidden');
    await p.click('#instog'); ok(await p.evaluate(() => !document.getElementById('ins').hidden), 'insights shown again');
    // a viewer: no panel, no request
    WHO = { user: 'v.syn', role: 'viewer' }; insCalls = 0;
    const v = await browser.newPage({ viewport: { width: 1300, height: 900 } }); v.on('pageerror', (x) => errs.push(x.message));
    await v.goto(base); await v.waitForSelector('#list table', { timeout: 10000 });
    ok(await v.evaluate(() => document.getElementById('ins').hidden && document.getElementById('ai5').hidden) && insCalls === 0, 'a viewer gets no insights (names people and hosts) and does not ask for them');
    await v.close();
    WHO = { user: 'nora.syn', role: 'analyst' };
    const ph = await browser.newPage({ viewport: { width: 390, height: 900 } }); ph.on('pageerror', (x) => errs.push(x.message));
    await ph.goto(base); await wait(ph, () => !document.getElementById('ins').hidden);
    ok(await ph.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1), 'phone width: no sideways scroll');
    ok(await ph.evaluate(() => document.getElementById('ai5').hidden), 'an analyst cannot run the AI batch');
    await ph.close();
  } finally { await browser.close(); srv.close(); fs.rmSync(dir, { recursive: true, force: true }); }
  ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks');
  process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
