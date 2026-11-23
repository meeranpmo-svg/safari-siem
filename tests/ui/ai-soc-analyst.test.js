// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// ai-soc-analyst.html against the REAL SOC Copilot (sentra-siem engine/soc/copilot.js + copilot-routes.js) with a SCRIPTED model and
// SYNTHETIC alerts: a quick question is asked in the context of an alert, the answer is shown as text (a hostile answer stays text,
// no links from model text), the proposed case waits on the right and an operator accepts it (the case opens as that person); the
// conversation is listed and reopened; an incident report is drafted (marked as an AI draft, copy / download offered); a viewer is
// refused with the reason; the menu entry, installer and the old portal's "AI SOC Analyst" redirect.
// Run: SENTRA_SIEM_DIR=/home/user/sentra-siem PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node ai-soc-analyst.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const SIEM = process.env.SENTRA_SIEM_DIR || path.resolve(__dirname, '../../backend/siem');
const DASH = path.resolve(__dirname, '../../ui');
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const XSS = '<img src=x onerror="window.__xss=1">';
const { createState } = require(path.join(SIEM, 'engine/soc/state'));
const { createAlerts } = require(path.join(SIEM, 'engine/soc/alerts'));
const { createCases } = require(path.join(SIEM, 'engine/soc/cases'));
const { fakeApi, tmpDir, quietLog } = require(path.join(SIEM, 'tests/soc-fakes'));
const H = 36e5, NOW = Date.now();
const use = (id, name, input) => ({ type: 'tool_use', id, name, input });
const turn = (content, stop = 'tool_use') => ({ content, stop_reason: stop, usage: { input_tokens: 50, output_tokens: 10 } });
const say = (text) => turn([{ type: 'text', text }], 'end_turn');
(async () => {
  const dir = tmpDir(), state = createState({ dir, log: quietLog }), alerts = createAlerts({ state, log: quietLog }), cases = createCases({ state, alerts, log: quietLog });
  let script = [];
  class FakeAnthropic { constructor() { this.messages = { create: async () => { const r = script.shift(); if (!r) throw new Error('script ended'); return r; } }; } }
  const config = { soc_analyst: {}, secrets: { netops: { anthropic_api_key: 'sk-ant-synthetic-for-tests' } }, ai_limits: { per_user_hour: 100, per_user_day: 1000, daily_tokens: 1e9, max_prompt_chars: 1e6 } };
  const api = fakeApi({ realRanks: true }); require(path.join(SIEM, 'engine/soc/copilot-routes')).register(api, { state, alerts, cases, config, log: quietLog, sdk: FakeAnthropic, noTimers: true });
  const a1 = alerts.raise({ rule_id: 'SENTRA-AUTH-001', rule_name: 'Brute force then success', severity: 3, group: { user: 'dave' }, fields: {}, summary: 'synthetic', ts_first: NOW - 2 * H, ts_last: NOW - H, source: 'engine', count: 3 }).alert;
  let WHO = { user: 'omar.syn', role: 'operator' };
  const srv = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://x'), json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u.pathname === '/dashboards/whoami.json') return json(200, WHO);
    if (u.pathname.startsWith('/api/soc/')) { let b = ''; req.on('data', (c) => { b += c; }); req.on('end', async () => { const r = await api.call(req.method, u.pathname + u.search, { role: WHO.role, user: WHO.user, body: b ? JSON.parse(b) : undefined }); json(r.status, r.body); }); return; }
    if (u.pathname.startsWith('/api/')) return json(404, { error: 'not in this test' });
    const f = path.join(DASH, u.pathname.replace(/^\/dashboards\//, '/')); if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (err, d) => { if (err) { res.writeHead(404); res.end(); return; } res.writeHead(200, { 'Content-Type': u.pathname.endsWith('.js') ? 'application/javascript' : u.pathname.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const url = 'http://127.0.0.1:' + srv.address().port + '/dashboards/ai-soc-analyst.html';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  const wait = (p, fn, arg) => p.waitForFunction(fn, arg, { timeout: 20000 }).then(() => true, () => false);
  try {
    const p = await browser.newPage({ viewport: { width: 1500, height: 1000 } }); p.on('pageerror', (x) => errs.push(x.message)); p.on('dialog', (d) => d.accept(''));
    await p.goto(url + '?kind=alert&id=' + a1.id); ok(await wait(p, () => !document.getElementById('main').hidden && /AI on/.test(document.getElementById('st').textContent)), 'opens with the AI on');
    ok(await p.$eval('#ck', (s) => s.value) === 'alert' && await p.$eval('#cid', (i) => i.value) !== '', 'the alert from the link is the context');
    ok((await p.$$('#quick button')).length === 7, 'seven quick questions');
    script = [turn([use('c1', 'get_alert', { id: a1.id })]), turn([use('c2', 'propose_open_case', { title: 'Account compromise dave (synthetic)', alert_ids: [a1.id], reason: 'brute force then success' })]),
      say('Work ' + a1.id + ' first: a brute force then success for dave. ' + XSS + ' I proposed opening a case.')];
    await p.click('#quick button[data-qk="0"]');
    ok(await wait(p, () => /Work ALR-/.test(document.getElementById('chat').textContent) && /proposed opening a case/.test(document.getElementById('chat').textContent)), 'the answer appears, citing the alert');
    ok(/read: get_alert/.test(await p.textContent('#chat')), 'which records it read');
    ok(!(await p.evaluate(() => window.__xss)) && !(await p.$('#chat a')), 'model text stays text: no markup, no links');
    ok(await wait(p, () => /open case/.test(document.getElementById('props').textContent)), 'the proposed case waits on the right');
    ok(state.collection('cases').all().length === 0, 'nothing opened before a person accepts');
    await p.click('[data-dec="accept"]'); ok(await wait(p, () => /Accepted - done as you: open case/.test(document.body.textContent)), 'an operator accepts');
    ok(state.collection('cases').all().length === 1, 'the case is opened as that person');
    ok(await wait(p, () => document.querySelectorAll('#convs .conv').length === 1), 'the conversation is listed');
    await p.click('#new'); ok(/Ask a question/.test(await p.textContent('#chat')), 'a new conversation starts empty');
    await p.click('#convs .conv'); ok(await wait(p, () => /Work ALR-/.test(document.getElementById('chat').textContent)), 'a past conversation reopens');
    // a draft
    script = [turn([use('d1', 'get_alert', { id: a1.id })]), say('AI DRAFT - review before use\nINCIDENT REPORT\nSummary: brute force then success for dave (' + a1.id + ').\nRoot cause: not yet established.')];
    await p.selectOption('#dk', 'incident_report'); await p.click('#draft');
    ok(await wait(p, () => /INCIDENT REPORT/.test(document.getElementById('dout').textContent)), 'an incident report is drafted from the alert');
    ok(/AI draft - review before use/.test(await p.textContent('#dout')) && await p.$('#dcopy') && await p.$('#ddl'), 'marked as a draft; copy and download offered');
    const [dl] = await Promise.all([p.waitForEvent('download', { timeout: 10000 }), p.click('#ddl')]); ok(/^incident_report-\d{4}-\d{2}-\d{2}\.txt$/.test(dl.suggestedFilename()), 'download as a text file');
    // phone
    const ph = await browser.newPage({ viewport: { width: 390, height: 900 } }); await ph.goto(url); await wait(ph, () => !document.getElementById('main').hidden);
    ok(await ph.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1), 'phone width: no sideways scroll'); await ph.close();
    // viewer
    WHO = { user: 'vera.syn', role: 'viewer' }; await p.goto(url);
    ok(await wait(p, () => /for analysts and above/.test(document.getElementById('err').textContent)), 'a viewer is refused with the reason (PDPL)');
    const nav = fs.readFileSync(path.join(DASH, 'vendor', 'zyb-nav.js'), 'utf8');
    ok(/"h": "ai-soc-analyst.html"/.test(nav) && / ai-soc-analyst\.html /.test(fs.readFileSync(path.join(DASH, 'install-dashboards.sh'), 'utf8')), 'menu entry and installer');
    ok(/aisoc: 'ai-soc-analyst\.html'/.test(fs.readFileSync(path.join(DASH, 'vendor', 'zyb-menu.js'), 'utf8')) && /aisoc: 'ai-soc-analyst\.html'/.test(fs.readFileSync(path.join(DASH, 'vendor', 'zyb-early.js'), 'utf8')), 'the old portal\'s "AI SOC Analyst" opens this page');
    ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  } finally { await browser.close(); srv.close(); fs.rmSync(dir, { recursive: true, force: true }); }
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n);
  process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
