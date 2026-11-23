// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for the SOC Copilot panel (vendor/zyb-copilot.js) on the Alert Queue against the REAL SIEM modules (sentra-siem
// engine/soc/routes.js, analyst-routes.js, investigate-routes.js, copilot-routes.js) with a scripted model and SYNTHETIC
// alerts: the button and panel, the page + record context reaching the model, a suggestion asked, the answer rendered safely
// (bold kept, hostile HTML and links never live), a proposal card accepted and run as the person (case opened), a rejected
// card, earlier conversations reloaded, an analyst told the role a card needs, no Copilot for a viewer.
// Run: SENTRA_SIEM_DIR=/home/user/sentra-siem PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node soc-copilot.test.js
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
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'soccp-'));
  const state = createState({ dir, log: quiet }), alerts = createAlerts({ state, log: quiet }), cases = createCases({ state, alerts, log: quiet });
  const T = Date.now(), H = 36e5;
  const a1 = alerts.raise({ rule_id: 'SENTRA-AUTH-001', rule_name: 'Brute force then success', severity: 4, group: { user: 'dave' }, fields: {}, summary: 'Brute force for dave', ts_first: T - H, ts_last: T - H, source: 'engine' }).alert;
  const a2 = alerts.raise({ rule_id: 'SENTRA-EXO-001', rule_name: 'Forwarding rule', severity: 2, group: { user: 'dave' }, fields: {}, summary: 'Inbox forwarding', ts_first: T - H, ts_last: T - H, source: 'engine' }).alert;
  const calls = []; let script = [];
  class FakeAnthropic { constructor() { this.messages = { create: async (p) => { calls.push(JSON.parse(JSON.stringify(p))); const r = script.shift(); if (!r) throw new Error('script ended'); return r; } }; } }
  const turn = (content, stop = 'tool_use') => ({ content, stop_reason: stop, usage: { input_tokens: 50, output_tokens: 10 } });
  const say = (text) => turn([{ type: 'text', text }], 'end_turn');
  const deps = { state, alerts, cases, search: { parse }, log: quiet, sdk: FakeAnthropic, noTimers: true,
    config: { soc_analyst: {}, secrets: { netops: { anthropic_api_key: 'sk-ant-synthetic-for-tests' } }, ai_limits: { per_user_hour: 100, per_user_day: 1000, daily_tokens: 1e9, max_prompt_chars: 1e6 } } };
  const api = fakeApi({ realRanks: true });
  for (const m of ['routes', 'analyst-routes', 'investigate-routes', 'copilot-routes']) require(path.join(SIEM, 'engine/soc/' + m)).register(api, deps);
  let WHO = { user: 'omar.syn', role: 'operator' };
  const srv = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://x'), json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u.pathname === '/dashboards/whoami.json') return json(200, WHO);
    if (u.pathname.startsWith('/api/soc/')) {
      let b = ''; req.on('data', (c) => { b += c; }); req.on('end', async () => { const r = await api.call(req.method, '/api/soc' + u.pathname.slice(8) + u.search, { role: WHO.role, user: WHO.user, body: b ? JSON.parse(b) : undefined }); json(r.status, r.body); }); return;
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
    await p.goto(base + 'soc-alerts.html?standalone=1&id=' + encodeURIComponent(a1.id)); await p.waitForSelector('#cop-b', { timeout: 15000 });
    ok(await wait(p, () => !document.getElementById('zd').hidden), 'the alert drawer opened (context set)');
    await p.keyboard.press('Escape');
    await p.click('#cop-b'); ok(await p.isVisible('#cop'), 'panel opens');
    ok(new RegExp('alert\\s*' + a1.id).test(await p.textContent('#cop .ctx')), 'context line names the alert: ' + await p.textContent('#cop .ctx'));
    ok((await p.$$('#cop [data-sug]')).length === 3, 'page suggestions');
    script = [turn([{ type: 'tool_use', id: 'c1', name: 'get_alert', input: { id: a1.id } }, { type: 'tool_use', id: 'c2', name: 'related_alerts', input: { id: a1.id } }]),
      turn([{ type: 'tool_use', id: 'c3', name: 'propose_open_case', input: { title: 'Account compromise dave (synthetic)', alert_ids: [a1.id, a2.id], reason: 'brute force then a forwarding rule' } }]),
      say('**Likely account compromise** for dave ' + XSS + '\n- ' + a1.id + ' brute force then success\n- ' + a2.id + ' new forwarding rule\nSee https://evil.example/steal for details. I proposed a case.')];
    await p.click('#cop [data-sug] >> nth=0');
    ok(await wait(p, () => /Likely account compromise/.test(document.querySelector('#cop .msgs').textContent)), 'answer shown');
    ok(new RegExp('looking at alert ' + a1.id).test(calls[0].messages[0].content), 'the page context reached the model');
    ok(await p.$eval('#cop .msgs', (m) => !!m.querySelector('.m.a b') && !!m.querySelector('.m.a li') && !m.querySelector('img') && !m.querySelector('a')), 'bold and bullets rendered; hostile HTML and the URL are not live');
    ok(/Used: get_alert, related_alerts/.test(await p.textContent('#cop .msgs')), 'tools used are listed');
    ok(await p.isVisible('#cop [data-acc]') && /Open a case/.test(await p.textContent('#cop .pc')), 'proposal card');
    ok(state.collection('cases').all().length === 0, 'nothing opened before a person accepts');
    await p.click('#cop [data-acc]');
    ok(await wait(p, () => /accepted by omar\.syn/.test(document.querySelector('#cop .pc').textContent)), 'card shows accepted');
    const cs = state.collection('cases').all()[0]; ok(cs && cs.owner === 'omar.syn' && cs.alerts.length === 2, 'case opened as the person with both alerts');
    // a second question in the same conversation, then reject its proposal
    script = [turn([{ type: 'tool_use', id: 'd1', name: 'propose_assign_alert', input: { alert_id: a2.id, assignee: 'nora.syn', reason: 'on shift' } }]), say('Proposed assigning it to nora.syn.')];
    await p.fill('#cop-q', 'Who should take the forwarding alert?'); await p.press('#cop-q', 'Enter');
    ok(await wait(p, () => document.querySelectorAll('#cop .pc').length === 2), 'second proposal');
    await p.click('#cop [data-rej]'); ok(await wait(p, () => /rejected by omar\.syn/.test(document.querySelectorAll('#cop .pc')[1].textContent)), 'rejected');
    ok(!(alerts.get(a2.id).assignee), 'rejected = nothing changed');
    // reload: the conversation is in the history and comes back with its cards
    await p.reload(); await p.waitForSelector('#cop-b', { timeout: 15000 }); await p.click('#cop-b');
    ok(await wait(p, () => document.querySelectorAll('#cop-h option').length === 2), 'earlier conversation listed');
    await p.selectOption('#cop-h', { index: 1 });
    ok(await wait(p, () => document.querySelectorAll('#cop .m.q').length === 2 && document.querySelectorAll('#cop .pc').length === 2), 'conversation reloaded with its proposals');
    ok(api.audits.some((x) => x.action === 'soc.copilot.ask') && api.audits.some((x) => x.action === 'soc.copilot.decide'), 'audited');
    // an analyst: the card says which role it needs
    WHO = { user: 'ana.syn', role: 'analyst' };
    script = [turn([{ type: 'tool_use', id: 'e1', name: 'propose_save_hunt', input: { name: 'Dave logons', q: 'user:dave', reason: 'keep watching' } }]), say('Proposed a saved hunt.')];
    await p.goto(base + 'soc-overview.html?standalone=1'); await p.waitForSelector('#cop-b', { timeout: 15000 }); await p.click('#cop-b');
    ok(/overview/.test(await p.textContent('#cop .ctx')), 'overview context');
    await p.fill('#cop-q', 'Save a hunt for dave'); await p.press('#cop-q', 'Enter');
    ok(await wait(p, () => /Save a hunt/.test((document.querySelector('#cop .pc') || {}).textContent || '')), 'an analyst may get a save-hunt proposal');
    WHO = { user: 'v.syn', role: 'viewer' }; await p.reload(); await p.waitForTimeout(1500);
    ok(!(await p.$('#cop-b')), 'no Copilot for a viewer');
  } finally { await browser.close(); srv.close(); fs.rmSync(dir, { recursive: true, force: true }); }
  ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks');
  process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
