// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for AI Security (ai-security.html) against the REAL SIEM module (sentra-siem engine/soc/ai-security.js +
// ai-security-routes.js) fed through ai-guard's ledger with SYNTHETIC usage: KPIs, the usage chart, the red team table and a
// run by an administrator, the inventory with proposal tools, quality, unusual use, injection flags (no text), the limits,
// hostile values stay text; an analyst is refused (the page names people).
// Run: SENTRA_SIEM_DIR=/home/user/sentra-siem PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node ai-security-page.test.js
const http = require('http'), fs = require('fs'), path = require('path'), os = require('os');
const SIEM = process.env.SENTRA_SIEM_DIR || path.resolve(__dirname, '../../backend/siem');
const DASH = path.resolve(__dirname, '../../ui');
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const XSS = '<img src=x onerror=alert(1)>';
const { createState } = require(path.join(SIEM, 'engine/soc/state'));
const { fakeApi } = require(path.join(SIEM, 'tests/soc-fakes'));
const quiet = { info() {}, warn() {}, error() {}, debug() {}, child() { return quiet; } };

(async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'aisec-'));
  const state = createState({ dir, log: quiet });
  const deps = { state, log: quiet, noTimers: true, config: { ai_limits: { per_user_hour: 30, per_user_day: 200, daily_tokens: 3000000, max_prompt_chars: 200000 } } };
  const api = fakeApi({ realRanks: true }); require(path.join(SIEM, 'engine/soc/ai-security-routes')).register(api, deps);
  const A = deps.aiSecurity, T = Date.now(), DAY = 864e5;
  for (let k = 1; k <= 6; k++) for (let i = 0; i < 4; i++) { A.onEntry({ at: new Date(T - k * DAY).toISOString(), user: 'eve.syn', feature: 'soc.copilot', tokens: 500 }); A.onEntry({ at: new Date(T - k * DAY).toISOString(), user: 'nora.syn', feature: 'soc.triage', tokens: 800 }); }
  for (let i = 0; i < 120; i++) A.onEntry({ at: new Date(T).toISOString(), user: 'eve.syn', feature: 'soc.copilot', tokens: 400 });
  A.onEntry({ at: new Date(T).toISOString(), user: 'x' + XSS, feature: 'soc.copilot', tokens: 1, injection_signals: [2] });
  A.onEntry({ at: new Date(T).toISOString(), user: 'nora.syn', feature: 'soc.triage', tokens: 300, injection_signals: [1, 6] });
  A.onEntry({ at: new Date(T).toISOString(), user: 'omar.syn', feature: 'soc.copilot', refused: 'too large' });
  const tri = state.collection('soc_ai_triage'); ['accepted', 'accepted', 'rejected', 'draft'].forEach((s, i) => tri.put({ id: 'T' + i, state: s }));
  let WHO = { user: 'omar.syn', role: 'operator' };
  const srv = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://x'), json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u.pathname === '/dashboards/whoami.json') return json(200, WHO);
    if (u.pathname.startsWith('/api/soc/')) { let b = ''; req.on('data', (c) => { b += c; }); req.on('end', async () => { const r = await api.call(req.method, '/api/soc' + u.pathname.slice(8) + u.search, { role: WHO.role, user: WHO.user, body: b ? JSON.parse(b) : undefined }); json(r.status, r.body); }); return; }
    if (u.pathname.startsWith('/api/')) return json(404, { error: 'not in this test' });
    const f = path.join(DASH, u.pathname.replace(/^\/dashboards\//, '/')); if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (err, d) => { if (err) { res.writeHead(404); res.end(); return; } res.writeHead(200, { 'Content-Type': u.pathname.endsWith('.js') ? 'application/javascript' : u.pathname.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port + '/';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  const wait = (p, fn) => p.waitForFunction(fn, null, { timeout: 10000 }).then(() => true, () => false);
  try {
    const p = await browser.newPage({ viewport: { width: 1500, height: 1000 } }); p.on('pageerror', (x) => errs.push(x.message)); p.on('dialog', (d) => { errs.push('dialog'); d.dismiss(); });
    await p.goto(base + 'ai-security.html?standalone=1'); await p.waitForFunction(() => /updated/.test(document.getElementById('up').textContent), null, { timeout: 15000 });
    const kp = await p.textContent('#kpis');
    ok(/AI calls today\s*122/.test(kp) && /Refused today\s*1/.test(kp) && /Unusual use today\s*1/.test(kp), 'KPIs: ' + kp.replace(/\s+/g, ' ').slice(0, 220));
    ok(/Guard rails\s*—/.test(kp) && /has not run yet/.test(await p.textContent('#rtl')), 'red team not run yet says so');
    ok(await p.$$eval('#c-use,#c-feat', (c) => c.every((x) => x.getAttribute('role') === 'img' && /calls|tokens/i.test(x.getAttribute('aria-label')))), 'charts labelled');
    ok(/mitigated, not solved/.test(await p.textContent('main')), 'honest framing');
    ok(await p.$eval('#rt', (b) => b.hidden), 'an operator cannot run the red team');
    await p.click('[data-tab="inv"]'); const inv = await p.textContent('#inv');
    ok(/SOC Copilot/.test(inv) && /propose_open_case/.test(inv) && /AI Network \/ Security Engineer/.test(inv), 'inventory with proposal tools');
    await p.click('[data-tab="q"]'); ok(/67%/.test(await p.textContent('#q')) && /needs 3 decisions/.test(await p.textContent('#q')), 'quality: measured where 3+ decisions, withheld otherwise');
    await p.click('[data-tab="anom"]'); ok(/eve\.syn/.test(await p.textContent('#anom')) && /robust z/.test(await p.textContent('#anom')), 'unusual use with the reason');
    await p.click('[data-tab="flags"]'); ok(/#1/.test(await p.textContent('#flags')) && /AI SOC analyst/.test(await p.textContent('#flags')) && !(await p.$('#flags img')), 'injection flags; a hostile user name stays text');
    await p.click('[data-tab="lim"]'); ok(/3,000,000/.test(await p.textContent('#lim')), 'limits');
    WHO = { user: 'syed', role: 'admin' }; await p.reload(); await p.waitForFunction(() => /updated/.test(document.getElementById('up').textContent), null, { timeout: 15000 });
    await p.click('#rt'); ok(await wait(p, () => /9 \/ 9/.test(document.getElementById('kpis').textContent)), 'admin ran the red team: every guard rail passes');
    ok(/pass/.test(await p.textContent('#rtl')) && !/FAIL/.test(await p.textContent('#rtl')), 'red team table');
    ok(api.audits.some((a) => a.action === 'soc.ai.redteam' && a.user === 'syed'), 'audited');
    WHO = { user: 'ana.syn', role: 'analyst' }; await p.reload();
    ok(await wait(p, () => /role|cannot/i.test(document.getElementById('err').textContent)), 'an analyst is refused');
    ok(await p.evaluate(() => (window.ZYB_NAV || []).some((a) => a.id === 'ai' && a.pages.some((x) => x.h === 'ai-security.html'))), 'in the AI Team menu');
  } finally { await browser.close(); srv.close(); fs.rmSync(dir, { recursive: true, force: true }); }
  ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks');
  process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
