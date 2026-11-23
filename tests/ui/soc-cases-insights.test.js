// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for the case insights of Investigations & Cases (soc-cases.html + GET /soc/cases/insights and the workspace's ml part)
// against the REAL SIEM modules (sentra-siem engine/soc/alerts.js, cases.js, routes.js, investigate-routes.js, case-insights.js) with
// SYNTHETIC history: cases at risk of an SLA breach with the reason, a stalled case, duplicate candidates, the stage bottleneck,
// suggested owners, the breach-risk tag in the list, the "Forecast & similar" tab (expected close, similar past cases with their
// resolution and note, assign the suggested owner in the person's name), a hostile title stays text, a viewer gets no panel,
// phone width, no page errors.
// Run: SENTRA_SIEM_DIR=/home/user/sentra-siem PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node soc-cases-insights.test.js
const http = require('http'), fs = require('fs'), path = require('path'), os = require('os');
const SIEM = process.env.SENTRA_SIEM_DIR || path.resolve(__dirname, '../../backend/siem');
const DASH = path.resolve(__dirname, '../../ui');
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const { createState } = require(path.join(SIEM, 'engine/soc/state'));
const { createAlerts } = require(path.join(SIEM, 'engine/soc/alerts'));
const { createCases } = require(path.join(SIEM, 'engine/soc/cases'));
const { fakeApi } = require(path.join(SIEM, 'tests/soc-fakes'));
const quiet = { info() {}, warn() {}, error() {}, debug() {}, child() { return quiet; } };
const XSS = '<img src=x onerror=window.__cx=1>';

(async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'socci-'));
  let T = Date.now(); const H = 3600e3, now = () => T;
  const state = createState({ dir, log: quiet }), alerts = createAlerts({ state, log: quiet, now }), cases = createCases({ state, alerts, log: quiet, now });
  let k = 0;
  const alert = (o) => alerts.raise(Object.assign({ rule_id: 'R-PHISH', rule_name: 'Synthetic phishing', severity: 3, group: {}, fields: {}, summary: 'synthetic', ts_first: T - H, ts_last: T - H, source: 'engine', count: 1, group_key: 'g' + (++k) }, o)).alert;
  const base = T;
  for (let i = 0; i < 6; i++) {
    T = base - (200 + i * 24) * H; const a = alert({ group: { user: 'syn.lina' }, mitre: ['T1566'] });
    const c = cases.create({ title: 'Past phishing on syn.lina ' + i, alert_ids: [a.id], auto_playbook: false, owner: i < 4 ? 'syn.huda' : 'syn.omar' }, 'syn.lead');
    for (let h = 4; h < 10 + i * 10; h += 4) { T = base - (200 + i * 24) * H + h * H; cases.note(c.id, 'progress', 'syn.huda'); }
    T = base - (200 + i * 24) * H + (10 + i * 10) * H; cases.setStatus(c.id, 'investigating', 'syn.huda'); cases.setStatus(c.id, 'closed', 'syn.huda', { resolution: 'true-positive', note: 'removed the forwarding rule ' + i });
  }
  T = base - 80 * H; const c1 = cases.create({ title: 'Phishing on syn.lina ' + XSS, alert_ids: [alert({ group: { user: 'syn.lina', host: 'pc-syn-3' }, mitre: ['T1566'] }).id], auto_playbook: false }, 'syn.lead');
  T = base - 70 * H; const c2 = cases.create({ title: 'Forwarding rule on syn.lina', alert_ids: [alert({ rule_id: 'R-FWD', group: { user: 'syn.lina', host: 'pc-syn-3' } }).id], auto_playbook: false, owner: 'syn.omar' }, 'syn.lead');
  T = base;
  const deps = { state, alerts, cases, log: quiet, now, noTimers: true, config: {} };
  const api = fakeApi({ realRanks: true });
  require(path.join(SIEM, 'engine/soc/routes')).register(api, deps);
  require(path.join(SIEM, 'engine/soc/investigate-routes')).register(api, deps);
  let WHO = { user: 'nora.syn', role: 'operator' }, insCalls = 0;
  const srv = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://x'), json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u.pathname === '/dashboards/whoami.json') return json(200, WHO);
    if (u.pathname.startsWith('/api/soc/')) {
      if (u.pathname === '/api/soc/soc/cases/insights') insCalls++;
      let b = ''; req.on('data', (c) => { b += c; }); req.on('end', async () => { const r = await api.call(req.method, '/api/soc' + u.pathname.slice(8) + u.search, { role: WHO.role, user: WHO.user, body: b ? JSON.parse(b) : undefined }); json(r.status, r.body); }); return;
    }
    if (u.pathname.startsWith('/api/')) return json(404, { error: 'not in this test' });
    const f = path.join(DASH, u.pathname.replace(/^\/dashboards\//, '/')); if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (err, d) => { if (err) { res.writeHead(404); res.end(); return; } res.writeHead(200, { 'Content-Type': u.pathname.endsWith('.js') ? 'application/javascript' : u.pathname.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base2 = 'http://127.0.0.1:' + srv.address().port + '/soc-cases.html?standalone=1';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  const wait = (p, fn, arg) => p.waitForFunction(fn, arg === undefined ? null : arg, { timeout: 15000 }).then(() => true, () => false);
  const TX = (p, id) => p.textContent('#' + id);
  try {
    const p = await browser.newPage({ viewport: { width: 1500, height: 1100 } }); p.on('pageerror', (x) => errs.push(x.message));
    await p.goto(base2);
    ok(await wait(p, () => !document.getElementById('cins').hidden && /CASE|C-|\d/.test(document.getElementById('ci-risk').textContent)), 'case insights shown to an operator');
    const rk = await TX(p, 'ci-risk');
    ok(rk.includes(c1.id) && /6 closed high cases took a median 40 h/.test(rk) && /100%/.test(rk), 'at risk of an SLA breach with the reason: ' + rk.slice(0, 200));
    ok((await TX(p, 'ci-stall')).includes(c1.id) && /comparable cases are touched every 4 h/.test(await TX(p, 'ci-stall')), 'stalled case');
    const dp = await TX(p, 'ci-dup'); ok(dp.includes(c1.id) && dp.includes(c2.id) && /user:syn\.lina/.test(dp) && /close one as “duplicate”/.test(dp), 'duplicate candidates, decided by a person');
    ok(/median time|investigating|open/.test(await TX(p, 'ci-stage')) && /cases spend the longest in/.test(await TX(p, 'ci-stage')), 'stage bottleneck');
    ok(/syn\.huda/.test(await TX(p, 'ci-own')) && /closed 4 comparable case\(s\)/.test(await TX(p, 'ci-own')), 'suggested owner with the reason');
    ok(!(await p.$('#cins img')) && !(await p.evaluate(() => window.__cx)), 'a hostile title stays text');
    ok(await wait(p, (id) => /breach risk 100%/.test((document.querySelector('tr[data-case="' + id + '"]') || {}).textContent || ''), c1.id), 'breach-risk tag in the list');
    // open the case from the risk list, then the Forecast & similar tab
    await p.click('#ci-risk li[data-case="' + c1.id + '"]');
    ok(await wait(p, () => !!document.querySelector('[data-tab="ml"]')), 'the case opens with a Forecast & similar tab');
    await p.click('[data-tab="ml"]');
    const ml = await TX(p, 'tabb');
    ok(/Expected close around/.test(ml) && /breach risk/.test(ml) && /stalled/.test(ml), 'forecast and stall in the case');
    ok(/removed the forwarding rule/.test(ml) && /true-positive/.test(ml) && /user:syn\.lina/.test(ml), 'similar past cases with their resolution, note and shared entities');
    await p.click('#sugown');
    ok(await wait(p, () => /assigned to syn\.huda/.test(document.body.innerText)) && cases.get(c1.id).owner === 'syn.huda', 'assigned to the suggested owner');
    ok((cases.get(c1.id).timeline || []).some((x) => x.kind === 'assign' && x.by === 'nora.syn'), 'recorded in the person\'s name');
    // a viewer: no panel, no request
    WHO = { user: 'vera.syn', role: 'viewer' }; insCalls = 0;
    const v = await browser.newPage({ viewport: { width: 1300, height: 900 } }); v.on('pageerror', (x) => errs.push(x.message));
    await v.goto(base2); await wait(v, () => !!document.querySelector('#list table'));
    ok(await v.evaluate(() => document.getElementById('cins').hidden) && insCalls === 0, 'a viewer gets no case insights');
    await v.close();
    WHO = { user: 'nora.syn', role: 'operator' };
    const ph = await browser.newPage({ viewport: { width: 390, height: 900 } }); ph.on('pageerror', (x) => errs.push(x.message));
    await ph.goto(base2); await wait(ph, () => !document.getElementById('cins').hidden);
    ok(await ph.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1), 'phone width: no sideways scroll'); await ph.close();
    if (process.env.SHOT) { const s2 = await browser.newPage({ viewport: { width: 1500, height: 1100 } }); await s2.goto(base2); await wait(s2, () => !document.getElementById('cins').hidden); await s2.waitForTimeout(600); await s2.screenshot({ path: process.env.SHOT + '-cases.png', fullPage: true }); await s2.close(); }
  } finally { await browser.close(); srv.close(); fs.rmSync(dir, { recursive: true, force: true }); }
  ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks'); process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
