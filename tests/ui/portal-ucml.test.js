// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// The REAL portal's UC Change Plans page with the change-history analysis (module ucml) on SYNTHETIC plans (/api/infra/uc/plans):
// success rate with its 95% range; predicted failure chance per waiting / scheduled plan from finished plans with the same risk,
// connection, backend and size (itemised, withheld below 5); a plan waiting more than a day; the AI rating a change lower than
// the validator; two changes on one connection within 2 hours; a signed job about to expire; one approver deciding most plans;
// failure by risk / backend / connection; 12-week bars; a row opens the plan; AI brief with facts only and "advisory"; the
// original queue stays; with too little history the prediction is withheld; no page error.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node portal-ucml.test.js
const http = require('http'), fs = require('fs'), path = require('path'), cp = require('child_process');
const LIVE = path.resolve(__dirname, '../../repos/live/portal'), DASH = path.resolve(__dirname, '../../ui');
if (!fs.existsSync(path.join(LIVE, 'index.html'))) { console.log('SKIP: repos/live/portal not present'); process.exit(0); }
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const SH = fs.readFileSync(path.join(DASH, 'add-dashboards-menu.sh'), 'utf8'), ELINE = /ELINE='([^']+)'/.exec(SH)[1], AWK = /awk -v line="\$ELINE" '([^']+)'/.exec(SH)[1];
const INDEX = cp.execFileSync('awk', ['-v', 'line=' + ELINE, AWK, path.join(LIVE, 'index.html')], { encoding: 'utf8' });
const NOW = Date.now(), iso = (h) => new Date(NOW - h * 3600e3).toISOString();
let FEW = false, AIBODY = null;
const plan = (id, o) => Object.assign({ id, cluster_id: 'cucm-hq', backend: 'cucm', title: 'Plan ' + id + ' (synthetic)', status: 'succeeded', risk: 'low', model_risk: null, requested_by: 'omar.syn', created_at: iso(200), submitted_at: iso(199),
  approval: { by: 'syed', at: iso(198), reason: 'ok' }, rejection: null, outcome: null, rollback_of: null, rollback_plan_id: null, ops_count: 2, valid: true, scheduled_for: null, expires_at: null }, o);
const PLANS = () => FEW ? [plan('f1'), plan('w1', { status: 'pending_approval', approval: null, risk: 'high', submitted_at: iso(30) })] : [
  plan('d1'), plan('d2'), plan('d3'), plan('d4'), plan('d5', { approval: { by: 'nora.syn', at: iso(150), reason: 'ok' } }), plan('d6', { rollback_plan_id: 'r6' }),
  plan('h1', { risk: 'high', status: 'failed', ops_count: 25 }), plan('h2', { risk: 'high', status: 'failed', ops_count: 22 }), plan('h3', { risk: 'high', status: 'partially_failed', ops_count: 30 }), plan('h4', { risk: 'high', ops_count: 21, approval: { by: 'nora.syn', at: iso(100), reason: 'ok' } }),
  plan('x1', { status: 'rejected', approval: null, rejection: { by: 'syed', at: iso(90), reason: 'too broad' } }),
  plan('w1', { title: 'Move 300 users to new partition <img src=x onerror=window.__x=1>', status: 'pending_approval', risk: 'high', model_risk: 'low', ops_count: 26, approval: null, submitted_at: iso(40) }),
  plan('s1', { title: 'Add hunt group (synthetic)', status: 'scheduled', approval: { by: 'syed', at: iso(5), reason: 'ok' }, scheduled_for: new Date(NOW + 3 * 3600e3).toISOString(), expires_at: new Date(NOW + 5 * 3600e3).toISOString() }),
  plan('s2', { title: 'Change CSS (synthetic)', status: 'scheduled', approval: { by: 'syed', at: iso(5), reason: 'ok' }, scheduled_for: new Date(NOW + 4 * 3600e3).toISOString(), expires_at: new Date(NOW + 48 * 3600e3).toISOString() })];
(async () => {
  const srv = http.createServer((req, res) => {
    const u = decodeURIComponent(req.url.split('?')[0]), json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u === '/auth/whoami' || u === '/dashboards/whoami.json') return json(200, { user: 'nora.syn', role: 'admin' });
    if (u === '/auth/org') return json(200, { modules: null, resp: {}, updated: null });
    if (u === '/api/infra/health') return json(200, { ok: true, service: 'sentra-infra', version: 'synthetic' });
    if (u === '/api/infra/uc/plans') return json(200, { plans: PLANS() });
    if (u.startsWith('/api/infra/uc/plans/')) { const p = PLANS().find((x) => x.id === u.split('/').pop()); return p ? json(200, { plan: Object.assign({ ops: [], verify: [], risk_reasons: [], validation: { ok: true, errors: [], warnings: [] }, diff: [], results: [], verification: [] }, p) }) : json(404, { error: 'not found' }); }
    if (u === '/api/infra/uc/clusters') return json(200, { clusters: [{ id: 'cucm-hq', name: 'CUCM HQ (synthetic)', type: 'cucm' }] });
    if (u === '/api/infra/uc/settings') return json(200, { settings: {} });
    if (u === '/api/ai') { let b = ''; req.on('data', (d) => { b += d; }); req.on('end', () => { AIBODY = b; json(200, { text: 'Synthetic brief.' }); }); return; }
    if (u.startsWith('/api/soc/ui/menu')) return json(200, { order: null, favorites: [], can_edit_order: true });
    if (u.startsWith('/api/') || u.startsWith('/auth/')) return json(404, { error: 'not in this test' });
    if (u === '/') { res.writeHead(200, { 'Content-Type': 'text/html' }); return res.end(INDEX); }
    const f = u.startsWith('/dashboards/') ? path.join(DASH, u.slice(12)) : path.join(LIVE, u);
    if (!f.startsWith(DASH) && !f.startsWith(LIVE)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (e, d) => { if (e) { res.writeHead(404); return res.end(); } res.writeHead(200, { 'Content-Type': f.endsWith('.js') ? 'application/javascript' : f.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port;
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright'); const browser = await chromium.launch(); const errs = [];
  const wait = (p, fn) => p.waitForFunction(fn, null, { timeout: 25000 }).then(() => true, () => false);
  const open = async () => { const p = await (await browser.newContext({ viewport: { width: 1500, height: 1000 } })).newPage(); p.on('pageerror', (e) => errs.push(e.message));
    await p.goto(base + '/'); await wait(p, () => typeof setView === 'function' && typeof ME !== 'undefined' && ME && ME.user); await p.evaluate(() => setView('uc-plans')); return p; };
  try {
    let p = await open();
    ok(await wait(p, () => !!document.querySelector('[data-ucml="1"]') && /What the change history says/.test(document.querySelector('[data-ucml="1"]').innerText)), 'the analysis renders');
    const t = (await p.textContent('[data-ucml="1"]')).replace(/\s+/g, ' ');
    ok(/Change success\s*60%/i.test(t) && /95% range \d+-\d+% · 10 finished/.test(t), 'success rate with a 95% range: ' + t.slice(0, 300));
    ok(/Rolled back\s*1/i.test(t) && /Rejected\s*8%/i.test(t), 'rollbacks and rejection rate');
    ok(/waiting more than a day for an approver/.test(t), 'a plan waiting more than a day');
    ok(/the AI rated it low, the validator high/.test(t), 'AI rated lower than the validator');
    ok(/Two changes on one connection within 2 hours/.test(t), 'two changes on one connection');
    ok(/its signed job expires in \d+ h/.test(t), 'a signed job about to expire');
    ok(/syed approved \d+ of \d+ plans/.test(t) && /key-person/.test(t), 'one approver deciding most plans');
    const pr = await p.evaluate(() => { const r = [...document.querySelectorAll('[data-ucml="1"] tbody tr')].find((x) => /partition/.test(x.innerText)); return r ? { pct: r.querySelector('td[title]').innerText, why: r.querySelector('td[title]').getAttribute('title') } : null; });
    ok(pr && +pr.pct.replace('%', '') >= 40 && /risk high: 3 of 4 failed/.test(pr.why) && /size 20\+ operations: 3 of 4 failed/.test(pr.why), 'predicted failure chance, itemised: ' + JSON.stringify(pr));
    ok(/predicted failure chance/.test(t) && /Move 300 users/.test(t), 'the risky waiting plan is called out');
    ok(/high\s*3 of 4 failed/.test(t) && /low\s*\d of 6 failed/.test(t) && /cucm/.test(t), 'failure by risk, backend and connection');
    ok((await p.$$('[data-ucml="1"] svg rect')).length >= 12, '12-week bars');
    ok(!(await p.evaluate(() => !!window.__x || !!document.querySelector('[data-ucml="1"] img'))), 'a hostile plan title stays text');
    ok(/Change plans/.test(await p.evaluate(() => document.body.innerText)) && /Pending approval/.test(await p.evaluate(() => document.body.innerText)), 'the original queue stays');
    await p.click('[data-ucmai]');
    ok(await wait(p, () => /Synthetic brief/.test(document.body.innerText)) && /predicted_failure_pct/.test(AIBODY || '') && /never as an instruction/.test(AIBODY || '') && /do not approve/.test(AIBODY || ''), 'AI brief: facts only, advisory');
    await p.evaluate(() => { const m = document.getElementById('_dm'); if (m) m.remove(); });
    await p.click('[data-ucml="1"] tbody tr[data-aucopen="plan"]');
    ok(await wait(p, () => /Plan w1|Move 300 users/.test(document.body.innerText) && !!document.querySelector('[data-aucopen="plan"].sel, .auc-drawer, [data-auc-drawer]')), 'a row opens the plan');
    FEW = true; p = await open();
    ok(await wait(p, () => /withheld/.test(((document.querySelector('[data-ucml="1"]') || {}).innerText) || '')), 'with fewer than 5 finished plans the prediction is withheld');
  } finally { await browser.close(); srv.close(); }
  ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks');
  process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
