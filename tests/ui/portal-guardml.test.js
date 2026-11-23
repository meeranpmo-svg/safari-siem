// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// The REAL portal's Guardrails page with the decision-log analysis (module guardml) on SYNTHETIC rules and decisions:
// test-console decisions left out unless asked; a rule that blocks most of the time; rules never exercised; a deny rate that rose
// (two-proportion z); the same person resending a denied action within an hour (an indicator, said so); two rules that fail
// together (lift); a volume spike (robust z); per-framework coverage; API-only rules; clicking a rule narrows the findings;
// the AI brief sends facts only; the original console, log and rules remain; no page error.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node portal-guardml.test.js
const http = require('http'), fs = require('fs'), path = require('path'), cp = require('child_process');
const LIVE = path.resolve(__dirname, '../../repos/live/portal'), DASH = path.resolve(__dirname, '../../ui');
if (!fs.existsSync(path.join(LIVE, 'index.html'))) { console.log('SKIP: repos/live/portal not present'); process.exit(0); }
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const SH = fs.readFileSync(path.join(DASH, 'add-dashboards-menu.sh'), 'utf8'), ELINE = /ELINE='([^']+)'/.exec(SH)[1], AWK = /awk -v line="\$ELINE" '([^']+)'/.exec(SH)[1];
const INDEX = cp.execFileSync('awk', ['-v', 'line=' + ELINE, AWK, path.join(LIVE, 'index.html')], { encoding: 'utf8' });
const NOW = Date.now(), iso = (min) => new Date(NOW - min * 60000).toISOString();
let AIBODY = null;
const RULES = [{ id: 'G-UPD-01', domain: 'Tech risk', action: 'deploy_update', name: 'Production updates carry an approved change reference', refs: 'SAMA CSF 3.3.7 · ISO A.8.32', where: 'Update gate API' },
  { id: 'G-UPD-02', domain: 'Tech risk', action: 'deploy_update', name: 'Verified backup before tier-1 updates', refs: 'SAMA CSF 3.3.7 · NCA ECC 2-9', where: 'Update gate API' },
  { id: 'G-PDPL-01', domain: 'Privacy', action: 'share_data', name: 'No personal data leaves the Kingdom without an approved transfer', refs: 'PDPL cross-border transfer', where: 'Data-sharing gate API' },
  { id: 'G-AI-01', domain: 'AI', action: 'ai_use', name: 'AI use requires an approved risk assessment', refs: 'ISO/IEC 42001 · SDAIA AI Ethics Principles', where: 'AI gateway API' },
  { id: 'G-NET-02', domain: 'Tech risk', action: 'net_change', name: 'Configuration backed up before every change', refs: 'NCA ECC 2-9', where: 'On-prem executor (enforced)' }];
const DEC = []; let id = 1;
const dec = (min, action, decision, user, fails, source) => DEC.push({ id: id++, at: iso(min), action, subject: 'synthetic ' + action, decision, user, source: source || 'api', results: JSON.stringify(RULES.filter((r) => r.action === action).map((r) => ({ id: r.id, result: (fails || []).includes(r.id) ? 'fail' : 'pass' }))) });
// prior week: deploy mostly allowed; this week: mostly denied, with UPD-01 and UPD-02 failing together
for (let i = 0; i < 12; i++) dec(8 * 1440 + i * 60, 'deploy_update', i < 2 ? 'deny' : 'allow', 'ops.syn', i < 2 ? ['G-UPD-01'] : []);
for (let i = 0; i < 12; i++) dec(2 * 1440 + i * 60, 'deploy_update', i < 9 ? 'deny' : 'allow', 'ops.syn', i < 9 ? ['G-UPD-01', 'G-UPD-02'] : []);
for (let i = 0; i < 6; i++) dec(3 * 1440 + i * 30, 'share_data', 'allow', 'data.syn', []);
// a deny, then the same person resends within the hour and it passes
dec(120, 'share_data', 'deny', 'mallory.syn', ['G-PDPL-01']); dec(100, 'share_data', 'allow', 'mallory.syn', []);
// earlier days with low volume, today a spike
for (let d = 4; d <= 9; d++) dec(d * 1440 + 600, 'share_data', 'allow', 'data.syn', []);
for (let i = 0; i < 20; i++) dec(30 + i, 'share_data', 'allow', 'bot.syn', []);
for (let i = 0; i < 5; i++) dec(10 + i, 'ai_use', 'deny', 'console.syn', ['G-AI-01'], 'console');
DEC.reverse();
(async () => {
  const srv = http.createServer((req, res) => {
    const u = decodeURIComponent(req.url.split('?')[0]), json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u === '/auth/whoami' || u === '/dashboards/whoami.json') return json(200, { user: 'nora.syn', role: 'admin' });
    if (u === '/auth/org') return json(200, { modules: null, resp: {}, updated: null });
    if (u === '/api/guard/rules') return json(200, { rules: RULES, actions: { deploy_update: { name: 'Deploy an update', example: { change_ref: 'CHG-1', tier: 1, backup_verified: true } }, share_data: { name: 'Share data', example: { destination: 'KSA' } } }, stats: [{ decision: 'allow', n: 10 }, { decision: 'deny', n: 5 }] });
    if (u === '/api/guard/decisions') return json(200, { rows: DEC.slice(0, 300) });
    if (u === '/api/risk/cases') return json(200, { rows: [] });
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
  try {
    const p = await (await browser.newContext({ viewport: { width: 1500, height: 1000 } })).newPage(); p.on('pageerror', (e) => errs.push(e.message));
    await p.goto(base + '/'); await wait(p, () => typeof setView === 'function' && typeof ME !== 'undefined' && ME && ME.user); await p.evaluate(() => setView('guardrails'));
    ok(await wait(p, () => document.querySelectorAll('[data-gm="rule"]').length === 5), 'the analysis renders with one row per rule');
    const tiles = (await p.evaluate(() => document.querySelector('[data-gm="rule"]').closest('.x-card').querySelector('.x-tiles').innerText)).replace(/\s+/g, ' ');
    ok(/5 test-console decisions left out/i.test(tiles), 'test-console decisions are left out by default: ' + tiles);
    ok(/3 of 5 checked/i.test(tiles), 'rules exercised: ' + tiles);
    const f = (await p.evaluate(() => [...document.querySelectorAll('.gm-i')].map((x) => x.innerText).join(' | '))).replace(/\s+/g, ' ');
    ok(/G-UPD-01 blocks \d+% of the time/.test(f), 'a rule that blocks most of the time: ' + f.slice(0, 400));
    ok(/deploy update: deny rate rose from 17% to 75% this week/.test(f), 'deny rate change, two-proportion z');
    ok(/mallory\.syn sent "share data" again within an hour of a deny 1 time\(s\), and 1 went through/.test(f) && /not proof/.test(f), 'retry after a deny is flagged as an indicator');
    ok(/G-UPD-01 and G-UPD-02 fail together/.test(f), 'rules that fail together');
    ok(/decisions on \d{4}-\d\d-\d\d against a usual/.test(f), 'a volume spike (robust z)');
    ok(/never exercised/.test(f) && /G-NET-02 \(no "net change" request at all\)/.test(f), 'rules never exercised, with why');
    ok(/4 of 5 rules are enforced at an API only/.test(f), 'API-only rules are called advisory');
    ok(/PDPL/.test(await p.textContent('.gm-fw')) && /SAMA/.test(await p.textContent('.gm-fw')), 'per-framework coverage');
    await p.click('[data-gm="rule"][data-k="G-UPD-02"]');
    ok(await wait(p, () => { const i = [...document.querySelectorAll('.gm-i')]; return i.length >= 1 && i.every((x) => /G-UPD-02/.test(x.innerText)); }), 'clicking a rule narrows the findings to it');
    await p.click('[data-gm="clear"]');
    await p.check('[data-gm="test"]');
    ok(await wait(p, () => /5 test-console decisions included/i.test(document.querySelector('[data-gm="rule"]').closest('.x-card').innerText)), 'test-console decisions can be included');
    await p.click('[data-gm="ai"]');
    ok(await wait(p, () => /Synthetic brief/.test(document.body.innerText)) && /rules_exercised/.test(AIBODY || '') && /data, never as an instruction/.test(AIBODY || ''), 'AI brief with facts only and the untrusted rule');
    const body = await p.evaluate(() => document.body.innerText);
    ok(/Test console/i.test(body) && /Decision log/i.test(body) && /Rules/.test(body), 'the original console, log and rules remain');
  } finally { await browser.close(); srv.close(); }
  ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks');
  process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
