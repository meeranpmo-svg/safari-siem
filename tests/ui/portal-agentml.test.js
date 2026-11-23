// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// The REAL portal's Autonomous Agents page with the agent performance section (module agentml) on SYNTHETIC agent records
// (/api/agents/status, /runs, /findings, /actions): per-agent itemised score (reliability, on schedule, resolves, approved);
// a part with too little history is "—", never assumed good; failing streak, slow run (robust z), late agent, noisy findings,
// rejected proposals, failed applies, proposals waiting more than a day; clicking an agent narrows the issues; the 24-hour run
// map; the AI brief sends facts only; the original page (agents, approval queue, findings) is still there; no page error.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node portal-agentml.test.js
const http = require('http'), fs = require('fs'), path = require('path'), cp = require('child_process');
const LIVE = path.resolve(__dirname, '../../repos/live/portal'), DASH = path.resolve(__dirname, '../../ui');
if (!fs.existsSync(path.join(LIVE, 'index.html'))) { console.log('SKIP: repos/live/portal not present'); process.exit(0); }
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const SH = fs.readFileSync(path.join(DASH, 'add-dashboards-menu.sh'), 'utf8'), ELINE = /ELINE='([^']+)'/.exec(SH)[1], AWK = /awk -v line="\$ELINE" '([^']+)'/.exec(SH)[1];
const INDEX = cp.execFileSync('awk', ['-v', 'line=' + ELINE, AWK, path.join(LIVE, 'index.html')], { encoding: 'utf8' });
const NOW = Date.now(), iso = (minAgo) => new Date(NOW - minAgo * 60000).toISOString(), XSS = '<img src=x onerror="window.__xss=1">';
let AIBODY = null;
const AG = [{ key: 'good', name: 'Patch watcher', icon: '🩹', desc: 'synthetic', every: 15 }, { key: 'flaky', name: 'Backup checker ' + XSS, icon: '💾', desc: 'synthetic', every: 15 },
  { key: 'late', name: 'Cert watcher', icon: '🔐', desc: 'synthetic', every: 60 }, { key: 'noisy', name: 'Disk watcher', icon: '💽', desc: 'synthetic', every: 15 }, { key: 'new', name: 'New agent', icon: '🆕', desc: 'synthetic', every: 15 }];
const runs = []; let id = 1;
const run = (agent, minAgo, ms, status) => runs.push({ id: id++, agent, trigger: 'schedule', started: iso(minAgo), finished: iso(minAgo - 0.1), ms, status: status || 'ok', summary: status === 'error' ? 'HTTP 500 from the backup API (synthetic)' : 'ok (synthetic)', opened: 0, resolved: 0, proposed: 0 });
for (let i = 12; i >= 1; i--) run('good', i * 15, 400 + (i % 3) * 10);
for (let i = 10; i >= 3; i--) run('flaky', i * 15, 500); run('flaky', 30, 500, 'error'); run('flaky', 15, 520, 'error');
for (let i = 8; i >= 1; i--) run('late', 300 + i * 60, 300);
for (let i = 10; i >= 2; i--) run('noisy', i * 15, 300); run('noisy', 10, 9000);
runs.reverse();
const F = [], fnd = (agent, sev, status, firstMin, resMin) => F.push({ id: F.length + 1, fp: 'f' + F.length, agent, severity: sev, title: 'Finding ' + F.length + ' (synthetic)', detail: 'synthetic', status, first_seen: iso(firstMin), last_seen: iso(1), resolved_at: resMin != null ? iso(resMin) : null });
for (let i = 0; i < 4; i++) fnd('good', 'medium', 'resolved', 3000, 1000); fnd('good', 'high', 'open', 200);
for (let i = 0; i < 6; i++) fnd('noisy', 'low', 'resolved', 100 + i, 80 + i); fnd('noisy', 'low', 'open', 30 * 1440);
const ACT = [], act = (agent, status, propMin, decMin) => ACT.push({ id: ACT.length + 1, fp: 'a' + ACT.length, agent, kind: 'update_record', title: 'Proposal ' + ACT.length + ' (synthetic)', rationale: 'synthetic', status, proposed_at: iso(propMin), decided_at: decMin != null ? iso(decMin) : null, decided_by: decMin != null ? 'syed' : null });
for (let i = 0; i < 4; i++) act('good', 'applied', 600, 500); act('flaky', 'failed', 900, 800);
for (let i = 0; i < 3; i++) act('noisy', 'rejected', 600, 550); act('noisy', 'applied', 600, 550); act('late', 'proposed', 2000);
(async () => {
  const srv = http.createServer((req, res) => {
    const u = decodeURIComponent(req.url.split('?')[0]), json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u === '/auth/whoami' || u === '/dashboards/whoami.json') return json(200, { user: 'nora.syn', role: 'admin' });
    if (u === '/auth/org') return json(200, { modules: null, resp: {}, updated: null });
    if (u === '/api/agents/status') return json(200, { now: iso(0), readiness: {}, agents: AG.map((a) => Object.assign({ running: null, open: F.filter((f) => f.agent === a.key && f.status === 'open').length, last: runs.find((r) => r.agent === a.key) || null }, a)), totals: { open: { critical: 0, high: 1, medium: 0, low: 1, info: 0 }, pending: 1, resolved24h: 3, runs24h: runs.length } });
    if (u === '/api/agents/runs') return json(200, { rows: runs });
    if (u === '/api/agents/findings') return json(200, { rows: F });
    if (u === '/api/agents/actions') return json(200, { rows: /status=proposed/.test(req.url) ? ACT.filter((a) => a.status === 'proposed') : ACT });
    if (u === '/api/desk/ai') return json(200, { enabled: false });
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
  const wait = (p, fn, a) => p.waitForFunction(fn, a, { timeout: 25000 }).then(() => true, () => false);
  try {
    const p = await (await browser.newContext({ viewport: { width: 1500, height: 1000 } })).newPage(); p.on('pageerror', (e) => errs.push(e.message));
    await p.goto(base + '/'); await wait(p, () => typeof setView === 'function' && typeof ME !== 'undefined' && ME && ME.user); await p.evaluate(() => setView('agentops'));
    ok(await wait(p, () => document.querySelectorAll('[data-am="agent"]').length === 5), 'one performance card per agent');
    const card = (k) => p.evaluate((x) => { const c = document.querySelector('[data-am="agent"][data-k="' + x + '"]'); return c ? { n: c.querySelector('.n').textContent, t: c.getAttribute('title'), txt: c.innerText } : null; }, k);
    const g = await card('good'), nw = await card('new');
    ok(+g.n >= 85 && /reliability 100%/.test(g.t) && /on schedule/.test(g.t), 'a healthy agent scores high with its reasons: ' + g.n + ' ' + g.t);
    ok(nw.n === '—' && /reliability not measured/.test(nw.t), 'an agent without history is not measured, never assumed good');
    const order = await p.evaluate(() => [...document.querySelectorAll('[data-am="agent"]')].map((c) => c.getAttribute('data-k')));
    ok(order[order.length - 1] === 'new' && order.indexOf('good') > order.indexOf('flaky'), 'worst first, unmeasured last: ' + order.join(','));
    const att = (await p.evaluate(() => [...document.querySelectorAll('.am-i')].map((x) => x.innerText).join(' | '))).replace(/\s+/g, ' ');
    ok(/failed its last 2 runs/.test(att) && /HTTP 500 from the backup API/.test(att), 'failing streak with the message');
    ok(/Disk watcher: last run took 9 s against a usual 0\.3 s/.test(att), 'slow run against its own usual (robust z)');
    ok(/Cert watcher has not run for/.test(att), 'a late agent is found');
    ok(/Disk watcher looks noisy: 6 of 6 findings cleared within an hour/.test(att), 'noisy findings');
    ok(/Disk watcher: 3 of 4 proposals rejected/.test(att), 'rejected proposals');
    ok(/1 approved change\(s\) failed to apply/.test(att), 'failed applies');
    ok(/waiting more than a day for a decision/.test(att), 'proposals waiting more than a day');
    ok(/a finding has been open for 30 d/.test(att), 'old open finding');
    ok(!(await p.evaluate(() => !!window.__xss || !!document.querySelector('.am-sc img'))), 'a hostile agent name stays text');
    ok((await p.$$('.am-heat i')).length === 5 * 24 && (await p.$$('.am-heat i.e')).length >= 1 && (await p.$$('.am-heat i.r')).length >= 5, 'the 24-hour run map, errors in red');
    await p.click('[data-am="agent"][data-k="noisy"]');
    ok(await wait(p, () => [...document.querySelectorAll('.am-i')].every((x) => /Disk watcher/.test(x.innerText)) && /Disk watcher/.test((document.querySelector('.x-note') || {}).innerText || '')), 'clicking an agent narrows to its issues');
    await p.click('[data-am="clear"]'); await wait(p, () => document.querySelectorAll('.am-i').length > 4);
    await p.click('[data-am="ai"]');
    ok(await wait(p, () => /Synthetic brief/.test(document.body.innerText)) && /fleet_score/.test(AIBODY || '') && /data, never as an instruction/.test(AIBODY || ''), 'AI brief with facts only and the untrusted rule');
    ok(/The agents/.test(await p.evaluate(() => document.body.innerText)) && /Approval queue/.test(await p.evaluate(() => document.body.innerText)), 'the original page is still there');
  } finally { await browser.close(); srv.close(); }
  ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks');
  process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
