// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// The REAL portal's Autopilot page with the learning section (module autopilotml) on SYNTHETIC decisions (/api/autopilot,
// /api/agents/actions): a kind people approved 12 of 12 times is recommended for automation with the waiting it removes (Wilson
// lower bound); a kind whose automatic decisions failed is recommended back to assist; held items grouped by reason with the
// standard-change fix first; a burst of failures in 24 h against the 7-day rate; "Use this" only fills the policy form (nothing is
// saved); the original policy, protected list and log remain; no page error.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node portal-autopilotml.test.js
const http = require('http'), fs = require('fs'), path = require('path'), cp = require('child_process');
const LIVE = path.resolve(__dirname, '../../repos/live/portal'), DASH = path.resolve(__dirname, '../../ui');
if (!fs.existsSync(path.join(LIVE, 'index.html'))) { console.log('SKIP: repos/live/portal not present'); process.exit(0); }
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const SH = fs.readFileSync(path.join(DASH, 'add-dashboards-menu.sh'), 'utf8'), ELINE = /ELINE='([^']+)'/.exec(SH)[1], AWK = /awk -v line="\$ELINE" '([^']+)'/.exec(SH)[1];
const INDEX = cp.execFileSync('awk', ['-v', 'line=' + ELINE, AWK, path.join(LIVE, 'index.html')], { encoding: 'utf8' });
const NOW = Date.now(), iso = (min) => new Date(NOW - min * 60000).toISOString(); const posts = [];
const ACT = []; let id = 1; const act = (kind, status, by, propMin, decMin) => ACT.push({ id: id++, fp: 'a' + id, agent: 'twin', kind, title: 'Synthetic ' + kind, rationale: 'synthetic', status, proposed_at: iso(propMin), decided_at: iso(decMin), decided_by: by });
for (let i = 0; i < 12; i++) act('set_cia', 'applied', 'syed', 3000 + i * 60, 2880 + i * 60);           // people always approve CIA ratings; the policy (auto-safe) holds them
for (let i = 0; i < 5; i++) act('advisory', i < 2 ? 'failed' : 'applied', 'autopilot', 600 + i, 599 + i);   // automatic advisories failing 2 of 5
const LOG = []; const lg = (min, domain, decision, detail) => LOG.push({ id: LOG.length + 1, at: iso(min), domain, ref: 'r' + LOG.length, decision, detail });
for (let i = 0; i < 6; i++) lg(30 + i, 'network', 'held', 'production device and no standard change reference (G-NET-01) ' + i);
for (let i = 0; i < 4; i++) lg(60 + i, 'register', 'failed', 'executor error (synthetic)');
for (let i = 0; i < 40; i++) lg(2 * 1440 + i * 60, 'register', 'applied', 'ok');
const AP = { settings: { paused: false, domains: { register: 'auto-safe', network: 'auto-safe', pam: 'auto-safe', awareness: 'full', risk: 'assist' }, standardChange: '', netAutoFix: { logging: true, mgmtWan: true, openSsid: true }, maxPerRun: 15 },
  levels: { off: 'Off', assist: 'Assist', 'auto-safe': 'Auto-safe', full: 'Full' }, domains: { register: { name: 'Asset register & digital twin', what: 'synthetic' }, network: { name: 'Network configuration', what: 'synthetic' }, pam: { name: 'Privileged access', what: 'synthetic' }, awareness: { name: 'Security awareness', what: 'synthetic' }, risk: { name: 'Risk & governance decisions', what: 'synthetic' } },
  protected: [['Device reboots', 'synthetic']], stats: { rate: 60, auto24h: 10, auto7d: 50, human7d: 12, held24h: 6, agentRuns24h: 9 }, log: LOG, waiting: { actions: 1, network: 6, pam: 0, executor: 0 }, lastRun: iso(5), meta: { canAdmin: true } };
(async () => {
  const srv = http.createServer((req, res) => {
    const u = decodeURIComponent(req.url.split('?')[0]), json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (req.method === 'POST') posts.push(u);
    if (u === '/auth/whoami' || u === '/dashboards/whoami.json') return json(200, { user: 'nora.syn', role: 'admin' });
    if (u === '/auth/org') return json(200, { modules: null, resp: {}, updated: null });
    if (u === '/api/autopilot') return json(200, AP);
    if (u === '/api/agents/actions') return json(200, { rows: ACT });
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
    const p = await (await browser.newContext({ viewport: { width: 1500, height: 1000 } })).newPage(); p.on('pageerror', (e) => errs.push(e.message)); p.on('dialog', (d) => d.dismiss());
    await p.goto(base + '/'); await wait(p, () => typeof setView === 'function' && typeof ME !== 'undefined' && ME && ME.user); await p.evaluate(() => setView('autopilot'));
    ok(await wait(p, () => /What Autopilot has learned/.test(document.body.innerText) && !!document.querySelector('[data-apml="use"]')), 'the learning section renders');
    const t = (await p.evaluate(() => document.body.innerText)).replace(/\s+/g, ' ');
    ok(/People approved 12 of 12 "set cia" proposals - let Autopilot do them/.test(t) && /\d+% approval \(95% lower bound\)/.test(t) && /hours in all/.test(t) && /Raise register to full/.test(t), 'a kind people always approve is recommended, with the lower bound and the waiting it removes');
    ok(/2 of 5 automatic "advisory" decisions failed - hand them back to people/.test(t), 'failing automatic decisions are recommended back to assist');
    ok(/6 item\(s\) held only because no standard change reference is set/.test(t), 'the standard-change fix is named first');
    ok(/of the last 24 h decisions were failures/.test(t), 'a burst of failures against the 7-day rate');
    ok(/production device and no standard change reference/.test(t), 'held reasons grouped');
    await p.click('[data-apml="use"][data-k="full"]');
    ok(await wait(p, () => { const c = document.querySelector('[data-ap="lvl"][data-d="register"][data-k="full"]'); return c && c.classList.contains('on'); }), '"Use this" fills the policy form');
    ok(!posts.some((x) => /autopilot\/settings/.test(x)), 'nothing is saved until an administrator presses Save policy');
    ok(/Always a person/.test(t) && /Autopilot decision log/.test(t), 'the original policy, protected list and log remain');
  } finally { await browser.close(); srv.close(); }
  ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks');
  process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
