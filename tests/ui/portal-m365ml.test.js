// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// The REAL portal's Microsoft 365 page with the tenant analysis (module m365ml) on a SYNTHETIC /api/m365: posture tiles (secure
// score, MFA, risky users, guests, external forwarding) or "not measured"; disabled accounts holding a licence; unassigned paid
// seats; a SKU filling at its recorded pace (history seeded in this browser); a renewal due; a password-spray pattern; one
// account failing from many addresses; sign-ins from abroad; impossible travel; risky sign-ins; tabs filter; the AI brief gets
// no person, address or UPN; with Graph not connected the section shows no figure; hostile names stay text; no page error.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node portal-m365ml.test.js
const http = require('http'), fs = require('fs'), path = require('path'), cp = require('child_process');
const LIVE = path.resolve(__dirname, '../../repos/live/portal'), DASH = path.resolve(__dirname, '../../ui');
if (!fs.existsSync(path.join(LIVE, 'index.html'))) { console.log('SKIP: repos/live/portal not present'); process.exit(0); }
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const SH = fs.readFileSync(path.join(DASH, 'add-dashboards-menu.sh'), 'utf8'), ELINE = /ELINE='([^']+)'/.exec(SH)[1], AWK = /awk -v line="\$ELINE" '([^']+)'/.exec(SH)[1];
const INDEX = cp.execFileSync('awk', ['-v', 'line=' + ELINE, AWK, path.join(LIVE, 'index.html')], { encoding: 'utf8' });
const NOW = Date.now(), iso = (min) => new Date(NOW - min * 60000).toISOString();
let CONNECTED = true, AIBODY = null, SIEMON = false;
const users = [{ name: 'Ahmed SYN', upn: 'ahmed.syn@example.test', dept: 'Finance', lic: 1, enabled: true }, { name: 'Left SYN <img src=x onerror=window.__x=1>', upn: 'left.syn@example.test', dept: 'Sales', lic: 1, enabled: false },
  { name: 'Gone SYN', upn: 'gone.syn@example.test', dept: 'IT', lic: 2, enabled: false }, { name: 'Svc SYN', upn: 'svc.syn@example.test', dept: '', lic: 0, enabled: true }];
const S = []; const sign = (min, upn, ip, loc, status, risk) => S.push({ time: iso(min), user: upn.split('@')[0], upn, app: 'Office 365', ip, loc, status, os: 'Windows', risk: risk || 'none' });
for (let i = 0; i < 6; i++) sign(30 + i, 'u' + i + '.syn@example.test', '203.0.113.9', 'Riyadh, SA', 'Failure');
for (let i = 0; i < 5; i++) sign(60 + i, 'target.syn@example.test', '198.51.100.' + i, 'Riyadh, SA', 'Failure');
sign(200, 'trav.syn@example.test', '192.0.2.1', 'Riyadh, SA', 'Success'); sign(150, 'trav.syn@example.test', '192.0.2.2', 'London, GB', 'Success');
sign(10, 'ahmed.syn@example.test', '192.0.2.3', 'Jeddah, SA', 'Success', 'high');
const M365 = () => CONNECTED ? { configured: true, updated: iso(1), licenses: [{ sku: 'M365 E3 (synthetic)', total: 100, consumed: 96, renews: '2026-12-20', days: 29 }, { sku: 'Visio Plan 2 (synthetic)', total: 40, consumed: 10, days: 200 }],
  users: { list: users }, signins: S, signinsOk: true, security: { secureScore: { ok: true, data: { current: 42, max: 100 } }, mfa: { ok: true, data: { users: 100, registered: 82 } }, riskyUsers: { ok: true, data: [{ id: 1 }, { id: 2 }] }, guestUsers: { ok: false }, mailboxRules: { ok: true, data: [{ id: 'r1' }] } } } : { configured: false };
(async () => {
  const srv = http.createServer((req, res) => {
    const u = decodeURIComponent(req.url.split('?')[0]), json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u === '/auth/whoami' || u === '/dashboards/whoami.json') return json(200, { user: 'nora.syn', role: 'admin' });
    if (u === '/auth/org') return json(200, { modules: null, resp: {}, updated: null });
    if (u === '/api/m365') return json(200, M365());
    if (u === '/api/soc/m365/insights') return SIEMON ? json(200, { configured: true, updated: new Date().toISOString(), kpis: { members: 310, guests: 12, disabled: 9, mfa_pct: 87.5, mfa_missing: 39, admins_no_mfa: 2, secure_score: { current: 51, max: 100, pct: 51 }, seats: 400, seats_used: 330, reclaimable: 21, compliance_pct: 91, noncompliant: 14, risky_users: 3 },
      actions: [{ priority: 100, title: 'Register MFA for 2 administrator account(s)', detail: 'An administrator account without MFA is the highest-value identity gap in the tenant.' }] }) : json(404, { error: 'not found' });
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
  const hist = {}; for (let d = 10; d >= 1; d--) hist[new Date(NOW - d * 864e5).toISOString().slice(0, 10)] = { 'M365 E3 (synthetic)': 96 - d, 'Visio Plan 2 (synthetic)': 10 };
  const open = async (seed) => { const ctx = await browser.newContext({ viewport: { width: 1500, height: 1000 } });
    if (seed) await ctx.addInitScript((h) => { try { localStorage.setItem('asM365LicHist', JSON.stringify(h)); } catch (e) { /* storage off */ } }, hist);
    const p = await ctx.newPage(); p.on('pageerror', (e) => errs.push(e.message));
    await p.goto(base + '/'); await wait(p, () => typeof setView === 'function' && typeof ME !== 'undefined' && ME && ME.user); await p.evaluate(() => setView('m365')); return p; };
  try {
    let p = await open(true);
    ok(await wait(p, () => { const s = document.querySelector('[data-m3="1"] .m3-k'); return s && /42%/.test(s.innerText); }), 'the analysis renders from Graph data');
    const k = (await p.textContent('[data-m3="1"] .m3-k')).replace(/\s+/g, ' ');
    ok(/Secure score\s*42%/i.test(k) && /MFA registered\s*82%/i.test(k) && /Risky users\s*2/i.test(k), 'posture tiles: ' + k);
    ok(/Guest accounts\s*—\s*not measured/i.test(k), 'a block Graph did not return is not measured');
    ok(/External forwarding rules\s*1/i.test(k), 'external forwarding rules');
    const f = (await p.evaluate(() => [...document.querySelectorAll('.m3-f')].map((x) => x.innerText).join(' | '))).replace(/\s+/g, ' ');
    ok(/One address failed sign-in for 6 different accounts/.test(f) && /203\.0\.113\.9/.test(f), 'password-spray pattern: ' + f.slice(0, 300));
    ok(/Impossible travel: one account signed in from SA and GB within 50 min/.test(f), 'impossible travel');
    ok(/1 sign-in\(s\) Microsoft rated risky/.test(f), 'risky sign-ins');
    ok(/2 disabled account\(s\) still hold a licence/.test(f), 'disabled accounts holding a licence');
    ok(/18 user\(s\) without MFA registered/.test(f), 'users without MFA');
    await p.click('[data-m3tab="lic"]');
    const lf = (await p.evaluate(() => [...document.querySelectorAll('.m3-f')].map((x) => x.innerText).join(' | '))).replace(/\s+/g, ' ');
    ok(/M365 E3 \(synthetic\) fills in about 4 days/.test(lf) && /renews in 29 days/.test(lf) && /30 paid seat\(s\) unassigned/.test(lf) && !/Impossible travel/.test(lf), 'licence tab: fill forecast, renewal, unassigned seats: ' + lf.slice(0, 300));
    await p.click('[data-m3tab="sign"]');
    ok(/One account failed sign-in from 5 addresses/.test(await p.textContent('[data-m3="1"]')), 'one account failing from many addresses');
    ok(/sign-in\(s\) from outside the Kingdom/.test(await p.textContent('[data-m3="1"]')), 'sign-ins from abroad');
    ok(!(await p.evaluate(() => !!window.__x || !!document.querySelector('[data-m3="1"] img'))), 'hostile names stay text');
    await p.click('[data-m3ai]');
    ok(await wait(p, () => /Synthetic brief/.test(document.body.innerText)), 'AI brief opens');
    ok(AIBODY && !/example\.test|203\.0\.113|Ahmed|Left SYN|Gone SYN|trav\.syn/.test(AIBODY) && /disabled_with_licence/.test(AIBODY), 'the AI brief carries no person, address or UPN');
    CONNECTED = false; p = await open(false);
    ok(await wait(p, () => /Once Microsoft Graph is connected/.test(((document.querySelector('[data-m3="1"]') || {}).innerText) || '')), 'not connected: says what it will analyse');
    ok(!(await p.$('[data-m3="1"] .m3-k')), 'not connected: no figure is shown');
    SIEMON = true; p = await open(false);
    ok(await wait(p, () => !!document.querySelector('[data-m3src="siem"]')), 'portal link not set up but the SIEM collector is: its figures are used');
    const sk = (await p.textContent('[data-m3src="siem"]')).replace(/\s+/g, ' ');
    ok(/Active accounts\s*310/i.test(sk) && /MFA coverage\s*87\.5%/i.test(sk) && /Seats to reclaim\s*21/i.test(sk) && /Register MFA for 2 administrator/.test(sk) && /SIEM's Microsoft Graph collector/.test(sk), 'SIEM tenant figures and first action: ' + sk.slice(0, 200));
  } finally { await browser.close(); srv.close(); }
  ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks');
  process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
