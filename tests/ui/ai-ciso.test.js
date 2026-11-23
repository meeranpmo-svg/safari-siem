// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for the AI CISO page (dashboards/server/ai-ciso.html) against the REAL ITAM engine (engine/ciso.js) with the SIEM
// link stubbed by SYNTHETIC records and 40 days of SYNTHETIC posture history: the half-dial gauge with the score and its change
// against 7 and 30 days ago; the posture trend with its grade bands and a domain switched on from the legend; the domain radar
// now against 30 days ago; the risk matrix (domain x severity) filters the register when a cell is clicked; risk age bars; a
// stale answer says so and refreshes on its own; phone width; no page error.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node ai-ciso.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const ITAM = path.join(__dirname, '..', '..', 'backend', 'itam'), DASH = path.join(__dirname, '..', '..', 'ui');
const H = require(path.join(ITAM, 'tests', 'helpers'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
function siemStub(calls) {
  return (method, path, body, who) => {
    calls.push({ method, path, who });
    if (method === 'POST' && path === '/duty/patrol') return Promise.resolve({ results: [{ engineer: 'network', opened: 2, errors: [] }, { engineer: 'security', opened: 0, errors: ['firewall API timeout'] }] });
    if (path === '/duty/engineers') return Promise.resolve({ engineers: [{ id: 'network', name: 'AI Network Engineer', open: 1, critical: 1, high: 0, last_patrol: 1, late: false }, { id: 'security', name: 'AI Security Engineer', open: 1, critical: 0, high: 1, late: true }] });
    if (path.startsWith('/duty/items')) return Promise.resolve({ items: [
      { id: 'DW-000101', engineer: 'network', severity: 'critical', status: 'awaiting-approval', title: 'core-sw-01: uplink errors', site: 'HQ', detected_at: Date.now() - 3600000 },
      { id: 'DW-000102', engineer: 'security', severity: 'high', status: 'needs-human', title: 'FW-JED: any-any rule', site: 'Jeddah', detected_at: Date.now() - 5 * 86400000 },
    ] });
    if (path === '/metrics') return Promise.resolve({ open_by_severity: { 4: 2, 3: 5 }, mttd_s: 120, mttr_s: 3600, sla: { breaching_now: [{ id: 'C-7', title: 'Brute force on VPN', severity: 4, resolve_breached: true }], resolve_compliance_pct: 80, ack_compliance_pct: 95 } });
    if (path === '/compliance/sama') return Promise.resolve({ summary: { coverage_pct: 72, counts: { covered: 20, partial: 8, gap: 4 } }, controls: [{ id: '3.3.14', title: 'Security event management', status: 'gap', owner: 'SOC' }, { id: '3.3.5', title: 'Identity', status: 'covered' }] });
    if (path === '/collection/assurance') return Promise.resolve({ summary: { required: 40, covered: 30, silent: 4, coverage_pct: 75 }, inventory: { connected: true }, collector: { quiet: false }, unknown_senders: [] });
    if (path.startsWith('/approvals')) return Promise.resolve({ items: [{ id: 'AP-1', title: 'Isolate PC-123', case_id: 'C-7' }] });
    return Promise.reject(new Error('unexpected ' + path));
  };
}


(async () => {
  const e = await H.startApp({ noAi: true });
  const calls = []; let T = Date.now();
  const C = require(path.join(ITAM, 'engine/ciso')).registerCiso(e.app.srv, e.app, { siem: siemStub(calls), now: () => T });
  const hist = e.app.store.collection('ciso_history'), DAY = 864e5;
  for (let d = 40; d >= 1; d--) { const t = T - d * DAY, day = new Date(t + 3 * 3600e3).toISOString().slice(0, 10), base = 52 + Math.round((40 - d) * 0.4);
    hist.put({ id: day, day, at: t, overall: base, grade: base >= 70 ? 'adequate' : 'weak', measured: 4, domains: { governance: base + 5, compliance: base - 3, detection: base - 8, exposure: base + 2, resilience: null, operations: base + 10 }, risks: 4, critical: 1, decisions: 2 }); }
  let WHO = { user: 'nora.syn', role: 'operator' };
  const web = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://x'), json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u.pathname === '/dashboards/whoami.json') return json(200, WHO);
    if (u.pathname.startsWith('/api/itam/')) {
      const h = Object.assign({}, req.headers, { 'x-sentra-proxy-secret': H.SECRET, 'x-auth-user': WHO.user, 'x-auth-role': WHO.role });
      const up = http.request({ host: '127.0.0.1', port: e.port, method: req.method, path: req.url, headers: h }, (r) => { res.writeHead(r.statusCode, r.headers); r.pipe(res); });
      req.pipe(up); return;
    }
    if (u.pathname.startsWith('/api/')) return json(404, { error: 'not in this test' });
    const f = path.join(DASH, u.pathname.replace(/^\/dashboards\//, '/')); if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (err, d) => { if (err) { res.writeHead(404); res.end(); return; } res.writeHead(200, { 'Content-Type': u.pathname.endsWith('.js') ? 'application/javascript' : u.pathname.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => web.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + web.address().port + '/dashboards/';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  const wait = (p, fn, arg) => p.waitForFunction(fn, arg, { timeout: 15000 }).then(() => true, () => false);
  const txt = (p, id) => p.evaluate((i) => document.getElementById(i).innerText, id);
  try {
    const p = await browser.newPage({ viewport: { width: 1500, height: 1100 } }); p.on('pageerror', (x) => errs.push(x.message));
    await p.goto(base + 'ai-ciso.html');
    ok(await wait(p, () => document.querySelector('#ring svg') && /of \d+ domains measured|domains measured/.test(document.getElementById('ring').innerText)), 'gauge drawn');
    ok(/vs 7 d/.test(await txt(p, 'ring')) && /vs 30 d/.test(await txt(p, 'ring')), 'change against 7 and 30 days ago: ' + (await txt(p, 'ring')).slice(0, 200));
    ok(await p.$('#trend svg path') && /\d+ days recorded/.test(await txt(p, 'trn')), 'posture trend over the recorded days');
    const paths0 = await p.evaluate(() => document.querySelectorAll('#trend svg path').length);
    await p.click('#trlg [data-tr="detection"]');
    ok(await p.evaluate((n0) => document.querySelectorAll('#trend svg path').length > n0, paths0), 'a domain line switched on from the legend');
    ok(await p.evaluate(() => document.querySelectorAll('#radar svg polygon').length >= 6) && /┄/.test(await txt(p, 'radn')), 'radar now vs an earlier day');
    ok(/n\/m/.test(await p.evaluate(() => document.getElementById('radar').textContent)), 'a domain not measured is marked, not scored');
    const cell = await p.$('#matrix button[data-mx]:not([disabled])'); ok(!!cell, 'risk matrix cells');
    const key = await cell.getAttribute('data-mx'); await cell.click();
    const sev = key.split('|')[1];
    ok(await wait(p, (s) => { const rows = [...document.querySelectorAll('#risks tr')]; return rows.length && rows.every((r) => r.innerText.toLowerCase().indexOf(s) >= 0); }, sev), 'clicking a cell filters the register to ' + key);
    ok(await p.evaluate(() => document.querySelector('#matrix button.sel') !== null), 'the chosen cell is marked');
    ok(await p.$('#ages svg rect') && /open longer than 30 days|none older than 30 days/.test(await txt(p, 'agen')), 'risk age bars');
    // a stale answer: says so and refreshes on its own
    T += 5 * 60000; const before = calls.filter((c) => c.path === '/metrics').length;
    await p.reload(); await wait(p, () => /refreshing/.test(document.getElementById('up').textContent));
    ok(/figures from 5 min ago · refreshing/.test(await txt(p, 'up')), 'stale figures labelled');
    ok(await wait(p, () => /^updated/.test(document.getElementById('up').textContent)), 'refreshed on its own');
    ok(calls.filter((c) => c.path === '/metrics').length === before + 1, 'one background read of the SIEM');
    const ph = await browser.newPage({ viewport: { width: 390, height: 900 } }); ph.on('pageerror', (x) => errs.push(x.message));
    await ph.goto(base + 'ai-ciso.html'); await wait(ph, () => document.querySelector('#trend svg'));
    ok(await ph.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1), 'phone width: no sideways scroll'); await ph.close();
    if (process.env.SHOT) await p.screenshot({ path: process.env.SHOT + '-ai-ciso.png', fullPage: true });
  } finally { await browser.close(); web.close(); C && C.stop && C.stop(); await e.close(); }
  ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks'); process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
