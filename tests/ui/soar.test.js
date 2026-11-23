// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// SOAR - Automated Response (dashboards/server/soar.html) against the REAL SIEM modules (engine/soc/soar-routes.js + the approval route
// in engine/soc/routes.js) with SYNTHETIC alerts: empty state; matches with itemised confidence and the actions they will request;
// filter by confidence; an operator runs a playbook (a case, actions waiting); the requester sees "another person decides"; a
// different administrator approves one with a comment; dismiss needs a reason; automation is admin-only and saves a version; the
// learning tab; AI off says why; a hostile alert stays text; viewer sees no write controls; menu, installer and the portal redirect.
// Run: SENTRA_SIEM_DIR=/home/user/sentra-siem PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node soar.test.js
const http = require('http'), fs = require('fs'), os = require('os'), path = require('path');
const DASH = path.resolve(__dirname, '../../ui');
const SIEM = process.env.SENTRA_SIEM_DIR || path.resolve(__dirname, '../../backend/siem');
const req = (m) => require(path.join(SIEM, 'engine', m));
const { createState } = req('soc/state'), { createAlerts } = req('soc/alerts'), { createCases } = req('soc/cases');
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const XSS = '<img src=x onerror="window.__xss=1">';
let ROLE = 'viewer', USER = 'vera.syn';
const RANK = { viewer: 0, analyst: 1, operator: 2, admin: 3 };

(async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sentra-soar-')), Lq = { info() {}, warn() {}, error() {} };
  const state = createState({ dir: path.join(dir, 'state'), log: Lq }), alerts = createAlerts({ state, log: Lq }), cases = createCases({ state, alerts, log: Lq });
  const deps = { state, alerts, cases, config: { soc_analyst: { enabled: false } }, log: Lq, noTimer: true };
  const R = {}, AUD = [];
  const api = { route: (m, p, h) => { R[m + ' ' + p] = { re: new RegExp('^' + p.replace(/:([a-zA-Z]+)/g, '(?<$1>[^/]+)') + '$'), h }; } };
  req('soc/routes').register(api, deps); req('soc/soar-routes').register(api, deps);
  const srv = http.createServer((rq, res) => {
    const url = new URL(rq.url, 'http://x'), u = url.pathname, json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u === '/dashboards/whoami.json') return json(200, { user: USER, role: ROLE });
    const hit = Object.entries(R).find(([k, v]) => k.startsWith(rq.method + ' ') && v.re.test(u));
    if (hit) { let b = ''; rq.on('data', (x) => { b += x; }); rq.on('end', async () => {
      const o = {}, m = hit[1].re.exec(u), ctx = { role: ROLE, user: USER, body: b ? JSON.parse(b) : {}, params: m.groups ? Object.fromEntries(Object.entries(m.groups).map(([k, v]) => [k, decodeURIComponent(v)])) : {}, query: Object.fromEntries(url.searchParams), path: u,
        need(r) { if (RANK[ROLE] < RANK[r]) { o.status = 403; o.error = 'requires ' + r; return false; } return true; }, audit: (a, t, d) => AUD.push({ a, t, d }), ok: (x) => { o.body = x; return x; }, fail(code, msg) { o.status = code; o.error = msg; } };
      try { await hit[1].h(ctx); if (o.status) return json(o.status, { error: o.error || 'refused' }); json(200, o.body); } catch (e) { json(e.code || e.status || 500, { error: e.message }); } }); return; }
    if (u.startsWith('/api/')) return json(404, { error: 'not in this test' });
    const f = path.join(DASH, u.replace(/^\/dashboards\//, '')); if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (e, d) => { if (e) { res.writeHead(404); return res.end(); } res.writeHead(200, { 'Content-Type': f.endsWith('.js') ? 'application/javascript' : f.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const url = 'http://127.0.0.1:' + srv.address().port + '/dashboards/soar.html?standalone=1';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  const wait = (p, fn, a) => p.waitForFunction(fn, a, { timeout: 15000 }).then(() => true, () => false);
  const open = async (role, user) => { ROLE = role; USER = user; const p = await browser.newPage({ viewport: { width: 1500, height: 1000 } }); p.on('pageerror', (e) => errs.push(e.message)); await p.goto(url); await wait(p, () => !document.getElementById('main').hidden); return p; };
  try {
    let p = await open('viewer', 'vera.syn');
    ok(await wait(p, () => /No open alert waits for a playbook/.test(document.getElementById('matches').innerText)), 'empty state');
    await p.close();
    alerts.raise({ rule_id: 'SENTRA-AUTH-001', rule_name: 'Brute force ' + XSS, severity: 4, group: { user: 'dana.syn' }, fields: { src_ip: '198.51.100.7' }, mitre: ['T1110'], summary: 'synthetic' });
    alerts.raise({ rule_id: 'SENTRA-AUTH-002', rule_name: 'Spray', severity: 1, group: { user: 'omar.syn' }, mitre: [], summary: 'synthetic' });
    p = await open('viewer', 'vera.syn');
    ok(await wait(p, () => document.querySelectorAll('.sr-card').length === 2), 'two matches');
    ok(!(await p.$('[data-run]')), 'viewer: no Run');
    await p.close();
    p = await open('operator', 'nora.syn');
    await wait(p, () => document.querySelectorAll('.sr-card').length === 2);
    const t = await p.evaluate(() => document.getElementById('matches').innerText);
    ok(/detection rule this playbook/.test(t) && /severity 4 of 4/.test(t) && /needs 3 closed cases/.test(t), 'confidence itemised');
    ok(/Block external IP/.test(t) && /198\.51\.100\.7/.test(t), 'actions it will request, with targets');
    ok(await p.evaluate(() => !window.__xss), 'hostile rule name stays text');
    ok(await p.evaluate(() => document.querySelector('[data-ask]').disabled), 'AI off: brief disabled');
    await p.selectOption('#f-conf', '75'); ok(await wait(p, () => document.querySelectorAll('.sr-card').length === 1), 'confidence filter');
    await p.selectOption('#f-conf', '0');
    await p.click('.sr-card [data-dis]'); await p.click('#dlg-ok'); ok(await wait(p, () => /reason/.test(document.getElementById('dlg-e').innerText)), 'dismiss needs a reason'); await p.click('#dlg-x');
    const key = await p.evaluate(() => [...document.querySelectorAll('.sr-card')].find((c) => /dana\.syn/.test(c.innerText)).getAttribute('data-key'));
    await p.click('[data-run="' + key + '"]'); await p.click('#dlg-ok');
    ok(await wait(p, () => document.querySelectorAll('.sr-card').length === 1), 'run: the match becomes a case');
    ok(cases.all(() => true).length === 1 && cases.approvals.list({ status: 'pending' }).length >= 1, 'case + pending approvals');
    await p.click('[data-tab="wait"]'); ok(await wait(p, () => /another person decides/.test(document.getElementById('wait').innerText)), 'requester cannot decide');
    await p.click('[data-tab="runs"]'); ok(await wait(p, () => /nora\.syn/.test(document.getElementById('runs').innerText)), 'run listed');
    await p.click('[data-tab="auto"]'); ok(await p.evaluate(() => document.getElementById('a-on').disabled && !document.getElementById('a-save')), 'operator: automation read-only');
    await p.close();
    p = await open('admin', 'sec.admin');
    await p.click('[data-tab="wait"]'); await wait(p, () => document.querySelector('[data-dec="approved"]'));
    await p.click('[data-dec="approved"]'); await p.fill('#d-cm', 'NOC blocks it under CHG-SYN-9'); await p.click('#dlg-ok');
    ok(await wait(p, () => document.querySelectorAll('[data-dec="approved"]').length === 0 || /Approved/.test(document.body.innerText)), 'approved');
    ok(cases.approvals.list({}).some((a) => a.status === 'approved' && a.decided_by === 'sec.admin'), 'decision recorded by the admin');
    await p.click('[data-tab="auto"]'); await p.check('#a-on'); await p.selectOption('[data-pm="PB-BRUTE-FORCE"]', 'propose'); await p.click('#a-save');
    ok(await wait(p, () => /version 1/.test(document.getElementById('ver').innerText)), 'automation saved (v1)');
    await p.click('[data-tab="learn"]'); ok(await wait(p, () => /Response actions/.test(document.getElementById('learn').innerText) && /Block external IP/.test(document.getElementById('learn').innerText)), 'learning tab');
    await p.close();
    ok(AUD.some((a) => a.a === 'soc.soar.run') && AUD.some((a) => a.a === 'soc.soar.config'), 'audited');
    const nav = fs.readFileSync(path.join(DASH, 'vendor', 'zyb-nav.js'), 'utf8');
    ok(/"h": "soar.html"/.test(nav) && / soar\.html /.test(fs.readFileSync(path.join(DASH, 'install-dashboards.sh'), 'utf8')), 'menu entry and installer');
    ok(/soar: 'soar\.html'/.test(fs.readFileSync(path.join(DASH, 'vendor', 'zyb-menu.js'), 'utf8')) && /soar: 'soar\.html'/.test(fs.readFileSync(path.join(DASH, 'vendor', 'zyb-early.js'), 'utf8')), 'the portal\'s SOAR opens this page');
    ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  } finally { await browser.close(); srv.close(); fs.rmSync(dir, { recursive: true, force: true }); }
  console.log((bad ? 'FAILED ' : 'ok ') + (n - bad) + '/' + n);
  process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
