// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Insider Risk (dashboards/server/insider-risk.html) against the REAL SIEM module (engine/soc/insider-routes.js) with a SYNTHETIC UEBA
// and DLP: the PDPL framing; people pseudonymised (no name in the page); the itemised score and the behaviour-and-data pattern; tier
// chips; a person's indicators; context requested (the requester cannot approve, a second administrator does) and it adds the
// departing indicators; a case requested, authorised by a different administrator, the name shown only to the case team, a note and
// closure with an outcome; departments; an analyst is refused; menu entry, installer and the portal redirect.
// Run: SENTRA_SIEM_DIR=/home/user/sentra-siem PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node insider-risk.test.js
const http = require('http'), fs = require('fs'), os = require('os'), path = require('path');
const DASH = path.resolve(__dirname, '../../ui');
const SIEM = process.env.SENTRA_SIEM_DIR || path.resolve(__dirname, '../../backend/siem');
const req = (m) => require(path.join(SIEM, 'engine', m));
const { createState } = req('soc/state');
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
let ROLE = 'operator', USER = 'nora.syn';
const RANK = { viewer: 0, analyst: 1, operator: 2, admin: 3 }, DAY = 86400e3;
const day = (d) => new Date(Date.now() + d * DAY).toISOString().slice(0, 10);

(async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sentra-insider-')), Lq = { info() {}, warn() {}, error() {} };
  const state = createState({ dir: path.join(dir, 'state'), log: Lq });
  const U = ['dana.syn', 'omar.syn', 'rana.syn', 'sami.syn', 'huda.syn', 'zaid.syn'];
  const ueba = { entities: () => ({ items: U.map((u, i) => ({ id: 'user:' + u, type: 'user', name: u, peer_group: i < 5 ? 'Claims' : 'Finance', risk: { score: i === 0 ? 90 : 12 + i, tier: i === 0 ? 'high' : 'low' } })) }) };
  const dlp = { summary: async () => ({ available: true, users: [{ user: 'dana.syn', risk: 80, why: ['data left 6 times'], left: 6, incidents: 9, tamper: 0, sensitive: ['national ID'] }] }) };
  const deps = { state, ueba, dlp, config: { soc_analyst: { enabled: false } }, log: Lq, now: () => Date.now() };
  const R = {}, AUD = [];
  const api = { route: (m, p, h) => { R[m + ' ' + p] = { re: new RegExp('^' + p.replace(/:([a-zA-Z]+)/g, '(?<$1>[^/]+)') + '$'), h }; } };
  req('soc/insider-routes').register(api, deps);
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
  const url = 'http://127.0.0.1:' + srv.address().port + '/dashboards/insider-risk.html?standalone=1';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright'); const browser = await chromium.launch(), errs = [];
  const wait = (p, fn, arg) => p.waitForFunction(fn, arg, { timeout: 15000 }).then(() => true, () => false);
  const toast = (p, re) => wait(p, (s) => [...document.querySelectorAll('.toast')].some((t) => new RegExp(s).test(t.textContent)), re);
  let ANS = [];
  const open = async (ctx) => { const p = await ctx.newPage(); p.on('pageerror', (e) => errs.push(e.message)); p.on('dialog', (d) => { const a = ANS.shift(); if (a === undefined) { errs.push('unexpected dialog: ' + d.message()); d.dismiss(); } else d.accept(a); }); await p.goto(url); return p; };
  try {
    const ctx = await browser.newContext({ viewport: { width: 1500, height: 1000 } });
    let p = await open(ctx); ok(await wait(p, () => document.querySelectorAll('#pl tr[data-f]').length > 0), 'people listed');
    ok(/not proof of wrongdoing \(PDPL\)/.test(await p.textContent('#frame')), 'PDPL framing');
    ok(!(await p.content()).includes('dana.syn'), 'no name anywhere in the page');
    const top = await p.$eval('#pl tr[data-f]', (r) => r.getAttribute('data-f')); ok(/^P-[0-9a-f]{8}$/.test(top), 'pseudonym');
    ok(/behaviour AND data/.test(await p.textContent('#pl tr[data-f]')), 'the two-signal pattern shown');
    await p.click('[data-t="two"]'); ok(await wait(p, () => document.querySelectorAll('#pl tr[data-f]').length === 1), 'Behaviour AND data chip');
    await p.click('[data-t="high"]'); ok(await wait(p, () => /Nobody in this view/.test(document.getElementById('pl').textContent)), 'High chip: nobody high before the context');
    await p.click('[data-t="all"]'); await p.click('#pl tr[data-f]'); ok(await wait(p, () => /Why this score/.test(document.getElementById('dlgb').textContent) && /behaviour risk 90/.test(document.getElementById('dlgb').textContent)), 'person indicators itemised');
    // context: requested by the operator, approved by a different administrator
    await p.click('[data-close]'); await p.click('#wf summary');
    await p.fill('#wform [name=user]', 'dana.syn'); await p.fill('#wform [name=last_day]', day(20)); await p.fill('#wform [name=until]', day(40)); await p.fill('#wform [name=reason]', 'resigned - notice period (synthetic)');
    await p.click('#wform button[type=submit]'); ok(await toast(p, 'Context requested'), 'context requested');
    ok(!(await p.$('[data-wd]')), 'the requester (an operator) cannot approve');
    ROLE = 'admin'; USER = 'syed'; const a = await open(ctx); await wait(a, () => document.querySelector('[data-wd="approve"]'));
    await a.click('[data-wd="approve"]'); ok(await toast(a, 'Context approved'), 'a second person approved the context');
    ok(await wait(a, () => /departing/.test(document.getElementById('wl').textContent) && /active/.test(document.getElementById('wl').textContent)), 'context active');
    // case: the operator requests, the administrator authorises, the operator (case team) sees the name
    ROLE = 'operator'; USER = 'nora.syn'; p = await open(ctx); await wait(p, () => document.querySelectorAll('#pl tr[data-f]').length > 0);
    await p.click('#pl tr[data-f]'); await p.waitForSelector('[data-open]');
    ok(/departing/.test(await p.textContent('#dlgb')), 'the departing context now counts');
    ANS = ['indicators', 'behaviour and data both stand out while departing (synthetic)']; await p.click('[data-open]'); ok(await toast(p, 'Case requested'), 'case requested');
    ok(await wait(p, () => /requested/.test(document.getElementById('cs').textContent)) && !(await p.$('[data-cd]')), 'the requester cannot authorise');
    ROLE = 'admin'; USER = 'syed'; const a2 = await open(ctx); await wait(a2, () => document.querySelector('[data-cd="authorise"]'));
    await a2.click('[data-cd="authorise"]'); ok(await toast(a2, 'Case authorised'), 'authorised by a different administrator');
    ROLE = 'operator'; USER = 'khalid.syn'; const o2 = await open(ctx); await wait(o2, () => /authorised/.test(document.getElementById('cs').textContent)); ok(!(await o2.$('[data-cr]')), 'outside the case team: no Show name');
    ROLE = 'operator'; USER = 'nora.syn'; p = await open(ctx); await wait(p, () => document.querySelector('[data-cr]'));
    await p.click('[data-cr]'); ok(await wait(p, () => /dana\.syn/.test(document.getElementById('cs').textContent)), 'the case team sees the name');
    ok(AUD.some((x) => x.a === 'insider.case.reveal') && !JSON.stringify(AUD).includes('dana.syn'), 'the look is audited, the name is not in the audit');
    ANS = ['spoke with the manager: hand-over export (synthetic)']; await p.click('[data-cn]'); ok(await toast(p, 'Note added'), 'note');
    ANS = ['policy_reminder', 'hand-over explained it; reminded of the data policy']; await p.click('[data-cc]'); ok(await toast(p, 'Case closed'), 'closed with an outcome');
    ok(/Claims/.test(await p.textContent('#dp')), 'departments');
    if (process.env.SHOT) await p.screenshot({ path: process.env.SHOT, fullPage: true });   // optional: a picture for review
    ROLE = 'analyst'; USER = 'ali.syn'; const an = await open(ctx); ok(await wait(an, () => /operators and administrators/.test(document.getElementById('err').textContent)), 'an analyst is refused');
    const nav = fs.readFileSync(path.join(DASH, 'vendor', 'zyb-nav.js'), 'utf8');
    ok(/"h": "insider-risk.html"/.test(nav) && /insider-risk\.html/.test(fs.readFileSync(path.join(DASH, 'install-dashboards.sh'), 'utf8')), 'menu entry and installer');
    ok(/irm: 'insider-risk\.html'/.test(fs.readFileSync(path.join(DASH, 'vendor', 'zyb-menu.js'), 'utf8')) && /irm: 'insider-risk\.html'/.test(fs.readFileSync(path.join(DASH, 'vendor', 'zyb-early.js'), 'utf8')), 'the portal Insider Risk opens this page');
    ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  } finally { await browser.close(); srv.close(); fs.rmSync(dir, { recursive: true, force: true }); }
  console.log((bad ? 'FAILED ' : 'ok ') + (n - bad) + '/' + n);
  process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
