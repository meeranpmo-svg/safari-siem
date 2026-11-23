// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Shadow AI DLP (shadow-ai.html) against the REAL SIEM module (sentra-siem engine/soc/shadow-ai-routes.js) with a stubbed ClickHouse
// and stubbed SOC cases - all data SYNTHETIC. An operator: AI apps in use with people (PDPL: operators), the trend, a large
// upload opened as a case; asks for DeepSeek to be blocked (a request, nothing changes yet). An administrator approves it
// (four-eyes: a different person): the register shows it blocked and the app shows a policy gap; DLP signals; the extension
// token (shown once) and settings. A viewer: counts only, no names, no request form, no extension details. No logs: the page
// says what to connect. A hostile classification stays text. No page error.
// Run: SENTRA_SIEM_DIR=/home/user/sentra-siem PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node shadow-ai.test.js
const http = require('http'), fs = require('fs'), os = require('os'), path = require('path');
const DASH = path.resolve(__dirname, '../../ui');
const SIEM = process.env.SENTRA_SIEM_DIR || path.resolve(__dirname, '../../backend/siem');
const R = require(path.join(SIEM, 'engine/soc/shadow-ai-routes'));
const { createState } = require(path.join(SIEM, 'engine/soc/state'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const XSS = '<img src=x onerror="window.__xss=1">', MB = 1048576, RANK = { viewer: 1, analyst: 2, operator: 3, admin: 4 };
let ROLE = 'operator', LOGS = true;
const A = {
  sa_any: [{ c: 'web', n: 90000 }],
  sa_src: [{ s: 'fortigate', c: 'web', n: 5000, last: '2026-11-14 08:59:00' }],
  sa_hosts: [{ host: 'chatgpt.com', app: '', n: 4000, blk: 0, u: 60, out: 80 * MB, first: '2026-11-08 07:00:00', last: '2026-11-14 08:58:00' },
    { host: 'chat.deepseek.com', app: '', n: 120, blk: 20, u: 4, out: 2 * MB, first: '2026-11-12 10:00:00', last: '2026-11-14 07:00:00' },
    { host: '', app: 'Claude.AI', n: 500, blk: 0, u: 9, out: 0, first: '2026-11-07 10:00:00', last: '2026-11-14 06:00:00' }],
  sa_days: [{ d: '2026-11-13', host: 'chatgpt.com', app: '', n: 600 }, { d: '2026-11-14', host: 'chatgpt.com', app: '', n: 700 }, { d: '2026-11-14', host: 'chat.deepseek.com', app: '', n: 50 }],
  sa_users: [{ who: 'nora.syn', host: 'chatgpt.com', app: '', n: 300, blk: 0, out: 75 * MB, last: '2026-11-14 08:58:00' }, { who: 'omar.syn', host: 'chat.deepseek.com', app: '', n: 60, blk: 10, out: 2 * MB, last: '2026-11-14 07:00:00' }],
  sa_first: [{ host: 'chat.deepseek.com', app: '', first: '2026-11-12 10:00:00' }],
  sa_dlp: [{ ts: '2026-11-14 08:30:00', id: 'INC-SYN-1', who: 'nora.syn', host: 'syn-pc-01', ai: '', dest: 'chatgpt.com', urlhost: '', chan: 'web', act: 'permitted', cls: 'National ID, IBAN', pol: 'PII', m: 14, prod: 'Somansa', vendor: 'somansa', zdlp: '' },
    { ts: '2026-11-14 08:20:00', id: 'INC-SYN-2', who: 'omar.syn', host: '', ai: 'chatgpt', dest: 'chatgpt.com', urlhost: '', chan: 'web', act: 'blocked', cls: XSS, pol: '', m: 1, prod: 'Forcepoint', vendor: 'forcepoint', zdlp: '' }],
  sa_ext: [{ v: '1.0.0', u: 40, d: 42, last: '2026-11-14 08:59:00' }], sa_ext_act: [{ a: 'blocked', n: 3 }],
};

(async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sentra-sai-ui-')), state = await createState({ dir: path.join(dir, 'st') });
  const sec = path.join(dir, 'secrets.json'); fs.writeFileSync(sec, '{}');
  const config = {}; Object.defineProperty(config, 'secrets', { value: {}, enumerable: false, writable: true }); Object.defineProperty(config, '_paths', { value: { secrets: sec }, enumerable: false });
  const ch = { query: async (sql) => { const tag = /^\/\*q:([a-z_0-9]+)\*\//.exec(sql)[1]; if (!LOGS) return []; return (A[tag] || []).map((r) => Object.assign({}, r)); } };
  const made = [], cases = { create: (i, by) => { const c = { id: 'CASE-SYN-' + (made.length + 1), status: 'open', input: i, by }; made.push(c); return c; }, get: (id) => made.find((c) => c.id === id) };
  const routes = {}, audits = [], api = { route: (m, p, fn) => { routes[m + ' ' + p] = fn; } };
  R.register(api, { state, config, log: { info() {}, warn() {}, error() {}, every() {} }, ch, cases, noTimers: true, emitEvent() {} });
  const srv = http.createServer((req, res) => {
    const url = new URL(req.url, 'http://x'), u = url.pathname, json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u === '/dashboards/whoami.json') return json(200, { user: ROLE + '.syn', role: ROLE });
    const key = Object.keys(routes).find((k) => { const [m, p] = k.split(' '); if (m !== req.method) return false; const re = new RegExp('^' + p.replace(/:[a-z]+/g, '([^/]+)') + '$'); return re.test(u); });
    if (key) { let b = ''; req.on('data', (c) => { b += c; }); req.on('end', async () => { let out = null; const [, p] = key.split(' '), names = (p.match(/:[a-z]+/g) || []).map((x) => x.slice(1)), mm = new RegExp('^' + p.replace(/:[a-z]+/g, '([^/]+)') + '$').exec(u);
      const ctx = { query: Object.fromEntries(url.searchParams), body: b ? JSON.parse(b) : {}, params: Object.fromEntries(names.map((k, i) => [k, decodeURIComponent(mm[i + 1])])), role: ROLE, user: ROLE + '.syn', ip: '10.0.0.5', path: u, headers: {},
        ok: (x) => { out = [200, x]; return out; }, fail: (s, m) => { out = [s, { error: m }]; return out; },
        need: (r) => { if ((RANK[ROLE] || 0) < RANK[r]) { out = [403, { error: 'requires role ' + r }]; return false; } return true; }, audit: (a, t, d) => audits.push({ a, t, d, by: ROLE }) };
      const rv = await routes[key](ctx); if (!out) out = [200, rv]; json(out[0], out[1]); }); return; }
    if (u.startsWith('/api/')) return json(404, { error: 'not in this test' });
    const f = path.join(DASH, u.replace(/^\/dashboards\//, '')); if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (e, d) => { if (e) { res.writeHead(404); return res.end(); } res.writeHead(200, { 'Content-Type': f.endsWith('.js') ? 'application/javascript' : f.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const url = 'http://127.0.0.1:' + srv.address().port + '/dashboards/shadow-ai.html';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright'); const browser = await chromium.launch(), errs = [];
  const wait = (p, fn, arg, ms) => p.waitForFunction(fn, arg, { timeout: ms || 15000 }).then(() => true, () => false);
  try {
    const ctx = await browser.newContext({ viewport: { width: 1500, height: 1000 } });
    const p = await ctx.newPage(); p.on('pageerror', (e) => errs.push(e.message)); p.on('dialog', (d) => d.accept('not approved'));
    await p.goto(url);
    ok(await wait(p, () => /ChatGPT/.test(document.getElementById('apps').textContent)), 'AI apps load');
    const k = await p.textContent('#kpis'); ok(/3\s*AI apps in use/.test(k) && /2\s*people using them/.test(k), 'tiles: apps and people: ' + k.replace(/\s+/g, ' '));
    ok(/Claude/.test(await p.textContent('#apps')) && /new/.test(await p.textContent('#apps')), 'found by App-ID too; a new app is marked');
    ok((await p.$$('#trend .bars .c')).length === 2, 'trend: one bar per day');
    ok(await p.isVisible('#peoplecard') && /nora\.syn/.test(await p.textContent('#people')), 'an operator sees people');
    await p.click('#uploads [data-case="upload"]'); ok(await wait(p, () => /Case opened: CASE-SYN-1/.test(document.body.textContent)), 'a large upload opened as a SOC case');
    ok(made[0] && made[0].by === 'operator.syn' && /large upload/.test(made[0].input.title), 'the case names the app and the reason');

    // operator: ask for DeepSeek to be blocked
    await p.click('[data-tab="reg"]'); await wait(p, () => document.querySelector('[data-edit="deepseek"]'));
    await p.click('[data-edit="deepseek"]'); await p.selectOption('#r-status', 'blocked'); await p.fill('#r-owner', 'CISO SYN'); await p.fill('#r-reason', 'data leaves the Kingdom (synthetic)');
    await p.click('#reqf button[type=submit]'); ok(await wait(p, () => /different person approves/.test(document.getElementById('r-msg').textContent)), 'the change is sent for approval');
    ok(await wait(p, () => /DeepSeek/.test(document.getElementById('pending').textContent)), 'it waits for approval');
    ok(/change pending/.test(await p.textContent('#reg')), 'the register says a change is pending and nothing changed yet');

    // administrator: approves (a different person); the register and the apps follow
    ROLE = 'admin'; await p.reload(); await p.click('[data-tab="reg"]');
    ok(await wait(p, () => !!document.querySelector('#pending [data-dec="approve"]')), 'the administrator sees the request');
    await p.click('#pending [data-dec="approve"]'); ok(await wait(p, () => /Approved/.test(document.body.textContent)), 'approved');
    ok(await wait(p, () => /DeepSeek[\s\S]*Blocked/.test(document.getElementById('reg').textContent)), 'DeepSeek is blocked in the register');
    ok(audits.some((a) => a.a === 'shadow_ai.request.approve' && a.by === 'admin'), 'the approval is audited');
    await p.click('[data-tab="apps"]'); ok(await wait(p, () => /gap/.test(document.getElementById('apps').textContent)), 'a blocked app still reachable is a policy gap');

    // signals
    await p.click('[data-tab="sig"]'); ok(await wait(p, () => /INC|Somansa|let through/.test(document.getElementById('inc').textContent)), 'DLP incidents towards AI apps');
    ok(/let through/.test(await p.textContent('#inc')) && /Personal/.test(await p.textContent('#inc')) && /DeepSeek is blocked in the register/.test(await p.textContent('#gaps')), 'what was let through, its data classes, the gap');
    ok(/<img src=x/.test(await p.textContent('#inc')) && !(await p.evaluate(() => window.__xss)), 'a hostile classification stays text');

    // extension: token once, settings
    await p.click('[data-tab="ext"]'); ok(await wait(p, () => !!document.getElementById('mktok')), 'an administrator can create the token');
    await p.click('#mktok'); ok(await wait(p, () => document.querySelector('#tokout .tok') && document.querySelector('#tokout .tok').textContent.length > 20), 'the token is shown once');
    ok(/1\.0\.0/.test(await p.textContent('#vers')) && /"mode": "warn"/.test(await p.textContent('#pol')), 'versions seen and the policy the extension receives');
    await p.selectOption('#s-mode', 'block'); await p.fill('#s-kw', 'Project Falcon SYN'); await p.click('#setf button[type=submit]');
    ok(await wait(p, () => /Saved: .*extension\.mode/.test(document.getElementById('s-msg').textContent)), 'settings saved');

    // viewer: counts only
    ROLE = 'viewer'; await p.reload(); await wait(p, () => /ChatGPT/.test(document.getElementById('apps').textContent));
    ok(!(await p.isVisible('#peoplecard')) && /hidden/.test(await p.textContent('#uploads')) && !/nora\.syn/.test(await p.textContent('main')), 'a viewer sees no names (PDPL)');
    await p.click('[data-tab="reg"]'); ok(!(await p.isVisible('#reqcard')) && !(await p.$('[data-edit]')), 'a viewer cannot ask for changes');
    await p.click('[data-tab="ext"]'); ok(/operators and administrators/.test(await p.textContent('#vers')), 'extension details are for operators');

    // no logs yet
    LOGS = false; ROLE = 'operator'; await p.reload(); await p.click('[data-tab="apps"]');
    ok(await wait(p, () => /web-filter/.test(document.getElementById('appsnote').textContent)), 'no logs: the page says what to connect');
  } finally { await browser.close(); srv.close(); }
  ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks'); process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
