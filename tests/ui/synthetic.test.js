// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for synthetic.html (Synthetic Monitoring & Apdex): tiles, the checks table (down first, Apdex with rating,
// availability 24 h / 7 d / 30 d, response-time breakdown, certificate), filters, the check drawer (timings, hourly chart, daily
// table), Run now (operator), viewer sees no actions and no settings, administrator: allowed hosts, add / edit a check with
// transaction steps (GET only), a bad step line is refused in the page, Portal Apdex tab, empty state, engine missing, escaping.
// API answers are SYNTHETIC, in the shape engine/netops/synthetic-routes.js returns.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node synthetic.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const DASH = path.resolve(__dirname, '../../ui');
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const H = 3600000, T0 = Date.UTC(2026, 10, 13, 9, 0, 0);
const S = (o) => Object.assign({ runs: 0, apdex: null, rating: null, uptime_pct: null, error_rate_pct: null, avg_ms: null, p50_ms: null, p95_ms: null, satisfied: 0, tolerating: 0, frustrated: 0 }, o);
const d1 = S({ runs: 288, apdex: 0.97, rating: 'excellent', uptime_pct: 100, error_rate_pct: 0, avg_ms: 210, p50_ms: 200, p95_ms: 500, satisfied: 280, tolerating: 8 });
const CHECKS = [
  { id: 'syn-portal', name: 'SYN Customer portal', app: 'SYN Portal', url: 'https://portal.syn.test/health', method: 'GET', steps: 0, step_list: [], enabled: true, interval_s: 300, apdex_t_ms: 500, timeout_ms: 10000, expect_status: [200], expect_text: 'OK', follow_redirects: true, max_redirects: 5, tls_verify: true, cert_warn_days: 30,
    status: 'up', last: { at: T0, ok: true, status: 200, error: '', ms: { dns: 12, connect: 20, tls: 40, ttfb: 180, total: 230 }, redirects: 0 }, cert: { state: 'ok', days_left: 210, issuer: 'SYN CA', subject: 'portal.syn.test', valid_to: T0 + 210 * 86400000, authorized: true }, d1, d7: d1, d30: d1, recent: [] },
  { id: 'syn-claims', name: '<img src=x onerror=alert(1)>', app: 'SYN Claims', url: 'https://claims.syn.test/', method: 'GET', steps: 2, step_list: [{ url: 'https://claims.syn.test/' }, { link_text: 'Motor claims', expect_text: 'Status' }], enabled: true, interval_s: 300, apdex_t_ms: 800, timeout_ms: 10000, expect_status: [], expect_text: '', follow_redirects: true, max_redirects: 5, tls_verify: true, cert_warn_days: 30,
    status: 'down', last: { at: T0, ok: false, status: 503, error: 'step 2: HTTP 503', ms: { dns: 10, connect: 15, tls: 30, ttfb: 900, total: 1200 }, redirects: 1 }, cert: { state: 'expiring', days_left: 9, issuer: 'SYN CA', subject: 'claims.syn.test', valid_to: T0 + 9 * 86400000, authorized: true },
    d1: S({ runs: 288, apdex: 0.61, rating: 'poor', uptime_pct: 96.5, error_rate_pct: 3.5, p50_ms: 750, p95_ms: 3000, satisfied: 150, tolerating: 52, frustrated: 86 }), d7: S({ uptime_pct: 99.2 }), d30: S({ uptime_pct: 99.6 }), recent: [] },
  { id: 'syn-new', name: 'SYN Intranet', app: '', url: 'http://intranet.syn.test/', method: 'HEAD', steps: 0, step_list: [], enabled: true, interval_s: 600, apdex_t_ms: 500, timeout_ms: 10000, expect_status: [], expect_text: '', follow_redirects: true, max_redirects: 5, tls_verify: true, cert_warn_days: 30,
    status: 'pending', last: null, cert: null, d1: S(), d7: S(), d30: S(), recent: [] }];
const VIEW = () => ({ summary: { checks: 3, up: 1, degraded: 0, down: 1, pending: 1, certs_expiring: 1, certs_bad: 0, d1: S({ runs: 576, apdex: 0.79, rating: 'fair', uptime_pct: 98.25 }) }, checks: EMPTY ? [] : CHECKS,
  apps: [Object.assign({ app: 'SYN Claims', checks: 1, down: 1 }, CHECKS[1].d1), Object.assign({ app: 'SYN Portal', checks: 1, down: 0 }, d1)],
  certs: [{ id: 'syn-claims', name: CHECKS[1].name, url: CHECKS[1].url, state: 'expiring', days_left: 9, valid_to: T0 + 9 * 86400000, issuer: 'SYN CA', subject: 'claims.syn.test' }, { id: 'syn-portal', name: 'SYN Customer portal', url: CHECKS[0].url, state: 'ok', days_left: 210, valid_to: T0 + 210 * 86400000, issuer: 'SYN CA', subject: 'portal.syn.test' }],
  engine: { enabled: true, running: true }, role: ROLE, settings: ROLE === 'admin' ? { allow: ['*.syn.test'], allow_private: false, default_t_ms: 500 } : undefined });
const DETAIL = { check: CHECKS[1], hours: Array.from({ length: 49 }, (_, i) => S(i % 3 ? { runs: 12, apdex: 0.5 + (i % 5) / 10, p95_ms: 800 + i * 20 } : {})).map((x, i) => Object.assign({ hour: T0 - (48 - i) * H }, x)),
  days: [Object.assign({ day: '2026-11-12' }, CHECKS[1].d1), Object.assign({ day: '2026-11-13' }, d1)], recent: [],
  last_result: { at: T0, ok: false, status: 503, error: 'step 2: HTTP 503', ms: CHECKS[1].last.ms, redirects: 1, steps: [{ url: 'https://claims.syn.test/', status: 200, ms: 300, ok: true }, { url: 'https://claims.syn.test/motor', status: 503, ms: 900, ok: false, error: 'HTTP 503' }] } };
let ROLE = 'admin', EMPTY = false, MISSING = false; const CALLS = [];
(async () => {
  const srv = http.createServer((q, r) => {
    const u = q.url.split('?')[0], j = (c, o) => { r.writeHead(c, { 'Content-Type': 'application/json' }); r.end(JSON.stringify(o)); };
    if (u === '/dashboards/whoami.json') return j(200, { user: 'syn.' + ROLE, role: ROLE });
    if (u.startsWith('/api/')) {
      let b = ''; q.on('data', (c) => { b += c; }); q.on('end', () => {
        CALLS.push({ m: q.method, u: q.url, b: b ? JSON.parse(b) : null });
        const P = '/api/soc/netops/';
        if (MISSING) return j(404, { error: 'not found' });
        if (u === P + 'synthetic' && q.method === 'GET') return j(200, VIEW());
        if (u === P + 'synthetic/checks/syn-claims' && q.method === 'GET') return j(200, DETAIL);
        if (/synthetic\/checks\/[^/]+\/run$/.test(u)) return j(200, { at: T0, ok: false, error: 'step 2: HTTP 503', ms: { total: 1200 } });
        if (u === P + 'synthetic/checks' && q.method === 'POST') return j(200, Object.assign({ id: 'x' }, JSON.parse(b)));
        if (u === P + 'synthetic/settings') return j(200, JSON.parse(b));
        if (u === P + 'apdex/portal') return j(200, { hours: 24, t_ms: 500, measured: true, note: 'Apdex counts only requests whose log line carries the request time; a 5xx answer is frustrated.',
          sites: [{ site: 'portal.syn.test', requests: 1000, timed: 900, satisfied: 700, tolerating: 120, frustrated: 80, server_errors: 30, apdex: 0.84, rating: 'fair', error_rate_pct: 3, p50_ms: 210, p95_ms: 1800 }],
          series: [{ hour: T0 - H, timed: 450, apdex: 0.82, p95_ms: 1700 }, { hour: T0, timed: 450, apdex: 0.86, p95_ms: 1600 }] });
        return j(404, { error: 'not in this test' });
      }); return;
    }
    const f = path.join(DASH, u.replace(/^\/dashboards\//, '/')); if (!f.startsWith(DASH)) { r.writeHead(403); return r.end(); }
    fs.readFile(f, (e, d) => { if (e) { r.writeHead(404); return r.end(); } r.writeHead(200, { 'Content-Type': u.endsWith('.js') ? 'application/javascript' : u.endsWith('.css') ? 'text/css' : 'text/html' }); r.end(d); });
  });
  await new Promise((res) => srv.listen(0, '127.0.0.1', res));
  const base = 'http://127.0.0.1:' + srv.address().port + '/dashboards/';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  const open = async () => { const p = await browser.newPage({ viewport: { width: 1500, height: 950 } }); p.on('pageerror', (e) => errs.push(e.message)); p.on('dialog', (d) => { if (/Delete this check/.test(d.message())) return d.accept(); errs.push('dialog ' + d.message()); d.dismiss(); }); await p.goto(base + 'synthetic.html?standalone=1'); return p; };
  const txt = (p, sel) => p.evaluate((s) => (document.querySelector(s) || {}).textContent || '', sel);
  try {
    let p = await open(); await p.waitForSelector('#chk tr[data-id]');
    const k = await txt(p, '#kpi');
    ok(/Checks3/.test(k) && /Down1/.test(k) && /Apdex 24 h0\.79/.test(k) && /Availability 24 h98\.25 %/.test(k) && /Certificates1/.test(k), 'tiles: ' + k.slice(0, 200));
    ok(await p.title() === 'Synthetic Monitoring & Apdex', 'title');
    const rows = await p.$$eval('#chk tr[data-id]', (l) => l.map((r) => r.getAttribute('data-id')));
    ok(JSON.stringify(rows) === '["syn-portal","syn-claims","syn-new"]', 'rows in the engine order: ' + rows);
    const claims = await txt(p, '#chk tr[data-id="syn-claims"]');
    ok(/<img src=x onerror=alert\(1\)>/.test(claims) && !(await p.$('#chk img')), 'a name is escaped, never HTML');
    ok(/0\.61/.test(claims) && /Poor/.test(claims) && /96\.50 %/.test(claims) && /99\.20 %/.test(claims) && /step 2: HTTP 503/.test(claims) && /Expiring soon/.test(claims) && /9 d/.test(claims) && /2 steps/.test(claims), 'down check: Apdex, availability, error, certificate: ' + claims.slice(0, 300));
    ok(/≈750 ms \/ ≈3\.0 s/.test(claims), 'p50 / p95 marked approximate');
    ok((await p.$$('#chk tr[data-id="syn-portal"] .brk i')).length === 5, 'response-time breakdown (DNS, connect, TLS, server, download)');
    ok(/Not run yet/.test(await txt(p, '#chk tr[data-id="syn-new"]')) && /–/.test(await txt(p, '#chk tr[data-id="syn-new"]')), 'a check not run yet shows dashes, no numbers');
    await p.selectOption('#fst', 'down'); ok((await p.$$('#chk tr[data-id]')).length === 1, 'status filter');
    await p.selectOption('#fst', ''); await p.fill('#q', 'intranet'); ok((await p.$$('#chk tr[data-id]')).length === 1, 'search'); await p.fill('#q', ''); await p.dispatchEvent('#q', 'input');

    await p.click('#chk tr[data-id="syn-claims"] td:nth-child(3)'); await p.waitForFunction(() => /Last 48 hours/.test((document.getElementById('zd-b') || {}).textContent || ''));
    const dr = await txt(p, '#zd-b');
    ok(/Server \(first byte\)/.test(dr) && /Daily \(30 days\)/.test(dr) && /2026-11-12/.test(dr) && /motor/.test(dr) && /HTTP 503/.test(dr), 'drawer: breakdown, steps, daily: ' + dr.slice(0, 200));
    ok((await p.$$('#zd-b svg rect')).length > 20 && (await p.$$('#zd-b svg circle')).length > 20, 'hourly chart drawn');
    await p.evaluate(() => document.querySelector('#zd-b [data-a="run"]').click()); await p.waitForTimeout(300);
    ok(CALLS.some((c) => c.m === 'POST' && /synthetic\/checks\/syn-claims\/run$/.test(c.u)), 'Run now from the drawer');
    await p.keyboard.press('Escape'); await p.waitForTimeout(200);

    await p.click('[data-tab="crt"]'); const crt = await txt(p, '#crt'); ok(/claims\.syn\.test/.test(crt) && /Expiring soon/.test(crt) && /SYN CA/.test(crt), 'certificates tab');
    await p.click('[data-tab="app"]'); const ap = await txt(p, '#apps'); ok(/SYN Claims/.test(ap) && /0\.61/.test(ap) && /86/.test(ap), 'applications tab: satisfied / tolerating / frustrated');
    await p.click('[data-tab="por"]'); await p.waitForSelector('#por table');
    const por = await txt(p, '#por'); ok(/portal\.syn\.test/.test(por) && /0\.84/.test(por) && /Fair/.test(por) && /1\.8 s/.test(por), 'portal Apdex: ' + por.slice(0, 160));
    await p.selectOption('#pt', '1000'); await p.waitForTimeout(200); ok(CALLS.some((c) => /apdex\/portal\?hours=24&t_ms=1000/.test(c.u)), 'threshold sent to the engine');

    // administrator: allowed hosts, add a check with steps, a bad step line is refused in the page, edit, delete
    await p.click('[data-tab="set"]'); await p.waitForSelector('#allow');
    ok((await p.inputValue('#allow')) === '*.syn.test', 'current allow-list shown');
    await p.fill('#allow', '*.syn.test\n10.20.0.0/16'); await p.check('#apriv'); await p.click('#sf button[type=submit]'); await p.waitForTimeout(300);
    const put = CALLS.filter((c) => c.m === 'PUT').pop(); ok(put && JSON.stringify(put.b) === JSON.stringify({ allow: ['*.syn.test', '10.20.0.0/16'], allow_private: true, default_t_ms: 500 }), 'allow-list saved: ' + JSON.stringify(put && put.b));
    await p.fill('#cf [name=name]', 'SYN Motor quote'); await p.fill('#cf [name=url]', 'https://quote.syn.test/'); await p.fill('#cf [name=steps]', 'url https://quote.syn.test/\nlink Motor | Get a quote');
    await p.click('#cf button[type=submit]'); await p.waitForTimeout(300);
    const post = CALLS.filter((c) => c.m === 'POST' && /synthetic\/checks$/.test(c.u)).pop();
    ok(post && post.b.name === 'SYN Motor quote' && post.b.method === 'GET' && JSON.stringify(post.b.steps) === JSON.stringify([{ url: 'https://quote.syn.test/' }, { link_text: 'Motor', expect_text: 'Get a quote' }]) && post.b.id === undefined, 'add check with steps: ' + JSON.stringify(post && post.b));
    const before = CALLS.length;
    await p.fill('#cf [name=name]', 'x'); await p.fill('#cf [name=url]', 'https://quote.syn.test/'); await p.fill('#cf [name=steps]', 'post https://quote.syn.test/form'); await p.click('#cf button[type=submit]'); await p.waitForTimeout(300);
    ok(CALLS.slice(before).every((c) => !(c.m === 'POST' && /synthetic\/checks$/.test(c.u))) && /starts with "url" or "link"/.test(await txt(p, '.toast:last-of-type')), 'a step that is not url / link is refused in the page');
    await p.click('[data-tab="chk"]'); await p.click('#chk tr[data-id="syn-claims"] [data-a="edit"]'); await p.waitForSelector('#cf [data-a="del"]');
    ok((await p.inputValue('#cf [name=steps]')) === 'url https://claims.syn.test/\nlink Motor claims | Status', 'edit shows the steps');
    await p.fill('#cf [name=iv]', '120'); await p.click('#cf button[type=submit]'); await p.waitForTimeout(300);
    const upd = CALLS.filter((c) => c.m === 'POST' && /synthetic\/checks$/.test(c.u)).pop(); ok(upd.b.id === 'syn-claims' && upd.b.interval_s === 120, 'edit sends the id');
    await p.click('[data-tab="chk"]'); await p.click('#chk tr[data-id="syn-claims"] [data-a="edit"]'); await p.waitForSelector('#cf [data-a="del"]'); await p.click('#cf [data-a="del"]'); await p.waitForTimeout(300);
    ok(CALLS.some((c) => c.m === 'DELETE' && /synthetic\/checks\/syn-claims$/.test(c.u)), 'delete after confirmation');
    await p.close();

    // viewer: no actions, no settings
    ROLE = 'viewer'; p = await open(); await p.waitForSelector('#chk tr[data-id]');
    ok(!(await p.$('[data-a="run"]')) && !(await p.$('[data-a="edit"]')) && await p.evaluate(() => document.getElementById('tab-set').hidden), 'viewer: no Run now, no Edit, no Settings');
    await p.close();
    ROLE = 'operator'; p = await open(); await p.waitForSelector('#chk tr[data-id]');
    ok((await p.$$('[data-a="run"]')).length === 3 && !(await p.$('[data-a="edit"]')), 'operator: Run now, no Edit'); await p.close();

    // empty state and engine missing: says what to do, no numbers invented
    ROLE = 'admin'; EMPTY = true; p = await open(); await p.waitForSelector('#chk .empty');
    ok(/No synthetic checks yet/.test(await txt(p, '#chk')) && /Settings & checks/.test(await txt(p, '#chk')), 'empty state says what to do'); await p.close();
    EMPTY = false; MISSING = true; p = await open(); await p.waitForSelector('#chk .err');
    ok(/not installed in the SIEM engine yet/.test(await txt(p, '#chk')), 'engine without the module: says so'); await p.close();
    ok(!errs.length, 'no page errors / unexpected dialogs: ' + errs.join(' | '));
  } finally { await browser.close(); srv.close(); }
  console.log((bad ? 'FAILED ' + bad + ' of ' : 'OK ') + n + ' checks');
  process.exit(bad ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });
