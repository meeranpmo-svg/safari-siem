// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// soc-performance.html against the REAL SOC analyst routes (sentra-siem engine/soc/analyst-routes.js + watchlist.js) with SYNTHETIC
// alerts: response times (median / p90 with n, withheld below 3), the alerts to work first with their priority factors, an operator
// adds a host to the watchlist and removes it (with a reason), an admin rates a crown jewel and the alert's priority shows it; an
// analyst sees no add form, a viewer sees only the times; hostile values stay text; the menu entry, installer and the old portal's
// "SOC Performance & Operations" redirect.
// Run: SENTRA_SIEM_DIR=/home/user/sentra-siem PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node soc-performance.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const SIEM = process.env.SENTRA_SIEM_DIR || path.resolve(__dirname, '../../backend/siem');
const DASH = path.resolve(__dirname, '../../ui');
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const XSS = '<img src=x onerror="window.__xss=1">';
const { createState } = require(path.join(SIEM, 'engine/soc/state'));
const { createAlerts } = require(path.join(SIEM, 'engine/soc/alerts'));
const { createCases } = require(path.join(SIEM, 'engine/soc/cases'));
const { parse } = require(path.join(SIEM, 'engine/api/query'));
const { fakeApi, tmpDir, quietLog } = require(path.join(SIEM, 'tests/soc-fakes'));
const MIN = 60000, NOW = Date.now();
(async () => {
  const dir = tmpDir(), state = createState({ dir, log: quietLog }), alerts = createAlerts({ state, log: quietLog }), cases = createCases({ state, alerts, log: quietLog });
  const search = { parse, search: async () => ({ rows: [] }), top: async () => ({ values: [] }), histogram: async (o) => ({ buckets: [{ t: o.from, n: 0 }] }) };
  const api = fakeApi({ realRanks: true });
  require(path.join(SIEM, 'engine/soc/analyst-routes')).register(api, { state, alerts, cases, search, config: { soc_analyst: {} }, log: quietLog, noTimers: true });
  // five closed criticals with known times, one open medium on the claims database, one open with a hostile rule name
  for (let i = 0; i < 5; i++) { const x = alerts.raise({ rule_id: 'SYN-C' + i, rule_name: 'Synthetic critical ' + i, severity: 4, group: { host: 'pc-' + i }, fields: {}, summary: 'synthetic', ts_first: NOW - 60 * MIN - (i + 1) * 10 * MIN, ts_last: NOW - 60 * MIN, source: 'engine', count: 1 }).alert;
    state.collection('alerts').put(Object.assign({}, alerts.get(x.id), { created: NOW - 60 * MIN, ack_at: NOW - 60 * MIN + (i + 1) * MIN, closed_at: NOW - 60 * MIN + (i + 1) * 30 * MIN, status: 'closed-true-positive' })); }
  const db = alerts.raise({ rule_id: 'SYN-DB', rule_name: 'Synthetic odd login on the database', severity: 2, group: { host: 'srv-db-01' }, fields: {}, summary: 'synthetic', ts_first: NOW - 5 * MIN, ts_last: NOW, source: 'engine', count: 1 }).alert;
  alerts.raise({ rule_id: 'SYN-X', rule_name: 'Synthetic ' + XSS, severity: 1, group: { host: 'pc-x' }, fields: {}, summary: 'synthetic', ts_first: NOW - 5 * MIN, ts_last: NOW, source: 'engine', count: 1 });
  let WHO = { user: 'omar.syn', role: 'operator' };
  const srv = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://x'), json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u.pathname === '/dashboards/whoami.json') return json(200, WHO);
    if (u.pathname.startsWith('/api/soc/')) { let b = ''; req.on('data', (c) => { b += c; }); req.on('end', async () => { const r = await api.call(req.method, u.pathname + u.search, { role: WHO.role, user: WHO.user, body: b ? JSON.parse(b) : undefined }); json(r.status, r.body); }); return; }
    if (u.pathname.startsWith('/api/')) return json(404, { error: 'not in this test' });
    const f = path.join(DASH, u.pathname.replace(/^\/dashboards\//, '/')); if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (err, d) => { if (err) { res.writeHead(404); res.end(); return; } res.writeHead(200, { 'Content-Type': u.pathname.endsWith('.js') ? 'application/javascript' : u.pathname.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const url = 'http://127.0.0.1:' + srv.address().port + '/dashboards/soc-performance.html';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  const wait = (p, fn, arg) => p.waitForFunction(fn, arg, { timeout: 20000 }).then(() => true, () => false);
  let reason = 'cleaned and verified (synthetic)';
  try {
    const p = await browser.newPage({ viewport: { width: 1500, height: 1000 } }); p.on('pageerror', (x) => errs.push(x.message)); p.on('dialog', (d) => d.accept(reason));
    await p.goto(url); ok(await wait(p, () => !document.getElementById('main').hidden && document.querySelectorAll('#kpis .kpi').length === 6), 'opens with six KPI tiles');
    const kp = await p.textContent('#kpis'); ok(/7alerts in 30 days/.test(kp), 'alerts raised in 30 days: ' + kp);
    ok(/3 mintime to acknowledge/.test(kp) && /1\.5 htime to resolve/.test(kp), 'median acknowledge 3 min, resolve 1.5 h');
    ok(/2not acknowledged/.test(kp), 'two open alerts not acknowledged');
    const sev = await p.textContent('#sev'); ok(/critical5/.test(sev.replace(/\s+/g, '')) && /3 min \/ 5 min \(5\)/.test(sev), 'critical row: acknowledge median / p90 with n');
    ok(await p.$eval('#sev tbody tr:nth-child(3) td:nth-child(4)', (td) => /—/.test(td.textContent) && /fewer than 3/.test(td.querySelector('[title]').title)), 'medium: withheld, with the reason');
    ok(await p.$('#wk svg rect'), 'week chart drawn');
    ok(await wait(p, () => /Synthetic odd login/.test(document.getElementById('top').textContent)), 'work-first list from the queue');
    ok(!(await p.evaluate(() => window.__xss)) && /<img src=x/.test(await p.textContent('#top')), 'a hostile rule name stays text');
    ok(/Nothing watched/.test(await p.textContent('#wl')) && /No system rated/.test(await p.textContent('#ac')), 'empty states say what to do');
    ok(!(await p.$('#aadd')) && /Administrators rate/.test(await p.textContent('#acform')), 'an operator does not rate systems');
    // operator: watch a host
    await p.selectOption('#wk1', 'host'); await p.fill('#wv', 'pc-x'); await p.fill('#wr', 'synthetic: suspected infection'); await p.click('#wadd');
    ok(await wait(p, () => /pc-x/.test(document.getElementById('wl').textContent) && /suspected infection/.test(document.getElementById('wl').textContent)), 'the host is on the watchlist');
    ok(/omar\.syn/.test(await p.textContent('#wl')) && /not checked yet/.test(await p.textContent('#wl')), 'who added it; not checked yet');
    ok(await p.$eval('#wl tbody tr td:nth-child(3)', (td) => td.textContent.trim() === '1'), 'its open alert counted as a hit');
    ok(api.audits.some((a) => a.action === 'soc.watchlist.add' && a.detail.value === 'pc-x'), 'audited');
    ok(await wait(p, () => /\+15 watchlist/.test(document.getElementById('top').textContent)), 'the alert priority shows the watchlist factor');
    await p.fill('#wv', 'not a cve'); await p.fill('#wr', 'synthetic'); await p.selectOption('#wk1', 'cve'); await p.click('#wadd');
    ok(await wait(p, () => /not a valid cve/.test(document.body.textContent)), 'validation error shown');
    await p.click('[data-wrm]'); ok(await wait(p, () => /Nothing watched/.test(document.getElementById('wl').textContent)), 'removed with a reason');
    ok(api.audits.some((a) => a.action === 'soc.watchlist.remove' && a.detail.reason === reason), 'removal audited with the reason');
    // admin rates a crown jewel
    WHO = { user: 'adam.syn', role: 'admin' }; await p.goto(url); await wait(p, () => document.getElementById('aadd'));
    await p.fill('#av', 'srv-db-01'); await p.selectOption('#al', 'crown_jewel'); await p.fill('#ar', 'claims database (synthetic)'); await p.click('#aadd');
    ok(await wait(p, () => /srv-db-01/.test(document.getElementById('ac').textContent) && /crown jewel/.test(document.getElementById('ac').textContent)), 'an admin rates a crown jewel');
    ok(await wait(p, (id) => { const r = [...document.querySelectorAll('#top tr')].find((tr) => /odd login/.test(tr.textContent)); return r && /\+20 asset criticality \(.*crown jewel/.test(r.textContent); }, db.id), 'the database alert shows +20 asset criticality');
    ok(api.audits.some((a) => a.action === 'soc.criticality.rate' && a.detail.level === 'crown_jewel'), 'rating audited');
    await p.click('[data-arm]'); ok(await wait(p, () => /No system rated/.test(document.getElementById('ac').textContent)), 'rating removed');
    // analyst: lists, no forms
    WHO = { user: 'ana.syn', role: 'analyst' }; await p.goto(url); await wait(p, () => !document.getElementById('wlcard').hidden && /Synthetic/.test(document.getElementById('top').textContent));
    ok(!(await p.$('#wadd')) && !(await p.$('#aadd')), 'an analyst reads the lists without add forms');
    // viewer: times only
    WHO = { user: 'vera.syn', role: 'viewer' }; await p.goto(url); await wait(p, () => !document.getElementById('main').hidden);
    ok(await p.$eval('#wlcard', (e) => e.hidden) && await p.$eval('#topcard', (e) => e.hidden) && await p.$eval('#accard', (e) => e.hidden), 'a viewer sees only the response times (no named systems or people)');
    // phone
    const ph = await browser.newPage({ viewport: { width: 390, height: 900 } }); await ph.goto(url); await wait(ph, () => !document.getElementById('main').hidden);
    ok(await ph.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1), 'phone width: no sideways scroll'); await ph.close();
    const nav = fs.readFileSync(path.join(DASH, 'vendor', 'zyb-nav.js'), 'utf8');
    ok(/"h": "soc-performance.html"/.test(nav) && / soc-performance\.html /.test(fs.readFileSync(path.join(DASH, 'install-dashboards.sh'), 'utf8')), 'menu entry and installer');
    ok(/socops: 'soc-performance\.html'/.test(fs.readFileSync(path.join(DASH, 'vendor', 'zyb-menu.js'), 'utf8')) && /socops: 'soc-performance\.html'/.test(fs.readFileSync(path.join(DASH, 'vendor', 'zyb-early.js'), 'utf8')), 'the old portal\'s "SOC Performance & Operations" opens this page');
    ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  } finally { await browser.close(); srv.close(); fs.rmSync(dir, { recursive: true, force: true }); }
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n);
  process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
