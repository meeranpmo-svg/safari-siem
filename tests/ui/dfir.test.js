// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// DFIR (dashboards/server/dfir.html) against the REAL SIEM module (sentra-siem engine/dfir/routes.js, dfir.js, forensics.js) with real
// SOC cases and a stubbed event store holding SYNTHETIC events: no case says where cases come from; the board (clocks ring, KPIs,
// attention); a case opened from the list; incident facts saved → PDPL 72 h clock; phase moved one step; evidence registered and a
// custody entry whose re-hash differs shows MISMATCH; an indicator added and its sightings; the legal hold; reconstruct a host →
// attention score with itemised reasons, burst chart, attack stages in order, pivots (click → reconstruct the pivot), timeline lane
// chips; triage collection requested; administrator settings; viewer sees the board but no forensic record or raw events (PDPL);
// AI off says why; Excel; a hostile command line stays text; menu entry, installer and the portal redirect.
// Run: SENTRA_SIEM_DIR=/home/user/sentra-siem PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node dfir.test.js
const http = require('http'), fs = require('fs'), os = require('os'), path = require('path');
const DASH = path.resolve(__dirname, '../../ui');
const SIEM = process.env.SENTRA_SIEM_DIR || path.resolve(__dirname, '../../backend/siem');
const routes = require(path.join(SIEM, 'engine/dfir/routes')), { createState } = require(path.join(SIEM, 'engine/soc/state'));
const { createAlerts } = require(path.join(SIEM, 'engine/soc/alerts')), { createCases } = require(path.join(SIEM, 'engine/soc/cases'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const XSS = '<img src=x onerror="window.__xss=1">', H = 3600e3, NOW = Date.now();
const iso = (t) => new Date(t).toISOString().replace('T', ' ').replace('Z', '');
function rows() {
  const out = [];
  for (let i = 0; i < 40; i++) out.push({ ts: iso(NOW - 24 * H + i * 35 * 60e3), category: 'authentication', action: 'logon', outcome: 'success', host: 'pc-syn-7', target_user: 'dana.syn', src_ip: '10.20.0.7' });
  const b = NOW - 3 * H;
  for (let i = 0; i < 9; i++) out.push({ ts: iso(b + i * 10e3), category: 'authentication', action: i < 8 ? 'logon-failed' : 'logon', outcome: i < 8 ? 'failure' : 'success', host: 'pc-syn-7', target_user: 'dana.syn', src_ip: '198.51.100.23' });
  for (let i = 0; i < 8; i++) out.push({ ts: iso(b + 120e3 + i * 5e3), category: 'process', action: 'process-start', host: 'pc-syn-7', process: 'cmd.exe', parent_process: 'powershell.exe', cmdline: 'whoami ' + XSS });
  out.push({ ts: iso(b + 200e3), category: 'system', action: 'service-installed', host: 'pc-syn-7', message: 'New service: updater-syn' });
  out.push({ ts: iso(b + 260e3), category: 'system', action: 'audit-log-cleared', host: 'pc-syn-7', message: 'Security log cleared' });
  for (let i = 0; i < 10; i++) out.push({ ts: iso(b + 300e3 + i * 6e3), category: 'network', action: 'connection', host: 'pc-syn-7', src_ip: '10.20.0.7', dst_ip: '203.0.113.66', dst_port: '443', proto: 'tcp' });
  // machine-learning material: a DNS beacon every 3 h, a document starting encoded PowerShell, a fan-out to three servers
  for (let i = 0; i < 8; i++) out.push({ ts: iso(NOW - 23 * H + i * 3 * H), category: 'dns', action: 'dns-query', host: 'pc-syn-7', dns_query: 'cdn-syn.example' });
  out.push({ ts: iso(b + 150e3), category: 'process', action: 'process-start', host: 'pc-syn-7', process: 'powershell.exe', parent_process: 'winword.exe', cmdline: 'powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAA=' });
  for (const [i, h] of ['srv-syn-a', 'srv-syn-b', 'srv-syn-c'].entries()) out.push({ ts: iso(b + 500e3 + i * 60e3), category: 'authentication', action: 'logon', outcome: 'success', host: h, target_user: 'adm.syn', src_ip: '10.20.0.7', fields: { logon_type: '3' } });
  return out;
}
let ROLE = 'operator', USER = 'omar.syn';
const RANK = { viewer: 0, analyst: 1, operator: 2, admin: 3 };

(async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sentra-dfirpage-')), Lq = { info() {}, warn() {}, error() {} };
  const state = createState({ dir: path.join(dir, 'state'), log: Lq }), alerts = createAlerts({ state, log: Lq }), cases = createCases({ state, alerts, log: Lq });
  const search = async (o) => ({ rows: rows().sort((a, c) => (o.order === 'desc' ? c.ts.localeCompare(a.ts) : a.ts.localeCompare(c.ts))).slice(0, o.limit), total_estimate: 69 });
  search.newValues = async (o) => ({ values: o.field === 'dst_ip' ? [{ v: '203.0.113.66', n: 10 }] : [] });
  const config = { soc_analyst: { enabled: false } };
  const R = {}, AUD = [];
  routes.register({ route: (m, p, h) => { R[m + ' ' + p] = { re: new RegExp('^' + p.replace(/:([a-z]+)/g, '(?<$1>[^/]+)') + '$'), h }; } }, { state, alerts, cases, search, config, log: Lq });
  const al = (host) => alerts.raise({ rule_id: 'SENTRA-EXFIL-SYN', rule_name: 'Exfiltration (synthetic)', severity: 3, group: { host }, fields: {}, summary: 'synthetic', ts_first: NOW - 4 * H, ts_last: NOW - 3 * H, source: 'engine', count: 1, mitre: ['T1567'] }).alert.id;
  const old = cases.create({ title: 'Earlier exfiltration from pc-syn-2 (synthetic)', alert_ids: [al('pc-syn-2')] }, 'nora.syn');
  cases.setStatus(old.id, 'closed', 'nora.syn', { resolution: 'true-positive', note: 'synthetic' });
  const c = cases.create({ title: 'Data theft from pc-syn-7 (synthetic)', severity: 3, alert_ids: [al('pc-syn-7')] }, 'nora.syn');
  const srv = http.createServer((req, res) => {
    const url = new URL(req.url, 'http://x'), u = url.pathname, json = (code, b) => { res.writeHead(code, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u === '/dashboards/whoami.json') return json(200, { user: USER, role: ROLE });
    const hit = Object.entries(R).find(([k, v]) => k.startsWith(req.method + ' ') && v.re.test(u));
    if (hit) { let b = ''; req.on('data', (x) => { b += x; }); req.on('end', async () => {
      const o = {}, m = hit[1].re.exec(u), ctx = { role: ROLE, user: USER, body: b ? JSON.parse(b) : {}, params: Object.assign({}, m.groups ? Object.fromEntries(Object.entries(m.groups).map(([k, v]) => [k, decodeURIComponent(v)])) : {}), query: Object.fromEntries(url.searchParams), path: u,
        need(r) { if (RANK[ROLE] < RANK[r]) { o.status = 403; o.error = 'requires ' + r; return false; } return true; }, audit: (a, t, d) => AUD.push({ a, t, d }), ok: (x) => { o.body = x; return x; }, fail(code, msg) { o.status = code; o.error = msg; } };
      try { await hit[1].h(ctx); if (o.status) return json(o.status, { error: o.error || 'refused' }); json(200, o.body); } catch (e) { json(e.code || e.status || 500, { error: e.message }); } }); return; }
    if (u.startsWith('/api/')) return json(404, { error: 'not in this test' });
    const f = path.join(DASH, u.replace(/^\/dashboards\//, '')); if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (e, d) => { if (e) { res.writeHead(404); return res.end(); } res.writeHead(200, { 'Content-Type': f.endsWith('.js') ? 'application/javascript' : f.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const url = 'http://127.0.0.1:' + srv.address().port + '/dashboards/dfir.html?standalone=1';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright'); const browser = await chromium.launch(), errs = [];
  const wait = (p, fn, arg) => p.waitForFunction(fn, arg, { timeout: 15000 }).then(() => true, () => false);
  const txt = (p, s) => p.textContent(s);
  try {
    const ctx = await browser.newContext({ viewport: { width: 1500, height: 1000 }, acceptDownloads: true });
    const p = await ctx.newPage(); p.on('pageerror', (e) => errs.push(e.message)); p.on('dialog', (d) => { errs.push('unexpected dialog ' + d.message()); d.dismiss(); });
    await p.goto(url); ok(await wait(p, () => document.querySelectorAll('tr[data-case]').length === 1), 'the SOC case is listed');
    ok(/Open cases/.test(await txt(p, '#kpis')) && /No clock overdue/.test(await txt(p, '#ring')), 'KPIs and clocks ring');
    await p.click('tr[data-case]'); ok(await wait(p, () => /Incident facts/.test(document.getElementById('cw').textContent)), 'case workspace opens');
    ok(await wait(p, (id) => { const e = document.getElementById('sim'); return e && e.textContent.includes(id) && /true-positive/.test(e.textContent) && /SENTRA-EXFIL-SYN/.test(e.textContent) && /T1567/.test(e.textContent); }, old.id), 'cases like this one: the earlier case, what they share and how it ended');
    await p.selectOption('#ovtype', 'data-breach'); await p.fill('#ovaware', new Date(NOW - 20 * H).toISOString().slice(0, 16)); await p.check('#ovpd'); await p.check('[data-reg="sama"]'); await p.click('#ovsave');
    ok(await wait(p, () => /SDAIA \(PDPL\) · 72 h/.test(document.getElementById('cw').textContent) && /hours not set/.test(document.getElementById('cw').textContent)), 'PDPL 72 h clock runs; SAMA waits for its hours');
    ok(/Data theft/.test(await txt(p, '#attn')) || /hours are not set/.test(await txt(p, '#attn')), 'attention lists the case');
    await p.click('#phgo'); ok(await wait(p, () => document.querySelector('.steps .cur') && document.querySelector('.steps .cur').textContent === 'preservation'), 'phase moved one step');
    await p.fill('#evdesc', 'pc-syn-7 disk image (synthetic)'); await p.fill('#evsha', 'a'.repeat(64)); await p.fill('#evloc', 'Evidence safe SYN'); await p.click('#evadd');
    ok(await wait(p, () => /EV-000001/.test(document.getElementById('cw').textContent)), 'evidence registered');
    await p.click('#cw details summary'); await p.selectOption('[data-cact="EV-000001"]', 'analysed'); await p.fill('[data-csha="EV-000001"]', 'b'.repeat(64)); await p.click('[data-cgo="EV-000001"]');
    ok(await wait(p, () => /hash MISMATCH/.test(document.getElementById('cw').textContent)), 'a re-hash that differs shows MISMATCH');
    ok(await wait(p, () => /Integrity \/ custody failures/.test(document.getElementById('kpis').textContent) && /failed an integrity/.test(document.getElementById('attn').textContent)), 'board flags the integrity failure');
    await p.fill('#ioval', '203.0.113.66'); await p.click('#ioadd'); ok(await wait(p, () => /203\.0\.113\.66/.test(document.getElementById('cw').textContent)), 'indicator added');
    await p.click('#sight'); ok(await wait(p, () => /69 events/.test(document.getElementById('cw').textContent)), 'sightings from the event store');
    await p.fill('#hreason', 'litigation expected (synthetic)'); await p.click('#hplace'); ok(await wait(p, () => /legal hold/.test(document.getElementById('cases').textContent)), 'legal hold placed');
    ok(/analyst is off/.test(await txt(p, '#ai')), 'AI off says why');
    if (process.env.SHOT) await p.screenshot({ path: process.env.SHOT, fullPage: true });   // optional: a picture for review
    // investigate
    await p.click('[data-tab="inv"]'); await p.fill('#ent', 'pc-syn-7'); await p.click('#go');
    ok(await wait(p, () => /Why this score/.test(document.getElementById('invout').textContent)), 'reconstruction with the score');
    const inv = await txt(p, '#invout');
    ok(/defence impairment/.test(inv) && /attack stages in order/.test(inv), 'itemised reasons');
    ok((await p.$$('#invout svg rect[fill="#e5484d"]')).length >= 1, 'burst drawn in red');
    ok(/credential use/.test(inv) && /persistence/.test(inv), 'attack stages in order');
    ok(/dst_ip: 203\.0\.113\.66/.test(inv), 'first-seen against the 30-day baseline');
    ok(/Machine-learning findings/.test(inv) && /cdn-syn\.example/.test(inv) && /3 h/.test(inv), 'a regular DNS beacon with its period');
    ok(/encoded PowerShell/.test(inv) && /started by winword\.exe/.test(inv) && /T1059\.001/.test(inv), 'the encoded command line with its named features and technique');
    ok(/10\.20\.0\.7 logged on to 3 hosts/.test(inv) && await p.$('#invout [data-pivot="host:srv-syn-b"]'), 'lateral movement fan-out, each host a pivot');
    await p.click('#lanes [data-lane="network"]'); ok(await wait(p, () => document.querySelectorAll('#tl .ev').length === 10), 'lane chip filters the timeline');
    ok(!(await p.evaluate(() => window.__xss)), 'a hostile command line stayed text');
    await p.check('#colform input[value="memory"]'); await p.fill('#colrat', 'exfil triage (synthetic)'); await p.click('#colgo');
    ok(await wait(p, () => /Collection DFC-000001 requested/.test(document.body.textContent)), 'triage collection requested');
    await p.click('#invout [data-pivot="ip:203.0.113.66"]'); ok(await wait(p, () => document.getElementById('ent').value === '203.0.113.66'), 'a pivot reconstructs that entity');
    const [dl] = await Promise.all([p.waitForEvent('download', { timeout: 10000 }), p.click('#xls')]);
    ok(/^dfir-\d{4}-\d{2}-\d{2}\.xlsx$/.test(dl.suggestedFilename()), 'Excel export');
    { const x = fs.readFileSync(await dl.path(), 'latin1'); ok(x.includes(c.id) && x.includes('Integrity failures'), 'the Excel file holds the header and the cases'); }
    ok(AUD.some((x) => x.a === 'dfir.evidence.custody' && x.d.integrity === 'mismatch') && AUD.some((x) => x.a === 'dfir.analyse'), 'actions and reads are audited');
    // administrator: settings
    ROLE = 'admin'; USER = 'sara.syn'; const a = await ctx.newPage(); a.on('pageerror', (e) => errs.push(e.message)); await a.goto(url); await wait(a, () => document.querySelectorAll('tr[data-case]').length === 1);
    await a.click('[data-tab="ready"]'); await a.fill('[data-rh="sama"]', '24'); await a.fill('#stor', 'Evidence safe SYN'); await a.click('#setsave');
    ok(await wait(a, () => /Settings saved/.test(document.body.textContent)), 'administrator saves the reporting hours');
    // viewer: board only
    ROLE = 'viewer'; USER = 'vera.syn'; const v = await ctx.newPage(); v.on('pageerror', (e) => errs.push(e.message)); await v.goto(url); await wait(v, () => document.querySelectorAll('tr[data-case]').length === 1);
    await v.click('tr[data-case]'); ok(await wait(v, () => /shown to analysts and above/.test(document.getElementById('cw').textContent)), 'viewer: no forensic record (PDPL)');
    await v.click('[data-tab="inv"]'); await v.fill('#ent', 'pc-syn-7'); await v.click('#go'); ok(/for analysts and above/.test(await txt(v, '#invout')), 'viewer: no raw events');
    const nav = fs.readFileSync(path.join(DASH, 'vendor', 'zyb-nav.js'), 'utf8');
    ok(/"h": "dfir.html"/.test(nav) && / dfir\.html /.test(fs.readFileSync(path.join(DASH, 'install-dashboards.sh'), 'utf8')), 'menu entry and installer');
    ok(/forensics: 'dfir\.html'/.test(fs.readFileSync(path.join(DASH, 'vendor', 'zyb-menu.js'), 'utf8')) && /forensics: 'dfir\.html'/.test(fs.readFileSync(path.join(DASH, 'vendor', 'zyb-early.js'), 'utf8')), 'the portal\'s DFIR view opens this page');
    ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  } finally { await browser.close(); srv.close(); fs.rmSync(dir, { recursive: true, force: true }); }
  console.log((bad ? 'FAILED ' : 'ok ') + (n - bad) + '/' + n);
  process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
