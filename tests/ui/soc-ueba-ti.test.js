// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for User Behaviour (soc-ueba.html) and Threat Intelligence (soc-ti.html) against the REAL SIEM modules (sentra-siem
// engine/ueba on SYNTHETIC history, ueba/api.js, soc/views-routes.js, soc/departments.js) with a scripted model: KPIs and charts,
// a tier tile filters the entities, the entity workspace (score over time, contributions, behaviour vs baseline, peers, the AI
// assessment with verified / unverified points), findings reviewed (precision learned), peer groups, threats by department;
// sightings, retro-hunt, indicator lookup, lists and feeds; hostile values stay text; a viewer cannot review or run the AI.
// Run: SENTRA_SIEM_DIR=/home/user/sentra-siem PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node soc-ueba-ti.test.js
const http = require('http'), fs = require('fs'), path = require('path'), os = require('os');
const SIEM = process.env.SENTRA_SIEM_DIR || path.resolve(__dirname, '../../backend/siem');
const DASH = path.resolve(__dirname, '../../ui');
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const XSS = '<img src=x onerror=alert(1)>';
const { createState } = require(path.join(SIEM, 'engine/soc/state'));
const { createAlerts } = require(path.join(SIEM, 'engine/soc/alerts'));
const { createUeba } = require(path.join(SIEM, 'engine/ueba/index'));
const { parse } = require(path.join(SIEM, 'engine/api/query'));
const { fakeApi } = require(path.join(SIEM, 'tests/soc-fakes'));
const quiet = { info() {}, warn() {}, error() {}, debug() {}, child() { return quiet; } };

(async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'socut-'));
  const state = createState({ dir, log: quiet }), alerts = createAlerts({ state, log: quiet });
  const ueba = createUeba({ state, ch: null, alerts: null, config: {}, settings: {}, log: quiet });
  const T = Date.now(), DAY = 864e5, H = 36e5, hist = [];
  for (let d = 20; d >= 1; d--) for (let i = 0; i < 20; i++) hist.push({ ts: T - d * DAY + (10 + (i % 6)) * H, user: 'alice', host: 'pc-1', src_ip: '10.0.0.5', category: 'authentication', action: 'logon', outcome: 'success', src_type: 'windows', fields: { logon_type: '2' } });
  ueba.rebuildFromEvents(hist, T - H);
  const win = [];
  for (let i = 0; i < 30; i++) win.push({ ts: T - 600e3 + i * 1000, user: 'alice', host: 'srv-' + i, src_ip: '10.9.9.9', category: 'authentication', action: 'logon', outcome: i < 25 ? 'failure' : 'success', src_type: 'windows', fields: { logon_type: '3' } });
  ueba.detectFromEvents(win, T);
  alerts.raise({ rule_id: 'R-C2', rule_name: 'C2 traffic ' + XSS, severity: 4, group: { host: 'pc-7' }, fields: { dst_ip: '203.0.113.66' }, summary: 'C2 beacon ' + XSS, ts_first: T - H, ts_last: T - H });
  const LISTS = { '203.0.113.66': ['abuse-ch-feodo'], 'evil.example': ['threatfox'], 'partner.example': ['allow-partners'] };
  const intel = { lookup: (v) => LISTS[String(v).toLowerCase()] || [],
    stats: () => ({ loaded_at: T - H, ip: 1200, domain: 300, hash: 50, lists: 3, invalid_lines: 0, hits: {} }),
    lists: () => [{ name: 'abuse-ch-feodo', ip: 1200, domain: 0, hash: 0 }, { name: 'threatfox', ip: 0, domain: 300, hash: 50 }, { name: 'allow-partners', ip: 0, domain: 1, hash: 0 }] };
  const search = { parse, search: async () => ({ rows: [] }), top: async (o) => ({ values: o.field === 'dst_ip' ? [{ v: '203.0.113.66', n: 42 }] : o.field === 'dns_query' ? [{ v: 'evil.example', n: 7 }] : [] }) };
  const feeds = [{ id: 'abuse-feodo', name: 'abuse.ch Feodo Tracker', url: 'https://feodotracker.abuse.ch/x', enabled: true, interval_h: 12, count: 1200, last_ok: T - H, last_error: '' },
    { id: 'urlhaus', name: 'abuse.ch URLhaus', url: 'https://urlhaus.abuse.ch/x', enabled: false, interval_h: 12, count: 0 }];
  let script = [];
  class FakeAnthropic { constructor() { this.messages = { create: async () => { const r = script.shift(); if (!r) throw new Error('script ended'); return r; } }; } }
  const turn = (content, stop = 'tool_use') => ({ content, stop_reason: stop, usage: { input_tokens: 50, output_tokens: 10 } });
  const deps = { state, alerts, ueba, intel, search, log: quiet, sdk: FakeAnthropic,
    config: { soc_analyst: {}, secrets: { netops: { anthropic_api_key: 'sk-ant-synthetic-for-tests' } }, ai_limits: { per_user_hour: 100, per_user_day: 1000, daily_tokens: 1e9, max_prompt_chars: 1e6 } } };
  const api = fakeApi({ realRanks: true });
  require(path.join(SIEM, 'engine/ueba/api')).register(api, deps);
  require(path.join(SIEM, 'engine/soc/views-routes')).register(api, deps);
  require(path.join(SIEM, 'engine/soc/departments')).register(api, deps);
  // the feed and lookup routes of detect/routes.js, stubbed (their own tests cover them): admin writes
  api.route('GET', '/api/soc/intel/feeds', async () => ({ items: feeds }));
  api.route('POST', '/api/soc/intel/feeds', async (ctx) => { ctx.need('admin'); const f = feeds.find((x) => x.id === ctx.body.id); f.enabled = ctx.body.enabled; return f; });
  api.route('POST', '/api/soc/intel/check', async (ctx) => { const results = {}, reference = {}; for (const v of ctx.body.values) { const L = intel.lookup(v); const t = L.filter((x) => !/^allow-/.test(x)), r = L.filter((x) => /^allow-/.test(x)); if (t.length) results[v.toLowerCase()] = t; if (r.length) reference[v.toLowerCase()] = r; } return { enabled: true, results, reference }; });
  let WHO = { user: 'nora.syn', role: 'operator' };
  const srv = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://x'), json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u.pathname === '/dashboards/whoami.json') return json(200, WHO);
    if (u.pathname.startsWith('/api/soc/')) {
      let b = ''; req.on('data', (c) => { b += c; }); req.on('end', async () => {
        const r = await api.call(req.method, '/api/soc' + u.pathname.slice(8) + u.search, { role: WHO.role, user: WHO.user, body: b ? JSON.parse(b) : undefined });
        json(r.status, r.body);
      }); return;
    }
    if (u.pathname.startsWith('/api/')) return json(404, { error: 'not in this test' });
    const f = path.join(DASH, u.pathname.replace(/^\/dashboards\//, '/')); if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (err, d) => { if (err) { res.writeHead(404); res.end(); return; } res.writeHead(200, { 'Content-Type': u.pathname.endsWith('.js') ? 'application/javascript' : u.pathname.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port + '/';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  const wait = (p, fn, arg) => p.waitForFunction(fn, arg, { timeout: 10000 }).then(() => true, () => false);
  try {
    const p = await browser.newPage({ viewport: { width: 1500, height: 1000 } }); p.on('pageerror', (x) => errs.push(x.message));
    p.on('dialog', (d) => { errs.push('dialog: ' + d.message()); d.dismiss(); });
    // ================= User Behaviour
    await p.goto(base + 'soc-ueba.html?standalone=1'); await p.waitForSelector('#ents table', { timeout: 15000 });
    const kp = await p.textContent('#kpis'); ok(/Critical risk\s*1/.test(kp) && /Entities monitored/.test(kp), 'KPIs: ' + kp.replace(/\s+/g, ' ').slice(0, 200));
    ok(/never proof of wrongdoing/.test(await p.textContent('main')), 'indicators-not-proof framing on the page');
    ok(await p.$$eval('#c-trend,#c-tier,#c-hist', (c) => c.length === 3 && c.every((x) => x.hidden || (x.getAttribute('role') === 'img' && x.getAttribute('aria-label')))), 'top charts drawn and labelled');
    await p.click('.so-kpi:has-text("Critical risk")'); ok(await wait(p, () => document.getElementById('e-tier').value === 'critical' && document.querySelectorAll('#ents tbody tr').length === 1), 'Critical tile filters the entities');
    await p.click('#ents tr[data-ent="user:alice"]'); await p.waitForSelector('#wsp', { timeout: 10000 });
    const ws = await p.textContent('#wsp');
    ok(/Why this score/.test(ws) && /brute_force_then_success/.test(ws), 'contributions itemised');
    ok(/new: srv-/.test(ws), 'new hosts against the baseline');
    ok(/Hunt this user/.test(ws), 'link into hunting');
    script = [turn([{ type: 'tool_use', id: 'a1', name: 'entity_findings', input: { id: 'user:alice' } }]),
      turn([{ type: 'tool_use', id: 'a2', name: 'submit_assessment', input: { summary: 'Many failures on new servers then a success (synthetic) ' + XSS, recommendation: 'investigate',
        concerns: [{ point: 'brute force then success', ref: ueba.findings({ entity_id: 'user:alice', detector: 'brute_force_then_success' }).items[0].id }, { point: 'invented', ref: 'FAKE-1' }], benign_explanations: ['password change'], questions: ['Did alice change her password?'] } }])];
    await p.click('[data-assess="user:alice"]');
    ok(await wait(p, () => /Investigate/.test((document.getElementById('wsp') || {}).textContent || '') && /Rule out first/.test(document.getElementById('wsp').textContent)), 'AI assessment shown');
    ok(/1 point\(s\) cite something no tool returned/.test(await p.textContent('#wsp')) && !(await p.$('#wsp img')), 'unverified point flagged; hostile text stays text');
    await p.click('#wsclose');
    await p.click('[data-tab="find"]'); await p.waitForSelector('#finds table', { timeout: 10000 });
    for (let i = 0; i < 3; i++) { await p.click('#finds [data-rev="benign"] >> nth=0'); await p.waitForTimeout(400); }
    await p.click('[data-tab="det"]');
    ok(await wait(p, () => /\d+%/.test(document.getElementById('dets').textContent)), 'precision learned once a detector has 3 reviews');
    ok(ueba.findings({ status: 'benign', include_benign: true, limit: 50 }).items.some((f) => f.reviewed_by === 'nora.syn'), 'reviews recorded with the analyst\'s name');
    await p.click('[data-tab="peer"]'); ok(/user\/default|default/.test(await p.textContent('#peers')), 'peer groups');
    await p.click('[data-tab="dept"]'); ok(await wait(p, () => /attributed/.test(document.getElementById('depts').textContent) || /No alert/.test(document.body.textContent)), 'threats by department tab');
    // ================= Threat Intelligence
    await p.goto(base + 'soc-ti.html?standalone=1'); await p.waitForSelector('#sight table', { timeout: 15000 });
    ok(/Open sightings\s*1/.test(await p.textContent('#kpis')), 'open sightings KPI');
    ok(/203\.0\.113\.66/.test(await p.textContent('#sight')) && /abuse-ch-feodo/.test(await p.textContent('#sight')) && /host:pc-7/.test(await p.textContent('#sight')), 'sighting with list and host');
    ok(!(await p.$('main img')), 'hostile text stays text');
    await p.click('[data-tab="retro"]'); await p.click('#rf [type=submit]');
    ok(await wait(p, () => /evil\.example/.test(document.getElementById('rout').textContent)), 'retro-hunt finds listed traffic');
    ok(/soc-hunt\.html\?q=/.test(await p.innerHTML('#rout')), 'retro-hunt hit links into hunting');
    await p.click('[data-tab="look"]'); await p.fill('#lv', '203.0.113.66\npartner.example\n198.51.100.200'); await p.click('#lf [type=submit]');
    ok(await wait(p, () => /abuse-ch-feodo/.test(document.getElementById('lout').textContent) && /reference/.test(document.getElementById('lout').textContent) && /not on any list/.test(document.getElementById('lout').textContent)), 'lookup: threat, reference and clean');
    await p.click('[data-tab="lists"]'); ok(/reference - not a threat/.test(await p.textContent('#lists')), 'reference lists marked');
    await p.click('[data-tab="feeds"]'); ok(!(await p.$('[data-tog]')), 'an operator cannot switch feeds');
    // ================= admin and viewer
    WHO = { user: 'syed', role: 'admin' }; await p.reload(); await p.waitForSelector('#sight', { timeout: 15000 }); await p.click('[data-tab="feeds"]');
    await p.click('[data-tog="urlhaus"]'); ok(await wait(p, () => /Switch off/.test((document.querySelector('[data-tog="urlhaus"]') || {}).textContent || '')), 'admin switched a feed on');
    WHO = { user: 'v.syn', role: 'viewer' };
    await p.goto(base + 'soc-ueba.html?standalone=1&entity=' + encodeURIComponent('user:alice')); await p.waitForSelector('#wsp', { timeout: 15000 });
    ok(/operator role and above/.test(await p.textContent('#wsp')) && !(await p.$('[data-assess]')), 'a viewer cannot run the AI assessment');
    await p.click('[data-tab="find"]'); await p.waitForSelector('#finds table', { timeout: 10000 }); ok(!(await p.$('[data-rev]')), 'a viewer cannot review findings');
    await p.goto(base + 'soc-ti.html?standalone=1'); await p.waitForSelector('#sight', { timeout: 15000 }); await p.click('[data-tab="retro"]'); await p.click('#rf [type=submit]');
    ok(await wait(p, () => /requires role analyst/.test(document.getElementById('rout').textContent)), 'a viewer is refused the traffic retro-hunt');
    ok(await p.evaluate(() => { const a = (window.ZYB_NAV || []).find((x) => x.id === 'soc'); const inv = a ? a.pages.filter((x) => x.g === 'Investigate').map((x) => x.h) : []; return a && a.pages[0].h === 'soc-overview.html' && a.pages[1].h === 'soc-alerts.html' && ['soc-cases.html', 'soc-hunt.html', 'soc-ueba.html', 'soc-ti.html'].every((h) => inv.includes(h)) && !a.pages.some((x) => x.h === 'threats-by-department.html'); }), 'menu: Overview and Alert Queue first, the rebuilt pages under Investigate, Threats by Department folded in');
  } finally { await browser.close(); srv.close(); fs.rmSync(dir, { recursive: true, force: true }); }
  ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks');
  process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
