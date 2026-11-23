// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// soc-console.html against the REAL SIEM modules (sentra-siem engine/soc/console.js + analyst-routes.js for the offense queue) with
// SYNTHETIC alerts and a stubbed event store: KPIs, offenses with a magnitude and the priority explained, ATT&CK tactics, the
// ingest chart, agents (active / disconnected / outdated / degraded) and an operator retiring a disconnected one with a reason,
// watched-file changes with coverage and an administrator editing the watch list, the live events; a viewer sees counts and
// offenses but no host lists or raw events; a hostile rule name and file path stay text; phone width; the menu entry, the
// installer and the old portal's "LogRhythm SIEM — SOC Console" redirect.
// Run: SENTRA_SIEM_DIR=/home/user/sentra-siem PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node soc-console.test.js
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
const MIN = 60e3, NOW = Date.now();
const iso = (t) => new Date(t).toISOString().replace('T', ' ').replace('Z', '');
(async () => {
  const dir = tmpDir(), state = createState({ dir, log: quietLog }), alerts = createAlerts({ state, log: quietLog }), cases = createCases({ state, alerts, log: quietLog });
  const hb = [['pc-syn-1', 2, '1.3.0'], ['pc-syn-2', 3, '1.2.9'], ['srv-syn-4', 900, '1.1.0'], ['pc-syn-5', 1, '1.3.0', true]];
  const search = { parse,
    rare: async () => ({ values: hb.map(([h, m]) => ({ v: h, n: 100, first: iso(NOW - 6 * 864e5), last: iso(NOW - m * MIN) })) }),
    fetchEvents: async (q) => (/^action:agent-heartbeat/.test(q.q) ? hb.filter(([, m]) => m <= 30).map(([h, m, v, d]) => ({ ts: NOW - m * MIN, host: h, action: 'agent-heartbeat', message: 'Agent heartbeat v' + v, fields: { agent_version: v, queue_files: d ? '350' : '0' }, tags: d ? ['heartbeat', 'agent-degraded'] : ['heartbeat'] }))
      : [{ ts: NOW - 20 * MIN, host: 'pc-syn-1', category: 'file', action: 'file-created', process: 'C:\\Temp\\drop.exe', user: 'dana.syn', fields: { target_filename: 'C:\\Users\\dana.syn\\Start Menu\\Programs\\Startup\\' + XSS + '.lnk' }, tags: ['T1547.001'] }]),
    top: async (q) => (q.field === 'host' ? { values: [{ v: 'pc-syn-1', n: 40 }, { v: 'pc-syn-2', n: 5 }] } : { values: [{ v: 'windows', n: 4000 }] }),
    histogram: async (q) => ({ buckets: Array.from({ length: 60 }, (_, i) => ({ t: q.from + i * MIN, n: 120 + (i % 5) })), step_ms: MIN }),
    search: async (q) => (q.limit === 25 ? { rows: [{ ts: iso(NOW - MIN), host: 'pc-syn-1', src_type: 'windows', action: 'logon', severity: 0, message: 'synthetic logon' }] } : { rows: [] }),
    newValues: async () => ({ values: [] }),
  };
  const api = fakeApi({ realRanks: true }), deps = { state, alerts, cases, search, config: { soc_analyst: {} }, log: quietLog, noTimers: true };
  require(path.join(SIEM, 'engine/soc/analyst-routes')).register(api, deps);
  require(path.join(SIEM, 'engine/soc/console')).register(api, deps);
  alerts.raise({ rule_id: 'SYN-1', rule_name: 'Brute force then success ' + XSS, severity: 4, group: { user: 'dana.syn' }, fields: {}, summary: 'synthetic', ts_first: NOW - 30 * MIN, ts_last: NOW - MIN, source: 'engine', count: 14, mitre: ['T1110'], tactic: 'Credential Access' });
  alerts.raise({ rule_id: 'SYN-2', rule_name: 'Run key persistence', severity: 2, group: { host: 'pc-syn-1' }, fields: {}, summary: 'synthetic', ts_first: NOW - 20 * MIN, ts_last: NOW - 19 * MIN, source: 'engine', count: 1, mitre: ['T1547.001'], tactic: 'Persistence' });
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
  const url = 'http://127.0.0.1:' + srv.address().port + '/dashboards/soc-console.html';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  const wait = (p, fn, arg) => p.waitForFunction(fn, arg, { timeout: 20000 }).then(() => true, () => false);
  let answer = 'server decommissioned (synthetic CHG-7)';
  try {
    const p = await browser.newPage({ viewport: { width: 1500, height: 1000 } }); p.on('pageerror', (x) => errs.push(x.message)); p.on('dialog', (d) => d.accept(answer));
    await p.goto(url); ok(await wait(p, () => !document.getElementById('main').hidden && document.querySelectorAll('#off tbody tr').length === 2 && document.querySelectorAll('#ag tbody tr').length === 4), 'offenses and agents load');
    const kp = await p.textContent('#kpis');
    ok(/2open offenses/.test(kp) && /1critical/.test(kp), 'offense KPIs: ' + kp); ok(/3 \/ 4agents active/.test(kp) && /1agents disconnected/.test(kp) && /1 outdated/.test(kp), 'agent KPIs');
    ok(/1watched-file changes/.test(kp), 'FIM KPI');
    ok(await p.$eval('#off tbody tr td:first-child', (td) => /priority \d+/.test(td.title) && Number(td.textContent) >= 1), 'magnitude with the priority explained on hover');
    ok(/Credential Access/.test(await p.textContent('#tac')) && /Persistence/.test(await p.textContent('#tac')), 'ATT&CK tactics');
    ok(await p.$('#ing svg polyline') && /within the hour's normal/.test(await p.textContent('#ing')), 'ingest chart and its verdict');
    const ag = await p.textContent('#ag'); ok(/srv-syn-4\s*disconnected/.test(ag) && /behind v1\.3\.0/.test(ag) && /degraded/.test(ag) && /350 file/.test(ag), 'agent states, version drift, degraded queue');
    ok(/Startup/.test(await p.textContent('#fim')) && /T1547\.001/.test(await p.textContent('#fim')) && /2 host\(s\) send file/.test(await p.textContent('#fim')), 'a watched-path change with its technique and the coverage');
    ok(!(await p.evaluate(() => window.__xss)) && /<img src=x/.test(await p.textContent('#off')) && /<img src=x/.test(await p.textContent('#fim')), 'a hostile rule name and file path stay text');
    ok(/synthetic logon/.test(await p.textContent('#live')), 'live events');
    // intel: hosts needing attention, source health, riskiest file changes, flapping agents
    ok(await wait(p, () => !document.getElementById('intel').hidden && /pc-syn-1/.test(document.getElementById('hosts').textContent)), 'intel section for an operator');
    const hs = await p.textContent('#hosts');
    ok(/pc-syn-1/.test(hs) && /2 kinds of signal/.test(hs) && /offense: Run key persistence/.test(hs) && /file change:/.test(hs), 'host fusing an offense and a file change, every part named: ' + hs.slice(0, 220));
    ok(/srv-syn-4/.test(hs) && /agent disconnected/.test(hs), 'a disconnected agent is a host signal');
    const fr = await p.textContent('#fimr');
    ok(/technique: T1547\.001/.test(fr) && /first seen/.test(fr) && /drop\.exe is not an installer/.test(fr) && /<img src=x/.test(fr) && !(await p.$('#fimr img')), 'riskiest file change scored with reasons, hostile path as text');
    ok(/windows/.test(await p.textContent('#srch')) && /normal/.test(await p.textContent('#srch')), 'log source health');
    ok(/No agent dropped its heartbeat/.test(await p.textContent('#flap')), 'no flapping agent');
    if (process.env.SHOT) await p.screenshot({ path: process.env.SHOT + '-console.png', fullPage: true });
    ok(!(await p.$('#wsave')), 'an operator does not edit the watch list');
    // retire the disconnected agent
    await p.click('[data-retire="srv-syn-4"]'); ok(await wait(p, () => /retired/.test(document.getElementById('ag').textContent) && /CHG-7/.test(document.getElementById('ag').textContent)), 'an operator retires a disconnected agent with a reason');
    ok(api.audits.some((a) => a.action === 'soc.console.agent.retire' && a.user === 'omar.syn'), 'audited');
    // admin edits the watch list
    WHO = { user: 'syed', role: 'admin' }; await p.goto(url); await wait(p, () => document.getElementById('wsave'));
    await p.click('#watch summary'); await p.fill('#wl', '\\Documents\\\n/etc/passwd'); await p.click('#wsave');
    ok(await wait(p, () => /Watched paths \(2\)/.test(document.getElementById('watch').textContent)), 'an administrator saves the watch list');
    ok(api.audits.some((a) => a.action === 'soc.console.fim.watch' && a.user === 'syed'), 'watch list audited');
    // viewer
    WHO = { user: 'vera.syn', role: 'viewer' }; await p.goto(url); await wait(p, () => !document.getElementById('main').hidden && document.querySelectorAll('#off tbody tr').length === 2);
    ok(await p.$eval('#agcard', (e) => e.hidden) && await p.$eval('#fimcard', (e) => e.hidden) && await p.$eval('#livecard', (e) => e.hidden), 'a viewer sees no host lists or raw events');
    ok(/agents active/.test(await p.textContent('#kpis')), 'but still the counts');
    ok(await p.$eval('#intel', (e) => e.hidden), 'a viewer gets no intel (it names hosts)');
    const ph = await browser.newPage({ viewport: { width: 390, height: 900 } }); await ph.goto(url); await wait(ph, () => !document.getElementById('main').hidden);
    ok(await ph.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1), 'phone width: no sideways scroll'); await ph.close();
    const nav = fs.readFileSync(path.join(DASH, 'vendor', 'zyb-nav.js'), 'utf8');
    ok(/"h": "soc-console.html"/.test(nav) && / soc-console\.html /.test(fs.readFileSync(path.join(DASH, 'install-dashboards.sh'), 'utf8')), 'menu entry and installer');
    ok(/wazuh: 'soc-console\.html'/.test(fs.readFileSync(path.join(DASH, 'vendor', 'zyb-menu.js'), 'utf8')) && /wazuh: 'soc-console\.html'/.test(fs.readFileSync(path.join(DASH, 'vendor', 'zyb-early.js'), 'utf8')), 'the old portal\'s "LogRhythm SIEM — SOC Console" opens this page');
    ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  } finally { await browser.close(); srv.close(); fs.rmSync(dir, { recursive: true, force: true }); }
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n);
  process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
