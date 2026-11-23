// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for XDR (soc-xdr.html) against the REAL SIEM modules (sentra-siem engine/xdr/xdr.js, xdr-ml.js, routes.js, soc alerts /
// cases) with SYNTHETIC history: the correlated incident list, the AI / ML tab (what may come next learned from past incidents, the
// path so far, similar closed incidents with their verdict, attack paths learned, incidents per day labelled), the incident detail
// with its attack graph and the next-tactic section, "Ask the Copilot" with the incident in the question (Copilot stubbed), a hostile
// rule name stays text, a viewer gets no ML tab and no request, phone width, no page errors.
// Run: SENTRA_SIEM_DIR=/home/user/sentra-siem PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node soc-xdr.test.js
const http = require('http'), fs = require('fs'), path = require('path'), os = require('os');
const SIEM = process.env.SENTRA_SIEM_DIR || path.resolve(__dirname, '../../backend/siem');
const DASH = path.resolve(__dirname, '../../ui');
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const { createState } = require(path.join(SIEM, 'engine/soc/state'));
const { createAlerts } = require(path.join(SIEM, 'engine/soc/alerts'));
const { createCases } = require(path.join(SIEM, 'engine/soc/cases'));
const { fakeApi } = require(path.join(SIEM, 'tests/soc-fakes'));
const quiet = { info() {}, warn() {}, error() {}, debug() {}, child() { return quiet; } };
const XSS = '<img src=x onerror=window.__xx=1>';

(async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'socxdr-'));
  const state = createState({ dir, log: quiet }), alerts = createAlerts({ state, log: quiet }), cases = createCases({ state, alerts, log: quiet });
  const NOW = Date.now(), H = 3600e3, DAY = 24 * H; let k = 0;
  const raise = (o) => alerts.raise(Object.assign({ severity: 3, group: {}, fields: {}, group_key: 'g' + (++k), count: 1, sample_event_ids: [], summary: 'synthetic' }, o)).alert;
  for (let i = 0; i < 4; i++) {
    const t = NOW - (10 + i * 5) * DAY, u = { user: 'syn.u' + i };
    const a = [raise({ rule_id: 'SENTRA-MAIL-001', rule_name: 'Phishing link clicked', mitre: ['T1566'], group: u, ts_first: t, ts_last: t }),
      raise({ rule_id: 'SENTRA-EXEC-002', rule_name: 'Encoded PowerShell', mitre: ['T1059'], group: u, ts_first: t + H, ts_last: t + H }),
      raise({ rule_id: 'SENTRA-CRED-001', rule_name: 'LSASS access', mitre: ['T1003'], group: u, ts_first: t + 2 * H, ts_last: t + 2 * H })];
    for (const x of a) alerts.setStatus(x.id, i < 3 ? 'closed-true-positive' : 'closed-false-positive', 'syn.ana', 'synthetic');
  }
  raise({ rule_id: 'SENTRA-MAIL-001', rule_name: 'Phishing link clicked ' + XSS, mitre: ['T1566'], group: { user: 'syn.lina' }, host: 'pc-syn-7', ts_first: NOW - 3 * H, ts_last: NOW - 3 * H });
  raise({ rule_id: 'SENTRA-EXEC-002', rule_name: 'Encoded PowerShell', mitre: ['T1059'], group: { user: 'syn.lina' }, host: 'pc-syn-7', ts_first: NOW - 2 * H, ts_last: NOW - 2 * H });
  const api = fakeApi({ realRanks: true });
  require(path.join(SIEM, 'engine/xdr/routes')).register(api, { state, alerts, cases, config: {}, log: quiet });
  let WHO = { user: 'nora.syn', role: 'operator' }, intelCalls = 0; const asked = [];
  const srv = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://x'), json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u.pathname === '/dashboards/whoami.json') return json(200, WHO);
    if (u.pathname === '/api/soc/soc/copilot/status') return json(200, { enabled: true, model: 'synthetic' });
    if (u.pathname === '/api/soc/soc/copilot/conversations') return json(200, { items: [] });
    if (u.pathname === '/api/soc/soc/copilot/ask') { let b = ''; req.on('data', (c) => (b += c)); req.on('end', () => { asked.push(JSON.parse(b)); json(200, { answer: 'Synthetic incident explanation.', conversation: 'CPC-1', steps: [], proposals: [] }); }); return; }
    if (u.pathname.startsWith('/api/soc/')) { if (u.pathname === '/api/soc/xdr/intel') intelCalls++; let b = ''; req.on('data', (c) => (b += c)); req.on('end', async () => { const r = await api.call(req.method, u.pathname + u.search, { role: WHO.role, user: WHO.user, body: b ? JSON.parse(b) : undefined }); json(r.status, r.body); }); return; }
    if (u.pathname.startsWith('/api/')) return json(404, { error: 'not in this test' });
    const f = path.join(DASH, u.pathname.replace(/^\/dashboards\//, '/')); if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (err, d) => { if (err) { res.writeHead(404); res.end(); return; } res.writeHead(200, { 'Content-Type': u.pathname.endsWith('.js') ? 'application/javascript' : u.pathname.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port + '/soc-xdr.html?standalone=1';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright'); const browser = await chromium.launch(), errs = [];
  const wait = (p, fn, arg) => p.waitForFunction(fn, arg === undefined ? null : arg, { timeout: 15000 }).then(() => true, () => false);
  const zd = (p, re) => wait(p, (src) => new RegExp(src).test((document.getElementById('zd') || {}).textContent || ''), re.source);
  try {
    const p = await browser.newPage({ viewport: { width: 1500, height: 1100 } }); p.on('pageerror', (x) => errs.push(x.message));
    await p.goto(base);
    ok(await wait(p, () => document.querySelectorAll('#inc tr[data-inc]').length >= 1), 'incident list');
    ok(!(await p.$('#inc img')) && !(await p.evaluate(() => window.__xx)), 'a hostile rule name stays text');
    ok(await wait(p, () => !document.getElementById('mltab').hidden), 'AI / ML tab offered to an operator');
    await p.click('#mltab');
    ok(await wait(p, () => /Credential Access/i.test(document.getElementById('mlnext').textContent)), 'what may come next: credential access learned');
    const nx = await p.textContent('#mlnext');
    ok(/\d+%/.test(nx) && /observed transition/.test(nx) && /true-positive/.test(nx), 'with a probability, the transitions it stands on and a similar closed incident: ' + nx.slice(0, 260));
    ok(/Initial Access/i.test(nx) && /Execution/i.test(nx), 'the path so far');
    ok(/→/.test(await p.textContent('#mlpaths')) && /Incidents per day/.test(await p.getAttribute('#mltrend [role=img]', 'aria-label')), 'attack paths learned and the trend labelled');
    // incident detail
    await p.click('#mlnext [data-inc]');
    ok(await zd(p, /Attack graph/), 'incident detail with the attack graph');
    ok(/Attack graph: 2 alerts/.test(await p.getAttribute('#zd svg.gsvg', 'aria-label')) && /user:syn\.lina/.test(await p.textContent('#zd svg.gsvg')), 'graph of alerts and the entities joining them');
    ok(await zd(p, /May come next/) && await zd(p, /a lead to watch for, not a prediction/), 'next-tactic section in the detail, framed');
    await p.click('[data-askinc]');
    ok(await wait(p, () => /Synthetic incident explanation/.test(document.body.innerText)) && asked.length === 1 && /Explain XDR incident XDR-/.test(asked[0].question), 'Ask the Copilot with the incident in the question');
    // viewer
    WHO = { user: 'vera.syn', role: 'viewer' }; intelCalls = 0;
    const v = await browser.newPage({ viewport: { width: 1300, height: 900 } }); v.on('pageerror', (x) => errs.push(x.message));
    await v.goto(base); await wait(v, () => document.querySelectorAll('#inc tr[data-inc]').length >= 1);
    ok(await v.evaluate(() => document.getElementById('mltab').hidden) && intelCalls === 0, 'a viewer gets no ML tab and no request');
    await v.click('#inc tr[data-inc]'); ok(await zd(v, /Attack graph/) && !(await v.$('#xmlsec')), 'a viewer sees the graph but not the learned statistics'); await v.close();
    WHO = { user: 'nora.syn', role: 'operator' };
    const ph = await browser.newPage({ viewport: { width: 390, height: 900 } }); ph.on('pageerror', (x) => errs.push(x.message));
    await ph.goto(base); await wait(ph, () => document.querySelectorAll('#inc tr[data-inc]').length >= 1);
    ok(await ph.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1), 'phone width: no sideways scroll'); await ph.close();
    if (process.env.SHOT) { await p.keyboard.press('Escape'); await p.click('#mltab'); await p.waitForTimeout(400); await p.screenshot({ path: process.env.SHOT + '-xdr-ml.png', fullPage: true }); }
  } finally { await browser.close(); srv.close(); alerts.stop(); state.close(); fs.rmSync(dir, { recursive: true, force: true }); }
  ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks'); process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
