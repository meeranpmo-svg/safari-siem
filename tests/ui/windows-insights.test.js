// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// AI Windows Server Administrator - the AI / ML insight band (windows-admin.html + vendor/zyb-sysadmin.js) against the REAL SIEM
// sysadmin routes with a fake WinRM helper and SYNTHETIC servers: four charts drawn from the health checks (problems by severity,
// server health, problems by kind, most affected servers), each with a readable summary; with the AI on, "Ask AI" on a problem
// opens the Ask tab with a question about it; with the AI off, or for a viewer, no Ask AI; a hostile server name stays text;
// without the charts library the band hides and the tables still work.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node windows-insights.test.js
const http = require('http'), fs = require('fs'), os = require('os'), path = require('path');
const DASH = path.resolve(__dirname, '../../ui');
const SIEM = process.env.SENTRA_SIEM_DIR || path.resolve(__dirname, '../../backend/siem');
const { createState } = require(path.join(SIEM, 'engine/soc/state'));
const routes = require(path.join(SIEM, 'engine/sysadmin/routes'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const XSS = '<img src=x onerror=alert(1)>';

(async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'win-ins-')), secrets = path.join(dir, 'secrets.json'); fs.writeFileSync(secrets, '{}', { mode: 0o600 });
  const state = await createState({ dir: path.join(dir, 'state') }), config = {};
  Object.defineProperty(config, 'secrets', { value: {}, enumerable: false, writable: true });
  Object.defineProperty(config, '_paths', { value: { secrets }, enumerable: false });
  const exec = async (r) => (r.op === 'version' ? { ok: true } : r.op === 'run' ? { ok: true, data: r.check === 'disks' ? [{ drive: 'C:', size_gb: 100, free_gb: 3, free_pct: 3 }] : [], errors: [] } : { ok: false, kind: 'input', error: 'bad op' });
  const S = routes.createSysadmin({ state, config, log: { info() {}, warn() {}, error() {} }, sysadminExec: exec });
  const R = []; routes.register({ route: (m, p, h) => R.push({ m, re: new RegExp('^' + p.replace(/:(\w+)/g, '(?<$1>[^/]+)') + '$'), h }) }, { state, config, log: { error() {}, info() {} }, sysadmin: S });
  const RANK = { viewer: 0, analyst: 1, operator: 2, admin: 3 }, audits = [];
  let WHO = { user: 'syed', role: 'admin' };
  // synthetic servers: two at site UAT, one in production
  S.targets.setProfile('windows', { username: 'SYN\\svc-ai-winread', password: 'Synthetic-1' }, 'syed');
  S.targets.put({ id: 'uat-app01', name: 'UAT-APP01', ip: '10.9.0.11', site: 'UAT' }, 'syed');
  S.targets.put({ id: 'uat-db01', name: 'UAT-DB01', ip: '10.9.0.12', site: 'UAT' }, 'syed');
  S.targets.put({ id: 'prod-fs01', name: 'PROD-FS01', ip: '10.1.0.10', site: 'HQ' }, 'syed');
  S.targets.put({ id: 'evil', name: XSS, ip: '10.1.0.66', site: 'HQ' }, 'syed'); await S.health.pollServer('evil', {});
  let AION = false; const st0 = S.ai.status.bind(S.ai); S.ai.status = () => (AION ? { enabled: true, model: 'synthetic-model' } : st0());
  await S.health.pollServer('uat-app01', {}); await S.health.pollServer('prod-fs01', {});

  const srv = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://x'), json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u.pathname === '/dashboards/whoami.json') return json(200, WHO);
    if (u.pathname.startsWith('/api/soc/sysadmin')) {
      let raw = ''; req.on('data', (d) => { raw += d; }); req.on('end', async () => {
        const r = R.find((x) => x.m === req.method && x.re.test(u.pathname)); if (!r) return json(404, { error: 'not found' });
        const out = {}, role = WHO.role, ctx = { role, user: WHO.user, body: raw ? JSON.parse(raw) : undefined, params: Object.assign({}, u.pathname.match(r.re).groups), query: Object.fromEntries(u.searchParams), path: u.pathname,
          need(x) { if (RANK[role] < RANK[x]) { out.status = 403; out.error = 'requires ' + x + ' role'; return false; } return true; }, audit: (a, t, d) => audits.push([a, t, d, WHO.user]), ok(b) { out.status = 200; out.body = b; }, fail(c, m) { out.status = c; out.error = m; } };
        try { const rv = await r.h(ctx); if (rv !== undefined && !out.status) { out.status = 200; out.body = rv; } } catch (e) { out.status = e.status || e.code || 500; out.error = e.message; }
        json(out.status || 500, out.status === 200 ? out.body : { error: out.error });
      }); return;
    }
    if (u.pathname.startsWith('/api/')) return json(404, { error: 'not in this test' });
    const f = path.join(DASH, u.pathname.replace(/^\/dashboards\//, '/')); if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (err, d) => { if (err) { res.writeHead(404); return res.end(); } res.writeHead(200, { 'Content-Type': f.endsWith('.js') ? 'application/javascript' : f.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port + '/dashboards/';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  try {
    const p = await browser.newPage({ viewport: { width: 1400, height: 950 } }); p.on('pageerror', (x) => errs.push(x.message));
    p.on('dialog', (d) => d.accept());
    await p.goto(base + 'windows-admin.html?standalone=1'); await p.waitForSelector('#sgrid table', { state: 'attached' });
    await p.evaluate(() => { try { localStorage.clear(); } catch (e) { /* storage may be unavailable */ } });
    await p.waitForFunction(() => document.getElementById('cv-sev') && document.getElementById('cv-sev').getAttribute('aria-label'), null, { timeout: 10000 });
    const lab = await p.$$eval('#aiband canvas', (x) => x.map((c) => c.getAttribute('aria-label') || ''));
    ok(lab.length === 4 && lab.every(Boolean), 'four charts with a readable summary: ' + lab.map((l) => l.slice(0, 50)).join(' | '));
    ok(/Problems by severity/.test(lab[0]) && /Server health/.test(lab[1]) && /Problems by kind/.test(lab[2]) && /Most affected servers/.test(lab[3]), 'the charts say what they show');
    ok(/PROD-FS01|UAT-APP01/.test(lab[3]), 'the most affected servers are named from the checks: ' + lab[3].slice(0, 120));
    ok(!(await p.$('[data-askf]')), 'AI off: no Ask AI button');
    ok(!(await p.$('#sgrid img')), 'the hostile server name stays text');
    // AI on: Ask AI on a problem opens the Ask tab with that problem
    AION = true; await p.reload(); await p.waitForSelector('[data-askf]');
    const t0 = await p.$eval('#findings tr[data-f] td:nth-child(2)', (e) => e.textContent), s0 = await p.$eval('#findings tr[data-f] td:nth-child(3)', (e) => e.textContent);
    await p.click('#findings [data-askf]');
    ok(!(await p.$eval('#tab-ask', (e) => e.hidden)), 'the Ask tab opens');
    const q = await p.$eval('#q', (e) => e.value); ok(q.includes('Investigate this problem on ' + s0) && q.includes(t0), 'the question names the problem and server: ' + q.slice(0, 160));
    // a viewer: no Ask AI even with the AI on
    WHO = { user: 'vera', role: 'viewer' }; await p.reload(); await p.waitForSelector('#findings tr[data-f]', { state: 'attached' });
    ok(!(await p.$('[data-askf]')), 'viewer: no Ask AI');
    // without the charts library: band hidden, problems still listed
    WHO = { user: 'syed', role: 'admin' };
    const p2 = await browser.newPage(); p2.on('pageerror', (x) => errs.push(x.message)); await p2.route('**/chart.umd.js', (r) => r.fulfill({ status: 404, body: '' }));
    await p2.goto(base + 'windows-admin.html?standalone=1'); await p2.waitForSelector('#findings tr[data-f]');
    ok(await p2.$eval('#aiband', (e) => e.hidden), 'no charts library: the band hides, the problems are still listed');
    ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  } finally { await browser.close(); srv.close(); }
  console.log((bad ? 'FAILED ' : 'ok ') + (n - bad) + '/' + n + ' windows-insights checks'); process.exit(bad ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });
