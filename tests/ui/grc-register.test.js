// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// GRC Register (grc-register.html) against the REAL ITAM engines (policy register, GRC registers, engine/grc-register.js) with SYNTHETIC
// records created through their own registers: hygiene ring and KPIs; kind and health chips; orphans; the record drawer with its
// relationship map, moving to a linked node; possible duplicates; owner filter from the load table; Excel with content; a viewer gets
// no Excel and no analyst; menu entry, the portal's GRC Register redirect and the installer.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node grc-register.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const ITAM = path.join(__dirname, '..', '..', 'backend', 'itam'), DASH = path.join(__dirname, '..', '..', 'ui');
const H = require(path.join(ITAM, 'tests', 'helpers'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const FACTS = () => ({
  grc: { available: true, total: 20, reviews_overdue: 0, attested: 15, policies: [{ title: 'Information Security Policy (synthetic)', status: 'Approved', next_review: '2027-06-01' }], control_status: {} },
  hardening: { available: true, assets: 40, scanned: 38, coverage_pct: 95, score: 82, fail: 30, critical_fail: 2 },
  pentest: { available: true, assets: 12, findings: 4, by_severity: { critical: 0, high: 0 }, internet_facing: 3, exposed_assets: 0 },
  siem: { available: true, retention_days: 400, logflow: { required: 10, silent: 0, not_onboarded: 0, no_connector: 0 } },
});

(async () => {
  const e = await H.startApp({ noAi: true });
  require(path.join(ITAM, 'engine/duty')).registerDuty(e.app.srv, e.app, { noTimer: true, python: process.env.PYTHON || 'python3', samaFacts: async () => FACTS(), eccFacts: async () => FACTS() });
  let WHO = { user: 'nora.syn', role: 'operator' };
  const srv = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://x'), json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u.pathname === '/dashboards/whoami.json') return json(200, WHO);
    if (u.pathname.startsWith('/api/itam/')) {
      const h = Object.assign({}, req.headers, { 'x-sentra-proxy-secret': H.SECRET, 'x-auth-user': WHO.user, 'x-auth-role': WHO.role });
      const up = http.request({ host: '127.0.0.1', port: e.port, method: req.method, path: req.url, headers: h }, (r) => { res.writeHead(r.statusCode, r.headers); r.pipe(res); });
      req.pipe(up); return;
    }
    if (u.pathname.startsWith('/api/')) return json(404, { error: 'not in this test' });
    const f = path.join(DASH, u.pathname.replace(/^\/dashboards\//, '')); if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (err, d) => { if (err) { res.writeHead(404); return res.end(); } res.writeHead(200, { 'Content-Type': f.endsWith('.js') ? 'application/javascript' : f.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port + '/dashboards/';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright'); const browser = await chromium.launch(), errs = [];
  const wait = (p, fn, arg) => p.waitForFunction(fn, arg, { timeout: 30000 }).then(() => true, () => false);
  const toast = (p, re) => wait(p, (s) => [...document.querySelectorAll('.toast')].some((t) => new RegExp(s).test(t.textContent)), re);
  const page = async (ctx, f) => { const p = await ctx.newPage(); p.on('pageerror', (x) => errs.push(x.message)); p.on('dialog', (d) => { errs.push('unexpected dialog'); d.dismiss(); }); await p.goto(base + f + '?standalone=1'); await p.waitForSelector('#main:not([hidden])', { timeout: 60000 }); return p; };
  try {
    const P = (p, b) => e.req('POST', p, { body: b, user: 'nora.syn', role: 'operator' });
    const pol = (await e.req('GET', '/grc/register', { user: 'nora.syn', role: 'operator' })).json.items[0];
    const r1 = (await P('/grc/risks', { title: 'Ransomware on claims servers (synthetic)', likelihood: 4, impact: 5, treatment: 'mitigate', owner: 'omar.syn', controls: [pol.sub_code], review_due: '2027-01-15' })).json;
    const r2 = (await P('/grc/risks', { title: 'Ransomware on claims servers synthetic copy', likelihood: 3, impact: 4, treatment: 'mitigate' })).json;
    const a1 = (await P('/grc/actions', { title: 'Immutable backups for claims (synthetic)', source: 'risk', ref: r1.id, owner: 'omar.syn', due: '2027-02-01' })).json;
    await P('/grc/exceptions', { policy_id: pol.doc_id, title: 'Legacy system without MFA <img src=x onerror="window.__xss=1"> (synthetic)', reason: 'vendor end of life', expires: '2027-03-01' });
    const ctx = await browser.newContext({ viewport: { width: 1500, height: 1000 }, acceptDownloads: true });
    const p = await page(ctx, 'grc-register.html');
    ok(/%/.test(await p.textContent('#ring')) && /Register hygiene/.test(await p.textContent('#ring')), 'hygiene ring');
    ok(/Orphans/.test(await p.textContent('#kpis')) && /Possible duplicates/.test(await p.textContent('#kpis')), 'KPIs');
    await p.click('[data-k="risk"]'); ok(await wait(p, () => { const r = document.querySelectorAll('#tbl tr[data-f]'); return r.length === 2 && [...r].every((x) => /^risk\|/.test(x.getAttribute('data-f'))); }), 'kind chip: the two risks');
    await p.click('[data-h="orphan"]'); ok(await wait(p, (id) => { const r = document.querySelectorAll('#tbl tr[data-f]'); return r.length === 1 && r[0].getAttribute('data-f') === 'risk|' + id; }, r2.id), 'orphan chip: the risk with nothing linked');
    await p.click('[data-k="all"]'); await p.click('[data-h="all"]');
    await p.click('#tbl tr[data-f="risk|' + r1.id + '"]'); ok(await wait(p, (a) => document.querySelector('#dlgb svg [data-rec="action|' + a + '"]'), a1.id), 'relationship map shows the remediation action');
    ok(await wait(p, () => [...document.querySelectorAll('#dlgb svg .nd')].some((g) => /^policy\|/.test(g.getAttribute('data-rec')))), 'two steps out: the policy behind the control');
    await p.click('#dlgb svg [data-rec="action|' + a1.id + '"]'); ok(await wait(p, (a) => document.getElementById('dlgb').textContent.includes(a) && /Immutable backups/.test(document.querySelector('#dlgb h2').textContent), a1.id), 'clicking a node moves to that record');
    await p.keyboard.press('Escape');
    ok(/Ransomware/.test(await p.textContent('#orph')) && /\d+%/.test(await p.textContent('#orph')), 'possible duplicates with similarity');
    await p.click('#owners [data-own="omar.syn"]'); ok(await wait(p, () => { const r = document.querySelectorAll('#tbl tr[data-f]'); return r.length === 2 && [...r].every((x) => /omar\.syn/.test(x.textContent)); }), 'owner filter from the load table');
    const [dl] = await Promise.all([p.waitForEvent('download', { timeout: 15000 }), p.click('#xls')]);
    ok(/^grc-register-\d{4}-\d{2}-\d{2}\.xlsx$/.test(dl.suggestedFilename()), 'Excel');
    { const x = fs.readFileSync(await dl.path(), 'latin1'); ok(x.includes(r2.id) && x.includes('Quality issues') && x.includes('mitigate, but no open action'), 'Excel holds the records and their quality issues'); }
    ok(!(await p.evaluate(() => window.__xss)), 'a hostile title stayed text');
    if (process.env.SHOT) await p.screenshot({ path: process.env.SHOT, fullPage: true });   // optional: a picture for review
    WHO = { user: 'vera.syn', role: 'viewer' }; const v = await page(ctx, 'grc-register.html');
    ok(!(await v.isVisible('#xls')) && /shown to operators and administrators/.test(await v.textContent('#ai')), 'viewer: no Excel, no analyst');
    const nav = fs.readFileSync(path.join(DASH, 'vendor', 'zyb-nav.js'), 'utf8');
    ok(/"h": "grc-register.html"/.test(nav) && /grc-register\.html/.test(fs.readFileSync(path.join(DASH, 'install-dashboards.sh'), 'utf8')), 'menu entry and installer');
    ok(/archer: 'grc-register\.html'/.test(fs.readFileSync(path.join(DASH, 'vendor', 'zyb-menu.js'), 'utf8')) && /archer: 'grc-register\.html'/.test(fs.readFileSync(path.join(DASH, 'vendor', 'zyb-early.js'), 'utf8')), 'the portal GRC Register opens this page');
    ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  } finally { await browser.close(); srv.close(); await e.close(); }
  console.log((bad ? 'FAILED ' : 'ok ') + (n - bad) + '/' + n);
  process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
