// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// AppSec & Code Review (dashboards/server/appsec.html) against the REAL ITAM engine (engine/appsec.js) with SYNTHETIC code and
// scans: empty state says what to do; register an application; import a SARIF file (file input) → findings, gate fails; quick
// review of pasted code finds a secret that is masked (never in the page); triage a false positive (note required); ask for a
// risk acceptance and see the requester cannot approve it, an administrator does; a go with a failed gate needs a note and
// waits for an override that someone else gives; KPIs, ring, hotspots, CWE; Excel holds the rows; AI off says why; a hostile
// file path stays text; viewer sees no snippet and no write controls; menu entry, installer and the portal redirect.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node appsec.test.js
const http = require('http'), fs = require('fs'), os = require('os'), path = require('path');
const ITAM = path.join(__dirname, '..', '..', 'backend', 'itam'), DASH = path.join(__dirname, '..', '..', 'ui');
const H = require(path.join(ITAM, 'tests', 'helpers'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const KEY = 'AKIA' + 'SYNTHETIC0EXAMPL', XSS = '<img src=x onerror="window.__xss=1">';
const SARIF = JSON.stringify({ version: '2.1.0', runs: [{ tool: { driver: { name: 'Semgrep', rules: [{ id: 'js.sqli', shortDescription: { text: 'SQL injection' }, properties: { 'security-severity': '9.1', tags: ['CWE-89'] } }] } },
  results: [{ ruleId: 'js.sqli', level: 'error', message: { text: 'user input reaches a query' }, locations: [{ physicalLocation: { artifactLocation: { uri: 'src/claims/' + XSS + '.js' }, region: { startLine: 12, snippet: { text: 'db.query("SELECT * FROM claims WHERE id=" + req.params.id)' } } } }] },
    { ruleId: 'js.sqli', level: 'warning', message: { text: 'fixture' }, locations: [{ physicalLocation: { artifactLocation: { uri: 'test/fixtures/q.js' }, region: { startLine: 3, snippet: { text: 'db.query("SELECT " + x)' } } } }] }] }] });

(async () => {
  const e = await H.startApp({ noAi: true });
  require(path.join(ITAM, 'engine/duty')).registerDuty(e.app.srv, e.app, { noTimer: true });
  let WHO = { user: 'nora.syn', role: 'operator' }, HOLD = null, HELD = 0;   // HOLD: a promise one application's GET waits on (a slow refresh, on purpose)
  const srv = http.createServer(async (req, res) => {
    const u = new URL(req.url, 'http://x'), json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u.pathname === '/dashboards/whoami.json') return json(200, WHO);
    if (u.pathname.startsWith('/api/itam/')) {
      if (HOLD && req.method === 'GET' && /\/appsec\/apps\/[^/]+$/.test(u.pathname)) { HELD++; await HOLD; }
      const h = Object.assign({}, req.headers, { 'x-sentra-proxy-secret': H.SECRET, 'x-auth-user': WHO.user, 'x-auth-role': WHO.role });
      const up = http.request({ host: '127.0.0.1', port: e.port, method: req.method, path: req.url, headers: h }, (r) => { res.writeHead(r.statusCode, r.headers); r.pipe(res); });
      req.pipe(up); return;
    }
    if (u.pathname.startsWith('/api/')) return json(404, { error: 'not in this test' });
    const f = path.join(DASH, u.pathname.replace(/^\/dashboards\//, '')); if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (err, d) => { if (err) { res.writeHead(404); return res.end(); } res.writeHead(200, { 'Content-Type': f.endsWith('.js') ? 'application/javascript' : f.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const url = 'http://127.0.0.1:' + srv.address().port + '/dashboards/appsec.html?standalone=1';
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'sentra-appsec-')), sarifFile = path.join(tmp, 'semgrep.sarif'); fs.writeFileSync(sarifFile, SARIF);
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright'); const browser = await chromium.launch(), errs = [];
  const wait = (p, fn, arg) => p.waitForFunction(fn, arg, { timeout: 20000 }).then(() => true, () => false);
  const dlg = (p) => p.textContent('#dlg');
  try {
    const ctx = await browser.newContext({ viewport: { width: 1500, height: 1000 }, acceptDownloads: true });
    const p = await ctx.newPage(); p.on('pageerror', (x) => errs.push(x.message)); p.on('dialog', (d) => { errs.push('unexpected dialog'); d.dismiss(); });
    await p.goto(url); ok(await wait(p, () => /Register the first application/.test(document.getElementById('attn').textContent)), 'empty state says what to do');
    await p.fill('#na-name', 'Claims portal (synthetic)'); await p.selectOption('#na-exp', 'internet'); await p.fill('#na-owner', 'claims-dev'); await p.click('#na-go');
    ok(await wait(p, () => !document.getElementById('dlg').hidden && /Claims portal/.test(document.getElementById('dlg').textContent)), 'registered and opened');
    await p.setInputFiles('#imp-f', sarifFile); await p.click('#imp-go');
    ok(await wait(p, () => /sarif: Semgrep \+2 new/.test(document.body.textContent)), 'SARIF imported');
    ok(await wait(p, () => document.querySelectorAll('#dlg tr[data-f]').length === 2), 'two findings');
    ok(/fails/.test(await dlg(p)) && /open critical/.test(await dlg(p)), 'gate fails on the critical');
    ok(!(await p.evaluate(() => window.__xss)), 'a hostile file path stayed text');
    await p.fill('#rev-p', 'src/config.js'); await p.fill('#rev-c', "const awsKey = '" + KEY + "';\nconst h = crypto.createHash('md5');"); await p.click('#rev-paste');
    ok(await wait(p, () => /2 finding\(s\) - pattern rules/.test(document.body.textContent)), 'quick review');
    ok(await wait(p, () => /secret/.test(document.getElementById('dlg').textContent)) && !(await p.content()).includes(KEY), 'secret found and never in the page');
    // triage the fixture finding as a false positive
    const fx = await p.$$eval('#dlg tr[data-f]', (rs) => rs.filter((r) => /fixtures/.test(r.textContent)).map((r) => r.getAttribute('data-f'))[0]);
    ok(/60 %/.test(await p.textContent('#dlg tr[data-f="' + fx + '"]')), 'path rule: a fixture is a likely false positive');
    await p.click('#dlg tr[data-f="' + fx + '"]'); await p.click('[data-tri="false_positive"][data-id="' + fx + '"]');
    ok(await wait(p, () => /note is required/.test(document.body.textContent)), 'false positive needs a note');
    await p.fill('#tn-' + fx, 'test fixture (synthetic)'); await p.click('[data-tri="false_positive"][data-id="' + fx + '"]');
    ok(await wait(p, (i) => /false positive/.test((document.querySelector('#dlg tr[data-f="' + i + '"]') || {}).textContent || ''), fx) || await wait(p, () => /Saved/.test(document.body.textContent)), 'triaged');
    // risk acceptance on the md5 finding
    await p.click('#dlg [data-ff="all"]');
    const md5 = await p.$$eval('#dlg tr[data-f]', (rs) => rs.filter((r) => /Weak hash/.test(r.textContent)).map((r) => r.getAttribute('data-f'))[0]);
    await p.click('#dlg tr[data-f="' + md5 + '"]'); await p.fill('#ar-' + md5, 'legacy checksum only, not for passwords (synthetic)');
    await p.fill('#au-' + md5, new Date(Date.now() + 30 * 86400000).toISOString().slice(0, 10)); await p.click('[data-acc="' + md5 + '"]');
    ok(await wait(p, () => /Risk acceptance requested/.test(document.body.textContent)), 'acceptance requested');
    ok(await wait(p, (i) => { const b = document.querySelector('[data-accd="approve"][data-id="' + i + '"]'); return b && b.disabled; }, md5), 'the requester cannot approve');
    // release with a failed gate
    await p.fill('#rel-v', '2.4.1'); await p.click('#rel-go'); ok(await wait(p, () => /gate failed/.test(document.body.textContent)), 'go with a failed gate needs a note');
    await p.fill('#rel-n', 'regulatory deadline (synthetic)'); await p.click('#rel-go'); ok(await wait(p, () => /override requested/.test(document.getElementById('dlg').textContent)), 'release waits for an override');
    // closed while a refresh is still loading the application: it stays closed (it opened again when the load finished)
    let release; HOLD = new Promise((r) => { release = r; }); HELD = 0;
    await p.evaluate(() => document.getElementById('refresh').click()); for (let i = 0; i < 100 && !HELD; i++) await new Promise((r) => setTimeout(r, 50));
    ok(HELD > 0, 'the refresh reloads the open application');
    await p.keyboard.press('Escape');
    const loaded = p.waitForResponse((r) => r.request().method() === 'GET' && /\/appsec\/apps\/[^/]+$/.test(new URL(r.url()).pathname)); HOLD = null; release(); await loaded; await p.waitForTimeout(300);
    ok(await p.evaluate(() => document.getElementById('dlg').hidden), 'a dialog closed while it was reloading stays closed');
    ok(/Secrets in source/.test(await p.textContent('#kpis')) && /Pass the release gate/.test(await p.textContent('#ring')), 'KPIs and the gate ring');
    ok(/src\/config\.js/.test(await p.textContent('#hot')) && /CWE-89|CWE-798/.test(await p.textContent('#cwe')), 'hotspots and CWE');
    ok(/AI reviewer is off/.test(await p.textContent('#ai')), 'AI off says why');
    const [dl] = await Promise.all([p.waitForEvent('download', { timeout: 15000 }), p.click('#xls')]);
    { const x = fs.readFileSync(await dl.path(), 'latin1'); ok(/^appsec-findings-\d{4}-\d{2}-\d{2}\.xlsx$/.test(dl.suggestedFilename()) && x.includes('Chance of false positive') && x.includes('Claims portal') && !x.includes(KEY), 'Excel holds the findings, never the secret'); }
    if (process.env.SHOT) await p.screenshot({ path: process.env.SHOT, fullPage: true });   // optional: a picture for review
    // administrator: approve the acceptance and override the release
    WHO = { user: 'syed', role: 'admin' }; const a = await ctx.newPage(); a.on('pageerror', (x) => errs.push(x.message)); await a.goto(url);
    await wait(a, () => document.querySelectorAll('.app').length === 1); await a.click('.app');
    await wait(a, () => document.querySelectorAll('#dlg tr[data-f]').length > 0); await a.click('#dlg [data-ff="all"]'); await a.click('#dlg tr[data-f="' + md5 + '"]');
    await a.click('[data-accd="approve"][data-id="' + md5 + '"]'); ok(await wait(a, () => /approved/i.test(document.body.textContent)), 'an administrator approves the acceptance');
    await wait(a, () => !!document.querySelector('[data-rel="approve"]')); await a.click('[data-rel="approve"]');
    ok(await wait(a, () => /Release overridden/.test(document.body.textContent)), 'someone else overrides the gate');
    // viewer
    WHO = { user: 'vera.syn', role: 'viewer' }; const v = await ctx.newPage(); v.on('pageerror', (x) => errs.push(x.message)); await v.goto(url);
    await wait(v, () => document.querySelectorAll('.app').length === 1); ok(!(await v.isVisible('#xls')) && !(await v.$('#na-go')), 'viewer: no Excel, no register form');
    await v.click('.app'); await wait(v, () => document.querySelectorAll('#dlg tr[data-f]').length > 0); await v.click('#dlg tr[data-f]');
    ok(!(await v.$('#imp-go')) && !(await v.$('[data-tri]')) && !(await v.$('pre.snip')), 'viewer: no import, triage or code snippet');
    const nav = fs.readFileSync(path.join(DASH, 'vendor', 'zyb-nav.js'), 'utf8');
    ok(/"h": "appsec.html"/.test(nav) && /appsec\.html/.test(fs.readFileSync(path.join(DASH, 'install-dashboards.sh'), 'utf8')), 'menu entry and installer');
    ok(/appsec: 'appsec\.html'/.test(fs.readFileSync(path.join(DASH, 'vendor', 'zyb-menu.js'), 'utf8')) && /appsec: 'appsec\.html'/.test(fs.readFileSync(path.join(DASH, 'vendor', 'zyb-early.js'), 'utf8')), 'the portal\'s AppSec opens this page');
    ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  } finally { await browser.close(); srv.close(); await e.close(); fs.rmSync(tmp, { recursive: true, force: true }); }
  console.log((bad ? 'FAILED ' : 'ok ') + (n - bad) + '/' + n);
  process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
