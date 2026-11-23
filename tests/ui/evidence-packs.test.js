// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for Regulator Evidence Packs (dashboards/server/evidence-packs.html) against the REAL ITAM engine
// (engine/evidence-packs.js over engine/duty.js: SAMA CSF, IA, NCA ECC, PDPL, NDMO with pyengine), SYNTHETIC facts and evidence
// only: the empty state; last month's packs built by the monthly job; "Build now" by an operator builds this month's; a pack
// opened (fingerprint, controls, evidence names and hashes); compared with the previous month (a control that got worse, the
// evidence that expired); exported to Excel (a real .xlsx) and printed; the builder cannot sign it, a second person (an
// administrator) signs it off and it is locked; a hostile evidence title stays text; a viewer is refused with an explanation;
// no page errors.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node evidence-packs.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const ITAM = path.join(__dirname, '..', '..', 'backend', 'itam'), DASH = path.join(__dirname, '..', '..', 'ui');
const H = require(path.join(ITAM, 'tests', 'helpers'));
const { registerDuty } = require(path.join(ITAM, 'engine', 'duty'));
const EP = require(path.join(ITAM, 'engine', 'evidence-packs'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const XSS = '<img src=x onerror=alert(1)> Patch report (synthetic)';
const FILE = Buffer.from('SYNTHETIC evidence - not real data\n');

(async () => {
  const S = { clock: Date.parse('2026-10-02T06:00:00Z'), critical: 0 };
  const facts = () => ({
    grc: { available: true, total: 20, reviews_overdue: 0, attested: 15, policies: [], control_status: {} },
    hardening: { available: true, assets: 40, scanned: 38, coverage_pct: 95, score: 82, fail: 30, critical_fail: S.critical },
    pentest: { available: true, assets: 12, findings: 4, by_severity: { critical: 0, high: 0 }, internet_facing: 3, exposed_assets: 0 },
    cadence: { available: true, assets: 12, out_of_policy: 3 },
    siem: { available: true, sama: { '3.3.14': 'covered' }, retention_days: 400, logflow: { required: 10, silent: 0, not_onboarded: 0, no_connector: 0 } },
  });
  const e = await H.startApp({ noAi: true });
  const now = () => S.clock;
  registerDuty(e.app.srv, e.app, { noTimer: true, now, python: process.env.PYTHON || 'python3', samaFacts: async () => facts(), eccFacts: async () => facts() });
  const X = EP.createEvidencePacks(e.app, { now, noTimer: true }); e.app.addons.evidencePacks = X; EP.registerEvidencePacks(e.app.srv, e.app, X);
  let WHO = { user: 'nora.syn', role: 'operator' };
  const srv = http.createServer((req, res) => {
    const u2 = new URL(req.url, 'http://x'), json = (c, b2) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b2)); };
    if (u2.pathname === '/dashboards/whoami.json') return json(200, WHO);
    if (u2.pathname.startsWith('/api/itam/')) {
      const h = Object.assign({}, req.headers, { 'x-sentra-proxy-secret': H.SECRET, 'x-auth-user': WHO.user, 'x-auth-role': WHO.role });
      const up = http.request({ host: '127.0.0.1', port: e.port, method: req.method, path: req.url, headers: h }, (r) => { res.writeHead(r.statusCode, r.headers); r.pipe(res); });
      req.pipe(up); return;
    }
    if (u2.pathname.startsWith('/api/')) return json(404, { error: 'not in this test' });
    const f = path.join(DASH, u2.pathname.replace(/^\/dashboards\//, '/')); if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (err, d) => { if (err) { res.writeHead(404); res.end(); return; } res.writeHead(200, { 'Content-Type': u2.pathname.endsWith('.js') ? 'application/javascript' : u2.pathname.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port + '/';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  const has = (p, sel, re) => p.waitForFunction((a) => new RegExp(a[1]).test((document.querySelector(a[0]) || {}).textContent || ''), [sel, re.source], { timeout: 15000 }).then(() => true, () => false);
  try {
    const p = await browser.newPage({ viewport: { width: 1400, height: 1000 }, acceptDownloads: true }); p.on('pageerror', (x) => errs.push(x.message));
    await p.goto(base + 'evidence-packs.html?standalone=1');
    ok(await has(p, '#body', /No pack yet/), 'empty state says what to do');
    // last month: SYNTHETIC evidence that expires, and the monthly job's packs
    const ev = await e.req('POST', '/grc/evidence', { body: { framework: 'SAMA CSF', control: 'SA-3.3.8-01', title: XSS, owner: 'faisal.syn', filename: 'patch-synthetic.txt', content_b64: FILE.toString('base64'), collected: '2026-09-15', valid_days: 30 }, user: 'nora.syn', role: 'operator' });
    if (ev.status !== 200) throw new Error(ev.text);
    await X.tick();
    // this month: hardening has critical failures; an operator presses Build now
    S.clock = Date.parse('2026-11-04T06:00:00Z'); S.critical = 2;
    await p.reload(); await p.waitForSelector('#body tr[data-pack]', { timeout: 15000 });
    ok((await p.$$('#body tr[data-pack]')).length === 5, 'last month: 5 packs from the monthly job');
    await p.selectOption('#fw', 'all');
    await Promise.all([p.waitForResponse((r) => /\/evidence-packs\/build$/.test(r.url()), { timeout: 60000 }), p.click('#build')]);
    await p.waitForFunction(() => document.querySelectorAll('#body tr[data-pack]').length === 10, null, { timeout: 30000 });
    ok(await has(p, '#kpis', /awaiting sign-off/), 'framework cards show the latest pack');
    await p.click('#body tr[data-pack="EP-SAMA-2026-11-01"] [data-act="open"]');
    await p.waitForSelector('#pack[data-pack="EP-SAMA-2026-11-01"]', { timeout: 15000 });
    const sha = (await p.textContent('#sha')).trim();
    ok(/^[0-9a-f]{64}$/.test(sha) && sha === e.app.store.collection('evidence_packs').get('EP-SAMA-2026-11-01').sha256, 'the SHA-256 fingerprint is shown');
    ok(await has(p, '#pack', /fingerprint intact/), 'integrity re-checked');
    const row = await p.$('#controls tr[data-ref="SA-3.3.8-01"]');
    const rowText = row ? await row.textContent() : '';
    ok(/not implemented/.test(rowText) && /patch-synthetic\.txt/.test(rowText) && /evidence expired/.test(rowText), 'a control: result, evidence file, what is missing');
    ok(rowText.includes(XSS) && !(await p.$('#controls img')), 'a hostile evidence title stays text');
    ok(!(await p.textContent('#body')).includes('SYNTHETIC evidence - not real data'), 'the evidence content is not on the page');
    await p.selectOption('#cf', 'not_implemented');
    ok((await p.$$('#controls tr[data-ref]')).length >= 1 && !(await p.$$eval('#controls tr[data-ref] td:nth-child(3)', (x) => x.map((t) => t.textContent))).some((t) => /^implemented/.test(t)), 'filter by result');
    await p.selectOption('#cf', 'all');
    // compare with the previous month
    await Promise.all([p.waitForResponse((r) => /\/compare$/.test(r.url())), p.click('[data-act="compare"]')]);
    ok(await has(p, '#compare', /Compared with EP-SAMA-2026-10-01/), 'compared with the previous month');
    ok(await has(p, '#worse', /SA-3\.3\.8-01/), 'the control that got worse');
    ok(await has(p, '#expired', /patch-synthetic|Patch report/), 'the evidence that expired');
    ok(!(await p.$('#compare img')), 'hostile text stays text in the comparison');
    // Excel and print
    const [dl] = await Promise.all([p.waitForEvent('download'), p.click('[data-act="xlsx"]')]);
    ok(dl.suggestedFilename() === 'evidence-pack-EP-SAMA-2026-11-01.xlsx', 'Excel file name');
    const xf = await dl.path(); const head = fs.readFileSync(xf).slice(0, 2).toString('latin1');
    ok(head === 'PK', 'a real .xlsx (zip)');
    ok(e.app.store.auditTail(500).some((a) => a.action === 'evidence-packs.export' && a.by === 'nora.syn'), 'the export is audited');
    await p.evaluate(() => { window.__printed = 0; window.print = () => { window.__printed++; }; });
    await p.click('[data-act="print"]');
    ok(await p.evaluate(() => window.__printed) === 1, 'print');
    // the operator who built it cannot sign; a second person (an administrator) signs it off
    ok(!(await p.$('[data-act="sign"]')) && await has(p, '#signwhy', /administrator/), 'the operator sees why they cannot sign');
    WHO = { user: 'syed', role: 'admin' }; await p.reload(); await p.waitForSelector('#body tr[data-pack]', { timeout: 15000 });
    await p.click('#body tr[data-pack="EP-SAMA-2026-11-01"] [data-act="open"]'); await p.waitForSelector('[data-act="sign"]', { timeout: 15000 });
    await p.click('[data-act="sign"]'); ok(await has(p, '#signmsg', /Tick the statement/), 'the statement must be ticked');
    await p.check('#stmt'); await p.fill('#signnote', 'Reviewed for the SAMA request (synthetic)');
    await Promise.all([p.waitForResponse((r) => /\/sign$/.test(r.url())), p.click('[data-act="sign"]')]);
    ok(await has(p, '#signbox', /Signed off by syed/), 'signed off and locked');
    ok(!(await p.$('[data-act="sign"]')), 'no second sign-off');
    const signed = e.app.store.collection('evidence_packs').get('EP-SAMA-2026-11-01');
    ok(signed.signoff && signed.signoff.by === 'syed' && signed.signoff.sha256 === sha, 'the sign-off records the fingerprint');
    ok(e.app.store.auditTail(500).some((a) => a.action === 'evidence-packs.sign' && a.by === 'syed' && a.role === 'admin'), 'the sign-off is audited');
    await p.click('[data-act="back"]'); ok(await has(p, '#body tr[data-pack="EP-SAMA-2026-11-01"]', /signed/), 'the list shows it signed');
    // a viewer is refused gracefully
    WHO = { user: 'vera.syn', role: 'viewer' };
    await Promise.all([p.waitForResponse((r) => /\/api\/itam\/evidence-packs$/.test(r.url())), p.reload()]);
    ok(await has(p, '#refused', /operator role/), 'a viewer is told why');
    ok(!(await p.$('#pack')) && !(await p.$('tr[data-pack]')) && await p.$eval('#tools', (x) => x.hidden), 'a viewer sees no pack and no build button');
  } finally { await browser.close(); srv.close(); await e.close(); }
  ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks');
  process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
