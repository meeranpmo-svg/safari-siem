// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// GRC Dashboard (grc-dashboard.html) against the REAL ITAM engines (policy register, Risk Studio, GRC registers, the framework
// registers through the crosswalk, control monitoring) over SYNTHETIC facts: the posture index with its explanation, five pillar
// cards (assurance not available until control monitoring has run - never counted as good), the attention list, frameworks, the risk
// heat map (residual / inherent), remediation, named roles - naming the CISO raises governance; the trend says what it needs; a
// viewer sees no advisor; menu entry, portal redirect and installer.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node grc-dashboard.test.js
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
  { // Workflow Automation (the real engine): GRC's evidence request late with the DBA team, a backup evidence request fulfilled and waiting for acceptance
    const W = e.app.addons.workflow, col = e.app.store.collection('wf_requests');
    W.settingsSave({ version: 0, functions: { grc: ['nora.syn'] }, teams: { dba: ['dba.syn'], backup: ['bk.syn'] } }, { user: 'syed', role: 'admin', ip: '' });
    const late = W.create({ type: 'db-audit-trail', from: 'grc', title: 'Audit trail evidence for SAMA 3.3.14 <img src=x onerror=window.__wfx=1>', details: 'production databases', priority: 'high' }, { user: 'nora.syn', role: 'operator', ip: '' });
    const lr = col.get(late.id); lr.due = new Date(Date.now() - 3600000).toISOString(); col.put(lr);
    const done = W.create({ type: 'backup-evidence', from: 'grc', title: 'Backup success evidence, October', details: 'monthly' }, { user: 'nora.syn', role: 'operator', ip: '' });
    W.act(done.id, 'evidence', { kind: 'note', text: 'report attached' }, { user: 'bk.syn', role: 'operator', ip: '' }); W.act(done.id, 'fulfil', { response: 'attached' }, { user: 'bk.syn', role: 'operator', ip: '' }); }
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
    const ctx = await browser.newContext({ viewport: { width: 1500, height: 1000 } });
    let p = await page(ctx, 'grc-dashboard.html');
    ok(/^\d+$/.test((await p.textContent('#ring svg text')).trim()) && /mean of \d measured pillar/.test(await p.textContent('#ring')), 'posture index with its explanation');
    ok((await p.$$('#pls .pl')).length === 5, 'five pillar cards');
    ok(/no control-monitoring run yet/.test(await p.textContent('#pls [data-pl="assurance"]')) && /Assurance not available and left out/.test(await p.textContent('#ring')), 'assurance not available and left out of the index');
    ok(/CISO \(NCA ECC profile\) is not named/.test(await p.textContent('#attn')), 'attention: CISO not named');
    ok(/no risk rated yet/.test(await p.textContent('#pls [data-pl="risk"]')), 'an empty risk register is not shown as a good score');
    ok(!(await p.$('.top .zyb-uh-link')), 'no stray error link in the introduction');
    ok((await p.$$('#fws .fw')).length === 7, 'framework cards: NCA ECC, SAMA, ISO 27001, NDMO, PDPL, SOC 2, ISO/IEC 42001');
    // every card and figure opens a page that exists (bug: SOC 2 and ISO/IEC 42001 linked to "undefined", so a click went nowhere)
    const lk = await p.evaluate(() => ({ all: [...document.querySelectorAll('main a[href], body a[href]')].map((a) => a.getAttribute('href')), fw: [...document.querySelectorAll('#fws a.fw')].map((a) => a.getAttribute('href')), gov: [...document.querySelectorAll('#gov a.kpi')].map((a) => a.getAttribute('href')), rem: document.querySelectorAll('#rem a.fb').length }));
    ok(!lk.all.some((h) => /undefined|null/.test(h)), 'no link reads undefined: ' + lk.all.filter((h) => /undefined|null/.test(h)).join(' '));
    ok(lk.fw.length === 7 && lk.fw.every((h) => fs.existsSync(path.join(DASH, h))) && lk.fw.filter((h) => h === 'gap-analysis.html').length === 2, 'every framework card opens an existing page (SOC 2 and ISO/IEC 42001: the gap analysis): ' + lk.fw.join(' '));
    ok(lk.gov.length === 4 && lk.gov.every((h) => h === 'grc-policies.html') && lk.rem === 5, 'the governance figures open the policy register, the remediation rows the GRC workspace');
    ok(/no risk rated yet/.test(await p.textContent('#hm')), 'heat map: says no risk is rated yet instead of an empty grid');
    ok(/Overdue/.test(await p.textContent('#rem')) && /without an owner/.test(await p.textContent('#rem')), 'remediation funnel and unowned gaps');
    ok(/not named/.test(await p.textContent('#gov')), 'named roles table');
    { const w = await p.textContent('#wfcard');
      ok(!(await p.$eval('#wfcard', (c) => c.hidden)) && /1\s*open with the IT teams/.test(w) && /1\s*late with the IT teams/.test(w) && /1\s*results for you to accept/.test(w) && /100 %\s*IT teams on time \(1 of 1\)/.test(w), 'Workflow Automation: GRC\'s requests open, late, to accept, on time - from the real engine: ' + w.replace(/\s+/g, ' ').slice(0, 260));
      ok(w.indexOf('Audit trail evidence') < w.indexOf('Backup success evidence') && /Audit trail evidence for SAMA 3\.3\.14 <img/.test(w) && !(await p.$('#wfcard img')) && !(await p.evaluate(() => window.__wfx)) && /late with the IT team \+35, high priority \+10/.test(w), 'Workflow: ranked by points with the reasons; a hostile title stays text'); }
    const gx = await p.evaluate(() => ({ radar: document.querySelector('#ring svg.radar polygon[fill-opacity]') ? 1 : 0, rtxt: [...document.querySelectorAll('#ring svg.radar text')].map((x) => x.textContent).join('|'), dashed: document.querySelectorAll('#ring svg.radar line[stroke-dasharray]').length,
      fwr: document.querySelectorAll('#fws .fw .fwr svg').length, tg: document.querySelectorAll('#fws .stack .tg').length, fb: [...document.querySelectorAll('#rem .fb span')].map((x) => x.textContent).join(','), gr: document.querySelectorAll('#gov .gr svg').length, grt: document.querySelector('#gov .gr').textContent }));
    ok(gx.radar && /Risk —/.test(gx.rtxt) && /Assurance —/.test(gx.rtxt) && gx.dashed === 2 && /Governance \d+/.test(gx.rtxt), 'pillar radar: measured pillars plotted, Risk and Assurance not measured (dashed, no point): ' + gx.rtxt);
    ok(gx.fwr >= 5 && gx.tg >= 5, 'framework rings and the 80 % target marked on each bar (' + gx.fwr + ', ' + gx.tg + ')');
    ok(gx.fb === 'Open,Due soon,Overdue,To verify,Closed 30 d' && gx.gr === 2 && /policies attested/.test(gx.grt) && /\d+ \/ 3roles named/.test(gx.grt), 'remediation funnel bars; governance rings for attestation and named roles: ' + gx.grt);
    ok(/needs 7 daily snapshots|appears after two daily snapshots/.test(await p.textContent('#trend') + await p.textContent('#ml')), 'the learning says what it needs');
    const g1 = Number(await p.textContent('#pls [data-pl="governance"] .big'));
    e.app.store.collection('ecc_profile').put(Object.assign(e.app.store.collection('ecc_profile').get('profile') || { id: 'profile' }, { ciso_user: 'khalid.syn' }));
    await p.click('#refresh'); ok(await wait(p, (g) => Number(document.querySelector('#pls [data-pl="governance"] .big').textContent) > g, g1), 'naming the CISO raises governance');
    if (process.env.SHOT) await p.screenshot({ path: process.env.SHOT, fullPage: true });   // optional: a picture for review
    WHO = { user: 'vera.syn', role: 'viewer' }; const v = await page(ctx, 'grc-dashboard.html');
    ok(/shown to operators and administrators/.test(await v.textContent('#ai')), 'viewer: no advisor');
    const nav = fs.readFileSync(path.join(DASH, 'vendor', 'zyb-nav.js'), 'utf8');
    ok(/"h": "grc-dashboard.html"/.test(nav) && /grc-dashboard\.html/.test(fs.readFileSync(path.join(DASH, 'install-dashboards.sh'), 'utf8')), 'menu entry and installer');
    ok(/'dash-grc': 'grc-dashboard\.html'/.test(fs.readFileSync(path.join(DASH, 'vendor', 'zyb-menu.js'), 'utf8')) && /'dash-grc': 'grc-dashboard\.html'/.test(fs.readFileSync(path.join(DASH, 'vendor', 'zyb-early.js'), 'utf8')), 'the portal GRC Dashboard opens this page');
    ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  } finally { await browser.close(); srv.close(); await e.close(); }
  console.log((bad ? 'FAILED ' : 'ok ') + (n - bad) + '/' + n);
  process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
