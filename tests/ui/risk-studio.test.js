// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for Risk Studio (dashboards/server/risk-studio.html) against the REAL ITAM engine (engine/risk-studio.js over
// grc-registers) with SYNTHETIC risks and audit findings: the KPIs and heat map; a heat-map cell and a KPI filter the register;
// a risk opens with its linked evidence and the evidence-based rating; applying it needs a note and updates the rating; a proposed
// risk needs an owner and is added to the register; appetite is admin-only and a bad value is refused; the Excel report downloads
// with its sheets; a hostile risk title stays text; a viewer sees no action buttons.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node risk-studio.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const ITAM = path.join(__dirname, '..', '..', 'backend', 'itam'), DASH = path.join(__dirname, '..', '..', 'ui');
const H = require(path.join(ITAM, 'tests', 'helpers'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const ADM = { user: 'syed', role: 'admin' }, OP = { user: 'nora.syn', role: 'operator' }, VW = { user: 'vera.syn', role: 'viewer' };
const XSS = '<img src=x onerror="window.__xss=1">';

(async () => {
  const e = await H.startApp({ noAi: true });
  const T0 = Date.parse('2026-10-31T09:00:00Z'), iso = (d) => new Date(T0 - d * 86400000).toISOString();
  require(path.join(ITAM, 'engine/duty')).registerDuty(e.app.srv, e.app, { noTimer: true, now: () => T0 });
  if (e.app.addons.updateHealth) e.app.addons.updateHealth.view = () => ({ pages: [] });
  const P = (p, body) => e.req('POST', p, Object.assign({ body }, OP));
  const r1 = (await P('/grc/risks', { title: 'Privileged admin accounts not reviewed', description: 'Domain admin accounts without periodic access review', likelihood: 2, impact: 2, owner: 'Siva (synthetic)', category: 'Access & identity', review_due: '2026-12-01' })).json.id;
  await P('/grc/risks', { title: 'Supplier contracts lack security clauses ' + XSS, likelihood: 3, impact: 3, owner: '', treatment: 'mitigate' });
  const F = (col, id, title, rating, d, x) => e.app.store.collection(col).put(Object.assign({ id, title, rating, state: 'issued', issued_at: iso(d), engagement: 'E-SYN' }, x || {}));
  F('ia_findings', 'IAF-1', 'Privileged admin accounts not reviewed for 12 months', 'high', 20, { condition: 'domain admin accounts access review missing' });
  F('csa_findings', 'CSA-1', 'Admin accounts privileged access review not performed', 'high', 10);
  F('iad_findings', 'IAD-1', 'Nightly backup restore test never performed', 'high', 5);
  F('ia_findings', 'IAF-2', 'Backup restore testing evidence missing', 'medium', 3);
  let WHO = ADM;
  const srv = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://x'), json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u.pathname === '/dashboards/whoami.json') return json(200, WHO);
    if (u.pathname.startsWith('/api/itam/')) {
      const h = Object.assign({}, req.headers, { 'x-sentra-proxy-secret': H.SECRET, 'x-auth-user': WHO.user, 'x-auth-role': WHO.role });
      const up = http.request({ host: '127.0.0.1', port: e.port, method: req.method, path: req.url, headers: h }, (r) => { res.writeHead(r.statusCode, r.headers); r.pipe(res); });
      req.pipe(up); return;
    }
    if (u.pathname.startsWith('/api/')) return json(404, { error: 'not in this test' });
    const f = path.join(DASH, u.pathname.replace(/^\/dashboards\//, '/')); if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (err, d) => { if (err) { res.writeHead(404); res.end(); return; } res.writeHead(200, { 'Content-Type': u.pathname.endsWith('.js') ? 'application/javascript' : u.pathname.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const url = 'http://127.0.0.1:' + srv.address().port + '/dashboards/risk-studio.html';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  const wait = (p, fn, arg) => p.waitForFunction(fn, arg, { timeout: 15000 }).then(() => true, () => false);
  const tab = (p, t) => p.click('#tabs [data-tab="' + t + '"]');
  const as = async (p, who) => { WHO = who; await p.goto(url); await wait(p, () => !document.getElementById('main').hidden); };
  const txt = (p) => p.textContent('#view');
  try {
    const ctx = await browser.newContext({ viewport: { width: 1440, height: 1000 }, acceptDownloads: true });
    const p = await ctx.newPage(); p.on('pageerror', (x) => errs.push(x.message));
    await as(p, OP); if (process.env.SHOT) await p.screenshot({ path: process.env.SHOT, fullPage: true });   // optional: a picture for review
    ok(/open risks/.test(await p.textContent('#kpis')) && /under-rated/.test(await p.textContent('#kpis')), 'KPIs');
    const pu = await p.evaluate(() => ({ gauge: (document.querySelector('.pg svg') || { getAttribute: () => '' }).getAttribute('aria-label'), journey: document.querySelectorAll('.jr[data-risk]').length, diamond: document.querySelectorAll('.jr rect').length,
      att: [...document.querySelectorAll('.att[data-risk]')].map((x) => x.innerText.replace(/\s+/g, ' ')), treat: document.querySelector('[aria-label="treatment mix"]') ? 1 : 0 }));
    ok(/mean rated risk [\d.]+ of 25/.test(pu.gauge) && pu.journey === 2 && pu.diamond >= 1 && pu.treat, 'risk pulse: gauge, journey with the evidence-suggested marker, treatment mix: ' + JSON.stringify(pu).slice(0, 300));
    ok(pu.att.length >= 1 && /under-rated: the evidence suggests 4×5 = 20/.test(pu.att[0]), 'needs attention, ranked, with its reason: ' + pu.att.join(' | '));
    const jid = await p.getAttribute('.jr[data-risk]', 'data-risk'); await p.click('.jr[data-risk]');
    ok(await wait(p, (i) => !!document.querySelector('tr.rk.sel[data-risk="' + i + '"]'), jid), 'a journey row opens that risk in the register');
    await p.click('tr.rk.sel'); await p.click('[data-tab="overview"]');   // deselect: a second click on the same risk closes it
    ok(await p.$('.heat [data-cell="i:2x2"]') && await p.$('.heat [data-cell="i:3x3"]'), 'inherent heat map has both risks');
    ok(/under-rated: the evidence suggests 4×5 = 20/.test(await txt(p)), 'overview lists the rating the evidence disagrees with');
    await p.click('.heat [data-cell="i:3x3"]');
    ok(await wait(p, () => document.querySelectorAll('tr.rk').length === 1 && /Supplier contracts/.test(document.getElementById('view').textContent)), 'a heat-map cell filters the register');
    ok(/no owner/.test(await txt(p)) && /Third party/.test(await txt(p)), 'housekeeping and the suggested category');
    await p.click('#clr');
    await p.click('[data-go="reg:under"]');
    ok(await wait(p, () => document.querySelectorAll('tr.rk').length === 1), 'the under-rated KPI filters the register');
    await p.click('tr.rk[data-risk="' + r1 + '"]');
    ok(await wait(p, () => /Linked evidence \(2\)/.test(document.getElementById('view').textContent)), 'risk opens with 2 linked findings');
    ok(/IAF-1/.test(await txt(p)) && /CSA-1/.test(await txt(p)) && /text similarity/.test(await txt(p)), 'evidence shows reference and how it was linked');
    await p.click('[data-apply]');
    ok(await wait(p, () => /note is required/.test(document.body.textContent)), 'applying needs a note');
    await p.fill('#anote', 'two high audit findings agree (synthetic)'); await p.click('[data-apply]');
    ok(await wait(p, () => /Rating updated/.test(document.body.textContent)), 'suggestion applied');
    const after = (await e.req('GET', '/grc/risks', ADM)).json.items.find((x) => x.id === r1);
    ok(after.likelihood * after.impact === 20, 'the register holds the new rating');
    await tab(p, 'candidates');
    ok(await wait(p, () => /Resilience & DR/.test(document.getElementById('view').textContent) && document.querySelector('[data-create]')), 'the backup findings are one proposed risk');
    await p.click('[data-create]');
    ok(await wait(p, () => /owner is required/.test(document.body.textContent)), 'a proposed risk needs an owner');
    await p.fill('[data-cown]', 'Mohamed Arshath (synthetic)'); await p.click('[data-create]');
    ok(await wait(p, () => /Added to the register as/.test(document.body.textContent)), 'proposed risk added');
    ok(await wait(p, () => /No proposed risks/.test(document.getElementById('view').textContent)), 'it is no longer proposed');   // after the reload, not just the toast
    await tab(p, 'appetite'); ok(/An administrator sets the appetite/.test(await txt(p)) && !(await p.$('#apsave')), 'operator: appetite read-only');
    const [dl] = await Promise.all([p.waitForEvent('download', { timeout: 10000 }), p.click('#xls')]);
    ok(/^risk-register-2026-10-31\.xlsx$/.test(dl.suggestedFilename()), 'Excel report');
    const buf = fs.readFileSync(await dl.path()), zip = buf.toString('latin1');
    ok(['Summary', 'Register', 'Heatmap', 'Appetite breaches', 'Calibration', 'Evidence', 'Proposed risks', 'Trend', 'Housekeeping'].every((s) => zip.indexOf('name="' + s + '"') >= 0 || zip.indexOf(s) >= 0), 'workbook carries every sheet');
    await tab(p, 'ai'); ok(/AI risk analyst is off/.test(await txt(p)), 'AI off says why');
    // admin: appetite
    await as(p, ADM); await tab(p, 'appetite');
    await p.fill('#apd', '30'); await p.click('#apsave');
    ok(await wait(p, () => /default must be/.test(document.body.textContent)), 'a bad appetite is refused with the field named');
    await p.fill('#apd', '9'); await p.fill('[data-apc="Access & identity"]', '6'); await p.click('#apsave');
    ok(await wait(p, () => /Appetite saved/.test(document.body.textContent)), 'appetite saved');
    await p.click('[data-go="reg:over"]');
    ok(await wait(p, () => /over 6/.test(document.getElementById('view').textContent)), 'the access risk is over its category appetite');
    // a link opens the register filtered (the Enterprise Risk Dashboard's tiles link here)
    await p.goto('about:blank'); await p.goto(url + '#reg=over');
    ok(await wait(p, () => document.getElementById('flag') && document.getElementById('flag').value === 'over' && document.querySelectorAll('tr.rk').length >= 1 && [...document.querySelectorAll('tr.rk')].every((r) => /over \d/.test(r.textContent))), 'a link with #reg=over opens the register showing only the risks over appetite');
    await p.goto('about:blank'); await p.goto(url + '#cand'); ok(await wait(p, () => !!document.querySelector('#tabs [data-tab="candidates"][aria-selected="true"]')), 'a link with #cand opens the proposed risks');
    // viewer
    await as(p, VW); await tab(p, 'register'); await p.click('tr.rk[data-risk="' + r1 + '"]');
    ok(await wait(p, () => /Linked evidence/.test(document.getElementById('view').textContent)) && !(await p.$('[data-apply]')), 'viewer: no apply button');
    await tab(p, 'candidates'); ok(!(await p.$('[data-create]')), 'viewer: no create button');
    ok(/Read-only/.test(await p.textContent('#me')), 'viewer is read-only');
    ok(!(await p.evaluate(() => window.__xss)), 'hostile risk title stayed text');
    const acts = e.app.store.auditTail(80).map((a) => a.action);
    ok(['risk-studio.suggestion.apply', 'risk-studio.candidate.create', 'risk-studio.appetite'].every((a) => acts.includes(a)), 'audit records');
    const nav = fs.readFileSync(path.join(DASH, 'vendor', 'zyb-nav.js'), 'utf8');
    ok(/"h": "risk-studio.html"/.test(nav) && /risk-studio\.html/.test(fs.readFileSync(path.join(DASH, 'install-dashboards.sh'), 'utf8')), 'menu entry and installer');
    ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  } finally { await browser.close(); srv.close(); await e.close(); }
  console.log((bad ? 'FAILED ' : 'ok ') + (n - bad) + '/' + n);
  process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
