// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Framework Crosswalk (crosswalk.html) and Gap Analysis - All Frameworks (gap-analysis.html) against the REAL ITAM engines (NCA ECC,
// SAMA CSF / IA, ISO 27001, NDMO, PDPL assessment, engine/crosswalk.js) over SYNTHETIC facts: framework cards with their share and
// the PDPL "no approved self-assessment" state; the crosswalk matrix, its chips and search; a line's detail; suggestions (operator
// sees them, only an administrator maps), an administrator maps and removes; the gap work items, the 2+ frameworks chip, the
// priority breakdown, a plan saved (owner + date), not assessed listed apart, Send to GRC, Excel with content; a viewer gets no
// Excel / GRC / plan form and no analyst; menu entries, portal redirects and the installer.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node crosswalk.test.js
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
    const ctx = await browser.newContext({ viewport: { width: 1500, height: 1000 }, acceptDownloads: true });
    // ---- crosswalk
    let p = await page(ctx, 'crosswalk.html');
    ok((await p.$$('#fws .fw')).length === 7 && /NCA ECC/.test(await p.textContent('#fws')) && /\d+%/.test(await p.textContent('#fws')), 'seven framework cards with a share (NCA ECC, SAMA, ISO 27001, NDMO, PDPL, SOC 2, ISO/IEC 42001)');
    ok(/no approved PDPL self-assessment/i.test(await p.textContent('#fws')), 'PDPL without an approved assessment says so');
    const rows = (await p.$$('#mx tr[data-f]')).length; ok(rows >= 40, 'crosswalk lines: ' + rows);
    const dis = Number(await p.evaluate(() => [...document.querySelectorAll('#kpis .kpi')].find((k) => /Disagreements/.test(k.textContent)).querySelector('.n').textContent));
    await p.click('[data-ch="disagree"]'); ok((await p.$$('#mx tr[data-f]')).length === dis, 'the Disagreements chip shows exactly the counted lines (' + dis + ')');
    // the tiles open what they count (they were plain boxes)
    const kc = await p.$$eval('#kpis button.kpi[data-kgo]', (b) => b.map((x) => x.getAttribute('data-kgo')));
    ok(kc.join() === 'all,multi,disagree,gap,met,all,all,#unm', 'every crosswalk tile opens its list: ' + kc.join(' '));
    await p.click('#kpis button.kpi[data-kgo="all"]'); await p.click('#kpis button.kpi[data-kgo="disagree"]');
    ok(await wait(p, (n) => document.querySelector('[data-ch="disagree"]').getAttribute('aria-pressed') === 'true' && document.querySelectorAll('#mx tr[data-f]').length === n, dis), 'the Disagreements tile shows exactly those ' + dis + ' lines');
    await p.click('#kpis button.kpi[data-kgo="all"]'); ok(await wait(p, () => document.querySelector('[data-ch="all"]').getAttribute('aria-pressed') === 'true'), 'Crosswalk lines: every line again');
    await p.click('[data-ch="all"]'); await p.fill('#q', 'ZS-1-1-01'); ok(await wait(p, () => document.querySelectorAll('#mx tr[data-f]').length === 1), 'search narrows to one control');
    await p.click('#mx tr[data-f]'); ok(await wait(p, () => !document.getElementById('dlg').hidden && /NCA ECC/.test(document.getElementById('dlgb').textContent)), 'line detail');
    await p.keyboard.press('Escape'); await p.fill('#q', '');
    ok(await wait(p, () => document.querySelector('#sug table') || /No suggestion/.test(document.getElementById('sug').textContent)), 'suggestions shown to an operator');
    ok(!(await p.$('[data-map]')), 'an operator sees suggestions but cannot map');
    // administrator maps a suggestion, then removes it
    WHO = { user: 'syed', role: 'admin' }; const a = await page(ctx, 'crosswalk.html');
    if (await wait(a, () => document.querySelector('[data-map]'))) {
      const id = (await a.getAttribute('[data-map]', 'data-map')).split('|')[1];
      await a.click('[data-map]'); ok(await toast(a, 'Mapped ' + id.replace(/\./g, '\\.')), 'administrator mapped ' + id);
      ok(await wait(a, (i) => document.getElementById('maps').textContent.includes(i) && /syed/.test(document.getElementById('maps').textContent), id), 'mapping listed with who');
      await a.click('[data-unmap]'); ok(await toast(a, 'Mapping removed'), 'mapping removed');
    } else ok(false, 'a suggestion to map');
    // ---- gap analysis
    WHO = { user: 'nora.syn', role: 'operator' }; p = await page(ctx, 'gap-analysis.html');
    ok((await p.$$('#wl tr[data-f]')).length > 0, 'work items listed');
    ok(/\d+ \/ 7\s*Frameworks read/.test((await p.textContent('#kpis')).replace(/\s+/g, ' ')), 'frameworks read out of the seven, not a fixed five: ' + (await p.textContent('#kpis')).replace(/\s+/g, ' '));
    // the tiles open what they count (they were plain boxes): the work list filtered, or the not-assessed / framework parts
    const kg = await p.$$eval('#kpis button.kpi[data-kgo]', (b) => b.map((x) => x.getAttribute('data-kgo')));
    ok(kg.join() === 'all,multi,all,high,unowned,overdue,#nasum,#fws', 'every tile opens its list: ' + kg.join(' '));
    await p.click('#kpis button.kpi[data-kgo="unowned"]'); ok(await wait(p, () => document.querySelector('[data-ch="unowned"]').getAttribute('aria-pressed') === 'true' && [...document.querySelectorAll('#wl tr[data-f]')].every((r) => !/khalid\.syn/.test(r.textContent))), 'No owner tile: the work list filtered to items without an owner');
    await p.click('#kpis button.kpi[data-kgo="all"]'); ok(await wait(p, () => document.querySelector('[data-ch="all"]').getAttribute('aria-pressed') === 'true'), 'Work items tile: the whole list');
    await p.click('[data-ch="multi"]'); ok(await wait(p, () => { const r = document.querySelectorAll('#wl tr[data-f]'); return r.length > 0 && [...r].every((x) => x.querySelectorAll('td:nth-child(3) .pill').length >= 2); }), '2+ frameworks chip: every row closes 2+ references');
    await p.click('#wl tr[data-f]'); ok(await wait(p, () => /Priority \d+ - why/.test(document.getElementById('dlgb').textContent) && /closes the gap in \d frameworks/.test(document.getElementById('dlgb').textContent)), 'priority breakdown names the leverage');
    const due = new Date(Date.now() + 30 * 86400000).toISOString().slice(0, 10);
    await p.fill('#planf [name=owner]', 'khalid.syn'); await p.fill('#planf [name=due]', due); await p.click('#planf button[type=submit]');
    ok(await toast(p, 'Plan saved'), 'plan saved'); ok(await wait(p, () => /khalid\.syn/.test(document.getElementById('wl').textContent)), 'owner shown in the list');
    await p.keyboard.press('Escape');
    ok(/not assessed - show/.test(await p.textContent('#nasum')), 'not assessed listed apart');
    ok(/needs 3 daily snapshots|target reached|not improving|\d{4}-\d{2}-\d{2}/.test(await p.textContent('#fc')), 'forecast says what it needs');
    await p.click('#grc'); ok(await toast(p, 'ECC: (sent|failed)'), 'Send to GRC runs every engine and says what happened');
    const [dl] = await Promise.all([p.waitForEvent('download', { timeout: 15000 }), p.click('#xls')]);
    ok(/^gap-analysis-all-frameworks-\d{4}-\d{2}-\d{2}\.xlsx$/.test(dl.suggestedFilename()), 'Excel');
    { const x = fs.readFileSync(await dl.path(), 'latin1'); ok(x.includes('Frameworks closed') && x.includes('khalid.syn') && x.includes('not assessed'), 'Excel holds the work items, the owner and the not-assessed rows'); }
    if (process.env.SHOT) await p.screenshot({ path: process.env.SHOT, fullPage: true });   // optional: a picture for review
    // viewer
    WHO = { user: 'vera.syn', role: 'viewer' }; const v = await page(ctx, 'gap-analysis.html');
    ok(!(await v.isVisible('#xls')) && !(await v.isVisible('#grc')), 'viewer: no Excel, no Send to GRC');
    await v.click('#wl tr[data-f]'); ok(await wait(v, () => !document.getElementById('dlg').hidden) && !(await v.$('#planf')), 'viewer: no plan form');
    ok(/shown to operators and administrators/.test(await v.textContent('#ai')), 'viewer: no analyst');
    const nav = fs.readFileSync(path.join(DASH, 'vendor', 'zyb-nav.js'), 'utf8'), inst = fs.readFileSync(path.join(DASH, 'install-dashboards.sh'), 'utf8');
    ok(/"h": "crosswalk.html"/.test(nav) && /"h": "gap-analysis.html"/.test(nav) && /crosswalk\.html/.test(inst) && /gap-analysis\.html/.test(inst), 'menu entries and installer');
    const menu = fs.readFileSync(path.join(DASH, 'vendor', 'zyb-menu.js'), 'utf8'), early = fs.readFileSync(path.join(DASH, 'vendor', 'zyb-early.js'), 'utf8');
    ok(/crosswalk: 'crosswalk\.html', gapall: 'gap-analysis\.html'/.test(menu) && /crosswalk: 'crosswalk\.html', gapall: 'gap-analysis\.html'/.test(early), 'the portal\'s Framework Crosswalk and Gap Analysis open these pages');
    ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  } finally { await browser.close(); srv.close(); await e.close(); }
  console.log((bad ? 'FAILED ' : 'ok ') + (n - bad) + '/' + n);
  process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
