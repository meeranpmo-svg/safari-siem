// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for Audit Analytics (dashboards/server/audit-analytics.html) against the REAL ITAM engine (engine/audit-analytics.js,
// engine/audit-engage.js) over a SYNTHETIC payments file: import through the dialog, the column profile and suggested tests, a
// suggestion run in one click (duplicates), a hostile value stays text, Benford with its chart, a sample, an exception decided in the
// drawer, a review refused for the person who ran it and recorded by a second person, a finding raised into an IT Audit engagement,
// the CSV export, the command log, a script saved, a viewer refused without a broken page, the menu has the page under Audit.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node audit-analytics.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const ITAM = path.join(__dirname, '..', '..', 'backend', 'itam'), DASH = path.join(__dirname, '..', '..', 'ui');
const H = require(path.join(ITAM, 'tests', 'helpers'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const XSS = '<img src=x onerror=alert(1)>';
const OP = { user: 'nora.syn', role: 'operator' }, LEAD = { user: 'laila.syn', role: 'operator' }, HEAD = { user: 'hana.syn', role: 'operator' }, OWNER = { user: 'omar.syn', role: 'operator' };
const ADM = { user: 'syed', role: 'admin' }, VIEW = { user: 'vera.syn', role: 'viewer' };

function payments() {
  let a = 7; const r = () => { a = (a * 1103515245 + 12345) % 2147483648; return a / 2147483648; };
  const V = ['Synthetic Trading Co', 'Example Supplies LLC', 'Test Services Est', 'Demo Logistics'], rows = ['voucher,vendor,amount,paid_on,dept'];
  let v = 1000;
  for (let i = 0; i < 300; i++) { v++; if (v === 1050) v = 1051; rows.push([v, V[i % 4], Math.round(Math.pow(10, 1 + r() * 4) * 100) / 100, '2026-' + String(1 + (i % 12)).padStart(2, '0') + '-15', i % 3 ? 'Claims' : 'Finance'].join(',')); }
  rows.push([++v, '"' + XSS + '"', '4999.00', '2026-12-01', 'Claims'].join(','), [++v, '"' + XSS + '"', '4999.00', '2026-12-01', 'Claims'].join(','));
  return rows.join('\n') + '\n';
}

(async () => {
  const e = await H.startApp({ noAi: true });
  require(path.join(ITAM, 'engine/duty')).registerDuty(e.app.srv, e.app, { noTimer: true });
  const api = async (who, m, p, body) => { const r = await e.req(m, p, Object.assign(body !== undefined ? { body } : {}, who)); if (r.status !== 200) throw new Error(p + ': ' + r.raw); return r.json; };
  await api(ADM, 'POST', '/ia/profile', { head_of_audit: HEAD.user, auditors: [LEAD.user] });
  const today = new Date().toISOString().slice(0, 10), later = new Date(Date.now() + 20 * 86400000).toISOString().slice(0, 10);
  const eng = await api(LEAD, 'POST', '/ia/engagements', { title: 'Payments (synthetic)', area: 'change', auditee_dept: 'Finance', auditee_owner: OWNER.user, lead: LEAD.user, objectives: ['each invoice paid once'], scope: 's', start: today, fieldwork_end: later, report_due: later });
  await (await api(LEAD, 'POST', '/ia/engagements/' + eng.id + '/prior-none', { note: 'first audit of this area (synthetic)' }), api(LEAD, 'POST', '/ia/engagements/' + eng.id + '/advance', { to: 'fieldwork' }));
  const CSV = path.join(require('os').tmpdir(), 'aa-synthetic-payments.csv'); fs.writeFileSync(CSV, payments());
  let WHO = OP;
  const srv = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://x'), json = (c, b2) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b2)); };
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
  const base = 'http://127.0.0.1:' + srv.address().port + '/';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  const wait = (p, fn, arg) => p.waitForFunction(fn, arg, { timeout: 10000 }).then(() => true, () => false);
  const zd = (p, re) => wait(p, (src) => new RegExp(src).test((document.getElementById('zd') || {}).textContent || ''), re.source);
  try {
    const p = await browser.newPage({ viewport: { width: 1400, height: 950 }, acceptDownloads: true }); p.on('pageerror', (x) => errs.push(x.message));
    p.on('dialog', (d) => { errs.push('dialog: ' + d.message()); d.dismiss(); });
    await p.goto(base + 'audit-analytics.html?standalone=1'); await p.waitForSelector('[data-ds="src:assets"]', { timeout: 15000 });
    ok((await p.$$('[data-ds^="src:"]')).length === 10, 'ten platform datasets');
    ok(/not proof of wrongdoing/.test(await p.textContent('.alert-info')) && /Runs in the command log/.test(await p.textContent('#kpis')), 'indicators, not proof; KPIs');
    // import through the dialog
    await p.click('#imp'); await p.setInputFiles('#if-file', CSV); await p.fill('#if-name', 'Synthetic payments 2026'); await p.fill('#if-purpose', 'duplicate payment review (synthetic)'); await p.click('#if-go');
    ok(await wait(p, () => /Synthetic payments 2026/.test(document.getElementById('dsh').textContent) && document.querySelectorAll('#prof tbody tr').length === 5), 'imported and profiled (5 columns)');
    ok(/number/.test(await p.textContent('#prof')) && /date/.test(await p.textContent('#prof')), 'column types');
    ok((await p.$$('[data-sug]')).length >= 5, 'suggested tests');
    // a suggestion in one click
    const dupIdx = await p.$$eval('[data-sug]', (b) => b.findIndex((x) => /^.*Duplicates/.test(x.textContent)));
    ok(dupIdx >= 0, 'a duplicates suggestion'); await (await p.$$('[data-sug]'))[dupIdx].click();
    ok(await wait(p, () => /duplicate group/.test(document.getElementById('ress').textContent) && document.querySelectorAll('#resx tbody tr').length === 2), 'duplicates: one group, two rows');
    ok(!(await p.$('#resx img')) && /<img/.test(await p.textContent('#resx')), 'a hostile value stays text');
    // Benford with its chart
    await p.selectOption('#rf-test', 'benford'); await p.selectOption('#rf-field', 'amount'); await p.click('#rf button[type=submit]');
    ok(await wait(p, () => /chi-square/.test(document.getElementById('ress').textContent) && !document.getElementById('resch').hidden), 'Benford with its chart');
    if (process.env.SHOT) await p.screenshot({ path: process.env.SHOT, fullPage: true });
    // a sample: attribute size 59
    await p.selectOption('#rf-test', 'sample'); await p.fill('#rf-seed', '42'); await p.click('#rf button[type=submit]');
    ok(await wait(p, () => /59 items/.test(document.getElementById('ress').textContent) && /seed 42/.test(document.getElementById('ress').textContent)), 'attribute sample: 59 items, seed recorded');
    // a validation error is shown with the field named
    await p.selectOption('#rf-test', 'duplicates'); await p.click('#rf button[type=submit]');
    ok(await wait(p, () => /keys/.test(document.getElementById('rf-msg').textContent)), 'validation names the field');
    // the duplicates run from the log: decide an exception, refuse a self-review
    await p.click('[data-tab="log"]'); ok(await wait(p, () => document.querySelectorAll('#logt tr[data-run]').length === 3), 'three runs in the command log');
    const dupRun = await p.$$eval('#logt tr[data-run]', (r) => (r.find((x) => /Duplicates/.test(x.textContent)) || {}).getAttribute && r.find((x) => /Duplicates/.test(x.textContent)).getAttribute('data-run'));
    await p.click('#logt tr[data-run="' + dupRun + '"]'); ok(await wait(p, () => !document.getElementById('t-wb').hidden && document.querySelectorAll('[data-dx]').length === 2), 'the run reopens from the log');
    await p.click('[data-dx="0"]'); await p.fill('#xd-n', 'the same invoice paid twice (synthetic)'); await p.click('[data-dec="finding"]');
    ok(await wait(p, () => /for a finding/.test(document.getElementById('resx').textContent)), 'exception decided');
    await p.click('#rv'); await p.fill('#rvf-n', 'self'); await p.click('#rvf button[type=submit]'); ok(await zd(p, /different person/), 'a self-review is refused with the reason');
    await p.keyboard.press('Escape');
    // the lead reviews and raises the finding
    WHO = LEAD; await p.reload(); await p.waitForSelector('[data-tab="log"]'); await p.click('[data-tab="log"]'); await p.waitForSelector('#logt tr[data-run]'); await p.click('#logt tr[data-run="' + dupRun + '"]');
    await p.waitForSelector('#rv'); await p.click('#rv'); await p.fill('#rvf-n', 'parameters fit the objective; re-performed (synthetic)'); await p.click('#rvf button[type=submit]');
    ok(await wait(p, () => /Reviewed by/.test(document.getElementById('ress').textContent)), 'reviewed by a second person');
    await p.click('#rfnd'); for (const [k, v] of [['title', 'Duplicate payment (synthetic)'], ['criteria', 'each invoice is paid once'], ['cause', 'no duplicate check'], ['effect', 'overpayment'], ['recommendation', 'add a duplicate check'], ['eng', eng.id], ['owner', OWNER.user]]) await p.fill('#ff-' + k, v);
    await p.click('#ff button[type=submit]'); ok(await wait(p, () => /Raised as finding/.test(document.getElementById('ress').textContent)), 'finding raised');
    const f = e.app.addons.auditEngage.listFindings({}).find((x) => x.engagement === eng.id); ok(f && f.raised_by === LEAD.user && /re-performable/.test(f.condition), 'a real finding in the engagement, raised by the auditor');
    const [dl] = await Promise.all([p.waitForEvent('download'), p.click('#rx')]); ok(/^audit-analytics-AAR-\d{4}\.csv$/.test(dl.suggestedFilename()), 'CSV export');
    // a script
    await p.click('[data-tab="sc"]'); await p.fill('#sf-name', 'Payments weekly (synthetic)');
    const dsId = await p.$eval('#sf-ds', (s) => [...s.options].find((o) => /Synthetic payments/.test(o.textContent)).value); await p.selectOption('#sf-ds', dsId);
    await p.fill('#sf-steps', JSON.stringify([{ test: 'gaps', params: { field: 'voucher' } }])); await p.selectOption('#sf-sched', 'weekly'); await p.click('#sf button[type=submit]');
    ok(await wait(p, () => /Payments weekly/.test(document.getElementById('sct').textContent) && /waiting for a second person/.test(document.getElementById('sct').textContent)), 'script saved, waiting for approval');
    await p.click('[data-tab="ai"]'); ok(await wait(p, () => /Not available/.test(document.getElementById('ais').textContent)), 'advisor off until allowed');
    ok(await p.evaluate(() => { const a = (window.ZYB_NAV || []).find((x) => x.id === 'aud'); return !!(a && a.pages.some((x) => x.h === 'audit-analytics.html')); }), 'the menu has the page under Audit');
    WHO = VIEW; await p.reload(); await p.waitForTimeout(1500);
    ok(/operator role|named person|HTTP 403|not loaded/.test(await p.textContent('body')) && !(await p.$('[data-ds]')), 'a viewer is refused and the page says why');
  } finally { await browser.close(); srv.close(); await e.close(); try { fs.unlinkSync(CSV); } catch (x) { /* the temporary synthetic file may already be gone */ } }
  ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks');
  process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
