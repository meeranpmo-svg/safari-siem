// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for the IT Budget in Excel (dashboards/server/budget.html) against the REAL ITAM engine (engine/budget.js), SYNTHETIC
// lines: "Excel" downloads the budget (sheet Budget, one row per line with its Line ID) and it reads back with the engine's own
// reader; the edited workbook chosen on "Excel import" shows what will change and nothing is saved until Apply; a row that needs a
// note is listed with its row number and there is no Apply; last year's budget is accepted as .xlsx; after the year-end rollover
// the page says the year is closed until an administrator marks the carry-over reviewed; a viewer exports but cannot import or
// sign off; a hostile title stays text; no page error.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node budget-excel.test.js
const http = require('http'), fs = require('fs'), os = require('os'), path = require('path'), vm = require('vm');
const ITAM = path.join(__dirname, '..', '..', 'backend', 'itam'), DASH = path.join(__dirname, '..', '..', 'ui');
const H = require(path.join(ITAM, 'tests', 'helpers'));
const { readXlsx } = require(path.join(ITAM, 'engine', 'xlsx-read'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const XSS = '<img src=x onerror="window.__xss=1">';
const XL = (() => { const w = { TextEncoder, Blob }; w.window = w; vm.runInNewContext(fs.readFileSync(path.join(DASH, 'vendor', 'zyb-xlsx.js'), 'utf8'), w); return w.zybXlsx; })();
const save = async (file, sheets) => { fs.writeFileSync(file, Buffer.from(await XL.build(sheets, { title: 'synthetic' }).arrayBuffer())); return file; };

(async () => {
  const e = await H.startApp({ noAi: true });
  const clock = { t: Date.parse('2026-11-10T08:00:00Z') };
  require(path.join(ITAM, 'engine/duty')).registerDuty(e.app.srv, e.app, { noTimer: true, now: () => clock.t });
  const B = require(path.join(ITAM, 'engine/budget')).registerBudget(e.app.srv, e.app, { noTimer: true, now: () => clock.t });
  const A1 = { user: 'syed', role: 'admin' };
  B.putSettings({ fy: 2027 }, A1);
  B.saveLine({ title: 'Backup appliance SYN', envelope: 'it_ops', area: 'infrastructure', kind: 'capex', amount: 300000 }, A1);
  B.saveLine({ title: 'Firewall SYN ' + XSS, envelope: 'cyber', kind: 'capex', amount: 250000 }, A1);
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'budget-xl-'));
  let WHO = { user: 'syed', role: 'admin' };
  const web = http.createServer((req, res) => {
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
  await new Promise((r) => web.listen(0, '127.0.0.1', r));
  const url = 'http://127.0.0.1:' + web.address().port + '/dashboards/budget.html?standalone=1';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  const wait = (p, fn, arg) => p.waitForFunction(fn, arg, { timeout: 15000 }).then(() => true, () => false);
  try {
    const ctx = await browser.newContext({ acceptDownloads: true, viewport: { width: 1400, height: 1000 } });
    const p = await ctx.newPage(); p.on('pageerror', (x) => errs.push(x.message));
    await p.goto(url); ok(await wait(p, () => /Backup appliance SYN/.test(document.getElementById('lines').textContent)), 'the budget loads');

    // export: the workbook reads back with the engine's own reader
    const [dl] = await Promise.all([p.waitForEvent('download'), p.click('#xl-exp')]);
    ok(dl.suggestedFilename() === 'it-budget-FY2027.xlsx', 'file name: ' + dl.suggestedFilename());
    const X = readXlsx(fs.readFileSync(await dl.path()));
    ok(['Line ID', 'FY', 'Envelope', 'Type', 'Title', 'Amount', 'Priority', 'Status', 'Due', 'Note'].every((h) => X.fields.includes(h)), 'the Budget sheet has the round-trip columns: ' + X.fields.join(', '));
    ok(X.rows.length === B.build().lines.length && X.rows.every((r) => r['Line ID'] && r.FY === '2027'), 'one row per line, each with its Line ID');
    const bak = X.rows.find((r) => r.Title === 'Backup appliance SYN');
    ok(bak && bak.Amount === '300000' && bak.Envelope === 'IT Operations' && bak.Type === 'CAPEX', 'amount, envelope and type as numbers / words: ' + JSON.stringify(bak));
    ok(X.rows.some((r) => r.Title === 'Firewall SYN ' + XSS), 'a hostile title is exported as text');

    // edited in Excel and chosen on "Excel import": the preview, then Apply
    const fields = X.fields, asRows = (list) => list.map((r) => fields.map((f) => r[f]));
    const edited = X.rows.map((r) => Object.assign({}, r));
    Object.assign(edited.find((r) => r.Title === 'Backup appliance SYN'), { Amount: '320000', Status: 'approved' });
    edited.push(Object.assign(Object.fromEntries(fields.map((f) => [f, ''])), { FY: '2027', Envelope: 'IT Operations', Type: 'CAPEX', Title: 'Network refresh SYN', Amount: '900000', Priority: 'must', Reason: 'core switches end of support' }));
    const cols = fields.map((h) => ({ h }));
    await p.click('[data-tab="xl"]');
    ok(await p.isVisible('#xl-file'), 'an administrator can choose a workbook');
    const wrong = edited.map((r) => Object.assign({}, r)); wrong.find((r) => r.Title === 'Backup appliance SYN').Status = 'rejected';
    await p.setInputFiles('#xl-file', await save(path.join(tmp, 'wrong.xlsx'), [{ name: 'Budget', columns: cols, rows: asRows(wrong) }]));
    ok(await wait(p, () => !!document.querySelector('#xl-err tbody tr')), 'a row that needs fixing is listed');
    ok(/Note with the reason/.test(await p.textContent('#xl-err')) && !(await p.$('#xl-go')), 'with its reason, and there is no Apply: ' + (await p.textContent('#xl-prev')).slice(0, 200));
    await p.setInputFiles('#xl-file', await save(path.join(tmp, 'edited.xlsx'), [{ name: 'Budget', columns: cols, rows: asRows(edited) }]));
    ok(await wait(p, () => document.querySelectorAll('#xl-chg tbody tr').length === 2), 'two changes are shown');
    const chg = await p.textContent('#xl-chg');
    ok(/Amount: 300,000 → 320,000/.test(chg) && /Status: proposed → approved/.test(chg) && /new Network refresh SYN/.test(chg), 'what will change: ' + chg.replace(/\s+/g, ' ').slice(0, 300));
    ok(B.build().lines.find((l) => l.title === 'Backup appliance SYN').amount === 300000, 'nothing is saved before Apply');
    await p.click('#xl-go'); ok(await wait(p, () => !!document.getElementById('xl-done')), 'applied');
    const L = B.build().lines;
    ok(L.find((l) => l.title === 'Backup appliance SYN').amount === 320000 && L.find((l) => l.title === 'Backup appliance SYN').status === 'approved' && L.some((l) => l.title === 'Network refresh SYN' && l.amount === 900000), 'stored in the budget');
    ok(e.app.store.auditTail(200).some((a) => a.action === 'budget.import_workbook' && a.by === 'syed' && a.detail.file === 'edited.xlsx'), 'audited with the file name');

    // last year's budget as .xlsx
    await p.click('[data-tab="prev"]'); await p.fill('#p-fy', '2026');
    await p.setInputFiles('#p-file', await save(path.join(tmp, 'fy2026.xlsx'), [{ name: 'FY2026', columns: ['Item', 'Budget', 'Type', 'Approved', 'Spent', 'Status'].map((h) => ({ h })), rows: [['Core switch replacement SYN', 'IT Operations', 'CAPEX', '1200000', '450000', 'In progress']] }]));
    ok(await wait(p, () => !document.getElementById('p-go').hidden), 'Import is offered for the workbook');
    await p.click('#p-go'); ok(await wait(p, () => /FY2026 · 1 lines imported/.test(document.getElementById('pvs').textContent)), 'imported');
    ok(B.build().lines.some((l) => l.source === 'carryover' && l.amount === 750000), 'it carries over approved minus spent');

    // the year-end rollover: the page says so until an administrator signs off the carry-over
    B.putSettings({ fy: 2027 }, A1); clock.t = Date.parse('2028-01-02T06:00:00Z'); B.rollover();
    await p.reload(); ok(await wait(p, () => !!document.getElementById('roll-card')), 'the closed year is announced');
    ok(/FY2027 is closed - check the carry-over/.test(await p.textContent('#roll-card')) && /automatically at year end/.test(await p.textContent('#roll-card')), 'with what happened: ' + (await p.textContent('#roll-card')).slice(0, 160));
    ok(/FY2028/.test(await p.textContent('#fyh')), 'planning moved to FY2028');
    await p.click('[data-tab="prev"]'); ok(/FY2027/.test(await p.textContent('#p-years')), 'the closed year is listed');

    // a viewer: exports, cannot import or sign off
    WHO = { user: 'vera.syn', role: 'viewer' }; await p.reload(); await wait(p, () => !!document.getElementById('roll-card'));
    await p.click('[data-tab="xl"]');
    ok(await p.isHidden('#xl-form') && await p.isVisible('#xl-exp2') && !(await p.$('#roll-ok')), 'a viewer exports only');
    WHO = { user: 'syed', role: 'admin' }; await p.reload(); await wait(p, () => !!document.getElementById('roll-ok'));
    await p.click('#roll-ok'); ok(await wait(p, () => !document.getElementById('roll-card')), 'marked reviewed');
    ok(e.app.store.auditTail(200).some((a) => a.action === 'budget.rollover_reviewed' && a.by === 'syed'), 'the sign-off is audited');
    ok(await p.evaluate(() => window.__xss === undefined), 'no script from a title ran');
  } finally { await browser.close(); web.close(); await e.close(); fs.rmSync(tmp, { recursive: true, force: true }); }
  ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks'); process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
