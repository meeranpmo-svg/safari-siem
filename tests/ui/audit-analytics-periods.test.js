// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for the period and Excel half of Audit Analytics (dashboards/server/audit-analytics.html) against the REAL ITAM engine
// over a SYNTHETIC payroll: two months imported as Excel workbooks into a series through the dialog, the series listed, "Period to
// period" offers the previous month first, the run shows new / gone / changed with the changed IBAN on top, a hostile name stays
// text, the exceptions export to Excel (the download is a real workbook) and come back with decisions through "Import decisions"
// (applied and refused lines listed), the script form offers "Latest of series" and the on-import / monthly schedules.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node audit-analytics-periods.test.js
const http = require('http'), fs = require('fs'), os = require('os'), path = require('path'), vm = require('vm');
const ITAM = path.join(__dirname, '..', '..', 'backend', 'itam'), DASH = path.join(__dirname, '..', '..', 'ui');
const H = require(path.join(ITAM, 'tests', 'helpers'));
const { readXlsx } = require(path.join(ITAM, 'engine', 'xlsx-read'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const XSS = '<img src=x onerror="window.__xss=1">';
const OP = { user: 'nora.syn', role: 'operator' };
const XL = (() => { const w = { TextEncoder, Blob }; w.window = w; vm.runInNewContext(fs.readFileSync(path.join(DASH, 'vendor', 'zyb-xlsx.js'), 'utf8'), w); return w.zybXlsx; })();
const COLS = [{ h: 'emp_id' }, { h: 'name' }, { h: 'iban' }, { h: 'basic', t: 'n' }, { h: 'dept' }, { h: 'paid_on', t: 'd' }];
const JAN = [['E001', 'Synthetic One', 'SA00 0001', 9000, 'Claims', '2027-01-27'], ['E002', XSS, 'SA00 0002', 10000, 'Finance', '2027-01-27'], ['E003', 'Synthetic Three', 'SA00 0003', 8000, 'IT', '2027-01-27'], ['E004', 'Synthetic Four', 'SA00 0004', 7000, 'IT', '2027-01-27']];
const FEB = [['E001', 'Synthetic One', 'SA00 0001', 9000, 'Claims', '2027-02-24'], ['E002', XSS, 'SA99 9999', 14000, 'Finance', '2027-02-24'], ['E003', 'Synthetic Three', 'SA00 0003', 8240, 'IT', '2027-02-24'], ['E005', XSS, 'SA00 0005', 6000, 'Claims', '2027-02-24']];
const book = async (file, columns, rows) => { fs.writeFileSync(file, Buffer.from(await XL.build([{ name: 'Sheet', columns, rows }], { title: 'synthetic' }).arrayBuffer())); return file; };

(async () => {
  const e = await H.startApp({ noAi: true });
  require(path.join(ITAM, 'engine/duty')).registerDuty(e.app.srv, e.app, { noTimer: true });
  const TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'aa-periods-'));
  const jan = await book(path.join(TMP, 'payroll-2027-01.xlsx'), COLS, JAN), feb = await book(path.join(TMP, 'payroll-2027-02.xlsx'), COLS, FEB);
  const srv = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://x'), json = (c, b2) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b2)); };
    if (u.pathname === '/dashboards/whoami.json') return json(200, OP);
    if (u.pathname.startsWith('/api/itam/')) {
      const h = Object.assign({}, req.headers, { 'x-sentra-proxy-secret': H.SECRET, 'x-auth-user': OP.user, 'x-auth-role': OP.role });
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
  try {
    const p = await browser.newPage({ viewport: { width: 1400, height: 950 }, acceptDownloads: true }); p.on('pageerror', (x) => errs.push(x.message));
    p.on('dialog', (d) => { errs.push('dialog: ' + d.message()); d.dismiss(); });
    await p.goto(base + 'audit-analytics.html?standalone=1'); await p.waitForSelector('[data-ds="src:assets"]', { timeout: 15000 });
    const imp = async (file, name, period) => { await p.click('#imp'); await p.setInputFiles('#if-file', file); await p.fill('#if-name', name); await p.fill('#if-purpose', 'monthly payroll review (synthetic)'); await p.fill('#if-series', 'Payroll'); await p.fill('#if-period', period); await p.click('#if-go'); };
    await imp(jan, 'Payroll January (synthetic)', '2027-01');
    ok(await wait(p, () => /Payroll January/.test(document.getElementById('dsh').textContent) && document.querySelectorAll('#prof tbody tr').length === 6), 'an Excel workbook imported and profiled (6 columns)');
    await imp(feb, 'Payroll February (synthetic)', '2027-02');
    ok(await wait(p, () => /Payroll February/.test(document.getElementById('dsh').textContent)), 'the second month imported');
    ok(await wait(p, () => /payroll 2027-02/.test(document.getElementById('dsl').textContent) && /latest 2027-02 · previous 2027-01/.test(document.getElementById('dsl').textContent) && /Excel/.test(document.getElementById('dsl').textContent)), 'the series and its periods are listed');
    // this month against the last
    await p.selectOption('#rf-test', 'compare');
    ok(/previous period/.test(await p.$eval('#rf-other', (s) => s.options[s.selectedIndex].textContent)), 'the previous month is offered first');
    for (const c of ['name', 'iban', 'basic', 'dept']) await p.check('#rf-watch input[value="' + c + '"]');
    await p.selectOption('#rf-key', 'emp_id'); await p.selectOption('#rf-amount', 'basic'); await p.click('#rf button[type=submit]');
    ok(await wait(p, () => /1 new, 1 gone, 2 changed, 1 unchanged/.test(document.getElementById('ress').textContent)), 'new, gone, changed counted');
    ok(/1 new/.test(await p.textContent('#ress')) && /2 changed/.test(await p.textContent('#ress')), 'the counts as badges');
    const first = await p.$eval('#resx tbody tr', (r) => r.textContent); ok(/changed/.test(first) && /iban changed/.test(first) && /pay rose in the same period/.test(first), 'the changed IBAN with a pay rise is first');
    ok(await p.evaluate(() => !window.__xss) && /<img/.test(await p.textContent('#resx')), 'a hostile name stays text');
    // the exceptions go to Excel ...
    const [dl] = await Promise.all([p.waitForEvent('download'), p.click('#rxx')]); ok(/^audit-analytics-AAR-\d{4}\.xlsx$/.test(dl.suggestedFilename()), 'Excel export: ' + dl.suggestedFilename());
    const got = path.join(TMP, 'got.xlsx'); await dl.saveAs(got); const X = readXlsx(fs.readFileSync(got));
    ok(X.fields.slice(0, 4).join() === 'run,exception,row,why' && X.rows.length === 4, 'the download is a real workbook with the exceptions');
    // ... and come back with the auditee's decisions
    const di = X.fields.indexOf('decision'), ni = X.fields.indexOf('note');
    const rows = X.rows.map((r) => X.fields.map((f) => r[f])); rows[0][di] = 'Finding'; rows[0][ni] = 'no HR request for the IBAN change (synthetic)'; rows[1][di] = 'explained'; rows[1][ni] = 'joiner letter (synthetic)'; rows[2][di] = 'maybe'; rows[2][ni] = 'x';
    const back = await book(path.join(TMP, 'back.xlsx'), X.fields.map((h) => ({ h, t: h === 'exception' || h === 'row' ? 'n' : 's' })), rows);
    await p.click('#rxi').catch(() => {}); await p.setInputFiles('#dfile', back);
    ok(await wait(p, () => /Decisions imported/.test((document.getElementById('zd') || {}).textContent || '') && /Applied\s*2/.test(document.getElementById('zd').textContent) && /decision "maybe"/.test(document.getElementById('zd').textContent)), 'decisions applied, the bad line named');
    await p.evaluate(() => window.zybDetail.close());
    ok(await wait(p, () => /for a finding/.test(document.getElementById('resx').textContent) && /explained/.test(document.getElementById('resx').textContent)), 'the run shows the imported decisions');
    // a script on the series
    await p.click('[data-tab="sc"]');
    ok(await p.$eval('#sf-ds', (s) => [...s.options].some((o) => o.value === 'latest:payroll')), 'the script form offers the latest of the series');
    ok(await p.$eval('#sf-sched', (s) => ['monthly', 'on_import'].every((v) => [...s.options].some((o) => o.value === v))), 'monthly and on-import schedules');
    await p.selectOption('#sf-ds', 'latest:payroll');
    ok(/previous:payroll/.test(await p.inputValue('#sf-steps')), 'steps from this session read previous:payroll');
    const inst = fs.readFileSync(path.join(DASH, 'install-dashboards.sh'), 'utf8'); ok(/vendor\/zyb-xlsx\.js/.test(inst), 'the Excel writer is installed');
  } finally { await browser.close(); srv.close(); await e.close(); fs.rmSync(TMP, { recursive: true, force: true }); }
  ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks');
  process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
