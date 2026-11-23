// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for Business Risk (business-risk.html, business-risk-register.html, risk-appetite.html) against the REAL engine
// (engine/business-risk.js) with SYNTHETIC workbooks (backend/itam/tests/brisk-fixture.js): import preview and apply from the page,
// the register with calculated ratings and flags, the drawer, suggestions for a new risk, re-assessment, the RAS import, a value
// refused then recorded with an explanation, bulk reporting, a link, the dashboard heat maps and ML insights, menu, viewer, phone.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node business-risk.test.js   (SHOTS=dir also saves a screenshot of the dashboard)
const http = require('http'), fs = require('fs'), path = require('path');
const ITAM = path.join(__dirname, '..', '..', 'backend', 'itam'), DASH = path.join(__dirname, '..', '..', 'ui');
const H = require(path.join(ITAM, 'tests', 'helpers'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
(async () => {
  const e = await H.startApp({ noAi: true });
  require(path.join(ITAM, 'engine/duty')).registerDuty(e.app.srv, e.app, { noTimer: true, now: () => Date.parse('2026-11-11T08:00:00Z'), python: process.env.PYTHON || 'python3' });
  const F = require(path.join(ITAM, 'tests', 'brisk-fixture'));
  const tmp = fs.mkdtempSync(path.join(require('os').tmpdir(), 'brisk-')), reg = path.join(tmp, 'register-synthetic.xlsx'), ras = path.join(tmp, 'ras-synthetic.xlsx');
  fs.writeFileSync(reg, Buffer.from(await F.registerB64(), 'base64')); fs.writeFileSync(ras, Buffer.from(await F.rasB64(), 'base64'));
  { // Workflow Automation (the real engine): the risk function's DR test evidence late with Backup & DR
    const W = e.app.addons.workflow, col = e.app.store.collection('wf_requests');
    W.settingsSave({ version: 0, functions: { risk: ['adam.syn'] }, teams: { backup: ['bk.syn'] } }, { user: 'syed', role: 'admin', ip: '' });
    const late = W.create({ type: 'dr-test', from: 'risk', title: 'DR test evidence for claims <img src=x onerror=window.__wfx=1>', details: 'last test', priority: 'high' }, { user: 'adam.syn', role: 'admin', ip: '' });
    const lr = col.get(late.id); lr.due = '2026-11-11T07:00:00.000Z'; col.put(lr); }
  let who = { user: 'adam.syn', role: 'admin' };
  const srv = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://x'), json = (code, b) => { res.writeHead(code, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u.pathname === '/dashboards/whoami.json') return json(200, who);
    if (u.pathname.startsWith('/api/itam/')) { const h = Object.assign({}, req.headers, { 'x-sentra-proxy-secret': H.SECRET, 'x-auth-user': who.user, 'x-auth-role': who.role });
      const up = http.request({ host: '127.0.0.1', port: e.port, method: req.method, path: req.url, headers: h }, (r) => { res.writeHead(r.statusCode, r.headers); r.pipe(res); }); req.pipe(up); return; }
    if (u.pathname.startsWith('/api/') || u.pathname === '/') return json(404, { error: 'not in this test' });
    const f = path.join(DASH, u.pathname.replace(/^\/dashboards\//, '/')); if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (err, d) => { if (err) { res.writeHead(404); res.end(); return; } res.writeHead(200, { 'Content-Type': u.pathname.endsWith('.js') ? 'application/javascript' : u.pathname.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port + '/';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  const wait = (p, fn, arg) => p.waitForFunction(fn, arg === undefined ? null : arg, { timeout: 30000 }).then(() => true, () => false);
  const tab = (p, t) => p.click('[data-tab="' + t + '"]');
  const toast = (p, re) => wait(p, (s) => [...document.querySelectorAll('.toast')].some((t) => new RegExp(s).test(t.textContent)), re);
  try {
    const p = await browser.newPage({ viewport: { width: 1400, height: 1000 } }); p.on('pageerror', (x) => errs.push(x.message));
    await p.goto(base + 'business-risk.html?standalone=1');
    ok(await wait(p, () => /No risk register yet/.test(document.getElementById('src').textContent)), 'empty dashboard says what to import');
    // register import from the page
    await p.goto(base + 'business-risk-register.html?standalone=1'); await wait(p, () => /register is empty/.test(document.getElementById('list').textContent));
    await p.click('#imp'); await p.setInputFiles('#file', reg); await p.click('#preview');
    ok(await wait(p, () => /Preview:.*38 risks/.test(document.getElementById('impres').textContent)), 'preview: 38 risks');
    ok(/1 rating\(s\) differ/.test(await p.textContent('#impres')), 'preview names the rating mismatch');
    await p.click('#apply'); ok(await wait(p, () => document.querySelectorAll('tr.row').length === 38), 'imported: 38 rows');
    ok(/Medium \(12\)/.test(await p.textContent('tr.row:has-text("IT-90")')) && /Class II/.test(await p.textContent('tr.row:has-text("IT-90")')), 'IT-90 rated by the methodology');
    await p.selectOption('#fflag', 'solved_untreated'); ok((await p.$$('tr.row')).length === 1, 'filter by flag'); await p.selectOption('#fflag', '');
    // the summary graphics: drawn from the list, and each one a filter
    const rows = () => p.$$eval('tr.row', (x) => x.length);
    const gv = await p.evaluate(() => ({ seg: document.querySelectorAll('#viz [data-f^="fclass|"]').length, st: document.querySelectorAll('#viz [data-f^="fst|"]').length, cells: [...document.querySelectorAll('#viz .mh .c')].reduce((t, c) => t + (parseInt(c.textContent, 10) || 0), 0),
      flags: document.querySelectorAll('#viz .fb').length, stripe: getComputedStyle(document.querySelector('tr.row')).getPropertyValue('--rc').trim(), badge: !!document.querySelector('tr.row .sc') }));
    ok(gv.seg >= 2 && gv.st >= 1 && gv.cells === 38 && gv.flags >= 1 && gv.stripe && gv.badge, 'register graphics: class and status bars, the 5 x 5 grid holds every rated risk, the flag bars, row colour and score badge: ' + JSON.stringify(gv));
    if (process.env.SHOTS) await p.screenshot({ path: path.join(process.env.SHOTS, 'register-list.png') });
    await p.click('#viz [data-f="fclass|2"]'); const fc2 = await p.evaluate(() => ({ v: document.getElementById('fclass').value, rows: [...document.querySelectorAll('tr.row')].map((r) => r.children[5].textContent) }));
    ok(fc2.v === '2' && fc2.rows.length && fc2.rows.every((t) => t === 'Class II'), 'a class segment filters the list: ' + JSON.stringify(fc2).slice(0, 200));
    await p.click('#viz [data-f="fclass|2"]'); ok(await p.$eval('#fclass', (x) => x.value) === '' && (await rows()) === 38, 'clicking it again clears the filter');
    const cell = await p.$('#viz button[data-cell]'); const cv = (await cell.getAttribute('data-cell')).split('|'), cn = parseInt(await cell.textContent(), 10); await cell.click();
    ok((await rows()) === cn && /likelihood \d × impact \d/.test(await p.textContent('#cnt')), 'a grid cell filters the list to its ' + cn + ' risk(s) (L' + cv[0] + ' I' + cv[1] + ')');
    await p.click('#nocell'); ok((await rows()) === 38, 'the grid filter clears');
    await p.click('#viz .fb'); ok((await p.$eval('#fflag', (x) => x.value)) !== '' && (await rows()) < 38, 'a flag bar filters the list'); await p.selectOption('#fflag', ''); await p.waitForTimeout(100);
    await p.click('tr.row:has-text("IT-90")'); ok(await wait(p, () => /Most similar risks/.test(document.getElementById('drawer').textContent)), 'drawer with similar risks');
    ok(/solved, treatment not in place/.test(await p.textContent('#drawer')), 'flags explained in the drawer');
    await p.selectOption('#a-l', '2'); await p.selectOption('#a-i', '4'); await p.selectOption('#a-e', '2'); await p.click('#assess');
    ok(await toast(p, 'note is required'), 'assessment needs a note');
    await p.fill('#a-n', 'redundant server added (synthetic)'); await p.click('#assess'); ok(await toast(p, 'Assessed: Low-Medium \\(8\\)'), 'assessed');
    await p.waitForTimeout(400); await p.click('#dclose'); await p.click('tr.row:has-text("IT-90")'); ok(await wait(p, () => document.querySelectorAll('#drawer .pos .mh .c.on').length === 2 && !!document.querySelector('#drawer svg.spark')), 'drawer: the risk marked on both grids, its score over time');
    const dz = await p.evaluate(() => ({ on: [...document.querySelectorAll('#drawer .pos .mh .c.on')].map((c) => c.textContent), pts: document.querySelectorAll('#drawer svg.spark circle').length, sim: document.querySelectorAll('#drawer .sim .trk').length }));
    ok(dz.on[0] === '8' && dz.on[1] === 'II' && dz.pts === 2 && dz.sim >= 1, 'drawer: inherent 8 on the grid, Class II on the residual matrix (Limited x Low-Medium), two points of history, similarity bars: ' + JSON.stringify(dz));
    if (process.env.SHOTS) { await p.waitForTimeout(500); await p.screenshot({ path: path.join(process.env.SHOTS, 'register-drawer.png') }); }
    // a new risk with suggestions
    await p.click('#dclose'); await p.click('#new'); await p.fill('#f-title', 'Delay in claim settlement because of slow workshop approval'); await p.click('#sug');
    ok(await wait(p, () => /Insurance_Risk/.test(document.getElementById('sugres').textContent)), 'suggestion: Insurance_Risk');
    await p.click('[data-use^="area|Insurance_Risk"]'); ok((await p.inputValue('#f-area')) === 'Insurance_Risk', 'suggestion applied with one click');
    await p.fill('#f-department', 'Synthetic Claims'); await p.fill('#f-owner', 'Head of Claims'); await p.selectOption('#f-likelihood', '3'); await p.selectOption('#f-impact', '3'); await p.click('#save');
    ok(await toast(p, 'Created BR-0039'), 'created');
    // RAS
    const a = await browser.newPage({ viewport: { width: 1400, height: 1000 } }); a.on('pageerror', (x) => errs.push(x.message));
    await a.goto(base + 'risk-appetite.html?standalone=1'); await wait(a, () => /No Risk Appetite Statement/.test(document.getElementById('list').textContent));
    await a.click('#imp'); await a.setInputFiles('#file', ras); await a.click('#preview');
    ok(await wait(a, () => /8 metrics in 2 sections/.test(document.getElementById('impres').textContent)), 'RAS preview'); ok(/ceilings out of order/.test(await a.textContent('#impres')), 'limit issue listed');
    await a.click('#apply'); ok(await wait(a, () => document.querySelectorAll('tr.row').length === 8), 'RAS imported');
    await a.click('tr[data-id="RAS-01.02"]'); ok(await wait(a, () => /appetite/.test(document.querySelector('.zones') ? document.querySelector('.zones').textContent : '')), 'zone bar');
    await a.fill('#a-v', '99'); await a.click('#record'); ok(await toast(a, 'ratio - enter 99%'), 'a whole number on a ratio is refused');
    await a.fill('#a-v', '99%'); await a.click('#record'); ok(await toast(a, 'note is required'), 'outside appetite needs an explanation');
    await a.fill('#a-n', 'large motor claims (synthetic)'); await a.click('#record'); ok(await toast(a, 'Recorded: outside tolerance - GRC action ACT-[0-9]+ raised automatically'), 'recorded outside tolerance, the GRC action raised at once');
    ok(await wait(a, () => /raised automatically/.test(document.getElementById('drawer').textContent)) && !(await a.$('#action')), 'no second action offered for it');
    await a.click('#dclose'); await a.click('#bulk');
    await a.fill('#bulktxt', ['320%', '300%', '290%', '275%', '262%'].map((v, i) => 'RAS-01.01,2026-' + String(6 + i).padStart(2, '0') + ',' + v + ',').join('\n'));
    await a.click('#bulksave'); ok(await wait(a, () => /Recorded 5/.test(document.getElementById('bulkres').textContent)), 'bulk recorded');
    ok(await wait(a, () => /warning/.test(document.querySelector('tr[data-id="RAS-01.01"]').textContent)), 'early warning on falling solvency');
    // the graphics: the summary (each part a filter), the ladder and trend in the list, the chart in the drawer
    const ag = await a.evaluate(() => ({ zs: [...document.querySelectorAll('#viz [data-fz]')].map((x) => x.dataset.fz), secs: document.querySelectorAll('#viz .sec-t').length, kic: document.querySelectorAll('#kpis .ic .ti').length,
      ld: !!document.querySelector('tr[data-id="RAS-01.01"] .ld .val') && !!document.querySelector('tr[data-id="RAS-01.01"] .ld .fc'), dots: document.querySelectorAll('tr[data-id="RAS-01.01"] svg.sp circle').length,
      stripe: getComputedStyle(document.querySelector('tr[data-id="RAS-01.02"]')).getPropertyValue('--zc').trim() }));
    ok(ag.zs.includes('within') && ag.zs.includes('tolerance') && ag.zs.includes('due') && ag.secs === 2 && ag.kic === 7, 'summary: zones bar, one tile per section, KPI icons: ' + JSON.stringify(ag));
    ok(ag.ld && ag.dots === 5 && ag.stripe === '#f2683c', 'list: the latest value and next forecast on the limit ladder, five points coloured by zone, the row stripe of a value outside tolerance: ' + JSON.stringify(ag));
    await a.click('#viz [data-fz="tolerance"]'); ok(await a.$eval('#fz', (x) => x.value) === 'tolerance' && (await a.$$eval('tr.row', (x) => x.map((r) => r.dataset.id))).join() === 'RAS-01.02', 'a zone segment filters the list');
    await a.click('#viz [data-fz="tolerance"]'); ok(await a.$eval('#fz', (x) => x.value) === '' && (await a.$$('tr.row')).length === 8, 'and clears it');
    await a.click('#viz .sec-t[data-sec="2"]'); ok((await a.$$eval('tr.row', (x) => x.every((r) => /^RAS-02/.test(r.dataset.id)))) && /OPERATIONAL RISK/.test(await a.textContent('#cnt')), 'a section tile filters the list, with a chip');
    await a.click('#nosec'); ok((await a.$$('tr.row')).length === 8, 'the section filter clears');
    const zh = await a.evaluate(() => ({ cols: document.querySelectorAll('#viz2 .zh .col').length, segs: document.querySelectorAll('#viz2 .zh .st i').length, deps: document.querySelectorAll('#viz2 [data-resp]').length, labels: [...document.querySelectorAll('#viz2 .zx span')].map((x) => x.textContent) }));
    ok(zh.cols === 5 && zh.labels[0] === '2026-06' && zh.labels[4] === '2026-10' && zh.segs >= 6 && zh.deps === 2, 'zone history: one column per reported period, zones stacked; departments: ' + JSON.stringify(zh));
    await a.click('#viz2 [data-resp="Synthetic IT"]'); ok(await a.$eval('#fresp', (x) => x.value) === 'Synthetic IT' && (await a.$$eval('tr.row', (x) => x.every((r) => /^RAS-02/.test(r.dataset.id)))), 'a department bar filters the list');
    await a.click('#viz2 [data-resp="Synthetic IT"]'); ok((await a.$$('tr.row')).length === 8, 'and clears it');
    await a.click('tr[data-id="RAS-01.01"]'); ok(await wait(a, () => document.querySelectorAll('#drawer svg.chart circle.pt').length === 5), 'drawer: the five values on the chart');
    const ch = await a.evaluate(() => { const svg = document.querySelector('#drawer svg.chart'); return { bands: svg.querySelectorAll('rect').length, labels: [...svg.querySelectorAll('text')].map((x) => x.textContent).join(' '), fc: svg.querySelectorAll('path[stroke-dasharray]').length, lg: document.querySelector('#drawer .lg').textContent }; });
    ok(ch.bands >= 3 && /250 %/.test(ch.labels) && /2026-06/.test(ch.labels) && /\+1/.test(ch.labels) && ch.fc >= 1 && /forecast, 80 % band/.test(ch.lg), 'drawer chart: the limits as zones (250 % appetite floor), periods, the forecast with its band: ' + JSON.stringify(ch).slice(0, 220));
    if (process.env.SHOTS) { await a.waitForTimeout(300); await a.screenshot({ path: path.join(process.env.SHOTS, 'ras-drawer.png') }); }
    await a.click('#dclose');
    await a.click('tr[data-id="RAS-02.01"]'); ok(await wait(a, () => document.querySelector('[data-link^="add|"]')), 'link suggestions');
    await a.click('[data-link^="add|"]'); ok(await toast(a, 'Linked'), 'linked');
    // dashboard
    await p.goto(base + 'business-risk.html?standalone=1'); await wait(p, () => /risks/.test(document.getElementById('kpis').textContent));
    { await wait(p, () => !document.getElementById('wfcard').hidden); const w = await p.textContent('#wfcard');
      ok(/1\s*open with the IT teams/.test(w) && /1\s*late with the IT teams/.test(w) && /1\s*overdue across the IT teams/.test(w) && /DR test evidence for claims <img/.test(w) && !(await p.$('#wfcard img')) && !(await p.evaluate(() => window.__wfx)) && /late with the IT team \+35, high priority \+10/.test(w), 'Workflow Automation on the Business Risk dashboard, from the real engine: ' + w.replace(/\s+/g, ' ').slice(0, 240)); }
    ok(/39/.test(await p.textContent('#kpis')), '39 risks'); ok((await p.$$('#heatI .c')).length === 25, 'inherent heat map 5 x 5');
    const gx = await p.evaluate(() => { const q = (s) => [...document.querySelectorAll(s)], sum = (s) => q(s).reduce((t, c) => t + (parseInt(c.textContent, 10) || 0), 0);
      return { cls: q('#classes svg.donut circle.seg').length, lg: document.querySelector('#classes .lg').textContent.replace(/\s/g, ''), inh: sum('#heatI .c'), res: q('#heatR .c').length, resSum: sum('#heatR .c > span'),
        resLbl: q('#heatR .c small').map((x) => x.textContent).join(''), areas: q('#areas .br').length, depts: q('#depts .br').length, sec: q('#sections .br').length, app: q('#appetite svg.donut circle.seg').length, ring: !!document.querySelector('#appetite svg.ring'),
        warnBar: q('#warnings .fill').length, dupBar: q('#dups .fill').length, flags: q('#flags .br').length, due: q('#due .br').length, kicons: q('#kpis .ic .ti').length }; });
    ok(gx.cls >= 1 && /ClassI\d+ClassII\d+ClassIII\d+ClassIV\d+/.test(gx.lg), 'residual class donut with its four classes: ' + gx.lg);
    ok(gx.inh === 39 && gx.res === 20 && gx.resSum >= 1 && /^(I|II|III|IV)+$/.test(gx.resLbl), 'heat maps: every rated risk on the inherent grid, the residual grid labels each cell with its class (' + gx.inh + ', ' + gx.res + ' cells)');
    ok(gx.areas >= 1 && gx.depts >= 1 && gx.sec === 2 && gx.app >= 1 && gx.ring, 'bars by area, department and RAS section; the appetite donut and reporting ring');
    if (process.env.SHOTS) { await p.waitForTimeout(1200); await p.screenshot({ path: path.join(process.env.SHOTS, 'business-risk.png'), fullPage: true }); }
    ok(gx.warnBar >= 1 && gx.dupBar >= 1 && gx.flags >= 1 && gx.due >= 1 && gx.kicons === 11, 'probability, similarity, quality-flag and due bars; KPI icons');
    ok(/server outage/i.test(await p.textContent('#dups')), 'likely duplicates'); ok(/RAS-01.02/.test(await p.textContent('#breaches')), 'breach listed'); ok(/RAS-01.01/.test(await p.textContent('#warnings')), 'early warning listed');
    ok(!(await p.isHidden('#askcard')), 'the AI officer is offered to an admin');
    await p.fill('#zs-q', 'risk appetite'); await p.waitForTimeout(150);
    ok((await p.$$eval('#zs-best a b', (x) => x.map((y) => y.textContent))).some((t) => /Risk Appetite/.test(t)), 'menu search finds the page');
    // the Head of Risk's one dashboard: IT & cyber risk + business risk + appetite, one ranked list
    await p.goto(base + 'enterprise-risk.html?standalone=1'); ok(await wait(p, () => /RAS-01.02/.test(document.getElementById('prio').textContent)), 'Enterprise Risk: the appetite breach is a priority');
    ok(/Synthetic solvency|RAS-01.01/.test(await p.textContent('#prio')), 'Enterprise Risk: the early warning is a priority'); ok(/39/.test(await p.textContent('#kpis')), 'Enterprise Risk: business KPIs');
    // in Arabic: right to left, headings and the menu translated
    await p.evaluate(() => localStorage.setItem('zyb-dash-prefs', JSON.stringify({ lang: 'ar' })));
    await p.goto(base + 'enterprise-risk.html'); await wait(p, () => /RAS-01.02/.test(document.getElementById('prio').textContent));
    const ar = await p.evaluate(() => ({ dir: document.documentElement.dir, h: document.querySelector('h1').textContent, prio: document.querySelector('#prio').closest('.card').querySelector('h2').textContent, menu: document.body.textContent.includes('سجل المخاطر') }));
    ok(ar.dir === 'rtl' && /لوحة المخاطر المؤسسية/.test(ar.h) && /الأولويات الموحّدة/.test(ar.prio), 'Enterprise Risk in Arabic: ' + JSON.stringify(ar));
    ok(ar.menu, 'the Business Risk menu in Arabic');
    // every tile and chart part opens the list it counts, filtered (it was a plain box: "click not working")
    await p.goto(base + 'business-risk.html?standalone=1'); await wait(p, () => document.querySelectorAll('#kpis a.k').length === 11);
    const hrefs = await p.$$eval('#kpis a.k', (a) => a.map((x) => x.getAttribute('href')));
    ok(hrefs.length === 11 && hrefs[2] === 'business-risk-register.html#class=34' && hrefs[8] === 'risk-appetite.html#zone=outside', 'every KPI tile is a link to its filtered list: ' + hrefs.join(' '));
    const c34 = await p.evaluate(() => { const t = document.querySelectorAll('#kpis a.k')[2]; return Number(t.querySelector('.v').textContent); });
    await Promise.all([p.waitForURL(/business-risk-register\.html#class=34/), p.click('#kpis a.k:nth-child(3)')]);
    ok(await wait(p, (n) => document.getElementById('fclass').value === '34' && document.querySelectorAll('tr.row').length === n && [...document.querySelectorAll('tr.row')].every((r) => /Class (III|IV)/.test(r.textContent)), c34), 'Class III / IV tile -> the register showing exactly those ' + c34 + ' risks');
    await p.goto(base + 'business-risk.html?standalone=1'); await wait(p, () => document.querySelectorAll('#kpis a.k').length === 11);
    await Promise.all([p.waitForURL(/business-risk-register\.html#flag=\*/), p.click('#kpis a.k:nth-child(5)')]);
    ok(await wait(p, () => document.getElementById('fflag').value === '*' && document.querySelectorAll('tr.row').length > 0 && [...document.querySelectorAll('tr.row')].every((r) => r.querySelector('.flag'))), 'quality-flag tile -> every flagged risk');
    await p.goto(base + 'business-risk.html?standalone=1'); await wait(p, () => !!document.querySelector('#appetite .lg a.lgl'));
    await Promise.all([p.waitForURL(/risk-appetite\.html#zone=due/), p.click('#appetite .lg a.lgl[href$="zone=due"]')]);
    ok(await wait(p, () => document.getElementById('fz').value === 'due' && document.querySelectorAll('tr.row').length > 0), 'the "not reported" part of the appetite donut -> Risk appetite showing what is due');
    await p.goto(base + 'business-risk.html?standalone=1'); await wait(p, () => !!document.querySelector('#classes svg.donut circle.seg[data-go]'));
    await Promise.all([p.waitForURL(/business-risk-register\.html#class=1/), p.$eval('#classes svg.donut circle.seg[data-go$="class=1"]', (c) => c.dispatchEvent(new MouseEvent('click', { bubbles: true })))]);
    ok(await wait(p, () => document.getElementById('fclass').value === '1'), 'a slice of the residual-class donut -> the register filtered to that class');
    await p.evaluate(() => localStorage.setItem('zyb-dash-prefs', JSON.stringify({ lang: 'en' })));   // the Arabic checks above are done
    // quantification: the Monte Carlo runs only on the loss ranges people enter; the appetite; quarterly exposure; correlations
    await p.goto(base + 'business-risk.html?standalone=1'); await wait(p, () => !document.getElementById('quant').hidden && document.getElementById('qr'));
    ok(/No risk has a loss range yet/.test(await p.textContent('#mc')), 'Monte Carlo: nothing assumed before a risk owner enters a range');
    ok(/Not quantified/.test(await p.textContent('#qin')), 'the risks with no loss range are listed');
    await p.fill('#qmin', '200000'); await p.fill('#qml', '3000000'); await p.fill('#qmax', '2500000'); await p.fill('#qfr', '1.5'); await p.fill('#qbs', 'synthetic incident history');
    await p.click('#qsave'); ok(await wait(p, () => /loss_likely must lie between/.test(document.getElementById('qmsg').textContent)), 'a most-likely above the highest is refused with the field named');
    await p.fill('#qml', '500000'); await p.click('#qsave');
    ok(await wait(p, () => document.querySelectorAll('#mc svg.mc rect').length >= 20), 'the loss histogram is drawn from the entered range');
    ok(/P90/.test(await p.textContent('#mc')) && /P95 \/ P99/.test(await p.textContent('#mc')) && /independent/.test(await p.textContent('#mc')), 'percentiles and the independence caveat');
    ok(await p.$('#mc svg.mc path') && /Expected \(mean\)/.test(await p.textContent('#mc')), 'the cumulative curve and the expected loss');
    ok((await p.$$('#drv .br')).length === 1 && /100 %/.test(await p.textContent('#drv')), 'drivers: the one quantified risk carries the whole loss');
    ok(/1 \/ \d+ open risks have a loss range/.test(await p.textContent('#qcov')), 'coverage counted');
    ok(/No loss appetite set/.test(await p.textContent('#mc')), 'no appetite yet: said');
    await p.fill('#qapp', '3000000'); await p.fill('#qappb', 'synthetic board RAS'); await p.click('#qappsave');
    ok(await wait(p, () => /Chance a year exceeds the loss appetite of 3\.00M SAR/.test(document.getElementById('mc').textContent)), 'the chance of exceeding the appetite');
    ok(await p.$('#qtr svg.qr path') !== null || /No assessment history yet/.test(await p.textContent('#qtr')), 'quarterly exposure drawn from the history, or says why not');
    ok(await p.$('#corr svg.sc') !== null || /6 or more periods/.test(await p.textContent('#corr')), 'correlation plot, or what it needs');
    const au = e.app.store.auditTail(300); ok(au.some((x) => x.action === 'brisk.risk.quant' && x.by === 'adam.syn') && au.some((x) => x.action === 'brisk.risk.quant.settings'), 'both changes audited');
    await p.evaluate(() => localStorage.setItem('zyb-dash-prefs', JSON.stringify({ lang: 'ar' })));
    await p.goto(base + 'business-risk.html'); await wait(p, () => document.querySelectorAll('#heatI .c').length === 25);
    const arb = await p.evaluate(() => ({ h: document.querySelector('h1').textContent, d: document.querySelector('#classes svg.donut text:last-of-type').textContent, wide: document.documentElement.scrollWidth <= innerWidth + 1, ltr: getComputedStyle(document.querySelector('#heatI .hm')).direction }));
    ok(/لوحة مخاطر الأعمال/.test(arb.h) && arb.d === 'المخاطر' && arb.wide && arb.ltr === 'ltr', 'the dashboard in Arabic: translated, chart labels inside the SVG too, the grids keep their axes, no sideways scroll: ' + JSON.stringify(arb));
    await p.goto(base + 'business-risk-register.html'); await wait(p, () => document.querySelectorAll('tr.row').length === 39);
    ok(await p.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1 && getComputedStyle(document.querySelector('#viz .mh')).direction === 'ltr'), 'the register in Arabic: no sideways scroll, the grid keeps its axes');
    ok(/سجل المخاطر/.test(await p.textContent('h1')) && /IT-90/.test(await p.textContent('#list')), 'the register in Arabic keeps its data (codes, titles) as written');
    await p.evaluate(() => localStorage.setItem('zyb-dash-prefs', JSON.stringify({ lang: 'en' })));
    who = { user: 'vera.syn', role: 'viewer' };
    const v = await browser.newPage({ viewport: { width: 400, height: 900 } }); v.on('pageerror', (x) => errs.push(x.message));
    await v.goto(base + 'business-risk-register.html?standalone=1'); await wait(v, () => document.querySelectorAll('tr.row').length);
    ok(await v.isHidden('#new') && await v.isHidden('#imp') && await v.isHidden('#export'), 'a viewer sees no write controls');
    await v.click('tr.row'); ok(await wait(v, () => !document.getElementById('drawer').hidden) && !(await v.$('#assess')), 'a viewer cannot re-assess');
    ok(await v.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1), 'phone width: no sideways scroll');
    await v.goto(base + 'business-risk.html?standalone=1'); await wait(v, () => /risks/.test(document.getElementById('kpis').textContent)); ok(await v.isHidden('#askcard'), 'no AI for a viewer');
    ok(await wait(v, () => !document.getElementById('quant').hidden) && !(await v.$('#qsave')) && !(await v.$('#qappsave')) && /P50/.test(await v.textContent('#mc')), 'a viewer sees the simulation but cannot enter ranges or the appetite');
    ok(await v.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1), 'the dashboard at phone width: no sideways scroll');
  } finally { await browser.close(); srv.close(); await e.close(); fs.rmSync(tmp, { recursive: true, force: true }); }
  ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks'); process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
