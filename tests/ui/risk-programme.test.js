// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for the Enterprise Risk Programme pages against the REAL engine (Business Risk + engine/risk-programme.js) with
// SYNTHETIC workbooks (backend/itam/tests/brisk-fixture.js), clicked through by named synthetic people so the four-eyes rules are
// exercised in the pages themselves:
//  - Risk Register drawer: the change log, the insurance category, a Class III close asked by one person and approved by another;
//  - Risk Assessment Cycle: opened by an administrator, a risk assessed in the page, a department signed off by a non-assessor, the
//    committee's approval by a third person, frozen;
//  - RAS Management: a metric proposed from an insurance template, approved by another administrator; the RAS frozen and its Board
//    approval recorded;
//  - Insurance Risk Catalogue: suggestions confirmed, an emerging risk recorded and promoted to the register;
//  - Risk Reports: committee / Board / regulator, Excel downloaded; a viewer is told reports need the operator role;
//  - record text stays text; Arabic; phone width; the menu and the installer.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node risk-programme.test.js   (SHOTS=dir also saves screenshots)
const http = require('http'), fs = require('fs'), path = require('path');
const ITAM = path.join(__dirname, '..', '..', 'backend', 'itam'), DASH = path.join(__dirname, '..', '..', 'ui');
const H = require(path.join(ITAM, 'tests', 'helpers'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
(async () => {
  const e = await H.startApp({ noAi: true });
  require(path.join(ITAM, 'engine/duty')).registerDuty(e.app.srv, e.app, { noTimer: true, now: () => Date.parse('2026-11-11T08:00:00Z'), python: process.env.PYTHON || 'python3' });
  const F = require(path.join(ITAM, 'tests', 'brisk-fixture'));
  const OP = { user: 'nora.syn', role: 'operator' }, OP2 = { user: 'omar.syn', role: 'operator' }, ADM = { user: 'adam.syn', role: 'admin' }, ADM2 = { user: 'aisha.syn', role: 'admin' }, VIEW = { user: 'vera.syn', role: 'viewer' };
  const api = (m, p, b, w) => e.req(m, p, Object.assign(b !== undefined ? { body: b } : {}, w || OP));
  let who = ADM;
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
  const wait = (p, fn, arg) => p.waitForFunction(fn, arg === undefined ? null : arg, { timeout: 20000 }).then(() => true, () => false);
  const shot = async (p, name) => { if (process.env.SHOTS) { await p.waitForTimeout(300); await p.screenshot({ path: path.join(process.env.SHOTS, name + '.png'), fullPage: true }); } };
  let p;
  const as = async (w, page) => { who = w; await p.goto('about:blank'); await p.goto(base + page + (page.includes('?') ? '&' : '?') + 'standalone=1'); };
  try {
    // synthetic register and RAS, reopened as a live register; one hostile title
    await api('POST', '/brisk/import/register', { filename: 'reg.xlsx', xlsx_b64: await F.registerB64(), apply: true }, ADM);
    await api('POST', '/brisk/import/ras', { filename: 'ras.xlsx', xlsx_b64: await F.rasB64(), apply: true }, ADM);
    for (const r of (await api('GET', '/brisk/risks', undefined, VIEW)).json.risks) if (r.status === 'solved') await api('POST', '/brisk/risks', { id: r.id, status: 'open' });
    const R = Object.fromEntries((await api('GET', '/brisk/risks', undefined, VIEW)).json.risks.map((r) => [r.code, r]));
    await api('POST', '/brisk/risks', { id: R['FIN-1'].id, title: 'Synthetic liquidity shortfall <img src=x onerror=window.__x=1>' });
    await api('POST', '/brisk/risks/' + R['FIN-1'].id + '/assess', { likelihood: 4, impact: 4, exposure: 3, note: 'synthetic re-rating' });
    p = await browser.newPage({ viewport: { width: 1400, height: 1000 }, acceptDownloads: true }); p.on('pageerror', (x) => errs.push(x.message));

    // 1 the register drawer: change log, category, close asked by one, approved by another
    const fin1 = R['FIN-1'].id, openRow = async () => { await wait(p, () => document.querySelectorAll('tr.row').length > 10); await p.evaluate(() => { const d = document.getElementById('drawer'); if (d) d.hidden = true; }); await p.click('tr.row[data-id="' + fin1 + '"]'); return wait(p, () => /assessed/.test((document.getElementById('l-log') || {}).textContent || '')); };
    await as(OP, 'business-risk-register.html'); await wait(p, () => document.querySelectorAll('#viz2 > div').length === 4);
    const rg = await p.evaluate(() => ({ tiles: document.querySelectorAll('#kk .t').length, filt: document.querySelectorAll('#kk [data-f]').length, bands: document.querySelectorAll('#viz2 > div:first-child .cb').length, deps: document.querySelectorAll('#viz2 [data-f^="fdept|"]').length, donut: !!document.querySelector('#viz2 .dn2 svg'), cnt: document.getElementById('cnt').textContent }));
    ok(rg.tiles === 6 && rg.filt === 4 && rg.bands >= 2 && rg.deps === 3 && rg.donut, 'register graphics: 6 tiles (4 filter), inherent band -> residual, departments, treatment donut, assessment age: ' + JSON.stringify(rg));
    await p.click('#viz2 [data-f="fdept|Synthetic IT"]'); ok(await wait(p, () => /^14 of 3[89] risks/.test(document.getElementById('cnt').textContent) && document.getElementById('fdept').value === 'Synthetic IT'), 'a department bar filters the list: ' + await p.textContent('#cnt'));
    await p.click('#viz2 [data-f="fdept|Synthetic IT"]'); await wait(p, () => document.getElementById('fdept').value === '');
    ok(await openRow(), 'the change log shows the edit and the assessment');
    ok(await p.evaluate(() => /title: .* → Synthetic liquidity/.test(document.getElementById('l-log').textContent) && !document.querySelector('#l-log img')), 'the change log names the field, from and to; record text stays text');
    await p.selectOption('#l-cat', 'liquidity'); await p.click('#l-catsave');
    ok(await wait(p, () => /Liquidity risk/.test(((document.getElementById('life') || {}).textContent) || '') && !!document.getElementById('l-closeb')), 'the insurance category is set from the drawer');
    await p.selectOption('#l-reason', 'treated'); await p.fill('#l-note', 'synthetic: controls now in place'); await p.click('#l-closeb');
    ok(await wait(p, () => /Close waiting for a second administrator/.test((document.getElementById('l-pend') || {}).textContent || '')), 'a Class III close waits for a second administrator');
    await as(ADM2, 'business-risk-register.html'); await wait(p, () => document.querySelectorAll('tr.row').length > 10); await p.click('tr.row[data-id="' + fin1 + '"]'); await wait(p, () => !!document.querySelector('[data-cdec="approve"]'));
    await p.click('[data-cdec="approve"]'); ok(await wait(p, () => /Closed/.test((document.getElementById('life') || {}).textContent || '') && /approved by aisha\.syn/.test(document.getElementById('life').textContent)), 'another administrator approves; the drawer says who');
    await shot(p, 'risk-register-close');

    // 2 the assessment cycle
    await as(ADM, 'risk-cycle.html'); ok(await wait(p, () => !document.getElementById('opencard').hidden), 'an administrator can open a cycle');
    await p.fill('#o-p', '2026-Q4'); await p.fill('#o-d', '2026-12-15'); await p.selectOption('#o-dep', ['Synthetic IT']); await p.click('#o-go');
    ok(await wait(p, () => /Risks to assess/.test(document.body.textContent) && document.querySelectorAll('tr.it').length > 5), 'the cycle opens with the IT risks');
    const C = (await api('GET', '/brisk/cycles/RC-2026-Q4', undefined, VIEW)).json;
    await as(OP, 'risk-cycle.html'); await wait(p, () => document.querySelectorAll('tr.it').length > 5);
    const first = C.items[0].risk; await p.click('.af[data-risk="' + first + '"] >> xpath=..//summary').catch(() => p.evaluate((r) => { document.querySelector('.af[data-risk="' + r + '"]').closest('details').open = true; }, first));
    await p.evaluate((r) => { document.querySelector('.af[data-risk="' + r + '"]').closest('details').open = true; }, first);
    await p.selectOption('.af[data-risk="' + first + '"] [data-k="likelihood"]', '5'); await p.fill('.af[data-risk="' + first + '"] [data-k="note"]', 'synthetic: more outages this quarter'); await p.click('[data-sub="' + first + '"]');
    ok(await wait(p, (r) => { const tr = [...document.querySelectorAll('tr.it')].find((x) => x.querySelector('[data-risk="' + r + '"]') || x.textContent.includes('synthetic: more outages')); return tr && /higher/.test(tr.textContent); }, first), 'a risk assessed in the page shows its movement');
    for (const i of C.items.slice(1)) await api('POST', '/brisk/cycles/RC-2026-Q4/submit', { risk: i.risk, unchanged: true, note: 'synthetic: no change' }, OP);
    await as(OP2, 'risk-cycle.html'); await wait(p, () => !!document.querySelector('[data-sign]')); await p.click('[data-sign="Synthetic IT"]');
    ok(await wait(p, () => /Risk committee decision/.test(document.body.textContent)), 'signed off by a person who assessed none of them; the committee is next');
    await as(ADM, 'risk-cycle.html'); await wait(p, () => /Risk committee decision/.test(document.body.textContent));
    ok(await p.evaluate(() => !document.querySelector('[data-dec]') && /did not open the cycle/.test(document.body.textContent)), 'the opener cannot approve: no buttons, told why');
    await as(ADM2, 'risk-cycle.html'); await wait(p, () => !!document.querySelector('[data-dec="approve"]')); await p.click('[data-dec="approve"]');
    ok(await wait(p, () => /Frozen/.test(document.body.textContent) && /approved by aisha\.syn/.test(document.body.textContent)), 'the committee approves; the cycle is frozen');
    ok(await p.evaluate(() => document.querySelectorAll('.tl li').length === 4 && [...document.querySelectorAll('.tl li')].every((s) => s.className === 'done') && document.querySelectorAll('.tx .c').length === 16 && document.querySelectorAll('.dc svg').length >= 1 && document.querySelectorAll('.mix .bar').length === 2), 'every step done; the class mix, the 4 x 4 transitions and the department rings are drawn');
    await shot(p, 'risk-cycle');

    // 3 RAS management: a template proposed, approved by another administrator; the Board approval
    await as(OP, 'ras-manage.html?template=T-UW-01'); ok(await wait(p, () => document.getElementById('n-comp').value === 'Loss ratio (by line of business)'), 'the insurance template fills the definition');
    await p.fill('#n-sec', 'INSURANCE RISK'); await p.fill('#n-comp', 'Synthetic loss ratio motor'); await p.fill('#n-resp', 'Synthetic Claims'); await p.fill('#n-app_ceil', '<60%'); await p.fill('#n-tol_ceil', '70%'); await p.fill('#n-cap_ceil', '>80%'); await p.fill('#n-note', 'synthetic: asked by the committee');
    ok(await p.evaluate(() => !!document.querySelector('#n-lad svg') && !document.querySelector('#n-lad .w') && document.querySelectorAll('#viz .dn svg').length === 1 && document.querySelectorAll('#viz .sb').length >= 2), 'RAS composition, sections and owners drawn; the limits shown on one scale, in order');
    await p.fill('#n-tol_ceil', '50%'); ok(await wait(p, () => /out of order/.test((document.querySelector('#n-lad .w') || {}).textContent || '')), 'limits out of order are flagged while typing'); await p.fill('#n-tol_ceil', '70%');
    await p.click('#n-go');
    ok(await wait(p, () => /Synthetic loss ratio motor/.test(document.getElementById('pend').textContent) && /Yours - a different administrator decides/.test(document.getElementById('pend').textContent)), 'the proposal waits; its author is told a different administrator decides');
    await as(ADM, 'ras-manage.html'); await wait(p, () => !!document.querySelector('[data-pdec="approve"]')); await p.click('[data-pdec="approve"]');
    ok(await wait(p, () => /Activemetrics9/.test(document.getElementById('kk').textContent.replace(/\s+/g, ''))), 'approved: the RAS has the new metric');
    await as(OP, 'ras-manage.html'); await wait(p, () => !!document.getElementById('b-ask')); await p.fill('#b-rnote', 'synthetic: December Board'); await p.click('#b-ask');
    await as(ADM2, 'ras-manage.html'); await wait(p, () => !!document.querySelector('[data-bdec="approve"]')); await p.fill('#b-ref', 'Synthetic Board 2026/8'); await p.click('[data-bdec="approve"]');
    ok(await wait(p, () => document.querySelectorAll('#board .vt .v').length === 1 && !!document.querySelector('#board .dr svg') && /exactly what the Board approved/.test(document.getElementById('board').textContent) && /Synthetic Board 2026\/8/.test(document.getElementById('board').textContent)), 'the Board approval is recorded with its reference; the version timeline and the drift ring');
    await shot(p, 'ras-manage');

    // 4 the insurance catalogue: suggestions confirmed, an emerging risk recorded and promoted
    await as(OP, 'risk-catalogue.html'); ok(await wait(p, () => document.querySelectorAll('.cat').length === 13), 'thirteen insurance categories with their templates');
    ok(await p.evaluate(() => [...document.querySelectorAll('.cat')].some((c) => /Loss ratio/.test(c.textContent) && /in the RAS/.test(c.textContent))), 'a template already in the RAS says so');
    ok(await p.evaluate(() => document.querySelectorAll('#viz .dn svg').length === 1 && document.querySelectorAll('#viz .ls').length >= 3 && document.querySelectorAll('#viz .cv svg').length === 13 && document.querySelectorAll('.cat .ico .ti').length === 13 && document.querySelectorAll('.cat .rg svg').length === 13), 'catalogue graphics: categorisation donut, risk landscape, RAS coverage rings, an icon and a coverage ring per category');
    await p.click('[data-tab="risks"]'); await wait(p, () => document.querySelectorAll('[data-pick]').length > 5);
    const ticked = await p.evaluate(() => document.querySelectorAll('[data-pick]:checked').length); await p.click('#confirm');
    ok(await wait(p, (t) => Number((document.getElementById('kk').textContent.match(/Categorised\s*(\d+)/) || [])[1]) >= t, ticked), 'the ticked suggestions are confirmed: ' + ticked);
    await p.click('[data-tab="emerg"]'); ok(!(await p.$('#v-emerg .em')), 'no emerging-risk map before any is watched'); await p.fill('#m-title', 'Synthetic cyber accumulation across policies'); await p.selectOption('#m-cat', 'catastrophe'); await p.fill('#m-own', 'Synthetic CRO'); await p.click('#m-go');
    ok(await wait(p, () => /Synthetic cyber accumulation/.test(document.getElementById('v-emerg').textContent) && document.querySelectorAll('#v-emerg .em .d').length === 1), 'an emerging risk is recorded and placed on the horizon x impact map');
    await p.click('[data-tab="emerg"]'); await p.evaluate(() => { document.querySelector('[data-em]').closest('details').open = true; });
    await p.fill('[data-em] [data-k="department"]', 'Synthetic IT'); await p.fill('[data-em] [data-k="note"]', 'synthetic: now material'); await p.click('[data-prom]');
    ok(await wait(p, () => /promoted/.test(document.getElementById('v-emerg').textContent)), 'promoted to the register');
    await shot(p, 'risk-catalogue');

    // 5 reports (the promoted risk has left the watch list; one more is watched)
    await api('POST', '/brisk/emerging', { title: 'Synthetic pandemic claims surge', category: 'catastrophe', horizon: '1-3y', trend: 'rising', impact: 4, owner: 'Synthetic CRO' });
    await as(OP, 'risk-reports.html'); ok(await wait(p, () => /Risk Committee pack/.test(document.getElementById('title').textContent) && /Class III \/ IV risks/.test(document.getElementById('rep').textContent)), 'the committee pack is built from the records');
    ok(await p.evaluate(() => /Synthetic Board 2026\/8/.test(document.getElementById('rep').textContent) && /2026-Q4/.test(document.getElementById('rep').textContent) && /Synthetic pandemic claims surge/.test(document.getElementById('rep').textContent) && !/Synthetic cyber accumulation/.test(document.getElementById('rep').textContent)), 'it carries the Board approval, the approved cycle and the emerging risks');
    const ch = await p.evaluate(() => ({ donuts: document.querySelectorAll('.dn svg').length, heat: document.querySelectorAll('.hm .c').length, heads: document.querySelectorAll('.hl li').length, em: document.querySelectorAll('.em .d').length,
      tile: Number((document.getElementById('rep').querySelector('.k').textContent.match(/Class III \/ IV\s*(\d+)/) || [])[1]), listed: Number((document.getElementById('rep').textContent.match(/Class III \/ IV risks\s*(\d+)/) || [])[1]) }));
    ok(ch.donuts === 2 && ch.heat === 25 && ch.heads >= 4 && ch.em >= 1, 'charts: residual and appetite donuts, the 5 x 5 heat map, headlines, the emerging-risk matrix: ' + JSON.stringify(ch));
    ok(ch.tile === ch.listed, 'the Class III / IV tile counts the same open risks as the list: ' + ch.tile + ' / ' + ch.listed);
    // every figure opens the list behind it: tiles, the donut legends, the headlines
    const lk = await p.evaluate(() => { const r = document.getElementById('rep'), hrefOf = (sel, re) => { const a = [].find.call(r.querySelectorAll(sel), (x) => re.test(x.textContent)); return a ? a.getAttribute('href') : null; };
      return { open: hrefOf('.k a.t', /Open risks/), c34: hrefOf('.k a.t', /Class III \/ IV/), out: hrefOf('.k a.t', /Outside appetite/), ras: hrefOf('.k a.t', /RAS approved/), em: hrefOf('.k a.t', /Emerging risks/),
        cls3: hrefOf('.lg a', /Class III/), notrep: hrefOf('.lg a', /Not reported/), head: [].map.call(r.querySelectorAll('.hl li a.lk'), (x) => x.getAttribute('href')) }; });
    ok(lk.open === 'business-risk-register.html#status=active' && lk.c34 === 'business-risk-register.html#class=34&status=active' && lk.out === 'ras-cockpit.html#ov' && lk.ras === 'ras-manage.html' && lk.em === '#sec-emerging', 'tiles link to the filtered lists: ' + JSON.stringify(lk));
    ok(lk.cls3 === 'business-risk-register.html#class=3&status=active' && lk.notrep === 'ras-cockpit.html#rep' && lk.head.length >= 4 && lk.head.every(Boolean), 'legends and headlines link too');
    await p.click('.k a.t[href="#sec-emerging"]'); ok(await wait(p, () => location.hash === '#sec-emerging'), 'the emerging tile jumps to its section');
    await p.click('.k a.t[href$="class=34&status=active"]'); ok(await wait(p, () => /business-risk-register\.html/.test(location.pathname) && document.getElementById('fclass') && document.getElementById('fclass').value === '34' && document.getElementById('fst').value === 'active'), 'the Class III / IV tile opens the register filtered');
    await p.goBack(); await wait(p, () => document.getElementById('rep') && /Board|Committee/.test(document.getElementById('title').textContent));
    await p.click('[data-kind="regulator"]'); ok(await wait(p, () => /Insurance Authority risk pack/.test(document.getElementById('title').textContent) && /7\. Risk register/.test(document.getElementById('rep').textContent)), 'the regulator pack has the full register and the RAS');
    ok(await p.evaluate(() => /check it against the Insurance Authority/.test(document.getElementById('sub').textContent)), 'it says to check the Authority\'s template');
    const [dl] = await Promise.all([p.waitForEvent('download', { timeout: 10000 }), p.click('#xlsx')]); const xb = fs.readFileSync(await dl.path());
    ok(/regulator-risk-report-.*\.xlsx$/.test(dl.suggestedFilename()) && xb.slice(0, 2).toString() === 'PK', 'a real Excel file is downloaded: ' + dl.suggestedFilename());
    await shot(p, 'risk-reports');
    await as(VIEW, 'risk-reports.html'); ok(await wait(p, () => /need the operator role/.test(document.getElementById('err').textContent)), 'a viewer is told reports need the operator role');
    ok(await p.evaluate(() => window.__x !== 1 && !document.querySelector('img[src="x"]')), 'no record text ran as markup');

    // Arabic, phone width, menu and installer
    who = ADM; await p.evaluate(() => localStorage.setItem('zyb-dash-prefs', JSON.stringify({ lang: 'ar' }))); await p.goto(base + 'risk-cycle.html'); await wait(p, () => document.querySelectorAll('tr.it').length > 0);
    ok(await p.evaluate(() => document.documentElement.dir === 'rtl' && document.documentElement.scrollWidth <= innerWidth + 1), 'Arabic: right to left, no sideways scroll');
    ok(await wait(p, () => /التقدم/.test(document.getElementById('viz').textContent) && /ما الذي تغيّر/.test(document.getElementById('viz').textContent) && /مقيَّمة/.test(document.getElementById('cur').textContent)), 'Arabic: the cycle graphics are labelled in Arabic');
    await p.evaluate(() => localStorage.setItem('zyb-dash-prefs', JSON.stringify({ lang: 'en' })));
    const m = await browser.newPage({ viewport: { width: 390, height: 860 } }); m.on('pageerror', (x) => errs.push(x.message));
    for (const pg of ['risk-cycle.html', 'ras-manage.html', 'risk-catalogue.html', 'risk-reports.html']) { await m.goto(base + pg + '?standalone=1'); await m.waitForTimeout(1200); ok(await m.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1), 'phone width, no sideways scroll: ' + pg); }
    const nav = await p.evaluate(() => (window.ZYB_NAV.find((a) => a.id === 'brisk') || { pages: [] }).pages.map((x) => x.h)), inst = fs.readFileSync(path.join(DASH, 'install-dashboards.sh'), 'utf8');
    ok(['risk-cycle.html', 'ras-manage.html', 'risk-catalogue.html', 'risk-reports.html'].every((x) => nav.includes(x) && inst.includes(x)), 'in the Business Risk menu and the installer');
  } finally { await browser.close(); srv.close(); await e.close(); }
  ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks'); process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
