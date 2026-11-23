// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for the Risk Appetite Cockpit (ras-cockpit.html) against the REAL engine (engine/business-risk.js + brisk-ras.js) with
// SYNTHETIC workbooks (backend/itam/tests/brisk-fixture.js) and synthetic open risks: the overview (KPIs, section tiles, the watch
// list on six-limit ladders, what changed), risk coverage (evidence, link one, reject one, approve the strong ones in bulk), reporting
// (a department's due values in one form, the live zone preview, a note required outside appetite, the automatic GRC action),
// limit fixes (request a proposed correction, the requester cannot approve, a second administrator does), viewer, escaping, Arabic, phone.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node ras-cockpit.test.js   (SHOTS=dir also saves screenshots)
const http = require('http'), fs = require('fs'), path = require('path');
const ITAM = path.join(__dirname, '..', '..', 'backend', 'itam'), DASH = path.join(__dirname, '..', '..', 'ui');
const H = require(path.join(ITAM, 'tests', 'helpers'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
(async () => {
  const e = await H.startApp({ noAi: true });
  require(path.join(ITAM, 'engine/duty')).registerDuty(e.app.srv, e.app, { noTimer: true, now: () => Date.parse('2026-11-11T08:00:00Z'), python: process.env.PYTHON || 'python3' });
  const F = require(path.join(ITAM, 'tests', 'brisk-fixture'));
  const OP = { user: 'nora.syn', role: 'operator' }, ADM = { user: 'adam.syn', role: 'admin' };
  const api = (m, p, b, who) => e.req(m, '/brisk' + p, Object.assign(b !== undefined ? { body: b } : {}, who || OP));
  await api('POST', '/import/register', { filename: 'reg.xlsx', xlsx_b64: await F.registerB64(), apply: true }, ADM);
  await api('POST', '/import/ras', { filename: 'ras.xlsx', xlsx_b64: await F.rasB64(), apply: true }, ADM);
  const mk = async (o) => (await api('POST', '/risks', Object.assign({ likelihood: 4, impact: 4, exposure: 3, owner: 'Synthetic owner' }, o))).json;
  const solv = await mk({ department: 'Synthetic Finance', title: 'Solvency ratio falls below the regulatory capital margin', description: 'Synthetic: regulatory capital over the required margin drops', area: 'Strategic_Risk' });
  await mk({ department: 'Synthetic IT', title: 'Core system availability below target <img src=x onerror=window.__x=1>', description: 'Synthetic: core system availability uptime drops', area: 'Operational_Risk' });
  await mk({ department: 'Synthetic Facilities', title: 'Office pantry supplies run short', description: 'Synthetic: coffee and tea stock', area: 'Projects_Risks' });
  // values: the combined ratio moves from within appetite to outside tolerance; solvency falls towards its floor (early warning)
  await api('POST', '/ras/actuals', { rows: [{ metric: 'RAS-01.02', period: '2026-09', value: '95%' }, { metric: 'RAS-01.02', period: '2026-10', value: '99%', note: 'synthetic: large claims' }]
    .concat(['320%', '300%', '290%', '275%', '262%'].map((v, i) => ({ metric: 'RAS-01.01', period: '2026-' + String(6 + i).padStart(2, '0'), value: v }))) });

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
  const base = 'http://127.0.0.1:' + srv.address().port + '/ras-cockpit.html', SHOTS = process.env.SHOTS;
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  const wait = (p, fn, arg) => p.waitForFunction(fn, arg === undefined ? null : arg, { timeout: 30000 }).then(() => true, () => false);
  const toast = (p, re) => wait(p, (s) => [...document.querySelectorAll('.toast')].some((t) => new RegExp(s).test(t.textContent)), re);
  const ready = (p) => wait(p, () => document.querySelectorAll('#kpis .k').length > 0 && document.querySelectorAll('#covlist li, #covlist .empty').length > 0);
  try {
    const p = await browser.newPage({ viewport: { width: 1400, height: 1000 } }); p.on('pageerror', (x) => errs.push(x.message)); p.on('dialog', (d) => d.accept());
    await p.goto(base + '?standalone=1'); ok(await ready(p), 'the cockpit draws');
    // overview
    const ov = await p.evaluate(() => ({ k: document.getElementById('kpis').textContent, tiles: document.querySelectorAll('#tiles .tile').length, watch: [...document.querySelectorAll('#watch li')].map((li) => li.textContent),
      ladder: document.querySelectorAll('#watch .ld .val').length, fc: document.querySelectorAll('#watch .ld .fc').length, chg: document.getElementById('changes').textContent }));
    ok(/^8/.test(ov.k.trim()) && /1 \/ 7|2 \/ 7/.test(ov.k) && ov.tiles === 2, 'KPIs and one tile per section: ' + ov.k.slice(0, 160));
    const gx = await p.evaluate(() => ({ gauge: !!document.querySelector('#pos .gauge svg'), donut: !!document.querySelector('#pos .donut'), ring: !!document.querySelector('#pos .rp2 svg'), gs: (document.querySelector('#pos .gs') || {}).textContent || '',
      cards: document.querySelectorAll('#trends .spk').length, lines: document.querySelectorAll('#trends .spk polyline').length, band: document.querySelectorAll('#trends .spk rect').length, fc: [...document.querySelectorAll('#trends .spk polyline')].filter((l) => l.getAttribute('stroke-dasharray')).length }));
    ok(gx.gauge && gx.donut && gx.ring && /within appetite/.test(gx.gs), 'position: appetite gauge, zone donut, reporting ring: ' + gx.gs);
    ok(gx.cards >= 4 && gx.lines >= 2 && gx.band >= 2 && gx.fc >= 1, 'metric trends: a small chart per metric with limits, the appetite band, and the forecast dotted: ' + JSON.stringify(gx));
    ok(ov.watch.some((t) => /RAS-01\.02/.test(t) && /outside tolerance/.test(t)) && ov.watch.some((t) => /RAS-01\.01/.test(t) && /chance/.test(t)), 'watch list: the breach and the early warning, with why');
    ok(ov.ladder >= 2 && ov.fc >= 1, 'each watched metric sits on its limit ladder, with the next forecast (' + ov.ladder + ' values, ' + ov.fc + ' forecasts)');
    ok(/RAS-01\.02/.test(ov.chg) && /within appetite/.test(ov.chg) && /outside tolerance/.test(ov.chg), 'what changed: within appetite -> outside tolerance');
    // section x period heat map and closest to the edge
    const hv = await p.evaluate(() => { const row = [...document.querySelectorAll('#hm .hmg > *')], i = row.findIndex((x) => /STRATEGIC RISK/.test(x.textContent)), hd = [...document.querySelectorAll('#hm .hd')].map((x) => x.textContent);
      return { hd, cells: row.slice(i + 1, i + 1 + hd.length).map((x) => [x.textContent, x.style.background]), edge: [...document.querySelectorAll('#edge .eg')].map((x) => x.querySelector(':scope > b').textContent + ' ' + x.querySelector('.nm b').textContent) }; });
    ok(hv.hd.length === 5 && hv.hd[4] === '2026-10' && hv.cells[4][0] === '2' && /242, 104, 60/.test(hv.cells[4][1]) && /47, 179, 68/.test(hv.cells[0][1]), 'heat map: the five periods with values (at most six); STRATEGIC RISK in 2026-10 holds 2 values, the worst outside tolerance: ' + JSON.stringify(hv.cells));
    ok(/^-2\.1 % RAS-01\.02$/.test(hv.edge[0]) && hv.edge.some((e) => /^\+4\.8 % RAS-01\.01$/.test(e)), 'closest to the edge: the combined ratio breached by 2.1 %, solvency 4.8 % above its floor, worst first: ' + hv.edge.join(' | '));
    await p.click('#hm button.c'); ok(await wait(p, () => document.querySelectorAll('#hm button.c.on').length >= 1 && document.querySelectorAll('#tiles .tile[aria-pressed="true"]').length === 1), 'a heat-map row selects its section');
    await p.click('#hm button.c');
    await p.click('#tiles .tile:nth-child(2)'); ok(await wait(p, () => !/RAS-01\.0/.test(document.getElementById('watch').textContent)), 'a section tile filters the watch list');
    ok(/No value reported yet/.test(await p.textContent('#edge')), 'closest to the edge follows the section (nothing reported there yet)');
    await p.click('#tiles .tile:nth-child(2)');
    if (SHOTS) { await p.waitForTimeout(400); await p.screenshot({ path: path.join(SHOTS, 'ras-cockpit-overview.png'), fullPage: true }); }

    // coverage
    await p.click('[data-tab="cov"]'); ok(await p.isVisible('#p-cov') && !(await p.isVisible('#p-ov')), 'the coverage tab opens');
    const cv = await p.evaluate(() => ({ sum: document.getElementById('covsum').textContent, rows: [...document.querySelectorAll('#covlist .rl > li')].map((li) => li.textContent), xss: window.__x === 1 || !!document.querySelector('#covlist img') }));
    ok(/0\/4/.test(cv.sum) && /Class III \/ IV not watched/.test(cv.sum), 'coverage summary: 0 of 4 open risks watched, serious ones counted: ' + cv.sum.slice(0, 120));
    const sr = cv.rows.find((t) => /Solvency ratio falls/.test(t)); ok(sr && /RAS-01\.01/.test(sr) && /same department/.test(sr) && /same family of risk/.test(sr), 'the solvency risk: RAS-01.01 suggested with its evidence');
    ok(cv.rows.some((t) => /pantry/.test(t) && /nothing watches it/.test(t)), 'the pantry risk: nothing watches it'); ok(!cv.xss, 'risk text is escaped');
    await p.click('button[data-link="RAS-01.01"][data-risk="' + solv.id + '"]'); ok(await toast(p, 'Link'), 'one suggestion linked');
    ok(await wait(p, () => /1\/4/.test(document.getElementById('covsum').textContent)), 'the risk is now covered (1 of 4)');
    await p.selectOption('#cst', ''); await wait(p, () => /pantry/.test(document.getElementById('covlist').textContent));
    const rej = await p.$('#covlist button[data-reject]'); const rm = await rej.getAttribute('data-reject'), rr = await rej.getAttribute('data-risk'); await rej.click(); ok(await toast(p, 'Not this'), 'a suggestion rejected');
    ok(await wait(p, (a) => !document.querySelector('button[data-link="' + a[0] + '"][data-risk="' + a[1] + '"]'), [rm, rr]), 'the rejected suggestion is gone');
    await p.selectOption('#cst', 'todo'); await p.waitForTimeout(150);
    await p.click('#selstrong'); const sel = await p.$$eval('.pick:checked', (x) => x.length);
    if (sel) { await p.click('#linksel'); ok(await toast(p, 'Link'), 'the strong suggestions linked in bulk (' + sel + ')'); } else ok(true, 'no strong suggestion left to approve in bulk');
    if (SHOTS) { await p.waitForTimeout(600); await p.screenshot({ path: path.join(SHOTS, 'ras-cockpit-coverage.png'), fullPage: true }); }

    // reporting
    await p.click('[data-tab="rep"]'); await p.click('button[data-dept="Synthetic IT"]'); ok(await wait(p, () => document.querySelectorAll('#form .fr').length === 3), 'Synthetic IT: three values due in one form');
    await p.fill('.fv[data-id="RAS-02.01"]', '0.99'); ok(/within appetite/.test(await p.textContent('[data-pv="RAS-02.01"]')), 'live preview: within appetite');
    await p.fill('.fv[data-id="RAS-02.02"]', '2 days'); ok(/capacity breached/.test(await p.textContent('[data-pv="RAS-02.02"]')) && /note needed/.test(await p.textContent('[data-pv="RAS-02.02"]')), 'live preview: capacity breached, note needed');
    await p.click('#save'); ok(await wait(p, () => /note is required/.test(document.getElementById('fres').textContent)), 'the server refuses a value outside appetite without a note, and says so');
    await p.fill('.fn[data-id="RAS-02.02"]', 'synthetic outage'); await p.click('#save'); ok(await toast(p, '2 recorded.*GRC action'), 'saved: two values, the GRC action raised automatically');
    ok(await wait(p, () => /2 \/ 3/.test((document.querySelector('button[data-dept="Synthetic IT"]') || {}).textContent || '') && document.querySelectorAll('#form .fr').length === 1), 'the department progress moves and the form shrinks');
    ok(/^mailto:\?subject=RAS%20reporting%20due/.test(await p.getAttribute('#mail', 'href')), 'an email reminder is drafted for a person to send');

    // limit fixes: request, the requester cannot approve, a second administrator approves
    await p.click('[data-tab="lim"]'); ok(/RAS-01\.03/.test(await p.textContent('#props')) && /ceilings are put in order/.test(await p.textContent('#props')), 'the correction is proposed with why');
    ok(await p.evaluate(() => document.querySelectorAll('#props .cmp .ld').length >= 2), 'the current and proposed limits as ladders');
    await p.click('button[data-request="RAS-01.03"]'); ok(await wait(p, () => document.activeElement && document.activeElement.id === 'pn-RAS-01.03'), 'a note is asked for first');
    await p.fill('[id="pn-RAS-01.03"]', 'synthetic: ceilings in order'); await p.click('button[data-request="RAS-01.03"]');
    ok(await wait(p, () => /you requested it/.test(document.getElementById('pend').textContent)) && !(await p.$('button[data-approve]')), 'pending: the requester sees no approve button');
    who = { user: 'aisha.syn', role: 'admin' }; await p.reload(); await ready(p); await p.click('[data-tab="lim"]');
    await p.click('button[data-approve="RAS-01.03"]'); ok(await wait(p, () => /RAS-01\.03/.test(document.getElementById('appr').textContent) && /aisha\.syn/.test(document.getElementById('appr').textContent)), 'approved by a second administrator');
    if (SHOTS) { await p.screenshot({ path: path.join(SHOTS, 'ras-cockpit-limits.png'), fullPage: true }); }

    // a viewer sees, cannot change
    who = { user: 'vera.syn', role: 'viewer' }; await p.goto('about:blank'); await p.goto(base + '?standalone=1#cov'); await ready(p);
    ok(!(await p.$('#covlist button[data-link]')) && !(await p.$('.pick')) && await p.isHidden('#bulk'), 'a viewer: no link, reject or bulk controls');
    await p.click('[data-tab="rep"]'); await p.click('button[data-dept="Synthetic Finance"]'); ok(!(await p.$('#save')) && await p.$eval('.fv', (x) => x.disabled), 'a viewer: the form is read-only');
    await p.click('[data-tab="lim"]'); ok(!(await p.$('button[data-request]')), 'a viewer cannot request a limit change');
    // Arabic
    who = ADM; await p.evaluate(() => localStorage.setItem('zyb-dash-prefs', JSON.stringify({ lang: 'ar' }))); await p.goto(base); await ready(p);
    const ar = await p.evaluate(() => ({ dir: document.documentElement.dir, h1: document.querySelector('h1').textContent, tab: document.querySelector('[data-tab="cov"]').textContent, wide: document.documentElement.scrollWidth <= innerWidth + 1 }));
    ok(ar.dir === 'rtl' && /لوحة قيادة الرغبة/.test(ar.h1) && /تغطية المخاطر/.test(ar.tab) && ar.wide, 'Arabic: right to left, translated, no sideways scroll: ' + JSON.stringify(ar));
    await p.evaluate(() => localStorage.setItem('zyb-dash-prefs', JSON.stringify({ lang: 'en' })));
    // phone
    const m = await browser.newPage({ viewport: { width: 390, height: 860 } }); m.on('pageerror', (x) => errs.push(x.message));
    for (const t of ['ov', 'cov', 'rep', 'lim']) { await m.goto(base + '?standalone=1#' + t); await ready(m); ok(await m.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1), 'phone width, ' + t + ': no sideways scroll'); }
  } finally { await browser.close(); srv.close(); await e.close(); }
  ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks'); process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
