// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for the Enterprise Risk Automation Flow (risk-flow.html) against the REAL engine (Business Risk, Risk Command, the AI
// Risk Officer) with SYNTHETIC workbooks (backend/itam/tests/brisk-fixture.js) and synthetic risks: before anything is imported
// every stage that has no source is grey; after the import, values, the officer's proposals and one decision, each stage is lit and
// counted from its own API, the learning loop is drawn, the scorecard and learning come from the officer; a stage opens its page;
// record text stays text; a viewer reads; Arabic; phone width.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node risk-flow.test.js   (SHOTS=dir also saves a screenshot)
const http = require('http'), fs = require('fs'), path = require('path');
const ITAM = path.join(__dirname, '..', '..', 'backend', 'itam'), DASH = path.join(__dirname, '..', '..', 'ui');
const H = require(path.join(ITAM, 'tests', 'helpers'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
(async () => {
  const e = await H.startApp({ noAi: true });
  require(path.join(ITAM, 'engine/duty')).registerDuty(e.app.srv, e.app, { noTimer: true, now: () => Date.parse('2026-11-11T08:00:00Z'), python: process.env.PYTHON || 'python3' });
  const F = require(path.join(ITAM, 'tests', 'brisk-fixture'));
  const OP = { user: 'nora.syn', role: 'operator' }, ADM = { user: 'adam.syn', role: 'admin' };
  const api = (m, p, b, who) => e.req(m, p, Object.assign(b !== undefined ? { body: b } : {}, who || OP));
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
  const base = 'http://127.0.0.1:' + srv.address().port + '/risk-flow.html';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  const wait = (p, fn) => p.waitForFunction(fn, null, { timeout: 30000 }).then(() => true, () => false);
  const drawn = (p) => wait(p, () => document.querySelectorAll('#flow a[data-stage]').length === 7 && document.querySelectorAll('#kk .t').length === 6);
  const stages = (p) => p.evaluate(() => Object.fromEntries([...document.querySelectorAll('#flow a[data-stage]')].map((a) => [a.dataset.stage, { stroke: a.querySelector('rect').getAttribute('stroke'), text: [...a.querySelectorAll('text')].map((t) => t.textContent).join(' | ') }])));
  try {
    const p = await browser.newPage({ viewport: { width: 1400, height: 1000 } }); p.on('pageerror', (x) => errs.push(x.message));
    // nothing imported yet: no source, nothing lit as working
    await p.goto(base + '?standalone=1'); ok(await drawn(p), 'the flow draws seven stages and six tiles');
    let S = await stages(p);
    ok(/register not imported/.test(S.src.text) && /RAS not imported/.test(S.src.text) && S.src.stroke !== '#3fb950', 'before the import: the sources say what is missing, not green: ' + S.src.text);
    ok(S.rate.stroke !== '#3fb950' && S.people.stroke !== '#3fb950', 'nothing rated or decided is not shown as working');

    // import, report values, let the officer patrol and propose, decide one
    await api('POST', '/brisk/import/register', { filename: 'reg.xlsx', xlsx_b64: await F.registerB64(), apply: true }, ADM);
    await api('POST', '/brisk/import/ras', { filename: 'ras.xlsx', xlsx_b64: await F.rasB64(), apply: true }, ADM);
    const solv = (await api('POST', '/brisk/risks', { likelihood: 4, impact: 4, exposure: 3, owner: 'syn.owner', department: 'Synthetic Finance', title: 'Solvency ratio falls below the regulatory capital margin <img src=x onerror=window.__x=1>', description: 'Synthetic: regulatory capital over the required margin drops', area: 'Strategic_Risk' })).json;
    await api('POST', '/brisk/ras/actuals', { rows: [{ metric: 'RAS-02.03', period: '2026-10', value: 'no', note: 'synthetic' }].concat(['320%', '300%', '290%', '275%', '262%'].map((v, i) => ({ metric: 'RAS-01.01', period: '2026-' + String(6 + i).padStart(2, '0'), value: v }))) });
    const O = e.app.addons.riskOfficer; let k = 0; for (const it of await O.current()) await O.propose(Object.assign({ id: 'DI-' + (++k) }, it));
    const q = (await api('GET', '/brisk/officer', undefined, OP)).json.queue, link = q.find((x) => x.step === 'link' && x.params.risk === solv.id);
    ok(!!link, 'the officer proposed a link for the unwatched risk');
    await api('POST', '/brisk/officer/' + encodeURIComponent(link.id) + '/decide', { decision: 'approve' }, OP);
    const V = (await api('GET', '/brisk/officer', undefined, OP)).json;

    await p.goto(base + '?standalone=1'); await drawn(p); S = await stages(p);
    ok(/38 register risks/.test(S.src.text) && /8 appetite metrics/.test(S.src.text) && S.src.stroke === '#3fb950', 'sources: both workbooks, lit: ' + S.src.text);
    ok(/39\/39 rated/.test(S.rate.text) && /Class III \/ IV: \d+/.test(S.rate.text), 'methodology: rated on the server: ' + S.rate.text);
    ok(/likely duplicate/.test(S.ml.text) && /early warning/.test(S.ml.text) && S.ml.stroke === '#3fb950', 'machine learning: duplicates, consistency, early warnings: ' + S.ml.text);
    ok(new RegExp(V.queue.length + ' proposal').test(S.officer.text) && /1 decided/.test(S.officer.text) && S.officer.stroke === '#3fb950', 'officer: its queue and decisions from /brisk/officer: ' + S.officer.text);
    ok(/passed/.test(S.sup.text) && /held, escalated/.test(S.sup.text), 'supervisor: its verdicts: ' + S.sup.text);
    ok(/1 approved · 0 rejected/.test(S.people.text) && /limit change/.test(S.people.text) && S.people.stroke === '#3fb950', 'people decide: approvals, limit changes waiting, acceptances: ' + S.people.text);
    ok(/\d+\/\d+ targets met/.test(S.act.text), 'actions and outcomes: from the scorecard: ' + S.act.text);
    const pg = await p.evaluate(() => ({ loop: [...document.querySelectorAll('#flow text')].some((t) => t.textContent === 'learns from every decision'), tiles: document.getElementById('kk').textContent, score: document.querySelectorAll('#score .row').length, learn: document.getElementById('learn').textContent, how: document.querySelectorAll('#how li').length, xss: window.__x === 1 || !!document.querySelector('img[src="x"]') }));
    ok(pg.loop && /Stages working/.test(pg.tiles) && pg.score === 7 && /risk unwatched/.test(pg.learn) && /threshold/.test(pg.learn) && pg.how === 7, 'the loop, the tiles, the 7 outcome measures, what it learned, what each stage does');
    ok(!pg.xss, 'record text stays text');
    if (process.env.SHOTS) { await p.waitForTimeout(300); await p.screenshot({ path: path.join(process.env.SHOTS, 'risk-flow.png'), fullPage: true }); }
    await Promise.all([p.waitForURL(/ai-team\.html/, { timeout: 10000 }).catch(() => null), p.click('#flow a[data-stage="officer"]')]); ok(/ai-team\.html/.test(p.url()), 'a stage opens its page');
    // a viewer reads; Arabic; phone
    who = { user: 'vera.syn', role: 'viewer' }; await p.goto(base + '?standalone=1'); ok(await drawn(p), 'a viewer reads the flow');
    who = ADM; await p.evaluate(() => localStorage.setItem('zyb-dash-prefs', JSON.stringify({ lang: 'ar' }))); await p.goto(base); await drawn(p);
    ok(await p.evaluate(() => document.documentElement.dir === 'rtl' && document.documentElement.scrollWidth <= innerWidth + 1 && getComputedStyle(document.querySelector('#flow svg')).direction === 'ltr'), 'Arabic: right to left, the flow keeps its direction, no sideways scroll');
    await p.evaluate(() => localStorage.setItem('zyb-dash-prefs', JSON.stringify({ lang: 'en' })));
    const m = await browser.newPage({ viewport: { width: 390, height: 860 } }); m.on('pageerror', (x) => errs.push(x.message));
    await m.goto(base + '?standalone=1'); await drawn(m); ok(await m.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1), 'phone width: the flow scrolls in its card, the page does not');
    const nav = await p.evaluate(() => (window.ZYB_NAV.find((a) => a.id === 'ai') || { pages: [] }).pages.map((x) => x.h));
    ok(nav.includes('risk-flow.html') && /risk-flow\.html/.test(fs.readFileSync(path.join(DASH, 'install-dashboards.sh'), 'utf8')), 'in the AI section of the menu and the installer');
  } finally { await browser.close(); srv.close(); await e.close(); }
  ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks'); process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
