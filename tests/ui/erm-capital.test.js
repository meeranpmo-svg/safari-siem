// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for Capital, ORSA & Stress Testing (dashboards/server/erm-capital.html) against the REAL engine (engine/erm-capital.js),
// SYNTHETIC figures, several named people: finance enters a position on the form and cannot confirm it, the CFO confirms it; the CRO
// links the RAS metric and the ratio is judged; an actuary proposes a stress scenario (a hostile name stays text) and the CRO
// approves it - the ladder shows before / after the shock / after the actions; the ORSA is opened, written, submitted and the Board
// approval recorded by someone else, and its report shows; an initiative is raised, reviewed and decided by three people; a viewer
// reads everything and has no form or button that writes; no page error.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node erm-capital.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const ITAM = path.join(__dirname, '..', '..', 'backend', 'itam'), DASH = path.join(__dirname, '..', '..', 'ui');
const H = require(path.join(ITAM, 'tests', 'helpers'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const XSS = '<img src=x onerror="window.__xss=1">';

(async () => {
  const e = await H.startApp({ noAi: true });
  const M = require(path.join(ITAM, 'engine/erm-capital')), X = M.createErmCapital(e.app); M.registerErmCapital(e.app.srv, e.app, X);
  e.app.store.collection('br_metrics').put({ id: 'M-SOL', component: 'Solvency coverage ratio SYN', kind: 'floor', unit: 'ratio', limits: { app_floor: 1.5, tol_floor: 1.2, cap_floor: 1.0 } });
  let WHO = { user: 'fin.syn', role: 'operator' };
  const web = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://x'), json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u.pathname === '/dashboards/whoami.json') return json(200, WHO);
    if (u.pathname.startsWith('/api/itam/')) {
      const h = Object.assign({}, req.headers, { 'x-sentra-proxy-secret': H.SECRET, 'x-auth-user': WHO.user, 'x-auth-role': WHO.role });
      const up = http.request({ host: '127.0.0.1', port: e.port, method: req.method, path: req.url, headers: h }, (r) => { res.writeHead(r.statusCode, r.headers); r.pipe(res); });
      req.pipe(up); return;
    }
    if (u.pathname.startsWith('/api/') || u.pathname.startsWith('/auth/')) return json(404, { error: 'not in this test' });
    const f = path.join(DASH, u.pathname.replace(/^\/dashboards\//, '/')); if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (err, d) => { if (err) { res.writeHead(404); res.end(); return; } res.writeHead(200, { 'Content-Type': u.pathname.endsWith('.js') ? 'application/javascript' : u.pathname.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => web.listen(0, '127.0.0.1', r));
  const url = 'http://127.0.0.1:' + web.address().port + '/dashboards/erm-capital.html?standalone=1';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  const wait = (p, fn, arg) => p.waitForFunction(fn, arg, { timeout: 15000 }).then(() => true, () => false);
  const T = (p, id) => p.textContent('#' + id);
  try {
    const p = await browser.newPage({ viewport: { width: 1400, height: 1100 } }); p.on('pageerror', (x) => errs.push(x.message));
    const as = async (who) => { WHO = who; await p.goto(url); await wait(p, () => !!document.querySelector('#kk .t')); };
    await as({ user: 'fin.syn', role: 'operator' });
    ok(/No capital position yet/.test(await T(p, 'plist')), 'the empty state says what to enter');
    // finance enters the position on the form
    await p.fill('#p-per', '2026-Q3'); await p.fill('#p-av', '900000000'); await p.fill('#p-rq', '500000000'); await p.fill('#p-lq', '600000000'); await p.fill('#p-of', '300000000'); await p.fill('#p-src', 'Q3 management accounts SYN');
    const li = await p.$$('#p-lines [data-k]'); const vals = ['Motor SYN', '800000000', '700000000', '600000000', '150000000', '-20000000', '250000000']; for (let i = 0; i < vals.length; i++) await li[i].fill(vals[i]);
    await p.click('#p-go'); ok(await wait(p, () => /2026-Q3/.test(document.getElementById('plist').textContent) && /not yet/.test(document.getElementById('plist').textContent)), 'the position is saved, not confirmed');
    ok(/180\.0%/.test(await T(p, 'plist')) && /link the RAS metric/.test(await T(p, 'plist')), 'solvency shown, not judged without a linked metric');
    ok(!(await p.$('[data-confirm]')), 'the person who entered it has no Confirm button');
    // the CFO confirms; the CRO links the metric
    await as({ user: 'cfo.syn', role: 'admin' }); await p.click('[data-confirm="pos-2026-Q3"]');
    ok(await wait(p, () => /cfo\.syn/.test(document.getElementById('plist').textContent)), 'confirmed by the CFO');
    await as({ user: 'cro.syn', role: 'admin' }); await p.click('[data-tab="set"]'); await p.selectOption('#st-sol', 'M-SOL'); await p.fill('#st-h', '12'); await p.click('#st-go');
    ok(await wait(p, () => /within appetite/.test(document.getElementById('plist').textContent)), 'judged against the RAS once linked');
    ok(/90\.0%/.test(await T(p, 'sens')), 'the sensitivity table: a 50% fall leaves 90%');
    // an actuary proposes a scenario; the CRO approves it
    await as({ user: 'actuary.syn', role: 'operator' }); await p.click('[data-tab="stress"]');
    await p.fill('#s-name', 'Cat and market SYN ' + XSS); await p.selectOption('#s-cat', 'combined'); await p.fill('#s-desc', 'a 1-in-200 flood with markets down (synthetic)'); await p.fill('#s-cap', '-45'); await p.fill('#s-req', '10');
    const ac = await p.$$('#s-acts [data-k]'); const av = ['Suspend the dividend SYN', 'solvency below 130%', 'cfo.syn', '80000000', '-60000000', '']; for (let i = 0; i < av.length; i++) if (av[i]) await ac[i].fill(av[i]);
    await p.click('#s-go'); ok(await wait(p, () => /proposed/.test(document.getElementById('slist').textContent)), 'proposed');
    ok(!(await p.$('[data-sdec]')), 'the proposer cannot approve');
    await as({ user: 'cro.syn', role: 'admin' }); await p.click('[data-tab="stress"]');
    const sid = await p.getAttribute('[data-sdec="approve"]', 'data-id'); await p.fill('#sn-' + sid, 'risk committee SYN'); await p.click('[data-sdec="approve"]');
    ok(await wait(p, () => /117\.3%/.test(document.getElementById('slist').textContent)), 'the ladder: after the actions 117.3%');
    const sl = await T(p, 'slist'); ok(/90\.0%/.test(sl) && /capacity breach/.test(sl) && /outside tolerance/.test(sl) && /reaches 100% if available capital falls 38\.89%/.test(sl), 'shock judged, reverse stress said: ' + sl.replace(/\s+/g, ' ').slice(0, 300));
    ok(sl.includes(XSS) && await p.evaluate(() => window.__xss === undefined), 'a hostile name stays text');
    // the ORSA
    await p.click('[data-tab="orsa"]'); await p.fill('#o-yr', '2026'); await p.selectOption('#o-pos', 'pos-2026-Q3'); await p.fill('#o-due', '2027-04-30'); await p.click('#o-go');
    ok(await wait(p, () => /ORSA-2026/.test(document.getElementById('olist').textContent)), 'opened');
    await as({ user: 'actuary.syn', role: 'operator' }); await p.click('[data-tab="orsa"]'); await p.click('[data-orsa="ORSA-2026"]');
    await p.fill('#oe-business_plan', 'Grow medical 8% a year, hold motor flat (synthetic)'); await p.fill('#oe-conclusions', 'Capital covers the plan and the approved stress after actions (synthetic).');
    const pj = await p.$$('#oe-proj [data-k]'); await pj[0].fill('2027'); await pj[1].fill('950000000'); await pj[2].fill('540000000');
    await p.click('#oe-sub'); ok(await wait(p, () => /submitted/.test(document.getElementById('olist').textContent)), 'submitted and frozen');
    await as({ user: 'cfo.syn', role: 'admin' }); await p.click('[data-tab="orsa"]'); await p.click('[data-orsa="ORSA-2026"]');
    await p.fill('#od-ref', 'BRD-2026-11 SYN'); await p.fill('#od-n', 'approved by the Board (synthetic)'); await p.click('#od-go');
    ok(await wait(p, () => /BRD-2026-11 SYN/.test(document.getElementById('olist').textContent)), 'the Board approval recorded with its reference');
    await p.click('[data-orsa="ORSA-2026"]'); await p.click('#oe-rep'); ok(await wait(p, () => /Stress testing/.test(document.getElementById('oe-out').textContent) && /sha256:/.test(document.getElementById('oe-out').textContent)), 'the report with its fingerprint');
    // an initiative: raised by finance, reviewed by the actuary, decided by the CRO
    await as({ user: 'fin.syn', role: 'operator' }); await p.click('[data-tab="ini"]');
    await p.fill('#i-t', 'Acquire a takaful book SYN'); await p.selectOption('#i-k', 'm_and_a'); await p.fill('#i-sp', 'ceo.syn'); await p.fill('#i-d', 'buy a medical book (synthetic)'); await p.fill('#i-ca', '-150000000'); await p.fill('#i-rq', '80000000'); await p.fill('#i-due', '2027-01-31');
    await p.click('#i-go'); ok(await wait(p, () => /awaiting review/.test(document.getElementById('ilist').textContent) && /129\.3%/.test(document.getElementById('ilist').textContent)), 'raised with its pro-forma solvency');
    ok(!(await p.$('[data-review]')), 'the person who raised it does not review it');
    await as({ user: 'actuary.syn', role: 'operator' }); await p.click('[data-tab="ini"]');
    const iid = await p.getAttribute('[data-review]', 'data-review'); await p.selectOption('#rv-a-' + iid, 'outside'); await p.fill('#rv-r-' + iid, 'solvency falls to 129%, outside appetite (synthetic)'); await p.click('[data-review]');
    ok(await wait(p, () => /awaiting decision/.test(document.getElementById('ilist').textContent)), 'reviewed');
    await as({ user: 'cro.syn', role: 'admin' }); await p.click('[data-tab="ini"]'); await p.fill('#dc-n-' + iid, 'Board accepted a temporary breach with a capital plan (synthetic)'); await p.click('[data-idec="' + iid + '"]');
    ok(await wait(p, () => /Decision: approve/.test(document.getElementById('ilist').textContent)), 'decided by a third person');
    ok(/Return on risk capital/.test(await p.textContent('#t-perf')), 'the performance tab is there');
    // a viewer reads, no write controls
    await as({ user: 'vera.syn', role: 'viewer' });
    ok(await p.isHidden('#pform') && await p.isHidden('#sform') && await p.isHidden('#iform') && !(await p.$('[data-confirm],[data-sdec],[data-review],[data-idec],#o-go:visible,#st-go')), 'a viewer has nothing that writes');
    await p.click('[data-tab="perf"]'); ok(/Motor SYN/.test(await T(p, 'perf')) && /below the hurdle of 12%/.test(await T(p, 'perf')), 'the performance table with its flags');
    ok(e.app.store.auditTail(200).filter((a) => /^erm-capital\./.test(a.action)).length >= 10, 'every step audited');
  } finally { await browser.close(); web.close(); await e.close(); }
  ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks'); process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
