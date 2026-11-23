// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for the Risk Command Center (dashboards/server/risk-command.html) against the REAL ITAM engines (risk register,
// Risk Studio, scenario assessment, engine/risk-command.js) with SYNTHETIC risks: the posture gauge and its itemised breakdown, KPIs,
// the residual / inherent heat map toggle, the Monte Carlo with its stated model, risks above appetite, categories against appetite,
// treatment effectiveness, owners, the ten scenarios, quick links to the risk pages, a hostile title stays text, the advisor off
// until allowed, and the menu: Risk & Governance with the page first, sub-menus in order.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node risk-command.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const ITAM = path.join(__dirname, '..', '..', 'backend', 'itam'), DASH = path.join(__dirname, '..', '..', 'ui');
const H = require(path.join(ITAM, 'tests', 'helpers'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const XSS = '<img src=x onerror=alert(1)>';
const OP = { user: 'nora.syn', role: 'operator' }, LEAD = { user: 'laila.syn', role: 'operator' }, HEAD = { user: 'hana.syn', role: 'operator' }, OWNER = { user: 'omar.syn', role: 'operator' };
const ADM = { user: 'syed', role: 'admin' }, VIEW = { user: 'vera.syn', role: 'viewer' };


(async () => {
  const e = await H.startApp({ noAi: true });
  require(path.join(ITAM, 'engine/duty')).registerDuty(e.app.srv, e.app, { noTimer: true });
  const api = async (who, m, p, body) => { const r = await e.req(m, p, Object.assign(body !== undefined ? { body } : {}, who)); if (r.status !== 200) throw new Error(p + ': ' + r.raw); return r.json; };
  for (const [title, likelihood, impact, rl, ri, treatment, owner] of [['Ransomware on claims servers (synthetic) ' + XSS, 4, 5, 3, 5, 'mitigate', 'ali.syn'], ['Leaver accounts not disabled (synthetic)', 4, 4, 2, 3, 'mitigate', 'ali.syn'],
    ['Vendor outage of the policy system (synthetic)', 3, 5, 3, 5, 'mitigate', 'sara.syn'], ['PDPL breach notified late (synthetic)', 2, 5, null, null, 'accept', 'omar.syn']]) {
    const b = { title, likelihood, impact, treatment, owner, description: 'synthetic' }; if (rl) Object.assign(b, { residual_likelihood: rl, residual_impact: ri }); await api(OP, 'POST', '/grc/risks', b);
  }
  let WHO = VIEW;
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
    const p = await browser.newPage({ viewport: { width: 1400, height: 950 } }); p.on('pageerror', (x) => errs.push(x.message));
    p.on('dialog', (d) => { errs.push('dialog: ' + d.message()); d.dismiss(); });
    await p.goto(base + 'risk-command.html?standalone=1'); await p.waitForSelector('#kpis .card', { timeout: 15000 });
    ok(/risk posture/i.test(await p.textContent('#gauge')) && /\d+/.test(await p.textContent('#gauge')), 'the posture gauge');
    ok((await p.$$('#ix > div')).length >= 2 && /open risks rated high/.test(await p.textContent('#ix')), 'the posture breakdown is itemised');
    ok(/4\s*Open risks/.test((await p.textContent('#kpis')).replace(/\s+/g, ' ')), 'KPIs');
    const kh = await p.$$eval('#kpis a.kt', (a) => a.map((x) => x.getAttribute('href')));
    ok(kh.join() === 'risk-studio.html#reg=,risk-studio.html#reg=high,risk-studio.html#reg=over,risk-studio.html#reg=under,risk-studio.html#reg=hygiene,risk-studio.html#reg=worse,risk-studio.html#cand,risk-assess.html', 'every tile is a link to the list it counts: ' + kh.join(' '));
    await Promise.all([p.waitForURL(/risk-studio\.html#reg=high/), p.click('#kpis a.kt[href$="#reg=high"]')]);
    ok(await wait(p, () => document.getElementById('flag') && document.getElementById('flag').value === 'high'), 'the "Rated high" tile opens Risk Studio\'s register filtered to high');
    await p.goto(base + 'risk-command.html?standalone=1'); await p.waitForSelector('#kpis .card', { timeout: 15000 });
    ok((await p.$$('#hm td')).length === 25, 'a 5 x 5 heat map');
    const res = await p.textContent('#hm'); await p.click('[data-hm="inherent"]'); ok(await wait(p, () => /before any control/.test(document.getElementById('hm').textContent)), 'the inherent heat map'); ok(res !== await p.textContent('#hm'), 'the toggle changes the map');
    ok(/expected per year/.test(await p.textContent('#simk')) && /not a forecast/.test(await p.textContent('#simwhy')), 'the Monte Carlo with its stated model');
    ok(/above appetite/.test(await p.textContent('#urg')) && (await p.$$('#urg .rk')).length >= 2, 'risks above appetite or rated high');
    ok(!(await p.$('img[src="x"]')) && /<img/.test(await p.textContent('#urg')), 'a hostile title stays text');
    ok((await p.$$('#cat .tr')).length >= 1, 'categories against appetite');
    ok(/mitigate/.test(await p.textContent('#trt')) && /no reduction recorded/.test(await p.textContent('#trt')), 'treatment effectiveness');
    ok(/ali\.syn/.test(await p.textContent('#own')) && /residual score/.test(await p.textContent('#own')), 'risk owners and concentration');
    ok((await p.$$('#scn .sc')).length === 10, 'the ten insurer scenarios');
    const gx = await p.evaluate(() => ({ kic: document.querySelectorAll('#kpis .kt .ic .ti').length, tb: document.querySelectorAll('#trt .tb .stk').length, ring: (document.querySelector('#scg svg.ring text') || {}).textContent, scg: document.getElementById('scg').textContent, num: [...document.querySelectorAll('#scn .sc .n')].map((x) => x.textContent).join(',') }));
    ok(gx.kic === 8 && gx.tb >= 2 && gx.ring === '0/10' && /assess the rest/.test(gx.scg) && /An assessed scenario appears here/.test(gx.scg) && gx.num === '1,2,3,4,5,6,7,8,9,10', 'graphics: KPI icons, treatment bars, the assessed ring (0/10) and numbered scenarios: ' + JSON.stringify(gx));
    ok((await p.$$('#links a')).length === 6 && await p.getAttribute('#links a', 'href') === 'risk-studio.html', 'quick links to the risk pages');
    ok(/Not available/.test(await p.textContent('#ais')), 'the advisor is off until allowed');
    if (process.env.SHOT) await p.screenshot({ path: process.env.SHOT, fullPage: true });
    const nav = await p.evaluate(() => { const a = (window.ZYB_NAV || []).find((x) => x.id === 'grc'); return a ? { name: a.name, pages: a.pages.map((x) => x.h), groups: a.pages.map((x) => x.g) } : null; });
    ok(nav && nav.name === 'Risk & Governance' && nav.pages[0] === 'risk-command.html', 'the menu: Risk & Governance, the Command Center first');
    ok(nav && JSON.stringify([...new Set(nav.groups)]) === JSON.stringify(['Overview', 'Identify & assess', 'Treat & track', 'Registers & reports', 'Policies & roles']), 'risk sub-menus in order: ' + (nav && [...new Set(nav.groups)].join(' > ')));
    ok(/risk-command\.html/.test(fs.readFileSync(path.join(DASH, 'install-dashboards.sh'), 'utf8')), 'in the installer');
  } finally { await browser.close(); srv.close(); await e.close(); }
  ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks');
  process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
