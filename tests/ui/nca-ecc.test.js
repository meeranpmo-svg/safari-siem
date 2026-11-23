// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for the NCA ECC Verification page (dashboards/server/nca-ecc.html) against the REAL ITAM engine
// (engine/nca-ecc.js + pyengine/nca_ecc_rules.py) with SYNTHETIC facts: 29 subdomain tiles with labelled bars, the sources
// card, a subdomain tile filters the controls, verified / gap / not measured shown with their reasons, a manual control
// recorded in the drawer and approved by a different person, the official list imported and a suggestion accepted, the
// profile saved, gaps sent to GRC, a hostile value stays text, a viewer cannot record, the menu has the page.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node nca-ecc.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const ITAM = path.join(__dirname, '..', '..', 'backend', 'itam'), DASH = path.join(__dirname, '..', '..', 'ui');
const H = require(path.join(ITAM, 'tests', 'helpers'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const XSS = '<img src=x onerror=alert(1)>';
const FACTS = () => ({
  grc: { available: true, total: 20, reviews_overdue: 0, attested: 15, policies: [], control_status: { assets: { state: 'pass', metric: '40 registered', detail: 'ok' }, patch: { state: 'fail', metric: '30/40 healthy', detail: '10 host(s) missing critical patches ' + XSS } } },
  ownership: { available: true, assets: 40, missing_it: 0, missing_business: 0 },
  siem: { available: true, sama: { '3.3.14': 'covered' }, retention_days: 400, logflow: { required: 10, silent: 0 } },
});

(async () => {
  const e = await H.startApp({ noAi: true });
  require(path.join(ITAM, 'engine/duty')).registerDuty(e.app.srv, e.app, { noTimer: true, python: process.env.PYTHON || 'python3', eccFacts: async () => FACTS() });
  const adm = async (p, body) => { const r = await e.req('POST', p, { body, user: 'syed', role: 'admin' }); if (r.status !== 200) throw new Error(p + ': ' + r.raw); return r.json; };
  await adm('/nca-ecc/profile', { ciso_user: 'khalid.syn', function_established: '2025-01-01', reports_to: 'CEO' });
  let WHO = { user: 'nora.syn', role: 'operator' };
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
  const zd = (p, re) => p.waitForFunction((src) => new RegExp(src).test((document.getElementById('zd') || {}).textContent || ''), re.source, { timeout: 10000 }).then(() => true, () => false);
  try {
    const p = await browser.newPage({ viewport: { width: 1400, height: 950 }, acceptDownloads: true }); p.on('pageerror', (x) => errs.push(x.message));
    p.on('dialog', (d) => d.accept('no report (synthetic)'));
    await p.goto(base + 'nca-ecc.html?standalone=1'); await p.waitForSelector('#list table', { state: 'attached', timeout: 15000 });
    ok((await p.$$eval('#subs .sub', (x) => x.length)) === 29, '29 subdomain tiles');
    ok(await p.$$eval('#subs .stack span', (x) => x.length > 0 && x.every((s) => s.getAttribute('title'))), 'every bar segment labelled');
    const lg = await p.textContent('#subs .legend');
    ok(/Fully compliant/.test(lg) && /Partially compliant/.test(lg) && /Not compliant/.test(lg) && /Not assessed/.test(lg), 'legend names the colours in NCA terms');
    // every subdomain tile and domain heading gives the four NCA percentages, adding up to 100
    const tiles = await p.$$eval('#subs .sub', (x) => x.map((t) => t.textContent));
    const sums = tiles.filter((t) => !/not applicable/.test(t)).map((t) => [...t.matchAll(/(\d+)%/g)].reduce((a, m) => a + Number(m[1]), 0));
    ok(sums.length > 20 && sums.every((n) => n === 100), 'each subdomain: fully / partially / not / not assessed % add up to 100: ' + sums.join(','));
    ok(tiles.every((t) => /Fully compliant|Partially compliant|Not compliant|Not assessed|Not applicable/.test(t)), 'every subdomain tile states its NCA status');
    ok((await p.$$eval('#subs .dhead', (x) => x.filter((h) => /Fully \d+%/.test(h.textContent) && /Not assessed \d+%/.test(h.textContent)).length)) === 5, 'each domain heading gives its percentages');
    ok(/not connected/.test(await p.textContent('#srcs')) && /connected/.test(await p.textContent('#srcs')), 'sources card');
    const kp = await p.textContent('#kpis');
    ok(/Overall \(NCA assessment\)/.test(kp) && /Fully compliant/.test(kp) && /Partially compliant/.test(kp) && /Not compliant/.test(kp) && /Not assessed yet/.test(kp) && /Not measured/.test(kp), 'KPIs: ' + kp.replace(/\s+/g, ' ').slice(0, 160));
    const list = await p.textContent('#list');
    ok(/ZS-2-3-02/.test(list) && list.includes(XSS) && !(await p.$('#list img')), 'a gap with its reason; a hostile value stays text');
    ok(/not measured: /.test(list), 'not measured says what to connect');
    // filter by a subdomain tile
    await p.click('[data-sub="2-12"]');
    ok((await p.$$eval('#list tbody tr', (x) => x.length)) === 3 && /\(3 of /.test(await p.textContent('#filt')), 'subdomain tile filters the controls');
    await p.click('[data-sub="2-12"]');
    // record a manual control
    await p.selectOption('#fsub', '2-14'); await p.click('#list tr[data-id="ZS-2-14-01"]'); await p.waitForSelector('#cform', { timeout: 8000 });
    await p.selectOption('#cform [name=status]', 'compliant'); await p.fill('#cform [name=evidence]', 'badge access review Q3 (synthetic)'); await p.click('#cform [type=submit]');
    ok(await zd(p, /waiting for a second person/), 'recorded, waiting for approval');
    await p.click('[data-decide="approve"]'); ok(await zd(p, /CISO or an administrator|never the person/), 'the recorder sees the four-eyes rule');
    await p.keyboard.press('Escape');
    WHO = { user: 'khalid.syn', role: 'operator' }; await p.reload(); await p.waitForSelector('#list table', { state: 'attached', timeout: 15000 });
    await p.selectOption('#fsub', '2-14'); await p.click('#list tr[data-id="ZS-2-14-01"]'); await p.waitForSelector('[data-decide="approve"]', { timeout: 8000 }); await p.click('[data-decide="approve"]');
    ok(await zd(p, /Approved by khalid\.syn/), 'approved by the CISO');
    await p.keyboard.press('Escape');
    // official list
    WHO = { user: 'syed', role: 'admin' }; await p.reload(); await p.waitForSelector('#list table', { state: 'attached', timeout: 15000 });
    await p.click('[data-tab="official"]');
    await p.fill('#paste', 'code,title,specification\n2-12-3-5,"Retention of cybersecurity event logs (synthetic text)",\n9-9-9,bad,\n');
    await p.click('#imp'); await p.waitForFunction(() => /imported/.test(document.getElementById('impmsg').textContent), null, { timeout: 10000 });
    ok(/1 imported, 1 refused/.test(await p.textContent('#impmsg')), 'import checked: ' + await p.textContent('#impmsg'));
    await p.waitForSelector('[data-accept="2-12-3-5"]', { timeout: 10000 });
    ok(/ZS-2-12-03/.test(await p.textContent('#unmapped')), 'suggestion within the subdomain');
    await p.click('[data-accept="2-12-3-5"]'); await p.waitForFunction(() => /Every|^\s*$/.test(document.getElementById('unmapped').textContent) || !document.querySelector('[data-accept]'), null, { timeout: 10000 });
    ok((await e.req('GET', '/nca-ecc', { user: 'syed', role: 'admin' })).json.coverage.mapped === 1, 'mapped');
    // profile: ICS not applicable needs a reason
    await p.click('[data-tab="profile"]'); await p.selectOption('#pform [name=ics]', 'not_applicable'); await p.click('#pform [type=submit]');
    await p.waitForFunction(() => /applicability_note/.test(document.getElementById('pform').textContent), null, { timeout: 8000 }).then(() => ok(true), () => ok(false, 'a reason is required'));
    await p.fill('#pform [name=ics_note]', 'no industrial control systems (synthetic)'); await p.click('#pform [type=submit]');
    await p.waitForFunction(() => /not applicable/i.test(document.getElementById('subs').textContent), null, { timeout: 8000 }).then(() => ok(true), () => ok(false, 'ICS marked not applicable'));
    // gaps to GRC
    const [gr] = await Promise.all([p.waitForResponse((r) => /gaps-to-grc$/.test(r.url())), p.click('#grc')]);
    ok(gr.status() === 200, 'gaps to GRC: ' + gr.status() + ' ' + (await gr.text()).slice(0, 200));
    ok(e.app.store.collection('grc_actions').all((a) => a.source === 'nca').length > 0, 'GRC actions created: ' + (await p.textContent('.toast-zyb').catch(() => '')));
    const [dl] = await Promise.all([p.waitForEvent('download'), p.click('#csv')]);
    ok(/^nca-ecc-register-\d{4}-\d{2}-\d{2}\.csv$/.test(dl.suggestedFilename()), 'CSV export');
    ok(await p.evaluate(() => (window.ZYB_NAV || []).some((a) => a.pages.some((x) => x.h === 'nca-ecc.html' && x.g === 'NCA ECC'))), 'in the menu under Compliance -> NCA ECC');
    // a viewer cannot record
    WHO = { user: 'v.syn', role: 'viewer' }; await p.reload(); await p.waitForSelector('#list table', { state: 'attached', timeout: 15000 });
    await p.selectOption('#fsub', '2-15'); await p.click('#list tr[data-id="ZS-2-15-01"]'); await p.waitForSelector('#cform', { timeout: 8000 });
    await p.selectOption('#cform [name=status]', 'compliant'); await p.fill('#cform [name=evidence]', 'x'); await p.click('#cform [type=submit]');
    await p.waitForFunction(() => /operator|not allowed|forbidden|403/i.test(document.getElementById('cform').textContent), null, { timeout: 8000 }).then(() => ok(true), () => ok(false, 'a viewer is refused'));
  } finally { await browser.close(); srv.close(); e.close(); }
  ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks');
  process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
