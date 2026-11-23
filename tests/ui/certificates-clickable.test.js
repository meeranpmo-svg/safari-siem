// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test: every number on certificates.html opens the list it counts, against the REAL ITAM engine (certs.js + the
// Python rules) with a stubbed TLS reader and SYNTHETIC endpoints. Each summary tile filters the Endpoints tab (expired, not
// read); "renewals open" opens Renewals. In the four pillars, the certificate count opens All certificates, "expired or
// ≤ 30 days" and an expiry bar narrow it (with a chip and Show all), and "within policy" lists what is outside policy. On the
// Discover tab, "Added from discovery" filters the endpoints. Report tiles open their tab. A tile also opens with the keyboard.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node certificates-clickable.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const ITAM = path.join(__dirname, '..', '..', 'backend', 'itam'), DASH = path.join(__dirname, '..', '..', 'ui');
const H = require(path.join(ITAM, 'tests', 'helpers'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const NOW = Date.now(), DAY = 86400000;
const CERT = (cn, days) => ({ ok: true, subject: cn, issuer: 'Corp Issuing CA', names: [cn], name_ok: true, trusted: true, self_signed: false, not_before: NOW - 300 * DAY, not_after: NOW + days * DAY, not_after_iso: new Date(NOW + days * DAY).toISOString().slice(0, 10), key_type: 'rsa', key_bits: 2048, serial: 'AB' + cn.length, fingerprint256: 'FP:' + cn });
const TLS = { '10.9.0.1:443': CERT('old.corp.syn', -5), '10.9.0.2:443': CERT('good.corp.syn', 200), '10.9.0.4:443': CERT('found.corp.syn', 120) };

(async () => {
  const e = await H.startApp({ noAi: true });
  require(path.join(ITAM, 'engine/duty')).registerDuty(e.app.srv, e.app, { noTimer: true, python: process.env.PYTHON || 'python3', readCert: async (h, p) => TLS[h + ':' + p] || { ok: false, error: 'ECONNREFUSED' } });
  const C = e.app.addons.certs, W = { user: 'nora.syn', role: 'operator', ip: '' };
  C.putEndpoint({ host: '10.9.0.1', port: 443, label: 'Old portal', owner: 'nora.syn' }, W);
  C.putEndpoint({ host: '10.9.0.2', port: 443, label: 'Good site', owner: 'nora.syn' }, W);
  C.putEndpoint({ host: '10.9.0.3', port: 443, label: 'Dead box' }, W);
  C.putEndpoint({ host: '10.9.0.4', port: 443, label: 'Found server', source: 'discovery' }, W);
  await C.scan(null, W);
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
  const rows = (p, sel) => p.$$eval(sel + ' tbody tr', (x) => x.map((r) => r.textContent));
  const visible = (p, id) => p.$eval('#v-' + id, (x) => !x.hidden);
  try {
    const p = await browser.newPage({ viewport: { width: 1400, height: 1000 } }); p.on('pageerror', (x) => errs.push(x.message));
    await p.goto(base + 'certificates.html?standalone=1'); await p.waitForSelector('#inv tbody tr', { state: 'attached', timeout: 15000 });   // loaded behind the Renewal autopilot, the default tab since a2b2ed77 await p.waitForSelector('#pillars [data-goto]', { timeout: 15000 }).catch(async (x) => { console.log('PILLARS', (await p.innerHTML('#pillars')).slice(0, 600)); throw x; });
    // summary tiles
    await p.click('#kpis [data-goto="inventory|expired"]');
    let r = await rows(p, '#inv');
    ok(await visible(p, 'inventory') && (await p.inputValue('#st')) === 'expired' && r.length === 1 && /Old portal/.test(r[0]), 'expired tile -> the expired endpoint only: ' + r.length);
    await p.click('#kpis [data-goto="inventory|notread"]');
    r = await rows(p, '#inv'); ok(r.length === 1 && /Dead box/.test(r[0]), 'not read tile -> the unreachable endpoint');
    await p.click('#kpis [data-goto="inventory|"]'); ok((await rows(p, '#inv')).length === 4, 'endpoints tile -> all four');
    await p.click('#kpis [data-goto="renewals"]'); ok(await visible(p, 'renewals'), 'renewals open tile -> Renewals');
    // the pillars
    await p.click('#pillars [data-goto="estate|"]'); await p.waitForSelector('#estate tbody tr', { timeout: 8000 });
    ok(await visible(p, 'estate') && (await rows(p, '#estate')).length === 3, 'certificates -> All certificates (3 read)');
    await p.click('#pillars [data-goto="estate|soon"]');
    r = await rows(p, '#estate');
    ok(r.length === 1 && /old\.corp\.syn/.test(r[0]) && /Showing: expired or ≤ 30 days/.test(await p.textContent('#esrcs')), 'expired or ≤ 30 days -> only that one, with the chip');
    await p.click('[data-efclear]'); ok((await rows(p, '#estate')).length === 3 && !/Showing/.test(await p.textContent('#esrcs')), 'Show all clears it');
    await p.click('#pillars [data-goto="estate|b:180+"]'); r = await rows(p, '#estate'); ok(r.length === 1 && /good\.corp\.syn/.test(r[0]), 'an expiry bar -> its bucket');
    await p.click('#pillars [data-goto="estate|risk"]'); r = await rows(p, '#estate'); ok(r.length === 1 && /old\.corp\.syn/.test(r[0]) && /outside policy/.test(await p.textContent('#esrcs')), 'within policy -> what is outside policy');
    await p.click('#pillars [data-goto="requests"]'); ok(await visible(p, 'requests'), 'issued -> Issuance');
    await p.click('#pillars [data-goto="install"]'); ok(await visible(p, 'install'), 'published -> Publishing');
    // the Discover tab
    await p.click('[data-tab="discover"]'); await p.waitForSelector('#autod [data-goto="inventory|discovery"]', { timeout: 8000 });
    await p.click('#autod [data-goto="inventory|discovery"]'); r = await rows(p, '#inv');
    ok(r.length === 1 && /Found server/.test(r[0]) && /Added from discovery/.test(await p.textContent('#ifl')), 'added from discovery -> that endpoint, with the chip');
    await p.click('[data-ifclear]'); ok((await rows(p, '#inv')).length === 4, 'Show all on the endpoints');
    // the report, and the keyboard
    await p.click('[data-tab="report"]'); await p.waitForSelector('#report [data-goto="inventory|noowner"]', { timeout: 8000 });
    await p.focus('#report [data-goto="inventory|noowner"]'); await p.keyboard.press('Enter');
    r = await rows(p, '#inv'); ok(r.length === 2 && r.every((x) => /Dead box|Found server/.test(x)), 'endpoints with an owner (keyboard) -> the two without one');
    ok(await p.$$eval('[data-goto]', (x) => x.every((el) => el.getAttribute('role') === 'button' && el.getAttribute('tabindex') === '0')), 'every clickable number is a keyboard button');
  } finally { await browser.close(); srv.close(); e.close(); }
  ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks');
  process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
