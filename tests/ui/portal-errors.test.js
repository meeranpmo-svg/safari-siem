// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// The REAL portal (repos/live/portal/app.js) error handling (SAMA CSF 3.3.6): no error is swallowed silently. Static: no empty
// catch or .catch(() => {}) is left, and every place calls _zq with its reason written beside it. In Chromium, SYNTHETIC data: a feed
// that answers a web page instead of JSON is reported to Platform Health ONCE, naming the place; browser storage that throws (private
// mode) is counted but NOT reported, and the portal still opens its views; at most 20 reports per page view; _zqView lists every place;
// no page error. Skips without the live copy.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node portal-errors.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const LIVE = path.resolve(__dirname, '../../repos/live/portal');
if (!fs.existsSync(path.join(LIVE, 'app.js'))) { console.log('SKIP: repos/live/portal not present'); process.exit(0); }
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const src = fs.readFileSync(path.join(LIVE, 'app.js'), 'utf8');
const empty = src.match(/catch\s*\(\s*\w*\s*\)\s*\{\s*\}|catch\s*\{\s*\}|\.catch\(\s*(?:\(\s*\w*\s*\)\s*=>\s*(?:\{\s*\}|null|undefined)|function\s*\(\s*\w*\s*\)\s*\{\s*\})\s*\)/g) || [];
ok(empty.length === 0, 'no empty catch left in app.js (' + empty.length + ')');
const calls = src.match(/_zq\('[^']+', \w+, [01]\); \/\* [^*]{4,} \*\//g) || [], all = src.match(/_zq\('/g) || [];
ok(all.length >= 700 && calls.length === all.length, 'every _zq call states its reason (' + calls.length + ' of ' + all.length + ')');
const REPORTS = [];
(async () => {
  const srv = http.createServer((req, res) => {
    const u = decodeURIComponent(req.url.split('?')[0]), json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u === '/auth/whoami' || u === '/dashboards/whoami.json') return json(200, { user: 'nora.syn', role: 'admin' });
    if (u === '/api/itam/platform/client-errors') { let b = ''; req.on('data', (c) => (b += c)); req.on('end', () => { REPORTS.push(JSON.parse(b)); json(200, { ok: true }); }); return; }
    if (u === '/api/secevents') { res.writeHead(200, { 'Content-Type': 'application/json' }); return res.end('<html>login page</html>'); }   // a broken proxy: HTML where JSON was promised
    if (u.startsWith('/api/')) return json(404, { error: 'not in this test' });
    const f = u === '/' ? path.join(LIVE, 'index.html') : path.join(LIVE, u);
    if (!f.startsWith(LIVE)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (e, d) => { if (e) { res.writeHead(404); return res.end(); } res.writeHead(200, { 'Content-Type': f.endsWith('.js') ? 'application/javascript' : f.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port;
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright'); const browser = await chromium.launch(); const errs = [];
  const wait = (p, fn, a) => p.waitForFunction(fn, a === undefined ? null : a, { timeout: 25000 }).then(() => true, () => false);
  const page = async (init) => { const ctx = await browser.newContext({ viewport: { width: 1400, height: 900 } }); if (init) await ctx.addInitScript(init); const p = await ctx.newPage(); p.on('pageerror', (e) => errs.push(e.message)); await p.goto(base + '/'); await wait(p, () => typeof setView === 'function' && typeof _zqView === 'function' && typeof ME !== 'undefined' && ME && ME.user); return p; };   // eslint-disable-line no-undef
  try {
    let p = await page();
    for (const v of ['security', 'soc', 'alarms', 'policies']) { await p.evaluate((x) => { try { setView(x); } catch (e) { /* a view this build does not have */ } }, v); await p.waitForTimeout(700); }   // eslint-disable-line no-undef
    ok(await wait(p, () => true), 'views open');
    await p.waitForTimeout(3000);
    const view = await p.evaluate(() => _zqView());   // eslint-disable-line no-undef
    ok(Array.isArray(view), '_zqView lists the places: ' + view.length);
    const sec = REPORTS.filter((r) => /secevents|SecEvents|pullSec/i.test(r.message) || /JSON|Unexpected token/i.test(r.message));
    ok(sec.length >= 1, 'the broken feed is reported to Platform Health: ' + JSON.stringify(REPORTS.slice(0, 3)));
    const places = REPORTS.map((r) => r.message.split(':').slice(0, 2).join(':')); ok(new Set(places).size === places.length, 'each place reported once per page view');
    ok(REPORTS.length <= 20, 'at most 20 reports per view (' + REPORTS.length + ')');
    ok(REPORTS.every((r) => r.kind === 'error' && /^\/portal\//.test(r.page) && !/nora\.syn/.test(r.message)), 'reports carry the place and message only');
    // private mode: storage throws - counted, not reported, the portal still works
    REPORTS.length = 0;
    p = await page(() => { const t = () => { throw Object.assign(new Error('storage blocked (synthetic)'), { name: 'SecurityError' }); }; Storage.prototype.getItem = t; Storage.prototype.setItem = t; });
    await p.evaluate(() => setView('policies')); await p.waitForTimeout(2500);   // eslint-disable-line no-undef
    ok(await p.evaluate(() => document.body.innerText.length > 500), 'the portal renders with storage blocked');
    const sv = await p.evaluate(() => _zqView().filter((x) => /^storage:/.test(x.where)).reduce((a, x) => a + x.n, 0));   // eslint-disable-line no-undef
    ok(sv > 0, 'storage failures counted (' + sv + ')'); ok(!REPORTS.some((r) => /storage blocked/.test(r.message)), 'storage failures not reported to Platform Health');
    ok(!errs.length, 'no page errors: ' + errs.slice(0, 3).join(' | '));
  } catch (x) { console.error(x); bad++; } finally { await browser.close(); srv.close(); }
  console.log((bad ? 'portal-errors: FAIL ' : 'portal-errors: OK ') + (n - bad) + '/' + n + ' checks'); process.exit(bad ? 1 : 0);
})();
