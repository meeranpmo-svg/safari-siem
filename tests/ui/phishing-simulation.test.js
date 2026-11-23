// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for Phishing Simulation (dashboards/server/phishing-simulation.html) against the REAL ITAM engine (engine/phish-sim.js)
// with a stubbed Microsoft Graph (SYNTHETIC tenant, three campaigns, 30 people): not connected says so; the admin connection form
// (save, test); Sync now; KPIs (click, report, resilience, repeat clickers, trend); findings; the campaign chart and table; smoothed
// departments with the flagged one; people to support with the indicators-not-proof banner and search (operator); a viewer sees no
// names anywhere (PDPL) and no Sync / settings; AI off says why; Excel; a hostile campaign name stays text; menu entry and redirect.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node phishing-simulation.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const ITAM = path.join(__dirname, '..', '..', 'backend', 'itam'), DASH = path.join(__dirname, '..', '..', 'ui');
const H = require(path.join(ITAM, 'tests', 'helpers'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const XSS = '<img src=x onerror="window.__xss=1">';
const DAY = 86400000, NOW = Date.now(), day = (d) => new Date(NOW - d * DAY).toISOString();
const PEOPLE = []; for (let i = 0; i < 8; i++) PEOPLE.push({ id: 'f' + i, name: 'Fin Person ' + i, email: 'fin' + i + '@corpgroup.test', dept: 'Finance' });
for (let i = 0; i < 22; i++) PEOPLE.push({ id: 'o' + i, name: 'Ops Person ' + i, email: 'ops' + i + '@corpgroup.test', dept: 'Operations' });
const users = (k) => PEOPLE.map((p, j) => { const comp = (p.dept === 'Finance' && (j + k) % 2 === 0) || (p.dept === 'Operations' && j % 11 === k); const rep = !comp && p.dept === 'Operations' && j % 3 === 0;
  return { simulationUser: { userId: p.id, displayName: p.name, email: p.email }, isCompromised: comp, compromisedDateTime: comp ? new Date(Date.parse(day(90 - 30 * k)) + (2 + j) * 60000).toISOString() : null, reportedPhishDateTime: rep ? day(90 - 30 * k) : null, assignedTrainingsCount: comp ? 1 : 0, completedTrainingsCount: comp && j % 2 ? 1 : 0 }; });
const graph = async (url, o) => {
  if (/oauth2\/v2.0\/token/.test(url)) return { status: 200, json: { access_token: 'tok-synthetic' } };
  if (o.method !== 'GET') return { status: 405, json: {} };
  const p = new URL(url).pathname.replace('/v1.0', '');
  if (p === '/security/attackSimulation/simulations') return { status: 200, json: { value: [0, 1, 2].map((k) => ({ id: 's' + k, displayName: k === 2 ? 'Payroll ' + XSS : 'Campaign ' + k, status: 'succeeded', attackTechnique: 'credentialHarvesting', launchDateTime: day(90 - 30 * k) })) } };
  const m = /^\/security\/attackSimulation\/simulations\/s(\d)\/report\/simulationUsers$/.exec(p); if (m) return { status: 200, json: { value: users(+m[1]) } };
  if (p === '/users') return { status: 200, json: { value: PEOPLE.map((x) => ({ id: x.id, department: x.dept })) } };
  return { status: 404, json: {} };
};
const sealer = { available: () => true, unavailableReason: () => '', seal: (id, t) => 'SEALED:' + Buffer.from(t).toString('base64'), unseal: (id, e) => Buffer.from(String(e).slice(7), 'base64').toString() };

(async () => {
  const e = await H.startApp({ noAi: true });
  require(path.join(ITAM, 'engine/duty')).registerDuty(e.app.srv, e.app, { noTimer: true, psRequest: graph, psSealer: sealer });
  let WHO = { user: 'syed', role: 'admin' };
  const srv = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://x'), json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u.pathname === '/dashboards/whoami.json') return json(200, WHO);
    if (u.pathname.startsWith('/api/itam/')) {
      const h = Object.assign({}, req.headers, { 'x-sentra-proxy-secret': H.SECRET, 'x-auth-user': WHO.user, 'x-auth-role': WHO.role });
      const up = http.request({ host: '127.0.0.1', port: e.port, method: req.method, path: req.url, headers: h }, (r) => { res.writeHead(r.statusCode, r.headers); r.pipe(res); });
      req.pipe(up); return;
    }
    if (u.pathname.startsWith('/api/')) return json(404, { error: 'not in this test' });
    const f = path.join(DASH, u.pathname.replace(/^\/dashboards\//, '')); if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (err, d) => { if (err) { res.writeHead(404); return res.end(); } res.writeHead(200, { 'Content-Type': f.endsWith('.js') ? 'application/javascript' : f.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const url = 'http://127.0.0.1:' + srv.address().port + '/dashboards/phishing-simulation.html?standalone=1';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright'); const browser = await chromium.launch(), errs = [];
  const wait = (p, fn, arg) => p.waitForFunction(fn, arg, { timeout: 15000 }).then(() => true, () => false);
  try {
    const ctx = await browser.newContext({ viewport: { width: 1500, height: 1000 }, acceptDownloads: true });
    const p = await ctx.newPage(); p.on('pageerror', (x) => errs.push(x.message));
    await p.goto(url); ok(await wait(p, () => /No simulation results yet/.test(document.getElementById('nc').textContent)), 'not connected says so');
    ok(await p.isVisible('#s-ten'), 'admin sees the connection form');
    await p.fill('#s-ten', '11111111-2222-3333-4444-555555555555'); await p.fill('#s-cli', '66666666-7777-8888-9999-000000000000'); await p.fill('#s-sec', 'Synthetic-Secret-1'); await p.check('#s-en');
    await p.click('#s-save'); ok(await wait(p, () => /Saved/.test(document.body.textContent)), 'save connection');
    await p.click('#s-test'); ok(await wait(p, () => /Connection works/.test(document.body.textContent)), 'test connection');
    await p.click('#sync'); ok(await wait(p, () => document.querySelectorAll('.kpi').length === 8), 'sync then KPIs');
    if (process.env.SHOT) await p.screenshot({ path: process.env.SHOT, fullPage: true });   // optional: a picture for review
    const k = await p.textContent('#kpis'); ok(/Campaigns read/.test(k) && /30 people/.test(k) && /Resilience/.test(k) && /Repeat clickers/.test(k), 'KPIs');
    ok(/Finance is more susceptible/.test(await p.textContent('#findings')), 'findings name the flagged department');
    ok((await p.$$('#chart svg rect')).length === 6, 'campaign chart: click + report per campaign');
    ok(/Finance[\s\S]*above/.test(await p.textContent('#deps')), 'smoothed departments with the flagged one');
    ok((await p.$$('#camps tbody tr')).length === 3, 'campaign table');
    ok(/never a basis for discipline/.test(await p.textContent('#people')) && /Fin Person/.test(await p.textContent('#people')), 'people to support with the indicators banner');
    await p.fill('#pq', 'ops1'); ok(await wait(p, () => document.querySelectorAll('#people tbody tr').length >= 1 && !/Fin Person/.test(document.querySelector('#people tbody').textContent)), 'people search');
    ok(/advisor is off/.test(await p.textContent('#ai')), 'AI off says why');
    const [dl] = await Promise.all([p.waitForEvent('download', { timeout: 10000 }), p.click('#xls')]);
    ok(/^phishing-simulation-\d{4}-\d{2}-\d{2}\.xlsx$/.test(dl.suggestedFilename()), 'Excel export');
    ok(!(await p.evaluate(() => window.__xss)), 'hostile campaign name stayed text');
    WHO = { user: 'vera.syn', role: 'viewer' }; const q = await ctx.newPage(); q.on('pageerror', (x) => errs.push(x.message)); await q.goto(url); await wait(q, () => document.querySelectorAll('.kpi').length === 8);
    ok(!/@corpgroup\.test|Fin Person|Ops Person/.test(await q.textContent('body')) && /operators and administrators \(PDPL\)/.test(await q.textContent('#people')), 'viewer: no names or addresses anywhere');
    ok(!(await q.isVisible('#sync')) && !(await q.isVisible('#setcard')), 'viewer: no Sync, no settings');
    const nav = fs.readFileSync(path.join(DASH, 'vendor', 'zyb-nav.js'), 'utf8');
    ok(/"h": "phishing-simulation.html"/.test(nav) && /phishing-simulation\.html/.test(fs.readFileSync(path.join(DASH, 'install-dashboards.sh'), 'utf8')), 'menu entry and installer');
    ok(/phishsim: 'phishing-simulation\.html'/.test(fs.readFileSync(path.join(DASH, 'vendor', 'zyb-menu.js'), 'utf8')) && /phishsim: 'phishing-simulation\.html'/.test(fs.readFileSync(path.join(DASH, 'vendor', 'zyb-early.js'), 'utf8')), 'the portal\'s Phishing Simulation opens this page');
    ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  } finally { await browser.close(); srv.close(); await e.close(); }
  console.log((bad ? 'FAILED ' : 'ok ') + (n - bad) + '/' + n);
  process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
