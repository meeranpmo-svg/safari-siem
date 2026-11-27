// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// NAC by Site (nac-sites.html) driven by the REAL routes (backend/siem engine/netops/nac-sites.js) over SYNTHETIC endpoints: tiles, the
// Saudi map with a point per site, the kind tabs (project sites only), compliance chart, findings with the H3C port move, the filter by
// site; an operator proposes a time-limited authorisation (sent to the NAC decisions route with its end date); an administrator saves
// the profile (a site's kind) and the page follows; an analyst sees no profile and no buttons; a viewer is told why; hostile text stays
// text; POC mode draws the illustrative sites with one ribbon; menu entry and installer.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node nac-sites.test.js
const http = require('http'), fs = require('fs'), os = require('os'), path = require('path');
const DASH = path.resolve(__dirname, '../../ui'), SIEM = path.resolve(__dirname, '../../backend/siem');
const NS = require(path.join(SIEM, 'engine/netops/nac-sites')), { createState } = require(path.join(SIEM, 'engine/soc/state'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const XSS = '<img src=x onerror=window.PWN=1>';
const NOW = Date.now(), D = 864e5, iso = (t) => new Date(t).toISOString();
const sw = (s, port, vlan) => ({ switch: s, device: s, port, vlan: String(vlan), desc: '', vendor: 'h3c-comware', shared: 1, moves24: 0 });
const ep = (mac, o) => Object.assign({ mac, ip: '10.1.0.5', host: 'PC-SYN', os: 'Windows 11', site: 'Riyadh Head Office', first_seen: iso(NOW - 30 * D), last_seen: iso(NOW - 3600e3), risk: 0, authorised: true, sw: sw('HO-ACC-01', 'GE1/0/5', 10) }, o);
(async () => {
  const E = [ep('aa:00:00:00:00:01'), ep('aa:00:00:00:00:02', { host: 'CAM-LOBBY', os: 'Hikvision IPC', sw: sw('HO-ACC-01', 'GE1/0/9', 10) }), ep('aa:00:00:00:00:03', { site: 'Jubail Project Site', host: XSS, authorised: false, sw: sw('JUB-ACC-01', 'GE1/0/7', 10) }),
    ep('aa:00:00:00:00:04', { site: 'Jeddah Branch' })];
  const state = createState({ dir: fs.mkdtempSync(path.join(os.tmpdir(), 'nacs-ui-')) }), R = {}, RANK = { viewer: 1, analyst: 2, operator: 3, admin: 4 }, posted = [];
  NS.register({ route: (m, p, h) => { R[m + ' ' + p] = h; } }, { state, config: {}, nacApi: { view: () => ({ connected: true, learning: false, endpoints: E }) } });
  let WHO = { user: 'syn.admin', role: 'admin' };
  const srv = http.createServer((req, res) => { const u = new URL(req.url, 'http://x'), json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u.pathname === '/dashboards/whoami.json') return json(200, WHO);
    if (u.pathname.startsWith('/api/soc/')) { let raw = ''; req.on('data', (c) => { raw += c; }); req.on('end', async () => {
      if (req.method === 'POST' && u.pathname === '/api/soc/nac/decisions') { posted.push(JSON.parse(raw)); return json(200, { id: 'NAC-00001' }); }
      const h = R[req.method + ' ' + u.pathname]; if (!h) return json(404, {});
      const o = {}, ctx = { role: WHO.role, user: WHO.user, body: raw ? JSON.parse(raw) : undefined, query: {}, params: {}, audit() {}, ok(x) { o.s = 200; o.b = x; }, fail(c, m) { o.s = c; o.b = { error: m }; }, need(r) { if ((RANK[WHO.role] || 0) >= (RANK[r] || 0)) return true; this.fail(403, 'forbidden'); return false; } };
      try { const rv = await h(ctx); if (o.s === undefined) { o.s = 200; o.b = rv; } } catch (e) { o.s = e.status || e.code || 500; o.b = { error: e.message }; } json(o.s, o.b); }); return; }
    if (u.pathname.startsWith('/api/')) return json(500, { error: 'down (synthetic)' });
    fs.readFile(path.join(DASH, u.pathname.replace(/^\/dashboards\//, '/')), (err, d) => { if (err) { res.writeHead(404); return res.end(); } res.writeHead(200, { 'Content-Type': u.pathname.endsWith('.js') ? 'application/javascript' : u.pathname.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); }); });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port + '/dashboards/nac-sites.html';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright'); const browser = await chromium.launch(), errs = [];
  const open = async (q) => { const p = await browser.newPage({ viewport: { width: 1500, height: 1100 } }); p.on('pageerror', (x) => errs.push(x.message)); await p.goto(base + (q || '?standalone=1')); return p; };
  try {
    let p = await open(); await p.waitForSelector('#main:not([hidden])', { timeout: 15000 });
    const kp = (await p.$eval('#kp', (x) => x.innerText)).replace(/\s+/g, ' ');
    ok(/Sites 3/.test(kp) && /Devices 4/.test(kp) && /Violations 2/.test(kp), 'tiles: ' + kp);
    ok((await p.$$('#ksa .zksa-pt')).length === 3, 'a point per site on the map');
    ok((await p.$$('canvas')).length >= 2, 'charts');
    ok(/port access vlan 40/.test(await p.textContent('#fl')) && /A camera on the corporate VLAN 10/.test(await p.textContent('#fl')), 'a finding with the H3C port move');
    await p.click('[data-k="project_site"]'); ok((await p.$$('#sites tbody tr')).length === 1 && /Jubail/.test(await p.textContent('#sites')), 'the project-sites tab');
    await p.click('[data-k=""]'); await p.selectOption('#fsite', 'Riyadh Head Office'); ok((await p.$$('#fl tbody tr')).length === 1, 'filter by site');
    await p.selectOption('#fsite', ''); await p.click('[data-act="authorise"][data-mac="aa:00:00:00:00:03"]'); await p.waitForSelector('#dlg[open]');
    await p.fill('#df [name=owner]', 'Scaffolding Contractor (synthetic)'); await p.fill('#df [name=expires]', new Date(NOW + 20 * D).toISOString().slice(0, 10)); await p.fill('#df [name=reason]', 'contractor laptop for the shutdown work');
    await p.click('#df button[type=submit]'); await p.waitForTimeout(500); ok(posted.length === 1 && posted[0].action === 'authorise' && /^\d{4}-\d{2}-\d{2}$/.test(posted[0].expires) && posted[0].owner, 'a time-limited authorisation proposed: ' + JSON.stringify(posted));
    ok(!(await p.evaluate(() => window.PWN)), 'hostile text stays text');
    await p.selectOption('[data-site="Jeddah Branch"]', 'office'); await p.click('#psave'); await p.waitForFunction(() => /saved by syn\.admin/.test(document.getElementById('pstat').textContent), null, { timeout: 8000 });
    ok(/Offices/.test(await p.textContent('#tabs')), 'the administrator saves a site kind; the tabs follow'); await p.close();
    WHO = { user: 'ana.syn', role: 'analyst' }; p = await open(); await p.waitForSelector('#main:not([hidden])', { timeout: 15000 }); ok(await p.$eval('#profc', (x) => x.hidden) && !(await p.$('[data-act]')), 'an analyst: no profile, no decisions'); await p.close();
    WHO = { user: 'vera.syn', role: 'viewer' }; p = await open(); await p.waitForSelector('#err .err', { timeout: 15000 }); ok(/analysts and above/.test(await p.textContent('#err')), 'a viewer is told why'); await p.close();
    WHO = { user: 'syn.admin', role: 'admin' }; p = await open('?poc=1'); await p.waitForSelector('#main:not([hidden])', { timeout: 15000 }); await p.waitForTimeout(500);
    ok((await p.$$('.zyb-poc-r.br')).length === 1 && (await p.$$('#ksa .zksa-pt')).length >= 9, 'POC: illustrative sites on the map, one ribbon');
    if (process.env.SHOT) { await p.waitForTimeout(800); await p.screenshot({ path: process.env.SHOT, fullPage: true }); }
    await p.close();
    ok(fs.readFileSync(path.join(DASH, 'vendor/zyb-nav.js'), 'utf8').includes('"h": "nac-sites.html"') && / nac-sites\.html( |$)/m.test(fs.readFileSync(path.join(DASH, 'install-dashboards.sh'), 'utf8')), 'menu entry and installer');
    ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  } finally { await browser.close(); srv.close(); }
  console.log((bad ? 'FAILED ' : 'ok ') + (n - bad) + '/' + n + ' nac-sites checks'); process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
