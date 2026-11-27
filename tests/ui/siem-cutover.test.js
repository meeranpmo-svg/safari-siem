// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// SIEM Cutover page (siem-cutover.html) driven by the REAL routes (backend/siem engine/soc/cutover.js) with SYNTHETIC data: an
// administrator imports NewEvol's three exports from CSV / JSON files (a bad row is skipped and said), the readiness, five gates,
// charts, blockers, sources with the filter, missed rules, rule mapping and ours-only; the four-eyes switch (the proposer sees no
// Approve, another administrator approves); an analyst sees no import or proposal; a viewer is told it is for analysts; hostile text
// stays text; POC mode draws from the illustrative data with the ribbon; menu entry and installer.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node siem-cutover.test.js
const http = require('http'), fs = require('fs'), os = require('os'), path = require('path');
const DASH = path.resolve(__dirname, '../../ui'), SIEM = path.resolve(__dirname, '../../backend/siem');
const C = require(path.join(SIEM, 'engine/soc/cutover')), { createState } = require(path.join(SIEM, 'engine/soc/state'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const XSS = '<img src=x onerror=window.PWN=1>';
const DAY = 864e5, NOW = Date.now(), day = (k) => new Date(NOW - k * DAY + 3 * 36e5).toISOString().slice(0, 10);
(async () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'cut-ui-')), vol = [];
  let csv = 'Log Source,IP,Type,Date,Event Count\n';
  for (let k = 0; k < 15; k++) { csv += 'FW-SYN-01,10.1.0.1,FortiGate,' + day(k) + ',1000\n"' + XSS + '",10.1.0.7,Odd,' + day(k) + ',50\nOLD-SYN-PROXY,10.9.9.9,Squid,' + day(k) + ',400\n'; vol.push({ d: day(k), host: 'fw-syn-01', ip: '10.1.0.1', src_type: 'fortigate', n: 990 }, { d: day(k), host: 'odd', ip: '10.1.0.7', src_type: 'x', n: 50 }); }
  csv += 'BROKEN,,,,not-a-number\n';
  fs.writeFileSync(path.join(tmp, 'sources.csv'), csv);
  fs.writeFileSync(path.join(tmp, 'alerts.json'), JSON.stringify([{ id: 'a1', time: new Date(NOW - 5 * 36e5).toISOString(), rule: 'Brute force syn', severity: 'high', host: 'FW-SYN-01' }, { id: 'a2', time: new Date(NOW - 9 * 36e5).toISOString(), rule: 'Proxy bypass syn', severity: 'high', host: 'OLD-SYN-PROXY' }]));
  fs.writeFileSync(path.join(tmp, 'rules.csv'), 'name,technique,severity,enabled\nBrute force syn,T1110,high,true\nProxy bypass syn,T1090,high,true\n');
  const state = createState({ dir: tmp });
  const cut = C.createCutover({ state, alerts: { all: () => [{ id: 'ALR-1', ts_first: NOW - 5 * 36e5 + 6e4, rule_name: 'Brute force syn', host: 'fw-syn-01', group: {} }, { id: 'ALR-2', ts_first: NOW - 7 * 36e5, rule_name: 'UEBA syn', host: 'ws-syn', group: {} }] }, rules: () => [{ id: 'r1', name: 'Brute force syn', mitre: ['T1110'] }], volumes: async () => vol });
  const R = {}, RANK = { viewer: 1, analyst: 2, operator: 3, admin: 4 };
  C.register({ route: (m, p, h) => { R[m + ' ' + p] = h; } }, { state, cutover: cut });
  const route = (m, p) => { for (const k of Object.keys(R)) { const [mm, pp] = k.split(' '); if (mm !== m) continue; const names = []; const re = new RegExp('^' + pp.replace(/:([a-z]+)/g, (x, nm) => { names.push(nm); return '([^/]+)'; }) + '$'); const g = re.exec(p); if (g) return { h: R[k], params: Object.fromEntries(names.map((nm, i) => [nm, decodeURIComponent(g[i + 1])])) }; } return null; };
  let WHO = { user: 'syn.admin', role: 'admin' }; const audits = [];
  const srv = http.createServer((req, res) => { const u = new URL(req.url, 'http://x'), json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u.pathname === '/dashboards/whoami.json') return json(200, WHO);
    if (u.pathname.startsWith('/api/soc/')) { let raw = ''; req.on('data', (c) => { raw += c; }); req.on('end', async () => { const r = route(req.method, u.pathname); if (!r) return json(404, {});
      const o = {}, ctx = { role: WHO.role, user: WHO.user, body: raw ? JSON.parse(raw) : undefined, query: Object.fromEntries(u.searchParams), params: r.params, audit(action, target, detail) { audits.push({ action, user: WHO.user }); }, ok(x) { o.s = 200; o.b = x; }, fail(c, m) { o.s = c; o.b = { error: m }; }, need(rr) { if ((RANK[WHO.role] || 0) >= (RANK[rr] || 0)) return true; this.fail(403, 'forbidden'); return false; } };
      try { const rv = await r.h(ctx); if (o.s === undefined) { o.s = 200; o.b = rv; } } catch (e) { o.s = e.status || 500; o.b = { error: e.message }; } json(o.s, o.b); }); return; }
    if (u.pathname.startsWith('/api/')) return json(500, { error: 'down (synthetic)' });
    fs.readFile(path.join(DASH, u.pathname.replace(/^\/dashboards\//, '/')), (err, d) => { if (err) { res.writeHead(404); return res.end(); } res.writeHead(200, { 'Content-Type': u.pathname.endsWith('.js') ? 'application/javascript' : u.pathname.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); }); });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port + '/dashboards/siem-cutover.html';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright'); const browser = await chromium.launch(), errs = [];
  const open = async (q) => { const p = await browser.newPage({ viewport: { width: 1500, height: 1100 } }); p.on('pageerror', (x) => errs.push(x.message)); p.on('dialog', (d) => d.accept('approved for the synthetic run')); await p.goto(base + (q || '?standalone=1')); return p; };
  const imp = async (p, kind, file) => { await p.selectOption('#imf [name=kind]', kind); await p.setInputFiles('#imf [name=file]', path.join(tmp, file)); await p.click('#imf button[type=submit]'); await p.waitForFunction((k) => new RegExp(k + ': [0-9,]+ rows').test(document.getElementById('imps').textContent), kind, { timeout: 8000 }); };
  try {
    let p = await open(); await p.waitForSelector('#main:not([hidden])', { timeout: 15000 });
    ok(/sources: not imported/.test(await p.textContent('#imps')), 'nothing imported yet');
    await imp(p, 'sources', 'sources.csv'); ok(/45 rows/.test(await p.textContent('#imps')) && /1 skipped/.test(await p.textContent('#imps')), 'CSV imported, the broken row skipped and said');
    await imp(p, 'alerts', 'alerts.json'); await imp(p, 'rules', 'rules.csv');
    const kp = (await p.$eval('#kp', (x) => x.innerText)).replace(/\s+/g, ' ');
    ok(/NewEvol sources 3/.test(kp) && /1 not in ours/.test(kp) && /Detections matched 1 \/ 2/.test(kp) && /Rules mapped 1 \/ 2/.test(kp), 'tiles: ' + kp);
    ok(/Not ready/.test(await p.textContent('#verdict')) && (await p.$$('#gates .gate')).length === 5, 'verdict and five gates');
    ok((await p.$$('.g3 canvas')).length === 4, 'four charts');
    ok(/OLD-SYN-PROXY/.test(await p.textContent('#bl')) && /Proxy bypass syn/.test(await p.textContent('#miss')) && /UEBA syn/.test(await p.textContent('#only')), 'blockers, missed detections, ours only');
    await p.selectOption('#fs', 'missing'); ok((await p.$$('#src tbody tr')).length === 1, 'filter sources by status');
    ok(!(await p.evaluate(() => window.PWN)), 'hostile text stays text');
    await p.fill('#sof [name=note]', 'switch over on Thursday night with rollback'); await p.click('#sof button[type=submit]'); await p.waitForSelector('.toast', { timeout: 8000 });
    ok(/accept_risk/.test(await p.evaluate(() => [].map.call(document.querySelectorAll('.toast'), (t) => t.textContent).join(' '))), 'an open gate needs a written risk');
    await p.fill('#sof [name=accept_risk]', 'the old proxy is retired the same night (synthetic)'); await p.click('#sof button[type=submit]');
    await p.waitForFunction(() => /proposed/.test(document.getElementById('so').textContent), null, { timeout: 8000 });
    ok(!(await p.$('[data-dec]')) && /Waiting for another administrator/.test(await p.textContent('#so')) && await p.$eval('#sof', (x) => x.hidden), 'the proposer cannot decide'); await p.close();
    WHO = { user: 'syn.ciso', role: 'admin' }; p = await open(); await p.waitForSelector('[data-dec=approve]', { timeout: 15000 }); await p.click('[data-dec=approve]');
    await p.waitForFunction(() => /approved by syn\.ciso/.test(document.getElementById('so').textContent), null, { timeout: 8000 }); ok(audits.some((a) => a.action === 'cutover.approve' && a.user === 'syn.ciso'), 'another administrator approves, audited'); await p.close();
    WHO = { user: 'ana.syn', role: 'analyst' }; p = await open(); await p.waitForSelector('#main:not([hidden])', { timeout: 15000 }); ok(await p.$eval('#impc', (x) => x.hidden) && await p.$eval('#sof', (x) => x.hidden), 'an analyst sees no import or proposal'); await p.close();
    WHO = { user: 'vera.syn', role: 'viewer' }; p = await open(); await p.waitForSelector('#err .err', { timeout: 15000 }); ok(/analysts and above/.test(await p.textContent('#err')), 'a viewer is told it is for analysts'); await p.close();
    WHO = { user: 'syn.admin', role: 'admin' }; const before = audits.length; p = await open('?poc=1'); await p.waitForSelector('#main:not([hidden])', { timeout: 15000 });
    ok((await p.$$('.zyb-poc-r.br')).length === 1 && /OLD-PROXY-POC/.test(await p.textContent('#bl')) && audits.length === before, 'POC: illustrative parallel run, one ribbon, no server read');
    if (process.env.SHOT) { await p.waitForTimeout(900); await p.screenshot({ path: process.env.SHOT, fullPage: true }); }
    await p.close();
    ok(fs.readFileSync(path.join(DASH, 'vendor/zyb-nav.js'), 'utf8').includes('"h": "siem-cutover.html"') && / siem-cutover\.html /.test(fs.readFileSync(path.join(DASH, 'install-dashboards.sh'), 'utf8')), 'menu entry and installer');
    ok(fs.readFileSync(path.join(DASH, 'vendor/zyb-poc-cutover.js'), 'utf8').match(/\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/g).every((ip) => /^(10\.|192\.0\.2\.|198\.51\.100\.|203\.0\.113\.)/.test(ip)), 'only private or documentation addresses in the POC data');
    ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  } finally { await browser.close(); srv.close(); }
  console.log((bad ? 'FAILED ' : 'ok ') + (n - bad) + '/' + n + ' siem-cutover checks'); process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
