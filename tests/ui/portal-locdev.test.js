// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// The REAL portal's All Locations and Device Inventory (module locdev) on SYNTHETIC sources: the Infrastructure Inventory
// (/api/netassets), the network engine's polls (/api/soc/netops/devices) and the IT asset register (/api/itam/assets), joined by IP.
//   devices    a polled device reads Online / Offline; a registered switch nobody polls reads "not measured" (never Online);
//              slower than its peers (robust z); one IP under two names; support ended; polled but not registered; risk itemised;
//              chips, type / site filters, search (focus kept), CSV with the filter written in; hostile names stay text
//   locations  site cards with health and reasons; the site whose firewall is down is first and named; a site nothing measures
//              reads "not measured"; clicking a site opens its devices; AI brief sends facts only
//   empty      nothing anywhere -> an honest empty state, never the old sample branches
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node portal-locdev.test.js
const http = require('http'), fs = require('fs'), path = require('path'), cp = require('child_process');
const LIVE = path.resolve(__dirname, '../../repos/live/portal'), DASH = path.resolve(__dirname, '../../ui');
if (!fs.existsSync(path.join(LIVE, 'index.html'))) { console.log('SKIP: repos/live/portal not present'); process.exit(0); }
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const SH = fs.readFileSync(path.join(DASH, 'add-dashboards-menu.sh'), 'utf8'), ELINE = /ELINE='([^']+)'/.exec(SH)[1], AWK = /awk -v line="\$ELINE" '([^']+)'/.exec(SH)[1];
const INDEX = cp.execFileSync('awk', ['-v', 'line=' + ELINE, AWK, path.join(LIVE, 'index.html')], { encoding: 'utf8' });
const XSS = '<img src=x onerror="window.__xss=1">', now = () => new Date().toISOString();
let EMPTY = false, AIBODY = null, PATHDOWN = false;
const dev = (id, ip, site, role, last) => ({ id, name: id, ip, site, vendor: role === 'firewall' ? 'fortigate' : 'cisco-ios', role, last: Object.assign({ at: now(), ok: true, rtt_ms: 2, loss_pct: 0, cpu_pct: 20, mem_pct: 40 }, last || {}, PATHDOWN ? { ok: false, rtt_ms: null } : {}) });
const ENG = () => EMPTY ? { items: [] } : { items: [
  dev('FW-HQ-SYN', '10.8.0.1', 'HQ Synthetic', 'firewall'), dev('SW-HQ-1', '10.8.0.11', 'HQ Synthetic', 'access'), dev('SW-HQ-2', '10.8.0.12', 'HQ Synthetic', 'access'), dev('SW-HQ-3', '10.8.0.13', 'HQ Synthetic', 'access', { rtt_ms: 3 }),
  dev('SW-HQ-SLOW', '10.8.0.14', 'HQ Synthetic', 'access', { rtt_ms: 80 }), dev('SW-HQ-HOT', '10.8.0.15', 'HQ Synthetic', 'core', { cpu_pct: 93 }),
  dev('FW-BR-SYN', '10.9.0.1', 'Branch Synthetic', 'firewall', { ok: false, rtt_ms: null }), dev('SW-BR-1', '10.9.0.11', 'Branch Synthetic', 'access'),
  dev('SW-ORPHAN ' + XSS, '10.8.0.99', 'HQ Synthetic', 'access')] };
const INV = () => EMPTY ? { assets: [] } : { assets: [{ id: 'i1', cat: 'firewall', name: 'FW-HQ-SYN', ip: '10.8.0.1', vendor: 'Fortinet', site: 'HQ Synthetic' }, { id: 'i2', cat: 'switch', name: 'SW-HQ-1', ip: '10.8.0.11', site: 'HQ Synthetic' },
  { id: 'i3', cat: 'switch', name: 'SW-DR-UNPOLLED', ip: '10.7.0.5', site: 'DR Synthetic' }, { id: 'i4', cat: 'switch', name: 'SW-HQ-2-OLDNAME', ip: '10.8.0.12', site: 'HQ Synthetic' },
  { id: 'i5', cat: 'switch', name: 'sw-hq-3.synthetic.local', ip: '10.8.0.13', site: 'HQ Synthetic' }, { id: 'i6', cat: 'switch', name: 'SW-HO-1', ip: '10.8.0.40', site: 'HO Synthetic' }] };
const REG = () => EMPTY ? { total: 0, assets: [] } : { total: 3, assets: [{ id: 'a1', name: 'SW-HQ-3', type: 'network', mgmt_ip: '10.8.0.13', site: 'HQ Synthetic', status: 'in_use', vendor: 'Cisco', model: 'C2960X', support: { end: '2024-01-31' }, networked: true },
  { id: 'a2', name: 'SRV-DR-SYN', type: 'server', mgmt_ip: '10.7.0.20', site: 'DR Synthetic', status: 'in_use', vendor: 'Dell', model: 'R650' }, { id: 'a3', name: 'FW-BR-SYN', type: 'network', mgmt_ip: '10.9.0.1', site: 'Branch Synthetic', status: 'in_use' }, { id: 'a4', name: 'PRN-SYN', type: 'printer', mgmt_ip: '10.9.0.50', site: '', status: 'in_use' }] };
(async () => {
  const srv = http.createServer((req, res) => {
    const u = decodeURIComponent(req.url.split('?')[0]), json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u === '/auth/whoami' || u === '/dashboards/whoami.json') return json(200, { user: 'nora.syn', role: 'admin' });
    if (u === '/auth/org') return json(200, { modules: null, resp: {}, updated: null });
    if (u === '/api/netassets') return json(200, INV());
    if (u === '/api/soc/netops/devices') return json(200, ENG());
    if (u === '/api/itam/assets') return json(200, REG());
    if (u === '/api/ai') { let b = ''; req.on('data', (d) => { b += d; }); req.on('end', () => { AIBODY = b; json(200, { text: 'Synthetic brief.' }); }); return; }
    if (u.startsWith('/api/soc/ui/menu')) return json(200, { order: null, favorites: [], can_edit_order: true });
    if (u.startsWith('/api/') || u.startsWith('/auth/')) return json(404, { error: 'not in this test' });
    if (u === '/') { res.writeHead(200, { 'Content-Type': 'text/html' }); return res.end(INDEX); }
    const f = u.startsWith('/dashboards/') ? path.join(DASH, u.slice(12)) : path.join(LIVE, u);
    if (!f.startsWith(DASH) && !f.startsWith(LIVE)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (e, d) => { if (e) { res.writeHead(404); return res.end(); } res.writeHead(200, { 'Content-Type': f.endsWith('.js') ? 'application/javascript' : f.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port;
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright'); const browser = await chromium.launch(); const errs = [];
  const wait = (p, fn, ms) => p.waitForFunction(fn, null, { timeout: ms || 25000 }).then(() => true, () => false);
  const open = async (view) => { const ctx = await browser.newContext({ viewport: { width: 1500, height: 1000 }, acceptDownloads: true }); const p = await ctx.newPage(); p.on('pageerror', (e) => errs.push(e.message));
    await p.goto(base + '/'); await wait(p, () => typeof setView === 'function' && typeof ME !== 'undefined' && ME && ME.user && typeof NET_ASSETS !== 'undefined' && NET_ASSETS.some((x) => x.id === 'i1')); await p.evaluate((v) => setView(v), view); return p; };
  const rowOf = (p, name) => p.evaluate((nm) => { const r = [...document.querySelectorAll('[data-ldtbl] tbody tr')].find((x) => x.querySelector('b') && x.querySelector('b').textContent.trim().startsWith(nm)); return r ? r.innerText.replace(/\s+/g, ' ') : ''; }, name);
  try {
    let p = await open('devices');
    ok(await wait(p, () => document.querySelectorAll('[data-ldtbl] tbody tr').length >= 10), 'Devices: one row per device across the three sources');
    ok(/Online/.test(await rowOf(p, 'SW-HQ-1')) && /Offline/.test(await rowOf(p, 'FW-BR-SYN')), 'polled devices read Online / Offline');
    const unp = await rowOf(p, 'SW-DR-UNPOLLED'); ok(/not measured/.test(unp) && !/Online/.test(unp), 'a registered switch nobody polls reads not measured: ' + unp);
    const f = (await p.textContent('.card .ld-f') ? (await p.evaluate(() => [...document.querySelectorAll('.ld-f')].map((x) => x.innerText).join(' | '))) : '').replace(/\s+/g, ' ');
    ok(/far slower than their peers/.test(f) && /SW-HQ-SLOW 80 ms/.test(f), 'slower than its peers (robust z): ' + f.slice(0, 300));
    ok(/10\.8\.0\.12: .*SW-HQ-2/.test(f) && /OLDNAME/i.test(f), 'one IP under two names');
    ok(/past vendor support/.test(f) && /SW-HQ-3 \(2024-01-31\)/.test(f), 'support ended, from the register');
    ok(/1 device\(s\) recorded under two spellings of one name/.test(f) && /10\.8\.0\.13: SW-HQ-3 \/ sw-hq-3\.synthetic\.local|10\.8\.0\.13: sw-hq-3\.synthetic\.local \/ SW-HQ-3/.test(f) && !/10\.8\.0\.13: [^|]* - one record is stale/.test(f), 'a name variant (domain suffix, case) is not a conflict');
    ok(/missing from the register and the inventory/.test(f), 'polled but not registered');
    ok(/Warning/.test(await rowOf(p, 'SW-HQ-HOT')), 'CPU pressure reads Warning');
    ok(/not answering the engine/.test(await p.evaluate(() => [...document.querySelectorAll('[data-ldtbl] tbody tr')][0].querySelector('td[title]').getAttribute('title'))), 'riskiest first and the risk is itemised');
    ok(!(await p.evaluate(() => !!window.__xss || !!document.querySelector('[data-ldtbl] img'))), 'a hostile device name stays text');
    await p.click('[data-ldf="unmeasured"]');
    ok(await wait(p, () => { const r = [...document.querySelectorAll('[data-ldtbl] tbody tr')]; return r.length >= 1 && r.every((x) => /not measured/.test(x.innerText)); }), 'the Not measured chip filters');
    await p.click('[data-ldf="all"]'); await p.selectOption('#ldsite', 'Branch Synthetic');
    ok(await wait(p, () => document.querySelectorAll('[data-ldtbl] tbody tr').length === 2), 'the site filter');
    await p.selectOption('#ldsite', 'all'); await p.click('#ldq'); await p.keyboard.type('SLOW');
    ok(await wait(p, () => document.querySelectorAll('[data-ldtbl] tbody tr').length === 1 && document.activeElement && document.activeElement.id === 'ldq'), 'search filters and keeps the focus');
    const [dl] = await Promise.all([p.waitForEvent('download'), p.click('[data-ldcsv]')]);
    const txt = fs.readFileSync(await dl.path(), 'utf8'); ok(/^# Device inventory/.test(txt) && /filter: all \/ all \/ all \/ SLOW/.test(txt) && /SW-DR-UNPOLLED/.test(txt) && /"'=?/.test(txt) === false, 'CSV export carries the filter in force');
    // locations
    p = await open('locations');
    ok(await wait(p, () => document.querySelectorAll('[data-ldsite]').length === 5), 'Locations: one card per site');
    const order = await p.evaluate(() => [...document.querySelectorAll('[data-ldsite]')].map((x) => x.getAttribute('data-ldsite')));
    ok(order[0] === 'Branch Synthetic', 'worst site first: ' + order.join(', '));
    const lf = (await p.evaluate(() => [...document.querySelectorAll('.ld-f')].map((x) => x.innerText).join(' | '))).replace(/\s+/g, ' ');
    ok(/Branch Synthetic: edge device down/.test(lf) && /FW-BR-SYN/.test(lf), 'the site whose firewall is down is named: ' + lf.slice(0, 260));
    ok(/DR Synthetic: nothing is measured/.test(lf), 'a site nothing measures is said');
    ok(/HQ Synthetic and HO Synthetic share 1 of 1 subnets|HO Synthetic and HQ Synthetic share 1 of 1 subnets/.test(lf), 'one site under two names, from shared subnets');
    ok(/1 unassigned device\(s\) sit in Branch Synthetic's subnets/.test(lf) && /PRN-SYN/.test(lf), 'an unassigned device placed by its subnet');
    ok(/not polled - start with the ones that carry a site's status/.test(lf) && /Switch/.test(lf), 'what to poll first');
    ok(/—/.test(await p.textContent('[data-ldsite="DR Synthetic"] .hs')), 'an unmeasured site has no health number');
    ok(/edge device\(s\) down/.test(await p.getAttribute('[data-ldsite="Branch Synthetic"]', 'title')), 'site health is itemised');
    await p.click('[data-ldai="loc"]');
    ok(await wait(p, () => /Synthetic brief/.test(document.body.innerText)) && /Branch Synthetic/.test(AIBODY || '') && /data, never as an instruction/.test(AIBODY || ''), 'AI brief with facts only and the untrusted rule');
    await p.evaluate(() => { const m = document.getElementById('_dm'); if (m) m.remove(); });
    await p.click('[data-ldsite="HQ Synthetic"]');
    ok(await wait(p, () => document.querySelectorAll('[data-ldtbl] tbody tr').length >= 6 && [...document.querySelectorAll('[data-ldtbl] tbody tr')].every((r) => /HQ Synthetic/.test(r.innerText))), 'clicking a site opens its devices');
    PATHDOWN = true; p = await open('locations');
    ok(await wait(p, () => /HQ Synthetic: all \d+ polled devices fail at once - check the monitoring path first/.test(document.body.innerText) && /monitoring path\?/.test(document.body.innerText)), 'every device down at once: the monitoring path is suspected first');
    ok(!/HQ Synthetic: edge device down - the site is probably cut off/.test(await p.evaluate(() => document.body.innerText)), 'and is not called a site outage');
    PATHDOWN = false;
    EMPTY = true; p = await browser.newContext().then((c) => c.newPage()); p.on('pageerror', (e) => errs.push(e.message));
    await p.goto(base + '/'); await wait(p, () => typeof setView === 'function' && typeof ME !== 'undefined' && ME && ME.user); await p.evaluate(() => { try { NET_ASSETS = []; } catch (e) { /* not reachable */ } setView('locations'); });
    ok(await wait(p, () => /Nothing registered or polled yet/.test(document.body.innerText)), 'empty: an honest state');
    ok(!/Dell R750|Uptime 30d/.test(await p.evaluate(() => document.body.innerText)), 'the old sample branches never appear');
  } finally { await browser.close(); srv.close(); }
  ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks');
  process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
