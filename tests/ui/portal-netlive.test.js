// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// The REAL portal's Switches and Site Map with live state from the SIEM network engine (module netlive), SYNTHETIC devices, and the
// portal views now opened as the platform pages that read the engines (Performance, Traffic / Flow, User/Device Track, Wi-Fi):
//   switches  the redesigned page: a polled switch reads Online / Offline, one nobody measures "not measured"; problems first;
//             fabric health with its reasons; findings with what to do - slower than its peers (robust z), CPU >= 85 %, not
//             answering, registered but not polled; filter chips and search in place (focus kept over a redraw); a row's reasons;
//             the hooks the inventory / SIEM add-ons use (.vhead, name in <b>, data-zav-ip, data-openurl)
//   map       the site's firewall reads Online from the engine; the site card lists the site's devices
//   menu      netperf -> branch-connectivity.html, traffic -> netflow.html, udt -> rogue-detection.html, wireless -> wireless.html
//   missing   the engine not answering is said; hostile names stay text; no page error
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node portal-netlive.test.js
const http = require('http'), fs = require('fs'), path = require('path'), cp = require('child_process');
const LIVE = path.resolve(__dirname, '../../repos/live/portal'), DASH = path.resolve(__dirname, '../../ui');
if (!fs.existsSync(path.join(LIVE, 'index.html'))) { console.log('SKIP: repos/live/portal not present'); process.exit(0); }
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const SH = fs.readFileSync(path.join(DASH, 'add-dashboards-menu.sh'), 'utf8'), ELINE = /ELINE='([^']+)'/.exec(SH)[1], AWK = /awk -v line="\$ELINE" '([^']+)'/.exec(SH)[1];
const INDEX = cp.execFileSync('awk', ['-v', 'line=' + ELINE, AWK, path.join(LIVE, 'index.html')], { encoding: 'utf8' });
const XSS = '<img src=x onerror="window.__xss=1">', now = () => new Date().toISOString();
let ENGINE = true;
const dev = (id, ip, o) => Object.assign({ id, name: id, ip, vendor: 'cisco-ios', role: 'access', last: { at: now(), ok: true, rtt_ms: 2, loss_pct: 0, cpu_pct: 20, mem_pct: 40, errors: [] } }, o);
const DEVICES = () => ({ items: [dev('SW-SYN-1', '10.9.0.1'), dev('SW-SYN-2', '10.9.0.2'), dev('SW-SYN-3', '10.9.0.3', { last: { at: now(), ok: true, rtt_ms: 3, cpu_pct: 91, mem_pct: 40, errors: [] } }), dev('SW-SYN-4', '10.9.0.4'),
  dev('SW-SLOW ' + XSS, '10.9.0.5', { last: { at: now(), ok: true, rtt_ms: 60, cpu_pct: 20, mem_pct: 40, errors: [] } }), dev('SW-DOWN', '10.9.0.6', { last: { at: now(), ok: false, errors: [{ message: 'timeout (synthetic)' }] } }),
  dev('FGT-SYN', '10.9.0.254', { vendor: 'fortigate', role: 'firewall' })] });
const ASSETS = { assets: [{ id: 's1', cat: 'switch', name: 'SW-SYN-1', ip: '10.9.0.1', vendor: 'Cisco 9300' }, { id: 's6', cat: 'switch', name: 'SW-DOWN', ip: '10.9.0.6', vendor: 'Cisco 9300' }, { id: 's9', cat: 'switch', name: 'SW-UNPOLLED', ip: '10.9.0.99', vendor: 'Cisco 9300' }, { id: 'f1', cat: 'firewall', name: 'FGT-SYN', ip: '10.9.0.254' }] };
(async () => {
  const srv = http.createServer((req, res) => {
    const u = decodeURIComponent(req.url.split('?')[0]), json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u === '/auth/whoami' || u === '/dashboards/whoami.json') return json(200, { user: 'nora.syn', role: 'admin' });
    if (u === '/auth/org') return json(200, { modules: null, resp: {}, updated: null });
    if (u === '/api/netassets') return json(200, ASSETS);
    if (u === '/api/soc/netops/devices') return ENGINE ? json(200, DEVICES()) : json(404, { error: 'not found' });
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
  const wait = (p, fn) => p.waitForFunction(fn, null, { timeout: 25000 }).then(() => true, () => false);
  const open = async (view) => { const p = await (await browser.newContext({ viewport: { width: 1500, height: 1000 } })).newPage(); p.on('pageerror', (e) => errs.push(e.message));
    await p.goto(base + '/'); await wait(p, () => typeof setView === 'function' && typeof ME !== 'undefined' && ME && ME.user && typeof NET_ASSETS !== 'undefined' && NET_ASSETS.some((x) => x.name === 'SW-UNPOLLED')); await p.evaluate((v) => setView(v), view); return p; };   // eslint-disable-line no-undef
  try {
    let p = await open('switches');
    ok(await wait(p, () => document.querySelector('[data-netlive-kpi]') && document.querySelector('[data-swrow]') && document.querySelector('.stpill.ok')), 'Switches: redesigned page with live state from the network engine');
    const rows = await p.evaluate(() => [...document.querySelectorAll('[data-swrow]')].map((r) => r.innerText.replace(/\s+/g, ' ')));
    ok(rows.some((r) => /SW-SYN-1/.test(r) && /Online/i.test(r)) && rows.some((r) => /SW-DOWN/.test(r) && /Offline/i.test(r)), 'a polled switch reads Online / Offline, not unknown');
    ok(rows.some((r) => /SW-UNPOLLED/.test(r) && /not measured/i.test(r)) && !rows.some((r) => /SW-UNPOLLED/.test(r) && /Online/i.test(r)), 'a switch nobody measures stays "not measured", never Online');
    ok(/SW-DOWN/.test(rows[0]), 'problems first: the switch that is down is the first row: ' + rows[0]);
    ok(rows.some((r) => /polled, not registered/.test(r) && /SW-SYN-2/.test(r)) && !rows.some((r) => /FGT-SYN/.test(r)), 'a switch the engine polls but nobody registered is listed and marked; the firewall is not a switch');
    const k = (await p.textContent('[data-netlive-kpi]')).replace(/\s+/g, ' ');
    ok(/Usual response \(median\)/i.test(k) && /2 ms/.test(k), 'KPIs: usual response from the peers: ' + k);
    const why = await p.textContent('[data-sw-why]');
    ok(/5 of 6 measured switches answer/.test(why) && /2 with a warning/.test(why) && /1 down/.test(why) && /1 not measured/.test(why), 'fabric health explains itself: ' + why);
    ok(await p.evaluate(() => /^\d+%?$/.test((document.querySelector('[data-sw-band] svg text') || {}).textContent || '') || !!document.querySelector('[data-sw-band] svg circle')), 'fabric health ring and response strip drawn');
    const c = (await p.textContent('[data-sw-findings]')).replace(/\s+/g, ' ');
    ok(/slow 60 ms/.test(c) && /peers answer in about 2 ms/.test(c), 'slow switch named against its peers (robust z): ' + c.slice(0, 300));
    ok(/SW-SYN-3 · CPU 91 %/.test(c) && /SW-DOWN · not answering/.test(c) && /timeout \(synthetic\)/.test(c) && /SW-UNPOLLED · not polled/.test(c), 'high CPU, the switch not answering with its error and the unpolled one, each with what to do');
    ok(/→ Check power and the uplink/.test(c), 'a finding says what to do');
    // filter chips and search hide rows in place
    await p.click('[data-swf="down"]');
    ok(await p.evaluate(() => [...document.querySelectorAll('[data-swrow]')].filter((r) => r.style.display !== 'none').map((r) => r.getAttribute('data-swrow')).join() === '10.9.0.6'), 'chip Down shows only the switch that is down');
    await p.click('[data-swf="all"]'); await p.fill('[data-swq]', '10.9.0.99');
    ok(await p.evaluate(() => [...document.querySelectorAll('[data-swrow]')].filter((r) => r.style.display !== 'none').length === 1 && document.activeElement && document.activeElement.hasAttribute('data-swq')), 'search filters in place and keeps focus');
    await p.evaluate(() => renderFocus());   // eslint-disable-line no-undef
    ok(await p.evaluate(() => document.activeElement && document.activeElement.hasAttribute('data-swq') && document.activeElement.value === '10.9.0.99' && [...document.querySelectorAll('[data-swrow]')].filter((r) => r.style.display !== 'none').length === 1), 'a redraw keeps the search, its focus and the filter');
    await p.fill('[data-swq]', 'nothing-matches-syn'); ok(/No switch matches/.test(await p.evaluate(() => document.body.innerText)), 'an empty filter says so');
    await p.fill('[data-swq]', '');
    // a row opens its reasons; the add-ons' hooks are still there
    await p.click('[data-swrow="10.9.0.3"] td:first-child'); ok(await wait(p, () => /Look for a broadcast storm/.test((document.querySelector('[data-swdetail]') || {}).innerText || '')), 'clicking a switch shows its reasons and what to do');
    ok(await p.evaluate(() => !!document.querySelector('.vhead') && !!document.querySelector('[data-zav-ip="10.9.0.1"]') && !!document.querySelector('[data-openurl="https://10.9.0.1"]') && document.querySelector('[data-swrow="10.9.0.1"] td b').textContent === 'SW-SYN-1'), 'header, name, IP cell and Open GUI keep what the inventory and SIEM add-ons use');
    ok(await p.evaluate(() => !window.__xss && [...document.querySelectorAll('[data-swrow] td b')].some((b) => /<img src=x/.test(b.textContent))), 'a hostile device name stays text');
    ok(await p.evaluate(() => !NETDEV.devices.some((d) => d.source === 'siem')), 'NETDEV is not changed by the page');   // eslint-disable-line no-undef
    p = await open('map');
    ok(await wait(p, () => document.querySelector('[data-netlive-kpi]')), 'Site Map: live card');
    ok(/HEAD OFFICE\s*ONLINE/i.test(await p.evaluate(() => document.body.innerText)) && !/no live feed/i.test(await p.evaluate(() => document.body.innerText)), 'Site Map: the firewall reads Online from the engine');
    // the menu opens the platform pages for the four feed-gated views
    const hrefs = await p.evaluate(() => Object.fromEntries(['netperf', 'traffic', 'udt', 'wireless'].map((v) => { const li = document.querySelector('.nav li[data-view="' + v + '"]'); return [v, li && li.getAttribute('data-zyb-href')]; })));
    ok(/branch-connectivity\.html$/.test(hrefs.netperf) && /netflow\.html$/.test(hrefs.traffic) && /rogue-detection\.html$/.test(hrefs.udt) && /wireless\.html$/.test(hrefs.wireless), 'menu: Performance, Traffic / Flow, User/Device Track and Wi-Fi open their platform pages: ' + JSON.stringify(hrefs));
    ENGINE = false; p = await open('switches');
    ok(await wait(p, () => /network engine is not answering/.test(document.body.innerText)), 'engine not answering is said');
    ok(!errs.length, 'no page errors: ' + errs.slice(0, 3).join(' | '));
  } catch (x) { console.error(x); bad++; } finally { await browser.close(); srv.close(); }
  console.log((bad ? 'portal-netlive: FAIL ' : 'portal-netlive: OK ') + (n - bad) + '/' + n + ' checks'); process.exit(bad ? 1 : 0);
})();
