// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// IP Address Management (ipam.html + vendor/zyb-ipam.js) against the REAL ITAM engine (engine/ipam.js) with SYNTHETIC addresses:
// KPIs, subnet utilisation and next free, findings with fixes, a proposed network registered in one click (form prefilled),
// reserving the next free address, the address grid in the subnet detail, filters and search, a hostile host name stays text,
// a viewer sees counts only, menu entry, installer and the portal's ipam redirect.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node ipam.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const ITAM = path.join(__dirname, '..', '..', 'backend', 'itam'), DASH = path.join(__dirname, '..', '..', 'ui');
const H = require(path.join(ITAM, 'tests', 'helpers'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };

(async () => {
  const e = await H.startApp({ noAi: true });
  require(path.join(ITAM, 'engine/duty')).registerDuty(e.app.srv, e.app, { noTimer: true, python: process.env.PYTHON || 'python3' });
  const st = e.app.store, seen = new Date().toISOString();
  st.collection('assets').put({ id: 'A1', name: 'core-sw-syn', type: 'switch', status: 'active', mgmt_ip: '10.20.5.2' });
  st.collection('disc_devices').put({ id: 'd1', status: 'new', ips: ['10.20.5.2'], macs: ['aa:aa:aa:aa:aa:01'], hostname: 'core-sw-syn', last_seen: seen });
  st.collection('disc_devices').put({ id: 'd2', status: 'new', ips: ['10.20.5.20'], macs: ['aa:aa:aa:aa:aa:02'], hostname: 'pc-a<img src=x onerror="window.__xss=1">', last_seen: seen });
  st.collection('disc_devices').put({ id: 'd3', status: 'new', ips: ['10.20.5.20'], macs: ['aa:aa:aa:aa:aa:03'], hostname: 'pc-b', last_seen: seen });
  st.collection('disc_devices').put({ id: 'd5', status: 'new', ips: ['10.99.1.7'], macs: ['aa:aa:aa:aa:aa:05'], hostname: 'cam-syn', last_seen: seen });
  e.app.addons.ipam.putSubnet({ cidr: '10.20.5.0/24', name: 'HQ floor 5 (synthetic)', site: 'HQ', vlan: 105, gateway: '10.20.5.1', dhcp_start: '10.20.5.100', dhcp_end: '10.20.5.199' }, { user: 'nora.syn', role: 'operator' });
  let WHO = { user: 'nora.syn', role: 'operator' };
  const srv = http.createServer((rq, res) => {
    const u = new URL(rq.url, 'http://x').pathname, json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u === '/dashboards/whoami.json') return json(200, WHO);
    if (u.startsWith('/api/itam/')) {
      const h = Object.assign({}, rq.headers, { 'x-sentra-proxy-secret': H.SECRET, 'x-auth-user': WHO.user, 'x-auth-role': WHO.role });
      const up = http.request({ host: '127.0.0.1', port: e.port, method: rq.method, path: rq.url, headers: h }, (r) => { res.writeHead(r.statusCode, r.headers); r.pipe(res); });
      rq.pipe(up); return;
    }
    if (u.startsWith('/api/')) return json(404, { error: 'not in this test' });
    const f = path.join(DASH, u.replace(/^\/dashboards\//, '')); if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (err, d) => { if (err) { res.writeHead(404); return res.end(); } res.writeHead(200, { 'Content-Type': f.endsWith('.js') ? 'application/javascript' : f.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port + '/dashboards/ipam.html?standalone=1';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright'); const browser = await chromium.launch(), errs = [];
  const wait = (p, fn, arg) => p.waitForFunction(fn, arg, { timeout: 20000 }).then(() => true, () => false);
  const toast = (p, re) => wait(p, (s) => [...document.querySelectorAll('.toast-zyb')].some((t) => new RegExp(s).test(t.textContent)), re);
  try {
    const ctx = await browser.newContext({ viewport: { width: 1500, height: 1000 } });
    let p = await ctx.newPage(); p.on('pageerror', (x) => errs.push(x.message)); p.on('dialog', (d) => d.accept('moved (synthetic)'));
    await p.goto(base);
    ok(await wait(p, () => !document.getElementById('main').hidden), 'page loads');
    const k = await p.textContent('#kpis'); ok(/Subnets in the plan/.test(k) && /Conflicts/.test(k), 'KPIs');
    const sub = await p.textContent('#subs'); ok(/10\.20\.5\.0\/24/.test(sub) && /10\.20\.5\.3/.test(sub) && /VLAN 105/.test(sub), 'subnet row with next free: ' + sub.slice(0, 200));
    ok(/is used by 2 devices/.test(await p.textContent('#finds')), 'conflict finding with its fix');
    ok(await p.evaluate(() => !window.__xss && /<img/.test(document.getElementById('addr').textContent)), 'a hostile host name stays text');
    // filters and search
    await p.click('[data-f="conflict"]'); ok(await wait(p, () => document.querySelectorAll('#addr tbody tr').length === 1), 'Conflicts tile filters the addresses');
    await p.click('[data-f="conflict"]'); await p.fill('#q', 'cam-syn'); ok(await wait(p, () => document.querySelectorAll('#addr tbody tr').length === 1 && /not in the plan/.test(document.getElementById('addr').textContent)), 'search');
    await p.fill('#q', '');
    // register the proposed network in one click
    await p.click('[data-prop="10.99.1.0/24"]'); await p.waitForSelector('#sf');
    ok((await p.inputValue('#sf [name=cidr]')) === '10.99.1.0/24', 'the form is prefilled');
    await p.fill('#sf [name=name]', 'CCTV (synthetic)'); await p.click('#sf button[type=submit]');
    ok(await toast(p, 'Saved 10\\.99\\.1\\.0/24'), 'proposed network registered');
    ok(await wait(p, () => /every address in use is inside a registered subnet/i.test(document.getElementById('props').textContent)), 'no network left outside the plan');
    // reserve the next free address
    await p.click('#subs [data-res="10.20.5.3"]'); await p.waitForSelector('#rf'); await p.fill('#rf [name=name]', 'new-printer-syn'); await p.click('#rf button[type=submit]');
    ok(await toast(p, '10\\.20\\.5\\.3 reserved for new-printer-syn'), 'reserved');
    ok(await wait(p, () => /10\.20\.5\.4/.test(document.getElementById('subs').textContent)), 'the next free moves on');
    ok(st.auditTail(50).some((x) => x.action === 'ipam.reserve' && x.by === 'nora.syn'), 'reservation audited');
    // subnet detail with the address grid
    await p.click('#subs tr[data-sub] td:first-child'); ok(await wait(p, () => document.querySelectorAll('[aria-label="address map"] span').length === 254), 'address grid of the /24');
    await p.evaluate(() => window.zybDetail.close());
    // release
    await p.click('[data-rel]'); ok(await toast(p, 'Released'), 'released with a reason');
    // a viewer
    WHO = { user: 'vera.syn', role: 'viewer' }; p = await ctx.newPage(); p.on('pageerror', (x) => errs.push(x.message)); await p.goto(base + '&v=2');
    ok(await wait(p, () => !document.getElementById('main').hidden && /operators and administrators/i.test(document.getElementById('addr').textContent)), 'a viewer sees counts, not addresses');
    ok(!(await p.$('[data-res]')) && await p.$eval('#addsub', (b) => b.hidden), 'no actions for a viewer');
    const nav = fs.readFileSync(path.join(DASH, 'vendor', 'zyb-nav.js'), 'utf8');
    ok(/"h": "ipam\.html"/.test(nav) && /ipam\.html/.test(fs.readFileSync(path.join(DASH, 'install-dashboards.sh'), 'utf8')) && /zyb-ipam\.js/.test(fs.readFileSync(path.join(DASH, 'install-dashboards.sh'), 'utf8')), 'menu entry and installer');
    ok(/ipam: 'ipam\.html'/.test(fs.readFileSync(path.join(DASH, 'vendor', 'zyb-menu.js'), 'utf8')) && /ipam: 'ipam\.html'/.test(fs.readFileSync(path.join(DASH, 'vendor', 'zyb-early.js'), 'utf8')), 'the portal IP Addresses view opens this page');
    ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  } finally { await browser.close(); srv.close(); await e.close(); }
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n);
  process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
