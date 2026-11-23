// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for branch-connectivity.html after the static build. The answers come from the REAL SIEM engine (sentra-siem
// engine/netops/branchnet.js over the real route map) on a SYNTHETIC network: DC, DR and three branches - one healthy on two
// ISPs, one whose firewall is down, one on a single path with no DR route. Reachable from the menu; tiles filter the matrix;
// what to do first; the site drawer with the 7-day strip; the ISP ticket draft (analyst) and nothing for a viewer; the SLA
// target (admin only); search keeps focus; the empty map says what to do; the portal's sample page redirects here; escaping.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node branch-connectivity.test.js
const http = require('http'), fs = require('fs'), path = require('path'), os = require('os'), cp = require('child_process');
const SRC = path.resolve(__dirname, '../../ui');
let n = 0, bad = 0;
const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const B = fs.mkdtempSync(path.join(os.tmpdir(), 'apmpage-')); fs.mkdirSync(path.join(B, 'vendor'));
fs.readdirSync(SRC).filter((f) => f.endsWith('.html')).forEach((f) => fs.copyFileSync(path.join(SRC, f), path.join(B, f)));
fs.readdirSync(path.join(SRC, 'vendor')).filter((f) => /\.(js|json|css)$/.test(f)).forEach((f) => fs.copyFileSync(path.join(SRC, 'vendor', f), path.join(B, 'vendor', f)));
['zyb-menu.js', 'zyb-dash.js'].forEach((t) => fs.writeFileSync(path.join(B, 'vendor', t), fs.readFileSync(path.join(B, 'vendor/zyb-nav.js'), 'utf8') + '\n' + fs.readFileSync(path.join(B, 'vendor', t), 'utf8')));
cp.execFileSync(process.execPath, [path.join(SRC, 'build-static.js'), B, 't1'], { stdio: 'ignore' });


const SIEM = process.env.SENTRA_SIEM_DIR || path.resolve(__dirname, '../../backend/siem');
const { createState } = require(path.join(SIEM, 'engine/soc/state'));
const routes = require(path.join(SIEM, 'engine/netops/routes'));
const DEVS = [['pa-dc', 'PA-DC-SYN', 'paloalto'], ['fw-dr', 'FW-DR-SYN', 'fortigate'], ['fgt-jed', 'FGT-JED-SYN', 'fortigate'], ['fgt-dmm', 'FGT-DMM-SYN', 'fortigate'], ['fgt-abh', 'FGT-ABH-SYN', 'fortigate']]
  .map(([id, name, vendor], i) => ({ id, name, vendor, ip: '10.' + i + '.0.1', role: 'firewall' }));
const MAP = {
  sites: [{ id: 'dc', name: 'Riyadh DC', kind: 'dc' }, { id: 'dr', name: 'DR Site', kind: 'dr' }, { id: 'jed', name: 'Jeddah Branch', kind: 'branch', city: 'Jeddah' },
    { id: 'dmm', name: 'Dammam <b>Branch</b>', kind: 'branch' }, { id: 'abh', name: 'Abha Branch', kind: 'branch' }],
  nodes: [{ id: 'pa', label: 'PA-DC', kind: 'edge-firewall', site: 'dc', device: 'pa-dc' }, { id: 'drfw', label: 'FW-DR', kind: 'firewall', site: 'dr', device: 'fw-dr' },
    { id: 'fjed', label: 'FGT-JED', kind: 'firewall', site: 'jed', device: 'fgt-jed' }, { id: 'fdmm', label: 'FGT-DMM', kind: 'firewall', site: 'dmm', device: 'fgt-dmm' }, { id: 'fabh', label: 'FGT-ABH', kind: 'firewall', site: 'abh', device: 'fgt-abh' }],
  links: [{ id: 'dc-dr', a: 'drfw', b: 'pa', kind: 'ipsec', tunnel: 'to-dc' },
    { id: 'jed-a', a: 'fjed', b: 'pa', kind: 'ipsec', tunnel: 'dc-a', isp: 'STC (synthetic)', circuit: 'CIR-SYN-J1' }, { id: 'jed-b', a: 'fjed', b: 'pa', kind: 'ipsec', tunnel: 'dc-b', isp: 'Mobily (synthetic)', circuit: 'CIR-SYN-J2' },
    { id: 'jed-dr', a: 'fjed', b: 'drfw', kind: 'ipsec', tunnel: 'dr' },
    { id: 'dmm-a', a: 'fdmm', b: 'pa', kind: 'ipsec', tunnel: 'dc-a', isp: 'STC (synthetic)', circuit: 'CIR-SYN-D1' }, { id: 'dmm-dr', a: 'fdmm', b: 'drfw', kind: 'ipsec', tunnel: 'dr' },
    { id: 'abh-a', a: 'fabh', b: 'pa', kind: 'ipsec', tunnel: 'dc-a', isp: 'Zain (synthetic)', circuit: 'CIR-SYN-A1' }] };
const up = (t) => ({ at: 1, ok: true, sources: ['ping'], errors: [], reach: { sent: 5, received: 5, rtt_avg_ms: 4 }, system: {}, tunnels: (t || []).map(([name, status]) => ({ name, status: status || 'up' })) });
const snaps = { 'pa-dc': up(), 'fw-dr': up([['to-dc']]), 'fgt-jed': up([['dc-a'], ['dc-b'], ['dr']]), 'fgt-dmm': { at: 1, ok: false, sources: ['ping'], errors: [], reach: { sent: 5, received: 0 } }, 'fgt-abh': up([['dc-a']]) };
let ROLE = 'analyst', EMPTY = false; const POSTS = [];
(async () => {
  const state = await createState({ dir: fs.mkdtempSync(path.join(os.tmpdir(), 'brpage-st-')) });
  const config = { netops: { enabled: false } }; Object.defineProperty(config, 'secrets', { value: {}, enumerable: false, writable: true });
  let clock = Date.now() - 3 * 3600000;
  const poller = { snapshot: (id) => snaps[id] || null, snapshots: () => snaps, stats: () => ({}), forget() {}, start() {} };
  const N = routes.createNetops({ state, config, log: { info() {}, warn() {}, error() {} }, poller, now: () => clock });
  for (const d of DEVS) N.inventory.put(d, 'test');
  N.routemap.save(MAP, 'admin.syn');
  for (let i = 0; i < 36; i++) { N.branches.record(); clock += 300000; }
  const R = {}; routes.register({ route: (m, p, h) => { R[m + ' ' + p] = h; } }, { state, config, log: { error() {}, info() {} }, netops: N });
  const RANK = { viewer: 0, analyst: 1, operator: 2, admin: 3 };
  const srv = http.createServer((q, r) => {
    const u = q.url.split('?')[0], j = (c, o) => { r.writeHead(c, { 'Content-Type': 'application/json' }); r.end(JSON.stringify(o)); };
    if (u.endsWith('whoami.json')) return j(200, { user: 'oscar.syn', role: ROLE });
    if (u.startsWith('/api/soc/netops/')) {
      let b = ''; q.on('data', (c) => { b += c; }); q.on('end', async () => {
        const body = b ? JSON.parse(b) : {}; if (q.method === 'POST') POSTS.push({ u, body });
        const p = u.slice('/api/soc'.length), m = p.match(/^\/netops\/branches\/([^/]+)$/);
        let key = 'GET /api/soc/netops/branches', params = {};
        if (q.method === 'POST') key = 'POST /api/soc' + p; else if (m) { key = 'GET /api/soc/netops/branches/:id'; params = { id: decodeURIComponent(m[1]) }; }
        if (EMPTY && key === 'GET /api/soc/netops/branches') return j(200, { configured: false, reason: 'No sites on the WAN / LAN route map yet - an administrator draws (or accepts the proposed) map on Network → WAN / LAN Route Map, then every site appears here.' });
        const h = R[key]; if (!h) return j(404, { error: 'not in this test' });
        const out = {}; const ctx = { role: ROLE, user: 'oscar.syn', body, params, query: {}, need(x) { if (RANK[ROLE] < RANK[x]) { out.c = 403; out.e = 'requires ' + x; return false; } return true; }, audit() {}, fail(c, e) { out.c = c; out.e = e; } };
        try { const rv = await h(ctx); if (out.c) return j(out.c, { error: out.e }); return j(200, rv); } catch (e) { return j(e.code || e.status || 500, { error: e.message }); }
      }); return;
    }
    if (u.startsWith('/api/')) return j(404, { error: 'not in this test' });
    const f = path.join(B, u === '/' ? 'index.html' : u); if (!f.startsWith(B)) { r.writeHead(403); return r.end(); }
    fs.readFile(f, (e, d) => { if (e) { r.writeHead(404); return r.end(); } r.writeHead(200, { 'Content-Type': u.endsWith('.js') ? 'application/javascript' : u.endsWith('.css') ? 'text/css' : 'text/html' }); r.end(d); });
  });
  await new Promise((res) => srv.listen(0, '127.0.0.1', res));
  const base = 'http://127.0.0.1:' + srv.address().port + '/';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  const open = async (pg) => { const p = await browser.newPage({ viewport: { width: 1500, height: 950 } }); p.on('pageerror', (e) => errs.push(e.message)); p.on('dialog', (d) => { errs.push('dialog ' + d.message()); d.dismiss(); }); await p.goto(base + (pg || 'branch-connectivity.html')); return p; };
  const txt = (p, id) => p.evaluate((i) => (document.getElementById(i) || {}).textContent || '', id);
  const rows = (p) => p.evaluate(() => [].map.call(document.querySelectorAll('#x-mx tr.br'), (r) => r.getAttribute('data-id')));

  let p = await open('network-route-map.html'); await p.waitForTimeout(800);
  const link = await p.evaluate(() => { const a = document.querySelector('a[href="branch-connectivity.html"]'); return a ? a.textContent.trim() : null; });
  ok(/Branch Connectivity/.test(link || ''), 'menu entry exists: ' + link);
  await p.evaluate(() => document.querySelector('a[href="branch-connectivity.html"]').click());
  await p.waitForURL(/branch-connectivity\.html/); await p.waitForSelector('#x-mx tr.br');
  const kp = await txt(p, 'kp');
  ok(/Cannot reach DC1/i.test(kp) && /DC but not DR1/i.test(kp) && /Sites healthy2\/4/i.test(kp), 'tiles: ' + kp.slice(0, 220));
  ok((await rows(p))[0] === 'dmm', 'worst site first');
  ok(/1 site\(s\) cannot reach the data centre/.test(await txt(p, 'x-act')), 'what to do first');
  ok(await p.evaluate(() => !document.querySelector('#x-mx b') || ![].some.call(document.querySelectorAll('#x-mx b b'), () => true)) && /Dammam <b>Branch<\/b>/.test(await txt(p, 'x-mx')), 'site names are escaped');
  await p.click('#kp [data-act="f:partial"]'); ok(JSON.stringify(await rows(p)) === '["abh"]', 'tile filters the matrix');
  await p.click('#x-mx [data-f=""]'); ok((await rows(p)).length === 5, 'all sites again');
  await p.click('#x-mx [data-f="design"]'); ok((await rows(p)).includes('abh') && !(await rows(p)).includes('dc'), 'resilience gaps filter');
  await p.click('#x-mx [data-f=""]');
  await p.fill('#q', 'mobily'); ok(JSON.stringify(await rows(p)) === '["jed"]' && await p.evaluate(() => document.activeElement && document.activeElement.id === 'q'), 'search by ISP keeps focus');
  await p.fill('#q', '');
  ok(/STC \(synthetic\)/.test(await txt(p, 'x-isp')) && /Zain \(synthetic\)/.test(await txt(p, 'x-isp')), 'ISP scorecard');
  ok(/no route to the DR site/.test(await txt(p, 'x-des')) && /one WAN path only/.test(await txt(p, 'x-des')), 'resilience design');
  ok(!(await p.$('#slaSave')), 'analyst cannot set the target');

  await p.click('#x-mx tr.br[data-id="dmm"] td:first-child');
  await p.waitForFunction(() => /Last 7 days/i.test((document.getElementById('zd-b') || {}).textContent || ''));
  ok(await p.evaluate(() => document.querySelectorAll('#zd-b .strip i').length) >= 3, 'the 7-day strip has hours');
  ok(/cannot reach the data centre/.test(await txt(p, 'zd-b')), 'drawer: why');
  await p.click('#zd-b [data-draft="dmm-a"]'); await p.waitForSelector('#drtxt');
  const dr = await txt(p, 'drtxt');
  ok(/To: STC \(synthetic\)/.test(dr) && /CIR-SYN-D1/.test(dr) && /Raised by oscar\.syn/.test(dr), 'ISP ticket draft: ' + dr.slice(0, 120));
  ok(POSTS.some((x) => x.u.endsWith('/netops/branches/isp-draft') && x.body.link === 'dmm-a'), 'draft posts the link only');
  ok(/nothing was sent/.test(await txt(p, 'zd-b')), 'draft says nothing was sent');
  await p.close();

  ROLE = 'viewer'; p = await open(); await p.waitForSelector('#x-mx tr.br');
  await p.click('#x-mx tr.br[data-id="dmm"] td:first-child'); await p.waitForFunction(() => /WAN paths/i.test((document.getElementById('zd-b') || {}).textContent || ''));
  ok(!(await p.$('#zd-b [data-draft]')), 'viewer: no ticket draft');
  await p.close();

  ROLE = 'admin'; p = await open(); await p.waitForSelector('#slaSave');
  await p.fill('#sla', '99'); await p.click('#slaSave'); await p.waitForTimeout(500);
  ok(POSTS.some((x) => x.u.endsWith('/netops/branches/config') && x.body.sla_target_pct === 99), 'admin sets the availability target');
  ok(/target 99 %/i.test(await txt(p, 'kp')), 'target shown after save');
  await p.close();

  EMPTY = true; p = await open(); await p.waitForFunction(() => /WAN \/ LAN Route Map/.test(document.getElementById('body').textContent));
  ok(!(await p.$('#x-mx')), 'empty map: nothing invented, says what to do');
  await p.close();

  ok(/branchnet: 'branch-connectivity\.html'/.test(fs.readFileSync(path.join(SRC, 'vendor/zyb-menu.js'), 'utf8')) && /branchnet: 'branch-connectivity\.html'/.test(fs.readFileSync(path.join(SRC, 'vendor/zyb-early.js'), 'utf8')), 'the portal sample page redirects here');
  ok(/ branch-connectivity\.html /.test(fs.readFileSync(path.join(SRC, 'install-dashboards.sh'), 'utf8')), 'in the installer');
  ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  await browser.close(); srv.close();
  console.log(`${n - bad}/${n} checks passed`); process.exit(bad ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });
