// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// network-route-map.html (WAN & LAN Route Map) against the REAL SIEM route-map engine (sentra-siem engine/netops/routemap.js via
// routes.js; device polls stubbed) with a SYNTHETIC network: with no map the administrator builds one from the inventory
// (each proposed link with its reason), puts it in the draft and saves it; the map draws devices and links by state; a
// branch Silver Peak goes down and the incident list shows it once as the root cause with the firewall behind it covered;
// the incident shows the Silver Peak fix steps and read-only checks; a congested FortiGate link lists the signed-in users to
// an analyst and hides them from a viewer; an operator acknowledges; the AI Network Engineer answer is text (a hostile answer
// stays text); a link with nothing measuring it reads "not measured"; a viewer has no setup; the menu entry.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node network-route-map.test.js
const http = require('http'), fs = require('fs'), os = require('os'), path = require('path');
const DASH = path.resolve(__dirname, '../../ui');
const SIEM = process.env.SENTRA_SIEM || path.resolve(__dirname, '../..', 'backend', 'siem');
const routes = require(path.join(SIEM, 'engine/netops/routes'));
const { createState } = require(path.join(SIEM, 'engine/soc/state'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const XSS = '<img src=x onerror="window.__xss=1">';
const DEVS = [
  { id: 'pa-dc', name: 'PA-DC-SYN', vendor: 'paloalto', ip: '10.0.0.1', site: 'Riyadh DC', role: 'firewall' },
  { id: 'core-dc', name: 'CORE-DC-SYN', vendor: 'cisco-ios', ip: '10.0.0.2', site: 'Riyadh DC', role: 'core' },
  { id: 'sp-dc', name: 'SP-DC-SYN', vendor: 'edgeconnect', ip: '10.0.0.3', site: 'Riyadh DC', role: 'sdwan-appliance' },
  { id: 'sp-jed', name: 'SP-JED-SYN', vendor: 'edgeconnect', ip: '10.2.0.3', site: 'Jeddah Branch', role: 'sdwan-appliance' },
  { id: 'fgt-jed', name: 'FGT-JED-SYN', vendor: 'fortigate', ip: '10.2.0.1', site: 'Jeddah Branch', role: 'firewall' },
];
const up = (x) => Object.assign({ at: Date.now(), ok: true, sources: ['ping', 'api'], errors: [], reach: { sent: 5, received: 5, rtt_avg_ms: 4 }, system: { cpu_pct: 20, mem_pct: 40 } }, x || {});
const down = () => ({ at: Date.now(), ok: false, sources: ['ping'], errors: [], reach: { sent: 5, received: 0 } });

(async () => {
  const state = await createState({ dir: fs.mkdtempSync(path.join(os.tmpdir(), 'rm-page-')) });
  const config = { netops: { enabled: false } }; Object.defineProperty(config, 'secrets', { value: {}, enumerable: false, writable: true });
  const snaps = { 'pa-dc': up({ interfaces: [{ name: 'ethernet1/1', alias: 'untrust-STC', admin: 'up', oper: 'up', speed_mbps: 1000, in_bps: 400e6, out_bps: 80e6 }] }), 'core-dc': up(), 'sp-dc': up(), 'sp-jed': up(),
    'fgt-jed': up({ interfaces: [{ name: 'wan1', admin: 'up', oper: 'up', speed_mbps: 100, in_bps: 95e6, out_bps: 5e6 }], tunnels: [{ name: 'to-dc', peer: '10.0.0.1', status: 'up' }], users: [{ user: 'syn.user1', ip: '10.2.5.10', group: 'Staff', bytes: 8e9 }, { user: XSS, ip: '10.2.5.11', bytes: 1e6 }] }) };
  const poller = { snapshot: (id) => snaps[id] || null, snapshots: () => snaps, stats: () => ({}), forget() {}, start() {} };
  const N = routes.createNetops({ state, config, log: { info() {}, warn() {}, error() {} }, poller });
  for (const d of DEVS) N.inventory.put(d, 'test');
  const R = []; routes.register({ route: (m, p, h) => { R.push({ m, re: new RegExp('^' + p.replace(/:[a-z]+/g, '([^/]+)') + '$'), keys: (p.match(/:[a-z]+/g) || []).map((k) => k.slice(1)), h }); } }, { state, config, log: { error() {}, info() {} }, netops: N });
  let ROLE = 'admin'; const asked = [];
  const srv = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://x'), json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u.pathname === '/dashboards/whoami.json') return json(200, { user: 'nora.syn', role: ROLE });
    if (u.pathname.startsWith('/api/soc/netops/')) {
      let b = ''; req.on('data', (c) => { b += c; }); req.on('end', async () => {
        const body = b ? JSON.parse(b) : {};
        if (u.pathname === '/api/soc/netops/routemap/route/ai') { asked.push(Object.assign({ route: true }, body)); return json(200, { answer: 'Verdict: the route is down at FGT-JED-SYN. ' + XSS, analysis: {}, steps: [] }); }
        if (u.pathname === '/api/soc/netops/ask') { asked.push(body); return json(200, { answer: 'Root cause: SP-JED-SYN lost power. ' + XSS, steps: [] }); }
        const r = R.find((x) => x.m === req.method && x.re.test(u.pathname)); if (!r) return json(404, { error: 'not found' });
        const mm = r.re.exec(u.pathname), params = {}; r.keys.forEach((k, i) => { params[k] = decodeURIComponent(mm[i + 1]); });
        const RANK = { viewer: 0, analyst: 1, operator: 2, admin: 3 }, out = {};
        const ctx = { role: ROLE, user: 'nora.syn', body, params, query: Object.fromEntries(u.searchParams), path: u.pathname, need(x) { if (RANK[ROLE] < RANK[x]) { out.c = 403; out.e = 'requires ' + x; return false; } return true; }, audit() {}, fail(c, e) { out.c = c; out.e = e; } };
        const rv = await r.h(ctx); if (out.c) return json(out.c, { error: out.e }); json(200, rv);
      }); return;
    }
    if (u.pathname.startsWith('/api/')) return json(404, { error: 'not found' });
    const f = path.join(DASH, u.pathname.replace(/^\/dashboards\//, '/')); if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (err, d) => { if (err) { res.writeHead(404); res.end(); return; } res.writeHead(200, { 'Content-Type': u.pathname.endsWith('.js') ? 'application/javascript' : u.pathname.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const url = 'http://127.0.0.1:' + srv.address().port + '/dashboards/network-route-map.html';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  const wait = (p, fn, arg) => p.waitForFunction(fn, arg, { timeout: 15000 }).then(() => true, () => false);
  try {
    const p = await browser.newPage({ viewport: { width: 1440, height: 1000 } }); p.on('pageerror', (x) => errs.push(x.message));
    await p.goto(url);
    ok(await wait(p, () => !document.getElementById('main').hidden && /No map yet/.test(document.getElementById('map').textContent)), 'no map yet: says so, nothing invented');
    ok(await wait(p, () => document.getElementById('prop')), 'admin: Build from inventory offered');
    await p.click('#prop');
    ok(await wait(p, () => /IPsec tunnel to-dc on FGT-JED-SYN has peer 10\.0\.0\.1/.test(document.body.textContent)), 'proposal: the IPsec link with its reason');
    ok(/looks like the WAN port/.test(await p.textContent('#cbody')), 'proposal: the Palo Alto WAN port');
    await p.click('#useprop');
    ok(await wait(p, () => document.querySelectorAll('#cbody tbody tr').length >= 5), 'proposal in the draft');
    await p.click('[data-ct="links"]');
    const r0 = await p.$$eval('#cbody tbody tr', (L) => L.map((tr) => Array.from(tr.querySelectorAll('input,select')).map((x) => x.value).join('|')));
    const li = r0.findIndex((x) => /\|internet\|/.test(x)); ok(li >= 0, 'internet link in the draft');
    await p.fill('#cbody tbody tr:nth-child(' + (li + 1) + ') input[data-k="capacity_mbps"]', '1000'); await p.press('#cbody tbody tr:nth-child(' + (li + 1) + ') input[data-k="capacity_mbps"]', 'Tab');
    await p.click('#save');
    ok(await wait(p, () => /Map saved \(version 1\)/.test(document.body.textContent)), 'map saved');
    // WAN view first: sites as one node each, the WAN links between them
    ok(await wait(p, () => document.querySelectorAll('#map svg [data-site]').length === 2), 'WAN view: one node per site');
    ok(/Riyadh DC/.test(await p.textContent('#map')) && /Jeddah Branch/.test(await p.textContent('#map')), 'WAN view: site names');
    ok(await p.$$eval('#map svg [data-wane]', (L) => L.length) >= 1, 'WAN view: a site-to-site link');
    // LAN view: click the data centre, its devices in tiers
    await p.click('#map svg [data-site="riyadh-dc"] circle', { force: true }).catch(async () => { await p.click('#map svg [data-site] circle >> nth=0', { force: true }); });
    ok(await wait(p, () => document.querySelector('[data-mv="lan"]').getAttribute('aria-selected') === 'true' && /EDGE SECURITY/.test(document.getElementById('map').textContent) && /CORE/.test(document.getElementById('map').textContent)), 'LAN view: the site in tiers');
    ok(/PA-DC-SYN/.test(await p.textContent('#map')) && /internet →|ipsec →|sdwan →/.test(await p.textContent('#map')), 'LAN view: devices and the links leaving the site');
    await p.click('[data-mv="all"]');
    ok(await wait(p, () => document.querySelectorAll('#map svg .nd').length === 6), 'map: 5 devices + the internet drawn');
    ok(/RIYADH DC/.test(await p.textContent('#map')) && /JEDDAH BRANCH/.test(await p.textContent('#map')), 'site boxes');
    ok(/40%/.test(await p.textContent('#map')), 'internet link shows 40% of the contracted 1000 Mb/s');
    // a branch Silver Peak goes down; the FortiGate behind it too
    snaps['sp-jed'] = down(); snaps['fgt-jed'] = Object.assign(down(), { users: snaps['fgt-jed'].users });
    await p.click('#refresh');
    ok(await wait(p, () => /Jeddah Branch is down/.test(document.getElementById('incs').textContent)), 'root cause listed: the whole branch (SD-WAN and the VPN backup both gone)');
    const incs = await p.$$eval('#incs .li', (L) => L.map((x) => ({ t: x.textContent, cov: x.classList.contains('cov') })));
    ok(incs[0] && /Jeddah Branch is down/.test(incs[0].t) && !incs[0].cov, 'root cause first');
    ok(incs.filter((x) => x.cov && /covered by site:jeddah-branch/.test(x.t)).length === 2, 'the Silver Peak and the FortiGate are covered by it');
    // route trace: branch FortiGate to the data-centre core - DOWN, at the branch
    await p.click('[data-mv="trace"]');
    await p.selectOption('#trf', { label: 'FGT-JED-SYN' }); await p.selectOption('#trt', { label: 'CORE-DC-SYN' });
    ok(await wait(p, () => /The route is DOWN/.test(document.getElementById('map').textContent)), 'trace: the route is down');
    ok(await p.$$eval('#map .hop .hn', (L) => L.length) >= 3, 'trace: hop by hop');
    ok(/Weakest hop/.test(await p.textContent('#map')), 'trace: the weakest hop named');
    ok(await wait(p, () => /Route analysis/.test(document.getElementById('map').textContent) && /single points of failure/i.test(document.getElementById('map').textContent)), 'route analysis from the engine: score, verdict, single points');
    ok(/Down/.test(await p.textContent('#ra')) && /Score breakdown/.test(await p.textContent('#ra')), 'route analysis: verdict down, itemised score');
    await p.click('#raai');
    ok(await wait(p, () => /route is down at FGT-JED-SYN/.test((document.getElementById('raans') || {}).textContent || '')), 'AI route analysis answer shown');
    ok(!(await p.evaluate(() => window.__xss)) && /<img src=x/.test(await p.textContent('#raans')), 'the AI answer is text: an injected tag is not run');
    ok(asked.some((x) => x.route && x.from && x.to), 'the page sends only the two device ids');
    await p.click('[data-mv="wan"]');
    ok(await wait(p, () => /down/.test(document.getElementById('map').textContent)), 'WAN view: the branch shows its devices down');
    await p.check('#onlybad'); ok(await wait(p, () => document.querySelectorAll('#map svg [data-site]').length >= 1), 'WAN: problems-only filter keeps the down branch');
    await p.click('#incs .li:has-text("SP-JED-SYN is down")');
    ok(await wait(p, () => /Orchestrator/.test(document.getElementById('det').textContent)), 'Silver Peak read-only checks on the device incident');
    await p.click('#incs .li >> nth=0');
    ok(await wait(p, () => /How to fix it/i.test(document.getElementById('det').innerText) && /UPS/.test(document.getElementById('det').textContent)), 'site incident: what to check at the site');
    await p.click('[data-ack]');
    ok(await wait(p, () => /acknowledged by nora\.syn/.test(document.getElementById('incs').textContent)), 'acknowledged by a person');
    await p.click('#incs .li >> nth=0'); await p.click('[data-ask]');
    ok(await wait(p, () => /Root cause: SP-JED-SYN lost power/.test((document.getElementById('aiout') || {}).textContent || '')), 'AI Network Engineer answer shown');
    ok(asked.filter((x) => !x.route).length === 1 && /site:jeddah-branch/.test(asked.filter((x) => !x.route)[0].question), 'the question names the incident');
    // recovered, but the FortiGate WAN link is congested
    snaps['sp-jed'] = up(); snaps['fgt-jed'] = up({ interfaces: [{ name: 'wan1', admin: 'up', oper: 'up', speed_mbps: 100, in_bps: 95e6, out_bps: 5e6 }], tunnels: [{ name: 'to-dc', peer: '10.0.0.1', status: 'up' }], users: [{ user: 'syn.user1', ip: '10.2.5.10', group: 'Staff', bytes: 8e9 }, { user: XSS, ip: '10.2.5.11', bytes: 1e6 }] });
    const cfg = N.routemap.map(); const ln = cfg.links.find((l) => l.b === 'fgt-jed' || l.a === 'fgt-jed');
    if (ln) { if (ln.b === 'fgt-jed') ln.b_if = 'wan1'; else ln.a_if = 'wan1'; N.routemap.save({ sites: cfg.sites, nodes: cfg.nodes, links: cfg.links, thresholds: cfg.thresholds }, 'admin.syn'); }
    ROLE = 'analyst'; await p.goto(url);
    ok(await wait(p, () => /Bandwidth: .*95%/.test(document.getElementById('incs').textContent)), 'congestion incident on the FortiGate WAN link');
    await p.click('#incs .li:has-text("Bandwidth")');
    ok(await wait(p, () => /syn\.user1/.test(document.getElementById('det').textContent)), 'analyst: the heaviest FortiGate user listed');
    ok(/read-only - an administrator changes the map/.test(await p.textContent('#cfgc')) && !(await p.$('#save')), 'analyst: setup read-only');
    ROLE = 'viewer'; await p.goto(url);
    ok(await wait(p, () => /Bandwidth/.test(document.getElementById('incs').textContent)), 'viewer: incidents shown');
    await p.click('#incs .li:has-text("Bandwidth")');
    ok(await wait(p, () => /shown to analysts and above/.test(document.getElementById('det').textContent)), 'viewer: user names hidden (PDPL)');
    ok(!(await p.$('[data-ack]')) && !(await p.$('[data-ask]')), 'viewer: no acknowledge, no AI');
    ok(await p.$eval('#cfg', (e) => e.hidden), 'viewer: no map setup');
    await p.click('[data-mv="all"]');
    const lk = await p.$$eval('#map svg .lk', (L) => L.map((g) => g.dataset.link));
    const um = (await (await fetch('http://127.0.0.1:' + srv.address().port + '/api/soc/netops/routemap')).json()).links.find((l) => l.state === 'unmeasured');
    ok(um && lk.includes(um.id), 'a link nothing measures is drawn as not measured');
    if (um) { await p.click('#map svg .lk[data-link="' + um.id + '"] path >> nth=0', { force: true }); ok(await wait(p, () => /nothing measures this link/.test(document.getElementById('det').textContent)), 'not measured is explained, never shown as up'); }
    ok(!(await p.evaluate(() => window.__xss)), 'hostile user name and AI answer stayed text');
    const nav = fs.readFileSync(path.join(DASH, 'vendor', 'zyb-nav.js'), 'utf8');
    ok(/"h": "network-route-map.html"/.test(nav) && /network-route-map\.html/.test(fs.readFileSync(path.join(DASH, 'install-dashboards.sh'), 'utf8')), 'menu entry and installer');
    ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  } finally { await browser.close(); srv.close(); }
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks');
  process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
