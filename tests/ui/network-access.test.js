// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Network Access Control (network-access.html) against the REAL SIEM module (sentra-siem engine/netops/nac.js through netops routes)
// over a stubbed Genian NAC poll and switch MAC table with SYNTHETIC devices: enforcement gauge and tiles with the real counts,
// the state bar filters the device list, findings (clone, not seen by NAC), switches by exposure, devices sorted by risk with the
// reasons, device detail with 30 days of state, Record today (operator, audited), AI off says why, Excel, a hostile host name stays
// text, viewer sees counts and no device identity (PDPL), no NAC = says what to connect, the menu entry and the portal redirect.
// Run: SENTRA_SIEM_DIR=/home/user/sentra-siem PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node network-access.test.js
const http = require('http'), fs = require('fs'), os = require('os'), path = require('path');
const DASH = path.resolve(__dirname, '../../ui');
const SIEM = process.env.SENTRA_SIEM_DIR || path.resolve(__dirname, '../../backend/siem');
const routes = require(path.join(SIEM, 'engine/netops/routes')), { createState } = require(path.join(SIEM, 'engine/soc/state'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const XSS = '<img src=x onerror="window.__xss=1">';
const ITEMS = [
  { mac: '3c52.82aa.0001', ip: '10.10.0.21', host: 'PC-FIN-01', status: 'Authorized', switch: 'ACC-SYN', port: 'Gi1/0/1', vlan: '10' },
  { mac: '3c52.82aa.0002', ip: '10.10.0.22', host: 'PC-HR-02', status: 'Quarantined', switch: 'ACC-SYN', port: 'Gi1/0/2', vlan: '99' },
  { mac: '3c52.82aa.0003', ip: '10.10.0.33', host: 'LT-GUEST ' + XSS, status: 'unauthorized', switch: 'ACC-SYN', port: 'Gi1/0/3', vlan: '10' },
  { mac: '3c52.82aa.0004', ip: '10.10.0.44', host: 'PRN-2F', status: 'Authorized', switch: 'ACC-SYN', port: 'Gi1/0/7', vlan: '20' },
  { mac: '3c52.82aa.0004', ip: '10.10.0.44', host: 'PRN-2F', status: 'Authorized', switch: 'ACC-JED', port: 'Gi1/0/9', vlan: '20' }];
let ROLE = 'operator';
const RANK = { viewer: 0, analyst: 1, operator: 2, admin: 3 };

(async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sentra-nacpage-')), state = await createState({ dir: path.join(dir, 'state') });
  const config = { netops: { enabled: false } }; Object.defineProperty(config, 'secrets', { value: {}, enumerable: false, writable: true });
  const snaps = {}, poller = { snapshot: (id) => snaps[id] || null, snapshots: () => snaps, stats: () => ({}), forget() {}, start() {} };
  const N = routes.createNetops({ state, config, log: { info() {}, warn() {}, error() {} }, poller });
  const R = {}, AUD = []; routes.register({ route: (m, p, h) => { R[m + ' ' + p] = h; } }, { state, config, log: { error() {}, info() {} }, netops: N });
  N.inventory.put({ id: 'nac', name: 'GENIAN-SYN', vendor: 'genian', ip: '10.0.5.9', role: 'nac', site: 'Riyadh HQ' }, 'test');
  N.inventory.put({ id: 'acc-syn', name: 'ACC-SYN', vendor: 'cisco-ios', ip: '10.0.5.2', role: 'access', site: 'Riyadh HQ' }, 'test');
  snaps.nac = { at: Date.now(), ok: true, nac: { items: ITEMS } };
  state.collection('portmap_macs').put({ id: 'a4bb6d000099', device: 'acc-syn', port: 'Gi1/0/12', first: Date.now(), last: Date.now() });
  const srv = http.createServer((req, res) => {
    const url = new URL(req.url, 'http://x'), u = url.pathname, json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u === '/dashboards/whoami.json' || u === '/auth/whoami') return json(200, { user: ROLE + '.syn', role: ROLE });
    const key = req.method + ' ' + u;
    if (R[key]) { let b = ''; req.on('data', (c) => { b += c; }); req.on('end', async () => {
      const o = {}, ctx = { role: ROLE, user: ROLE + '.syn', body: b ? JSON.parse(b) : {}, params: {}, query: Object.fromEntries(url.searchParams), path: u,
        need(r) { if (RANK[ROLE] < RANK[r]) { o.status = 403; return false; } return true; }, audit: (a, t, d) => AUD.push({ a, t, d }), fail(c, m) { o.status = c; o.error = m; } };
      try { const rv = await R[key](ctx); if (o.status) return json(o.status, { error: o.error || 'refused' }); json(200, rv); } catch (e) { json(e.code || e.status || 500, { error: e.message }); } }); return; }
    if (u.startsWith('/api/')) return json(404, { error: 'not in this test' });
    const f = path.join(DASH, u.replace(/^\/dashboards\//, '')); if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (e, d) => { if (e) { res.writeHead(404); return res.end(); } res.writeHead(200, { 'Content-Type': f.endsWith('.js') ? 'application/javascript' : f.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const url = 'http://127.0.0.1:' + srv.address().port + '/dashboards/network-access.html?standalone=1';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright'); const browser = await chromium.launch(), errs = [];
  const wait = (p, fn, arg) => p.waitForFunction(fn, arg, { timeout: 15000 }).then(() => true, () => false);
  try {
    const ctx = await browser.newContext({ viewport: { width: 1500, height: 1000 }, acceptDownloads: true });
    const p = await ctx.newPage(); p.on('pageerror', (e) => errs.push(e.message));
    await p.goto(url); ok(await wait(p, () => /Devices seen\s*4/.test(document.getElementById('kk').textContent)), 'tiles with the real counts (one device per MAC)');
    if (process.env.SHOT) await p.screenshot({ path: process.env.SHOT, fullPage: true });   // optional: a picture for review
    const k = await p.textContent('#kk'); ok(/Quarantined\s*1/.test(k) && /Unauthorised \/ unknown\s*1/.test(k) && /Not seen by NAC\s*1/.test(k), 'quarantined, unauthorised, not seen by NAC');
    ok(/40%/.test(await p.textContent('#gauge')), 'enforcement gauge = authorised / (devices + not seen by NAC)');
    const f = await p.textContent('#findings'); ok(/PRN-2F .* is on 2 switch ports/.test(f) && /a4:bb:6d:00:00:99 is on ACC-SYN Gi1\/0\/12 but NAC has never seen it/.test(f), 'findings: clone and not seen by NAC');
    ok(/ACC-SYN/.test(await p.textContent('#sw')), 'switches by exposure');
    ok((await p.$$('tr[data-ep]')).length === 5, 'device list: 4 NAC devices + 1 not seen by NAC');
    ok(/\+35 the same MAC is on 2 switch ports/.test(await p.textContent('#eps')), 'risk reasons listed under the device');
    await p.click('#bar i[data-f="quarantined"]'); ok(await wait(p, () => document.querySelectorAll('tr[data-ep]').length === 1 && /PC-HR-02/.test(document.getElementById('eps').textContent)), 'state bar filters the list');
    await p.click('#chips [data-f=""]'); await p.fill('#q', 'PRN'); ok(await wait(p, () => document.querySelectorAll('tr[data-ep]').length === 1), 'search');
    await p.click('tr[data-ep]'); ok(await wait(p, () => !document.getElementById('dlg').hidden && /NAC state, last 30 days/.test(document.getElementById('dlg').textContent)), 'device detail');
    await p.keyboard.press('Escape'); await p.fill('#q', '');
    ok(await p.isVisible('#sample')); await p.click('#sample'); ok(await wait(p, () => /Recorded 4 devices/.test(document.body.textContent)), 'Record today');
    ok(AUD.some((x) => x.a === 'netops.nac.sample'), 'sample audited');
    ok(/AI NAC analyst is off/.test(await p.textContent('#ai')), 'AI off says why');
    const [dl] = await Promise.all([p.waitForEvent('download', { timeout: 10000 }), p.click('#xls')]);
    ok(/^network-access-control-\d{4}-\d{2}-\d{2}\.xlsx$/.test(dl.suggestedFilename()), 'Excel export');
    ok(!(await p.evaluate(() => window.__xss)), 'hostile host name stayed text');
    ROLE = 'viewer'; const q = await ctx.newPage(); q.on('pageerror', (e) => errs.push(e.message)); await q.goto(url); await wait(q, () => /Devices seen\s*4/.test(document.getElementById('kk').textContent));
    ok(!(await q.isVisible('#sample')) && /shown to analysts and above \(PDPL\)/.test(await q.textContent('#eps')) && !/PC-HR-02|PRN-2F|a4:bb/.test(await q.textContent('body')), 'viewer: counts only, no device identity anywhere');
    ROLE = 'operator'; snaps.nac = null; N.inventory.remove('nac', 'test');
    const r = await ctx.newPage(); await r.goto(url);
    ok(await wait(r, () => /No Genian NAC is polled yet/.test(document.getElementById('nc').textContent)), 'no NAC says what to connect');
    const nav = fs.readFileSync(path.join(DASH, 'vendor', 'zyb-nav.js'), 'utf8');
    ok(/"h": "network-access.html"/.test(nav) && /network-access\.html/.test(fs.readFileSync(path.join(DASH, 'install-dashboards.sh'), 'utf8')), 'menu entry and installer');
    ok(/nac: 'network-access\.html'/.test(fs.readFileSync(path.join(DASH, 'vendor', 'zyb-menu.js'), 'utf8')) && /nac: 'network-access\.html'/.test(fs.readFileSync(path.join(DASH, 'vendor', 'zyb-early.js'), 'utf8')), 'the portal\'s Network Access Control opens this page');
    ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  } finally { await browser.close(); srv.close(); }
  console.log((bad ? 'FAILED ' : 'ok ') + (n - bad) + '/' + n);
  process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
