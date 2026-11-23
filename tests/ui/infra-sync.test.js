// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for the "Infrastructure Automation link" card on reconcile.html against the REAL IT Asset Management
// engine (reconcile.js + infra-sync.js) talking to a fake sentra-infra API: before a sync it says what waits and what cannot
// go (with the reason); "Sync now" creates the targets and the card reports them; sentra-infra-only targets come back into the
// register; the link missing is named; a viewer sees no button. Data is SYNTHETIC.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node infra-sync.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const ITAM = path.resolve(__dirname, '../../backend/itam'), DASH = path.resolve(__dirname, '../../ui');
const H = require(path.join(ITAM, 'tests/helpers.js'));
let WHO = { user: 'ali.syn', role: 'operator' };
let n = 0, bad = 0;
const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const ADM = { user: 'syed', role: 'admin', ip: '' }, SECRET = 's'.repeat(32);

(async () => {
  const e = await H.startApp({ noAi: true });
  const A = e.app.assets;
  A.create({ name: 'SW-SYN-1', type: 'network', status: 'in_use', vendor: 'Cisco', model: 'C9300-48P', mgmt_ip: '10.1.0.2' }, ADM);
  A.create({ name: 'APP-SYN-LNX', type: 'server', status: 'in_use', os: 'Red Hat Enterprise Linux 9', mgmt_ip: '10.2.0.5' }, ADM);
  A.create({ name: '<b>RT-SYN-J</b>', type: 'network', status: 'in_use', vendor: 'Juniper', mgmt_ip: '10.1.0.9' }, ADM);
  const st = { probes: [{ id: 'relay-1' }], targets: [{ id: 't_x', kind: 'host', profile: 'linux', name: 'jump-syn-01', address: '10.3.0.10' }] };
  const fake = async (url, o) => {
    if (o.headers['X-Sentra-Proxy-Secret'] !== SECRET) return { status: 401, json: {} };
    const p = url.replace(/^https?:\/\/[^/]+\/api\/infra/, '');
    if (p === '/probes') return { status: 200, json: { probes: st.probes } };
    if (p === '/targets' && o.method === 'GET') return { status: 200, json: { targets: JSON.parse(JSON.stringify(st.targets)) } };
    if (p === '/targets' && o.method === 'POST') { const t = Object.assign({ id: 't_' + st.targets.length }, JSON.parse(o.body)); st.targets.push(t); return { status: 200, json: { target: t } }; }
    return { status: 404, json: {} };
  };
  let secretOk = false;
  try { require(path.join(ITAM, 'engine/reconcile')).registerReconcile(e.app.srv, e.app, { noTimer: true }); } catch (x) { /* the card under test does not need the reconciliation report */ }
  require(path.join(ITAM, 'engine/infra-sync')).registerInfraSync(e.app.srv, e.app, { request: fake, readFile: () => { if (!secretOk) throw Object.assign(new Error('no'), { code: 'ENOENT' }); return SECRET; }, noTimer: true });

  const srv = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://x'), json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u.pathname === '/dashboards/whoami.json') return json(200, WHO);
    if (u.pathname.startsWith('/api/itam/')) {
      const h = Object.assign({}, req.headers, { 'x-sentra-proxy-secret': H.SECRET, 'x-auth-user': WHO.user, 'x-auth-role': WHO.role });
      const up = http.request({ host: '127.0.0.1', port: e.port, method: req.method, path: req.url, headers: h }, (r) => { res.writeHead(r.statusCode, r.headers); r.pipe(res); });
      req.pipe(up); return;
    }
    if (u.pathname.startsWith('/api/')) return json(404, { error: 'not in this test' });
    const f = path.join(DASH, u.pathname); if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (err, d) => { if (err) { res.writeHead(404); res.end(); return; } res.writeHead(200, { 'Content-Type': u.pathname.endsWith('.js') ? 'application/javascript' : u.pathname.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const url = 'http://127.0.0.1:' + srv.address().port + '/reconcile.html';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  let page;
  const as = async (who) => { WHO = who; if (page) await page.close(); page = await browser.newPage({ viewport: { width: 1400, height: 950 } }); page.on('pageerror', (x) => errs.push(x.message)); page.on('dialog', (d) => d.accept()); await page.goto(url); await page.waitForFunction(() => !/Loading/.test(document.getElementById('inf').textContent)); };
  const card = () => page.textContent('#inf');
  try {
    await as({ user: 'ali.syn', role: 'operator' });
    let t = await card();
    ok(/2 waiting for the next sync/.test(t) && /1 cannot go/.test(t), 'before a sync: 2 waiting, 1 cannot go: ' + t.slice(0, 200));
    ok(/no read-only profile for Juniper/.test(t) && /<b>RT-SYN-J<\/b>/.test(t) && !(await page.$('#inf b b')), 'the reason is shown, names as text');
    await page.click('#infgo'); await page.waitForTimeout(500);
    ok(/link not set up/.test(await page.textContent('body')) || /link not set up/.test(await card()), 'a missing link is named');
    secretOk = true;
    await as({ user: 'ali.syn', role: 'operator' });
    await page.click('#infgo'); await page.waitForFunction(() => /added/.test(document.getElementById('inf').textContent));
    t = await card();
    ok(/2 added/.test(t) && /from there: 1 added to the register/.test(t), 'synced both ways: ' + t.slice(0, 300));
    ok(st.targets.filter((x) => x.probe_id === 'relay-1').length === 2 && st.targets.every((x) => !('credential_ref' in x)), 'two targets on the probe, no credentials');
    ok(e.app.store.collection('assets').all((a) => a.mgmt_ip === '10.3.0.10' || /jump-syn-01/i.test(a.name || '')).length === 1, 'the sentra-infra-only host is in the register');
    await as({ user: 'nora.syn', role: 'viewer' });
    ok(!(await page.$('#infgo')), 'viewer: no sync button');
    ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  } finally { await browser.close(); srv.close(); await e.close(); }
  console.log(bad ? 'FAILED ' + bad + '/' + n + ' checks' : 'OK ' + n + '/' + n + ' checks'); process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
