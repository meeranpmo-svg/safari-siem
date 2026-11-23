// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for app-route-map.html against the REAL IT Asset Management engine (engine/app-route.js + pyengine/app_route.py)
// with a stubbed SIEM (Applications Manager monitors, DBA Alert Center, Application Connections). Clicks through: an
// administrator adds an application from a discovered client machine, links its front-end monitor and an API monitor from
// the boxes; the map draws the route with the API down in red and the RAC database degraded; the dropped server with its
// listener refusal and fix; an operator sees the route and the discovered machines but no setup; a viewer sees "not checked"
// application servers (sessions are for operators); escaping. Data is SYNTHETIC.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node app-route-map.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const ITAM = path.resolve(__dirname, '../../backend/itam'), DASH = path.resolve(__dirname, '../../ui');
const H = require(path.join(ITAM, 'tests/helpers.js'));
let WHO = { user: 'syed', role: 'admin' };
let n = 0, bad = 0;
const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const XSS = '<img src=x onerror=alert(1)>';
const SIEM = {
  '/api/soc/integrations/apm/status': { configured: true, enabled: true, ok: true },
  '/api/soc/integrations/apm/monitors': { items: [{ id: '101', name: 'Claims portal URL', type: 'URL', host: 'claims.corpgroup.test', availability: 'up', health: 'clear', managed: true },
    { id: '102', name: 'Claims API ' + XSS, type: 'REST API', availability: 'down', health: 'critical', managed: true, message: 'HTTP 503' }] },
  '/api/soc/db/dba/status': { instances: [{ instance: 'ESP1', host: 'db1', db_name: 'ESP', level: 'ok', status: 'OPEN', open: { crit: 0, warn: 0 } }, { instance: 'ESP2', host: 'db2', db_name: 'ESP', level: 'ok', status: 'MOUNTED', open: { crit: 0, warn: 0 } }] },
  '/api/soc/db/oracle/connections': { reported: { sessions: true, listener: true }, applications: [{ machine: 'APPSRV1.corpgroup.test', program: 'w3wp.exe', service: 'CLAIMS', sessions: 40, state: 'connected' },
    { machine: 'APPSRV2', program: 'w3wp.exe', service: 'CLAIMS', sessions: 0, state: 'dropped' }],
    listener: [{ client_host: 'APPSRV2', service: 'CLAIMS', ok: 3, refused: 7, reasons: [{ code: '12514', meaning: 'service not known to the listener', fix: 'Check the service name in the connect string.', n: 7 }] }] },
};

(async () => {
  const e = await H.startApp({ noAi: true });
  require(path.join(ITAM, 'engine/app-route')).registerAppRouteRoutes(e.app.srv, e.app, {});
  const srv = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://x'), json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u.pathname === '/dashboards/whoami.json') return json(200, WHO);
    if (u.pathname.startsWith('/api/itam/')) {
      const h = Object.assign({}, req.headers, { 'x-sentra-proxy-secret': H.SECRET, 'x-auth-user': WHO.user, 'x-auth-role': WHO.role });
      const up = http.request({ host: '127.0.0.1', port: e.port, method: req.method, path: req.url, headers: h }, (r) => { res.writeHead(r.statusCode, r.headers); r.pipe(res); });
      req.pipe(up); return;
    }
    if (u.pathname === '/api/soc/db/oracle/connections' && WHO.role === 'viewer') return json(403, { error: 'requires role operator' });
    if (SIEM[u.pathname]) return json(200, SIEM[u.pathname]);
    if (u.pathname.startsWith('/api/')) return json(404, { error: 'not in this test' });
    const f = path.join(DASH, u.pathname); if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (err, d) => { if (err) { res.writeHead(404); res.end(); return; } res.writeHead(200, { 'Content-Type': u.pathname.endsWith('.js') ? 'application/javascript' : u.pathname.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const url = 'http://127.0.0.1:' + srv.address().port + '/app-route-map.html';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  let page, alerted = false;
  const as = async (who) => { WHO = who; if (page) await page.close(); page = await browser.newPage({ viewport: { width: 1450, height: 950 } }); page.on('pageerror', (x) => errs.push(x.message)); page.on('dialog', (d) => { alerted = true; d.dismiss(); }); await page.goto(url); await page.waitForFunction(() => /updated/.test(document.getElementById('up').textContent) || /not installed/.test(document.getElementById('svg').textContent)); };
  const txt = (sel) => page.textContent(sel);
  try {
    await as({ user: 'syed', role: 'admin' });
    ok(/No application recorded yet/.test(await txt('#svg')) && await page.isVisible('#add'), 'empty register: says so, admin can add');
    ok(/APPSRV1\.corpgroup\.test/.test(await txt('#disc')) && /APPSRV2/.test(await txt('#disc')), 'client machines the database sees are offered as discovered');
    // add from a discovered machine: the form is prefilled with the database, service and machine
    await page.click('#disc [data-adopt="0"]');
    ok(await page.inputValue('#detail [name="database"]') === 'ESP' && await page.inputValue('#detail [name="machines"]') === 'APPSRV1.corpgroup.test' && await page.inputValue('#detail [name="services"]') === 'CLAIMS', 'prefilled from the discovered machine');
    await page.fill('#detail [name="name"]', 'Claims'); await page.fill('#detail [name="url"]', 'https://claims.corpgroup.test');
    await page.fill('#detail [name="machines"]', 'APPSRV1.corpgroup.test, APPSRV2');
    await page.click('#detail form[data-new] button[type="submit"]');
    await page.waitForSelector('#svg g[data-node="a0-fe"]');
    ok(/Added Claims/.test(await txt('#detail')), 'added');
    ok(/Claims/.test(await txt('#svg svg')) && /Users/.test(await txt('#svg svg')), 'the route is drawn');
    // front end: link the URL monitor from its box
    await page.click('#svg g[data-node="a0-fe"]');
    ok(/no Applications Manager monitor linked/.test(await txt('#detail')), 'front end without a monitor: says what to link');
    await page.selectOption('#detail [name="front_monitor"]', '101'); await page.click('#detail form[data-hop="front"] button[type="submit"]');
    await page.waitForFunction(() => /Claims portal URL/.test(document.getElementById('svg').textContent));
    // APIs: tick the API monitor
    await page.click('#svg g[data-node="a0-api"]'); await page.check('#detail input[name="api_monitors"][value="102"]'); await page.click('#detail form[data-hop="api"] button[type="submit"]');
    await page.waitForSelector('#svg g[data-node="a0-api0"]');
    ok(/DOWN/.test(await txt('#svg g[data-node="a0-api0"]')), 'the API monitor is down on the map');
    ok(!(await page.$('#svg img')) && !(await page.$('#detail img')), 'monitor names are text, never HTML');
    ok(/Claims is down/.test(await txt('#banner')), 'banner names the application that is down');
    await page.click('#svg g[data-node="a0-srv1"]'); let d = await txt('#detail');
    ok(/APPSRV2 dropped its connections to ESP/.test(d) && /TNS-12514/.test(d) && /Check the service name in the connect string/.test(d), 'dropped server with the listener refusal and its fix');
    await page.click('#svg g[data-node="a0-db"]'); d = await txt('#detail');
    ok(/ESP2 not open/.test(d) && /ESP1 on db1/.test(d) && /warning/.test(await txt('#svg g[data-node="a0-db"]')), 'RAC with one instance not open: degraded, instances listed');
    ok(/Set up: database and service/.test(d) && await page.inputValue('#detail [name="services"]') === 'CLAIMS', 'database box carries its setup');
    ok(/Every client machine the databases see belongs to an application/.test(await txt('#disc')), 'both machines now belong to Claims');
    // operator: sees the route and the discovered list, no setup and no Add
    await as({ user: 'omar.syn', role: 'operator' });
    ok(!(await page.isVisible('#add')), 'operator: no Add');
    await page.click('#svg g[data-node="a0-fe"]'); ok(/set up by an administrator/.test(await txt('#detail')) && !(await page.$('#detail form')), 'operator: no setup form');
    // viewer: application servers not checked (sessions are for operators)
    await as({ user: 'v.syn', role: 'viewer' });
    ok(/not checked/.test(await txt('#svg g[data-node="a0-srv0"]')) && /visible to operators/.test(await txt('#disc')), 'viewer: servers not checked, discovered hidden with the reason');
    // the remove button asks twice
    await as({ user: 'syed', role: 'admin' }); await page.click('#svg g[data-node="a0-fe"]');
    await page.click('#detail [data-del]'); ok(/Click again to remove/.test(await txt('#detail')), 'remove asks for a second click');
    await page.click('#detail [data-del]'); await page.waitForFunction(() => /No application recorded yet/.test(document.getElementById('svg').textContent));
    ok(true, 'removed');
    ok(!alerted && !errs.length, 'no dialog, no page error: ' + errs.join(' | '));
  } finally { await browser.close(); srv.close(); e.close(); }
  console.log(bad ? 'FAILED ' + bad + ' of ' + n : 'OK ' + n + ' checks'); process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
