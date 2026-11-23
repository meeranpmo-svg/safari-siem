// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for apm-claims-portal.html (Claims Portal Performance) against a stubbed SIEM: the Claims monitor is chosen
// by default, its Applications Manager attributes are sorted into response time / errors / JVM / database cards with
// Applications Manager's own status, alarms are this monitor's only, another monitor can be chosen; with Applications
// Manager not connected, every card says what to connect - no sample figures; a viewer is told the operator role is needed
// for attributes; every server failing still draws. Data is SYNTHETIC.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node apm-claims-portal.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const DASH = path.resolve(__dirname, '../../ui');
let WHO = { user: 'omar.syn', role: 'operator' }, MODE = 'live';
let n = 0, bad = 0;
const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const LIVE = {
  '/api/soc/integrations/apm/status': { configured: true, enabled: true },
  '/api/soc/integrations/apm/monitors': { items: [{ id: '101', name: 'CRM SYN', type: 'URL', availability: 'up', health: 'clear', managed: true },
    { id: '202', name: 'Claims Portal SYN', type: 'Tomcat', host: 'app-syn-3', availability: 'up', health: 'warning', managed: true, message: 'Response time high', last_polled: '26 Oct 2026 10:00' },
    { id: '303', name: 'Unmanaged SYN', managed: false }] },
  '/api/soc/integrations/apm/alarms': { items: [{ resource_id: '202', name: 'Claims Portal SYN', severity: 'warning', attribute: 'Response Time', message: 'above 10 s' }, { resource_id: '101', name: 'CRM SYN', severity: 'critical', attribute: 'x', message: 'crm alarm' }] },
  '/api/soc/integrations/apm/monitors/202': { resource_id: '202', attributes: [{ name: 'Response Time', value: '11200', unit: 'ms', status: 'warning' }, { name: 'Requests per Minute', value: '340', unit: '', status: 'clear' },
    { name: 'Error Count', value: '7', unit: '', status: 'critical' }, { name: 'JVM Heap Used', value: '1.8', unit: 'GB', status: 'clear' }, { name: 'JDBC Connection Pool Active', value: '38', unit: '', status: 'clear' }, { name: 'Build <b>x</b>', value: '12', unit: '' }] },
  '/api/soc/integrations/apm/monitors/101': { resource_id: '101', attributes: [{ name: 'Response Time', value: '420', unit: 'ms', status: 'clear' }] },
};
let S = JSON.parse(JSON.stringify(LIVE));
(async () => {
  const srv = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://x'), json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u.pathname === '/dashboards/whoami.json') return json(200, WHO);
    if (u.pathname.startsWith('/api/')) {
      if (MODE === 'down') return json(404, { error: 'not found' });
      if (WHO.role === 'viewer' && /monitors\/\d+$/.test(u.pathname)) return json(403, { error: 'forbidden' });
      return S[u.pathname] ? json(200, S[u.pathname]) : json(404, { error: 'not found' });
    }
    const f = path.join(DASH, u.pathname.replace(/^\/dashboards\//, '/')); if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (err, d) => { if (err) { res.writeHead(404); res.end(); return; } res.writeHead(200, { 'Content-Type': u.pathname.endsWith('.js') ? 'application/javascript' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const url = 'http://127.0.0.1:' + srv.address().port + '/dashboards/apm-claims-portal.html';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  let page;
  const wait = () => page.waitForFunction(() => /updated/.test(document.getElementById('up').textContent), null, { timeout: 15000 });
  const as = async (who) => { WHO = who; if (page) await page.close(); page = await browser.newPage({ viewport: { width: 1400, height: 1000 } }); page.on('pageerror', (x) => errs.push(x.message)); await page.goto(url); await wait(); };
  const txt = (sel) => page.innerText(sel);
  const cards = () => page.evaluate(() => document.getElementById('kk').innerText + document.querySelector('.g').innerText);
  try {
    await as({ user: 'omar.syn', role: 'operator' });
    ok(await page.$eval('#mon', (s) => s.value) === '202', 'Claims monitor chosen by default');
    ok(!/Unmanaged SYN/.test(await txt('#mon')), 'unmanaged monitors not offered');
    ok(/Claims Portal SYN performance/.test(await txt('#title')), 'title names the monitor');
    const k = await txt('#kk'); ok(/AVAILABILITY\s*up/i.test(k) && /HEALTH\s*warning/i.test(k) && /ACTIVE ALARMS\s*1/i.test(k), 'state tiles: ' + k.replace(/\s+/g, ' '));
    ok(/Response Time/.test(await txt('#g-perf')) && /11200 ms/.test(await txt('#g-perf')) && /Requests per Minute/.test(await txt('#g-perf')), 'response time and calls');
    ok(/Error Count/.test(await txt('#g-err')) && /critical/.test(await txt('#g-err')), 'errors with APM status');
    ok(/JVM Heap Used/.test(await txt('#g-jvm')) && /JDBC Connection Pool Active/.test(await txt('#g-db')) && /Build <b>x<\/b>/.test(await txt('#g-other')), 'JVM, database, other (escaped)');
    const al = await txt('#al'); ok(/above 10 s/.test(al) && !/crm alarm/.test(al), "this monitor's alarms only");
    let c = await cards(); ok(!/NaN|undefined|null|sample/i.test(c), 'no NaN / sample: ' + (c.match(/.{0,60}(NaN|undefined|null|sample).{0,60}/i) || [''])[0]);
    ok(await page.isVisible('#live'), 'live badge');
    await page.selectOption('#mon', '101'); await page.waitForFunction(() => /CRM SYN/.test(document.getElementById('title').textContent));
    ok(/420 ms/.test(await txt('#g-perf')) && /no error attribute/.test(await txt('#g-err')) && /crm alarm/.test(await txt('#al')), 'another monitor: what it measures, and what it does not');

    S = { '/api/soc/integrations/apm/status': { configured: false }, '/api/soc/integrations/apm/monitors': { items: [] }, '/api/soc/integrations/apm/alarms': { items: [] } };
    await as({ user: 'omar.syn', role: 'operator' });
    c = await cards(); ok(/Applications Manager is not connected/.test(c) && !/NaN|undefined|null|sample/i.test(c) && !(await page.isVisible('#live')), 'not connected: says what to connect, no figures');

    MODE = 'down'; await as({ user: 'omar.syn', role: 'operator' });
    ok(/not installed on the server/.test(await txt('#kk')), 'every server failing: says so');

    MODE = 'live'; S = JSON.parse(JSON.stringify(LIVE));
    await as({ user: 'nora.syn', role: 'viewer' });
    ok(/needs the operator role/.test(await txt('#g-perf')) && /AVAILABILITY\s*up/i.test(await txt('#kk')), 'viewer: state shown, attributes need operator');
    ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  } finally { await browser.close(); srv.close(); }
  console.log(bad ? 'FAILED ' + bad + '/' + n + ' checks' : 'OK ' + n + '/' + n + ' checks'); process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
